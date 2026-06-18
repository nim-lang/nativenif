#
#           Arkham — Leng type navigation (shared)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The single source of truth for "what is the type/slot of this value?", shared
## by BOTH the register allocator (`register_allocator`) and the emitters
## (`codegen_x64` / `codegen_a64` via `codegen_common`). It used to live on
## `CodeGen` — i.e. inside the emitter — so the allocator could not reach it and
## grew a degraded shadow (`isFloatVal`, hand-rolled form-ladders). Lifting it
## here, below both, lets every pass call the same `getType` / `exprSlot`.
##
## A `TypeCtx` is a lightweight *view* — pointers into whoever owns the symbol
## tables (the `CodeGen`). It carries no storage of its own and is cheap to copy.

import std / tables
import nifcore, nifcdecl
import slots, programs

type
  SymCat* = enum
    scNone                      ## not a module-level symbol (a function-local)
    scGlobal                    ## ordinary .bss/.data global or const
    scTvar                      ## thread-local (macOS TLV)
    scProc                      ## a proc — as a value it is its code address
  SymInfo* = object
    cat*: SymCat
    decl*: Cursor               ## scGlobal/scTvar: the `(gvar|tvar|const :name pragmas type …)`
    asmName*: string            ## scProc: the asm symbol whose address the proc denotes

  TypeCtx* = object
    ## A view over the symbol tables `getType` consults. The fields are `ptr`s
    ## into the owner's storage (the `CodeGen`), so a `TypeCtx` is a cheap handle
    ## both the allocator and the emitter can hold over the same tables.
    prog*: ptr Program                         ## the whole program (cross-module type env)
    callTarget*: ptr Table[string, CallTarget] ## call name → signature (for a call's result type)
    globals*: ptr Table[string, Cursor]        ## global var name → its decl cursor
    tvars*: ptr Table[string, Cursor]          ## thread-local var name → its decl cursor
    symType*: ptr Table[string, Cursor]        ## local/param name → its Leng type cursor

proc lookupSym*(tc: TypeCtx; nm: string): SymInfo =
  ## The one place a module-level symbol resolves to its kind + declaration:
  ## a main-module global/tvar/proc, or a cross-module symbol loaded lazily from
  ## its owning module's index. Callers (`getType`/`srcWidthSigned`/`asLoc`/
  ## `genVal`) classify on the result rather than re-deciding local-vs-foreign.
  if tc.globals[].hasKey(nm): return SymInfo(cat: scGlobal, decl: tc.globals[][nm])
  if tc.tvars[].hasKey(nm): return SymInfo(cat: scTvar, decl: tc.tvars[][nm])
  if tc.callTarget[].hasKey(nm): return SymInfo(cat: scProc, asmName: tc.callTarget[][nm].asmName)
  var found = false
  let d = lookupForeignDecl(tc.prog[], nm, found)
  if found:
    case d.stmtKind
    of ProcS: return SymInfo(cat: scProc, asmName: nm)   # foreign proc: its fully-qualified NIF name
    of TvarS: return SymInfo(cat: scTvar, decl: d)
    else: return SymInfo(cat: scGlobal, decl: d)

proc getType*(tc: TypeCtx; c: Cursor): Cursor =
  ## The structural Leng type cursor of expression `c` (arkham's analog of
  ## `typenav.getType`). Symbols resolve through `symType` / the global/tvar
  ## decls; `dot`/`at`/`deref` navigate into the base's object/array/pointer
  ## type; typed nodes (arith, conv, cast, call) read their carried type. This is
  ## the single source of truth for "is this float?" — no per-form special cases.
  case c.kind
  of Symbol:
    let nm = symName(c)
    if tc.symType[].hasKey(nm): return tc.symType[][nm]
    let si = tc.lookupSym(nm)
    case si.cat
    of scProc: result = tc.prog[].procPtr     # a proc as a value → its code-pointer type
    of scGlobal, scTvar:
      var d = si.decl
      d.into:
        inc d; skip d                         # name, pragmas
        result = d                            # the declared type (a copy)
        while d.hasMore: skip d
    of scNone: raiseAssert "arkham: getType — unknown symbol " & nm
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC, BitandC, BitorC, BitxorC,
       BitnotC, NegC, ConvC, CastC, OconstrC, AconstrC:
      var t = c
      t.into:
        result = t                            # the carried result/target type
        while t.hasMore: skip t
    of DotC:
      var t = c
      t.into:
        let objTy = resolveType(tc.prog[], tc.getType(t)); skip t  # past the base subtree
        result = fieldType(tc.prog[], objTy, symName(t)); inc t
        while t.hasMore: skip t
    of AtC, PatC:
      # `(at array idx)` indexes an array, `(pat ptr idx)` a pointer; either way
      # the result is the element/pointee type, which `innerType` yields for
      # `array`/`ptr`/`aptr` alike.
      var t = c
      t.into:
        let arrTy = resolveType(tc.prog[], tc.getType(t)); skip t  # past the base subtree
        result = innerType(tc.prog[], arrTy)
        while t.hasMore: skip t
    of DerefC:
      var t = c
      t.into:
        let ptrTy = resolveType(tc.prog[], tc.getType(t))          # pointer type
        result = innerType(tc.prog[], ptrTy)
        while t.hasMore: skip t
    of CallC:
      var t = c
      t.into:
        let callee = symName(t)
        if tc.callTarget[].hasKey(callee):
          result = tc.callTarget[][callee].retType
        else:
          # A foreign call whose target the emitter hasn't lazily cached yet (allocation
          # runs before the call is emitted): resolve its return type from the owning
          # module now and cache it (the emitter reuses the entry). Needed e.g. for a
          # global var initialized by a cross-module call (`var s = newStringStream()`).
          if isForeignSym(tc.prog[], callee):
            let ct = foreignCallTarget(tc.prog[], callee)
            tc.callTarget[][callee] = ct
            result = ct.retType
          else:
            result = tc.callTarget[].getOrDefault(callee).retType
        while t.hasMore: skip t
    of NilC: result = tc.prog[].voidPtr       # nil → a generic pointer type
    of TrueC, FalseC,                         # bool literals & bool-valued operators
       EqC, NeqC, LtC, LeC, AndC, OrC, NotC, OvfC:   # `(not operand)` carries NO type child
      result = tc.prog[].boolType
    of AddrC:                                 # &lvalue → (ptr <type-of-lvalue>)
      var t = c; inc t
      result = tc.prog[].ptrTypeOf(tc.getType(t))
    of SufC, ParC:                            # wrappers → the inner value's type
      var t = c; inc t
      result = tc.getType(t)
    of BaseobjC:                              # `(baseobj BaseType depth value)` → the base type
      var t = c; inc t                        # → the base type (first child)
      result = t
    else: raiseAssert "arkham: getType — unsupported expression " & $c.exprKind
  of IntLit:   result = tc.prog[].intType     # a bare literal's natural type
  of UIntLit:  result = tc.prog[].uintType
  of CharLit:  result = tc.prog[].charType
  of FloatLit: result = tc.prog[].floatType
  of StrLit:   result = tc.prog[].voidPtr     # a string literal is a pointer
  else: raiseAssert "arkham: getType — literal has no stored type"

proc exprSlot*(tc: TypeCtx; c: Cursor): AsmSlot =
  ## The classified slot of any expression — `getType` for structural forms,
  ## with literals/`addr` (which carry no type cursor) handled directly.
  case c.kind
  of FloatLit: AsmSlot(cls: AFloat, size: 8, align: 8)   # default f64; width refined by context
  of IntLit, UIntLit: AsmSlot(cls: AInt, size: 8, align: 8)
  of CharLit: AsmSlot(cls: AUInt, size: 1, align: 1)
  of StrLit: AsmSlot(cls: AUInt, size: 8, align: 8)      # a pointer
  of Symbol: slotOf(tc.prog[], tc.getType(c))
  of TagLit:
    case c.exprKind
    of AddrC: slotOf(tc.prog[], tc.getType(c))                       # &lvalue → precise (ptr <elem>)
    of NilC: AsmSlot(cls: AUInt, size: 8, align: 8)                 # nil → a generic pointer
    of TrueC, FalseC: AsmSlot(cls: AUInt, size: 1, align: 1)        # a bool
    of SizeofC, AlignofC: AsmSlot(cls: AInt, size: 8, align: 8)     # an integer constant
    of SufC, ParC:                                                   # wrappers → the inner value
      var t = c; inc t
      tc.exprSlot(t)
    else: slotOf(tc.prog[], tc.getType(c))
  else: AsmSlot(cls: AMem)
