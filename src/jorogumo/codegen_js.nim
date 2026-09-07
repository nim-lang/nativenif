#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The half of the generator that owns linear memory: it decides where every
## global and every read-only blob lives and turns compile-time initializers
## into bytes at those absolute addresses.
##
## Leng already gives every object an explicit layout, so — exactly as in
## ithaqua — there are no relocations: an address-valued field of a constant
## (a string's `data` pointer, a `(addr g)` initializer, a proc symbol in an
## RTTI method table) is a FIXUP resolved here, while the whole program's
## layout is in this module's hands. What comes out is a `memTop`, one address
## per global and a list of `(address, bytes)` segments; `dataInitJs` renders
## them as loader calls that fill `JMEM` before the program body runs.
##
## Code emission is M4+. This is the ground it stands on.

import std / [tables, sets, strutils, base64, assertions, algorithm]
import nifcore, nifcdecl
import jsnif, jsenc
import "../arkham/core" / [asmslots, programs, typenav]

const
  JsPtrSize* = 4
  NullGuard* = 1024'u32     ## below this stays untouched, so a null deref
                            ## reads zeros instead of the static data
  ShadowStackSize* = 1 shl 20

type
  ScalKind* = enum skI32, skI64, skF32, skF64, skMem
  Scal* = object
    kind*: ScalKind
    bits*: int              ## source-level width (8/16/32/64); Mem: byte size
    signed*: bool

  LocalKind = enum
    lkReg                         ## a scalar: lives in a JS `let`
    lkSlot                        ## a value in the frame, at `fp + off`
    lkPtr                         ## an aggregate PARAM: the JS argument already
                                  ## holds its address, so no slot is needed

  LocalSlot = object
    kind: LocalKind
    off: int                      ## lkSlot: byte offset from the frame base
    taken: bool                   ## `(addr :name)` occurs in the body

  TempSlot = object
    off: int                      ## byte offset of a materialized value
    size: int                     ## what it holds, so a plan mismatch is caught

  ProcCtx = object
    jsName: string                ## the JS function name
    symType: Table[string, Cursor] ## local/param name → its Leng type
    locals: Table[string, LocalSlot]
    retType: Cursor
    sret: bool                    ## the result is an aggregate: hidden dest arg
    sretName: string              ## JS name of that hidden parameter
    frameSize: int                ## shadow-stack bytes; 0 needs no frame at all
    fp: string                    ## JS name of the frame base, when frameSize > 0
    tmpPlan: seq[TempSlot]        ## materializations, in preorder
    tmpAt: int                    ## how many codegen has consumed
    tmp: int                      ## per-proc temporary counter
    labs: seq[string]             ## open `(lab)` label blocks, innermost last
    regLocals: seq[string]        ## `lkReg` locals, in declaration order

  JsGen* = object
    prog*: Program
    tags*: TagPool                ## the Leng pool `buf` was parsed with
    outp*: TokenBuf               ## the jsnif program under construction — its OWN pool
    callTarget: Table[string, CallTarget] ## typenav needs a mutable copy
    globals: Table[string, Cursor]        ## name → gvar/const decl (foreign ones cached on use)
    tvars: Table[string, Cursor]
    memTop*: uint32                    ## static-data bump pointer
    globalAddr*: Table[string, uint32]   ## CANONICAL name → address (see `globalAddrOf`)
    canonDecl: Table[string, Cursor]     ## canonical name → the decl to serialize (a C-linkage
                                         ## pair resolves through whichever name came first)
    staticsDone: HashSet[string]         ## canonical names whose static init is in `dataSegs`
    rodataAddr: Table[string, uint32]  ## string literal → address (deduped)
    dataSegs*: seq[(uint32, string)]
    allocLog: seq[(uint32, uint32, string)] ## (addr, size, owner) for the overrun check
    tableSlot: Table[string, uint32]   ## proc symbol → function-table index (0 is null)
    nextTableSlot: uint32
    tableEntries: seq[string]          ## slot i (from 1) → the JS name to bind there
    pending: seq[(string, Cursor)]     ## reachable procs not yet lowered
    emitted: HashSet[string]
    jsNameOf: Table[string, string]    ## NIF symbol → JS identifier
    usedNames: HashSet[string]
    p: ProcCtx                         ## the proc being lowered
    entrySym*: string

type
  JsGenError* = object of CatchableError
    ## A program the generator does not understand. This is an ordinary
    ## failure, not a broken invariant: the CLI reports it as one line and the
    ## coverage harness can ask "can you generate this?" without dying. An
    ## assertion here would be fatal — `--panics` off makes a `Defect`
    ## uncatchable — so a refusal must never be one.

proc err(g: JsGen; msg: string) {.noreturn.} =
  raise (ref JsGenError)(msg: msg)

proc typeCtx(g: var JsGen): TypeCtx =
  TypeCtx(prog: addr g.prog, callTarget: addr g.callTarget,
          globals: addr g.globals, tvars: addr g.tvars,
          symType: addr g.p.symType)

proc scalOf(g: var JsGen; t: Cursor): Scal =
  ## The computation class of a Leng type: how wide and how signed the SOURCE
  ## type is, and whether it travels in memory rather than in a value.
  let s = slotOf(g.prog, t)
  case s.kind
  of AFloat:
    if s.size == 4: Scal(kind: skF32, bits: 32) else: Scal(kind: skF64, bits: 64)
  of AMem: Scal(kind: skMem, bits: s.size)
  of ABool: Scal(kind: skI32, bits: 8, signed: false)
  of AInt, AUInt:
    let signed = s.kind == AInt
    if s.size == 8: Scal(kind: skI64, bits: 64, signed: signed)
    else: Scal(kind: skI32, bits: s.size * 8, signed: signed)

# ── linear memory layout ─────────────────────────────────────────────────────

proc alignUp(x: uint32; a: uint32): uint32 = (x + a - 1) and not (a - 1)

proc isPtrType(g: var JsGen; t: Cursor): bool =
  let r = resolveType(g.prog, t)
  r.kind == TagLit and r.typeKind in {PtrT, AptrT}

proc isAggType(g: var JsGen; t: Cursor): bool =
  ## A DotToken is the ABSENCE of a type — a void result, an elided field type.
  ## It has no size to ask for, so it is not an aggregate. The spelled `(void)`
  ## is the same absence (ithaqua's sret test checks `isVoidType` first for
  ## exactly this reason): a void result returns nothing, it does not sret a
  ## zero-byte object.
  if t.kind == DotToken: return false
  if t.kind == TagLit and t.typeKind == VoidT: return false
  scalOf(g, t).kind == skMem

proc byteSize(g: var JsGen; t: Cursor): int =
  let (sz, _) = typeSizeAlign(g.prog, t)
  sz

proc byteAlign(g: var JsGen; t: Cursor): int =
  ## A FRAME slot's alignment. `stackSlotAlign` and `typeSizeAlign` differ on
  ## purpose: a 16-byte array is align 8 as a type — its elements are — but
  ## align 16 as a stack slot. Everything here is a stack slot. The floor of 8
  ## is what makes a slot a valid home for a pointer or an i64 in a 32-bit
  ## target's world of 4-byte scalars.
  max(stackSlotAlign(g.prog, t), 8)

proc elemTypeOf(g: var JsGen; arrType: Cursor): Cursor =
  innerType(g.prog, resolveType(g.prog, arrType))


proc allocStatic(g: var JsGen; size, align: int; tag = ""): uint32 =
  g.memTop = alignUp(g.memTop, uint32(max(align, 1)))
  result = g.memTop
  g.memTop += uint32(max(size, 1))
  g.allocLog.add (result, uint32(max(size, 1)), tag)

proc flexPayloadLen(g: var JsGen; initv: Cursor): int =
  ## Extra bytes a constant initializer stores past its type's fixed size:
  ## the payload of a flexarray tail (a string literal or an array
  ## constructor). +1 for a string's NUL so C-string views stay valid.
  result = 0
  if initv.kind != TagLit or initv.exprKind notin {OconstrC, AconstrC}: return
  var t = initv
  t.into:
    skip t                                     # the constructed type
    while t.hasMore:
      if t.kind == TagLit and t.substructureKind == KvU:
        var kv = t
        kv.into:
          inc kv                               # field name
          if kv.kind == StrLit:
            result += strVal(kv).len + 1
          elif kv.kind == TagLit and kv.exprKind == AconstrC:
            # Elements × element size, with the same container convention as
            # `serializeConstInto`: an array/flexarray type gives the element
            # via `innerType`, a bare pointer container (hexer's fixed method
            # tables) means the elements ARE pointers. Diverging undersizes
            # the allocation and the image silently overruns the next global.
            var ac = kv
            ac.into:
              let arrT = resolveType(g.prog, ac)
              var esz: int
              if arrT.kind == TagLit and arrT.typeKind in {PtrT, AptrT}:
                esz = JsPtrSize
              else:
                let elemT = innerType(g.prog, arrT)
                (esz, _) = typeSizeAlign(g.prog, elemT)
              skip ac
              var n = 0
              while ac.hasMore: (inc n; skip ac)
              result += n * esz
          while kv.hasMore: skip kv
      skip t

proc declHasInit(decl: Cursor): bool =
  ## True when a `(gvar|tvar :name PRAGMAS TYPE INIT?)` carries an initializer.
  var d = decl
  result = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    skip d                                     # type
    result = d.hasMore and d.kind != DotToken
    while d.hasMore: skip d

proc globalAddrOf(g: var JsGen; name: string): uint32 =
  ## The linear-memory address of a gvar/const — foreign ones included, the
  ## lazy loader resolves their decls and the layout here is whole-program.
  ## The address is keyed by `gvarRefName`: a C-linkage PAIR (the defining
  ## `exportc` gvar and a body module's `importc` reference) shares one C
  ## symbol, so it must share one slot — two names, two addresses, is the
  ## silent-zero miscompile arkham's `gvarRefName` exists to prevent.
  ## Zero-initialized globals reserve space only; static initializers become
  ## image segments in `serializeStatics`.
  let canon = gvarRefName(g.prog, name)
  if g.globalAddr.hasKey(canon): return g.globalAddr[canon]
  let si = lookupSym(typeCtx(g), name)
  if si.cat notin {scGlobal, scTvar}:          # tvar: single-threaded target → a global
    err g, "not a global: " & name
  var d = si.decl
  var typ: Cursor
  var initv: Cursor
  var hasInit = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    typ = d
    skip d
    if d.hasMore and d.kind != DotToken:
      initv = d
      hasInit = true
    while d.hasMore: skip d
  var (sz, al) = typeSizeAlign(g.prog, typ)
  if hasInit:
    sz += flexPayloadLen(g, initv)
  result = allocStatic(g, sz, al, tag = canon)
  g.globalAddr[canon] = result
  # The decl to serialize: prefer one that carries an initializer, so an
  # `importc` reference seen first cannot hide the defining module's static.
  if not g.canonDecl.hasKey(canon) or
      (hasInit and not declHasInit(g.canonDecl[canon])):
    g.canonDecl[canon] = si.decl
  if si.cat == scGlobal and not g.globals.hasKey(name):
    g.globals[name] = si.decl                  # cache foreign decls for typenav
  elif si.cat == scTvar and not g.tvars.hasKey(name):
    g.tvars[name] = si.decl

proc strLitAddr(g: var JsGen; s: string): uint32 =
  if g.rodataAddr.hasKey(s): return g.rodataAddr[s]
  result = allocStatic(g, s.len + 1, 1, tag = "strlit")  # NUL-terminated, like the C backend
  g.rodataAddr[s] = result
  g.dataSegs.add (result, s & '\0')

proc tableSlotOf(g: var JsGen; sym: string): uint32 =
  ## A proc as a VALUE is an index into the function table — the twin of
  ## wasm's funcref table, with 0 reserved for nil.
  if g.tableSlot.hasKey(sym): return g.tableSlot[sym]
  result = g.nextTableSlot
  inc g.nextTableSlot
  g.tableSlot[sym] = result
  while g.tableEntries.len <= int(result): g.tableEntries.add ""
  g.tableEntries[int(result)] = sym         # bound to its JS name at the end

proc procDeclOf(g: var JsGen; nm: string; found: var bool): Cursor
proc ensureProc(g: var JsGen; sym: string; decl: Cursor)

proc procValue(g: var JsGen; sym: string): uint32 =
  ## A proc as a VALUE: its function-table slot, AND a reachability edge —
  ## ithaqua's `tableSlotOf` resolves through `refProc`, which declares the
  ## body. A slot for a proc nobody lowered would bind the "unbound extern"
  ## stub: right for a bodyless import, wrong for a body that was forgotten.
  result = tableSlotOf(g, sym)
  var found = false
  let decl = procDeclOf(g, sym, found)
  if found: ensureProc(g, sym, decl)

# ── object offsets ───────────────────────────────────────────────────────────

proc fieldOffsetIn(g: var JsGen; objType: Cursor; field: string;
                   found: var bool): int =
  ## Byte offset of `field` inside the RESOLVED object type `objType` (own
  ## fields only; the caller walks inheritance). Mirrors `objSizeAlign`.
  var oc = objType
  var off = 0
  found = false
  oc.into:
    if oc.kind == Symbol:                      # an inherited base occupies the front
      let (bsz, _) = typeSizeAlign(g.prog, oc)
      off = bsz
    skip oc
    while oc.hasMore:
      if oc.kind == TagLit and oc.typeKind == UnionT:
        # A variant payload (hexer lowers case objects to a union of
        # anonymous objects): every branch OVERLAYS at the union's offset.
        let (usz, ual) = typeSizeAlign(g.prog, oc)
        off = align(off, int(ual))
        var un = oc
        un.into:
          while un.hasMore:
            if not found:
              var inner = false
              let innerOff = fieldOffsetIn(g, un, field, inner)
              if inner:
                found = true
                result = off + innerOff
            skip un
        if not found:
          off += int(usz)
        skip oc
        continue
      oc.into:                                 # (fld :name pragmas type)
        let fn = symName(oc); inc oc
        skip oc                                # pragmas
        let (fsz, fal) = typeSizeAlign(g.prog, oc)
        skip oc
        off = align(off, fal)
        if fn == field:
          found = true
          result = off
          while oc.hasMore: skip oc
        off += fsz
      if found:
        while oc.hasMore: skip oc              # keep the `into` balanced
        return

proc dotOffset(g: var JsGen; baseType: Cursor; field: string; depth: int): int =
  ## Offset of `field` accessed at inheritance `depth` (0 = this object; the
  ## base subobject always sits at 0, so depth picks WHICH body declares it).
  var t = resolveType(g.prog, baseType)
  var lvl = depth
  while true:
    if t.kind == TagLit and t.typeKind == UnionT:
      return 0                                 # plain C union: members overlay
    if t.kind != TagLit or t.typeKind != ObjectT:
      err g, "dot into a non-object type"
    var oc = t
    var base: Cursor
    var hasBase = false
    oc.into:
      base = oc
      hasBase = oc.kind != DotToken
      skip oc
      while oc.hasMore: skip oc
    if lvl > 0:
      if not hasBase: err g, "dot inheritance depth exceeds bases"
      t = resolveType(g.prog, base)
      dec lvl
    else:
      var found = false
      let off = fieldOffsetIn(g, t, field, found)
      if found: return off
      if not hasBase: err g, "field not found: " & field
      t = resolveType(g.prog, base)

# ── constant initializers ────────────────────────────────────────────────────

proc putLE(bytes: var string; off: int; v: uint64; width: int) =
  ## Write `width` little-endian bytes of `v` at `off`, zero-extending.
  while bytes.len < off + width: bytes.add '\0'
  var x = v
  for i in 0 ..< width:
    bytes[off + i] = char(x and 0xFF)
    x = x shr 8

proc isAggregateGlobal(g: var JsGen; nm: string): bool =
  ## True when `nm` names a gvar/tvar/const whose DECLARED type is an
  ## aggregate (skMem) — the case where a C cast of the bare symbol means
  ## array decay to its address rather than a value read.
  let si = lookupSym(typeCtx(g), nm)
  if si.cat notin {scGlobal, scTvar}: return false
  var d = si.decl
  result = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    result = scalOf(g, d).kind == skMem
    while d.hasMore: skip d

proc constScalarBits(g: var JsGen; v: Cursor; ok: var bool): uint64 =
  ## The bit pattern of a compile-time scalar. Addresses resolve to absolute
  ## numbers because jorogumo owns the layout — this is where a fixup lands.
  ok = true
  case v.kind
  of IntLit: result = cast[uint64](intVal(v))
  of UIntLit: result = uintVal(v)
  of CharLit: result = uint64(ord(charLit(v)))
  of FloatLit: result = cast[uint64](floatVal(v))
  of StrLit: result = uint64(strLitAddr(g, strVal(v)))
  of Symbol:
    let nm = symName(v)
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scProc: result = uint64(procValue(g, nm))
    of scGlobal, scTvar, scNone:
      ok = false                               # a VALUE copy is a runtime init
      result = 0
  of TagLit:
    case v.exprKind
    of TrueC: result = 1
    of FalseC, NilC: result = 0
    of SufC, ParC:
      var t = v
      inc t
      result = constScalarBits(g, t, ok)
    of ConvC, CastC:
      var t = v
      t.into:
        let floatTarget = t.kind == TagLit and t.typeKind == FT
        # A pointer TARGET makes the operand's ADDRESS the value: `(cast (ptr T)
        # sym)` is what nifler emits for a reference to a const scalar, where
        # array decay does it implicitly for an aggregate.
        let ptrTarget = t.kind != DotToken and isPtrType(g, t)
        skip t                                 # the conv target type
        if floatTarget:
          # A float TARGET: still compile-time when the operand is a literal —
          # only the representation changes. The bits are the f64 form; the image
          # writer narrows them for an `f 32` global.
          case t.kind
          of FloatLit: result = cast[uint64](floatVal(t))
          of IntLit: result = cast[uint64](float64(intVal(t)))
          of UIntLit: result = cast[uint64](float64(uintVal(t)))
          of CharLit: result = cast[uint64](float64(ord(charLit(t))))
          else:
            ok = false                         # a runtime value has no bits here
            result = 0
        elif t.kind == Symbol and (ptrTarget or isAggregateGlobal(g, symName(t))):
          # The ADDRESS of a global is a layout-time constant here, since
          # jorogumo owns the layout. A conv of a scalar global to a NON-pointer
          # type stays a runtime value copy.
          result = uint64(globalAddrOf(g, symName(t)))
        else:
          result = constScalarBits(g, t, ok)
        while t.hasMore: skip t
    of AddrC, HaddrC:
      # The global's address: assigning it here is what makes the initializer's
      # dependency part of the layout.
      var t = v
      inc t
      if t.kind == Symbol:
        result = uint64(globalAddrOf(g, symName(t)))
      else:
        ok = false
    of NegC:
      var t = v
      t.into:
        skip t                                 # the type
        var innerOk = true
        let inner = constScalarBits(g, t, innerOk)
        ok = innerOk
        result = cast[uint64](0'i64 - cast[int64](inner))
        while t.hasMore: skip t
    else:
      ok = false
  else:
    ok = false

proc serializeConstInto(g: var JsGen; bytes: var string; base: int;
                        typ, v: Cursor) =
  ## Serialize a compile-time aggregate/scalar initializer at `base` in
  ## `bytes`; offsets mirror the runtime layout queries, so a constant and a
  ## load of the same field agree by construction.
  let rt = resolveType(g.prog, typ)
  if v.kind == TagLit and v.exprKind == OconstrC:
    var t = v
    t.into:
      let objT = resolveType(g.prog, t)
      skip t
      while t.hasMore:
        if t.substructureKind != KvU: err g, "malformed const oconstr"
        var kv = t
        kv.into:
          let field = symName(kv); inc kv
          let value = kv
          skip kv
          var fdepth = 0
          if kv.hasMore and kv.kind == IntLit:
            fdepth = int(intVal(kv))
          while kv.hasMore: skip kv
          let off = dotOffset(g, objT, field, fdepth)
          let ft = fieldType(g.prog, objT, field)
          let ftr = resolveType(g.prog, ft)
          if ftr.kind == TagLit and ftr.typeKind == FlexarrayT:
            if value.kind == StrLit:
              let s = strVal(value)
              while bytes.len < base + off: bytes.add '\0'
              for ch in s: bytes.add ch
              bytes.add '\0'
            elif value.kind == TagLit and value.exprKind == AconstrC:
              serializeConstInto(g, bytes, base + off, ftr, value)
            else:
              err g, "unsupported flexarray const payload"
          else:
            serializeConstInto(g, bytes, base + off, ft, value)
        skip t
  elif v.kind == TagLit and v.exprKind == AconstrC:
    var t = v
    t.into:
      let arrT = resolveType(g.prog, t)
      var elemT: Cursor
      var esz: int
      if arrT.kind == TagLit and arrT.typeKind in {PtrT, AptrT}:
        elemT = arrT                           # a method table: the slots ARE pointers
        esz = JsPtrSize
      else:
        elemT = innerType(g.prog, arrT)
        (esz, _) = typeSizeAlign(g.prog, elemT)
      skip t
      var idx = 0
      while t.hasMore:
        serializeConstInto(g, bytes, base + idx * esz, elemT, t)
        skip t
        inc idx
  elif v.kind == TagLit and v.exprKind == NilC:
    putLE(bytes, base, 0, JsPtrSize)
  elif v.kind == Symbol and isPtrType(g, rt) and
      lookupSym(typeCtx(g), symName(v)).cat in {scGlobal, scTvar}:
    # Object-file semantics: a symbol written into POINTER-typed data denotes
    # its ADDRESS — what arkham's data section relocates to, and what makes
    # `(gvar p (ptr T) g)` point at `g`. A symbol in non-pointer data is a
    # VALUE copy, a runtime init the `ini` chain owns.
    putLE(bytes, base, uint64(globalAddrOf(g, symName(v))), JsPtrSize)
  else:
    let sc = scalOf(g, rt)
    if sc.kind == skMem:
      err g, "unsupported aggregate const initializer form"
    var ok = true
    var bits = constScalarBits(g, v, ok)
    if not ok: err g, "const initializer is not compile-time evaluable"
    if sc.kind == skF32:
      bits = uint64(cast[uint32](float32(cast[float64](bits))))
    putLE(bytes, base, bits, max(sc.bits div 8, 1))

proc staticInit(g: var JsGen; decl: Cursor; typ, initv: var Cursor;
                hasInit: var bool): bool =
  ## The initializer of a global DECL, but only when it is genuinely STATIC.
  ## Zero inits need no segment (the buffer starts zeroed) and runtime inits
  ## are the `ini` chain's job — skipping them here must not be an error.
  hasInit = false
  result = false
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    typ = d
    skip d
    if d.hasMore and d.kind != DotToken:
      initv = d
      hasInit = true
    while d.hasMore: skip d
  if not hasInit: return
  if initv.kind == TagLit and initv.exprKind in {FalseC, NilC}: return
  if initv.kind == Symbol:
    let ic = lookupSym(typeCtx(g), symName(initv)).cat
    if ic == scProc: discard                   # the function-table slot
    elif ic in {scGlobal, scTvar} and isPtrType(g, typ): discard
                                             # a POINTER-typed symbol init is an
                                             # address fixup, static by nature
    else: return                               # a value copy from another global
  if initv.kind == TagLit and initv.exprKind in {ConvC, CastC}:
    # Static only when the operand is itself compile-time; a conv of a
    # global's value is the ini chain's job.
    var t = initv
    var staticInner = false
    t.into:
      let ptrTarget = t.kind != DotToken and isPtrType(g, t)
      skip t                                   # the conv target type
      staticInner = t.kind in {IntLit, UIntLit, CharLit, FloatLit, StrLit} or
        (t.kind == TagLit and t.exprKind in {TrueC, FalseC, SufC, NegC}) or
        # a cast to a pointer holds an ADDRESS, which the layout already knows
        (ptrTarget and t.kind == Symbol and
         lookupSym(typeCtx(g), symName(t)).cat in {scGlobal, scTvar})
      while t.hasMore: skip t
    result = staticInner
  elif initv.kind == TagLit and
      initv.exprKind notin {OconstrC, AconstrC, TrueC, SufC, ParC, AddrC, HaddrC, NegC}:
    result = false                             # runtime-computed init
  else:
    result = true

proc serializeStatics(g: var JsGen) =
  ## Turn every addressed global's static initializer into image segments.
  ## Runs to a fixpoint: serializing one global can name another (`(addr g)`,
  ## a method table), which discovers a new address. `staticsDone` persists
  ## across calls — codegen addresses foreign globals on demand, and
  ## `generateJs` drains them after the last body is lowered.
  while true:
    var round: seq[string] = @[]
    for n in g.globalAddr.keys:
      if not g.staticsDone.containsOrIncl(n): round.add n
    sort round                                 # a deterministic image, not Table order
    if round.len == 0: break
    for n in round:
      var typ, initv: Cursor
      var hasInit = false
      if not staticInit(g, g.canonDecl[n], typ, initv, hasInit): continue
      var bytes = ""
      serializeConstInto(g, bytes, 0, typ, initv)
      if bytes.len > 0:
        g.dataSegs.add (g.globalAddr[n], bytes)

proc layoutProgram*(g: var JsGen) =
  ## Assign every global and thread-local an address and serialize the statics
  ## known up front; what codegen discovers later is drained before emission.
  var names: seq[string] = @[]
  for n in g.globals.keys: names.add n
  for n in g.tvars.keys: names.add n
  sort names                                   # a deterministic layout, not Table order
  for n in names: discard globalAddrOf(g, n)
  serializeStatics(g)

proc checkSegments(g: var JsGen) =
  ## No segment may write past the allocation it was given: an undersized
  ## global silently corrupts its neighbour, which surfaces far away.
  for (at, s) in g.dataSegs:
    var owner = -1
    var ownerStart = 0'u32
    for i, (a, sz, _) in g.allocLog:
      if a <= at and at < a + sz:
        # the innermost allocation containing it, when one is nested in another
        if owner < 0 or a >= ownerStart:
          owner = i
          ownerStart = a
    if owner < 0:
      err g, "data segment at " & $at & " lies outside every allocation"
    let (a, sz, tag) = g.allocLog[owner]
    if uint64(at) + uint64(s.len) > uint64(a) + uint64(sz):
      err g, "data segment at " & $at & " (" & $s.len &
        " bytes) overruns `" & tag & "` (" & $sz & " bytes at " & $a & ")"

proc dataInitJs*(g: var JsGen): string =
  ## The static image as JS: one `D(base64, address)` call per segment (the
  ## data section's twin). Base64 because the image is arbitrary bytes and a
  ## JS string literal is not.
  checkSegments(g)
  result = ""
  for (at, s) in g.dataSegs:
    result.add "D(\"" & encode(s) & "\", " & $at & ");\n"

proc createJsGen*(buf: var TokenBuf; inputPath: string; tags: TagPool): JsGen =
  setTargetWord Wasm32               # the linear-memory model: 4-byte pointers
  result.tags = tags
  result.memTop = NullGuard
  result.nextTableSlot = 1           # slot 0 stays the null function pointer
  result.outp = createTokenBuf(sharedTags = createJsTagPool())
  result.callTarget = initTable[string, CallTarget]()
  result.globals = initTable[string, Cursor]()
  result.tvars = initTable[string, Cursor]()
  result.globalAddr = initTable[string, uint32]()
  result.canonDecl = initTable[string, Cursor]()
  result.staticsDone = initHashSet[string]()
  result.rodataAddr = initTable[string, uint32]()
  result.tableSlot = initTable[string, uint32]()
  result.jsNameOf = initTable[string, string]()
  result.usedNames = initHashSet[string]()
  result.emitted = initHashSet[string]()
  result.p.symType = initTable[string, Cursor]()
  result.p.locals = initTable[string, LocalSlot]()
  result.prog = collect(buf, inputPath, tags)
  result.callTarget = result.prog.callTarget
  for name, decl in result.prog.globals:
    result.globals[name] = decl
  for name, decl in result.prog.tvars:
    result.tvars[name] = decl

# ── code generation ──────────────────────────────────────────────────────────
## Leng → jsnif. The value model is §1's: a ≤32-bit int or a float is a JS
## `Number`, a 64-bit int is a `BigInt`, a pointer is a `Number` offset into
## `JMEM`, and an aggregate lives in linear memory. Anything not yet understood
## is REFUSED by name — a half-lowered program is worse than no program.

proc lengType(g: var JsGen; c: Cursor): Cursor = getType(typeCtx(g), c)

proc exprScal(g: var JsGen; c: Cursor): Scal = scalOf(g, lengType(g, c))

proc widthOf(sc: Scal): WidthCode =
  result = case sc.kind
    of skI32:
      case sc.bits
      of 8: (if sc.signed: wI8 else: wU8)
      of 16: (if sc.signed: wI16 else: wU16)
      else: (if sc.signed: wI32 else: wU32)
    of skI64: (if sc.signed: wI64 else: wU64)
    of skF32: wF32
    of skF64: wF64
    of skMem: wU32               # a pointer is an unsigned offset into the buffer

proc widthOf(g: var JsGen; t: Cursor): WidthCode = widthOf(scalOf(g, t))

proc widthBits(w: WidthCode): int =
  case w
  of wI8, wU8: 8
  of wI16, wU16: 16
  of wI32, wU32, wF32: 32
  of wI64, wU64, wF64: 64

proc unsignedOf(w: WidthCode): WidthCode =
  case w
  of wI8: wU8
  of wI16: wU16
  of wI32: wU32
  else: w

proc sufWidth(g: var JsGen; s: string): WidthCode =
  ## The width a NIF numeric suffix names. Nifler marks an EXPLICITLY typed
  ## literal (`5'u32`) with a leading `+`, which says nothing about the width.
  ## These are the only widths there are; an unknown suffix is a dialect
  ## change, not something to guess at.
  let s = if s.len > 0 and s[0] == '+': s[1 .. ^1] else: s
  case s
  of "i8": wI8
  of "u8": wU8
  of "i16": wI16
  of "u16": wU16
  of "i32": wI32
  of "u32": wU32
  of "i64": wI64
  of "u64": wU64
  of "f32": wF32
  of "f64": wF64
  else: err g, "unknown numeric suffix: " & s

proc litWidth(g: var JsGen; c: Cursor): WidthCode =
  ## The width of a LITERAL. A bare literal's type is the program's natural int
  ## type — `i32` under Wasm32 — so trusting it would truncate
  ## `(conv (f 64) 9223372036854775808u)` to zero. A literal that does not fit
  ## its natural width IS a 64-bit one; a `suf` node states its width and is
  ## authoritative.
  if c.kind == TagLit and c.exprKind == SufC:
    result = widthOf(exprScal(g, c))
    var t = c
    t.into:
      skip t                                   # the value
      result = sufWidth(g, strVal(t))
      while t.hasMore: skip t
    return
  let w = widthOf(exprScal(g, c))
  if widthBits(w) >= 64: return w
  case c.kind
  of IntLit:
    let v = intVal(c)
    if v > 0xFFFFFFFF'i64 or v < -0x8000_0000'i64: wI64 else: w
  of UIntLit:
    if uintVal(c) > 0xFFFF_FFFF'u64: wU64 else: w
  else:
    w

proc jsName(g: var JsGen; sym: string): string =
  ## A JS identifier for a NIF symbol. NIF names carry dots and module suffixes,
  ## which are not identifier characters in JS. The mapping is memoized — a
  ## symbol and every later use of it get the same name — and made INJECTIVE by
  ## a counter, because two Nim symbols collapsing onto one JS name would be
  ## silent wrong code. The `n_` prefix keeps every generated name clear of the
  ## preamble (`JMEM`, `I8`, `EXT`, `D`, …) and of JS reserved words.
  if g.jsNameOf.hasKey(sym): return g.jsNameOf[sym]
  var base = "n_"
  for ch in sym:
    base.add (if ch in {'a'..'z', 'A'..'Z', '0'..'9', '_'}: ch else: '_')
  var cand = base
  var n = 0
  while g.usedNames.contains(cand):
    inc n
    cand = base & "_" & $n
  g.usedNames.incl cand
  g.jsNameOf[sym] = cand
  result = cand

proc tmpName(g: var JsGen): string =
  ## Reserved through the same injective table, so a generated temporary can
  ## never land on a user name.
  inc g.p.tmp
  jsName(g, "tmp." & $g.p.tmp)

proc declType(g: var JsGen; nm: string): Cursor =
  ## The declared type of a global/tvar, as a cursor into its decl.
  let si = lookupSym(typeCtx(g), nm)
  if si.cat notin {scGlobal, scTvar}: err g, "not a global: " & nm
  var d = si.decl
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    result = d
    while d.hasMore: skip d

proc genExpr(g: var JsGen; c: Cursor)
proc genAddr(g: var JsGen; c: Cursor)
proc procResultType(decl: Cursor): Cursor
proc procBody(decl: Cursor): Cursor
proc hasBody(decl: Cursor): bool

# ── scalar, pointer, aggregate ───────────────────────────────────────────────
# What a type IS decides how its value travels. A scalar is a JS local or a
# frame slot; a pointer is a Number offset into JMEM and can be dereferenced;
# an aggregate is a LOCATION whose "value" is its address, exactly as in C and
# in ithaqua. `scalOf` calls pointers AND aggregates `skMem`, so the two are
# told apart by the Leng type tag, never by the slot class.

# ── frame addressing ─────────────────────────────────────────────────────────

proc slotAddr(g: var JsGen; off: int) =
  ## `fp + off`, a Number because `fp` is one.
  if g.p.fp.len == 0: err g, "internal: frame slot in a frameless proc"
  g.outp.openTree Add
  g.outp.width wU32
  g.outp.symUse g.p.fp
  g.outp.numLit int64(off)
  g.outp.closeTag

proc takeTemp(g: var JsGen; size: int): int =
  ## The next planned temporary. `planFrame` walked the same tree in the same
  ## preorder and reserved an offset for every node that must be materialized;
  ## consuming that plan here is what keeps layout and codegen from disagreeing
  ## about where a temporary lives. A mismatch means the two walks diverged —
  ## an internal error, reported as a refusal rather than emitting a program
  ## that reads the wrong slot.
  if g.p.tmpAt >= g.p.tmpPlan.len:
    err g, "internal: unplanned temporary of " & $size & " bytes"
  if g.p.tmpPlan[g.p.tmpAt].size != size:
    err g, "internal: temporary plan mismatch (planned " &
           $g.p.tmpPlan[g.p.tmpAt].size & ", asked " & $size & ")"
  result = g.p.tmpPlan[g.p.tmpAt].off
  inc g.p.tmpAt

proc genSymAddr(g: var JsGen; c: Cursor) =
  ## The address a symbol denotes: a frame slot, the address an aggregate
  ## parameter arrived as, or a global's static address.
  let nm = symName(c)
  if g.p.locals.hasKey(nm):
    let s = g.p.locals[nm]
    case s.kind
    of lkReg: err g, "the register local `" & nm & "` has no address"
    of lkSlot: slotAddr(g, s.off)
    of lkPtr: g.outp.symUse jsName(g, nm)
  else:
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scGlobal, scTvar:
      # A foreign global resolves through the lazy loader and is laid out HERE:
      # the layout is whole-program, so one address per C symbol, no relocation.
      g.outp.numLit int64(globalAddrOf(g, nm))
    else: err g, "not addressable: " & nm

proc genBaseAddr(g: var JsGen; c: Cursor) =
  ## The address a `dot`/`at`/`pat` walks from: a pointer's VALUE is the base,
  ## an aggregate or a local is its location.
  let t = lengType(g, c)
  if isPtrType(g, t): genExpr(g, c) else: genAddr(g, c)

proc scaledIndex(g: var JsGen; idx: Cursor; factor: int) =
  ## `index * factor` as a Number: adding a BigInt to a Number is a JS type
  ## error, and an address is always a Number in this value model.
  let iw = widthOf(exprScal(g, idx))
  if factor == 1:
    g.outp.cvtNode(iw, wU32):
      genExpr(g, idx)
  else:
    g.outp.openTree Mul
    g.outp.width wU32
    g.outp.numLit int64(factor)
    g.outp.cvtNode(iw, wU32):
      genExpr(g, idx)
    g.outp.closeTag

proc genAddr(g: var JsGen; c: Cursor) =
  ## `(addr X)` and every lvalue base: the byte address X denotes.
  case c.kind
  of Symbol: genSymAddr(g, c)
  of TagLit:
    case c.exprKind
    of DerefC:
      var t = c
      t.into:
        genExpr(g, t)                    # a pointer's value IS the address
        while t.hasMore: skip t
    of CallC, OconstrC, AconstrC:
      # A struct-returning call and a constructor in value position both
      # materialize in a planned slot and travel as that slot's address, so the
      # address of one IS its value.
      genExpr(g, c)
    of DotC:
      var t = c
      t.into:
        let base = t
        skip t                               # `(dot BASE FIELD DEPTH?)`, in that order
        let fld = symName(t)
        inc t
        var depth = 0
        if t.hasMore and t.kind == IntLit:
          depth = int(intVal(t))
          inc t
        let bt = lengType(g, base)
        let objT = if isPtrType(g, bt): elemTypeOf(g, bt) else: bt
        let off = dotOffset(g, objT, fld, depth)
        g.outp.openTree Add
        g.outp.width wU32
        genBaseAddr(g, base)
        g.outp.numLit int64(off)
        g.outp.closeTag
        while t.hasMore: skip t
    of AtC, PatC:
      var t = c
      t.into:
        let base = t
        let esz = max(byteSize(g, elemTypeOf(g, lengType(g, base))), 1)
        g.outp.openTree Add
        g.outp.width wU32
        genBaseAddr(g, base)
        skip t                           # the array / the pointer
        scaledIndex(g, t, esz)
        g.outp.closeTag
        while t.hasMore: skip t
    of ConvC, CastC, BaseobjC:
      # A reinterpretation of an object's storage — a distinct-type wrapper
      # (`(conv Wrap.0 iv.0)`), a same-size `cast`, or a view of an object as one
      # of its bases (`(baseobj Base.0 1 x)`; arkham's `layoutObjBody` puts the
      # base subobject at offset 0). None moves a byte, so the address is the
      # operand's and only the TYPE changes. A pointer TARGET is a different
      # animal: it produces a value, not a location.
      var t = c
      t.into:
        if isPtrType(g, t): err g, "cannot take the address of `" & $c.exprKind & "`"
        skip t
        if c.exprKind == BaseobjC: skip t     # the inheritance depth
        genBaseAddr(g, t)
        while t.hasMore: skip t
    else:
      err g, "cannot take the address of `" & $c.exprKind & "`"
  else:
    err g, "cannot take the address of this expression"

proc genExprCoerced(g: var JsGen; c: Cursor; want: WidthCode) =
  ## The one place the two numeric worlds meet: an operand is moved to the
  ## width its position demands, and only when the widths actually differ.
  let have = litWidth(g, c)
  if have == want:
    genExpr(g, c)
  else:
    g.outp.cvtNode(have, want):
      genExpr(g, c)

proc genSymValue(g: var JsGen; c: Cursor) =
  ## The value a symbol holds. An aggregate's value IS its address; anything
  ## else is loaded from where it lives — a JS local, a frame slot, a global's
  ## static address.
  let nm = symName(c)
  if g.p.locals.hasKey(nm):
    let s = g.p.locals[nm]
    let ty = g.p.symType[nm]
    if isAggType(g, ty) or s.kind == lkPtr:
      genSymAddr(g, c)                    # a location travels as its address
    elif s.kind == lkReg:
      g.outp.symUse jsName(g, nm)
    else:
      g.outp.tree HLoad:
        g.outp.width widthOf(scalOf(g, ty))
        slotAddr(g, s.off)
  else:
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scProc: g.outp.numLit int64(procValue(g, nm))     # a proc as a value
    of scGlobal, scTvar:
      let ty = declType(g, nm)
      if isAggType(g, ty):
        g.outp.numLit int64(globalAddrOf(g, nm))         # the global's address
      else:
        g.outp.tree HLoad:
          g.outp.width widthOf(scalOf(g, ty))
          g.outp.numLit int64(globalAddrOf(g, nm))
    of scNone: err g, "unknown symbol: " & nm

# ── constructors: materializing an aggregate value ───────────────────────────

proc constrSize(g: var JsGen; c: Cursor): int =
  ## The bytes a constructor occupies. The node names its own type, so the size
  ## never depends on what typenav makes of the enclosing expression.
  var t = c
  t.into:
    result = byteSize(g, t)
    while t.hasMore: skip t
  if result <= 0: err g, "constructor of unknown size"

proc copyToSlot(g: var JsGen; dstOff: int; src: Cursor; size: int) =
  ## `copyMem(fp+dstOff, <src's address>, size)` — an EXPRESSION, so a
  ## constructor fill composes inside a `Seq`.
  g.outp.openTree Call
  g.outp.ident "copyMem"
  slotAddr(g, dstOff)
  genBaseAddr(g, src)
  g.outp.numLit int64(size)
  g.outp.closeTag

proc storeSlot(g: var JsGen; off: int; w: WidthCode; val: Cursor) =
  g.outp.openTree HStore
  g.outp.width w
  slotAddr(g, off)
  g.genExprCoerced(val, w)
  g.outp.closeTag

proc zeroSlot(g: var JsGen; off, size: int) =
  ## `zeroMem(fp+off, size)`, an expression so it composes in a statement.
  g.outp.openTree Call
  g.outp.ident "zeroMem"
  slotAddr(g, off)
  g.outp.numLit int64(size)
  g.outp.closeTag

proc partName(c: Cursor): string =
  ## The type name an `oconstr` declares, read without entering its entries.
  var t = c
  inc t
  symName(t)

proc isInheritedPart(g: var JsGen; objTy: Cursor; part: string): bool =
  ## Is `part` one of `objTy`'s bases? Only the base chain says which nested
  ## `oconstr` is the inherited part, and guessing would write it at offset 0 of
  ## an object it does not belong to.
  var t = resolveType(g.prog, objTy)
  while t.kind == TagLit and t.typeKind == ObjectT:
    var oc = t
    var base: Cursor
    var hasBase = false
    oc.into:
      base = oc
      hasBase = oc.kind != DotToken
      while oc.hasMore: skip oc
    if not hasBase or base.kind != Symbol: break
    if symName(base) == part: return true
    t = resolveType(g.prog, base)

proc genCtorInto(g: var JsGen; destOff: int; c: Cursor) =
  ## Fill the frame slot at `destOff` from an `oconstr`/`aconstr`, emitting one
  ## JS comma sequence whose value is the destination address. A nested
  ## constructor is filled in place at its field's offset, so a literal costs
  ## one materialization, not one per level.
  var t = c
  t.into:
    let ty = t
    skip t                                   # the constructed type
    let rt = resolveType(g.prog, ty)
    if rt.kind != TagLit or rt.typeKind notin {ObjectT, ArrayT, FlexarrayT}:
      err g, "constructor of a non-aggregate type"
    g.outp.openTree Seq
    var elemOff = 0
    var isFirst = true
    while t.hasMore:
      var val: Cursor
      var off = 0
      var vt: Cursor
      var header = false
      if rt.typeKind != ObjectT:
        val = t
        let et = elemTypeOf(g, ty)
        off = destOff + elemOff
        elemOff += max(byteSize(g, et), 1)
        vt = et
      elif t.kind == TagLit and t.substructureKind == KvU:
        var fld = ""
        var fdepth = 0
        var kv = t
        kv.into:
          fld = symName(kv)
          inc kv
          val = kv
          skip kv                                # `into` wants the value consumed too
          if kv.hasMore and kv.kind == IntLit:
            fdepth = int(intVal(kv))             # the field's inheritance level
          while kv.hasMore: skip kv
        # The FIELD's type, never the value's: `(kv x.0 4)` gives `4` the
        # program's natural i32, and storing a u8 field as an i32 walks over
        # its neighbours.
        vt = fieldType(g.prog, rt, fld)
        off = destOff + dotOffset(g, ty, fld, fdepth)
      elif isFirst:
        # The INHERITANCE HEADER, ahead of the named fields: either the vtable
        # pointer of a RootObj-derived object (`(addr T.vt.)`) stored in the slot
        # at offset 0 — as ithaqua stores it — or a nested `oconstr` for the base
        # subobject, which fills that same region IN PLACE.
        header = t.kind != TagLit or t.exprKind != OconstrC
        if not header and not isInheritedPart(g, ty, partName(t)):
          err g, "`oconstr` part of a type that is not a base"
        val = t
        off = destOff
      else:
        err g, "malformed `oconstr` entry"
      isFirst = false
      if header:
        storeSlot(g, off, wU32, val)
      elif val.kind == TagLit and val.exprKind in {OconstrC, AconstrC}:
        genCtorInto(g, off, val)             # nested: filled in place
      elif isAggType(g, vt):
        copyToSlot(g, off, val, byteSize(g, vt))
      elif isPtrType(g, vt) or val.kind == StrLit:
        storeSlot(g, off, wU32, val)         # a string literal is its address
      else:
        storeSlot(g, off, widthOf(scalOf(g, vt)), val)
      skip t
    slotAddr(g, destOff)                     # the sequence's value
    g.outp.closeTag

# ── frame planning ───────────────────────────────────────────────────────────

proc collectNames(c: Cursor; taken: var HashSet[string]) =
  ## Every symbol name in a subtree.
  case c.kind
  of Symbol: taken.incl symName(c)
  of TagLit:
    var t = c
    t.into:
      while t.hasMore:
        collectNames(t, taken)
        skip t
  else: discard

proc markTaken(c: Cursor; taken: var HashSet[string]) =
  ## Every name whose address is taken, at any depth. Such a local cannot live
  ## in a JS `let`: nothing can point at a JS binding, and the point of §2 is
  ## that a Nim address is a JMEM offset.
  if c.kind != TagLit: return
  if c.exprKind in {AddrC, HaddrC}:
    # Mark EVERY name in the operand, not just a top-level symbol: the base of
    # `(addr (baseobj …))` / `(addr (dot …))` needs a slot too. The walk
    # over-approximates on purpose — names that are not locals are ignored, and
    # the safe direction is a slot, since a missed mark means a wrong address
    # while a spurious one only costs frame space.
    var t = c
    t.into:
      collectNames(t, taken)
      while t.hasMore: skip t
    return
  var t = c
  t.into:
    while t.hasMore:
      markTaken(t, taken)
      skip t

proc ctorType(g: var JsGen; c: Cursor): Cursor =
  ## The type an `oconstr`/`aconstr` builds.
  var t = c
  t.into:
    result = t
    while t.hasMore: skip t

proc calleeProctype(g: var JsGen; target: Cursor): Cursor =
  ## The proctype of a callee expression, or a NIL cursor when there is no
  ## proctype to speak of — an unresolvable symbol, a non-function value.
  ## typenav's rule for a call's type is the callee proctype's return child;
  ## an unknown symbol would trip its `raiseAssert`, so the check that turns
  ## it into a refusal naming the symbol happens here instead.
  if target.kind == Symbol:
    let nm = symName(target)
    if not g.p.symType.hasKey(nm) and lookupSym(typeCtx(g), nm).cat == scNone:
      return Cursor()
  var pt = resolveType(g.prog, lengType(g, target))
  if pt.kind == TagLit and pt.typeKind != ProctypeT:
    var inner = pt; inc inner
    pt = resolveType(g.prog, inner)            # peel `(ptr proctype)`
  if pt.kind == TagLit and pt.typeKind == ProctypeT: result = pt

proc callResultType(g: var JsGen; c: Cursor): Cursor =
  ## The result type of a call node — direct or indirect — by typenav's ONE
  ## rule: the return type of the callee's proctype. `planFrame` and codegen
  ## must agree on which calls carry an sret destination, and deriving both
  ## from this one rule is what makes them agree by construction.
  var t = c
  t.into:
    var pt = calleeProctype(g, t)
    if not pt.cursorIsNil:
      pt.into:                                 # (proctype NAME PARAMS RET PRAGMAS)
        skip pt; skip pt
        result = pt
        while pt.hasMore: skip pt
    while t.hasMore: skip t

proc callDestSize(g: var JsGen; c: Cursor): (int, int) =
  ## What the CALLER must reserve for a call's result: (size, align) when the
  ## result is an aggregate (the struct-return slot), (0, 8) otherwise.
  result = (0, 8)
  if c.kind != TagLit or c.exprKind != CallC: return
  let rt = callResultType(g, c)
  if not rt.cursorIsNil and isAggType(g, rt): result = (byteSize(g, rt), byteAlign(g, rt))

type
  FramePlan = object
    ## The state of the pre-order frame walk: which names must be addressable,
    ## and the next free byte offset in the frame.
    taken: HashSet[string]
    off: int

proc planNode(g: var JsGen; pl: var FramePlan; c: Cursor; needsTemp: bool) =
  if c.kind != TagLit: return
  if c.stmtKind == VarS:
    var t = c
    t.into:
      let nm = symName(t); inc t
      skip t                                   # pragmas
      var typ = t
      if typ.kind == DotToken:
        # The optimizer passes synthesize `(var :t . . INIT)` with no type
        # spelled out; infer it from the initializer, as lengc does.
        var v = t
        inc v
        if v.kind == DotToken: err g, "local `" & nm & "` has no type"
        typ = lengType(g, v)
      g.p.symType[nm] = typ
      if isAggType(g, typ) or nm in pl.taken:
        let al = byteAlign(g, typ)
        pl.off = align(pl.off, al)
        g.p.locals[nm] = LocalSlot(kind: lkSlot, off: pl.off, taken: true)
        pl.off += max(byteSize(g, typ), 8)
      else:
        g.p.locals[nm] = LocalSlot(kind: lkReg)
        if nm notin g.p.regLocals: g.p.regLocals.add nm
      var init = t
      skip init                                # `inc` would ENTER the type, not pass it
      if init.kind == TagLit:
        planNode(g, pl, init, not (init.exprKind in {OconstrC, AconstrC}))
      while t.hasMore: skip t
    return
  var nest = needsTemp
  if c.exprKind in {OconstrC, AconstrC} and needsTemp:
    let sz = constrSize(g, c)
    let al = byteAlign(g, ctorType(g, c))
    pl.off = align(pl.off, al)
    g.p.tmpPlan.add TempSlot(off: pl.off, size: sz)
    pl.off += max(sz, 8)
    nest = false                             # nested constructors fill in place
  else:
    let (dsz, dal) = callDestSize(g, c)
    if dsz > 0:
      pl.off = align(pl.off, dal)
      g.p.tmpPlan.add TempSlot(off: pl.off, size: dsz)
      pl.off += max(dsz, 8)
  var t = c
  t.into:
    while t.hasMore:
      var childTemp = needsTemp
      if not nest and t.kind == TagLit and t.exprKind in {ConvC, CastC, BaseobjC}:
        # `genCtorInto` fills a child constructor IN PLACE, but a child that only
        # REACHES a constructor through a reinterpretation is read as a value and
        # copied — so the constructor behind it needs a temporary of its own.
        childTemp = true
      planNode(g, pl, t, childTemp)
      skip t

proc planFrame(g: var JsGen; body: Cursor; params: seq[(string, Cursor)];
               taken: HashSet[string]) =
  ## Give every local its frame slot (or none) and reserve a temporary for
  ## every node that must be materialized: a constructor in value position, and
  ## every call whose aggregate result needs a destination. The walk is PREORDER
  ## and reserves in exactly the order codegen asks for them — `takeTemp` checks
  ## that the two agree, so a divergence is a refusal instead of corruption.
  ##
  ## A constructor filled straight into a known destination (a `var`'s own slot,
  ## or a field inside another constructor) needs no temporary; `needsTemp`
  ## carries that context down the walk.
  var pl = FramePlan(taken: taken)
  for (pn, pt) in params:
    if isAggType(g, pt):
      # The JS argument already holds the address; no slot to point at.
      g.p.locals[pn] = LocalSlot(kind: lkPtr)
    elif pn in taken:
      g.p.locals[pn] = LocalSlot(kind: lkSlot, off: pl.off, taken: true)
      pl.off += max(byteSize(g, pt), 8)
    else:
      g.p.locals[pn] = LocalSlot(kind: lkReg)
  planNode(g, pl, body, true)
  g.p.frameSize = align(pl.off, 16)

proc jsOpOf(k: LengExpr): JsTag =
  case k
  of AddC: Add
  of SubC: Sub
  of MulC: Mul
  of DivC: Div
  of ModC: Mod
  of ShlC: Shl
  of ShrC: Shr
  of BitandC: And
  of BitorC: Or
  of BitxorC: Xor
  of EqC: Eq
  of NeqC: Neq
  of LtC: Lt
  of LeC: Le
  else: NoJs

proc genTypedBinop(g: var JsGen; c: Cursor) =
  ## `(add T a b)` — the node carries the type its operands and result share,
  ## which is exactly the WidthCode jsenc demands. Both operands are moved to
  ## it, so a mixed-width Leng operation cannot straddle Number and BigInt.
  let op = jsOpOf(c.exprKind)
  if op == NoJs: err g, "not a binary operation: " & $c.exprKind
  var t = c
  t.into:
    let w = widthOf(g, t)
    skip t
    g.outp.openTree op
    g.outp.width w
    g.genExprCoerced(t, w)
    skip t
    g.genExprCoerced(t, w)
    g.outp.closeTag
    while t.hasMore: skip t

proc genCmp(g: var JsGen; c: Cursor) =
  ## `(lt A B)` and kin. A comparison carries NO type child — the grammar gives
  ## it only its two operands — so the width jsenc asks for comes from the left
  ## operand. The renderer compares loosely and applies no narrow-wrap, which is
  ## right here: a loaded value is already canonical for its type, and `==` is
  ## the one operator that bridges Number and BigInt by value.
  let op = jsOpOf(c.exprKind)
  if op == NoJs: err g, "not a comparison: " & $c.exprKind
  var t = c
  t.into:
    let w = litWidth(g, t)
    g.outp.openTree op
    g.outp.width w
    genExpr(g, t)
    skip t
    genExpr(g, t)
    g.outp.closeTag
    while t.hasMore: skip t

proc genSufLit(g: var JsGen; c: Cursor) =
  ## `(suf LIT "i8")` — the suffix decides the world: a 64-bit one is a BigInt,
  ## and its digits go out as text because a u64 does not fit an IntLit token.
  let w = litWidth(g, c)                    # the suffix, not the natural type
  var t = c
  inc t
  if w in {wI64, wU64}:
    case t.kind
    of IntLit: g.outp.bigIntLit $intVal(t)
    of UIntLit: g.outp.bigIntLit $uintVal(t)
    else: err g, "unsupported 64-bit literal"
  else:
    genExpr(g, t)

proc genCall(g: var JsGen; c: Cursor; wantValue: bool)
proc genInstr(g: var JsGen; c: Cursor; wantValue: bool)

proc genExpr(g: var JsGen; c: Cursor) =
  case c.kind
  of Symbol: genSymValue(g, c)
  of IntLit:
    let w = litWidth(g, c)
    if w in {wI64, wU64}: g.outp.bigIntLit $intVal(c)
    else: g.outp.numLit intVal(c)
  of UIntLit:
    let w = litWidth(g, c)
    if w in {wI64, wU64}: g.outp.bigIntLit $uintVal(c)
    else: g.outp.numLit int64(uintVal(c) and 0xFFFFFFFF'u64)
  of CharLit: g.outp.numLit int64(ord(charLit(c)))
  of FloatLit: g.outp.floatLit floatVal(c)
  of StrLit: g.outp.numLit int64(strLitAddr(g, strVal(c)))   # a string is its address
  of TagLit:
    case c.exprKind
    of SufC: genSufLit(g, c)
    of ParC:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
    of TrueC: g.outp.lit TrueLit
    of FalseC: g.outp.lit FalseLit
    of NilC: g.outp.numLit 0
    of SizeofC, AlignofC:
      # A compile-time constant of the natural int type (typenav's rule), and
      # jorogumo owns the layout that makes it known: `(sizeof T)` is just the
      # size the loader and the frame plan already agree on.
      var t = c
      t.into:
        let (sz, al) = typeSizeAlign(g.prog, t)
        g.outp.numLit int64(if c.exprKind == SizeofC: sz else: al)
        while t.hasMore: skip t
    of OvfC: g.outp.ident "ovf"    # the flags register: two preamble globals,
    of ErrvC: g.outp.ident "errv"  # never addressable (ithaqua's model)
    of NanC: g.outp.lit NanLit
    of InfC: g.outp.lit InfLit
    of NeginfC:
      g.outp.tree Neg:
        g.outp.width wF64
        g.outp.lit InfLit
    of InstrC: genInstr(g, c, wantValue = true)
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC, BitandC, BitorC, BitxorC:
      genTypedBinop(g, c)
    of EqC, NeqC, LtC, LeC: genCmp(g, c)
    of NegC, BitnotC:
      let op = if c.exprKind == NegC: Neg else: BNot
      var t = c
      t.into:
        let w = widthOf(g, t)
        skip t
        g.outp.tree op:
          g.outp.width w
          g.genExprCoerced(t, w)
        while t.hasMore: skip t
    of NotC:
      # `(not v)` carries NO type child, unlike the arithmetic nodes.
      var t = c
      t.into:
        g.outp.tree Not:
          g.outp.width wI32
          genExpr(g, t)
        while t.hasMore: skip t
    of AndC, OrC:
      # C's `&&`/`||`: short-circuit, no type child, and no narrow-wrap — with
      # canonical 0/1 operands the JS result is already 0 or 1.
      let op = if c.exprKind == AndC: LAnd else: LOr
      var t = c
      t.into:
        g.outp.openTree op
        g.outp.width wI32                    # vacuous, but every op node carries one
        genExpr(g, t)
        skip t
        genExpr(g, t)
        g.outp.closeTag
        while t.hasMore: skip t
    of BaseobjC:
      # An object viewed as one of its bases: same address, different type.
      # typenav has no `baseobj` case, so the type is read from the node.
      var t = c
      t.into:
        let ty = t
        if not isAggType(g, ty): err g, "`baseobj` of a non-aggregate type"
        skip t
        skip t                                  # the inheritance depth
        genBaseAddr(g, t)
        while t.hasMore: skip t
    of ConvC, CastC:
      if isAggType(g, lengType(g, c)):
        # A record conversion between two layouts: the value, which for an
        # aggregate IS its address, does not move.
        genAddr(g, c)
        return
      var t = c
      t.into:
        let dst = widthOf(g, t)
        skip t
        let src = litWidth(g, t)
        # `cast` reinterprets the BIT PATTERN, so widening it zero-extends
        # whatever the source's signedness: `(cast (i 64) b)` for an i16 holding
        # -1000 is 64536 — the stored bits — where `conv` converts the VALUE and
        # sign-extends. The FROM width carries that choice to the renderer,
        # which masks narrow unsigned sources.
        let fromW = if c.exprKind == CastC and widthBits(src) < widthBits(dst):
                      unsignedOf(src)
                    else: src
        if c.exprKind == CastC and (src in {wF32, wF64}) != (dst in {wF32, wF64}):
          # `cast` between a float and an integer MOVES THE BITS — NaN's own
          # pattern, not a truncation of a value that has no integer reading.
          # Only equal sizes have bits to move; `conv` of the same pair stays
          # arithmetic.
          if widthBits(src) != widthBits(dst):
            err g, "cast between " & $src & " and " & $dst & " of different sizes"
          g.outp.reintNode(src, dst):
            genExpr(g, t)
        elif fromW == dst and src == dst:
          genExpr(g, t)
        else:
          g.outp.cvtNode(fromW, dst):
            genExpr(g, t)
        while t.hasMore: skip t
    of AddrC, HaddrC:
      # `(addr LVALUE)` — the address of anything addressable, which is exactly
      # what `genAddr` computes. A local's slot, a global's static address, the
      # pointer a `deref` walked through: all one Number.
      var t = c
      t.into:
        genAddr(g, t)
        while t.hasMore: skip t
    of DerefC, DotC, AtC, PatC:
      # An aggregate's value IS its address; a scalar is loaded through it.
      let ty = lengType(g, c)
      if isAggType(g, ty):
        genAddr(g, c)
      else:
        g.outp.tree HLoad:
          g.outp.width widthOf(scalOf(g, ty))
          genAddr(g, c)
    of OconstrC, AconstrC:
      # A constructor in value position materializes in its planned slot and
      # travels as that slot's address.
      let off = takeTemp(g, constrSize(g, c))
      genCtorInto(g, off, c)
    of CallC: genCall(g, c, wantValue = true)
    else: err g, "unsupported expression: " & $c.exprKind
  else:
    err g, "unsupported token in an expression: " & $c.kind

# ── calls ────────────────────────────────────────────────────────────────────

proc procDeclOf(g: var JsGen; nm: string; found: var bool): Cursor =
  ## The `(proc …)` decl of a symbol: the main module's list, then the lazy
  ## foreign loader — ithaqua's `refProc` pattern. This is what makes the
  ## `ini` chain callable: hexer emits `main` calling `ini.0.<module>` for
  ## every import, and those procs live in the imported modules' files.
  ## Registering the typenav target on the way out is what classifies the
  ## name as a proc (and a foreign syscall as a syscall) for every later use.
  result = Cursor()
  found = false
  for pi in g.prog.procs:
    var d = pi.decl
    inc d                                      # into: the name
    if d.kind == SymbolDef and symName(d) == nm:
      result = pi.decl
      found = true
      return
  if isForeignSym(g.prog, nm):
    let d = lookupForeignDecl(g.prog, nm, found)
    if found:
      if d.stmtKind != ProcS:
        found = false                          # a data symbol is not callable
      else:
        if not g.callTarget.hasKey(nm):
          g.callTarget[nm] = foreignCallTarget(g.prog, nm)
        result = d

proc procResultType(decl: Cursor): Cursor =
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # params
    result = d
    while d.hasMore: skip d

proc genSyscall(g: var JsGen; base: string; t: var Cursor; wantValue: bool) =
  ## The runtime floor, the same two entry points ithaqua imports from `env`:
  ## write goes to the host, exit leaves. Anything else is refused rather than
  ## silently doing nothing.
  case base
  of "write":
    g.outp.openTree Call
    g.outp.ident "nim_write"
    for i in 0 ..< 3:                          # fd, buf, len — all i32-shaped
      g.genExprCoerced(t, if i == 1: wU32 else: wI32)
      skip t
    g.outp.closeTag
    while t.hasMore: skip t
    if not wantValue: discard                  # a statement context drops it
  of "exit", "_exit", "exit_group":
    g.outp.openTree Call
    g.outp.ident "nim_exit"
    g.genExprCoerced(t, wI32)
    g.outp.closeTag
    while t.hasMore: skip t
  of "mmap", "munmap", "mprotect", "futex":
    # Functional syscalls, not a dying path: a program whose point is to map
    # memory or wait on a futex CANNOT be served here, and trapping at runtime
    # would silently change what it does. Refused by name, as planned (M7).
    err g, "syscall `" & base & "` has no JS host binding (the JS bridge is M7)"
  else:
    # ithaqua's ruling, kept: a syscall the target cannot serve is `unreachable`,
    # a loud runtime trap — not a refusal that strands the whole program, and
    # never a silent no-op. The abort path (getpid/kill) lands here: the program
    # is already dying, and a throw is the JS twin of the wasm trap.
    while t.hasMore: skip t
    g.outp.openTree Call
    g.outp.ident "nim_unreachable"
    g.outp.closeTag

proc genCalleeValue(g: var JsGen; target: Cursor) =
  ## The function-table index a callee expression denotes. A proc VALUE is
  ## the slot number (`genSymValue`'s `scProc` case), so a fn-ptr local,
  ## parameter or global already holds the index — loaded, not called.
  if target.kind == Symbol:
    let nm = symName(target)
    if g.p.locals.hasKey(nm):
      let s = g.p.locals[nm]
      case s.kind
      of lkReg: g.outp.symUse jsName(g, nm)
      of lkSlot:
        g.outp.tree HLoad:
          g.outp.width wU32
          slotAddr(g, s.off)
      of lkPtr: g.outp.symUse jsName(g, nm)
    else:
      g.outp.tree HLoad:
        g.outp.width wU32
        g.outp.numLit int64(globalAddrOf(g, nm))    # a proc-typed gvar/tvar
  else:
    genExpr(g, target)                          # a cast or a closure-field load

proc genIndirectCall(g: var JsGen; target: Cursor; t: var Cursor) =
  ## `(call EXPR ARG*)` dispatching through a fn-ptr VALUE: `FTAB[i](args)`.
  ## The signature is the callee's PROCTYPE, the same one rule typenav uses
  ## to type the call — so the sret decision here and `callDestSize`'s plan
  ## cannot disagree. JS, unlike `call_indirect`, is not signature-strict: a
  ## closure proctype's trailing env argument lands on a proc that ignores it,
  ## which is why ithaqua's synthetic thunk needs no twin here.
  var pt = calleeProctype(g, target)
  if pt.cursorIsNil:
    err g, (if target.kind == Symbol: "indirect call through unknown symbol " &
                                          symName(target)
            else: "indirect call through a non-proctype value")
  var retT: Cursor
  var paramsT: Cursor
  pt.into:
    skip pt                                    # the name slot
    paramsT = pt
    skip pt
    retT = pt
    while pt.hasMore: skip pt
  let aggRet = not retT.cursorIsNil and isAggType(g, retT)
  g.outp.openTree Call
  g.outp.openTree Index
  g.outp.ident "FTAB"
  genCalleeValue(g, target)
  g.outp.closeTag
  if aggRet: slotAddr(g, takeTemp(g, byteSize(g, retT)))
  if paramsT.kind == TagLit:
    paramsT.into:
      while paramsT.hasMore:
        var q = paramsT
        var w = wU32
        var agg = false
        q.into:
          inc q                                # name
          skip q                               # pragmas
          agg = isAggType(g, q)
          if not agg: w = widthOf(g, q)
          while q.hasMore: skip q
        skip paramsT
        if t.hasMore:
          if agg: genExpr(g, t)
          else: g.genExprCoerced(t, w)
          skip t
  # anything past the declared parameters (a closure's env, a varargs tail)
  # rides along as-is — JS hands extra arguments to whoever is willing
  while t.hasMore:
    genExpr(g, t)
    skip t
  g.outp.closeTag

proc emitMemCall(g: var JsGen; fn: string; t: var Cursor) =
  ## A preamble mem helper, three arguments, each moved to a Number index —
  ## the same move ithaqua performs by wrapping an `i64` count to `i32`.
  g.outp.openTree Call
  g.outp.ident fn
  g.genExprCoerced(t, wI32)
  skip t
  g.genExprCoerced(t, wI32)
  skip t
  g.genExprCoerced(t, wI32)
  skip t
  while t.hasMore: skip t
  g.outp.closeTag

proc genMemIntrin(g: var JsGen; name: string; t: var Cursor; wantValue: bool) =
  ## `memcpy/memmove(dst, src, n)`, `memset(dst, v, n)`, `memcmp(a, b, n)` —
  ## the bulk ops ithaqua lowers to wasm `memory.copy`/`memory.fill` and a
  ## synthetic byte loop. The JS twins are preamble helpers over the `U8`
  ## view; `copyMem` is `copyWithin`, overlap-safe, so BOTH copies take it —
  ## exactly why wasm's `memory.copy` serves both too.
  # The CALLER owns the statement wrapper (`genStmt` wraps a call statement;
  # an expression context wants a value), so this emits a bare call.
  case name
  of "memcpy", "memmove":
    if wantValue: err g, "memcpy result value not modelled"
    emitMemCall(g, "copyMem", t)
  of "memset":
    if wantValue: err g, "memset result value not modelled"
    emitMemCall(g, "fillMem", t)
  of "memcmp":
    # value-returning (C's sign-of-first-difference), so unlike the copies
    # the result IS modelled; as a statement the value simply goes unused.
    emitMemCall(g, "memcmp", t)
  else:
    err g, "mem intrinsic not supported yet: " & name

proc genInstr(g: var JsGen; c: Cursor; wantValue: bool) =
  ## `(instr SYM args…)` — an intrinsic/instruction application (nimony
  ## #2196/#2211). ithaqua's ruling holds: the ATOMICS collapse to plain
  ## memory ops on a single-threaded target and the memorders are dropped.
  ## A compound row — one that reads, modifies, stores and maybe returns the
  ## old value — becomes an immediately-invoked arrow: that is JS for
  ## ithaqua's scratch locals, it keeps the operand evaluation order the wasm
  ## path has, and it drops into statement AND expression position alike.
  ## Rows that JS cannot express at the operand's width stay refusals.
  var t = c
  t.into:
    let nm = symName(t)
    let it = instrTargetOf(g.prog, nm)
    skip t
    case it.op
    of AtomicLoadOp:
      let w = widthOf(scalOf(g, lengType(g, c)))
      g.outp.tree HLoad:
        g.outp.width w
        genExpr(g, t)                            # the pointer
        while t.hasMore: skip t                  # memorder
    of AtomicStoreOp:
      if wantValue: err g, "(instr …) atomic store has no value"
      var vc = t
      skip vc
      let w = widthOf(scalOf(g, lengType(g, vc)))
      g.outp.tree HStore:
        g.outp.width w
        genExpr(g, t)                            # pointer
        skip t
        g.genExprCoerced(t, w)                   # value
        while t.hasMore: skip t                  # memorder
    of AtomicAddFetchOp, AtomicSubFetchOp:
      # returns the NEW value: load, op, store.
      let w = widthOf(scalOf(g, lengType(g, c)))
      let op = if it.op == AtomicAddFetchOp: Add else: Sub
      let pv = tmpName(g)
      let rv = tmpName(g)
      g.outp.openTree Call
      g.outp.openTree Arrow
      g.outp.openTree Params
      g.outp.closeTag
      g.outp.tree Let:
        g.outp.symDef pv
        genExpr(g, t)                            # pointer
        skip t
      g.outp.tree Let:
        g.outp.symDef rv
        g.outp.openTree op
        g.outp.width w
        g.outp.tree HLoad:
          g.outp.width w
          g.outp.symUse pv
        g.genExprCoerced(t, w)                   # delta
        while t.hasMore: skip t                  # memorder
        g.outp.closeTag
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse pv
          g.outp.symUse rv
      if wantValue:
        g.outp.tree Return: g.outp.symUse rv
      g.outp.closeTag                            # Arrow
      g.outp.closeTag                            # Call
    of AtomicFetchAddOp, AtomicFetchSubOp, AtomicFetchAndOp,
       AtomicFetchOrOp, AtomicFetchXorOp:
      # returns the OLD value.
      let w = widthOf(scalOf(g, lengType(g, c)))
      let op = case it.op
               of AtomicFetchAddOp: Add
               of AtomicFetchSubOp: Sub
               of AtomicFetchAndOp: And
               of AtomicFetchOrOp: Or
               else: Xor
      let pv = tmpName(g)
      let dv = tmpName(g)
      let ov = tmpName(g)
      g.outp.openTree Call
      g.outp.openTree Arrow
      g.outp.openTree Params
      g.outp.closeTag
      g.outp.tree Let:
        g.outp.symDef pv
        genExpr(g, t)                            # pointer
        skip t
      g.outp.tree Let:
        g.outp.symDef dv
        g.genExprCoerced(t, w)                   # operand
        skip t
      while t.hasMore: skip t                    # memorder
      g.outp.tree Let:
        g.outp.symDef ov
        g.outp.tree HLoad:
          g.outp.width w
          g.outp.symUse pv
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse pv
          g.outp.openTree op
          g.outp.width w
          g.outp.symUse ov
          g.outp.symUse dv
          g.outp.closeTag
      if wantValue:
        g.outp.tree Return: g.outp.symUse ov
      g.outp.closeTag                            # Arrow
      g.outp.closeTag                            # Call
    of AtomicExchangeOp:
      # (ptr, val, order) → the old value. A single-threaded swap.
      var pT = lengType(g, t)
      let elemT = innerType(g.prog, resolveType(g.prog, pT))
      let w = widthOf(scalOf(g, elemT))
      let pv = tmpName(g)
      let vv = tmpName(g)
      let ov = tmpName(g)
      g.outp.openTree Call
      g.outp.openTree Arrow
      g.outp.openTree Params
      g.outp.closeTag
      g.outp.tree Let:
        g.outp.symDef pv
        genExpr(g, t)                            # pointer
        skip t
      g.outp.tree Let:
        g.outp.symDef vv
        g.genExprCoerced(t, w)                   # value
        skip t
      while t.hasMore: skip t                    # memorder
      g.outp.tree Let:
        g.outp.symDef ov
        g.outp.tree HLoad:
          g.outp.width w
          g.outp.symUse pv
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse pv
          g.outp.symUse vv
      if wantValue:
        g.outp.tree Return: g.outp.symUse ov
      g.outp.closeTag                            # Arrow
      g.outp.closeTag                            # Call
    of AtomicCompareExchangeOp:
      # (ptr, expected_ptr, desired, weak, succ_order, fail_order) → bool.
      # Single-threaded: if *ptr == *expected { *ptr = desired; true }
      #                  else { *expected = *ptr; false }
      var pT = lengType(g, t)
      let elemT = innerType(g.prog, resolveType(g.prog, pT))
      let w = widthOf(scalOf(g, elemT))
      let pv = tmpName(g)
      let ev = tmpName(g)
      let dv = tmpName(g)
      let cv = tmpName(g)
      let rv = tmpName(g)
      g.outp.openTree Call
      g.outp.openTree Arrow
      g.outp.openTree Params
      g.outp.closeTag
      g.outp.tree Let:
        g.outp.symDef pv
        genExpr(g, t)                            # ptr
        skip t
      g.outp.tree Let:
        g.outp.symDef ev
        genExpr(g, t)                            # expected: a POINTER
        skip t
      g.outp.tree Let:
        g.outp.symDef dv
        g.genExprCoerced(t, w)                   # desired
        skip t
      while t.hasMore: skip t                    # weak + memorders
      g.outp.tree Let:
        g.outp.symDef cv
        g.outp.tree HLoad:
          g.outp.width w
          g.outp.symUse pv
      g.outp.tree Let:
        g.outp.symDef rv
        g.outp.numLit 0
      g.outp.openTree If
      g.outp.openTree Eq
      g.outp.width w
      g.outp.symUse cv
      g.outp.tree HLoad:
        g.outp.width w
        g.outp.symUse ev
      g.outp.closeTag
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse pv
          g.outp.symUse dv
      g.outp.tree ExprStmt:
        g.outp.tree Assign:
          g.outp.symUse rv
          g.outp.numLit 1
      g.outp.openTree Else
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse ev
          g.outp.symUse cv
      g.outp.closeTag                            # Else
      g.outp.closeTag                            # If
      if wantValue:
        g.outp.tree Return: g.outp.symUse rv
      g.outp.closeTag                            # Arrow
      g.outp.closeTag                            # Call
    else:
      err g, "(instr …) not lowered by jorogumo: " & $it.op

proc genCall(g: var JsGen; c: Cursor; wantValue: bool) =
  var t = c
  t.into:
    let target = t
    var indirect = true
    var nm = ""
    var ct: CallTarget
    var known = false
    if t.kind == Symbol:
      nm = symName(t)
      # classify a foreign callee BEFORE dispatching: the typenav target says
      # whether it is a syscall, an extern, or an ordinary proc — the same
      # lazy resolution `getType` performs for the call's type.
      if not g.callTarget.hasKey(nm) and isForeignSym(g.prog, nm):
        var fnd = false
        let fd = lookupForeignDecl(g.prog, nm, fnd)
        if fnd and fd.stmtKind == ProcS:
          g.callTarget[nm] = foreignCallTarget(g.prog, nm)
      if g.callTarget.hasKey(nm):
        ct = g.callTarget[nm]
        known = true
      # a Symbol that is not a proc decl — a local, param or proc-typed
      # global holding a fn-ptr — dispatches through the table. arkham's
      # `isIndirectCallTarget` follows the same rule.
      indirect = lookupSym(typeCtx(g), nm).cat != scProc
      inc t                                    # a Symbol is one token: now at the args
    else:
      skip t                                   # a tree callee: PAST the subtree,
                                               # `inc` would step into it
    if known and ct.syscall:
      var base = nm
      let dotSys = ct.asmName.find(".sys.")
      if dotSys >= 0: base = ct.asmName[0 ..< dotSys]
      genSyscall(g, base, t, wantValue)
    elif known and ct.memIntrin.len > 0:
      genMemIntrin(g, ct.memIntrin, t, wantValue)
    elif known and ct.bitBuiltin.len > 0:
      # ithaqua lowers these to wasm opcodes; the page pair maps onto the
      # preamble's `memorySize`/`memoryGrow`. The bit-count builtins are the
      # M-next `instr` survey — refused by name, never guessed.
      case ct.bitBuiltin
      of "__builtin_wasm_memory_size":
        # () -> pages: the preamble's `memorySize`, wasm `memory.size`'s twin.
        g.outp.openTree Call
        g.outp.ident "memorySize"
        g.outp.closeTag
        while t.hasMore: skip t                # zero args, drain defensively
      of "__builtin_wasm_memory_grow":
        # (delta pages) -> old page count or -1: the preamble reallocates and
        # copies; offsets survive the move, so the grow is honest, not a stub.
        g.outp.openTree Call
        g.outp.ident "memoryGrow"
        g.genExprCoerced(t, wI32)
        skip t
        while t.hasMore: skip t
        g.outp.closeTag
      else:
        err g, "bit builtin `" & ct.bitBuiltin & "` has no JS lowering"
    elif indirect:
      genIndirectCall(g, target, t)
    else:
      var found = false
      let decl = procDeclOf(g, nm, found)
      if known and ct.extern and not (found and hasBody(decl)):
        # an `importc` WITH a body is an ordinary definition — the C compiler
        # emits bodies for its importcs too; only the bodyless signature
        # reaches across the M7 bridge.
        err g, "extern `" & nm & "` (the JS bridge is M7)"
      if not found: err g, "no body to call: " & nm
      ensureProc(g, nm, decl)
      let rt = callResultType(g, c)
      let aggRet = not rt.cursorIsNil and isAggType(g, rt)
      g.outp.openTree Call
      g.outp.symUse jsName(g, nm)
      # The struct-return destination is the CALLER's planned temporary, and it
      # is reserved before the arguments are walked: `planFrame` reserved it at
      # the call node, and any temporary an argument needs comes after it.
      if aggRet: slotAddr(g, takeTemp(g, byteSize(g, rt)))
      # Each argument is moved to the width the callee's parameter declares, so
      # a caller holding an `i32` cannot hand a BigInt to an `i64` parameter.
      # An aggregate parameter needs no coercion: it travels as its address.
      var p = decl
      p.into:
        inc p                                    # name
        p.into:                                  # params
          while p.hasMore:
            var q = p
            var w = wU32
            var agg = false
            q.into:
              inc q                              # name
              skip q                             # pragmas
              agg = isAggType(g, q)
              if not agg: w = widthOf(g, q)
              while q.hasMore: skip q
            skip p
            if t.hasMore:
              if agg: genExpr(g, t)
              else: g.genExprCoerced(t, w)
              skip t
        while p.hasMore: skip p                # result type, pragmas, body
      # anything past the declared parameters (a varargs tail) rides along as-is
      while t.hasMore:
        genExpr(g, t)
        skip t
      g.outp.closeTag

# ── statements ───────────────────────────────────────────────────────────────

proc genVar(g: var JsGen; c: Cursor) =
  ## `(var :name PRAGMAS TYPE INIT?)`. A plain scalar is a JS `let`, which is
  ## exactly as scoped as the Leng block that declares it. An aggregate or an
  ## address-taken local has no JS binding to point at: `planFrame` gave it a
  ## slot, and its initializer becomes a store into that slot.
  var nm = ""
  var initv: Cursor
  var hasInit = false
  var t = c
  t.into:
    nm = symName(t)
    inc t
    skip t                                     # pragmas
    skip t                                     # the type: planFrame recorded it
    if t.hasMore and t.kind != DotToken:
      initv = t
      hasInit = true
    while t.hasMore: skip t
  if not g.p.locals.hasKey(nm): err g, "internal: unplanned local `" & nm & "`"
  let sl = g.p.locals[nm]
  case sl.kind
  of lkReg:
    # The binding came from the prologue; this statement only gives it its value.
    # With no initializer the hoisted zero already is the answer.
    if hasInit:
      let w = widthOf(scalOf(g, g.p.symType[nm]))
      g.outp.tree ExprStmt:
        g.outp.tree Assign:
          g.outp.symUse jsName(g, nm)
          g.genExprCoerced(initv, w)
  of lkSlot:
    let ty = g.p.symType[nm]
    if isAggType(g, ty):
      if hasInit:
        if initv.kind == TagLit and initv.exprKind in {OconstrC, AconstrC}:
          g.outp.tree ExprStmt: genCtorInto(g, sl.off, initv)
        else:
          g.outp.tree ExprStmt: copyToSlot(g, sl.off, initv, byteSize(g, ty))
    elif not hasInit:
      # The slot must not carry whatever the previous frame left there: an
      # uninitialized address-taken local reads as zero, as a wasm local does.
      g.outp.tree ExprStmt: zeroSlot(g, sl.off, byteSize(g, ty))
    else:
      let w = widthOf(scalOf(g, ty))
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          slotAddr(g, sl.off)
          g.genExprCoerced(initv, w)
  of lkPtr: err g, "internal: `" & nm & "` is a parameter, not a local"

proc lvalueType(g: var JsGen; c: Cursor): Cursor =
  ## The type of the thing an lvalue denotes. Typenav answers the same question
  ## for an lvalue as for an rvalue, so `deref`/`dot`/`at`/`pat` need no case —
  ## but `baseobj` is not in typenav's grammar, so its declared type is read off
  ## the node.
  if c.kind == Symbol:
    let nm = symName(c)
    if g.p.locals.hasKey(nm): result = g.p.symType[nm]
    else: result = declType(g, nm)
  elif c.kind == TagLit and c.exprKind == BaseobjC:
    var t = c
    t.into:
      result = t
      while t.hasMore: skip t
  else:
    result = lengType(g, c)

proc assignTo(g: var JsGen; dst, src: Cursor) =
  ## One store, wherever the destination lives. Only a register local has no
  ## address to store through; every other destination — a frame slot, a
  ## global, a field, an element, a `deref` — reduces to an address, and an
  ## aggregate moves as a copy between two of them.
  if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)) and
      g.p.locals[symName(dst)].kind == lkReg:
    let nm = symName(dst)
    g.outp.tree Assign:
      g.outp.symUse jsName(g, nm)
      g.genExprCoerced(src, widthOf(scalOf(g, g.p.symType[nm])))
    return
  let ty = lvalueType(g, dst)
  if isAggType(g, ty):
    g.outp.openTree Call
    g.outp.symUse "copyMem"
    genAddr(g, dst)
    genExpr(g, src)                            # an aggregate value IS an address
    g.outp.numLit int64(byteSize(g, ty))
    g.outp.closeTag
  else:
    let w = widthOf(scalOf(g, ty))
    g.outp.tree HStore:
      g.outp.width w
      genAddr(g, dst)
      g.genExprCoerced(src, w)

proc genAsgn(g: var JsGen; c: Cursor) =
  var t = c
  t.into:
    let dst = t
    skip t
    if dst.kind == TagLit and dst.exprKind in {ErrvC, OvfC}:
      # errv/ovf as destinations → the flag globals, like ithaqua's
      g.outp.tree ExprStmt:
        g.outp.openTree Assign
        g.outp.ident (if dst.exprKind == OvfC: "ovf" else: "errv")
        genExpr(g, t)
        g.outp.closeTag
      while t.hasMore: skip t
      return
    g.outp.tree ExprStmt: assignTo(g, dst, t)
    while t.hasMore: skip t

proc zeroLit(g: var JsGen; w: WidthCode) =
  ## A zero in the right world: a 64-bit slot holds a BigInt, and mixing the two
  ## is a JS type error, not a truncation.
  if w in {wI64, wU64}: g.outp.bigIntLit "0" else: g.outp.numLit 0

proc storeTempTo(g: var JsGen; dst: Cursor; tmp: string; w: WidthCode) =
  ## Store a materialized, already-canonical value into an lvalue — the store
  ## half of `assignTo` for the case where the value is a `let`-bound temp
  ## rather than a cursor, so no coercion is needed.
  if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)) and
      g.p.locals[symName(dst)].kind == lkReg:
    g.outp.tree Assign:
      g.outp.symUse jsName(g, symName(dst))
      g.outp.symUse tmp
    return
  let ty = lvalueType(g, dst)
  if isAggType(g, ty):
    err g, "keepovf destination is not an integer"
  g.outp.tree HStore:
    g.outp.width w
    genAddr(g, dst)
    g.outp.symUse tmp

proc ovfTest(g: var JsGen; opKind: LengExpr; sc: Scal; w: WidthCode;
             av, bv, rv: string) =
  ## The boolean overflow test over the bound temps: operands `av`, `bv` and
  ## the already-wrapped result `rv`.
  if sc.kind == skI32:
    # ithaqua's ≤32-bit move: compare the wrapped result against the WIDE one.
    # The wide world is BigInt — exact at these widths — and `cvt` moves the
    # operands there without loss; `!=` then bridges back by value.
    let bigW = if sc.signed: wI64 else: wU64
    let op = case opKind
             of AddC: Add
             of SubC: Sub
             else: Mul
    template cvtTo(v: string) =
      g.outp.openTree Cvt
      g.outp.width w
      g.outp.width bigW
      g.outp.symUse v
      g.outp.closeTag
    g.outp.openTree Neq
    g.outp.width w
    cvtTo rv
    g.outp.openTree op
    g.outp.width bigW
    cvtTo av
    cvtTo bv
    g.outp.closeTag
    g.outp.closeTag
    return
  # skI64: the classic identities, in BigInt — the same ones ithaqua emits.
  case opKind
  of AddC:
    if sc.signed:
      # ovf iff sign(a)==sign(b) and sign(r)!=sign(a): ((a^r)&(b^r)) < 0
      g.outp.openTree Lt
      g.outp.width w
      g.outp.openTree And
      g.outp.width w
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse bv
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.closeTag
      g.zeroLit w
      g.outp.closeTag
    else:
      g.outp.openTree Lt                       # carry: r < a
      g.outp.width w
      g.outp.symUse rv
      g.outp.symUse av
      g.outp.closeTag
  of SubC:
    if sc.signed:
      # ovf iff sign(a)!=sign(b) and sign(r)!=sign(a): ((a^b)&(a^r)) < 0
      g.outp.openTree Lt
      g.outp.width w
      g.outp.openTree And
      g.outp.width w
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse bv
      g.outp.closeTag
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.closeTag
      g.zeroLit w
      g.outp.closeTag
    else:
      g.outp.openTree Lt                       # borrow: a < b
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse bv
      g.outp.closeTag
  else:
    # mul: ovf iff a != 0 and r/a != b. ithaqua's `a == -1` guard exists only
    # because wasm's `div` TRAPS on min/-1; BigInt division is exact — it
    # hands back 2^63, which is `!= b`, and that is exactly the flag wanted.
    g.outp.openTree LAnd
    g.outp.width w
    g.outp.openTree Neq
    g.outp.width w
    g.outp.symUse av
    g.zeroLit w
    g.outp.closeTag
    g.outp.openTree Neq
    g.outp.width w
    g.outp.openTree Div
    g.outp.width w
    g.outp.symUse rv
    g.outp.symUse av
    g.outp.closeTag
    g.outp.symUse bv
    g.outp.closeTag
    g.outp.closeTag

proc genKeepovf(g: var JsGen; c: Cursor) =
  ## `(keepovf (add|sub|mul Type a b) dst)` — overflow-checked arithmetic:
  ## `(ovf, dst) = a op b`. JS has no flags register; `ovf` is a preamble
  ## global, and the wrapped result is the renderer's width-wrap doing what
  ## the wasm ALU does for free.
  var t = c
  t.into:
    let arith = t
    skip t
    let dst = t
    skip t
    while t.hasMore: skip t
    var a = arith
    var opKind: LengExpr
    var typ, lhs, rhs: Cursor
    a.into:
      opKind = arith.exprKind
      typ = a
      skip a
      lhs = a
      skip a
      rhs = a
      skip a
      while a.hasMore: skip a
    if opKind notin {AddC, SubC, MulC}:
      err g, "keepovf on unsupported op: " & $opKind
    let sc = scalOf(g, typ)
    if sc.kind notin {skI32, skI64}:
      err g, "keepovf on a non-integer type"
    let w = widthOf(sc)
    let resOp = case opKind
                of AddC: Add
                of SubC: Sub
                else: Mul
    # Bind the operands and the wrapped result: the tests read each operand
    # twice, and the result serves both the test and the store.
    let av = tmpName(g)
    let bv = tmpName(g)
    let rv = tmpName(g)
    g.outp.tree Let:
      g.outp.symDef av
      g.genExprCoerced(lhs, w)
    g.outp.tree Let:
      g.outp.symDef bv
      g.genExprCoerced(rhs, w)
    g.outp.tree Let:
      g.outp.symDef rv
      g.outp.openTree resOp
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse bv
      g.outp.closeTag
    g.outp.tree ExprStmt:
      g.outp.openTree Assign
      g.outp.ident "ovf"
      g.outp.openTree Cond
      ovfTest(g, opKind, sc, w, av, bv, rv)
      g.outp.numLit 1
      g.outp.numLit 0
      g.outp.closeTag
      g.outp.closeTag
    g.outp.tree ExprStmt:
      storeTempTo(g, dst, rv, w)

proc leaveFrame(g: var JsGen) =
  ## Pop the shadow stack. Every `return` leaves first, and the epilogue leaves
  ## for the paths that fall off the end, so each path pops exactly once.
  if g.p.frameSize > 0:
    g.outp.tree ExprStmt:
      g.outp.openTree Call
      g.outp.symUse "leave"
      g.outp.symUse g.p.fp
      g.outp.closeTag

proc genRet(g: var JsGen; c: Cursor) =
  var src: Cursor
  var hasVal = false
  var t = c
  t.into:
    if t.kind != DotToken:
      src = t
      hasVal = true
    while t.hasMore: skip t
  if not hasVal:
    leaveFrame(g)
    g.outp.openTree Return
    g.outp.closeTag
    return
  if isAggType(g, g.p.retType):
    # The destination is the CALLER's slot, handed in as the hidden first
    # argument, so it outlives this frame and may be returned after the pop.
    g.outp.tree ExprStmt:
      g.outp.openTree Call
      g.outp.symUse "copyMem"
      g.outp.symUse g.p.sretName
      genExpr(g, src)
      g.outp.numLit int64(byteSize(g, g.p.retType))
      g.outp.closeTag
    leaveFrame(g)
    g.outp.tree Return: g.outp.symUse g.p.sretName
  else:
    # The value may be read out of this very frame, so it is computed before
    # the pop and parked in a binding of its own.
    let r = tmpName(g)
    g.outp.tree Let:
      g.outp.symDef r
      g.genExprCoerced(src, widthOf(g, g.p.retType))
    leaveFrame(g)
    g.outp.tree Return: g.outp.symUse r

proc genStmt(g: var JsGen; c: var Cursor)   # mutually recursive with genCase

proc widthLit(g: var JsGen; w: WidthCode; v: int64) =
  ## A constant in the scrutinee's world: BigInt for the 64-bit widths, Number
  ## for the rest, so a comparison never straddles the two.
  if w in {wI64, wU64}: g.outp.bigIntLit $v
  else: g.outp.numLit v

proc caseValue(g: var JsGen; r: Cursor): int64 =
  ## The literal a case branch selects on. Only numbers and chars are labels;
  ## anything else (a symbol constant, a range of them) is refused rather than
  ## guessed at.
  case r.kind
  of IntLit: intVal(r)
  of CharLit: int64(ord(charLit(r)))
  else:
    err g, "unsupported case label: " & $r.kind

proc caseRangeTest(g: var JsGen; w: WidthCode; scrutinee: string; r: Cursor) =
  ## One `BranchRange` — a value, or `(range LO HI)` — as a test on the bound
  ## scrutinee.
  if r.kind == TagLit and r.substructureKind == RangeU:
    var lo, hi: Cursor
    var t = r
    t.into:
      lo = t
      skip t
      hi = t
      while t.hasMore: skip t
    g.outp.openTree LAnd
    g.outp.width wI32                       # vacuous, but every op node carries one
    g.outp.openTree Le
    g.outp.width w
    widthLit(g, w, caseValue(g, lo))
    g.outp.symUse scrutinee
    g.outp.closeTag
    g.outp.openTree Le
    g.outp.width w
    g.outp.symUse scrutinee
    widthLit(g, w, caseValue(g, hi))
    g.outp.closeTag
    g.outp.closeTag
  else:
    g.outp.openTree Eq
    g.outp.width w
    g.outp.symUse scrutinee
    widthLit(g, w, caseValue(g, r))
    g.outp.closeTag

proc genCaseBranch(g: var JsGen; w: WidthCode; scrutinee: string;
                   branches: seq[(Cursor, Cursor)]; elseBody: Cursor; i: int) =
  ## The `of` branches from `i` on, as an `if / else if / else` chain. A JS
  ## `switch` is the obvious spelling but the wrong one: its `break` would
  ## capture a `(break)` that belongs to an enclosing loop, and it cannot say
  ## `(range LO HI)` at all.
  var rs: seq[Cursor]
  var t = branches[i][0]
  t.into:
    while t.hasMore:
      rs.add t
      skip t
  if rs.len == 0: err g, "empty `ranges` in a case branch"
  g.outp.openTree If
  # `c0 || (c1 || c2)`: each `||` wraps everything to its right, so the tests
  # are emitted between the opens and the closes.
  for j in 0 ..< rs.len:
    if j < rs.len - 1:
      g.outp.openTree LOr
      g.outp.width wI32                      # vacuous, but every op node carries one
    caseRangeTest(g, w, scrutinee, rs[j])
  for j in 0 ..< rs.len - 1: g.outp.closeTag
  var body = branches[i][1]
  genStmt(g, body)
  if i + 1 < branches.len:
    g.outp.openTree Else
    genCaseBranch(g, w, scrutinee, branches, elseBody, i + 1)
    g.outp.closeTag
  elif not elseBody.cursorIsNil and elseBody.kind == TagLit:
    g.outp.openTree Else
    var eb = elseBody
    genStmt(g, eb)
    g.outp.closeTag
  g.outp.closeTag

proc genCase(g: var JsGen; c: Cursor) =
  ## `(case E (of (ranges BR+) STMTS)* (else STMTLIST)?)`. The discriminant is
  ## evaluated ONCE into a binding, because every branch tests it.
  var branches: seq[(Cursor, Cursor)]
  var elseBody: Cursor
  var scrutinee: Cursor
  var t = c
  t.into:
    scrutinee = t
    skip t
    while t.hasMore:
      if t.kind == TagLit and t.substructureKind == OfU:
        var o = t
        o.into:
          let rg = o
          skip o
          if o.kind != TagLit or o.stmtKind != StmtsS:
            err g, "case branch without a statement list"
          branches.add (rg, o)
          while o.hasMore: skip o
      elif t.kind == TagLit and t.substructureKind == ElseU:
        elseBody = t
      skip t
  if not elseBody.cursorIsNil and elseBody.kind == TagLit:
    # `(else STMTLIST)` is a SUBSTRUCTURE; the statements are its child.
    elseBody = elseBody.sub()
  let ty = lengType(g, scrutinee)
  if isAggType(g, ty): err g, "case on an aggregate discriminant"
  let w = widthOf(scalOf(g, ty))
  if branches.len == 0:
    if not elseBody.cursorIsNil and elseBody.kind == TagLit:
      var eb = elseBody
      genStmt(g, eb)
    return
  let sw = tmpName(g)
  g.outp.tree Let:
    g.outp.symDef sw
    g.genExprCoerced(scrutinee, w)
  genCaseBranch(g, w, sw, branches, elseBody, 0)


proc genIf(g: var JsGen; c: Cursor) =
  ## `(if (elif COND ACTION)* (else ACTION)?)` → a JS `if/else` chain. JS has no
  ## `elif`, so every branch after the first is `else { if … }`; `open` counts
  ## the trees still waiting for their close, which the buffer unwinds LIFO.
  var open = 0
  var seen = false
  var t = c
  t.into:
    while t.hasMore:
      let isElif = t.kind == TagLit and t.substructureKind == ElifU
      let isElse = t.kind == TagLit and t.substructureKind == ElseU
      if not isElif and not isElse: err g, "malformed `if`"
      if seen:
        g.outp.openTree Else
        inc open
      if isElif:
        g.outp.openTree If
        inc open
      var e = t
      e.into:
        if isElif:
          genExpr(g, e)                          # the condition
          skip e
        genStmt(g, e)                            # the action: one (stmts …)
      seen = true
      skip t
    while open > 0:
      g.outp.closeTag
      dec open

proc labelTargets(g: var JsGen; c: Cursor): seq[string] =
  ## The labels declared by `(lab L)` statements in THIS list and not already
  ## open. A `jmp L` may sit at any depth inside the list, so L's block has to
  ## wrap the statements that precede its own marker.
  result = @[]
  var t = c
  t.into:
    while t.hasMore:
      if t.stmtKind == LabS:
        var l = t
        l.into:
          let nm = symName(l)
          if nm notin g.p.labs: result.add nm
          while l.hasMore: skip l
      skip t

proc genStmtList(g: var JsGen; c: Cursor) =
  ## `(stmts …)` / `(scope …)`: a JS block, wrapped in one labeled block per
  ## `(lab L)` the list declares. `jmp L` lowers to `break L`, and a `break`
  ## resumes right after L's block — which is why the `(lab L)` statement itself
  ## CLOSES that block rather than the end of the list. wasm has to nest these in
  ## reverse close order because `end` is positional; a JS label is named, so
  ## ordinary order is enough.
  g.outp.openTree Block
  let mark = g.p.labs.len
  # Open in REVERSE appearance order, ithaqua's trick with its positional
  # `br`: the `(lab L)` end markers appear in appearance order, so the first
  # label must be the INNERMOST block for the closes to unwind LIFO — and it
  # is also the right region semantics, because `break L` resumes right after
  # L's block, which is L's end marker, not the end of every later label's
  # region too. A named JS break does not care which label nests inside which;
  # both stay lexically enclosing their `jmp`.
  let targets = labelTargets(g, c)
  for i in countdown(targets.len - 1, 0):
    let nm = targets[i]
    g.outp.openTree Label
    g.outp.ident jsName(g, nm)
    g.p.labs.add nm
  var t = c
  t.into:
    while t.hasMore:
      genStmt(g, t)
  # A list whose `(lab)` marker never ran into this level (a pad's label, closed
  # by an inner list) leaves nothing to close here; the `>` guard keeps that safe.
  while g.p.labs.len > mark:
    discard g.p.labs.pop()
    g.outp.closeTag
  g.outp.closeTag

proc genStmt(g: var JsGen; c: var Cursor) =
  if c.kind == DotToken:
    # `.` in a statement list means nothing goes here — `(stmts .)` is a body
    # that is empty, not a statement to lower.
    skip c
    return
  case c.stmtKind
  of StmtsS, ScopeS: genStmtList(g, c)
  of VarS: genVar(g, c)
  of AsgnS: genAsgn(g, c)
  of KeepovfS: genKeepovf(g, c)
  of RetS: genRet(g, c)
  of IfS: genIf(g, c)
  of WhileS:
    g.outp.openTree While
    var t = c
    t.into:
      genExpr(g, t)                            # the condition
      skip t
      if t.kind != TagLit or t.stmtKind != StmtsS:
        err g, "`while` without a statement list"
      genStmt(g, t)
      while t.hasMore: skip t
    g.outp.closeTag
  of BreakS:
    # An unnamed break: the innermost enclosing JS loop, which is the innermost
    # enclosing Leng loop because a `case` became an `if` chain.
    g.outp.openTree Break
    g.outp.closeTag
  of LabS:
    # The block opened for this label at the head of its list ends HERE, so a
    # `break` to it resumes at exactly this point.
    var nm = ""
    var t = c
    t.into:
      nm = symName(t)
      while t.hasMore: skip t
    if g.p.labs.len == 0 or g.p.labs[^1] != nm:
      # Closing something else would strand a block that a later `jmp` still
      # needs, so this is a shape the generator does not understand.
      err g, "`lab` `" & nm & "` is not the innermost open label (open: " & $g.p.labs & ")"
    discard g.p.labs.pop()
    g.outp.closeTag
  of JmpS:
    var nm = ""
    var t = c
    t.into:
      nm = symName(t)
      while t.hasMore: skip t
    if nm notin g.p.labs:
      err g, "`jmp` to `" & nm & "`, whose block does not enclose this point"
    g.outp.openTree Break
    g.outp.ident jsName(g, nm)
    g.outp.closeTag
  of CaseS: genCase(g, c)
  of DiscardS:
    g.outp.tree ExprStmt:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
  of CallS:
    g.outp.tree ExprStmt:
      genCall(g, c, wantValue = false)
  of InstrS:
    g.outp.tree ExprStmt:
      genInstr(g, c, wantValue = false)
  else: err g, "unsupported statement: " & $c.stmtKind
  skip c                                   # NOT `inc`: that would enter the tree

proc hasPragmaIn(pragmas: Cursor; want: LengPragma): bool =
  ## True when a `(pragmas …)` list carries `want`.
  result = false
  if pragmas.kind != TagLit: return
  var p = pragmas
  p.into:
    while p.hasMore:
      if p.kind == TagLit and p.pragmaKind == want: result = true
      skip p

proc hasPragma(decl: Cursor; want: LengPragma): bool =
  ## True when the proc's `(pragmas …)` list carries `want`.
  result = false
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # params
    skip d                                     # result type
    if d.kind == TagLit: result = hasPragmaIn(d, want)
    while d.hasMore: skip d

proc procBody(decl: Cursor): Cursor =
  ## BODY of `(proc :name PARAMS RESULT PRAGMAS BODY)` — the last child, which
  ## is robust to wherever `parsePragmas` leaves its cursor.
  var d = decl
  d.into:
    while d.hasMore:
      result = d
      skip d

proc isVoidType(t: Cursor): bool =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

proc hasBody(decl: Cursor): bool =
  ## A bodyless `importc` declaration is a signature only: its body is `(stmts .)`
  ## or absent, so nothing but DotTokens is there.
  let b = procBody(decl)
  if b.kind != TagLit: return false
  var t = b
  result = false
  t.into:
    while t.hasMore:
      if t.kind != DotToken: result = true
      skip t

proc lowerProc(g: var JsGen; sym: string; decl: Cursor) =
  if g.emitted.containsOrIncl(sym): return
  if hasPragma(decl, AssemblerP):
    # `{.assembler.}` promises a body that maps one-to-one onto machine
    # instructions in source order. There is no JavaScript that answers that
    # promise, and lowering the body as ordinary code would silently change what
    # the program does.
    err g, "`{.assembler.}` proc `" & sym & "` has no JavaScript lowering"
  if hasPragma(decl, NakedP):
    # `{.naked.}` promises the raw register ABI of a machine function. JS has no
    # registers to promise, and inventing a calling convention for it is exactly
    # the plausible-but-wrong lowering this generator refuses by rule.
    err g, "`{.naked.}` proc `" & sym & "` has no JavaScript calling convention"
  g.p = ProcCtx(jsName: jsName(g, sym),
                symType: initTable[string, Cursor](),
                locals: initTable[string, LocalSlot]())
  let body = procBody(decl)
  var importcN, exportcN = ""
  var params: seq[(string, Cursor)]
  var t = decl
  t.into:
    inc t                                      # the name
    t.into:                                    # params
      while t.hasMore:
        var pname = ""
        var ptyp: Cursor
        var q = t
        q.into:
          pname = symName(q)
          inc q
          if hasPragmaIn(q, RegisterP):
            # A pinned register is an x86 calling-convention assertion; the
            # answer to it is a machine register, not a JavaScript argument.
            err g, "`{.register.}` parameter `" & pname & "` in `" & sym & '`'
          skip q                               # pragmas
          ptyp = q
          while q.hasMore: skip q
        g.p.symType[pname] = ptyp
        params.add (pname, ptyp)
        skip t
    g.p.retType = t
    skip t
    parsePragmas(t, importcN, exportcN)
    while t.hasMore: skip t

  # An aggregate result is returned through a slot the caller reserves, so the
  # JS signature gains a hidden first parameter for it.
  g.p.sret = not g.p.retType.cursorIsNil and isAggType(g, g.p.retType)
  var taken: HashSet[string]
  if body.kind == TagLit: markTaken(body, taken)
  planFrame(g, body, params, taken)

  g.outp.openTree Func
  g.outp.symDef g.p.jsName
  g.outp.openTree Params
  if g.p.sret:
    g.p.sretName = tmpName(g)
    g.outp.symDef g.p.sretName
  for (pn, _) in params: g.outp.symDef jsName(g, pn)
  g.outp.closeTag

  if g.p.frameSize > 0:
    g.p.fp = tmpName(g)
    g.outp.tree Let:
      g.outp.symDef g.p.fp
      g.outp.openTree Call
      g.outp.symUse "frame"
      g.outp.numLit int64(g.p.frameSize)
      g.outp.closeTag
    # A scalar parameter whose address is taken arrives in a JS binding, which
    # nothing can point at: it is spilled into the slot `addr` answers with.
    for (pn, pt) in params:
      let sl = g.p.locals[pn]
      if sl.kind == lkSlot:
        g.outp.tree ExprStmt:
          g.outp.tree HStore:
            g.outp.width widthOf(scalOf(g, pt))
            slotAddr(g, sl.off)
            g.outp.symUse jsName(g, pn)

  # Scalar locals are DECLARED here, at function scope, and assigned where the
  # `(var)` statement sits. A JS `let` is block-scoped, and a `(lab)`/`jmp` pair
  # wraps a statement list in a labeled block: a `let` inside it would be out of
  # sight the moment the `break` lands. wasm locals are function-scoped, which is
  # what the shadow stack and the label blocks need.
  for nm in g.p.regLocals:
    g.outp.tree Let:
      g.outp.symDef jsName(g, nm)
      zeroLit(g, widthOf(scalOf(g, g.p.symType[nm])))
  if body.kind == TagLit:
    var b = body
    while b.hasMore: genStmt(g, b)
  leaveFrame(g)
  if g.p.sret:
    # Reached only by a body that falls off its end without a `ret`; the slot
    # is still the answer, whatever it holds.
    g.outp.tree Return: g.outp.symUse g.p.sretName
  g.outp.closeTag

proc isHostDeclaration(decl: Cursor): bool =
  ## An `importc` proc is a SIGNATURE only: the host implements it. A proc with
  ## an empty body and no import pragma is a DEFINITION that does nothing, and
  ## it must still be emitted — a call to it is a call to that empty function,
  ## not to the host.
  hasPragma(decl, ImportcP) or hasPragma(decl, ImportcppP)

proc ensureProc(g: var JsGen; sym: string; decl: Cursor) =
  ## Schedule a proc for lowering. An `importc` declaration with no body is not
  ## a definition — the host implements it — so it is never lowered, and a call
  ## to it is refused at the call site (M7 binds those through the bridge).
  if g.emitted.contains(sym): return
  for s in g.pending:
    if s[0] == sym: return
  if hasBody(decl) or not isHostDeclaration(decl): g.pending.add (sym, decl)

proc generateJs*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                 memBytes = 64 * 1024 * 1024;
                 stackBytes = ShadowStackSize): string =
  var g = createJsGen(buf, inputPath, tags)
  layoutProgram(g)
  var entryDecl: Cursor
  var haveEntry = false
  for pi in g.prog.procs:
    if pi.isEntry:
      var nc = pi.decl
      inc nc
      g.entrySym = symName(nc)
      entryDecl = pi.decl
      haveEntry = true
      break
  if not haveEntry: err g, "no entry proc (exportc \"main\") in " & inputPath
  let entryRet = procResultType(entryDecl)
  g.outp.openTree Top
  ensureProc(g, g.entrySym, entryDecl)
  # Lowering and static serialization feed each other across module
  # boundaries: a body addresses a foreign global whose initializer names a
  # proc nobody has reached yet. Run both to the fixpoint.
  var i = 0
  while true:
    while i < g.pending.len:                   # lowering discovers more procs
      let (sym, decl) = g.pending[i]
      inc i
      lowerProc(g, sym, decl)
    serializeStatics(g)
    if i >= g.pending.len: break
  g.outp.closeTag

  result = jsPreamble(memBytes, stackBytes, int g.memTop) & dataInitJs(g)
  result.add genJs(g.outp)
  result.add "FTAB[0] = () => { throw new Error(\"nil function pointer\"); };\n"
  for slot in 1 ..< g.tableEntries.len:
    let sym = g.tableEntries[slot]
    if sym.len > 0:
      result.add "FTAB[" & $slot & "] = " & jsName(g, sym) & ";\n"
    else:
      # A slot taken by a proc with no JS body fails HERE, naming itself, rather
      # than as a "not a function" TypeError at the call site.
      result.add "FTAB[" & $slot & "] = () => { throw new Error(\"unbound extern\"); };\n"
  # argc/argv/envp reach the host in M6; the exit code is main's, like native's.
  if entryRet.kind == DotToken or isVoidType(entryRet):
    result.add jsName(g, g.entrySym) & "(0, 0, 0);\n"
  else:
    result.add "nim_exit(Number(" & jsName(g, g.entrySym) & "(0, 0, 0)) | 0);\n"
