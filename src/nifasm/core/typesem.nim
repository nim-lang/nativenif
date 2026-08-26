#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF's type parser, and the foreign-symbol resolution that is inseparable
## from it.
##
## Nominal typing is what welds the two together: a `(type …)` may name a type
## defined in another module, so parsing one can pull a foreign declaration in,
## and parsing THAT declaration is more type parsing. `parseType`,
## `resolveForeignSym` and `lookupWithAutoImport` are one strongly connected
## component — nine routines that call each other in a cycle — so they are one
## module. Splitting them further is not a matter of taste; Nim has no cyclic
## imports.

import std / [tables, sets]
import nifcore, nifmodules
import "../../../../nimony/src/lib" / foreignmodules   # `hasDecl` on a lazily-opened module
import "../../../../nimony/src/lib" / symparser
import sem, context, diagnostics, cursors, modules
import tags, model, tagconv, tagpool, decls, stackslots
import "../x64/regs" as x64regs
import "../arm64/regs" as a64regs
import "../thumb/regs" as mregs
import "../x64/encoder" as x86
import "../arm64/encoder" as arm64
from "../thumb/encoder" as thumb2 import nil
  # `(clobber …)` is part of a signature, so parsing one is type parsing —
  # and it names registers of whichever target the declaration was written
  # for, which is why all three tables are in scope here and nowhere else
  # in `core`.

# Nominal typing makes these nine one cycle: a `(type …)` can name a foreign
# symbol, resolving one parses a declaration, and that is more type parsing.
# The forward block is what lets them be written in a readable order.
proc parseType*(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parsePtrType*(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseParams*(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseResult*(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseExtprocSig*(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseUnionBody*(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc resolveForeignSym*(ctx: var GenContext; modname, fullName: string;
                        scope: Scope; n: Cursor): Symbol
proc lookupWithAutoImport*(ctx: var GenContext; scope: Scope; name: string;
                           n: Cursor): Symbol

proc isRegTag*(locTag: TagEnum): bool =
  rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag)

proc parseClobbers*(n: var Cursor; a64: var set[arm64.Register];
                   m: var set[thumb2.Register]): set[x86.Register]

proc parseClobbers*(n: var Cursor; a64: var set[arm64.Register];
                   m: var set[thumb2.Register]): set[x86.Register] =
  # (clobber (rax) (rbx) ...) — or its AArch64 twin (clobber (x0) (x1) ...), or
  # Cortex-M's (clobber (r0) (r1) ...).
  #
  # A Cortex-M register tag is ALSO a valid x86-64 one (`(r0)` is an alias for
  # rax there), so such a tag is recorded in BOTH sets rather than routed by a
  # target this proc cannot see. Each arch then reads its own set, and since a
  # declaration only ever names one arch's registers the extra membership is
  # never consulted.
  if declTag(n) == ClobberD:
    loopInto n:
      if n.kind == TagLit and rawTagIsX64Reg(rawTag(n)):
        if rawTagIsMGpr(rawTag(n)): m.incl tagToRegisterM(n.tag, n)
        result.incl parseRegister(n)
      elif n.kind == TagLit and rawTagIsMGpr(rawTag(n)):
        m.incl tagToRegisterM(n.tag, n)
        skip n
      elif n.kind == TagLit and rawTagIsA64Reg(rawTag(n)):
        a64.incl tagToRegisterA64(n.tag, n)
        skip n
      else:
        error("Expected register in clobber list", n)

proc findParam*(t: Type; name: SymId): ptr Param =
  ## Find a parameter by its interned id in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.params.len:
    if t.params[i].name == name:
      return addr t.params[i]
  nil

proc findResult*(t: Type; name: SymId): ptr Param =
  ## Find a result by its interned id in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.results.len:
    if t.results[i].name == name:
      return addr t.results[i]
  nil

proc computeStackArgSize*(t: Type): int =
  ## Compute total size needed for stack arguments. Rounded up to 16 bytes so a
  ## caller can `sub sp, sp, #csize` and keep SP 16-byte aligned (required by
  ## AArch64; harmless for x86-64 where the SysV ABI also wants 16-alignment).
  assert t.kind == ProcT
  result = 0
  for param in t.params:
    if param.typ.isOnStack:
      result += stackslots.alignedSize(param.typ)
  result = (result + 15) and not 15

proc atTypeStart*(n: Cursor): bool =
  ## True if `n` is positioned at the start of a `Type` (a named-type symbol or
  ## a recognized type tag) — i.e. NOT at an Empty/pragmas slot. Used to make
  ## Leng's optional pragmas/base slots tolerant.
  n.kind == Symbol or (n.kind == TagLit and rawTagIsNifasmType(n.tag))

proc parseObjectBody*(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  # Leng `ObjDecl ::= (object [Empty | Type-base] FieldDecl*)` — the `fields`
  # iterator tolerates the optional inheritance/base slot for us.
  var flds: seq[(string, Type, int)] = @[]
  var offset = 0
  var maxAlign = 1  # Track maximum alignment requirement

  # Inheritance: a leading base-type Symbol contributes ITS fields first (at
  # their own base offsets) and its full size as the starting offset for this
  # object's own fields. This mirrors Leng's object layout — typenav.typeOfField
  # searches the base recursively for an inherited field, and nimony's sizeof
  # lays the base out before the own fields, so derived fields begin exactly at
  # `sizeof(Base)` (base tail-padding included). arkham emits the base as the
  # first child of `(object …)`; a `.`/no slot means no inheritance.
  var baseC = n                   # a copy; `n` is walked by `fields(n)` below
  into baseC:
    # `baseC.hasMore` guards an EMPTY object body `(object)` — arkham emits a baseless
    # object with no base slot (the base is only present when there IS one), so a
    # fieldless `ref object` is just `(object)` with zero children; without this guard
    # `baseC.kind` reads past the end. A 0-field object is a valid 0-byte type.
    if baseC.hasMore and baseC.kind == Symbol:
      let baseType = parseType(baseC, scope, ctx)
      if baseType.kind != ObjectT:
        error("object base type must be an object", baseC)
      flds = baseType.fields      # inherited fields keep their base offsets
      offset = baseType.size      # own fields start after the complete base
      maxAlign = baseType.align
    while baseC.hasMore: skip baseC  # drain the field children (read via `n`)

  for fc in fields(n):
    if atTag(fc, UnionTagId):
      # An object VARIANT's union part: a region of `max(branchSize)` bytes whose
      # branches overlap. Place it at the next aligned offset and rebase the union's
      # (branch-local) field offsets onto it, then advance past the whole region.
      var u = fc
      let ut = parseUnionBody(u, scope, ctx)
      offset = alignTo(offset, ut.align)
      for (fn, ft, foff) in ut.fields:
        flds.add (fn, ft, offset + foff)
      if ut.align > maxAlign: maxAlign = ut.align
      offset += ut.size
      continue
    if not atTag(fc, FldTagId): error("Expected field definition or union", fc)
    var f = fc
    # Leng `FieldDecl ::= (fld SymbolDef FieldPragmas Type)` — takeField
    # tolerates the optional field-pragmas slot before the type.
    let fr = takeField(f, atTypeStart)
    var nameC = fr.name
    if nameC.kind != SymbolDef: error("Expected field name", nameC)
    let name = symName(nameC)
    var typC = fr.typ
    let ftype = parseType(typC, scope, ctx)

    # Align field to its natural alignment, then record its offset.
    let fieldAlign = asmAlignOf(ftype)
    offset = alignTo(offset, fieldAlign)
    flds.add (name, ftype, offset)

    # Track maximum alignment for the struct
    if fieldAlign > maxAlign:
      maxAlign = fieldAlign

    # Move past this field
    offset += asmSizeOf(ftype)
  skip n # advance past the whole (object …) node

  # Round up total size to be a multiple of the struct's alignment
  let finalSize = alignTo(offset, maxAlign)
  result = Type(kind: ObjectT, fields: flds, size: finalSize, align: maxAlign)

proc allocTlsSlotX64*(ctx: var GenContext; sym: Symbol; decl: Cursor) =
  ## x86-64: give a thread-local its displacement inside the unified
  ## `arkham.tls.0` block, and record a literal initializer so `setupTls` can bake
  ## it into the block's image. The block is ordinary `.bss` and nothing runs
  ## before `main` to fill it, so an initializer that is not baked in is simply
  ## LOST — `(tvar :t . (i 64) 7)` then read 0. Three callers allocate an offset
  ## (foreign decl, main-module pre-pass, `generateSymbol`); all three come here so
  ## the initializer cannot be honoured by only some of them.
  sym.offset = ctx.tlsOffset
  ctx.tlsOffset += stackslots.alignedSize(sym.typ)
  var dn = decl
  let lc = takeLocal(dn)
  if lc.hasVal and lc.val.kind == IntLit:
    ctx.tlsInits.add (off: int64(sym.offset), val: getInt(lc.val),
                      size: asmSizeOf(sym.typ))

proc resolveForeignSym*(ctx: var GenContext; modname, fullName: string; scope: Scope; n: Cursor): Symbol =
  ## Resolve ONE foreign declaration by following its qualified name through the
  ## shared `nifmodules` loader: `getDecl` jumps to the indexed byte offset and
  ## parses just that decl (cached, its buffer kept alive in the ForeignModule),
  ## we then define it in `scope` and return it. A decl's body pulls in further
  ## declarations the same lazy way, on demand — so forward and self/mutually-
  ## recursive references resolve naturally regardless of file order (a pointer
  ## pointee stays nominal via `parsePtrType`; only a by-value reference forces a
  ## follow). `declStart` is unused for foreign symbols — generateSymbol re-reads
  ## the cached decl by name.
  let m = ctx.modules[modname]            # ref: stable across table growth
  if not hasDecl(m.foreign, fullName): return nil
  var c = getDecl(m.foreign, fullName, asmTags, ctx.pool)  # cursor at the one decl tree
  let declStartCur = c                    # the un-entered decl (a tvar reads its initializer)
  let declTag = tagToNifasmDecl(c.tag)
  case declTag
  of TypeD:
    inc c                                 # enter: type tag → name
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)                  # advance past the name
    # Define a placeholder BEFORE parsing the body so a self/mutually-recursive
    # by-value reference inside it (e.g. a proctype field whose result names this
    # very type) resolves to this symbol instead of recursing back into here. The
    # placeholder is filled in place, so the captured reference observes the
    # resolved type.
    result = Symbol(name: ctx.symIdOf(fullName), kind: skType, typ: Type(kind: ErrorT),
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
    var parsed: Type
    if c.kind == TagLit and c.tag == ObjectTagId:
      parsed = parseObjectBody(c, scope, ctx)
    elif c.kind == TagLit and c.tag == UnionTagId:
      parsed = parseUnionBody(c, scope, ctx)
    else:
      parsed = parseType(c, scope, ctx)
    result.typ[] = parsed[]
  of ProcD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
    block:
      let sig = takeSig(c)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
    result = Symbol(name: ctx.symIdOf(fullName), kind: skProc, typ: procTyp, offset: -1,
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
  of GvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: ctx.symIdOf(fullName), kind: skGvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
  of TvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: ctx.symIdOf(fullName), kind: skTvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
    # x86-64 bakes a thread-local's FS displacement at every *reference* site (no
    # relocation), so the offset must be fixed BEFORE the first reference. A
    # reference resolves the symbol through here first, so allocate the FS offset
    # eagerly now — exactly like the main-module tvar pre-pass — and mark it
    # generated so `generateSymbol` does not re-allocate (which would advance
    # `tlsOffset` twice and hand out two offsets for the same tvar). The main-module
    # pre-pass only walks the main buffer, so foreign-module tvars (e.g. the stdlib
    # allocator's thread-local `MemRegion`) would otherwise keep the default offset 0
    # until their lazy `generateSymbol`, baking offset 0 into any earlier reference
    # and the real offset into later ones — a size field then aliases what a pointer
    # field should be. (macOS/A64 relocates tvars through descriptors and allocates
    # lazily in `generateSymbol`, so leave that path untouched.)
    if ctx.arch == Arch.X64 and ctx.nameOf(result.name) notin ctx.generatedSymbols:
      allocTlsSlotX64(ctx, result, declStartCur)
      ctx.generatedSymbols.incl ctx.nameOf(result.name)
  of RodataD:
    # A foreign read-only data blob (e.g. a string literal, or a gvar with a
    # constant-scalar initializer laid out as static data — see arkham genGlobal).
    var probe = c              # the un-entered decl, for the `(reloc …)` scan below
    inc c
    if c.kind != SymbolDef: return nil
    result = Symbol(name: ctx.symIdOf(fullName), kind: skRodata, offset: -1, isForeign: true,
                    moduleName: modname)
    # A blob with symbol-pointer fields must be flagged here too — exactly as pass 1
    # flags a main-module one. Without it the Mach-O path leaves a foreign vtable in
    # read-only __TEXT, where no rebase can reach its pointer fields, so every one of
    # them reads back as 0 (a `=destroy` hook dispatched through it branches to null).
    into probe:
      skip probe               # name
      skip probe               # bytes string literal
      if probe.hasMore:        # one or more trailing (reloc ...) children
        result.dataConst = true
      while probe.hasMore: skip probe   # drain so `into` sees rem == 0
    ctx.rootScope.define(result)
  of ExtprocD:
    # A foreign module's dynamic libc extern (`(extproc :write.c.<mod> "_write")` —
    # arkham emits each used extern's decl in the module that declares the `importc`;
    # a bundle whose MAIN module has no externs of its own still reaches them here).
    # Mirrors the main-module pass-1 ExtprocD case: define the skExtProc symbol with
    # its external name and a fresh GOT slot, and register it for import binding.
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    if c.kind != StrLit: return nil
    let extName = getStr(c)
    inc c
    let libOrdinal = ctx.extprocLib(c)           # the decl's own dll operand
    let typ = parseExtprocSig(c, scope, ctx)     # the Windows form carries a signature
    let gotSlot = ctx.gotSlotCount
    ctx.gotSlotCount += 1
    result = Symbol(name: ctx.symIdOf(fullName), kind: skExtProc, typ: typ, extName: extName,
                    libName: "", gotSlot: gotSlot, isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
    ctx.extProcs.add ExtProcInfo(name: fullName, extName: extName, libOrdinal: libOrdinal,
                                 gotSlot: gotSlot, stubOffset: -1)
  of SyprocD:
    # A foreign syscall (arkham emits each used syscall's `(syproc …)` in the module
    # that declares the `importc`; another module that calls it resolves it here).
    # Mirrors `pass1Syproc`: proctype (params/result/clobber) + number in `offset`.
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
    block:
      let sig = takeSig(c)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
    let sysNr = if c.kind == IntLit: int(getInt(c)) else: 0
    result = Symbol(name: ctx.symIdOf(fullName), kind: skSysProc, typ: procTyp, offset: sysNr,
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
  else:
    return nil

proc lookupWithAutoImport*(ctx: var GenContext; scope: Scope; name: string; n: Cursor): Symbol =
  ## Lookup a symbol, lazily opening + following names into foreign modules.
  ## Also marks the symbol as used for dependency tracking.
  ##
  ## Important: Symbols with module suffixes (e.g., `foo.0.mymodule`) are distinct
  ## from local symbols (e.g., `foo.0`). When a module suffix is present, we only
  ## look in the foreign module, not in the local scope.
  let modname = extractModule(name)
  if modname != "" and modname != ctx.thisModule:
    # Foreign symbol: open the module's index, then resolve this one decl lazily
    # if it isn't already in scope. (A `…0.<thisModule>` suffix names *this*
    # module's own symbol — arkham emits self-module globals fully qualified — so
    # it must NOT be treated as foreign, which would shadow the local definition.)
    openForeignModule(ctx, modname, n)
    result = scope.lookup(ctx.symIdOf(name))
    if result == nil:
      result = resolveForeignSym(ctx, modname, name, scope, n)
  else:
    # This is a local symbol - look up in current scope
    result = scope.lookup(ctx.symIdOf(name))

  # Mark symbol as used for dependency tracking
  if result != nil:
    # Redirect a deduplicated duplicate to its CANONICAL symbol so every reference
    # shares ONE symbol — hence ONE label. A weak/COMDAT proc or data blob (e.g. an
    # enum `$`) is emitted in several modules with the same dedup key but only its
    # canonical copy's body is generated (processReachableSymbols); a reference left
    # pointing at a non-canonical duplicate's own (never-defined) label id would fail
    # linking with "Label not found". First sighting of a key becomes canonical; later
    # duplicates resolve back to it (its symbol is already in scope from that sighting).
    let resultName = ctx.nameOf(result.name)
    let dedupKey = extractDedupKey(resultName)
    if dedupKey != "" and dedupKey in ctx.dedupTable and
       ctx.dedupTable[dedupKey] != resultName:
      let canon = scope.lookup(ctx.symIdOf(ctx.dedupTable[dedupKey]))
      if canon != nil: result = canon
    # `markSymbolUsed` owns dedupTable registration + pending-queue insertion for the
    # first-seen (canonical) name; we only READ the table above to redirect duplicates.
    markSymbolUsed(ctx, resultName)

proc parsePtrType*(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## Parse the pointee of a `(ptr X)` / `(aptr X)`. A pointer is 8 bytes whatever
  ## it points at, so a bare-symbol pointee carries its qualified NAME in
  ## `baseName` — this is its nominal identity (used for strict, name-based
  ## pointer compatibility, see `compatible`) and, when the type is not yet
  ## defined, the handle for resolving it lazily on first structural access (see
  ## `resolvedBase`). An already-defined symbol also resolves `base` eagerly; a
  ## genuine forward reference (pointee declared later in the still-loading
  ## module, e.g. `(ptr Rtti)`) leaves `base` nil until forced. A structural
  ## pointee (`(ptr (i 32))`) has no name and is resolved eagerly.
  var base: Type = nil
  var baseName = ""
  if n.kind == Symbol:
    baseName = getSym(n)
    let sym = scope.lookup(getSymId(n))
    inc n
    if sym != nil and sym.kind == skType:
      base = sym.typ          # resolved eagerly, but keep baseName (nominal id)
  else:
    base = parseType(n, scope, ctx)
  # Construct with a literal discriminator (Nim can't prove a runtime one safe).
  if kind == AptrT:
    result = Type(kind: AptrT, base: base, baseName: baseName)
  else:
    result = Type(kind: PtrT, base: base, baseName: baseName)

proc resolvedBase*(t: Type; ctx: var GenContext; n: Cursor): Type =
  ## Return a pointer/aptr's pointee, resolving & memoizing a lazily-recorded
  ## forward reference (see `parsePtrType`) on first use. By the time any field
  ## or element access runs, the pointee's declaration has been parsed, so the
  ## lookup — which also auto-imports the owning module if needed — succeeds.
  if t.base == nil and t.baseName.len > 0:
    let sym = lookupWithAutoImport(ctx, ctx.scope, t.baseName, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & t.baseName, n)
    t.base = sym.typ
  result = t.base

proc parseType*(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, scope, name, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & name, n)
    result = sym.typ
    inc n
  elif n.kind == TagLit:
    let t = n.tag
    # Inline aggregate types (e.g. an array of anonymous objects, or a field
    # whose type is spelled out in place) — parseObjectBody/parseUnionBody each
    # consume the whole `(object …)`/`(union …)` tree, so return directly.
    if t == ObjectTagId:
      return parseObjectBody(n, scope, ctx)
    elif t == UnionTagId:
      return parseUnionBody(n, scope, ctx)
    var nodeEnd = n
    skip nodeEnd          # a cursor positioned just past this whole type node
    inc n
    case t
    of BoolTagId:
      result = Type(kind: BoolT)
    of NilTagId:
      result = Type(kind: NilT)
    of ITagId:
      result = Type(kind: IntT, bits: normScalarBits(getInt(n)))
      inc n
    of UTagId:
      result = Type(kind: UIntT, bits: normScalarBits(getInt(n)))
      inc n
    of FTagId:
      result = Type(kind: FloatT, bits: normScalarBits(getInt(n)))
      inc n
    of PtrTagId:
      result = parsePtrType(PtrT, n, scope, ctx)
    of AptrTagId:
      result = parsePtrType(AptrT, n, scope, ctx)
    of ArrayTagId:
      let elem = parseType(n, scope, ctx)
      let len = getInt(n)
      inc n
      result = Type(kind: ArrayT, elem: elem, len: len)
    of ProcTagId:
      # (proc (params ...) (result ...) (clobber ...))
      var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
      result = procTyp
    of CTagId:
      # Leng character type `(c N)` — an N-bit UNSIGNED integer for the machine.
      # Unsigned is not cosmetic: `intMemAccess`/`memWidthOpc` derive the extension
      # of a sub-word load from the kind, so an `IntT` char made `(mem p)` on a
      # `(ptr (c 8))` emit `movsbq` and every byte ≥ 0x80 arrived as a negative
      # number (`c shr 3` in a `set[char]` test then indexed far out of bounds).
      # The C backend agrees: `typedef unsigned char NC8`, and arkham's own
      # `isSignedType` already answers false for `CT`.
      result = Type(kind: UIntT, bits: normScalarBits(getInt(n)))
      inc n
    of VoidTagId:
      result = Type(kind: VoidT)
    of VarargsTagId:
      # `(varargs)` — a zero-size variadic marker; modeled as void.
      result = Type(kind: VoidT)
    of FlexarrayTagId:
      # `(flexarray T)` — flexible array member: a zero-length array of T.
      let elem = parseType(n, scope, ctx)
      result = Type(kind: ArrayT, elem: elem, len: 0)
    of EnumTagId:
      # `(enum BaseType EnumFieldDecl*)` — collapses to its base integer type
      # for codegen; the `efld` children are consumed by the trailing skip.
      result = parseType(n, scope, ctx)
    of ProctypeTagId:
      # `(proctype (params …) (result …)? (clobber …)?)` — a function pointer
      # (8 bytes; see `asmSizeOf`). arkham emits the full ABI signature (not an
      # opaque pointer) so an indirect `(prepare <fnptr> … (call))` resolves its
      # args/result against this, exactly like a direct call to a proc.
      var ptParams: seq[Param] = @[]
      var ptResults: seq[Param] = @[]
      var ptClobbers: set[x86.Register] = {}
      var ptClobbersA64: set[arm64.Register] = {}
      var ptClobbersM: set[thumb2.Register] = {}
      var ptHasClobberDecl = false
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; ptParams = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; ptResults = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber; ptClobbers = parseClobbers(cl, ptClobbersA64, ptClobbersM)
        ptHasClobberDecl = true
      result = Type(kind: ProcT, params: ptParams, results: ptResults, clobbers: ptClobbers,
                    clobbersA64: ptClobbersA64, hasClobberDecl: ptHasClobberDecl)
    else:
      error("Unknown type tag: " & $t, n)
    # Jump to the precomputed node end: this consumes any Leng type qualifiers we
    # don't model (IntQualifier atomic/ro, PtrQualifier atomic/ro/restrict, the
    # trailing (cppref) marker) and lands exactly past the whole type node —
    # rem-independent, unlike a `while hasMore` walk over a manually-entered node.
    n = nodeEnd
  else:
    error("Expected type", n)

proc parseUnionBody*(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## A union's members OVERLAP (max size, shared base). Leng object VARIANTS spell each
  ## branch as a nested `(object …)` whose fields are SEQUENTIAL — so a branch's fields
  ## keep their intra-branch offsets and only branches overlap. A bare `(fld …)` member
  ## (a flat union) sits at offset 0. Offsets are relative to the union's base; the
  ## enclosing `parseObjectBody` rebases them.
  var flds: seq[(string, Type, int)] = @[]
  var maxSize = 0
  var maxAlign = 1  # Track maximum alignment requirement
  var c = n
  into c:
    while c.hasMore:
      if atTag(c, ObjectTagId):                # a variant branch: sequential fields
        var b = c
        let bt = parseObjectBody(b, scope, ctx)  # 0-based branch field offsets + size
        for f in bt.fields: flds.add f
        if bt.size > maxSize: maxSize = bt.size
        if bt.align > maxAlign: maxAlign = bt.align
        skip c
      elif atTag(c, FldTagId):                 # a flat union member at offset 0
        var f = c
        let fr = takeField(f, atTypeStart)     # tolerates Leng's FieldPragmas slot
        if fr.name.kind != SymbolDef: error("Expected field name", fr.name)
        var typC = fr.typ
        let ftype = parseType(typC, scope, ctx)
        flds.add (symName(fr.name), ftype, 0)
        if asmSizeOf(ftype) > maxSize: maxSize = asmSizeOf(ftype)
        if asmAlignOf(ftype) > maxAlign: maxAlign = asmAlignOf(ftype)
        skip c
      else:
        error("union member must be an object branch or a field", c)
  skip n # advance past the whole (union …) node

  # Round up size to be a multiple of the union's alignment
  let finalSize = alignTo(maxSize, maxAlign)
  result = Type(kind: UnionT, fields: flds, size: finalSize, align: maxAlign)

proc parseParams*(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (params (param :name (reg) Type) ...)
  for pc in params(n):
    if declTag(pc) != ParamD: error("Expected param declaration", pc)
    var p = pc
    let pr = takeParam(p)
    var nameC = pr.name
    if nameC.kind != SymbolDef: error("Expected param name", nameC)
    let name = getSymId(nameC)

    # (reg) / (regs (r0) (r1) …) / (s) location
    var loc = pr.location
    var reg = InvalidTagId
    var regs: seq[TagEnum] = @[]
    var onStack = false
    var viaRegs = false
    if loc.kind == TagLit:
      let locTag = rawTag(loc)
      if rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag):
        reg = locTag
        regs = @[locTag]
      elif locTag == STagId:
        onStack = true
      elif locTag == RegsTagId:
        # An aggregate param (≤16B by-value spread over several registers, or a >16B
        # by-ref pointer in one) consumed RAW by the code generator — ABI-only, not bound.
        viaRegs = true
        var rc = loc
        into rc:
          while rc.hasMore:
            if rc.kind != TagLit or
               not (rawTagIsX64Reg(rawTag(rc)) or rawTagIsA64Reg(rawTag(rc))):
              error("expected register in (regs …)", rc)
            regs.add rawTag(rc)
            skip rc
        if regs.len == 0: error("empty (regs …)", loc)
        reg = regs[0]
      else:
        error("Expected location", loc)
    else:
      error("Expected location", loc)

    var typC = pr.typ
    var typ = parseType(typC, scope, ctx)
    if onStack:
      typ = Type(kind: StackOffT, offType: typ)
    result.add Param(name: name, typ: typ, reg: reg, regs: regs, viaRegs: viaRegs)
  skip n # advance past the whole (params …) node

proc parseResult*(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (result (ret :name (reg) Type) ...)
  if n.kind == TagLit and tagToNifasmDecl(n.tag) == ResultD:
    loopInto n:
      # An entry is either wrapped `(ret :name (reg) Type)` or the three slots
      # `:name (reg) Type` inline. Either way we consume them linearly, so the
      # loop's bound stays correct; the (elided) wrapper close needs no skip.
      if n.kind == TagLit:
        enterNode n                 # enter the (ret …) wrapper
      if n.kind != SymbolDef: error("Expected result definition", n)
      let name = getSymId(n)
      skip n
      var reg = InvalidTagId
      if n.kind == TagLit:
        let locTag = n.tag
        if isRegTag(locTag):
          reg = locTag
          skip n                    # the whole (reg) location node
        else:
          error "result must be a register", n
      else:
        error("Expected location", n)
      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg)

proc parseExtprocSig*(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## The OPTIONAL `(params …)(result …)(clobber …)` tail of an `(extproc :name "ext" …)`,
  ## advancing `n` past it. `nil` when the decl carries none.
  ##
  ## A signature turns the extern into an ordinary declarative call target: the call site
  ## binds `(arg pN)`/`(res ret.0)` and is type-checked against it, and the frame pre-scan
  ## can size the call's outgoing stack-argument area — neither of which a bare extern
  ## permits, because there is nothing to check against and no way to know how many
  ## arguments spill. The Windows backend declares one for every import (`emitWinExtproc`);
  ## the Darwin one declares none and marshals into raw ABI registers at the call site,
  ## which is why both forms have to keep working.
  let sig = takeSig(n)
  if not (sig.hasParams or sig.hasResult or sig.hasClobber): return nil
  result = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
  if sig.hasParams:
    var p = sig.params; result.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; result.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    result.clobbers = parseClobbers(cl, result.clobbersA64, result.clobbersM)
    result.hasClobberDecl = true
