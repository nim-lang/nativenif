#
#           Ithaqua — Leng → wasm32 code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## ithaqua translates Leng `.c.nif` modules into a single self-contained
## WebAssembly (wasm32) module. Unlike the native pipeline (arkham emits
## per-module typed asm-NIF, nifasm links a static image), ithaqua is
## WHOLE-PROGRAM: starting from the entry proc it pulls every reachable
## declaration — across modules, via the same lazy foreign-module loader
## arkham uses — and emits one `.wasm` binary directly. No linker exists
## in the wasm toolchain; the JS/wasm host resolves only the tiny fixed
## import set (see `HostImports`).
##
## Model:
## - wasm is a stack machine with unlimited typed locals: no register
##   allocation, no scheduling. Leng locals become wasm locals unless
##   their address is taken or they are aggregates — those live on a
##   SHADOW STACK in linear memory (mutable global `sp`, grows down).
## - All gvars live at fixed linear-memory addresses (they must be
##   addressable). `(errv)`/`(ovf)` become wasm globals (never addressed).
## - Leng control flow is already structured/forward-only: `while`/`loop`
##   are the only back edges (`loop`+`br`), `lab`/`jmp` become
##   `block`+`br` (forward), `if`/`ite` nest, `case` lowers to a chain.
## - Sub-32-bit integers hold a CANONICAL i32 form (sign-/zero-extended
##   per signedness); loads canonicalize, overflowing arithmetic
##   re-canonicalizes, so comparisons/div pick `_s`/`_u` directly.

import std / [tables, sets, assertions, strutils]
import nifcore, nifcdecl, nifcoreparse
import slots, programs, typenav
import wasmenc

const
  WasmPtrSize* = 4
  NullGuard = 1024'u32          ## linear memory below this stays unmapped-ish (null deref lands here)
  ShadowStackSize = 1 shl 20    ## 1 MiB shadow stack
  PageSize = 65536

  # Host import set — fixed and declared up front so the function index
  # space is stable before codegen discovers calls (imports come first in
  # the wasm index space). Unused imports are harmless.
  HostImports = [
    (name: "nim_write", params: @[ValI32, ValI32, ValI32], results: @[ValI32]),
    (name: "nim_exit",  params: @[ValI32], results: newSeq[byte]())]
  ImpWrite = 0'u32
  ImpExit = 1'u32

type
  MemLocal = object
    frameOff: int32              ## offset from the frame pointer local
    typ: Cursor

  RegLocal = object
    idx: uint32                  ## wasm local index
    typ: Cursor
    vt: byte

  ProcCtx = object
    locals: Table[string, RegLocal]
    memLocals: Table[string, MemLocal]
    symType: Table[string, Cursor] ## local/param name → Leng type (TypeCtx view)
    localTypes: seq[byte]        ## declared (non-param) wasm locals, in order
    nparams: int
    frameSize: int32
    fpIdx: uint32                ## local holding the frame pointer (frameSize > 0)
    scratchI32: uint32           ## reserved i32 scratch local (stores through complex lvalues)
    scratchI32b: uint32
    scratchI64: uint32
    retType: Cursor
    body: ByteBuf
    depth: int                   ## current block nesting depth inside the proc body
    labelDepth: Table[string, int] ## lab symbol → depth to `br` out of (block closes at the lab)
    loopExits: seq[int]          ## enclosing `while`/`loop` exit-block depths (`break` targets)

  WasmGen* = object
    prog*: Program
    wm*: WasmModule
    tags*: TagPool
    callTarget: Table[string, CallTarget]  ## like arkham's CodeGen (typenav view needs a mutable copy)
    globals: Table[string, Cursor]
    tvars: Table[string, Cursor]
    funcIdx: Table[string, uint32]         ## proc decl symbol → wasm function index
    funcBodies: Table[uint32, tuple[locals: seq[byte]; nparams: int; code: seq[byte]]]
    pendingProcs: seq[(string, Cursor)]    ## reachable, not yet lowered
    emitted: HashSet[string]
    nextFunc: uint32                       ## next function index (imports pre-assigned)
    typeIdxOf: Table[string, uint32]       ## rendered signature key → functype index
    memTop: uint32                         ## static-data bump pointer
    globalAddr: Table[string, uint32]
    rodataAddr: Table[string, uint32]      ## string literal → address (deduped)
    dataSegs: seq[(uint32, string)]
    tableSlot: Table[string, uint32]       ## proc symbol → funcref table slot (0 = null)
    tableEntries: seq[uint32]              ## slot i+1 → function index
    p: ProcCtx                             ## the proc being lowered
    entrySym: string

# ── small helpers ────────────────────────────────────────────────────────────

proc err(g: WasmGen; msg: string) {.noreturn.} =
  raiseAssert "ithaqua: " & msg

proc typeCtx(g: var WasmGen): TypeCtx =
  TypeCtx(prog: addr g.prog, callTarget: addr g.callTarget,
          globals: addr g.globals, tvars: addr g.tvars,
          symType: addr g.p.symType)

proc lengType(g: var WasmGen; c: Cursor): Cursor =
  getType(typeCtx(g), c)

proc typeSlot(g: var WasmGen; t: Cursor): AsmSlot =
  slotOf(g.prog, t)

type
  ScalKind = enum skI32, skI64, skF32, skF64, skMem
  Scal = object
    kind: ScalKind
    bits: int                    ## source-level width (8/16/32/64); Mem: byte size
    signed: bool

proc scalOf(g: var WasmGen; t: Cursor): Scal =
  ## The computation class of a Leng type: which wasm value type carries it
  ## and how wide/signed the SOURCE type is (for canonicalization + loads).
  let s = typeSlot(g, t)
  case s.kind
  of AFloat:
    if s.size == 4: Scal(kind: skF32, bits: 32) else: Scal(kind: skF64, bits: 64)
  of AMem: Scal(kind: skMem, bits: s.size)
  of ABool: Scal(kind: skI32, bits: 8, signed: false)
  of AInt, AUInt:
    let signed = s.kind == AInt
    if s.size == 8: Scal(kind: skI64, bits: 64, signed: signed)
    else: Scal(kind: skI32, bits: s.size * 8, signed: signed)

proc valType(sc: Scal): byte =
  case sc.kind
  of skI32: ValI32
  of skI64: ValI64
  of skF32: ValF32
  of skF64: ValF64
  of skMem: ValI32               # an address

proc valTypeOf(g: var WasmGen; t: Cursor): byte = valType(scalOf(g, t))

proc isVoidType(t: Cursor): bool =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

# ── linear memory layout ─────────────────────────────────────────────────────

proc alignUp(x: uint32; a: uint32): uint32 = (x + a - 1) and not (a - 1)

proc allocStatic(g: var WasmGen; size, align: int): uint32 =
  g.memTop = alignUp(g.memTop, uint32(max(align, 1)))
  result = g.memTop
  g.memTop += uint32(max(size, 1))

proc globalAddrOf(g: var WasmGen; name: string): uint32 =
  ## The linear-memory address of a gvar/const, assigning it on first use.
  ## Zero-initialized globals reserve address space only (wasm memory is
  ## zeroed); constant initializers become data segments at finalize.
  if g.globalAddr.hasKey(name): return g.globalAddr[name]
  let si = lookupSym(typeCtx(g), name)
  if si.cat notin {scGlobal, scTvar}:          # tvar: single-threaded target → a global
    err g, "not a global: " & name
  var d = si.decl
  var typ: Cursor
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    typ = d
    while d.hasMore: skip d
  let (sz, al) = typeSizeAlign(g.prog, typ)
  result = allocStatic(g, sz, al)
  g.globalAddr[name] = result
  if si.cat == scGlobal and not g.globals.hasKey(name):
    g.globals[name] = si.decl                  # cache foreign decls for typenav
  elif si.cat == scTvar and not g.tvars.hasKey(name):
    g.tvars[name] = si.decl

proc strLitAddr(g: var WasmGen; s: string): uint32 =
  if g.rodataAddr.hasKey(s): return g.rodataAddr[s]
  result = allocStatic(g, s.len + 1, 1)        # NUL-terminated, matching C backend strings
  g.rodataAddr[s] = result
  g.dataSegs.add (result, s & '\0')

# ── function signatures ──────────────────────────────────────────────────────

proc sigKey(params, results: seq[byte]): string =
  result = newStringOfCap(params.len + results.len + 1)
  for p in params: result.add char(p)
  result.add ':'
  for r in results: result.add char(r)

proc procSigTypes(g: var WasmGen; decl: Cursor; isProctype: bool): (seq[byte], seq[byte]) =
  ## The wasm (params, results) of a `(proc …)` decl or `(proctype …)`.
  ## Aggregate params/results are not modelled yet (assert loudly).
  var params: seq[byte] = @[]
  var results: seq[byte] = @[]
  var d = decl
  d.into:
    inc d                                      # name slot (SymbolDef or Empty)
    if d.kind == TagLit and d.typeKind == ParamsT:
      var pc = d
      pc.into:
        while pc.hasMore:
          pc.into:                             # (param :name pragmas type)
            inc pc                             # name
            skip pc                            # pragmas
            let sc = scalOf(g, pc)
            if sc.kind == skMem:
              err g, "aggregate parameters not supported yet"
            params.add valType(sc)
            while pc.hasMore: skip pc
    skip d                                     # params
    if not isVoidType(d):
      let sc = scalOf(g, d)
      if sc.kind == skMem:
        err g, "aggregate results not supported yet"
      results.add valType(sc)
    while d.hasMore: skip d
  result = (params, results)

proc funcTypeIdx(g: var WasmGen; params, results: seq[byte]): uint32 =
  let key = sigKey(params, results)
  if g.typeIdxOf.hasKey(key): return g.typeIdxOf[key]
  result = g.wm.addFuncType(params, results)
  g.typeIdxOf[key] = result

# ── proc reachability ────────────────────────────────────────────────────────

proc declareProc(g: var WasmGen; sym: string; decl: Cursor): uint32 =
  ## Assign `sym` its function index and queue its body for lowering.
  if g.funcIdx.hasKey(sym): return g.funcIdx[sym]
  result = g.nextFunc
  inc g.nextFunc
  g.funcIdx[sym] = result
  g.pendingProcs.add (sym, decl)

proc localProcDecl(g: var WasmGen; sym: string): Cursor =
  for pi in g.prog.procs:
    var nc = pi.decl
    inc nc                                     # (proc → name
    if nc.kind == SymbolDef and symName(nc) == sym:
      return pi.decl
  err g, "no local declaration for proc " & sym

proc refProc(g: var WasmGen; sym: string): uint32 =
  ## Function index of `sym`, loading a foreign module's decl if needed.
  if g.funcIdx.hasKey(sym): return g.funcIdx[sym]
  if isForeignSym(g.prog, sym):
    var found = false
    let d = lookupForeignDecl(g.prog, sym, found)
    if not found: err g, "unresolved proc " & sym
    if d.stmtKind != ProcS: err g, "call target is not a proc: " & sym
    if not g.callTarget.hasKey(sym):
      g.callTarget[sym] = foreignCallTarget(g.prog, sym)
    result = declareProc(g, sym, d)
  else:
    result = declareProc(g, sym, localProcDecl(g, sym))

proc tableSlotOf(g: var WasmGen; sym: string): uint32 =
  ## A proc used as a VALUE: its funcref-table slot (its wasm "address").
  ## Slot 0 is reserved as null so a nil fn-ptr compares/faults sanely.
  if g.tableSlot.hasKey(sym): return g.tableSlot[sym]
  let fi = refProc(g, sym)
  result = uint32(g.tableEntries.len + 1)
  g.tableSlot[sym] = result
  g.tableEntries.add fi

# ── instruction emission helpers ─────────────────────────────────────────────

template op(g: var WasmGen; o: byte) = g.p.body.add o

proc emitU32(g: var WasmGen; x: uint32) = g.p.body.addU32 x
proc constI32(g: var WasmGen; v: int32) =
  g.op OpI32Const; g.p.body.addI32 v
proc constI64(g: var WasmGen; v: int64) =
  g.op OpI64Const; g.p.body.addI64 v
proc localGet(g: var WasmGen; idx: uint32) = (g.op OpLocalGet; g.emitU32 idx)
proc localSet(g: var WasmGen; idx: uint32) = (g.op OpLocalSet; g.emitU32 idx)
proc localTee(g: var WasmGen; idx: uint32) = (g.op OpLocalTee; g.emitU32 idx)
proc globalGet(g: var WasmGen; idx: uint32) = (g.op OpGlobalGet; g.emitU32 idx)
proc globalSet(g: var WasmGen; idx: uint32) = (g.op OpGlobalSet; g.emitU32 idx)

# wasm globals (created at finalize, in this fixed order)
const
  GlobSp = 0'u32
  GlobErrv = 1'u32
  GlobOvf = 2'u32

proc memArg(g: var WasmGen; align: int) =
  ## alignment hint (log2) + offset 0 — addresses are computed explicitly.
  var a = 0
  var s = max(align, 1)
  while s > 1: (inc a; s = s shr 1)
  g.emitU32 uint32(a)
  g.emitU32 0

proc emitLoad(g: var WasmGen; sc: Scal) =
  ## Load a scalar of class `sc` from the address on the stack (canonicalizing
  ## narrow ints).
  case sc.kind
  of skF32: g.op OpF32Load; g.memArg 4
  of skF64: g.op OpF64Load; g.memArg 8
  of skI64: g.op OpI64Load; g.memArg 8
  of skI32:
    case sc.bits
    of 8:  g.op (if sc.signed: OpI32Load8S else: OpI32Load8U); g.memArg 1
    of 16: g.op (if sc.signed: OpI32Load16S else: OpI32Load16U); g.memArg 2
    else:  g.op OpI32Load; g.memArg 4
  of skMem: discard                            # aggregates are handled as addresses
proc emitStore(g: var WasmGen; sc: Scal) =
  ## Store (addr, value on stack) a scalar of class `sc`.
  case sc.kind
  of skF32: g.op OpF32Store; g.memArg 4
  of skF64: g.op OpF64Store; g.memArg 8
  of skI64: g.op OpI64Store; g.memArg 8
  of skI32:
    case sc.bits
    of 8:  g.op OpI32Store8; g.memArg 1
    of 16: g.op OpI32Store16; g.memArg 2
    else:  g.op OpI32Store; g.memArg 4
  of skMem: err g, "aggregate store must go through memory.copy"

proc canonNarrow(g: var WasmGen; sc: Scal) =
  ## Re-canonicalize a possibly-overflowed narrow i32 value in place.
  if sc.kind != skI32 or sc.bits >= 32: return
  if sc.signed:
    g.op (if sc.bits == 8: OpI32Extend8S else: OpI32Extend16S)
  else:
    g.constI32 (if sc.bits == 8: 0xFF'i32 else: 0xFFFF'i32)
    g.op OpI32And

# ── expressions ──────────────────────────────────────────────────────────────

proc genExpr(g: var WasmGen; c: Cursor)
proc genLvalAddr(g: var WasmGen; c: Cursor)
proc genStmt(g: var WasmGen; c: var Cursor)
proc genStmtList(g: var WasmGen; c: Cursor)

proc fieldOffsetIn(g: var WasmGen; objType: Cursor; field: string;
                   found: var bool): int =
  ## Byte offset of `field` inside resolved object type `objType` (own fields
  ## only; the caller walks inheritance). Mirrors `objSizeAlign`'s layout walk.
  var oc = objType
  var off = 0
  found = false
  oc.into:
    if oc.kind == Symbol:                      # inherited base occupies the front
      let (bsz, _) = typeSizeAlign(g.prog, oc)
      off = bsz
    skip oc
    while oc.hasMore:
      if oc.kind == TagLit and oc.typeKind == UnionT:
        err g, "union field offsets not supported yet"
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
        # drain the remaining fields to keep the `into` balanced
        while oc.hasMore: skip oc
        return

proc dotOffset(g: var WasmGen; baseType: Cursor; field: string; depth: int): int =
  ## Offset of `field` accessed at inheritance `depth` (0 = own object; the
  ## base subobject always sits at offset 0, so depth only picks WHICH object
  ## body declares the field).
  var t = resolveType(g.prog, baseType)
  var lvl = depth
  while true:
    if t.kind != TagLit or t.typeKind != ObjectT:
      err g, "dot into a non-object type"
    if lvl > 0:
      var oc = t
      var base: Cursor
      var hasBase = false
      oc.into:
        base = oc
        hasBase = oc.kind != DotToken
        skip oc
        while oc.hasMore: skip oc
      if not hasBase: err g, "dot inheritance depth exceeds bases"
      t = resolveType(g.prog, base)
      dec lvl
    else:
      var found = false
      let off = fieldOffsetIn(g, t, field, found)
      if found: return off
      # not declared at this level → keep walking the base chain
      var oc = t
      var base: Cursor
      var hasBase = false
      oc.into:
        base = oc
        hasBase = oc.kind != DotToken
        skip oc
        while oc.hasMore: skip oc
      if not hasBase: err g, "field not found: " & field
      t = resolveType(g.prog, base)

proc genSymValue(g: var WasmGen; c: Cursor) =
  let nm = symName(c)
  if g.p.locals.hasKey(nm):
    g.localGet g.p.locals[nm].idx
  elif g.p.memLocals.hasKey(nm):
    let ml = g.p.memLocals[nm]
    let sc = scalOf(g, ml.typ)
    g.localGet g.p.fpIdx
    if ml.frameOff != 0:
      g.constI32 ml.frameOff
      g.op OpI32Add
    if sc.kind == skMem: discard               # aggregate value = its address
    else: g.emitLoad sc
  else:
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scProc:
      g.constI32 int32(tableSlotOf(g, nm))     # proc as a value → table slot
    of scGlobal, scTvar:
      let a = globalAddrOf(g, nm)
      let t = lengType(g, c)
      let sc = scalOf(g, t)
      g.constI32 int32(a)
      if sc.kind != skMem: g.emitLoad sc
    of scNone:
      err g, "unknown symbol " & nm

proc genLvalAddr(g: var WasmGen; c: Cursor) =
  ## Push the linear-memory ADDRESS of an lvalue.
  case c.kind
  of Symbol:
    let nm = symName(c)
    if g.p.memLocals.hasKey(nm):
      let ml = g.p.memLocals[nm]
      g.localGet g.p.fpIdx
      if ml.frameOff != 0:
        g.constI32 ml.frameOff
        g.op OpI32Add
    elif g.p.locals.hasKey(nm):
      err g, "address of a register local (pre-scan should have demoted it): " & nm
    else:
      let si = lookupSym(typeCtx(g), nm)
      case si.cat
      of scGlobal, scTvar: g.constI32 int32(globalAddrOf(g, nm))
      else: err g, "cannot take address of " & nm
  of TagLit:
    case c.exprKind
    of DerefC:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
    of DotC:
      var t = c
      t.into:
        let baseT = lengType(g, t)
        genLvalAddr(g, t); skip t
        let field = symName(t); inc t
        var depth = 0
        if t.hasMore and t.kind == IntLit:
          depth = int(intVal(t))
        while t.hasMore: skip t
        let off = dotOffset(g, baseT, field, depth)
        if off != 0:
          g.constI32 int32(off)
          g.op OpI32Add
    of AtC, PatC:
      var t = c
      t.into:
        let baseT = resolveType(g.prog, lengType(g, t))
        let elemT = innerType(g.prog, baseT)
        let (esz, _) = typeSizeAlign(g.prog, elemT)
        if c.exprKind == AtC: genLvalAddr(g, t)   # array value → its address
        else: genExpr(g, t)                       # pointer value
        skip t
        # index (an i32/i64 expression; wasm32 addresses are i32)
        let idxT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, idxT).kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        if esz != 1:
          g.constI32 int32(esz)
          g.op OpI32Mul
        g.op OpI32Add
    of ErrvC, OvfC:
      err g, "errv/ovf have no address"
    else:
      err g, "not an lvalue: " & $c.exprKind
  else:
    err g, "not an lvalue"

proc litScal(g: var WasmGen; c: Cursor): Scal =
  ## The class a literal computes in, given its Leng-typed context is absent:
  ## bare literals default to the machine word (32-bit on wasm32).
  case c.kind
  of IntLit: Scal(kind: skI32, bits: 32, signed: true)
  of UIntLit: Scal(kind: skI32, bits: 32, signed: false)
  of CharLit: Scal(kind: skI32, bits: 8, signed: false)
  of FloatLit: Scal(kind: skF64, bits: 64)
  else: err g, "not a literal"

proc genSufLit(g: var WasmGen; c: Cursor) =
  ## `(suf LIT "i32")` — the suffix names the literal's type.
  var t = c
  t.into:
    let lit = t
    inc t
    let sfx = strVal(t)
    while t.hasMore: skip t
    case sfx
    of "i64", "u64":
      case lit.kind
      of IntLit: g.constI64 intVal(lit)
      of UIntLit: g.constI64 cast[int64](uintVal(lit))
      else: err g, "bad i64 literal"
    of "f32":
      g.op OpF32Const
      g.p.body.addF32 float32(floatVal(lit))
    of "f64", "f":
      g.op OpF64Const
      g.p.body.addF64 floatVal(lit)
    else:                                       # i8/i16/i32/u8/u16/u32/…
      case lit.kind
      of IntLit: g.constI32 int32(intVal(lit))
      of UIntLit: g.constI32 cast[int32](uint32(uintVal(lit) and 0xFFFFFFFF'u64))
      of CharLit: g.constI32 int32(ord(charLit(lit)))
      else: err g, "bad int literal"

type
  BinOpKind = enum boAdd, boSub, boMul, boDiv, boMod, boShl, boShr,
                   boBitand, boBitor, boBitxor

proc genBinArith(g: var WasmGen; c: Cursor; kind: BinOpKind) =
  ## `(op Type a b)` — compute in the carried type's class.
  var t = c
  t.into:
    let typ = t
    let sc = scalOf(g, typ)
    skip t
    genExpr(g, t); skip t
    genExpr(g, t)
    while t.hasMore: skip t
    case sc.kind
    of skF32, skF64:
      let base = if sc.kind == skF32: OpF32Add else: OpF64Add
      case kind
      of boAdd: g.op base
      of boSub: g.op byte(base + 1)
      of boMul: g.op byte(base + 2)
      of boDiv: g.op byte(base + 3)
      else: err g, "float op unsupported: " & $kind
    of skI32:
      case kind
      of boAdd: g.op OpI32Add
      of boSub: g.op OpI32Sub
      of boMul: g.op OpI32Mul
      of boDiv: g.op (if sc.signed: OpI32DivS else: OpI32DivU)
      of boMod: g.op (if sc.signed: OpI32RemS else: OpI32RemU)
      of boShl: g.op OpI32Shl
      of boShr: g.op (if sc.signed: OpI32ShrS else: OpI32ShrU)
      of boBitand: g.op OpI32And
      of boBitor: g.op OpI32Or
      of boBitxor: g.op OpI32Xor
      if kind in {boAdd, boSub, boMul, boShl}:
        g.canonNarrow sc
    of skI64:
      case kind
      of boAdd: g.op OpI64Add
      of boSub: g.op OpI64Sub
      of boMul: g.op OpI64Mul
      of boDiv: g.op (if sc.signed: OpI64DivS else: OpI64DivU)
      of boMod: g.op (if sc.signed: OpI64RemS else: OpI64RemU)
      of boShl: g.op OpI64Shl
      of boShr: g.op (if sc.signed: OpI64ShrS else: OpI64ShrU)
      of boBitand: g.op OpI64And
      of boBitor: g.op OpI64Or
      of boBitxor: g.op OpI64Xor
    of skMem: err g, "arithmetic on an aggregate"

proc genCompare(g: var WasmGen; c: Cursor; kind: LengExpr) =
  ## `(eq a b)` etc. — signedness comes from the OPERAND type.
  var t = c
  t.into:
    let opT = lengType(g, t)
    let sc = scalOf(g, opT)
    genExpr(g, t); skip t
    genExpr(g, t)
    while t.hasMore: skip t
    case sc.kind
    of skI32, skMem:
      case kind
      of EqC: g.op OpI32Eq
      of NeqC: g.op OpI32Ne
      of LtC: g.op (if sc.signed: OpI32LtS else: OpI32LtU)
      of LeC: g.op (if sc.signed: OpI32LeS else: OpI32LeU)
      else: err g, "bad compare"
    of skI64:
      case kind
      of EqC: g.op OpI64Eq
      of NeqC: g.op OpI64Ne
      of LtC: g.op (if sc.signed: OpI64LtS else: OpI64LtU)
      of LeC: g.op (if sc.signed: OpI64LeS else: OpI64LeU)
      else: err g, "bad compare"
    of skF32:
      case kind
      of EqC: g.op OpF32Eq
      of NeqC: g.op OpF32Ne
      of LtC: g.op OpF32Lt
      of LeC: g.op OpF32Le
      else: err g, "bad compare"
    of skF64:
      case kind
      of EqC: g.op OpF64Eq
      of NeqC: g.op OpF64Ne
      of LtC: g.op OpF64Lt
      of LeC: g.op OpF64Le
      else: err g, "bad compare"

proc genConv(g: var WasmGen; c: Cursor) =
  ## `(conv Type value)` / `(cast Type value)` — numeric/pointer conversions.
  var t = c
  t.into:
    let dstT = t
    let dst = scalOf(g, dstT)
    skip t
    let srcT = lengType(g, t)
    let src = scalOf(g, srcT)
    genExpr(g, t)
    while t.hasMore: skip t
    case dst.kind
    of skI32:
      case src.kind
      of skI32:
        if dst.bits < src.bits or (dst.bits == src.bits and dst.signed != src.signed):
          g.canonNarrow dst                    # narrow/re-sign to the target width
      of skI64: g.op OpI32WrapI64; g.canonNarrow dst
      of skF32: g.op (if dst.signed: OpI32TruncF32S else: OpI32TruncF32U)
      of skF64: g.op (if dst.signed: OpI32TruncF64S else: OpI32TruncF64U)
      of skMem: discard                        # address → integer
    of skI64:
      case src.kind
      of skI32, skMem:
        g.op (if src.signed: OpI64ExtendI32S else: OpI64ExtendI32U)
      of skI64: discard
      of skF32: g.op (if dst.signed: OpI64TruncF32S else: OpI64TruncF32U)
      of skF64: g.op (if dst.signed: OpI64TruncF64S else: OpI64TruncF64U)
    of skF32:
      case src.kind
      of skI32: g.op (if src.signed: OpF32ConvertI32S else: OpF32ConvertI32U)
      of skI64: g.op (if src.signed: OpF32ConvertI64S else: OpF32ConvertI64U)
      of skF64: g.op OpF32DemoteF64
      of skF32: discard
      of skMem: err g, "aggregate → float conversion"
    of skF64:
      case src.kind
      of skI32: g.op (if src.signed: OpF64ConvertI32S else: OpF64ConvertI32U)
      of skI64: g.op (if src.signed: OpF64ConvertI64S else: OpF64ConvertI64U)
      of skF32: g.op OpF64PromoteF32
      of skF64: discard
      of skMem: err g, "aggregate → float conversion"
    of skMem: discard                          # pointer casts are free (both i32)

proc genCallArgsAndTarget(g: var WasmGen; c: Cursor) =
  ## Emit a `(call fn args…)` (used for both statement and value position).
  var t = c
  t.into:
    let target = t
    # direct call ONLY through a symbol that names a proc declaration; a
    # proc-typed local/param/gvar/tvar is a fn-ptr VALUE → call_indirect
    let indirect = target.kind != Symbol or
                   lookupSym(typeCtx(g), symName(target)).cat != scProc
    var calleeType: Cursor
    if indirect:
      calleeType = lengType(g, target)
    skip t
    # arguments, in order
    while t.hasMore:
      genExpr(g, t)
      skip t
    if not indirect:
      let sym = symName(target)
      # lowered intrinsics (atomics/mem*/bit builtins) never reach here —
      # genCall handles them before argument emission.
      let fi = refProc(g, sym)
      g.op OpCall
      g.emitU32 fi
    else:
      genExpr(g, target)                       # the table slot (an i32)
      var pt = resolveType(g.prog, calleeType)
      if pt.kind == TagLit and pt.typeKind == PtrT:
        var inner = pt
        inc inner
        pt = resolveType(g.prog, inner)
      if pt.kind != TagLit or pt.typeKind != ProctypeT:
        err g, "indirect call through a non-proctype value"
      let (ps, rs) = procSigTypes(g, pt, isProctype = true)
      g.op OpCallIndirect
      g.emitU32 funcTypeIdx(g, ps, rs)
      g.emitU32 0                              # table 0

proc callResultType(g: var WasmGen; c: Cursor): Cursor =
  lengType(g, c)                               # typenav: return type of the callee

proc lowersInline(g: var WasmGen; c: Cursor): bool =
  ## Calls arkham classifies as atomics / mem-intrinsics / bit builtins are
  ## not real calls on wasm either. Detect them from the call target symbol.
  var t = c
  var res = false
  t.into:
    if t.kind == Symbol:
      let nm = symName(t)
      if not g.callTarget.hasKey(nm) and isForeignSym(g.prog, nm):
        # only classify actual proc decls — a foreign GVAR call target is a
        # fn-ptr (indirect call), and foreignCallTarget would misparse it
        var found = false
        let d = lookupForeignDecl(g.prog, nm, found)
        if found and d.stmtKind == ProcS:
          g.callTarget[nm] = foreignCallTarget(g.prog, nm)
      if g.callTarget.hasKey(nm):
        let ct = g.callTarget[nm]
        res = ct.atomic.len > 0 or ct.memIntrin.len > 0 or
              ct.bitBuiltin.len > 0 or ct.syscall
    while t.hasMore: skip t
  result = res

proc genInlineCall(g: var WasmGen; c: Cursor; wantValue: bool) =
  ## Lower an intrinsic call: single-threaded atomics become plain memory
  ## ops; memcpy/memmove/memset become bulk-memory instructions; syscalls
  ## map onto the host import set (write/exit) or trap.
  var t = c
  t.into:
    let nm = symName(t)
    let ct = g.callTarget[nm]
    skip t
    if ct.memIntrin.len > 0:
      case ct.memIntrin
      of "memcpy", "memmove":
        # (dst, src, n) → memory.copy; both intrinsics: memory.copy is overlap-safe
        genExpr(g, t); skip t                  # dst
        genExpr(g, t); skip t                  # src
        let nT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, nT).kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
        if wantValue: err g, "memcpy result value not modelled"
      of "memset":
        genExpr(g, t); skip t                  # dst
        let vT = lengType(g, t)
        genExpr(g, t)                          # value
        if scalOf(g, vT).kind == skI64: g.op OpI32WrapI64
        skip t
        let nT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, nT).kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op 0xFC'u8; g.emitU32 11; g.emitU32 0                # memory.fill
        if wantValue: err g, "memset result value not modelled"
      else:
        err g, "mem intrinsic not supported yet: " & ct.memIntrin
    elif ct.atomic.len > 0:
      # Single-threaded target: __atomic_* collapse to plain operations.
      case ct.atomic
      of "__atomic_load_n":
        let retT = callResultType(g, c)
        genExpr(g, t); skip t                  # the pointer
        while t.hasMore: skip t                # memorder
        g.emitLoad scalOf(g, retT)
      of "__atomic_store_n":
        var pT = lengType(g, t)
        genExpr(g, t); skip t                  # pointer
        let valT = lengType(g, t)
        genExpr(g, t); skip t                  # value
        while t.hasMore: skip t
        discard pT
        g.emitStore scalOf(g, valT)
      of "__atomic_add_fetch", "__atomic_sub_fetch":
        # fetch-op returning the NEW value; single-threaded → load, op, store,
        # reload via scratch local.
        let valT = callResultType(g, c)
        let sc = scalOf(g, valT)
        genExpr(g, t); skip t                  # pointer
        g.localTee g.p.scratchI32              # keep the address
        g.emitLoad sc
        let deltaT = lengType(g, t)
        genExpr(g, t); skip t
        discard deltaT
        while t.hasMore: skip t
        case sc.kind
        of skI64:
          g.op (if ct.atomic == "__atomic_add_fetch": OpI64Add else: OpI64Sub)
          g.localSet g.p.scratchI64
          g.localGet g.p.scratchI32
          g.localGet g.p.scratchI64
          g.emitStore sc
          if wantValue: g.localGet g.p.scratchI64
        else:
          g.op (if ct.atomic == "__atomic_add_fetch": OpI32Add else: OpI32Sub)
          g.canonNarrow sc
          g.localSet g.p.scratchI32b
          g.localGet g.p.scratchI32
          g.localGet g.p.scratchI32b
          g.emitStore sc
          if wantValue: g.localGet g.p.scratchI32b
      else:
        err g, "atomic not supported yet: " & ct.atomic
    elif ct.bitBuiltin.len > 0:
      case ct.bitBuiltin
      of "__builtin_ctz":  genExpr(g, t); g.op OpI32Ctz
      of "__builtin_clz":  genExpr(g, t); g.op OpI32Clz
      of "__builtin_popcount": genExpr(g, t); g.op OpI32Popcnt
      of "__builtin_ctzll":  genExpr(g, t); g.op OpI64Ctz; g.op OpI32WrapI64
      of "__builtin_clzll":  genExpr(g, t); g.op OpI64Clz; g.op OpI32WrapI64
      of "__builtin_popcountll": genExpr(g, t); g.op OpI64Popcnt; g.op OpI32WrapI64
      else: err g, "bit builtin not supported yet: " & ct.bitBuiltin
      skip t
      while t.hasMore: skip t
    elif ct.syscall:
      # The WW3 runtime floor: write goes to the host, exit traps the
      # instance. Everything else traps loudly.
      var base = nm
      # the syscall's C name is encoded in the target's asmName "<c>.sys.<mod>"
      let dotSys = ct.asmName.find(".sys.")
      if dotSys >= 0: base = ct.asmName[0 ..< dotSys]
      case base
      of "write":
        let fdT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, fdT).kind == skI64: g.op OpI32WrapI64
        skip t
        genExpr(g, t); skip t                  # buf (a pointer)
        let nT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, nT).kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op OpCall; g.emitU32 ImpWrite
        let retT = callResultType(g, c)
        if scalOf(g, retT).kind == skI64: g.op OpI64ExtendI32S
        if not wantValue:
          g.op OpDrop
      of "exit", "exit_group", "_exit":
        let cT = lengType(g, t)
        genExpr(g, t)
        if scalOf(g, cT).kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op OpCall; g.emitU32 ImpExit
        g.op OpUnreachable                     # exit does not return
      else:
        while t.hasMore: skip t
        g.op OpUnreachable                     # unsupported syscall: trap loudly
    else:
      err g, "genInlineCall on a plain call"

proc genCall(g: var WasmGen; c: Cursor; wantValue: bool) =
  if lowersInline(g, c):
    genInlineCall(g, c, wantValue)
    return
  genCallArgsAndTarget(g, c)
  let retT = callResultType(g, c)
  if not isVoidType(retT) and not wantValue:
    g.op OpDrop

proc genExpr(g: var WasmGen; c: Cursor) =
  case c.kind
  of Symbol: genSymValue(g, c)
  of IntLit: g.constI32 int32(intVal(c))
  of UIntLit: g.constI32 cast[int32](uint32(uintVal(c) and 0xFFFFFFFF'u64))
  of CharLit: g.constI32 int32(ord(charLit(c)))
  of FloatLit:
    g.op OpF64Const
    g.p.body.addF64 floatVal(c)
  of StrLit:
    g.constI32 int32(strLitAddr(g, strVal(c)))
  of TagLit:
    case c.exprKind
    of SufC: genSufLit(g, c)
    of ParC:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
    of TrueC: g.constI32 1
    of FalseC: g.constI32 0
    of NilC: g.constI32 0
    of ErrvC: g.globalGet GlobErrv
    of OvfC: g.globalGet GlobOvf
    of AddC: genBinArith(g, c, boAdd)
    of SubC: genBinArith(g, c, boSub)
    of MulC: genBinArith(g, c, boMul)
    of DivC: genBinArith(g, c, boDiv)
    of ModC: genBinArith(g, c, boMod)
    of ShlC: genBinArith(g, c, boShl)
    of ShrC: genBinArith(g, c, boShr)
    of BitandC: genBinArith(g, c, boBitand)
    of BitorC: genBinArith(g, c, boBitor)
    of BitxorC: genBinArith(g, c, boBitxor)
    of NegC:
      var t = c
      t.into:
        let sc = scalOf(g, t)
        skip t
        case sc.kind
        of skF32: genExpr(g, t); g.op OpF32Neg
        of skF64: genExpr(g, t); g.op OpF64Neg
        of skI64:
          g.constI64 0
          genExpr(g, t)
          g.op OpI64Sub
        else:
          g.constI32 0
          genExpr(g, t)
          g.op OpI32Sub
          g.canonNarrow sc
        while t.hasMore: skip t
    of BitnotC:
      var t = c
      t.into:
        let sc = scalOf(g, t)
        skip t
        genExpr(g, t)
        while t.hasMore: skip t
        if sc.kind == skI64:
          g.constI64 -1
          g.op OpI64Xor
        else:
          g.constI32 -1
          g.op OpI32Xor
          g.canonNarrow sc
    of EqC, NeqC, LtC, LeC: genCompare(g, c, c.exprKind)
    of NotC:
      var t = c
      t.into:
        # `(not (lab) flag)` NJ-annotates the last vflag use — not expected in
        # classic Leng output; assert if it shows up.
        if t.kind == TagLit and t.exprKind notin {NoExpr}:
          discard
        genExpr(g, t)
        while t.hasMore: skip t
      g.op OpI32Eqz
    of AndC:
      # C's `&&`: short-circuit via a result-carrying `if`.
      var t = c
      t.into:
        genExpr(g, t); skip t
        g.op OpIf; g.p.body.add ValI32
        genExpr(g, t)
        g.op OpI32Eqz; g.op OpI32Eqz           # normalize to 0/1
        g.op OpElse
        g.constI32 0
        g.op OpEnd
        while t.hasMore: skip t
    of OrC:
      var t = c
      t.into:
        genExpr(g, t); skip t
        g.op OpIf; g.p.body.add ValI32
        g.constI32 1
        g.op OpElse
        genExpr(g, t)
        g.op OpI32Eqz; g.op OpI32Eqz
        g.op OpEnd
        while t.hasMore: skip t
    of AddrC:
      var t = c
      t.into:
        genLvalAddr(g, t)
        while t.hasMore: skip t
    of DerefC:
      let t = lengType(g, c)
      let sc = scalOf(g, t)
      genLvalAddr(g, c)
      if sc.kind != skMem: g.emitLoad sc
    of DotC, AtC, PatC:
      let t = lengType(g, c)
      let sc = scalOf(g, t)
      genLvalAddr(g, c)
      if sc.kind != skMem: g.emitLoad sc
    of ConvC, CastC: genConv(g, c)
    of CallC: genCall(g, c, wantValue = true)
    of SizeofC:
      var t = c
      t.into:
        let (sz, _) = typeSizeAlign(g.prog, t)
        g.constI32 int32(sz)
        while t.hasMore: skip t
    of AlignofC:
      var t = c
      t.into:
        let (_, al) = typeSizeAlign(g.prog, t)
        g.constI32 int32(al)
        while t.hasMore: skip t
    of InfC:
      g.op OpF64Const; g.p.body.addF64 Inf
    of NeginfC:
      g.op OpF64Const; g.p.body.addF64 NegInf
    of NanC:
      g.op OpF64Const; g.p.body.addF64 NaN
    of BaseobjC:
      # base-object view of a derived object: same address
      var t = c
      t.into:
        skip t                                 # base type
        if t.kind == IntLit: inc t             # depth
        genExpr(g, t)
        while t.hasMore: skip t
    else:
      err g, "expression not supported yet: " & $c.exprKind
  else:
    err g, "unexpected token in expression"

# ── statements ───────────────────────────────────────────────────────────────

proc genAsgn(g: var WasmGen; lhs, rhs: Cursor) =
  # errv/ovf as destinations → wasm globals
  if lhs.kind == TagLit and lhs.exprKind == ErrvC:
    genExpr(g, rhs)
    g.globalSet GlobErrv
    return
  if lhs.kind == TagLit and lhs.exprKind == OvfC:
    genExpr(g, rhs)
    g.globalSet GlobOvf
    return
  if lhs.kind == Symbol:
    let nm = symName(lhs)
    if g.p.locals.hasKey(nm):
      genExpr(g, rhs)
      g.localSet g.p.locals[nm].idx
      return
  # memory destination
  let lhsT = lengType(g, lhs)
  let sc = scalOf(g, lhsT)
  if sc.kind == skMem:
    genLvalAddr(g, lhs)                        # dst
    genExpr(g, rhs)                            # src address (aggregates are addresses)
    g.constI32 int32(sc.bits)                  # byte size
    g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
  else:
    genLvalAddr(g, lhs)
    genExpr(g, rhs)
    g.emitStore sc

proc genIf(g: var WasmGen; c: Cursor) =
  ## `(if (elif cond stmts)+ (else stmts)?)` → nested if/else: each elif
  ## opens ONE wasm `if` (closed at the end), later branches nest in its
  ## else arm.
  var t = c
  var nIfs = 0
  t.into:
    while t.hasMore:
      case t.substructureKind
      of ElifU:
        var e = t
        e.into:
          genExpr(g, e); skip e
          g.op OpIf; g.p.body.add BlockVoid
          inc g.p.depth
          inc nIfs
          genStmtList(g, e); skip e
          while e.hasMore: skip e
        skip t
        if t.hasMore:
          g.op OpElse                          # the next elif/else nests here
      of ElseU:
        var e = t
        e.into:
          genStmtList(g, e); skip e
          while e.hasMore: skip e
        skip t
      else:
        err g, "unexpected if branch"
  while nIfs > 0:
    g.op OpEnd
    dec g.p.depth
    dec nIfs

proc genWhile(g: var WasmGen; c: Cursor) =
  ## `(while cond body)` →
  ## block { loop { cond eqz br_if 1; body; br 0 } }
  var t = c
  t.into:
    g.op OpBlock; g.p.body.add BlockVoid       # exit block
    inc g.p.depth
    let exitDepth = g.p.depth
    g.op OpLoop; g.p.body.add BlockVoid
    inc g.p.depth
    g.p.loopExits.add exitDepth
    genExpr(g, t); skip t
    g.op OpI32Eqz
    g.op OpBrIf; g.emitU32 1                   # → exit block
    genStmtList(g, t); skip t
    while t.hasMore: skip t
    g.op OpBr; g.emitU32 0                     # back edge
    g.op OpEnd                                 # loop
    dec g.p.depth
    g.op OpEnd                                 # block
    dec g.p.depth
    discard g.p.loopExits.pop()

proc genLoop(g: var WasmGen; c: Cursor) =
  ## `(loop pre cond body)` (spec) / 4-slot NJ form (pre, cond, body, after) →
  ## block { loop { pre; cond eqz br_if 1; body; br 0 } } after?
  var t = c
  t.into:
    g.op OpBlock; g.p.body.add BlockVoid
    inc g.p.depth
    let exitDepth = g.p.depth
    g.op OpLoop; g.p.body.add BlockVoid
    inc g.p.depth
    g.p.loopExits.add exitDepth
    genStmtList(g, t); skip t                  # pre-condition block
    genExpr(g, t); skip t                      # condition
    g.op OpI32Eqz
    g.op OpBrIf; g.emitU32 1
    genStmtList(g, t); skip t                  # body
    g.op OpBr; g.emitU32 0
    g.op OpEnd
    dec g.p.depth
    g.op OpEnd
    dec g.p.depth
    discard g.p.loopExits.pop()
    if t.hasMore:                              # optional `after` part
      genStmtList(g, t); skip t
    while t.hasMore: skip t

proc genCase(g: var WasmGen; c: Cursor) =
  ## `(case sel (of (ranges …) stmts)* (else stmts)?)` — lowered to a chain of
  ## range tests (br_table is a later optimization). The selector is evaluated
  ## once into a scratch local.
  var t = c
  t.into:
    let selT = lengType(g, t)
    let sc = scalOf(g, selT)
    let is64 = sc.kind == skI64
    genExpr(g, t); skip t
    let selLocal = if is64: g.p.scratchI64 else: g.p.scratchI32
    g.localSet selLocal
    var nIfs = 0
    while t.hasMore:
      case t.substructureKind
      of OfU:
        var branch = t
        branch.into:
          # (ranges BranchRange+)
          var cond = 0
          var r = branch
          r.into:
            while r.hasMore:
              # each range test ORs into the condition
              if r.kind == TagLit and r.substructureKind == RangeU:
                var rr = r
                rr.into:
                  g.localGet selLocal
                  genExpr(g, rr); skip rr
                  g.op (if is64: (if sc.signed: OpI64GeS else: OpI64GeU)
                        else: (if sc.signed: OpI32GeS else: OpI32GeU))
                  g.localGet selLocal
                  genExpr(g, rr)
                  while rr.hasMore: skip rr
                  g.op (if is64: (if sc.signed: OpI64LeS else: OpI64LeU)
                        else: (if sc.signed: OpI32LeS else: OpI32LeU))
                  g.op OpI32And
              else:
                g.localGet selLocal
                genExpr(g, r)
                g.op (if is64: OpI64Eq else: OpI32Eq)
              inc cond
              if cond > 1: g.op OpI32Or
              skip r
          skip branch                          # past (ranges …)
          g.op OpIf; g.p.body.add BlockVoid
          inc g.p.depth
          inc nIfs
          genStmtList(g, branch); skip branch
          while branch.hasMore: skip branch
        skip t
        if t.hasMore:
          g.op OpElse                          # the next of/else nests here
      of ElseU:
        var e = t
        e.into:
          genStmtList(g, e); skip e
          while e.hasMore: skip e
        skip t
      else:
        err g, "unexpected case branch"
    while nIfs > 0:
      g.op OpEnd
      dec g.p.depth
      dec nIfs

proc genRet(g: var WasmGen; c: Cursor) =
  var t = c
  t.into:
    if t.hasMore and not (t.kind == DotToken):
      genExpr(g, t)
      skip t
    while t.hasMore: skip t
  if g.p.frameSize > 0:
    g.localGet g.p.fpIdx
    g.constI32 g.p.frameSize
    g.op OpI32Add
    g.globalSet GlobSp
  g.op OpReturn

proc genOnerr(g: var WasmGen; c: Cursor) =
  ## `(onerr action fn args…)`: perform the call; if `(errv)` is set, run the
  ## action (typically a `jmp`). A `.` action means "propagate by hand later".
  var t = c
  t.into:
    let action = t
    skip t
    # rebuild a call cursor view: fn + args follow
    # We lower the call inline here (mirrors genCall but from the second child).
    let target = t
    let indirect = target.kind != Symbol or
                   lookupSym(typeCtx(g), symName(target)).cat != scProc
    var calleeType: Cursor
    if indirect: calleeType = lengType(g, target)
    skip t
    while t.hasMore:
      genExpr(g, t)
      skip t
    var retT: Cursor
    if not indirect:
      let sym = symName(target)
      let fi = refProc(g, sym)
      # result type = callee's return type
      var found = false
      var d: Cursor
      if g.callTarget.hasKey(sym) and not cursorIsNil(g.callTarget[sym].retType):
        retT = g.callTarget[sym].retType
        found = true
      if not found:
        d = localProcDecl(g, sym)
        var dd = d
        dd.into:
          inc dd; skip dd
          retT = dd
          while dd.hasMore: skip dd
      g.op OpCall
      g.emitU32 fi
    else:
      genExpr(g, target)
      var pt = resolveType(g.prog, calleeType)
      if pt.kind == TagLit and pt.typeKind == PtrT:
        var inner = pt; inc inner
        pt = resolveType(g.prog, inner)
      let (ps, rs) = procSigTypes(g, pt, isProctype = true)
      g.op OpCallIndirect
      g.emitU32 funcTypeIdx(g, ps, rs)
      g.emitU32 0
      var q = pt
      q.into:
        skip q; skip q
        retT = q
        while q.hasMore: skip q
    if not cursorIsNil(retT) and not isVoidType(retT):
      g.op OpDrop                              # onerr calls discard their value
    # if errv: run the action
    if not (action.kind == DotToken):
      g.globalGet GlobErrv
      g.op OpIf; g.p.body.add BlockVoid
      inc g.p.depth
      var a = action
      genStmt(g, a)
      g.op OpEnd
      dec g.p.depth

proc genVarDecl(g: var WasmGen; c: Cursor) =
  var t = c
  t.into:
    let nm = symName(t); inc t
    skip t                                     # pragmas
    let typ = t
    skip t
    var hasInit = t.hasMore and t.kind != DotToken
    if g.p.memLocals.hasKey(nm):
      if hasInit:
        let sc = scalOf(g, typ)
        if sc.kind == skMem:
          # aggregate initializer: oconstr/aconstr or copy from another aggregate
          err g, "aggregate local initializers not supported yet"
        let ml = g.p.memLocals[nm]
        g.localGet g.p.fpIdx
        if ml.frameOff != 0:
          g.constI32 ml.frameOff
          g.op OpI32Add
        genExpr(g, t)
        g.emitStore sc
    else:
      if hasInit:
        genExpr(g, t)
        g.localSet g.p.locals[nm].idx
      # else: wasm locals are zero-initialized — matches Leng's default init
    while t.hasMore: skip t

proc genStmt(g: var WasmGen; c: var Cursor) =
  case c.stmtKind
  of InstrS:
    # (instr …) — a native instruction row. The pinned and flags/two-address
    # rows have no wasm equivalent (no flags, no register ties); the portable
    # rows (ctz/clz/popcount/bswap) are not lowered here yet. Flag loudly
    # rather than miscompile.
    err g, "(instr …) native instruction intrinsics are not supported on wasm32"
  of StmtsS, ScopeS:
    genStmtList(g, c)
    skip c
  of VarS:
    genVarDecl(g, c)
    skip c
  of ConstS:
    # local consts were folded by hexer; a named const at proc level acts as
    # a global (address on demand)
    skip c
  of AsgnS:
    var t = c
    t.into:
      let lhs = t
      skip t
      genAsgn(g, lhs, t)
      skip t
      while t.hasMore: skip t
    skip c
  of StoreS:
    # (store value lvalue) — asgn with reversed operands. Wasm needs the
    # address BEFORE the value, so stash the value in a scratch local.
    var t = c
    t.into:
      let rhs = t
      skip t
      let lhs = t
      # evaluation order: value first (matches textual order)
      let lhsT = lengType(g, lhs)
      let sc = scalOf(g, lhsT)
      if sc.kind == skMem:
        genLvalAddr(g, lhs)
        genExpr(g, rhs)                        # order swap acceptable for aggregates? keep strict:
        err g, "aggregate (store) not supported yet"
      else:
        genExpr(g, rhs)
        case valType(sc)
        of ValI64:
          g.localSet g.p.scratchI64
          genLvalAddr(g, lhs)
          g.localGet g.p.scratchI64
        of ValI32:
          g.localSet g.p.scratchI32
          genLvalAddr(g, lhs)
          g.localGet g.p.scratchI32
        else:
          err g, "float (store) not supported yet"
        g.emitStore sc
      skip t
      while t.hasMore: skip t
    skip c
  of CallS:
    genCall(g, c, wantValue = false)
    skip c
  of OnerrS:
    genOnerr(g, c)
    skip c
  of IfS:
    genIf(g, c)
    skip c
  of WhileS:
    genWhile(g, c)
    skip c
  of LoopS:
    genLoop(g, c)
    skip c
  of CaseS:
    genCase(g, c)
    skip c
  of BreakS:
    if g.p.loopExits.len == 0: err g, "break outside a loop"
    g.op OpBr
    g.emitU32 uint32(g.p.depth - g.p.loopExits[^1])
    skip c
  of LabS:
    var t = c
    t.into:
      let nm = symName(t)
      while t.hasMore: skip t
      if not g.p.labelDepth.hasKey(nm):
        err g, "lab without a pre-scanned block: " & nm
      g.op OpEnd                               # the block opened for this label ends here
      dec g.p.depth
      g.p.labelDepth.del nm
    skip c
  of JmpS:
    var t = c
    t.into:
      let nm = symName(t)
      while t.hasMore: skip t
      if not g.p.labelDepth.hasKey(nm):
        err g, "jmp to an unscanned label: " & nm
      g.op OpBr
      g.emitU32 uint32(g.p.depth - g.p.labelDepth[nm])
    skip c
  of RetS:
    genRet(g, c)
    skip c
  of DiscardS:
    var t = c
    t.into:
      if t.hasMore and t.kind != DotToken:
        let vT = lengType(g, t)
        genExpr(g, t)
        if not isVoidType(vT):
          g.op OpDrop
        skip t
      while t.hasMore: skip t
    skip c
  of KeepovfS:
    err g, "keepovf not implemented yet (WW2 scope: unchecked arithmetic)"
  of EmitS:
    err g, "(emit) has no wasm lowering"
  of TryS, RaiseS:
    err g, "C++-mode try/raise cannot appear in wasm Leng"
  of IteS, ItecS, JtrueS, MflagS, VflagS:
    err g, "NJ instruction reached the backend: " & $c.stmtKind &
           " (run the Final IR pass first)"
  of GvarS, TvarS, ProcS, TypeS:
    skip c                                     # module-level decls inside a body: skip
  of NoStmt:
    if c.kind == DotToken:
      inc c
    else:
      err g, "unknown statement"

proc genStmtList(g: var WasmGen; c: Cursor) =
  ## Lower a `(stmts …)` list. Every `(lab L)` at THIS level gets a wasm
  ## `block` opened at the head of the list (nested in reverse appearance
  ## order, so the first label closes innermost) — a forward `jmp L` from
  ## anywhere inside then `br`s to it.
  var labs: seq[string] = @[]
  var scan = c
  scan.into:
    while scan.hasMore:
      if scan.stmtKind == LabS:
        var t = scan
        t.into:
          labs.add symName(t)
          while t.hasMore: skip t
      skip scan
  for i in countdown(labs.len - 1, 0):
    g.op OpBlock; g.p.body.add BlockVoid
    inc g.p.depth
    g.p.labelDepth[labs[i]] = g.p.depth
  var t = c
  t.into:
    while t.hasMore:
      genStmt(g, t)

# ── proc lowering ────────────────────────────────────────────────────────────

proc scanAddrTaken(c: Cursor; taken: var HashSet[string]) =
  ## Which symbols appear under `(addr …)` in this proc body.
  if c.kind != TagLit: return
  if c.exprKind == AddrC:
    var inner = c
    inc inner                                  # into the (addr …) → the lvalue
    # the addressed ROOT symbol: peel dot/at/pat chains
    while inner.kind == TagLit and inner.exprKind in {DotC, AtC, PatC}:
      inc inner                                # into the chain → base
    if inner.kind == Symbol:
      taken.incl symName(inner)
  var t = c
  t.into:
    while t.hasMore:
      scanAddrTaken(t, taken)
      skip t

proc scanLocals(g: var WasmGen; c: Cursor; taken: HashSet[string];
                frameOff: var int32) =
  ## Register every `(var …)` declaration in the body: a wasm local, or a
  ## shadow-stack slot when address-taken or aggregate.
  if c.kind != TagLit: return
  if c.stmtKind == VarS:
    var t = c
    t.into:
      let nm = symName(t); inc t
      skip t                                   # pragmas
      let typ = t
      let sc = scalOf(g, typ)
      g.p.symType[nm] = typ
      if sc.kind == skMem or nm in taken:
        let (sz, al) = typeSizeAlign(g.prog, typ)
        frameOff = int32(align(int(frameOff), max(al, 1)))
        g.p.memLocals[nm] = MemLocal(frameOff: frameOff, typ: typ)
        frameOff += int32(max(sz, 1))
      else:
        let idx = uint32(g.p.nparams + g.p.localTypes.len)
        g.p.locals[nm] = RegLocal(idx: idx, typ: typ, vt: valType(sc))
        g.p.localTypes.add valType(sc)
      while t.hasMore: skip t
    return                                     # a var's init expr declares nothing
  var t = c
  t.into:
    while t.hasMore:
      scanLocals(g, t, taken, frameOff)
      skip t

proc lowerProc(g: var WasmGen; sym: string; decl: Cursor) =
  var params: seq[(string, Cursor)] = @[]
  var retType: Cursor
  var body: Cursor
  var hasBody = false
  var d = decl
  d.into:
    inc d                                      # name
    if d.kind == TagLit and d.typeKind == ParamsT:
      var pc = d
      pc.into:
        while pc.hasMore:
          pc.into:
            let pn = symName(pc); inc pc
            skip pc                            # pragmas
            params.add (pn, pc)
            skip pc
            while pc.hasMore: skip pc
    skip d                                     # params
    retType = d
    skip d                                     # return type
    skip d                                     # pragmas
    if d.hasMore and d.kind != DotToken:
      body = d
      hasBody = true
    while d.hasMore: skip d
  if not hasBody:
    err g, "no body for reachable proc " & sym & " (importc without lowering?)"

  # fresh per-proc state
  g.p = ProcCtx(retType: retType, nparams: params.len)

  # address-taken analysis over the body
  var taken = initHashSet[string]()
  scanAddrTaken(body, taken)

  # params: wasm params are locals 0..n-1; an address-taken param is copied
  # into a frame slot at entry
  var frameOff = 0'i32
  var paramCopies: seq[(uint32, string)] = @[]
  for i, (pn, pt) in params:
    let sc = scalOf(g, pt)
    if sc.kind == skMem:
      err g, "aggregate parameter reached lowering: " & pn
    g.p.symType[pn] = pt
    if pn in taken:
      let (sz, al) = typeSizeAlign(g.prog, pt)
      frameOff = int32(align(int(frameOff), max(al, 1)))
      g.p.memLocals[pn] = MemLocal(frameOff: frameOff, typ: pt)
      paramCopies.add (uint32(i), pn)
      frameOff += int32(max(sz, 1))
    else:
      g.p.locals[pn] = RegLocal(idx: uint32(i), typ: pt, vt: valType(sc))

  # locals: walk the body for (var …) decls (any nesting level)
  scanLocals(g, body, taken, frameOff)

  # scratch + frame-pointer locals (always declared; cheap)
  g.p.scratchI32 = uint32(params.len + g.p.localTypes.len)
  g.p.localTypes.add ValI32
  g.p.scratchI32b = uint32(params.len + g.p.localTypes.len)
  g.p.localTypes.add ValI32
  g.p.scratchI64 = uint32(params.len + g.p.localTypes.len)
  g.p.localTypes.add ValI64
  g.p.frameSize = int32(align(int(frameOff), 16))
  if g.p.frameSize > 0:
    g.p.fpIdx = uint32(params.len + g.p.localTypes.len)
    g.p.localTypes.add ValI32
    # prologue: sp -= frame; fp = sp
    g.globalGet GlobSp
    g.constI32 g.p.frameSize
    g.op OpI32Sub
    g.localTee g.p.fpIdx
    g.globalSet GlobSp
    for (pidx, pn) in paramCopies:
      let ml = g.p.memLocals[pn]
      g.localGet g.p.fpIdx
      if ml.frameOff != 0:
        g.constI32 ml.frameOff
        g.op OpI32Add
      g.localGet pidx
      g.emitStore scalOf(g, ml.typ)

  genStmtList(g, body)

  # epilogue (fallthrough return path)
  if g.p.frameSize > 0:
    g.localGet g.p.fpIdx
    g.constI32 g.p.frameSize
    g.op OpI32Add
    g.globalSet GlobSp
  # implicit return: a value-returning proc must have returned already; wasm
  # still requires the body to type as the result — end with unreachable when
  # a result is expected but control can fall off the end.
  if not isVoidType(retType):
    g.op OpUnreachable

  let (ps, rs) = procSigTypes(g, decl, isProctype = false)
  let ti = funcTypeIdx(g, ps, rs)
  discard ti
  g.funcBodies[g.funcIdx[sym]] =
    (locals: g.p.localTypes, nparams: params.len, code: g.p.body.data)

# ── module generation ────────────────────────────────────────────────────────

proc emitGlobalInit(g: var WasmGen; nm: string; addrv: uint32) =
  ## Turn a gvar/const's STATIC initializer into a data segment. Zero inits
  ## reserve address space only; runtime inits are the ini chain's job. A
  ## Symbol initializer naming a proc is a static fn-ptr default → its
  ## funcref-table slot (this can discover new reachable procs).
  let si = lookupSym(typeCtx(g), nm)
  if si.cat notin {scGlobal, scTvar}: return
  var d = si.decl
  var typ, initv: Cursor
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
  if not hasInit: return
  let sc = scalOf(g, typ)
  var bytes = ""
  var ok = true
  case initv.kind
  of IntLit:
    var v = cast[uint64](intVal(initv))
    for i in 0 ..< min(sc.bits div 8, 8):
      bytes.add char(v and 0xFF)
      v = v shr 8
  of UIntLit:
    var v = uintVal(initv)
    for i in 0 ..< min(sc.bits div 8, 8):
      bytes.add char(v and 0xFF)
      v = v shr 8
  of CharLit:
    bytes.add char(ord(charLit(initv)))
  of FloatLit:
    let fv = floatVal(initv)
    if sc.kind == skF32:
      let b32 = cast[uint32](float32(fv))
      for i in 0 ..< 4: bytes.add char((b32 shr (i * 8)) and 0xFF)
    else:
      let b64 = cast[uint64](fv)
      for i in 0 ..< 8: bytes.add char((b64 shr (i * 8)) and 0xFF)
  of Symbol:
    let initSym = symName(initv)
    let isi = lookupSym(typeCtx(g), initSym)
    if isi.cat == scProc or (isForeignSym(g.prog, initSym) and
                             isi.cat == scNone):
      let slot = tableSlotOf(g, initSym)       # may enqueue the proc
      for i in 0 ..< 4: bytes.add char((slot shr (i * 8)) and 0xFF)
    else:
      err g, "global initializer symbol not supported yet: " & initSym
  of StrLit:
    let a = strLitAddr(g, strVal(initv))
    for i in 0 ..< 4: bytes.add char((a shr (i * 8)) and 0xFF)
  of TagLit:
    case initv.exprKind
    of TrueC: bytes.add '\1'
    of FalseC, NilC: ok = false                # zero is the default
    else: ok = false                           # runtime init handled by ini chain
  else: ok = false
  if ok and bytes.len > 0:
    g.dataSegs.add (addrv, bytes)

proc generateWasm*(buf: var TokenBuf; inputPath: string; tags: TagPool): seq[byte] =
  var g = WasmGen(tags: tags, memTop: NullGuard, nextFunc: uint32(HostImports.len))
  g.prog = collect(buf, inputPath, tags, ptrSize = WasmPtrSize)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars

  # imports pin the low function indices
  for hi in HostImports:
    let ti = g.wm.addFuncType(hi.params, hi.results)
    discard g.wm.addImportFunc("env", hi.name, ti)

  # entry = the exportc "main" proc (arkham's convention)
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
  if not haveEntry:
    raiseAssert "ithaqua: no entry proc (exportc \"main\") in " & inputPath
  discard declareProc(g, g.entrySym, entryDecl)

  # every other exportc proc in the main module is an external entry point:
  # a reachability root, exported from the wasm module under its C name
  var exportRoots: seq[(string, string)] = @[]  # (decl symbol, C name)
  for pi in g.prog.procs:
    if pi.isEntry: continue
    var nc = pi.decl
    inc nc                                     # (proc → name
    if nc.kind != SymbolDef: continue
    let sym = symName(nc)
    var d = pi.decl
    var importcN, exportcN = ""
    d.into:
      inc d                                    # name
      skip d                                   # params
      skip d                                   # return type
      parsePragmas(d, importcN, exportcN)
      while d.hasMore: skip d
    if exportcN.len > 0 and importcN.len == 0:
      exportRoots.add (sym, exportcN)
      discard declareProc(g, sym, pi.decl)

  # drain the worklist to a fixpoint: lowering procs discovers globals, and a
  # global's static initializer can name a proc (fn-ptr default) — which puts
  # more procs on the worklist.
  var processedGlobals = initHashSet[string]()
  while true:
    while g.pendingProcs.len > 0:
      let (sym, decl) = g.pendingProcs.pop()
      if sym in g.emitted: continue
      g.emitted.incl sym
      lowerProc(g, sym, decl)
    var newGlobals: seq[string] = @[]
    for nm in g.globalAddr.keys:
      if nm notin processedGlobals: newGlobals.add nm
    if newGlobals.len == 0: break
    for nm in newGlobals:
      processedGlobals.incl nm
      emitGlobalInit(g, nm, g.globalAddr[nm])

  # declare functions in index order and register bodies
  var order = newSeq[string](g.funcIdx.len)
  for sym, fi in g.funcIdx:
    order[int(fi) - HostImports.len] = sym
  for sym in order:
    var decl: Cursor
    if isForeignSym(g.prog, sym):
      var found = false
      decl = lookupForeignDecl(g.prog, sym, found)
    else:
      decl = localProcDecl(g, sym)
    let (ps, rs) = procSigTypes(g, decl, isProctype = false)
    discard g.wm.addFunction(funcTypeIdx(g, ps, rs))
  for sym in order:
    let fi = g.funcIdx[sym]
    let fb = g.funcBodies[fi]
    # run-length compress the local declarations
    var decls: seq[(uint32, byte)] = @[]
    for vt in fb.locals:
      if decls.len > 0 and decls[^1][1] == vt: inc decls[^1][0]
      else: decls.add (1'u32, vt)
    g.wm.addCode(decls, fb.code)

  # string literals + explicit data
  for (a, s) in g.dataSegs:
    var bytes = newSeq[byte](s.len)
    for i, ch in s: bytes[i] = byte(ch)
    g.wm.addData(int32(a), bytes)

  # funcref table for indirect calls — always present (call_indirect can be
  # emitted through a fn-ptr that only ever holds null); slot 0 = null
  discard g.wm.addTable(uint32(g.tableEntries.len + 1))
  if g.tableEntries.len > 0:
    g.wm.addElem(1, g.tableEntries)

  # shadow stack above the static data; sp starts at the top
  let stackBase = alignUp(g.memTop, 16)
  let stackTop = stackBase + uint32(ShadowStackSize)
  let pages = (stackTop + uint32(PageSize) - 1) div uint32(PageSize) + 1
  g.wm.addMemory(pages)
  var spInit = ByteBuf()
  spInit.add OpI32Const
  spInit.addI32 int32(stackTop)
  discard g.wm.addGlobal(ValI32, mutable = true, spInit.data)    # 0: sp
  var zeroInit = ByteBuf()
  zeroInit.add OpI32Const
  zeroInit.addI32 0
  discard g.wm.addGlobal(ValI32, mutable = true, zeroInit.data)  # 1: errv
  discard g.wm.addGlobal(ValI32, mutable = true, zeroInit.data)  # 2: ovf

  # _start: call main(0, nil, nil), drop the exit code
  # (the entry's C signature is (argc, argv, envp) — see the Leng `main`)
  var startBody = ByteBuf()
  startBody.add OpI32Const; startBody.addI32 0
  startBody.add OpI32Const; startBody.addI32 0
  startBody.add OpI32Const; startBody.addI32 0
  startBody.add OpCall
  startBody.addU32 g.funcIdx[g.entrySym]
  startBody.add OpDrop
  let startTi = g.wm.addFuncType(newSeq[byte](), newSeq[byte]())
  let startFi = g.wm.addFunction(startTi)
  g.wm.addCode(@[], startBody.data)
  g.wm.addExportFunc("_start", startFi)
  g.wm.addExportMemory("memory", 0)
  for (sym, cName) in exportRoots:
    g.wm.addExportFunc(cName, g.funcIdx[sym])

  result = encode(g.wm)
