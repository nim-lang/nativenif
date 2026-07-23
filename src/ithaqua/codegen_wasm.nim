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

import std / [tables, sets, assertions, strutils, os, syncio]
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
    retSret: bool                ## aggregate result → hidden dest-pointer param 0
    constrDests: seq[uint32]     ## per-nesting-depth constructor dest locals
    dynSret: int32               ## outstanding sret-temp bytes on the shadow stack,
                                 ## reclaimed at the end of the enclosing statement
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

proc flexPayloadLen(g: var WasmGen; initv: Cursor): int =
  ## Extra bytes a constant initializer stores past its type's fixed size:
  ## the payload of a flexarray tail field (a string literal or an array
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
            # count elements × element size, resolved from the aconstr type
            var ac = kv
            ac.into:
              let elemT = innerType(g.prog, resolveType(g.prog, ac))
              let (esz, _) = typeSizeAlign(g.prog, elemT)
              skip ac
              var n = 0
              while ac.hasMore: (inc n; skip ac)
              result += n * esz
          while kv.hasMore: skip kv
      skip t

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
    sz += flexPayloadLen(g, initv)             # flexarray tail data (string consts)
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
            # an aggregate parameter travels as the address of a fresh
            # caller-made copy (see genCallArgs)
            params.add valType(sc)
            while pc.hasMore: skip pc
    skip d                                     # params
    if not isVoidType(d):
      let sc = scalOf(g, d)
      if sc.kind == skMem:
        # sret convention: the caller passes the result destination as a
        # hidden FIRST parameter; the wasm signature returns nothing
        params.insert(ValI32, 0)
      else:
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
proc constrDest(g: var WasmGen; depth: int): uint32
proc genConstrInto(g: var WasmGen; constr: Cursor; depth: int)
proc newLocal(g: var WasmGen; vt: byte): uint32
proc callResultType(g: var WasmGen; c: Cursor): Cursor
proc litScal(g: var WasmGen; c: Cursor): Scal

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
        # variant-object payload (hexer lowers case-objects to a union of
        # anonymous object branches): every branch OVERLAYS at the union's
        # offset — search each for the field; the union occupies max-size
        # bytes at max-alignment
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
      # an aggregate param's wasm local HOLDS the aggregate's address
      if scalOf(g, g.p.locals[nm].typ).kind == skMem:
        g.localGet g.p.locals[nm].idx
      else:
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
    of BaseobjC:
      # base-object view of a derived object: same address (base at offset 0)
      var t = c
      t.into:
        skip t                                 # base type
        if t.kind == IntLit: inc t             # depth
        genLvalAddr(g, t)
        while t.hasMore: skip t
    of ErrvC, OvfC:
      err g, "errv/ovf have no address"
    else:
      err g, "not an lvalue: " & $c.exprKind
  else:
    err g, "not an lvalue"

proc exprScal(g: var WasmGen; c: Cursor): Scal =
  ## The class an expression's genExpr output actually has. Differs from
  ## `scalOf(lengType(...))` for suffixed literals: typenav reports the
  ## bare-literal default type, but genSufLit emits at the SUFFIX's width.
  if c.kind == TagLit and c.exprKind == SufC:
    var t = c
    t.into:
      inc t                                    # past the literal
      let sfx = strVal(t)
      while t.hasMore: skip t
      case sfx
      of "i64": result = Scal(kind: skI64, bits: 64, signed: true)
      of "u64": result = Scal(kind: skI64, bits: 64, signed: false)
      of "f32": result = Scal(kind: skF32, bits: 32)
      of "f64", "f": result = Scal(kind: skF64, bits: 64)
      of "i8": result = Scal(kind: skI32, bits: 8, signed: true)
      of "i16": result = Scal(kind: skI32, bits: 16, signed: true)
      of "u8": result = Scal(kind: skI32, bits: 8, signed: false)
      of "u16": result = Scal(kind: skI32, bits: 16, signed: false)
      of "u", "u32": result = Scal(kind: skI32, bits: 32, signed: false)
      else: result = Scal(kind: skI32, bits: 32, signed: true)
  elif c.kind in {IntLit, UIntLit, CharLit, FloatLit}:
    result = litScal(g, c)
  else:
    result = scalOf(g, lengType(g, c))

proc coerceTo(g: var WasmGen; have, want: Scal) =
  ## Convert the value on the stack from class `have` to class `want` —
  ## Leng inherits C's implicit arithmetic conversions (an op's carried type
  ## may differ from an operand's own type), so every typed value context
  ## coerces.
  if have.kind == want.kind:
    if want.kind == skI32 and want.bits < 32 and
       (want.bits < have.bits or want.signed != have.signed):
      g.canonNarrow want                       # re-canonicalize to the target width
    return
  case want.kind
  of skI64:
    case have.kind
    of skI32, skMem:
      g.op (if have.kind == skI32 and have.signed: OpI64ExtendI32S
            else: OpI64ExtendI32U)
    of skF32: g.op (if want.signed: OpI64TruncF32S else: OpI64TruncF32U)
    of skF64: g.op (if want.signed: OpI64TruncF64S else: OpI64TruncF64U)
    else: discard
  of skI32:
    case have.kind
    of skI64:
      g.op OpI32WrapI64
      g.canonNarrow want
    of skF32: g.op (if want.signed: OpI32TruncF32S else: OpI32TruncF32U)
    of skF64: g.op (if want.signed: OpI32TruncF64S else: OpI32TruncF64U)
    else: discard                              # skMem: an address is an i32
  of skF64:
    case have.kind
    of skF32: g.op OpF64PromoteF32
    of skI32: g.op (if have.signed: OpF64ConvertI32S else: OpF64ConvertI32U)
    of skI64: g.op (if have.signed: OpF64ConvertI64S else: OpF64ConvertI64U)
    else: discard
  of skF32:
    case have.kind
    of skF64: g.op OpF32DemoteF64
    of skI32: g.op (if have.signed: OpF32ConvertI32S else: OpF32ConvertI32U)
    of skI64: g.op (if have.signed: OpF32ConvertI64S else: OpF32ConvertI64U)
    else: discard
  of skMem:
    if have.kind == skI64: g.op OpI32WrapI64   # a 64-bit "address" narrows

proc genValueAs(g: var WasmGen; c: Cursor; sc: Scal) =
  ## Emit expression `c` in a context of class `sc`. Bare literals carry no
  ## width in Leng — the CONTEXT types them — so they are emitted directly
  ## at the context's width; everything else emits via genExpr and is then
  ## COERCED to the context's class (C implicit-conversion semantics).
  case c.kind
  of IntLit:
    case sc.kind
    of skI64: g.constI64 intVal(c)
    of skF64: g.op OpF64Const; g.p.body.addF64 float64(intVal(c))
    of skF32: g.op OpF32Const; g.p.body.addF32 float32(intVal(c))
    else: g.constI32 int32(intVal(c))
  of UIntLit:
    case sc.kind
    of skI64: g.constI64 cast[int64](uintVal(c))
    of skF64: g.op OpF64Const; g.p.body.addF64 float64(uintVal(c))
    of skF32: g.op OpF32Const; g.p.body.addF32 float32(uintVal(c))
    else: g.constI32 cast[int32](uint32(uintVal(c) and 0xFFFFFFFF'u64))
  of CharLit:
    if sc.kind == skI64: g.constI64 int64(ord(charLit(c)))
    else: g.constI32 int32(ord(charLit(c)))
  of FloatLit:
    if sc.kind == skF32:
      g.op OpF32Const; g.p.body.addF32 float32(floatVal(c))
    else:
      g.op OpF64Const; g.p.body.addF64 floatVal(c)
  of TagLit:
    case c.exprKind
    of NilC, FalseC:
      if sc.kind == skI64: g.constI64 0 else: g.constI32 0
    of TrueC:
      if sc.kind == skI64: g.constI64 1 else: g.constI32 1
    of ParC:
      var t = c
      inc t
      genValueAs(g, t, sc)
    else:
      genExpr(g, c)
      coerceTo(g, exprScal(g, c), sc)
  else:
    genExpr(g, c)
    coerceTo(g, exprScal(g, c), sc)

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
    genValueAs(g, t, sc); skip t
    genValueAs(g, t, sc)
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
    # the comparison width/signedness comes from a NON-LITERAL operand when
    # one exists. Bare literals default to the machine word, and SUFFIXED
    # literals count as literals too: typenav reports `(suf N "u64")` as the
    # bare-literal default (i32), so typing the compare from a suf operand
    # would truncate the other side (`BIGLIT <= u64var` became a signed
    # 32-bit compare of wrapped halves). When both sides are literal-ish,
    # exprScal reads the suffix (or the bare default) directly.
    var lhs = t
    var rhs = t
    skip rhs
    let lhsLit = lhs.kind in {IntLit, UIntLit, CharLit, FloatLit} or
      (lhs.kind == TagLit and lhs.exprKind == SufC)
    let rhsLit = rhs.kind in {IntLit, UIntLit, CharLit, FloatLit} or
      (rhs.kind == TagLit and rhs.exprKind == SufC)
    let sc =
      if not lhsLit: scalOf(g, lengType(g, lhs))
      elif not rhsLit: scalOf(g, lengType(g, rhs))
      else: exprScal(g, lhs)
    genValueAs(g, t, sc); skip t
    genValueAs(g, t, sc)
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
    let src = exprScal(g, t)
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

proc scalForVal(vt: byte): Scal =
  ## Minimal context class for a wasm value type (drives literal widths).
  case vt
  of ValI64: Scal(kind: skI64, bits: 64, signed: true)
  of ValF32: Scal(kind: skF32, bits: 32)
  of ValF64: Scal(kind: skF64, bits: 64)
  else: Scal(kind: skI32, bits: 32, signed: true)

proc genCallArgs(g: var WasmGen; t: var Cursor; expected: seq[byte]): int32 =
  ## Emit the remaining children of a call as arguments, in order. An
  ## aggregate argument is passed BY REFERENCE TO A FRESH COPY: bump the
  ## shadow stack (dynamic — `ret` unwinds from fp regardless, but the
  ## caller restores sp right after the call so loops don't creep),
  ## construct or copy the value there, pass the address. Returns the
  ## dynamic byte count the caller must give back to sp after the call.
  result = 0
  var argIdx = 0
  while t.hasMore:
    let argT = lengType(g, t)
    let sc = scalOf(g, argT)
    if sc.kind == skMem:
      let sz = int32(align(max(sc.bits, 1), 16))
      result += sz
      let tmp = constrDest(g, g.p.constrDests.len)  # a fresh dedicated local
      g.globalGet GlobSp
      g.constI32 sz
      g.op OpI32Sub
      g.localTee tmp
      g.globalSet GlobSp
      if t.kind == TagLit and t.exprKind in {OconstrC, AconstrC}:
        g.localGet tmp
        genConstrInto(g, t, g.p.constrDests.len)
      else:
        g.localGet tmp
        genExpr(g, t)                          # source address
        g.constI32 int32(sc.bits)
        g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
      g.localGet tmp                           # the argument value: the copy's address
    else:
      if argIdx < expected.len:
        genValueAs(g, t, scalForVal(expected[argIdx]))
      else:
        genExpr(g, t)                          # varargs tail: self-described
    skip t
    inc argIdx

proc restoreDynStack(g: var WasmGen; dynBytes: int32) =
  ## Give back the shadow-stack space genCallArgs borrowed (safe with a call
  ## result on the wasm value stack — global ops don't touch values below).
  if dynBytes > 0:
    g.globalGet GlobSp
    g.constI32 dynBytes
    g.op OpI32Add
    g.globalSet GlobSp

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
    # aggregate result → allocate the sret destination and pass it as the
    # hidden first argument; the temp survives until end of statement
    let retT = callResultType(g, c)
    var sretTmp = 0'u32
    var hasSret = false
    if not isVoidType(retT):
      let rsc = scalOf(g, retT)
      if rsc.kind == skMem:
        hasSret = true
        let sz = int32(align(max(rsc.bits, 1), 16))
        g.p.dynSret += sz
        sretTmp = constrDest(g, g.p.constrDests.len)
        g.globalGet GlobSp
        g.constI32 sz
        g.op OpI32Sub
        g.localTee sretTmp
        g.globalSet GlobSp
        g.localGet sretTmp                     # the hidden first argument
    # the callee's wasm param types (for context-typing bare literal args);
    # strip the sret slot — genCallArgs never sees that argument
    var fi = 0'u32
    var pt: Cursor
    var expected: seq[byte] = @[]
    if not indirect:
      let sym = symName(target)
      # lowered intrinsics (atomics/mem*/bit builtins) never reach here —
      # genCall handles them before argument emission.
      fi = refProc(g, sym)
      if g.callTarget.hasKey(sym) and not cursorIsNil(g.callTarget[sym].sigType):
        let (ps, _) = procSigTypes(g, g.callTarget[sym].sigType, isProctype = true)
        expected = ps
    else:
      pt = resolveType(g.prog, calleeType)
      if pt.kind == TagLit and pt.typeKind == PtrT:
        var inner = pt
        inc inner
        pt = resolveType(g.prog, inner)
      if pt.kind != TagLit or pt.typeKind != ProctypeT:
        err g, "indirect call through a non-proctype value"
      let (ps, _) = procSigTypes(g, pt, isProctype = true)
      expected = ps
    if hasSret and expected.len > 0:
      expected.delete(0)
    let dynBytes = genCallArgs(g, t, expected)
    if not indirect:
      g.op OpCall
      g.emitU32 fi
    else:
      genExpr(g, target)                       # the table slot (an i32)
      let (ps, rs) = procSigTypes(g, pt, isProctype = true)
      g.op OpCallIndirect
      g.emitU32 funcTypeIdx(g, ps, rs)
      g.emitU32 0                              # table 0
    restoreDynStack(g, dynBytes)               # arg copies are consumed; sret temp is NOT
    if hasSret:
      g.localGet sretTmp                       # the call's value: the result's address

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

const MemcmpSym = "memcmp.ithaqua.synth" ## dots make collision with NIF syms impossible

proc refMemcmp(g: var WasmGen): uint32 =
  ## Function index of the synthetic memcmp helper, emitting it on first use.
  ## Unlike memcpy/memset there is no bulk-memory instruction for compare, so
  ## call sites become plain calls to this hand-encoded byte loop. It lives in
  ## `funcIdx`/`funcBodies` like a lowered proc; only the module-assembly decl
  ## loop special-cases the signature (no Leng decl exists to read it from).
  if g.funcIdx.hasKey(MemcmpSym): return g.funcIdx[MemcmpSym]
  result = g.nextFunc
  inc g.nextFunc
  g.funcIdx[MemcmpSym] = result
  # (a: i32, b: i32, n: i32) -> i32; C semantics: sign of the first differing
  # UNSIGNED byte pair, 0 if the first n bytes match.
  # params a=0 b=1 n=2, locals ca=3 cb=4
  var b = ByteBuf()
  b.add OpLoop; b.add BlockVoid
  #   if n == 0: return 0
  b.add OpLocalGet; b.addU32 2
  b.add OpI32Eqz
  b.add OpIf; b.add BlockVoid
  b.add OpI32Const; b.addI32 0
  b.add OpReturn
  b.add OpEnd
  #   ca = load8_u a; cb = load8_u b
  b.add OpLocalGet; b.addU32 0
  b.add OpI32Load8U; b.addU32 0; b.addU32 0
  b.add OpLocalSet; b.addU32 3
  b.add OpLocalGet; b.addU32 1
  b.add OpI32Load8U; b.addU32 0; b.addU32 0
  b.add OpLocalSet; b.addU32 4
  #   if ca != cb: return ca - cb
  b.add OpLocalGet; b.addU32 3
  b.add OpLocalGet; b.addU32 4
  b.add OpI32Ne
  b.add OpIf; b.add BlockVoid
  b.add OpLocalGet; b.addU32 3
  b.add OpLocalGet; b.addU32 4
  b.add OpI32Sub
  b.add OpReturn
  b.add OpEnd
  #   a += 1; b += 1; n -= 1; continue
  b.add OpLocalGet; b.addU32 0
  b.add OpI32Const; b.addI32 1
  b.add OpI32Add
  b.add OpLocalSet; b.addU32 0
  b.add OpLocalGet; b.addU32 1
  b.add OpI32Const; b.addI32 1
  b.add OpI32Add
  b.add OpLocalSet; b.addU32 1
  b.add OpLocalGet; b.addU32 2
  b.add OpI32Const; b.addI32 1
  b.add OpI32Sub
  b.add OpLocalSet; b.addU32 2
  b.add OpBr; b.addU32 0
  b.add OpEnd                                  # loop
  b.add OpUnreachable                          # loop never falls through; type the i32 result
  g.funcBodies[result] = (locals: @[ValI32, ValI32], nparams: 3, code: b.data)

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
        let nSc = exprScal(g, t)               # exprScal: a suf-u64 literal is i64
        genExpr(g, t)
        if nSc.kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
        if wantValue: err g, "memcpy result value not modelled"
      of "memset":
        genExpr(g, t); skip t                  # dst
        let vSc = exprScal(g, t)               # exprScal: a suf-u64 literal is i64
        genExpr(g, t)                          # value
        if vSc.kind == skI64: g.op OpI32WrapI64
        skip t
        let nSc = exprScal(g, t)               # exprScal: a suf-u64 literal is i64
        genExpr(g, t)
        if nSc.kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op 0xFC'u8; g.emitU32 11; g.emitU32 0                # memory.fill
        if wantValue: err g, "memset result value not modelled"
      of "memcmp":
        # (a, b, n) → call the synthetic byte-compare loop (value-returning,
        # so unlike memcpy/memset the result IS modelled)
        genExpr(g, t); skip t                  # a
        genExpr(g, t); skip t                  # b
        let nSc = exprScal(g, t)               # exprScal: a suf-u64 literal is i64
        genExpr(g, t)
        if nSc.kind == skI64: g.op OpI32WrapI64
        skip t
        while t.hasMore: skip t
        g.op OpCall
        g.emitU32 refMemcmp(g)
        if not wantValue: g.op OpDrop
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
      of "__atomic_compare_exchange_n":
        # (ptr, expected_ptr, desired, weak, succ_order, fail_order) → bool.
        # Single-threaded: if *ptr == *expected: *ptr = desired; true
        #                  else: *expected = *ptr; false
        var pT = lengType(g, t)
        let elemT = innerType(g.prog, resolveType(g.prog, pT))
        let sc = scalOf(g, elemT)
        let ptrL = newLocal(g, ValI32)
        let expL = newLocal(g, ValI32)
        let desL = newLocal(g, valType(sc))
        let curL = newLocal(g, valType(sc))
        genExpr(g, t); skip t                  # ptr
        g.localSet ptrL
        genExpr(g, t); skip t                  # expected (a pointer)
        g.localSet expL
        genExpr(g, t); skip t                  # desired
        g.localSet desL
        while t.hasMore: skip t                # weak + memorders (constants)
        g.localGet ptrL
        g.emitLoad sc
        g.localSet curL
        g.localGet curL
        g.localGet expL
        g.emitLoad sc
        g.op (if sc.kind == skI64: OpI64Eq else: OpI32Eq)
        g.op OpIf; g.p.body.add ValI32
        g.localGet ptrL
        g.localGet desL
        g.emitStore sc
        g.constI32 1
        g.op OpElse
        g.localGet expL
        g.localGet curL
        g.emitStore sc
        g.constI32 0
        g.op OpEnd
        if not wantValue: g.op OpDrop
      of "__atomic_exchange_n":
        # (ptr, val, order) → old value. Single-threaded swap.
        var pT = lengType(g, t)
        let elemT = innerType(g.prog, resolveType(g.prog, pT))
        let sc = scalOf(g, elemT)
        let ptrL = newLocal(g, ValI32)
        let valL = newLocal(g, valType(sc))
        let oldL = newLocal(g, valType(sc))
        genExpr(g, t); skip t
        g.localSet ptrL
        genExpr(g, t); skip t
        g.localSet valL
        while t.hasMore: skip t
        g.localGet ptrL
        g.emitLoad sc
        g.localSet oldL
        g.localGet ptrL
        g.localGet valL
        g.emitStore sc
        if wantValue: g.localGet oldL
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
      of "__builtin_wasm_memory_size":
        # () -> current size in 64 KiB pages
        g.op OpMemorySize; g.p.body.add 0'u8
      of "__builtin_wasm_memory_grow":
        # (delta pages) -> previous size in pages, or -1 on failure
        genExpr(g, t)
        g.op OpMemoryGrow; g.p.body.add 0'u8
      else: err g, "bit builtin not supported yet: " & ct.bitBuiltin
      # memory_size is the one ZERO-ARG builtin — the shared skip below
      # assumes exactly-one-arg and would overrun its ParRi
      if ct.bitBuiltin != "__builtin_wasm_memory_size":
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
        let nSc = exprScal(g, t)               # exprScal: a suf-u64 literal is i64
        genExpr(g, t)
        if nSc.kind == skI64: g.op OpI32WrapI64
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
    of OconstrC, AconstrC:
      # a constructor in VALUE position: build it in a shadow-stack temp
      # (stmt-scoped, reclaimed with the dynSret pool) and yield its address —
      # the same aggregate-value convention as sret results
      var ty = c
      inc ty                                   # the carried type
      let (sz0, _) = typeSizeAlign(g.prog, resolveType(g.prog, ty))
      let sz = int32(align(max(sz0, 1), 16))
      g.p.dynSret += sz
      let depth = g.p.constrDests.len
      let tmp = constrDest(g, depth)
      g.globalGet GlobSp
      g.constI32 sz
      g.op OpI32Sub
      g.localTee tmp
      g.globalSet GlobSp
      g.localGet tmp
      genConstrInto(g, c, depth)
      g.localGet tmp                           # the expression's value: its address
    else:
      err g, "expression not supported yet: " & $c.exprKind
  else:
    err g, "unexpected token in expression"

# ── statements ───────────────────────────────────────────────────────────────

proc newLocal(g: var WasmGen; vt: byte): uint32 =
  ## Allocate a fresh wasm local mid-emission (the locals header is written
  ## after the body, so late allocation is safe).
  result = uint32(g.p.nparams + g.p.localTypes.len)
  g.p.localTypes.add vt

proc genFieldStore(g: var WasmGen; dest: uint32; off: int; ft: Cursor;
                   value: Cursor; depth: int)

proc constrDest(g: var WasmGen; depth: int): uint32 =
  ## The i32 local holding the destination address of the constructor
  ## currently being emitted at nesting `depth` (nested constructors each
  ## need their own).
  while g.p.constrDests.len <= depth:
    g.p.constrDests.add newLocal(g, ValI32)
  result = g.p.constrDests[depth]

proc genConstrInto(g: var WasmGen; constr: Cursor; depth: int) =
  ## Store an `(oconstr Type (kv field value)*)` / `(aconstr Type value*)`
  ## field by field through the destination ADDRESS on top of the stack.
  let dest = constrDest(g, depth)
  g.localSet dest
  var t = constr
  t.into:
    let typ = t
    let objT = resolveType(g.prog, typ)
    skip t
    if constr.exprKind == OconstrC:
      var isFirst = true
      while t.hasMore:
        if t.substructureKind != KvU:
          if isFirst:
            # inheritance header: a leading non-kv child is the vtable
            # pointer of a RootObj-derived object — `(oconstr T (addr T.vt.)
            # (kv …)…)`, e.g. hexer's coroutine frames (method cancel).
            # Stored at offset 0, ahead of the named fields.
            g.localGet dest
            genExpr(g, t)                      # the vtable's address (i32)
            g.emitStore Scal(kind: skI32, bits: 32, signed: false)
            skip t
            isFirst = false
            continue
          err g, "malformed oconstr"
        isFirst = false
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
          genFieldStore(g, dest, off, ft, value, depth)
        skip t
    else:                                      # aconstr: consecutive elements
      let elemT = innerType(g.prog, objT)
      let (esz, _) = typeSizeAlign(g.prog, elemT)
      var idx = 0
      while t.hasMore:
        genFieldStore(g, dest, idx * esz, elemT, t, depth)
        skip t
        inc idx

proc genFieldStore(g: var WasmGen; dest: uint32; off: int; ft: Cursor;
                   value: Cursor; depth: int) =
  ## One member store inside a constructor: dest[off] = value.
  let sc = scalOf(g, ft)
  if value.kind == TagLit and value.exprKind in {OconstrC, AconstrC}:
    g.localGet dest
    if off != 0:
      g.constI32 int32(off)
      g.op OpI32Add
    genConstrInto(g, value, depth + 1)
  elif sc.kind == skMem:
    g.localGet dest
    if off != 0:
      g.constI32 int32(off)
      g.op OpI32Add
    genExpr(g, value)                          # the source aggregate's address
    g.constI32 int32(sc.bits)
    g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0     # memory.copy
  else:
    g.localGet dest
    if off != 0:
      g.constI32 int32(off)
      g.op OpI32Add
    genValueAs(g, value, sc)
    g.emitStore sc

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
      genValueAs(g, rhs, scalOf(g, g.p.locals[nm].typ))
      g.localSet g.p.locals[nm].idx
      return
  # memory destination
  let lhsT = lengType(g, lhs)
  let sc = scalOf(g, lhsT)
  if sc.kind == skMem:
    genLvalAddr(g, lhs)                        # dst
    if rhs.kind == TagLit and rhs.exprKind in {OconstrC, AconstrC}:
      genConstrInto(g, rhs, 0)                 # construct in place
    else:
      genExpr(g, rhs)                          # src address (aggregates are addresses)
      g.constI32 int32(sc.bits)                # byte size
      g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
  else:
    genLvalAddr(g, lhs)
    genValueAs(g, rhs, sc)
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
                  genValueAs(g, rr, sc); skip rr
                  g.op (if is64: (if sc.signed: OpI64GeS else: OpI64GeU)
                        else: (if sc.signed: OpI32GeS else: OpI32GeU))
                  g.localGet selLocal
                  genValueAs(g, rr, sc)
                  while rr.hasMore: skip rr
                  g.op (if is64: (if sc.signed: OpI64LeS else: OpI64LeU)
                        else: (if sc.signed: OpI32LeS else: OpI32LeU))
                  g.op OpI32And
              else:
                g.localGet selLocal
                genValueAs(g, r, sc)
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
      if g.p.retSret:
        # copy the aggregate result into the caller's sret destination
        let sc = scalOf(g, g.p.retType)
        g.localGet 0                           # the hidden dest pointer
        if t.kind == TagLit and t.exprKind in {OconstrC, AconstrC}:
          genConstrInto(g, t, 0)
        else:
          genExpr(g, t)                        # result value = its address
          g.constI32 int32(sc.bits)
          g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
      else:
        genValueAs(g, t, scalOf(g, g.p.retType))
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
    # resolve the callee signature + return type BEFORE the arguments (sret
    # and literal-typing both need them)
    var expected: seq[byte] = @[]
    var retT: Cursor
    var fi = 0'u32
    var pt: Cursor
    if not indirect:
      let sym = symName(target)
      fi = refProc(g, sym)
      if g.callTarget.hasKey(sym) and not cursorIsNil(g.callTarget[sym].sigType):
        let (ps, _) = procSigTypes(g, g.callTarget[sym].sigType, isProctype = true)
        expected = ps
      if g.callTarget.hasKey(sym) and not cursorIsNil(g.callTarget[sym].retType):
        retT = g.callTarget[sym].retType
      else:
        var dd = localProcDecl(g, sym)
        dd.into:
          inc dd; skip dd
          retT = dd
          while dd.hasMore: skip dd
    else:
      pt = resolveType(g.prog, calleeType)
      if pt.kind == TagLit and pt.typeKind == PtrT:
        var inner = pt; inc inner
        pt = resolveType(g.prog, inner)
      let (ps, _) = procSigTypes(g, pt, isProctype = true)
      expected = ps
      var q = pt
      q.into:
        skip q; skip q
        retT = q
        while q.hasMore: skip q
    # aggregate result → sret destination (discarded; reclaimed at stmt end)
    var hasSret = false
    if not cursorIsNil(retT) and not isVoidType(retT):
      let rsc = scalOf(g, retT)
      if rsc.kind == skMem:
        hasSret = true
        let sz = int32(align(max(rsc.bits, 1), 16))
        g.p.dynSret += sz
        let sretTmp = constrDest(g, g.p.constrDests.len)
        g.globalGet GlobSp
        g.constI32 sz
        g.op OpI32Sub
        g.localTee sretTmp
        g.globalSet GlobSp
        g.localGet sretTmp
    if hasSret and expected.len > 0:
      expected.delete(0)
    let dynBytes = genCallArgs(g, t, expected)
    if not indirect:
      g.op OpCall
      g.emitU32 fi
    else:
      genExpr(g, target)
      let (ps, rs) = procSigTypes(g, pt, isProctype = true)
      g.op OpCallIndirect
      g.emitU32 funcTypeIdx(g, ps, rs)
      g.emitU32 0
    restoreDynStack(g, dynBytes)
    if not hasSret and not cursorIsNil(retT) and not isVoidType(retT):
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

proc genKeepovf(g: var WasmGen; c: Cursor) =
  ## `(keepovf (add|sub|mul Type a b) dst)` — overflow-checked arithmetic:
  ## `(ovf, dst) = a op b`. Wasm has no flags register: ≤32-bit ops compute
  ## in i64 and compare the wrapped result against the wide one; i64 ops use
  ## the classic sign/division identities.
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
    case sc.kind
    of skI32:
      # widen → op in i64 → overflow iff the wrapped (canonical) result
      # disagrees with the wide result
      let rWide = newLocal(g, ValI64)
      let rNarrow = newLocal(g, ValI32)
      genValueAs(g, lhs, sc)
      g.op (if sc.signed: OpI64ExtendI32S else: OpI64ExtendI32U)
      genValueAs(g, rhs, sc)
      g.op (if sc.signed: OpI64ExtendI32S else: OpI64ExtendI32U)
      case opKind
      of AddC: g.op OpI64Add
      of SubC: g.op OpI64Sub
      else: g.op OpI64Mul
      g.localTee rWide
      g.op OpI32WrapI64
      g.canonNarrow sc
      g.localSet rNarrow
      g.localGet rNarrow
      g.op (if sc.signed: OpI64ExtendI32S else: OpI64ExtendI32U)
      g.localGet rWide
      g.op OpI64Ne
      g.globalSet GlobOvf
      # store the wrapped result
      if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)):
        g.localGet rNarrow
        g.localSet g.p.locals[symName(dst)].idx
      else:
        genLvalAddr(g, dst)
        g.localGet rNarrow
        g.emitStore sc
    of skI64:
      let aL = newLocal(g, ValI64)
      let bL = newLocal(g, ValI64)
      let rL = newLocal(g, ValI64)
      genValueAs(g, lhs, sc)
      g.localSet aL
      genValueAs(g, rhs, sc)
      g.localSet bL
      g.localGet aL
      g.localGet bL
      case opKind
      of AddC: g.op OpI64Add
      of SubC: g.op OpI64Sub
      else: g.op OpI64Mul
      g.localSet rL
      if sc.signed:
        case opKind
        of AddC:
          # ovf iff sign(a)==sign(b) and sign(r)!=sign(a):
          # ((a xor r) and (b xor r)) < 0
          g.localGet aL; g.localGet rL; g.op OpI64Xor
          g.localGet bL; g.localGet rL; g.op OpI64Xor
          g.op OpI64And
          g.constI64 0
          g.op OpI64LtS
        of SubC:
          # ovf iff sign(a)!=sign(b) and sign(r)!=sign(a):
          # ((a xor b) and (a xor r)) < 0
          g.localGet aL; g.localGet bL; g.op OpI64Xor
          g.localGet aL; g.localGet rL; g.op OpI64Xor
          g.op OpI64And
          g.constI64 0
          g.op OpI64LtS
        else:
          # mul: a == 0 → no ovf; a == -1 → ovf iff b == low(i64)
          # (guards the div trap); else ovf iff r div a != b
          g.localGet aL
          g.op OpI64Eqz
          g.op OpIf; g.p.body.add ValI32
          g.constI32 0
          g.op OpElse
          g.localGet aL
          g.constI64 -1
          g.op OpI64Eq
          g.op OpIf; g.p.body.add ValI32
          g.localGet bL
          g.constI64 low(int64)
          g.op OpI64Eq
          g.op OpElse
          g.localGet rL
          g.localGet aL
          g.op OpI64DivS
          g.localGet bL
          g.op OpI64Ne
          g.op OpEnd
          g.op OpEnd
      else:
        case opKind
        of AddC:
          g.localGet rL
          g.localGet aL
          g.op OpI64LtU                        # carry: r < a
        of SubC:
          g.localGet aL
          g.localGet bL
          g.op OpI64LtU                        # borrow: a < b
        else:
          g.localGet aL
          g.op OpI64Eqz
          g.op OpIf; g.p.body.add ValI32
          g.constI32 0
          g.op OpElse
          g.localGet rL
          g.localGet aL
          g.op OpI64DivU
          g.localGet bL
          g.op OpI64Ne
          g.op OpEnd
      g.globalSet GlobOvf
      if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)):
        g.localGet rL
        g.localSet g.p.locals[symName(dst)].idx
      else:
        genLvalAddr(g, dst)
        g.localGet rL
        g.emitStore sc
    else:
      err g, "keepovf on a non-integer type"

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
        let ml = g.p.memLocals[nm]
        g.localGet g.p.fpIdx
        if ml.frameOff != 0:
          g.constI32 ml.frameOff
          g.op OpI32Add
        if t.kind == TagLit and t.exprKind in {OconstrC, AconstrC}:
          genConstrInto(g, t, 0)               # construct in place
        elif sc.kind == skMem:
          genExpr(g, t)                        # copy from another aggregate
          g.constI32 int32(sc.bits)
          g.op 0xFC'u8; g.emitU32 10; g.emitU32 0; g.emitU32 0   # memory.copy
        else:
          genValueAs(g, t, sc)
          g.emitStore sc
    else:
      if hasInit:
        genValueAs(g, t, scalOf(g, typ))
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
        genValueAs(g, rhs, sc)
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
    genKeepovf(g, c)
    skip c
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

proc landingPadLabel(c: Cursor): string =
  ## Non-empty iff `c` is hexer's jump-into-guarded-region idiom:
  ## `(if (elif (false) (stmts (lab L) …)))` — C's `if (0) { L: … }`, the
  ## flag-based error model's exception landing pad. The try body `jmp`s
  ## INTO the guarded branch, so a plain if-lowering could never reach the
  ## label; genStmtList restructures it into block/br form instead.
  result = ""
  if c.stmtKind != IfS: return
  var t = c
  var lab = ""
  var arms = 0
  t.into:
    while t.hasMore:
      inc arms
      if arms == 1 and t.substructureKind == ElifU:
        var e = t
        e.into:
          if e.kind == TagLit and e.exprKind == FalseC:
            skip e                             # (false)
            if e.hasMore and e.stmtKind == StmtsS:
              var s = e
              s.into:
                if s.hasMore and s.stmtKind == LabS:
                  var l = s
                  l.into:
                    lab = symName(l)
                    while l.hasMore: skip l
                while s.hasMore: skip s
          while e.hasMore: skip e
      skip t
  if arms == 1: result = lab

proc genStmtList(g: var WasmGen; c: Cursor) =
  ## Lower a `(stmts …)` list. Every `(lab L)` at THIS level gets a wasm
  ## `block` opened at the head of the list (nested in reverse appearance
  ## order, so the first label closes innermost) — a forward `jmp L` from
  ## anywhere inside then `br`s to it. A label already registered by an
  ## OUTER list (the landing-pad restructure below) is not reopened; the
  ## `(lab)` statement closes the outer block.
  ##
  ## A landing-pad child `(if (elif (false) (stmts (lab L) …)))` becomes
  ##   block $join { block $L { …try children…; br $join } …guarded body… }
  ## with both blocks opened at the head of the list: `jmp L` inside the
  ## try children brs past $L's end into the guarded body; normal
  ## fallthrough brs to $join, skipping it.
  # Collect the CLOSE events of this level in child order — each `(lab L)`
  # statement and each landing-pad if-child closes the block(s) opened for
  # it here. wasm `end` is positional (it always closes the innermost open
  # block), so blocks must nest in REVERSE close order: the event that
  # closes first gets the innermost block. A single flat "labs then pads"
  # nesting breaks as soon as a loop-exit label closes before a pad child.
  var events: seq[(bool, string)] = @[]        # (isPad, label)
  var scan = c
  scan.into:
    while scan.hasMore:
      if scan.stmtKind == LabS:
        var t = scan
        t.into:
          let nm = symName(t)
          if not g.p.labelDepth.hasKey(nm):
            events.add (false, nm)
          while t.hasMore: skip t
      else:
        let pl = landingPadLabel(scan)
        if pl.len > 0: events.add (true, pl)
      skip scan
  var padJoin = initTable[string, int]()
  for i in countdown(events.len - 1, 0):
    let (isPad, nm) = events[i]
    if isPad:
      g.op OpBlock; g.p.body.add BlockVoid     # $join
      inc g.p.depth
      padJoin[nm] = g.p.depth
      g.op OpBlock; g.p.body.add BlockVoid     # $L (jmp target)
      inc g.p.depth
      g.p.labelDepth[nm] = g.p.depth
    else:
      g.op OpBlock; g.p.body.add BlockVoid
      inc g.p.depth
      g.p.labelDepth[nm] = g.p.depth
  var t = c
  t.into:
    while t.hasMore:
      # sret temps allocated inside this statement are dead once it
      # completes — give their shadow-stack space back so loops don't creep
      let savedSret = g.p.dynSret
      let pl = landingPadLabel(t)
      if pl.len > 0 and padJoin.hasKey(pl):
        g.op OpBr                              # fallthrough skips the pad body
        g.emitU32 uint32(g.p.depth - padJoin[pl])
        var f = t
        f.into:                                # (if
          var e = f
          e.into:                              # (elif
            skip e                             # (false)
            genStmtList(g, e)                  # (stmts (lab L) …): lab closes $L
            skip e
            while e.hasMore: skip e
          skip f
          while f.hasMore: skip f
        g.op OpEnd                             # $join
        dec g.p.depth
        skip t
      else:
        genStmt(g, t)
      if g.p.dynSret > savedSret:
        restoreDynStack(g, g.p.dynSret - savedSret)
        g.p.dynSret = savedSret

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

  # fresh per-proc state. An aggregate result makes param 0 the hidden sret
  # destination pointer; declared params shift up by one.
  let retSret = not isVoidType(retType) and scalOf(g, retType).kind == skMem
  let paramBase = if retSret: 1 else: 0
  g.p = ProcCtx(retType: retType, retSret: retSret,
                nparams: params.len + paramBase)

  # address-taken analysis over the body
  var taken = initHashSet[string]()
  scanAddrTaken(body, taken)

  # params: wasm params are locals 0..n-1; an address-taken param is copied
  # into a frame slot at entry
  var frameOff = 0'i32
  var paramCopies: seq[(uint32, string)] = @[]
  for j, (pn, pt) in params:
    let i = j + paramBase
    let sc = scalOf(g, pt)
    g.p.symType[pn] = pt
    if sc.kind == skMem:
      # the wasm local holds the address of the caller-made copy; `(addr p)`
      # and field access both go through that address, no frame slot needed
      g.p.locals[pn] = RegLocal(idx: uint32(i), typ: pt, vt: ValI32)
    elif pn in taken:
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
  g.p.scratchI32 = uint32(g.p.nparams + g.p.localTypes.len)
  g.p.localTypes.add ValI32
  g.p.scratchI32b = uint32(g.p.nparams + g.p.localTypes.len)
  g.p.localTypes.add ValI32
  g.p.scratchI64 = uint32(g.p.nparams + g.p.localTypes.len)
  g.p.localTypes.add ValI64
  g.p.frameSize = int32(align(int(frameOff), 16))
  if g.p.frameSize > 0:
    g.p.fpIdx = uint32(g.p.nparams + g.p.localTypes.len)
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
    (locals: g.p.localTypes, nparams: g.p.nparams, code: g.p.body.data)

# ── module generation ────────────────────────────────────────────────────────

proc putLE(bytes: var string; off: int; v: uint64; width: int) =
  ## Write `width` little-endian bytes of `v` at `off`, zero-extending the
  ## buffer as needed.
  while bytes.len < off + width: bytes.add '\0'
  var x = v
  for i in 0 ..< width:
    bytes[off + i] = char(x and 0xFF)
    x = x shr 8

proc isAggregateGlobal(g: var WasmGen; nm: string): bool =
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

proc constScalarBits(g: var WasmGen; v: Cursor; ok: var bool): uint64 =
  ## The bit pattern of a compile-time scalar initializer value. Addresses
  ## (string literals, `(addr global)`, proc symbols → table slots) resolve
  ## to absolute numbers — ithaqua owns the memory layout, so no relocations
  ## are needed.
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
    of scProc: result = uint64(tableSlotOf(g, nm))
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
      # `(conv (u N) LIT)` — hexer wraps unsigned-typed literal gvar inits
      # like this. An integer conv of an integer literal is a bit
      # passthrough (putLE truncates to the declared width, which equals
      # the conv target for these). A float conv target is static only when
      # the operand is already a FloatLit (bits pass through; the f32 case
      # is re-narrowed by the caller) — int→float needs a conversion, so it
      # stays a runtime init.
      var t = v
      t.into:
        let floatTarget = t.kind == TagLit and t.typeKind == FT
        skip t                                 # the conv target type
        if floatTarget and t.kind != FloatLit:
          ok = false
          result = 0
        elif t.kind == Symbol and isAggregateGlobal(g, symName(t)):
          # C array decay: a cast of an AGGREGATE global (e.g. the vtable's
          # `(cast (ptr (u 32)) X.coro.dy.)` method-table chain) means its
          # ADDRESS — a link-time constant here, since ithaqua owns the
          # layout. A cast of a SCALAR global stays a runtime value copy.
          result = uint64(globalAddrOf(g, symName(t)))
        else:
          result = constScalarBits(g, t, ok)
        while t.hasMore: skip t
    of AddrC:
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
    else: ok = false
  else: ok = false

proc serializeConstInto(g: var WasmGen; bytes: var string; base: int;
                        typ, v: Cursor) =
  ## Serialize a compile-time aggregate/scalar initializer at `base` in
  ## `bytes` (offsets mirror the runtime layout queries; a flexarray tail
  ## takes string-literal payload verbatim, NUL-terminated).
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
            # flexarray tail: raw payload
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
      let elemT = innerType(g.prog, arrT)
      let (esz, _) = typeSizeAlign(g.prog, elemT)
      skip t
      var idx = 0
      while t.hasMore:
        serializeConstInto(g, bytes, base + idx * esz, elemT, t)
        skip t
        inc idx
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
  # a zero initializer needs no segment (wasm memory starts zeroed); runtime
  # initializers are the ini chain's job (skip them here, don't fail)
  if initv.kind == TagLit and initv.exprKind in {FalseC, NilC}: return
  if initv.kind == TagLit and initv.exprKind in {ConvC, CastC}:
    # static only when the operand is itself compile-time (see the ConvC arm
    # of constScalarBits); a conv of a global's value is the ini chain's job
    var t = initv
    var staticInner = false
    t.into:
      skip t                                   # the conv target type
      staticInner = t.kind in {IntLit, UIntLit, CharLit, FloatLit, StrLit} or
        (t.kind == TagLit and t.exprKind in {TrueC, FalseC, SufC, NegC})
      while t.hasMore: skip t
    if not staticInner: return
  elif initv.kind == TagLit and
     initv.exprKind notin {OconstrC, AconstrC, TrueC, SufC, ParC, AddrC, NegC}:
    return                                     # runtime-computed init
  if initv.kind == Symbol and
     lookupSym(typeCtx(g), symName(initv)).cat != scProc:
    return                                     # a value copy from another global: runtime init
  var bytes = ""
  serializeConstInto(g, bytes, 0, typ, initv)
  if bytes.len > 0:
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
    if sym == MemcmpSym:                       # synthetic: no Leng decl to read
      discard g.wm.addFunction(funcTypeIdx(g,
        @[ValI32, ValI32, ValI32], @[ValI32]))
      continue
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

  if getEnv("ITHAQUA_DEBUG").len > 0:
    for sym, fi in g.funcIdx:
      echo "func #", fi, " = ", sym
    for nm, a in g.globalAddr:
      echo "gvar @", a, " = ", nm
  if getEnv("ITHAQUA_EXPORT_ALL").len > 0:
    for sym, fi in g.funcIdx:
      g.wm.addExportFunc("dbg$" & sym, fi)     # debug: drive any proc from the host

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
