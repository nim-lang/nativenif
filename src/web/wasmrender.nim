#
#           The web back end — Leng → JavaScript / wasm32
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## The web IR → wasm32 renderer. No codegen logic lives here: it walks the
## `(top …)` tree `codegen` produced — the same tree `jsrender` prints as
## JavaScript — and encodes it as one self-contained wasm module through
## `wasmenc`.
##
## The tree is typed, so the rendering is mostly a direct transcription: a
## node's width picks the value type and the signed/unsigned opcode, a
## function's `(params …)`/`(locals …)` become wasm locals, `(label …)` and
## `(while …)` become `block`/`loop` with `br` depths counted from a control
## stack. Every expression is rendered AGAINST the type its position demands
## (`want`): a literal takes that type, a value of another type is a
## generator bug and refused by name, and a value in statement position is
## dropped. What wasm needs beyond the tree:
##
## - narrow integers (8/16 bit) keep a CANONICAL i32 form — sign- or
##   zero-extended per the width — so arithmetic that can leave the range
##   re-canonicalizes, exactly as the JS renderer's `<< 24 >> 24` does;
## - the shadow stack's pointer is the mutable global 0; `(frame N)` parks the
##   entry value in a hidden local that `(leave)` restores;
## - an `(icall …)` evaluates its target FIRST, as JS does, so a target with
##   effects goes through a scratch local (wasm wants it last on the stack);
## - the module owns the host contract: `env` imports (`nim_write`,
##   `nim_exit`, and the discovered host imports), the memory and table
##   exports, and `_start`, which runs `main` and hands its result to
##   `nim_exit` — the exit code of the native program — unless the module is
##   a host-driven library.

import std / [tables, strutils, assertions]
import nifcore
import webnif, wasmenc, diag

include compat2   # getOrQuit on host Nim

const
  PageSize = 65536

type
  VT = enum
    vtVoid, vtI32, vtI64, vtF32, vtF64,
    vtAny                          ## `unreachable`: fits every position

  FuncSig = object
    params: seq[VT]
    ret: VT

  CtlKind = enum ckBlock, ckLabel, ckLoopExit
  Ctl = object
    kind: CtlKind
    name: SymId

  WasmRender = object
    wm: WasmModule
    pool: Pool                     ## the tree's own pool: every name below is
                                   ## a `SymId` in it, never a rebuilt string
    funcIdx: Table[SymId, uint32]
    sigs: Table[SymId, FuncSig]
    globals: Table[SymId, (uint32, VT)]
    # the function being rendered
    fname: SymId
    locals: Table[SymId, (uint32, VT)]
    localTypes: seq[byte]          ## non-parameter locals, in index order
    nparams: int
    body: ByteBuf
    ctl: seq[Ctl]
    ret: VT
    savedSp: int                   ## hidden local: SP on entry (-1: none yet)
    frameTmp: int                  ## hidden local: the new frame base

const SpGlobal = 0'u32

proc err(r: WasmRender; msg: string) {.noreturn.} =
  ## The wasm renderer's half of the refusal channel — same contract as the
  ## generator's, see `diag.refuse`.
  refuse "wasm: " & msg &
    (if r.fname != SymId(0): " (in `" & poolSym(r.pool, r.fname) & "`)" else: "")

proc bigIntValue(digits: string): int64 =
  ## A `(bigint …)` payload: decimal digits spanning the WHOLE u64 range, which
  ## is why the IR carries them as text at all. Folded here rather than through
  ## `strutils` — its `parseBiggestUInt` is host-Nim only and its
  ## `parseBiggestInt` raises — and negated in u64 so `int64.low` survives the
  ## round trip.
  var mag = 0'u64
  let neg = digits.startsWith("-")
  for i in (if neg: 1 else: 0) ..< digits.len:
    mag = mag * 10'u64 + uint64(ord(digits[i]) - ord('0'))
  result = cast[int64](if neg: 0'u64 - mag else: mag)

proc vtOf(w: WidthCode): VT =
  case w
  of wI8, wU8, wI16, wU16, wI32, wU32: vtI32
  of wI64, wU64: vtI64
  of wF32: vtF32
  of wF64: vtF64

proc valType(vt: VT): byte =
  case vt
  of vtI32, vtVoid, vtAny: ValI32
  of vtI64: ValI64
  of vtF32: ValF32
  of vtF64: ValF64

# ── small cursor helpers ────────────────────────────────────────────────────

proc nameOf(r: WasmRender; c: Cursor): SymId =
  ## A name as its POOL ID. An `ident` (the JS bridge's raw names) is interned
  ## into the same pool, so label and callee lookups are integer compares.
  case c.kind
  of Symbol, SymbolDef: symId(c)
  of Ident, StrLit: r.pool.syms.getOrIncl(strVal(c))
  else: raiseAssert "wasmrender: name expected, got " & $c.kind

proc spell(r: WasmRender; id: SymId): string = poolSym(r.pool, id)

proc widthAt(c: Cursor): WidthCode =
  if c.kind != IntLit: raiseAssert "wasmrender: width expected, got " & $c.kind
  WidthCode(c.intVal)

proc firstWidth(c: Cursor): WidthCode = widthAt(c.sub())

proc pairWidths(c: Cursor): (WidthCode, WidthCode) =
  var it = c.sub()
  let src = widthAt(it)
  skip it
  result = (src, widthAt(it))

# ── emission helpers ────────────────────────────────────────────────────────

template op(r: var WasmRender; o: byte) = r.body.add o
proc u32(r: var WasmRender; x: uint32) = r.body.addU32 x
proc constI32(r: var WasmRender; v: int32) = (r.op OpI32Const; r.body.addI32 v)
proc constI64(r: var WasmRender; v: int64) = (r.op OpI64Const; r.body.addI64 v)
proc localGet(r: var WasmRender; i: uint32) = (r.op OpLocalGet; r.u32 i)
proc localSet(r: var WasmRender; i: uint32) = (r.op OpLocalSet; r.u32 i)
proc localTee(r: var WasmRender; i: uint32) = (r.op OpLocalTee; r.u32 i)

proc memArg(r: var WasmRender; bytes: int) =
  ## The alignment hint (log2 of the natural size) and offset 0 — addresses
  ## are computed explicitly. The hint is a promise the engine may use for
  ## speed, never for correctness.
  var a = 0
  var s = bytes
  while s > 1: (inc a; s = s shr 1)
  r.u32 uint32(a)
  r.u32 0

proc newLocal(r: var WasmRender; vt: VT): uint32 =
  result = uint32(r.nparams + r.localTypes.len)
  r.localTypes.add valType(vt)

proc canon(r: var WasmRender; w: WidthCode) =
  ## Re-canonicalize a narrow i32 value that may have left its range.
  case w
  of wI8: r.op OpI32Extend8S
  of wI16: r.op OpI32Extend16S
  of wU8: (r.constI32 0xFF; r.op OpI32And)
  of wU16: (r.constI32 0xFFFF; r.op OpI32And)
  else: discard

# ── typing ──────────────────────────────────────────────────────────────────

proc sigOfTree(c: Cursor): FuncSig =
  ## `(sig RET W*)`.
  result = default(FuncSig)
  var it = c.sub()
  result.ret = if it.kind == DotToken: vtVoid else: vtOf(widthAt(it))
  skip it
  while it.hasMore:
    result.params.add vtOf(widthAt(it))
    skip it

proc typeOf(r: WasmRender; c: Cursor): VT

proc lastChild(c: Cursor): Cursor =
  result = default(Cursor)
  var it = c.sub()
  while it.hasMore:
    result = it
    skip it

proc typeOf(r: WasmRender; c: Cursor): VT =
  ## The type an expression produces on its own — for a literal, its natural
  ## one. Only consulted where no position dictates the type (a condition, a
  ## statement), so a literal's default never overrides a context.
  case c.kind
  of IntLit, UIntLit, CharLit: return vtI32
  of FloatLit: return vtF64
  of Symbol, Ident:
    let n = nameOf(r, c)
    if r.locals.hasKey(n): return r.locals.getOrQuit(n)[1]
    if r.globals.hasKey(n): return r.globals.getOrQuit(n)[1]
    r.err "unknown name `" & r.spell(n) & "`"
  else: discard
  case webTagOf(c)
  of BigIntLit: vtI64
  of TrueLit, FalseLit: vtI32
  of NanLit, InfLit: vtF64
  of Call:
    let fn = nameOf(r, c.sub())
    if not r.sigs.hasKey(fn): r.err "call of unknown function `" & r.spell(fn) & "`"
    r.sigs.getOrQuit(fn).ret
  of ICall: sigOfTree(c.sub()).ret
  of Assign: typeOf(r, c.sub())
  of Cond:
    var it = c.sub()
    skip it
    typeOf(r, it)
  of Seq: typeOf(r, lastChild(c))
  of HLoad: vtOf(firstWidth(c))
  of HStore, MemCopy, MemFill: vtVoid
  of MemSize, MemGrow, Frame, Ctz, Clz, Popcnt: vtI32
  of Unreachable: vtAny
  of Add, Sub, Mul, Div, Mod, Shl, Shr, And, Or, Xor, Neg, BNot:
    vtOf(firstWidth(c))
  of LAnd, LOr, Not, Eq, Neq, Lt, Le, Gt, Ge: vtI32
  of Cvt, Reint: vtOf(pairWidths(c)[1])
  else:
    r.err "`" & $webTagOf(c) & "` is not a wasm expression"

# ── expressions ─────────────────────────────────────────────────────────────

proc genExpr(r: var WasmRender; c: Cursor; want: VT)
proc genStmt(r: var WasmRender; c: Cursor)

proc adapt(r: var WasmRender; have, want: VT; c: Cursor) =
  ## `have` is on the stack; the position wants `want`.
  if have == want or have == vtAny: return
  if want == vtVoid:
    r.op OpDrop
    return
  r.err "type mismatch: `" & $webTagOf(c) & "` yields " & $have & " where " &
        $want & " is wanted"

proc genCond(r: var WasmRender; c: Cursor) =
  ## A value as an i32 truth: non-zero is true, whatever its type.
  let t = typeOf(r, c)
  case t
  of vtI64:
    genExpr(r, c, vtI64)
    r.constI64 0
    r.op OpI64Ne
  of vtF32:
    genExpr(r, c, vtF32)
    r.op OpF32Const; r.body.addF32 0'f32
    r.op OpF32Ne
  of vtF64:
    genExpr(r, c, vtF64)
    r.op OpF64Const; r.body.addF64 0.0
    r.op OpF64Ne
  of vtAny:
    genExpr(r, c, vtAny)
  else:
    genExpr(r, c, vtI32)

proc intConst(r: var WasmRender; v: int64; want: VT; c: Cursor) =
  case want
  of vtVoid: discard
  of vtI32: r.constI32 cast[int32](uint32(cast[uint64](v) and 0xFFFF_FFFF'u64))
  of vtI64: r.constI64 v
  of vtF32: (r.op OpF32Const; r.body.addF32 float32(v))
  of vtF64: (r.op OpF64Const; r.body.addF64 float64(v))
  of vtAny: r.constI32 int32(v)

proc floatConst(r: var WasmRender; v: float64; want: VT; c: Cursor) =
  case want
  of vtVoid: discard
  of vtF32: (r.op OpF32Const; r.body.addF32 float32(v))
  of vtF64, vtAny: (r.op OpF64Const; r.body.addF64 v)
  else: r.err "a float literal where " & $want & " is wanted"

proc binOp(r: var WasmRender; tag: WebTag; w: WidthCode) =
  ## The opcode of `(tag w a b)` with both operands on the stack.
  let s = w.isSigned
  case vtOf(w)
  of vtI32:
    r.op(case tag
         of Add: OpI32Add
         of Sub: OpI32Sub
         of Mul: OpI32Mul
         of Div: (if s: OpI32DivS else: OpI32DivU)
         of Mod: (if s: OpI32RemS else: OpI32RemU)
         of Shl: OpI32Shl
         of Shr: (if s: OpI32ShrS else: OpI32ShrU)
         of And: OpI32And
         of Or: OpI32Or
         else: OpI32Xor)
    if tag in {Add, Sub, Mul, Div, Mod, Shl}: r.canon w
  of vtI64:
    r.op(case tag
         of Add: OpI64Add
         of Sub: OpI64Sub
         of Mul: OpI64Mul
         of Div: (if s: OpI64DivS else: OpI64DivU)
         of Mod: (if s: OpI64RemS else: OpI64RemU)
         of Shl: OpI64Shl
         of Shr: (if s: OpI64ShrS else: OpI64ShrU)
         of And: OpI64And
         of Or: OpI64Or
         else: OpI64Xor)
  of vtF32, vtF64:
    let base = if w == wF32: OpF32Add else: OpF64Add
    case tag
    of Add: r.op base
    of Sub: r.op byte(base + 1)
    of Mul: r.op byte(base + 2)
    of Div: r.op byte(base + 3)
    else: r.err "`" & $tag & "` has no wasm instruction for " & $w
  else: discard

proc cmpOp(r: var WasmRender; tag: WebTag; w: WidthCode) =
  let s = w.isSigned
  case vtOf(w)
  of vtI32:
    r.op(case tag
         of Eq: OpI32Eq
         of Neq: OpI32Ne
         of Lt: (if s: OpI32LtS else: OpI32LtU)
         of Le: (if s: OpI32LeS else: OpI32LeU)
         of Gt: (if s: OpI32GtS else: OpI32GtU)
         else: (if s: OpI32GeS else: OpI32GeU))
  of vtI64:
    r.op(case tag
         of Eq: OpI64Eq
         of Neq: OpI64Ne
         of Lt: (if s: OpI64LtS else: OpI64LtU)
         of Le: (if s: OpI64LeS else: OpI64LeU)
         of Gt: (if s: OpI64GtS else: OpI64GtU)
         else: (if s: OpI64GeS else: OpI64GeU))
  of vtF32:
    r.op(case tag
         of Eq: OpF32Eq
         of Neq: OpF32Ne
         of Lt: OpF32Lt
         of Le: OpF32Le
         of Gt: OpF32Gt
         else: OpF32Ge)
  of vtF64:
    r.op(case tag
         of Eq: OpF64Eq
         of Neq: OpF64Ne
         of Lt: OpF64Lt
         of Le: OpF64Le
         of Gt: OpF64Gt
         else: OpF64Ge)
  else: discard

proc convert(r: var WasmRender; fromW, toW: WidthCode) =
  ## `(cvt FROM TO v)` with v on the stack as FROM's value type. The same
  ## table the JS renderer spells with `Number`/`BigInt`/`Math.fround`: a
  ## narrowing re-canonicalizes, a widening extends by the SOURCE's
  ## signedness (a `cast` widening arrives with an unsigned FROM, which masks
  ## a narrow source first), and float → integer traps out of range.
  let f = vtOf(fromW)
  let t = vtOf(toW)
  case t
  of vtI32:
    case f
    of vtI32:
      if toW != fromW and widthBits(toW) < 32: r.canon toW
    of vtI64:
      r.op OpI32WrapI64
      r.canon toW
    of vtF32:
      r.op(if toW.isSigned: OpI32TruncF32S else: OpI32TruncF32U)
      r.canon toW
    of vtF64:
      r.op(if toW.isSigned: OpI32TruncF64S else: OpI32TruncF64U)
      r.canon toW
    else: discard
  of vtI64:
    case f
    of vtI32:
      case fromW
      of wU8: (r.constI32 0xFF; r.op OpI32And)
      of wU16: (r.constI32 0xFFFF; r.op OpI32And)
      else: discard
      r.op(if fromW.isSigned: OpI64ExtendI32S else: OpI64ExtendI32U)
    of vtF32: r.op(if toW.isSigned: OpI64TruncF32S else: OpI64TruncF32U)
    of vtF64: r.op(if toW.isSigned: OpI64TruncF64S else: OpI64TruncF64U)
    else: discard
  of vtF32:
    case f
    of vtI32: r.op(if fromW.isSigned: OpF32ConvertI32S else: OpF32ConvertI32U)
    of vtI64: r.op(if fromW.isSigned: OpF32ConvertI64S else: OpF32ConvertI64U)
    of vtF64: r.op OpF32DemoteF64
    else: discard
  of vtF64:
    case f
    of vtI32: r.op(if fromW.isSigned: OpF64ConvertI32S else: OpF64ConvertI32U)
    of vtI64: r.op(if fromW.isSigned: OpF64ConvertI64S else: OpF64ConvertI64U)
    of vtF32: r.op OpF64PromoteF32
    else: discard
  else: discard

proc isPure(c: Cursor): bool =
  ## An expression whose evaluation can move past others unobserved.
  case c.kind
  of IntLit, UIntLit, CharLit, FloatLit, Symbol, Ident: true
  else: false

proc genArgs(r: var WasmRender; it: var Cursor; params: seq[VT]; what: string) =
  var i = 0
  while it.hasMore:
    if i >= params.len:
      r.err what & " passes more arguments than its signature takes"
    genExpr(r, it, params[i])
    skip it
    inc i
  if i != params.len:
    r.err what & " passes " & $i & " arguments, its signature takes " & $params.len

proc genExpr(r: var WasmRender; c: Cursor; want: VT) =
  case c.kind
  of IntLit:
    intConst(r, intVal(c), want, c)
    return
  of UIntLit:
    intConst(r, cast[int64](uintVal(c)), want, c)
    return
  of CharLit:
    intConst(r, int64(ord(charLit(c))), want, c)
    return
  of FloatLit:
    if want in {vtI32, vtI64}: r.err "a float literal where " & $want & " is wanted"
    floatConst(r, floatVal(c), want, c)
    return
  of Symbol, Ident:
    let n = nameOf(r, c)
    if r.locals.hasKey(n):
      let (i, t) = r.locals.getOrQuit(n)
      if want != vtVoid:
        r.localGet i
        adapt(r, t, want, c)
    elif r.globals.hasKey(n):
      let (i, t) = r.globals.getOrQuit(n)
      if want != vtVoid:
        r.op OpGlobalGet; r.u32 i
        adapt(r, t, want, c)
    else:
      r.err "unknown name `" & r.spell(n) & "`"
    return
  else: discard
  let tag = webTagOf(c)
  case tag
  of BigIntLit:
    let digits = strVal(c.sub())
    let v = bigIntValue(digits)
    case want
    of vtVoid: discard
    of vtI64, vtAny: r.constI64 v
    of vtF64, vtF32: intConst(r, v, want, c)
    else: r.err "a 64-bit literal where " & $want & " is wanted"
  of TrueLit, FalseLit:
    intConst(r, (if tag == TrueLit: 1 else: 0), want, c)
  of NanLit: floatConst(r, NaN, want, c)
  of InfLit: floatConst(r, Inf, want, c)
  of Call:
    var it = c.sub()
    let fn = nameOf(r, it)
    skip it
    if not r.funcIdx.hasKey(fn):
      r.err "call of unknown function `" & r.spell(fn) & "`"
    let sig = r.sigs.getOrQuit(fn)
    genArgs(r, it, sig.params, "the call of `" & r.spell(fn) & "`")
    r.op OpCall
    r.u32 r.funcIdx.getOrQuit(fn)
    adapt(r, sig.ret, want, c)
  of ICall:
    var it = c.sub()
    let sig = sigOfTree(it)
    skip it
    let target = it
    skip it
    # JS evaluates the target before the arguments; wasm wants it last on the
    # stack. A target with effects is therefore computed into a scratch first.
    var scratch = -1
    if not isPure(target):
      genExpr(r, target, vtI32)
      scratch = int(newLocal(r, vtI32))
      r.localSet uint32(scratch)
    genArgs(r, it, sig.params, "an indirect call")
    if scratch >= 0: r.localGet uint32(scratch)
    else: genExpr(r, target, vtI32)
    var ps: seq[byte] = @[]
    for p in sig.params: ps.add valType(p)
    var rs: seq[byte] = @[]
    if sig.ret != vtVoid: rs.add valType(sig.ret)
    r.op OpCallIndirect
    r.u32 r.wm.addFuncType(ps, rs)
    r.u32 0                                    # table 0
    adapt(r, sig.ret, want, c)
  of Assign:
    var it = c.sub()
    let n = nameOf(r, it)
    skip it
    if r.locals.hasKey(n):
      let (i, t) = r.locals.getOrQuit(n)
      genExpr(r, it, t)
      if want == vtVoid: r.localSet i
      else:
        r.localTee i
        adapt(r, t, want, c)
    elif r.globals.hasKey(n):
      let (i, t) = r.globals.getOrQuit(n)
      genExpr(r, it, t)
      r.op OpGlobalSet; r.u32 i
      if want != vtVoid:
        r.op OpGlobalGet; r.u32 i
        adapt(r, t, want, c)
    else:
      r.err "assignment to unknown name `" & r.spell(n) & "`"
  of Cond:
    var it = c.sub()
    genCond(r, it)
    skip it
    r.op OpIf
    let bt = if want in {vtVoid, vtAny}: vtVoid else: want
    if bt == vtVoid: r.body.add BlockVoid else: r.body.add valType(bt)
    r.ctl.add Ctl(kind: ckBlock)
    genExpr(r, it, bt)
    skip it
    r.op OpElse
    genExpr(r, it, bt)
    r.op OpEnd
    discard r.ctl.pop()
  of Seq:
    var it = c.sub()
    while it.hasMore:
      var nx = it
      skip nx
      if nx.hasMore: genExpr(r, it, vtVoid)
      else: genExpr(r, it, want)
      it = nx
  of HLoad:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    genExpr(r, it, vtI32)
    case w
    of wI8: (r.op OpI32Load8S; r.memArg 1)
    of wU8: (r.op OpI32Load8U; r.memArg 1)
    of wI16: (r.op OpI32Load16S; r.memArg 2)
    of wU16: (r.op OpI32Load16U; r.memArg 2)
    of wI32, wU32: (r.op OpI32Load; r.memArg 4)
    of wI64, wU64: (r.op OpI64Load; r.memArg 8)
    of wF32: (r.op OpF32Load; r.memArg 4)
    of wF64: (r.op OpF64Load; r.memArg 8)
    adapt(r, vtOf(w), want, c)
  of HStore:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    genExpr(r, it, vtI32)
    skip it
    genExpr(r, it, vtOf(w))
    case w
    of wI8, wU8: (r.op OpI32Store8; r.memArg 1)
    of wI16, wU16: (r.op OpI32Store16; r.memArg 2)
    of wI32, wU32: (r.op OpI32Store; r.memArg 4)
    of wI64, wU64: (r.op OpI64Store; r.memArg 8)
    of wF32: (r.op OpF32Store; r.memArg 4)
    of wF64: (r.op OpF64Store; r.memArg 8)
    adapt(r, vtVoid, want, c)
  of MemCopy, MemFill:
    var it = c.sub()
    for _ in 0 ..< 3:
      genExpr(r, it, vtI32)
      skip it
    r.op 0xFC'u8
    if tag == MemCopy:
      r.u32 10; r.u32 0; r.u32 0              # memory.copy 0 0
    else:
      r.u32 11; r.u32 0                       # memory.fill 0
    adapt(r, vtVoid, want, c)
  of MemSize:
    r.op OpMemorySize; r.body.add 0'u8
    adapt(r, vtI32, want, c)
  of MemGrow:
    genExpr(r, c.sub(), vtI32)
    r.op OpMemoryGrow; r.body.add 0'u8
    adapt(r, vtI32, want, c)
  of Frame:
    # Push an N-byte frame: the entry SP is parked for `(leave)`, the new base
    # is the value. N is a multiple of 16 and so is every SP, so the base stays
    # 16-aligned without masking.
    let n = intVal(c.sub())
    if r.savedSp < 0: r.savedSp = int(newLocal(r, vtI32))
    if r.frameTmp < 0: r.frameTmp = int(newLocal(r, vtI32))
    r.op OpGlobalGet; r.u32 SpGlobal
    r.localTee uint32(r.savedSp)
    r.constI32 int32(n)
    r.op OpI32Sub
    r.localTee uint32(r.frameTmp)
    r.op OpGlobalSet; r.u32 SpGlobal
    r.localGet uint32(r.frameTmp)
    adapt(r, vtI32, want, c)
  of Ctz, Clz, Popcnt:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    if w.isBig:
      genExpr(r, it, vtI64)
      r.op(case tag
           of Ctz: OpI64Ctz
           of Clz: OpI64Clz
           else: OpI64Popcnt)
      r.op OpI32WrapI64
    else:
      genExpr(r, it, vtI32)
      r.op(case tag
           of Ctz: OpI32Ctz
           of Clz: OpI32Clz
           else: OpI32Popcnt)
    adapt(r, vtI32, want, c)
  of Unreachable:
    r.op OpUnreachable
  of Add, Sub, Mul, Div, Mod, Shl, Shr, And, Or, Xor:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    let t = vtOf(w)
    genExpr(r, it, t)
    skip it
    genExpr(r, it, t)
    binOp(r, tag, w)
    adapt(r, t, want, c)
  of Neg, BNot:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    let t = vtOf(w)
    case t
    of vtF32, vtF64:
      if tag == BNot: r.err "bitwise not of a float"
      genExpr(r, it, t)
      r.op(if t == vtF32: OpF32Neg else: OpF64Neg)
    of vtI64:
      if tag == Neg:
        r.constI64 0
        genExpr(r, it, t)
        r.op OpI64Sub
      else:
        genExpr(r, it, t)
        r.constI64 -1
        r.op OpI64Xor
    else:
      if tag == Neg:
        r.constI32 0
        genExpr(r, it, t)
        r.op OpI32Sub
      else:
        genExpr(r, it, t)
        r.constI32 -1
        r.op OpI32Xor
      r.canon w
    adapt(r, t, want, c)
  of Not:
    var it = c.sub()
    skip it                                    # the vacuous width
    genCond(r, it)
    r.op OpI32Eqz
    adapt(r, vtI32, want, c)
  of LAnd, LOr:
    # C's `&&`/`||`: the right-hand side runs only when it decides.
    var it = c.sub()
    skip it                                    # the vacuous width
    genCond(r, it)
    skip it
    r.op OpIf; r.body.add ValI32
    r.ctl.add Ctl(kind: ckBlock)
    if tag == LAnd:
      genCond(r, it)                           # a && b: if a then (b != 0) else 0
      r.op OpElse
      r.constI32 0
    else:
      r.constI32 1
      r.op OpElse
      genCond(r, it)
    r.op OpEnd
    discard r.ctl.pop()
    adapt(r, vtI32, want, c)
  of Eq, Neq, Lt, Le, Gt, Ge:
    var it = c.sub()
    let w = widthAt(it)
    skip it
    genExpr(r, it, vtOf(w))
    skip it
    genExpr(r, it, vtOf(w))
    cmpOp(r, tag, w)
    adapt(r, vtI32, want, c)
  of Cvt:
    let (fromW, toW) = pairWidths(c)
    var it = c.sub()
    skip it
    skip it
    genExpr(r, it, vtOf(fromW))
    convert(r, fromW, toW)
    adapt(r, vtOf(toW), want, c)
  of Reint:
    let (fromW, toW) = pairWidths(c)
    var it = c.sub()
    skip it
    skip it
    genExpr(r, it, vtOf(fromW))
    case fromW
    of wF64: r.op OpI64ReinterpretF64
    of wF32: r.op OpI32ReinterpretF32
    of wI64, wU64: r.op OpF64ReinterpretI64
    of wI32, wU32: r.op OpF32ReinterpretI32
    else: r.err "cannot reinterpret " & $fromW & " as " & $toW
    adapt(r, vtOf(toW), want, c)
  of Index, Arrow, EWrap, EUnwrap, EStrLit, Raw:
    r.err "`" & $tag & "` is part of the JavaScript bridge (`importjs`)"
  else:
    r.err "`" & $tag & "` is not an expression"

# ── statements ──────────────────────────────────────────────────────────────

proc genStmts(r: var WasmRender; it: var Cursor) =
  while it.hasMore:
    genStmt(r, it)
    skip it

proc depthOf(r: WasmRender; name: SymId; unnamed: bool): uint32 =
  ## The `br` depth of the innermost matching control entry.
  for i in countdown(r.ctl.high, 0):
    let e = r.ctl[i]
    if (unnamed and e.kind == ckLoopExit) or
       (not unnamed and e.kind == ckLabel and e.name == name):
      return uint32(r.ctl.high - i)
  r.err (if unnamed: "`break` outside a loop"
         else: "`break " & r.spell(name) & "` outside its label")

proc genStmt(r: var WasmRender; c: Cursor) =
  if c.kind == DotToken: return
  let tag = webTagOf(c)
  case tag
  of ExprStmt:
    genExpr(r, c.sub(), vtVoid)
  of Block:
    var it = c.sub()
    genStmts(r, it)
  of Label:
    var it = c.sub()
    let n = nameOf(r, it)
    skip it
    r.op OpBlock; r.body.add BlockVoid
    r.ctl.add Ctl(kind: ckLabel, name: n)
    genStmts(r, it)
    r.op OpEnd
    discard r.ctl.pop()
  of Break:
    let it = c.sub()
    let unnamed = not it.hasMore
    let d = depthOf(r, (if unnamed: SymId(0) else: nameOf(r, it)), unnamed)
    r.op OpBr
    r.u32 d
  of If:
    var it = c.sub()
    genCond(r, it)
    skip it
    r.op OpIf; r.body.add BlockVoid
    r.ctl.add Ctl(kind: ckBlock)
    while it.hasMore and webTagOf(it) != Else:
      genStmt(r, it)
      skip it
    if it.hasMore:
      r.op OpElse
      var e = it.sub()
      genStmts(r, e)
    r.op OpEnd
    discard r.ctl.pop()
  of While:
    # block { loop { cond eqz br_if 1; body; br 0 } }
    var it = c.sub()
    r.op OpBlock; r.body.add BlockVoid
    r.ctl.add Ctl(kind: ckLoopExit)
    r.op OpLoop; r.body.add BlockVoid
    r.ctl.add Ctl(kind: ckBlock)
    if webTagOf(it) != TrueLit:
      genCond(r, it)
      r.op OpI32Eqz
      r.op OpBrIf; r.u32 1
    skip it
    genStmts(r, it)
    r.op OpBr; r.u32 0
    r.op OpEnd
    discard r.ctl.pop()
    r.op OpEnd
    discard r.ctl.pop()
  of Return:
    let it = c.sub()
    if it.hasMore:
      if r.ret == vtVoid: r.err "`return` of a value from a void function"
      genExpr(r, it, r.ret)
    elif r.ret != vtVoid:
      r.err "`return` without the value the function declares"
    r.op OpReturn
  of Leave:
    if r.savedSp < 0: r.err "`leave` without a `frame`"
    r.localGet uint32(r.savedSp)
    r.op OpGlobalSet; r.u32 SpGlobal
  else:
    r.err "`" & $tag & "` is not a statement"

# ── functions and the module ────────────────────────────────────────────────

proc funcHeader(r: WasmRender; c: Cursor; name: var SymId; sig: var FuncSig) =
  var it = c.sub()
  name = nameOf(r, it)
  skip it
  var ps = it.sub()
  while ps.hasMore:
    var p = ps.sub()
    skip p
    sig.params.add vtOf(widthAt(p))
    skip ps
  skip it
  sig.ret = if it.kind == DotToken: vtVoid else: vtOf(widthAt(it))

proc genFunc(r: var WasmRender; c: Cursor) =
  var it = c.sub()
  r.fname = nameOf(r, it)
  skip it
  r.locals = initTable[SymId, (uint32, VT)]()
  r.localTypes = @[]
  r.body = ByteBuf()
  r.ctl = @[]
  r.savedSp = -1
  r.frameTmp = -1
  r.nparams = 0
  var ps = it.sub()
  while ps.hasMore:
    var p = ps.sub()
    let n = nameOf(r, p)
    skip p
    r.locals[n] = (uint32(r.nparams), vtOf(widthAt(p)))
    inc r.nparams
    skip ps
  skip it
  r.ret = if it.kind == DotToken: vtVoid else: vtOf(widthAt(it))
  skip it
  var ls = it.sub()
  while ls.hasMore:
    var p = ls.sub()
    let n = nameOf(r, p)
    skip p
    let t = vtOf(widthAt(p))
    r.locals[n] = (newLocal(r, t), t)
    skip ls
  skip it
  genStmts(r, it)
  # A value-returning function must have returned already; wasm still wants
  # the body to type as the result.
  if r.ret != vtVoid: r.op OpUnreachable
  var decls: seq[(uint32, byte)] = @[]
  for vt in r.localTypes:
    if decls.len > 0 and decls[^1][1] == vt: inc decls[^1][0]
    else: decls.add (1'u32, vt)
  r.wm.addCode(decls, r.body.data)
  r.fname = SymId(0)

proc sigTypes(sig: FuncSig): (seq[byte], seq[byte]) =
  var ps: seq[byte] = @[]
  var rs: seq[byte] = @[]
  for p in sig.params: ps.add valType(p)
  if sig.ret != vtVoid: rs.add valType(sig.ret)
  result = (ps, rs)

proc renderWasm*(tree: var TokenBuf; m: WebModule; stackBytes: int;
                 exportAll = false): seq[byte] =
  ## The whole program as one wasm32 module.
  var r = WasmRender(savedSp: -1, frameTmp: -1, pool: tree.pool)
  # The module's own names arrive as text (a renderer prints them); they are
  # interned ONCE here, into the tree's pool, and matched as ids from then on.
  template id(name: string): SymId = r.pool.syms.getOrIncl(name)
  # imports pin the low function indices
  for imp in m.imports:
    var sig = FuncSig(ret: if imp.hasRet: vtOf(imp.ret) else: vtVoid)
    for w in imp.params: sig.params.add vtOf(w)
    let (ps, rs) = sigTypes(sig)
    r.funcIdx[id imp.name] = r.wm.addImportFunc("env", imp.name,
                                                r.wm.addFuncType(ps, rs))
    r.sigs[id imp.name] = sig
  # every function is declared before any body is rendered: calls go forward
  var root = beginRead(tree)
  if webTagOf(root) != Top: raiseAssert "wasmrender: expects a `top` root"
  var it = root.sub()
  var order: seq[SymId] = @[]
  while it.hasMore:
    if webTagOf(it) != Func: raiseAssert "wasmrender: `top` holds functions only"
    var name = SymId(0)
    var sig = default(FuncSig)
    funcHeader(r, it, name, sig)
    let (ps, rs) = sigTypes(sig)
    r.funcIdx[name] = r.wm.addFunction(r.wm.addFuncType(ps, rs))
    r.sigs[name] = sig
    order.add name
    skip it
  # a slot nobody bound traps when called — as a null slot does
  var unbound = -1
  for slot in 1 ..< m.table.len:
    if m.table[slot].len == 0 or not r.funcIdx.hasKey(id m.table[slot]):
      unbound = int(r.wm.addFunction(r.wm.addFuncType(newSeq[byte](), newSeq[byte]())))
      break
  let startFi = r.wm.addFunction(r.wm.addFuncType(newSeq[byte](), newSeq[byte]()))
  # globals: the shadow stack pointer, then the module's scalar globals
  let stackBase = (m.memTop + 15'u32) and not 15'u32
  let stackTop = stackBase + uint32(stackBytes)
  var spInit = ByteBuf()
  spInit.add OpI32Const
  spInit.addI32 cast[int32](stackTop)
  discard r.wm.addGlobal(ValI32, mutable = true, spInit.data)
  for (n, w) in m.globals:
    var z = ByteBuf()
    case vtOf(w)
    of vtI64: (z.add OpI64Const; z.addI64 0)
    of vtF32: (z.add OpF32Const; z.addF32 0'f32)
    of vtF64: (z.add OpF64Const; z.addF64 0.0)
    else: (z.add OpI32Const; z.addI32 0)
    r.globals[id n] = (r.wm.addGlobal(valType(vtOf(w)), mutable = true, z.data),
                       vtOf(w))
  # bodies, in declaration order
  it = root.sub()
  while it.hasMore:
    genFunc(r, it)
    skip it
  if unbound >= 0:
    r.wm.addCode(newSeq[(uint32, byte)](), [OpUnreachable])
  # _start: call the entry with a zero for every parameter; its result is the
  # exit code, as a native `main`'s is — unless the module is a library the
  # host drives through its exports, which must not exit.
  var sb = ByteBuf()
  for w in m.entryParams:
    case vtOf(w)
    of vtI64: (sb.add OpI64Const; sb.addI64 0)
    of vtF32: (sb.add OpF32Const; sb.addF32 0'f32)
    of vtF64: (sb.add OpF64Const; sb.addF64 0.0)
    else: (sb.add OpI32Const; sb.addI32 0)
  sb.add OpCall
  sb.addU32 r.funcIdx.getOrQuit(id m.entry)
  if m.entryHasRet:
    if m.exports.len > 0:
      sb.add OpDrop
    else:
      case vtOf(m.entryRet)
      of vtI64: sb.add OpI32WrapI64
      of vtF32: sb.add OpI32TruncF32S
      of vtF64: sb.add OpI32TruncF64S
      else: discard
      sb.add OpCall
      sb.addU32 r.funcIdx.getOrQuit(id m.imports[1].name)   # nim_exit
  r.wm.addCode(newSeq[(uint32, byte)](), sb.data)
  # the image
  for (a, s) in m.dataSegs:
    var bytes = newSeq[byte](s.len)
    for i, ch in s: bytes[i] = byte(ch)
    r.wm.addData(cast[int32](a), bytes)
  # the function table — always present, since `call_indirect` can be
  # emitted through a fn-ptr that only ever holds null; slot 0 is null
  discard r.wm.addTable(uint32(max(m.table.len, 1)))
  if m.table.len > 1:
    var elems: seq[uint32] = @[]
    for slot in 1 ..< m.table.len:
      let f = m.table[slot]
      elems.add(if f.len > 0 and r.funcIdx.hasKey(id f): r.funcIdx.getOrQuit(id f)
                else: uint32(unbound))
    r.wm.addElem(1, elems)
  let pages = (stackTop + uint32(PageSize) - 1) div uint32(PageSize) + 1
  r.wm.addMemory(pages)
  r.wm.addExportFunc("_start", startFi)
  r.wm.addExportMemory("memory", 0)
  r.wm.addExportTable("table", 0)              # JS bridge: callbacks call back
                                               # into wasm via table.get(slot)
  for (cName, f) in m.exports:
    r.wm.addExportFunc(cName, r.funcIdx.getOrQuit(id f))
  if exportAll:
    for f in order:
      r.wm.addExportFunc("dbg$" & r.spell(f), r.funcIdx.getOrQuit(f))
  result = encode(r.wm)
