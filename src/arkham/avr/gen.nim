#
#           Arkham — the AVR value core: expressions, statements, frames
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## **A destination-passing walker, not a fused decide-and-emit.** The other two
## backends thread a `Location` constraint through the walk and resolve it
## against each expression, which buys store forwarding, in-place immediates and
## register-level fusion. This one takes a concrete pair and materializes into
## it.
##
## That is a deliberate trade, not a stub. The fused core is four thousand lines
## whose register-binding protocol has a formal model behind it, and the machine
## it would be buying code quality for has 32 KB of flash and no pipeline to
## speak of. What matters here is that the answer is right and that every gap is
## a diagnostic. The optimizations are recoverable later; a wrong 16-bit carry is
## not.
##
## **Totality without a spiller.** An operand that has to be computed rather than
## read is parked in a frame slot the emitter mints, so the register demand of a
## nested expression is constant: the destination, plus the staging bridge for
## the one operand being loaded. That is why this core cannot run out of
## registers, and why it needs none of the reserve/steal machinery the fused one
## has.
##
## Three registers are the emitter's, never the allocator's:
##
##  * `StagingBridge` (X) loads an operand out of memory, and is live for one
##    instruction pair. **Never a destination** — that is the invariant the whole
##    scheme rests on.
##  * `ValueBridge` (r17:r16) is where a value is produced when its home is
##    memory, and the accumulator of the multiply.
##  * `ProduceBridge` (Z) is the indirect-call target and the flash pointer.

import std / [tables]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, regbind, diag, mirrors, analyser]
import machine
import emit

proc emitValue(g: var CodeGen; c: Cursor; dst: Reg)
proc genStmt(g: var CodeGen; c: Cursor)
proc emitCall(g: var CodeGen; c: Cursor; dst: Reg; wantResult: bool;
              aggrDst = "")


var gRetAggrSlot = ""
  ## The frame slot holding this proc's hidden result pointer, or empty. A
  ## module-level `var` rather than a `CodeGen` field: `CodeGen` is shared with
  ## three other backends that have no such thing, and arkham compiles one proc
  ## at a time — the reasoning `gArkhamCurProc` already rests on.

template retAggrSlot(g: CodeGen): string = gRetAggrSlot

proc refuse(c: Cursor; what: string) {.noreturn.} =
  lengError c, "AVR: " & what & " is not implemented yet " &
               "(see doc/internals/avr.md)", lengInfo(c)

# ── minted slots ────────────────────────────────────────────────────────────

proc checkWidth(g: var CodeGen; typeCur: Cursor; what: string) =
  ## A value wider than a pair does not fit anything this core emits, and every
  ## load and store below moves exactly two bytes — so a 32-bit local would be
  ## silently truncated rather than rejected. Refuse it by name instead.
  var t = typeCur
  let s = typeToSlot(t)
  if s.cls == AFloat:
    lengError typeCur, "AVR: " & what & " is a float; this target has no FPU " &
              "and no softfloat library", lengInfo(typeCur)
  if s.cls == AMem:
    # An aggregate lives in a frame slot sized by its own type and is never in a
    # pair, so the width check below does not apply to it.
    return
  if s.size > 2:
    lengError typeCur, "AVR: " & what & " is " & $(s.size * 8) & " bits wide; " &
              "this backend's word is 16 and a wider value is not truncated " &
              "silently (see M5 in doc/internals/avr.md)", lengInfo(typeCur)

proc refuseAggr(g: var CodeGen; c: Cursor; what: string) =
  ## An aggregate where only a SCALAR is handled. This has to be a refusal and
  ## not a silent partial job: a struct copy, a struct argument and a struct
  ## return all look like ordinary moves to a value core that only knows how to
  ## move one word, so the answer comes out WRONG rather than missing. Ten
  ## fixtures did exactly that before this check existed.
  if g.exprSlot(c).cls == AMem:
    lengError c, "AVR: " & what & " is an aggregate — copying, passing and " &
              "returning one are not implemented yet (see M5 in " &
              "doc/internals/avr.md)", lengInfo(c)

proc mintSlot(g: var CodeGen; c: Cursor): string =
  ## A frame slot for one parked operand. Declared where it is used: nifasm
  ## assigns the offset, and `(scope …)` is not needed because these never
  ## outlive the expression that minted them — the next one reuses the space only
  ## if the assembler chooses to, and correctness does not depend on it.
  inc g.emitTmpSpills
  result = SynthMark & "etmp" & $g.emitTmpSpills & ".0"
  g.ab.open NifasmDecl.VarD
  g.ab.symDef result
  g.ab.keyword SO
  g.ab.intType 16
  g.ab.close()

# ── how the second operand of a binary op is supplied ───────────────────────

type
  BKind = enum
    bkImm      ## a constant: rides in the instruction where a form exists
    bkReg      ## already in a pair that the destination does not alias
    bkSlot     ## in memory: loaded into the staging bridge at the point of use

  BPlan = object
    kind: BKind
    imm: int64
    r: Reg
    slot: string

proc classifyB(g: var CodeGen; c: Cursor; dst: Reg): BPlan =
  ## Decide where the second operand will come from, and PARK it now if that
  ## takes work. Parking happens before the first operand is emitted, because
  ## both want the destination.
  ##
  ## The `home.r == dst` case is the one that is easy to get wrong: `x - y` with
  ## the destination already being `y`'s home would compute `x` into `y` and then
  ## subtract the result from itself. It parks.
  case c.kind
  of IntLit:
    return BPlan(kind: bkImm, imm: intVal(c))
  of UIntLit:
    return BPlan(kind: bkImm, imm: cast[int64](uintVal(c)))
  of CharLit:
    return BPlan(kind: bkImm, imm: int64(ord(charLit(c))))
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == InReg and home.r != dst:
      return BPlan(kind: bkReg, r: home.r)
    if home.kind == NamedStack:
      return BPlan(kind: bkSlot, slot: home.name)
  else: discard
  # Anything else — a nested expression, or a local whose home IS the
  # destination — is computed into the destination and parked.
  # Into the value BRIDGE, not into `dst`. `dst` is very often a local's home —
  # `x = x + f(5)` computes into `x`'s pair — and parking there destroys that
  # local BEFORE the first operand is read, which then reads the parked value
  # instead of itself. A bridge is scratch and belongs to nobody.
  let parkReg = if dst == ValueBridge: dst else: ValueBridge
  let slot = g.mintSlot(c)
  g.emitValue(c, parkReg)
  g.emStoreSlot(slot, parkReg)
  BPlan(kind: bkSlot, slot: slot)

proc materializeB(g: var CodeGen; p: BPlan): Reg =
  ## Bring the operand into a pair, AFTER the first operand has been emitted —
  ## the staging bridge is only free once that walk is finished.
  case p.kind
  of bkReg: p.r
  of bkSlot:
    g.emLoadSlot(StagingBridge, p.slot)
    StagingBridge
  of bkImm:
    g.emLdi16(StagingBridge, p.imm)
    StagingBridge

# ── conditions ──────────────────────────────────────────────────────────────

proc isSignedCmp(g: var CodeGen; c: Cursor): bool =
  ## The comparison's SIGNEDNESS, read off the operand type the node carries. It
  ## decides between two different instructions here — an unsigned `<` leaves its
  ## answer in the carry and a signed one in S — so guessing is not available.
  var t = c
  inc t                       # into the node, at the operand type
  let s = typeToSlot(t)
  result = s.cls != AUInt

proc cmpBranchOf(g: var CodeGen; c: Cursor; signed: bool):
    tuple[cond: AvrCond; swap: bool] =
  ## The branch that HOLDS when the comparison is true, and whether its operands
  ## must be exchanged first.
  ##
  ## `<=` and `>` have no branch of their own on this machine: every branch tests
  ## one status bit, and "less or equal" is two. `a <= b` is `not (b < a)`, so it
  ## is the `>=` branch with the operands the other way round — which costs
  ## nothing, because the exchange happens while deciding, not while running.
  case c.exprKind
  of EqC: (acEq, false)
  of NeqC: (acNe, false)
  of LtC: ((if signed: acLt else: acLo), false)
  of LeC: ((if signed: acGe else: acHs), true)
  else:
    refuse(c, "the comparison `" & $c.exprKind & "`")

proc emitCmpFlags(g: var CodeGen; c: Cursor; dst: Reg): AvrCond =
  ## Emit the compare, leaving the answer in the flags and `dst` clobbered.
  ## Returns the branch that holds when the comparison is true.
  let signed = g.isSignedCmp(c)
  let (cond, swap) = g.cmpBranchOf(c, signed)
  var a = c
  inc a; skip a               # into the node, past the operand type
  var b = a; skip b
  let lhs = if swap: b else: a
  let rhs = if swap: a else: b
  let plan = g.classifyB(rhs, dst)
  g.emitValue(lhs, dst)
  if plan.kind == bkImm and ldiOk(dst) and
     (plan.imm and 0xFFFF) == (plan.imm and 0xFF) and plan.imm >= 0:
    discard g.emCmpImm16(dst, plan.imm)
  else:
    let br = g.materializeB(plan)
    g.emCmp16(dst, br)
  result = cond

proc emitCond(g: var CodeGen; c: Cursor; target: string; whenTrue: bool) =
  ## Branch to `target` when `c` is true (or false), WITHOUT materializing a
  ## bool. A comparison lands straight in the flags, which is the one fusion this
  ## core does keep: it is not an optimization here but the natural shape, since
  ## the compare has to happen either way.
  case c.exprKind
  of EqC, NeqC, LtC, LeC:
    let cond = g.emitCmpFlags(c, ValueBridge)
    g.emBranch((if whenTrue: cond else: invert(cond)), target)
  of NotC:
    var inner = c
    inc inner
    g.emitCond(inner, target, not whenTrue)
  of TrueC:
    if whenTrue: g.emJmp(target)
  of FalseC:
    if not whenTrue: g.emJmp(target)
  else:
    # An ordinary bool value: materialize it and test it against zero. `or` of a
    # pair with itself sets Z from all sixteen bits at once, which is cheaper
    # than a compare against a constant that would need `ldi`-capability.
    g.emitValue(c, ValueBridge)
    g.ab.tree OrAvr: (g.emLo ValueBridge; g.emHi ValueBridge)
    g.emBranch((if whenTrue: acNe else: acEq), target)

# ── lvalues ─────────────────────────────────────────────────────────────────

type
  LvalKind = enum
    lvReg, lvSlot, lvPtr
    lvNode       ## a `(dot …)`/`(at …)` node, handed to nifasm to fold

  Lval = object
    kind: LvalKind
    r: Reg
    slot: string
    off: int
    node: Cursor
    width: int

proc accessWidth(g: var CodeGen; c: Cursor): int =
  ## How wide the access at `c` is, read off the EXPRESSION's own type rather
  ## than its operand's: `(deref p)` is a T, not a `ptr T`.
  let s = g.exprSlot(c)
  if s.size <= 0 or s.size > 2: 2 else: s.size

proc isPow2(n: int): bool {.inline.} = n > 0 and (n and (n - 1)) == 0

proc log2i(n: int): int =
  var w = n
  while w > 1: (w = w shr 1; inc result)

proc scaledIndex(g: var CodeGen; p: BPlan; elemW: int): Reg =
  ## The index, scaled by the element size and left in the staging bridge.
  ## `materializeB` may hand back a local's HOME pair, and shifting that in place
  ## would destroy the local.
  ##
  ## The stride is NOT always a power of two — an array of three-word structs
  ## strides by six — and shifting by `log2` of that quietly multiplies by four,
  ## which is a wrong answer rather than a crash.
  result = g.materializeB(p)
  if elemW <= 1: return
  if result != StagingBridge:
    g.emMovw(StagingBridge, result)
    result = StagingBridge
  if isPow2(elemW):
    g.emShl16(result, log2i(elemW))
  else:
    # A real multiply. Its accumulator is the value bridge, so the stride goes
    # into the produce bridge — free here, since nothing is being addressed yet.
    g.emLdi16(ProduceBridge, int64(elemW))
    g.emMul16(result, ProduceBridge)

proc strideOf(g: var CodeGen; c: Cursor): int =
  ## The size of what `c` denotes, UNCLAMPED. `accessWidth` caps at a pair
  ## because it sizes a load; a stride must not be capped, or an array of
  ## two-word rows indexes by one word.
  let s = g.exprSlot(c)
  if s.size <= 0: 2 else: s.size

proc emitAddrOf(g: var CodeGen; c: Cursor; dst: Reg)

proc emitIndexedAddr(g: var CodeGen; c: Cursor; dst: Reg) =
  ## The address of `(at base idx)` with a COMPUTED index. One procedure rather
  ## than three copies, because the ordering is what goes wrong: the base address
  ## and the scaled index are both live at the add, and a non-power-of-two stride
  ## needs the multiply's own registers in between.
  let stride = g.strideOf(c)
  var base = c; inc base
  var idx = base; skip idx
  g.emitAddrOf(base, dst)
  if isPow2(stride):
    let plan = g.classifyB(idx, dst)
    let ir = g.scaledIndex(plan, stride)
    g.emBin16(boAdd, dst, ir)
    return
  let addrSlot = g.mintSlot(c)
  g.emStoreSlot(addrSlot, dst)
  let plan = g.classifyB(idx, dst)
  var ir = g.scaledIndex(plan, stride)
  if ir == dst:
    g.emMovw(ProduceBridge, ir)
    ir = ProduceBridge
  g.emLoadSlot(dst, addrSlot)
  g.emBin16(boAdd, dst, ir)

proc emitAddrOf(g: var CodeGen; c: Cursor; dst: Reg) =
  ## The ADDRESS of an lvalue, in a pair.
  ##
  ## The recursive cases are the point: `(at (at m i) j)` asks for the address of
  ## an inner ROW, and falling back to `emitValue` there would LOAD the row's
  ## first word and use it as a pointer.
  if c.kind == Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == NamedStack:
      g.emLeaSlot(dst, home.name)
      return
    if home.kind == InReg:
      g.emMovw(dst, home.r)                 # already a pointer VALUE
      return
    refuse(c, "the address of `" & symName(c) & "`")
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      g.emLeaNode(dst, c)
      return
    of AtC:
      var idx = c; inc idx; skip idx
      if idx.kind in {IntLit, UIntLit}:
        g.emLeaNode(dst, c)
        return
      g.emitIndexedAddr(c, dst)
      return
    of DerefC, HaddrC:
      var v = c; inc v
      g.emitValue(v, dst)                   # the pointer IS the address
      return
    else: discard
  g.emitValue(c, dst)

proc emitLval(g: var CodeGen; c: Cursor; scratch: Reg): Lval =
  case c.kind
  of Symbol:
    let name = symName(c)
    let home = g.plan.locationOfSym(name, cursorToPosition(g.buf[], c))
    case home.kind
    of InReg:
      # A register-homed AGGREGATE is not the aggregate: it is a POINTER to one.
      # The allocator only gives an aggregate a pair when Leng passed it by
      # reference, which it does above `aggrByRefThreshold`.
      if g.exprSlot(c).cls == AMem: Lval(kind: lvPtr, r: home.r, off: 0, width: 1)
      else: Lval(kind: lvReg, r: home.r)
    of NamedStack: Lval(kind: lvSlot, slot: home.name)
    else: refuse(c, "a store to `" & name & "`, whose location is " & $home.kind)
  of TagLit:
    case c.exprKind
    of DerefC, HaddrC:
      let w = g.accessWidth(c)
      var v = c; inc v
      g.emitValue(v, scratch)
      Lval(kind: lvPtr, r: scratch, off: 0, width: w)
    of DotC:
      Lval(kind: lvNode, node: c, width: g.accessWidth(c))
    of AtC:
      var idx = c; inc idx; skip idx
      if idx.kind in {IntLit, UIntLit}:
        return Lval(kind: lvNode, node: c, width: g.accessWidth(c))
      g.emitIndexedAddr(c, scratch)
      Lval(kind: lvPtr, r: scratch, off: 0, width: g.accessWidth(c))
    of PatC:
      # `(pat p idx)` — the element size is a SHIFT here, not a scale in an
      # address mode, because this machine has no scaled addressing at all.
      let elemW = g.accessWidth(c)
      var base = c; inc base
      var idx = base; skip idx
      g.emitValue(base, scratch)
      let plan = g.classifyB(idx, scratch)
      let ir = g.scaledIndex(plan, elemW)
      g.emBin16(boAdd, scratch, ir)
      Lval(kind: lvPtr, r: scratch, off: 0, width: elemW)
    else:
      refuse(c, "a store to the expression `" & $c.exprKind & "`")
  else:
    refuse(c, "this store destination")

# ── aggregate copy ──────────────────────────────────────────────────────────

proc emitByteLoad(g: var CodeGen; lv: Lval; off: int; into: Reg) =
  case lv.kind
  of lvSlot: g.emLoadByteAt(into, lv.slot, off)
  of lvNode: g.emLoadByteNode(into, lv.node, off)
  of lvPtr: g.emLoadBytePtr(into, lv.r, off)
  of lvReg: raiseAssert "arkham avr: an aggregate cannot live in a pair"

proc emitByteStore(g: var CodeGen; lv: Lval; off: int; src: Reg) =
  case lv.kind
  of lvSlot: g.emStoreByteAt(lv.slot, off, src)
  of lvNode: g.emStoreByteNode(lv.node, off, src)
  of lvPtr: g.emStoreBytePtr(lv.r, off, src)
  of lvReg: raiseAssert "arkham avr: an aggregate cannot live in a pair"

proc emitAggrCopy(g: var CodeGen; dst, src: Lval; size: int) =
  ## Copy `size` bytes, one at a time and fully unrolled.
  ##
  ## A byte at a time because this IS a byte machine — the word is two of them
  ## and an odd size is common, so a word-at-a-time copy would need a tail for no
  ## saving worth the code. Unrolled because a loop needs a counter and two live
  ## pointers, which is more than the emitter owns; the sizes reaching here are
  ## struct sizes, not buffer sizes.
  const MaxUnroll = 32
  if size > MaxUnroll:
    lengError default(Cursor),
      "AVR: an aggregate copy of " & $size & " bytes would unroll to " & $size &
      " byte moves; a copy that large wants a runtime routine (see M5 in " &
      "doc/internals/avr.md)"
  # The data pair must be neither address pair. Choosing it against the
  # destination alone is not enough: a load into the pair holding the SOURCE
  # pointer destroys that pointer after the first byte.
  let into = (if (dst.kind == lvPtr and dst.r == ValueBridge) or
                 (src.kind == lvPtr and src.r == ValueBridge): StagingBridge
              else: ValueBridge)
  for off in 0 ..< size:
    g.emitByteLoad(src, off, into)
    g.emitByteStore(dst, off, into)

proc mintAggrSlot(g: var CodeGen; size: int): string =
  ## A frame slot sized to hold an aggregate, declared as an ARRAY OF BYTES: what
  ## is wanted is `size` bytes, and repeating the type would make this a second
  ## place the layout has to agree.
  inc g.emitTmpSpills
  result = SynthMark & "eagg" & $g.emitTmpSpills & ".0"
  g.ab.open NifasmDecl.VarD
  g.ab.symDef result
  g.ab.keyword SO
  g.ab.arrayType:
    g.ab.uintType 8
    g.ab.intLit size
  g.ab.close()

proc aggrSize(g: var CodeGen; c: Cursor): int =
  let s = g.exprSlot(c)
  if s.size <= 0: 0 else: s.size

proc isAggrCall(g: var CodeGen; c: Cursor): bool =
  c.kind == TagLit and c.exprKind == CallC and g.exprSlot(c).cls == AMem

proc tryAggrAssign(g: var CodeGen; lhs, rhs: Cursor): bool =
  if g.exprSlot(rhs).cls != AMem: return false
  if g.isAggrCall(rhs):
    # The callee writes THROUGH a pointer, so the destination is handed over
    # rather than copied afterwards.
    let dstLv = g.emitLval(lhs, ValueBridge)
    if dstLv.kind != lvSlot:
      refuse(lhs, "an aggregate call result stored anywhere but a frame slot")
    g.emitCall(rhs, ValueBridge, wantResult = false, aggrDst = dstLv.slot)
    return true
  let size = g.aggrSize(rhs)
  if size <= 0: refuse(rhs, "an aggregate of unknown size")
  let srcLv = g.emitLval(rhs, StagingBridge)
  let dstLv = g.emitLval(lhs, ValueBridge)
  if srcLv.kind == lvPtr and dstLv.kind == lvPtr:
    refuse(lhs, "an aggregate copy where BOTH sides are computed addresses")
  g.emitAggrCopy(dstLv, srcLv, size)
  true

# ── expressions ─────────────────────────────────────────────────────────────

proc binOpOf(c: Cursor): AvrBinOp =
  case c.exprKind
  of AddC: boAdd
  of SubC: boSub
  of BitandC: boAnd
  of BitorC: boOr
  of BitxorC: boXor
  else: refuse(c, "the operator `" & $c.exprKind & "`")

proc emitBin(g: var CodeGen; c: Cursor; dst: Reg) =
  let op = binOpOf(c)
  var a = c
  inc a; skip a               # into the node, past the operand type
  var b = a; skip b
  let plan = g.classifyB(b, dst)
  g.emitValue(a, dst)
  if plan.kind == bkImm:
    # `adiw`/`sbiw` first: one instruction rather than two, and it needs no
    # `ldi`-capable register because the constant never leaves the encoding.
    if op in {boAdd, boSub}:
      let delta = if op == boAdd: int(plan.imm) else: -int(plan.imm)
      if g.emAdiw(dst, delta): return
    if g.emBinImm16(op, dst, plan.imm): return
  let br = g.materializeB(plan)
  g.emBin16(op, dst, br)

proc emitMul(g: var CodeGen; c: Cursor; dst: Reg) =
  var a = c
  inc a; skip a
  var b = a; skip b
  # The multiply needs its operand in a PAIR — there is no immediate form — and
  # it needs the value bridge as an accumulator, so an operand sitting there
  # would be destroyed. Parking through a slot avoids both questions.
  let plan = g.classifyB(b, dst)
  g.emitValue(a, dst)
  var br = g.materializeB(plan)
  if br == ValueBridge:
    g.emLoadSlot(StagingBridge, plan.slot)
    br = StagingBridge
  g.emMul16(dst, br)

proc emitShift(g: var CodeGen; c: Cursor; dst: Reg) =
  var a = c
  inc a
  let signed = typeToSlot(a).cls != AUInt
  skip a
  var b = a; skip b
  if b.kind notin {IntLit, UIntLit}:
    refuse(b, "a shift by a value that is not a constant (this machine has no " &
              "variable-shift instruction at all, so it is a loop)")
  let n = int(if b.kind == IntLit: intVal(b) else: cast[int64](uintVal(b)))
  if n < 0 or n > 15:
    refuse(b, "a shift by " & $n & " bits of a 16-bit value")
  g.emitValue(a, dst)
  if c.exprKind == ShlC: g.emShl16(dst, n)
  else: g.emShr16(dst, n, signed)

proc emitCmpValue(g: var CodeGen; c: Cursor; dst: Reg) =
  ## A comparison used as a VALUE rather than as a branch: 0 or 1 in `dst`.
  ## `ldi` and `movw` leave the flags alone, which is what lets the zero be
  ## materialized between the compare and the branch that reads it.
  let cond = g.emitCmpFlags(c, dst)
  let lEnd = g.freshLabel("cmp")
  g.emLdi16(dst, 0)
  g.emBranch(invert(cond), lEnd)
  g.emLdi16(dst, 1)
  g.emLab(lEnd)

proc emitValue(g: var CodeGen; c: Cursor; dst: Reg) =
  ## Materialize `c` into the pair `dst`.
  assert dst != StagingBridge,
    "arkham avr: the staging bridge is the operand loader and can never be a " &
    "destination — see the module header"
  case c.kind
  of IntLit: g.emLdi16(dst, intVal(c))
  of UIntLit: g.emLdi16(dst, cast[int64](uintVal(c)))
  of CharLit: g.emLdi16(dst, int64(ord(charLit(c))))
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    case home.kind
    of InReg: g.emMovw(dst, home.r)
    of NamedStack: g.emLoadSlot(dst, home.name)
    else: refuse(c, "a read of `" & symName(c) & "`, whose location is " & $home.kind)
  of StrLit:
    refuse(c, "a string literal — this is a HARVARD machine, so a constant lives " &
              "in flash and is read by `lpm` rather than by `ld`, which is a " &
              "different address space and a different instruction (M6)")
  of TagLit:
    case c.exprKind
    of SufC:
      var v = c; inc v         # `(suf <literal> "u8")` — the literal, then a tag
      g.emitValue(v, dst)
    of ParC:
      var v = c; inc v
      g.emitValue(v, dst)
    of TrueC: g.emLdi16(dst, 1)
    of FalseC: g.emLdi16(dst, 0)
    of NilC: g.emLdi16(dst, 0)
    of AddC, SubC, BitandC, BitorC, BitxorC: g.emitBin(c, dst)
    of MulC: g.emitMul(c, dst)
    of ShlC, ShrC: g.emitShift(c, dst)
    of EqC, NeqC, LtC, LeC: g.emitCmpValue(c, dst)
    of NotC:
      # A BOOL not, not a bitwise one: the value is 0 or 1, so flipping bit 0 is
      # the whole of it — and the high half is already zero. `eor` has no
      # immediate form on this machine, so the 1 comes through the staging
      # bridge's low half.
      var v = c; inc v
      g.emitValue(v, dst)
      g.ab.tree LdiAvr: (g.emLo StagingBridge; g.ab.intLit 1)
      g.ab.tree XorAvr: (g.emLo dst; g.emLo StagingBridge)
    of NegC:
      var v = c; inc v
      g.emitValue(v, dst)
      g.emNeg16(dst)
    of BitnotC:
      var v = c; inc v
      g.emitValue(v, dst)
      g.emNot16(dst)
    of ConvC, CastC:
      # Every scalar this backend has fits one pair, so a conversion between two
      # of them moves no bits. What it can still do is NARROW, and that is a
      # truncation this slice does not implement — refused rather than silently
      # kept wide.
      var v = c; inc v
      let toSlot = typeToSlot(v)
      skip v
      let fromSlot = typeToSlot(v)
      if toSlot.size < fromSlot.size:
        refuse(c, "a narrowing conversion (" & $(fromSlot.size * 8) & " to " &
                  $(toSlot.size * 8) & " bits)")
      g.emitValue(v, dst)
    of AddrC, HaddrC:
      # `emitAddrOf` covers every case: a local (already spilled by the analyser,
      # since taking an address marks it `AddrTaken`) and a field or element.
      var v = c; inc v
      g.emitAddrOf(v, dst)
    of DotC:
      g.emLoadNode(dst, c, g.accessWidth(c))
    of AtC:
      var idx = c; inc idx; skip idx
      let w = g.accessWidth(c)
      if idx.kind in {IntLit, UIntLit}:
        g.emLoadNode(dst, c, w)
      else:
        g.emitIndexedAddr(c, dst)
        g.emLoadPtr(dst, dst, 0, w)
    of DerefC:
      let w = g.accessWidth(c)
      var v = c; inc v
      g.emitValue(v, dst)
      g.emLoadPtr(dst, dst, 0, w)
    of PatC:
      let elemW = g.accessWidth(c)
      var base = c; inc base
      var idx = base; skip idx
      g.emitValue(base, dst)
      let plan = g.classifyB(idx, dst)
      let ir = g.scaledIndex(plan, elemW)
      g.emBin16(boAdd, dst, ir)
      g.emLoadPtr(dst, dst, 0, elemW)
    of CallC: g.emitCall(c, dst, wantResult = true)
    else:
      refuse(c, "the expression `" & $c.exprKind & "`")
  else:
    refuse(c, "this expression")

# ── calls ───────────────────────────────────────────────────────────────────

proc emitCall(g: var CodeGen; c: Cursor; dst: Reg; wantResult: bool;
              aggrDst = "") =
  ## `aggrDst` names the frame slot an AGGREGATE result must be written into.
  ## This target's aggregate convention is by-REFERENCE at every size: an
  ## aggregate argument is a pointer to a copy the caller made, and an aggregate
  ## result is written through a hidden first pointer. Uniform, because arkham
  ## owns both ends of every call here and one rule with no size threshold cannot
  ## be applied differently by the two.
  ##
  ## `(call f a b …)` — arguments into the ABI pairs, then `(prepare …)`.
  ##
  ## Every argument is parked in a slot first. That is heavier than the other
  ## backends' marshalling and it is what makes this total: an argument whose
  ## own evaluation is a call would otherwise have to keep the earlier arguments
  ## alive across it, in registers a call destroys.
  var f = c
  inc f
  if f.kind != Symbol:
    refuse(c, "an indirect call")
  let callee = symName(f)
  var args: seq[Cursor] = @[]
  var a = c
  # `into`, not `inc`: after `inc` a cursor's `hasMore` is relative to the
  # ENCLOSING node, so the loop would collect the statements after the call as
  # arguments. The same trap the `plain(…)` template fell into.
  a.into:
    skip a                                     # the callee
    while a.hasMore:
      args.add a
      skip a
  let target = g.callTarget.getOrDefault(callee)
  if target.asmName.len == 0:
    refuse(c, "a call to `" & callee & "`, which is not a known proc")
  if target.extern or target.syscall or target.memIntrin.len > 0 or
     target.bitBuiltin.len > 0:
    refuse(c, "a call to `" & callee & "`: externs, syscalls and inlined " &
              "intrinsics have no meaning on a bare-metal target")

  var rtc = target.retType
  # A VOID result is `.` in the decl and `slotOf` of that answers `AMem`, so
  # without the two guards every call to a void proc would think it needed a
  # hidden result pointer and shift every argument by one.
  let retsAggr = not cursorIsNil(rtc) and rtc.kind != DotToken and
                 not (rtc.kind == TagLit and rtc.typeKind == VoidT) and
                 slotOf(g.prog, rtc).cls == AMem
  if retsAggr and aggrDst.len == 0:
    refuse(c, "the result of `" & callee & "`, which is an aggregate, used " &
              "somewhere with no place to put it")
  let shift = if retsAggr: 1 else: 0
  if args.len + shift > g.md.intArgRegs.len:
    refuse(c, "a call with " & $args.len & " arguments plus a hidden result " &
              "pointer — more than this target passes in registers (M5)")

  var slots: seq[string] = @[]
  for i in 0 ..< args.len:
    let sl = g.mintSlot(args[i])
    if g.exprSlot(args[i]).cls == AMem:
      # The callee gets a pointer to the CALLER's copy, so it may write through
      # it without the caller seeing that.
      let size = g.aggrSize(args[i])
      let tmp = g.mintAggrSlot(size)
      let srcLv = g.emitLval(args[i], StagingBridge)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: tmp), srcLv, size)
      g.emLeaSlot(ValueBridge, tmp)
    else:
      g.emitValue(args[i], ValueBridge)
    g.emStoreSlot(sl, ValueBridge)
    slots.add sl

  # The declarative call ABI: arguments are written to `(arg pN.0)` by NAME and
  # the result read from `(res ret.0)`, so nifasm checks both against the
  # callee's signature. Positional names, because that is what this backend
  # emits at the other end too — see `genProcAvr`.
  g.ab.open PrepareAvr
  g.ab.sym target.asmName
  if retsAggr:
    g.emLeaSlot(ValueBridge, aggrDst)
    g.ab.tree MovwAvr:
      g.ab.tree ArgX: g.ab.sym paramName(0)
      g.emPair ValueBridge
  for i in 0 ..< args.len:
    g.emLoadSlot(ValueBridge, slots[i])
    g.ab.tree MovwAvr:
      g.ab.tree ArgX: g.ab.sym paramName(i + shift)
      g.emPair ValueBridge
  g.ab.keyword CallAvr
  # The result is bound whether or not the caller wants it: nifasm checks that
  # every result the signature declares was read exactly once, and a discarded
  # call still returned one. It goes to the value bridge when nobody asked.
  if retsAggr:
    discard                                   # already written into `aggrDst`
  elif not cursorIsNil(target.retType) and target.retType.typeKind != VoidT:
    g.ab.tree MovwAvr:
      (if wantResult: g.emPair dst else: g.emPair ValueBridge)
      g.ab.tree ResX: g.ab.sym synth("ret.0")
  elif wantResult:
    refuse(c, "using the result of `" & callee & "`, which returns nothing")
  g.ab.close()


# ── statements ──────────────────────────────────────────────────────────────

proc storeToSym(g: var CodeGen; name: string; pos: int; src: Reg) =
  let home = g.plan.locationOfSym(name, pos)
  case home.kind
  of InReg: g.emMovw(home.r, src)
  of NamedStack: g.emStoreSlot(home.name, src)
  else:
    raiseAssert "arkham avr: `" & name & "` has no storage (" & $home.kind & ")"

proc destOfSym(g: var CodeGen; name: string; pos: int): Reg =
  ## Where to COMPUTE a value that is about to become `name`. A register-homed
  ## local is computed in place; a memory-homed one goes through the value
  ## bridge, which is what that bridge is for.
  let home = g.plan.locationOfSym(name, pos)
  if home.kind == InReg: home.r else: ValueBridge

proc emitAggrInit(g: var CodeGen; c: Cursor; slot: string) =
  ## `(oconstr T (kv f v)…)` / `(aconstr T v…)` into a frame slot, one field or
  ## element at a time.
  ##
  ## A constructor is TOTAL — sem names every field of the type, in any order —
  ## so nothing has to be zeroed first and nothing can be left uninitialized.
  case c.exprKind
  of OconstrC:
    var f = c
    f.into:
      skip f                                     # the type
      while f.hasMore:
        if f.substructureKind != KvU:
          refuse(f, "a non-`kv` entry in an object constructor")
        var kv = f
        inc kv
        if kv.kind != Symbol:
          refuse(kv, "an object constructor without a field name")
        let fieldName = symName(kv)
        skip kv                                  # the field name
        g.refuseAggr(kv, "the value of field `" & fieldName & "`")
        let w = g.accessWidth(kv)
        g.emitValue(kv, ValueBridge)
        g.emStoreField(slot, fieldName, ValueBridge, w)
        skip f
  of AconstrC:
    var e = c
    var i = 0
    e.into:
      skip e                                     # the type
      while e.hasMore:
        g.refuseAggr(e, "element " & $i & " of this array constructor")
        let w = g.accessWidth(e)
        g.emitValue(e, ValueBridge)
        g.emStoreElem(slot, i, ValueBridge, w)
        inc i
        skip e
  else:
    refuse(c, "this aggregate initializer")

proc genVarDecl(g: var CodeGen; c: Cursor) =
  var v = c
  inc v                                   # into `(var …)`, at the name
  let name = symName(v)
  let pos = cursorToPosition(g.buf[], v)
  inc v
  skip v                                  # the var's pragmas
  let typeCur = v
  skip v                                  # the type
  g.checkWidth(typeCur, "the local `" & name & "`")
  let home = g.plan.locationOfSym(name, pos)
  case home.kind
  of InReg: g.emRegPairVar(name, home.r, typeCur)
  of NamedStack: g.emSlotVar(home.name, typeCur)
  else:
    lengError c, "AVR: the local `" & name & "` was given no storage",
              lengInfo(c)
  if v.hasMore and v.kind != DotToken:
    if not (v.kind == TagLit and v.exprKind in {OconstrC, AconstrC}) and
       g.exprSlot(v).cls == AMem:
      if home.kind != NamedStack:
        lengError c, "an aggregate local must live in a frame slot", lengInfo(c)
      if g.isAggrCall(v):
        # The callee writes straight into this local, with no copy in between.
        g.emitCall(v, ValueBridge, wantResult = false, aggrDst = home.name)
        return
      # Any other aggregate initializer IS a copy.
      let srcLv = g.emitLval(v, StagingBridge)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: home.name), srcLv, g.aggrSize(v))
      return
    if v.kind == TagLit and v.exprKind in {OconstrC, AconstrC}:
      if home.kind != NamedStack:
        lengError c, "an aggregate local must live in a frame slot", lengInfo(c)
      g.emitAggrInit(v, home.name)
      return
    let dst = g.destOfSym(name, pos)
    g.emitValue(v, dst)
    if home.kind != InReg: g.emStoreSlot(home.name, dst)

proc genAsgn(g: var CodeGen; c: Cursor) =
  var lhs = c
  inc lhs
  var rhs = lhs
  skip rhs
  if g.tryAggrAssign(lhs, rhs): return
  if lhs.kind == Symbol:
    let name = symName(lhs)
    let pos = cursorToPosition(g.buf[], lhs)
    let dst = g.destOfSym(name, pos)
    g.emitValue(rhs, dst)
    let home = g.plan.locationOfSym(name, pos)
    if home.kind != InReg: g.emStoreSlot(home.name, dst)
    return
  # A store through an address. Both the address and the value are parked: each
  # is computed into the value bridge, and neither could survive the other's walk
  # otherwise — every bridge this machine has is in play during one.
  let lv = g.emitLval(lhs, ValueBridge)
  case lv.kind
  of lvNode:
    # nifasm folds the address, so nothing has to survive the value's walk.
    g.emitValue(rhs, ValueBridge)
    g.emStoreNode(lv.node, ValueBridge, lv.width)
  of lvPtr:
    # A computed address. Both it and the value are parked: each is produced into
    # the value bridge, and neither could survive the other's walk — every bridge
    # this machine has is in play during one.
    let addrSlot = g.mintSlot(lhs)
    g.emStoreSlot(addrSlot, lv.r)
    g.emitValue(rhs, ValueBridge)
    let valSlot = g.mintSlot(lhs)
    g.emStoreSlot(valSlot, ValueBridge)
    g.emLoadSlot(ValueBridge, valSlot)
    g.emLoadSlot(StagingBridge, addrSlot)
    g.emStorePtr(StagingBridge, lv.off, ValueBridge, lv.width)
  else:
    refuse(lhs, "an assignment to this destination")

proc genRet(g: var CodeGen; c: Cursor) =
  var v = c
  inc v
  if v.hasMore and v.kind != DotToken:
    if g.exprSlot(v).cls == AMem:
      # An aggregate result is written through the hidden pointer the caller
      # supplied, which the prologue parked in `retAggrSlot`.
      if g.retAggrSlot.len == 0:
        refuse(v, "an aggregate return from a proc with no hidden result pointer")
      let size = g.aggrSize(v)
      let srcLv = g.emitLval(v, ValueBridge)
      g.emLoadSlot(StagingBridge, g.retAggrSlot)
      g.emitAggrCopy(Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 1),
                     srcLv, size)
    else:
      g.emitValue(v, g.md.intRetReg)
  g.retLabelUsed2 = true
  g.emJmp(g.retLabel2)

proc genIf(g: var CodeGen; c: Cursor) =
  let lEnd = g.freshLabel("ifend")
  var cc = c
  cc.into:
    while cc.hasMore:
      case cc.substructureKind
      of ElifU:
        let lNext = g.freshLabel("elif")
        var peek = cc; skip peek
        let isLast = not peek.hasMore
        var bc = cc
        bc.into:
          let condC = bc; skip bc
          g.emitCond(condC, lNext, whenTrue = false)
          while bc.hasMore: (g.genStmt(bc); skip bc)
          # The hop over the later branches. The last branch has none, so it
          # falls through its own (empty) `lNext` into `lEnd`.
          if not isLast: g.emJmp(lEnd)
        g.emLab(lNext)
      of ElseU:
        var bc = cc
        bc.into:
          while bc.hasMore: (g.genStmt(bc); skip bc)
      else: discard
      skip cc
  g.emLab(lEnd)

proc genWhile(g: var CodeGen; c: Cursor) =
  ## `(loop (stmts …))` — the assembler adds the back edge, so nothing here
  ## emits a backward branch. The exit is a FORWARD branch to a label defined
  ## after the loop, which is the only shape nifasm's structural discipline
  ## accepts.
  let lEnd = g.freshLabel("wend")
  g.loopEnds.add lEnd
  g.ab.tree LoopAvr:
    g.ab.tree StmtsAvr:
      var cc = c
      cc.into:
        let condC = cc; skip cc
        g.emitCond(condC, lEnd, whenTrue = false)
        while cc.hasMore: (g.genStmt(cc); skip cc)
  g.emLab(lEnd)
  discard g.loopEnds.pop()

proc genStmt(g: var CodeGen; c: Cursor) =
  case c.stmtKind
  of StmtsS, ScopeS:
    var cc = c
    cc.into:
      while cc.hasMore: (g.genStmt(cc); skip cc)
  of VarS: g.genVarDecl(c)
  of AsgnS: g.genAsgn(c)
  of RetS: g.genRet(c)
  of IfS: g.genIf(c)
  of WhileS: g.genWhile(c)
  of BreakS:
    if g.loopEnds.len == 0:
      lengError c, "AVR: `break` outside a loop", lengInfo(c)
    g.emJmp(g.loopEnds[^1])
  of CallS:
    # A discarded call. An aggregate result still has to go SOMEWHERE — the
    # callee writes through the pointer whether anyone reads it or not.
    if g.exprSlot(c).cls == AMem:
      let tmp = g.mintAggrSlot(g.aggrSize(c))
      g.emitCall(c, ValueBridge, wantResult = false, aggrDst = tmp)
    else:
      g.emitCall(c, ValueBridge, wantResult = false)
  of DiscardS:
    var v = c
    inc v
    if v.hasMore and v.kind != DotToken:
      g.emitValue(v, ValueBridge)
  of LabS:
    var v = c; inc v
    g.emLab(symName(v))
  of JmpS:
    var v = c; inc v
    g.emJmp(symName(v))
  else:
    refuse(c, "the statement `" & $c.stmtKind & "`")


# ── frames ──────────────────────────────────────────────────────────────────

const
  RamEnd = 0x08FF
    ## The last SRAM byte on an ATmega328P. The entry proc establishes SP here,
    ## because on this machine nothing else does: SP resets to zero, which is the
    ## register file, so the first `call` would push over r0 and r1.
  SplIo = 0x3D
  SphIo = 0x3E
    ## SP is an I/O register PAIR, reachable only by `in`/`out`. That is the whole
    ## reason Y exists as a frame pointer: SP cannot address memory.
  AvrtestExit = 30

proc emPushPair(g: var CodeGen; r: Reg) =
  g.ab.tree PushAvr: g.ab.regNamed lowName(r)
  g.ab.tree PushAvr: g.ab.regNamed highName(r)

proc emPopPair(g: var CodeGen; r: Reg) =
  ## High first: a pop must undo the pushes in reverse, and the pair went down
  ## low half first.
  g.ab.tree PopAvr: g.ab.regNamed highName(r)
  g.ab.tree PopAvr: g.ab.regNamed lowName(r)

proc emFrameSetup(g: var CodeGen) =
  ## Y = SP - frame size, and SP follows it down. Seven instructions, because SP
  ## has to be read and written one byte at a time through the I/O space — which
  ## is why a proc with no slot pays for none of this.
  g.emPushPair(Y)
  g.ab.tree InbAvr: (g.ab.regNamed lowName(Y); g.ab.intLit SplIo)
  g.ab.tree InbAvr: (g.ab.regNamed highName(Y); g.ab.intLit SphIo)
  g.ab.tree SbiwAvr: (g.ab.rawReg Y; g.ab.keyword SsizeX)
  g.ab.tree OutbAvr: (g.ab.intLit SphIo; g.ab.regNamed highName(Y))
  g.ab.tree OutbAvr: (g.ab.intLit SplIo; g.ab.regNamed lowName(Y))

proc emFrameTeardown(g: var CodeGen) =
  g.ab.tree AdiwAvr: (g.ab.rawReg Y; g.ab.keyword SsizeX)
  g.ab.tree OutbAvr: (g.ab.intLit SphIo; g.ab.regNamed highName(Y))
  g.ab.tree OutbAvr: (g.ab.intLit SplIo; g.ab.regNamed lowName(Y))
  g.emPopPair(Y)

proc emEntrySetup(g: var CodeGen) =
  ## What a reset leaves undone. SP is zero — i.e. pointing at the register file
  ## — and r1 holds whatever it holds, while every borrow sequence this backend
  ## emits reads r1 as a known zero.
  g.ab.tree LdiAvr: (g.ab.regNamed "r20"; g.ab.intLit(RamEnd and 0xFF))
  g.ab.tree OutbAvr: (g.ab.intLit SplIo; g.ab.regNamed "r20")
  g.ab.tree LdiAvr: (g.ab.regNamed "r20"; g.ab.intLit(RamEnd shr 8))
  g.ab.tree OutbAvr: (g.ab.intLit SphIo; g.ab.regNamed "r20")
  g.ab.tree XorAvr: (g.ab.regNamed "r1"; g.ab.regNamed "r1")

proc collectParams(g: var CodeGen; decl: Cursor): seq[tuple[name: string; typ: Cursor]] =
  result = @[]
  var c = decl
  inc c; inc c                 # into `(proc …)`, past the name, at `(params …)`
  if c.kind != TagLit: return
  var p = c
  p.into:
    while p.hasMore:
      var d = p
      d.into:
        let nm = symName(d)
        inc d
        skip d                 # the param's pragmas
        result.add (nm, d)
        while d.hasMore: skip d
      skip p

proc recordVarType(g: var CodeGen; c: Cursor) =
  ## `(param :nm . type)` / `(var :nm pragmas type …)` → `symType[nm] = type`.
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc                                    # pragmas
      let typeCur = cc; skip cc
      g.symType[nm] = g.declType(typeCur, cc)    # `.` ⇒ inferred from the initializer
    while cc.hasMore: skip cc

proc recordSymTypes(g: var CodeGen; c: Cursor) =
  ## Pre-pass: fill `symType` for every local before emission starts, so that
  ## asking an expression its own type works from the first node. Without it a
  ## `(deref p)` cannot be sized — and sizing it by the POINTER instead of the
  ## pointee makes every byte access a word access.
  if c.kind != TagLit: return
  case c.stmtKind
  of VarS, GvarS, TvarS, ConstS: g.recordVarType(c)
  of ProcS, TypeS: discard
  else:
    var cc = c
    cc.into:
      while cc.hasMore:
        g.recordSymTypes(cc)
        skip cc

proc genProcAvr*(g: var CodeGen; info: ProcInfo) =
  if info.isAsm or info.isNaked or info.irqName.len > 0:
    lengError info.decl,
      "AVR: `{.assembler.}`, `{.naked.}` and `{.interrupt.}` are not implemented " &
      "yet (see M6 in doc/internals/avr.md)", lengInfo(info.decl)

  g.varType.clear()
  g.symType.clear()
  block:                                  # every local's type, before anything asks
    var pc = info.decl
    pc.into:
      inc pc                              # the name
      if pc.kind == TagLit:               # (params …)
        var p = pc
        p.into:
          while p.hasMore: (g.recordVarType(p); skip p)
      skip pc                             # params
      skip pc                             # the result type
      skip pc                             # pragmas
      if pc.stmtKind == StmtsS: g.recordSymTypes(pc)
      while pc.hasMore: skip pc
  g.curProcName = info.asmName
  g.isEntryProc = info.isEntry
  g.rb.resetProc()
  g.loopEnds = @[]
  g.emitTmpSpills = 0
  g.labelCount = 0
  g.retLabel2 = SynthMark & "epi.0"
  g.retLabelUsed2 = false

  let an = analyseProc(g.buf[], info.decl)
  g.plan = allocateProc(g.buf[], info.decl, an, g.prog, avrMachine, g.typeCtx)

  let params = g.collectParams(info.decl)

  # The return type, read off the decl.
  var rt = info.decl
  inc rt; inc rt; skip rt      # name, params → the result type
  let hasResult = not (rt.kind == DotToken or
                       (rt.kind == TagLit and rt.typeKind == VoidT))
  var rtc0 = rt
  let retsAggr = hasResult and slotOf(g.prog, rtc0).cls == AMem
  gRetAggrSlot = ""
  let shift = if retsAggr: 1 else: 0
  if params.len + shift > g.md.intArgRegs.len:
    lengError info.decl,
      "AVR: this proc takes " & $params.len & " parameters" &
      (if retsAggr: " plus a hidden result pointer" else: "") &
      "; the target passes " & $g.md.intArgRegs.len &
      " pairs in registers and the rest on the stack (M5)", lengInfo(info.decl)

  g.ab.open NifasmDecl.ProcD
  g.ab.symDef info.asmName
  g.ab.tree NifasmDecl.ParamsD:
    if retsAggr:
      # The hidden result pointer, first. Its TYPE is a pointer, not the
      # aggregate — what arrives in the pair is an address.
      g.ab.tree NifasmDecl.ParamD:
        g.ab.symDef paramName(0)
        g.ab.rawReg g.md.intArgRegs[0]
        g.ab.ptrType: g.ab.voidType()
    for i in 0 ..< params.len:
      g.ab.tree NifasmDecl.ParamD:
        g.ab.symDef paramName(i + shift)
        g.ab.rawReg g.md.intArgRegs[i + shift]
        var ptc0 = params[i].typ
        if slotOf(g.prog, ptc0).cls == AMem:
          # `(ptr <the object>)`, not `(ptr (void))`: nifasm folds `(dot p f)`
          # against the POINTEE's layout, and an opaque pointer has none.
          g.ab.ptrType:
            var inner = params[i].typ
            g.genTypeBodyAvr(inner)
        else:
          var tc = params[i].typ
          g.genTypeBodyAvr(tc)
  if hasResult and not retsAggr:
    g.checkWidth(rt, "the result of `" & info.asmName & "`")
    g.ab.tree NifasmDecl.ResultD:
      g.ab.symDef synth("ret.0")
      g.ab.rawReg g.md.intRetReg
      var tc = rt
      g.genTypeBodyAvr(tc)
  g.ab.tree NifasmDecl.ClobberD:
    for r in g.md.convClobbersGpr: g.ab.rawReg r

  # ── the body, into a side buffer ────────────────────────────────────────
  # Its shape decides the prologue's: whether any slot was minted, and hence
  # whether a frame pointer has to be established at all, is only known once the
  # walk is finished.
  var side = g.ab.sideBuf()
  swap(g.ab, side)
  g.rb.enterScope()

  if retsAggr: g.rb.bindParam(g.md.intArgRegs[0], paramName(0))
  for i in 0 ..< params.len:
    g.rb.bindParam(g.md.intArgRegs[i + shift], paramName(i + shift))
  if retsAggr:
    # Park the hidden pointer for the proc's lifetime: it is needed at every
    # `ret`, and the first argument pair is caller-saved and also the first
    # argument of any call the body makes.
    gRetAggrSlot = SynthMark & "retp.0"
    g.emPtrSlot gRetAggrSlot
    g.emStoreSlot(gRetAggrSlot, g.md.intArgRegs[0])
    g.ab.tree KillAvr: g.ab.sym paramName(0)
    discard g.rb.takeBinding(g.md.intArgRegs[0])
  for i in 0 ..< params.len:
    let nm = params[i].name
    var ptc = params[i].typ
    let home = g.plan.homeOfSym(nm)
    let src = g.md.intArgRegs[i + shift]
    if slotOf(g.prog, ptc).cls == AMem and home.kind == NamedStack:
      # An aggregate arrives as a POINTER to the caller's copy and is copied into
      # this proc's own slot. That is what makes it call-by-value: the callee may
      # write to its parameter and the caller must not see it.
      var stc = params[i].typ
      g.emSlotVar(home.name, params[i].typ)
      g.emMovw(StagingBridge, src)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: home.name),
                     Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 1),
                     slotOf(g.prog, stc).size)
    elif slotOf(g.prog, ptc).cls == AMem:
      # The ALLOCATOR gave this aggregate a pair home, which it only does for one
      # above `aggrByRefThreshold` — Leng passes those by reference already, so
      # what arrives is a pointer and the pair holds it for the proc's life.
      if home.kind != InReg:
        lengError info.decl, "AVR: the aggregate parameter `" & nm &
                  "` was given neither a slot nor a pair (" & $home.kind & ")",
                  lengInfo(info.decl)
      g.emRegPairVar(nm, home.r, params[i].typ)
      g.emMovw(home.r, src)
    else:
      g.checkWidth(params[i].typ, "the parameter `" & nm & "`")
      case home.kind
      of InReg:
        g.emRegPairVar(nm, home.r, params[i].typ)  # kills `pN.0` when it IS this pair
        g.emMovw(home.r, src)
      of NamedStack:
        g.emSlotVar(home.name, params[i].typ)
        g.emStoreSlot(home.name, src)
      else:
        lengError info.decl, "AVR: the parameter `" & nm & "` was given no storage",
                  lengInfo(info.decl)
    if g.rb.boundName(src) == paramName(i + shift):
      g.ab.tree KillAvr: g.ab.sym paramName(i + shift)
      discard g.rb.takeBinding(src)

  var body = info.decl
  inc body; inc body; skip body; skip body; skip body   # name params rettype pragmas
  if body.stmtKind == StmtsS:
    var bc = body
    bc.into:
      while bc.hasMore: (g.genStmt(bc); skip bc)

  discard g.rb.exitScope()
  swap(g.ab, side)                     # `side` now holds the body

  # ── the prologue, now that the body's demands are known ────────────────
  let needFrame = g.emitTmpSpills > 0 or g.plan.hasStackVars or
                  g.plan.spillTemps.len > 0 or
                  (block:
                     var any = false
                     for nm, _ in g.plan.symPos:
                       if g.plan.homeOfSym(nm).kind == NamedStack: any = true
                     any)
  var saved: seq[Reg] = @[]
  for r in g.md.intCalleeSaved:
    if r in g.plan.usedCallee: saved.add r

  g.ab.open StmtsAvr
  if info.isEntry: g.emEntrySetup()
  for r in saved: g.emPushPair(r)
  if needFrame: g.emFrameSetup()
  g.ab.append(side)
  if g.retLabelUsed2: g.emLab(g.retLabel2)
  if needFrame: g.emFrameTeardown()
  for i in countdown(saved.len - 1, 0): g.emPopPair(saved[i])
  if info.isEntry:
    # A freestanding image has nothing to return to: the entry's result IS the
    # exit status, handed to the simulator the way Cortex-M hands it to the
    # semihosting host.
    g.ab.tree BkptAvr: g.ab.intLit AvrtestExit
  else:
    g.ab.keyword RetAvr
  g.ab.close()                         # (stmts …)
  g.ab.close()                         # (proc …)
