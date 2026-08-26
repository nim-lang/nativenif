#
#           Arkham — the RV32 value core: expressions, statements, frames
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## A destination-passing walker, in the shape `src/arkham/avr/gen.nim`
## established and for the same reason: the fused decide-and-emit core is four
## thousand lines whose register-binding protocol has a formal model behind it,
## and what matters for a new target is that the answer is right and every gap is
## a diagnostic. The optimizations are recoverable; a wrong branch is not.
##
## It is markedly shorter than AVR's, and every line of the difference is the
## machine being regular. A three-operand ALU means an operand never has to be
## moved into the destination first. One addressing mode means a spilled operand
## is loaded straight into the register that wants it. `x0` means `mov`, `neg`,
## `not` and comparison-against-zero are ordinary instructions.
##
## **No flags.** A comparison used as a CONDITION is a two-register branch, and
## one used as a VALUE is `slt` — never a flag left between two instructions.
## That is the one place this backend is genuinely simpler than the flag targets
## rather than merely smaller: there is no window in which a comparison's result
## can be clobbered, so there is nothing to protect.

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
  ## module-level `var` rather than a `CodeGen` field because `CodeGen` is shared
  ## with three other backends that have no such thing, and arkham compiles one
  ## proc at a time — the same reasoning `gArkhamCurProc` already rests on.

template retAggrSlot(g: CodeGen): string = gRetAggrSlot

proc refuse(c: Cursor; what: string) {.noreturn.} =
  lengError c, "RV32: " & what & " is not implemented yet " &
               "(see doc/internals/rv32.md)", lengInfo(c)

proc checkWidth(g: var CodeGen; typeCur: Cursor; what: string) =
  var t = typeCur
  let s = typeToSlot(t)
  if s.cls == AFloat:
    lengError typeCur, "RV32: " & what & " is a float; this target is `ilp32` " &
              "soft-float and has no FPU registers (see R5)", lengInfo(typeCur)
  if s.cls == AMem:
    # An aggregate lives in a frame slot sized by its own type, and is never in a
    # register — so the width check below does not apply to it.
    return
  if s.size > 4:
    lengError typeCur, "RV32: " & what & " is " & $(s.size * 8) & " bits wide; " &
              "this backend's word is 32 and a wider value lives in a register " &
              "PAIR, which is not implemented yet (see R5)", lengInfo(typeCur)

proc refuseAggr(g: var CodeGen; c: Cursor; what: string) =
  ## An aggregate where only a SCALAR is handled. This has to be a refusal and
  ## not a silent partial job: a struct copy, a struct argument and a struct
  ## return all look like ordinary moves to a value core that only knows how to
  ## move one word, so the answer comes out WRONG rather than missing. Ten
  ## fixtures did exactly that before this check existed.
  if g.exprSlot(c).cls == AMem:
    lengError c, "RV32: " & what & " is an aggregate — copying, passing and " &
              "returning one are not implemented yet (see R5c in " &
              "doc/internals/rv32.md)", lengInfo(c)

proc mintSlot(g: var CodeGen; prefix: string): string =
  inc g.emitTmpSpills
  result = SynthMark & prefix & $g.emitTmpSpills & ".0"
  g.emWordSlot result

# ── how a second operand is supplied ────────────────────────────────────────

type
  BKind = enum
    bkImm      ## a constant: rides in an `i`-form where one exists
    bkReg      ## already in a register nothing is about to overwrite
    bkSlot     ## in memory: loaded into the bridge at the point of use

  BPlan = object
    kind: BKind
    imm: int64
    r: Reg
    slot: string

proc classifyB(g: var CodeGen; c: Cursor; dst: Reg): BPlan =
  ## Decide where an operand comes from, PARKING it now if that takes work.
  ##
  ## The `home.r == dst` case is why this is a separate step: `x - y` with the
  ## destination already being `y`'s home would compute `x` into `y` and then
  ## subtract the result from itself.
  case c.kind
  of IntLit: return BPlan(kind: bkImm, imm: intVal(c))
  of UIntLit: return BPlan(kind: bkImm, imm: cast[int64](uintVal(c)))
  of CharLit: return BPlan(kind: bkImm, imm: int64(ord(charLit(c))))
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == InReg and home.r != dst:
      return BPlan(kind: bkReg, r: home.r)
    if home.kind == NamedStack:
      return BPlan(kind: bkSlot, slot: home.name)
  else: discard
  # Into a BRIDGE, not into `dst`. `dst` is very often a local's home — `x = x +
  # f(5)` computes into `x`'s register — and parking there destroys that local
  # BEFORE the first operand is read, which then reads the parked value instead
  # of itself. A bridge is scratch and belongs to nobody.
  let parkReg = if dst in {StagingBridge, StagingBridge2}: dst else: StagingBridge
  let slot = g.mintSlot("etmp")
  g.emitValue(c, parkReg)
  g.emStoreSlot(slot, parkReg)
  BPlan(kind: bkSlot, slot: slot)

proc otherBridge(dst: Reg): Reg {.inline.} =
  ## The bridge that is NOT the destination. Both operands of a comparison are
  ## live across one instruction, so a value produced into `StagingBridge` must
  ## have its partner somewhere else — and one bridge silently compared a
  ## constant with itself.
  if dst == StagingBridge: StagingBridge2 else: StagingBridge

proc materializeB(g: var CodeGen; p: BPlan; dst: Reg): Reg =
  ## Into a bridge, AFTER the other operand has been emitted — that walk may use
  ## a bridge itself, and nothing nests inside the one instruction this is live
  ## for.
  case p.kind
  of bkReg: p.r
  of bkSlot:
    let into = otherBridge(dst)
    g.emLoadSlot(into, p.slot)
    into
  of bkImm:
    let into = otherBridge(dst)
    g.emLi(into, p.imm)
    into

# ── comparisons ─────────────────────────────────────────────────────────────

proc cmpOperandUnsigned(g: var CodeGen; c: Cursor): bool =
  ## Does one comparison operand carry an unsigned (or char) type? A bare signed
  ## literal is AMBIGUOUS — it answers false and lets the other operand decide,
  ## which is the whole point: `(lt 5 u)` is an unsigned comparison and only the
  ## second operand says so.
  case c.kind
  of UIntLit, CharLit: true
  of IntLit: false
  else: g.exprSlot(c).cls == AUInt

proc isSignedCmp(g: var CodeGen; c: Cursor): bool =
  ## Read off the FIRST OPERAND's own type, because a comparison carries NO type
  ## child — unlike `(add T a b)` and every other arithmetic node. That asymmetry
  ## is easy to miss and this backend missed it: reading a type where the first
  ## OPERAND is left every comparison one child out of step, and `(lt x 5)` — the
  ## form the frontend actually emits — compared `5` against whatever followed
  ## the node. Twenty-three fixtures in the Cortex-M corpus refused on it.
  var a = c
  inc a                       # into the node, at the first operand
  var b = a; skip b
  not (g.cmpOperandUnsigned(a) or g.cmpOperandUnsigned(b))

proc condOf(c: Cursor; signed: bool): tuple[cond: RvCond; swap: bool] =
  ## The branch that HOLDS when the comparison is true, and whether the operands
  ## must be exchanged first. `<=` is `not (b < a)`, i.e. the `>=` branch with
  ## the operands the other way round.
  case c.exprKind
  of EqC: (rcEq, false)
  of NeqC: (rcNe, false)
  of LtC: ((if signed: rcLt else: rcLtu), false)
  of LeC: ((if signed: rcGe else: rcGeu), true)
  else: refuse(c, "the comparison `" & $c.exprKind & "`")

proc cmpOperands(g: var CodeGen; c: Cursor; dst: Reg; swap: bool):
    tuple[a, b: Reg] =
  var x = c
  inc x                       # into the node, at the first operand
  var y = x; skip y
  let lhs = if swap: y else: x
  let rhs = if swap: x else: y
  let plan = g.classifyB(rhs, dst)
  g.emitValue(lhs, dst)
  (dst, g.materializeB(plan, dst))

proc emitCond(g: var CodeGen; c: Cursor; target: string; whenTrue: bool) =
  ## Branch to `target` when `c` holds (or does not), with no bool materialized.
  ## On a flag machine this is an optimization; here it is simply what a
  ## comparison IS.
  case c.exprKind
  of EqC, NeqC, LtC, LeC:
    let signed = g.isSignedCmp(c)
    let (cond, swap) = condOf(c, signed)
    let (a, b) = g.cmpOperands(c, StagingBridge, swap)
    g.emBranch((if whenTrue: cond else: invert(cond)), a, b, target)
  of NotC:
    var inner = c; inc inner
    g.emitCond(inner, target, not whenTrue)
  of TrueC:
    if whenTrue: g.emJmp(target)
  of FalseC:
    if not whenTrue: g.emJmp(target)
  else:
    g.emitValue(c, StagingBridge)
    g.emBranch((if whenTrue: rcNe else: rcEq), StagingBridge, Zero, target)

proc emitCmpValue(g: var CodeGen; c: Cursor; dst: Reg) =
  ## A comparison as a VALUE: 0 or 1 in `dst`.
  ##
  ## `slt` gives `<` directly. The other three are built from it and from `x0`:
  ## `a == b` is `(a xor b) == 0`, which is `seqz`; `a != b` is `snez` of the
  ## same; `a <= b` is `not (b < a)`, which is the `slt` with the operands
  ## exchanged and bit 0 flipped.
  let signed = g.isSignedCmp(c)
  var x = c
  inc x
  var y = x; skip y
  case c.exprKind
  of LtC:
    let plan = g.classifyB(y, dst)
    g.emitValue(x, dst)
    let b = g.materializeB(plan, dst)
    g.emSlt(dst, dst, b, signed)
  of LeC:
    let plan = g.classifyB(x, dst)
    g.emitValue(y, dst)
    let b = g.materializeB(plan, dst)
    g.emSlt(dst, dst, b, signed)        # b < a
    discard g.emBinImm(boXor, dst, dst, 1)
  of EqC, NeqC:
    let plan = g.classifyB(y, dst)
    g.emitValue(x, dst)
    let b = g.materializeB(plan, dst)
    g.emXorReg(dst, dst, b)
    if c.exprKind == EqC: g.emSeqz(dst, dst)
    else: g.emSnez(dst, dst)
  else:
    refuse(c, "the comparison `" & $c.exprKind & "`")

# ── lvalues ─────────────────────────────────────────────────────────────────

type
  LvalKind = enum
    lvReg        ## a local living in a register: the store is a move
    lvSlot       ## a local living in a frame slot
    lvPtr        ## through a pointer held in a register, at an offset
    lvNode       ## a `(dot …)`/`(at …)` node, handed to nifasm to fold

  Lval = object
    kind: LvalKind
    r: Reg              ## `lvReg`: the home. `lvPtr`: the pointer.
    slot: string
    off: int
    node: Cursor        ## `lvNode`: the `(dot …)`/`(at …)` itself, emitted
                        ## verbatim as a memory operand — nifasm folds it
    width: int          ## bytes: a narrow store writes only its own

proc accessWidth(g: var CodeGen; c: Cursor): tuple[bytes: int; signed: bool] =
  ## How wide the ACCESS at `c` is, and whether a load of it sign-extends. Read
  ## off the expression's own type rather than its operand's: `(deref p)` is a T,
  ## not a `ptr T`, and getting that backwards makes every byte load a word load.
  let s = g.exprSlot(c)
  let w = if s.size <= 0 or s.size > 4: 4 else: s.size
  (w, s.cls != AUInt)

proc isPow2(n: int): bool {.inline.} = n > 0 and (n and (n - 1)) == 0

proc log2i(n: int): int =
  var w = n
  while w > 1: (w = w shr 1; inc result)

proc scaledIndex(g: var CodeGen; p: BPlan; dst: Reg; elemW: int): Reg =
  ## The index, scaled by the element size and left somewhere it is safe to have
  ## scaled. `materializeB` may hand back a local's HOME register — shifting that
  ## in place would destroy the local, which is how `a[i]` first read the wrong
  ## element and left `i` multiplied by four.
  ##
  ## The stride is NOT always a power of two: an array of three-word structs
  ## strides by twelve. Shifting by `log2` of that quietly multiplies by eight,
  ## which is a wrong answer rather than a crash — `aggr_lval_copy` read the
  ## wrong array element and still exited with a plausible number.
  result = g.materializeB(p, dst)
  if elemW <= 1: return
  if result notin {StagingBridge, StagingBridge2}:
    let into = otherBridge(dst)
    g.emMv(into, result)
    result = into
  if isPow2(elemW):
    discard g.emBinImm(boShl, result, result, int64(log2i(elemW)))
  else:
    # A real multiply, and the stride has to be in a register for it. Both
    # bridges are spoken for — one holds the index, the other may hold the base
    # address — so the caller parks that address and this borrows the register.
    let other = (if result == StagingBridge: StagingBridge2 else: StagingBridge)
    g.emLi(other, int64(elemW))
    g.emBin(boMul, result, result, other)

proc strideOf(g: var CodeGen; c: Cursor): int =
  ## The size of what `c` denotes, UNCLAMPED. `accessWidth` caps at a register
  ## because it sizes a load; a stride must not be capped, or an array of
  ## two-word rows indexes by one word.
  let s = g.exprSlot(c)
  if s.size <= 0: 4 else: s.size

proc emitAddrOf(g: var CodeGen; c: Cursor; dst: Reg)

proc emitIndexedAddr(g: var CodeGen; c: Cursor; dst: Reg) =
  ## The address of `(at base idx)` with a COMPUTED index, into `dst`.
  ##
  ## One procedure rather than three copies, because the ordering here is what
  ## went wrong twice: the base address and the scaled index are both live at the
  ## `add`, and scaling can itself need both bridges when the stride is not a
  ## power of two. So the address is parked across the scaling and reloaded into
  ## a register the index is known not to be in.
  let stride = g.strideOf(c)
  var base = c; inc base
  var idx = base; skip idx
  g.emitAddrOf(base, dst)
  if isPow2(stride):
    let plan = g.classifyB(idx, dst)
    let ir = g.scaledIndex(plan, dst, stride)
    g.emBin(boAdd, dst, dst, ir)
    return
  let addrSlot = g.mintSlot("eaddr")
  g.emStoreSlot(addrSlot, dst)
  let plan = g.classifyB(idx, dst)
  var ir = g.scaledIndex(plan, dst, stride)
  if ir == dst:
    # The reload below would land on top of it.
    let other = otherBridge(dst)
    g.emMv(other, ir)
    ir = other
  g.emLoadSlot(dst, addrSlot)
  g.emBin(boAdd, dst, dst, ir)

proc emitAddrOf(g: var CodeGen; c: Cursor; dst: Reg) =
  ## The ADDRESS of an lvalue, in a register.
  ##
  ## The recursive cases are the point. `(at (at m i) j)` asks for the address of
  ## an inner ROW, and falling back to `emitValue` there would LOAD the row's
  ## first word and use it as a pointer — which is how the nested-array fixtures
  ## segfaulted rather than merely answering wrongly.
  if c.kind == Symbol:
    let name = symName(c)
    let home = g.plan.locationOfSym(name, cursorToPosition(g.buf[], c))
    if home.kind == NamedStack:
      g.emLeaSlot(dst, home.name)
      return
    if home.kind == InReg:
      g.emMv(dst, home.r)                 # already a pointer VALUE
      return
    if home.kind == NoLoc and g.prog.globals.hasKey(name):
      g.emGlobalAddr(dst, g.prog.gvarAsmName(name))
      return
    refuse(c, "the address of `" & name & "`")
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
      g.emitValue(v, dst)                 # the pointer IS the address
      return
    else: discard
  g.emitValue(c, dst)

proc mintCtorSlot(g: var CodeGen; c: Cursor): string
proc mintAggrSlot(g: var CodeGen; size: int): string
proc aggrSize(g: var CodeGen; c: Cursor): int
proc isAggrCall(g: var CodeGen; c: Cursor): bool
proc emitAggrInit(g: var CodeGen; c: Cursor; slot: string)

proc emitLval(g: var CodeGen; c: Cursor; scratch: Reg): Lval =
  ## Resolve where a store GOES, emitting whatever address arithmetic that takes.
  ## `scratch` is where a computed pointer lands; it must not be the register the
  ## value being stored will live in.
  case c.kind
  of Symbol:
    let name = symName(c)
    let home = g.plan.locationOfSym(name, cursorToPosition(g.buf[], c))
    case home.kind
    of InReg:
      # A register-homed AGGREGATE is not the aggregate: it is a POINTER to one.
      # The allocator only gives an aggregate a register when Leng passed it by
      # reference, which it does above `aggrByRefThreshold`.
      if g.exprSlot(c).cls == AMem: Lval(kind: lvPtr, r: home.r, off: 0, width: 4)
      else: Lval(kind: lvReg, r: home.r)
    of NamedStack: Lval(kind: lvSlot, slot: home.name)
    else:
      if not g.prog.globals.hasKey(name):
        refuse(c, "a store to `" & name & "`, whose location is " & $home.kind)
      g.emGlobalAddr(scratch, g.prog.gvarAsmName(name))
      Lval(kind: lvPtr, r: scratch, off: 0, width: g.accessWidth(c).bytes)
  of TagLit:
    case c.exprKind
    of CallC:
      # A call whose result is an AGGREGATE, used as a value. The callee writes
      # through a pointer, so it is handed a minted slot and the slot IS the
      # lvalue — which is what makes `f(g())` and `(kv p (g))` work without a
      # case of their own at either site.
      if not g.isAggrCall(c):
        refuse(c, "a store to the expression `call`")
      let slot = g.mintAggrSlot(g.aggrSize(c))
      g.emitCall(c, StagingBridge, wantResult = false, aggrDst = slot)
      Lval(kind: lvSlot, slot: slot)
    of OconstrC, AconstrC:
      # A constructor used as a VALUE — a returned one, a call argument, or the
      # value of an enclosing constructor's field. It has no home of its own, so
      # it gets one: a minted slot, built in place, handed back as an lvalue like
      # any other. That is what makes `f((oconstr T …))` a copy of a real object
      # rather than a shape with nowhere to live.
      let slot = g.mintCtorSlot(c)
      g.emitAggrInit(c, slot)
      Lval(kind: lvSlot, slot: slot)
    of DerefC, HaddrC:
      let (w, _) = g.accessWidth(c)
      var v = c; inc v
      g.emitValue(v, scratch)
      Lval(kind: lvPtr, r: scratch, off: 0, width: w)
    of DotC:
      # The field's offset is NIFASM's to compute — it has the layout, arkham
      # only names the field. So this is not an address computation at all: the
      # whole `(dot …)` becomes one memory operand.
      Lval(kind: lvNode, node: c, width: g.accessWidth(c).bytes)
    of AtC:
      # A CONSTANT index folds the same way. A computed one cannot: there is no
      # scaled address mode, so the multiply is arkham's and the result is a
      # plain pointer.
      var idx = c; inc idx; skip idx
      if idx.kind in {IntLit, UIntLit}:
        return Lval(kind: lvNode, node: c, width: g.accessWidth(c).bytes)
      g.emitIndexedAddr(c, scratch)
      Lval(kind: lvPtr, r: scratch, off: 0, width: g.accessWidth(c).bytes)
    of PatC:
      # `(pat p idx)` — a pointer indexed by an element count, which is a shift
      # the emitter writes out because the machine has no scaled address mode.
      let (elemW, _) = g.accessWidth(c)
      var base = c; inc base
      var idx = base; skip idx
      g.emitValue(base, scratch)
      let plan = g.classifyB(idx, scratch)
      let ir = g.scaledIndex(plan, scratch, elemW)
      g.emBin(boAdd, scratch, scratch, ir)
      Lval(kind: lvPtr, r: scratch, off: 0, width: elemW)
    else:
      refuse(c, "a store to the expression `" & $c.exprKind & "`")
  else:
    refuse(c, "this store destination")

proc storeTo(g: var CodeGen; lv: Lval; src: Reg) =
  case lv.kind
  of lvReg: g.emMv(lv.r, src)
  of lvSlot: g.emStoreSlotW(lv.slot, src, lv.width)
  of lvPtr: g.emStorePtr(lv.r, lv.off, src, lv.width)
  of lvNode: g.emStoreNode(lv.node, src, lv.width)

# ── aggregate copy ──────────────────────────────────────────────────────────

proc emitPieceLoad(g: var CodeGen; lv: Lval; off, w: int; into: Reg) =
  case lv.kind
  of lvSlot: g.emLoadSlotOff(into, lv.slot, off)
  of lvNode: g.emLoadNodeOff(into, lv.node, off, w)
  of lvPtr: g.emLoadPtr(into, lv.r, off, w, signed = false)
  of lvReg: raiseAssert "arkham rv32: an aggregate cannot live in a register"

proc emitPieceStore(g: var CodeGen; lv: Lval; off, w: int; src: Reg) =
  case lv.kind
  of lvSlot: g.emStoreSlotOff(lv.slot, off, src)
  of lvNode: g.emStoreNodeOff(lv.node, off, src, w)
  of lvPtr: g.emStorePtr(lv.r, off, src, w)
  of lvReg: raiseAssert "arkham rv32: an aggregate cannot live in a register"

proc emitAggrCopy(g: var CodeGen; dst, src: Lval; size: int) =
  ## Copy `size` bytes, a word at a time with a narrower tail.
  ##
  ## Fully unrolled, and that is a decision rather than an oversight: a loop
  ## needs a counter and two live pointers, which is three registers on a machine
  ## where the emitter owns two — and the sizes that reach here are struct sizes,
  ## not buffer sizes. A `memcpy` of a runtime length is a different problem and
  ## belongs to a runtime routine.
  ##
  ## Neither side needs an address REGISTER when it is frame-relative, which is
  ## the common case: `(mem <slot> off)` carries the whole address. Only a
  ## computed one occupies a bridge, and at most one of the two can — the other
  ## is then reloaded per piece.
  const MaxUnroll = 64
  if size > MaxUnroll:
    lengError default(Cursor),
      "RV32: an aggregate copy of " & $size & " bytes would unroll to " &
      $(size div 4) & " word moves; a copy that large wants a runtime routine " &
      "(see R5d in doc/internals/rv32.md)"
  # The data register must be neither address register. Choosing it against the
  # destination alone was not enough: a load into the register holding the SOURCE
  # pointer destroys that pointer, so only the first word copied correctly and
  # the second dereferenced a struct field.
  let into = (if (dst.kind == lvPtr and dst.r == StagingBridge) or
                 (src.kind == lvPtr and src.r == StagingBridge): StagingBridge2
              else: StagingBridge)
  var off = 0
  while off < size:
    # Word at a time, with a narrower tail. A frame slot's own moves are always
    # words — an aggregate slot is word-aligned and word-padded — so the tail
    # only arises for a POINTER destination into a packed structure.
    let w = if size - off >= 4: 4 elif size - off >= 2: 2 else: 1
    g.emitPieceLoad(src, off, w, into)
    g.emitPieceStore(dst, off, w, into)
    off += w

proc mintAggrSlot(g: var CodeGen; size: int): string =
  ## A frame slot sized to hold an aggregate. Declared as an ARRAY OF BYTES
  ## rather than with the aggregate's own type: what is wanted is `size` bytes,
  ## and repeating the type would make this a second place the layout has to
  ## agree.
  inc g.emitTmpSpills
  result = SynthMark & "eagg" & $g.emitTmpSpills & ".0"
  g.ab.open NifasmDecl.VarD
  g.ab.symDef result
  g.ab.keyword SO
  g.ab.arrayType:
    g.ab.uintType 8
    g.ab.intLit size
  g.ab.close()

proc mintCtorSlot(g: var CodeGen; c: Cursor): string =
  ## A frame slot for a CONSTRUCTOR's result, declared with the constructor's own
  ## type rather than as bytes.
  ##
  ## The type matters here where it does not in `mintAggrSlot`: a constructor is
  ## filled in by `(dot slot f)` and `(at slot i)`, and nifasm scales an index by
  ## the ELEMENT — so a byte-array slot made `(at slot 1)` mean byte 1. An
  ## `(aconstr IntArr3 20 15 7)` wrote 20, 15 and 7 into the first three bytes of
  ## the first element and the sum came out 20.
  inc g.emitTmpSpills
  result = SynthMark & "ector" & $g.emitTmpSpills & ".0"
  var tc = c; inc tc                        # into the constructor, at its type
  g.ab.open NifasmDecl.VarD
  g.ab.symDef result
  g.ab.keyword SO
  g.genTypeBodyRv(tc)
  g.ab.close()

proc aggrSize(g: var CodeGen; c: Cursor): int =
  let s = g.exprSlot(c)
  if s.size <= 0: 0 else: s.size

proc isAggrCall(g: var CodeGen; c: Cursor): bool =
  ## Whether a `(call …)` returns an AGGREGATE — the only kind of call that
  ## needs somewhere told to it in advance.
  ##
  ## Read off the CALLEE's declared result type rather than off `exprSlot` of the
  ## call node, and the difference is not academic: a VOID result is `.` in the
  ## decl and `slotOf` of that answers `AMem`, so `exprSlot` calls every void
  ## call an aggregate one. Every discarded void call minted a zero-byte frame
  ## slot on the strength of it.
  if c.kind != TagLit or c.exprKind != CallC: return false
  var f = c; inc f
  if f.kind != Symbol: return false
  let target = g.callTarget.getOrDefault(symName(f))
  if target.asmName.len == 0: return false
  var rtc = target.retType
  result = not cursorIsNil(rtc) and rtc.kind != DotToken and
           not (rtc.kind == TagLit and rtc.typeKind == VoidT) and
           slotOf(g.prog, rtc).cls == AMem

proc tryAggrAssign(g: var CodeGen; lhs, rhs: Cursor): bool =
  ## `b = a` where both are aggregates. Returns false when this is not one.
  if g.exprSlot(rhs).cls != AMem: return false
  if g.isAggrCall(rhs):
    # `b = f()` where `f` returns an aggregate: the callee writes THROUGH a
    # pointer, so the destination is handed over rather than copied afterwards.
    let dstLv = g.emitLval(lhs, StagingBridge)
    if dstLv.kind != lvSlot:
      refuse(lhs, "an aggregate call result stored anywhere but a frame slot")
    g.emitCall(rhs, StagingBridge, wantResult = false, aggrDst = dstLv.slot)
    return true
  let size = g.aggrSize(rhs)
  if size <= 0:
    refuse(rhs, "an aggregate of unknown size")
  # The SOURCE address is resolved first and into the second bridge, so that the
  # destination — resolved next — can have the first. Only one of the two can be
  # a computed address without the other losing its register, and the copy below
  # reads that assumption.
  let srcLv = g.emitLval(rhs, StagingBridge2)
  let dstLv = g.emitLval(lhs, StagingBridge)
  if srcLv.kind == lvPtr and dstLv.kind == lvPtr:
    refuse(lhs, "an aggregate copy where BOTH sides are computed addresses")
  g.emitAggrCopy(dstLv, srcLv, size)
  true

# ── expressions ─────────────────────────────────────────────────────────────

proc binOpOf(c: Cursor; signed: bool): RvBinOp =
  case c.exprKind
  of AddC: boAdd
  of SubC: boSub
  of MulC: boMul
  of DivC: (if signed: boDiv else: boDivu)
  of ModC: (if signed: boRem else: boRemu)
  of BitandC: boAnd
  of BitorC: boOr
  of BitxorC: boXor
  of ShlC: boShl
  of ShrC: (if signed: boSar else: boShr)
  else: refuse(c, "the operator `" & $c.exprKind & "`")

proc emitBin(g: var CodeGen; c: Cursor; dst: Reg) =
  var t = c
  inc t                       # the operand type
  let signed = typeToSlot(t).cls != AUInt
  let op = binOpOf(c, signed)
  var a = t; skip a
  var b = a; skip b
  let plan = g.classifyB(b, dst)
  g.emitValue(a, dst)
  if plan.kind == bkImm and g.emBinImm(op, dst, dst, plan.imm):
    return
  let br = g.materializeB(plan, dst)
  g.emBin(op, dst, dst, br)

proc emitValue(g: var CodeGen; c: Cursor; dst: Reg) =
  assert dst != StagingBridge or true    # the bridge IS a legal destination
                                         # here: it is only live for one
                                         # instruction and nothing nests inside
  case c.kind
  of IntLit: g.emLi(dst, intVal(c))
  of UIntLit: g.emLi(dst, cast[int64](uintVal(c)))
  of CharLit: g.emLi(dst, int64(ord(charLit(c))))
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    case home.kind
    of InReg: g.emMv(dst, home.r)
    of NamedStack:
      let (w, signed) = g.accessWidth(c)
      g.emLoadSlotW(dst, home.name, w, signed)
    else:
      # A GLOBAL. Its address is a `lui`+`addi` pair, so a read is that plus one
      # load — there is no PC-relative operand to fold it into.
      let name = symName(c)
      if not g.prog.globals.hasKey(name):
        refuse(c, "a read of `" & name & "`, whose location is " & $home.kind)
      let (w, signed) = g.accessWidth(c)
      g.emGlobalAddr(dst, g.prog.gvarAsmName(name))
      g.emLoadPtr(dst, dst, 0, w, signed)
  of StrLit:
    # A string literal becomes a read-only blob in the CODE segment — which is
    # readable here because this is a von Neumann machine and a hosted one, so
    # nothing special is needed to reach it. (AVR cannot do this: its constants
    # would be in flash, a different address space reached only by `lpm`.)
    let nm = "msg." & $g.rodata.len & "." & g.prog.thisModuleSuffix
    # NUL-terminated, for the reason x86-64's is: a Leng string literal reaches a
    # call as a bare address, and nothing downstream says whether the callee
    # reads it as a `cstring` or as the payload of a length-carrying `string`.
    # The terminator is invisible to the second use, whose size travels
    # separately.
    g.rodata.add (nm, strVal(c) & '\0')
    g.emGlobalAddrLabel(dst, nm)
  of TagLit:
    case c.exprKind
    of SufC, ParC:
      var v = c; inc v
      g.emitValue(v, dst)
    of TrueC: g.emLi(dst, 1)
    of FalseC: g.emLi(dst, 0)
    of NilC: g.emLi(dst, 0)
    of AddC, SubC, MulC, DivC, ModC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      g.emitBin(c, dst)
    of EqC, NeqC, LtC, LeC: g.emitCmpValue(c, dst)
    of NotC:
      # A BOOL not: the value is 0 or 1, so `seqz` is exactly it — and it is one
      # instruction, where a flag machine needs a compare and a set.
      var v = c; inc v
      g.emitValue(v, dst)
      g.emSeqz(dst, dst)
    of NegC:
      var v = c; inc v
      g.emitValue(v, dst)
      g.emBin(boSub, dst, Zero, dst)     # `neg` IS `sub d, x0, s`
    of BitnotC:
      var v = c; inc v
      g.emitValue(v, dst)
      discard g.emBinImm(boXor, dst, dst, -1)   # `not` IS `xori d, s, -1`
    of ConvC, CastC:
      var v = c; inc v
      let toSlot = typeToSlot(v)
      skip v
      let fromSlot = typeToSlot(v)
      if toSlot.size < fromSlot.size:
        refuse(c, "a narrowing conversion (" & $(fromSlot.size * 8) & " to " &
                  $(toSlot.size * 8) & " bits)")
      g.emitValue(v, dst)
    of AddrC, HaddrC:
      # `emitAddrOf` covers every case: a local (which the analyser has already
      # spilled, since taking an address marks it `AddrTaken`), a global, and a
      # field or element of either.
      var v = c; inc v
      g.emitAddrOf(v, dst)
    of DotC:
      let (w, signed) = g.accessWidth(c)
      g.emLoadNode(dst, c, w, signed)
    of AtC:
      var idx = c; inc idx; skip idx
      let (w, signed) = g.accessWidth(c)
      if idx.kind in {IntLit, UIntLit}:
        g.emLoadNode(dst, c, w, signed)
      else:
        g.emitIndexedAddr(c, dst)
        g.emLoadPtr(dst, dst, 0, w, signed)
    of DerefC:
      let (w, signed) = g.accessWidth(c)
      var v = c; inc v
      g.emitValue(v, dst)
      g.emLoadPtr(dst, dst, 0, w, signed)
    of PatC:
      let (elemW, signed) = g.accessWidth(c)
      var base = c; inc base
      var idx = base; skip idx
      g.emitValue(base, dst)
      let plan = g.classifyB(idx, dst)
      let ir = g.scaledIndex(plan, dst, elemW)
      g.emBin(boAdd, dst, dst, ir)
      g.emLoadPtr(dst, dst, 0, elemW, signed)
    of CallC: g.emitCall(c, dst, wantResult = true)
    else:
      refuse(c, "the expression `" & $c.exprKind & "`")
  else:
    refuse(c, "this expression")

# ── calls ───────────────────────────────────────────────────────────────────

proc emitCall(g: var CodeGen; c: Cursor; dst: Reg; wantResult: bool;
              aggrDst = "") =
  ## `aggrDst` names the frame slot an AGGREGATE result must be written into.
  ## This target's aggregate convention is by-REFERENCE throughout and at every
  ## size: an aggregate argument is a pointer to a copy the caller made, and an
  ## aggregate result is written through a hidden first pointer.
  ##
  ## That is NOT ilp32, which passes a two-word aggregate in two registers. It is
  ## chosen deliberately: arkham owns both sides of every call here — nothing
  ## links against C on this target yet — and one uniform rule with no size
  ## threshold and no register pairs is a rule the two ends cannot apply
  ## differently. When C interop arrives it becomes wrong, and
  ## `aggrByRefThreshold` in the machine model is where the real rule already is.
  var f = c
  inc f
  if f.kind != Symbol: refuse(c, "an indirect call")
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
  if args.len > g.md.intArgRegs.len:
    refuse(c, "a call with " & $args.len & " arguments — this target passes " &
              $g.md.intArgRegs.len & " in registers and the rest on the stack (R5)")

  let target = g.callTarget.getOrDefault(callee)
  if target.asmName.len == 0:
    refuse(c, "a call to `" & callee & "`, which is not a known proc")
  if target.extern or target.memIntrin.len > 0 or target.bitBuiltin.len > 0:
    refuse(c, "a call to `" & callee & "`: externs and inlined intrinsics are R5")
  # A SYSCALL is not special here: `emitSyscallShim` emitted it as an ordinary
  # proc, so the declarative call protocol applies to it unchanged.

  # Every argument is parked before any is marshalled. Heavier than the fused
  # backends' scheme, and what makes this total: an argument whose own evaluation
  # is a call would otherwise have to keep the earlier ones alive across it, in
  # registers a call destroys.
  var rtc = target.retType
  # A VOID result is `.` in the decl, and `typeToSlot` of that answers `AMem` —
  # so without the two guards below every call to a void proc thought it needed
  # a hidden result pointer, and shifted every argument by one.
  let retsAggr = not cursorIsNil(rtc) and rtc.kind != DotToken and
                 not (rtc.kind == TagLit and rtc.typeKind == VoidT) and
                 slotOf(g.prog, rtc).cls == AMem
  if retsAggr and aggrDst.len == 0:
    refuse(c, "the result of `" & callee & "`, which is an aggregate, used " &
              "somewhere with no place to put it")
  let shift = if retsAggr: 1 else: 0
  if args.len + shift > g.md.intArgRegs.len:
    refuse(c, "a call with " & $args.len & " arguments plus a hidden result " &
              "pointer — more than this target passes in registers (R5d)")

  # An AGGREGATE argument is copied first and its address passed: the callee gets
  # a pointer to the CALLER's copy, so it may write through it without the caller
  # seeing that.
  var slots: seq[string] = @[]
  for i in 0 ..< args.len:
    let sl = g.mintSlot("earg")
    if g.exprSlot(args[i]).cls == AMem:
      let size = g.aggrSize(args[i])
      let tmp = g.mintAggrSlot(size)
      let srcLv = g.emitLval(args[i], StagingBridge2)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: tmp), srcLv, size)
      g.emLeaSlot(StagingBridge, tmp)
    else:
      g.emitValue(args[i], StagingBridge)
    g.emStoreSlot(sl, StagingBridge)
    slots.add sl

  g.ab.open PrepareRv
  g.ab.sym target.asmName
  if retsAggr:
    # The hidden result pointer goes FIRST, which is why every other argument
    # shifts by one — the arrangement x86-64 uses too.
    g.emLeaSlot(StagingBridge, aggrDst)
    g.ab.tree MovRv:
      g.ab.tree ArgX: g.ab.sym paramName(0)
      g.emReg StagingBridge
  for i in 0 ..< args.len:
    g.emLoadSlot(StagingBridge, slots[i])
    g.ab.tree MovRv:
      g.ab.tree ArgX: g.ab.sym paramName(i + shift)
      g.emReg StagingBridge
  g.ab.keyword CallRv
  if retsAggr:
    discard                                   # already written into `aggrDst`
  elif not cursorIsNil(target.retType) and target.retType.typeKind != VoidT:
    g.ab.tree MovRv:
      (if wantResult: g.emReg dst else: g.emReg StagingBridge)
      g.ab.tree ResX: g.ab.sym synth("ret.0")
  elif wantResult:
    refuse(c, "using the result of `" & callee & "`, which returns nothing")
  g.ab.close()

# ── statements ──────────────────────────────────────────────────────────────

proc destOfSym(g: var CodeGen; name: string; pos: int): Reg =
  let home = g.plan.locationOfSym(name, pos)
  if home.kind == InReg: home.r else: StagingBridge

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
        if g.exprSlot(kv).cls == AMem:
          # A NESTED aggregate — a struct inside a struct, or a constructor for
          # one. The field is an address like any other destination, so this is
          # the ordinary copy rather than a case of its own.
          let size = g.aggrSize(kv)
          let srcLv = g.emitLval(kv, StagingBridge2)
          g.emLeaField(StagingBridge, slot, fieldName)
          g.emitAggrCopy(Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 4),
                         srcLv, size)
        else:
          let w = g.accessWidth(kv).bytes
          g.emitValue(kv, StagingBridge)
          g.emStoreField(slot, fieldName, StagingBridge, w)
        skip f
  of AconstrC:
    var e = c
    var i = 0
    e.into:
      skip e                                     # the type
      while e.hasMore:
        if g.exprSlot(e).cls == AMem:
          let size = g.aggrSize(e)
          let srcLv = g.emitLval(e, StagingBridge2)
          g.emLeaElem(StagingBridge, slot, i)
          g.emitAggrCopy(Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 4),
                         srcLv, size)
        else:
          let w = g.accessWidth(e).bytes
          g.emitValue(e, StagingBridge)
          g.emStoreElem(slot, i, StagingBridge, w)
        inc i
        skip e
  else:
    refuse(c, "this aggregate initializer")

proc genVarDecl(g: var CodeGen; c: Cursor) =
  var v = c
  inc v
  let name = symName(v)
  let pos = cursorToPosition(g.buf[], v)
  inc v
  skip v                                  # the var's pragmas
  let typeCur = v
  skip v
  g.checkWidth(typeCur, "the local `" & name & "`")
  let home = g.plan.locationOfSym(name, pos)
  case home.kind
  of InReg: g.emRegVar(name, home.r, typeCur)
  of NamedStack: g.emSlotVar(home.name, typeCur)
  else:
    lengError c, "RV32: the local `" & name & "` was given no storage", lengInfo(c)
  if v.hasMore and v.kind != DotToken:
    if not (v.kind == TagLit and v.exprKind in {OconstrC, AconstrC}) and
       g.exprSlot(v).cls == AMem:
      if home.kind != NamedStack:
        lengError c, "an aggregate local must live in a frame slot", lengInfo(c)
      if g.isAggrCall(v):
        # The callee writes straight into this local, with no copy in between.
        g.emitCall(v, StagingBridge, wantResult = false, aggrDst = home.name)
        return
      # Any other aggregate initializer IS a copy.
      let srcLv = g.emitLval(v, StagingBridge2)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: home.name), srcLv, g.aggrSize(v))
      return
    if v.kind == TagLit and v.exprKind in {OconstrC, AconstrC}:
      if home.kind != NamedStack:
        lengError c, "an aggregate local must live in a frame slot", lengInfo(c)
      g.emitAggrInit(v, home.name)
      return
    let dst = g.destOfSym(name, pos)
    g.emitValue(v, dst)
    if home.kind != InReg:
      var tc0 = typeCur
      g.emStoreSlotW(home.name, dst, slotOf(g.prog, tc0).size)

proc genAsgn(g: var CodeGen; c: Cursor) =
  var lhs = c
  inc lhs
  var rhs = lhs
  skip rhs
  if g.tryAggrAssign(lhs, rhs): return
  if lhs.kind == Symbol and
     g.plan.locationOfSym(symName(lhs), cursorToPosition(g.buf[], lhs)).kind !=
       NoLoc:
    # A LOCAL, kept separate because it needs no address at all. A global falls
    # through to the address path below.
    let name = symName(lhs)
    let pos = cursorToPosition(g.buf[], lhs)
    let dst = g.destOfSym(name, pos)
    g.emitValue(rhs, dst)
    let home = g.plan.locationOfSym(name, pos)
    if home.kind != InReg:
      g.emStoreSlotW(home.name, dst, g.accessWidth(lhs).bytes)
    return
  # A store through an address. The ADDRESS is computed first and parked, and
  # then the value: the other order would need the address to survive the value's
  # own walk, which may use every bridge there is.
  let addrSlot = g.mintSlot("eaddr")
  let lv = g.emitLval(lhs, StagingBridge)
  case lv.kind
  of lvNode:
    # nifasm folds the address, so nothing has to survive the value's walk.
    g.emitValue(rhs, StagingBridge)
    g.emStoreNode(lv.node, StagingBridge, lv.width)
  of lvPtr:
    # A computed address. It is parked before the value is evaluated: the other
    # order would need it to survive that walk, which uses every bridge there is.
    g.emStoreSlot(addrSlot, lv.r)
    g.emitValue(rhs, StagingBridge)
    let valSlot = g.mintSlot("eval")
    g.emStoreSlot(valSlot, StagingBridge)
    g.emLoadSlot(StagingBridge, addrSlot)
    g.emLoadSlot(StagingBridge2, valSlot)
    g.emStorePtr(StagingBridge, lv.off, StagingBridge2, lv.width)
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
      let srcLv = g.emitLval(v, StagingBridge2)
      g.emLoadSlot(StagingBridge, g.retAggrSlot)
      g.emitAggrCopy(Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 4),
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
  let lEnd = g.freshLabel("wend")
  g.loopEnds.add lEnd
  g.ab.tree LoopRv:
    g.ab.tree StmtsRv:
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
      lengError c, "RV32: `break` outside a loop", lengInfo(c)
    g.emJmp(g.loopEnds[^1])
  of CallS:
    # A discarded call. An aggregate result still has to go SOMEWHERE — the
    # callee writes through the pointer whether anyone reads it or not.
    if g.isAggrCall(c):
      let tmp = g.mintAggrSlot(g.aggrSize(c))
      g.emitCall(c, StagingBridge, wantResult = false, aggrDst = tmp)
    else:
      g.emitCall(c, StagingBridge, wantResult = false)
  of DiscardS:
    var v = c; inc v
    if v.hasMore and v.kind != DotToken: g.emitValue(v, StagingBridge)
  of LabS:
    var v = c; inc v
    g.emLab(symName(v))
  of JmpS:
    var v = c; inc v
    g.emJmp(symName(v))
  else:
    refuse(c, "the statement `" & $c.stmtKind & "`")

# ── frames ──────────────────────────────────────────────────────────────────

const SysExit = 93
  ## The asm-generic number, shared with RV64 and AArch64. The entry proc's
  ## `ret` IS the process exit: this is a hosted target, so unlike Cortex-M and
  ## AVR the exit is a real syscall rather than a simulator's private trap.

proc emitSyscallShim*(g: var CodeGen; sp: SyscallProc) =
  ## A syscall as an ordinary PROC, called like any other. Cortex-M does the same
  ## for its semihosting shims, and for the same reason: the call site then needs
  ## no special case at all, and the `(prepare …)` protocol keeps checking the
  ## arguments against the signature.
  ##
  ## Three instructions, because the ABIs already agree — a syscall takes its
  ## arguments in `a0`..`a5` and returns in `a0`, exactly as a call does. Only the
  ## NUMBER has to be put anywhere, and `a7` is not an argument register.
  ##
  ## RV32 shares the asm-generic numbers with AArch64, so `sysNrA64` is this
  ## target's number too — there is no third column to add.
  if sp.sysNrA64 < 0:
    lengError sp.decl, "RV32: `" & sp.asmName & "` has no syscall number in the " &
              "asm-generic table this target uses", lengInfo(sp.decl)
  var params: seq[Cursor] = @[]
  var c = sp.decl
  inc c; inc c
  if c.kind == TagLit:
    var p = c
    p.into:
      while p.hasMore:
        var d = p
        d.into:
          inc d                                # the name
          skip d                               # the param's pragmas
          params.add d
          while d.hasMore: skip d
        skip p
  if params.len > g.md.intArgRegs.len:
    lengError sp.decl, "RV32: `" & sp.asmName & "` takes more arguments than " &
              "the syscall ABI passes in registers", lengInfo(sp.decl)
  var rt = sp.decl
  inc rt; inc rt; skip rt
  let hasResult = not (rt.kind == DotToken or
                       (rt.kind == TagLit and rt.typeKind == VoidT))

  g.ab.open NifasmDecl.ProcD
  g.ab.symDef sp.asmName
  g.ab.tree NifasmDecl.ParamsD:
    for i in 0 ..< params.len:
      g.ab.tree NifasmDecl.ParamD:
        g.ab.symDef paramName(i)
        g.ab.rawReg g.md.intArgRegs[i]
        var tc = params[i]
        g.genTypeBodyRv(tc)
  if hasResult:
    g.ab.tree NifasmDecl.ResultD:
      g.ab.symDef synth("ret.0")
      g.ab.rawReg g.md.intRetReg
      var tc = rt
      g.genTypeBodyRv(tc)
  g.ab.tree NifasmDecl.ClobberD:
    for r in g.md.convClobbersGpr: g.ab.rawReg r
  g.ab.tree StmtsRv:
    # The arguments are already where the kernel wants them, and the parameters
    # are declared at those registers — so they are read by name here purely so
    # that nifasm's binding table sees them used, and then killed.
    for i in 0 ..< params.len:
      g.ab.tree KillRv: g.ab.sym paramName(i)
    g.emLi(R17, int64(sp.sysNrA64))          # a7
    g.ab.keyword EcallRv
    g.ab.keyword RetRv
  g.ab.close()

proc collectParams(g: var CodeGen; decl: Cursor): seq[tuple[name: string; typ: Cursor]] =
  result = @[]
  var c = decl
  inc c; inc c
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

proc genProcRv*(g: var CodeGen; info: ProcInfo) =
  if info.isAsm or info.isNaked or info.irqName.len > 0:
    lengError info.decl,
      "RV32: `{.assembler.}`, `{.naked.}` and `{.interrupt.}` are not " &
      "implemented yet (see R5 in doc/internals/rv32.md)", lengInfo(info.decl)

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
  g.plan = allocateProc(g.buf[], info.decl, an, g.prog, rv32Machine, g.typeCtx)

  let params = g.collectParams(info.decl)
  if params.len > g.md.intArgRegs.len:
    lengError info.decl,
      "RV32: this proc takes " & $params.len & " parameters; the target passes " &
      $g.md.intArgRegs.len & " in registers and the rest on the stack (R5)",
      lengInfo(info.decl)

  var rt = info.decl
  inc rt; inc rt; skip rt
  let hasResult = not (rt.kind == DotToken or
                       (rt.kind == TagLit and rt.typeKind == VoidT))
  var rtc0 = rt
  let retsAggr = hasResult and slotOf(g.prog, rtc0).cls == AMem
  gRetAggrSlot = ""
  let shift = if retsAggr: 1 else: 0
  if params.len + shift > g.md.intArgRegs.len:
    lengError info.decl,
      "RV32: this proc takes " & $params.len & " parameters plus a hidden " &
      "result pointer, more than the target passes in registers (R5d)",
      lengInfo(info.decl)

  g.ab.open NifasmDecl.ProcD
  g.ab.symDef info.asmName
  g.ab.tree NifasmDecl.ParamsD:
    if retsAggr:
      # The hidden result pointer, first. Its TYPE is a pointer, not the
      # aggregate — what arrives in the register is an address.
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
            g.genTypeBodyRv(inner)
        else:
          var tc = params[i].typ
          g.genTypeBodyRv(tc)
  if hasResult and not retsAggr:
    g.checkWidth(rt, "the result of `" & info.asmName & "`")
    g.ab.tree NifasmDecl.ResultD:
      g.ab.symDef synth("ret.0")
      g.ab.rawReg g.md.intRetReg
      var tc = rt
      g.genTypeBodyRv(tc)
  g.ab.tree NifasmDecl.ClobberD:
    for r in g.md.convClobbersGpr: g.ab.rawReg r

  # ── the body, into a side buffer ────────────────────────────────────────
  # Which callee-saved registers the allocator used, and whether anything was
  # spilled, is only known once the walk has finished — and both decide the
  # prologue.
  var side = g.ab.sideBuf()
  swap(g.ab, side)
  g.rb.enterScope()

  if retsAggr: g.rb.bindParam(g.md.intArgRegs[0], paramName(0))
  for i in 0 ..< params.len:
    g.rb.bindParam(g.md.intArgRegs[i + shift], paramName(i + shift))
  if retsAggr:
    # Park the hidden pointer for the proc's lifetime: it is needed at every
    # `ret`, and a0 is caller-saved and also the first argument of any call the
    # body makes.
    gRetAggrSlot = SynthMark & "retp.0"
    g.emWordSlot gRetAggrSlot
    g.emStoreSlot(gRetAggrSlot, g.md.intArgRegs[0])
    g.ab.tree KillRv: g.ab.sym paramName(0)
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
      g.emMv(StagingBridge, src)
      g.emitAggrCopy(Lval(kind: lvSlot, slot: home.name),
                     Lval(kind: lvPtr, r: StagingBridge, off: 0, width: 4),
                     slotOf(g.prog, stc).size)
    elif slotOf(g.prog, ptc).cls == AMem:
      # The ALLOCATOR gave this aggregate a register home, which it only does for
      # one above `aggrByRefThreshold` — Leng passes those by reference already,
      # so what arrives is a pointer and the register holds it for the proc's
      # life. No copy: by-reference is what the caller was told to do.
      if home.kind != InReg:
        lengError info.decl, "RV32: the aggregate parameter `" & nm &
                  "` was given neither a slot nor a register (" & $home.kind & ")",
                  lengInfo(info.decl)
      g.emRegPtrVar(nm, home.r, params[i].typ)
      g.emMv(home.r, src)
    else:
      g.checkWidth(params[i].typ, "the parameter `" & nm & "`")
      case home.kind
      of InReg:
        g.emRegVar(nm, home.r, params[i].typ)  # kills `pN.0` when it IS this reg
        g.emMv(home.r, src)
      of NamedStack:
        var ptc0 = params[i].typ
        g.emSlotVar(home.name, params[i].typ)
        g.emStoreSlotW(home.name, src, slotOf(g.prog, ptc0).size)
      else:
        lengError info.decl, "RV32: the parameter `" & nm & "` was given no storage",
                  lengInfo(info.decl)
    if g.rb.boundName(src) == paramName(i + shift):
      g.ab.tree KillRv: g.ab.sym paramName(i + shift)
      discard g.rb.takeBinding(src)

  var body = info.decl
  inc body; inc body; skip body; skip body; skip body
  if body.stmtKind == StmtsS:
    var bc = body
    bc.into:
      while bc.hasMore: (g.genStmt(bc); skip bc)

  discard g.rb.exitScope()
  swap(g.ab, side)

  # ── the prologue ────────────────────────────────────────────────────────
  var saved: seq[Reg] = @[]
  for r in g.md.intCalleeSaved:
    if r in g.plan.usedCallee: saved.add r
  # `ra` is saved exactly when something can overwrite it, which is exactly when
  # this proc calls something. The entry proc never returns, so it never needs
  # one either.
  let savesRa = an.callPositions.len > 0 and not info.isEntry

  g.ab.open StmtsRv
  var saveSlots: seq[string] = @[]
  var raSlot = ""
  # The save slots are declared FIRST, so nifasm gives them the lowest offsets
  # and `(ssize)` covers them along with everything the body minted.
  if savesRa:
    raSlot = SynthMark & "svra.0"
    g.emWordSlot raSlot
  for i in 0 ..< saved.len:
    let nm = SynthMark & "sv" & $i & ".0"
    g.emWordSlot nm
    saveSlots.add nm

  g.ab.tree SubRv: (g.ab.rawReg SP; g.ab.keyword SsizeX)
  if savesRa: g.emStoreSlot(raSlot, Ra)
  for i in 0 ..< saved.len: g.emStoreSlot(saveSlots[i], saved[i])

  g.ab.append(side)

  if g.retLabelUsed2: g.emLab(g.retLabel2)
  for i in 0 ..< saved.len: g.emLoadSlot(saved[i], saveSlots[i])
  if savesRa: g.emLoadSlot(Ra, raSlot)
  g.ab.tree AddRv: (g.ab.rawReg SP; g.ab.keyword SsizeX)
  if info.isEntry:
    # A hosted image's entry does not return: its result IS the exit status, and
    # `exit` is a real syscall rather than a simulator trap.
    g.emLi(R17, SysExit)                # a7
    g.ab.keyword EcallRv
  else:
    g.ab.keyword RetRv
  g.ab.close()                          # (stmts …)
  g.ab.close()                          # (proc …)
