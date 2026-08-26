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
proc emitCall(g: var CodeGen; c: Cursor; dst: Reg; wantResult: bool)

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
    lengError typeCur, "RV32: " & what & " is an aggregate; R5 covers those",
              lengInfo(typeCur)
  if s.size > 4:
    lengError typeCur, "RV32: " & what & " is " & $(s.size * 8) & " bits wide; " &
              "this backend's word is 32 and a wider value lives in a register " &
              "PAIR, which is not implemented yet (see R5)", lengInfo(typeCur)

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
  let slot = g.mintSlot("etmp")
  g.emitValue(c, dst)
  g.emStoreSlot(slot, dst)
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

proc isSignedCmp(c: Cursor): bool =
  var t = c
  inc t                       # into the node, at the operand type
  typeToSlot(t).cls != AUInt

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
  inc x; skip x               # into the node, past the operand type
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
    let signed = isSignedCmp(c)
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
  let signed = isSignedCmp(c)
  var x = c
  inc x; skip x
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
    of NamedStack: g.emLoadSlot(dst, home.name)
    else: refuse(c, "a read of `" & symName(c) & "`, whose location is " & $home.kind)
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
    of CallC: g.emitCall(c, dst, wantResult = true)
    else:
      refuse(c, "the expression `" & $c.exprKind & "`")
  else:
    refuse(c, "this expression")

# ── calls ───────────────────────────────────────────────────────────────────

proc emitCall(g: var CodeGen; c: Cursor; dst: Reg; wantResult: bool) =
  var f = c
  inc f
  if f.kind != Symbol: refuse(c, "an indirect call")
  let callee = symName(f)
  var args: seq[Cursor] = @[]
  var a = c
  inc a; skip a
  while a.hasMore:
    args.add a
    skip a
  if args.len > g.md.intArgRegs.len:
    refuse(c, "a call with " & $args.len & " arguments — this target passes " &
              $g.md.intArgRegs.len & " in registers and the rest on the stack (R5)")

  let target = g.callTarget.getOrDefault(callee)
  if target.asmName.len == 0:
    refuse(c, "a call to `" & callee & "`, which is not a known proc")
  if target.extern or target.syscall or target.memIntrin.len > 0 or
     target.bitBuiltin.len > 0:
    refuse(c, "a call to `" & callee & "`: externs, syscalls and inlined " &
              "intrinsics are R5")

  # Every argument is parked before any is marshalled. Heavier than the fused
  # backends' scheme, and what makes this total: an argument whose own evaluation
  # is a call would otherwise have to keep the earlier ones alive across it, in
  # registers a call destroys.
  var slots: seq[string] = @[]
  for i in 0 ..< args.len:
    let s = g.mintSlot("earg")
    g.emitValue(args[i], StagingBridge)
    g.emStoreSlot(s, StagingBridge)
    slots.add s

  g.ab.open PrepareRv
  g.ab.sym target.asmName
  for i in 0 ..< args.len:
    g.emLoadSlot(StagingBridge, slots[i])
    g.ab.tree MovRv:
      g.ab.tree ArgX: g.ab.sym paramName(i)
      g.emReg StagingBridge
  g.ab.keyword CallRv
  if not cursorIsNil(target.retType) and target.retType.typeKind != VoidT:
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
    let dst = g.destOfSym(name, pos)
    g.emitValue(v, dst)
    if home.kind != InReg: g.emStoreSlot(home.name, dst)

proc genAsgn(g: var CodeGen; c: Cursor) =
  var lhs = c
  inc lhs
  var rhs = lhs
  skip rhs
  if lhs.kind != Symbol: refuse(lhs, "an assignment to anything but a local")
  let name = symName(lhs)
  let pos = cursorToPosition(g.buf[], lhs)
  let dst = g.destOfSym(name, pos)
  g.emitValue(rhs, dst)
  let home = g.plan.locationOfSym(name, pos)
  if home.kind != InReg: g.emStoreSlot(home.name, dst)

proc genRet(g: var CodeGen; c: Cursor) =
  var v = c
  inc v
  if v.hasMore and v.kind != DotToken:
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
  of CallS: g.emitCall(c, StagingBridge, wantResult = false)
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

proc genProcRv*(g: var CodeGen; info: ProcInfo) =
  if info.isAsm or info.isNaked or info.irqName.len > 0:
    lengError info.decl,
      "RV32: `{.assembler.}`, `{.naked.}` and `{.interrupt.}` are not " &
      "implemented yet (see R5 in doc/internals/rv32.md)", lengInfo(info.decl)

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

  g.ab.open NifasmDecl.ProcD
  g.ab.symDef info.asmName
  g.ab.tree NifasmDecl.ParamsD:
    for i in 0 ..< params.len:
      g.ab.tree NifasmDecl.ParamD:
        g.ab.symDef paramName(i)
        g.ab.rawReg g.md.intArgRegs[i]
        var tc = params[i].typ
        g.genTypeBodyRv(tc)
  if hasResult:
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

  for i in 0 ..< params.len:
    g.rb.bindParam(g.md.intArgRegs[i], paramName(i))
  for i in 0 ..< params.len:
    let nm = params[i].name
    g.checkWidth(params[i].typ, "the parameter `" & nm & "`")
    let home = g.plan.homeOfSym(nm)
    let src = g.md.intArgRegs[i]
    case home.kind
    of InReg:
      g.emRegVar(nm, home.r, params[i].typ)   # kills `pN.0` when it IS this reg
      g.emMv(home.r, src)
    of NamedStack:
      g.emSlotVar(home.name, params[i].typ)
      g.emStoreSlot(home.name, src)
    else:
      lengError info.decl, "RV32: the parameter `" & nm & "` was given no storage",
                lengInfo(info.decl)
    if g.rb.boundName(src) == paramName(i):
      g.ab.tree KillRv: g.ab.sym paramName(i)
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
