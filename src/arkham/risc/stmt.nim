#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Statements: the walk over a proc body.
##
## `tryEmitCsel` folds a select diamond into a conditional select; it declines
## and leaves the ordinary path to it when the shape is not exactly right, which
## is what keeps the recogniser honest about what it does not handle.

import std / [assertions, tables, strformat]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, constdata,
                    mirrors, select]
import machine_a64 as machine
from machine_m as machine_m import nil
import emit, mem, aggr, value, frame
import runtime

proc genVarDecl2*(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = g.posOf(cc)
    let nm = symName(cc); inc cc
    skip cc                                                  # pragmas
    let declaredCur = cc; skip cc                            # type (`.` when shoggoth omitted it)
    let typeCur = g.declType(declaredCur, cc)                # infer from the initializer
    g.symType[nm] = typeCur
    let loc = g.plan.homeOfSym(nm)
    if typeCur.kind == TagLit and typeCur.typeKind == FT and
       typeBits(typeCur) == 128 and loc.kind != InFReg:
      # A 128-bit vector local (`(f 128)`) has no spill form: the scalar float
      # spill machinery moves 8 bytes and would silently truncate it. The
      # vectorizer keeps vector live ranges short precisely so this cannot
      # happen; failing loudly beats corrupting the upper lane.
      lengError c, "128-bit vector local `" & nm & "` did not get a SIMD register home"
    let hasVal = cc.hasMore and cc.kind != DotToken
    case loc.kind
    of InReg: g.emRegLocalVar(nm, loc.r, typeCur)
    of InRegPair:
      raiseAssert "arkham a64n: InRegPair is a param home, not a local: " & nm
    of InFReg: g.emFRegLocalVar(nm, loc.f, loc.typ.size * 8)
    of NamedStack:
      g.emTypedStackVar(nm, typeCur)                         # one route; dispatches on slot class
      if loc.typ.kind == AMem and typeCur.kind == Symbol:
        g.varType[nm] = typeCur.symId                     # aggregate field layout
    else: raiseAssert "arkham a64n: var home " & $loc.kind
    if hasVal: g.genStore2(cc, loc)
    while cc.hasMore: skip cc

proc cmpImm2(g: var CodeGen; selReg: Reg; v: int64) =
  if v >= 0 and v <= 0xFFFF:
    g.ab.tree CmpA64: (g.emReg selReg; g.ab.intLit v)
  else:
    let b = g.takeBridge(); g.movImm(b, v)
    g.ab.tree CmpA64: (g.emReg selReg; g.emReg b)
    g.dropBridge b

proc emitCaseTest2*(g: var CodeGen; selReg: Reg; c: var Cursor; lBody: string; signed: bool) =
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()
      g.cmpImm2(selReg, lo); g.emBr(if signed: BltA64 else: BloA64, lSkip)
      g.cmpImm2(selReg, hi); g.emBr(if signed: BgtA64 else: BhiA64, lSkip)
      g.emBr(BA64, lBody)
      g.emLab(lSkip)
  else:
    g.cmpImm2(selReg, branchImm(c)); g.emBr(BeqA64, lBody)

proc cselTagFor(branchTag: RiscInst): RiscInst =
  ## The `csel<cc>` whose condition matches branch tag `branchTag` (which fires
  ## when the relation holds): `csel<cc> D, S1, S2` yields `D = cc ? S1 : S2`.
  case branchTag
  of BeqA64: CseleqA64
  of BneA64: CselneA64
  of BltA64: CselltA64
  of BleA64: CselleA64
  of BgtA64: CselgtA64
  of BgeA64: CselgeA64
  of BloA64: CselloA64
  of BlsA64: CsellsA64
  of BhiA64: CselhiA64
  of BhsA64: CselhsA64
  else: raiseAssert "arkham a64n: no csel for " & $branchTag

proc tryEmitCsel(g: var CodeGen; c: Cursor): bool =
  ## Lower a select diamond (see `matchSelectDiamond`) branchlessly to
  ## `cmp; csel<cc> DST, A, B` — no forward jumps, no label. Returns false for
  ## anything that does not fit; the caller then falls back to branch lowering.
  var sd: SelectDiamond
  if not g.matchSelectDiamond(c, sd): return false
  # ── emit: cmp (sets NZCV) → THEN→bridge → ELSE→DST → csel DST, bridge, DST ──
  # The cmp reads the condition operands at their ORIGINAL values (DST not yet
  # written). THEN is captured into a fresh bridge before ELSE overwrites DST, so
  # `if c: x = x …` style self-reads stay correct; both stores are mov/ldr-only, so
  # the flags survive to the csel.
  let ct = cselTagFor(g.emitScalarCmpE(sd.a, sd.b, sd.ek, whenTrue = true))
  let rT = g.takeBridge(g.selectStagingSlot(sd))
  g.genStore2(sd.thenRhs, regLoc(rT, sd.dst.typ))
  g.genStore2(sd.elseRhs, sd.dst)
  g.ab.tree ct: (g.emReg sd.dst.r; g.emReg rT; g.emReg sd.dst.r)
  g.dropBridge rT
  return true

proc genStmt2*(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore: (g.genStmt2(cc); skip cc)
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore: (g.genStmt2(cc); skip cc)
    g.exitScope()
  of VarS, GvarS, TvarS, ConstS: g.genVarDecl2(c)
  of CallS:
    var d = dontCare                   # a statement call: result unused
    g.emitCall2(c, d)
    g.freeVal(d)
  of InstrS:
    var d = dontCare
    g.emitInstr2(c, d)
    g.freeVal(d)
  of BreakS:
    assert g.loopEnds.len > 0, "arkham a64n: `break` outside a loop"
    g.emBr(BA64, g.loopEnds[^1])
  of AsgnS:
    var cc = c
    cc.into:
      let asgnPos = g.posOf(c)
      if cc.kind == Symbol:
        let lhsCur = cc
        var dst = g.plan.locationOfSym(symName(cc), cursorToPosition(g.buf[], cc)); skip cc
        if dst.kind == NoLoc:
          var lc = lhsCur
          dst = g.asLoc(lc)
        elif dst.kind == InReg and g.varType.hasKey(symName(lhsCur)):
          # By-ref aggregate param, pointer register-homed: the destination is the
          # POINTEE — reclassify to the `Mem` lvalue form (see the x64 twin).
          dst = memLoc(lhsCur, g.exprSlot(lhsCur))
        g.genStore2(cc, dst)
      else:
        let lhsCur = cc
        var rhsCur = cc; skip rhsCur
        g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot))
      while cc.hasMore: skip cc
  of WhileS:
    let lEnd = g.freshLabel()
    g.loopEnds.add lEnd
    g.emitLoop:
      var cc = c
      cc.into:
        let condC = cc; skip cc
        g.emitCondE(condC, lEnd, whenTrue = false)     # forward exit when cond is false
        while cc.hasMore: (g.genStmt2(cc); skip cc)     # body
    g.emLab(lEnd)
    discard g.loopEnds.pop()
  of IfS:
    # `csel` is AArch64's. ARMv7-M has no conditional select at all — its
    # equivalent is an IT block, which is a different shape and not one this
    # emitter builds — so the target that lacks the instruction takes the branch
    # lowering below, which is what every other `if` on it already uses.
    if CondSelect notin g.md.caps or not g.tryEmitCsel(c):  # select diamond, else branch
      let lEnd = g.freshLabel()
      var cc = c
      cc.into:
        while cc.hasMore:
          case cc.substructureKind
          of ElifU:
            let lNext = g.freshLabel()
            var bc = cc
            bc.into:
              let condC = bc; skip bc
              g.emitCondE(condC, lNext, whenTrue = false)
              while bc.hasMore: (g.genStmt2(bc); skip bc)
              g.emBr(BA64, lEnd)
            g.emLab(lNext)
          of ElseU:
            var bc = cc
            bc.into:
              while bc.hasMore: (g.genStmt2(bc); skip bc)
          else: discard
          skip cc
      g.emLab(lEnd)
  of RetS:
    var cc = c
    cc.into:
      let hasVal = cc.hasMore and cc.kind != DotToken
      if g.isEntryProc and g.entryExits:
        if hasVal and g.isWideExpr(cc):
          # An entry that computes its exit code in 64 bits (`main` returns
          # `(i 32)`, the expression does not). The exit code is the LOW word —
          # the same truncation the ordinary narrowing return performs.
          g.wideArgTruncated(g.wideValueIntoTemp(cc), g.md.intRetReg)
        elif hasVal:
          var d = needsReg(g.valueSlot(cc))
          g.emitValue2(cc, d)
          g.place2(d, g.md.intRetReg)                            # exit code → x0 / r0
          g.freeVal(d)
        else: g.movImm(g.md.intRetReg, 0)
        if Freestanding in g.md.caps:
          g.ab.tree BlA64: g.ab.sym EntryExitShim
        else:
          g.movImm(R8, LinuxA64ExitNr.int64)
          g.ab.tree SvcA64: g.ab.intLit 0
      else:
        var tailed = false
        # An aggregate result travels by hidden pointer or in x0:x1; neither is a
        # shape the tail path marshals yet, so it keeps the ordinary route.
        # A target without `TailCall` never gets here through `emitCall2`, so
        # taking the branch below would only cost it the `wideRet` path: a 64-bit
        # result there is r0:r1 read raw, not a `NeedsReg` location `place2` can
        # settle.
        let canTail = g.retAggrSym == NoTypeSym and TailCall in g.md.caps
        if g.retAggrSym != NoTypeSym:
          var srcName: string
          if cc.kind == Symbol:
            srcName = symName(cc)                          # a named local aggregate
          else:
            # An inline aggregate VALUE returned by value (`(ret (oconstr …))` /
            # memory lvalue): materialize into a synthetic temp via the general store
            # path (mirrors the aggregate call-argument marshalling), then marshal out.
            let pos = g.posOf(cc)
            srcName = synth("rettmp") & $pos & ".0"
            var tcur = cc
            if cc.exprKind in {OconstrC, AconstrC}: inc tcur   # the constructed type
            else: tcur = g.getType(cc)
            g.emTypedStackVar(srcName, tcur)
            g.varType[srcName] = g.retAggrSym
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)))
          if g.retIndirect:
            g.copyStructThroughPtr2(srcName, g.retAggrSym, g.indirectReg)
            g.movReg(g.md.intRetReg, g.indirectReg)
          else:
            g.structToRegs(srcName, g.retAggrSym, 0)
        elif hasVal and cc.kind == TagLit and cc.exprKind == CallC and
             not g.retIsFloat and canTail:
          # `(ret (call …))` — the tail-call encoding. Leng binds every call and
          # forbids nesting them, so a call sitting directly under a `ret` is not
          # an expression that happens to be there: it is the producer saying
          # "tail-call this". Hand it to `emitCall2`, which marshals the arguments
          # exactly as for an ordinary call and then pops the frame and branches.
          #
          # It may still decline — an external target, an outgoing stack argument,
          # a by-reference result — in which case it emitted an ordinary call and
          # left the value in `d`, and we return through the epilogue as usual.
          var d = needsReg(g.valueSlot(cc))
          g.emitCall2(cc, d, tail = true)
          if not g.tailCallEmitted:
            g.place2(d, g.md.intRetReg)
            g.freeVal(d)
          tailed = g.tailCallEmitted
        elif hasVal:
          let retPos = g.posOf(cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(g.md.floatRetReg, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)))
          elif g.isWideExpr(cc):
            g.wideRet(cc)                    # 64-bit result: r0:r1, read raw
          else:
            g.genStore2(cc, regLoc(g.md.intRetReg, ScalarSlot))
        if not tailed:
          # A tail call has left the proc for good: no branch to the epilogue, and
          # nothing after it is reachable.
          g.emBr(BA64, g.retLabel2); g.retLabelUsed2 = true
      while cc.hasMore: skip cc
  of CaseS:
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      var selLoc = needsReg(g.valueSlot(selC))           # held across ALL range tests
      g.emitValue2(cc, selLoc); skip cc
      # Pool-dry etmp slot → a bridge for the (call-free) test chain; x15 stays
      # free for cmpImm2's large-literal materialization.
      var selReg: Reg
      var selBridge = NoReg
      if selLoc.kind == InReg: selReg = selLoc.r
      else:
        selBridge = g.takeBridge(selLoc.typ); g.place2(selLoc, selBridge); selReg = selBridge
      var bodies: seq[(string, Cursor)] = @[]
      var elseBody = cc
      var hasElse = false
      while cc.hasMore:
        case cc.substructureKind
        of OfU:
          let lBody = g.freshLabel()
          var branch = cc
          skip cc
          branch.into:
            branch.into:
              while branch.hasMore: g.emitCaseTest2(selReg, branch, lBody, signed)
            bodies.add (lBody, branch)
            skip branch
        of ElseU:
          elseBody = cc; hasElse = true; skip cc
        else: skip cc
      if selBridge != NoReg: g.dropBridge selBridge
      elif selLoc.isTemp: g.unbindTemp(selReg)
      # EMISSION ORDER MUST FOLLOW LENG ORDER — see the x64 twin. The `else` body is
      # Leng-LAST, so emitting it before the of-bodies retires every binding whose
      # last use lies inside an of-branch.
      let lElse = if hasElse: g.freshLabel() else: lEnd
      g.emBr(BA64, lElse)
      for (lBody, bc) in bodies:
        g.emLab(lBody)
        g.genStmt2(bc)
        g.emBr(BA64, lEnd)
      if hasElse:
        g.emLab(lElse)
        var e = elseBody
        e.into:
          while e.hasMore: (g.genStmt2(e); skip e)
    g.emLab(lEnd)
  of LabS:
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emBr(BA64, symName(cc)); skip cc
      while cc.hasMore: skip cc
  of KeepovfS:
    # `(keepovf (op type a b) dest)` — overflow-checked arithmetic store. The nifasm
    # a64 vocabulary has no flag-setting arithmetic (`adds`/`subs`) and no V/C-flag
    # branches, so the overflow PREDICATE is computed into a staging bridge right
    # after the op, from snapshots of the operand values:
    #   signed add:   ovf ⟺ ((d ^ a) and (d ^ b)) < 0
    #   signed sub:   ovf ⟺ ((a ^ b) and (d ^ a)) < 0
    #   unsigned add: ovf ⟺ d <u a   (carry out)
    #   unsigned sub: ovf ⟺ a <u b   (borrow)
    # The bridge(s) stay bound across the `(ovf)` test that follows (only trivial
    # register moves may sit between — the Leng spec guarantees no call/bridge user),
    # and that test consumes and releases them (see emitCond2's OvfC).
    var cc = c
    cc.into:
      var opCur = cc                                        # the (op …) value
      let ek = opCur.exprKind
      block:
        var opTy = opCur; inc opTy                          # past the op tag → its result type
        g.ovfSigned = isSignedType(opTy)
        # Register values are kept canonically at the WORD width; a narrower
        # keepovf would need a narrow op for its predicate to be exact. Reject
        # loudly (as x64 does).
        if intTypeWidth(opTy) < wordBits():
          raiseAssert "arkham a64n: keepovf for sub-64-bit type not yet supported " &
                      "(width " & $intTypeWidth(opTy) & ")"
      if ek notin {AddC, SubC, MulC}:
        raiseAssert "arkham a64n: keepovf op not yet supported: " & $ek
      var aC, bC: Cursor
      block:
        var oc = opCur
        oc.into:
          skip oc                                           # result type
          aC = oc; skip oc
          bC = oc; skip oc
          while oc.hasMore: skip oc
      skip cc                                               # advance to dest
      if cc.kind != Symbol:
        raiseAssert "arkham a64n: keepovf into a complex lvalue not yet supported"
      var dst = g.plan.locationOfSym(symName(cc), cursorToPosition(g.buf[], cc))
      if dst.kind == NoLoc:
        var lc = cc
        dst = g.asLoc(lc)
      skip cc
      # The sequence below READS `d` back to derive the overflow predicate, so the
      # destination has to be a register. When the allocator gave it a stack home
      # (peak pressure under `-d:release`), compute into a transient and store the
      # result once the predicate has been built from it.
      var rD: Reg
      var spillDst = dontCare
      if dst.kind == InReg:
        rD = dst.r
      else:
        rD = g.pickStagingA64()
        if rD == NoReg:
          raiseAssert "arkham a64n: no register for the keepovf destination in proc " &
                      g.curProcName
        g.pickedRegs.incl rD
        g.bindTemp(rD, ScalarSlot)
        spillDst = dst
      # Operand values at their pre-allocated locations, then snapshots into the two
      # staging bridges — the op below may overwrite either operand's register (the
      # allocator dest-passes into `rD`, which can alias an operand home or temp).
      var aLoc = dontCare
      g.emitValue2(aC, aLoc)
      var bLoc = dontCare
      g.emitValue2(bC, bLoc)
      let rA = g.takeBridge()
      g.place2(aLoc, rA)
      let rB = g.takeBridge()
      g.place2(bLoc, rB)
      if aLoc.kind == InReg and aLoc.isTemp: g.unbindTemp(aLoc.r)
      if bLoc.kind == InReg and bLoc.isTemp: g.unbindTemp(bLoc.r)
      if ek == MulC:
        # `d = a * b`; overflow is read straight off the 128-bit product's HIGH half
        # (`smulh`/`umulh` — the register-role equivalent of x86 `imul`→rdx), so there
        # is no division, no `INT64_MIN·-1` special case, and only the two bridges +
        # dest are ever live (no stack snapshot of `a`):
        #   unsigned: ovf ⟺ umulh(a,b) != 0
        #   signed:   ovf ⟺ smulh(a,b) != (d asr 63)   (the low result's sign extension)
        g.movReg(rD, rA)                                    # d := a
        g.binReg(MulA64, rD, rB)                            # d := a * b (low 64)
        if g.ovfSigned:
          g.binReg(SmulhA64, rA, rB)                        # rA := high(a*b); `a` now dead
          g.movReg(rB, rD)                                  # rB := d
          g.ab.splice &"(asr {g.emOp(rB)} 63)"             # rB := d asr 63 (expected high)
          g.binReg(EorA64, rA, rB)                          # rA := high ^ expected (0 ⟺ no ovf)
        else:
          g.binReg(UmulhA64, rA, rB)                        # rA := high(a*b) (0 ⟺ no ovf)
        g.dropBridge rB
        g.ovfMode = OvfNeqZero
        g.ovfReg = rA
        g.ovfBridges = @[rA]
      else:
        g.movReg(rD, rA)                                    # d := a
        g.binReg(if ek == AddC: AddA64 else: SubA64, rD, rB) # d := a op b
        if g.ovfSigned:
          if ek == AddC:
            g.binReg(EorA64, rA, rD)                        # rA = a ^ d
            g.binReg(EorA64, rB, rD)                        # rB = b ^ d
          else:
            g.binReg(EorA64, rB, rA)                        # rB = a ^ b (before rA is reused)
            g.binReg(EorA64, rA, rD)                        # rA = a ^ d
          g.binReg(AndA64, rA, rB)                          # rA sign bit = overflow
          g.dropBridge rB
          g.ovfMode = OvfSign
          g.ovfReg = rA
          g.ovfBridges = @[rA]
        elif ek == AddC:
          g.dropBridge rB
          g.ovfMode = OvfCmpLo                              # carry: d <u a
          g.ovfReg = rD
          g.ovfReg2 = rA
          g.ovfBridges = @[rA]
        else:
          g.ovfMode = OvfCmpLo                              # borrow: a <u b
          g.ovfReg = rA
          g.ovfReg2 = rB
          g.ovfBridges = @[rA, rB]
      if spillDst.kind != Undef:
        # After the predicate — which reads `rD` — and before the `(ovf)` test,
        # which may read it too (`OvfCmpLo`'s carry form compares `d <u a`). The
        # store does not touch `rD`, and the test's `ovfBridges` release frees it.
        g.storeReg2(spillDst, rD)
        g.ovfBridges.add rD
      while cc.hasMore: skip cc
  else: raiseAssert "arkham a64n: genStmt2 " & $c.stmtKind

proc recordVarType2*(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc
      let typeCur = cc; skip cc                  # type
      g.symType[nm] = g.declType(typeCur, cc)    # `.` ⇒ inferred from the initializer
    while cc.hasMore: skip cc

proc recordSymTypes2*(g: var CodeGen; c: Cursor) =
  if c.kind != TagLit: return
  case c.stmtKind
  of VarS, GvarS, TvarS, ConstS: g.recordVarType2(c)
  of ProcS, TypeS: discard
  else:
    var cc = c
    cc.into:
      while cc.hasMore:
        g.recordSymTypes2(cc)
        skip cc

proc emitProcBody2*(g: var CodeGen; info: ProcInfo; declarative: bool;
                   frameHasCall: bool) =
  ## Body-buffer model (the x64 stage-2 twin): the BODY is emitted into a side
  ## buffer first; the prologue — whose shape (callee-saved pairs, the `(s)`
  ## region `sub`) is only final once the body is known — is written after it,
  ## into the main buffer, and the body appended. This is what lets the merged
  ## value core mint spill slots and draw callee-saved temps INLINE during
  ## emission. The prologue text is written with POST-body RegBind state, so it
  ## uses only RAW register operands (see `emitStackParamLoads`).
  var side = g.ab.sideBuf()
  swap(g.ab, side)                        # emit into the side buffer; `side` holds main
  # One scope covers caller-save param bindings (`emRegLocalVar` in
  # emitParamMoves) and the body locals — `scopeLocals` must be non-empty
  # before those param binds, and param kills must outlive the body.
  g.enterScope()
  if g.retIndirect: g.movReg(g.indirectReg, g.indirectResultReg)
  g.emitParamMoves(info.decl)
  # A `PairFrame` addresses the caller's argument area through the frame pointer,
  # so these loads can sit at the top of the body. A `BlockFrame` re-derives the
  # base from SP (see `emIncomingArgBase`), which is only final once the prologue
  # has lowered it — so there they are emitted with the prologue instead.
  if g.md.frameStyle != BlockFrame:
    g.emitStackParamLoads(info.decl)          # via fp; the arg registers are free now
  g.retLabel2 = g.freshLabel()
  g.retLabelUsed2 = false
  var c = info.decl
  c.into:
    inc c; skip c; skip c; skip c
    if c.stmtKind == StmtsS:
      c.into:
        while c.hasMore: (g.genStmt2(c); skip c)
  g.exitScope()
  if g.retLabelUsed2: g.emLab(g.retLabel2)
  if info.isEntry and g.entryExits:              # the entry EXITS (no epilogue)
    g.movImm(g.md.intRetReg, 0)
    if Freestanding in g.md.caps:
      g.ab.tree BlA64: g.ab.sym EntryExitShim
    else:
      g.movImm(R8, LinuxA64ExitNr.int64)
      g.ab.tree SvcA64: g.ab.intLit 0
  swap(g.ab, side)                        # back to the main buffer; `side` holds the body
  # The body is emitted — `plan.usedCallee`/`usedCalleeF`/`hasStackVars` are final.
  # Finalize the frame and write the prologue, then splice the body after it.
  # `helperCalls` is only known now: the 64-bit divider is reached from an
  # expression the analyser sees as arithmetic, and its `bl` overwrites lr.
  g.computeFrame(frameHasCall or g.helperCalls)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsA64:
      # Before anything else, including the prologue: the frame may already save
      # a callee-saved FPv4-SP register, and that store is itself a floating-point
      # instruction.
      # The prologue is emitted AFTER the body but runs BEFORE it, and at that
      # point r0–r3 still hold what the caller put there — the incoming register
      # parameters, which `emitParamMoves` (at the top of the body) has not moved
      # to their homes yet. The entry proc's startup code reads and writes them
      # raw as well. So they are claimed for the whole prologue: a scratch draw
      # here must not take one, and `stagedArgs` is how it is told.
      let outerStaged = g.stagedArgs
      for r in g.md.intArgRegs: g.stagedArgs.incl r
      if Freestanding in g.md.caps and info.isEntry:
        # Bare metal: the image owns the machine, so whatever the program expects
        # to find established has to be established HERE — before the frame,
        # because the prologue may save a callee-saved register into RAM this has
        # not made trustworthy yet.
        #
        # RV32 goes first with `sp` and the FPU, because unlike Cortex-M it is
        # handed neither, and the copy loop below is itself a stack-free but
        # register-using sequence that wants a valid `sp` for anything after it.
        if g.md.arch == Rv32: g.emResetPathRv(g.rvStackTop)
        g.emStartupInitM()
        if g.md.arch == ThumbM: g.emEnableFpuM()
      if g.hasFrame: framePush(g)
      if g.plan.hasStackVars:
        g.ab.tree SubA64: g.ab.rawReg SP; g.ab.keyword SsizeX
      # etmp/eftmp/held slots minted DURING body emission: their decls must
      # precede the body's loads/stores, and the set is only known post-body —
      # so they are declared here, in the prologue, not in the side buffer.
      for st in g.plan.spillTemps:
        if st.isFloat: g.emFloatStackVar(st.name, st.typ.size * 8)
        elif g.isWideSlot(st.typ): g.emWideStackVar(st.name)
        elif g.slotIsPointer(st.typ):
          if isNilValue(st.typ.typ): g.emVoidPtrStackVar(st.name)
          else: g.emTypedStackVar(st.name, st.typ.typ)   # `(ptr T)` slot keeps its type
        else: g.emScalarStackVar(st.name)
      if g.md.frameStyle == BlockFrame:
        g.emitStackParamLoads(info.decl)          # SP is final only here
      g.stagedArgs = outerStaged                  # the prologue is over
      g.ab.append side                            # the body
      if not (info.isEntry and g.entryExits):
        if g.plan.hasStackVars:
          g.ab.tree AddA64: g.ab.rawReg SP; g.ab.keyword SsizeX
        if g.hasFrame: framePop(g)
        if g.isInterrupt: g.ab.keyword MretRv
        else: g.ab.keyword RetA64
