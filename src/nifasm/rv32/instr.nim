#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 instruction selector: one asm-NIF instruction node in, RV32IMAFD
## machine code out.
##
## Read alongside `thumb/instr.nim`, which it is deliberately shaped after. The
## one thing with no counterpart there is the **compare fusion**, and it is worth
## understanding before anything else here makes sense.
##
## Every other target nifasm emits for has condition flags: `(cmp a b)` writes
## them and a later `(beq L)` reads them, so the two nodes become two
## instructions. RISC-V has no flags at all — `beq`/`bne`/`blt`/`bge`/`bltu`/
## `bgeu` each take two source registers and compare them on the spot. The pair
## is therefore ONE instruction, and it is the branch that emits it.
##
## So `(cmp …)` here emits nothing. It records its operands in `ctx.pendingCmp`,
## and whichever node consumes a condition — a branch tag, an `(ite <flag>)`, a
## `(jtrue … <flag>)` — materializes the real instruction from them. Two things
## make that safe rather than merely convenient:
##
##  * **Adjacency is CHECKED, not assumed.** `pendingCmp.at` is the buffer length
##    when the compare was recorded, and consuming one requires the buffer to
##    still be that length. arkham always emits a compare immediately before the
##    branch that reads it, but "always" is exactly the kind of claim that turns
##    into a wrong answer rather than a crash when it stops being true.
##    Declarations emit no bytes and so stay transparent, which is what lets
##    `(cmp …) (cfvar …) (ite (zf) …)` work.
##  * **The immediate operand goes through `RvScratch`.** RISC-V branches are
##    register-register only, so `(cmp x 42)` materializes the 42 into `x31` AT the
##    compare (the only bytes it emits) and the branch reads it from there.
##
## `(fcmp …)` fuses the same way. Its instructions (`feq`/`flt`/`fle`) write a
## GPR rather than a flag, so the branch becomes a comparison followed by a
## `bne`/`beq` against `x0`.

import std / [tables, sets, algorithm]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, tagconv, decls, stackslots, relocs, buffers,
                    modules, emit]
import encoder as rv
import regs
import operands

proc genStmtRv(n: var Cursor; ctx: var GenContext)
proc genInstRv(n: var Cursor; ctx: var GenContext)

# ── the compare fusion ──────────────────────────────────────────────────────

proc recordCmpRv(ctx: var GenContext; lhs, rhs: rv.Register; node: Cursor) =
  ctx.pendingCmp = PendingCmp(live: true, isFloat: false,
                              at: ctx.buf.data.len, lhs: lhs, rhs: rhs,
                              node: node)

proc recordFCmpRv(ctx: var GenContext; a, b: rv.FloatRegister; w: rv.FpWidth;
                  node: Cursor) =
  ctx.pendingCmp = PendingCmp(live: true, isFloat: true,
                              at: ctx.buf.data.len, flhs: a, frhs: b,
                              width: w, node: node)

proc takeCmpRv(ctx: var GenContext; what: string; n: Cursor): PendingCmp =
  ## The pending compare, consumed. Errors if there is none, or if anything
  ## emitted code since it was recorded (see the module header).
  if not ctx.pendingCmp.live:
    error("RV32: " & what & " needs a preceding `(cmp …)`; this ISA has no " &
          "condition flags, so a branch IS the comparison", n)
    return PendingCmp()
  if ctx.pendingCmp.at != ctx.buf.data.len:
    error("RV32: instructions were emitted between `(cmp …)` and " & what &
          "; the compared registers may no longer hold what was compared. " &
          "A compare must sit immediately before the branch that reads it", n)
  result = ctx.pendingCmp
  ctx.pendingCmp.live = false

type
  RvRel = enum
    ## A relation to branch on, before it is turned into an instruction. Separate
    ## from `rv.BranchCond` because two of these have no encoding and become the
    ## same instruction with the operands SWAPPED — see `emitRelRv`.
    relEq, relNe,
    relLt, relLe, relGt, relGe,          ## signed
    relLtu, relLeu, relGtu, relGeu       ## unsigned

proc emitRelRv(ctx: var GenContext; rel: RvRel; lhs, rhs: rv.Register;
               target: LabelId) =
  ## Branch to `target` when `lhs rel rhs`.
  ##
  ## RISC-V encodes only `lt` and `ge` in each signedness; `gt` and `le` are those
  ## same instructions with the sources exchanged (`a > b` is `b < a`). Doing that
  ## here rather than in each caller is what keeps the swap from being forgotten
  ## at one site out of ten — which reads as a comparison that is simply backwards.
  case rel
  of relEq:  ctx.buf.emitBranchFar(rv.Beq, lhs, rhs, target)
  of relNe:  ctx.buf.emitBranchFar(rv.Bne, lhs, rhs, target)
  of relLt:  ctx.buf.emitBranchFar(rv.Blt, lhs, rhs, target)
  of relGe:  ctx.buf.emitBranchFar(rv.Bge, lhs, rhs, target)
  of relGt:  ctx.buf.emitBranchFar(rv.Blt, rhs, lhs, target)   # a > b  ==  b < a
  of relLe:  ctx.buf.emitBranchFar(rv.Bge, rhs, lhs, target)   # a <= b ==  b >= a
  of relLtu: ctx.buf.emitBranchFar(rv.Bltu, lhs, rhs, target)
  of relGeu: ctx.buf.emitBranchFar(rv.Bgeu, lhs, rhs, target)
  of relGtu: ctx.buf.emitBranchFar(rv.Bltu, rhs, lhs, target)
  of relLeu: ctx.buf.emitBranchFar(rv.Bgeu, rhs, lhs, target)

proc invertRel(r: RvRel): RvRel =
  case r
  of relEq: relNe
  of relNe: relEq
  of relLt: relGe
  of relGe: relLt
  of relGt: relLe
  of relLe: relGt
  of relLtu: relGeu
  of relGeu: relLtu
  of relGtu: relLeu
  of relLeu: relGtu

proc emitCondBranchRv(ctx: var GenContext; rel: RvRel; target: LabelId;
                      what: string; n: Cursor) =
  ## Consume the pending compare and branch on `rel`.
  let c = takeCmpRv(ctx, what, n)
  if not c.live: return
  if c.isFloat:
    # The FP comparisons write 1 or 0 into a GPR, so the branch tests THAT
    # against `x0`. Only the three the ISA has are used, and the other three come
    # from swapping the operands, exactly as on the integer side.
    #
    # NaN is why `flt`/`fle` are not simply negated: every FP comparison here is
    # "quiet false" on an unordered pair, so `not (a < b)` is not `a >= b`. The
    # relation is therefore always computed POSITIVELY and branched on with
    # `bne`, never computed inverted and branched on with `beq`.
    let d = RvScratch
    var branchIfSet = true
    case rel
    of relEq:  rv.emitFeq(ctx.buf.data, d, c.flhs, c.frhs, c.width)
    of relNe: (rv.emitFeq(ctx.buf.data, d, c.flhs, c.frhs, c.width);
               branchIfSet = false)
    of relLt, relLtu:  rv.emitFlt(ctx.buf.data, d, c.flhs, c.frhs, c.width)
    of relLe, relLeu:  rv.emitFle(ctx.buf.data, d, c.flhs, c.frhs, c.width)
    of relGt, relGtu:  rv.emitFlt(ctx.buf.data, d, c.frhs, c.flhs, c.width)
    of relGe, relGeu:  rv.emitFle(ctx.buf.data, d, c.frhs, c.flhs, c.width)
    if branchIfSet: ctx.buf.emitBranchFar(rv.Bne, d, rv.X0, target)
    else: ctx.buf.emitBranchFar(rv.Beq, d, rv.X0, target)
  else:
    emitRelRv(ctx, rel, c.lhs, c.rhs, target)

proc relOfFlagRv(flag: X64Flag; n: Cursor): RvRel =
  ## The relation an `(ite <flag>)` / `(jtrue … <flag>)` condition denotes, given
  ## that the pending compare computed `lhs - rhs`.
  ##
  ## Four of the eight map exactly and four cannot map at all. `zf`/`nz` are
  ## equality either way. `cf` is the borrow of an unsigned subtract, which is
  ## `lhs <u rhs`; its complement is `>=u`. But `sf` is the SIGN of the
  ## difference, and that only agrees with `lhs <s rhs` when the subtraction did
  ## not overflow — the reason AArch64's `blt` tests `N != V` rather than `N`. And
  ## `of` is that overflow itself, which no RISC-V comparison produces.
  ##
  ## So they are refused by name rather than approximated. A signed comparison
  ## that silently ignores overflow is right for almost every input and wrong for
  ## the ones a test is least likely to contain.
  case flag
  of ZfO: relEq
  of NzO: relNe
  of CfO: relLtu
  of NcO: relGeu
  of SfO, NsO, OfO, NoO:
    error("RV32 has no condition flags: `" & $flag & "` cannot be lowered. " &
          "`zf`/`nz`/`cf`/`nc` fuse into a comparison branch; the sign and " &
          "overflow flags have no RISC-V equivalent, because a comparison here " &
          "produces a relation rather than the bits of a subtraction", n)
    relEq
  else:
    error("RV32: unsupported flag condition", n)
    relEq

# ── structured control flow ─────────────────────────────────────────────────

proc genIteRv(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobberedRv
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar:
      error("Expected cfvar in ite condition: " & name, n)
    if sym.used: error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    ctx.buf.emitJ(lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    let flagTag = tagToX64Flag(n.tag)
    let condNode = n
    inc n
    # Branch to the ELSE arm when the condition does NOT hold, so the then-arm
    # falls through.
    let rel = invertRel(relOfFlagRv(flagTag, condNode))
    emitCondBranchRv(ctx, rel, lElse, "`(ite <flag>)`", condNode)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmtRv(n, ctx)
  let thenClobbered = ctx.clobberedRv
  ctx.buf.emitJ(lEnd)
  ctx.clobberedRv = oldClobbered
  ctx.buf.defineLabel(lElse)
  genStmtRv(n, ctx)
  let elseClobbered = ctx.clobberedRv
  ctx.buf.defineLabel(lEnd)
  ctx.clobberedRv = thenClobbered + elseClobbered

proc genLoopRv(n: var Cursor; ctx: var GenContext) =
  inc n
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtRv(n, ctx)
    ctx.buf.emitJ(lStart)
    return
  error("RV32: only the `(loop (stmts …))` form is supported", n)

proc genJtrueRv(n: var Cursor; ctx: var GenContext) =
  ## `(jtrue <cfvar>… <flag>)` — branch to the cfvar's label when the flag holds.
  inc n
  var target = LabelId(-1)
  while n.hasMore and n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in jtrue: " & name, n)
    if int(target) == -1: target = LabelId(sym.offset)
    sym.used = true
    inc n
  if int(target) == -1: error("jtrue needs a cfvar", n)
  if n.kind != TagLit: error("Expected a flag condition in jtrue", n)
  let flagTag = tagToX64Flag(n.tag)
  let condNode = n
  inc n
  emitCondBranchRv(ctx, relOfFlagRv(flagTag, condNode), target, "`(jtrue …)`",
                   condNode)

# ── bindings ────────────────────────────────────────────────────────────────

proc bindFRegRv(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                freg: rv.FloatRegister) =
  for r, nm in ctx.rvFRegBindings:
    if nm == name and r != freg:
      ctx.rvFRegBindings.del r
      break
  ctx.rvFRegBindings[freg] = name
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ, reg: regTag)
  ctx.scope.define(sym)

proc bindRegRv(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
               reg: rv.Register) =
  for r, nm in ctx.rvRegBindings:
    if nm == name and r != reg:
      ctx.rvRegBindings.del r
      break
  ctx.rvRegBindings[reg] = name
  ctx.clobberedRv.excl reg
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ, reg: regTag)
  ctx.scope.define(sym)

proc parseRebindHeaderRv(n: var Cursor; ctx: var GenContext):
                        tuple[name: string; reg: rv.Register] =
  ## Parse `:name TYPE (reg)` (cursor already inside the node) and establish the
  ## binding. Shared by `rebind` and `withreg`.
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  checkRegWidthRv(typ, "rebind of '" & name & "'", n)
  if n.kind == TagLit and rawTagIsRvFloatReg(n.tag):
    let fTag = n.tag
    let f = tagToFloatRegisterRv(fTag, n)
    inc n
    bindFRegRv(ctx, name, typ, fTag, f)
    return (name, rv.X0)          # the GPR half of the result is unused here
  if n.kind != TagLit or not rawTagIsRvGpr(n.tag):
    error("Expected a register for rebind/withreg", n)
  let regTag = n.tag
  let reg = tagToRegisterRv(regTag, n)
  inc n
  bindRegRv(ctx, name, typ, regTag, reg)
  result = (name, reg)

# ── calls ───────────────────────────────────────────────────────────────────

const RvCallClobbers* = {rv.X1, rv.X5, rv.X6, rv.X7,
                         rv.X10, rv.X11, rv.X12, rv.X13, rv.X14, rv.X15,
                         rv.X16, rv.X17, rv.X28, rv.X29, rv.X30, rv.X31}
  ## What a call destroys under the RISC-V calling convention: `ra` (which `jal`
  ## overwrites with the return address), the temporaries `t0`–`t6`, and the
  ## argument/return registers `a0`–`a7`. `s0`–`s11` are callee-saved, which is
  ## where a value that must survive a call belongs.

proc callClobbersRv(ctx: GenContext): set[rv.Register] =
  ## What THIS callee declares it destroys, falling back to the full volatile set
  ## when the signature declared nothing. An empty declared list is meaningful: it
  ## is what lets a caller keep a value in a caller-saved register across a call
  ## that provably preserves it.
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersRv
  else: RvCallClobbers

proc genPrepareRv(n: var Cursor; ctx: var GenContext) =
  var hdr = n
  inc hdr
  if hdr.kind != Symbol: error("Expected proc symbol, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)
  if sym == nil: error("Unknown symbol: " & name, hdr)

  let outerCall = ctx.callContext
  if outerCall.state != CallContextState.Disabled and
     outerCall.stackArgSize > outerCall.stackArgBase:
    error("Nested prepare blocks are not allowed when the outer call passes " &
          "arguments on the stack: both would write the one outgoing area", hdr)
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false)

  case sym.kind
  of skProc:
    ctx.callContext.typ = sym.typ
  of skGvar, skVar, skParam:
    if sym.typ.kind != ProcT:
      error("Expected proc symbol, got " & $sym.kind, hdr)
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  of skExtProc:
    error("RV32 is a bare-metal target: there is nothing to link against, so " &
          "`extproc` (" & name & ") has no meaning here", hdr)
  of skSysProc:
    error("RV32 has no OS and therefore no syscalls: '" & name & "'", hdr)
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
  if ctx.callContext.stackArgSize > ctx.reservedArgArea:
    error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
          " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
          " bytes); call target not visible to the frame pre-scan", hdr)

  into n:
    skip n
    while n.hasMore:
      genInstRv(n, ctx)

  for param in ctx.callContext.typ.params:
    if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
      error("Missing argument: " & ctx.nameOf(param.name), hdr)
  for res in ctx.callContext.typ.results:
    if res.name notin ctx.callContext.resultsSet:
      error("Missing result binding: " & ctx.nameOf(res.name), hdr)
  if not ctx.callContext.callEmitted:
    error("Missing (call) in prepare block", hdr)

  ctx.callContext = outerCall
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerRv(n: var Cursor; ctx: var GenContext) =
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedRv.incl callClobbersRv(ctx)

  if ctx.callContext.indirect:
    # Through a function pointer. `RvScratch` is the selector's own register and
    # is never an argument register, so loading the target there cannot disturb
    # the arguments already staged in `a0`–`a7`.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      rv.emitJalr(ctx.buf.data, rv.Ra, tagToRegisterRv(sym.reg, n), 0)
    elif sym.kind == skGvar:
      emitGvarAddrRv(ctx, RvScratch, sym)
      rv.emitLw(ctx.buf.data, RvScratch, RvScratch, 0)
      rv.emitJalr(ctx.buf.data, rv.Ra, RvScratch, 0)
    elif sym.kind in {skVar, skParam} and sym.typ.isOnStack:
      rv.emitLw(ctx.buf.data, RvScratch, rv.Sp, int32(sym.offset))
      rv.emitJalr(ctx.buf.data, rv.Ra, RvScratch, 0)
    else:
      error("RV32: indirect call through " & $sym.kind & " is not supported yet", n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  ctx.buf.emitJal(labId)
  ctx.callContext.callEmitted = true
  inc n

# ── ALU helpers ─────────────────────────────────────────────────────────────

type
  AluOp = enum
    aAdd, aSub, aAnd, aOr, aXor, aShl, aShr, aSar, aMul, aDivS, aDivU

proc emitAluRv(ctx: var GenContext; op: AluOp; d, a: rv.Register;
               b: OperandRv; n: Cursor) =
  ## `d = a op b`. The immediate forms exist only for `add`, the three logical
  ## ops and the shifts; everything else materializes `b` into a register first.
  ## `sub` has no immediate form at all — `addi` with the negation is it, which is
  ## why the negation happens here rather than at each call site.
  if b.kind == okImm and not b.isFloat:
    let v = b.immVal
    case op
    of aAdd:
      if rv.fitsImm12(v): (rv.emitAddi(ctx.buf.data, d, a, int32(v)); return)
    of aSub:
      # `-(-2048)` is 2048, which does NOT fit — so the bound is asymmetric and
      # checking `fitsImm12(v)` before negating would be wrong at exactly one value.
      if rv.fitsImm12(-v): (rv.emitAddi(ctx.buf.data, d, a, int32(-v)); return)
    of aAnd:
      if rv.fitsImm12(v): (rv.emitAndi(ctx.buf.data, d, a, int32(v)); return)
    of aOr:
      if rv.fitsImm12(v): (rv.emitOri(ctx.buf.data, d, a, int32(v)); return)
    of aXor:
      if rv.fitsImm12(v): (rv.emitXori(ctx.buf.data, d, a, int32(v)); return)
    of aShl:
      if v >= 0 and v < 32: (rv.emitSlli(ctx.buf.data, d, a, int(v)); return)
    of aShr:
      if v >= 0 and v < 32: (rv.emitSrli(ctx.buf.data, d, a, int(v)); return)
    of aSar:
      if v >= 0 and v < 32: (rv.emitSrai(ctx.buf.data, d, a, int(v)); return)
    of aMul, aDivS, aDivU: discard
  let br = toRegRv(ctx, b, n)
  case op
  of aAdd:  rv.emitAdd(ctx.buf.data, d, a, br)
  of aSub:  rv.emitSub(ctx.buf.data, d, a, br)
  of aAnd:  rv.emitAnd(ctx.buf.data, d, a, br)
  of aOr:   rv.emitOr(ctx.buf.data, d, a, br)
  of aXor:  rv.emitXor(ctx.buf.data, d, a, br)
  of aShl:  rv.emitSll(ctx.buf.data, d, a, br)
  of aShr:  rv.emitSrl(ctx.buf.data, d, a, br)
  of aSar:  rv.emitSra(ctx.buf.data, d, a, br)
  of aMul:  rv.emitMul(ctx.buf.data, d, a, br)
  of aDivS: rv.emitDiv(ctx.buf.data, d, a, br)
  of aDivU: rv.emitDivu(ctx.buf.data, d, a, br)

proc alu2Rv(n: var Cursor; ctx: var GenContext; op: AluOp) =
  ## `(op D S)` — the destructive two-operand spelling: `D = D op S`.
  inc n
  let dst = parseDestRv(n, ctx)
  let src = parseOperandRv(n, ctx)
  let d = regOfRv(dst, "destination", n)
  emitAluRv(ctx, op, d, d, src, n)

proc emit3Rv(ctx: var GenContext; op: AluOp; d: rv.Register;
             a, b: OperandRv; n: Cursor) =
  ## `d = a op b`, with neither source assumed to be a register already.
  # `a` may itself be a memory operand or an immediate. It cannot go through
  # `RvScratch` when `b` might need it too, so it lands in `d` — which is safe
  # only because `d` is written last by every op below. When `d` aliases `b`,
  # that would destroy `b` first, so `b` is materialized ahead of it.
  if a.kind in {okReg, okArg} and not a.isFloat:
    emitAluRv(ctx, op, d, a.reg, b, n)
  elif b.kind in {okReg, okArg} and not b.isFloat and b.reg != d:
    loadToRegRv(ctx, d, a, n)
    emitAluRv(ctx, op, d, d, b, n)
  else:
    let br = toRegRv(ctx, b, n)
    if br == d:
      error("RV32: `" & $op & "` needs two scratch registers here (codegen bug)", n)
    loadToRegRv(ctx, d, a, n)
    emitAluRv(ctx, op, d, d, OperandRv(kind: okReg, reg: br), n)

proc alu3Rv(n: var Cursor; ctx: var GenContext; op: AluOp) =
  ## `(op3 D A B)` — the natural RISC-V shape, and the one arkham prefers.
  inc n
  let dst = parseDestRv(n, ctx)
  let a = parseOperandRv(n, ctx)
  let b = parseOperandRv(n, ctx)
  emit3Rv(ctx, op, regOfRv(dst, "destination", n), a, b, n)

proc aluFlexRv(n: var Cursor; ctx: var GenContext; op: AluOp) =
  ## `(sdiv D S)` and `(sdiv D A B)` are the SAME tag at two arities — AArch64
  ## emits the destructive two-operand spelling, Cortex-M the three-operand one —
  ## and RISC-V's `div rd, rs1, rs2` reads either. Rather than pick one and reject
  ## the other target's asm-NIF, the arity is read off the node.
  # The arity is a property of THIS node, so the node's own scope has to be
  # entered to ask it: outside one, `hasMore` counts what is left of the
  # enclosing block, and a two-operand `(sdiv q b)` read the following statement
  # as its third operand.
  into n:
    let dst = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let d = regOfRv(dst, "destination", n)
    if n.hasMore:
      let b = parseOperandRv(n, ctx)
      emit3Rv(ctx, op, d, a, b, n)
    else:
      emitAluRv(ctx, op, d, d, a, n)

# ── the instruction dispatch ────────────────────────────────────────────────

proc genMovRv(n: var Cursor; ctx: var GenContext) =
  inc n
  let dst = parseDestRv(n, ctx)
  let src = parseOperandRv(n, ctx)
  if dst.isFloat:
    if src.isFloat:
      rv.emitFmv(ctx.buf.data, dst.freg, src.freg, dst.fw)
    elif src.kind == okMem:
      emitFpMemAccessRv(ctx, dst.freg, src.mem, dst.fw, isLoad = true, n = n)
    elif dst.fw == rv.FpS:
      # An integer register into a single-precision one: a raw 32-bit move.
      rv.emitFmvWX(ctx.buf.data, dst.freg, toRegRv(ctx, src, n))
    else:
      error("RV32 has no `fmv.x.d`: a double cannot pass through a 32-bit " &
            "integer register, only through memory", n)
    return
  if src.isFloat:
    if dst.kind == okMem:
      emitFpMemAccessRv(ctx, src.freg, dst.mem, src.fw, isLoad = false, n = n)
    elif src.fw == rv.FpS:
      rv.emitFmvXW(ctx.buf.data, regOfRv(dst, "destination", n), src.freg)
    else:
      error("RV32 has no `fmv.x.d`: a double cannot pass through a 32-bit " &
            "integer register, only through memory", n)
    return
  case dst.kind
  of okReg, okArg:
    loadToRegRv(ctx, dst.reg, src, n)
  of okMem:
    # Neither operand may be memory on the other side: there is no
    # memory-to-memory move, so the value passes through the scratch.
    let s = toRegRv(ctx, src, n)
    storeFromRegRv(ctx, s, dst, n)
  else:
    error("RV32: `(mov …)` destination must be a register or memory", n)

proc genLeaRv(n: var Cursor; ctx: var GenContext) =
  ## `(lea D S)` — the ADDRESS of `S`, not its contents.
  inc n
  let dst = parseDestRv(n, ctx)
  let src = parseOperandRv(n, ctx)
  let d = regOfRv(dst, "destination", n)
  case src.kind
  of okMem:
    if src.mem.offset == 0:
      rv.emitMv(ctx.buf.data, d, src.mem.base)
    elif rv.fitsImm12(int64(src.mem.offset)):
      rv.emitAddi(ctx.buf.data, d, src.mem.base, src.mem.offset)
    else:
      rv.emitLi(ctx.buf.data, d, cast[uint32](src.mem.offset))
      rv.emitAdd(ctx.buf.data, d, src.mem.base, d)
  else:
    if src.gvarSym != nil: emitGvarAddrRv(ctx, d, src.gvarSym)
    elif src.isCode or int(src.label) != 0: rv.emitLaAbs(ctx.buf, d, src.label)
    else: error("RV32: `(lea …)` needs an address operand", n)

proc genCmpRv(n: var Cursor; ctx: var GenContext; isFloat: bool) =
  ## Emits NOTHING. See the module header.
  let node = n
  inc n
  let a = parseOperandRv(n, ctx)
  let b = parseOperandRv(n, ctx)
  if isFloat or a.isFloat or b.isFloat:
    if not (a.isFloat and b.isFloat):
      error("RV32: `(fcmp …)` compares two floating-point registers", n)
      return
    if a.fw != b.fw:
      error("RV32: `(fcmp …)` operands differ in precision", n)
      return
    recordFCmpRv(ctx, a.freg, b.freg, a.fw, node)
  else:
    # Both sides become registers only at the BRANCH — but they must be
    # registers ALREADY, or materializing them here would emit bytes and break
    # the adjacency check that makes the fusion sound. A memory or immediate
    # operand is therefore recorded as a register the branch will fill.
    #
    # An immediate is the common case (`(cmp x 42)`), and the ONE thing allowed
    # to defer: it is a constant, so materializing it later cannot observe a
    # different value. A memory operand could, so it is refused.
    if a.kind notin {okReg, okArg} or a.isFloat:
      error("RV32: the left operand of `(cmp …)` must be a register — there is " &
            "no memory-operand compare on this ISA", n)
      return
    var rhs = b.reg
    if b.kind == okImm:
      if b.immVal == 0:
        rhs = rv.X0        # comparing against zero needs no register at all
      else:
        # Materialize into the scratch NOW and record the buffer length after it,
        # so the adjacency check still measures from "nothing has happened since".
        rv.emitLi(ctx.buf.data, RvScratch, imm32Rv(b.immVal, n))
        rhs = RvScratch
    elif b.kind notin {okReg, okArg} or b.isFloat:
      error("RV32: the right operand of `(cmp …)` must be a register or a " &
            "constant", n)
      return
    recordCmpRv(ctx, a.reg, rhs, node)

proc labelSymRv(n: Cursor; ctx: var GenContext; name: string): Symbol =
  ## The branch target `name`, created if this is the first mention of it.
  ##
  ## Two kinds arrive here. A LABEL inside a proc is pre-created by
  ## `collectLabels`, but a top-level statement sequence never goes through that
  ## pass — so a forward branch there would otherwise be "unknown label" for a
  ## label defined four lines down. A PROC arrives because `(bl …)` and `(b …)`
  ## take one: the entry's tail-call to the exit shim is a `(bl `mexit.0)`, and a
  ## tail call is a `(b …)` to a proc. Both resolve to a label id, and which kind
  ## it was stops mattering the moment it has one.
  result = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if result == nil:
    result = Symbol(name: ctx.symIdOf(name), kind: skLabel,
                    offset: int(ctx.buf.createLabel()),
                    typ: Type(kind: TypeKind.UIntT, bits: 32))
    ctx.scope.define(result)
    return
  if result.kind notin {skLabel, skProc}:
    error("RV32: `" & name & "` is a " & $result.kind &
          "; a branch needs a label or a proc", n)
  elif result.offset == -1:
    result.offset = int(ctx.buf.createLabel())

proc branchTargetRv(n: var Cursor; ctx: var GenContext): LabelId =
  if n.kind != Symbol:
    error("RV32: expected a branch target", n)
    return LabelId(0)
  let sym = labelSymRv(n, ctx, getSym(n))
  inc n
  LabelId(sym.offset)

proc genInstRv(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToRvInst(n.tag)

  case tagToNifasmDecl(n.tag)
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skCfvar,
                            typ: Type(kind: TypeKind.BoolT),
                            offset: int(cfvarLabel), used: false))
    return
  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsRvFloatReg(locTag):
        let (f, _) = parseFloatRegisterRv(n)
        let ftyp = parseType(n, ctx.scope, ctx)
        bindFRegRv(ctx, name, ftyp, locTag, f)  # binding implies a kill — see below
        return
      if rawTagIsRvGpr(locTag):
        let r = tagToRegisterRv(locTag, n)
        if r == rv.Sp:
          error("Cannot bind a variable to sp", n)
        if r == rv.X0:
          error("Cannot bind a variable to x0: it reads as zero and discards " &
                "every write", n)
        if r == rv.Ra:
          error("Cannot bind a variable to ra: every call overwrites it", n)
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    if not onStack:
      # A register `(var …)` binds a register to a typed name, which is precisely
      # what `(rebind …)` does — so it ends the register's prior binding the same
      # way, through the same helper. See `genInstX64` for what the old "kill it
      # first" rejection cost.
      checkRegWidthRv(baseTyp, "variable '" & name & "'", n)
      bindRegRv(ctx, name, baseTyp, reg, tagToRegisterRv(reg, n))
      return
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    sym.typ = Type(kind: TypeKind.StackOffT, offType: baseTyp)
    sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handled by `case instTag` below"
  else:
    raiseAssert("Unhandled declaration tag in RV32 selector")

  # An overflowing mnemonic's id is a leading child; skip it once so every arm's
  # own `inc n` still lands on operand 0. Same step as the other three selectors.
  if isEscapedTag(n): inc n

  case instTag
  of StmtsRv, ScopeRv:
    genStmtRv(n, ctx)
  of IteRv:   genIteRv(n, ctx)
  of LoopRv:  genLoopRv(n, ctx)
  of JtrueRv: genJtrueRv(n, ctx)
  of PrepareRv: genPrepareRv(n, ctx)
  of CallRv:  genCallMarkerRv(n, ctx)
  of ExtcallRv:
    error("RV32 is a bare-metal target: `(extcall)` has nothing to link against", n)
  of LabRv:
    inc n
    if n.kind != SymbolDef and n.kind != Symbol:
      error("Expected a label name", n)
    let name = (if n.kind == SymbolDef: symName(n) else: getSym(n))
    let sym = labelSymRv(n, ctx, name)
    inc n
    ctx.buf.defineLabel(LabelId(sym.offset))
    ctx.definedLabels.incl int(sym.offset)
  of BRv:
    inc n
    ctx.buf.emitJ(branchTargetRv(n, ctx))
  of BlRv:
    inc n
    ctx.buf.emitJal(branchTargetRv(n, ctx))
  of BeqRv, BneRv, BltRv, BleRv, BgtRv, BgeRv, BloRv, BlsRv, BhiRv, BhsRv:
    let node = n
    inc n
    let target = branchTargetRv(n, ctx)
    # The Arm condition names, mapped to relations. `lo`/`ls`/`hi`/`hs` are the
    # unsigned four — that is what those mnemonics MEAN on Arm, and arkham emits
    # them for unsigned comparisons on every RISC target.
    let rel = case instTag
              of BeqRv: relEq
              of BneRv: relNe
              of BltRv: relLt
              of BleRv: relLe
              of BgtRv: relGt
              of BgeRv: relGe
              of BloRv: relLtu
              of BlsRv: relLeu
              of BhiRv: relGtu
              else: relGeu
    emitCondBranchRv(ctx, rel, target, "a conditional branch", node)
  of CbzRv, CbnzRv:
    # `(cbz S L)` — branch when `S` is zero. No compare needed: `x0` IS the zero
    # this is testing against, so it is one instruction on RISC-V just as it is
    # on AArch64.
    inc n
    let s = parseOperandRv(n, ctx)
    let target = branchTargetRv(n, ctx)
    let r = regOfRv(s, "operand", n)
    if instTag == CbzRv: ctx.buf.emitBranchFar(rv.Beq, r, rv.X0, target)
    else: ctx.buf.emitBranchFar(rv.Bne, r, rv.X0, target)
  of CmpRv:  genCmpRv(n, ctx, isFloat = false)
  of FcmpRv: genCmpRv(n, ctx, isFloat = true)
  of MovRv:  genMovRv(n, ctx)
  of LeaRv:  genLeaRv(n, ctx)
  of AdrRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    let d = regOfRv(dst, "destination", n)
    if src.gvarSym != nil: emitGvarAddrRv(ctx, d, src.gvarSym)
    else: rv.emitLaAbs(ctx.buf, d, src.label)
  of LdrRv, LdrbRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if dst.isFloat:
      if src.kind != okMem: error("RV32: `(fldr …)` needs a memory operand", n)
      emitFpMemAccessRv(ctx, dst.freg, src.mem, dst.fw, isLoad = true, n = n)
    else:
      let d = regOfRv(dst, "destination", n)
      if src.kind != okMem: error("RV32: `(ldr …)` needs a memory operand", n)
      let w = if instTag == LdrbRv: MemByte else: memWidthRv(src.typ).width
      let sg = if instTag == LdrbRv: false else: memWidthRv(src.typ).signed
      emitMemAccessRv(ctx, d, src.mem, w, isLoad = true, signed = sg, n = n)
  of StrRv, StrbRv:
    inc n
    let a = parseOperandRv(n, ctx)
    let b = parseOperandRv(n, ctx)
    # `(str D S)` puts the memory operand FIRST on Arm and the value first on
    # x86. arkham emits the Arm order, but a hand-written body may do either, so
    # whichever side is memory is the destination.
    let (mem, val) = if a.kind == okMem: (a, b) else: (b, a)
    if mem.kind != okMem: error("RV32: `(str …)` needs a memory operand", n)
    if val.isFloat:
      emitFpMemAccessRv(ctx, val.freg, mem.mem, val.fw, isLoad = false, n = n)
    else:
      let s = toRegRv(ctx, val, n)
      let w = if instTag == StrbRv: MemByte else: memWidthRv(mem.typ).width
      emitMemAccessRv(ctx, s, mem.mem, w, isLoad = false, n = n)
  of AddRv, AddwRv:   alu2Rv(n, ctx, aAdd)
  of SubRv, SubwRv:   alu2Rv(n, ctx, aSub)
  of MulRv, MulwRv:   alu2Rv(n, ctx, aMul)
  of AndRv:           alu2Rv(n, ctx, aAnd)
  of OrrRv:           alu2Rv(n, ctx, aOr)
  of EorRv:           alu2Rv(n, ctx, aXor)
  of LslRv:           alu2Rv(n, ctx, aShl)
  of LsrRv:           alu2Rv(n, ctx, aShr)
  of AsrRv:           alu2Rv(n, ctx, aSar)
  of SdivRv:          aluFlexRv(n, ctx, aDivS)
  of UdivRv:          aluFlexRv(n, ctx, aDivU)
  of Add3Rv, Addw3Rv: alu3Rv(n, ctx, aAdd)
  of Sub3Rv, Subw3Rv: alu3Rv(n, ctx, aSub)
  of Mul3Rv, Mulw3Rv: alu3Rv(n, ctx, aMul)
  of And3Rv:          alu3Rv(n, ctx, aAnd)
  of Orr3Rv:          alu3Rv(n, ctx, aOr)
  of Eor3Rv:          alu3Rv(n, ctx, aXor)
  of Lsl3Rv:          alu3Rv(n, ctx, aShl)
  of Lsr3Rv:          alu3Rv(n, ctx, aShr)
  of Asr3Rv:          alu3Rv(n, ctx, aSar)
  of NegRv:
    inc n
    let dst = parseDestRv(n, ctx)
    if dst.isFloat:
      rv.emitFneg(ctx.buf.data, dst.freg, dst.freg, dst.fw)
    else:
      let d = regOfRv(dst, "destination", n)
      rv.emitNeg(ctx.buf.data, d, d)
  of FnegRv:
    inc n
    let dst = parseDestRv(n, ctx)
    if not dst.isFloat: error("RV32: `(fneg …)` needs a float register", n)
    rv.emitFneg(ctx.buf.data, dst.freg, dst.freg, dst.fw)
  of FmovRv:  genMovRv(n, ctx)
  of FldrRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if not dst.isFloat or src.kind != okMem:
      error("RV32: `(fldr D <mem>)` expected", n)
    else:
      emitFpMemAccessRv(ctx, dst.freg, src.mem, dst.fw, isLoad = true, n = n)
  of FstrRv:
    inc n
    let a = parseOperandRv(n, ctx)
    let b = parseOperandRv(n, ctx)
    let (mem, val) = if a.kind == okMem: (a, b) else: (b, a)
    if mem.kind != okMem or not val.isFloat:
      error("RV32: `(fstr <mem> S)` expected", n)
    else:
      emitFpMemAccessRv(ctx, val.freg, mem.mem, val.fw, isLoad = false, n = n)
  of FaddRv, FsubRv, FmulRv, FdivRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if not dst.isFloat or not src.isFloat:
      error("RV32: a floating-point op needs two float registers", n)
    else:
      let w = dst.fw
      case instTag
      of FaddRv: rv.emitFadd(ctx.buf.data, dst.freg, dst.freg, src.freg, w)
      of FsubRv: rv.emitFsub(ctx.buf.data, dst.freg, dst.freg, src.freg, w)
      of FmulRv: rv.emitFmul(ctx.buf.data, dst.freg, dst.freg, src.freg, w)
      else:      rv.emitFdiv(ctx.buf.data, dst.freg, dst.freg, src.freg, w)
  of ScvtfRv, UcvtfRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if not dst.isFloat: error("RV32: `(scvtf D S)` needs a float destination", n)
    else:
      rv.emitFcvtFromInt(ctx.buf.data, dst.freg, toRegRv(ctx, src, n), dst.fw,
                         signed = instTag == ScvtfRv)
  of FcvtzsRv, FcvtzuRv:
    inc n
    let dst = parseDestRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if not src.isFloat: error("RV32: `(fcvtzs D S)` needs a float source", n)
    else:
      rv.emitFcvtToInt(ctx.buf.data, regOfRv(dst, "destination", n), src.freg,
                       src.fw, signed = instTag == FcvtzsRv)
  of DmbRv:
    inc n
    rv.emitFence(ctx.buf.data)
  of YieldRv:
    inc n
    # There is no `pause` in the baseline (it is Zihintpause), and the canonical
    # encoding-space hint for it decodes as a `fence` on a core without it. A
    # `nop` is the honest lowering: correct everywhere, and merely not a hint.
    rv.emitNop(ctx.buf.data)
  of NopRv:
    inc n
    rv.emitNop(ctx.buf.data)
  of SemihostRv:
    inc n
    rv.emitSemihostCall(ctx.buf.data)
  of CsrwRv, CsrsRv:
    # `(csrw N S)` / `(csrs N S)`. The CSR number is an immediate and nothing
    # else: there is no register-indirect form in the ISA, so a non-literal is a
    # program error rather than something to materialize.
    inc n
    let csrOp = parseOperandRv(n, ctx)
    let src = parseOperandRv(n, ctx)
    if csrOp.kind != okImm or csrOp.immVal < 0 or csrOp.immVal > 0xFFF:
      error("RV32: a CSR number must be a literal in 0..4095", n)
    else:
      let r = toRegRv(ctx, src, n)
      if instTag == CsrwRv: rv.emitCsrw(ctx.buf.data, int32(csrOp.immVal), r)
      else: rv.emitCsrs(ctx.buf.data, int32(csrOp.immVal), r)
  of LrwRv:
    # `(lrw D S)` → `lr.w D, (S)`. `S` is an ADDRESS in a register; there is no
    # offset form, which is why nothing here parses a `(mem …)`.
    inc n
    let d = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    rv.emitLrW(ctx.buf.data, toRegRv(ctx, d, n), toRegRv(ctx, a, n))
  of ScwRv:
    # `(scw St D S)` → `sc.w St, D, (S)`. `St` is the DESTINATION — zero on
    # success — so it is parsed first and must differ from `D`, which is read.
    inc n
    let st = parseDestRv(n, ctx)
    let d = parseOperandRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let (stR, dR, aR) = (toRegRv(ctx, st, n), toRegRv(ctx, d, n), toRegRv(ctx, a, n))
    if stR == dR:
      error("RV32: `sc.w`'s status and value registers must differ — the status " &
            "is written and the value is read by the same instruction", n)
    else:
      rv.emitScW(ctx.buf.data, stR, aR, dR)
  of MretRv:
    inc n
    rv.emitMret(ctx.buf.data)
  of RetRv:
    inc n
    rv.emitRet(ctx.buf.data)
  of RebindRv:
    # `(rebind :name TYPE (reg))` — bind until an explicit kill, the next rebind
    # of the same register, or proc end. Bookkeeping; emits nothing.
    into n:
      discard parseRebindHeaderRv(n, ctx)
  of WithregRv:
    # `(withreg :name TYPE (reg) body…)` — a block-scoped rebind, auto-killed at
    # the end of the body.
    into n:
      let h = parseRebindHeaderRv(n, ctx)
      while n.hasMore: genInstRv(n, ctx)
      if ctx.rvRegBindings.getOrDefault(h.reg, "") == h.name:
        ctx.rvRegBindings.del(h.reg)
      ctx.scope.undefine(ctx.symIdOf(h.name))
  of KillRv:
    # `(kill name…)` — the binding ends here. Emits nothing: what it changes is
    # what a LATER raw use of the register means, so that reusing it reads as a
    # fresh binding rather than as a silent clobber of a live value.
    inc n
    while n.hasMore and n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym != nil and sym.reg != InvalidTagId:
        if rawTagIsRvFloatReg(sym.reg):
          ctx.rvFRegBindings.del(tagToFloatRegisterRv(sym.reg, n))
        else:
          ctx.rvRegBindings.del(tagToRegisterRv(sym.reg, n))
      inc n
  of NoRvInst:
    error("RV32: unsupported instruction", n)
  else:
    error("RV32: instruction not implemented yet: " & $instTag, n)

proc genStmtRv(n: var Cursor; ctx: var GenContext) =
  if n.kind == TagLit and (n.tag == StmtsTagId or n.tag == ScopeTagId):
    let isScope = n.tag == ScopeTagId
    let saved = ctx.slots.stackSize
    if isScope: ctx.scope = newScope(ctx.scope)
    loopInto n:
      genInstRv(n, ctx)
    if isScope:
      ctx.scope = ctx.scope.parent
      ctx.slots.stackSize = saved
  else:
    genInstRv(n, ctx)

proc genInstNodeRv*(n: var Cursor; ctx: var GenContext) =
  genInstRv(n, ctx)
