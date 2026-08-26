#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The AVR instruction selector: ONE asm-NIF node in, one AVR instruction out.
##
## "One" is the rule this file is built around, not a happy accident. A 16-bit
## add on this machine is `add`+`adc`, and both of those are written by arkham as
## separate nodes — the assembler does not expand one tag into two instructions,
## because a lowering here would be unreachable from the corpus and would blur
## who owns correctness. So every arm below is a parse, a check, and a single
## `emitXxx`.
##
## The exceptions are the two places where the operand is a value NIFASM ITSELF
## computes and the code generator cannot know: `(ssize)`, the frame size, and a
## frame slot's offset. Those are this assembler encoding its own numbers.
##
## Three facts drive most of the shape:
##
##  * **SP cannot address memory.** It lives in the I/O space. So Y is a real
##    frame pointer, established by the prologue, and every stack slot is `Y+q`.
##  * **A conditional branch reaches ±128 bytes**, which an ordinary loop body
##    outgrows. So one is never emitted alone: it is inverted and branches over
##    an `rjmp`, which reaches ±4 KB. Two words instead of one, and always right.
##  * **`ldi` does not reach r0..r15.** A constant destined for a low register is
##    the code generator's problem, not this one's — the encoder asserts it.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, tagconv, decls, stackslots, relocs, buffers,
                    listing]
import encoder as avr
import regs
import operands

proc genStmtAvr(n: var Cursor; ctx: var GenContext)
proc genInstAvr(n: var Cursor; ctx: var GenContext)

# ── branches ────────────────────────────────────────────────────────────────

proc emitBranchAvr*(ctx: var GenContext; cond: avr.Condition; target: LabelId) =
  ## A conditional branch, in the only form that is always correct here: the
  ## INVERTED condition branching over an `rjmp` to the real target.
  ##
  ## The direct form carries seven signed word bits — ±128 BYTES — which a loop
  ## body of about sixty instructions already exceeds, and the assembler cannot
  ## know the distance at the point it emits the branch. `rjmp` reaches ±4 KB,
  ## which no proc on a part this size comes near. The cost is one extra word per
  ## conditional branch; shrinking it back down where the target turns out to be
  ## near is a relaxation pass, exactly like `x64/relax.nim`, and does not exist
  ## for this target yet.
  let over = ctx.buf.createLabel()
  avr.emitBranch(ctx.buf, avr.invert(cond), over)
  avr.emitRjmp(ctx.buf, target)
  ctx.buf.defineLabel(over)

proc emitJumpAvr*(ctx: var GenContext; target: LabelId) =
  avr.emitRjmp(ctx.buf, target)

# ── structured control flow ─────────────────────────────────────────────────

proc genIteAvr(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobberedAvr
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar:
      error("Expected cfvar in ite condition: " & name, n)
    if sym.used: error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    ctx.emitJumpAvr(lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    let flagTag = tagToX64Flag(n.tag)
    inc n
    # Branch to the ELSE arm when the condition does NOT hold, so the then-arm
    # falls through. `emitBranchAvr` inverts again internally, which cancels out
    # to a direct branch over an `rjmp` to the else label.
    ctx.emitBranchAvr(avr.invert(condOfFlagAvr(flagTag, n)), lElse)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmtAvr(n, ctx)
  let thenClobbered = ctx.clobberedAvr
  ctx.emitJumpAvr(lEnd)
  ctx.clobberedAvr = oldClobbered
  ctx.buf.defineLabel(lElse)
  genStmtAvr(n, ctx)
  let elseClobbered = ctx.clobberedAvr
  ctx.buf.defineLabel(lEnd)
  ctx.clobberedAvr = thenClobbered + elseClobbered

proc genLoopAvr(n: var Cursor; ctx: var GenContext) =
  inc n
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtAvr(n, ctx)
    ctx.emitJumpAvr(lStart)
    return
  error("AVR: only the `(loop (stmts …))` form is supported", n)

proc genJtrueAvr(n: var Cursor; ctx: var GenContext) =
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
  inc n
  ctx.emitBranchAvr(condOfFlagAvr(flagTag, n), target)

# ── bindings ────────────────────────────────────────────────────────────────

proc evictAvr(ctx: var GenContext; r: avr.Register) =
  ## Kill whatever currently lives in `r`, and in its partner when the tenant is
  ## a PAIR. Both halves map to the same name, so the partner is found by name
  ## rather than by arithmetic — the tenant may be either half.
  if r notin ctx.avrRegBindings: return
  let victim = ctx.avrRegBindings[r]
  ctx.scope.undefine(ctx.symIdOf(victim))
  var same: seq[avr.Register] = @[]
  for k, v in ctx.avrRegBindings:
    if v == victim: same.add k
  for k in same: ctx.avrRegBindings.del k

proc bindRegAvr(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                reg: avr.Register; isPair: bool) =
  ## Bind a register (or both halves of a pair) to a typed name, KILLING the
  ## prior tenant first — so a later use of a value wrongly left there is an
  ## "Unknown symbol" error rather than a silent clobber. The "(re)bind implies a
  ## kill" rule that `rebind` and `withreg` share.
  ctx.evictAvr reg
  if isPair: ctx.evictAvr avr.Register(ord(reg) + 1)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.bindNames(name, reg, isPair)
  ctx.scope.define(sym)

proc parseRebindHeaderAvr(n: var Cursor; ctx: var GenContext):
                         tuple[name: string; reg: avr.Register; isPair: bool] =
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  checkRegWidthAvr(typ, "rebind of '" & name & "'", n)
  if n.kind != TagLit or not rawTagIsAvrReg(n.tag):
    error("Expected a register or register pair for rebind/withreg", n)
  let regTag = n.tag
  let isPair = rawTagIsAvrPair(regTag)
  let reg = if isPair: lowOf(tagToPairAvr(regTag, n)) else: tagToRegisterAvr(regTag, n)
  skip n
  bindRegAvr(ctx, name, typ, regTag, reg, isPair)
  result = (name, reg, isPair)

const AvrCallClobbers* = {avr.R18 .. avr.R27, avr.R30, avr.R31, avr.R0, avr.R1}
  ## What a call destroys, following AVR-GCC: r18–r27 and Z are caller-saved, and
  ## so are r1:r0 (which `mul` writes). r2–r17 and Y are callee-saved, which is
  ## where a value that must survive a call belongs.

proc callClobbersAvr(ctx: GenContext): set[avr.Register] =
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersAvr
  else: AvrCallClobbers

proc genPrepareAvr(n: var Cursor; ctx: var GenContext) =
  var hdr = n
  inc hdr
  if hdr.kind != Symbol: error("Expected proc symbol, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)
  if sym == nil: error("Unknown symbol: " & name, hdr)

  let outerCall = ctx.callContext
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
    error("AVR is a bare-metal target: there is nothing to link against, so " &
          "`extproc` (" & name & ") has no meaning here", hdr)
  of skSysProc:
    error("AVR has no OS and therefore no syscalls: '" & name & "'", hdr)
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
  if ctx.callContext.stackArgSize > 0:
    error("AVR: '" & name & "' passes arguments on the stack; this target passes " &
          "four pairs in registers and rejects the rest by name (see M5 in " &
          "doc/internals/avr.md)", hdr)

  into n:
    skip n
    while n.hasMore:
      genInstAvr(n, ctx)

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

proc genCallMarkerAvr(n: var Cursor; ctx: var GenContext) =
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedAvr.incl callClobbersAvr(ctx)

  if ctx.callContext.indirect:
    # `icall` is the ONLY indirect call and it reads Z, so the target must
    # already be there. Loading it here would need a register, and the three that
    # can hold an address are the two bridges and the frame pointer — putting the
    # target in one of them is the code generator's decision, not this one's.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId and
       rawTagIsAvrPair(sym.reg) and tagToPairAvr(sym.reg, n) == avr.Z:
      avr.emitIcall(ctx.buf.data)
    else:
      error("AVR: an indirect call reads Z; bind the target to `(rp30)` before " &
            "`(call)`", n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  # The two-word absolute form, not `rcall`: a 32 KB part is eight times the
  # ±4 KB an `rcall` reaches, so a call between two procs cannot be assumed near.
  avr.emitCall(ctx.buf, labId)
  ctx.callContext.callEmitted = true
  inc n

# ── memory ──────────────────────────────────────────────────────────────────

proc emitLoadAvr(ctx: var GenContext; rd: avr.Register; m: AvrMem; n: Cursor) =
  case m.kind
  of amPtr:
    if m.disp == 0: avr.emitLd(ctx.buf.data, rd, m.p)
    else: avr.emitLdd(ctx.buf.data, rd, m.p, m.disp)
  of amDirect:
    avr.emitLds(ctx.buf.data, rd, m.address)

proc emitStoreAvr(ctx: var GenContext; m: AvrMem; rs: avr.Register; n: Cursor) =
  case m.kind
  of amPtr:
    if m.disp == 0: avr.emitSt(ctx.buf.data, m.p, rs)
    else: avr.emitStd(ctx.buf.data, m.p, m.disp, rs)
  of amDirect:
    avr.emitSts(ctx.buf.data, m.address, rs)

# ── the selector ────────────────────────────────────────────────────────────

proc genInstAvr(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToAvrInst(n.tag)
  let start = n

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
    var regTag = InvalidTagId
    var onStack = false
    var slotAlign = 1     ## AVR has no alignment requirement at all
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsAvrReg(locTag):
        let isPair = rawTagIsAvrPair(locTag)
        let low = if isPair: lowOf(tagToPairAvr(locTag, n))
                  else: tagToRegisterAvr(locTag, n)
        if low in {avr.R0, avr.R1}:
          error("Cannot bind a variable to r1:r0: `mul` writes that pair and r1 " &
                "is the zero register every borrow sequence reads", n)
        if isPair and tagToPairAvr(locTag, n) == avr.Y:
          error("Cannot bind a variable to Y (`rp28`): it is the frame pointer, " &
                "and every stack slot in this proc is addressed through it", n)
        regTag = locTag
        skip n          # `skip`, not `inc`: an AVR register tag may be escaped
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: TypeKind.StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      checkRegWidthAvr(baseTyp, "variable '" & name & "'", n)
      sym.typ = baseTyp
      sym.reg = regTag
      let isPair = rawTagIsAvrPair(regTag)
      let low = if isPair: lowOf(tagToPairAvr(regTag, n))
                else: tagToRegisterAvr(regTag, n)
      if low in ctx.avrRegBindings:
        error("Register " & regName(low) & " is already bound to variable '" &
              ctx.avrRegBindings[low] & "', kill it first before reusing", n)
      if isPair and avr.Register(ord(low) + 1) in ctx.avrRegBindings:
        error("Register " & regName(avr.Register(ord(low) + 1)) &
              " is already bound to variable '" &
              ctx.avrRegBindings[avr.Register(ord(low) + 1)] &
              "', kill it first before reusing", n)
      ctx.bindNames(name, low, isPair)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handled by `case instTag` below"
  else:
    raiseAssert("Unhandled declaration tag in AVR selector")

  # An overflowing mnemonic's id is a leading child; skip it once so every arm's
  # own `inc n` still lands on operand 0.
  if isEscapedTag(n): inc n

  template regReg(emitter: untyped) =
    ## `(op D S)` on two 8-bit registers. Destructive: D is also the first
    ## source, which is what the machine does and what x86-64's two-operand
    ## spelling already means.
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    emitter(ctx.buf.data, regOfAvr(d, "destination", start),
            regOfAvr(s, "source", start))

  template regImm(emitter: untyped; lo, hi: int) =
    ## `(op D K)` — an immediate form, and the encoder asserts that D is
    ## r16..r31, since the field is biased and a low register would silently
    ## encode as a high one.
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    let dr = regOfAvr(d, "destination", start)
    if dr notin avr.ImmRegs:
      error("AVR: `" & $instTag & "` reaches r16..r31 only; " & regName(dr) &
            " needs the constant staged in a high register first", start)
    emitter(ctx.buf.data, dr, immOfAvr(s, "immediate", lo, hi, start))

  template unary(emitter: untyped) =
    inc n
    let d = parseDestAvr(n, ctx)
    emitter(ctx.buf.data, regOfAvr(d, "destination", start))

  template plain(emitter: untyped) =
    ## `skip n`, NOT `inc n` followed by draining `hasMore`: `inc` steps INTO the
    ## node, and `hasMore` is then relative to the enclosing `(stmts …)` — so the
    ## drain swallowed every statement after this one. It only ever showed up
    ## where such an instruction was not the last in its block.
    emitter(ctx.buf.data)
    skip n

  template branch(cond: avr.Condition) =
    inc n
    let t = parseOperandAvr(n, ctx)
    if t.kind != okLabel: error("AVR: a branch needs a label", start)
    ctx.emitBranchAvr(cond, t.label)

  case instTag
  of StmtsAvr:
    loopInto n:
      genInstAvr(n, ctx)
  of ScopeAvr:
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstAvr(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of LabAvr:
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil:
      let labId = ctx.buf.createLabel()
      ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skLabel, offset: int(labId)))
      ctx.buf.defineLabel(labId)
      ctx.definedLabels.incl int(labId)
    elif sym.kind == skLabel:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
      ctx.buf.defineLabel(LabelId(sym.offset))
      ctx.definedLabels.incl sym.offset
    else:
      error("Expected label, got " & $sym.kind, n)
    inc n
  of IteAvr: genIteAvr(n, ctx)
  of LoopAvr: genLoopAvr(n, ctx)
  of JtrueAvr: genJtrueAvr(n, ctx)
  of PrepareAvr: genPrepareAvr(n, ctx)
  of CallAvr:
    if ctx.inCall: genCallMarkerAvr(n, ctx)
    else: error("AVR: a call must appear inside a `(prepare …)` block", start)
  of KillAvr:
    inc n
    if n.kind != Symbol: error("Expected variable name in kill", n)
    let name = getSym(n)
    let sym = ctx.scope.lookup(ctx.symIdOf(name))
    if sym == nil: error("Unknown symbol in kill: " & name, n)
    if sym.reg != InvalidTagId:
      let isPair = rawTagIsAvrPair(sym.reg)
      let low = if isPair: lowOf(tagToPairAvr(sym.reg, n))
                else: tagToRegisterAvr(sym.reg, n)
      ctx.unbindNames(low, isPair)
    elif sym.typ != nil and sym.typ.isOnStack:
      ctx.slots.killSlot(sym.offset, sym.typ.offType)
    ctx.scope.undefine(ctx.symIdOf(name))
    inc n
  of RebindAvr:
    inc n
    discard parseRebindHeaderAvr(n, ctx)
  of WithregAvr:
    inc n
    let hdr = parseRebindHeaderAvr(n, ctx)
    while n.hasMore: genInstAvr(n, ctx)
    ctx.unbindNames(hdr.reg, hdr.isPair)
    ctx.scope.undefine(ctx.symIdOf(hdr.name))

  # ── moves ────────────────────────────────────────────────────────────────
  of MovAvr:
    ## Registers only. A constant is `(ldi)`, which is a different instruction
    ## and does not reach r0..r15 — choosing between them is code generation.
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    if s.kind == okImm:
      error("AVR: `(mov)` moves a register; use `(ldi D K)` for a constant — and " &
            "note it reaches r16..r31 only", start)
    avr.emitMov(ctx.buf.data, regOfAvr(d, "destination", start),
                regOfAvr(s, "source", start))
  of LdiAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    let dr = regOfAvr(d, "destination", start)
    if dr notin avr.ImmRegs:
      error("AVR: `ldi` reaches r16..r31 only; " & regName(dr) & " must receive " &
            "its value through a high register and a `(mov)`", start)
    avr.emitLdi(ctx.buf.data, dr, immOfAvr(s, "immediate", -128, 255, start) and 0xFF)
  of MovwAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    avr.emitMovw(ctx.buf.data, pairOfAvr(d, "destination", start),
                 pairOfAvr(s, "source", start))

  # ── 8-bit ALU ────────────────────────────────────────────────────────────
  of AddAvr: regReg(avr.emitAdd)
  of AdcAvr: regReg(avr.emitAdc)
  of SubAvr: regReg(avr.emitSub)
  of SbcAvr: regReg(avr.emitSbc)
  of AndAvr: regReg(avr.emitAnd)
  of OrAvr: regReg(avr.emitOr)
  of XorAvr: regReg(avr.emitEor)
  of CmpAvr: regReg(avr.emitCp)
  of CpcAvr: regReg(avr.emitCpc)
  of CpseAvr: regReg(avr.emitCpse)
  of MulbAvr: regReg(avr.emitMul)
  of MulsbAvr: regReg(avr.emitMuls)

  of SubiAvr: regImm(avr.emitSubi, -128, 255)
  of SbciAvr: regImm(avr.emitSbci, -128, 255)
  of AndiAvr: regImm(avr.emitAndi, -128, 255)
  of OriAvr: regImm(avr.emitOri, -128, 255)
  of CpiAvr: regImm(avr.emitCpi, -128, 255)

  of NegAvr: unary(avr.emitNeg)
  of NotAvr: unary(avr.emitCom)
  of IncAvr: unary(avr.emitInc)
  of DecAvr: unary(avr.emitDec)
  of SwapAvr: unary(avr.emitSwap)
  of Lsl1Avr: unary(avr.emitLsl)
  of Rol1Avr: unary(avr.emitRol)
  of Lsr1Avr: unary(avr.emitLsr)
  of Ror1Avr: unary(avr.emitRor)
  of Asr1Avr: unary(avr.emitAsr)
  of PushAvr: unary(avr.emitPush)
  of PopAvr: unary(avr.emitPop)

  # ── 16-bit forms on a pair ───────────────────────────────────────────────
  of AdiwAvr, SbiwAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    let dp = pairOfAvr(d, "destination", start)
    if dp notin avr.WordRegs:
      error("AVR: `" & $instTag & "` reaches rp24, X, Y and Z only; " &
            pairName(dp) & " is not one of them", start)
    if s.kind == okSsize:
      # The frame size — a value only the final layout knows. The site is the
      # 6-bit immediate of THIS instruction, which is fixed width, so patching it
      # never resizes anything and no position downstream moves.
      ctx.ssizePatches.add (ctx.buf.data.len, int(s.immVal))
      if instTag == AdiwAvr: avr.emitAdiw(ctx.buf.data, dp, 0)
      else: avr.emitSbiw(ctx.buf.data, dp, 0)
    else:
      let k = immOfAvr(s, "immediate", 0, 63, start)
      if instTag == AdiwAvr: avr.emitAdiw(ctx.buf.data, dp, k)
      else: avr.emitSbiw(ctx.buf.data, dp, k)

  # ── memory ───────────────────────────────────────────────────────────────
  of LdbAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    if s.kind != okMem: error("AVR: the source of `(ldb)` must be memory", start)
    ctx.emitLoadAvr(regOfAvr(d, "destination", start), s.mem, start)
  of StbAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    if d.kind != okMem: error("AVR: the destination of `(stb)` must be memory", start)
    ctx.emitStoreAvr(d.mem, regOfAvr(s, "source", start), start)
  of LdpiAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let p = parseOperandAvr(n, ctx)
    avr.emitLdInc(ctx.buf.data, regOfAvr(d, "destination", start),
                  ptrRegOf(pairOfAvr(p, "pointer", start), start))
  of StpiAvr:
    inc n
    let p = parseOperandAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    avr.emitStInc(ctx.buf.data, ptrRegOf(pairOfAvr(p, "pointer", start), start),
                  regOfAvr(s, "source", start))
  of InbAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    let a = parseOperandAvr(n, ctx)
    avr.emitIn(ctx.buf.data, regOfAvr(d, "destination", start),
               immOfAvr(a, "I/O address", 0, 63, start))
  of OutbAvr:
    inc n
    let a = parseOperandAvr(n, ctx)
    let s = parseOperandAvr(n, ctx)
    avr.emitOut(ctx.buf.data, immOfAvr(a, "I/O address", 0, 63, start),
                regOfAvr(s, "source", start))
  of LpmAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    avr.emitLpm(ctx.buf.data, regOfAvr(d, "destination", start), postInc = false)
  of LpmpiAvr:
    inc n
    let d = parseDestAvr(n, ctx)
    avr.emitLpm(ctx.buf.data, regOfAvr(d, "destination", start), postInc = true)

  # ── skips ────────────────────────────────────────────────────────────────
  of SbrcAvr, SbrsAvr:
    inc n
    let s = parseOperandAvr(n, ctx)
    let b = parseOperandAvr(n, ctx)
    let sr = regOfAvr(s, "source", start)
    let bit = immOfAvr(b, "bit index", 0, 7, start)
    if instTag == SbrcAvr: avr.emitSbrc(ctx.buf.data, sr, bit)
    else: avr.emitSbrs(ctx.buf.data, sr, bit)

  # ── branches ─────────────────────────────────────────────────────────────
  of BAvr, JmpAvr:
    inc n
    let t = parseOperandAvr(n, ctx)
    if t.kind != okLabel: error("AVR: a jump needs a label", start)
    ctx.emitJumpAvr(t.label)
  of BeqAvr: branch(avr.CondEq)
  of BneAvr: branch(avr.CondNe)
  of BltAvr: branch(avr.CondLt)
  of BgeAvr: branch(avr.CondGe)
  of BloAvr: branch(avr.CondLo)
  of BhsAvr: branch(avr.CondSh)
  of BlsAvr, BhiAvr, BleAvr, BgtAvr:
    error("AVR: `" & $instTag & "` has no single-instruction branch here — a " &
          "branch tests ONE status bit, so `<=` and `>` are `>=` and `<` with " &
          "the operands swapped", start)
  of IjmpAvr: plain(avr.emitIjmp)

  # ── the rest ─────────────────────────────────────────────────────────────
  of LeaAvr:
    ## The ADDRESS of a frame slot. Three instructions rather than one, and this
    ## is the one place in this file where that is allowed: the displacement is
    ## nifasm's OWN number — the slot manager assigned it, and the code generator
    ## cannot know it — which is the same exception `(ssize)` lives under.
    ## `emitAddOffsetA64` is the existing precedent.
    inc n
    let d = parseDestAvr(n, ctx)
    let sOp = parseOperandAvr(n, ctx)
    if sOp.kind != okMem or sOp.mem.kind != amPtr:
      error("AVR: `(lea D S)` takes a frame slot", start)
    let dp = pairOfAvr(d, "destination", start)
    let base = case sOp.mem.p
               of avr.PX: avr.X
               of avr.PY: avr.Y
               of avr.PZ: avr.Z
    avr.emitMovw(ctx.buf.data, dp, base)
    if sOp.mem.disp != 0:
      if dp in avr.WordRegs and avr.fitsWordImm(sOp.mem.disp):
        avr.emitAdiw(ctx.buf.data, dp, sOp.mem.disp)
      elif Register(ord(dp)) in avr.ImmRegs:
        # `subi`/`sbci` with the NEGATION, since there is no `addi` here.
        let neg = (-sOp.mem.disp) and 0xFFFF
        avr.emitSubi(ctx.buf.data, Register(ord(dp)), neg and 0xFF)
        avr.emitSbci(ctx.buf.data, Register(ord(dp) + 1), (neg shr 8) and 0xFF)
      else:
        error("AVR: `(lea …)` into " & pairName(dp) & " cannot carry an offset — " &
              "the pair reaches neither `adiw` nor `subi`", start)

  of RetAvr: plain(avr.emitRet)
  of RetiAvr: plain(avr.emitReti)
  of NopAvr: plain(avr.emitNop)
  of SeiAvr: plain(avr.emitSei)
  of CliAvr: plain(avr.emitCli)
  of SleepAvr: plain(avr.emitSleep)
  of WdrAvr: plain(avr.emitWdr)
  of BkptAvr:
    # The simulator trap. `cpse rN, rN` compares a register with itself, so it
    # ALWAYS skips the word that follows — and that word is the invalid opcode
    # `0xFFFF`, which therefore never executes. AVRtest recognises the pair and
    # services it; real silicon skips and carries on, which is the right
    # behaviour for a trap the hardware does not implement.
    #
    # It is one instruction plus one word of data, not two instructions, which is
    # what keeps it inside this file's rule.
    inc n
    let k = parseOperandAvr(n, ctx)
    let num = immOfAvr(k, "syscall number", 0, 31, start)
    avr.emitCpse(ctx.buf.data, avr.Register(num), avr.Register(num))
    ctx.buf.data.addUint16 0xFFFF'u16
  of IcallAvr:
    error("AVR: `(icall)` is emitted by `(call)` inside a `(prepare …)` block, " &
          "which is what checks the arguments against the signature", start)
  else:
    error("AVR: instruction '" & $instTag & "' is not implemented yet " &
          "(see doc/internals/avr.md)", start)

proc genStmtAvr(n: var Cursor; ctx: var GenContext) =
  genInstAvr(n, ctx)

proc genInstNodeAvr*(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstAvr(n, ctx)
