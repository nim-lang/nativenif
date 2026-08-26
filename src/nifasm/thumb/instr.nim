#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Cortex-M (ARMv7E-M / Thumb-2) instruction selection: the counterpart of
## `arm64/instr` and `x64/instr`, against `thumb/encoder`'s emitters.
##
## `genStmtM` deliberately does NOT wrap nested nodes in a listing row, which
## the other two selectors do. That asymmetry predates the split.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    modules, listing, tags, model, tagconv, decls, tagpool,
                    stackslots, relocs, buffers]
import encoder as thumb2
import regs, operands

proc genStmtM*(n: var Cursor; ctx: var GenContext)
proc genInstM*(n: var Cursor; ctx: var GenContext)



proc genIteM*(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobberedM
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar:
      error("Expected cfvar in ite condition: " & name, n)
    if sym.used: error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    thumb2.emitB(ctx.buf, lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    let flagTag = tagToX64Flag(n.tag)
    inc n
    # Branch to the ELSE arm when the condition does NOT hold, so the then-arm
    # falls through.
    ctx.emitBranchM(thumb2.invert(condOfFlagM(flagTag, n)), lElse)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmtM(n, ctx)
  let thenClobbered = ctx.clobberedM
  thumb2.emitB(ctx.buf, lEnd)
  ctx.clobberedM = oldClobbered
  ctx.buf.defineLabel(lElse)
  genStmtM(n, ctx)
  let elseClobbered = ctx.clobberedM
  ctx.buf.defineLabel(lEnd)
  # A register clobbered on EITHER branch is clobbered after the merge.
  ctx.clobberedM = thenClobbered + elseClobbered

proc genLoopM*(n: var Cursor; ctx: var GenContext) =
  inc n
  # The only form arkham emits: `(loop (stmts …))`, whose back-edge nifasm adds
  # here. The body carries a FORWARD branch to a break label defined after the
  # loop, so no backward branch ever appears in the input.
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtM(n, ctx)
    thumb2.emitB(ctx.buf, lStart)
    return
  error("Cortex-M: only the `(loop (stmts …))` form is supported", n)

proc genJtrueM*(n: var Cursor; ctx: var GenContext) =
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
  inc n
  ctx.emitBranchM(condOfFlagM(flagTag, n), target)

proc bindFRegM*(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
               freg: thumb2.FloatRegister) =
  ## The FPv4-SP twin of `bindRegM`: bind an s-register to a typed name, killing
  ## its prior tenant so a stale value shows up as "Unknown symbol" rather than
  ## as a silent clobber.
  if freg in ctx.mFRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.mFRegBindings[freg]))
    ctx.mFRegBindings.del(freg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.mFRegBindings[freg] = name
  ctx.scope.define(sym)

proc bindRegM*(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
              reg: thumb2.Register) =
  ## Bind `reg` to the typed name `name`, KILLING its prior tenant first — so a
  ## later use of a value wrongly left in that register is an "Unknown symbol"
  ## error rather than a silent clobber. The "(re)bind implies a kill" rule that
  ## `rebind` and `withreg` share; mirrors `bindRegA64`/`bindRegX64`.
  if reg in ctx.mRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.mRegBindings[reg]))
    ctx.mRegBindings.del(reg)
  ctx.clobberedM.excl(reg)   # a fresh binding abandons a prior call's clobber
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.mRegBindings[reg] = name
  ctx.scope.define(sym)

proc parseRebindHeaderM*(n: var Cursor; ctx: var GenContext):
                       tuple[name: string; reg: thumb2.Register] =
  ## Parse `:name TYPE (reg)` (cursor already inside the node) and establish the
  ## binding. Shared by `rebind` and `withreg`.
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  checkRegWidthM(typ, "rebind of '" & name & "'", n)
  if n.kind == TagLit and rawTagIsMFloatReg(n.tag):
    let fTag = n.tag
    let f = tagToFloatRegisterM(fTag, n)
    inc n
    bindFRegM(ctx, name, typ, fTag, f)
    return (name, thumb2.R0)          # the GPR half of the result is unused here
  if n.kind != TagLit or not rawTagIsMGpr(n.tag):
    error("Expected a register for rebind/withreg", n)
  let regTag = n.tag
  let reg = tagToRegisterM(regTag, n)
  inc n
  bindRegM(ctx, name, typ, regTag, reg)
  result = (name, reg)

const MCallClobbers* = {thumb2.R0 .. thumb2.R3, thumb2.IP, thumb2.LR}
  ## What a call destroys under AAPCS32: r0–r3 (arguments and return), r12 (IP,
  ## the intra-procedure scratch) and lr (which `bl` overwrites with the return
  ## address). r4–r11 are callee-saved, which is where a value that must survive
  ## a call belongs.

proc callClobbersM*(ctx: GenContext): set[thumb2.Register] =
  ## What THIS callee declares it destroys, falling back to the full volatile set
  ## when the signature declared nothing. An empty declared list is meaningful —
  ## it is what lets a caller keep a value in a caller-saved register across a
  ## call that provably preserves it.
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersM
  else: MCallClobbers

proc genPrepareM*(n: var Cursor; ctx: var GenContext) =
  ## `(prepare target … (call) …)` — the call-site protocol. Sets up the call
  ## context so every `(arg …)` is checked against the target's signature, then
  ## verifies on the way out that every register parameter was bound and that a
  ## call was actually emitted.
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
    error("Cortex-M is a bare-metal target: there is nothing to link against, " &
          "so `extproc` (" & name & ") has no meaning here", hdr)
  of skSysProc:
    error("Cortex-M has no OS and therefore no syscalls: '" & name & "'", hdr)
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
  if ctx.callContext.stackArgSize > ctx.reservedArgArea:
    error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
          " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
          " bytes); call target not visible to the frame pre-scan", hdr)

  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstM(n, ctx)

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

proc genCallMarkerM*(n: var Cursor; ctx: var GenContext) =
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedM.incl callClobbersM(ctx)

  if ctx.callContext.indirect:
    # Through a function pointer. r12 (IP) is the AAPCS32 scratch: caller-saved
    # and never an argument register, so loading the target there cannot disturb
    # the arguments already staged in r0–r3.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # The register holds the code address itself — call straight through it.
      thumb2.emitBlx(ctx.buf.data, tagToRegisterM(sym.reg, n))
    elif sym.kind == skGvar:
      # r12 = &fnptr (patched with the global's absolute address), then load the
      # pointer and call it. IP is the AAPCS32 scratch and never an argument
      # register, so the arguments already staged in r0–r3 are untouched.
      ctx.gvarSites.add (ctx.buf.data.len, sym)
      thumb2.emitMovImm16(ctx.buf.data, thumb2.IP, 0)
      thumb2.emitMovt(ctx.buf.data, thumb2.IP, 0)
      thumb2.emitLdr(ctx.buf.data, thumb2.IP, thumb2.IP, 0'i32)
      thumb2.emitBlx(ctx.buf.data, thumb2.IP)
    elif sym.kind in {skVar, skParam} and sym.typ.isOnStack:
      # A function pointer in a stack slot: load it into IP and call through it.
      thumb2.emitLdr(ctx.buf.data, thumb2.IP, thumb2.SP, int32(sym.offset))
      thumb2.emitBlx(ctx.buf.data, thumb2.IP)
    else:
      error("Cortex-M: indirect call through " & $sym.kind & " is not supported yet", n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  thumb2.emitBl(ctx.buf, labId)
  ctx.callContext.callEmitted = true
  inc n

proc genInstM*(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToMInst(n.tag)
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
    var reg = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsMFloatReg(locTag):
        let f = tagToFloatRegisterM(locTag, n)
        inc n
        let ftyp = parseType(n, ctx.scope, ctx)
        checkRegWidthM(ftyp, "variable '" & name & "'", n)
        if f in ctx.mFRegBindings:
          error("Register " & $f & " is already bound to variable '" &
                ctx.mFRegBindings[f] & "', kill it first before reusing", n)
        bindFRegM(ctx, name, ftyp, locTag, f)
        return
      if rawTagIsMGpr(locTag):
        let r = tagToRegisterM(locTag, n)
        if r == thumb2.IP:
          error("Cannot bind a variable to r12 (reserved as the AAPCS32 IP scratch)", n)
        if r == thumb2.SP or r == thumb2.LR:
          error("Cannot bind a variable to " & $r, n)
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
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: TypeKind.StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      checkRegWidthM(baseTyp, "variable '" & name & "'", n)
      sym.typ = baseTyp
      sym.reg = reg
      let targetReg = tagToRegisterM(reg, n)
      if targetReg in ctx.mRegBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.mRegBindings[targetReg] & "', kill it first before reusing", n)
      ctx.mRegBindings[targetReg] = name
      ctx.clobberedM.excl(targetReg)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handled by `case instTag` below"
  else:
    raiseAssert("Unhandled declaration tag in Cortex-M selector")

  # An overflowing mnemonic's id is a leading child; skip it once so every arm's
  # own `inc n` still lands on operand 0. Same step as genInstX64/genInstA64.
  if isEscapedTag(n): inc n

  template bin3(emitter: untyped) =
    ## `(op3 D A B)` → `D = A op B`, with B folded through a scratch when it is
    ## not already a register (Thumb-2's 3-operand forms take no immediate).
    inc n
    let d = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    let ar = regOfM(a, "first source", start)
    var br: thumb2.Register
    if b.kind == okReg: br = b.reg
    else:
      br = ctx.scratchM(dr, ar)
      ctx.loadToRegM(br, b, start)
    emitter(ctx.buf.data, dr, ar, br)

  template bin2(emitter: untyped) =
    ## `(op D S)` → `D = D op S`, the two-operand spelling. Thumb-2 is a
    ## three-operand ISA, so this is `op3 D, D, S`.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    var sr: thumb2.Register
    if sOp.kind == okReg: sr = sOp.reg
    else:
      sr = ctx.scratchM(dr)
      ctx.loadToRegM(sr, sOp, start)
    emitter(ctx.buf.data, dr, dr, sr)

  template unary(emitter: untyped) =
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    var sr: thumb2.Register
    if sOp.kind == okReg: sr = sOp.reg
    else:
      sr = ctx.scratchM(dr)
      ctx.loadToRegM(sr, sOp, start)
    emitter(ctx.buf.data, dr, sr)

  template loadStore(width: thumb2.MemWidth; loading: bool; signExt: bool) =
    ## The template parameters are deliberately NOT called `isLoad`/`signed`:
    ## those are the encoder's own parameter names, and a template argument of
    ## the same name substitutes into the named-argument syntax below, turning
    ## `isLoad = true` into `true = true`.
    inc n
    if loading:
      let d = parseDestM(n, ctx)
      let sOp = parseOperandM(n, ctx)
      if sOp.kind != okMem: error("load source must be memory", start)
      ctx.emitMemAccessM(regOfM(d, "destination", start), sOp.mem, width,
                         isLoad = true, signed = signExt, n = start)
    else:
      let d = parseDestM(n, ctx)
      let sOp = parseOperandM(n, ctx)
      if d.kind != okMem: error("store destination must be memory", start)
      var sr: thumb2.Register
      if sOp.kind in {okReg, okArg}: sr = sOp.reg
      else:
        sr = ctx.scratchM(d.mem.base, d.mem.index)
        ctx.loadToRegM(sr, sOp, start)
      ctx.emitMemAccessM(sr, d.mem, width, isLoad = false, n = start)

  case instTag
  of StmtsM:
    loopInto n:
      genInstM(n, ctx)
  of ScopeM:
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstM(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of LabM:
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
        ctx.buf.defineLabel(labId)
        ctx.definedLabels.incl int(labId)
      else:
        ctx.buf.defineLabel(LabelId(sym.offset))
        ctx.definedLabels.incl sym.offset
    else:
      error("Symbol is not a label", n)
    inc n
  of MovM:
    inc n
    let dest = parseDestM(n, ctx)
    let op = parseOperandM(n, ctx)
    if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
      error("Type mismatch in mov: expected " & $dest.typ & ", got " & $op.typ, start)
    checkPtrStore(dest.typ, op.kind, op.typ, start)
    checkRegWidthM(dest.typ, "mov destination", start)
    if dest.kind == okMem:
      var sr: thumb2.Register
      if op.kind == okReg: sr = op.reg
      else:
        sr = ctx.scratchM(dest.mem.base)
        ctx.loadToRegM(sr, op, start)
      ctx.storeFromRegM(sr, dest, start)
    else:
      ctx.loadToRegM(regOfM(dest, "mov destination", start), op, start)
  of AdrM, LeaM:
    inc n
    let dest = parseDestM(n, ctx)
    let op = parseOperandM(n, ctx)
    let dr = regOfM(dest, "adr destination", start)
    if op.kind == okMem:
      # `(lea D <lvalue>)` — the ADDRESS, not the contents. A folded index has to
      # be added in explicitly here; there is no address-computing instruction on
      # Thumb-2 that takes a scaled index the way x86's `lea` does.
      if op.mem.base != dr: thumb2.emitMovReg(ctx.buf.data, dr, op.mem.base)
      if op.mem.offset != 0:
        thumb2.emitAddImm(ctx.buf.data, dr, dr, uint32(op.mem.offset))
      if op.mem.hasIndex:
        if op.mem.shift == 0:
          thumb2.emitAdd3(ctx.buf.data, dr, dr, op.mem.index)
        else:
          thumb2.emitLslImm(ctx.buf.data, thumb2.IP, op.mem.index, op.mem.shift)
          thumb2.emitAdd3(ctx.buf.data, dr, dr, thumb2.IP)
    elif op.gvarSym != nil:
      # A global lives in SRAM, nowhere near the code, so its address is
      # materialized ABSOLUTELY (MOVW+MOVT) rather than PC-relatively. The pair is
      # a fixed 8 bytes; the image writer patches its immediates once the .bss
      # layout is known, exactly as the AArch64 backend patches its adrp+add.
      ctx.gvarSites.add (ctx.buf.data.len, op.gvarSym)
      thumb2.emitMovImm16(ctx.buf.data, dr, 0)
      thumb2.emitMovt(ctx.buf.data, dr, 0)
    else:
      # A code/rodata label. MOVW+MOVT carries the ABSOLUTE address, so unlike
      # ADR it has no ±4 KB reach limit — a firmware image's load address is
      # fixed at link time, so there is nothing to be relative to.
      #
      # A PROC's address additionally carries the Thumb bit: `blx` to an even
      # address switches to ARM state, which M-profile does not have.
      if op.isCode: thumb2.emitMovwMovtFunc(ctx.buf, dr, op.label)
      else: thumb2.emitMovwMovtAbs(ctx.buf, dr, op.label)
  of CmpM:
    inc n
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let ar = regOfM(a, "cmp first operand", start)
    if b.kind == okImm and b.immVal >= 0 and thumb2.isModifiedImm(uint32(b.immVal)):
      thumb2.emitCmpImm(ctx.buf.data, ar, uint32(b.immVal))
    else:
      var br: thumb2.Register
      if b.kind == okReg: br = b.reg
      else:
        br = ctx.scratchM(ar)
        ctx.loadToRegM(br, b, start)
      thumb2.emitCmpReg(ctx.buf.data, ar, br)
  of TstM:
    inc n
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let ar = regOfM(a, "tst first operand", start)
    var br: thumb2.Register
    if b.kind == okReg: br = b.reg
    else:
      br = ctx.scratchM(ar)
      ctx.loadToRegM(br, b, start)
    thumb2.emitTstReg(ctx.buf.data, ar, br)
  of OrrM: bin2(thumb2.emitOrr3)
  of EorM: bin2(thumb2.emitEor3)
  of LslM: bin2(thumb2.emitLsl)
  of LsrM: bin2(thumb2.emitLsr)
  of AsrM: bin2(thumb2.emitAsr)
  # The W-forms are AArch64's 32-bit views of a 64-bit register. On Cortex-M a
  # register IS 32 bits, so each is simply its full-width counterpart — accepted
  # rather than rejected so the code generator need not know the difference.
  of AddwM: bin2(thumb2.emitAdd3)
  of SubwM: bin2(thumb2.emitSub3)
  of MulwM: bin2(thumb2.emitMul)
  of Addw3M: bin3(thumb2.emitAdd3)
  of Subw3M: bin3(thumb2.emitSub3)
  of Mulw3M: bin3(thumb2.emitMul)
  of AddM: bin2(thumb2.emitAdd3)
  of SubM: bin2(thumb2.emitSub3)
  of MulM: bin2(thumb2.emitMul)
  of AndM: bin2(thumb2.emitAnd3)
  of Add3M: bin3(thumb2.emitAdd3)
  of Sub3M: bin3(thumb2.emitSub3)
  of Mul3M: bin3(thumb2.emitMul)
  of And3M: bin3(thumb2.emitAnd3)
  of Orr3M: bin3(thumb2.emitOrr3)
  of Eor3M: bin3(thumb2.emitEor3)
  of Bic3M: bin3(thumb2.emitBic3)
  of Lsl3M: bin3(thumb2.emitLsl)
  of Lsr3M: bin3(thumb2.emitLsr)
  of Asr3M: bin3(thumb2.emitAsr)
  of Adds3M: bin3(thumb2.emitAddsCarry)
  of Adcs3M: bin3(thumb2.emitAdcs)
  of Subs3M: bin3(thumb2.emitSubsCarry)
  of Sbcs3M: bin3(thumb2.emitSbcs)
  of SdivM: bin3(thumb2.emitSdiv)
  of UdivM: bin3(thumb2.emitUdiv)
  of NegM: unary(thumb2.emitNeg)
  of MvnM: unary(thumb2.emitMvn)
  of ClzM: unary(thumb2.emitClz)
  of RbitM: unary(thumb2.emitRbit)
  of RevM: unary(thumb2.emitRev)
  of UxtbM: unary(thumb2.emitUxtb)
  of SxtbM: unary(thumb2.emitSxtb)
  of UxthM: unary(thumb2.emitUxth)
  of SxthM: unary(thumb2.emitSxth)
  of MlsM:
    # `(mls D A B C)` → D = C - A*B. The remainder half of a division.
    inc n
    let d = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let c = parseOperandM(n, ctx)
    thumb2.emitMls(ctx.buf.data, regOfM(d, "destination", start),
                   regOfM(a, "operand A", start), regOfM(b, "operand B", start),
                   regOfM(c, "operand C", start))
  of UmullM, SmullM:
    # `(umull L H A B)` → the 64-bit product into the register PAIR L (low) / H (high).
    inc n
    let lo = parseDestM(n, ctx)
    let hi = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let lr0 = regOfM(lo, "low destination", start)
    let hr = regOfM(hi, "high destination", start)
    if lr0 == hr: error("umull/smull need two DISTINCT destination registers", start)
    if instTag == UmullM:
      thumb2.emitUmull(ctx.buf.data, lr0, hr, regOfM(a, "operand A", start),
                       regOfM(b, "operand B", start))
    else:
      thumb2.emitSmull(ctx.buf.data, lr0, hr, regOfM(a, "operand A", start),
                       regOfM(b, "operand B", start))
  of LdrM:   loadStore(thumb2.MemWord, true, false)
  of StrM:   loadStore(thumb2.MemWord, false, false)
  of LdrbM:  loadStore(thumb2.MemByte, true, false)
  of StrbM:  loadStore(thumb2.MemByte, false, false)
  of LdrhM:  loadStore(thumb2.MemHalf, true, false)
  of StrhM:  loadStore(thumb2.MemHalf, false, false)
  of LdrsbM: loadStore(thumb2.MemByte, true, true)
  of LdrshM: loadStore(thumb2.MemHalf, true, true)
  of RebindM:
    # `(rebind :name TYPE (reg))` — bind until an explicit kill, the next rebind
    # of the same register, or proc end.
    into n:
      discard parseRebindHeaderM(n, ctx)
  of WithregM:
    # `(withreg :name TYPE (reg) body…)` — a block-scoped rebind, auto-killed at
    # the end of the body.
    into n:
      let h = parseRebindHeaderM(n, ctx)
      while n.hasMore: genInstM(n, ctx)
      if ctx.mRegBindings.getOrDefault(h.reg, "") == h.name:
        ctx.mRegBindings.del(h.reg)
      ctx.scope.undefine(ctx.symIdOf(h.name))
  of BeqM, BneM, BhsM, BloM, BltM, BlsM, BhiM, BgtM, BgeM, BleM:
    # The per-condition branch forms the code generator emits directly (as
    # opposed to `ite`/`jtrue`, which take a flag tag). Each maps to one Thumb
    # condition; the ±1 MB reach of B<cond>.W is the relocation's problem.
    inc n
    if n.kind != Symbol: error("conditional branch needs a label", start)
    let lbl = parseOperandM(n, ctx)
    let cond = case instTag
               of BeqM: thumb2.CondEQ
               of BneM: thumb2.CondNE
               of BhsM: thumb2.CondHS
               of BloM: thumb2.CondLO
               of BltM: thumb2.CondLT
               of BlsM: thumb2.CondLS
               of BhiM: thumb2.CondHI
               of BgtM: thumb2.CondGT
               of BgeM: thumb2.CondGE
               else: thumb2.CondLE
    thumb2.emitBcond(ctx.buf, cond, lbl.label)
  of PrepareM: genPrepareM(n, ctx)
  of CallM: genCallMarkerM(n, ctx)
  of IteM:  genIteM(n, ctx)
  of LoopM: genLoopM(n, ctx)
  of JtrueM: genJtrueM(n, ctx)
  of BM, BlM:
    inc n
    if n.kind != Symbol: error("b/bl needs a label or proc symbol", start)
    let op = parseOperandM(n, ctx)
    if instTag == BM: thumb2.emitB(ctx.buf, op.label)
    else: thumb2.emitBl(ctx.buf, op.label)
  of CbzM, CbnzM:
    # No CBZ/CBNZ encoder: their reach is +4..+126 bytes FORWARD only, which a
    # relocation pass cannot honour once anything moves. `cmp #0` + `b<cond>` is
    # two bytes larger and always correct.
    inc n
    let rOp = parseOperandM(n, ctx)
    let rr = regOfM(rOp, "cbz operand", start)
    if n.kind != Symbol: error("cbz/cbnz needs a label", start)
    let lbl = parseOperandM(n, ctx)
    thumb2.emitCmpImm(ctx.buf.data, rr, 0)
    ctx.emitBranchM((if instTag == CbzM: thumb2.CondEQ else: thumb2.CondNE), lbl.label)
  of BxM:
    inc n
    thumb2.emitBx(ctx.buf.data, parseRegisterM(n))
  of BlxM:
    inc n
    thumb2.emitBlx(ctx.buf.data, parseRegisterM(n))
  of RetM:
    inc n
    thumb2.emitRet(ctx.buf.data)
  of NopM:
    inc n
    thumb2.emitNop(ctx.buf.data)
  of YieldM:
    inc n
    thumb2.emitYield(ctx.buf.data)
  of WfiM:
    inc n
    thumb2.emitWfi(ctx.buf.data)
  of BkptM:
    inc n
    if n.kind != IntLit: error("bkpt needs an immediate", start)
    thumb2.emitBkpt(ctx.buf.data, uint8(getInt(n) and 0xFF))
    inc n
  # ── FPv4-SP ───────────────────────────────────────────────────────────────
  # Single precision only; a double is refused by `checkRegWidthM` long before
  # it can reach an encoder that has no `.f64` form to offer.
  of FmovM:
    # `(fmov D S)` is three instructions in one mnemonic, exactly as it is on
    # AArch64: fp<-fp, fp<-gpr and gpr<-fp. Which one is decided by the operand
    # REGISTER CLASSES, not by a separate tag.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if d.isFloat and sOp.isFloat:
      thumb2.emitVmovReg(ctx.buf.data, d.freg, sOp.freg)
    elif d.isFloat:
      var sr: thumb2.Register
      if sOp.kind in {okReg, okArg} and not sOp.isFloat: sr = sOp.reg
      else:
        sr = ctx.scratchM()
        ctx.loadToRegM(sr, sOp, start)
      thumb2.emitVmovToFp(ctx.buf.data, d.freg, sr)
    elif sOp.isFloat:
      thumb2.emitVmovFromFp(ctx.buf.data, regOfM(d, "fmov destination", start),
                            sOp.freg)
    else:
      error("fmov needs a floating-point register on one side", start)
  of FaddM, FsubM, FmulM, FdivM:
    # `(fop D S)` — destructive on AArch64, three-operand on Thumb-2, so `D` is
    # repeated as the first source.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat or not sOp.isFloat:
      error("fadd/fsub/fmul/fdiv need floating-point registers", start)
    case instTag
    of FaddM: thumb2.emitVadd(ctx.buf.data, d.freg, d.freg, sOp.freg)
    of FsubM: thumb2.emitVsub(ctx.buf.data, d.freg, d.freg, sOp.freg)
    of FmulM: thumb2.emitVmul(ctx.buf.data, d.freg, d.freg, sOp.freg)
    else:     thumb2.emitVdiv(ctx.buf.data, d.freg, d.freg, sOp.freg)
  of FnegM:
    inc n
    let d = parseDestM(n, ctx)
    if not d.isFloat: error("fneg needs a floating-point register", start)
    thumb2.emitVneg(ctx.buf.data, d.freg, d.freg)
  of FcmpM:
    # VCMP writes FPSCR and the conditional branches read APSR, so a float
    # compare is always the PAIR. There is no float-condition branch to fuse it
    # into, which is why this cannot be split.
    inc n
    let d = parseOperandM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat or not sOp.isFloat:
      error("fcmp needs floating-point registers", start)
    thumb2.emitVcmp(ctx.buf.data, d.freg, sOp.freg)
    thumb2.emitVmrsApsr(ctx.buf.data)
  of FldrM:
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat: error("fldr destination must be a floating-point register", start)
    if sOp.kind != okMem: error("fldr source must be memory", start)
    ctx.emitVfpMemAccessM(d.freg, sOp.mem, isLoad = true, n = start)
  of FstrM:
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if d.kind != okMem: error("fstr destination must be memory", start)
    if not sOp.isFloat: error("fstr source must be a floating-point register", start)
    ctx.emitVfpMemAccessM(sOp.freg, d.mem, isLoad = false, n = start)
  of ScvtfM, UcvtfM:
    # `(scvtf D S)` — D fp, S integer. FPv4 converts inside the FPU, so the
    # integer crosses with VMOV first and is converted in place in D.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat: error("scvtf/ucvtf destination must be a float register", start)
    var sr: thumb2.Register
    if sOp.kind in {okReg, okArg} and not sOp.isFloat: sr = sOp.reg
    else:
      sr = ctx.scratchM()
      ctx.loadToRegM(sr, sOp, start)
    thumb2.emitVmovToFp(ctx.buf.data, d.freg, sr)
    thumb2.emitVcvtToF32(ctx.buf.data, d.freg, d.freg, signed = instTag == ScvtfM)
  of FcvtzsM, FcvtzuM:
    # `(fcvtzs D S)` — D integer, S fp. The converted value has to land in an fp
    # register before it can cross, and S may still be live, so it lands in the
    # selector's own float scratch.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not sOp.isFloat: error("fcvtzs/fcvtzu source must be a float register", start)
    thumb2.emitVcvtFromF32(ctx.buf.data, MFpScratch, sOp.freg,
                           signed = instTag == FcvtzsM)
    thumb2.emitVmovFromFp(ctx.buf.data, regOfM(d, "destination", start), MFpScratch)
  of LdrexM:
    # `(ldrex D S N)` — D ← the N-bit cell at [S], taking the monitor's claim.
    # Both operands may be `rebind`-bound scratch names: the atomics lowering
    # binds every register it stages through, so this goes through the same
    # operand parser as an ordinary load rather than a raw-register one.
    inc n
    let rt = regOfM(parseOperandM(n, ctx), "ldrex destination", start)
    let rn = regOfM(parseOperandM(n, ctx), "ldrex address", start)
    if n.kind != IntLit: error("ldrex needs an access width (8, 16 or 32)", start)
    let bits = int(getInt(n)); inc n
    if bits notin [8, 16, 32]:
      error("ARMv7-M has no " & $bits & "-bit exclusive load", start)
    thumb2.emitLdrex(ctx.buf.data, rt, rn, bits)
  of StrexM:
    # `(strex St D S N)` — store D into [S] if the claim holds; St ← 0 on success.
    inc n
    let rd = regOfM(parseOperandM(n, ctx), "strex status", start)
    let rt = regOfM(parseOperandM(n, ctx), "strex value", start)
    let rn = regOfM(parseOperandM(n, ctx), "strex address", start)
    if n.kind != IntLit: error("strex needs an access width (8, 16 or 32)", start)
    let bits = int(getInt(n)); inc n
    if bits notin [8, 16, 32]:
      error("ARMv7-M has no " & $bits & "-bit exclusive store", start)
    if rd == rt or rd == rn:
      # UNPREDICTABLE per the architecture, and the retry loop branches on the
      # status — so this is an infinite loop rather than a wrong value, which is
      # exactly the kind of thing a typed assembler exists to refuse.
      error("strex status register must differ from its value and address registers",
            start)
    thumb2.emitStrex(ctx.buf.data, rd, rt, rn, bits)
  of DmbM:
    inc n
    thumb2.emitDmb(ctx.buf.data)
  of ClrexM:
    inc n
    thumb2.emitClrex(ctx.buf.data)
  of DsbM:
    inc n
    thumb2.emitDsb(ctx.buf.data)
  of IsbM:
    inc n
    thumb2.emitIsb(ctx.buf.data)
  of KillM:
    # `(kill name…)` — end a register binding so the register may be rebound.
    inc n
    while n.hasMore and n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym != nil and sym.reg != InvalidTagId:
        if rawTagIsMFloatReg(sym.reg):
          ctx.mFRegBindings.del(tagToFloatRegisterM(sym.reg, n))
        else:
          ctx.mRegBindings.del(tagToRegisterM(sym.reg, n))
      inc n
  of NoMInst:
    error("Cortex-M: unsupported instruction", start)
  else:
    error("Cortex-M: instruction '" & $instTag & "' is not implemented yet " &
          "(see doc/cortex_m.md)", start)

proc genStmtM*(n: var Cursor; ctx: var GenContext) =
  genInstM(n, ctx)

proc genInstNodeM*(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstM(n, ctx)
