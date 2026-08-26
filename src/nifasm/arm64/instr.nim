#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## AArch64 instruction selection: one asm-NIF node in, encoded bytes out.
##
## Serves Darwin, Linux and Windows on arm64 — they differ in their object
## format and their syscall convention, not in their instruction set, so what
## varies here is guarded by `ctx.arch` rather than duplicated.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    listing, emit, tags, model, tagconv, decls,
                    tagpool, stackslots, relocs, buffers]
import encoder as arm64
import regs, operands

proc genStmtA64*(n: var Cursor; ctx: var GenContext)
proc genInstA64*(n: var Cursor; ctx: var GenContext)

const A64CallClobbers* = {arm64.X0 .. arm64.X15}
  ## The caller-saved GPRs a call destroys (AAPCS64; x16/x17 are assembler veneers
  ## never bound to a variable, x18 is platform-reserved). A bound value living in one
  ## of these across a `(call)`/`(extcall)` is gone — exactly what arkham's allocator
  ## avoids by homing cross-call values in callee-saved x19–x28, and what the clobber
  ## check guards against. Matches arkham's emitted `(clobber …)` (`ConvClobbersGpr`).

proc genPrepareA64*(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  let outerCall = ctx.callContext            # restored at the end — see genPrepareX64
  # `> stackArgBase`, not `> 0`: the base is Win64 shadow space, which the CALLEE
  # writes after the call, so two nested calls never contend for it. Genuine stack
  # ARGUMENTS are the conflict — the outer call has already placed some in the one
  # outgoing area the inner call is about to reuse.
  if outerCall.state != CallContextState.Disabled and
     outerCall.stackArgSize > outerCall.stackArgBase:
    error("Nested prepare blocks are not allowed when the outer call passes arguments " &
          "on the stack: both would write the one outgoing argument area", hdr)
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the IAT/extcall path.
    ctx.callContext.typ = sym.typ
  elif sym.kind == skSysProc:
    # A Linux syscall with a full proctype: args land in the syscall ABI registers
    # the proctype names (x0–x5); the invocation marker is `(svc 0)`, which
    # `genSyscallMarkerA64` turns into `mov x8,NR; svc 0`. No `bl`/address.
    ctx.callContext.typ = sym.typ
    ctx.callContext.isSyscall = true
    ctx.callContext.syscallNr = sym.offset
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls through it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    ctx.callContext.state = CallContextState.ExternalCall
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Compute stack argument size (only for internal procs)
  if ctx.callContext.state == CallContextState.NormalCall:
    ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
    # Fixed-frame soundness (AArch64): this call's outgoing stack args occupy
    # `[sp, sp+stackArgSize)`, the region `scanStackArgArea` reserved at the frame bottom.
    # If the pre-scan didn't see this target (an indirect call through a not-yet-declared
    # local fn-ptr), the reservation may be too small — fail loudly rather than let the
    # args overwrite a local `(s)` slot.
    if ctx.callContext.stackArgSize > ctx.reservedArgArea:
      error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
            " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
            " bytes); call target not visible to the frame pre-scan", hdr)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstA64(n, ctx)

  # Verify call was emitted and all bindings are done
  if ctx.callContext.state == CallContextState.NormalCall:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & ctx.nameOf(param.name), hdr)

    if not ctx.callContext.isTailcall:
      # A tail call binds no result: the callee's return value IS this proc's, and
      # it is already in the return register when the callee's own `ret` runs.
      for res in ctx.callContext.typ.results:
        if res.name notin ctx.callContext.resultsSet:
          error("Missing result binding: " & ctx.nameOf(res.name), hdr)

    if not ctx.callContext.callEmitted:
      error("Missing (call), (tailcall) or (extcall) in prepare block", hdr)
  else:
    if not ctx.callContext.callEmitted:
      error("Missing (extcall) in prepare block", hdr)

  # Resume the enclosing call, if this prepare was nested inside one. arkham emits that
  # for an argument that is itself a call — `f(g(x))`, which hexer leaves unflattened in
  # a global's initializer expression. The inner call completes (its result lands in the
  # return register) before any of the outer call's `(arg …)` bindings that follow it.
  ctx.callContext = outerCall
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc callClobbersA64*(ctx: GenContext): set[arm64.Register] =
  ## What the callee currently being `prepare`d actually destroys. The signature's
  ## own `(clobber …)` wins when it declared one: arkham emits an EMPTY list for a
  ## `(attr "noreturn")` callee (panic, raiseAssert, the bounds-check failure path),
  ## because a call that never returns has no "afterwards" in which a caller could
  ## observe the damage — and taking that at face value is what lets the allocator
  ## keep a value in a caller-saved register across a cold guard instead of forcing
  ## it onto a callee-saved home with the prologue push/pop that entails. A
  ## signature that declared nothing at all falls back to the full volatile set.
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersA64
  else: A64CallClobbers

proc genCallMarkerA64*(n: var Cursor; ctx: var GenContext) =
  ## Handle (call) marker inside a prepare block - emits the actual call instruction
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedA64.incl callClobbersA64(ctx)   # what the callee declares it destroys

  if ctx.callContext.indirect:
    # Indirect call through a function-pointer variable: load the pointer into x16
    # (IP0 — caller-saved, not an argument register, so the prepared args in x0–x7
    # are untouched) and `blr` through it. A global's address is formed with adrp+add
    # (recorded as a gvar site and patched once the data layout is known), exactly
    # like a `(lea reg gvar)`; then the pointer value is loaded and called.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # A function pointer held directly in a REGISTER (vtable-method load / reg-resident
      # `var f: proc`): the register holds the code address itself → `blr reg`, no load.
      arm64.emitBlr(ctx.buf.data, tagToRegisterA64(sym.reg, n))
    elif sym.kind == skGvar:
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X16)            # x16 = &fnptr
      ctx.gvarSites.add (pos, sym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X16, 0'i32)  # x16 = fnptr
      arm64.emitBlr(ctx.buf.data, arm64.X16)
    else:
      error("Indirect call through unsupported function-pointer location: " &
            $sym.kind, n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)

  ctx.buf.emitBL(labId)
  ctx.callContext.callEmitted = true

  inc n

proc genTailcallMarkerA64*(n: var Cursor; ctx: var GenContext) =
  ## `(tailcall)` — the `(call)` marker's no-link twin. Same prepared arguments,
  ## same clobber declaration, `b`/`br` instead of `bl`/`blr`: control leaves this
  ## proc for good, so the callee returns to OUR caller and its `ret` is ours.
  ##
  ## The frame is already gone. arkham tears it down between the last argument
  ## store and this marker — the teardown touches only SP and callee-saved
  ## registers, never x0–x7 — so nothing here may address a stack slot, which is
  ## also why arkham refuses to form a tail call that needs stack arguments.
  if not ctx.inCall:
    error("(tailcall) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedA64.incl callClobbersA64(ctx)
  ctx.callContext.isTailcall = true
  if ctx.callContext.indirect:
    # An INDIRECT tail call would have to survive the `(popframe)` that precedes
    # it, and the pointer is exactly what does not: it sits in a register the
    # prologue saved, so restoring the frame restores the caller's value over it.
    # Staging it in x16 first is possible but not expressible here — `(popframe)`
    # is already emitted by the time this marker is read — so the backend must not
    # form one, and this says so loudly rather than branching to whatever the
    # caller happened to leave in that register.
    error("indirect tail call: the target register does not survive (popframe)", n)
  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  ctx.buf.emitB(labId)
  ctx.callContext.callEmitted = true
  inc n

proc genSyscallMarkerA64*(n: var Cursor; ctx: var GenContext) =
  ## `(svc 0)` inside a `(prepare <syproc> …)` block: the syscall counterpart of
  ## `(call)`. The args are already in x0–x5 (the syproc's params); this loads the
  ## number into x8 and traps. Unlike a `bl`, a Linux/AArch64 `svc` preserves every
  ## register except x0 (the result), so only x0 is marked clobbered.
  if ctx.callContext.callEmitted:
    error("Multiple call/syscall instructions in prepare block", n)
  intoOperands n:                        # `(svc 0)` — consume and ignore the immediate
    skip n
    while n.hasMore: skip n
  arm64.emitMovImm64(ctx.buf.data, arm64.X8, uint64(ctx.callContext.syscallNr))
  arm64.emitSvc(ctx.buf.data, 0'u16)
  ctx.clobberedA64.incl arm64.X0
  ctx.callContext.callEmitted = true

proc genExtcallA64*(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)
  ctx.clobberedA64.incl callClobbersA64(ctx)   # what the callee declares it destroys

  # Record call site and emit BL (will be patched to point to stub)
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.data.addUint32(0x94000000'u32)  # BL placeholder

  ctx.callContext.callEmitted = true

  inc n

proc genIteA64*(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobbered
  let oldClobberedA64 = ctx.clobberedA64
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)
    if sym.used:
      error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    ctx.buf.emitB(lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    # Hardware condition - ARM64 uses flags from CMP
    let flagTag = tagToX64Flag(n.tag)
    inc n

    # Emit branch to else if condition is NOT met (inverted condition)
    case flagTag
    of ZfO: ctx.buf.emitBne(lElse)   # if ZF set wanted, jump to else if ZF clear
    of NzO: ctx.buf.emitBeq(lElse)   # if ZF clear wanted, jump to else if ZF set
    else: error("Unsupported ARM64 flag condition: " & $flagTag, n)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmtA64(n, ctx)
  let thenClobbered = ctx.clobbered
  let thenClobberedA64 = ctx.clobberedA64
  ctx.buf.emitB(lEnd)
  ctx.clobbered = oldClobbered
  ctx.clobberedA64 = oldClobberedA64
  ctx.buf.defineLabel(lElse)
  genStmtA64(n, ctx)
  let elseClobbered = ctx.clobbered
  let elseClobberedA64 = ctx.clobberedA64
  ctx.buf.defineLabel(lEnd)
  # A register clobbered on EITHER branch is clobbered after the merge.
  ctx.clobbered = thenClobbered + elseClobbered
  ctx.clobberedA64 = thenClobberedA64 + elseClobberedA64

proc genLoopA64*(n: var Cursor; ctx: var GenContext) =
  inc n
  # Bare infinite-loop form `(loop (stmts …))` — the back-edge is emitted INTERNALLY here,
  # so no backward branch reaches the input; the body carries a FORWARD branch to a break/
  # exit label defined AFTER the loop. This is the form arkham emits for every loop (mirrors
  # the x64 `genLoopX64`). The legacy `(loop <pre> <condflag> <body>)` form below is unused.
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtA64(n, ctx)                 # the body (contains the forward break/exit branch)
    ctx.buf.emitB(lStart)           # the loop back-edge — emitted by nifasm, not the input
    return

  genStmtA64(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  ctx.buf.defineLabel(lStart)
  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

  # ARM64 loop conditions - exit loop if condition is NOT met
  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitBne(lEnd)   # if ZF set wanted, exit if ZF clear
  of NzO: ctx.buf.emitBeq(lEnd)   # if ZF clear wanted, exit if ZF set
  else: error("Unsupported ARM64 loop condition: " & $loopFlagTag, n)

  genStmtA64(n, ctx)
  ctx.buf.emitB(lStart)
  ctx.buf.defineLabel(lEnd)

proc genJtrueA64*(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  var jumpTarget: LabelId
  var firstCfvar = true
  while n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown cfvar: " & name, n)
    if sym.kind != skCfvar: error("Symbol is not a cfvar: " & name, n)
    if firstCfvar:
      jumpTarget = LabelId(sym.offset)
      firstCfvar = false
    inc n
  if firstCfvar: error("jtrue requires at least one cfvar", start)
  ctx.buf.emitB(jumpTarget)

proc genKillA64*(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)
  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  elif sym.reg != InvalidTagId:
    if isA64FpRegTag(sym.reg):
      ctx.a64FRegBindings.del(tagToFloatRegA64(sym.reg))
    else:
      ctx.a64RegBindings.del(tagToRegisterA64(sym.reg, n))
  ctx.scope.undefine(sym.name)
  inc n

proc bindRegA64*(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                reg: arm64.Register) =
  ## Bind physical register `reg` to the typed name `name`, *killing its prior tenant
  ## first* (the previous binding's name is undefined, so a later use of a value
  ## wrongly left in that register becomes an "Unknown symbol" error rather than a
  ## silent clobber). The "(re)bind implies a kill of the prior tenant" rule shared by
  ## `rebind` and `withreg`. Mirrors x64's `bindRegX64`.
  if reg in ctx.a64RegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.a64RegBindings[reg]))
    ctx.a64RegBindings.del(reg)
  ctx.clobberedA64.excl(reg)   # a fresh binding abandons a prior call's clobber (see bindRegX64)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.a64RegBindings[reg] = name
  ctx.scope.define(sym)

proc bindFRegA64*(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                 reg: arm64.FloatRegister) =
  ## The SIMD twin of `bindRegA64`: bind v-register `reg` to the typed float name
  ## `name`, killing its prior tenant first. The binding's type carries the precision
  ## (`(f 32)`/`(f 64)`) so a *named* use recovers s/d. Used for float register locals
  ## and float scratch temps.
  if reg in ctx.a64FRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.a64FRegBindings[reg]))
    ctx.a64FRegBindings.del(reg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.a64FRegBindings[reg] = name
  ctx.scope.define(sym)

proc parseRebindHeaderA64*(n: var Cursor; ctx: var GenContext):
                          tuple[name: string; isFp: bool; reg: arm64.Register;
                                freg: arm64.FloatRegister] =
  ## Parse `:name TYPE (reg)` (cursor past the rebind/withreg tag, inside the node)
  ## and establish the binding. Shared by `rebind` and `withreg`. The register may be
  ## a GPR (`(xN)`) or — for a float binding — a v-register (`(dN)`/`(sN)`).
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  if isA64FpRegOperand(n):
    let regTag = n.tag
    let freg = tagToFloatRegA64(regTag)
    inc n
    bindFRegA64(ctx, name, typ, regTag, freg)
    result = (name, true, arm64.Register(0), freg)
  elif n.kind == TagLit and rawTagIsA64Reg(n.tag):
    let regTag = n.tag
    let reg = tagToRegisterA64(regTag, n)
    inc n
    bindRegA64(ctx, name, typ, regTag, reg)
    result = (name, false, reg, arm64.FloatRegister(0))
  else:
    error("Expected a register for rebind/withreg", n)

proc genRebindA64*(n: var Cursor; ctx: var GenContext) =
  ## `(rebind :name TYPE (reg))` — bind `reg` to `name`, killing its prior tenant. The
  ## binding lives until an explicit `kill`, the next `rebind` of `reg`, or proc end
  ## (`a64RegBindings` is reset per proc).
  into n:
    discard parseRebindHeaderA64(n, ctx)

proc genWithregA64*(n: var Cursor; ctx: var GenContext) =
  ## `(withreg :name TYPE (reg) body…)` — a block-scoped `rebind`: the binding is
  ## auto-killed at the end of the body, in addition to killing `reg`'s prior tenant.
  into n:
    let h = parseRebindHeaderA64(n, ctx)
    while n.hasMore: genInstA64(n, ctx)
    if h.isFp:
      if ctx.a64FRegBindings.getOrDefault(h.freg, "") == h.name:
        ctx.a64FRegBindings.del(h.freg)
    elif ctx.a64RegBindings.getOrDefault(h.reg, "") == h.name:
      ctx.a64RegBindings.del(h.reg)
    ctx.scope.undefine(ctx.symIdOf(h.name))

proc genPopframeA64*(ctx: var GenContext) =
  ## `(popframe)` — undo this proc's prologue, wherever we are in its body.
  ##
  ## The frame's shape is nifasm's to know, not the backend's: arkham finalizes
  ## `usedCallee`/`hasStackVars` only AFTER it has emitted the body (a register
  ## claimed by a last-resort pick mid-body still adds a prologue pair), so a
  ## teardown written at a mid-body site would have to guess how many pairs to pop
  ## and whether a frame `sub` exists at all. Here neither is a guess: the prologue
  ## has already been assembled and `ctx.unwind[^1].steps` records every one of its
  ## stores, in order, with the registers it saved. Replaying that in reverse is the
  ## epilogue by construction.
  ##
  ## A tail call is the caller of this: arguments in place, frame gone, `b` to the
  ## callee, whose `ret` returns to OUR caller.
  if ctx.unwind.len == 0: return
  let steps = ctx.unwind[^1].steps
  for i in countdown(steps.len - 1, 0):
    let st = steps[i]
    if st.ssizeSlot:
      # The frame `sub`'s twin — same two halves, same patch list, since the size
      # is still unknown until the slots are laid out.
      arm64.emitAddImm(ctx.buf.data, arm64.SP, arm64.SP, 0'u16)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, 0))
      arm64.emitAddImmShifted12(ctx.buf.data, arm64.SP, arm64.SP, 0'u16)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, 0))
    elif st.saves.len == 2:
      # One pair push: `stp a, b, [sp, #-16]!` undone by `ldp a, b, [sp], #16`.
      if st.saves[0].isFloat:
        arm64.emitFldpPost(ctx.buf.data,
                           arm64.FloatRegister(st.saves[0].reg),
                           arm64.FloatRegister(st.saves[1].reg), arm64.SP, 16'i32)
      else:
        arm64.emitLdp(ctx.buf.data,
                      arm64.Register(st.saves[0].reg),
                      arm64.Register(st.saves[1].reg), arm64.SP, 16'i32)

proc genInstA64*(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToA64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: ctx.symIdOf(name), kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)
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
      if rawTagIsA64Reg(locTag):
        # Check for reserved registers (x16/x17 are reserved for assembler scratch)
        let regTag = tagToA64Reg(locTag)
        if regTag == X16R:
          error("Cannot bind variable to x16 (reserved for assembler use as IP0)", n)
        elif regTag == X17R:
          error("Cannot bind variable to x17 (reserved for assembler use as IP1)", n)
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)         # reads (s (align N)); advances past (s …)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      sym.typ = baseTyp
      sym.reg = reg
      # Track the register binding so a raw `(xN)` use is rejected; reject reusing a
      # register that still hosts a live variable (kill it first).
      let targetReg = tagToRegisterA64(reg, n)
      if targetReg in ctx.a64RegBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.a64RegBindings[targetReg] & "', kill it first before reusing", n)
      ctx.a64RegBindings[targetReg] = name
      # A fresh binding abandons a prior call's clobber — the same rule
      # `bindRegA64` applies to `rebind`. A `(var …)` starts a NEW variable's life
      # in the register, so whatever an earlier call destroyed there is not this
      # variable's value. Without this a local declared after a call, in a
      # caller-saved register, was rejected on its first read.
      ctx.clobberedA64.excl(targetReg)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handle via `case instTag`"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, LenientD,
     ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD, SyprocD, RegsD,
     InterruptsD, IrqD, LayoutD, FlashD, SramD, StacksD, HeapD,
     NoinitD, CoreD:
    raiseAssert("Unhandled declaration tag: " & $declTag)

  # See the same step in `genInstX64`: an overflowing mnemonic's id is a leading
  # child, so skip it once here and every arm's own `inc n` still lands on the
  # first operand.
  if isEscapedTag(n): inc n

  case instTag
  of StmtsA64:
    loopInto n:
      genInstA64(n, ctx)
  of ScopeA64:
    # See `ScopeX64`: reclaimable stack-slot arena for a call's caller-save spills.
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstA64(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of PrepareA64:
    genPrepareA64(n, ctx)
  of CallA64:
    genCallMarkerA64(n, ctx)
  of TailcallA64:
    genTailcallMarkerA64(n, ctx)
  of PopframeA64:
    inc n
    genPopframeA64(ctx)
  of ExtcallA64:
    genExtcallA64(n, ctx)
  of IteA64:
    genIteA64(n, ctx)
  of LoopA64:
    genLoopA64(n, ctx)
  of JtrueA64:
    genJtrueA64(n, ctx)
  of KillA64:
    genKillA64(n, ctx)
  of RebindA64:
    genRebindA64(n, ctx)
  of WithregA64:
    genWithregA64(n, ctx)
  of LabA64:
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

  of MovA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    # Type-check the move against THE shared rule (`movTypeOk`), the same one
    # `genMovX64` applies: a named local carries its declared type, so a narrowing
    # `(mov i8local i64val)` is rejected while a widening one, a sized mem↔reg pair
    # and an ABI-truncating `(arg …)` store are accepted. Both arches must answer
    # identically — arkham emits one program and picks a target afterwards.
    if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
      typeError(dest.typ, op.typ, start)
    checkPtrStore(dest.typ, op.kind, op.typ, start)
    if dest.kind == okMem:
      if op.kind == okImm:
        error("Moving immediate to memory not fully supported yet for ARM64", n)
      elif op.kind == okSsize:
        error("Moving ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot move memory to memory", n)
      elif dest.mem.hasIndex:
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        let m = a64IntMemBase(ctx, dest.mem, size)
        if not m.hasIndex:
          arm64.emitLoadStoreUImm(ctx.buf.data, op.reg, m.base, m.offset, size, opc)
        else:
          var base = m.base
          if m.offset != 0:
            emitAddOffsetA64(ctx, arm64.X16, base, m.offset, arm64.X16)
            base = arm64.X16
          arm64.emitLoadStoreReg(ctx.buf.data, op.reg, base, m.index, size, opc, m.shift)
      else:
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        arm64.emitLoadStoreUImm(ctx.buf.data, op.reg, dest.mem.base, dest.mem.offset, size, opc)
    else:
      if op.kind == okSsize:
        arm64.emitMovImm(ctx.buf.data, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitMovImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          # MOVZ + MOVK loads the full 64-bit pattern, including negatives and
          # the raw bit patterns of floating-point constants.
          arm64.emitMovImm64(ctx.buf.data, dest.reg, cast[uint64](op.immVal))
      elif op.kind == okMem and op.mem.hasIndex:
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        let m = a64IntMemBase(ctx, op.mem, size)
        if not m.hasIndex:
          arm64.emitLoadStoreUImm(ctx.buf.data, dest.reg, m.base, m.offset, size, opc)
        else:
          var base = m.base
          if m.offset != 0:
            emitAddOffsetA64(ctx, arm64.X16, base, m.offset, arm64.X16)
            base = arm64.X16
          arm64.emitLoadStoreReg(ctx.buf.data, dest.reg, base, m.index, size, opc, m.shift)
      elif op.kind == okMem:
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        arm64.emitLoadStoreUImm(ctx.buf.data, dest.reg, op.mem.base, op.mem.offset, size, opc)
      elif dest.reg == op.reg:
        # 64-bit register self-move is a no-op; elide it. This makes a result
        # self-binding such as `(mov (x0) (res ret.0))` cost nothing, so callers
        # can declaratively bind results to their natural register for free.
        discard
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, op.reg)

  of LeaA64:
    # (lea reg <mem>): load the *address* of a stack var / field into `reg`
    # (`add reg, base, #offset`), rather than the value at it.
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("lea destination must be a register", n)
    if op.kind != okMem: error("lea source must be a memory operand", n)
    if op.mem.hasIndex:
      # `add dest, base, index, lsl #shift` (+ displacement) — an indexed address
      # (e.g. `(at base regIdx)`) folds its index into the computed pointer. A SP base
      # (a stack array) needs the EXTENDED-register ADD (the shifted form reads reg 31
      # as XZR, not SP); a normal base uses the shifted form (which allows shift 0..63).
      if op.mem.base == arm64.SP:
        arm64.emitAddExtended(ctx.buf.data, dest.reg, op.mem.base, op.mem.index, uint8(op.mem.shift))
      else:
        arm64.emitAddShifted(ctx.buf.data, dest.reg, op.mem.base, op.mem.index, uint8(op.mem.shift))
      if op.mem.offset != 0:
        emitAddOffsetA64(ctx, dest.reg, dest.reg, op.mem.offset, arm64.X17)
    else:
      emitAddOffsetA64(ctx, dest.reg, op.mem.base, op.mem.offset, arm64.X17)

  of AdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("ADR destination must be register", n)
    if op.tlvSym != nil:
      # Thread-local variable (macOS/arm64): obtain its address through the TLV
      # descriptor thunk. The descriptor lives in __DATA/__thread_vars; its first
      # word is a function pointer that, called with the descriptor address in
      # x0, returns the variable's address in x0 (preserving all other regs).
      #   adrp x0, desc@PAGE ; add x0, x0, desc@PAGEOFF   (patched in writeMachO)
      #   ldr  x16, [x0]                                   ; load the thunk
      #   blr  x16                                         ; x0 = &var
      #
      # x0 and x16 are the sequence's OWN scratch, not the caller's to lose. Every
      # other instruction here writes its destination and nothing else, and a code
      # generator that staged `f(a, tvar)` — arg 0 already parked in x0 — would
      # otherwise watch that argument vanish with no instruction to blame. Spill
      # both around the thunk so `(adr D tvar)` writes D alone. (`blr` still sets
      # lr, which is why a proc touching a thread-local is analysed as having a
      # call and keeps a frame.)
      arm64.emitSubImm(ctx.buf.data, arm64.SP, arm64.SP, 16'u16)
      arm64.emitStr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
      arm64.emitStr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X0)     # x0 = &descriptor
      ctx.tlvSites.add (pos, op.tlvSym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X0, 0'i32)
      arm64.emitBlr(ctx.buf.data, arm64.X16)
      # Land the result in `dest` and restore the two scratch registers — skipping
      # whichever one `dest` IS, since that one now holds the address.
      if dest.reg == arm64.X0:
        arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      elif dest.reg == arm64.X16:
        arm64.emitMov(ctx.buf.data, arm64.X16, arm64.X0)
        arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, arm64.X0)
        arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
        arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      arm64.emitAddImm(ctx.buf.data, arm64.SP, arm64.SP, 16'u16)
    elif op.gvarSym != nil:
      # Global in __DATA/.bss: form its address with adrp+add (PC-relative adr
      # can't reach __DATA). Emit placeholders; writeMachO patches the page /
      # page-offset once the __DATA layout is known.
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, dest.reg)
      ctx.gvarSites.add (pos, op.gvarSym)
    else:
      # Check if operand is a label: type should be UIntT and not immediate/memory
      if op.typ.kind != UIntT or op.kind == okImm or op.kind == okMem:
        error("ADR source must be a label", n)
      # Long form (`adr`+`add`): a rodata blob can sit anywhere in a multi-megabyte
      # `.text`, well past plain ADR's ±1 MB.
      arm64.emitAdrLong(ctx.buf, dest.reg, op.label)

  of GloadA64, GstoreA64:
    # `(gload D S)` / `(gstore D S)` — scalar load/store of a __DATA/.bss global `S`
    # with the page OFFSET folded into the ldr/str immediate instead of a separate
    # `add`: `adrp x17, S@PAGE ; ldr/str D, [x17, S@PAGEOFF]`. The page-offset patch
    # rides on the SAME gvar site (recorded at the adrp) — writeMachO/writeElf detect
    # the folded ldr/str at pos+4 by its opcode and patch the scaled imm12 there.
    let isLoad = instTag == GloadA64
    inc n
    let dreg = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dreg.kind != okReg: error((if isLoad: "gload" else: "gstore") & " needs a register", n)
    if op.gvarSym == nil: error((if isLoad: "gload" else: "gstore") & " source must be a global", n)
    # Size the access from the global's own scalar type (byte/half/word/dword).
    let (size, opc) = memWidthOpc(op.gvarSym.typ, isLoad)
    let pos = ctx.buf.data.getCurrentPosition()
    arm64.emitAdrpGvarPage(ctx.buf.data, arm64.X17)          # adrp x17, S@PAGE (page patched)
    ctx.gvarSites.add (pos, op.gvarSym)                      # pos+4 (the ldr/str) gets S@PAGEOFF
    arm64.emitLoadStoreUImm(ctx.buf.data, dreg.reg, arm64.X17, 0'i32, size, opc)

  of AddA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkArithCompatible(dest.typ, op.typ, "add", start)  # sized ints of any width (64-bit reg)
    if dest.kind == okMem:
      error("ADD to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        # A PAIR: `add sp, sp, #lo12` + `add sp, sp, #hi12, lsl #12`. The frame size is
        # only known at patch time and ADD's immediate is 12 bits, so a single
        # instruction silently truncated any frame over 4095 bytes (a 10KB frame came
        # out as `sub sp, sp, #2000`, leaving every local access off the end of the
        # stack — an ASLR-dependent crash). The patcher fills each half; see `finalize`.
        arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        arm64.emitAddImmShifted12(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          # ADD's immediate field is 12 bits; a larger (or negative) constant is
          # synthesized through the reserved assembler scratch X17. (The former
          # `<= 0xFFFF` gate silently mis-encoded 4096..65535: the immediate
          # overflowed into the shift/opcode bits.)
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("ADD from memory not supported yet", n)
      else:
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SubA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkArithCompatible(dest.typ, op.typ, "sub", start)  # sized ints of any width (64-bit reg)
    if dest.kind == okMem:
      error("SUB to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)   # lo12 (see AddA64)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        arm64.emitSubImmShifted12(ctx.buf.data, dest.reg, dest.reg, 0'u16)  # hi12
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        if ctx.inPrologue and dest.reg == arm64.SP:
          # Both halves of the pair are one CFA event; record it after the second
          # so the FDE's `advance_loc` covers them together.
          ctx.cfiStep(0, [], ssizeSlot = true)        # delta filled in at proc end
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          # SUB's immediate field is 12 bits — synthesize larger/negative constants
          # through X17 (see the ADD case above for the mis-encode this closes).
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("SUB from memory not supported yet", n)
      else:
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of MulA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "mul", start)
    checkIntegerType(op.typ, "mul", start)
    if dest.kind == okMem: error("MUL destination cannot be memory", n)
    if op.kind == okImm: error("MUL immediate not supported", n)
    if op.kind == okMem: error("MUL memory not supported yet", n)
    arm64.emitMul(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SmulhA64, UmulhA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    let mn = if instTag == SmulhA64: "smulh" else: "umulh"
    checkIntegerType(dest.typ, mn, start)
    checkIntegerType(op.typ, mn, start)
    if dest.kind == okMem: error(mn & " destination cannot be memory", n)
    if op.kind == okImm: error(mn & " immediate not supported", n)
    if op.kind == okMem: error(mn & " memory not supported yet", n)
    if instTag == SmulhA64:
      arm64.emitSmulh(ctx.buf.data, dest.reg, dest.reg, op.reg)
    else:
      arm64.emitUmulh(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "sdiv", start)
    checkIntegerType(op.typ, "sdiv", start)
    if dest.kind == okMem: error("SDIV destination cannot be memory", n)
    if op.kind == okImm: error("SDIV immediate not supported", n)
    if op.kind == okMem: error("SDIV memory not supported yet", n)
    arm64.emitSdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of UdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "udiv", start)
    checkIntegerType(op.typ, "udiv", start)
    if dest.kind == okMem: error("UDIV destination cannot be memory", n)
    if op.kind == okImm: error("UDIV immediate not supported", n)
    if op.kind == okMem: error("UDIV memory not supported yet", n)
    arm64.emitUdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of AndA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkBitwiseCompatible(dest.typ, op.typ, "and", start)
    if dest.kind == okMem: error("AND to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitAndImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitAnd(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("AND from memory not supported yet", n)
      else:
        arm64.emitAnd(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of OrrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "orr", start)
    checkBitwiseType(op.typ, "orr", start)
    checkBitwiseCompatible(dest.typ, op.typ, "orr", start)
    if dest.kind == okMem: error("ORR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitOrrImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitOrr(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("ORR from memory not supported yet", n)
      else:
        arm64.emitOrr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of EorA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "eor", start)
    checkBitwiseType(op.typ, "eor", start)
    checkBitwiseCompatible(dest.typ, op.typ, "eor", start)
    if dest.kind == okMem: error("EOR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitEorImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitEor(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("EOR from memory not supported yet", n)
      else:
        arm64.emitEor(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of LslA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLslImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsl(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of LsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of AsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "asr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitAsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitAsr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of Add3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "add3")
    checkIntegerArithmetic(dstT, "add", start)
    checkIntegerArithmetic(rm.typ, "add", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAdd(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind == okMem: error("add3 from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, rd, rn, rm.reg)

  of Sub3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "sub3")
    checkIntegerArithmetic(dstT, "sub", start)
    checkIntegerArithmetic(rm.typ, "sub", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, rd, rn, uint16(rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitSub(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind == okMem: error("sub3 from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, rd, rn, rm.reg)

  of Mul3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "mul3")
    checkIntegerType(dstT, "mul", start)
    checkIntegerType(rm.typ, "mul", start)
    if rm.kind != okReg: error("mul3 second source must be a register", n)
    arm64.emitMul(ctx.buf.data, rd, rn, rm.reg)

  of And3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "and3")
    checkBitwiseType(dstT, "and", start)
    checkBitwiseType(rm.typ, "and", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitAndImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAnd(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("and3 second source must be a register or immediate", n)
    else: arm64.emitAnd(ctx.buf.data, rd, rn, rm.reg)

  of Orr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "orr3")
    checkBitwiseType(dstT, "orr", start)
    checkBitwiseType(rm.typ, "orr", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitOrrImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitOrr(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("orr3 second source must be a register or immediate", n)
    else: arm64.emitOrr(ctx.buf.data, rd, rn, rm.reg)

  of Eor3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "eor3")
    checkBitwiseType(dstT, "eor", start)
    checkBitwiseType(rm.typ, "eor", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitEorImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitEor(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("eor3 second source must be a register or immediate", n)
    else: arm64.emitEor(ctx.buf.data, rd, rn, rm.reg)

  of Lsl3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "lsl3")
    checkBitwiseType(dstT, "lsl", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitLslImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitLsl(ctx.buf.data, rd, rn, rm.reg)

  of Lsr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "lsr3")
    checkBitwiseType(dstT, "lsr", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitLsrImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitLsr(ctx.buf.data, rd, rn, rm.reg)

  of Asr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "asr3")
    checkBitwiseType(dstT, "asr", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitAsrImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitAsr(ctx.buf.data, rd, rn, rm.reg)

  of AddwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "addw", start)
    checkIntegerArithmetic(op.typ, "addw", start)
    if dest.kind == okMem: error("ADDW to memory not supported", n)
    elif op.kind == okImm or op.kind == okCsize:
      if op.immVal >= 0 and op.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, arm64.X17, w = true)
    elif op.kind == okMem: error("ADDW from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of SubwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "subw", start)
    checkIntegerArithmetic(op.typ, "subw", start)
    if dest.kind == okMem: error("SUBW to memory not supported", n)
    elif op.kind == okImm or op.kind == okCsize:
      if op.immVal >= 0 and op.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, arm64.X17, w = true)
    elif op.kind == okMem: error("SUBW from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of MulwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "mulw", start)
    checkIntegerType(op.typ, "mulw", start)
    if dest.kind == okMem: error("MULW destination cannot be memory", n)
    if op.kind == okImm: error("MULW immediate not supported", n)
    if op.kind == okMem: error("MULW memory not supported", n)
    arm64.emitMul(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of Addw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "addw3")
    checkIntegerArithmetic(dstT, "addw", start)
    checkIntegerArithmetic(rm.typ, "addw", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(rm.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAdd(ctx.buf.data, rd, rn, arm64.X17, w = true)
    elif rm.kind == okMem: error("addw3 from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, rd, rn, rm.reg, w = true)

  of Subw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "subw3")
    checkIntegerArithmetic(dstT, "subw", start)
    checkIntegerArithmetic(rm.typ, "subw", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, rd, rn, uint16(rm.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitSub(ctx.buf.data, rd, rn, arm64.X17, w = true)
    elif rm.kind == okMem: error("subw3 from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, rd, rn, rm.reg, w = true)

  of Mulw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "mulw3")
    checkIntegerType(dstT, "mulw", start)
    checkIntegerType(rm.typ, "mulw", start)
    if rm.kind != okReg: error("mulw3 second source must be a register", n)
    arm64.emitMul(ctx.buf.data, rd, rn, rm.reg, w = true)

  of NegA64:
    inc n
    let op = parseDestA64(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    arm64.emitNeg(ctx.buf.data, op.reg, op.reg)

  # Bit-counting / bit- and byte-reversal: `(clz D S N)`, `(rbit D S N)`,
  # `(rev D S N)`. All are three-address (D is a pure destination), so unlike
  # x86's `bswap` they need no copy into the destination first. `N` (32 or 64) is
  # the operand size, given EXPLICITLY: a 32-bit `clz` counts from bit 31, and the
  # declared type of a bit-count destination says nothing about that width.
  of ClzA64, RbitA64, RevA64:
    let mnemonic = $instTag
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, mnemonic, start)
    checkBitwiseType(op.typ, mnemonic, start)
    if dest.kind != okReg: error(mnemonic & " destination must be a register", n)
    if op.kind != okReg: error(mnemonic & " source must be a register", n)
    if n.kind != IntLit: error(mnemonic & " requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error(mnemonic & " width must be 32 or 64", n)
    let w = bits == 32
    case instTag
    of ClzA64:  arm64.emitClz(ctx.buf.data, dest.reg, op.reg, w)
    of RbitA64: arm64.emitRbit(ctx.buf.data, dest.reg, op.reg, w)
    else:       arm64.emitRev(ctx.buf.data, dest.reg, op.reg, w)

  of CmpA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    # Comparisons work on integers, pointers, bool (the "if bool" test) and `nil` —
    # the same loose rule as x64's CmpX64 (was the stricter integer-arithmetic check).
    checkComparable(dest.typ, "cmp", start)
    checkComparable(op.typ, "cmp", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okMem:
      error("CMP memory not supported yet", n)
    else:
      if op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitCmpImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          # CMP's immediate field is 12 bits — synthesize larger/negative constants
          # through the reserved scratch X17. (The former `<= 0xFFFF` gate silently
          # MIS-ENCODED 4096..65535: the immediate overflowed into the opcode bits.)
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitCmp(ctx.buf.data, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("CMP memory not supported yet", n)
      else:
        arm64.emitCmp(ctx.buf.data, dest.reg, op.reg)

  of CseleqA64, CselneA64, CselltA64, CselleA64, CselgtA64, CselgeA64,
     CselloA64, CsellsA64, CselhiA64, CselhsA64:
    # (csel<cc> D S1 S2): D = S1 if <cc> else S2, reading the NZCV flags of the
    # preceding `cmp` — the flag-consuming select that turns a min/max/abs branch
    # diamond into straight-line code. Register-only: CSEL has no immediate or
    # memory form, so constants must be materialized into a register first.
    inc n
    let dest = parseDestA64(n, ctx)
    let s1 = parseOperandA64(n, ctx)
    let s2 = parseOperandA64(n, ctx)
    if dest.kind != okReg: error("CSEL destination must be a register", n)
    for src in [s1, s2]:
      if src.kind != okReg: error("CSEL sources must be registers", n)
      # Both sources must fit the destination's type: the `mov` rule, applied twice.
      if dest.typ != nil and src.typ != nil and not movCompatible(dest.typ, src.typ):
        typeError(dest.typ, src.typ, start)
    arm64.emitCsel(ctx.buf.data, dest.reg, s1.reg, s2.reg, a64CondOf(instTag))

  of CseteqA64, CsetneA64, CsetltA64, CsetleA64, CsetgtA64, CsetgeA64,
     CsetloA64, CsetlsA64, CsethiA64, CsethsA64:
    # (cset<cc> D): D = 1 if <cc> else 0 — materializes the NZCV flags of the
    # preceding `cmp` as a bool value (alias of CSINC D, XZR, XZR, inv(<cc>)).
    inc n
    let dest = parseDestA64(n, ctx)
    if dest.kind != okReg: error("CSET destination must be a register", n)
    if dest.typ != nil and dest.typ.kind notin {IntT, UIntT, BoolT, IntLitT}:
      error("CSET requires an integer or bool destination", n)
    arm64.emitCset(ctx.buf.data, dest.reg, a64CondOf(instTag))

  of RetA64:
    inc n
    arm64.emitRet(ctx.buf.data)

  of NopA64:
    inc n
    arm64.emitNop(ctx.buf.data)

  of SvcA64:
    if ctx.inCall and ctx.callContext.isSyscall:
      # Consumes the whole node (`intoOperands`), so it wants the head back
      # rather than the escaped-id step-over `genInstA64` already did.
      n = start
      genSyscallMarkerA64(n, ctx)   # `(svc)` as the prepare invocation marker
    else:
      inc n
      let op = parseOperandA64(n, ctx)
      if op.kind != okImm:
        error("SVC requires immediate operand", n)
      if op.immVal < 0 or op.immVal > 0xFFFF:
        error("SVC immediate must be 0-65535", n)
      arm64.emitSvc(ctx.buf.data, uint16(op.immVal))  # a raw `svc` (e.g. entry exit)

  of LdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("LDR destination must be register", n)
    if op.kind == okMem:
      ctx.buf.data.emitLdr(dest.reg, op.mem.base, op.mem.offset)
    else:
      error("LDR source must be memory", n)

  of StrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("STR destination must be memory", n)
    if op.kind == okMem: error("STR source cannot be memory", n)
    ctx.buf.data.emitStr(op.reg, dest.mem.base, dest.mem.offset)

  of LdaxrA64:
    # (ldaxr Dt Sptr bits?) — Dt ← exclusive-acquire load of [Sptr]. Operands may be
    # `rebind`-bound scratch names (the atomics lowering binds its temps). The optional
    # trailing int is the access width in bits (default 64); arkham emits it so a
    # sub-64-bit atomic uses the matching `ldaxr{b,h}`/`Wt` form (see sizeFieldA64).
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitLdaxr(ctx.buf.data, rt, rn, bits)

  of StlxrA64:
    # (stlxr St Dval Sptr bits?) — store-release-exclusive Dval to [Sptr]; St ← status.
    inc n
    let rs = parseGprA64(n, ctx)
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitStlxr(ctx.buf.data, rs, rt, rn, bits)

  of LdarA64:
    # (ldar Dt Sptr bits?) — Dt ← acquire load of [Sptr].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitLdar(ctx.buf.data, rt, rn, bits)

  of StlrA64:
    # (stlr Dval Sptr bits?) — release store Dval to [Sptr].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitStlr(ctx.buf.data, rt, rn, bits)

  of LdrbA64:
    # (ldrb Dt Bbase Iindex) — Dt ← zero-extended byte [Bbase + Iindex].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let rm = parseGprA64(n, ctx)
    arm64.emitLdrbReg(ctx.buf.data, rt, rn, rm)

  of StrbA64:
    # (strb Dval Bbase Iindex) — store low byte of Dval to [Bbase + Iindex].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let rm = parseGprA64(n, ctx)
    arm64.emitStrbReg(ctx.buf.data, rt, rn, rm)

  of DmbA64:
    inc n
    arm64.emitDmbIsh(ctx.buf.data)

  of ClrexA64:
    inc n
    arm64.emitClrex(ctx.buf.data)

  of YieldA64:
    inc n
    arm64.emitYield(ctx.buf.data)

  of VgreqA64:
    # (vgreq D S) — D = valgrind's answer to the request block at S.
    #
    # Nothing here is checked against valgrind's protocol because nothing here can
    # get it wrong: the register assignment is fixed inside the encoder, not read
    # off these operands. What IS checked is the only thing the caller chooses — two
    # registers of a plausible type — since the encoder writes through both.
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkExchangeType(dest.typ, "vgreq", start)
    checkExchangeType(op.typ, "vgreq", start)
    if dest.kind != okReg: error("vgreq destination must be a register", n)
    if op.kind != okReg: error("vgreq request-block operand must be a register", n)
    arm64.emitVgClientRequest(ctx.buf.data, dest.reg, op.reg)

  of FmovA64:
    # (fmov D S): D=fp,S=fp → reg copy; D=fp,S=gpr / D=gpr,S=fp → bit move.
    # The size (s/d) comes from whichever operand is an fp register.
    #
    # The GPR side goes through `parseGprA64`, not `parseRegisterA64`: it is a
    # VALUE, so a register bound to a local or a scratch temp arrives as its
    # name — the same spelling the Thumb-2 handler has always accepted, and the
    # one that lets a raw use of a bound register stay an error. Same for the
    # `scvtf`/`ucvtf`/`fcvtzs`/`fcvtzu` GPR operand below.
    inc n
    if isA64FpOperand(n, ctx):
      let single = isA64FpSingle(n, ctx)
      let rd = parseFloatOperandA64(n, ctx)
      if isA64FpOperand(n, ctx):
        arm64.emitFmov(ctx.buf.data, rd, parseFloatOperandA64(n, ctx), single)
      else:
        arm64.emitFmovFromGpr(ctx.buf.data, rd, parseGprA64(n, ctx), single)
    else:
      let rd = parseGprA64(n, ctx)
      let single = isA64FpSingle(n, ctx)
      arm64.emitFmovToGpr(ctx.buf.data, rd, parseFloatOperandA64(n, ctx), single)

  of FaddA64, FsubA64, FmulA64, FdivA64:
    # (fop D S) → D = D op S  (emitted as `fop Dd, Dd, Ds`).
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rs = parseFloatOperandA64(n, ctx)
    case instTag
    of FaddA64: arm64.emitFadd(ctx.buf.data, rd, rd, rs, single)
    of FsubA64: arm64.emitFsub(ctx.buf.data, rd, rd, rs, single)
    of FmulA64: arm64.emitFmul(ctx.buf.data, rd, rd, rs, single)
    else:       arm64.emitFdiv(ctx.buf.data, rd, rd, rs, single)

  of FnegA64:
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    arm64.emitFneg(ctx.buf.data, rd, rd, single)

  of FcmpA64:
    inc n
    let single = isA64FpSingle(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    let rm = parseFloatOperandA64(n, ctx)
    arm64.emitFcmp(ctx.buf.data, rn, rm, single)

  of FldrA64:
    # (fldr D <mem>) — load a double/single.
    inc n
    let single = isA64FpSingle(n, ctx)
    let rt = parseFloatOperandA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem: error("FLDR source must be memory", n)
    let (base, off) = a64FpMemBase(ctx, op.mem, single)
    arm64.emitFldr(ctx.buf.data, rt, base, off, single)

  of FstrA64:
    # (fstr <mem> D) — store a double/single.
    inc n
    let dest = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("FSTR destination must be memory", n)
    let single = isA64FpSingle(n, ctx)
    let rt = parseFloatOperandA64(n, ctx)
    let (base, off) = a64FpMemBase(ctx, dest.mem, single)
    arm64.emitFstr(ctx.buf.data, rt, base, off, single)

  of ScvtfA64, UcvtfA64:
    # (scvtf Dfp Sgpr) — int → double/single.
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    if instTag == ScvtfA64: arm64.emitScvtf(ctx.buf.data, rd, rn, single)
    else:                   arm64.emitUcvtf(ctx.buf.data, rd, rn, single)

  of FcvtzsA64, FcvtzuA64:
    # (fcvtzs Dgpr Sfp) — double/single → int (toward zero).
    inc n
    let rd = parseGprA64(n, ctx)
    let single = isA64FpSingle(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if instTag == FcvtzsA64: arm64.emitFcvtzs(ctx.buf.data, rd, rn, single)
    else:                    arm64.emitFcvtzu(ctx.buf.data, rd, rn, single)

  of FcvtA64:
    # (fcvt Ddst Ssrc) — precision convert; direction from the operand sizes.
    inc n
    let dstSingle = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if dstSingle: arm64.emitFcvtToSingle(ctx.buf.data, rd, rn)  # double → single
    else:         arm64.emitFcvtToDouble(ctx.buf.data, rd, rn)  # single → double

  of FldrqA64:
    # (fldrq D <mem>) — 128-bit q load; D names the v register by its d/s tag.
    inc n
    let rt = parseFloatOperandA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem: error("FLDRQ source must be memory", n)
    arm64.emitLdrQ(ctx.buf.data, rt, op.mem.base, op.mem.offset)

  of FstrqA64:
    # (fstrq <mem> D) — 128-bit q store, operand order as `fstr`.
    inc n
    let dest = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("FSTRQ destination must be memory", n)
    let rt = parseFloatOperandA64(n, ctx)
    arm64.emitStrQ(ctx.buf.data, rt, dest.mem.base, dest.mem.offset)

  of VfaddA64, VfsubA64, VfmulA64, VfmlaA64:
    # (vop D A B bits?) — lane-wise vector fp; `.2d` when d-spelled, `.4s` when
    # s-spelled. The optional trailing lane-bits literal (32/64) overrides the
    # spelling-derived arrangement: a 128-bit VALUE binding (`(f 128)`, arkham's
    # vector locals) names the register without naming a lane width, so the
    # instruction carries it explicitly — the same shape as `(clz D S N)`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let ra = parseFloatOperandA64(n, ctx)
    let rb = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    case instTag
    of VfaddA64: arm64.emitVFadd(ctx.buf.data, rd, ra, rb, single)
    of VfsubA64: arm64.emitVFsub(ctx.buf.data, rd, ra, rb, single)
    of VfmulA64: arm64.emitVFmul(ctx.buf.data, rd, ra, rb, single)
    else:        arm64.emitVFmla(ctx.buf.data, rd, ra, rb, single)

  of VdupA64:
    # (vdup D S bits?) — broadcast S's lane 0 to every lane of D; trailing
    # lane-bits literal as in `vfadd`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    arm64.emitVDup(ctx.buf.data, rd, rn, single)

  of VaddvA64:
    # (vaddv D S bits?) — horizontal fp add of S's lanes into the scalar D;
    # trailing lane-bits literal as in `vfadd`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    arm64.emitVAddv(ctx.buf.data, rd, rn, single)

  of VeorA64:
    # (veor D A B) — 16-byte xor; `(veor X X X)` zeroes X.
    inc n
    let rd = parseFloatOperandA64(n, ctx)
    let ra = parseFloatOperandA64(n, ctx)
    let rb = parseFloatOperandA64(n, ctx)
    arm64.emitVEor(ctx.buf.data, rd, ra, rb)

  of BA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitB(ctx.buf, op.label)
  of BlA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBL(ctx.buf, op.label)

  of CbzA64, CbnzA64:
    # (cbz S L) / (cbnz S L) — branch on S being zero / non-zero. Unlike every
    # `b.cc` above these read no flags, so they stand in for a whole `cmp S, #0`
    # plus conditional branch. Register-only by encoding (no immediate, no memory);
    # the value is compared as a full 64-bit register, which is what arkham's
    # sign-/zero-extension invariant makes correct for a narrower type too.
    let isZero = instTag == CbzA64
    inc n
    let src = parseOperandA64(n, ctx)
    if src.kind != okReg: error("CBZ/CBNZ source must be a register", n)
    checkComparable(src.typ, (if isZero: "cbz" else: "cbnz"), start)
    let lab = parseOperandA64(n, ctx)
    if lab.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, lab.label, n)
    if isZero: arm64.emitCbz(ctx.buf, src.reg, lab.label)
    else: arm64.emitCbnz(ctx.buf, src.reg, lab.label)

  of BeqA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBeq(ctx.buf, op.label)

  of BneA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBne(ctx.buf, op.label)

  of BltA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBlt(ctx.buf, op.label)

  of BleA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBle(ctx.buf, op.label)

  of BgtA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBgt(ctx.buf, op.label)

  of BgeA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBge(ctx.buf, op.label)

  of BloA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBlo(ctx.buf, op.label)

  of BlsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBls(ctx.buf, op.label)

  of BhiA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBhi(ctx.buf, op.label)

  of BhsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBhs(ctx.buf, op.label)

  of StpA64:
    # (stp (rt1) (rt2) (rn) offset) → STP rt1, rt2, [rn, #offset]!  (pre-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("stp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitStp(ctx.buf.data, rt1, rt2, rn, off)
    if ctx.inPrologue and rn == arm64.SP and off < 0:
      # `stp rt1, rt2, [sp, #-N]!` — the AArch64 prologue's pair push. rt1 lands
      # at the new bottom of the frame, rt2 8 bytes above it.
      ctx.cfiStep(-off, [int32(ord(rt1)), int32(ord(rt2))])

  of LdpA64:
    # (ldp (rt1) (rt2) (rn) offset) → LDP rt1, rt2, [rn], #offset  (post-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("ldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitLdp(ctx.buf.data, rt1, rt2, rn, off)

  of FstpA64:
    # (fstp (dt1) (dt2) (rn) offset) → STP Dt1, Dt2, [Xn, #offset]!  (pre-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fstp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFstpPre(ctx.buf.data, rt1, rt2, rn, off)
    if ctx.inPrologue and rn == arm64.SP and off < 0:
      ctx.cfiStep(-off, [int32(ord(rt1)), int32(ord(rt2))], floats = true)  # see `StpA64`

  of FldpA64:
    # (fldp (dt1) (dt2) (rn) offset) → LDP Dt1, Dt2, [Xn], #offset  (post-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFldpPost(ctx.buf.data, rt1, rt2, rn, off)

  of NoA64Inst:
    error("Invalid ARM64 instruction", start)

proc genInstNodeA64*(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstA64(n, ctx)

proc genStmtA64*(n: var Cursor; ctx: var GenContext) =
  if atTag(n, StmtsTagId):
    loopInto n:
      genInstNodeA64(n, ctx)
  else:
    genInstNodeA64(n, ctx)
