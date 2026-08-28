#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## x86-64 instruction selection: one asm-NIF node in, encoded bytes out.
##
## Serves both `x64` (Linux/ELF) and `win_x64` (PE). They share every encoding;
## what differs is the calling convention — the shadow space a Win64 caller
## reserves, and the import-address-table indirection an `extcall` goes
## through — and that is guarded by `ctx.arch` rather than duplicated.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    listing, emit, tags, model, tagconv, decls,
                    tagpool, stackslots, relocs, buffers]
import encoder as x86
import regs, operands

proc genStmtX64(n: var Cursor; ctx: var GenContext)
proc genInstX64(n: var Cursor; ctx: var GenContext)

type
  SizedAluKind* = enum
    saAdd, saSub, saAnd, saOr, saXor, saCmp, saTest

const
  # MR-form opcode pairs (8-bit / 16-32-bit) and the /digit of the imm form,
  # indexed by SizedAluKind. TEST's imm form is special-cased (0xF6/0xF7 /0).
  sizedAluOpcMR8: array[SizedAluKind, byte] = [0x00'u8, 0x28, 0x20, 0x08, 0x30, 0x38, 0x84]
  sizedAluOpcMR:  array[SizedAluKind, byte] = [0x01'u8, 0x29, 0x21, 0x09, 0x31, 0x39, 0x85]
  sizedAluOpcRM8: array[SizedAluKind, byte] = [0x02'u8, 0x2A, 0x22, 0x0A, 0x32, 0x3A, 0x84]
  sizedAluOpcRM:  array[SizedAluKind, byte] = [0x03'u8, 0x2B, 0x23, 0x0B, 0x33, 0x3B, 0x85]
  sizedAluDigit:  array[SizedAluKind, int]  = [0, 5, 4, 1, 6, 7, 0]

proc genPopframeX64(ctx: var GenContext) =
  ## `(popframe)` — the x86-64 twin of `genPopframeA64`, and for the same reason:
  ## arkham finalizes `usedCallee` / `hasStackVars` only AFTER the body is emitted,
  ## so a teardown written at a mid-body site would have to guess how many `pop`s
  ## and whether a frame `sub` exists at all. Here nothing is guessed — the
  ## prologue is already assembled and `ctx.unwind[^1].steps` records each of its
  ## instructions in order. Replaying that in reverse is `framePop` by construction:
  ## the frame `add` (the `sub`'s twin, same forced imm32, same patch list, since
  ## the size is unknown until the slots are laid out), then each `pop` in reverse
  ## push order.
  ##
  ## Afterwards rsp points at the return address exactly as it did at entry, which
  ## is what makes the `jmp` a tail call: the callee is entered in a normal callee's
  ## state and its `ret` returns to OUR caller.
  if ctx.unwind.len == 0: return
  let steps = ctx.unwind[^1].steps
  for i in countdown(steps.len - 1, 0):
    let st = steps[i]
    if st.ssizeSlot:
      x86.emitAddImm32(ctx.buf.data, x86.RSP, 0)     # forced imm32: back-patched
      ctx.ssizePatches.add((ctx.buf.data.len - 4, int(st.frameImm)))
    elif st.saves.len == 1:
      x86.emitPop(ctx.buf.data, x86.Register(st.saves[0].reg))
    elif st.saves.len == 0 and st.frameImm != 0:
      # The alignment-pad-only frame: `sub rsp, 8` with no `(s)` region.
      x86.emitAddImm(ctx.buf.data, x86.RSP, st.frameImm)

proc genPrepareX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  # A prepare block may NEST inside another: arkham emits that for an argument that is
  # itself a call — `f(g(x))`, which hexer leaves unflattened in a global's initializer
  # expression. The inner call is complete before the outer one's following `(arg …)`
  # bindings, so the enclosing context just has to survive it; save it and restore at
  # the end. The one shape that cannot work is an outer call with STACK arguments: both
  # calls write the single outgoing argument area the frame reserves, so the inner one
  # would overwrite what the outer already put there.
  let outerCall = ctx.callContext
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
    callEmitted: false,
    stackArgBase: (if ctx.arch == Arch.WinX64: WinShadowSpace else: 0)
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the extcall path.
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
  elif sym.kind == skSysProc:
    # A Linux syscall with a full proctype: arg/result checking and register
    # assignment proceed exactly as for a direct call (args land in the syscall
    # ABI registers the proctype names, e.g. arg4 → r10), but the invocation
    # marker is `(syscall)` — `genSyscallMarkerX64` inlines `mov rax,NR; syscall`
    # and applies the proctype's clobbers. No `call`/address is involved.
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
    ctx.callContext.isSyscall = true
    ctx.callContext.syscallNr = sym.offset
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    # A dynamic import: the invocation is an indirect `(extcall)` through the IAT/GOT
    # slot rather than a `call rel32`. If the decl carried a signature (the Windows
    # form — see `parseExtprocSig`) it is checked and laid out exactly like any other
    # call; a bare Darwin extern has no signature to check against, so its call site
    # marshals into raw ABI registers and only the marker is verified below.
    ctx.callContext.state = CallContextState.ExternalCall
    ctx.callContext.typ = sym.typ
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Whether the call is checked against a signature — every internal call, plus an
  # extern whose decl declared one.
  let typed = ctx.callContext.typ != nil

  # Compute stack argument size
  if typed:
    ctx.callContext.stackArgSize = ctx.callContext.stackArgBase +
                                   computeStackArgSize(ctx.callContext.typ)
    # Fixed-frame soundness (same as the A64 path): this call's outgoing stack args
    # occupy `[rsp, rsp+stackArgSize)`, the region `scanStackArgArea` reserved at the
    # frame bottom. If the pre-scan missed this target (an indirect call through a
    # not-yet-declared local fn-ptr), the reservation may be too small — fail loudly
    # rather than let the args overwrite a local `(s)` slot.
    if ctx.callContext.stackArgSize > ctx.reservedArgArea:
      error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
            " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
            " bytes); call target not visible to the frame pre-scan", hdr)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstX64(n, ctx)

  # Verify all bindings are done
  if typed:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & ctx.nameOf(param.name), hdr)

    if not ctx.callContext.isTailcall:
      # A tail call binds no result: the callee's return value IS this proc's, and
      # it is already in the return register when the callee's own `ret` runs.
      for res in ctx.callContext.typ.results:
        if res.name notin ctx.callContext.resultsSet:
          error("Missing result binding: " & ctx.nameOf(res.name), hdr)

  # Verify call was emitted
  if not ctx.callContext.callEmitted:
    if ctx.callContext.state == CallContextState.NormalCall:
      error("Missing (call), (tailcall) or (extcall) in prepare block", hdr)
    else:
      error("Missing (extcall) in prepare block", hdr)
  ctx.callContext = outerCall                  # resume the enclosing call, if any
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(call)` inside a `prepare` block emits the actual call: a direct `call rel32`
  ## to the prepared proc, or — when the prepare target is a function-pointer
  ## variable — an indirect call that loads the pointer and `call`s through it.
  if not ctx.inCall:
    if lenient():
      # Lenient bare call: `(call P)` with no `(prepare)` ceremony — the
      # ported body has already marshalled its arguments (arkham's ABI is
      # plain SysV, so gcc code's registers line up as-is).
      into n:
        if n.kind != Symbol: error("bare (call P) requires a proc symbol", n)
        let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
        if sym == nil:
          error("bare (call P): unknown proc: " & getSym(n), n)
        inc n
        if sym.kind == skProc:
          var labId: LabelId
          if sym.offset == -1:
            labId = ctx.buf.createLabel()
            sym.offset = int(labId)
          else:
            labId = LabelId(sym.offset)
          ctx.buf.emitCall(labId)
        elif sym.kind == skGvar:
          # A GLOBAL holding a function pointer: same lowering as the prepare
          # path — lea the global's address (patched by writeElf), load the
          # pointer, call through RAX (volatile at any call site).
          let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RAX)
          ctx.gvarSites.add (pos, sym)
          x86.emitMov(ctx.buf.data, x86.RAX,
                      x86.MemoryOperand(base: x86.RAX))
          x86.emitCallReg(ctx.buf.data, x86.RAX)
        else:
          error("bare (call P): not a proc or fn-pointer global: " & $sym.kind, n)
      return
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)

  # Clobber registers
  ctx.clobbered.incl(ctx.callContext.typ.clobbers)

  if ctx.callContext.indirect:
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # A function pointer held directly in a REGISTER (e.g. arkham's vtable-method load,
      # or a reg-resident `var f: proc`): the register holds the code address itself, so
      # `call reg` — no load. (The register is caller-saved/non-arg per the proctype's
      # clobber, so the prepared args in rdi…r9 are untouched.)
      x86.emitCallReg(ctx.buf.data, tagToRegister(sym.reg, n))
    else:
      # A function pointer stored in a GLOBAL: form its RIP-relative address (recorded as
      # a site, patched by writeElf like a `(lea reg gvar)`), load the pointer, call it.
      let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RAX)               # lea rax, [rip+fnptr]
      ctx.gvarSites.add (pos, sym)
      x86.emitMov(ctx.buf.data, x86.RAX, x86.MemoryOperand(base: x86.RAX)) # mov rax, [rax]
      x86.emitCallReg(ctx.buf.data, x86.RAX)                              # call rax
  else:
    var labId: LabelId
    if sym.offset == -1:
      labId = ctx.buf.createLabel()
      sym.offset = int(labId)
    else:
      labId = LabelId(sym.offset)
    ctx.buf.emitCall(labId)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(call` head

proc genTailcallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(tailcall)` — the `(call)` marker's no-return-address twin: same prepared
  ## arguments, same clobber declaration, `jmp rel32` instead of `call rel32`.
  ## Control leaves this proc for good, so the callee returns to OUR caller and its
  ## `ret` is ours.
  ##
  ## The frame is already gone: arkham emits `(popframe)` between the last argument
  ## store and this marker — a teardown that touches only rsp and callee-saved
  ## registers, never the argument registers the arguments now sit in — so nothing
  ## here may address a stack slot. That is also why arkham refuses to form a tail
  ## call that needs outgoing stack arguments.
  if not ctx.inCall:
    error("(tailcall) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("(tailcall) cannot reach an external proc: the IAT/GOT call is indirect", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  if ctx.callContext.typ != nil:
    ctx.clobbered.incl(ctx.callContext.typ.clobbers)
  ctx.callContext.isTailcall = true
  if ctx.callContext.indirect:
    # An INDIRECT tail call would have to survive the `(popframe)` that precedes it,
    # and the pointer is exactly what does not: it sits either in a register the
    # prologue saved and `(popframe)` has just restored the caller's value into, or
    # behind a load through rax that the same reasoning applies to. Staging it is not
    # expressible here — `(popframe)` is already emitted by the time this marker is
    # read — so the backend must not form one, and this says so loudly rather than
    # jumping to whatever the caller happened to leave in that register.
    error("indirect tail call: the target register does not survive (popframe)", n)
  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  ctx.buf.emitJmp(labId)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(tailcall)` head

proc genSyscallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(syscall)` inside a `(prepare <syproc> …)` block: the syscall counterpart of
  ## `(call)`. The args are already in the syscall ABI registers (the syproc's
  ## params), so this just loads the number into rax and traps into the kernel,
  ## then marks rcx/r11 clobbered (the registers the `syscall` instruction
  ## destroys, declared as the syproc's `(clobber …)`). The result is in rax.
  if ctx.callContext.callEmitted:
    error("Multiple call/syscall instructions in prepare block", n)
  x86.emitMovImmToReg(ctx.buf.data, x86.RAX, int64(ctx.callContext.syscallNr))
  x86.emitSyscall(ctx.buf.data)
  ctx.clobbered.incl(ctx.callContext.typ.clobbers)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(syscall)` head

proc genExtcallX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call via IAT
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)

  # The registers the callee destroys — declared by a signature-carrying extern, so a
  # value the caller left bound in one is reported rather than silently read back after
  # the call. (A bare extern declares none; its call site marshals raw and binds nothing.)
  if ctx.callContext.typ != nil:
    ctx.clobbered.incl(ctx.callContext.typ.clobbers)

  # Record call site and emit IAT call
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.emitIatCall(ctx.extProcs[ctx.callContext.extProcIdx].gotSlot)

  ctx.callContext.callEmitted = true

  inc n

  #for (res, dest) in boundResults:
  #  let resReg = tagToRegister(res.reg)
  #  if dest.reg != resReg:
  #    x86.emitMov(ctx.buf.data, dest.reg, resReg)

proc genIatX64(n: var Cursor; ctx: var GenContext) =
  # (iat symbol) - Indirect call through IAT for external procs
  inc n
  if n.kind != Symbol: error("Expected proc symbol for iat", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil or sym.kind != skExtProc: error("iat requires external proc, got: " & name, n)
  inc n
  # Find the extproc to get its IAT slot
  var iatSlot = -1
  for i in 0..<ctx.extProcs.len:
    if ctx.extProcs[i].name == name:
      iatSlot = ctx.extProcs[i].gotSlot
      break
  if iatSlot == -1:
    error("External proc not found: " & name, n)
  # Emit indirect call through IAT using relocation system
  ctx.buf.emitIatCall(iatSlot)

proc genMovX64(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  let dest = parseDest(n, ctx)
  let op = parseOperand(n, ctx)

  # Type checking against THE shared rule (`movTypeOk`), the same one the a64 `mov`
  # applies — see it for what each admitted pairing rests on.
  if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
    typeError(dest.typ, op.typ, start)
  checkPtrStore(dest.typ, op.kind, op.typ, start)

  if dest.kind == okMem:
    if op.kind == okImm:
      # `mov r/m, imm32` (C7 /0), sign-extended into a 64-bit destination and
      # SIZED like every other store here so a narrow field's neighbours survive.
      if op.immVal >= low(int32) and op.immVal <= high(int32):
        x86.emitMovImmToMem(ctx.buf.data, dest.mem, int32(op.immVal),
                            intMemAccess(dest.typ).bits)
      else:
        error("Immediate too large for memory move (must fit in 32 bits)", n)
    elif op.kind == okSsize:
      # Similar issue, ssize is immediate 0 (patched).
      error("Moving ssize to memory not supported", n)
    elif op.kind == okMem:
      error("Cannot move memory to memory", n)
    else:
      let (bits, _) = intMemAccess(dest.typ)     # sized store: don't clobber neighbors
      x86.emitMovToMemSized(ctx.buf.data, dest.mem, op.reg, bits)
  else:
    # dest is reg
    if op.kind == okSsize:
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, 0)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
    elif op.kind == okCsize:
      # csize is a known value - the stack argument size for the current call
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okImm:
      if op.immVal >= low(int32) and op.immVal <= high(int32):
        x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
      else:
        x86.emitMovImmToReg(ctx.buf.data, dest.reg, op.immVal)
    elif op.kind == okMem:
      let (bits, signed) = intMemAccess(op.typ)  # sized load: sign-/zero-extend sub-word
      x86.emitLoadExt(ctx.buf.data, dest.reg, op.mem, bits, signed)
    elif dest.reg != op.reg:
      x86.emitMov(ctx.buf.data, dest.reg, op.reg)
    # else: a redundant same-register move — elide it. The declarative-call
    # `(arg …)`/`(res …)` markers resolve to a fixed ABI register, so a value
    # already in that register marshals to `(mov (arg pN) (rN))` == `mov rN,rN`.
    # arkham's own `movReg` elides d==s; this mirrors it for the marshalling path.

    # A register destination now holds a freshly-written value, so an earlier call's
    # clobber no longer applies — mirror LeaX64 (5211) and the a64 mov (1877). This is
    # what lets a caller-save reload `(mov x.0 <slot>)` (x.0 bound to a call-clobbered
    # volatile) pass the clobber verifier: the reload re-defines the register. Sound —
    # `parseOperand` still rejects reading a clobbered SOURCE; a mov defines its dest.
    ctx.clobbered.excl(dest.reg)

proc genIteX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Check if condition is a cfvar (symbol) or a hardware flag (parens)
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  # Save clobbered state
  let oldClobbered = ctx.clobbered

  if n.kind == Symbol:
    # Control flow variable: (ite cfvar ...)
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)

    # Check if this cfvar has already been used
    if sym.used:
      error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true

    inc n

    # When using a cfvar in ite, we don't emit any jump here.
    # The cfvar's label should be defined at the start of the "then" branch.
    # If jtrue was called, it jumped directly to the "then" branch.
    # If jtrue was NOT called, execution falls through to the "else" branch.

    # We need to emit an unconditional jump to else before the then branch
    ctx.buf.emitJmp(lElse)

    # Define the cfvar's label here (start of then branch)
    ctx.buf.defineLabel(LabelId(sym.offset))

  elif n.kind == TagLit:
    # Hardware flag: (ite (flag) ...)
    let flagTag = tagToX64Flag(n.tag)
    inc n
    inc n

    case flagTag
    of OfO: ctx.buf.emitJno(lElse)
    of NoO: ctx.buf.emitJo(lElse)
    of ZfO: ctx.buf.emitJne(lElse)
    of NzO: ctx.buf.emitJe(lElse)
    of SfO: ctx.buf.emitJns(lElse)
    of NsO: ctx.buf.emitJs(lElse)
    of CfO: ctx.buf.emitJae(lElse)
    of NcO: ctx.buf.emitJb(lElse)
    of PfO: ctx.buf.emitJnp(lElse)
    of NpO: ctx.buf.emitJp(lElse)
    else: error("Unsupported condition: " & $flagTag, n)
  else:
    error("Expected cfvar or flag condition in ite", n)

  genStmtX64(n, ctx) # Then block
  # Clobbered state propagates?
  # Control flow merge: union of clobbered sets?
  # If a register is clobbered in THEN but not ELSE, it is clobbered after? Yes.
  let thenClobbered = ctx.clobbered

  ctx.buf.emitJmp(lEnd)

  ctx.clobbered = oldClobbered # Reset for Else
  ctx.buf.defineLabel(lElse)
  genStmtX64(n, ctx) # Else block
  let elseClobbered = ctx.clobbered

  ctx.buf.defineLabel(lEnd)

  # Merge clobbered
  ctx.clobbered = thenClobbered + elseClobbered

proc genLoopX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Bare infinite-loop form `(loop (stmts …))` — the body is a single statement block. The
  # back-edge is emitted INTERNALLY here, so no token-level backward `jmp` reaches the input:
  # the body carries a FORWARD `jmp` to a break/exit label defined AFTER the loop. This is
  # the form arkham emits for every loop; it keeps "every `jmp` is forward, back-edges are
  # `loop`" true. (The legacy `(loop <pre> <condflag> <body>)` cfvar form below is unused.)
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtX64(n, ctx)                 # the body (contains the forward break/exit jmp)
    ctx.buf.emitJmp(lStart)         # the loop back-edge — emitted by nifasm, not the input
    return

  # Pre-loop
  genStmtX64(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  ctx.buf.defineLabel(lStart)

  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitJne(lEnd)
  of NzO: ctx.buf.emitJe(lEnd)
  else: error("Unsupported loop condition: " & $loopFlagTag, n)

  # Body
  genStmtX64(n, ctx)
  ctx.buf.emitJmp(lStart)
  ctx.buf.defineLabel(lEnd)

  # Loop body clobbers propagate
  # But we might execute loop 0 times?
  # If it's a while loop check at start (which this seems to be? No, structure is (loop pre cond post)?)
  # "As in NJVL... (loop (stmts) (cond) (stmts))"
  # It's a do-while or mid-test loop.
  # If we execute the body, clobbers happen.
  # If we skip, they don't?
  # "All control flow variables are always virtual... The first implementations... do not check if these jumps would skip useful instructions"
  # For clobber tracking, we should assume body MIGHT run.
  # So union with pre-loop state?
  # But `ctx.clobbered` accumulates.
  # So whatever happened in body is added.

proc genJtrueX64(n: var Cursor; ctx: var GenContext) =
  # (jtrue cfvar1.0 cfvar2.0 ...)
  # Set control flow variable(s) to true by emitting an unconditional jump
  # The jump targets are stored in the cfvar symbols
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
    # For multiple cfvars, they all jump to the same place (first one's target)
    # This matches the semantics where all are set to true together
    inc n

  if firstCfvar: error("jtrue requires at least one cfvar", start)

  # Emit unconditional jump to the cfvar's target label
  ctx.buf.emitJmp(jumpTarget)

proc genKillX64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)

  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  elif sym.reg != InvalidTagId:
    # Remove register binding when variable is killed
    if isXmmTagEnum(sym.reg):
      ctx.xmmBindings.del(tagToXmm(sym.reg))
    else:
      ctx.regBindings.del(tagToRegister(sym.reg, n))

  # Remove from scope to ensure it's not used again
  ctx.scope.undefine(sym.name)

  inc n

proc bindRegX64(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                reg: x86.Register) =
  ## Bind physical register `reg` to the typed name `name`, *killing its prior
  ## tenant first*: the previous binding's name is undefined, so a later use of a
  ## value wrongly left in that register becomes an "Unknown variable" error rather
  ## than a silent clobber. This is the "(re)bind implies a kill (of the prior
  ## tenant)" rule shared by `rebind` and `withreg`.
  if reg in ctx.regBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.regBindings[reg]))
    ctx.regBindings.del(reg)
  # Establishing a fresh binding abandons whatever a prior call left in `reg`: arkham
  # only rebinds-at-borrow right before writing the scratch, so the register's stale
  # clobbered status no longer applies (it would otherwise reject a scratch temp that
  # happens to reuse a caller-saved register clobbered by an earlier call).
  ctx.clobbered.excl(reg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.regBindings[reg] = name
  ctx.scope.define(sym)

proc bindXmmX64(ctx: var GenContext; name: string; typ: Type; xmmTag: TagEnum;
                xmm: x86.XmmRegister) =
  ## The SIMD twin of `bindRegX64`: bind xmm register `xmm` to the typed float name
  ## `name`, killing its prior tenant first. Used for float register locals and
  ## float scratch temps.
  if xmm in ctx.xmmBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.xmmBindings[xmm]))
    ctx.xmmBindings.del(xmm)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = xmmTag
  ctx.xmmBindings[xmm] = name
  ctx.scope.define(sym)

proc parseRebindHeader(n: var Cursor; ctx: var GenContext):
                       tuple[name: string; typ: Type; isXmm: bool;
                             regTag: TagEnum; reg: x86.Register; xmm: x86.XmmRegister] =
  ## Parse `:name TYPE (reg)` (the cursor is past the rebind/withreg tag, inside the
  ## node) and establish the binding. Shared by `rebind` and `withreg`. The register
  ## may be a GPR (`(rN)`) or — for a float binding — an xmm register (`(xmmN)`).
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  result.name = symName(n); inc n
  result.typ = parseType(n, ctx.scope, ctx)
  if isXmmTag(n):
    result.isXmm = true
    result.regTag = n.tag
    result.xmm = tagToXmm(result.regTag)
    inc n
    bindXmmX64(ctx, result.name, result.typ, result.regTag, result.xmm)
  elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.regTag = n.tag
    result.reg = tagToRegister(result.regTag, n)
    inc n
    bindRegX64(ctx, result.name, result.typ, result.regTag, result.reg)
  else:
    error("Expected a register for rebind/withreg", n)

proc genRebindX64(n: var Cursor; ctx: var GenContext) =
  ## `(rebind :name TYPE (reg))` — bind `reg` to `name`, killing its prior tenant.
  ## The binding lives until an explicit `kill`, the next `rebind` of `reg`, or the
  ## end of the proc (`regBindings` is reset per proc — the auto-kill backstop).
  into n:
    discard parseRebindHeader(n, ctx)

proc genWithregX64(n: var Cursor; ctx: var GenContext) =
  ## `(withreg :name TYPE (reg) body…)` — a block-scoped `rebind`: the binding is
  ## auto-killed at the end of the body (its own implied kill), in addition to
  ## killing `reg`'s prior tenant on entry.
  into n:
    let h = parseRebindHeader(n, ctx)
    while n.hasMore: genInstX64(n, ctx)
    if h.isXmm:
      if ctx.xmmBindings.getOrDefault(h.xmm, "") == h.name:
        ctx.xmmBindings.del(h.xmm)
    elif ctx.regBindings.getOrDefault(h.reg, "") == h.name:
      ctx.regBindings.del(h.reg)
    ctx.scope.undefine(ctx.symIdOf(h.name))

proc genCasejmpX64(n: var Cursor; ctx: var GenContext) =
  ## `(casejmp S T (stmts …)+)` — computed-goto case dispatch (issue #32). The
  ## k-th `(stmts …)` child is slot k's branch body. Bodies are emitted
  ## back-to-back and NOP-padded to the measured uniform slot size N, so the
  ## dispatch is pure arithmetic — no lookup table, no memory load:
  ##     imul S, S, N          ; slot index → byte offset (N patched below)
  ##     lea  T, [rip+slots]   ; T ← &slot0
  ##     add  T, S
  ##     jmp  T                ; the pad NOPs are never executed
  ## Every body must end in a terminating jump/exit (arkham emits `jmp lEnd`),
  ## so falling into the padding is impossible. The [slots, end) region is
  ## registered as a layout-frozen `fixedRange`: the jump optimizers must not
  ## delete/invert/shrink instructions inside, or `T + S*N` lands mid-instruction.
  let start = n
  intoOperands n:                # `casejmp` is an x86-64-only mnemonic, so its
                                 # id may not fit a tag — see tagpool.nim
    # S: the slot-index register (read, then destroyed by the imul). A raw `(reg)`
    # or a register-bound local name; parseOperand also runs the clobber check.
    let selOp = parseOperand(n, ctx)
    if selOp.kind != okReg:
      error("casejmp selector must be a register or register-bound local", start)
    # T: the base scratch — write-only, so parse it like a `lea` destination.
    var baseReg: x86.Register
    if not leaRegBase(n, ctx, baseReg):
      error("casejmp scratch must be a register or register-bound local", start)
    if baseReg == selOp.reg:
      error("casejmp scratch and selector occupy the same register (" & $baseReg & ")", start)
    # ── dispatch preamble: fixed byte size, independent of the patched N ──
    x86.emitImulImm(ctx.buf.data, selOp.reg, 0)      # S *= N (imm32 patched below)
    let immPos = ctx.buf.data.len - 4
    let slotsLab = ctx.buf.createLabel()
    x86.emitLea(ctx.buf, baseReg, slotsLab)          # T ← &slot0 (rkLea, always 7 bytes)
    x86.emitAdd(ctx.buf.data, baseReg, selOp.reg)
    x86.emitJmpReg(ctx.buf.data, baseReg)
    ctx.clobbered.excl(selOp.reg)                    # both are freshly written here
    ctx.clobbered.excl(baseReg)
    # ── slot bodies, back-to-back; measure each. Slots execute EXCLUSIVELY
    # (exactly one runs per dispatch), so clobber state forks per slot and
    # merges as the union — same rule as `ite`'s branches. ──
    ctx.buf.defineLabel(slotsLab)
    let slotsStart = ctx.buf.data.len
    let clobBefore = ctx.clobbered
    var clobUnion = ctx.clobbered
    var bounds: seq[(int, int)] = @[]
    while n.hasMore:
      if not (n.kind == TagLit and n.tag == StmtsTagId):
        error("casejmp children must be (stmts …) branch bodies", n)
      let s = ctx.buf.data.len
      ctx.clobbered = clobBefore
      genInstX64(n, ctx)                             # the StmtsX64 arm drains the body
      clobUnion = clobUnion + ctx.clobbered
      bounds.add (s, ctx.buf.data.len)
    ctx.clobbered = clobUnion
    if bounds.len == 0:
      error("casejmp requires at least one (stmts …) branch body", start)
    var slotSize = 0
    for (s, e) in bounds: slotSize = max(slotSize, e - s)
    # ── NOP-pad every slot to the uniform size, last-to-first so earlier insert
    # points stay valid; every recorded position past an insert is rebased ──
    for i in countdown(bounds.len - 1, 0):
      let (s, e) = bounds[i]
      let pad = slotSize - (e - s)
      if pad > 0:
        insertRepeated(ctx.buf.data, e, 0x90'u8, pad)
        shiftCodePositions(ctx, e, pad)
    # patch the measured slot size into the imul (immPos precedes the region: stable)
    let nv = uint32(slotSize)
    ctx.buf.data[immPos]     = byte(nv and 0xFF)
    ctx.buf.data[immPos + 1] = byte((nv shr 8) and 0xFF)
    ctx.buf.data[immPos + 2] = byte((nv shr 16) and 0xFF)
    ctx.buf.data[immPos + 3] = byte((nv shr 24) and 0xFF)
    ctx.buf.fixedRanges.add (slotsStart, slotsStart + bounds.len * slotSize)

proc checkSubWidthImm(imm: int64; bits: int; n: Cursor) =
  ## The immediate must fit the operation width under EITHER signedness —
  ## only its low `bits` reach the hardware, so `(cmp (cast (u 8) r) 255)`
  ## and `(cmp (cast (i 8) r) -1)` are both meaningful (and identical).
  let lo = -(1'i64 shl (bits - 1))
  let hi = (1'i64 shl bits) - 1
  if imm < lo or imm > hi:
    error("immediate " & $imm & " does not fit a " & $bits &
          "-bit sub-width operation", n)

proc genAluSubWidth(ctx: var GenContext; dest, op: Operand; kind: SizedAluKind;
                    n: Cursor) =
  ## Two-operand ALU whose destination is an explicitly width-cast register:
  ## the operation runs at `dest.castBits` (8/16/32). A 32-bit op zero-extends
  ## the destination, 8/16-bit ops preserve its upper bits, flags are set at
  ## the operation width — the hardware's own sub-width semantics. The source
  ## may be an immediate or a register; a cast on the source register must
  ## agree (an uncast one contributes its low bits, which is what the
  ## instruction reads anyway).
  let bits = dest.castBits
  case op.kind
  of okImm:
    checkSubWidthImm(op.immVal, bits, n)
    let imm = cast[int32](uint32(op.immVal and 0xFFFFFFFF'i64))
    if kind == saTest:
      x86.emitTestImmSizedR(ctx.buf.data, dest.reg, imm, bits)
    else:
      x86.emitAluImmSizedR(ctx.buf.data, dest.reg, imm, sizedAluDigit[kind], bits)
  of okReg:
    if op.castBits != 0 and op.castBits != bits:
      error("sub-width operand widths disagree: " & $bits & " vs " &
            $op.castBits, n)
    if kind == saTest:
      x86.emitTestSizedRR(ctx.buf.data, dest.reg, op.reg, bits)
    else:
      x86.emitAluSizedRR(ctx.buf.data, dest.reg, op.reg,
                         sizedAluOpcMR8[kind], sizedAluOpcMR[kind], bits)
  of okMem:
    # reg(cast) OP mem — the memory side is read at the same width.
    if kind == saTest:
      error("TEST with memory operand not supported yet", n)
    x86.emitAluSizedRM(ctx.buf.data, dest.reg, op.mem,
                       sizedAluOpcRM8[kind], sizedAluOpcRM[kind], bits)
  else:
    error("sub-width ALU source must be a register or immediate", n)

proc genInstX64(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToX64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    # (cfvar :name.0)
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n

    # Control flow variables are always virtual (bool type, never materialized)
    # We create a label for when this cfvar becomes "true"
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
      if rawTagIsX64Reg(locTag):
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
      # Positive, base-relative offsets (like AArch64): the code generator lowers
      # rsp by a 16-aligned `sub rsp, (ssize)` so the slots sit ABOVE rsp, where a
      # `call`'s pushed return address (and any callee pushes) can't reach them. A
      # red-zone (negative-offset) slot whose address escapes into a call would be
      # clobbered by that call. No frame pointer is needed.
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      sym.typ = baseTyp
      sym.reg = reg
      # Check if register is already bound to another variable
      let targetReg = tagToRegister(reg, n)
      if targetReg in ctx.regBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.regBindings[targetReg] & "', kill it first before reusing", n)
      # Track the register binding
      ctx.regBindings[targetReg] = name

    ctx.scope.define(sym)

    return
  of NoDecl:
    discard "continue with case instTag"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, LenientD, ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD, SyprocD, RegsD, InterruptsD, IrqD, LayoutD, FlashD, SramD, StacksD, HeapD, NoinitD, CoreD:
    error("Unexpected declaration: " & $declTag, n)

  # A mnemonic whose id overflowed the 9-bit tag field carries that id in a
  # leading child (see tagpool.nim), so step over it HERE, once, rather than in
  # each of the ~90 arms below: nifcore has no closing token, so a node is
  # consumed by walking its children, and every arm's own `inc n` then lands on
  # the first operand either way. Only the tags numbered up front reach an arm
  # that treats `n` as a whole node again (`(stmts …)`, `(scope …)`, `(ite …)`),
  # and those can never overflow — `gen_instructions` numbers them first.
  if isEscapedTag(n): inc n

  case instTag
  of NoX64Inst:
    error("No x86 instruction", start)
  of StmtsX64:
    loopInto n:
      genInstX64(n, ctx)
  of ScopeX64:
    # A `(scope …)` is a `(stmts …)` with a reclaimable stack-slot arena: `(s)`
    # locals declared inside are freed when the scope closes, so sibling scopes
    # (e.g. the caller-save spill slots of consecutive calls) reuse the same
    # frame bytes. Sound because a call is straight-line control flow — the saved
    # values are restored before the scope ends, so nothing outside the scope
    # observes those slots. The prologue still reserves the peak via `maxStackSize`.
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstX64(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of PrepareX64:
    genPrepareX64(n, ctx)
  of CallX64:
    genCallMarkerX64(n, ctx)
  of TailcallX64:
    genTailcallMarkerX64(n, ctx)
  of PopframeX64:
    inc n
    genPopframeX64(ctx)
  of ExtcallX64:
    genExtcallX64(n, ctx)
  of IatX64:
    genIatX64(n, ctx)

  of MovX64:
    genMovX64(n, ctx)
  of IteX64:
    genIteX64(n, ctx)
  of LoopX64:
    genLoopX64(n, ctx)
  of JtrueX64:
    genJtrueX64(n, ctx)
  of KillX64:
    genKillX64(n, ctx)
  of RebindX64:
    genRebindX64(n, ctx)
  of WithregX64:
    genWithregX64(n, ctx)
  of AddX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)

    # Type check: add works on integers and pointers
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkArithCompatible(dest.typ, op.typ, "add", start)  # sized ints of any width (64-bit reg)

    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saAdd, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitAddImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # ADD m, imm (sized)
      elif op.kind == okSsize:
        error("Adding ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot add memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x00, 0x01, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okSsize:
        x86.emitAddImm32(ctx.buf.data, dest.reg, 0)   # forced imm32: back-patched
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okCsize:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitAdd(ctx.buf.data, dest.reg, op.mem)
      else:
        x86.emitAdd(ctx.buf.data, dest.reg, op.reg)

  of SubX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)

    # Type check: sub works on integers and pointers
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkArithCompatible(dest.typ, op.typ, "sub", start)  # sized ints of any width (64-bit reg)

    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saSub, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitSubImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # SUB m, imm (sized)
      elif op.kind == okSsize:
        error("Subtracting ssize from memory not supported", n)
      elif op.kind == okMem:
        error("Cannot subtract memory from memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x28, 0x29, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okSsize:
        x86.emitSubImm32(ctx.buf.data, dest.reg, 0)   # forced imm32: back-patched
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        if ctx.inPrologue and dest.reg == x86.RSP:
          # delta filled in at proc end; `frameImm` keeps the pad `(popframe)` needs
          ctx.cfiStep(0, [], ssizeSlot = true, frameImm = int32(op.immVal))
      elif op.kind == okCsize:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
        if ctx.inPrologue and dest.reg == x86.RSP:
          # the alignment-pad-only frame (`hasStackVars` false, `framePad` 8)
          ctx.cfiStep(int32(op.immVal), frameImm = int32(op.immVal))
      elif op.kind == okMem:
        x86.emitSub(ctx.buf.data, dest.reg, op.mem)
      else:
        checkDistinctAluRegs(dest, op, "sub", start)
        x86.emitSub(ctx.buf.data, dest.reg, op.reg)

  of MulX64:
    inc n
    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "mul", start)
    if op.kind == okImm: error("MUL immediate not supported (use IMUL)", n)
    elif op.kind == okMem:
      x86.emitMul(ctx.buf.data, op.mem)
    else:
      x86.emitMul(ctx.buf.data, op.reg)

  of ImulX64:
    inc n
    # `(imul D S)` or the three-operand `(imul D S imm)` (D = S * imm). An
    # explicit sub-width cast on D sizes the operation like the ALU family.
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "imul", start)
    checkIntegerType(op.typ, "imul", start)
    if dest.kind == okMem: error("IMUL destination cannot be memory", n)
    if n.kind == IntLit:
      # (imul D S imm)
      if op.kind != okReg: error("3-operand imul source must be a register", n)
      let bits = if dest.castBits != 0: dest.castBits else: 64
      x86.emitImulImm3(ctx.buf.data, dest.reg, op.reg, int32(getInt(n)), bits)
      inc n
    elif op.kind == okImm:
      x86.emitImulImm(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okMem:
      x86.emitImul(ctx.buf.data, dest.reg, op.mem)
    else:
      x86.emitImul(ctx.buf.data, dest.reg, op.reg)

  of DivX64:
    # (div (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for div", n)
    checkFixedRegFree(ctx, x86.RDX, "div", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for div", n)
    checkFixedRegFree(ctx, x86.RAX, "div", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "div", start)
    if op.kind == okImm: error("DIV immediate not supported", n)
    # Unsigned divide needs the high half of the dividend (RDX) zeroed.
    x86.emitXor(ctx.buf.data, x86.RDX, x86.RDX)
    if op.kind == okMem:
      x86.emitDiv(ctx.buf.data, op.mem)
    else:
      x86.emitDiv(ctx.buf.data, op.reg)

  of IdivX64:
    # (idiv (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for idiv", n)
    checkFixedRegFree(ctx, x86.RDX, "idiv", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    checkFixedRegFree(ctx, x86.RAX, "idiv", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "idiv", start)
    if op.kind == okImm: error("IDIV immediate not supported", n)
    # Signed divide needs RAX sign-extended into RDX:RAX first.
    x86.emitCqo(ctx.buf.data)
    if op.kind == okMem:
      x86.emitIdiv(ctx.buf.data, op.mem)
    else:
      x86.emitIdiv(ctx.buf.data, op.reg)

  # Bitwise
  of AndX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkBitwiseCompatible(dest.typ, op.typ, "and", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saAnd, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitAndImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # AND m, imm (sized)
      elif op.kind == okMem:
        error("Cannot AND memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x20, 0x21, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitAndImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitAndMem(ctx.buf.data, dest.reg, op.mem)   # and reg, [mem]
      else:
        checkDistinctAluRegs(dest, op, "and", start)
        x86.emitAnd(ctx.buf.data, dest.reg, op.reg)

  of OrX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "or", start)
    checkBitwiseType(op.typ, "or", start)
    checkBitwiseCompatible(dest.typ, op.typ, "or", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saOr, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitOrImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)   # OR m, imm (sized)
      elif op.kind == okMem:
        error("Cannot OR memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x08, 0x09, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitOrImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitOrMem(ctx.buf.data, dest.reg, op.mem)    # or reg, [mem]
      else:
        checkDistinctAluRegs(dest, op, "or", start)
        x86.emitOr(ctx.buf.data, dest.reg, op.reg)

  of XorX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "xor", start)
    checkBitwiseType(op.typ, "xor", start)
    checkBitwiseCompatible(dest.typ, op.typ, "xor", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saXor, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitXorImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # XOR m, imm (sized)
      elif op.kind == okMem:
        error("Cannot XOR memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x30, 0x31, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitXorImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitXorMem(ctx.buf.data, dest.reg, op.mem)   # xor reg, [mem]
      else:
        x86.emitXor(ctx.buf.data, dest.reg, op.reg)

  of ShlX64, SalX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 4, dest.castBits)
      else:
        x86.emitShl(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 4, dest.castBits)
      else:
        x86.emitShlCl(ctx.buf.data, dest.reg)      # shl dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  of ShrX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 5, dest.castBits)
      else:
        x86.emitShr(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 5, dest.castBits)
      else:
        x86.emitShrCl(ctx.buf.data, dest.reg)      # shr dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  of SarX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "sar", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 7, dest.castBits)
      else:
        x86.emitSar(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 7, dest.castBits)
      else:
        x86.emitSarCl(ctx.buf.data, dest.reg)      # sar dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  # Unary
  of IncX64:
    inc n
    let op = parseDest(n, ctx) # Dest/Src same
    checkIntegerArithmetic(op.typ, "inc", start)
    if op.kind == okMem: error("INC memory not supported yet", n)
    x86.emitInc(ctx.buf.data, op.reg)

  of DecX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "dec", start)
    if op.kind == okMem: error("DEC memory not supported yet", n)
    x86.emitDec(ctx.buf.data, op.reg)

  of NegX64:
    inc n
    let op = parseDest(n, ctx, allowWidthCast = true)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    if op.castBits != 0:
      x86.emitUnarySizedR(ctx.buf.data, op.reg, 3, op.castBits)   # NEG = /3
    else:
      x86.emitNeg(ctx.buf.data, op.reg)

  of NotX64:
    inc n
    let op = parseDest(n, ctx, allowWidthCast = true)
    checkBitwiseType(op.typ, "not", start)
    if op.kind == okMem: error("NOT memory not supported yet", n)
    if op.castBits != 0:
      x86.emitUnarySizedR(ctx.buf.data, op.reg, 2, op.castBits)   # NOT = /2
    else:
      x86.emitNot(ctx.buf.data, op.reg)

  # Rotates: `(rol D S)` etc. D is a register, S an immediate count (the CL
  # form has no emitter yet). Mirrors the shift dispatch above.
  of RolX64, RorX64, RclX64, RcrX64:
    let name = $instTag
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, name, start)
    if dest.kind == okMem: error("Rotate destination cannot be memory", n)
    if op.kind == okReg and op.reg == RCX and instTag in {RolX64, RorX64}:
      # Rotate by CL — same 0xD3 group as the shifts, digits /0 and /1.
      x86.emitShiftCl(ctx.buf.data, dest.reg, if instTag == RolX64: 0 else: 1)
    elif op.kind != okImm:
      error("Rotate count must be immediate or CL", n)
    else:
      let count = int(op.immVal)
      case instTag
      of RolX64: x86.emitRol(ctx.buf.data, dest.reg, count)
      of RorX64: x86.emitRor(ctx.buf.data, dest.reg, count)
      of RclX64: x86.emitRcl(ctx.buf.data, dest.reg, count)
      else:      x86.emitRcr(ctx.buf.data, dest.reg, count)

  # Bit scan: `(bsf D S)` / `(bsr D S)` — D and S are both registers.
  of BsfX64, BsrX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    if dest.kind != okReg: error("Bit-scan destination must be a register", n)
    if op.kind != okReg: error("Bit-scan source must be a register", n)
    if instTag == BsfX64:
      x86.emitBsf(ctx.buf.data, dest.reg, op.reg)
    else:
      x86.emitBsr(ctx.buf.data, dest.reg, op.reg)

  # Population count: `(popcnt D S N)`. `N` (32 or 64) is the operand size, given
  # EXPLICITLY rather than inferred from the operand types — the destination of a
  # bit-counting instruction is a small count whose declared type says nothing
  # about the width the instruction must run at. Same convention as `(bswap D N)`.
  of PopcntX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    checkBitwiseType(op.typ, $instTag, start)
    if dest.kind != okReg: error("popcnt destination must be a register", n)
    if op.kind != okReg: error("popcnt source must be a register", n)
    if n.kind != IntLit: error("popcnt requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error("popcnt width must be 32 or 64", n)
    x86.emitPopcnt(ctx.buf.data, dest.reg, op.reg, bits)

  # Byte swap: `(bswap D bits)` — D is a register reversed IN PLACE; `bits` is 32 or 64
  # (selects the operand size). Used to lower `__builtin_bswap32/64`.
  of BswapX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind != okReg: error("bswap destination must be a register", n)
    if n.kind != IntLit: error("bswap requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error("bswap width must be 32 or 64", n)
    x86.emitBswap(ctx.buf.data, dest.reg, bits)

  # Bit test family: `(bt D S)` etc. D is a register, S an immediate bit
  # index or a REGISTER bit index (taken modulo the operand width). An
  # explicit sub-width cast on D sizes the operation like the ALU family.
  of BtX64, BtsX64, BtrX64, BtcX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    if dest.kind != okReg: error("Bit-test destination must be a register", n)
    if op.kind == okReg:
      let bits = if dest.castBits != 0: dest.castBits else: 64
      if op.castBits != 0 and op.castBits != bits:
        error("sub-width operand widths disagree: " & $bits & " vs " &
              $op.castBits, n)
      let opc = case instTag
                of BtX64: 0xA3'u8
                of BtsX64: 0xAB'u8
                of BtrX64: 0xB3'u8
                else: 0xBB'u8
      x86.emitBtxRR(ctx.buf.data, dest.reg, op.reg, opc, bits)
    elif op.kind != okImm:
      error("Bit-test bit index must be immediate or a register", n)
    else:
      let bit = int(op.immVal)
      case instTag
      of BtX64:  x86.emitBt(ctx.buf.data, dest.reg, bit)
      of BtsX64: x86.emitBts(ctx.buf.data, dest.reg, bit)
      of BtrX64: x86.emitBtr(ctx.buf.data, dest.reg, bit)
      else:      x86.emitBtc(ctx.buf.data, dest.reg, bit)

  # Comparison
  of CmpX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true) # Actually just operand 1
    let op = parseOperand(n, ctx)
    # Comparisons work on integers, pointers, and bool (the "if bool" test).
    checkComparable(dest.typ, "cmp", start)
    checkComparable(op.typ, "cmp", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saCmp, start)
    elif dest.kind == okMem:
      if op.kind == okImm:
        x86.emitCmpImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # CMP m, imm (sized)
      elif op.kind == okMem:
        error("Cannot compare memory with memory", n)
      else:
        # CMP mem, reg — sized by the memory operand's type so a byte/word/dword
        # compare does not over-read adjacent bytes (the `cmp r/m64,r64` default read
        # 8 bytes of a `char` element and always mismatched).
        x86.emitCmpSized(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitCmpImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitCmpSized(ctx.buf.data, dest.reg, op.mem, intMemAccess(op.typ).bits)
      else:
        x86.emitCmp(ctx.buf.data, dest.reg, op.reg)

  # Width extension: `(movzx D S N)` / `(movsx D S N)`. Three-address like the a64
  # `(clz D S N)` — `N` (8/16/32) is the SOURCE width, given explicitly because the
  # declared type of a register says nothing about how many of its bits are the
  # value. The register-source counterpart of the sized load `(mov D (mem …))`
  # already performs.
  of MovzxX64, MovsxX64:
    let mnemonic = $instTag
    let signed = instTag == MovsxX64
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    # `checkComparable` for the same reason as `test`: a bool IS an 8-bit value a
    # zero-extension is meaningful on, and `canDoBitwiseOps` excludes it.
    checkComparable(dest.typ, mnemonic, start)
    checkComparable(op.typ, mnemonic, start)
    if dest.kind != okReg: error(mnemonic & " destination must be a register", n)
    if op.kind != okReg: error(mnemonic & " source must be a register", n)
    if n.kind != IntLit: error(mnemonic & " requires a width operand (8, 16 or 32)", n)
    let bits = int(getInt(n)); inc n
    if bits notin {8, 16, 32}: error(mnemonic & " width must be 8, 16 or 32", n)
    x86.emitRegExt(ctx.buf.data, dest.reg, op.reg, bits, signed)
    # The destination is freshly written, so an earlier call's clobber no longer
    # applies — same rule as `mov`/`lea` (see genMovX64).
    ctx.clobbered.excl(dest.reg)

  of TestX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    # `checkComparable`, not `checkBitwiseType`: `test r, r` is the canonical
    # zero-test and so has exactly `cmp`'s operand domain — a bool ("is this flag
    # set") and a pointer ("is this nil") are both legitimate, and `cmp x, 0`
    # already accepts them. `test` only reads its operands to set flags.
    checkComparable(dest.typ, "test", start)
    checkComparable(op.typ, "test", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saTest, start)
    elif dest.kind == okMem:
      if op.kind == okImm:
        # TEST mem, imm — 0xF6/0xF7 /0, sized by the memory operand's type.
        x86.emitTestImmSizedM(ctx.buf.data, dest.mem, int32(op.immVal),
                              intMemAccess(dest.typ).bits)
      elif op.kind == okReg:
        # TEST mem, reg — sized by the memory operand's type (0x84/0x85 MR).
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x84, 0x85,
                           intMemAccess(dest.typ).bits)
      else:
        error("TEST memory requires a register or immediate source", n)
    elif op.kind == okImm:
      # emitTestImm
      error("TEST immediate not supported yet", n)
    elif op.kind == okMem:
      error("TEST with memory operand not supported yet", n)
    else:
      x86.emitTest(ctx.buf.data, dest.reg, op.reg)

  # Conditional Sets
  of SeteX64, SetzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSete(ctx.buf.data, dest.reg)

  of SetneX64, SetnzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetne(ctx.buf.data, dest.reg)

  of SetaX64, SetnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeta(ctx.buf.data, dest.reg)

  of SetaeX64, SetnbX64, SetncX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetae(ctx.buf.data, dest.reg)

  of SetbX64, SetnaeX64, SetcX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetb(ctx.buf.data, dest.reg)
  of SetbeX64, SetnaX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetbe(ctx.buf.data, dest.reg)

  of SetgX64, SetnleX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetg(ctx.buf.data, dest.reg)

  of SetgeX64, SetnlX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetge(ctx.buf.data, dest.reg)
  of SetlX64, SetngeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetl(ctx.buf.data, dest.reg)

  of SetleX64, SetngX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetle(ctx.buf.data, dest.reg)

  of SetoX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeto(ctx.buf.data, dest.reg)

  of SetsX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSets(ctx.buf.data, dest.reg)

  of SetpX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetp(ctx.buf.data, dest.reg)
  # Conditional moves
  of CmoveX64, CmovzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmove(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmove(ctx.buf.data, dest.reg, op.reg)

  of CmovneX64, CmovnzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovne(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovne(ctx.buf.data, dest.reg, op.reg)

  of CmovaX64, CmovnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmova(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmova(ctx.buf.data, dest.reg, op.reg)

  of CmovaeX64, CmovnbX64, CmovncX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovae(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovae(ctx.buf.data, dest.reg, op.reg)

  of CmovbX64, CmovnaeX64, CmovcX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovb(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovb(ctx.buf.data, dest.reg, op.reg)

  of CmovbeX64, CmovnaX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovbe(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovbe(ctx.buf.data, dest.reg, op.reg)

  of CmovgX64, CmovnleX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovg(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovg(ctx.buf.data, dest.reg, op.reg)

  of CmovgeX64, CmovnlX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovge(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovge(ctx.buf.data, dest.reg, op.reg)

  of CmovlX64, CmovngeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovl(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovl(ctx.buf.data, dest.reg, op.reg)

  of CmovleX64, CmovngX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovle(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovle(ctx.buf.data, dest.reg, op.reg)

  of CmovoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovo(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovo(ctx.buf.data, dest.reg, op.reg)

  of CmovsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovs(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovs(ctx.buf.data, dest.reg, op.reg)

  of CmovpX64, CmovpeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovp(ctx.buf.data, dest.reg, op.reg)

  of CmovnpX64, CmovpoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovnp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovnp(ctx.buf.data, dest.reg, op.reg)

  of CmovnsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovns(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovns(ctx.buf.data, dest.reg, op.reg)

  of CmovnoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovno(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovno(ctx.buf.data, dest.reg, op.reg)
  # Stack
  of PushX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.kind == okImm:
      x86.emitPush(ctx.buf.data, int32(op.immVal))
    elif op.kind == okMem:
      error("PUSH memory not supported yet", n)
    else:
      x86.emitPush(ctx.buf.data, op.reg)
      if ctx.inPrologue:
        # A callee-saved register saved by the prologue: the CFA moves 8 further
        # from SP and the register now lives at the new bottom of the frame.
        ctx.cfiStep(8, [int32(ord(op.reg))])

  of PopX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      error("POP memory not supported yet", n)
    else:
      x86.emitPop(ctx.buf.data, dest.reg)

  of SyscallX64:
    if ctx.inCall and ctx.callContext.isSyscall:
      genSyscallMarkerX64(n, ctx)   # `(syscall)` as the prepare invocation marker
    else:
      inc n
      x86.emitSyscall(ctx.buf.data)  # a raw `syscall` (e.g. the entry's exit path)
  of LeaX64:
    # (lea dest base-reg offset) or (lea dest label). The destination is a
    # register or a named register local. `lea` *defines* its destination, so a
    # raw register node is accepted whether or not it is bound (unlike a use,
    # which parseDest would reject); a named local resolves to its register.
    inc n
    var dest: x86.Register
    if n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      # A register-homed local OR param is a legal `lea` destination: `lea` DEFINES it,
      # and a param kept in its incoming arg register (e.g. `lea rdi, [rdi+off]` when the
      # param is dead afterwards) is exactly the address-of-a-field marshalling arkham
      # emits. Match the `{skVar, skParam}` convention used by every other operand path.
      if sym != nil and sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
        dest = tagToRegister(sym.reg, n)
        ctx.clobbered.excl(dest)            # writing it makes it valid again
        inc n
      else:
        error("lea destination must be a register or register-bound local", n)
    elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
      dest = parseRegister(n)
    else:
      error("lea destination must be a register", n)

    # Check if next is a label or register
    var baseReg: x86.Register
    if n.kind == TagLit and n.tag == LabTagId:
      # (lea dest (lab label)) - RIP-relative address
      inc n
      if n.kind != Symbol: error("Expected label name", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      if sym == ctx.tlsSizeSym: ctx.tlsSizeUsed = true   # emit the cell (appendTlsSize)
      inc n
      x86.emitLea(ctx.buf, dest, LabelId(sym.offset))
    elif leaRegBase(n, ctx, baseReg):
      # (lea dest base-reg offset) - explicit addressing. `base-reg` is a raw `(reg)`
      # or a register-bound local name (a `rebind`'d scratch temp).
      var displacement: int32 = 0

      # Parse offset - can be integer or stack variable name
      if n.kind == IntLit:
        displacement = int32(getInt(n))
        inc n
      elif n.kind == Symbol:
        let offsetName = getSym(n)
        let offsetSym = lookupWithAutoImport(ctx, ctx.scope, offsetName, n)
        if offsetSym != nil and offsetSym.kind == skTvar:
          # `lea dest, (fsbase) tvar` ⇒ dest = fsbase + tvar.offset = &tvar. A
          # thread-local has no link-time address (it lives at FS_base + offset);
          # nifasm owns the offset, the caller supplies the FS-base register, and
          # the offset folds into the lea displacement — no pointer arithmetic.
          displacement = int32(offsetSym.offset)
        elif offsetSym != nil and (offsetSym.kind == skVar or offsetSym.kind == skParam) and offsetSym.typ.isOnStack:
          displacement = int32(offsetSym.offset)
        else:
          error("Expected stack variable, thread-local, or integer offset in lea", n)
        inc n
      else:
        error("Expected offset (integer or stack variable) in lea", n)

      let mem = x86.MemoryOperand(
        base: baseReg,
        displacement: displacement,
        hasIndex: false
      )
      x86.emitLea(ctx.buf.data, dest, mem)
    else:
      # Try parsing as a label operand (rodata, gvar, etc.) or an addressing
      # expression — `(at …)` / `(dot …)` / `(mem …)` all parse to an `okMem`
      # operand carrying a full base+index*scale+displacement, which `lea`
      # materializes as an address (matching the AArch64 backend, whose `lea`
      # accepts the same forms). This is how arkham takes the address of an array
      # element or aggregate field on x86-64.
      let op = parseOperand(n, ctx)
      if op.gvarSym != nil:
        # Global in .bss (a different segment): emit a placeholder RIP-relative lea
        # and record the site; writeElf patches the disp32 against the .bss vaddr.
        let pos = x86.emitLeaRipPlaceholder(ctx.buf, dest)
        ctx.gvarSites.add (pos, op.gvarSym)
      elif op.kind == okLabel:
        x86.emitLea(ctx.buf, dest, op.label)
      elif op.kind == okMem:
        # `lea dest, [dest]` is a no-op. It is not incidental: the 3-operand
        # `(at base index scratch)` form computes the address INTO the scratch and
        # hands back `okMem{base: scratch}`, and arkham deliberately passes the
        # consuming instruction's destination as that scratch (`prematLval2`'s
        # `hint`, so the stride needs no third register). The address is therefore
        # already in `dest` by the time we get here.
        if not (op.mem.base == dest and not op.mem.hasIndex and
                op.mem.displacement == 0):
          x86.emitLea(ctx.buf.data, dest, op.mem)
      else:
        error("lea requires an address expression (base-reg offset, mem, dot, at, or label)", n)
  of JmpX64:
    inc n
    if lenient() and n.kind == Symbol:
      # Lenient tail call: `(jmp P)` straight to another proc's entry.
      let tsym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
      if tsym != nil and tsym.kind == skProc:
        inc n
        var labId: LabelId
        if tsym.offset == -1:
          labId = ctx.buf.createLabel()
          tsym.offset = int(labId)
        else:
          labId = LabelId(tsym.offset)
        ctx.buf.emitJmp(labId)
        return
    let op = parseOperand(n, ctx)
    if op.kind == okMem:
      error("JMP memory not supported yet", n)
    elif op.label != LabelId(0) or op.typ.kind == UIntT: # Label check
      # op.label is set if it was a label operand
      if op.typ.kind == UIntT: # Label address
        checkForwardJump(ctx, op.label, n)
        x86.emitJmp(ctx.buf, op.label)
      else:
        x86.emitJmpReg(ctx.buf.data, op.reg)
    else:
      x86.emitJmpReg(ctx.buf.data, op.reg) # Default to reg jump if not label?
  of JeX64, JzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJe(ctx.buf, op.label)
  of JneX64, JnzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJne(ctx.buf, op.label)
  of JgX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJg(ctx.buf, op.label)
  of JgeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJge(ctx.buf, op.label)
  of JlX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJl(ctx.buf, op.label)
  of JleX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJle(ctx.buf, op.label)
  of JaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJa(ctx.buf, op.label)
  of JaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJae(ctx.buf, op.label)
  of JbX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJb(ctx.buf, op.label)
  of JbeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJbe(ctx.buf, op.label)
  of JoX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJo(ctx.buf, op.label)
  of JnoX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJno(ctx.buf, op.label)
  of JsX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJs(ctx.buf, op.label)
  of JnsX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJns(ctx.buf, op.label)
  of JpX64:
    # PF=1. After `comisd`/`comiss` that is the UNORDERED result (an operand was
    # NaN), which is how a float comparison tells "equal" from "either is NaN" —
    # ZF alone cannot, since unordered sets ZF too.
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJp(ctx.buf, op.label)
  of JngX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJle(ctx.buf, op.label)
  of JngeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJl(ctx.buf, op.label)
  of JnaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJbe(ctx.buf, op.label)
  of JnaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJb(ctx.buf, op.label)
  of NopX64:
    inc n
    x86.emitNop(ctx.buf.data)
  of CasejmpX64:
    # The one escaped arm that consumes the WHOLE node itself (`n.into`) rather
    # than walking operands, so it wants the head back, not the step-over above.
    n = start
    genCasejmpX64(n, ctx)
  of RepstosbX64, RepstosqX64:
    # `rep stos`: fills `rcx` units at `[rdi]` with al/rax, advancing rdi and
    # zeroing rcx — record those clobbers like the `rep movs` family below.
    inc n
    ctx.clobbered.incl {x86.RDI, x86.RCX}
    if instTag == RepstosbX64: x86.emitRepStosb(ctx.buf.data)
    else:                      x86.emitRepStosq(ctx.buf.data)
  of RepmovsbX64, RepmovswX64, RepmovsdX64, RepmovsqX64:
    # The `rep movs` family names NONE of its operands in the tree: it copies `rcx`
    # units from `[rsi]` to `[rdi]`, advancing both pointers and leaving `rcx` at 0.
    # Record that clobber explicitly — without it a later read of a local homed in
    # rdi/rsi/rcx would silently see a destroyed value instead of raising here.
    # (DF is 0 throughout: SysV guarantees it clear at entry and at every call, and
    # nothing in this assembler emits `std`, so `movs` always steps upward.)
    inc n
    ctx.clobbered.incl {x86.RDI, x86.RSI, x86.RCX}
    if instTag == RepmovsbX64:   x86.emitRepMovsb(ctx.buf.data)
    elif instTag == RepmovswX64: x86.emitRepMovsw(ctx.buf.data)
    elif instTag == RepmovsdX64: x86.emitRepMovsd(ctx.buf.data)
    else:                        x86.emitRepMovsq(ctx.buf.data)
  of RetX64:
    inc n
    x86.emitRet(ctx.buf.data)
  of LabX64:
    # (lab :label)
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # Label might not be defined yet if this is inside a proc body?
    # No, Pass 1 handles types/procs. Labels are local to procs?
    # Labels are typically declared in Pass 1?
    # nifasm: labels can be defined inline.
    # We need to define the label symbol in the scope if not exists, or look it up.
    # If it's a forward jump, we need to have created it.
    # Pass 1 does not scan bodies for labels.
    # So we create it here if missing.
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

  of MovapdX64:
    # `(movapd D S)`: aligned 128-bit float move, one side may be memory —
    # same shape as movdqu; the aligned form faults on a misaligned address.
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        x86.emitMovapd(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movapd source must be xmm or memory", n)
        x86.emitMovapdLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movapd destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      x86.emitMovapdStore(ctx.buf.data, d.mem, s)
  of MovsdX64, MovssX64:
    # `(movsd D S)`: a scalar-float move where one side may be memory:
    #   (movsd (xmmD) (xmmS))   reg→reg ;  (movsd (xmmD) (mem …))  load
    #   (movsd (mem …) (xmmS))  store
    let isD = instTag == MovsdX64
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        if isD: x86.emitMovsd(ctx.buf.data, d, s)
        else:   x86.emitMovss(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movsd/movss source must be xmm or memory", n)
        if isD: x86.emitMovsdLoad(ctx.buf.data, d, s.mem)
        else:   x86.emitMovssLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movsd/movss destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      if isD: x86.emitMovsdStore(ctx.buf.data, d.mem, s)
      else:   x86.emitMovssStore(ctx.buf.data, d.mem, s)

  of MovdquX64:
    # `(movdqu D S)`: unaligned 128-bit move, one side may be memory —
    #   (movdqu (xmmD) (xmmS)) reg→reg; (movdqu (xmmD) (mem …)) load;
    #   (movdqu (mem …) (xmmS)) store.
    # The access is inherently 16 bytes: the mem operand's declared scalar type is
    # NOT consulted (the hardware instruction has no operand-size field either), so
    # a word-typed `(cast (u 64) (mem …))` operand is fine — the aggregate copier
    # addresses its 16-byte chunks with the same operand shapes as its word moves.
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        x86.emitMovdqu(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movdqu source must be xmm or memory", n)
        x86.emitMovdquLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movdqu destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      x86.emitMovdquStore(ctx.buf.data, d.mem, s)

  of PunpcklqdqX64:
    # `(punpcklqdq D S)`: D = [D.lo, S.lo] — xmm registers only. gcc uses the
    # self form to broadcast a quadword before a 16-byte store.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    x86.emitPunpcklqdq(ctx.buf.data, d, s)

  of MovupdX64, MovupsX64:
    # `(movupd D S)` / `(movups D S)`: unaligned 128-bit float move, one side may
    # be memory. Like `movdqu`, the access is inherently 16 bytes and the mem
    # operand's declared scalar type is not consulted.
    let packedSingle = instTag == MovupsX64
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        if packedSingle: x86.emitMovups(ctx.buf.data, d, s)
        else: x86.emitMovupd(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movupd/movups source must be xmm or memory", n)
        if packedSingle: x86.emitMovupsLoad(ctx.buf.data, d, s.mem)
        else: x86.emitMovupdLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movupd/movups destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      if packedSingle: x86.emitMovupsStore(ctx.buf.data, d.mem, s)
      else: x86.emitMovupdStore(ctx.buf.data, d.mem, s)

  of AddpdX64, SubpdX64, MulpdX64, AddpsX64, SubpsX64, MulpsX64:
    # Packed float ALU — xmm registers only.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    case instTag
    of AddpdX64: x86.emitAddpd(ctx.buf.data, d, s)
    of SubpdX64: x86.emitSubpd(ctx.buf.data, d, s)
    of MulpdX64: x86.emitMulpd(ctx.buf.data, d, s)
    of AddpsX64: x86.emitAddps(ctx.buf.data, d, s)
    of SubpsX64: x86.emitSubps(ctx.buf.data, d, s)
    else: x86.emitMulps(ctx.buf.data, d, s)

  of ShufpsX64:
    # `(shufps D S N)`: xmm registers + an 8-bit immediate lane selector.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    if n.kind != IntLit: error("shufps needs an integer immediate", n)
    let imm = getInt(n)
    if imm < 0 or imm > 255: error("shufps immediate out of range", n)
    inc n
    x86.emitShufps(ctx.buf.data, d, s, byte(imm))

  of AddsdX64, AddssX64, SubsdX64, SubssX64,
     MulsdX64, MulssX64, DivsdX64, DivssX64, Cvtsd2ssX64, Cvtss2sdX64,
     ComisdX64, ComissX64:
    # Scalar SSE op on two XMM registers: `(op (xmmD) (xmmS))` → dest = dest op src
    # (or just sets EFLAGS for comisd/comiss).
    let it = instTag
    inc n
    let d = parseXmmOperand(n, ctx)
    if isXmmOperand(n, ctx):
      let s = parseXmmOperand(n, ctx)
      case it
      of AddsdX64:   x86.emitAddsd(ctx.buf.data, d, s)
      of AddssX64:   x86.emitAddss(ctx.buf.data, d, s)
      of SubsdX64:   x86.emitSubsd(ctx.buf.data, d, s)
      of SubssX64:   x86.emitSubss(ctx.buf.data, d, s)
      of MulsdX64:   x86.emitMulsd(ctx.buf.data, d, s)
      of MulssX64:   x86.emitMulss(ctx.buf.data, d, s)
      of DivsdX64:   x86.emitDivsd(ctx.buf.data, d, s)
      of DivssX64:   x86.emitDivss(ctx.buf.data, d, s)
      of Cvtsd2ssX64: x86.emitCvtsd2ss(ctx.buf.data, d, s)
      of Cvtss2sdX64: x86.emitCvtss2sd(ctx.buf.data, d, s)
      of ComisdX64:  x86.emitComisd(ctx.buf.data, d, s)
      of ComissX64:  x86.emitComiss(ctx.buf.data, d, s)
      else: discard
    else:
      # Folded memory source: `op xmm, m32/m64` — same opcode bytes, RM form.
      let s = parseOperand(n, ctx)
      if s.kind != okMem:
        error("scalar SSE source must be an xmm register or memory", n)
      let (prefix, opcode) = case it
        of AddsdX64:    (0xF2u8, 0x58u8)
        of AddssX64:    (0xF3u8, 0x58u8)
        of SubsdX64:    (0xF2u8, 0x5Cu8)
        of SubssX64:    (0xF3u8, 0x5Cu8)
        of MulsdX64:    (0xF2u8, 0x59u8)
        of MulssX64:    (0xF3u8, 0x59u8)
        of DivsdX64:    (0xF2u8, 0x5Eu8)
        of DivssX64:    (0xF3u8, 0x5Eu8)
        of Cvtsd2ssX64: (0xF2u8, 0x5Au8)
        of Cvtss2sdX64: (0xF3u8, 0x5Au8)
        of ComisdX64:   (0x66u8, 0x2Fu8)
        else:           (0x00u8, 0x2Fu8)   # ComissX64
      x86.emitSseOpMem(ctx.buf.data, prefix, opcode, d, s.mem)

  of Cvtsi2sdX64, Cvtsi2ssX64:
    # int -> float: `(cvtsi2sd (xmmD) gprS)`; the GPR source may be a named local.
    let it = instTag
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseOperand(n, ctx).reg
    if it == Cvtsi2sdX64: x86.emitCvtsi2sd(ctx.buf.data, d, s)
    else:                 x86.emitCvtsi2ss(ctx.buf.data, d, s)

  of Cvttsd2siX64, Cvttss2siX64:
    # float -> int (truncating): `(cvttsd2si gprD (xmmS))`; GPR dest may be a local.
    let it = instTag
    inc n
    let d = parseDest(n, ctx).reg
    let s = parseXmmOperand(n, ctx)
    if it == Cvttsd2siX64: x86.emitCvttsd2si(ctx.buf.data, d, s)
    else:                  x86.emitCvttss2si(ctx.buf.data, d, s)

  of MovfqX64, MovfdX64:
    # Bit-transfer between a GPR and an XMM register; direction by operand kinds.
    # `(movfq (xmmD) gprS)` = gpr→xmm; `(movfq gprD (xmmS))` = xmm→gpr. The GPR
    # side may be a raw register or a named local. `(movfq (xmmD) (xmmS))` is the
    # SSE `movq xmm,xmm` (F3 0F 7E): D.lo = S.lo, D's HIGH lane zeroed — the lane
    # sanitizer gcc emits before packed ops on a scalar value (movfq only).
    let it = instTag
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        if it != MovfqX64: error("movfd between two xmm registers is not encodable", n)
        let s = parseXmmOperand(n, ctx)
        x86.emitMovqXmmToXmm(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx).reg
        if it == MovfqX64: x86.emitMovqGprToXmm(ctx.buf.data, d, s)
        else:              x86.emitMovdGprToXmm(ctx.buf.data, d, s)
    else:
      let d = parseDest(n, ctx).reg
      let s = parseXmmOperand(n, ctx)
      if it == MovfqX64: x86.emitMovqXmmToGpr(ctx.buf.data, d, s)
      else:              x86.emitMovdXmmToGpr(ctx.buf.data, d, s)

  of LockX64:
    inc n
    if n.kind != TagLit: error("Expected instruction to lock", n)
    let innerInstTag = tagToX64Inst(n.tag)
    if isEscapedTag(n): inc n  # as in `genInstX64`: step over the escaped id
    case innerInstTag
    of AddX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock add", start)
      checkIntegerArithmetic(op.typ, "lock add", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock add", start)
      if dest.kind != okMem: error("Atomic ADD requires memory destination", n)
      if op.kind == okMem: error("Atomic ADD memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitAddImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitAdd(ctx.buf.data, dest.mem, op.reg)
    of SubX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock sub", start)
      checkIntegerArithmetic(op.typ, "lock sub", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock sub", start)
      if dest.kind != okMem: error("Atomic SUB requires memory destination", n)
      if op.kind == okMem: error("Atomic SUB memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitSubImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitSub(ctx.buf.data, dest.mem, op.reg)
    of AndX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock and", start)
      checkBitwiseType(op.typ, "lock and", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock and", start)
      if dest.kind != okMem: error("Atomic AND requires memory destination", n)
      if op.kind == okMem: error("Atomic AND memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitAndImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitAnd(ctx.buf.data, dest.mem, op.reg)
    of OrX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock or", start)
      checkBitwiseType(op.typ, "lock or", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock or", start)
      if dest.kind != okMem: error("Atomic OR requires memory destination", n)
      if op.kind == okMem: error("Atomic OR memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitOrImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitOr(ctx.buf.data, dest.mem, op.reg)
    of XorX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock xor", start)
      checkBitwiseType(op.typ, "lock xor", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock xor", start)
      if dest.kind != okMem: error("Atomic XOR requires memory destination", n)
      if op.kind == okMem: error("Atomic XOR memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitXorImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitXor(ctx.buf.data, dest.mem, op.reg)
    of IncX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock inc", start)
      if dest.kind != okMem: error("Atomic INC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitInc(ctx.buf.data, dest.mem)
    of DecX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock dec", start)
      if dest.kind != okMem: error("Atomic DEC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitDec(ctx.buf.data, dest.mem)
    of NotX64:
      inc n
      let dest = parseDest(n, ctx)
      checkBitwiseType(dest.typ, "lock not", start)
      if dest.kind != okMem: error("Atomic NOT requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNot(ctx.buf.data, dest.mem)
    of NegX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock neg", start)
      if dest.kind != okMem: error("Atomic NEG requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNeg(ctx.buf.data, dest.mem)
    of XaddX64:
      # `lock xadd [mem], reg` — atomic exchange-and-add; reg receives the old value.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic XADD requires memory destination", n)
      if op.kind != okReg: error("Atomic XADD source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    of CmpxchgX64:
      # `lock cmpxchg [mem], reg` — compares RAX with [mem]; on equal stores reg,
      # else loads [mem] into RAX. ZF reflects success.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic CMPXCHG requires memory destination", n)
      if op.kind != okReg: error("Atomic CMPXCHG source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
       error("Unsupported instruction for LOCK prefix: " & $innerInstTag, n)

    # Each inner branch already consumed the inner instruction (including its
    # closing `)`), so `n` is now at the `(lock …)` form's own closing paren.

  of XchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkExchangeType(dest.typ, "xchg", start)    # int OR pointer (atomic ptr swap)
    checkExchangeType(op.typ, "xchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "xchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XCHG memory, immediate not supported", n)
      if op.kind == okMem: error("XCHG memory, memory not supported", n)
      x86.emitXchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("XCHG reg, immediate not supported", n)
      if op.kind == okMem:
        x86.emitXchg(ctx.buf.data, op.mem, dest.reg)
      else:
        x86.emitXchg(ctx.buf.data, dest.reg, op.reg)
  of XaddX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xadd", start)
    checkIntegerType(op.typ, "xadd", start)
    checkCompatibleTypes(dest.typ, op.typ, "xadd", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XADD memory, immediate not supported", n)
      if op.kind == okMem: error("XADD memory, memory not supported", n)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("XADD reg, immediate not supported", n)
      if op.kind == okMem: error("XADD reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitXadd(ctx.buf.data, dest.reg, op.reg)
  of CmpxchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "cmpxchg", start)
    checkIntegerType(op.typ, "cmpxchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmpxchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("CMPXCHG memory, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG memory, memory not supported", n)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("CMPXCHG reg, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitCmpxchg(ctx.buf.data, dest.reg, op.reg)
  of Cmpxchg8bX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      x86.emitCmpxchg8b(ctx.buf.data, dest.mem)
    else:
      x86.emitCmpxchg8b(ctx.buf.data, dest.reg)
  of MfenceX64:
    inc n
    x86.emitMfence(ctx.buf.data)
  of SfenceX64:
    inc n
    x86.emitSfence(ctx.buf.data)
  of LfenceX64:
    inc n
    x86.emitLfence(ctx.buf.data)
  of PauseX64:
    inc n
    x86.emitPause(ctx.buf.data)

  of ClflushX64:
    inc n
    let op = parseDest(n, ctx)
    if op.kind == okMem: error("CLFLUSH expects memory operand via register?", n)
    # emitClflush(Register). x86.nim takes Register. CLFLUSH m8. ModRM encodes address.
    # So it takes a register which holds the address? No, it takes an address.
    # x86.nim implementation: emitClflush(reg) -> 0F AE /7 (CLFLUSH m8).
    # encodeModRM(amDirect, 7, int(reg)).
    # amDirect means register mode (11).
    # CLFLUSH requires memory operand (ModRM != 11).
    # So emitClflush in x86.nim is BUGGY if it uses amDirect!
    # It should use amIndirect or whatever.
    # If emitClflush(reg) means "flush address in reg", it should be [reg].
    # I'll leave it for now but this looks suspicious.
    x86.emitClflush(ctx.buf.data, op.reg)

  of ClflushoptX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitClflushopt(ctx.buf.data, op.reg)
  of Prefetcht0X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT0(ctx.buf.data, op.reg)
  of Prefetcht1X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT1(ctx.buf.data, op.reg)
  of Prefetcht2X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT2(ctx.buf.data, op.reg)
  of PrefetchntaX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchNta(ctx.buf.data, op.reg)

proc genInstNodeX64*(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstX64(n, ctx)

proc genStmtX64(n: var Cursor; ctx: var GenContext) =
  if atTag(n, StmtsTagId):
    loopInto n:
      genInstNodeX64(n, ctx)
  else:
    genInstNodeX64(n, ctx)
