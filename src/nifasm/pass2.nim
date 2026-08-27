#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Pass 2: emit.
##
## Target-neutral by construction — `genInst` is a five-line dispatch into
## whichever CPU directory this assembly is for, and everything around it
## (per-proc scope, the frame's `(ssize)` patch, the fixed outgoing-argument
## area, the unwind record) is the same shape on all three.
##
## This is also the module that decides a proc's frame size, which is why the
## `(ssize)` placeholders are patched HERE and not at the instruction that
## carries one: the peak stack depth is not known until the body is done.

import std / [tables, sets, algorithm]
import nifcore
import core / [context, sem, cursors, diagnostics, typesem, 
               emit, tags, model, tagconv, decls, stackslots, relocs,
               buffers]
import image/dwarf                    # ProcUnwind: the per-proc CFI record
import x64/encoder as x86
import arm64/encoder as arm64
from thumb/encoder as thumb2 import nil
import x64/regs as x64regs
import x64/instr
import arm64/instr
import thumb/instr
import thumb/board
import rv32/instr
import pass1                          # `handleArch`: `(arch …)` also appears in pass 2

proc genInst(n: var Cursor; ctx: var GenContext)

proc collectLabels(n: var Cursor; ctx: var GenContext; scope: Scope) =
  ## Pre-scan a cursor subtree and create placeholder symbols for labels.
  if n.kind == TagLit:
    if n.tag == LabTagId:
      var tmp = n
      inc tmp
      if tmp.kind == SymbolDef:
        let nameId = getSymId(tmp)
        var sym = scope.lookup(nameId)
        if sym == nil:
          let labId = ctx.buf.createLabel()
          sym = Symbol(name: nameId, kind: skLabel, offset: int(labId))
          scope.define(sym)
        elif sym.kind == skLabel and sym.offset == -1:
          sym.offset = int(ctx.buf.createLabel())
    loopInto n:
      collectLabels(n, ctx, scope)
  else:
    inc n

proc scanStackArgArea(n: var Cursor; ctx: var GenContext; scope: Scope; acc: var int) =
  ## Pre-scan a proc body for the largest outgoing stack-argument area any `(prepare …)`
  ## needs (AArch64 fixed-frame model). The result seeds the slot allocator so the area is
  ## reserved ONCE at the frame bottom: local `(s)` slots then sit ABOVE it and `(ssize)`
  ## includes it, so the caller writes `(mem (sp) (arg pN))` with no per-call `sub sp` and
  ## SP stays constant between prologue and epilogue. A target that doesn't resolve here
  ## (an indirect call through a not-yet-declared local fn-ptr) contributes 0; `genPrepareA64`
  ## guards against an under-reservation at emit time.
  if n.kind == TagLit:
    if n.tag == PrepareTagId:
      # A Win64 call owns the 32-byte shadow space at the bottom of the area whatever
      # its signature says — reserved even for a call with no stack argument at all,
      # and even for one whose target does not resolve here. Must match
      # `genPrepareX64`'s `stackArgBase`, which is what it checks against.
      let base = if ctx.arch == Arch.WinX64: WinShadowSpace else: 0
      acc = max(acc, base)
      var t = n; inc t                           # the call target symbol
      if t.kind == Symbol:
        let s = lookupWithAutoImport(ctx, scope, getSym(t), t)
        if s != nil and s.typ != nil and s.typ.kind == ProcT:
          acc = max(acc, base + computeStackArgSize(s.typ))
    loopInto n:
      scanStackArgArea(n, ctx, scope, acc)
  else:
    inc n

proc pass2Proc*(n: var Cursor; ctx: var GenContext) =
  let oldScope = ctx.scope
  ctx.scope = newScope(oldScope)

  # `into` bounds the cursor to the proc's own children, so walking to the body
  # can never run into the following decls (the main module's buffer continues
  # past this proc) and a body-less proc just iterates to its end.
  into n:
    if n.kind != SymbolDef:
      error("Expected symbol definition", n)
    let name = symName(n)
    ctx.procName = name
    setCurProc name

    # Proc code must start 4-aligned: a lazily emitted rodata blob (arbitrary byte
    # length, e.g. a 2-byte string constant) may immediately precede this proc in
    # the text stream, and AArch64 instructions are fixed 4-byte words — a
    # misaligned body desynchronizes the whole following instruction stream.
    if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM, Arch.Rv32}:
      # Cortex-M needs only halfword alignment, but a 32-bit Thumb encoding
      # straddling a word boundary costs a cycle on some cores and nothing here
      # benefits from the two saved bytes, so it aligns like the others. RV32
      # without the C extension is fixed 4-byte words, so it needs this outright.
      while (ctx.buf.data.len and 3) != 0: ctx.buf.data.add 0'u8

    # Find/Create label for proc
    let sym = oldScope.lookup(getSymId(n))
    if sym.offset == -1:
      let lab = ctx.buf.createLabel()
      sym.offset = int(lab)
    ctx.buf.defineLabel(LabelId(sym.offset))
    ctx.definedLabels.clear()   # fresh backward-jump tracking per proc

    # Open this proc's debug-info record. The CFA at a proc's entry is fixed by
    # the ABI: on x86-64 the `call` has pushed the return address (CFA = SP+8),
    # on AArch64 it is still in the link register (CFA = SP).
    ctx.unwind.add ProcUnwind(name: ctx.nameOf(getSymId(n)),
                              start: ctx.buf.data.len, stop: -1)
    ctx.inPrologue = true
    # CFA at entry: on x86-64 the `call` pushed the return address (SP+8); on
    # AArch64, Cortex-M and RV32 it is still in the link register (`lr`, `ra`),
    # so the CFA is SP.
    ctx.cfaOff = if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM,
                                 Arch.Rv32}: 0'i32
                 else: 8'i32

    # Initialize stack context
    ctx.slots = initSlotManager()
    ctx.ssizePatches = @[]
    # Clear register bindings at the start of each proc
    ctx.regBindings = initTable[x86.Register, string]()
    ctx.a64RegBindings = initTable[arm64.Register, string]()
    ctx.mRegBindings = initTable[thumb2.Register, string]()
    ctx.xmmBindings = initTable[x86.XmmRegister, string]()
    ctx.a64FRegBindings = initTable[arm64.FloatRegister, string]()
    # Each proc is a fresh control flow: no registers are clobbered on entry.
    # (Matters now that proc bodies are emitted back-to-back when bundling.)
    ctx.clobbered = {}
    ctx.clobberedA64 = {}
    ctx.clobberedM = {}
    ctx.clobberedRv = {}
    setLenient false

    # Add params to scope.
    #
    # Stack-passed params live in the incoming argument area. On x86-64 that area
    # sits above the saved RBP and return address (RBP+16). On AArch64 the return
    # address is in LR (not on the stack) and the caller leaves SP pointing right
    # at the first stack arg, so incoming stack params are addressed SP-relative
    # from offset 0 (valid before the callee shifts SP).
    # Cortex-M and RV32 share AArch64's frame shape here: the return address is
    # in the link register rather than on the stack, and the caller leaves SP
    # pointing at the first stack argument, so incoming stack params are
    # SP-relative from offset 0.
    let isA64Proc = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM,
                                 Arch.Rv32}
    # …and on Win64 the caller's stack arguments start above the shadow space it also
    # reserved, so the callee's view of them shifts by the same amount.
    var paramOffset = if isA64Proc: 0
                      elif ctx.arch == Arch.WinX64: 16 + WinShadowSpace
                      else: 16
    for param in sym.typ.params:
      if param.typ.isOnStack:
        # param.typ is already StackOffT
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, offset: paramOffset))
        paramOffset += stackslots.alignedSize(param.typ.offType)
      else:
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, reg: param.reg))
        # Track register-passed params for the bound-register check. x86 spells a
        # register param by its name in the body, so a raw use of it is a code-gen bug
        # → reject it. The A64 backend instead reads its register params as raw `(xN)`
        # (a leaf param stays unnamed in its incoming arg register), so params are NOT
        # tracked there — only A64 register *locals* and `rebind`-bound scratch enter
        # `a64RegBindings`.
        if not isA64Proc and param.reg != InvalidTagId and not param.viaRegs:
          ctx.regBindings[tagToRegister(param.reg, n)] = ctx.nameOf(param.name)

    skip n   # past the proc name

    # Fixed-frame model — BOTH AArch64 and x86-64 use it here: reserve the largest
    # outgoing stack-argument area any call in this proc needs at the BOTTOM of the frame
    # BEFORE any local `(s)` slot is allocated, so locals land above it and `(ssize)`
    # covers it. The caller then passes stack args by writing `(mem (sp) (arg pN))` into
    # that region with NO per-call `sub sp` — SP is constant from prologue to epilogue, so
    # a stack-passed value (which can't sit in a register across a shift) is addressed at a
    # stable offset. This MUST run on x86-64 too: arkham emits the same `(mem (rsp)(arg
    # pN))`-into-`[rsp+off]` sequence with no per-call `sub rsp`, so without the reservation
    # the outgoing arg slots alias the caller's own locals at `[rsp+0…]` and clobber them
    # (e.g. a 6th integer arg overwrote a local `Info`'s first 8 bytes).
    ctx.reservedArgArea = 0
    block:
      var scanArgs = n
      var maxArgs = 0
      while scanArgs.hasMore:
        scanStackArgArea(scanArgs, ctx, ctx.scope, maxArgs)
      ctx.reservedArgArea = maxArgs
      ctx.slots.stackSize = max(ctx.slots.stackSize, maxArgs)

    # Emit the body — the `(stmts …)` child — and skip the signature sections
    # (already consumed in pass1). The `while hasMore` is bounded by the proc's
    # `into`, so it stops at the proc end naturally.
    while n.hasMore:
      if atTag(n, LenientTagId):
        # `(lenient)` precedes the body (takeSig consumed it in pass1); it
        # relaxes the structural checks for THIS proc only.
        setLenient true
        skip n
      elif atTag(n, StmtsTagId):
        var scan = n
        collectLabels(scan, ctx, ctx.scope)
        loopInto n:
          genInst(n, ctx)
      else:
        skip n

  # Check that all declared cfvars were used exactly once
  for cfvarName, cfvarSym in ctx.scope.syms:
    if cfvarSym.kind == skCfvar:
      if not cfvarSym.used:
        quit "[Error] Control flow variable '" & ctx.nameOf(cfvarName) & "' declared but never used in proc " & ctx.procName

  # Patch ssize. On x86 the placeholder is a raw imm32 in the instruction; on
  # AArch64 the immediate is a bit-field of a 32-bit instruction, so the patch
  # rewrites that field (MOVZ imm16 at [20:5]; ADD/SUB imm12 at [21:10]).
  # `(scope …)` blocks reclaim their slots (reset `stackSize`), so the FINAL
  # `stackSize` under-counts the frame. Reserve the peak seen at any point.
  let peakStackSize = max(ctx.slots.stackSize, ctx.slots.maxStackSize)
  let alignedStackSize = (peakStackSize + 15) and not 15
  let isA64 = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}
  let isM = ctx.arch == Arch.CortexM
  var deadFrameAdjusts: seq[int] = @[]   ## frame `add`/`sub` halves that patch to #0
  for (pos, pad) in ctx.ssizePatches:
    # `pad` is the caller-supplied alignment correction from `(ssize N)`: the frame
    # `sub`/`add` folds the 16-alignment pad into the SAME instruction instead of
    # emitting a second `sub rsp, 8` / `add rsp, 8` around it. `alignedStackSize` is
    # 16-aligned, so `+ pad` lands the frame exactly where the separate pair did.
    let v = uint32(alignedStackSize + pad)
    if pos + 4 > ctx.buf.data.len: continue
    if ctx.arch == Arch.Rv32:
      # A `lui`+`addi` pair, always 8 bytes, so no instruction changes length and
      # no position downstream moves — the same property that lets the Cortex-M
      # arm below patch in place, and for the same reason it was chosen over a
      # bare `addi`: `addi` reaches only ±2048, so picking between the forms would
      # make the instruction's WIDTH depend on a number that is not known until
      # here. See `operands.emitSsizeRv`.
      #
      # Any frame size fits, unlike the 12- or 16-bit immediates the Arm targets
      # are limited to.
      if pos + 8 > ctx.buf.data.len: continue
      ctx.buf.data.patchRvLuiAddiPair(pos, v)
      continue
    if isM:
      # A MOVW/MOVT pair, always 8 bytes, so no instruction changes length and no
      # position downstream moves. That is why the Cortex-M frame needs none of
      # the dead-adjust removal the AArch64 path does below — and why any frame
      # size at all fits, rather than the 12- or 16-bit immediate the other two
      # targets are limited to.
      if pos + 8 > ctx.buf.data.len: continue
      ctx.buf.data.patchThumbMovwMovtPair(pos, v)
      continue
    if isA64:
      var instr = uint32(ctx.buf.data[pos]) or (uint32(ctx.buf.data[pos+1]) shl 8) or
                  (uint32(ctx.buf.data[pos+2]) shl 16) or (uint32(ctx.buf.data[pos+3]) shl 24)
      if (instr shr 24) == 0xD2'u32:        # MOVZ Xd, #imm16 → imm16 at [20:5]
        if v > 0xFFFF'u32:
          quit "nifasm: stack frame of " & $alignedStackSize &
               " bytes exceeds the 16-bit `mov reg, (ssize)` immediate"
        instr = (instr and not (0xFFFF'u32 shl 5)) or ((v and 0xFFFF'u32) shl 5)
      else:
        # ADD/SUB Xd, Xn, #imm12 → imm12 at [21:10]. These come in PAIRS (see the
        # `okSsize` emit sites): the instruction carrying the `sh` bit takes the HIGH
        # 12 bits, the other the low 12. Masking both to `v and 0xFFF` is what silently
        # truncated every frame over 4095 bytes.
        if v > 0xFFFFFF'u32:
          quit "nifasm: stack frame of " & $alignedStackSize &
               " bytes exceeds the 24-bit ADD/SUB immediate pair"
        let half = if (instr and arm64.ShBit12) != 0: (v shr 12) and 0xFFF'u32
                   else: v and 0xFFF'u32
        instr = (instr and not (0xFFF'u32 shl 10)) or (half shl 10)
        # Either half of the pair can patch to ZERO, and then that whole instruction
        # does nothing: the HIGH one for every frame of 4095 bytes or less (the
        # common case — `sub sp, sp, #0, lsl #12`), the LOW one for a frame that is
        # an exact multiple of 4096 (`sub sp, sp, #0`, which disassembles as
        # `mov sp, sp`). It sits in every prologue AND every epilogue, so twice per
        # call, which is where it is least affordable. The frame size is only known
        # HERE, so it cannot be skipped at emit time — but it can be pruned now.
        if half == 0'u32 and not inFixedRange(ctx.buf, pos):
          deadFrameAdjusts.add pos
      ctx.buf.data[pos]   = byte(instr and 0xFF)
      ctx.buf.data[pos+1] = byte((instr shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((instr shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((instr shr 24) and 0xFF)
    else:
      ctx.buf.data[pos]   = byte(v and 0xFF)
      ctx.buf.data[pos+1] = byte((v shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((v shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((v shr 24) and 0xFF)

  # Drop them HIGHEST position first: a removal only rebases positions after
  # itself, so the lower ones stay valid as we go.
  if deadFrameAdjusts.len > 0:
    deadFrameAdjusts.sort(Descending)
    for pos in deadFrameAdjusts:
      ctx.buf.data.removeRange(pos, 4)
      shiftCodePositions(ctx, pos + 4, -4)

  # Close this proc's debug-info record. The frame `sub`'s CFA delta is exactly
  # the immediate just patched into it, which is why the FDE could not be
  # finished at the instruction itself.
  if ctx.unwind.len > 0 and ctx.unwind[^1].stop < 0:
    var carry = 0'i32
    for k in 0 ..< ctx.unwind[^1].steps.len:
      if ctx.unwind[^1].steps[k].ssizeSlot:
        carry += int32(alignedStackSize) +
                 int32(if ctx.ssizePatches.len > 0: ctx.ssizePatches[0].pad else: 0)
        ctx.unwind[^1].steps[k].ssizeSlot = false
      ctx.unwind[^1].steps[k].cfaOff += carry
    ctx.unwind[^1].stop = ctx.buf.data.len
  ctx.inPrologue = false

  ctx.scope = oldScope

proc genInst(n: var Cursor; ctx: var GenContext) =
  ## ONE asm-NIF instruction node, for whichever target this assembly is for.
  ## The listing row is recorded inside each arm rather than around this call:
  ## `withListingRow` is a template, so the three selectors stay independent of
  ## each other and of this dispatcher.
  case ctx.arch
  of Arch.X64, Arch.WinX64:
    genInstNodeX64(n, ctx)
  of Arch.A64, Arch.WinA64, Arch.LinuxA64:
    genInstNodeA64(n, ctx)
  of Arch.CortexM:
    genInstNodeM(n, ctx)
  of Arch.Rv32:
    genInstNodeRv(n, ctx)

proc pass2*(n: Cursor; ctx: var GenContext) =
  ## Pass2: Generate code only for top-level instructions (entry point).
  ## Declarations (procs, rodata, gvars, etc.) are NOT generated here,
  ## EXCEPT for entry point procs (named `_start`).
  ## Other declarations are only generated when referenced via lookupWithAutoImport,
  ## which marks them as used and adds them to the pending list.
  ## This enables dead code elimination for the main module.
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          # Types were fully handled in pass1; skip the definition body.
          n = start
          skip n
        of ProcD:
          # Check if this is an entry point proc (_start or main.0)
          inc n
          if n.kind != SymbolDef:
            error("Expected symbol definition", n)
          let name = symName(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym != nil and sym.isForeign:
            # Skip foreign proc body
            n = start
            skip n
          elif name == "_start" or name == "main.0":
            # Entry point proc - generate it immediately. Mark it generated so
            # processReachableSymbols (which sees it in the pending list via the
            # lookupWithAutoImport above) does not emit a duplicate copy.
            n = start
            pass2Proc(n, ctx)
            ctx.generatedSymbols.incl name
            ctx.entrySym = sym             # the FS-setup prologue jumps here
          else:
            # Regular proc - skip, will be generated if referenced
            n = start
            skip n
        of RodataD, GvarD, TvarD:
          # Declarations are NOT generated here - they are subject to dead code elimination.
          # They will only be generated when referenced via lookupWithAutoImport.
          # Skip the declaration body.
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of LayoutD:
          handleLayout(n, ctx)
        of InterruptsD:
          handleInterrupts(n, ctx)
        of ImpD, ExtprocD, SyprocD:
          # Already handled in pass1, skip. A syproc emits no code: it is a
          # syscall's proctype + number, consulted by the `(syscall)`/`(svc)` marker.
          skip n
        else:
          # Top-level instructions (entry point) - generate these
          genInst(n, ctx)
      else:
        error("Expected instruction", n)
  else:
    error("Expected stmts", n)
