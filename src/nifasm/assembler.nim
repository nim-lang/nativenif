
import std / [tables, sets, streams, os, osproc, strutils, algorithm]
import nifcore, nifcoreparse, nifmodules
import "../../../nimony/src/lib" / [nifreader, symparser]
import core / [tags, model, tagconv, tagpool, buffers, relocs]
import x64/encoder as x86
import arm64/encoder as arm64
import image / [elf, macho, pe]
from thumb/encoder as thumb2 import nil   # qualified: Nim conflates `emitBL` (arm64) with `emitBl`
                         # (thumb2), and `Register` would clash three ways
from image/elf32 as elf32 import nil        # qualified: `elf32` repeats ET_EXEC/PT_LOAD/PF_*
                                 # under 32-bit types, which would shadow `elf`'s
import image / [dwarf, tracetable]
import image / [writecommon, writeelf, writemacho, writepe, writecortexm]
import core / [sem, stackslots, decls]
import core / [context, diagnostics, cursors, typecheck, modules, typesem, listing, emit]
import x64/regs as x64regs
import x64/instr
import arm64/regs as a64regs
import arm64/instr
import thumb/regs as mregs
import thumb/board
import thumb/instr
  # `context`: the one state record every pass threads through (see its
  # header for why it cannot live in any module that also uses it).
  # `diagnostics`: `error`, and the two pieces of run state only a message
  # or a lenience check reads.

proc genInst(n: var Cursor; ctx: var GenContext)
proc pass1Proc(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
  inc n
  if n.kind != SymbolDef: error("Expected proc name", n)
  let name = symName(n)  # Full qualified name
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})

  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  let sym = Symbol(name: ctx.symIdOf(name), kind: skProc, typ: procTyp, offset: -1,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc pass1Syproc(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (syproc :Name (params ...) (result ...) (clobber ...) NR) — a Linux syscall with a
  # full proctype: params bound to the syscall ABI registers (so an `(arg pN)` binding
  # in a `(prepare …)` lands in the right register, e.g. x86-64 arg4 → r10), a result in
  # the kernel's return register, and the registers the syscall instruction clobbers
  # (x86-64: rcx, r11). It has no code/address; the number is kept in `offset` and the
  # `(syscall)`/`(svc)` marker reads it. See genSyscallMarker*.
  inc n
  if n.kind != SymbolDef: error("Expected syproc name", n)
  let name = symName(n)
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  if n.kind != IntLit: error("Expected syscall number in syproc", n)
  let sysNr = int(getInt(n))

  let sym = Symbol(name: ctx.symIdOf(name), kind: skSysProc, typ: procTyp, offset: sysNr,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc handleArch(n: var Cursor; ctx: var GenContext) =
  ## Also fixes the target WORD SIZE for the whole assembly. asm-NIF always states
  ## `(arch …)` before any declaration, so every type is built under the right
  ## width — and arkham's `slots.setTargetWord` must have picked the same one, or
  ## a `(i -1)` field is sized differently on the two sides of the pipe.
  inc n
  if n.kind != Ident: error("Expected architecture symbol", n)
  let arch = n.strVal
  if arch == "x64":
    ctx.arch = Arch.X64
  elif arch == "linux_arm64":
    ctx.arch = Arch.LinuxA64
  elif arch == "arm64":
    ctx.arch = Arch.A64
  elif arch == "win_x64":
    ctx.arch = Arch.WinX64
  elif arch == "win_arm64":
    ctx.arch = Arch.WinA64
  elif arch == "cortex_m":
    ctx.arch = Arch.CortexM
  else:
    error("Unknown architecture: " & arch, n)
  setAsmWordSize(case ctx.arch
                 of Arch.X64, Arch.LinuxA64, Arch.A64, Arch.WinX64, Arch.WinA64: 8
                 of Arch.CortexM: 4)
  inc n

proc pass1(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; buf: var TokenBuf) =
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declStart = cursorToPosition(buf, start)
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          inc n
          if n.kind != SymbolDef: error("Expected type name", n)
          let name = symName(n)  # Full qualified name
          inc n
          if n.kind == TagLit and n.tag == ObjectTagId:
            let typ = parseObjectBody(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          elif n.kind == TagLit and n.tag == UnionTagId:
            let typ = parseUnionBody(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          else:
            let typ = parseType(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
        of ProcD:
          # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
          pass1Proc(n, scope, ctx, moduleName, declStart)

          n = start
          skip n
        of RodataD:
          inc n
          if n.kind != SymbolDef: error("Expected rodata name", n)
          let name = symName(n)  # Full qualified name
          var sym = Symbol(name: ctx.symIdOf(name), kind: skRodata,
                          moduleName: moduleName, declStart: declStart)
          sym.offset = -1  # Mark as forward reference until defined
          # A `(rodata :name "bytes" (reloc off sym)*)` whose blob carries
          # symbol-pointer fields cannot live in read-only __TEXT on a PIE image:
          # the absolute target vaddr baked in would be stale under the ASLR slide.
          # Flag it so the Mach-O backend places it in writable __DATA and emits a
          # dyld rebase for each pointer field (see writeMachO). Arch-independent
          # flag; only the macOS path acts on it.
          block:
            var probe = start
            into probe:        # bound the cursor to this rodata's children
              skip probe       # name
              skip probe       # bytes string literal
              if probe.hasMore:  # one or more trailing (reloc ...) children
                sym.dataConst = true
              while probe.hasMore: skip probe   # drain so `into` sees rem == 0
          scope.define(sym)
          n = start
          skip n
        of GvarD:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skGvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of TvarD:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skTvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD:
          # (imp "libpath")
          inc n
          if n.kind != StrLit: error("Expected library path string", n)
          let libPath = getStr(n)
          inc n
          # Load this library; `(imp …)` no longer decides what BINDS to it — each
          # `(extproc …)` names its own, so an import that only needs loading (the
          # Darwin TLV bootstrap, with no externs at all) is expressible too.
          discard ctx.importOrdinal(libPath)
        of ExtprocD:
          # (extproc :name "external_name" "dll"? (params …)? (result …)? (clobber …)?)
          inc n
          if n.kind != SymbolDef: error("Expected extproc name", n)
          let name = symName(n)
          inc n
          if n.kind != StrLit: error("Expected external symbol name string", n)
          let extName = getStr(n)
          inc n
          let libOrdinal = ctx.extprocLib(n)     # the optional dll operand
          let typ = parseExtprocSig(n, scope, ctx)
          # Allocate GOT slot
          let gotSlot = ctx.gotSlotCount
          ctx.gotSlotCount += 1
          # Create symbol
          let sym = Symbol(name: ctx.symIdOf(name), kind: skExtProc, typ: typ, extName: extName, libName: "", gotSlot: gotSlot)
          scope.define(sym)
          # Track for code generation
          ctx.extProcs.add ExtProcInfo(name: name, extName: extName, libOrdinal: libOrdinal, gotSlot: gotSlot, stubOffset: -1)
        of SyprocD:
          # (syproc :name (params ...) (result ...) (clobber ...) NR) — defines a
          # syscall's proctype + number; emits no code (see genSyscallMarker*).
          pass1Syproc(n, scope, ctx, moduleName, declStart)
          n = start
          skip n
        else:
          skip n
      else:
        skip n


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

proc pass2Proc(n: var Cursor; ctx: var GenContext) =
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
    if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}:
      # Cortex-M needs only halfword alignment, but a 32-bit Thumb encoding
      # straddling a word boundary costs a cycle on some cores and nothing here
      # benefits from the two saved bytes, so it aligns like the others.
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
    # AArch64 and Cortex-M it is still in the link register, so the CFA is SP.
    ctx.cfaOff = if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}: 0'i32
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
    setLenient false

    # Add params to scope.
    #
    # Stack-passed params live in the incoming argument area. On x86-64 that area
    # sits above the saved RBP and return address (RBP+16). On AArch64 the return
    # address is in LR (not on the stack) and the caller leaves SP pointing right
    # at the first stack arg, so incoming stack params are addressed SP-relative
    # from offset 0 (valid before the callee shifts SP).
    # Cortex-M shares AArch64's frame shape here: the return address is in LR
    # rather than on the stack, and the caller leaves SP pointing at the first
    # stack argument, so incoming stack params are SP-relative from offset 0.
    let isA64Proc = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}
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

proc pass2(n: Cursor; ctx: var GenContext) =
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


proc generateSymbol(ctx: var GenContext; sym: Symbol) =
  ## Generate code for a single reachable symbol on-demand. nifasm is the linker:
  ## a reachable FOREIGN symbol is bundled into this same output (its body/storage
  ## emitted, cross-module references resolved as ordinary direct relocations) —
  ## exactly like a local symbol, only the declaration is read from the foreign
  ## module's stream (at its indexed byte offset) instead of the main TokenBuf.
  if ctx.nameOf(sym.name) in ctx.generatedSymbols:
    return
  ctx.generatedSymbols.incl ctx.nameOf(sym.name)

  if sym.moduleName notin ctx.modules:
    return  # Module not loaded, can't generate

  let m = ctx.modules[sym.moduleName]
  var n: Cursor
  if sym.isForeign:
    n = getDecl(m.foreign, ctx.nameOf(sym.name), asmTags, ctx.pool)  # cached one-decl tree
  else:
    n = cursorAt(m.buf, sym.declStart)
  let declTag = tagToNifasmDecl(n.tag)

  case sym.kind
  of skProc:
    if declTag == ProcD:
      when defined(arkhamDbgSym):
        stderr.writeLine "DBG generateSymbol proc: " & ctx.nameOf(sym.name)
      pass2Proc(n, ctx)
  of skRodata:
    if declTag == RodataD:
      if ctx.arch == Arch.A64 and sym.dataConst:
        # Mach-O: a const whose fields are symbol addresses must be rebased by dyld,
        # which can only write a *writable* segment — so place it in __DATA (the .bss
        # image, like a statically-initialized gvar) rather than read-only __TEXT.
        # Its bytes go into the data image; each pointer field is recorded for a dyld
        # rebase (writeMachO bakes the preferred target vaddr and slides it at load).
        var rc = n                            # (rodata :name "str" (reloc off sym)*)
        into rc:
          skip rc                             # name (already have sym)
          let s = getStr(rc); skip rc
          # 8-align: pointer fields must be aligned for the load and for dyld's rebase.
          ctx.bssOffset = (ctx.bssOffset + 7) and not 7
          sym.size = ctx.bssOffset            # __DATA byte offset (for adrp+add)
          for i, ch in s:
            if ch != '\0':                    # zero bytes are already zero in the image
              ctx.bssInits.add (off: int64(sym.size + i), val: int64(ch), size: 1)
          ctx.bssOffset += s.len
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                ctx.rodataRebases.add (owner: sym, blobOff: blobOff.int, target: tsym)
            skip rc
      else:
        if sym.offset == -1:
          let labId = ctx.buf.createLabel()
          sym.offset = int(labId)
        ctx.buf.defineLabel(LabelId(sym.offset))
        var rc = n                            # (rodata :name "str" (reloc off sym)*)
        into rc:
          skip rc                             # name (already have sym)
          let s = getStr(rc); skip rc
          for ch in s: ctx.buf.data.add byte(ch)
          # Optional `(reloc off sym)` children: a field of this blob holds the
          # address of another symbol (vtable/RTTI). Mark the target reachable and
          # record the site so `writeElf` bakes its vaddr into the blob (in `.text`).
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                # One WORD, not a fixed eightbyte: arkham reserves exactly
                # `wordSize()` placeholder bytes for the field (see
                # `constToBytes`), and baking 8 over a 4-byte field overwrites
                # whatever follows it in the blob.
                ctx.rodataSymInits.add (labelId: sym.offset, blobOff: blobOff.int,
                                        sym: tsym, size: asmWordSize())
            skip rc
  of skGvar:
    if declTag == GvarD:
      # Allocate space in .bss section
      let size = stackslots.alignedSize(sym.typ)
      let align = asmSizeOf(sym.typ)
      if align > 1:
        ctx.bssOffset = (ctx.bssOffset + align - 1) and not (align - 1)
      let labId = ctx.bssBuf.createLabel()
      sym.offset = int(labId)
      sym.size = ctx.bssOffset      # byte offset within .bss (for arm64 adrp+add)
      ctx.bssBuf.defineLabel(labId)
      # A constant-scalar initializer (arkham emits its bits as the gvar's value
      # in `(gvar :name type value?)`): record it so writeElf writes the value into
      # the (writable) .bss image. `takeLocal` bounds the decl and exposes the
      # optional value via `hasVal`.
      var dn = n
      let lc = takeLocal(dn)
      if lc.hasVal and lc.val.kind == IntLit:
        ctx.bssInits.add (off: sym.size.int64, val: getInt(lc.val),
                          size: asmSizeOf(sym.typ))
      elif lc.hasVal and lc.val.kind == Symbol:
        # Symbol-address initializer (a function-pointer hook, or a gvar pointing
        # at another global). Resolve+mark the target (so its body/storage is
        # generated) and record the slot for address baking in writeElf.
        let initName = getSym(lc.val)
        let initSym = lookupWithAutoImport(ctx, ctx.scope, initName, lc.val)
        if initSym != nil:
          ctx.bssSymInits.add (off: sym.size.int64, sym: initSym,
                               size: asmSizeOf(sym.typ))
      elif lc.hasVal and lc.val.kind == StrLit:
        # An AGGREGATE constant initializer — an object/array constructor or a
        # string, laid out by arkham's `constToBytes` as the raw little-endian
        # bytes of the value. Fill the writable image byte-wise, exactly like a
        # `dataConst` rodata blob; zero bytes are already zero in the image.
        # Trailing `(reloc <off> <sym>)` children name the fields holding a
        # symbol ADDRESS, which only the final layout knows — same treatment as
        # the scalar symbol case above, one entry per field.
        let s = getStr(lc.val)
        for i, ch in s:
          if ch != '\0':
            ctx.bssInits.add (off: int64(sym.size + i), val: int64(ch), size: 1)
        var rc = n                            # (gvar :name type "bytes" (reloc …)*)
        into rc:
          skip rc                             # name
          skip rc                             # type
          skip rc                             # the byte blob
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                # One WORD, matching the placeholder arkham reserved — the same
                # rule as the rodata relocation above.
                ctx.bssSymInits.add (off: int64(sym.size) + blobOff, sym: tsym,
                                     size: asmWordSize())
            skip rc
      ctx.bssOffset += size
  of skTvar:
    if declTag == TvarD:
      let size = stackslots.alignedSize(sym.typ)
      case ctx.arch
      of Arch.A64:
        # macOS TLV: give the variable a descriptor index and a byte offset in
        # the per-thread storage region, and bake a literal initializer (if any)
        # into the __thread_data template dyld copies on first access per thread.
        let align = max(asmSizeOf(sym.typ), 1)
        while (ctx.tlvData.len mod align) != 0: ctx.tlvData.add 0
        sym.offset = ctx.tlvSyms.len    # descriptor index
        sym.size = ctx.tlvData.len      # byte offset within the per-thread region
        ctx.tlvSyms.add sym
        # Parse the optional initializer: (tvar :name type value?)
        var dn = n
        let lc = takeLocal(dn)
        var initVal = 0'i64
        if lc.hasVal and lc.val.kind == IntLit: initVal = getInt(lc.val)
        for i in 0 ..< size:
          ctx.tlvData.add byte((initVal shr (8 * i)) and 0xFF)
      else:
        allocTlsSlotX64(ctx, sym, n)
  else:
    discard  # Types and other symbols don't need code generation

proc processReachableSymbols(ctx: var GenContext) =
  ## Process all pending symbols until queue is empty
  while ctx.pendingSymbols.len > 0:
    let fullName = ctx.pendingSymbols.pop()
    if fullName in ctx.generatedSymbols:
      continue

    # Handle deduplication
    let canonicalName = getCanonicalName(ctx, fullName)
    if canonicalName != fullName and canonicalName in ctx.generatedSymbols:
      continue  # Already generated the canonical version

    # Find the symbol by its full qualified name (nominal identity).
    let sym = ctx.scope.lookup(ctx.symIdOf(fullName))
    if sym != nil:
      generateSymbol(ctx, sym)

proc setupWinEntry(ctx: var GenContext) =
  ## Synthesize the PE entry stub — the Windows counterpart of `setupTls`'s prologue.
  ##
  ## arkham's `main.0` has the C signature `main(argc, argv, envp)` and reads those
  ## three from its argument registers, which on Linux the entry prologue fills from
  ## the stack block the kernel hands over. Windows hands the entry point NOTHING:
  ## the command line is fetched from `GetCommandLineW`, and every register is
  ## undefined. So zero them — `paramCount()` then reports no arguments rather than
  ## `main` storing garbage into `cmdCount`/`cmdLine`/`nimEnviron` and every later
  ## `paramStr` walking a wild pointer. (Wiring the real command line through
  ## `GetCommandLineW` + `CommandLineToArgvW` is a separate step.)
  if ctx.arch != Arch.WinX64 or ctx.entrySym == nil: return
  ctx.winEntryOffset = ctx.buf.data.len
  x86.emitMovImmToReg(ctx.buf.data, x86.RDI, 0)             # argc = 0
  x86.emitMovImmToReg(ctx.buf.data, x86.RSI, 0)             # argv = nil
  x86.emitMovImmToReg(ctx.buf.data, x86.RDX, 0)             # envp = nil
  x86.emitJmp(ctx.buf, LabelId(ctx.entrySym.offset))        # → real entry

proc setupLinuxA64Entry(ctx: var GenContext) =
  ## Synthesize the AArch64/Linux entry stub — the counterpart of `setupTls`'s
  ## argc/argv tail on x86-64.
  ##
  ## arkham's `main.0` has the C signature `main(argc, argv, envp)` and reads the
  ## three from x0/x1/x2 straight into the `cmdCount`/`cmdLine`/`nimEnviron` globals
  ## that `std/cmdline` and `std/envvars` are built on. The kernel does NOT put them
  ## in registers: at process entry SP points at the argument block — argc is the
  ## word at [sp], argv[0] follows at [sp+8] — and the registers are undefined. With
  ## no stub the ELF entry was `main.0` itself, so `cmdCount` took whatever x0 held
  ## and `paramCount()` reported -1 (argc 0 ⇒ count = argc-1).
  ##
  ## Unlike x86-64 this is unconditional: AArch64 needs no TLS prologue to hang the
  ## argument setup off, so the stub exists purely for this.
  if ctx.arch != Arch.LinuxA64 or ctx.entrySym == nil: return
  # Same 4-alignment rule as a proc body (see `pass2Proc`): the stub is appended
  # to a `.text` whose last bytes are a lazily emitted rodata blob of arbitrary
  # length, and the ELF entry must land on an instruction boundary or the very
  # first `ldr` takes SIGBUS.
  while (ctx.buf.data.len and 3) != 0: ctx.buf.data.add 0'u8
  ctx.entryStubOffset = ctx.buf.data.len
  arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)      # x0 = argc
  arm64.emitAddImm(ctx.buf.data, arm64.X1, arm64.SP, 8'u16)   # x1 = &argv[0]
  # envp sits past argv[0..argc-1] and its NULL terminator, i.e. at &argv[argc+1]:
  # `x2 = x1 + 8*argc + 8`. argc is a full 64-bit word on the stack even though
  # `main` types it `(i 32)`, so the shifted add is exact.
  arm64.emitAddShifted(ctx.buf.data, arm64.X2, arm64.X1, arm64.X0, 3'u8)
  arm64.emitAddImm(ctx.buf.data, arm64.X2, arm64.X2, 8'u16)   # x2 = &envp[0]
  arm64.emitB(ctx.buf, LabelId(ctx.entrySym.offset))          # → real entry

proc setupTls(ctx: var GenContext) =
  ## nifasm owns the per-thread TLS. After every bundled tvar has an FS offset
  ## (`ctx.tlsOffset`), reserve the unified `arkham.tls.0` block in `.bss` (sized
  ## for all modules' tvars) and synthesize the entry prologue that points FS at it
  ## via `arch_prctl(ARCH_SET_FS, &arkham.tls.0)`, then jumps to the real entry.
  ## Nim thread-locals have no initializers, so the block is just zeroed `.bss`.
  ## x86-64 only (AArch64 TLS uses a different mechanism, not yet implemented).
  const ArchSetFs = 0x1002      # arch_prctl(2) ARCH_SET_FS
  const ArchPrctlNr = 158       # x86-64 syscall number for arch_prctl
  if ctx.arch != Arch.X64 or ctx.tlsOffset == 0: return
  if ctx.tlsBlockSym == nil or ctx.entrySym == nil: return
  # Reserve the per-thread block in .bss (16-byte aligned); its address is the FS
  # base, and every tvar lives at `FS:[its offset]` within it.
  ctx.bssOffset = (ctx.bssOffset + 15) and not 15
  ctx.tlsBlockSym.size = ctx.bssOffset
  ctx.bssOffset += (ctx.tlsOffset + 15) and not 15
  # Now that the block has its `.bss` offset, every tvar's literal initializer is at
  # a known image address: bake it in like a gvar's (`allocTlsSlotX64`).
  for it in ctx.tlsInits:
    ctx.bssInits.add (off: int64(ctx.tlsBlockSym.size) + it.off, val: it.val,
                      size: it.size)
  # Synthesize the FS-setup prologue at the end of .text — it becomes the ELF entry
  # (see writeElf) and tail-jumps to the program's real entry proc.
  ctx.entryStubOffset = ctx.buf.data.len
  let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RSI)     # lea rsi, [rip+arkham.tls.0]
  ctx.gvarSites.add (pos, ctx.tlsBlockSym)
  x86.emitMovImmToReg(ctx.buf.data, x86.RDI, ArchSetFs)
  x86.emitMovImmToReg(ctx.buf.data, x86.RAX, ArchPrctlNr)
  x86.emitSyscall(ctx.buf.data)                             # arch_prctl(ARCH_SET_FS, &block)
  # Hand the kernel-provided argc/argv to `main(argc, argv)` the way a C crt0 would.
  # At process entry the SysV ABI puts argc at [rsp] and argv[0] at [rsp+8] (NOT in
  # rdi/rsi — the kernel zeroes the registers), and the prologue above leaves rsp
  # untouched. main's full signature takes argc in rdi (param 0) and argv in rsi
  # (param 1); without this they were garbage, so `cmdCount`/`cmdLine` stayed 0 and
  # `paramCount()` returned -1 (every `paramStr` was empty).
  x86.emitMov(ctx.buf.data, x86.RDI, x86.MemoryOperand(base: x86.RSP))            # rdi = argc
  x86.emitLea(ctx.buf.data, x86.RSI, x86.MemoryOperand(base: x86.RSP, displacement: 8'i32))  # rsi = &argv[0]
  # main's 3rd arg (rdx) = the environment block. After argv[0..argc-1] and the NULL
  # terminator, the kernel lays out `envp` at `&argv[argc+1]`. With rdi=argc and
  # rsi=&argv[0]: `envp = rsi + 8*(argc+1) = rsi + 8*argc + 8`. (genMainProc stores
  # this into the `nimEnviron` global; std/envvars + std/posix read it under
  # `-d:nimNativeIo`, matching how rsi feeds `cmdLine`.)
  x86.emitLea(ctx.buf.data, x86.RDX, x86.MemoryOperand(base: x86.RSI, index: x86.RDI,
                                                       scale: 8, displacement: 8'i32, hasIndex: true))  # rdx = &envp[0]
  x86.emitJmp(ctx.buf, LabelId(ctx.entrySym.offset))        # → real entry

proc assemble*(filename, outfile: string; symMap = false; emitObj = false;
               listing = ""; debugInfo = true;
               memMap = elf32.defaultMemoryMap()) =
  var buf = parseFromFile(filename, sharedTags = asmTags)
  # The main module's pool is shared with every foreign module (getDecl is passed
  # `ctx.pool`), so a `SymId` from ANY cursor is a valid key in the one scope table.
  # Captured before the `move buf` below so the ref keeps the pool alive regardless.
  let mainPool = buf.pool

  # Extract base directory from filename
  let baseDir = filename.splitFile.dir
  # The module being assembled — its symbol suffix (e.g. `foo.asm.nif` → "foo"), so a
  # `name.0.foo` reference resolves to a local definition instead of a foreign import.
  let thisModule = extractModuleSuffix(filename)

  var ctx = newGenContext(mainPool, baseDir, thisModule,
                          symMap = symMap, emitObj = emitObj,
                          debugInfo = debugInfo, listing = listing)
  let scope = ctx.rootScope

  # Store main module. `beginRead` BEFORE the move forces the buffer's
  # CursorOwner into existence, which takes a tracked ref on its pool/tags. The
  # move's `=wasMoved` ARC-decrements the moved-from buffer's `pool`; without the
  # owner's ref that would free a pool no cursor yet protects (the classic
  # "beginRead-after-move" heap bug, see [[reindex-tool]]).
  discard beginRead(buf)
  ctx.modules[MainModuleName] = LoadedModule(buf: move buf, loaded: true)

  # The unified per-thread TLS block is owned by nifasm, not any single module
  # (arkham only references it for `&tvar`/`FS:[off]`). Define it up front so those
  # references resolve; it's pre-marked generated (nifasm sizes + allocates it in
  # `setupTls` once all bundled tvars are known) and FS is set in the entry prologue.
  ctx.tlsBlockSym = Symbol(name: ctx.symIdOf("arkham.tls.0"), kind: skGvar,
                           typ: Type(kind: UIntT, bits: 8), offset: -1)
  scope.define(ctx.tlsBlockSym)
  ctx.generatedSymbols.incl "arkham.tls.0"

  # Same treatment for the stack-trace table's label: nifasm owns the data, so it
  # owns the symbol. Defining it up front is what lets `lea D, (lab arkham.traceinfo.0)`
  # resolve like any other label instead of sending `lookupWithAutoImport` off to
  # look for a module named `traceinfo`. Its LabelId is created after the pass-2
  # buffer reset below (the reset restarts label numbering).
  ctx.traceSym = Symbol(name: ctx.symIdOf(TraceInfoSymbol), kind: skLabel, offset: -1)
  scope.define(ctx.traceSym)
  ctx.generatedSymbols.incl TraceInfoSymbol

  var n1 = beginRead(ctx.modules[MainModuleName].buf)
  pass1(n1, scope, ctx, MainModuleName, ctx.modules[MainModuleName].buf)

  # x86-64: a thread-local is read/written as `FS:[sym.offset]` with the
  # displacement baked at the *reference* site (no relocation), so every tvar's
  # offset must be fixed before any code is generated — otherwise a reference
  # compiled before the tvar's lazy `generateSymbol` would capture the default 0.
  # (macOS/A64 resolves tvars through relocated descriptors and allocates lazily.)
  if ctx.arch == Arch.X64:
    var tn = beginRead(ctx.modules[MainModuleName].buf)
    if tn.kind == TagLit and tn.tag == StmtsTagId:
      loopInto tn:
        if tn.kind == TagLit and tagToNifasmDecl(tn.tag) == TvarD:
          let start = tn
          inc tn                              # tvar tag
          if tn.kind == SymbolDef:
            let sym = scope.lookup(getSymId(tn))
            if sym != nil and sym.kind == skTvar and ctx.nameOf(sym.name) notin ctx.generatedSymbols:
              allocTlsSlotX64(ctx, sym, start)
              ctx.generatedSymbols.incl ctx.nameOf(sym.name)   # don't re-allocate in generateSymbol
          tn = start
        skip tn

  # Update ctx with proper buffers for pass2
  ctx.buf = initBuffer()
  ctx.bssBuf = initBuffer()
  ctx.traceLabel = ctx.buf.createLabel()
  ctx.traceSym.offset = int(ctx.traceLabel)

  # Generate code for entry point (top-level instructions only)
  # This marks symbols as used via lookupWithAutoImport when they are referenced
  var n = beginRead(ctx.modules[MainModuleName].buf)
  pass2(n, ctx)

  # Process all pending symbols (both main module and foreign modules)
  # This generates code only for symbols that were actually referenced (dead code elimination)
  processReachableSymbols(ctx)

  # Now that every bundled tvar has an FS offset, reserve the unified TLS block and
  # synthesize the per-target entry stub: the FS base (x86-64), zeroed arguments
  # (Windows), the kernel's argument block (AArch64/Linux). At most one applies.
  appendTraceTable(ctx)
  setupTls(ctx)
  setupWinEntry(ctx)
  setupLinuxA64Entry(ctx)

  if ctx.emitObj:
    # Relocatable object for the system linker (foreign `.o` / framework linking).
    # Standalone executable emission below is unaffected.
    case ctx.arch
    of Arch.A64:
      writeMachOObject(ctx, outfile)
    else:
      quit "nifasm: --emit-obj is only supported for macOS arm64"
  else:
    # A memory map describes a BOARD, and only the firmware target has one. Every
    # other arch is handed its address space by a loader, so honouring the flags
    # there is impossible and ignoring them silently is worse than saying so.
    if memMap.given and ctx.arch != Arch.CortexM:
      quit "nifasm: the memory-map flags apply to the cortex_m target only"
    case ctx.arch
    of Arch.X64, Arch.LinuxA64:
      writeElf(ctx, outfile)
    of Arch.A64:
      writeMachO(ctx, outfile)
    of Arch.WinX64, Arch.WinA64:
      writeExe(ctx, outfile.changeFileExt("exe"))
    of Arch.CortexM:
      # A firmware image, not a hosted executable: vector table, then code.
      #
      # `absBase` is what makes the MOVW+MOVT absolute relocations correct: those
      # carry a label's real ADDRESS, and the code is loaded 8 bytes above the
      # image base because the vector table sits there. Without it every
      # `(adr …)` would resolve 8 bytes low — near enough to look plausible and
      # read the wrong bytes.
      ctx.buf.absBase = memMap.flashBase + uint32(ctx.interruptTableBytes)
      finalize(ctx.buf)
      var code: seq[byte] = newSeq[byte](ctx.buf.data.len)
      for i in 0 ..< ctx.buf.data.len: code[i] = ctx.buf.data[i]
      # The reset vector points at the ENTRY PROC, not at the first byte emitted.
      # Those coincide today only because `pass2` generates `_start`/`main.0`
      # eagerly the moment it sees it; nothing guarantees that, and a wrong reset
      # vector starts executing some other proc's prologue with no diagnostic.
      # A module of bare top-level statements has no entry symbol, and there 0 is
      # genuinely right.
      var entryOff = 0
      if ctx.entrySym != nil:
        let pos = ctx.buf.getLabelPosition(LabelId(ctx.entrySym.offset))
        if pos < 0:
          quit "nifasm: entry point '" & ctx.nameOf(ctx.entrySym.name) &
               "' has no address"
        entryOff = pos
      writeFile(outfile, writeCortexMImage(ctx, code, entryOff, memMap))

  # Close all foreign-module readers (the main module has no reader).
  for modname, module in ctx.modules.mpairs:
    if modname != MainModuleName and module.foreign != nil:
      nifreader.close(module.foreign.r)
