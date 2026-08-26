
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
import arm64/regs as a64regs
import arm64/instr
import thumb/regs as mregs
import thumb/board
import thumb/instr
  # `context`: the one state record every pass threads through (see its
  # header for why it cannot live in any module that also uses it).
  # `diagnostics`: `error`, and the two pieces of run state only a message
  # or a lenience check reads.

const
  WinShadowSpace = 32
    ## Win64 makes the CALLER reserve 32 bytes at the bottom of the outgoing argument
    ## area that the callee may spill its four register arguments into, whether or not
    ## it has four parameters. So a call's stack arguments start at `[rsp+32]`, not
    ## `[rsp+0]`, and even a no-stack-argument call occupies 32 bytes of frame.
    ##
    ## Reserved for EVERY call in a `win_x64` image, not only the ones that leave it.
    ## arkham's own procs never touch the area (their convention is SysV-shaped —
    ## see arkham's `generateX64`), so those 32 bytes are pure frame waste there; but
    ## a call THROUGH a function pointer cannot be told apart from an internal one at
    ## this level — `winlean` reaches every one of its `dynlib` imports that way — and
    ## reserving uniformly is what makes the layout agree on both sides regardless.
    ## Mirrored in arkham's `machine_x64.WinShadowSpace`.


type
  Operand = object
    kind: OperandKind
    typ: Type
    reg: x86.Register
    castBits: int             # non-zero only for an okReg operand under an EXPLICIT
                              # sub-width int `(cast …)`: the ALU family then operates
                              # at that width (8/16/32). Never inferred from a
                              # symbol's declared type — existing output is unchanged.
    immVal: int64
    mem: x86.MemoryOperand
    argName: SymId
    label: LabelId
    gvarSym: Symbol           # non-nil when the operand is a global's address; the
                              # ELF backend patches its `lea` against the .bss segment

proc genStmtX64(n: var Cursor; ctx: var GenContext)
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

proc genInstX64(n: var Cursor; ctx: var GenContext)


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

proc shiftCodePositions(ctx: var GenContext; at, by: int)   # defined below

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


proc parseOperand(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsX64Reg(t):
      result.reg = parseRegister(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # Check if this register is bound to a variable
      if result.reg in ctx.regBindings and not lenient():
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.regBindings[result.reg] & "', use the variable name instead", n)
      # R11 is the codegen's RESERVED staging bridge — never a syscall/call argument
      # or a callee-saved home. A *raw* `(reg r11)` therefore always means a value or
      # address was left in the bridge as an UNTRACKED, untyped register; the codegen
      # must hand it out as a typed `(rebind)` binding (see arkham `pickStagingSealed`).
      # Rejecting it here keeps the staging bridge inside the typed-binding model so a
      # dropped/clobbered operand is an assemble-time error, not a runtime miscompile.
      if result.reg == x86.R11 and not lenient():
        error("raw r11 operand: the staging bridge must be a typed (rebind) binding, " &
              "never a bare (reg) — untracked value/address in the bridge", n)
    elif t == NilTagId:
      # `(nil)` as a value: the null pointer — a 0 immediate typed `nil` (compatible
      # with any pointer, never a sized integer). See `compatible`'s NilT arm.
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == DotTagId:
      # (dot <base-reg> <stackvar> <fieldname>) for stack objects, or
      # (dot <ptr-var> <fieldname>) for pointer variables
      inc n

      var objType: Type
      var baseReg: x86.Register
      var baseDisp: int32 = 0
      var baseIndex: x86.Register
      var baseScale = 1
      var baseHasIndex = false
      var useFsSegment = false
      var fieldName: string

      # Check if first arg is a register (explicit stack addressing)
      if n.kind == TagLit and rawTagIsX64Reg(n.tag):
        # (dot (base-reg) stackvar fieldname) - explicit stack object access
        baseReg = parseRegister(n)

        # Parse stack variable name for offset
        if n.kind != Symbol:
          error("Expected stack variable name in dot expression", n)
        let stackVarName = getSym(n)
        let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
        if stackSym == nil or not stackSym.typ.isOnStack:
          error("Expected stack variable in dot, got: " & stackVarName, n)
        # Unwrap StackOffT to get the base type
        let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
        if baseTyp.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("dot requires object/union type, got " & $baseTyp, n)
        baseDisp = int32(stackSym.offset)
        objType = baseTyp
        inc n

        # Parse field name
        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n
      else:
        # (dot ptr-var fieldname) - pointer variable access
        var baseOp = parseOperand(n, ctx)

        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n

        if baseOp.typ.kind == TypeKind.PtrT:
          # Base is a pointer to an object or union
          objType = resolvedBase(baseOp.typ, ctx, n)
          if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
            error("Cannot access field of non-object/union type " & $objType, n)
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
            baseHasIndex = baseOp.mem.hasIndex
            baseIndex = baseOp.mem.index
            baseScale = baseOp.mem.scale
            useFsSegment = baseOp.mem.useFsSegment
          else:
            baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
          objType = baseOp.typ
          baseReg = baseOp.mem.base
          baseDisp = baseOp.mem.displacement
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
          # A stack-resident object/union named DIRECTLY: `(dot p.0 x.0)`. The slot
          # symbol already parses to `[rsp+offset]` (see the `Symbol` arm below), so
          # the frame base needs no operand of its own — same as the Arm parsers.
          # The older `(dot (rsp) p.0 x.0)` spelling above stays accepted.
          objType = baseOp.typ.offType
          baseReg = baseOp.mem.base
          baseDisp = baseOp.mem.displacement
        else:
          error("dot requires a stack object/union, a pointer to one, or (base-reg stackvar field), got " &
                $baseOp.typ, n)

      # Find field in object/union type. Offsets are precomputed in
      # parseObjectBody/parseUnionBody — inherited (base) fields carry their base
      # offsets, own fields start at sizeof(base), unions are all 0 — so a plain
      # name lookup yields the right displacement.
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break

      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)

      # Result is memory operand pointing to the field
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: baseReg,
        index: baseIndex,
        scale: baseScale,
        displacement: baseDisp + int32(fieldOffset),
        hasIndex: baseHasIndex,
        useFsSegment: useFsSegment
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)

    elif t == AtTagId:
      # (at <base-reg> <stackvar> <index>)            stack array, OR
      # (at <aptr-or-ptr-to-array> <index>)           folds to base+index*scale, OR
      # (at <base> <index> <scratch-reg>)             3-operand form: the element
      #   stride isn't a legal SIB scale (a multi-dimensional array's outer
      #   dimension), so arkham hands us a scratch register and WE compute the
      #   address `base + index*stride` into it — keeping the size arithmetic in
      #   the typed layer (we know the stride) and the register allocation in
      #   arkham (it owns the scratch). `into` bounds the node so the optional
      #   third operand is read without running into the following sibling.
      into n:
        var elemType: Type
        var baseReg: x86.Register
        var baseDisp: int32 = 0
        var baseIndex: x86.Register
        var baseScale: int = 0
        var baseHasIndex = false
        var indexOp: Operand

        if n.kind == TagLit and rawTagIsX64Reg(n.tag):
          # (at (base-reg) stackvar index) - explicit stack array access
          baseReg = parseRegister(n)
          if n.kind != Symbol:
            error("Expected stack variable name in at expression", n)
          let stackVarName = getSym(n)
          let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
          if stackSym == nil or not stackSym.typ.isOnStack:
            error("Expected stack variable in at, got: " & stackVarName, n)
          let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
          if baseTyp.kind != TypeKind.ArrayT:
            error("at requires array type, got " & $baseTyp, n)
          baseDisp = int32(stackSym.offset)
          elemType = baseTyp.elem
          inc n
          indexOp = parseOperand(n, ctx)
        else:
          # (at <base> index) where <base> is an array-pointer variable (`aptr`) or
          # a pointer-to-array address `(cast (ptr (array elem N)) base)` — how
          # arkham reaches a global array or a deref'd array field. A nested `(at …)`
          # base carries its own base register + displacement (+ index), folded on.
          var baseOp = parseOperand(n, ctx)
          indexOp = parseOperand(n, ctx)
          if baseOp.typ.kind == TypeKind.AptrT:
            elemType = resolvedBase(baseOp.typ, ctx, n)
            baseReg = baseOp.reg
          elif baseOp.typ.kind == TypeKind.PtrT and
               resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
            elemType = resolvedBase(baseOp.typ, ctx, n).elem
            if baseOp.kind == okMem:
              baseReg = baseOp.mem.base
              baseDisp = baseOp.mem.displacement
              baseIndex = baseOp.mem.index
              baseScale = baseOp.mem.scale
              baseHasIndex = baseOp.mem.hasIndex
            else:
              baseReg = baseOp.reg
          elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
            elemType = baseOp.typ.elem
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
          elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
               baseOp.typ.offType.kind == TypeKind.ArrayT:
            # A stack-resident array named DIRECTLY: `(at arr.0 (rcx))`. The slot
            # symbol carries its own `[rsp+offset]`, so the frame base is implicit —
            # same as the Arm parsers. `(at (rsp) arr.0 (rcx))` stays accepted.
            elemType = baseOp.typ.offType.elem
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
          else:
            error("at requires a stack array, an aptr, a pointer-to-array base, or (base-reg stackvar index), got " &
                  $baseOp.typ, n)

        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)

        # Optional third operand: an arkham-supplied scratch register for a stride
        # that can't be a SIB scale.
        var hasScratch = false
        var scratchReg: x86.Register
        if n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
          scratchReg = parseRegister(n)
          hasScratch = true
        elif n.hasMore and n.kind == Symbol:
          # arkham may pass the scratch as a `rebind`-bound temp name rather than a
          # raw `(reg)`; resolve it to its register (a raw `(reg)` for a bound reg is
          # itself rejected elsewhere, so the name is the only legal spelling).
          let scratchOp = parseOperand(n, ctx)
          if scratchOp.kind != okReg:
            error("at: scratch operand must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          # Compute `scratch = baseAddr + index*stride` ourselves (stride from the
          # element type). arkham only emits this for a register index, so indexOp
          # is in a register. base+disp (and a power-of-two-free stride) collapse via
          # one `imul` + one `lea`; a base that already holds an index would need a
          # second index slot we don't have (a deeper mixed-stride nest — not emitted
          # by the current arkham).
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # Disjointness: the stride scratch must not alias the base register. The
          # `mov scratch,index` below clobbers `scratch` before the `lea` reads `base`,
          # so `scratch==base` silently drops the base (→ a wild address). This is the
          # arkham allocation bug class ("Bug J") that used to surface only as an
          # ASLR-only runtime segfault; flag it at assemble time. `scratch==index` is
          # fine (the mov is then a no-op) and is intentionally allowed (under register
          # pressure it can be the only free choice).
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          let stride = asmSizeOf(elemType)
          # `base + index*stride` without a multiply wherever the stride allows it.
          # A SIB scale covers {1,2,4,8}; a SUM of two scales covers the strides that
          # actually dominate this compiler — 16 (`HashEntry`, and any pair of words)
          # is 8+8, so two `lea`s replace `mov`+`imul`+`lea`: one instruction fewer,
          # and no 3-cycle `imul` on the address path of every indexed access.
          #
          # The split form reads `index` TWICE, so it needs `scratch != index` —
          # which the disjointness rule above deliberately permits (under pressure
          # arkham may hand us the index register as the scratch). When they alias,
          # the first `lea` would destroy the index before the second reads it, so
          # fall through to the sequential form, where `mov scratch, index` is a
          # no-op and the shift/multiply operates in place.
          var loScale = 0
          var hiScale = 0
          if scratchReg != indexOp.reg:
            if stride in [1, 2, 4, 8]:
              loScale = stride                       # a single `lea` does it all
            else:
              for a in [8, 4, 2, 1]:
                if stride > a and (stride - a) in [1, 2, 4, 8]:
                  loScale = a; hiScale = stride - a; break
          if loScale != 0:
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + index*lo
              x86.MemoryOperand(base: baseReg, index: indexOp.reg, scale: loScale,
                                displacement: baseDisp, hasIndex: true))
            if hiScale != 0:
              x86.emitLea(ctx.buf.data, scratchReg,                 # scratch += index*hi
                x86.MemoryOperand(base: scratchReg, index: indexOp.reg, scale: hiScale,
                                  displacement: 0, hasIndex: true))
          else:
            x86.emitMov(ctx.buf.data, scratchReg, indexOp.reg)      # scratch = index
            if stride > 0 and (stride and (stride - 1)) == 0:
              var sh = 0
              while (1 shl sh) < stride: inc sh
              x86.emitShl(ctx.buf.data, scratchReg, sh)             # scratch <<= log2(stride)
            else:
              x86.emitImulImm(ctx.buf.data, scratchReg, int32(stride))
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + scratch
              x86.MemoryOperand(base: baseReg, index: scratchReg, scale: 1,
                                displacement: baseDisp, hasIndex: true))
          result.kind = okMem
          result.mem = x86.MemoryOperand(base: scratchReg, displacement: 0, hasIndex: false)
        elif indexOp.kind == okImm:
          # Immediate index: fold into the displacement (any stride).
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: baseIndex, scale: baseScale,
            displacement: baseDisp + int32(offset), hasIndex: baseHasIndex)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          # Register index folded as a SIB scale. arkham only emits the 2-operand
          # form when the stride is a legal scale and the base has no index, so these
          # are invariants here (kept as asserts).
          if baseHasIndex:
            error("at: two register indices cannot fold into one memory operand", n)
          # Disjointness: in the folded SIB `[base + index*scale]`, base and index are
          # two distinct live values (an array address and an element index); aliasing
          # them computes `base + base*scale` (a codegen bug). Flag it rather than emit
          # a silently-wrong address.
          if indexOp.reg == baseReg:
            error("at: array base and index occupy the same register (" &
                  $baseReg & ") — distinct values aliased (codegen bug)", n)
          let elemSize = asmSizeOf(elemType)
          if elemSize notin [1, 2, 4, 8]:
            error("Element size " & $elemSize & " not a SIB scale and no scratch supplied", n)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: indexOp.reg, scale: elemSize,
            displacement: baseDisp, hasIndex: true)

        result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n

    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      inc n
      result.reg = RAX
      result.label = LabelId(sym.offset)
      # Label address type is pointer to code?
      result.typ = Type(kind: UIntT, bits: 64) # Address
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      # Cast allows us to opt-out of type system, so we don't check against expectedType here
      var op = parseOperand(n, ctx)
      op.typ = castType
      # An explicit sub-width int cast over a REGISTER is a width annotation:
      # the ALU family operates on the low `castBits` of the register (32-bit
      # zero-extends the destination, 8/16 preserve its upper bits, flags at
      # that width). Recorded only here — a symbol's declared sub-width type
      # never sizes a register operation, so existing output is byte-identical.
      if op.kind == okReg and castType != nil and
         castType.kind in {IntT, UIntT} and castType.bits in [8, 16, 32]:
        op.castBits = castType.bits
      else:
        op.castBits = 0
      result = op
    elif t == MemTagId:
      # (mem <address-expr>) or (mem <base> <offset>) or (mem <base> <index> <scale>) etc.
      # `into` bounds the cursor to the mem node, so the OPTIONAL index/scale/offset
      # checks below are gated by `hasMore` and never read into the following sibling
      # (there is no ParRi sentinel to stop them otherwise).
      into n:
        # Check if first child is an address expression (dot/at) or explicit addressing
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          # Wrapped address expression: (mem (dot ...) or (mem (at ...))
          var addrOp = parseOperand(n, ctx)
          if addrOp.kind != okMem:
            error("mem requires address expression", n)

          # Dereference the pointer type
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)

          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)  # Dereference: ptr T -> T
        elif n.kind == IntLit and getInt(n) == 0:
          # `(mem 0 index scale [disp])` — the NO-BASE scaled form
          # `[index*scale + disp]` (SIB base=101). The literal 0 base is
          # unambiguous: a plain base is never an immediate. This is how a pure
          # scaled index (`lea D, [S*8]`, gcc's `[rax*4+0]`) is spelled.
          inc n
          var indexReg: x86.Register
          if n.kind == TagLit and rawTagIsX64Reg(n.tag):
            let idxOp = parseOperand(n, ctx)   # keeps the binding guards
            indexReg = idxOp.reg
          elif n.kind == Symbol:
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind in {skVar, skParam} and
               indexSym.reg != InvalidTagId:
              indexReg = tagToRegister(indexSym.reg, n)
              inc n
            else:
              error("Expected register index in no-base mem", n)
          else:
            error("Expected register index in no-base mem", n)
          if not (n.hasMore and n.kind == IntLit):
            error("no-base mem requires an explicit scale", n)
          let scale0 = int(getInt(n))
          if scale0 notin [1, 2, 4, 8]:
            error("mem scale must be 1, 2, 4, or 8", n)
          inc n
          var disp0: int32 = 0
          if n.hasMore and n.kind == IntLit:
            disp0 = int32(getInt(n))
            inc n
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: x86.RAX,          # unused; RAX keeps REX.B-from-base silent
            index: indexReg,
            scale: scale0,
            displacement: disp0,
            hasIndex: true,
            noBase: true
          )
          result.typ = Type(kind: IntT, bits: 64)
        else:
          # Explicit addressing: (mem base) or (mem base offset) or
          # (mem base index scale [offset]) — or the BASE-FREE slot form
          # `(mem <stackvar> [offset])` handled first below.
          let baseTok = n                      # peeked for the slot diagnostics
          var baseOp = parseOperand(n, ctx)
          if baseOp.kind == okImm:
            error("mem base must be a register", n)

          var memBase = baseOp.reg
          var displacement: int32 = 0
          var hasIndex = false
          var indexReg: x86.Register = x86.RAX
          var scale: int = 1

          # Check for an optional offset/index (present only if the mem node has
          # more children).
          var stackVarType: Type = nil
          if baseOp.kind == okMem:
            # `(mem name)` / `(mem name off)` — the base-free slot form. A slot
            # symbol already parses to `[rsp + slotOffset]` (the `Symbol` arm of
            # `parseOperand`), so the frame base carries no information and needs no
            # operand of its own. This is the Thumb-2 and AArch64 spelling; the older
            # `(mem (rsp) name [off])` goes through the `Symbol` branch further down
            # and stays accepted.
            if baseOp.typ == nil or baseOp.typ.kind != StackOffT:
              error("mem base must be a register", n)
            memBase = baseOp.mem.base
            displacement = baseOp.mem.displacement
            stackVarType = baseOp.typ.offType
            if n.hasMore and n.kind == IntLit:
              # A raw byte offset WITHIN the named slot, bounds-checked against it —
              # the one safety a `(cast (aptr T) <reg>)` access can never have. See
              # the twin check in the `(mem <base> <stackvar> <disp>)` branch below.
              let extra = getInt(n)
              let slotSize = asmSizeOf(baseOp.typ)
              if extra < 0 or extra >= slotSize:
                error("offset " & $extra & " is outside stack slot '" &
                      (if baseTok.kind == Symbol: getSym(baseTok) else: "?") &
                      "' (" & $slotSize & " bytes)", n)
              displacement += int32(extra)
              inc n
          elif n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (rsp) (arg name)) — an outgoing stack-argument slot. The arg's
            # byte offset within the reserved area becomes the displacement.
            var an = n; inc an                  # peek the arg name before consuming
            let argName = if an.kind == Symbol: getSymId(an) else: SymId(0)
            let argOff = parseOperand(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            displacement = int32(argOff.immVal)
            if argName != SymId(0): ctx.callContext.argsSet.incl argName
            # The slot IS the parameter, so it carries the parameter's declared type —
            # not the machine word a bare `(rsp)` base would otherwise imply. Without
            # this, storing e.g. a `nil` into a stack-passed `pointer` parameter is a
            # type error against a phantom `(i 64)`. An AGGREGATE keeps the word type:
            # `(arg pN k)` addresses one eightbyte of it, not the whole object.
            if argOff.typ != nil:
              let pt = if argOff.typ.kind == StackOffT: argOff.typ.offType else: argOff.typ
              if pt != nil and pt.kind notin {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}:
                stackVarType = pt
          elif n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
            # `(mem <base> <index-reg> [scale [disp]])` with a raw register index —
            # the general SIB form `[base + index*scale + disp]`. Parsing the index
            # through parseOperand keeps the binding guards (a bound register must be
            # named, r11 stays a typed binding). Base==index is legal here: unlike
            # `(at)`, this form makes no claim that the two are distinct values — it
            # IS the encoding, as a distilled gcc body may spell it.
            let idxOp = parseOperand(n, ctx)
            hasIndex = true
            indexReg = idxOp.reg
            if n.hasMore and n.kind == IntLit:
              scale = int(getInt(n))
              if scale notin [1, 2, 4, 8]:
                error("mem scale must be 1, 2, 4, or 8", n)
              inc n
              if n.hasMore and n.kind == IntLit:
                displacement = int32(getInt(n))
                inc n
          elif n.hasMore and (n.kind == IntLit or n.kind == Symbol):
            if n.kind == IntLit:
              displacement = int32(getInt(n))
              inc n
            elif n.kind == Symbol:
              # Could be index register or stack variable (used as offset)
              let indexName = getSym(n)
              let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
              if indexSym != nil and (indexSym.kind == skVar or indexSym.kind == skParam) and indexSym.typ.isOnStack:
                # Stack variable - use its offset as displacement and preserve type (unwrap StackOffT)
                displacement = int32(indexSym.offset)
                stackVarType = if indexSym.typ.kind == StackOffT: indexSym.typ.offType else: indexSym.typ
                inc n
                if n.hasMore and n.kind == IntLit:
                  # `(mem <base> <stackvar> <disp>)` — a raw byte offset WITHIN the named
                  # slot, folded into the slot's own displacement. This is what lets a
                  # word of a stack aggregate be read/written without first materializing
                  # the aggregate's address in a register: a copy out of a named slot then
                  # costs zero address registers instead of one. The access WIDTH still
                  # comes from the operand's type, so a caller reading a raw eightbyte
                  # wraps this in `(cast (u 64) …)`.
                  #
                  # Bounds-checked against the slot — the one safety a `(cast (aptr T)
                  # <reg>)` access can never have, since the register form has no
                  # object to check against.
                  let extra = getInt(n)
                  let slotSize = asmSizeOf(indexSym.typ)
                  if extra < 0 or extra >= slotSize:
                    error("offset " & $extra & " is outside stack slot '" & indexName &
                          "' (" & $slotSize & " bytes)", n)
                  displacement += int32(extra)
                  inc n
              elif indexSym != nil and indexSym.kind in {skVar, skParam} and
                   indexSym.reg != InvalidTagId:
                # This is the index register (a register-homed local or param —
                # the same {skVar, skParam} convention as every operand path)
                hasIndex = true
                indexReg = tagToRegister(indexSym.reg, n)
                inc n

                # Check for scale
                if n.hasMore and n.kind == IntLit:
                  scale = int(getInt(n))
                  if scale notin [1, 2, 4, 8]:
                    error("mem scale must be 1, 2, 4, or 8", n)
                  inc n

                  # Check for displacement after scale
                  if n.hasMore and n.kind == IntLit:
                    displacement = int32(getInt(n))
                    inc n
              else:
                error("Expected index register or stack variable in mem", n)

          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: memBase,
            index: indexReg,
            scale: scale,
            displacement: displacement,
            hasIndex: hasIndex
          )
          # The deref of `(ptr T)` has type T — no special cases (a stack var contributes
          # its own type). `memWidthOpc`/`intMemAccess` size it from T (a sub-word int/bool
          # → a narrow movzx/movsx, e.g. the SSO `(ptr (u 8))` slen byte; everything ≥8
          # bytes → a word); `movCompatible` decides whether T can move to/from the chosen
          # register. A bare register base (no pointer type) is a plain machine word.
          if stackVarType != nil:
            result.typ = stackVarType
          elif baseOp.typ != nil and baseOp.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
            result.typ = resolvedBase(baseOp.typ, ctx, n)
          else:
            result.typ = Type(kind: IntT, bits: 64)
    elif t == SsizeTagId:
      # `(ssize)` is the frame size, filled in at `finalize` once every `(s)` slot is
      # allocated. The optional `(ssize N)` adds N bytes to THIS site only — the
      # prologue/epilogue use it to fold the 16-byte alignment pad into the frame
      # adjustment instead of emitting a second `sub rsp, 8` / `add rsp, 8`.
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      result.immVal = 0
      inc n
      if n.kind == IntLit:
        result.immVal = n.intVal
        inc n
    elif t == CsizeTagId:
      # (csize) - call stack argument size
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name [k]) - argument reference in prepare block. Capture the node cursor
      # for diagnostics that run after we've advanced past it. `into` bounds the cursor
      # to the arg's children so the optional word index `k` is read without leaking the
      # following sibling.
      let argTok = n
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", argTok)
      var argName = SymId(0)
      var wordIdx = 0          # selects the k-th register of a ≤16B by-value aggregate arg
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n

      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), argTok)

      if paramPtr.typ.isOnStack:
        # Stack argument - return its byte offset as an immediate. The base offset is
        # the running byte position among the stack-passed params; the optional word
        # index `k` selects the k-th eightbyte of a multi-word stack aggregate (each
        # word is 8 bytes), so a by-value struct that spilled to the stack can be
        # marshalled/read one word at a time the same way a register-passed one is.
        var offset = ctx.callContext.stackArgBase   # Win64 extern: above the shadow space
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
            offset += stackslots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset + wordIdx * asmWordSize())
        result.typ = paramPtr.typ
      else:
        # Register argument - return the (word-`wordIdx`) register
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), argTok)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegister(paramPtr.regs[wordIdx], argTok)
        result.typ =
          if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
          else: paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference in prepare block (after call). Capture the
      # node cursor for diagnostics: the semantic checks below run after we've
      # advanced past the node, where `n` would sit at the scope end (no loadable
      # token under nifcore).
      let resTok = n
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", resTok)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n

      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", resTok)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & ctx.nameOf(resName), resTok)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), resTok)
      ctx.callContext.resultsSet.incl(resName)

      result.reg = tagToRegister(resPtr.reg, resTok)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64, litVal: result.immVal)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegister(sym.reg, n)

        # Check if clobbered
        if result.reg in ctx.clobbered and not lenient():
          error("Access to variable '" & name & "' in register " & $result.reg & " which was clobbered", n)

      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.kind = okLabel
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now but don't define it yet
        # It will be defined when the rodata is actually written
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of rodata
      inc n
    elif sym != nil and sym.kind == skGvar:
      # Global variable - return its address. A foreign global is bundled into
      # this same image (see generateSymbol) and accessed like a local one.
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.gvarSym = sym                       # carry the symbol so `lea` can patch
      result.typ = Type(kind: UIntT, bits: 64) # Address of gvar
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Accessing thread local variable via FS segment
      # On x86-64 Linux, TLS variables are accessed via FS segment
      # The offset is stored in sym.offset (allocated in pass2)
      # Use RBP as base register (standard for offset-only addressing)
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: x86.RBP,  # RBP allows displacement-only addressing
        displacement: int32(sym.offset),
        hasIndex: false,
        useFsSegment: true  # Use FS segment register
      )
      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skProc:
      # A proc used as a value → its code address (RIP-relative): `lea reg, proc`
      # materializes a function pointer. Same label the proc's definition / a
      # direct `(call)` binds, so it resolves to the proc's entry.
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)   # a code pointer
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDest(n: var Cursor; ctx: var GenContext;
               allowWidthCast = false): Operand =
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.reg = parseRegister(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings and not lenient():
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
    if result.reg == x86.R11 and not lenient():   # the reserved staging bridge
      error("raw r11 destination: the staging bridge must be a typed (rebind) binding, " &
            "never a bare (reg)", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name [k]) as destination - for register arguments in prepare block. `into`
    # bounds the cursor to the arg's own children so the optional word index `k` is read
    # without leaking the following sibling (the `(mov)` source) into the check.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0                      # selects the k-th register of a ≤16B aggregate arg
    into n:
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      argName = getSymId(n)
      inc n
      if n.hasMore and n.kind == IntLit:
        wordIdx = int(getInt(n))
        inc n

    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil:
      error("Unknown argument: " & ctx.nameOf(argName), n)

    if paramPtr.typ.isOnStack:
      error("Stack argument '" & ctx.nameOf(argName) & "' cannot be used directly as destination, use (mem (rsp) (arg " & ctx.nameOf(argName) & "))", n)

    # Track that this argument is being set. A multi-word aggregate fills several words
    # under the same name; count it once (on word 0) so the missing-arg check passes,
    # but allow the later words without a "already set" error.
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)

    # Return the (word-`wordIdx`) register for this argument
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegister(paramPtr.regs[wordIdx], n)
    # A by-value aggregate spread over registers receives a raw 64-bit word per slot,
    # not the whole aggregate — type it as a register so the word `(mov)` type-checks.
    result.typ =
      if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
      else: paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId or
                             n.tag == CastTagId):
    # `(cast T <mem>)` is a legal destination: a cast only retypes an operand, and a
    # memory operand is a legal destination, so retyping one is too. This is how a raw
    # eightbyte is STORED into a named stack slot at an offset — `(cast (u 64) (mem (rsp)
    # v 8))` — where the slot's own declared (aggregate) type would otherwise size the
    # access. `okMem` is still required, so `(cast T (reg))` remains rejected: a register
    # destination must be a typed binding, never a retyped raw register.
    #
    # ONE exception, and only where the instruction opts in (`allowWidthCast` —
    # the ALU family, never `mov`): an explicit SUB-WIDTH int cast over a
    # register destination is a width annotation on the operation, not a
    # retyping — `(add (cast (u 32) (rax)) …)` is a 32-bit add. A 64-bit cast
    # stays rejected everywhere (that is the escape hatch this guard exists
    # for), and `mov` keeps the strict rule so the pointer-store protection
    # cannot be casted away.
    let op = parseOperand(n, ctx)
    if op.kind != okMem and not (allowWidthCast and op.kind == okReg and
                                 op.castBits != 0):
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # A param (skParam) is bound to a register / stack slot exactly like a var, so
    # it is a valid destination too (mirrors parseDestA64 and the source paths).
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
       if sym.typ.isOnStack:
         # Return StackOffT - operations like `add` will reject this at type check
         result.kind = okMem
         result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
         result.typ = sym.typ  # Already StackOffT from declaration
         inc n
         return
       elif sym.reg != InvalidTagId:
         result.reg = tagToRegister(sym.reg, n)
         result.typ = sym.typ
         # Writing to a register makes it valid (unclobbered)
         ctx.clobbered.excl(result.reg)
       else:
         error("Variable has no location", n)
       inc n
    elif sym != nil and sym.kind == skTvar:
       # Writing to thread local variable via FS segment
       result.kind = okMem
       result.mem = x86.MemoryOperand(
         base: RBP,  # RBP allows displacement-only addressing
         displacement: int32(sym.offset),
         hasIndex: false,
         useFsSegment: true  # Use FS segment register
       )
       result.typ = sym.typ
       inc n
    else:
       error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc isXmmOperand(n: Cursor; ctx: GenContext): bool =
  ## True if `n` denotes an xmm register operand — a raw `(xmmN)` tag or a `Symbol`
  ## naming a float local bound to an xmm register. The float instruction handlers
  ## dispatch on this (reg form vs memory form / movfq direction) so a bound float
  ## local, emitted as its name, is recognized as a register operand.
  if isXmmTag(n): return true
  if n.kind == Symbol:
    let sym = ctx.scope.lookup(getSymId(n))   # float locals are never foreign
    result = sym != nil and sym.reg != InvalidTagId and isXmmTagEnum(sym.reg)

proc parseXmmOperand(n: var Cursor; ctx: var GenContext): x86.XmmRegister =
  ## Parse an SSE register *operand* in a scalar-float instruction. The SIMD twin
  ## of `parseOperand`'s register arm: a raw `(xmmN)` tag is accepted only if the
  ## register is not bound (a bound register must be named, so the binding checker
  ## sees the use); a `Symbol` is resolved to the xmm register its float local is
  ## bound to. This is how a raw use of a value still live in a bound xmm register
  ## becomes a build error instead of a silent clobber.
  if isXmmTag(n):
    result = tagToXmm(n.tag)
    if result in ctx.xmmBindings:
      error("Register " & $result & " is bound to variable '" &
            ctx.xmmBindings[result] & "', use the variable name instead", n)
    inc n
  elif n.kind == Symbol:
    let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if sym == nil:
      error("Unknown symbol: " & getSym(n), n)
    if sym.reg == InvalidTagId or not isXmmTagEnum(sym.reg):
      error("Expected float register variable, got: " & getSym(n), n)
    result = tagToXmm(sym.reg)
    inc n
  else:
    error("expected xmm register or float variable", n)

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

proc checkFixedRegFree(ctx: GenContext; reg: x86.Register; insn: string; n: Cursor) =
  if lenient(): return
  ## A fixed-register instruction (`idiv`/`div` write RDX:RAX) is about to clobber
  ## `reg`. If a live variable is still bound to it, that is a code-generator bug —
  ## the clobber would silently destroy the value. Reject it: the value must be moved
  ## (or the binding `kill`ed / `rebind`ed) first. Without this the raw `(rdx)`/`(rax)`
  ## operands bypass `parseOperand`'s binding check, which is how a live parameter
  ## sitting in RDX/RCX used to be miscompiled in silence.
  if reg in ctx.regBindings:
    error(insn & " clobbers " & $reg & ", still bound to variable '" &
          ctx.regBindings[reg] & "' — move/kill it first", n)

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

proc leaRegBase(n: var Cursor; ctx: var GenContext; baseReg: var x86.Register): bool =
  ## Detect and consume a `lea` base register: a raw `(reg)` tag, or a
  ## register-bound local name (a `rebind`'d scratch temp now reaches `lea` by name,
  ## not as a raw reg). Leaves `n` untouched and returns false for any other operand
  ## (label / gvar / mem / dot / at — handled by `parseOperand` instead).
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    baseReg = parseRegister(n); return true
  if n.kind == Symbol:
    let s = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if s != nil and (s.kind == skVar or s.kind == skParam) and
       not s.typ.isOnStack and s.reg != InvalidTagId:
      baseReg = tagToRegister(s.reg, n); inc n; return true
  return false

proc checkDistinctAluRegs(dest, op: Operand; mnemonic: string; n: Cursor) =
  if lenient(): return
  ## A register `and`/`or`/`sub` whose two operands are the SAME register is never
  ## intentional in arkham's codegen: `x and x == x`, `x or x == x`, `x - x == 0`,
  ## so the real source operand has been dropped — the signature of a staging /
  ## scratch register colliding with the destination (e.g. the set-membership
  ## `setbyte and mask` degrading to `setbyte and setbyte`). nifasm is the strict
  ## checker that must catch such a value-dropping miscompile at assemble time
  ## instead of leaving it to surface at runtime. (`xor`/`test`/`cmp` with equal
  ## registers ARE idioms — zero a register / test for zero — so they are excluded.)
  if dest.kind == okReg and op.kind == okReg and dest.reg == op.reg:
    error("`" & mnemonic & "` with identical register operands (" & $dest.reg &
          ") — dropped source operand (staging/scratch register collided with the " &
          "destination); the value-carrying register must be a distinct typed binding", n)

proc shiftCodePositions(ctx: var GenContext; at, by: int) =
  ## Rebase every recorded byte position `>= at` by `by` freshly inserted bytes
  ## (the `casejmp` NOP padding). A label/reloc exactly AT the insert point
  ## belongs to the code AFTER the padding (the next slot), so `>=` is right —
  ## which is also why a casejmp branch body must not define a label at its very
  ## end (see doc/instructions.md).
  for k in 0 ..< ctx.buf.relocs.len:
    if ctx.buf.relocs[k].position >= at: ctx.buf.relocs[k].position += by
  for k in 0 ..< ctx.buf.labels.len:
    if ctx.buf.labels[k].position >= at: ctx.buf.labels[k].position += by
  for k in 0 ..< ctx.buf.fixedRanges.len:      # a NESTED casejmp region inside a slot
    let (s, e) = ctx.buf.fixedRanges[k]
    ctx.buf.fixedRanges[k] = ((if s >= at: s + by else: s), (if e >= at: e + by else: e))
  for k in 0 ..< ctx.gvarSites.len:
    if ctx.gvarSites[k][0] >= at: ctx.gvarSites[k] = (ctx.gvarSites[k][0] + by, ctx.gvarSites[k][1])
  for k in 0 ..< ctx.ssizePatches.len:
    if ctx.ssizePatches[k].pos >= at: ctx.ssizePatches[k].pos += by
  for k in 0 ..< ctx.csizePatches.len:
    if ctx.csizePatches[k][0] >= at: ctx.csizePatches[k] = (ctx.csizePatches[k][0] + by, ctx.csizePatches[k][1])
  for k in 0 ..< ctx.tlvSites.len:
    if ctx.tlvSites[k][0] >= at: ctx.tlvSites[k] = (ctx.tlvSites[k][0] + by, ctx.tlvSites[k][1])
  # An EXTERNAL call's `bl` is not a reloc — its position is recorded per extproc and
  # patched at image layout — so it needs rebasing here too. Missing it left the `bl`
  # unpatched (a branch to itself) and wrote the IAT displacement over whatever had
  # moved into the stale slot, which for a pruned frame `add` was the epilogue's
  # `add sp, sp, #frame`.
  for e in 0 ..< ctx.extProcs.len:
    for k in 0 ..< ctx.extProcs[e].callSites.len:
      if ctx.extProcs[e].callSites[k] >= at: ctx.extProcs[e].callSites[k] += by
  for k in 0 ..< ctx.listRows.len:      # `--listing` byte ranges
    if ctx.listRows[k].start >= at: ctx.listRows[k].start += by
    if ctx.listRows[k].stop >= at: ctx.listRows[k].stop += by
  for k in 0 ..< ctx.unwind.len:        # `.symtab` / `.eh_frame` proc + CFI positions
    if ctx.unwind[k].start >= at: ctx.unwind[k].start += by
    if ctx.unwind[k].stop >= at: ctx.unwind[k].stop += by
    for s in 0 ..< ctx.unwind[k].steps.len:
      if ctx.unwind[k].steps[s].at >= at: ctx.unwind[k].steps[s].at += by

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

type
  SizedAluKind = enum
    saAdd, saSub, saAnd, saOr, saXor, saCmp, saTest

const
  # MR-form opcode pairs (8-bit / 16-32-bit) and the /digit of the imm form,
  # indexed by SizedAluKind. TEST's imm form is special-cased (0xF6/0xF7 /0).
  sizedAluOpcMR8: array[SizedAluKind, byte] = [0x00'u8, 0x28, 0x20, 0x08, 0x30, 0x38, 0x84]
  sizedAluOpcMR:  array[SizedAluKind, byte] = [0x01'u8, 0x29, 0x21, 0x09, 0x31, 0x39, 0x85]
  sizedAluOpcRM8: array[SizedAluKind, byte] = [0x02'u8, 0x2A, 0x22, 0x0A, 0x32, 0x3A, 0x84]
  sizedAluOpcRM:  array[SizedAluKind, byte] = [0x03'u8, 0x2B, 0x23, 0x0B, 0x33, 0x3B, 0x85]
  sizedAluDigit:  array[SizedAluKind, int]  = [0, 5, 4, 1, 6, 7, 0]

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


proc genInstNodeX64(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstX64(n, ctx)

proc genStmtX64(n: var Cursor; ctx: var GenContext) =
  if atTag(n, StmtsTagId):
    loopInto n:
      genInstNodeX64(n, ctx)
  else:
    genInstNodeX64(n, ctx)

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
