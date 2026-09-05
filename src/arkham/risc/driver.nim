#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `generateA64` and `generateM` — a Leng module in, Arm asm-NIF out.
##
## One emitter, three targets. What `generateM` does differently is not a
## different instruction selector: it is a different machine model, a 4-byte
## word, a synthesized reset path, and an honest refusal by name for the
## features Cortex-M does not have (`rejectForThumbM`). A second emitter would
## have had to reimplement the register-binding protocol, which is the part with
## a formal model behind it (`proofs/arkham_bindings.tla`).

import std / [assertions, tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, analyser, planer, programs, asmbuf,
                    context, diag, typeutil, constdata,
                    regbind, 
                    layout, stress]
import "../risc/machine_a64" as machine
from "../risc/machine_m" as machine_m import nil
import "../risc/machine_rv32" as machine_rv32
import emit, value, frame, stmt, asmproc
import runtime

proc genProc2(g: var CodeGen; info: ProcInfo) =
  when defined(arkhamTraceProcs):
    stderr.writeLine "arkham genProc2: " & info.asmName
  if info.isAsm:
    g.genAsmProc2(info)
    return
  if info.isNaked:
    # An allocated body assumes a frame everywhere: a spill goes to an `(s)` slot,
    # a call needs the outgoing-argument area, a stack-passed parameter is read
    # relative to it. Removing the prologue under that does not produce a smaller
    # proc, it produces a wrong one — so `{.naked.}` is only ever legal where
    # every location is declared.
    lengError info.decl, "`{.naked.}` requires `{.assembler.}`: without a frame " &
              "the register allocator has nowhere to spill", lengInfo(info.decl)
  if not g.cleanSigComputed:                   # compute the clean-signature set once
    g.cleanSigProcs = cleanSigProcNames(g.prog)
    g.noReturnProcs = noReturnProcs(g.prog)
    g.cleanSigComputed = true
  let an = analyseProc(g.buf[], info.decl, g.tvarNames,
                       cleanCallees = g.cleanSigProcs,
                       procIsClean = isCleanSigProc(g.prog, info.decl),
                       noReturnCallees = g.noReturnProcs)
  g.varType.clear()
  g.symType.clear()
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.loopEnds = @[]
  g.savedHomes.clear()
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc
    g.retIsVoid = rc.kind == DotToken            # `(proc :f (params …) . (pragmas …) …)`
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrSym = rc.symId
      # The indirect-result rule stated in WORDS, matching
      # `slots.classifyResult`'s `> 2*wordSize()`: an aggregate result wider than
      # two words is written through a caller-supplied pointer. 16 on the 64-bit
      # targets, 8 on Cortex-M — one rule, not two constants that can drift.
      g.retIndirect = aggrByteSize(g.prog, g.retAggrSym) > 2 * wordSize()
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  # The register reserved for a hidden result POINTER. AArch64 parks it in x19,
  # the first callee-saved; Cortex-M's first callee-saved is r4. Reading it off
  # `g.md` rather than naming a constant is what keeps the two in step.
  let indirectHome = if g.md.intCalleeSaved.len > 0: g.md.intCalleeSaved[0] else: NoReg
  let preseal = if g.retIndirect: {indirectHome} else: {}
  block:                                            # pre-fill symType for allocation-time getType
    var pc = info.decl
    pc.into:
      inc pc
      if pc.kind == TagLit:
        var p = pc
        p.into:
          while p.hasMore: (g.recordVarType2(p); skip p)
      skip pc; skip pc; skip pc
      if pc.stmtKind == StmtsS: g.recordSymTypes2(pc)
      while pc.hasMore: skip pc
  # The pre-pass allocates HOMES only (decl walk); every expression decision is
  # made inline by the fused emitters at the point of emission. The `(at base
  # idx scratch)` stride scratch is a pick-time reservation inside the fused
  # lvalue walk (emitLvalWalk → ra.aux memo).
  g.pickedRegs = {}
  g.pickedFRegs = {}
  g.rawHomeRegs = {}
  g.emitTmpSpills = 0
  # `g.md`, not a constant: this emitter serves AArch64 AND Cortex-M, and handing
  # the allocator the wrong register file is not a compile error — it silently
  # assigns registers the target does not have.
  g.plan = allocateProc(g.buf[], info.decl, an, g.prog, g.md, g.md, g.typeCtx, preseal)
  if g.retIndirect:
    g.indirectReg = indirectHome
    g.plan.usedCallee.incl indirectHome
  # fp/lr only when a `bl` exists. An atomic is an
  # instruction now, not a call, so a CAS loop no longer drags a frame onto an
  # otherwise-leaf hot path (rawDealloc and friends) — that is what `hasCall` says.
  # (The frame itself is finalized INSIDE emitProcBody2, after the body —
  # body-buffer model.)
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  g.rb.resetProc(); g.aliasToDecl.clear(); g.savedHomes.clear()
  g.noFoldPos = -1
  g.curProcName = info.asmName            # names the proc in this backend's diagnostics
  # Can an address into THIS frame exist at all? Only a stack-homed symbol has one, and
  # a tail call gives the frame back BEFORE it branches. The x64 twin in `driver.nim`
  # spells out why the syntactic `tailCallLeaksFrame` alone is not enough.
  g.frameIsAddressable = false
  for pos in g.plan.symPos.values:
    if g.plan.planned(pos).kind == NamedStack:
      g.frameIsAddressable = true
      break
  g.helperCalls = false
  g.isInterrupt = info.irqName.len > 0 and g.md.arch == Rv32
  when defined(arkhamBridgeDbg):
    dbgPeakBridges = 0
    dbgPeakHeldAtRecursion = 0
    tightCompositions = 0
    lastResortTakes = 0
  g.emitProcBody2(info, declarative, frameHasCall = an.hasCall)
  when defined(arkhamBridgeDbg):
    stderr.writeLine "BRIDGE peak=" & $dbgPeakBridges & " heldAtRecursion=" &
                     $dbgPeakHeldAtRecursion & " tight=" & $tightCompositions &
                     " lastResort=" & $lastResortTakes &
                     " " & g.curProcName

proc genType*(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(type :name <translated body>)` — a top-level type definition that
  ## nifasm's stack-slot allocator consults for aggregate field offsets.
  var c = decl
  c.into:                                     # (type SymbolDef TypePragmas body)
    inc c                                     # name
    skip c                                    # TypePragmas (one slot: `.` or (pragmas …))
    g.ab.tree TypeD:
      g.ab.symDef name
      g.genTypeBody(c)

proc genGlobal*(g: var CodeGen; nifName: string; decl: Cursor) =
  ## Emit a top-level `const`/`gvar`. A true `const` with a value becomes a
  ## read-only `.text` data blob; a `gvar` with a compile-time-constant SCALAR
  ## initializer is laid out as static `.bss`-image data (so it is correct even for
  ## a FOREIGN module's gvar in a bundle, whose entry-time `emitGlobalInits` never
  ## runs — and for a `var` later mutated). Any other (runtime) initializer is a
  ## zeroed slot filled at entry by `emitGlobalInits`.
  # An importc-WITHOUT-exportc gvar names an external (its slot is an `exportc`
  # definition in another bundled module): emit NO slot — references resolve to the
  # bare C name via `emGlobalAddr`. An exportc gvar IS the definition, emitted under
  # that bare C name so importc references in other modules link to it.
  if nifName in g.prog.importcOnlyGvars: return
  let name = g.prog.gvarAsmName(nifName)
  var c = decl
  let isConst = c.stmtKind == ConstS
  c.into:                                     # (gvar SymbolDef VarPragmas Type Value?)
    inc c                                     # name
    skip c                                    # pragmas
    let typeCur = c
    skip c                                    # type
    let hasValue = c.hasMore and c.kind != DotToken
    if isConst and hasValue:
      var bytes = ""
      var relocs: seq[(int, string)] = @[]
      constToBytes(g.prog, typeCur, c, bytes, relocs)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
        for (off, sym) in relocs:               # symbol-address fields (vtable/RTTI)
          g.ab.tree RelocX:
            g.ab.intLit off
            g.ab.sym sym
    else:
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                       # type
      g.genGlobalInitValue(name, typeCur, c, hasValue)
      g.ab.close()
    while c.hasMore: skip c                   # value (runtime inits done at entry)

proc genTvar*(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(tvar :name <type> <intlit>?)` — a thread-local variable. A literal
  ## initializer is baked into the per-thread template dyld copies on first
  ## access; non-literal initializers are unsupported (a thread-local is
  ## per-thread, so the entry-time `emitGlobalInits` path cannot serve them).
  ##
  ## THE one place the single-thread question is asked. Everything downstream —
  ## every `(adr …)` that reaches the variable — is the same tree either way, so
  ## deciding here decides everything, and a stdlib that wants a thread-local
  ## gets to say so on every target rather than conditioning its own source on
  ## which one it is being built for.
  var c = decl
  c.into:                                     # (tvar SymbolDef VarPragmas Type Value?)
    inc c                                     # name
    skip c                                    # pragmas
    if g.oneThread:
      # One thread of execution — a static ELF (per-thread == per-process) or a
      # board with a single stack slot: emit the thread-local as a plain `.bss`
      # global (no Darwin TLV template, no per-core storage). Its access routes
      # through the ordinary global address path; a compile-time-constant scalar
      # initializer is baked as static `.bss`-image data (correct cross-module),
      # any other initializer is stored at entry by `emitGlobalInits`.
      let typeCur = c
      skip c                                  # type
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                       # type
      if c.hasMore and c.kind != DotToken and isConstScalarInit(c):
        g.ab.intLit cast[int64](constLitBits(c))
      g.ab.close()
      while c.hasMore: skip c                 # value (runtime inits done at entry)
      return
    g.ab.open NifasmDecl.TvarD
    g.ab.symDef name
    g.genTypeBody(c)                          # type
    if c.kind == IntLit:
      g.ab.intLit intVal(c)                   # literal initializer → TLV template
    elif c.kind != DotToken:
      raiseAssert "arkham: thread-local initializer must be an integer literal: " & name
    g.ab.close()
    while c.hasMore: skip c

proc rejectForThumbM(g: var CodeGen) =
  ## Everything the Cortex-M target does NOT have, refused by name at the module
  ## level before a single instruction is emitted. Each of these would otherwise
  ## reach an AArch64-shaped emitter and produce something plausible and wrong.
  if g.prog.tvars.len > 0 and not g.oneThread:
    # A board with more than one stack slot has more than one thread, and each
    # needs its own copy. The mechanism the layout was designed around is in
    # place on the nifasm side — `(stacks (slots N) (bytes S) (tvar (bytes T)))`
    # reserves T bytes at the top of every slot, and `S` is a power of two
    # precisely so a thread reaches its own by masking SP — but arkham does not
    # yet emit that masked base at a reference, and nifasm does not yet allocate
    # offsets within the reservation. Refusing here is the honest report; what is
    # missing is the addressing, not the target's ability to have threads.
    quit "arkham cortex-m: this board declares " & $g.board.slotCount &
         " stack slots, so a thread-local needs one copy per thread — and the " &
         "SP-masked thread-local base that would reach it is not implemented " &
         "yet. Declare `(stacks (slots 1) …)` for a single-core image, where a " &
         "thread-local IS a global."
  if g.prog.externOrder.len > 0:
    quit "arkham cortex-m: `importc` of \"" & g.prog.externOrder[0].extName &
         "\" cannot be satisfied — a firmware image has nothing to link against."

proc generateM*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                board = layout.Layout()): string =
  ## Compile a parsed Leng module to Cortex-M (ARMv7E-M) asm-NIF, which nifasm's
  ## `cortex_m` target assembles into a bare-metal firmware image.
  ##
  ## This is the AArch64 emitter driven with a different machine model, not a
  ## second code generator. The two targets share the asm-NIF vocabulary by
  ## design — `add3`, `cmp`, `beq`, `ldr`, `adr` mean the same thing on both — so
  ## what a third backend actually needs is the register file, the word size, and
  ## an honest refusal for the features Cortex-M lacks. Reimplementing the fused
  ## value core would mean reimplementing its register-binding protocol, which is
  ## the part with a formal model behind it (proofs/arkham_bindings.tla).
  setTargetWord Word32             # 4-byte pointers, 4-byte platform int
  var g = newCodeGen(buf, stressed(machine_m.cortexMMachine))
  g.thumbM = true
  g.entryExits = true
  g.board = board
  # A board that declares one stack slot has one thread; so does an image with no
  # board file at all, which declares no stacks and therefore no second thread for
  # anything to run on.
  g.oneThread = not board.given or board.slotCount <= 1
  g.ab.renderReg = machine_m.regNameM        # `(r0)`..`(r12)`/`(sp)`/`(lr)`
  g.ab.arch = "m"                  # no BodyLib entries apply to this target yet
  g.prog = collect(buf, inputPath, tags, darwin = false)
  g.rejectForThumbM()
  g.adoptProgram()
  g.ab.tree StmtsA64:
    g.ab.tree ArchD: g.ab.ident "cortex_m"
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)             # one thread here, so each becomes a gvar
    g.emitSemihostExitProc(EntryExitShim) # the entry's tail-call target, always
    if g.prog.syscalls.len > 0:
      # The `write` shim's console handle and the `:tt` device name it opens.
      # Emitted whenever any shim is, rather than tracked: one word of .bss and
      # four bytes of rodata is not worth a flag.
      g.ab.tree RodataD:
        g.ab.symDef g.semiTtyName
        g.ab.str ":tt\0"
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef g.semiTtyHandle
      g.ab.intType(32)
      g.ab.intLit 0
      g.ab.close()
    for sp in g.prog.syscalls:            # semihosting shims, called like any proc
      g.emitSemihostRuntime(sp)
    # The board, forwarded for nifasm to place segments from — with every size
    # NORMALIZED TO BYTES. The units are a convenience for whoever writes the
    # file (`(kilobytes 8)` is what a datasheet says); a second reader that has to
    # redo the multiplication is a second chance to get it wrong.
    if g.board.given:
      g.ab.tree NifasmDecl.LayoutD:
        g.ab.tree NifasmDecl.FlashD:
          g.ab.tree StartAddressX: g.ab.intLit int64(g.board.flashStart)
          g.ab.tree BytesX: g.ab.intLit int64(g.board.flashSize)
        g.ab.tree NifasmDecl.SramD:
          g.ab.tree StartAddressX: g.ab.intLit int64(g.board.sramStart)
          g.ab.tree BytesX: g.ab.intLit int64(g.board.sramSize)
        g.ab.tree NifasmDecl.StacksD:
          g.ab.tree SlotsX: g.ab.intLit int64(g.board.slotCount)
          g.ab.tree BytesX: g.ab.intLit int64(g.board.slotSize)
          g.ab.tree TvarX:
            g.ab.tree BytesX: g.ab.intLit int64(g.board.tvarSize)
        if g.board.heapSize > 0:
          g.ab.tree NifasmDecl.HeapD:
            g.ab.tree BytesX: g.ab.intLit int64(g.board.heapSize)
        if g.board.noinitSize > 0:
          g.ab.tree NifasmDecl.NoinitD:
            g.ab.tree BytesX: g.ab.intLit int64(g.board.noinitSize)
        g.ab.tree NifasmDecl.CoreD: g.ab.intLit int64(g.board.core)
    # The interrupt table, as slots rather than names: WHICH slot a name denotes
    # is the machine model's answer (`machine_m.interruptSlot`), and nifasm's job
    # is to place an address in a word — so the name is resolved here and never
    # leaves. Emitted before the bodies only so it reads first; it is a
    # declaration and its position in the module carries no meaning.
    var handlers: seq[(int, string)] = @[]
    for info in g.prog.procs:
      if info.irqName.len == 0: continue
      let slot = machine_m.interruptSlot(info.irqName)
      if slot < 0:
        quit "arkham cortex-m: `" & info.irqName & "` is not an interrupt of " &
             "this target. Expected one of NMI, HardFault, MemManage, BusFault, " &
             "UsageFault, SVCall, DebugMon, PendSV, SysTick, or IRQ<n>."
      for (s, other) in handlers:
        if s == slot:
          quit "arkham cortex-m: interrupt `" & info.irqName & "` is claimed by " &
               "both " & other & " and " & info.asmName &
               " — a table word holds one address."
      handlers.add (slot, info.asmName)
    if handlers.len > 0:
      g.ab.tree NifasmDecl.InterruptsD:
        for (slot, nm) in handlers:
          g.ab.tree NifasmDecl.IrqD:
            g.ab.intLit int64(slot)
            g.ab.sym nm
    for info in g.prog.procs:
      genProc2(g, info)
    # AFTER the bodies: whether anything divides is only known once they are
    # emitted. A firmware image has no `libgcc` to borrow `__aeabi_ldivmod`
    # from, so it carries its own — once, and only if used.
    if g.needsUDiv64: g.emitUDivMod64()
    if g.needsSDiv64: g.emitSDivMod64()
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)

proc rv32InterruptTable(g: var CodeGen) =
  ## `(interrupts (irq <cause> <handler>)*)` for RV32 — the same declaration
  ## Cortex-M emits, carrying a different number.
  ##
  ## The slot is a trap CAUSE here, not a word index into a table of addresses:
  ## `mtvec` in vectored mode sends cause `c` to `base + 4*c`, and a word there
  ## has to be an INSTRUCTION. Which name denotes which cause stays a machine
  ## model question (`machine_rv32.interruptCauseRv`), exactly as it is on
  ## Cortex-M, so the name is resolved here and never reaches nifasm.
  var handlers: seq[(int, string)] = @[]
  for info in g.prog.procs:
    if info.irqName.len == 0: continue
    let cause = machine_rv32.interruptCauseRv(info.irqName)
    if cause < 0:
      quit "arkham rv32: `" & info.irqName & "` is not an interrupt of this " &
           "target. Expected one of MachineSoftware, MachineTimer or " &
           "MachineExternal — the three M-mode interrupts of the privileged " &
           "spec. Supervisor and user modes do not exist in an image that never " &
           "leaves M-mode, and an EXCEPTION (a misaligned load, an illegal " &
           "instruction) is reached through mtvec's other mode, not this table."
    for (c, other) in handlers:
      if c == cause:
        quit "arkham rv32: interrupt `" & info.irqName & "` is claimed by both " &
             other & " and " & info.asmName &
             " — a table word holds one jump."
    handlers.add (cause, info.asmName)
  if handlers.len > 0:
    # The declaration is what makes nifasm mark each handler USED: nothing CALLS
    # one, so the reachability walk would otherwise drop it and leave the table
    # jumping at a proc that was never emitted. Its Cortex-M meaning — build a
    # table of addresses — does not apply here and `writeRv32Image` ignores it.
    g.ab.tree NifasmDecl.InterruptsD:
      for (cause, nm) in handlers:
        g.ab.tree NifasmDecl.IrqD:
          g.ab.intLit int64(cause)
          g.ab.sym nm
    g.emTrapTableRv(handlers)
    for (cause, _) in handlers: g.rvIrqCauses.incl uint8(cause)

proc generateRv32*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                   board = layout.Layout()): string =
  ## Compile a parsed Leng module to RV32IMAFD asm-NIF, which nifasm's `riscv32`
  ## target assembles into a bare-metal firmware image.
  ##
  ## The same emitter again, driven by a fourth machine model — which is what the
  ## whole `risc/` directory exists to make possible. 75 of the mnemonics it
  ## writes are the same tag id here as on AArch64, and everything the ISAs
  ## genuinely disagree about is a `TargetFeature` this model answers rather than
  ## a branch on which target is being emitted.
  setTargetWord Word32             # 4-byte pointers, 4-byte platform int
  var g = newCodeGen(buf, stressed(machine_rv32.rv32Machine))
  g.entryExits = true              # bare metal: the entry cannot RETURN, because
                                   # `ra` at reset holds no valid address
  g.board = board
  g.oneThread = not board.given or board.slotCount <= 1
  # Where the reset path points `sp`. From the board when there is one; otherwise
  # the top of QEMU `virt`'s SRAM region, which is the default `writerv32.nim`
  # lays out against. The two MUST agree — a stack pointer above the region the
  # image declares is not a diagnosable error, it is a store into nothing.
  g.rvStackTop = if board.given: int64(board.sramStart) + int64(board.sramSize)
                 else: Rv32DefaultStackTop
  g.ab.renderReg = machine_rv32.regNameRv     # `(x0)`..`(x30)`/`(sp)`
  g.ab.arch = "rv32"               # no BodyLib entries apply to this target yet
  g.prog = collect(buf, inputPath, tags, darwin = false)
  # No `rejectForRv32` twin of Cortex-M's declaration-time refusals: RV32IMAFD
  # has both float precisions, hardware divide and self-ordering atomics, so what
  # it lacks is refused per intrinsic (`BitScanOps`, narrow atomics) instead.
  g.adoptProgram()
  g.ab.tree StmtsA64:
    g.ab.tree ArchD: g.ab.ident "riscv32"
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)             # one thread here, so each becomes a gvar
    g.emitSemihostExitProc(EntryExitShim) # the entry's tail-call target, always
    if g.prog.syscalls.len > 0:
      g.ab.tree RodataD:
        g.ab.symDef g.semiTtyName
        g.ab.str ":tt\0"
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef g.semiTtyHandle
      g.ab.intType(32)
      g.ab.intLit 0
      g.ab.close()
    for sp in g.prog.syscalls:            # semihosting shims, called like any proc
      g.emitSemihostRuntime(sp)
    g.rv32InterruptTable()                # before the bodies only so it reads first
    for info in g.prog.procs:
      genProc2(g, info)
    if g.needsUDiv64: g.emitUDivMod64()
    if g.needsSDiv64: g.emitSDivMod64()
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)

proc generateA64*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                  linux = false): string =
  ## Compile a parsed Leng module to AArch64 asm-NIF text — Darwin/Mach-O by
  ## default, or Linux/ELF when `linux` (svc-based syscalls, static, no dyld/TLV),
  ## which `nifasm`'s `linux_arm64` target assembles to a qemu-runnable ELF.
  ## `inputPath` and `tags` let the program model load *other* modules on demand
  ## to resolve cross-module symbols (`Foo.0.othermod`).
  setTargetWord Word64             # AArch64: 8-byte pointers, 8-byte platform int
  var g = newCodeGen(buf, aarch64MachineA)
  g.a64Linux = linux
  g.entryExits = linux
  g.oneThread = linux
  g.ab.arch = "a64"                # BodyLib entries this target may splice
  g.prog = collect(buf, inputPath, tags, darwin = not linux)
  g.adoptProgram()
  g.ab.tree StmtsA64:
    g.ab.tree ArchD: g.ab.ident (if linux: "linux_arm64" else: "arm64")
    if not linux:
      # Darwin: thread-local vars resolve their TLV descriptor thunk against
      # libSystem (`__tlv_bootstrap`), so the dylib must be loaded even without
      # extern calls. Each extern is a dynamic import. (On Linux all externs lower
      # to `svc` syscalls — the static ELF needs no imports.)
      if g.prog.needsLibSystem or g.tvars.len > 0:
        g.ab.tree ImpD: g.ab.str DarwinLibSystem
      for ex in g.prog.externOrder:
        g.ab.tree ExtprocD:
          g.ab.symDef ex.asmName
          g.ab.str ex.extName
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)
    for sp in g.prog.syscalls:                  # one `(syproc …)` per used syscall
      g.emitSyprocA64(sp)
    for info in g.prog.procs:
      genProc2(g, info)
    # NOTE: foreign types are NOT emitted here. arkham loads other modules only to
    # resolve their layout for *its own* codegen (sizing, field offsets, ABI). The
    # actual cross-module linking is nifasm's job: a module-suffixed symbol like
    # `Foo.0.othermod` makes nifasm auto-import `othermod.asm.nif` (which arkham
    # produced when it compiled that module). Emitting the decl inline is ignored.
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
