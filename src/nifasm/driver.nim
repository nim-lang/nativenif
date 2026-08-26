#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `assemble` — the whole run, end to end.
##
## Read the module, pass 1 over its declarations, pass 2 over the reachable
## bodies, then hand the finished buffer to whichever image writer the target
## calls for. Dead-code elimination falls out of the order: only a symbol
## something referenced is ever given a body (`processReachableSymbols`), so a
## bundled module contributes exactly what is used of it.
##
## The synthesized entry stubs live here too — the FS-setup prologue on x86-64,
## the argc/argv/envp one on Linux/AArch64, the argument-supplying one on
## Windows. They are nifasm's own code rather than any module's, which is why
## they are built after every real proc has been emitted.

import std / [tables, sets, os]
import nifcore, nifcoreparse, nifmodules
import "../../../nimony/src/lib" / [nifreader]
import core / [context, sem, cursors, typesem, modules, 
               tags, model, tagconv, decls, tagpool, stackslots, relocs,
               buffers]
import x64/encoder as x86
import arm64/encoder as arm64
from image/elf32 as elf32 import nil
import image / [dwarf, tracetable]
import image / [writecommon, writeelf, writemacho, writepe, writecortexm]
import pass1, pass2

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
    of Arch.Avr:
      # Unreachable while `genInst` refuses the target: no instruction can have
      # been selected, so there is nothing to write. Named rather than folded
      # into another arm so that M2 has one place to fill in.
      quit "nifasm: the AVR image writer is not implemented yet " &
           "(M2 in doc/internals/avr.md)"

  # Close all foreign-module readers (the main module has no reader).
  for modname, module in ctx.modules.mpairs:
    if modname != MainModuleName and module.foreign != nil:
      nifreader.close(module.foreign.r)
