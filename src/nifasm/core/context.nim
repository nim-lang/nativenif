#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `GenContext` — everything one assembly run carries, and nothing else.
##
## Nim has no cyclic imports, so the state the whole assembler threads through
## itself cannot live in any module that also *does* something with it: the
## instruction selectors, the type checker, the module loader and the image
## writers all need it, and they need each other. It therefore sits here, in a
## module that imports only what the record's own field types require and that
## nothing below it imports back. Every other module takes `ctx: var GenContext`
## as a parameter.
##
## `newGenContext` is the "plus some creation logic" half of that arrangement:
## the record has enough fields that constructing one in the caller invites the
## kind of divergence where two entry points initialise different subsets.

import std / [tables, sets]
import nifcore, nifmodules
import sem, stackslots, relocs
import "../image/dwarf"                 # ProcUnwind: the per-proc CFI the writers emit
import "../x64/encoder" as x86
import "../arm64/encoder" as arm64
from "../thumb/encoder" as thumb2 import nil
from "../avr/encoder" as avr import nil
from "../rv32/encoder" as rv32 import nil

const
  NoArgBaseReg* = x86.RSP
    ## Sentinel for `GenContext.argBaseReg`: rsp is never the destination of the
    ## incoming stack-args base capture, so it cannot collide with a real one.

const MainModuleName* = ""  # Special name for main module

const
  WinShadowSpace* = 32
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
  LoadedModule* = ref object
    ## A loaded module. The MAIN module is parsed whole into `buf` (local symbols
    ## carry a `declStart` token position into it). A FOREIGN module is opened
    ## lazily through the shared `nifmodules.ForeignModule`: only its embedded NIF
    ## `.index` (symbol → byte offset) is read up front; declarations are parsed
    ## one at a time on demand, by following a referenced name (nominal typing).
    ## The foreign handle keeps each lazily-parsed decl tree alive so the Cursors
    ## into it stay valid. (A `ref` so a handle stays valid even if `ctx.modules`
    ## rehashes while a decl body recursively pulls in further foreign modules.)
    buf*: TokenBuf                          # whole-module tree (main module only)
    foreign*: ForeignModule                 # lazy per-symbol loader (foreign only)
    loaded*: bool  # True if already loaded into scope

  Arch* = enum
    X64        # Linux x86-64 (ELF)
    LinuxA64   # Linux ARM64 (ELF)
    A64        # macOS ARM64 (Mach-O)
    WinX64     # Windows x86-64 (PE)
    WinA64     # Windows ARM64 (PE)
    CortexM    # Bare-metal ARMv7E-M / Cortex-M4 (ELF32 firmware image, no OS)
    Avr        # Bare-metal AVR / avr5 (ELF32 firmware image, no OS)
    Rv32       # Bare-metal RV32IMAFD / ilp32d (ELF32 firmware image, no OS)

  ImportedLib* = object
    name*: string     # Library path (e.g. "/usr/lib/libSystem.B.dylib")
    ordinal*: int     # Library ordinal (1-based index)

  ExtProcInfo* = object
    name*: string     # Internal name
    extName*: string  # External symbol name (e.g. "_write")
    libOrdinal*: int  # Which library (1-based)
    gotSlot*: int     # GOT slot index
    stubOffset*: int  # Offset in stub section
    callSites*: seq[int]  # Positions of BL instructions that call this proc

  CallContextState* = enum
    Disabled, NormalCall, ExternalCall

  CallContext* = object          ## Context for a `prepare` block - tracks call setup state
    state*: CallContextState
    callEmitted*: bool           # True after (call), (tailcall) or (extcall)
    isTailcall*: bool            # the marker was `(tailcall)`: control does not come
                                # back, so there is no result to bind
    target*: string              # Target proc/symbol name (a qualified name whose
                                # module suffix `lookupWithAutoImport` parses — string)
    typ*: Type                   # ProcT type (contains params, results, clobbers)
    extProcIdx*: int             # Index into extProcs for external calls
    argsSet*: HashSet[SymId]    # Arguments assigned (keyed by `Param.name`, an interned id)
    resultsSet*: HashSet[SymId] # Results bound (keyed by `Param.name`, an interned id)
    stackArgSize*: int           # Computed size of stack arguments (csize), INCLUDING
                                # `stackArgBase` — it is what the frame must reserve
    stackArgBase*: int           # Byte offset of the FIRST stack argument within the
                                # outgoing area: 0 normally, `WinShadowSpace` for a
                                # Win64 `extproc` call. Added to every `(arg pN)`
                                # offset, so caller and callee agree on where the
                                # 5th+ argument lives
    indirect*: bool              # Target is a function-pointer variable: `typ` is its
                                # proctype signature and `(call)` is an indirect call
                                # through the loaded pointer (vs a direct `call rel32`)
    isSyscall*: bool             # Target is a `syproc`: the invocation marker is
                                # `(syscall)`/`(svc)` (inlined kernel trap, no `call`),
                                # and `syscallNr` is loaded into rax/x8 before it
    syscallNr*: int

  ListingRow* = object
    ## One `genInst` call: the asm-NIF instruction node and the `.text` byte range
    ## it produced. `--listing:FILE` writes these after branch relaxation, so the
    ## positions are the ones in the finished image — which is what makes an
    ## execution profile joinable to the SOURCE construct (and, because arkham
    ## renders a bound register by its variable name, to the variable) rather than
    ## to a bare register number.
    start*, stop*: int    # `.text` byte range [start, stop)
    depth*: int          # `listDepth` at this node; deeper = nearer the machine
    procName*: string
    text*: string        # the node, rendered as NIF (capped, see ListingTextCap)

  GenContext* = object
    scope*: Scope        # Current (possibly proc-local) lexical scope
    rootScope*: Scope    # Module/global scope; foreign symbols are defined here so
                        # they persist past the proc that first referenced them
                        # (processReachableSymbols looks them up to emit bodies).
    buf*: relocs.Buffer  # Code buffer (.text section) for x64
    bssBuf*: relocs.Buffer  # BSS buffer (.bss section) for zero-initialized global variables
    arch*: Arch
    emitObj*: bool       # `--emit-obj`: write a relocatable MH_OBJECT for the system
                        # linker (foreign `.o`/framework linking) instead of a
                        # standalone executable. Mach-O / arm64 only for now.
    symMap*: bool        # `--symmap`: dump each generated proc's vaddr to stderr
    listing*: bool       # `--listing:FILE`: record one row per asm-NIF instruction node
    listingPath*: string # where to write it
    debugInfo*: bool     # emit `.symtab` + `.eh_frame` (default on). Both are
                        # non-`SHF_ALLOC` and outside every PT_LOAD, so they change
                        # neither the loaded image nor its behaviour — only the
                        # file size — and they are what lets a debugger name and
                        # unwind frames in code that keeps no frame pointer.
    listDepth*: int      # nesting depth of the current `genInst` (a compound node such as
                        # `(ite …)`/`(loop …)` recurses); the DEEPEST row covering a byte
                        # is the instruction that actually emitted it
    listRows*: seq[ListingRow]
    procName*: string
    callContext*: CallContext # Current call context
    clobbered*: set[x86.Register] # Registers clobbered in current flow (x64 only)
    clobberedA64*: set[arm64.Register]  # AArch64 counterpart: caller-saved registers a
                        # `(call)`/`(extcall)` destroyed on the current control-flow
                        # path. Reading a register-bound local that lives in one of
                        # these (a value the call silently overwrote) is rejected — the
                        # call-safety guarantee. Cleared when the register is rewritten;
                        # merged across `ite` branches.
    slots*: SlotManager
    ssizePatches*: seq[tuple[pos: int; pad: int]]
    unwind*: seq[ProcUnwind]       # per-proc name + code range + prologue CFI states,
                                  # for `.symtab` and `.eh_frame` (see dwarf.nim). Grown
                                  # by `pass2Proc`; every position in it is remapped by
                                  # the post-emission layout passes, exactly like
                                  # `gvarSites`.
    inPrologue*: bool              # still inside the current proc's prologue: the run of
                                  # pushes / frame `sub` whose CFA effects the FDE records.
                                  # `genInst` clears it at the first instruction that emits
                                  # code and is not one of those (a zero-byte node — a slot
                                  # declaration, a `kill` — is transparent).
    prologueOp*: bool              # the instruction just dispatched recorded a CFI step
    argBaseReg*: x86.Register      # x64 prologue only: the callee-saved register a
                                  # `mov <reg>, rsp` is capturing the incoming stack-args
                                  # base into. That capture and the `add <reg>, imm` that
                                  # follows it sit BETWEEN the pushes and the frame `sub`
                                  # (they must: the base is rsp after the pushes), so they
                                  # are prologue forms too — ending the run on them would
                                  # drop the frame `sub`'s CFI step and with it the frame
                                  # `add` that `(popframe)` replays. `NoArgBaseReg` when
                                  # no capture has been seen in this proc.
    cfaOff*: int32                 # CFA offset in effect at the current point of the prologue
    reservedArgArea*: int          # AArch64 fixed-frame: bytes reserved at the frame bottom
                                  # for the largest outgoing stack-argument area (see
                                  # scanStackArgArea). Locals sit above it; the caller writes
                                  # `(mem (sp)(arg pN))` with no per-call `sub sp`.
    csizePatches*: seq[(int, int)] # (position, callStackDepth) for csize patches
    gvarSites*: seq[(int, Symbol)] # (adrp position in .text, gvar symbol) for adrp+add patching
    board*: CortexMBoard           # the `(layout …)` arkham forwarded, when one was
                                  # given. Supersedes the memory-map flags.
    interrupts*: seq[(int, Symbol)]
                                  # Cortex-M: (architectural table slot, handler).
                                  # Filled from `(interrupts …)`; the image writer
                                  # bakes each address, Thumb bit set.
    mimgSites*: seq[(int, MimgKind)]
                                  # Cortex-M: (MOVW position in .text, which layout number).
                                  # Patched by `writeCortexMImage` for the same reason
                                  # `gvarSites` is — the value is a final-layout fact, and
                                  # the MOVW+MOVT pair it patches is a fixed 8 bytes
                                  # whatever the number turns out to be.
    tlvSites*: seq[(int, Symbol)]  # (adrp position in .text, tvar symbol) for TLV descriptor adrp+add patching (arm64/macOS)
    tlvSyms*: seq[Symbol]          # thread-local vars in descriptor order (arm64/macOS); sym.offset = descriptor index, sym.size = byte offset within the per-thread region
    tlvData*: seq[byte]            # the __thread_data init template (concatenated per-thread initial values, arm64/macOS)
    tlsOffset*: int  # Current TLS offset for thread-local variables (x86)
    bssOffset*: int  # Current offset in .bss section
    modules*: Table[string, LoadedModule]  # Cache of loaded foreign modules
    pool*: Pool          # The main module's literal/symbol pool. Foreign decls are
                        # interned into it too (getDecl is passed `ctx.pool`), so every
                        # cursor's `symId` is a valid key in this one pool and the scope
                        # can be keyed by `SymId` instead of the qualified-name string.
    baseDir*: string  # Base directory for finding module files
    thisModule*: string  # The module being assembled (symbol suffix of the main file);
                        # a `name.0.<thisModule>` reference is local, not foreign
    regBindings*: Table[x86.Register, string]  # Maps registers to variable names they're bound to (x64 only)
    mRegBindings*: Table[thumb2.Register, string]
                        # Cortex-M counterpart of `regBindings`: which Thumb register
                        # currently hosts a named local, so a raw `(r4)` use of a bound
                        # register is rejected as the silent clobber it is.
    clobberedM*: set[thumb2.Register]
                        # Cortex-M counterpart of `clobberedA64`: caller-saved registers
                        # a call destroyed, so reading one before rewriting it is an error.
    mFRegBindings*: Table[thumb2.FloatRegister, string]
                        # The FPv4-SP twin of `mRegBindings`: which s-register hosts a
                        # named float local or scratch temp.
    avrRegBindings*: Table[avr.Register, string]
                        # AVR counterpart of `regBindings`, and the one that is keyed
                        # by a HALF: a 16-bit local occupies a pair, so binding it
                        # records both r and r+1 under the same name. That is what lets
                        # a raw 8-bit `(r24)` use of a register the high half of some
                        # pair-typed local lives in be rejected — the case a table keyed
                        # by pairs could not see at all.
    clobberedAvr*: set[avr.Register]
                        # AVR counterpart of `clobberedM`: caller-saved registers a call
    rvRegBindings*: Table[rv32.Register, string]
                        # RV32 counterpart of `regBindings`: which integer register
                        # currently hosts a named local.
    rvFRegBindings*: Table[rv32.FloatRegister, string]
                        # …and its floating-point twin. One file serves both
                        # precisions on RISC-V, so `(d3)` and `(s3)` name the SAME
                        # entry here — which is why the width lives on the operand
                        # and not in the binding.
    clobberedRv*: set[rv32.Register]
                        # RV32 twin of `clobberedM`.
    pendingCmp*: PendingCmp
                        # RV32 only: the operands of a `(cmp …)`/`(fcmp …)` that has
                        # been READ but not yet emitted. RISC-V has no condition
                        # flags — its branches compare two registers on the spot —
                        # so a compare emits nothing and the branch that consumes it
                        # emits both. See `rv32/instr.nim`.
    a64RegBindings*: Table[arm64.Register, string]  # AArch64 counterpart of `regBindings`:
                        # which physical x-register currently hosts which variable name. A
                        # raw `(xN)` use of a bound register is rejected (use the name);
                        # `rebind`/`withreg` (re)bind it, killing the prior tenant.
    xmmBindings*: Table[x86.XmmRegister, string]  # SSE/float counterpart of `regBindings`
                        # (x64 only): which xmm register currently hosts which float
                        # variable name. A raw `(xmmN)` use of a bound register is rejected;
                        # `rebind`/`withreg` with a float type (re)bind it. Reset per proc.
    a64FRegBindings*: Table[arm64.FloatRegister, string]  # SIMD/fp counterpart of
                        # `a64RegBindings` (arm64 only): which v-register currently hosts
                        # which float variable name. A raw `(dN)`/`(sN)` use of a bound
                        # register is rejected; `rebind`/`withreg` with a float type
                        # (re)bind it. The precision (s/d) is recovered from the bound
                        # symbol's type. Reset per proc.
    # Dynamic linking
    imports*: seq[ImportedLib]  # Imported libraries
    extProcs*: seq[ExtProcInfo]  # External procs to bind
    gotSlotCount*: int  # Number of GOT slots allocated
    # Module system / dead code elimination
    pendingSymbols*: seq[string]  # Symbols pending code generation
    generatedSymbols*: HashSet[string]  # Symbols already generated
    dedupTable*: Table[string, string]  # Maps dedup key to canonical symbol name
    definedLabels*: HashSet[int]  # LabelIds of *local* labels already defined in the
                        # current proc (populated by (lab …), cleared per proc). A
                        # `jmp`/`jcc`/`b`/`bcc` whose target is in here is a BACKWARD
                        # jump — forbidden: back-edges must be expressed as (loop), so
                        # every emitted control-flow branch stays forward. The internal
                        # loop back-edge is emitted via emitJmp/emitB directly (it never
                        # passes through the instruction handlers), so it is exempt.
    # Thread-local storage (x86-64). nifasm owns the unified per-thread block
    # `arkham.tls.0` (sized for ALL bundled modules' tvars) and synthesizes the
    # entry prologue that points FS at it (`arch_prctl`). Nim thread-locals have no
    # initializers, so the block is just zeroed `.bss`.
    tlsBlockSym*: Symbol          # the synthetic `arkham.tls.0` gvar (FS base block)
    # The runtime stack-trace table (`doc/tracetable.md`): the same per-proc facts
    # `.eh_frame` carries, in a form the RUNNING PROGRAM can read — arkham lowers the
    # `traceTable` intrinsic to `lea D, arkham.traceinfo.0`, and `lib/std/stacktraces`
    # walks the stack with it. It is deliberately NOT gated on `debugInfo`: that flag
    # governs what a debugger reads from the file, this is a program feature, and a
    # program that asks for it must get it. Emitted only when something references
    # the symbol, so a program that never calls `getStackTrace` pays nothing.
    traceSym*: Symbol             # the synthetic `arkham.traceinfo.0` label
    traceLabel*: LabelId          # its label in `buf` — defined where the table lands
    traceUsed*: bool              # something referenced it, so `appendTraceTable` runs
    tlsSelfSym*: Symbol           # the synthetic `arkham.tls.self.0` thread-local at
                                  # offset 0: each thread's block holds its OWN address
                                  # there, which is how `&threadvar` is computed
                                  # (x86-64 has no FS-relative `lea`). Same idea as
                                  # the psABI TCB's self-pointer.
    tlsSizeSym*: Symbol           # the synthetic `arkham.tlssize.0` label: an 8-byte cell
                                  # holding how many bytes ONE thread's TLS block takes.
                                  # A thread the runtime creates needs its own block, and
                                  # only nifasm knows how big it ended up (`tlsOffset` is
                                  # final after the last module's tvars are allocated).
    tlsSizeLabel*: LabelId        # its label in `buf`
    tlsSizeUsed*: bool            # something referenced it, so `appendTlsSize` runs
    # ── Windows thread-locals ──
    # The PE target cannot use the FS block above: GS holds the TEB, whose layout
    # nifasm does not own. It uses the mechanism the loader already provides —
    # static TLS. `.tls` carries a TEMPLATE of one thread's block; the loader
    # copies it for every thread the process ever creates (`CreateThread` included)
    # and leaves a pointer to that copy in
    # `TEB->ThreadLocalStoragePointer[*AddressOfIndex]`. So `&threadvar` is
    #     gs:[0x58]  →  [+ arkham.tlsindex.0 * 8]  →  + the tvar's offset
    # and nothing has to run per thread. See `setupTlsWin`.
    winTlsTemplate*: seq[byte]    # one thread's block as it starts out: `tlsOffset`
                                  # bytes with every `tlsInits` literal baked in
    winTlsIndexSym*: Symbol       # `arkham.tlsindex.0`, the 8-byte `.bss` cell the
                                  # loader fills with this image's TLS index. Eight
                                  # and not four so arkham can load it with an
                                  # ordinary 64-bit `mov`: the loader writes only the
                                  # low DWORD and the slot starts zeroed, so the high
                                  # half stays 0 and the value needs no extension.
    winTebTlsPtrSym*: Symbol      # `arkham.teb.tlsptr.0` — not a variable at all but
                                  # the fixed TEB field `gs:0x58`, spelled as a tvar
                                  # so the existing segment-operand path encodes it
                                  # (`Symbol.gsFixedSlot`).
    entrySym*: Symbol             # the entry proc (`_start`/`main.0`) — prologue jumps here
    entryStubOffset*: int          # .text offset of the synthesized ELF entry stub, or -1.
                                  # x86-64: the FS-setup prologue (setupTls); AArch64:
                                  # the argc/argv/envp prologue (setupLinuxA64Entry).
                                  # Both tail-jump to `entrySym`.
    winEntryOffset*: int          # .text offset of the synthesized PE entry stub, or -1
                                 # (see setupWinEntry — the Windows counterpart of the
                                 # FS-setup prologue: it supplies `main`'s arguments,
                                 # which the OS does not put anywhere it can find them)
    # A gvar with a compile-time constant scalar initializer is laid out as static
    # data: arkham emits its bits as the gvar value, and these are written into the
    # (writable) `.bss` image on disk so the slot starts with that value (correct in
    # a bundle, where a foreign module's entry-time initializer never runs).
    bssInits*: seq[tuple[off: int64, val: int64, size: int]]  # (.bss byte offset, value, size)
    # The same, for a THREAD-LOCAL's literal initializer, keyed by the tvar's
    # displacement inside the unified block. The block's own `.bss` offset is only
    # known once every tvar has one (`setupTls`), which is where these fold into
    # `bssInits`. x86-64 only — macOS/arm64 bakes a tvar initializer into the
    # `__thread_data` template instead (see `generateSymbol`).
    tlsInits*: seq[tuple[off: int64, val: int64, size: int]]
    # A gvar whose initializer is a *symbol address* (e.g. a function-pointer hook
    # like `gExitFlush = nimNoopFlush`): the target's absolute vaddr isn't known
    # until layout, so record (slot offset, target symbol) and bake the resolved
    # address into the `.bss` image in `writeElf` (after `finalize`). Without this
    # the slot stays zero and an indirect `call` through it jumps to address 0.
    bssSymInits*: seq[tuple[off: int64, sym: Symbol, size: int]]  # (.bss byte offset, target symbol, size)
    # A `const` read-only data blob (e.g. a vtable/RTTI table) with fields that are
    # *symbol addresses* (a pointer to another const, or a proc address). The blob
    # lives in `.text` at its rodata label; the target's vaddr isn't known until
    # layout, so record (rodata label id, byte offset within the blob, target
    # symbol) and bake the resolved address into `code` in `writeElf`.
    rodataSymInits*: seq[tuple[labelId: int, blobOff: int, sym: Symbol, size: int]]
    # Mach-O counterpart of `rodataSymInits` for a `dataConst` blob (one that lives
    # in writable __DATA, not __TEXT): the blob is rebased by dyld, so we record the
    # owning const, the byte offset of the pointer field within it, and the target
    # symbol. At `writeMachO` time these become (`__DATA` field offset, target vaddr)
    # pairs: the target's preferred vaddr is baked in and a dyld rebase opcode slides
    # it. Targets in __TEXT and __DATA are both supported.
    rodataRebases*: seq[tuple[owner: Symbol, blobOff: int, target: Symbol]]

  OperandKind* = enum
    ## What an operand IS, before any target says how to encode it: the x64,
    ## AArch64 and Thumb operand records all classify themselves with this.
    okReg       # Register operand
    okImm       # Immediate value
    okMem       # Memory operand
    okSsize     # Stack size placeholder (patched later)
    okCsize     # Call stack argument size
    okMimg      # Cortex-M: one of the four image-layout numbers (patched later)
    okArg       # Argument reference in prepare block
    okLabel     # Label reference

  PendingCmp* = object
    ## A `(cmp A B)` that has been read and deliberately NOT emitted.
    ##
    ## Every other target here sets condition flags and branches on them later.
    ## RISC-V has no flags at all: `beq`/`bne`/`blt`/`bge`/`bltu`/`bgeu` each take
    ## two source registers and compare them on the spot, so the pair `cmp` +
    ## branch is ONE instruction and the compare has nothing of its own to emit.
    ##
    ## `at` is the buffer length when the compare was recorded. Consuming a
    ## condition checks it: arkham always emits a compare IMMEDIATELY before the
    ## branch that reads it, and if anything emitted bytes in between, the recorded
    ## registers may no longer hold what was compared. That is a wrong answer
    ## rather than a crash, so it is checked rather than assumed. Declarations
    ## (`(cfvar …)`, `(var …)`) emit no bytes and are therefore transparent, which
    ## is what lets `(cmp …) (cfvar …) (ite (zf) …)` work.
    live*: bool
    isFloat*: bool          ## the pending compare was `(fcmp …)`
    at*: int                ## buffer length when it was recorded
    lhs*, rhs*: rv32.Register
    flhs*, frhs*: rv32.FloatRegister
    width*: rv32.FpWidth    ## for a float compare
    node*: Cursor           ## where it was written, for the diagnostic

  CortexMBoard* = object
    ## The board, reduced to what PLACEMENT needs. Derived from `(layout …)`; see
    ## `handleLayout`.
    given*: bool
    flashStart*, flashSize*: uint32
    sramStart*, sramSize*: uint32
    slots*: int
    slotSize*, tvarSize*: uint32
    heapSize*: uint32
    noinitSize*: uint32
    core*: int

  MimgKind* = enum
    ## The four numbers the Cortex-M startup code needs and only the IMAGE WRITER
    ## knows: where `.data`'s initializer image was placed in flash, where it
    ## belongs at run time, and how many bytes of each region there are. They are
    ## nifasm's own layout, exactly as `(ssize)` is nifasm's own frame — which is
    ## why they are numbers arkham asks for rather than numbers arkham computes.
    mikDataLoad     # LMA: the flash address the initializer image sits at
    mikDataVma      # VMA: the SRAM address `.data` occupies at run time
    mikDataSize     # bytes to copy from the LMA to the VMA
    mikBssSize      # bytes to zero, immediately above VMA + dataSize
    mikHeapStart    # the heap the board layout reserved
    mikHeapSize     # and how many bytes of it there are
    mikNoinitStart  # the region the startup code was told to leave alone
    mikNoinitSize   # and how many bytes of THAT there are


# ── reading the record ───────────────────────────────────────────────────────

proc inCall*(ctx: GenContext): bool {.inline.} =
  ## Returns true if we're inside a prepare block
  ctx.callContext.state != CallContextState.Disabled

template nameOf*(ctx: GenContext; s: SymId): string =
  ## Render a `SymId` back to its qualified name string (for the foreign-index
  ## lookup, dedup keys, diagnostics and extern emission — the genuine string sinks).
  poolSym(ctx.pool, s)

template symIdOf*(ctx: GenContext; s: string): SymId =
  ## Intern a qualified name into the main pool, yielding its scope key. Cheap for a
  ## name already interned (parsing interned every symbol) — a single hash + probe.
  ctx.pool.syms.getOrIncl(s)

proc newGenContext*(mainPool: Pool; baseDir, thisModule: string;
                    symMap, emitObj, debugInfo: bool; listing: string): GenContext =
  ## One assembly run's state, with every table and sequence already live and the
  ## two "no stub yet" offsets at their sentinel. `scope` and `rootScope` start as
  ## the SAME scope: a foreign symbol resolved inside a proc has to outlive that
  ## proc (`processReachableSymbols` looks it up again to emit the body), so the
  ## module scope is where it is defined.
  let scope = newScope()
  result = GenContext(
    scope: scope,
    rootScope: scope,
    buf: initBuffer(),
    bssBuf: initBuffer(),
    tlsOffset: 0,
    bssOffset: 0,
    modules: initTable[string, LoadedModule](),
    pool: mainPool,
    baseDir: baseDir,
    thisModule: thisModule,
    imports: @[],
    extProcs: @[],
    gotSlotCount: 0,
    pendingSymbols: @[],
    generatedSymbols: initHashSet[string](),
    dedupTable: initTable[string, string](),
    entryStubOffset: -1,
    winEntryOffset: -1,
    symMap: symMap,
    listing: listing.len > 0,
    listingPath: listing,
    emitObj: emitObj,
    debugInfo: debugInfo)
