#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## arkham's *program* model over the nifcore API — the nifcore analog of
## nimony's `programs.nim` (and leng's `nifmodules.nim`). A Leng name can refer
## to a declaration in **another module**: a mangled symbol like
## `Color.0.othermod` carries its defining module's suffix (`othermod`). This
## module manages that — it scans the main module's top level (`collect`) and
## lazily **loads foreign modules on demand** to resolve cross-module type
## references, keeping their buffers alive so cursors into them stay valid.
##
## All type-name resolution and size/layout queries (`lookupType`, `resolveType`,
## `slotOf`, `typeSizeAlign`, `aggrLayout`, …) route through the `Program`, so a
## named type defined in any module classifies correctly (e.g. a cross-module
## `enum` parameter is a scalar in a register, not a stack aggregate).

import std / [tables, assertions, sets]
import nifcore, nifcdecl, nifcoreparse
import slots, nifmodules
import "../../../nimony/src/lib" / [symparser, nifreader, stringviews]

type
  Extern* = object
    asmName*, extName*: string

  CallTarget* = object
    asmName*: string         ## the asm-NIF symbol to call
    extern*: bool            ## true → (extcall), false → (call)
    syscall*: bool           ## true → a Linux syscall: emitted as a `(syproc …)` and
                             ## invoked inline via `(syscall)`/`(svc)` (no libc, no PLT)
    sysNr*: int              ## x86-64 Linux syscall number (when `syscall`)
    sysNrA64*: int           ## AArch64 Linux syscall number (when `syscall`); `-1` if
                             ## the name has no syscall on that arch
    atomic*: string          ## non-empty → a GCC `__atomic_*` builtin lowered inline
    memIntrin*: string       ## non-empty → a mem* intrinsic (memcpy/…) lowered inline
    bitBuiltin*: string      ## non-empty → a GCC bit builtin (`__builtin_ctzll`, …)
                             ## lowered inline to a native bit instruction (bsf/bsr/…)
    retFloat*: bool          ## true → returns a float (in v0)
    retType*: Cursor         ## the proc's return-type cursor (for `getType`)
    sigType*: Cursor         ## the proc's SIGNATURE as a `(proctype …)` — the type of the
                             ## proc used as a VALUE, so `getType` treats a proc symbol like
                             ## any other fn-ptr (its return type drives a call's result type)
    declarative*: bool       ## true → emit/use nifasm's declarative call ABI
                             ## (typed params + `(arg)`/`(res)` cross-checking);
                             ## false → manual marshalling (floats/aggregates/…)
    indirect*: bool          ## true → call *through* a function-pointer variable
                             ## (`asmName` is the gvar/tvar holding the pointer)

  ProcInfo* = object
    asmName*: string         ## the proc's asm-NIF name (entry → "main.0")
    decl*: Cursor            ## the `(proc …)` declaration
    isEntry*: bool

  SyscallProc* = object
    asmName*: string         ## the `(syproc …)` symbol name (e.g. "mmap.0")
    decl*: Cursor            ## the importc proc decl (source of params + return type)
    sysNr*: int              ## x86-64 number
    sysNrA64*: int           ## AArch64 number (`-1` if none on that arch)

  Program* = object
    externOrder*: seq[Extern]               ## extproc decls, in order (main module)
    callTarget*: Table[string, CallTarget]  ## Leng proc symbol → how to call it
    procs*: seq[ProcInfo]                   ## internal procs to emit (entry first)
    syscalls*: seq[SyscallProc]             ## syscalls used → one `(syproc …)` decl each
    globals*: Table[string, Cursor]         ## global (gvar/const) var name → its decl cursor
    tvars*: Table[string, Cursor]           ## thread-local var name → its decl cursor (macOS TLV)
    typeDecls*: TypeEnv                     ## resolved type env: main + requested foreign
    mainTypeList*: seq[(string, Cursor)]    ## main-module types, in declaration order
    requestedForeign*: seq[(string, Cursor)] ## foreign types referenced (cross-module
                                             ## dependency record; nifasm links them)
    needsLibSystem*: bool
    darwin*: bool                           ## Mach-O target (libc via dyld, no raw syscalls)
    gvarCName*: Table[string, string]       ## importc/exportc gvar/tvar: NIF symbol → bare C
                                            ## name. The bare name lives in nifasm's shared
                                            ## root scope, so an `exportc` definition in one
                                            ## bundled module links to an `importc` reference
                                            ## in another (C-style global linkage). The
                                            ## exporting module emits the slot; importc-only
                                            ## references resolve to it (no local slot).
    importcOnlyGvars*: HashSet[string]      ## NIF symbols of importc gvars WITHOUT exportc:
                                            ## their slot is provided elsewhere, so genGlobal
                                            ## must not emit a (duplicate) definition.
    # ── cross-module machinery ──
    scheme: SplittedModulePath              ## path template (dir/<module>.ext)
    tags: TagPool                           ## shared tag pool for parsing foreign modules
    loaded: Table[string, ForeignModule]    ## module suffix → loaded foreign module
    procPtr*: Cursor                        ## a synthesized `(proctype)` — the code-pointer
                                            ## type of a proc used as a value. A nifcore
                                            ## Cursor keeps its own backing alive (refcounted
                                            ## owner), so no separate buffer must be stored.
    voidPtr*: Cursor                        ## a synthesized `(ptr (void))` — the structural
                                            ## type of a `nil` literal (a generic pointer).
    nilLit*: Cursor                         ## a synthesized Leng `(nil)` — the slot `typ` of
                                            ## a nil value, so its register binds to the asm
                                            ## `(nil)` type (not `(i 64)`) and emits `(nil)`.
    intType*: Cursor                        ## synthesized `(i 64)` — type of a bare IntLit
    uintType*: Cursor                       ## synthesized `(u 64)` — type of a bare UIntLit
    charType*: Cursor                       ## synthesized `(c 8)`  — type of a bare CharLit
    floatType*: Cursor                      ## synthesized `(f 64)` — type of a bare FloatLit
    boolType*: Cursor                       ## synthesized `(bool)` — type of a `(true)`/`(false)` literal

  TypeEnv* = Table[string, Cursor]          ## a type-symbol table

# ── Linux syscall table (shared) ────────────────────────────────────────────
# nifasm's ELF backend is static (no dynamic linker / PLT), so an `importc`'d libc
# call can't reach a shared object — arkham instead recognises these names and
# lowers them to a raw Linux syscall (emitted as a `(syproc …)` with the syscall
# ABI register assignment + the kernel's clobbers, invoked inline via the
# `(syscall)`/`(svc)` marker). One table, two columns: the x86-64 number and the
# AArch64 (asm-generic unistd) number, which differ (write=1 vs 64, exit=60 vs 93).
# `-1` in a column means "no syscall of this name on that arch" (e.g. x86-64 has
# `open`, AArch64 only `openat`). To teach arkham a new syscall, add one row here.
const LinuxSyscalls* = {
  "read":       (0,   63),
  "write":      (1,   64),
  "open":       (2,   -1),
  "openat":     (-1,  56),
  "close":      (3,   57),
  "mmap":       (9,   222),
  "munmap":     (11,  215),
  # File metadata / positioning. `stat`/`lstat` have no AArch64 syscall (the
  # asm-generic ABI uses `fstatat`/`statx` instead), so they get -1 there — like
  # `open` above, fine for an x86-64 target and flagged loudly if an a64 build
  # ever reaches them.
  "lseek":      (8,   62),
  # `getcwd(buf, size)` fills `buf` with the cwd. NOTE: the raw syscall returns the path
  # LENGTH (>0) on success / `-errno` on error, whereas libc returns `buf` / NULL —
  # `getCurrentDir` only uses the result for its `== nil` check (a positive length is
  # non-nil) and reads the path from `buf`, so the success path is correct. A failure
  # would be mis-read as success, but the cwd reliably exists on the boot path.
  "getcwd":     (79,  17),
  "fstat":      (5,   80),
  "stat":       (4,   -1),
  "lstat":      (6,   -1),
  "ftruncate":  (77,  46),
  # No libc `futex` symbol exists (callers use the generic `syscall(SYS_futex,…)`
  # wrapper), but `std/private/syslocks` declares a *named* `futex` importc for the
  # libc-free build precisely so this row recognizes it — the futex arguments map
  # straight onto the kernel ABI registers (uaddr/op/val/timeout → arg0..3).
  "futex":      (202, 98),
  "exit":       (60,  93),
  "exit_group": (231, 94),
  # libc `_exit(status)` terminates the process — map it to the `exit_group` syscall
  # (its glibc implementation), so a libc-free build's `cExit` links.
  "_exit":      (231, 94),
  # `cAbort`/`cExit` raise via `kill(getpid(), SIGABRT)` in the libc-free build.
  "getpid":     (39,  172),
  "kill":       (62,  129),
  # Process creation / replacement, used by os.execShellCmd's libc-free `system()`
  # (fork + execve of `/bin/sh -c` + wait). AArch64's asm-generic ABI has no `fork`
  # syscall (userspace uses `clone`), so it gets -1 there — like `open`/`stat`, fine
  # for an x86-64 target and flagged loudly if an a64 build ever reaches it.
  "fork":       (57,  -1),
  "execve":     (59,  221),
  # libc `waitpid(pid, status, opts)` is `wait4(pid, status, opts, rusage=NULL)`;
  # there is no bare `waitpid` syscall. posix.nim's libc-free `waitpid` wraps this
  # 4-arg `wait4` with `rusage = nil` so the 4th ABI register is a defined NULL.
  "wait4":      (61,  260),
  # std/osproc's libc-free startProcess: a pipe per std stream, dup2 to wire the
  # child's 0/1/2, close the unused ends, optional chdir (workingDir) / setpgid
  # (poDaemon). AArch64's asm-generic ABI replaces `pipe`/`dup2` with `pipe2`/`dup3`
  # (an extra flags arg), so they get -1 there — fine for an x86-64 target, flagged
  # loudly on a64. (`execvp` is NOT here — it is not a syscall; posix.nim implements
  # it on top of `execve` + a PATH scan.)
  "pipe":       (22,  -1),
  "dup2":       (33,  -1),
  "chdir":      (80,  49),
  "setpgid":    (109, 154),
  # getAppFilename → readlink("/proc/self/exe"). AArch64's asm-generic ABI has only
  # `readlinkat`, so -1 there (fine for x86-64, flagged loudly on a64).
  "readlink":   (89,  -1),
  # std/terminal's isatty → ioctl(fd, TCGETS). Same number on both arches.
  "ioctl":      (16,  29),
  # std/os filesystem mutators (mkdir/removeDir/removeFile/moveFile). AArch64's
  # asm-generic ABI replaced all of these with `*at` variants (mkdirat/unlinkat/
  # renameat), so they get -1 there — fine for an x86-64 target, flagged on a64.
  "mkdir":      (83,  -1),
  "rmdir":      (84,  -1),
  "unlink":     (87,  -1),
  "rename":     (82,  -1),
  # `abort` is a libc function, not a syscall. For now we lower it to the `exit`
  # syscall so a libc-free build links and terminates (it takes no args, so the exit
  # code is whatever is in the syscall's code register — abort is a cold error path).
  "abort":      (60,  93)}

const CLinkageGvars* = ["cmdCount", "cmdLine", "nimEnviron"]
  ## Runtime gvars that link by their bare C name (`<cName>.0`) across all bundled
  ## modules: defined+written by the generated `main`, read by std modules via
  ## `importc` (`cmdCount`/`cmdLine` ← std/cmdline; `nimEnviron` ← std/envvars,
  ## std/posix). See `collect` (same-module mapping) and `gvarRefName` (foreign).

const
  LinuxX64ExitNr* = 60
  LinuxA64ExitNr* = 93

proc lookupSyscall*(name: string): tuple[found: bool, x64, a64: int] =
  ## Resolve libc `name` to its (x86-64, AArch64) syscall numbers, or `found=false`
  ## if arkham does not lower it (the call then goes through the normal extern path).
  for (n, nr) in LinuxSyscalls:
    if n == name: return (true, nr[0], nr[1])
  result = (false, -1, -1)

# ── pass 0: collect the main module's top-level declarations ────────────────

proc parsePragmas(c: var Cursor; importcN, exportcN: var string) =
  if c.substructureKind == PragmasU:
    c.into:
      while c.hasMore:
        case c.pragmaKind
        of ImportcP:
          c.into:
            if c.hasMore: (importcN = strVal(c); inc c)
        of ExportcP:
          c.into:
            if c.hasMore: (exportcN = strVal(c); inc c)
        else: skip c
  else:
    skip c

proc resolveType*(p: var Program; c: Cursor): Cursor
proc slotOf*(p: var Program; c: Cursor): AsmSlot

proc abiScalarType(p: var Program; c: Cursor): bool =
  ## A type that travels in a single GPR with no layout resolution needed:
  ## a primitive non-float scalar (`(i N)`/`(u N)`/`(c N)`/`(bool)`), a pointer
  ## (`(ptr …)`/`(aptr …)`/`(proctype …)`), or a named type that resolves to one of
  ## those — notably an `enum`, which collapses to its base integer. Floats and
  ## aggregates (objects/unions/arrays) conservatively answer false so they keep
  ## the manual marshalling path.
  var t = c
  if t.kind == Symbol: t = resolveType(p, t)
  if t.kind != TagLit: return false
  case t.typeKind
  of IT, UT, CT, BoolT, PtrT, AptrT, ProctypeT, EnumT: true
  else: false

const FullSigAggrByRefThreshold = 16
  ## The SysV/AAPCS64 by-value aggregate threshold (both targets use 16). Aggregates
  ## larger than this travel by reference. Kept here so `isDeclarativeAbi` (which has
  ## no `MachineDesc`) can classify a result the same way the code generator does.

proc isDeclarativeAbi*(p: var Program; decl: Cursor): bool =
  ## Whether `decl`'s call boundary uses the FULL typed signature (the declarative
  ## `(arg pN [k])` / `(res ret.0)` scheme): every parameter is a scalar/pointer OR
  ## an aggregate (passed by-value in consecutive registers when ≤16B, by a pointer
  ## otherwise), and the result is void, a scalar, or a >16B by-reference aggregate
  ## (returned through a hidden result pointer). FLOAT params/results and ≤16B
  ## by-value aggregate RESULTS are not yet modelled in the typed signature, so those
  ## procs keep the empty-signature manual-marshalling path.
  var c = decl
  c.into:
    inc c                                     # name → params slot
    if c.kind == TagLit:                      # (params (param :n prag type) …)
      var pc = c
      pc.into:
        while pc.hasMore:
          var notFullSig = false
          pc.into:                            # (param :name pragmas type)
            inc pc                            # name
            skip pc                           # pragmas
            let ps = slotOf(p, pc)
            # Float params aren't in the typed signature yet; a zero-size aggregate
            # param (an empty object/tuple) would emit an empty `(regs)` location — both
            # keep the empty-signature manual-marshalling path (which passes 0 words).
            notFullSig = ps.kind == AFloat or (ps.kind == AMem and ps.size == 0)
            while pc.hasMore: skip pc          # type (+ anything else)
          if notFullSig: return false
    skip c                                    # params
    # return type: void / scalar / aggregate (≤16B by-value in rax:rdx, >16B by-ref via
    # the hidden pointer) ok — all declarative. Only a FLOAT result is not yet modelled.
    if not (c.kind == DotToken or (c.kind == TagLit and c.typeKind == VoidT)):
      let rs = slotOf(p, c)
      if rs.kind == AFloat: return false
    while c.hasMore: skip c                   # return type, pragmas, body
  result = true

proc thisModuleSuffix*(p: Program): string =
  ## The main module's NIF symbol suffix (e.g. `sysvq0asl`), used to compress
  ## self-module symbol suffixes when serializing the embedded-index output.
  p.scheme.name

proc ptrTypeOf*(p: Program; elem: Cursor): Cursor =
  ## Synthesize the type of `(addr lvalue)`: a `(ptr <elem>)` whose pointee is a
  ## copy of the element type `elem`. The new buffer SHARES `elem`'s literals and
  ## tag pools, so any symbol / literal ids the copied subtree carries stay valid
  ## (cross-pool copies would corrupt them). The returned cursor keeps its backing
  ## alive via the refcounted owner (the same idiom as `procPtr`). Mirrors
  ## `leng/typenav.getTypeImpl`'s `AddrC` case — a pointer is not just 8 bytes, it
  ## carries the pointee type so `(deref (addr x))` / `(pat (addr x) i)` navigate.
  var buf = createTokenBuf(8, sharedPool = elem.pool, sharedTags = elem.tags)
  buf.openTag registerTag(elem.tags, "ptr")
  buf.addSubtree elem
  buf.closeTag()
  result = beginRead(buf)

proc procSigType*(declStart: Cursor): Cursor =
  ## The TYPE of a proc used as a VALUE: its signature `(proctype . <params> <ret>
  ## <pragmas>)`, synthesized from the `(proc :name params ret pragmas body)` decl. Shares
  ## the decl's literal/tag pools so copied symbol/literal ids stay valid, and the owner
  ## refcount keeps it alive (the same idiom as `ptrTypeOf`/`procPtr`). Letting `getType`
  ## return this for a proc symbol makes a call's result type fall out of "the return type
  ## of the callee's proctype" uniformly — no static-vs-indirect special case.
  var d = declStart
  var buf = createTokenBuf(16, sharedPool = declStart.pool, sharedTags = declStart.tags)
  buf.openTag registerTag(declStart.tags, "proctype")
  buf.addDotToken()                            # the name slot (a proctype carries none)
  d.into:
    inc d                                      # skip the proc name
    buf.addSubtree d; skip d                   # params
    buf.addSubtree d; skip d                   # return type
    buf.addSubtree d; skip d                   # pragmas
    while d.hasMore: skip d                    # body (and anything else — `into` must drain)
  buf.closeTag()
  result = beginRead(buf)

proc collect*(buf: var TokenBuf; inputPath: string; tags: TagPool;
              darwin = false): Program =
  ## `darwin` selects the Mach-O target, which links dynamically against
  ## libSystem (dyld + PLT). Unlike the static-ELF Linux target, an `importc`'d
  ## libc name there resolves through the dynamic linker, so it must go through
  ## the normal extern path rather than being lowered to a raw kernel trap —
  ## Darwin's syscall numbers and `svc #0x80` convention differ from Linux's, and
  ## raw syscalls are unstable ABI on macOS. See the syscall branch below.
  result = Program(callTarget: initTable[string, CallTarget](),
                   typeDecls: initTable[string, Cursor](),
                   globals: initTable[string, Cursor](),
                   tvars: initTable[string, Cursor](),
                   loaded: initTable[string, ForeignModule](),
                   gvarCName: initTable[string, string](),
                   importcOnlyGvars: initHashSet[string](),
                   scheme: splitModulePath(inputPath), tags: tags,
                   darwin: darwin)
  block:
    # A standalone `(proctype)` parsed against the shared tag pool; its cursor
    # outlives this buffer (the owner refcount keeps the data alive).
    var ptBuf = parseFromBuffer("(proctype)", "", sharedTags = tags)
    result.procPtr = beginRead(ptBuf)
    var npBuf = parseFromBuffer("(ptr (void))", "", sharedTags = tags)
    result.voidPtr = beginRead(npBuf)
    var nilBuf = parseFromBuffer("(nil)", "", sharedTags = tags)
    result.nilLit = beginRead(nilBuf)
    var itBuf = parseFromBuffer("(i 64)", "", sharedTags = tags)
    result.intType = beginRead(itBuf)
    var utBuf = parseFromBuffer("(u 64)", "", sharedTags = tags)
    result.uintType = beginRead(utBuf)
    var ctBuf = parseFromBuffer("(c 8)", "", sharedTags = tags)
    result.charType = beginRead(ctBuf)
    var ftBuf = parseFromBuffer("(f 64)", "", sharedTags = tags)
    result.floatType = beginRead(ftBuf)
    var btBuf = parseFromBuffer("(bool)", "", sharedTags = tags)
    result.boolType = beginRead(btBuf)
  assert buf.beginRead().stmtKind == StmtsS, "Leng top level must be (stmts …)"
  # Pass 1: register every type declaration. Procs (pass 2) resolve their
  # param/return types via `isDeclarativeAbi`, and a proc may reference a type
  # declared *later* in the module (e.g. a tuple-instance returned by a helper),
  # so all types must be in `typeDecls` before any proc is processed.
  var ct = buf.beginRead()
  ct.into:
    while ct.hasMore:
      if ct.stmtKind == TypeS:
        let typeStart = ct
        var tc = ct
        tc.into:
          let nm = symName(tc)
          result.typeDecls[nm] = typeStart
          result.mainTypeList.add (nm, typeStart)
          while tc.hasMore: skip tc           # drain so `into` stays balanced
      skip ct
  # Pass 2: globals, thread-locals and procs.
  var c = buf.beginRead()
  c.into:
    while c.hasMore:
      if c.stmtKind in {GvarS, TvarS, ConstS}:
        let gStart = c
        var gc = c
        let isTvar = c.stmtKind == TvarS
        gc.into:
          let nm = symName(gc); inc gc
          if isTvar: result.tvars[nm] = gStart   # thread-local (macOS TLV)
          else: result.globals[nm] = gStart      # ordinary .bss global / const
          # An importc/exportc gvar uses its bare C name so the (single) nifasm
          # root scope links an `exportc` definition to `importc` references across
          # bundled modules (C-style global linkage). importc-WITHOUT-exportc means
          # the slot is defined elsewhere — record it so genGlobal emits no slot.
          var gImportc, gExportc = ""
          parsePragmas(gc, gImportc, gExportc)
          if not isTvar:                           # tvars use FS-segment access, not emGlobalAddr
            # Canonical C-linkage symbol: `<cName>.0`. A trailing numeric
            # disambiguator with NO module suffix is (a) a valid NIF Symbol token (a
            # bare `cName` would tokenize as an Ident nifasm rejects) and (b) treated
            # as module-less by `extractModule`, so it lives in nifasm's shared root
            # scope and links the same name across every bundled module.
            #
            # Scoped to the runtime's genuine cross-module exportc/importc gvar PAIRS
            # (`cmdCount`/`cmdLine`/`nimEnviron`: defined+written by the generated
            # `main`, read by `std/cmdline` / `std/envvars` / `std/posix`). A blanket
            # redirect would break the many importc consts that have NO in-bundle
            # definition (e.g. `__ATOMIC_RELAXED`): those rely on falling through to a
            # local zeroed slot, so they must keep their NIF name. (A full C-linkage
            # namespace in nifasm would generalize this.) See CLinkageGvars (top-level)
            # and gvarRefName for the cross-module (foreign-reference) resolution.
            if gExportc.len > 0 and gExportc in CLinkageGvars:
              result.gvarCName[nm] = gExportc & ".0"
            elif gImportc.len > 0 and gImportc in CLinkageGvars:
              result.gvarCName[nm] = gImportc & ".0"
              result.importcOnlyGvars.incl nm
          while gc.hasMore: skip gc           # drain so `into` stays balanced
        skip c
      elif c.stmtKind == ProcS:
        let procStart = c
        var pname, importcN, exportcN = ""
        var retFloat = false
        var retType: Cursor
        c.into:
          pname = symName(c); inc c           # name
          skip c                              # params
          retType = c                         # return-type cursor (for getType)
          retFloat = c.kind == TagLit and c.typeKind == FT   # `(f N)` return → v0
          skip c                              # return type
          parsePragmas(c, importcN, exportcN)
          skip c                              # body
        let sigType = procSigType(procStart)  # the proc-value's `(proctype …)` (for getType)
        if importcN.len >= 9 and importcN[0 .. 8] == "__atomic_":
          # GCC atomic builtin: not a real external call — arkham lowers it to a
          # lock-free instruction sequence (no extproc/libSystem dependency).
          result.callTarget[pname] = CallTarget(atomic: importcN, retType: retType, sigType: sigType)
        elif importcN in ["memcpy", "memmove", "memset", "memcmp"]:
          # C mem* intrinsic: lowered inline (no libc dependency) — see genMemIntrin.
          result.callTarget[pname] = CallTarget(memIntrin: importcN, retType: retType, sigType: sigType)
        elif importcN in ["__builtin_ctzll", "__builtin_ctz",
                          "__builtin_clzll", "__builtin_clz",
                          "__builtin_popcountll", "__builtin_popcount",
                          "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"]:
          # GCC bit builtin (count-trailing/leading-zeros, popcount, byte-swap):
          # lowered inline to a native bit instruction — no libc/extproc. See
          # genBitBuiltin. (nimony's `firstSetBit`/`countTrailingZeroBits` reach
          # `ctz64` ⇒ `__builtin_ctzll` ⇒ a single `bsf`.)
          result.callTarget[pname] = CallTarget(bitBuiltin: importcN, retType: retType, sigType: sigType)
        elif not darwin and importcN.len > 0 and lookupSyscall(importcN).found:
          # A Linux syscall: lowered to a raw kernel trap (no libc, no PLT). Emitted
          # as a `(syproc …)` whose proctype puts args in the syscall ABI registers
          # and declares the kernel's clobbers; calls go through the declarative
          # `(prepare …)` path with a `(syscall)`/`(svc)` marker. See genCall.
          let (_, x64Nr, a64Nr) = lookupSyscall(importcN)
          # Name the syproc as a proper SELF-MODULE symbol `<name>.sys.<thisModule>`:
          # nifasm resolves cross-module symbols by full module-qualified name (the render
          # compresses the suffix to a trailing dot and nifasm completes it back), so a
          # basename-only `mmap.sys` would be unresolvable from another bundled module that
          # calls it. Keying on the C `importcN` (not the proc's own `pname`) also collapses
          # aliases — e.g. both `die` and `exit` (`importc "exit"`) → one syproc. The `.sys.`
          # disambiguator is RESERVED: nimony proc disambiguators are always numeric, so a
          # synthesized syproc can never collide with a real proc of the same base name
          # (e.g. the `write` syscall syproc vs syncio's own `write.0` proc).
          let asmN = importcN & ".sys." & thisModuleSuffix(result)
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: false,
                                                syscall: true, sysNr: x64Nr, sysNrA64: a64Nr,
                                                declarative: true, retType: retType, sigType: sigType)
          # Record one syproc decl per distinct syscall symbol.
          var already = false
          for sp in result.syscalls:
            if sp.asmName == asmN: already = true; break
          if not already:
            result.syscalls.add SyscallProc(asmName: asmN, decl: procStart,
                                            sysNr: x64Nr, sysNrA64: a64Nr)
        elif importcN.len > 0:
          let asmN = importcN & ".0"
          result.externOrder.add Extern(asmName: asmN, extName: "_" & importcN)
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: true,
                                                retFloat: retFloat, retType: retType, sigType: sigType)
          result.needsLibSystem = true
        else:
          # The program entry is the C `main` (`exportc "main"`). Every OTHER
          # exported proc (`exportc "nimStrDestroy"`, …) is an ordinary proc whose
          # C name is irrelevant to this self-contained image — it must keep its
          # NIF name `pname` so cross-module calls (e.g. `=destroy.2.<mod>`) resolve.
          # (The old `exportcN.len > 0` test wrongly renamed all of them to `main.0`.)
          let entry = exportcN == "main"
          let asmN = if entry: "main.0" else: pname
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: false,
                                                retFloat: retFloat, retType: retType, sigType: sigType,
                                                declarative: isDeclarativeAbi(result, procStart))
          result.procs.add ProcInfo(asmName: asmN, decl: procStart, isEntry: entry)
      else:
        skip c
  # Emit the entry proc first so it begins the text section.
  for i in 0 ..< result.procs.len:
    if result.procs[i].isEntry and i != 0:
      swap result.procs[0], result.procs[i]
      break

# ── cross-module type lookup (lazy foreign-module loading) ──────────────────

proc loadModule(p: var Program; suffix: string): ForeignModule =
  ## Load (and cache) the foreign module identified by `suffix`. Its file is
  ## `<dir-of-main>/<suffix><ext-of-main>` (the same scheme leng uses). The file
  ## must carry an embedded `.indexat` index (run `nimony/tools/reindex.nim` on
  ## hand-written fixtures); the shared `nifmodules` loader keeps the reader open
  ## for lazy per-symbol jumps.
  if p.loaded.hasKey(suffix): return p.loaded[suffix]
  var sc = p.scheme
  sc.name = suffix
  let path = $sc
  let m = openForeignModule(path)
  if not m.hasEmbeddedIndex:
    raiseAssert "arkham: module has no embedded index (reindex it): " & path
  p.loaded[suffix] = m
  result = m

proc lookupType*(p: var Program; name: string): Cursor =
  ## The `(type :name …)` declaration for `name`, resolving across modules. A
  ## name with a module suffix (`Foo.0.othermod`) triggers loading that module
  ## (via its `.indexat` index when present); the decl is cached in `typeDecls`
  ## and recorded in `requestedForeign` as a cross-module dependency.
  if p.typeDecls.hasKey(name): return p.typeDecls[name]
  let s = splitSymName(name)
  if s.module.len == 0:
    raiseAssert "arkham: unknown type " & name
  # A reference qualified with our OWN module suffix denotes a local type whose
  # decl `collect` registered under its unqualified (local) name. De-qualify and
  # retry locally rather than (wrongly) trying to load ourselves as a foreign
  # module — generic-instance names like `t.0.I….<self>.<self>` are the case.
  if s.module == p.scheme.name:
    let localName = name[0 ..< name.len - s.module.len]
    if p.typeDecls.hasKey(localName): return p.typeDecls[localName]
    raiseAssert "arkham: unknown local type " & name
  let m = loadModule(p, s.module)
  if not hasDecl(m, name):
    raiseAssert "arkham: type " & name & " not found in module " & s.module
  let d = getDecl(m, name, p.tags)
  p.typeDecls[name] = d
  p.requestedForeign.add (name, d)
  result = d

proc lookupForeignDecl*(p: var Program; name: string; found: var bool): Cursor =
  ## The top-level declaration (`gvar|var|const|tvar|proc|type :name …`) for a
  ## cross-module symbol, loaded from the owning module's embedded index (same
  ## scheme as `lookupType`). Sets `found=false` for an unqualified name, a
  ## reference to our own module, or a symbol absent from the foreign module —
  ## so a single call classifies "local vs foreign" without a separate probe.
  ## A resolved decl is recorded in `requestedForeign` so nifasm links it.
  found = false
  let s = splitSymName(name)
  if s.module.len == 0 or s.module == p.scheme.name: return
  let m = loadModule(p, s.module)
  if not hasDecl(m, name): return
  result = getDecl(m, name, p.tags)
  p.requestedForeign.add (name, result)
  found = true

proc gvarAsmName*(p: Program; nifName: string): string {.inline.} =
  ## The asm-NIF symbol for a global reference: an importc/exportc gvar uses its
  ## bare C name (shared root-scope linkage across bundled modules); any other
  ## global keeps its fully-qualified NIF name.
  p.gvarCName.getOrDefault(nifName, nifName)

proc isForeignSym*(p: Program; name: string): bool =
  ## True if `name`'s qualified module is a DIFFERENT module than the one being
  ## compiled (so it must be resolved via its owning module, not the local tables).
  let s = splitSymName(name)
  s.module.len > 0 and s.module != p.scheme.name

proc foreignCallTarget*(p: var Program; name: string): CallTarget =
  ## Resolve a cross-module proc reference to a callable target by loading its
  ## declaration from the owning module's embedded index. The asm symbol is the
  ## fully-qualified NIF name; nifasm auto-imports `<module>.asm.nif` and links it.
  let s = splitSymName(name)
  assert s.module.len > 0 and s.module != p.scheme.name,
    "arkham: not a foreign proc: " & name
  let m = loadModule(p, s.module)
  assert hasDecl(m, name), "arkham: foreign proc not found: " & name
  let declCur = getDecl(m, name, p.tags)
  var d = declCur
  var retFloat = false
  var retType: Cursor
  var importcN, exportcN = ""
  d.into:
    inc d                                     # name
    skip d                                    # params
    retType = d
    retFloat = d.kind == TagLit and d.typeKind == FT
    skip d                                    # return type
    parsePragmas(d, importcN, exportcN)
    while d.hasMore: skip d                    # body
  let sigType = procSigType(declCur)
  # A cross-module call must classify the foreign decl EXACTLY as the owning
  # module's pass 0 did (see `collect`): an `importc`'d syscall / atomic / mem*
  # intrinsic / bit builtin is lowered inline (or to a `<name>.sys.<mod>` syproc
  # the foreign module emits), NOT called by its plain `<name>.0.<mod>` symbol —
  # which would be an unresolved extern. The asm symbol for a foreign syscall is
  # the foreign module's `<importc>.sys.<that module>` (its suffix is `s.module`).
  if importcN.len >= 9 and importcN[0 .. 8] == "__atomic_":
    result = CallTarget(atomic: importcN, retType: retType, sigType: sigType)
  elif importcN in ["memcpy", "memmove", "memset", "memcmp"]:
    result = CallTarget(memIntrin: importcN, retType: retType, sigType: sigType)
  elif importcN in ["__builtin_ctzll", "__builtin_ctz",
                    "__builtin_clzll", "__builtin_clz",
                    "__builtin_popcountll", "__builtin_popcount",
                    "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"]:
    result = CallTarget(bitBuiltin: importcN, retType: retType, sigType: sigType)
  elif not p.darwin and importcN.len > 0 and lookupSyscall(importcN).found:
    let (_, x64Nr, a64Nr) = lookupSyscall(importcN)
    result = CallTarget(asmName: importcN & ".sys." & s.module, extern: false,
                        syscall: true, sysNr: x64Nr, sysNrA64: a64Nr,
                        declarative: true, retType: retType, sigType: sigType)
  elif importcN.len > 0:
    # A genuine libc extern (the foreign module records it in its own externOrder
    # + needsLibSystem; here we only need the matching call target). The asm name
    # is the bare `<importc>.0` the foreign module's extern decl uses.
    p.needsLibSystem = true
    result = CallTarget(asmName: importcN & ".0", extern: true, retFloat: retFloat,
                        retType: retType, sigType: sigType)
  else:
    result = CallTarget(asmName: name, extern: false, retFloat: retFloat,
                        retType: retType, sigType: sigType,
                        declarative: isDeclarativeAbi(p, declCur))

proc gvarRefName*(p: var Program; nifName: string): string =
  ## Like `gvarAsmName`, but also resolves a CLinkage gvar referenced from a
  ## DIFFERENT module than the one that declares it (e.g. `std/posix`'s
  ## `posix_environ {.importc:"nimEnviron".}` read from `std/os`). The per-module
  ## `gvarCName` only covers same-module decls, so a foreign reference would keep
  ## its raw NIF name and fail to link against the canonical `<cName>.0` slot. We
  ## load the owning module's decl, and if its importc/exportc name is a CLinkage
  ## gvar, map to `<cName>.0` (and cache it).
  let local = p.gvarCName.getOrDefault(nifName, "")
  if local.len > 0: return local
  if isForeignSym(p, nifName):
    let s = splitSymName(nifName)
    let m = loadModule(p, s.module)
    if hasDecl(m, nifName):
      let declCur = getDecl(m, nifName, p.tags)
      var d = declCur
      var importcN, exportcN = ""
      d.into:
        inc d                                   # name
        parsePragmas(d, importcN, exportcN)     # at the pragmas node
        while d.hasMore: skip d                 # drain (type, value)
      let cname =
        if exportcN.len > 0 and exportcN in CLinkageGvars: exportcN
        elif importcN.len > 0 and importcN in CLinkageGvars: importcN
        else: ""
      if cname.len > 0:
        result = cname & ".0"
        p.gvarCName[nifName] = result           # cache for subsequent refs
        return
  result = nifName

# ── named-type resolution ───────────────────────────────────────────────────

proc typeBody*(p: var Program; name: string): Cursor =
  ## The body (3rd child) of a named type decl `(type :name pragmas body)`.
  var d = lookupType(p, name)
  d.into:
    inc d; skip d                             # name, type-pragmas
    result = d                                # the body (a copy)
    skip d                                    # balance the `into`

proc resolveType*(p: var Program; c: Cursor): Cursor =
  ## Follow named-type `Symbol`s (across modules) to the underlying structural
  ## type. A type that is not a named alias is returned unchanged.
  result = c
  var guard = 0
  while result.kind == Symbol:
    result = typeBody(p, symName(result))
    inc guard
    assert guard < 1000, "arkham: cyclic type alias"

# ── size / layout (name-resolving — lives here, not in slots) ────────────────

proc typeSizeAlign*(p: var Program; c: Cursor): (int, int)

proc unionSizeAlign(p: var Program; unionc: Cursor): (int, int) =
  ## A union's branches OVERLAP: size = max(branch size), align = max(branch align).
  ## Leng object-variant branches are `(object …)` nodes (sized via `objSizeAlign`).
  var uc = unionc
  var maxSz = 0
  var maxAl = 1
  uc.into:
    while uc.hasMore:
      let (bsz, bal) = typeSizeAlign(p, uc)   # each branch is an (object …)
      if bsz > maxSz: maxSz = bsz
      if bal > maxAl: maxAl = bal
      skip uc
  result = (align(maxSz, maxAl), maxAl)

proc objSizeAlign(p: var Program; bodyc: Cursor): (int, int) =
  var oc = bodyc
  var off = 0
  var maxAl = 1
  oc.into:
    if oc.kind == Symbol:                      # inherited base: laid out FIRST,
      let (bsz, bal) = typeSizeAlign(p, oc)    # so own fields start at sizeof(base)
      off = bsz
      if bal > maxAl: maxAl = bal
    skip oc                                    # base / inheritance slot
    while oc.hasMore:
      if oc.kind == TagLit and oc.typeKind == UnionT:   # an object VARIANT's union part
        let (usz, ual) = unionSizeAlign(p, oc)
        off = align(off, ual) + usz
        if ual > maxAl: maxAl = ual
        skip oc
      else:
        oc.into:                              # (fld :name pragmas type)
          inc oc; skip oc                     # name, field-pragmas
          let (fsz, fal) = typeSizeAlign(p, oc)
          skip oc                             # consume the field type
          off = align(off, fal) + fsz
          if fal > maxAl: maxAl = fal
  result = (align(off, maxAl), maxAl)

proc typeSizeAlign*(p: var Program; c: Cursor): (int, int) =
  ## Size and alignment (bytes) of a Leng type, mirroring nifasm's layout.
  case c.kind
  of Symbol:
    var d = lookupType(p, symName(c))
    d.into:
      inc d; skip d                           # name, type-pragmas
      let r = typeSizeAlign(p, d); skip d
      result = r
  of TagLit:
    case c.typeKind
    of IT, UT, FT, CT:
      let bits = typeBits(c)
      let bytes = (if bits > 0: bits else: 64) div 8
      result = (bytes, bytes)
    of BoolT: result = (1, 1)
    of VoidT: result = (0, 1)
    of PtrT, AptrT, ProctypeT: result = (8, 8)
    of FlexarrayT:
      # A flexible array member contributes no fixed size; its alignment is that
      # of the element type (so the enclosing struct's tail is aligned for it).
      var t = c
      t.into:
        let (_, eal) = typeSizeAlign(p, t); skip t
        while t.hasMore: skip t               # consume any trailing qualifiers
        result = (0, eal)
    of ObjectT: result = objSizeAlign(p, c)
    of UnionT: result = unionSizeAlign(p, c)
    of EnumT:                                 # collapses to its base integer type
      var t = c
      t.into:
        result = typeSizeAlign(p, t); skip t
        while t.hasMore: skip t               # efld members
    of ArrayT:
      var t = c
      t.into:
        let (esz, eal) = typeSizeAlign(p, t); skip t
        let n = if t.kind == IntLit: int(intVal(t)) else: 0
        while t.hasMore: skip t               # consume the length (+ any extra)
        result = (esz * n, eal)
    else: raiseAssert "arkham: cannot size type " & $c.typeKind
  else: raiseAssert "arkham: malformed type for sizing"

proc stackSlotAlign*(p: var Program; c: Cursor): int =
  ## The STACK-slot alignment for a local of type `c`. Starts from the type's natural
  ## alignment, then applies the AMD64 SysV rule (psABI p.14): an array whose total
  ## size is ≥ 16 bytes is aligned to at least 16. This is a STACK-LAYOUT property
  ## ONLY — the type's own alignment (`typeSizeAlign`, which drives struct-field
  ## offsets) is deliberately left element-based and unchanged. Emitted as the
  ## `(s (align N))` annotation; nifasm honours it when allocating the slot.
  let (sz, al) = typeSizeAlign(p, c)
  result = al
  let r = resolveType(p, c)
  if r.kind == TagLit and r.typeKind == ArrayT and sz >= 16:
    result = max(16, al)

proc slotOf*(p: var Program; c: Cursor): AsmSlot =
  ## Classify a type cursor into an `AsmSlot`, resolving named types (across
  ## modules) first. A named `enum`/scalar typedef becomes its underlying scalar
  ## slot; a named/inline object, union or array stays `AMem` with its real byte
  ## size and alignment filled in (for AAPCS64 size-based ABI decisions).
  let r = resolveType(p, c)
  if r.kind != TagLit:
    return typeToSlot(r)                       # defensive: shouldn't occur
  case r.typeKind
  of EnumT:
    var base = r
    var t = r
    t.into:
      base = t; skip t                         # base type (a copy)
      while t.hasMore: skip t                  # efld members
    result = slotOf(p, base)                   # base may itself be a named type
  of ObjectT, UnionT, ArrayT:
    let (sz, al) = typeSizeAlign(p, r)
    result = AsmSlot(cls: AMem, size: sz, align: al, typ: r)  # carry the type, like every other path
  else:
    result = typeToSlot(r)                      # scalars, ptr, void, …

# ── aggregate layout (shared by the allocator + the code generator) ─────────

proc isCleanSigProc*(p: var Program; decl: Cursor): bool =
  ## True if the proc's ABI is "clean" for `ArgResident` reasoning: a non-aggregate
  ## result (no hidden rdi return pointer) and every parameter a single-GPR scalar
  ## (integer/pointer — no aggregate that spans >1 arg register, no float that consumes an
  ## xmm and so skips a GPR ordinal). For such a proc/callee the k-th argument lands in the
  ## k-th arg GPR, so a param passed at its own index is a self-move. Conservative: any
  ## aggregate/float in the signature ⇒ not clean.
  var c = decl
  inc c                                         # (proc → name
  inc c                                         # name → params slot
  var rt = c; skip rt                           # params → return type
  # A void result (`.` or `(void)`) needs no return register and no hidden pointer — clean.
  # Any real aggregate result is conservatively treated as non-clean (a >16B one takes the
  # rdi hidden pointer, shifting every arg down; a ≤16B one uses the manual-marshal path).
  let rtVoid = rt.kind == DotToken or (rt.kind == TagLit and rt.typeKind == VoidT)
  if not rtVoid and slotOf(p, rt).kind == AMem: return false
  result = true
  if c.kind != TagLit: return                   # no params
  c.into:
    while c.hasMore:
      c.into:                                   # (param :name pragmas type)
        inc c                                   # name
        skip c                                  # pragmas
        let s = slotOf(p, c)
        if s.kind in {AMem, AFloat}: result = false
        while c.hasMore: skip c
      if not result: return

proc cleanSigProcNames*(p: var Program): HashSet[string] =
  ## The decl-symbol names of every internal proc with a clean signature
  ## (`isCleanSigProc`). Keyed by the decl's `SymbolDef` name — the SAME symbol a call
  ## site names as its target — so the analyser can test a direct callee by name.
  result = initHashSet[string]()
  for pi in p.procs:
    var nc = pi.decl; inc nc                    # (proc → name
    if nc.kind == SymbolDef and isCleanSigProc(p, pi.decl):
      result.incl symName(nc)

proc aggregateTypeNames*(p: var Program): HashSet[string] =
  ## Names of all types whose ABI class is `AMem` (object/union/array, or an alias to
  ## one) — passed by value across >1 register or by hidden reference. The analyser uses
  ## this to spot aggregate CALL ARGUMENTS, which consume >1 arg register and so shift the
  ## ABI ordinals of the arguments after them (breaking an `ArgResident` param's
  ## same-position self-move assumption). Collect names first: `slotOf` resolves named
  ## types and may cache foreign ones into `typeDecls`, which must not mutate mid-iteration.
  result = initHashSet[string]()
  var names: seq[string] = @[]
  for name in p.typeDecls.keys: names.add name
  for name in names:
    var d = p.typeDecls[name]
    d.into:
      inc d; skip d                             # name, type-pragmas → body
      if slotOf(p, d).cls == AMem: result.incl name

proc aggrByteSize*(p: var Program; typeName: string): int =
  var d = lookupType(p, typeName)
  d.into:
    inc d; skip d                             # name, type-pragmas
    let r = typeSizeAlign(p, d); skip d
    result = r[0]

# ── structural type navigation (the pieces arkham's `getType` walks) ────────

proc fieldType*(p: var Program; objType: Cursor; field: string): Cursor =
  ## The structural type cursor of `field` in a resolved `(object …)` type.
  ## An inherited field (the Leng `(dot base field depth)` selector counts the
  ## base levels) is resolved by recursing into the object's base type.
  assert objType.kind == TagLit and objType.typeKind == ObjectT,
    "arkham: field access requires an object type"
  var oc = objType
  var baseType: Cursor
  var hasBase = false
  oc.into:
    baseType = oc                             # base / inheritance (a type, or `.`)
    hasBase = oc.kind != DotToken
    skip oc
    while oc.hasMore:
      if oc.kind == TagLit and oc.typeKind == UnionT:
        # An object VARIANT: search each `(union (object …branch)+)` branch's fields.
        var u = oc
        u.into:
          while u.hasMore:                    # each branch is an (object . fld*)
            var br = u
            br.into:
              skip br                          # branch base slot (`.`)
              while br.hasMore:
                br.into:                       # (fld :name pragmas type)
                  let fn = symName(br); inc br
                  skip br                       # field-pragmas
                  result = br; skip br
                  if fn == field: return
            skip u
        skip oc
      else:
        oc.into:                              # (fld :name pragmas type)
          let fn = symName(oc); inc oc
          skip oc                             # field-pragmas
          result = oc; skip oc                # field type (a copy)
          if fn == field: return
  if hasBase:                                 # not here → look in the inherited base
    return fieldType(p, resolveType(p, baseType), field)
  raiseAssert "arkham: field '" & field & "' not found"

proc innerType*(p: var Program; t: Cursor): Cursor =
  ## The element/pointee type of a resolved `(ptr T)` / `(aptr T)` / `(array T …)`
  ## / `(flexarray T)` — in each the first child is the element/pointee type.
  assert t.kind == TagLit, "arkham: expected a pointer/array type"
  case t.typeKind
  of PtrT, AptrT, ArrayT, FlexarrayT:
    var tc = t
    tc.into:
      result = tc; skip tc                    # the pointee / element type
      while tc.hasMore: skip tc
  else: raiseAssert "arkham: deref/index of a non-pointer/array type"

proc aggrWordCount*(p: var Program; typeName: string): int =
  ## Number of 8-byte GPRs a ≤16-byte aggregate occupies (1 or 2).
  let sz = aggrByteSize(p, typeName)
  assert sz <= 16, "arkham v1: >16-byte aggregate ABI (by-ref / x8) not yet supported"
  (sz + 7) div 8

proc aggrLayout*(p: var Program; typeName: string): seq[FieldInfo] =
  result = @[]
  var d = lookupType(p, typeName)
  var body: Cursor
  d.into:
    inc d; skip d                             # name, type-pragmas
    body = d; skip d                          # the body
  if body.kind == Symbol:
    # a DISTINCT type / type alias (`(type :Wrap . Inner)`) — its body is the underlying
    # nominal type, with the SAME layout. Resolve through to it (mirrors `aggrByteSize`,
    # which already resolves via `typeSizeAlign`). Handles chains of distincts.
    return aggrLayout(p, symName(body))
  assert body.kind == TagLit and body.typeKind == ObjectT,
    "arkham: aggregate ABI requires an object type: " & typeName
  var oc = body
  var off = 0
  oc.into:
    if oc.kind == Symbol:                     # inherited base: its fields come
      result = aggrLayout(p, symName(oc))     # first, at their base offsets (the
      off = aggrByteSize(p, symName(oc))      # base sits at offset 0 in derived)
    skip oc                                   # base / inheritance slot
    while oc.hasMore:
      oc.into:                                # (fld :name pragmas type)
        let fn = symName(oc); inc oc
        skip oc                               # field-pragmas
        let (fsz, fal) = typeSizeAlign(p, oc)
        skip oc
        off = align(off, fal)
        result.add (name: fn, off: off, size: fsz)
        off += fsz
