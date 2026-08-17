import std/[os, osproc, streams, strutils]

const
  runTimeoutMs = 30_000
    ## Wall-clock budget for ONE generated test binary. Generous: every fixture in the
    ## corpus finishes in milliseconds, so anything near this is a hang, not slowness.
  timeoutExitCode = 124
    ## What `runProgram` reports for a killed child, following `timeout(1)`. No fixture
    ## expects it (`.exitcode` files hold small values), so it always reads as a failure.

proc runProgram(exe: string; args: openArray[string] = [];
                timeoutMs = runTimeoutMs): tuple[output: string, exitCode: int] =
  ## `execCmdEx` for a *generated program*, with a deadline. Miscompiled code loops
  ## forever as readily as it crashes — a call site patched at the wrong offset leaves
  ## a `bl` branching to itself — and `execCmdEx` would then wedge the whole suite with
  ## no clue which fixture did it. Killing the child turns that into an ordinary
  ## failure naming the test.
  ##
  ## `exe` is a PATH and `args` its argument vector: no shell, so nothing here depends
  ## on a platform's quoting or redirection syntax (`poEvalCommand` does not even go
  ## through a shell on Windows — the string lands in `CreateProcess` verbatim).
  ##
  ## The child's output is drained only after it exits, so a program that wrote more
  ## than a pipe buffer holds would block in `write` and be reported as a timeout. Every
  ## fixture prints at most a line or two, which is why that trade is worth the
  ## simplicity of not needing a reader thread.
  let p = startProcess(exe, args = args, options = {poStdErrToStdOut, poUsePath})
  var waited = 0
  while waited < timeoutMs and p.running:
    sleep 5
    inc waited, 5
  if p.running:
    p.terminate()
    sleep 50
    if p.running: p.kill()
    discard p.waitForExit()
    p.close()
    result = ("", timeoutExitCode)
  else:
    # The child is gone and its end of the pipe with it, so `readAll` drains what it
    # wrote and stops at EOF rather than blocking.
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    result = (output, code)

proc exec(cmd: string; showProgress = false) =
  if showProgress:
    let exitCode = execShellCmd(cmd)
    if exitCode != 0:
      quit "FAILURE " & cmd & "\n"
  else:
    let (s, exitCode) = execCmdEx(cmd)
    if exitCode != 0:
      quit "FAILURE " & cmd & "\n" & s

proc execExpectFailure(cmd: string; expectedSubstr = "") =
  let (s, exitCode) = execCmdEx(cmd)
  if exitCode == 0:
    quit "EXPECTED FAILURE " & cmd & "\n"
  if expectedSubstr.len > 0 and not s.contains(expectedSubstr):
    quit "UNEXPECTED OUTPUT " & cmd & "\nExpected to contain: " & expectedSubstr & "\nGot:\n" & s

proc execRun(exe: string) =
  ## `exec` for a produced test binary — same "exit 0 or die", but hang-proof. Takes the
  ## executable's PATH, not a shell line: `runProgram` spawns it directly.
  let (s, exitCode) = runProgram(exe)
  if exitCode == timeoutExitCode:
    quit "FAILURE (TIMEOUT after " & $(runTimeoutMs div 1000) & "s) " & exe & "\n"
  if exitCode != 0:
    quit "FAILURE " & exe & "\n" & s

proc execExpectOutput(exe: string; expected: string) =
  let (s, exitCode) = runProgram(exe)
  if exitCode == timeoutExitCode:
    quit "FAILURE (TIMEOUT after " & $(runTimeoutMs div 1000) & "s) " & exe & "\n"
  if exitCode != 0:
    quit "FAILURE " & exe & "\n" & s
  if s != expected:
    quit "UNEXPECTED OUTPUT " & exe & "\nExpected:\n" & expected & "\nGot:\n" & s

const arkhamKnownUnsupported: seq[string] =
  # Both backends now route the whole corpus through the value-core pure-emit path:
  # register-pressure totality for deep right-nested expression trees (the Sethi–Ullman
  # reorder in allocBin/allocFBin, plus the produce-into-memory spill bridge) and the
  # runtime `(aconstr …)`/`(oconstr …)` constructor as a direct call argument are both
  # handled on x86-64 AND AArch64. No quarantine remains.
  @[]

# Tests that cannot run on ANY AArch64 target, whichever OS hosts it: the Linux
# `linux_arm64` qemu pass and the macOS native pass both skip these. Keep the two
# reasons apart — a stem belongs here when the FIXTURE is x86-64-specific, and in
# `arkhamDarwinUnsupported` when the fixture is fine but the OS differs.
const arkhamA64Unsupported: seq[string] = @[
  # x86-64 target-pinned instructions (`{.instruction: "bsf".}` and friends). Being
  # unavailable on a64 is the POINT — the row's `targets` column says so and the
  # backend errors at the call site naming the target, exactly as C does. The
  # portable counterparts are covered by `intrinsics`, which runs on both.
  "intrinsics_x64",
  # `{.assembler.}` transliteration. Its `{.register: "rdi".}` pins name x86-64
  # registers, so there is no target-neutral reading of the body — that is the
  # mode's premise ("no fallbacks", doc/intrinsics.md §8), not a gap: an AArch64
  # version is a different `when` branch the user writes, with `x0`/`x9` in it.
  "assembler_x64",
  # Six by-ref array params exhaust x86-64's FIVE callee-saved registers, so the
  # sixth pointer spills to a `StackPtr` slot — the shape this fixture exists to
  # pin (`genAconstr2` must store through that pointer, not over the slot).
  # AAPCS64 has TEN, so every pointer stays `InReg` and the same source reaches a
  # DIFFERENT, still-open a64 gap: `genStore2` serves an aggregate destination only
  # for `NamedStack`/`StackPtr`/`Glob`/`Tvar`, and an `InReg` by-ref pointer's home
  # carries an 8-byte pointer slot (`effSlot`, planer) rather than
  # `AMem` — so the location cannot say "this register addresses an aggregate" and
  # the aconstr falls through to `emitValue2`'s scalar arm. Closing it means giving
  # that home its pointee type, as `StackPtr` already does, NOT re-deriving the fact
  # from `varType` at the use site (the "two answers to one question" shape the
  # `spilledByRefPtr` predicate was retired for). The a64 `genAconstr2` StackPtr arm
  # is in place and mirrors x86-64; it is what this gap currently keeps unreachable.
  "aconstr_byref_spilled",
]

const arkhamDarwinUnsupported: seq[string] =
  # The hand-written Leng fixture bakes in a Linux flag constant that has a
  # different numeric value on macOS, so the call genuinely fails on Darwin.
  # x86-64-only fixtures do NOT go here — they go in `arkhamA64Unsupported`,
  # which the macOS pass also honours (it targets arm64, see `arch` below).
  @[
    # `mmap_anon` passes `flags = 34` (MAP_PRIVATE | MAP_ANONYMOUS where
    # MAP_ANONYMOUS == 0x20 on Linux). On macOS MAP_ANON == 0x1000, so 34 is
    # MAP_PRIVATE plus an unsupported bit and mmap returns MAP_FAILED.
    "mmap_anon",
    # `futex` is a Linux syscall lowered to a raw kernel trap (svc/syscall); macOS has
    # no `futex` symbol, so it's Linux-only here. The Darwin equivalent is exercised by
    # `ulock_wake` (just as `std/private/syslocks` selects `futex` vs `__ulock_wake`
    # with a `when defined(linux)`/`elif defined(osx)` split). Mirror it: this pair is
    # one logical test, each half skipped on the platform it doesn't target.
    "futex_wake",
  ]

const arkhamOsxOnly: seq[string] =
  # The Darwin counterpart of the Linux-only `futex_wake` (see arkhamDarwinUnsupported):
  # `ulock_wake` calls `__ulock_wake`, the real libSystem symbol `syslocks` uses on
  # macOS. It links only against libSystem, so it's skipped on Linux (native x64 and
  # the linux_arm64 qemu path), where the symbol doesn't exist.
  @["ulock_wake"]

const arkhamRejections: seq[(string, string)] = @[
  # Arkham owns the `{.assembler.}` rules outright — nimony's sem only forwards
  # the pragmas — so its REJECTIONS need regression coverage as much as its code
  # generation does. Each fixture is a hand-written Leng module that must not
  # compile, paired with the part of the message that says why. See
  # `doc/intrinsics.md` §6 and §8.
  ("err_flag_value", "is a flag, not a value"),
  ("err_flag_outside_asm", "only legal inside an `{.assembler.}` proc"),
  ("err_nonflag_cond", "condition must be a flag intrinsic"),
  ("err_unannotated_local", "declares every location"),
  ("err_wrong_param_reg", "is passed in rdi by the C ABI, but is pinned to rsi"),
  ("err_inout_value", "writes through its first operand and returns nothing"),
  ("err_inout_dest", "must be a `var` argument naming a local"),
  # Not an `{.assembler.}` rule but the same duty: arithmetic on a POINTER is not a
  # Leng form, whichever pointer it is. `(add (ptr T) …)` used to be made to assemble
  # by rebinding the destination to `(i 64)` for the instruction and back after — i.e.
  # by picking a raw-byte reading of `+` that lengc's C backend (which emits scaled C
  # pointer arithmetic for the same node) does not share. `(aptr T)` was admitted for
  # a while longer on the theory that its element stride made the arithmetic
  # well-defined; it does not — the stride says what one element is, not whether `+ 8`
  # meant eight of them. Offsetting an array pointer is `(at …)`/`(pat …)`.
  ("err_ptr_arith", "arithmetic result type is a pointer (ptr)"),
  ("err_aptr_arith", "arithmetic result type is a pointer (aptr)"),
]

proc arkhamRejectionTests(arkham: string) =
  ## Every fixture above must fail, with the stated reason. x86-64 only: the
  ## register names in an `{.assembler.}` body are x86-64's, and the AArch64
  ## backend rejects the whole mode before reaching any of these checks.
  var passed = 0
  for (name, expected) in arkhamRejections:
    execExpectFailure(quoteShell(arkham) & " -a:x64 -o:" &
                      quoteShell("tests" / "arkham" / "nimcache" / (name & ".rej.nif")) &
                      " " & quoteShell("tests" / "arkham" / (name & ".c.nif")), expected)
    inc passed
  echo passed, " / ", arkhamRejections.len, " arkham rejection tests successful"

proc arkhamDebugInfoTests() =
  ## nifasm emits `.symtab` + `.eh_frame`, so a debugger can name and unwind
  ## frames in code that keeps NO frame pointer. Assert that end to end, through
  ## GDB itself: break in the innermost proc of a four-deep chain and demand the
  ## whole chain back, in order, by name.
  ##
  ## Worth an external tool in the harness because the two halves fail
  ## independently and quietly: wrong DWARF register numbers still produce a
  ## plausible-looking trace, and a prologue whose CFA states are not recorded
  ## unwinds correctly right up until the crash happens in a frame that has one.
  ## Only the debugger's own reader can tell us the tables mean what we think.
  if findExe("gdb").len == 0:
    echo "0 / 0 arkham debug-info tests (gdb not installed)"
    return
  let exe = "tests" / "arkham" / "nimcache" / "debuginfo_chain.out"
  if not fileExists(exe):
    quit "FAILURE arkham debug-info: " & exe & " was not built"
  let (s, _) = execCmdEx("gdb -batch -ex \"break leaf.0\" -ex run -ex bt " &
                         quoteShell(exe))
  # GDB prints one `#N 0x… in NAME ()` per frame; it renders `leaf.0` as `leaf`.
  var at = 0
  for want in ["in leaf ", "in middle ", "in outer ", "in main "]:
    let idx = s.find(want, at)
    if idx < 0:
      quit "FAILURE arkham debug-info: no `" & want & "` frame in the backtrace\n" & s
    at = idx
  if s.contains("?? ()"):
    quit "FAILURE arkham debug-info: unnamed frame in the backtrace\n" & s
  echo "1 / 1 arkham debug-info tests successful"

proc arkhamWinUnwindTests() =
  ## The Win64 half of the same story: `.pdata` + `.xdata`, checked by the ONLY
  ## authority that matters — the operating system's own unwinder.
  ##
  ## `tests/win_stacktrace.c.nif` calls `RtlCaptureStackBackTrace` from four
  ## frames down and exits with the number of frames the OS could walk. Wine
  ## implements that through `RtlVirtualUnwind`, which reads the exception
  ## directory, so the exit code IS the answer to "does our unwind info work".
  ## The `--no-debug-info` control run is what makes it a measurement rather
  ## than a hope: without `.pdata` every proc looks like a leaf and the walk
  ## stops at 1.
  if findExe("wine").len == 0:
    echo "0 / 0 arkham win64 unwind tests (wine not installed)"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasm = ("src" / "nifasm" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  let asmNif = workDir / "win_stacktrace.asm.nif"
  let exe = workDir / "win_stacktrace.exe"
  let bare = workDir / "win_stacktrace_nodbg.exe"
  exec quoteShell(arkham) & " -a:win_x64 -o:" & quoteShell(asmNif) & " " &
       quoteShell("tests" / "win_stacktrace.c.nif")
  exec quoteShell(nifasm) & " -o:" & quoteShell(exe) & " " & quoteShell(asmNif)
  exec quoteShell(nifasm) & " --no-debug-info -o:" & quoteShell(bare) & " " &
       quoteShell(asmNif)
  let (_, frames) = execCmdEx("wine " & quoteShell(exe) & " 2>/dev/null")
  let (_, bareFrames) = execCmdEx("wine " & quoteShell(bare) & " 2>/dev/null")
  if frames < 4:
    quit "FAILURE arkham win64 unwind: the OS walked only " & $frames &
         " frames of a four-deep stack — .pdata/.xdata is wrong or missing"
  if bareFrames >= frames:
    quit "FAILURE arkham win64 unwind: --no-debug-info walked " & $bareFrames &
         " frames too, so the " & $frames & " prove nothing"
  echo "1 / 1 arkham win64 unwind tests successful (", frames, " frames vs ",
       bareFrames, " without)"

proc arkhamTests() =
  ## Each `tests/arkham/*.c.nif` is hand-written Leng: arkham generates asm-NIF,
  ## nifasm assembles+links it to a native executable, and we check the run's exit
  ## code (`<stem>.exitcode`, default 0) and stdout (`<stem>.output`, default
  ## empty). The target arch follows the host so the binaries actually run here:
  ## x86-64/ELF on Linux, AArch64/Mach-O on macOS.
  const arch = when defined(macosx): "arm64" else: "x64"
  exec "nim c src/arkham/arkham.nim"
  exec "nim c src/nifasm/nifasm.nim"
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasm = ("src" / "nifasm" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  createDir workDir
  # Foreign helper modules (`mod_*.c.nif`) are not standalone tests: compile each
  # to `<workDir>/<name>.asm.nif` so nifasm can auto-import it when a cross-module
  # test references its symbols (e.g. `Foo.0.mod_xlib` → loads `mod_xlib.asm.nif`).
  for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
    let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
    exec quoteShell(arkham) & " -a:" & arch & " -o:" &
         quoteShell(workDir / (name & ".asm.nif")) & " " & quoteShell(file)
  var total, passed, skipped = 0
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_"): continue   # foreign helper, not standalone
    if base.startsWith("err_"): continue   # must NOT compile — see arkhamRejectionTests
    let name = base[0 ..< base.len - ".c.nif".len]
    when defined(macosx):
      # The macOS run targets arm64, so BOTH lists apply: the fixture may be
      # x86-64-pinned, or it may be portable but depend on a Linux-only symbol.
      if name in arkhamDarwinUnsupported or name in arkhamA64Unsupported: continue
    else:
      if name in arkhamOsxOnly: continue            # macOS-only libSystem symbol
    inc total
    let stem = file[0 ..< file.len - ".c.nif".len]
    let known = name in arkhamKnownUnsupported
    let asmNif = workDir / (name & ".asm.nif")
    let exe = workDir / (name & ".out")
    template tolerate(what, output: string) =
      ## A failure of a known-unsupported test is expected; anything else is fatal.
      if known: inc skipped; continue
      quit "FAILURE " & what & " " & file & "\n" & output
    let (ao, ac) = execCmdEx(quoteShell(arkham) & " -a:" & arch & " -o:" &
                             quoteShell(asmNif) & " " & quoteShell(file))
    if ac != 0: tolerate("arkham (codegen)", ao)
    let (no, nc) = execCmdEx(quoteShell(nifasm) & " -o:" & quoteShell(exe) & " " &
                             quoteShell(asmNif))
    if nc != 0: tolerate("nifasm (assemble/link)", no)
    let (po, pc) = runProgram(exe)
    if pc == timeoutExitCode:
      tolerate("TIMEOUT after " & $(runTimeoutMs div 1000) & "s running", "")
    let ecFile = stem & ".exitcode"
    let expectedCode = if fileExists(ecFile): parseInt(readFile(ecFile).strip) else: 0
    if pc != expectedCode:
      tolerate("exitcode " & $expectedCode & " but got " & $pc & " for", po)
    let outFile = stem & ".output"
    let expectedOut = if fileExists(outFile): readFile(outFile).strip else: ""
    if po.strip != expectedOut:
      tolerate("output mismatch (expected:\n" & expectedOut & "\ngot:\n" &
               po.strip & "\n) for", "")
    if known:
      echo "NOTE: ", name, " now passes — remove it from arkhamKnownUnsupported"
    inc passed
  echo passed, " / ", total - skipped, " arkham tests successful (",
       skipped, " known-unsupported skipped)"

# ── register-pressure stress pass (`-d:arkhamStress`, see src/arkham/stress.nim) ──
#
# The corpus above never runs a pool dry, so the emitters' pool-dry arms
# (produce-into-memory, staging chains, survivor parking) are never taken and every
# bug in one has been found by bootstrapping nimony instead. This pass re-runs the
# SAME fixtures against a starved register file (`ARKHAM_STRESS=k` keeps the first
# `k` registers of each allocatable pool), with each fixture's own
# `.exitcode`/`.output` still the oracle — so it checks both totality and
# correctness under maximum spilling.

const arkhamStressKnown: seq[string] = @[
  # Real defects found by this pass at x86-64's level, parked so that any NEW
  # failure is fatal. Remove an entry with its fix.
  # `takeHeld` with the default `canSpill = false` asserts instead of evicting a
  # live local. 11 of the 15 `takeHeld` sites across both backends do.
  "aggr_arg_parked",
  "aggr_arg_parked_manual",
  # `atomic_cas_regpressure`, `atomic_cas_operand_home` and `aggr_arg_parked_byref`
  # all sat here for the "intrinsic-operand pick has no steal/spill arm" reason and
  # all three now PASS. The missing arm was `pickTempReg`'s volatile candidate list,
  # which was `intTempRegs` = r10 ALONE, so the second live temp went straight to a
  # callee-saved register and under `k=2` stress there was nothing left to go to.
  # Widening it to the idle volatiles fixed them outright.
  # NO LONGER A SILENT MISCOMPILE. The comment here used to read "SILENT MISCOMPILE
  # (71 -> 95)": `produceIntoMem2` hands the produce bridge to the WHOLE node on the
  # claim that it is "not held across the recursion" — true for a leaf or a load,
  # false for a binop, whose left partial sits in the bridge while the other side is
  # Verified 2026-08-09 across k=2..5: the fixture either returns the correct 71
  # (k>=5) or ASSERTS (k<=4). It never answers wrong. What remains is a totality
  # gap, not a correctness one: at the failing pick every register is either SEALED
  # (a live partial the emitting step still needs) or a named local's home. Closing
  # it means needing fewer live values there — not a second allocator inside the
  # emitter, which is what the removed emergency borrow was.
  "addr_chain_depth",
]

const arkhamStressA64Known: seq[string] = @[
  # Both a64 passes take this list — the qemu `linux_arm64` one and the native
  # macOS one — because they drive the same emitters. The first is a SILENT
  # MISCOMPILE: fewer registers may cost performance or hit a documented
  # out-of-registers assert, but can never legitimately change what a program
  # computes, so a wrong answer here is a codegen bug by construction.
  "spill_produce_float",    # float produce-into-spill reads a clobbered register
  # (`atomic_cas_regpressure` lived here for the missing steal/spill arm on the
  # intrinsic-operand pick, and now passes at this list's own k=3.)
  # `instrOperandInPlace` — read a register-homed symbol operand where it lies
  # instead of copying it into a register the row then cannot find — is x86-64
  # ONLY, deliberately: that is the machine whose whole emitter budget is two
  # registers, and every atomic sequence there was read to confirm it writes no
  # operand. a64 has x9–x13 plus two bridges and passes this fixture unstressed;
  # porting the rule is a separate change with its own reading of the LDXR/STXR
  # sequences, not a paste.
  "atomic_cas_operand_home",
  # (`shift_count_clobbers_mask` lived here for the "stackoff into a value slot"
  # class — a spilled `(u 8)` whose slot arkham declared `(i 64)`. Slots now carry
  # their own type, so the class is gone and the fixture passes.)
  # NOT listed, but known: `addr_chain_depth` is the x16 twin of the x86-64
  # `addr_chain_depth` entry above — `produceIntoMem2` re-enters the produce
  # bridge while an enclosing `emitBin2`'s partial is still live in it — and
  # silently returns 221 instead of 71 at k<=2 (22 instead of 64 at chain depth
  # 10). It passes at this list's own k=3, so listing it would only report
  # "now passes". Lowering `arkhamStressA64Level` needs that fix first.
]

const
  arkhamStressLevel = 2       ## registers kept per pool, x86-64
  arkhamStressA64Level = 3
    ## One higher: `takeInstrReg` and `takeLvalStride` route through `takeHeld`
    ## with no spill arm, so at k=2 every atomic and every non-scale index dies on
    ## that documented assert and `call_stack_args` hits the ">8 integer params"
    ## limit. Those are the backend's stated contracts, not findings.

proc arkhamStressTests(arch: string; runner = ""; skip: seq[string] = @[];
                       known: seq[string]; level: int) =
  ## Re-emit + assemble + RUN the corpus with the register file starved to `level`
  ## registers per pool. Uses its own `bin/arkham_stress` binary so the shipped
  ## `bin/arkham` cannot be perturbed by a stray environment variable. `runner`
  ## prefixes the produced executable (`qemu-aarch64` for the `linux_arm64` pass).
  exec "nim c --hints:off -d:arkhamStress -o:bin/arkham_stress src/arkham/arkham.nim"
  let arkham = ("bin" / "arkham_stress").addFileExt(ExeExt)
  let nifasm = ("src" / "nifasm" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  createDir workDir
  # Inherited by the arkham children.
  putEnv("ARKHAM_STRESS", if level > 0: $level else: "")
  for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
    let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
    exec quoteShell(arkham) & " -a:" & arch & " -o:" &
         quoteShell(workDir / (name & ".asm.nif")) & " " & quoteShell(file)
  var total, passed, expectedFail = 0
  var newFailures: seq[string] = @[]
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_") or base.startsWith("err_"): continue
    let name = base[0 ..< base.len - ".c.nif".len]
    if name in skip: continue
    inc total
    let stem = file[0 ..< file.len - ".c.nif".len]
    let asmNif = workDir / (name & ".stress.nif")
    let exe = workDir / (name & ".stress.out")
    var failed = ""
    block run:
      let (ao, ac) = execCmdEx(quoteShell(arkham) & " -a:" & arch & " -o:" &
                               quoteShell(asmNif) & " " & quoteShell(file))
      if ac != 0:
        failed = "codegen: " & ao.splitLines[^2 .. ^1].join(" ").strip; break run
      let (no, nc) = execCmdEx(quoteShell(nifasm) & " -o:" & quoteShell(exe) &
                               " " & quoteShell(asmNif))
      if nc != 0:
        failed = "assemble: " & no.splitLines[^1].strip; break run
      let (po, pc) =
        if runner.len > 0: runProgram(runner, [exe])   # `qemu-aarch64 <exe>`
        else: runProgram(exe)
      if pc == timeoutExitCode:
        failed = "HANG: still running after " & $(runTimeoutMs div 1000) & "s"; break run
      let ecFile = stem & ".exitcode"
      let expectedCode = if fileExists(ecFile): parseInt(readFile(ecFile).strip) else: 0
      let outFile = stem & ".output"
      let expectedOut = if fileExists(outFile): readFile(outFile).strip else: ""
      if pc != expectedCode:
        failed = "MISCOMPILE: exitcode " & $expectedCode & " but got " & $pc; break run
      if po.strip != expectedOut:
        failed = "MISCOMPILE: output mismatch"; break run
    if failed.len == 0:
      if name in known:
        echo "NOTE: ", name, " now passes — remove it from the stress known list"
      inc passed
    elif name in known:
      inc expectedFail
    else:
      newFailures.add name & " — " & failed
  delEnv("ARKHAM_STRESS")
  echo passed, " / ", total - expectedFail, " arkham ", arch,
       " stress tests successful (k=", level, ", ", expectedFail, " known-broken)"
  if newFailures.len > 0:
    quit "FAILURE arkham register-pressure stress (" & arch &
         ") found NEW breakage:\n  " & newFailures.join("\n  ")

# Most `tests/arkham/*.c.nif` run end-to-end under the static Linux/ELF
# `linux_arm64` qemu path — the arm64 backend reached x86-64 feature parity for
# function-pointer calls, `(pat …)` pointer indexing, and thread-locals. List a
# test's stem here only when it fails under THIS pass alone (static ELF, svc
# syscalls, qemu); an AArch64 gap that the macOS run would hit too goes in
# `arkhamA64Unsupported`.
const arkhamLinuxA64Unsupported: seq[string] = @[
  # Nothing is quarantined for the qemu pass alone — the x86-64-pinned fixtures
  # live in `arkhamA64Unsupported`, which this pass also honours.
  #
  # (`keepovf`/`(ovf)` overflow checking now has a64 codegen too: the predicate is
  # computed into a staging bridge — xor/and sign trick for signed add/sub, unsigned
  # compare for carry/borrow, div-based check for mul — since the nifasm vocabulary
  # has no flag-setting `adds`/`subs`. See codegen_a64's KeepovfS.)
  #
  # The a64 backend otherwise reaches x86-64 parity on every arkham test, including
  # the value-core aggregate paths: object/array constructors as a var-init, a call
  # argument, or into a complex lvalue, plus NESTED aggregate fields. The last
  # blocker was a nifasm a64 bug — `parseOperandA64`'s `(dot …)` dropped the inner
  # displacement of a memory-lvalue base, so chained access (`(dot (dot o inner) a)`,
  # `(at (dot h arr) i)`) computed the wrong address; now folded like the x64 parser.
]
  # The arm64 backend reached parity with x86-64 on global / multi-dimensional array
  # addressing: codegen_a64 now uses the same premat-before-tree two-pass
  # (`prematAccess`/`emAccessAddr`) as x86-64 to materialize a global base, a computed
  # index, and a non-scale stride's scratch into registers *before* the operand tree
  # opens, then re-emits `(at base idx [scratch])` for nifasm to fold. Add a test's
  # stem here if a new arm64-only TODO is introduced.

proc arkhamQemuTests() =
  ## Cross-validate the AArch64 backend on Linux: emit each `tests/arkham/*.c.nif`
  ## as `linux_arm64` (static ELF, svc syscalls), assemble with nifasm, and run it
  ## under `qemu-aarch64`, checking exit code + stdout against the same fixtures the
  ## native pass uses. This lets the arm64 path be exercised end-to-end on an x86-64
  ## Linux host (the Darwin/Mach-O binaries can only run on macOS). Skipped silently
  ## when qemu is not installed.
  let qemu = findExe("qemu-aarch64")
  if qemu.len == 0:
    echo "qemu-aarch64 not found — skipping linux_arm64 run tests " &
         "(install: sudo apt-get install qemu-user)"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasm = ("src" / "nifasm" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  createDir workDir
  for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
    let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
    exec quoteShell(arkham) & " -a:linux_arm64 -o:" &
         quoteShell(workDir / (name & ".asm.nif")) & " " & quoteShell(file)
  var total, passed, skipped = 0
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_"): continue
    if base.startsWith("err_"): continue   # must NOT compile — see arkhamRejectionTests
    let name = base[0 ..< base.len - ".c.nif".len]
    if name in arkhamLinuxA64Unsupported or name in arkhamA64Unsupported or
       name in arkhamOsxOnly:
      (inc skipped; continue)                        # arm64-TODO or macOS-only symbol
    inc total
    let stem = file[0 ..< file.len - ".c.nif".len]
    let asmNif = workDir / (name & ".la64.nif")
    let exe = workDir / (name & ".la64.out")
    let (ao, ac) = execCmdEx(quoteShell(arkham) & " -a:linux_arm64 -o:" &
                             quoteShell(asmNif) & " " & quoteShell(file))
    if ac != 0: quit "FAILURE arkham (linux_arm64 codegen) " & file & "\n" & ao
    let (no, nc) = execCmdEx(quoteShell(nifasm) & " -o:" & quoteShell(exe) & " " &
                             quoteShell(asmNif))
    if nc != 0: quit "FAILURE nifasm (linux_arm64 assemble) " & file & "\n" & no
    let (po, pc) = runProgram(qemu, [exe])
    if pc == timeoutExitCode:
      quit "FAILURE (qemu linux_arm64) TIMEOUT after " &
           $(runTimeoutMs div 1000) & "s for " & file
    let ecFile = stem & ".exitcode"
    let expectedCode = if fileExists(ecFile): parseInt(readFile(ecFile).strip) else: 0
    if pc != expectedCode:
      quit "FAILURE (qemu linux_arm64) exitcode " & $expectedCode & " but got " &
           $pc & " for " & file & "\n" & po
    let outFile = stem & ".output"
    let expectedOut = if fileExists(outFile): readFile(outFile).strip else: ""
    if po.strip != expectedOut:
      quit "FAILURE (qemu linux_arm64) output mismatch for " & file &
           " (expected:\n" & expectedOut & "\ngot:\n" & po.strip & "\n)"
    inc passed
  echo passed, " / ", total, " arkham linux_arm64 (qemu) tests successful (",
       skipped, " Darwin-only skipped)"

when defined(macosx):
  exec "nim c -r src/nifasm/nifasm tests/hello_darwin.nif"
  exec "tests/hello_darwin"
  # Declarative call ABI on AArch64 (macOS arm64). Each test exits with
  # (computed - 42), i.e. 0 on success, so plain `exec` validates it.
  exec "nim c -r src/nifasm/nifasm tests/call_a64_reg_args.nif"
  exec "tests/call_a64_reg_args"
  exec "nim c -r src/nifasm/nifasm tests/call_a64_stack_args.nif"
  exec "tests/call_a64_stack_args"
  # AArch64 conditional select/set (csel*/cset*): branch-free min/max and bool
  # materialization from the NZCV flags. Exits 0 only if every result is correct.
  exec "nim c -r src/nifasm/nifasm tests/a64_csel.nif"
  exec "tests/a64_csel"
elif defined(windows):
  exec "nim c -r src/nifasm/nifasm tests/hello_win64.nif"
  execRun("tests" / "hello_win64.exe")

exec "nim c -r src/nifasm/nifasm tests/hello.nif"
exec "nim c -r src/nifasm/nifasm tests/thread_local_tls.nif"
exec "nim c -r src/nifasm/nifasm tests/thread_local_switch.nif"
exec "nim c -r src/nifasm/nifasm tests/atomic_ops.nif"
exec "nim c -r src/nifasm/nifasm tests/bitops_rotate_scan.nif"
exec "nim c -r src/nifasm/nifasm tests/bitops_bittest.nif"
exec "nim c -r src/nifasm/nifasm tests/unique_bind.nif"
exec "nim c -r src/nifasm/nifasm tests/kill_reuse.nif"
exec "nim c -r src/nifasm/nifasm tests/kill_reuse_multi.nif"
exec "nim c -r src/nifasm/nifasm tests/kill_reuse_types.nif"
exec "nim c -r src/nifasm/nifasm tests/dot_at_access.nif"
exec "nim c -r src/nifasm/nifasm tests/nested_dot_at.nif"
exec "nim c -r src/nifasm/nifasm tests/pointer_dot_store.nif"
exec "nim c -r src/nifasm/nifasm tests/array_i64_register_index.nif"
exec "nim c -r src/nifasm/nifasm tests/pointer_field_at.nif"
exec "nim c -r src/nifasm/nifasm tests/pointer_roundtrip.nif"
exec "nim c -r src/nifasm/nifasm tests/string_pointer_field.nif"
exec "nim c -r src/nifasm/nifasm tests/message_inline_array.nif"
exec "nim c -r src/nifasm/nifasm tests/rep_movs_copy.nif"
exec "nim c -r src/nifasm/nifasm tests/call_hello_chain.nif"
exec "nim c -r src/nifasm/nifasm tests/call_multi_result.nif"
exec "nim c -r src/nifasm/nifasm tests/call_result_binding.nif"

# Module system tests
exec "nim c -r src/nifasm/nifasm tests/module_chain.nif"
exec "nim c -r src/nifasm/nifasm tests/module_chain_three.nif"
exec "nim c -r src/nifasm/nifasm tests/module_selectany.nif"
exec "nim c -r src/nifasm/nifasm tests/module_foreign.nif"
exec "nim c -r src/nifasm/nifasm tests/module_type_import.nif"
exec "nim c -r src/nifasm/nifasm tests/module_dedup.nif"
exec "nim c -r src/nifasm/nifasm tests/module_dedup_nested.nif"
exec "nim c -r src/nifasm/nifasm tests/module_no_dedup.nif"


when defined(linux) and defined(amd64):
  # binaries have been built for linux only:
  exec "tests/hello"
  exec "tests/atomic_ops"
  # The new x86-64 bit instructions (rol/ror/rcl/rcr/bsf/bsr/bt/bts/btr/btc):
  # both binaries compute their checks and exit 0 only when every result matches.
  execRun "tests/bitops_rotate_scan"
  execRun "tests/bitops_bittest"
  execRun "tests/dot_at_access"
  execRun "tests/nested_dot_at"
  execRun "tests/pointer_dot_store"
  execRun "tests/array_i64_register_index"
  execRun "tests/pointer_field_at"
  execRun "tests/pointer_roundtrip"
  execExpectOutput("tests/string_pointer_field", "Hello\n")
  execExpectOutput("tests/message_inline_array", "Ping\n")
  execExpectOutput("tests/rep_movs_copy", "Rep!\n")
  execExpectOutput("tests/call_hello_chain", "Hello through calls\n")
  execRun "tests/call_multi_result"

# Failing tests are not platform specific!
execExpectFailure("nim c -r src/nifasm/nifasm tests/double_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/triple_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/quadruple_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/kill_use_after_kill.nif", "Expected variable or register as destination")
# x64 SSE/float register binding: a raw `(xmmN)` use of an xmm register bound to a
# float variable (via `rebind`/`withreg`) must be rejected — the SIMD twin of the
# GPR `(reg)` bound-use guard, closing the float silent-clobber hole.
execExpectFailure("nim c -r src/nifasm/nifasm tests/x64_xmm_raw_bound.nif", "Register XMM8 is bound to variable 'f.0', use the variable name instead")
# AArch64 register-binding checks (mirror the x64 binding guards above): a second
# `(var)` on a still-bound x-register, and a raw `(xN)` use of a bound register.
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_double_bind.nif", "Register X19 is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_raw_bound.nif", "Register X19 is bound to variable 'x.0', use the variable name instead")
# AArch64 SSE/float register binding: a raw `(dN)`/`(sN)` use of a v-register bound to
# a float variable must be rejected — the SIMD twin of the x64 xmm guard above.
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_raw_fbound.nif", "Register D8 is bound to variable 'f.0', use the variable name instead")
# Call-safety: a value living in a caller-saved register (x9) is destroyed by a
# `(call)`; reading it afterward must be rejected (a callee-saved x19 home would survive).
# The callee's own `(clobber …)` is what says so — see the accepting twin below.
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_clobber_after_call.nif", "in register X9 which was clobbered by a call")
# ...and the same code with an EMPTY `(clobber)` must ASSEMBLE: arkham emits that for a
# `(attr "noreturn")` callee, which returns to nobody, so no caller can observe what it
# destroyed. Taking the empty list at face value is what lets a value stay in a
# caller-saved register across a cold guard instead of paying a callee-saved home.
exec "nim c -r src/nifasm/nifasm tests/a64_noreturn_clobber.nif"
# The `rep movs` family names none of its operands in the tree, yet destroys rdi/rsi/rcx.
# Reading a local homed in one of them afterwards must be rejected here — otherwise the
# only symptom is a silently wrong value at run time.
execExpectFailure("nim c -r src/nifasm/nifasm tests/repmovs_clobber.nif", "in register RSI which was clobbered")
# `(at)` operand disjointness: an arkham register-allocation bug can hand the same
# physical register for two operands of one address computation, producing a silently
# wrong address (the "Bug J" class — caught before only as an ASLR-only runtime SEGV).
# nifasm now flags these at assemble time. Two distinct collisions, both arches:
#   * 3-operand `(at base index scratch)` where scratch == base: the `mov scratch,index`
#     clobbers the base before the address is formed (scratch == index stays legal).
#   * folded `(at base index)` SIB where base == index: two distinct live values aliased.
execExpectFailure("nim c -r src/nifasm/nifasm tests/at_scratch_base_collision.nif", "stride scratch aliases the base register (R14)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_at_scratch_base_collision.nif", "stride scratch aliases the base register (X14)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/at_base_index_collision.nif", "array base and index occupy the same register (R14)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_at_base_index_collision.nif", "array base and index occupy the same register (X14)")
# `(mem <base> <stackvar> <disp>)` addresses a word INSIDE a named slot with no address
# register. A named slot knows its size, so an out-of-range offset is a hard error — the
# one safety the `(cast (aptr T) <reg>)` form can never offer, and the reason the copy
# tiering prefers the named form. `(cast T …)` is a legal destination only over MEMORY:
# a register destination must stay a typed binding.
# Storing a non-zero integer literal into a pointer-typed binding is what a code
# generator's STALE REGISTER BINDING looks like (an ordinary value written under a dead
# local's name). It used to assemble silently, so the whole class was invisible unless
# the bad value reached an instruction with its own type rule. The fixture's preceding
# `(mov p.0 0)` must still pass — nulling a pointer is legal, and `cmp ptr, -1`
# (MAP_FAILED) stays legal too, because a COMPARE cannot corrupt a binding.
execExpectFailure("nim c -r src/nifasm/nifasm tests/ptr_store_nonzero.nif", "cannot store the non-zero integer 32 into the pointer-typed destination")
execExpectFailure("nim c -r src/nifasm/nifasm tests/mem_slot_offset_range.nif", "offset 16 is outside stack slot 'buf.0' (16 bytes)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/cast_dest_reg.nif", "Expected memory destination")
execExpectFailure("nim c -r src/nifasm/nifasm tests/missing_result_binding.nif", "Missing result binding: ret.0")
# `(mov <stack slot> (res ret.0))` — a call result stored straight into its stack home.
# This USED to be an expected failure, but only by accident: x86-64's mov check did not
# unwrap `(stackoff …)` while AArch64's did, so the same program was a type error on one
# target and a plain sized store on the other. It is an ordinary spill of a call result;
# both arches accept it now (one shared `movTypeOk`), and `intMemAccess`/`memWidthOpc`
# size the store by what the slot holds.
exec "nim c -r src/nifasm/nifasm tests/stack_result_binding.nif"
execExpectFailure("nim c -r src/nifasm/nifasm tests/result_type_mismatch.nif", "Type mismatch:")
execExpectFailure("nim c -r src/nifasm/nifasm tests/call_missing_argument.nif", "Missing argument: arg.1")
execExpectFailure("nim c -r src/nifasm/nifasm tests/call_a64_missing_arg.nif", "Missing argument: arg.1")
execExpectFailure("nim c -r src/nifasm/nifasm tests/call_duplicate_result_binding.nif", "Result already bound: ret.0")
execExpectFailure("nim c -r src/nifasm/nifasm tests/module_missing.nif", "Foreign module file not found: no_such_mod")
execExpectFailure("nim c -r src/nifasm/nifasm tests/module_missing_symbol.nif", "Unknown type: Missing.0.mod_missing_symbol")
# A foreign global is now bundled into the same image and accessed directly
# (nifasm links the whole program in one invocation), so this succeeds.
exec "nim c -r src/nifasm/nifasm tests/module_gvar_access.nif"

# arkham native-codegen tests: arkham emits the host arch (x86-64 on Linux,
# AArch64/Darwin on macOS), so we run them only where the binaries execute.
when (defined(linux) and defined(amd64)) or (defined(macosx) and defined(arm64)):
  arkhamTests()
  # The same corpus again, against a starved register file. Every argument is
  # picked by BACKEND, not by host: macOS drives the AArch64 emitters, so it takes
  # the same known set and level as the qemu `linux_arm64` pass below.
  arkhamStressTests(arch = (when defined(macosx): "arm64" else: "x64"),
                    skip = (when defined(macosx): arkhamDarwinUnsupported &
                                                  arkhamA64Unsupported
                            else: arkhamOsxOnly),
                    known = (when defined(macosx): arkhamStressA64Known
                             else: arkhamStressKnown),
                    level = (when defined(macosx): arkhamStressA64Level
                             else: arkhamStressLevel))

# The `{.assembler.}` rejections are x86-64-only (see `arkhamRejectionTests`).
when defined(linux) and defined(amd64):
  arkhamRejectionTests(("bin" / "arkham").addFileExt(ExeExt))
  # The debug-info check runs on the x86-64 host binaries `arkhamTests` just
  # built; the AArch64 half of the same tables is covered by the qemu pass only
  # as far as "the program still runs" — a host GDB cannot read its registers.
  arkhamDebugInfoTests()
  arkhamWinUnwindTests()

# Additionally exercise the AArch64 backend on an x86-64 Linux host by emitting the
# `linux_arm64` ELF variant and running it under qemu-aarch64 (no-op if qemu is
# absent). Gives the arm64 path end-to-end coverage without a macOS machine.
when defined(linux) and defined(amd64):
  arkhamQemuTests()

# The AArch64 backend gets the same starved-pool pass, under qemu.
when defined(linux) and defined(amd64):
  if findExe("qemu-aarch64").len > 0:
    arkhamStressTests(arch = "linux_arm64", runner = "qemu-aarch64",
                      skip = arkhamLinuxA64Unsupported & arkhamA64Unsupported &
                             arkhamOsxOnly,
                      known = arkhamStressA64Known,
                      level = arkhamStressA64Level)
