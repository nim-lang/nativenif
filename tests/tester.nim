import std/[os, osproc, streams, strutils]
# The SHARED intrinsic table arkham itself compiles against — imported for
# `declared(intrinsics.FldrqOp)` alone, to stage the vector fixtures (see
# `arkhamStagedVec`) in lock-step with codegen_arm's staged AdvSIMD block.
from "../../nimony/src/lib/intrinsics" import nil
# The AArch64 encoders, for the byte-level checks below. Importing the module is
# what lets a test assert an ENCODING rather than a program's output — the only
# way to check a sequence whose whole point is that running it changes nothing.
import "../src/nifasm/arm64/encoder"
import "../src/nifasm/core/buffers"

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
  ##
  ## A timed-out child's output is drained TOO, after the kill — by then its end of
  ## the pipe is closed, so the read hits EOF instead of blocking. It used to be
  ## thrown away, which made "what had it printed before it hung?" unanswerable
  ## from a failure message; a firmware image that deliberately never exits has
  ## nothing BUT that output to be judged on.
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
    let output = p.outputStream.readAll()
    p.close()
    result = (output, timeoutExitCode)
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

const arkhamStagedVec: seq[string] =
  # Staged exactly like codegen_arm's AdvSIMD block (`when declared(FldrqOp)`):
  # these fixtures declare `{.instruction: "fldrq".}`-family rows, which resolve
  # through the shared `nimony/src/lib/intrinsics` table. Against a nimony
  # checkout whose table lacks the vector rows (CI pins nimony's default
  # branch), arkham compiles with the vec path inert and the fixture cannot
  # even NAME its instructions — so every pass skips it here, and it un-skips
  # by itself the moment the rows land. No edit needed then, same as the guard.
  when declared(intrinsics.FldrqOp): @[]
  else: @["a64_vec_instr"]

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
  # mode's premise ("no fallbacks", doc/intrinsics.md §8), not a gap. The AArch64
  # version is the different `when` branch the user writes, and it exists:
  # `assembler_a64`, with `x0`/`x9`/`x19` in it.
  "assembler_x64",
  # `{.naked.}` — the same story as `assembler_x64` (it may only accompany it),
  # plus the `TraceTable` row, whose `targets` is x86-64 alone until the AArch64
  # stack walk exists. The table itself IS emitted on every target; what is
  # missing is the walk that reads it (`lib/std/stacktraces`).
  "naked_stacktrace_x64",
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

const arkhamX64Unsupported: seq[string] = @[
  # The mirror of `arkhamA64Unsupported`: a fixture whose `{.register: "…".}`
  # pins name ARM registers has no x86-64 reading either, and the native pass
  # targets x86-64 everywhere except macOS (where it targets arm64 and this
  # fixture is exactly what should run). Two lists, one rule — an `.assembler`
  # body belongs to the target it names.
  "assembler_a64",
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
  # `{.naked.}` is a promise about SP, and each of these three breaks it in a way
  # that produces no diagnostic of its own: an allocated body would spill into a
  # frame that is not there, a `{.stack.}` local names a slot in that same frame,
  # and a callee-saved register whose `push` never happened hands the caller back
  # a destroyed value — corruption that surfaces arbitrarily far from the cause.
  ("err_naked_alone", "`{.naked.}` requires `{.assembler.}`"),
  ("err_naked_stack", "cannot declare a `{.stack.}` local"),
  ("err_naked_callee", "cannot use the callee-saved register(s) rbx"),
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
  let nifasm = ("bin" / "nifasm").addFileExt(ExeExt)
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

proc arkhamWinTraceTableTests() =
  ## The runtime trace table (`doc/tracetable.md`) on the PE path, checked under
  ## Wine. Worth its own run because the table is written by each object writer
  ## SEPARATELY, after that writer's own layout passes: `writeElf` fills it after
  ## the jump shortener and the alignment pass have moved every proc, `writeExe`
  ## before either exists. A table whose offsets were computed against the wrong
  ## layout still has the right magic and the right count — it just names the
  ## wrong procs — so only running the walk catches it.
  ##
  ## `tests/win_tracetable.c.nif` is the ELF fixture `naked_stacktrace_x64` with
  ## `ExitProcess` in place of `exit`: a `{.naked.}` proc hands back its caller's
  ## frame, and the program exits with 1|2|4 for the three things that must hold
  ## — the table's magic, the return address lying below the table, and lying
  ## within a megabyte of it.
  if findExe("wine").len == 0:
    echo "0 / 0 arkham win64 trace-table tests (wine not installed)"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasm = ("bin" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  let asmNif = workDir / "win_tracetable.asm.nif"
  let exe = workDir / "win_tracetable.exe"
  exec quoteShell(arkham) & " -a:win_x64 -o:" & quoteShell(asmNif) & " " &
       quoteShell("tests" / "win_tracetable.c.nif")
  exec quoteShell(nifasm) & " -o:" & quoteShell(exe) & " " & quoteShell(asmNif)
  let (_, code) = execCmdEx("wine " & quoteShell(exe) & " 2>/dev/null")
  if code != 7:
    quit "FAILURE arkham win64 trace table: exit code " & $code &
         " (want 7 = magic|below-table|near-table)"
  echo "1 / 1 arkham win64 trace-table tests successful"

proc buildToolchain() =
  ## `bin/arkham` and `bin/nifasm`, built ONCE and BEFORE anything that runs them.
  ##
  ## They used to be built inside `arkhamTests`, which is two mistakes at once:
  ## that proc runs AFTER every Cortex-M suite, and it is `when`-gated to the two
  ## hosts whose output actually executes. So on a clean checkout the Cortex-M
  ## suites found no binaries — the qemu-gated ones skipped and said nothing,
  ## `cortexMInterruptTests` is a COMPILE-time rejection and rightly does not
  ## skip, and it failed with `bin/arkham: not found`.
  ##
  ## It never showed in a developer's tree, where both binaries are always lying
  ## around from the last manual build. That is exactly the class of thing CI is
  ## for, and the fix is to stop having a build be a side effect of a test.
  exec "nim c --hints:off src/arkham/arkham.nim"   # `--outdir: bin` in its nim.cfg
  exec "nim c --hints:off -o:bin/nifasm src/nifasm/nifasm.nim"

proc arkhamTests() =
  ## Each `tests/arkham/*.c.nif` is hand-written Leng: arkham generates asm-NIF,
  ## nifasm assembles+links it to a native executable, and we check the run's exit
  ## code (`<stem>.exitcode`, default 0) and stdout (`<stem>.output`, default
  ## empty). The target arch follows the host so the binaries actually run here:
  ## x86-64/ELF on Linux, AArch64/Mach-O on macOS.
  const arch = when defined(macosx): "arm64" else: "x64"
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasm = ("bin" / "nifasm").addFileExt(ExeExt)
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
    if name in arkhamStagedVec: continue   # vector rows not in the intrinsic table yet
    when defined(macosx):
      # The macOS run targets arm64, so BOTH lists apply: the fixture may be
      # x86-64-pinned, or it may be portable but depend on a Linux-only symbol.
      if name in arkhamDarwinUnsupported or name in arkhamA64Unsupported: continue
    else:
      if name in arkhamOsxOnly: continue            # macOS-only libSystem symbol
      if name in arkhamX64Unsupported: continue     # Arm-pinned `.assembler` body
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
  # Six 128-bit vector locals live at once. On x86-64 those can only come from
  # the VOLATILE xmm pool — SysV has no callee-saved xmm at all — and the stress
  # pass shrinks that pool until they no longer fit. The failure is the intended
  # one: a loud `no SIMD register home` at compile time, never a miscompile. It
  # goes away when a vector local can spill (which needs memory-operand forms of
  # the SSE rows) or when the pool is not artificially squeezed.
  "a64_vec_instr",
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
  # (`a64_vec_instr` lived here — six 128-bit vector locals live at once
  # overran the stress-starved SIMD pool into the designed loud
  # out-of-registers error. The planer's early-free now covers `InFReg`
  # homes too, so the dead vector temps hand their registers back in time
  # and the fixture passes even stressed.)
  # Back on this list at k=3 since the planer gives a call-free local a VOLATILE
  # register first (see `getSym`). It is the emitter's OWN long-known gap — the
  # intrinsic-operand pick has no arm that evicts a live local — and not a new one;
  # what changed is only what used to mask it. Under callee-saved-first, `main.0`'s
  # `a.0` found no home and spilled, which left one volatile over for the CAS's third
  # operand register; volatile-first homes `a.0`/`b.0`/`c.0` in x9/x10/x11 instead, so
  # at the `(instr acx.0 …)` every one of the six registers a k=3 machine has is taken:
  # three by those live locals, x19/x21 by the two operand temps already reserved, and
  # x20 sealed as the destination `ok.0`. Wanting a fourth, `takeInstrReg` reaches
  # `takeHeld`, whose whole point is that demoting a local mid-emission is impossible
  # in the merged core, and it fails LOUDLY. Verified across k=3..6 and unstressed:
  # k=3 asserts, every higher k returns the correct 112 — a totality gap, never a
  # wrong answer. Closing it is the same "evict a live local" arm the x86-64
  # `aggr_arg_parked` entries above wait on; the fixture needs 7 live registers where
  # a k=3 machine has 6, so nothing short of that arm makes it fit.
  "atomic_cas_regpressure",
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
  let nifasm = ("bin" / "nifasm").addFileExt(ExeExt)
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
    if name in skip or name in arkhamStagedVec: continue
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
  # has no flag-setting `adds`/`subs`. See codegen_arm's KeepovfS.)
  #
  # The a64 backend otherwise reaches x86-64 parity on every arkham test, including
  # the value-core aggregate paths: object/array constructors as a var-init, a call
  # argument, or into a complex lvalue, plus NESTED aggregate fields. The last
  # blocker was a nifasm a64 bug — `parseOperandA64`'s `(dot …)` dropped the inner
  # displacement of a memory-lvalue base, so chained access (`(dot (dot o inner) a)`,
  # `(at (dot h arr) i)`) computed the wrong address; now folded like the x64 parser.
]
  # The arm64 backend reached parity with x86-64 on global / multi-dimensional array
  # addressing: codegen_arm now uses the same premat-before-tree two-pass
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
  let nifasm = ("bin" / "nifasm").addFileExt(ExeExt)
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
       name in arkhamOsxOnly or name in arkhamStagedVec:
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

# BEFORE anything that runs them, and unconditionally: a suite that skips still
# leaves the next one needing these, and not every suite here can skip.
buildToolchain()

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
  when false:
    # AdvSIMD/NEON q-register forms (fldrq/fstrq/vfadd/vfsub/vfmul/vfmla/vdup/veor),
    # both arrangements (.2d via d-spelled regs, .4s via s-spelled). Exits 0 only if
    # every lane computes correctly.
    exec "nim c -r src/nifasm/nifasm tests/a64_neon.nif"
    exec "tests/a64_neon"
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
# The BASE-FREE slot spellings — `(mem slot)`, `(mem slot off)`, `(dot slot field)`,
# `(at slot idx)`, `(lea D slot)`. Every target spells a slot access this way now; the
# frame base is the slot's own and is never written out. `dot_at_access` above pins the
# older explicit-`(rsp)` forms, which stay accepted on x86-64.
exec "nim c -r src/nifasm/nifasm tests/slot_base_free.nif"
exec "nim c -r src/nifasm/nifasm tests/nested_dot_at.nif"
exec "nim c -r src/nifasm/nifasm tests/pointer_dot_store.nif"
exec "nim c -r src/nifasm/nifasm tests/array_i64_register_index.nif"
exec "nim c -r src/nifasm/nifasm tests/mem_reg_index.nif"
exec "nim c -r src/nifasm/nifasm tests/jcc_sign.nif"
exec "nim c -r src/nifasm/nifasm tests/alu_subwidth.nif"
exec "nim c -r src/nifasm/nifasm tests/alu_memreg.nif"
exec "nim c -r src/nifasm/nifasm tests/lenient_port.nif"
exec "nim c -r src/nifasm/nifasm tests/lenient_xmm.nif"
exec "nim c -r src/nifasm/nifasm tests/lea_scaled.nif"
exec "nim c -r src/nifasm/nifasm tests/packed_sse.nif"
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
  execRun "tests/slot_base_free"
  execRun "tests/nested_dot_at"
  execRun "tests/pointer_dot_store"
  execRun "tests/array_i64_register_index"
  # `(mem base index scale [disp])` with a RAW register index (the general SIB
  # form, what distilled gcc bodies spell) + a sub-width cast load over it.
  execRun "tests/mem_reg_index"
  # js/jns: sign-flag conditional jumps; exits 0 only when both are taken.
  execRun "tests/jcc_sign"
  # Sub-width register ALU via explicit `(cast (u N) (reg))`: 32-bit ops
  # zero-extend, 8/16-bit ops preserve the upper bits, flags at the operation
  # width, shift counts masked to it, REX-sensitive byte registers (sil/r14b).
  execRun "tests/alu_subwidth"
  # Sized mem±reg ALU (32/8-bit add/or into a cast-typed slot; reg += mem32)
  # and rotate-by-CL.
  execRun "tests/alu_memreg"
  # `(lenient)` proc pragma: backward jump, raw r11, bare (call P), tail (jmp P)
  # inside one ported proc, called normally from a strict main.
  execRun "tests/lenient_port"
  # The xmm splice-glue shapes inside a lenient proc: raw rsp arithmetic for a
  # spill area, movdqu save/restore through (mem (rsp) N), movfq gpr→xmm and
  # punpcklqdq packing two quadwords for one 16-byte store.
  execRun "tests/lenient_xmm"
  # lea over the general mem forms with NAMED locals: base+index (`[a+a]`,
  # `[a+b*4-3]`) and the no-base scaled form `(mem 0 a 8)` = `[a*8]`.
  execRun "tests/lea_scaled"
  # The packed-SSE vocabulary for the axpy vectorization plan: movupd/movups
  # loads+stores, mulpd/addpd on 2 f64 lanes, mulps/addps on 4 f32 lanes,
  # punpcklqdq f64 broadcast and shufps f32 broadcast; checks both lane sums.
  execRun "tests/packed_sse"
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
# The AArch64 twin of `slot_base_free`: the base-free slot spellings, including the
# `(mem <slot> <off>)` form that reads one word of a stack aggregate with NO address
# register. It targets `linux_arm64`, so unlike the Darwin a64 fixtures it produces an
# ELF this host can run under qemu (see the guarded `execRun` further down).
exec "nim c -r src/nifasm/nifasm tests/a64_slot_base_free.nif"
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
# The same check over the BASE-FREE spelling `(mem <slot> <off>)` — and on all three
# targets, because all three now accept it. The bounds check is the whole reason the
# named form is preferable to `(cast (aptr T) <reg>)`, so it must not be reachable
# only through x86-64's older explicit-`(rsp)` spelling.
execExpectFailure("nim c -r src/nifasm/nifasm tests/mem_slot_offset_range_basefree.nif", "offset 16 is outside stack slot 'p.0' (16 bytes)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_mem_slot_offset_range.nif", "offset 16 is outside stack slot 'p.0' (16 bytes)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/cortex_m_mem_slot_offset_range.nif", "offset 8 is outside stack slot 'p.0' (8 bytes)")
execExpectFailure("nim c -r src/nifasm/nifasm tests/cast_dest_reg.nif", "Expected memory destination")
# The sub-width width-cast destination is an ALU-only exception: `mov` keeps the
# strict rule, so the pointer-store protection cannot be casted away.
execExpectFailure("nim c -r src/nifasm/nifasm tests/mov_cast_dest_subwidth.nif", "Expected memory destination")
# The same backward-jump shape WITHOUT the (lenient) pragma must stay rejected.
execExpectFailure("nim c -r src/nifasm/nifasm tests/lenient_missing.nif", "backward jump to an already-defined label")
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

proc vgClientRequestEncodingTests() =
  ## The valgrind client request, checked as BYTES.
  ##
  ## Ungated, unlike everything below it: this executes nothing, it compares an
  ## encoder's output to constants, so it is as meaningful on an AArch64 host as on
  ## an x86-64 one. That matters here more than usual, because the two things this
  ## sequence can get wrong are both invisible to a program that runs it.
  ##
  ## The first is the sequence itself. Valgrind recognizes these five instructions
  ## and nothing else; one wrong bit and the request silently becomes what it already
  ## pretends to be — a no-op — so every downstream leak report is simply absent
  ## rather than wrong. The constants below are `valgrind/valgrind.h`'s arm64
  ## `__SPECIAL_INSTRUCTION_PREAMBLE` and marker, assembled and disassembled to
  ## confirm them rather than transcribed.
  ##
  ## The second is the register staging around it, and specifically the two aliasing
  ## cases: the request block arriving in x3 or x4 (the registers the protocol takes),
  ## and the destination BEING one of them. A test that runs a program cannot reach
  ## these — arkham's planner never leaves a live value in x3/x4 — so if they are not
  ## checked here they are not checked at all.
  proc words(b: Bytes): seq[uint32] =
    result = @[]
    let p = cast[ptr UncheckedArray[uint32]](b.rawData)
    for i in 0 ..< b.len div 4: result.add p[i]

  const
    Mov = 0xAA0003E0'u32   ## `mov Xd, Xm` = `orr Xd, XZR, Xm`
    Preamble = [0x93CC0D8C'u32, 0x93CC358C'u32, 0x93CCCD8C'u32, 0x93CCF58C'u32]
    Marker = 0xAA0A014A'u32
  proc mov(rd, rm: Register): uint32 =
    Mov or (uint32(ord(rm)) shl 16) or uint32(ord(rd))

  proc check(rd, rargs: Register; staged: Register; what: string) =
    ## `staged` is the register x4 must be loaded FROM: the operand itself, or the
    ## saved copy when the operand is one of the two the sequence overwrites.
    var b = default(Bytes)
    emitVgClientRequest(b, rd, rargs)
    let got = words(b)
    var want = @[mov(X16, X3), mov(X14, X4), 0xD2800003'u32, mov(X4, staged)]
    for w in Preamble: want.add w
    want.add Marker
    want.add mov(X15, X3)
    want.add mov(X3, X16)
    want.add mov(X4, X14)
    want.add mov(rd, X15)
    if got != want:
      var msg = "FAILURE vgreq encoding (" & what & "):\n  got  "
      for w in got: msg.add "0x" & toHex(w, 8) & " "
      msg.add "\n  want "
      for w in want: msg.add "0x" & toHex(w, 8) & " "
      quit msg

  # Ordinary: neither operand is one of the protocol's registers.
  check(X9, X11, X11, "plain")
  # The request block arrives in x3 / x4 — it must be read back from the SAVED copy,
  # or staging x4 would destroy the very address being staged.
  check(X9, X3, X16, "block in x3")
  check(X9, X4, X14, "block in x4")
  # The destination IS a protocol register. Legal, and it must be written after the
  # restores: the allocator chose x3/x4 to hold the result, so the old value is dead,
  # but a result written before the restore would be overwritten by it.
  check(X3, X11, X11, "dest in x3")
  check(X4, X3, X16, "dest in x4, block in x3")
  echo "5 / 5 vgreq encoding tests successful"

const cortexMQemu = "qemu-system-arm"
const cortexMArgs = ["-M", "mps2-an386", "-cpu", "cortex-m4",
                     "-display", "none", "-serial", "none", "-monitor", "none",
                     "-chardev", "stdio,id=semi",
                     "-semihosting-config", "enable=on,target=native,chardev=semi",
                     "-kernel"]
  ## The canonical Cortex-M runner. The `-chardev stdio` routing is load-bearing:
  ## without it QEMU writes the semihosting console to its own stderr, mixed in
  ## with its diagnostics, where it cannot be compared against expected output.
  ## See doc/cortex_m.md.

proc thumb2SelfTest() =
  ## Build the Thumb-2 encoder's self-checking image and run it. The image
  ## computes ~45 expressions and exits with the 1-based index of the first whose
  ## result differs from the expected value, so a failure NAMES the broken
  ## encoding rather than just crashing.
  ##
  ## Executing the instructions is the strongest oracle available: QEMU ships no
  ## disassembler in this configuration, but its DECODER is the one that will run
  ## whatever the backend emits, so "the result is right" checks the encoding at
  ## exactly the level that matters — and it exercises the branch encoders and the
  ## relocation patcher too, which a byte-comparison could not.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping Thumb-2 encoder self-test " &
         "(install: sudo apt-get install qemu-system-arm)"
    return
  let gen = ("bin" / "thumb2_selftest").addFileExt(ExeExt)
  exec "nim c --hints:off --warnings:off -o:" & gen & " tests/thumb2_selftest.nim"
  let elf = "tests" / "thumb2_selftest.elf"
  exec quoteShell(gen) & " " & quoteShell(elf)
  var args: seq[string] = @[]
  for a in cortexMArgs: args.add a
  args.add elf
  let (output, code) = runProgram(qemu, args)
  if code == timeoutExitCode:
    quit "FAILURE (TIMEOUT) Thumb-2 encoder self-test\n"
  if code != 0:
    quit "FAILURE Thumb-2 encoder self-test: check #" & $code &
         " produced the wrong value\n" & output &
         "\n(run `" & gen & " x.elf` to list the checks by index)"
  removeFile elf
  echo "Thumb-2 encoder self-test successful (all checks passed)"


const avrSim = "bin" / "avrtest"

proc avrSelfTest() =
  ## Build the AVR encoder's self-checking image and run it. The image computes
  ## 59 expressions and exits with the 1-based index of the first whose result
  ## differs from the expected value, so a failure NAMES the broken encoding.
  ##
  ## Then the same image is built 59 more times, each with one check's EXPECTED
  ## value corrupted, and each of those must fail with exactly that index. That
  ## sweep is what makes the first run mean something: a check whose emitter
  ## writes no bytes at all, or which compares against a value the harness itself
  ## left in the pair, passes the plain run and says nothing.
  ##
  ## AVRtest is built from source rather than installed — see doc/internals/avr.md.
  if not fileExists(avrSim):
    echo avrSim, " not found - skipping AVR encoder self-test ",
         "(build it: see doc/internals/avr.md)"
    return
  let gen = ("bin" / "avr_selftest").addFileExt(ExeExt)
  exec "nim c --hints:off --warnings:off -o:" & gen & " tests/avr_selftest.nim"
  let elf = "tests" / "avr_selftest.elf"

  proc runImage(): (string, int) =
    var args = @["-q", "-mmcu=avr5", "-s", "32k", elf]
    runProgram(avrSim, args)

  exec quoteShell(gen) & " " & quoteShell(elf)
  let (output, code) = runImage()
  if code == timeoutExitCode:
    quit "FAILURE (TIMEOUT) AVR encoder self-test\n"
  if code != 0:
    quit "FAILURE AVR encoder self-test: check #" & $code &
         " produced the wrong value\n" & output &
         "\n(run `" & gen & " --list` to name the checks by index)"

  let (listing, listCode) = runProgram(gen, @["--list"])
  if listCode != 0: quit "FAILURE AVR encoder self-test: --list failed"
  let total = listing.strip.splitLines.len
  for i in 1 .. total:
    exec quoteShell(gen) & " " & quoteShell(elf) & " --mutate:" & $i
    let (_, mutCode) = runImage()
    if mutCode != i:
      quit "FAILURE AVR encoder self-test: check #" & $i &
           " does not detect its own mutation (exited " & $mutCode &
           ", expected " & $i & ") — it is passing vacuously"
  removeFile elf
  echo "AVR encoder self-test successful (", total,
       " checks, each verified to detect its own mutation)"


proc avrAsmTests() =
  ## Assemble hand-written AVR asm-NIF with nifasm and run the resulting firmware
  ## under AVRtest. This is the END-TO-END gate for the instruction selector: the
  ## encoder self-test proves the ENCODINGS, but only these exercise the operand
  ## model, the register-binding table, the relocation patching and the ELF32
  ## image together.
  ##
  ## Each fixture exits with a value it COMPUTED, so a wrong encoding shows up as
  ## a wrong exit code rather than as output that happens to look right.
  if not fileExists(avrSim):
    echo avrSim, " not found - skipping AVR assembler tests"
    return
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  const fixtures = [("hello_avr", 0, "Hello AVR\n"),
                    ("avr_alu", 158, ""),
                    ("avr_branch", 42, ""),
                    ("avr_loop", 45, ""),
                    ("avr_frame", 42, ""),
                    ("avr_call", 42, "")]
  var passed = 0
  for (stem, wantCode, wantOut) in fixtures:
    let src = "tests" / (stem & ".nif")
    let elf = "tests" / (stem & ".elf")
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(src)
    let (output, code) = runProgram(avrSim,
      @["-q", "-mmcu=avr5", "-s", "32k", elf])
    if code == timeoutExitCode:
      quit "FAILURE (TIMEOUT) avr " & stem & "\n"
    if code != wantCode:
      quit "FAILURE avr " & stem & ": exit " & $code & ", want " &
           $wantCode & "\n" & output
    if output != wantOut:
      quit "FAILURE avr " & stem & " output\nExpected: " & escape(wantOut) &
           "\nGot:      " & escape(output)
    removeFile elf
    inc passed
  echo passed, " / ", fixtures.len, " AVR assembler tests successful"


const rvSim = "qemu-riscv32"

proc rv32SelfTest() =
  ## Build the RV32 encoder's self-checking image and run it. 51 expressions,
  ## each exiting with its own index on mismatch, then the same image rebuilt 51
  ## more times with one check's EXPECTED value corrupted — every one of those
  ## must fail with exactly that index, or the check was passing vacuously.
  ##
  ## The target is HOSTED, so this is a plain Linux binary under `qemu-riscv32`:
  ## no board, no semihosting, and the exit status is a real `exit` syscall.
  let qemu = findExe(rvSim)
  if qemu.len == 0:
    echo rvSim, " not found - skipping RV32 encoder self-test ",
         "(install: sudo apt-get install qemu-user)"
    return
  let gen = ("bin" / "rv32_selftest").addFileExt(ExeExt)
  exec "nim c --hints:off --warnings:off -o:" & gen & " tests/rv32_selftest.nim"
  let elf = "tests" / "rv32_selftest.elf"
  exec quoteShell(gen) & " " & quoteShell(elf)
  let (output, code) = runProgram(qemu, @[elf])
  if code == timeoutExitCode:
    quit "FAILURE (TIMEOUT) RV32 encoder self-test\n"
  if code != 0:
    quit "FAILURE RV32 encoder self-test: check #" & $code &
         " produced the wrong value\n" & output &
         "\n(run `" & gen & " --list` to name the checks by index)"

  let (listing, listCode) = runProgram(gen, @["--list"])
  if listCode != 0: quit "FAILURE RV32 encoder self-test: --list failed"
  let total = listing.strip.splitLines.len
  for i in 1 .. total:
    exec quoteShell(gen) & " " & quoteShell(elf) & " --mutate:" & $i
    let (_, mutCode) = runProgram(qemu, @[elf])
    if mutCode != i:
      quit "FAILURE RV32 encoder self-test: check #" & $i &
           " does not detect its own mutation (exited " & $mutCode &
           ", expected " & $i & ") — it is passing vacuously"
  removeFile elf
  echo "RV32 encoder self-test successful (", total,
       " checks, each verified to detect its own mutation)"


proc rv32AsmTests() =
  ## Assemble hand-written RV32 asm-NIF and run the result under `qemu-riscv32`.
  ## The END-TO-END gate for the instruction selector: the encoder self-test
  ## proves the ENCODINGS, but only these exercise the operand model, the
  ## register-binding table, the relocation patching and the ELF32 image
  ## together — including the two-PT_LOAD page separation, which is invisible to
  ## everything except actually running the file.
  let qemu = findExe(rvSim)
  if qemu.len == 0:
    echo rvSim, " not found - skipping RV32 assembler tests"
    return
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  const fixtures = [("hello_rv32", 0, "Hello RISC-V\n"),
                    ("rv32_alu", 158, ""),
                    ("rv32_branch", 42, ""),
                    ("rv32_loop", 45, ""),
                    ("rv32_mem", 42, ""),
                    ("rv32_call", 42, "")]
  var passed = 0
  for (stem, wantCode, wantOut) in fixtures:
    let src = "tests" / (stem & ".nif")
    let elf = "tests" / (stem & ".elf")
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(src)
    let (output, code) = runProgram(qemu, @[elf])
    if code == timeoutExitCode:
      quit "FAILURE (TIMEOUT) rv32 " & stem & "\n"
    if code != wantCode:
      quit "FAILURE rv32 " & stem & ": exit " & $code & ", want " & $wantCode &
           "\n" & output
    if output != wantOut:
      quit "FAILURE rv32 " & stem & " output\nExpected: " & escape(wantOut) &
           "\nGot:      " & escape(output)
    removeFile elf
    inc passed
  echo passed, " / ", fixtures.len, " RV32 assembler tests successful"


proc arkhamRv32Tests() =
  ## The RV32 Leng corpus: `arkham -a:rv32` → `nifasm` → `qemu-riscv32`, checking
  ## each fixture's exit code against its `.exitcode` file.
  let qemu = findExe(rvSim)
  if qemu.len == 0:
    echo rvSim, " not found - skipping arkham RV32 tests"
    return
  let arkhamExe = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  var passed = 0
  var total = 0
  for file in walkFiles("tests/arkham_rv32/*.c.nif"):
    inc total
    let stem = file.extractFilename.changeFileExt("").changeFileExt("")
    let asmFile = "tests" / "arkham_rv32" / (stem & ".asm.nif")
    let elf = "tests" / "arkham_rv32" / (stem & ".elf")
    exec quoteShell(arkhamExe) & " -a:rv32 -o:" & quoteShell(asmFile) & " " &
         quoteShell(file)
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(asmFile)
    let (output, code) = runProgram(qemu, @[elf])
    if code == timeoutExitCode:
      quit "FAILURE (TIMEOUT) arkham rv32 " & stem & "\n"
    let want = parseInt(readFile("tests" / "arkham_rv32" / (stem & ".exitcode")).strip)
    if code != want:
      quit "FAILURE arkham rv32 " & stem & ": exit " & $code & ", want " & $want &
           "\n" & output
    removeFile asmFile
    removeFile elf
    inc passed
  echo passed, " / ", total, " arkham RV32 tests successful"


proc arkhamAvrTests() =
  ## The AVR Leng corpus: `arkham -a:avr` → `nifasm` → AVRtest, checking each
  ## fixture's exit code against its `.exitcode` file — the same oracle every
  ## other target's corpus uses.
  if not fileExists(avrSim):
    echo avrSim, " not found - skipping arkham AVR tests"
    return
  let arkhamExe = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  var passed = 0
  var total = 0
  for file in walkFiles("tests/arkham_avr/*.c.nif"):
    inc total
    let stem = file.extractFilename.changeFileExt("").changeFileExt("")
    let asmFile = "tests" / "arkham_avr" / (stem & ".asm.nif")
    let elf = "tests" / "arkham_avr" / (stem & ".elf")
    exec quoteShell(arkhamExe) & " -a:avr -o:" & quoteShell(asmFile) & " " &
         quoteShell(file)
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(asmFile)
    let (output, code) = runProgram(avrSim, @["-q", "-mmcu=avr5", "-s", "32k", elf])
    if code == timeoutExitCode:
      quit "FAILURE (TIMEOUT) arkham avr " & stem & "\n"
    let want = parseInt(readFile("tests" / "arkham_avr" / (stem & ".exitcode")).strip)
    if code != want:
      quit "FAILURE arkham avr " & stem & ": exit " & $code & ", want " & $want &
           "\n" & output
    removeFile asmFile
    removeFile elf
    inc passed
  echo passed, " / ", total, " arkham AVR tests successful"


proc arkhamAvrRejections() =
  ## A partial backend is only safe to ship if the gap is a DIAGNOSTIC rather
  ## than a wrong answer, and this backend's gap is wide. So the diagnostics are
  ## what these pin: each input names a construct the emitter does not implement,
  ## and the refusal has to say which one and where to look.
  let arkhamExe = ("bin" / "arkham").addFileExt(ExeExt)
  const cases = [
    # A 32-bit value. The failure a user is most likely to hit, because the
    # frontend's default `int` is wider than this machine's word — and the one
    # that must never be silently truncated, since every load and store the
    # emitter writes moves exactly two bytes.
    ("tests/arkham_m/leafret.c.nif", "32 bits wide"),
    # An aggregate: a shape the value core has no representation for at all.
    ("tests/arkham_avr_reject/aggr.c.nif", "is an aggregate"),
    # A shift by a value rather than a constant. Refused for what the MACHINE is
    # — there is no variable-shift instruction — not for a missing feature.
    ("tests/arkham_avr_reject/varshift.c.nif", "variable-shift"),
    # A syscall. Refused for what it IS rather than as an unimplemented feature:
    # a firmware image has no OS underneath it, on this target or any other.
    ("tests/arkham/hello.c.nif", "no OS to call into")]
  var passed = 0
  for (file, want) in cases:
    let (output, code) = runProgram(arkhamExe,
      @["-a:avr", "-o:" & (getTempDir() / "avr_reject.asm.nif"), file])
    if code == 0:
      quit "FAILURE arkham avr rejection: " & file & " was ACCEPTED"
    if not output.contains(want):
      quit "FAILURE arkham avr rejection: " & file & "\nexpected to mention: " &
           want & "\ngot: " & output
    inc passed
  echo passed, " / ", cases.len, " arkham AVR rejection tests successful"


proc cortexMAsmTests() =
  ## Assemble hand-written Cortex-M asm-NIF with nifasm and run the resulting
  ## firmware under QEMU. This is the END-TO-END gate for the instruction
  ## selector: the encoder self-test above proves the ENCODINGS, but only these
  ## exercise the operand model, the register-binding table, the relocation
  ## patching and the ELF32 image together.
  ##
  ## Each fixture exits with a value it COMPUTED, so a wrong encoding shows up as
  ## a wrong exit code rather than as output that happens to look right.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping Cortex-M assembler tests"
    return
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  const fixtures = [("hello_cortex_m", 0, "Hello Cortex-M\n"),
                    ("cortex_m_alu", 42, ""),
                    ("cortex_m_call", 42, ""),
                    ("cortex_m_stackargs", 42, ""),
                    ("cortex_m_global", 42, ""),
                    ("cortex_m_aggr", 42, "")]
  var passed = 0
  for (stem, wantCode, wantOut) in fixtures:
    let src = "tests" / (stem & ".nif")
    let elf = "tests" / (stem & ".elf")
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(src)
    var args: seq[string] = @[]
    for a in cortexMArgs: args.add a
    args.add elf
    let (output, code) = runProgram(qemu, args)
    if code == timeoutExitCode:
      quit "FAILURE (TIMEOUT) cortex-m " & stem & "\n"
    if code != wantCode:
      quit "FAILURE cortex-m " & stem & ": exit " & $code & ", want " &
           $wantCode & "\n" & output
    if output != wantOut:
      quit "FAILURE cortex-m " & stem & " output\nExpected: " & escape(wantOut) &
           "\nGot:      " & escape(output)
    removeFile elf
    inc passed
  echo passed, " / ", fixtures.len, " Cortex-M assembler tests successful"


const cortexMRejections: seq[(string, string)] = @[
  # A name this target has no such thing as. WHICH names exist is arkham's
  # question by design — sem deliberately does not ask — so this is the only
  # place the answer can be given, and it is given BY NAME.
  ("err_interrupt_unknown", "is not an interrupt of this target"),
  # Two handlers for one entry. A table word holds one address, so the second
  # would silently win; refusing is the only reading that is not a coin toss.
  ("err_interrupt_dup", "a table word holds one address"),
  # A volatile access wider than one machine access. Splitting it into halves is
  # two accesses, which is not what a device register was asked for — and the
  # 64-bit path exists on this target, so nothing but the row's meaning stops it.
  ("err_volatile_wide", "must be ONE machine access"),
  # ── `{.assembler.}` pins (doc/intrinsics.md §8) ────────────────────────────
  # Arkham owns these rules outright — nimony's sem only forwards the pragmas —
  # and every one of them is target-specific, which is precisely why the Arm mode
  # needs its own rejection coverage rather than inheriting x86-64's.
  #
  # A register spelling from the other target. It is the mode's premise that a
  # body names ONE machine, so the useful answer says which names this one has.
  ("err_asm_foreign_reg", "is not a Cortex-M general-purpose register"),
  # r12 is nifasm's operand-folding scratch, written at sites arkham never sees:
  # a value pinned there dies to an instruction the code generator did not emit.
  ("err_asm_scratch_reg", "is the assembler's own scratch"),
  # r10/r11 are arkham's staging bridges, and r8/r9 its produce bridge and
  # indirect-result pointer. All four are callee-saved under AAPCS32 but absent
  # from `md.intCalleeSaved`, so the prologue saves none of them — a pin there
  # destroys the caller's value with no local symptom.
  ("err_asm_bridge_reg", "staging bridges"),
  # A frame slot wider than the machine word. A 64-bit `(s)` slot would be a
  # 64-bit-typed access, which nifasm refuses on this target — naming the LOCAL
  # here beats pointing at a `(mov …)` the user never wrote.
  ("err_asm_wide_stack", "moves one 4-byte word at a time"),
  # A pin that contradicts the ABI. In an `.assembler` proc a location
  # constraint is an assertion, not a request, so the two must agree.
  ("err_asm_param_reg", "is passed in r0 by this target's ABI"),
]

proc cortexMInterruptTests() =
  ## The two ways to name an interrupt handler wrong. The POSITIVE path is
  ## `tests/arkham_m/interrupt_pendsv`, which pends PendSV through ICSR and exits
  ## with what the handler wrote — so it runs the table, the Thumb bit and the
  ## handler's return, not just the emission.
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  var passed = 0
  for (name, expected) in cortexMRejections:
    execExpectFailure(quoteShell(arkham) & " -a:cortex_m -o:" &
                      quoteShell("tests" / "arkham_m" / (name & ".rej.nif")) &
                      " " & quoteShell("tests" / "arkham_m" / (name & ".c.nif")),
                      expected)
    inc passed
  echo passed, " / ", cortexMRejections.len, " Cortex-M interrupt/volatile rejection tests successful"


proc cortexMLayoutTests() =
  ## `--layout:<board.nif>` — the file that replaced a command-line namespace it
  ## had outgrown. Regions are a LIST, a stack slot has a size and a count and a
  ## thread-local reservation, and none of that survives being flattened into
  ## `--flag:value` pairs.
  ##
  ## What is checked is that the FILE reaches the IMAGE, which means reading the
  ## two words a cold core reads and the segment addresses back out of the ELF.
  ## Running is not enough on its own: an image that ignored the file entirely
  ## would still exit 42 from its compiled-in defaults.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping Cortex-M layout tests"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham_m" / "nimcache_m"
  createDir workDir
  let src = "tests" / "arkham_m" / "global_data_init.c.nif"
  var passed = 0

  proc u32At(img: string; off: int): uint32 =
    for i in countdown(3, 0): result = (result shl 8) or uint32(img[off + i].byte)

  proc build(board, stem: string): string =
    let asmNif = workDir / (stem & ".asm.nif")
    let elf = workDir / (stem & ".elf")
    exec quoteShell(arkham) & " -a:cortex_m --layout:" & quoteShell(board) &
         " -o:" & quoteShell(asmNif) & " " & quoteShell(src)
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(asmNif)
    result = elf

  # ── 1. the MPS2 board: placed from the file, and RUNS ──
  let mpsElf = build("tests" / "layout" / "mps2.nif", "layout_mps2")
  var args: seq[string] = @[]
  for a in cortexMArgs: args.add a
  args.add mpsElf
  let (mout, mcode) = runProgram(qemu, args)
  if mcode != 42:
    quit "FAILURE cortex-m layout: mps2 board exited " & $mcode & "\n" & mout
  block:
    let img = readFile(mpsElf)
    # 16 bytes of globals, then a 16K heap, then the stacks rounded UP to the 8K
    # slot size — 0x20006000 — so slot 0's top is 0x20008000 and SP starts below
    # the 256-byte thread-local reservation at its top.
    let msp = u32At(img, int(u32At(img, 52 + 4)))
    if msp != 0x20007F00'u32:
      quit "FAILURE cortex-m layout: mps2 initial MSP 0x" & toHex(msp, 8) &
           ", want 0x20007F00 (globals + heap + slot - tls)"
  inc passed

  # ── 2. a DIFFERENT board moves everything ──
  # An STM32F407: flash at 0x08000000, 128K of SRAM, a 32K heap and a 512-byte
  # reservation. Nothing here can come from a compiled-in default.
  let stmElf = build("tests" / "layout" / "stm32f407.nif", "layout_stm32")
  block:
    let img = readFile(stmElf)
    let flashV = u32At(img, 52 + 8)
    let msp = u32At(img, int(u32At(img, 52 + 4)))
    if flashV != 0x08000000'u32:
      quit "FAILURE cortex-m layout: stm32 text at 0x" & toHex(flashV, 8)
    if msp != 0x2000BE00'u32:
      quit "FAILURE cortex-m layout: stm32 initial MSP 0x" & toHex(msp, 8) &
           ", want 0x2000BE00"
    # THE POINT of that unchanged number: this board also carries a `(noinit …)`
    # row, and the region comes off the FAR END of sram. If it were taken from
    # anywhere the globals, the heap or the stacks are placed, this MSP would have
    # moved — so an unmoved MSP is what says the reservation is disjoint from
    # everything else rather than merely declared.
    #
    # And the SRAM segment — the bytes the startup code establishes — must END
    # below it. That is the part that cannot be shown by running: QEMU hands the
    # guest zeroed RAM, so a zero loop that DID reach the region would look
    # exactly like one that did not.
    let ramVaddr = u32At(img, 52 + 32 + 8)
    let ramMemSz = u32At(img, 52 + 32 + 20)
    let noinitBase = 0x20020000'u32 - 256'u32
    if ramVaddr + ramMemSz > noinitBase:
      quit "FAILURE cortex-m layout: the startup code establishes 0x" &
           toHex(ramVaddr, 8) & "+" & $ramMemSz & ", which reaches the noinit " &
           "region at 0x" & toHex(noinitBase, 8)
  inc passed

  # ── 3. the heap the layout reserved, read back by the code that uses it ──
  # `HeapStart`/`HeapSize` are link-time constants the image writer patches, and
  # they are how `osalloc` gets pages on a target with no OS to ask. The probe
  # exits with `heapStart - ramBase`, so a wrong ADDRESS is a wrong exit code
  # rather than a crash somewhere later; a wrong SIZE exits 12.
  block:
    let asmNif = workDir / "heap_probe.asm.nif"
    let elf = workDir / "heap_probe.elf"
    exec quoteShell(arkham) & " -a:cortex_m --layout:" &
         quoteShell("tests" / "layout" / "mps2.nif") & " -o:" & quoteShell(asmNif) &
         " " & quoteShell("tests" / "layout" / "heap_probe.c.nif")
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(asmNif)
    var hargs: seq[string] = @[]
    for a in cortexMArgs: hargs.add a
    hargs.add elf
    let (hout, hcode) = runProgram(qemu, hargs)
    if hcode == 12:
      quit "FAILURE cortex-m layout: HeapSize is not the 16K the board reserved"
    if hcode != 0:
      quit "FAILURE cortex-m layout: heap starts " & $hcode & " bytes above the " &
           "RAM base; this module has no globals, so it should start AT it\n" & hout
  # Without a layout there is no reserved heap to name, and saying so beats
  # answering with a compiled-in default.
  execExpectFailure(quoteShell(arkham) & " -a:cortex_m -o:" &
                    quoteShell(workDir / "x.asm.nif") & " " &
                    quoteShell("tests" / "layout" / "heap_probe.c.nif"),
                    "needs a board layout")
  inc passed

  # ── 4. what the file refuses ──
  # The power-of-two rule is the one the whole thread-local scheme rests on: a
  # thread reaches its own slot by masking SP with the slot size.
  let bad = workDir / "bad_layout.nif"
  proc reject(edit: (string, string); expected: string) =
    var t = readFile("tests" / "layout" / "mps2.nif")
    t = t.replace(edit[0], edit[1])
    writeFile(bad, t)
    execExpectFailure(quoteShell(arkham) & " -a:cortex_m --layout:" & quoteShell(bad) &
                      " -o:" & quoteShell(workDir / "x.asm.nif") & " " & quoteShell(src),
                      expected)
  reject(("(kilobytes 8)", "(kilobytes 5)"), "power of two")
  reject(("(startAddress 536870912)", "(startAddress 0)"), "overlap")
  reject(("(bytes 256)", "(kilobytes 8)"), "fills the whole stack slot")
  reject(("(core 0)", "(core 3)"), "outside the 1 slot")
  reject(("(kilobytes 16)", "16"), "expected a size")
  # A file that says nothing about where the image ships is not a layout with a
  # default — it is a layout with a hole in it.
  reject((" (flash (startAddress 0) (megabytes 4))\n", ""),
         "nothing says where the image ships")
  # A heap that does not fit is a LINK-time fact — arkham cannot know how many
  # bytes of globals the module has — so this one is nifasm's to refuse.
  block:
    var t = readFile("tests" / "layout" / "mps2.nif")
    t = t.replace("(kilobytes 16)", "(kilobytes 512)")
    writeFile(bad, t)
    let asmNif = workDir / "toobig.asm.nif"
    exec quoteShell(arkham) & " -a:cortex_m --layout:" & quoteShell(bad) &
         " -o:" & quoteShell(asmNif) & " " & quoteShell(src)
    execExpectFailure(quoteShell(nifasmExe) & " -o:" & quoteShell(workDir / "x.elf") &
                      " " & quoteShell(asmNif), "does not fit")
  # ── 5. the region kept back from the startup code ──
  # `(noinit …)` is bytes at the top of `sram` that nothing establishes at reset,
  # for the one thing that must NOT be established: a record written by the run
  # that failed and read by the run after it.
  #
  # What is checked here is the ADDRESS and the SIZE, from the code that would
  # use them. Running proves less than it looks on this target — a reset the
  # image ignored entirely would still exit 0 — so the disjointness claim is made
  # in section 2 against the ELF, and the RESERVATION is proved by the rejection
  # below rather than by anything a passing run shows.
  block:
    let board = "tests" / "layout" / "mps2_noinit.nif"
    let asmNif = workDir / "noinit_probe.asm.nif"
    let elf = workDir / "noinit_probe.elf"
    exec quoteShell(arkham) & " -a:cortex_m --layout:" & quoteShell(board) &
         " -o:" & quoteShell(asmNif) & " " &
         quoteShell("tests" / "layout" / "noinit_probe.c.nif")
    exec quoteShell(nifasmExe) & " -o:" & quoteShell(elf) & " " & quoteShell(asmNif)
    var nargs: seq[string] = @[]
    for a in cortexMArgs: nargs.add a
    nargs.add elf
    let (nout, ncode) = runProgram(qemu, nargs)
    case ncode
    of 12: quit "FAILURE cortex-m noinit: NoinitSize is not the 256 bytes reserved"
    of 13: quit "FAILURE cortex-m noinit: NoinitStart is not 0x2000FF00 — the " &
                "region is not the top 256 bytes of the 64K region at 0x20000000"
    of 14: quit "FAILURE cortex-m noinit: the region did not hold what was stored " &
                "in it, so it is not RAM the image owns"
    of 0: discard
    else: quit "FAILURE cortex-m noinit: probe exited " & $ncode & "\n" & nout
  # THE test that the reservation is real. 36K of noinit still passes arkham's
  # whole-file check (8K of stacks plus a 16K heap plus 36K fits in 64K), and it
  # is only at link time — where the globals and the slot-size rounding are known
  # — that the stacks are seen to run into it. Were the region merely declared and
  # not reserved, this would assemble.
  block:
    var t = readFile("tests" / "layout" / "mps2_noinit.nif")
    t = t.replace("(noinit (bytes 256))", "(noinit (kilobytes 36))")
    writeFile(bad, t)
    let asmNif = workDir / "noinit_toobig.asm.nif"
    exec quoteShell(arkham) & " -a:cortex_m --layout:" & quoteShell(bad) &
         " -o:" & quoteShell(asmNif) & " " & quoteShell(src)
    execExpectFailure(quoteShell(nifasmExe) & " -o:" & quoteShell(workDir / "x.elf") &
                      " " & quoteShell(asmNif), "past the noinit region")
  # And naming the region when the file keeps nothing back is a question with no
  # answer, not a zero.
  execExpectFailure(quoteShell(arkham) & " -a:cortex_m --layout:" &
                    quoteShell("tests" / "layout" / "mps2.nif") & " -o:" &
                    quoteShell(workDir / "x.asm.nif") & " " &
                    quoteShell("tests" / "layout" / "noinit_probe.c.nif"),
                    "keeps nothing back")
  inc passed
  echo passed, " / 4 Cortex-M layout-file tests successful"


proc cortexMMemMapTests() =
  ## The board memory map (`--flash`/`--flash-size`/`--ram`/`--ram-size`/
  ## `--stack-top`) actually reaching the image.
  ##
  ## The load-bearing case is the RELOCATED one, and it is relocated within the
  ## address range QEMU's SSRAM covers so that it can be RUN rather than merely
  ## inspected: if any of the globals' `movw/movt` sites, the `(datavma)` the
  ## startup copy writes to, or the interrupt table's initial-MSP word still carried
  ## a compiled-in constant, the fixture reads a global that was never written or
  ## pushes onto a stack that is not there. It exits 42 only if all three follow
  ## the map.
  ##
  ## The board case (an STM32F407) cannot be run — nothing in QEMU has flash at
  ## 0x08000000 — so it is checked by reading the two words a cold core reads.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping Cortex-M memory-map tests"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham_m" / "nimcache_m"
  createDir workDir
  let src = "tests" / "arkham_m" / "global_data_init.c.nif"
  let asmNif = workDir / "memmap.asm.nif"
  exec quoteShell(arkham) & " -a:cortex_m -o:" & quoteShell(asmNif) & " " &
       quoteShell(src)
  var passed = 0

  proc u32At(img: string; off: int): uint32 =
    for i in countdown(3, 0): result = (result shl 8) or uint32(img[off + i].byte)

  # ── 1. relocated RAM, run under QEMU ──
  let relocElf = workDir / "memmap_reloc.elf"
  exec quoteShell(nifasmExe) & " --ram:0x20001000 --ram-size:32K -o:" &
       quoteShell(relocElf) & " " & quoteShell(asmNif)
  var args: seq[string] = @[]
  for a in cortexMArgs: args.add a
  args.add relocElf
  let (relocOut, relocCode) = runProgram(qemu, args)
  if relocCode == timeoutExitCode:
    quit "FAILURE (TIMEOUT) cortex-m memmap relocated RAM"
  if relocCode != 42:
    quit "FAILURE cortex-m memmap relocated RAM: exit " & $relocCode & "\n" & relocOut
  # Running is not by itself evidence: an image that ignored `--ram` entirely and
  # put everything back at the default base is INTERNALLY consistent and exits 42
  # just the same. So read the addresses back and require that they moved.
  block:
    let relocImg = readFile(relocElf)
    let ramV = u32At(relocImg, 52 + 32 + 8)
    let mspV = u32At(relocImg, int(u32At(relocImg, 52 + 4)))
    if ramV != 0x20001000'u32:
      quit "FAILURE cortex-m memmap: relocated RAM segment at 0x" & toHex(ramV, 8) &
           ", want 0x20001000 — the --ram flag did not reach the image"
    if mspV != 0x20009000'u32:
      quit "FAILURE cortex-m memmap: relocated initial MSP 0x" & toHex(mspV, 8) &
           ", want 0x20009000"
  inc passed

  # ── 2. an STM32F407 map, read back out of the image ──
  # Segment vaddrs live in the program headers, which this reads at their fixed
  # ELF32 offsets rather than by shelling out to readelf.
  let stmElf = workDir / "memmap_stm32.elf"
  exec quoteShell(nifasmExe) &
       " --flash:0x08000000 --flash-size:1M --ram-size:128K -o:" &
       quoteShell(stmElf) & " " & quoteShell(asmNif)
  let img = readFile(stmElf)
  const PhOff = 52          # e_phoff: the headers follow the 52-byte ELF header
  const PhSize = 32
  let flashVaddr = u32At(img, PhOff + 8)
  let ramVaddr = u32At(img, PhOff + PhSize + 8)
  let flashFileOff = u32At(img, PhOff + 4)
  if flashVaddr != 0x08000000'u32:
    quit "FAILURE cortex-m memmap: flash segment at 0x" & toHex(flashVaddr, 8)
  if ramVaddr != 0x20000000'u32:
    quit "FAILURE cortex-m memmap: RAM segment at 0x" & toHex(ramVaddr, 8)
  # The two words a cold M-profile core reads: initial MSP, then the reset
  # handler WITH the Thumb bit — an even address here is a UsageFault at reset.
  let msp = u32At(img, int(flashFileOff))
  let reset = u32At(img, int(flashFileOff) + 4)
  if msp != 0x20020000'u32:
    quit "FAILURE cortex-m memmap: initial MSP 0x" & toHex(msp, 8) & ", want 0x20020000"
  if (reset and 1) == 0 or reset < 0x08000000'u32 or reset >= 0x08100000'u32:
    quit "FAILURE cortex-m memmap: reset vector 0x" & toHex(reset, 8)
  inc passed

  # ── 3. the target triple, which is how nimony names this target ──
  # `--os:embedded --cpu:arm32` and the legacy `-a:cortex_m` must select the same
  # backend, so compare the OUTPUT rather than trusting the mapping table: this
  # is the spelling `deps.nim` forwards verbatim from nimony's platform table,
  # and a mapping that quietly picked another arch would still exit 0.
  let byTriple = workDir / "memmap_triple.asm.nif"
  exec quoteShell(arkham) & " --os:embedded --cpu:arm32 -o:" & quoteShell(byTriple) &
       " " & quoteShell(src)
  if readFile(byTriple) != readFile(asmNif):
    quit "FAILURE cortex-m: --os:embedded --cpu:arm32 does not select the same " &
         "backend as -a:cortex_m"
  # `--cpu:arm` is what was written before the rename and still resolves.
  let byOldCpu = workDir / "memmap_triple_arm.asm.nif"
  exec quoteShell(arkham) & " --os:embedded --cpu:arm -o:" & quoteShell(byOldCpu) &
       " " & quoteShell(src)
  if readFile(byOldCpu) != readFile(asmNif):
    quit "FAILURE cortex-m: --cpu:arm no longer resolves to arm32"
  # `standalone` is Nim's word for a different arrangement and must NOT be taken
  # for this one.
  execExpectFailure(quoteShell(arkham) & " --os:standalone --cpu:arm32 -o:" &
                    quoteShell(workDir / "memmap_x.asm.nif") & " " & quoteShell(src),
                    "unknown --os:standalone")

  # ── 4. the bounds, which are the whole point of declaring a size ──
  execExpectFailure(quoteShell(nifasmExe) & " --flash-size:256 -o:" &
                    quoteShell(workDir / "memmap_x.elf") & " " & quoteShell(asmNif),
                    "holds 256")
  execExpectFailure(quoteShell(nifasmExe) &
                    " --ram-size:8 --stack-top:0x20000008 -o:" &
                    quoteShell(workDir / "memmap_x.elf") & " " & quoteShell(asmNif),
                    "reach the stack top")
  execExpectFailure(quoteShell(nifasmExe) & " --ram:0x00000000 -o:" &
                    quoteShell(workDir / "memmap_x.elf") & " " & quoteShell(asmNif),
                    "overlap")
  execExpectFailure(quoteShell(nifasmExe) & " --stack-top:0x30000000 -o:" &
                    quoteShell(workDir / "memmap_x.elf") & " " & quoteShell(asmNif),
                    "outside the RAM region")
  inc passed

  inc passed
  echo passed, " / 4 Cortex-M memory-map and target-triple tests successful"


const cortexMUnsupported: seq[string] = @[
  # `tests/arkham/` — the FULL 64-bit corpus — is run against Cortex-M as well.
  # These are the fixtures it cannot serve, each parked under the reason, so that
  # any OTHER failure is fatal and a fixture that starts working is reported.
  # Every one of them refuses BY NAME (a compile-time error from arkham or
  # nifasm); the single exception is called out at the bottom.

  # ── float64 ─────────────────────────────────────────────────────────────────
  # Missing HARDWARE, not a missing feature: Cortex-M4F's FPv4-SP is single
  # precision and has no `.f64` instruction at all. `float32` works (M5) — see
  # `tests/arkham_m/fp32_*` — and a double is refused rather than lowered through
  # a softfloat library nobody asked for.
  "a64_vec_instr", "addrfloat", "float_array_index", "float_global_field",
  "float_global_read", "float_special_values", "fp3264", "fparg_spill",
  "fparith", "fparith2", "fparray", "fpasgn", "fpasgn2", "fpcall", "fpcmp",
  "fpdeep", "fpderef", "fpfield", "fpfunc", "fpparamspill", "fpspill",
  "global_init_float", "spill_produce_float", "store_forward",
  "uint_literal_to_float",

  # ── float <-> 64-bit integer ────────────────────────────────────────────────
  # FPv4-SP converts to and from a THIRTY-TWO bit integer. `int64(f)` past 2^31
  # would need a runtime routine, and a `vcvt` plus a sign-extend would be
  # quietly wrong exactly there — so it is refused. `int32(f)` and `float32(i32)`
  # are what this core has, and they work.
  "div_floatparam", "float_const_conv", "fp32", "fpconv", "fpconv2",

  # ── no such hardware, no such OS ────────────────────────────────────────────
  # `mmap`/`futex`/`___ulock_wake` (no kernel to ask) and the x86-64-pinned
  # stack-walk fixture. The three `tvar_*` fixtures used to be here too: a
  # thread-local is now emitted as a global on a board that declares ONE stack
  # slot, which is a decision about the board and not about the ISA — a Cortex-M
  # part with four cores has four threads and is refused by name until the
  # SP-masked thread-local base exists.
  "mmap_anon", "futex_wake", "ulock_wake", "naked_stacktrace_x64",

  # ── 64-bit intrinsics ───────────────────────────────────────────────────────
  # `clz`/`rbit`/`rev` and the atomics at 64 bits: ARMv7-M's are 32-bit, and its
  # exclusives have no 64-bit form on this core either — there is no `ldrexd`, and
  # two exclusive pairs over the halves would be two claims rather than one atom,
  # so a 64-bit cell is refused BY NAME. The 8/16/32-bit atomics are lowered
  # (`ldrex`/`strex` bracketed by `dmb`): `atomic_subword_cas` runs here, and
  # `tests/arkham_m/atomics` covers every row at 32 bits. The overflow-checked
  # 64-bit multiply wants `smulh`, which does not exist here.
  "atomic", "atomic2", "atomic_cas", "atomic_cas_regpressure",
  "intrinsics", "intrinsics_x64",
  "mul_overflow", "mul_overflow_pow2",

  # ── register pressure ───────────────────────────────────────────────────────
  # Four allocatable homes and an empty volatile pool (see machine_m.nim). Each
  # of these fails LOUDLY at the pick — never with a wrong answer.
  #
  # The list shrank again when the last-resort scratch draw learned which
  # argument registers are actually STAGED (`stagedArgs`): r0–r3 are this
  # target's only volatiles, and outside a call's marshalling window and the
  # prologue, nothing has a claim on them. `atomic_ptr_cell` runs on that alone.
  #
  # The list SHRANK when the produce bridge (r8) joined the staging set:
  # `at_scratch_deref_base` and `nested_at_read` are address chains that need a
  # third scratch register, and a third was reserved all along — it just was not
  # reachable from the staging draw. What is left is demand of a different KIND —
  # an ATOMIC's operands, which may not use a bridge at all because the LL/SC loop
  # owns them, and an aggregate whose two ends are both computed.
  "aconstr_byref_spilled", "aggr_arg_parked_manual",
  "atomic_cas_operand_home",

  # ── WRONG ANSWER, and the second one in this list ───────────────────────────
  # `array2d` used to fail loudly for register pressure. It compiles now, and
  # computes 1 where it should compute 24 — so it is parked next to
  # `stack_array_align` rather than among the refusals, because a tolerated wrong
  # answer is the one thing this list must not hide.
  #
  # The cause is NOT the register draw that let it compile: the same shape with
  # no register pressure at all — a 3x3 `array[array[i 64]]`, one store, one read
  # — makes zero last-resort draws and still breaks, with nifasm refusing the
  # STORE outright: "element stride 24 is not an LDR/STR scale; use the
  # 3-operand form with a scratch register". The read of the same lvalue emits
  # the 3-operand form correctly, so the wide (64-bit) store path reaches the
  # `(at …)` without the stride-scratch reservation `emitLvalWalk` makes for the
  # read. That is a Cortex-M 64-bit addressing bug that was unreachable while the
  # fixture refused earlier, not a consequence of reaching it.
  "array2d",

  # ── x86-64 assembly ─────────────────────────────────────────────────────────
  # An `{.assembler.}` proc whose register pins name x86-64 registers. Refused on
  # AArch64 too, and for the same reason: there is no target-neutral reading of
  # `{.register: "rax".}`.
  "assembler_x64",

  # The AArch64 `.assembler` fixture, for the same reason in the other
  # direction: its pins are `x0`/`x9`/`x19`, which this target does not have.
  # The Cortex-M half of that mode is `tests/arkham_m/assembler_m`, whose pins
  # are `r0`..`r7` and which runs in the 32-bit corpus.
  "assembler_a64",

  # ── INAPPLICABLE, not unsupported ───────────────────────────────────────────
  # The one entry that does not refuse: it runs and returns the wrong exit code,
  # because what it asserts is not true of this target. `stack_array_align`
  # checks `addr big and 15 == 0` — a 16-byte stack alignment that SysV and
  # AAPCS64 happen to give it. AAPCS32 promises 8, and over-aligning every frame
  # to buy it back would cost stack on a device that has kilobytes of it.
  "stack_array_align",
]

proc arkhamCortexM64Tests() =
  ## The FULL `tests/arkham/` corpus — the 64-bit one — compiled for Cortex-M and
  ## run under QEMU. This is what M4 (64-bit integers on a 32-bit target) is
  ## measured by; `tests/arkham_m/` stays as the 32-bit-specific corpus.
  ##
  ## A fixture in `cortexMUnsupported` may fail; anything else may not, and a
  ## parked fixture that starts passing is reported so the list shrinks with the
  ## backend instead of drifting.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping the arkham cortex-m 64-bit corpus"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache_m"
  createDir workDir
  # Foreign helper modules first, so a cross-module fixture can auto-import them.
  for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
    let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
    discard execCmdEx(quoteShell(arkham) & " -a:cortex_m -o:" &
                      quoteShell(workDir / (name & ".asm.nif")) & " " & quoteShell(file))
  var total, passed, skipped = 0
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_"): continue        # foreign helper, not standalone
    if base.startsWith("err_"): continue        # must NOT compile
    let name = base[0 ..< base.len - ".c.nif".len]
    inc total
    let stem = file[0 ..< file.len - ".c.nif".len]
    let known = name in cortexMUnsupported
    let asmNif = workDir / (name & ".asm.nif")
    let exe = workDir / (name & ".elf")
    template tolerate(what, output: string) =
      if known: inc skipped; continue
      quit "FAILURE (cortex-m 64) " & what & " " & file & "\n" & output
    let (ao, ac) = execCmdEx(quoteShell(arkham) & " -a:cortex_m -o:" &
                             quoteShell(asmNif) & " " & quoteShell(file))
    if ac != 0: tolerate("arkham (codegen)", ao)
    let (no, nc) = execCmdEx(quoteShell(nifasmExe) & " -o:" & quoteShell(exe) & " " &
                             quoteShell(asmNif))
    if nc != 0: tolerate("nifasm (assemble)", no)
    var args: seq[string] = @[]
    for a in cortexMArgs: args.add a
    args.add exe
    let (po, pc) = runProgram(qemu, args)
    if pc == timeoutExitCode: tolerate("TIMEOUT running", "")
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
      echo "NOTE: ", name, " now passes on cortex-m - remove it from cortexMUnsupported"
    removeFile asmNif
    removeFile exe
    inc passed
  echo passed, " / ", total, " arkham cortex-m 64-bit corpus tests successful (",
       skipped, " known-unsupported skipped)"

proc arkhamCortexMTests() =
  ## The Cortex-M end-to-end pass: Leng `.c.nif` → arkham → nifasm → firmware →
  ## QEMU, checking each fixture's exit code.
  ##
  ## `tests/arkham_m/` is its OWN corpus, mechanically derived from
  ## `tests/arkham/` with the 64-bit scalars rewritten to 32-bit. It has to be
  ## separate: 206 of the 236 originals declare `(i 64)`, which on a 32-bit
  ## target needs the register-pair lowering that is milestone M4. The corpus
  ## grows as features land rather than carrying a skip list the size of itself.
  let qemu = findExe(cortexMQemu)
  if qemu.len == 0:
    echo cortexMQemu, " not found - skipping arkham Cortex-M tests"
    return
  let arkham = ("bin" / "arkham").addFileExt(ExeExt)
  let nifasmExe = ("bin" / "nifasm").addFileExt(ExeExt)
  var total = 0
  var passed = 0
  for file in walkFiles("tests/arkham_m/*.c.nif"):
    let stem = file.extractFilename.replace(".c.nif", "")
    if stem.startsWith("err_"): continue   # must NOT compile; see cortexMInterruptTests
    let expectedCode = parseInt(readFile("tests" / "arkham_m" / (stem & ".exitcode")).strip())
    inc total
    let asmFile = "tests" / "arkham_m" / (stem & ".asm.nif")
    let exe = "tests" / "arkham_m" / (stem & ".elf")
    let (ao, ac) = execCmdEx(quoteShell(arkham) & " -a:cortex_m -o:" &
                             quoteShell(asmFile) & " " & quoteShell(file))
    if ac != 0: quit "FAILURE arkham (cortex_m codegen) " & file & "\n" & ao
    let (no, nc) = execCmdEx(quoteShell(nifasmExe) & " -o:" & quoteShell(exe) & " " &
                             quoteShell(asmFile))
    if nc != 0: quit "FAILURE nifasm (cortex_m assemble) " & file & "\n" & no
    var args: seq[string] = @[]
    for a in cortexMArgs: args.add a
    args.add exe
    let (po, pc) = runProgram(qemu, args)
    if pc == timeoutExitCode:
      quit "FAILURE (cortex-m) TIMEOUT after " & $(runTimeoutMs div 1000) &
           "s for " & file & "\n"
    if pc != expectedCode:
      quit "FAILURE (cortex-m) exitcode " & $expectedCode & " but got " & $pc &
           " for " & file & "\n" & po
    # An `.output` file makes the fixture's OUTPUT part of the assertion. Most of
    # this corpus is judged by its exit code alone — a firmware image has one
    # number to report — but a fixture whose whole point is that something reached
    # the console (`semihost_writec` writes through `bkpt`) has nothing else to be
    # judged on. Optional, so the other 128 fixtures need no empty file.
    let outFile = "tests" / "arkham_m" / (stem & ".output")
    if fileExists(outFile):
      let expectedOut = readFile(outFile).strip
      if po.strip != expectedOut:
        quit "FAILURE (cortex-m) output mismatch for " & file &
             "\nexpected:\n" & expectedOut & "\ngot:\n" & escape(po)
    removeFile asmFile
    removeFile exe
    inc passed
  echo passed, " / ", total, " arkham cortex-m (qemu) tests successful"


vgClientRequestEncodingTests()

# Cortex-M: encoder-level coverage. Host-independent — it only needs
# qemu-system-arm, so it runs wherever that is installed.
thumb2SelfTest()
cortexMAsmTests()
cortexMMemMapTests()
cortexMInterruptTests()
cortexMLayoutTests()
arkhamCortexMTests()
arkhamCortexM64Tests()

# AVR: encoder-level coverage, then the selector end to end. Host-independent —
# both need only `bin/avrtest`.
avrSelfTest()
avrAsmTests()

# RISC-V 32: encoder-level coverage. Hosted, so it needs only `qemu-riscv32`.
rv32SelfTest()
rv32AsmTests()
arkhamRv32Tests()
arkhamAvrTests()
arkhamAvrRejections()

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
                            else: arkhamOsxOnly & arkhamX64Unsupported),
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
  arkhamWinTraceTableTests()

# Additionally exercise the AArch64 backend on an x86-64 Linux host by emitting the
# `linux_arm64` ELF variant and running it under qemu-aarch64 (no-op if qemu is
# absent). Gives the arm64 path end-to-end coverage without a macOS machine.
when defined(linux) and defined(amd64):
  arkhamQemuTests()

# On an AArch64 Linux host (a Raspberry Pi is the common one) the `linux_arm64`
# binaries are NATIVE: the same corpus runs without an emulator, and it is the only
# arkham coverage such a host gets — the x64 pass above needs an x86-64 CPU and the
# Darwin pass a Mac. `arkhamQemuTests` still spells the runner `qemu-aarch64`, so
# provide it as a shell shim that just execs its argument.
when defined(linux) and defined(arm64):
  arkhamQemuTests()

# The hand-written AArch64 fixture assembled above is a `linux_arm64` ELF: run it.
when defined(linux):
  if findExe("qemu-aarch64").len > 0:
    let (sbfOut, sbfCode) = runProgram(findExe("qemu-aarch64"),
                                       ["tests" / "a64_slot_base_free"])
    if sbfCode != 0:
      quit "FAILURE a64_slot_base_free: exit " & $sbfCode & "\n" & sbfOut
    echo "1 / 1 a64 base-free slot addressing tests successful"
  else:
    echo "qemu-aarch64 not found - skipping a64_slot_base_free"

# The AArch64 backend gets the same starved-pool pass, under qemu.
when defined(linux) and defined(amd64):
  if findExe("qemu-aarch64").len > 0:
    arkhamStressTests(arch = "linux_arm64", runner = "qemu-aarch64",
                      skip = arkhamLinuxA64Unsupported & arkhamA64Unsupported &
                             arkhamOsxOnly,
                      known = arkhamStressA64Known,
                      level = arkhamStressA64Level)
