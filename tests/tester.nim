import std/[os, osproc, strutils]

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

proc execExpectOutput(cmd: string; expected: string) =
  let (s, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    quit "FAILURE " & cmd & "\n" & s
  if s != expected:
    quit "UNEXPECTED OUTPUT " & cmd & "\nExpected:\n" & expected & "\nGot:\n" & s

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
    let (po, pc) = execCmdEx(quoteShell(exe))
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

# Most `tests/arkham/*.c.nif` run end-to-end under the static Linux/ELF
# `linux_arm64` qemu path — the arm64 backend reached x86-64 feature parity for
# function-pointer calls, `(pat …)` pointer indexing, and thread-locals. List a
# test's stem here only when it fails under THIS pass alone (static ELF, svc
# syscalls, qemu); an AArch64 gap that the macOS run would hit too goes in
# `arkhamA64Unsupported`.
# ── register-pressure stress pass (`-d:arkhamStress`, see src/arkham/stress.nim) ──
#
# The corpus above is NECESSARY BUT NEVER SUFFICIENT, and the project has the
# receipts: the five 2026-07-30 nimsem regressions and the eight 2026-08-03
# self-host fixes were ALL green here before they were found, every one of them by
# bootstrapping nimony instead. The common factor is register pressure — these
# fixtures are small enough that no pool ever runs dry, so the emitters' pool-dry
# arms (produce-into-memory, staging chains, survivor parking) are never taken.
#
# This pass reaches that regime without writing bigger fixtures: it re-runs the SAME
# corpus against a deliberately starved register file (`ARKHAM_STRESS=k` keeps only
# the first `k` registers of each allocatable pool). Each fixture's own
# `.exitcode`/`.output` remains the oracle, so the pass checks totality (no pool-dry
# assert) AND correctness under maximum spilling — the second half is the one a
# totality argument alone cannot give you, and it is where the `cmpxchg` miscompile
# below was caught.
const arkhamStressLevel = 2
  ## Registers kept per pool. `2` is the working point: it starves the pools hard
  ## enough to reach every fallback arm while staying above the floors in
  ## `stress.nim` (where an exhaustion means "this machine is too small", not a
  ## bug). Override with `ARKHAM_STRESS_LEVELS=4,3,2` to sweep.

const arkhamStressKnown: seq[(string, int, string)] = @[
  # FOUND BY THIS PASS, 2026-08-03, not yet fixed. Each entry is a REAL defect with
  # a reproduction (`ARKHAM_STRESS=k bin/arkham_stress -a:x64 …`), parked here so
  # the gate is green on today's known set and any NEW failure is fatal. Remove an
  # entry with its fix — and add the shrunk-pool fixture that pins it.
  #
  # The middle field is the LOOSEST pool at which the fixture still breaks, so the
  # entry pins a threshold rather than just a name: failing at a level ABOVE it is a
  # regression (the defect got easier to hit) and reported as new, while passing at
  # or below it says the defect is gone. That keeps a sweep quiet and still strict.
  #
  # 1. FIXED — the cmpxchg/RAX silent miscompile. `emitAtomicInstr2` claims RAX
  #    (architecturally `cmpxchg`'s comparand) but nothing kept the `expected` /
  #    `desired` / cell operands off it: RAX is in no allocator POOL, yet
  #    `takeInstrReg`'s staging fallback draws from `StagingCandidates`, where RAX
  #    sits second. Starve the pools, `desired` lands in RAX, the `mov rax, *expected`
  #    emitted between them destroys it, and the CAS compares the cell against itself
  #    — it "succeeds" and stores the OLD value back. `emitInstr2` now seals
  #    `atomicRegClaims(op)` across the result and operand picks. Stating the claim
  #    PER ROW is what keeps it affordable: a compare-exchange uses no `work`
  #    register, so it gets the R11 bridge back in exchange for RAX and still fits.
  #    Pinned by `atomic_cas_regpressure` (k<=3) and `atomic_ptr_cell`/`atomic2`
  #    (k<=2). Emission at full pools is byte-identical across the whole corpus.
  # 2. INVALID ASM-NIF (k<=3), caught by nifasm rather than miscompiled:
  #    `(mov (mem (rsp) p3.0) p3.0)` — "expected (i 64), got (stackoff (i 64))".
  ("aggr_copy_regpressure", 3, "nested-aggregate copy emits a stackoff into a value slot"),
  # 3. INVALID ASM-NIF (k<=3): "Expected index register or stack variable in mem"
  #    — a by-ref aggregate's base failed to materialize into a register.
  ("stack_aggr_byref", 3, "by-ref aggregate base not materialized before the (mem …)"),
  # 4. TOTALITY GAP (k<=4, i.e. ONE callee-saved register removed). The
  #    clobber-exposed aggregate-argument park calls `takeHeld` with the default
  #    `canSpill = false` and asserts. 11 of the 15 `takeHeld` sites across both
  #    backends do. This is the `ParkTotal` obligation — and note that
  #    `formal/regproto.nif` asserts it HOLDS, with `regproto_bug_noparkslot.nif`
  #    as the variant that removes the slot arm: the model states the property the
  #    code does not have, because its `SlotAvail` is a tautology at Vals == Slots.
  ("aggr_arg_parked", 4, "clobber-exposed aggregate-arg park has no spill arm"),
  ("aggr_arg_parked_byref", 3, "clobber-exposed aggregate-arg park has no spill arm"),
  ("aggr_arg_parked_manual", 4, "clobber-exposed aggregate-arg park has no spill arm"),
  # 5. TOTALITY GAP (k<=2), the same class as 4 and found by the fixture written to
  #    pin 1. `takeInstrReg` documents its assert as a contract — an `(instr …)`
  #    operand has no memory form — so when the pools AND the staging set are dry it
  #    raises rather than evicting a live local to a slot. Three live locals plus a
  #    three-operand compare-exchange do not fit two registers per pool. Loud and
  #    correct, not a miscompile, but it is still an arm with no answer; the fix is
  #    the same steal-and-spill arm `takeHeld(canSpill)` already has.
  ("atomic_cas_regpressure", 2, "intrinsic-operand pick has no steal/spill arm"),
]

proc arkhamStressTests(arch: string; runner = ""; skip: seq[string] = @[];
                       known: seq[(string, int, string)]; floorLevel = 2) =
  ## Re-emit + assemble + RUN the corpus with the register file artificially
  ## starved. Uses its own `bin/arkham_stress` binary: the shrink is behind
  ## `-d:arkhamStress`, so the shipped `bin/arkham` cannot be perturbed by a stray
  ## environment variable, and with `ARKHAM_STRESS` unset the two binaries are
  ## byte-identical on every fixture (the inert-addition check).
  ##
  ## `runner` prefixes the produced executable (`qemu-aarch64` for the
  ## `linux_arm64` pass); empty means run it natively.
  ##
  ## `floorLevel` is where THIS backend stops giving signal: below it the
  ## backend's own documented out-of-registers asserts dominate and every fixture
  ## with an atomic or a non-scale array index dies on one, which says "the
  ## machine is too small", not "the emitter is wrong". Levels under it are
  ## skipped with a note rather than silently, because the line is a judgement and
  ## should be visible.
  exec "nim c --hints:off -d:arkhamStress -o:bin/arkham_stress src/arkham/arkham.nim"
  let arkham = ("bin" / "arkham_stress").addFileExt(ExeExt)
  let nifasm = ("src" / "nifasm" / "nifasm").addFileExt(ExeExt)
  let workDir = "tests" / "arkham" / "nimcache"
  createDir workDir
  # The default (CI) run is ONE level per backend: the tightest that still gives
  # signal, clamped UP to this backend's floor so every backend is actually
  # exercised. An explicit `ARKHAM_STRESS_LEVELS` sweep is taken literally and its
  # below-floor levels are skipped with a note — a manual sweep should be able to
  # ask for a level and be told why it was not run.
  var levels: seq[int] = @[max(arkhamStressLevel, floorLevel)]
  let envLevels = getEnv("ARKHAM_STRESS_LEVELS").strip
  if envLevels.len > 0:
    levels = @[]
    for part in envLevels.split(','): levels.add parseInt(part.strip)
  proc knownAt(name: string; k: int): bool =
    ## Is `name` a recorded defect EXPECTED to break at pool size `k`? Only at or
    ## below its recorded threshold: breaking at a LOOSER pool means the defect
    ## widened, which is a regression, not a known failure.
    ##
    ## Failure is not monotone in `k` — which registers survive the shrink decides
    ## whether a given aliasing bug is reachable, so a fixture can break at k=4 and
    ## k=3 yet pass at k=2. The threshold is therefore an upper bound on where the
    ## defect has been SEEN, and "it is fixed" is judged across the whole sweep
    ## (`sawFail` below), never from one level.
    for (stem, level, _) in known:
      if stem == name: return k <= level
    false
  proc everKnown(name: string): bool =
    for (stem, _, _) in known:
      if stem == name: return true
    false
  var newFailures: seq[string] = @[]
  var sawFail: seq[string] = @[]
  for k in levels:
    if k < floorLevel:
      echo "NOTE: ", arch, " stress: skipping k=", k, " (below this backend's floor of ",
           floorLevel, " every atomic / non-scale index dies on a documented ",
           "out-of-registers assert)"
      continue
    putEnv("ARKHAM_STRESS", $k)                 # inherited by the arkham children
    for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
      let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
      exec quoteShell(arkham) & " -a:" & arch & " -o:" &
           quoteShell(workDir / (name & ".asm.nif")) & " " & quoteShell(file)
    var total, passed, expectedFail = 0
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
        let (po, pc) = execCmdEx(
          (if runner.len > 0: quoteShell(runner) & " " else: "") & quoteShell(exe))
        let ecFile = stem & ".exitcode"
        let expectedCode = if fileExists(ecFile): parseInt(readFile(ecFile).strip) else: 0
        let outFile = stem & ".output"
        let expectedOut = if fileExists(outFile): readFile(outFile).strip else: ""
        if pc != expectedCode:
          failed = "MISCOMPILE: exitcode " & $expectedCode & " but got " & $pc; break run
        if po.strip != expectedOut:
          failed = "MISCOMPILE: output mismatch"; break run
      if failed.len == 0:
        inc passed
      else:
        if name notin sawFail: sawFail.add name
        if knownAt(name, k):
          inc expectedFail
        elif everKnown(name):
          newFailures.add "k=" & $k & " " & name &
                          " — breaks at a LOOSER pool than recorded: " & failed
        else:
          newFailures.add "k=" & $k & " " & name & " — " & failed
    echo passed, " / ", total - expectedFail, " arkham ", arch,
         " stress tests successful (k=", k, ", ", expectedFail, " known-broken)"
  delEnv("ARKHAM_STRESS")
  for (stem, _, why) in known:
    if stem notin sawFail:
      echo "NOTE: ", arch, " stress: ", stem, " passed at every swept level (",
           why, ") — drop its arkhamStressKnown entry, or sweep wider"
  if newFailures.len > 0:
    quit "FAILURE arkham register-pressure stress (" & arch &
         ") found NEW breakage:\n  " & newFailures.join("\n  ")

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
    let (po, pc) = execCmdEx(quoteShell(qemu) & " " & quoteShell(exe))
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
  exec "./tests/hello_win64.exe"

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
  exec "tests/bitops_rotate_scan"
  exec "tests/bitops_bittest"
  exec "tests/dot_at_access"
  exec "tests/nested_dot_at"
  exec "tests/pointer_dot_store"
  exec "tests/array_i64_register_index"
  exec "tests/pointer_field_at"
  exec "tests/pointer_roundtrip"
  execExpectOutput("./tests/string_pointer_field", "Hello\n")
  execExpectOutput("./tests/message_inline_array", "Ping\n")
  execExpectOutput("./tests/rep_movs_copy", "Rep!\n")
  execExpectOutput("./tests/call_hello_chain", "Hello through calls\n")
  exec "./tests/call_multi_result"

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
execExpectFailure("nim c -r src/nifasm/nifasm tests/a64_clobber_after_call.nif", "in register X9 which was clobbered by a call")
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
execExpectFailure("nim c -r src/nifasm/nifasm tests/stack_result_binding.nif", "Type mismatch: expected (stackoff")
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
  # The same corpus again, against a starved register file — the pool-dry arms the
  # fixtures are otherwise too small to reach (see `arkhamStressTests`).
  arkhamStressTests(arch = (when defined(macosx): "arm64" else: "x64"),
                    skip = (when defined(macosx): arkhamDarwinUnsupported &
                                                  arkhamA64Unsupported
                            else: arkhamOsxOnly),
                    known = arkhamStressKnown)

# The `{.assembler.}` rejections are x86-64-only (see `arkhamRejectionTests`).
when defined(linux) and defined(amd64):
  arkhamRejectionTests(("bin" / "arkham").addFileExt(ExeExt))

# Additionally exercise the AArch64 backend on an x86-64 Linux host by emitting the
# `linux_arm64` ELF variant and running it under qemu-aarch64 (no-op if qemu is
# absent). Gives the arm64 path end-to-end coverage without a macOS machine.
when defined(linux) and defined(amd64):
  arkhamQemuTests()

const arkhamStressA64Known: seq[(string, int, string)] = @[
  # The AArch64 half of the 2026-08-03 stress findings (see `arkhamStressKnown`).
  # The first two are SILENT MISCOMPILES — the fixture builds and runs and returns
  # the wrong answer, which is the class neither the corpus nor a totality argument
  # can see. Shrinking a pool may cost performance or hit a documented
  # out-of-registers assert; it can never legitimately change what a program
  # COMPUTES, so a changed exit code is a codegen bug by construction.
  #
  # `spill_produce_float` returns 219 / 19 / 84 instead of 16 at k=4/3/2 — a
  # different wrong value per level, i.e. it reads whatever the reused register
  # happened to hold, in `produceIntoFMem2`'s float spill path.
  ("spill_produce_float", 4, "float produce-into-spill reads a clobbered register"),
  # `steal_straddle` returns 84 instead of 94 at k=4 and k=3 (and passes at k=2 —
  # failure is not monotone in the pool size). The allocator's `trySteal` over a
  # straddling live range.
  ("steal_straddle", 4, "trySteal over a straddling live range yields a stale value"),
  # The a64 half of x64 finding 5: the same out-of-registers assert on the same new
  # fixture, one level LOOSER (this pass floors at k=3, and that is where it lands).
  # The compare-exchange itself is fine here — a64 has no fixed-register CAS, it is
  # `ldxr`/`stxr` on whatever the allocator picked — so this is purely the missing
  # steal/spill arm on the intrinsic-operand pick, not an aliasing bug.
  ("atomic_cas_regpressure", 3, "intrinsic-operand pick has no steal/spill arm"),
]

# The AArch64 backend gets the same starved-pool pass, under qemu. Its `takeHeld`
# has MORE no-spill call sites than x86-64's (7 of 9 vs 4 of 6), so the totality
# obligations are, if anything, looser here.
when defined(linux) and defined(amd64):
  if findExe("qemu-aarch64").len > 0:
    arkhamStressTests(arch = "linux_arm64", runner = "qemu-aarch64",
                      skip = arkhamLinuxA64Unsupported & arkhamA64Unsupported &
                             arkhamOsxOnly,
                      known = arkhamStressA64Known,
                      # a64's floor is one higher than x86-64's: `takeInstrReg` and
                      # `takeLvalStride` route through `takeHeld` with no spill arm,
                      # so at k=2 every atomic (`atomic2`, `atomic_ptr_cell`,
                      # `intrinsics`) and every non-scale index (`array2d`) dies on
                      # that documented assert, and `call_stack_args` reaches the
                      # ">8 integer params (stack TODO)" limit. Those are the
                      # backend's stated contracts, not findings — until the
                      # `canSpill` audit closes them, k=2 here is all noise.
                      floorLevel = 3)
