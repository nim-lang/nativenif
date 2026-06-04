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

const arkhamKnownUnsupported: seq[string] = @[]
  # Documented v0 TODOs that still `raiseAssert` in arkham's x86-64 backend.
  # Empty: the x64 backend now implements the full input corpus (the
  # float-in-call-signature ABI landed last). Any failure is a hard error. If a
  # new unimplemented feature is added, list its test stems here.

proc arkhamTests() =
  ## Each `tests/arkham/*.c.nif` is hand-written NIFC: arkham generates asm-NIF,
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
  # to `<workDir>/<name>.s.nif` so nifasm can auto-import it when a cross-module
  # test references its symbols (e.g. `Foo.0.mod_xlib` → loads `mod_xlib.s.nif`).
  for file in walkFiles("tests" / "arkham" / "mod_*.c.nif"):
    let name = extractFilename(file)[0 ..< extractFilename(file).len - ".c.nif".len]
    exec quoteShell(arkham) & " -a:" & arch & " -o:" &
         quoteShell(workDir / (name & ".s.nif")) & " " & quoteShell(file)
  var total, passed, skipped = 0
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_"): continue   # foreign helper, not standalone
    inc total
    let stem = file[0 ..< file.len - ".c.nif".len]
    let name = base[0 ..< base.len - ".c.nif".len]
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

# Tests not run under the static Linux/ELF `linux_arm64` qemu path: the tvar*
# cases rely on Darwin-only TLV thread-locals; `patidx` (`(pat …)` pointer
# indexing) and `indirect_call` (function-pointer calls) are implemented so far
# only in the x86-64 backend (arm64: TODO).
const arkhamLinuxA64Unsupported = ["tvar", "tvar_param", "tvar_addr", "patidx", "indirect_call"]

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
         quoteShell(workDir / (name & ".s.nif")) & " " & quoteShell(file)
  var total, passed, skipped = 0
  for file in walkFiles("tests" / "arkham" / "*.c.nif"):
    let base = extractFilename(file)
    if base.startsWith("mod_"): continue
    let name = base[0 ..< base.len - ".c.nif".len]
    if name in arkhamLinuxA64Unsupported: (inc skipped; continue)
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
elif defined(windows):
  exec "nim c -r src/nifasm/nifasm tests/hello_win64.nif"
  exec "./tests/hello_win64.exe"

exec "nim c -r src/nifasm/nifasm tests/hello.nif"
exec "nim c -r src/nifasm/nifasm tests/thread_local_tls.nif"
exec "nim c -r src/nifasm/nifasm tests/thread_local_switch.nif"
exec "nim c -r src/nifasm/nifasm tests/atomic_ops.nif"
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

# Additionally exercise the AArch64 backend on an x86-64 Linux host by emitting the
# `linux_arm64` ELF variant and running it under qemu-aarch64 (no-op if qemu is
# absent). Gives the arm64 path end-to-end coverage without a macOS machine.
when defined(linux) and defined(amd64):
  arkhamQemuTests()
