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

when defined(macosx):
  exec "nim c -r src/nifasm/nifasm tests/hello_darwin.nif"
  exec "tests/hello_darwin"
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
exec "nim c -r src/nifasm/nifasm tests/call_hello_chain.nif"
exec "nim c -r src/nifasm/nifasm tests/call_multi_result.nif"
exec "nim c -r src/nifasm/nifasm tests/call_result_binding.nif"

when defined(linux):
  # binaries have been built for linux only:
  exec "tests/hello"
  exec "tests/atomic_ops"
  #exec "tests/dot_at_access"
  #exec "tests/nested_dot_at"
  #exec "tests/pointer_dot_store"
  #exec "tests/array_i64_register_index"
  #exec "tests/pointer_field_at"
  #exec "tests/pointer_roundtrip"
  #execExpectOutput("./tests/string_pointer_field", "Hello\n")
  #execExpectOutput("./tests/message_inline_array", "Ping\n")
  #execExpectOutput("./tests/call_hello_chain", "Hello through calls\n")
  exec "./tests/call_multi_result"

# Failing tests are not platform specific!
execExpectFailure("nim c -r src/nifasm/nifasm tests/double_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/triple_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/quadruple_bind.nif", "Register RAX is already bound to variable 'x.0'")
execExpectFailure("nim c -r src/nifasm/nifasm tests/kill_use_after_kill.nif", "Expected variable or register as destination")
execExpectFailure("nim c -r src/nifasm/nifasm tests/missing_result_binding.nif", "Missing result binding: ret.0")
execExpectFailure("nim c -r src/nifasm/nifasm tests/stack_result_binding.nif", "Stack variable 'tmp.0' cannot be used directly")
execExpectFailure("nim c -r src/nifasm/nifasm tests/result_type_mismatch.nif", "Type mismatch:")
execExpectFailure("nim c -r src/nifasm/nifasm tests/call_missing_argument.nif", "Missing argument: arg.1")
execExpectFailure("nim c -r src/nifasm/nifasm tests/call_duplicate_result_binding.nif", "Result already bound: ret.0")
