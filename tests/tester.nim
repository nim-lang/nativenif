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
else:
  exec "nim c -r src/nifasm/nifasm tests/hello.nif"
  exec "tests/hello"
  exec "nim c -r src/nifasm/nifasm tests/thread_local_tls.nif"
  exec "nim c -r src/nifasm/nifasm tests/thread_local_switch.nif"
  exec "nim c -r src/nifasm/nifasm tests/atomic_ops.nif"
  exec "tests/atomic_ops"
  exec "nim c -r src/nifasm/nifasm tests/unique_bind.nif"
  exec "nim c -r src/nifasm/nifasm tests/kill_reuse.nif"
  exec "nim c -r src/nifasm/nifasm tests/kill_reuse_multi.nif"
  exec "nim c -r src/nifasm/nifasm tests/kill_reuse_types.nif"
  exec "nim c -r src/nifasm/nifasm tests/dot_at_access.nif"
  exec "tests/dot_at_access"
  exec "nim c -r src/nifasm/nifasm tests/nested_dot_at.nif"
  exec "tests/nested_dot_at"
  exec "nim c -r src/nifasm/nifasm tests/pointer_dot_store.nif"
  exec "tests/pointer_dot_store"
  exec "nim c -r src/nifasm/nifasm tests/array_i64_register_index.nif"
  exec "tests/array_i64_register_index"
  exec "nim c -r src/nifasm/nifasm tests/pointer_field_at.nif"
  exec "tests/pointer_field_at"
  exec "nim c -r src/nifasm/nifasm tests/pointer_roundtrip.nif"
  exec "tests/pointer_roundtrip"
  exec "nim c -r src/nifasm/nifasm tests/string_pointer_field.nif"
  execExpectOutput("./tests/string_pointer_field", "Hello\n")
  exec "nim c -r src/nifasm/nifasm tests/message_inline_array.nif"
  execExpectOutput("./tests/message_inline_array", "Ping\n")
  exec "nim c -r src/nifasm/nifasm tests/call_hello_chain.nif"
  execExpectOutput("./tests/call_hello_chain", "Hello through calls\n")
  exec "nim c -r src/nifasm/nifasm tests/call_multi_result.nif"
  exec "./tests/call_multi_result"
  exec "nim c -r src/nifasm/nifasm tests/call_result_binding.nif"
  execExpectFailure("nim c -r src/nifasm/nifasm tests/double_bind.nif", "Register RAX is already bound to variable 'x.0'")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/triple_bind.nif", "Register RAX is already bound to variable 'x.0'")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/quadruple_bind.nif", "Register RAX is already bound to variable 'x.0'")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/kill_use_after_kill.nif", "Expected variable or register as destination")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/missing_result_binding.nif", "Missing result binding: ret.0")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/stack_result_binding.nif", "Result 'ret.0' must be bound to a register")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/result_type_mismatch.nif", "Type mismatch:")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/call_missing_argument.nif", "Missing argument: arg.1")
  execExpectFailure("nim c -r src/nifasm/nifasm tests/call_duplicate_result_binding.nif", "Duplicate result binding: ret.0")
