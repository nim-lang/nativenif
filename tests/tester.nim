import std/[os, osproc]


proc exec(cmd: string; showProgress = false) =
  if showProgress:
    let exitCode = execShellCmd(cmd)
    if exitCode != 0:
      quit "FAILURE " & cmd & "\n"
  else:
    let (s, exitCode) = execCmdEx(cmd)
    if exitCode != 0:
      quit "FAILURE " & cmd & "\n" & s


when defined(macosx):
  exec "nim c -r src/nifasm/nifasm tests/hello_darwin.nif && tests/hello_darwin"
elif defined(windows):
  exec "nim c -r src/nifasm/nifasm tests/hello_win64.nif"
  exec "./tests/hello_win64.exe"
else:
  exec "nim c -r src/nifasm/nifasm tests/hello.nif && tests/hello"