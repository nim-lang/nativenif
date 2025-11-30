
task build, "Build nifasm binary":
  exec "nim c -o:bin/nifasm src/nifasm/nifasm.nim"

