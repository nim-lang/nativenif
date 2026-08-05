#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## arkham translates a single Leng `.c.nif` file into typed `nifasm` NIF
## (AArch64 / Darwin), which `nifasm` then type-checks, assembles and links.

import std / [parseopt, syncio, strutils]
import nifcoreparse              # parseFromFile + nifcore
import lengdecl                  # createLengTagPool
import codegen_a64               # AArch64 / Darwin backend
import codegen_x64               # x86-64 / Linux backend

const
  Version = "0.1.0"
  Usage = """arkham — native code generator for Leng """ & Version & """

Usage:
  arkham [options] file.c.nif

Options:
  -o:file, --output:file   output asm-NIF file (default: <input>.asm.nif)
  --os:SYMBOL              target OS: linux | macosx (default: host)
  --cpu:SYMBOL             target CPU: amd64 | arm64 (default: host)
  -a:arch, --arch:arch     legacy combined form: arm64 | x64 | linux_arm64
                           (cannot be mixed with --os/--cpu)
  -h, --help               show this help

Supported --os/--cpu combinations (same symbols as Nimony's flags):
  linux/amd64  linux/arm64  macosx/arm64
"""

proc archOf(os, cpu: string): string =
  ## Map a Nimony-style (--os, --cpu) pair onto arkham's internal arch name.
  ## The symbols are Nim `platform` names, so what Nimony forwards verbatim is
  ## accepted; an unsupported OS/CPU *combination* is an error, never a silent
  ## host-class fallback.
  let osN = os.normalize
  let cpuN = cpu.normalize
  let cpuC = case cpuN
             of "amd64", "x8664", "x86_64": "amd64"
             of "arm64", "aarch64": "arm64"
             else: quit("arkham: unknown --cpu:" & cpu &
                        " (supported: amd64, arm64)", QuitFailure)
  let osC = case osN
            of "linux": "linux"
            of "windows": "windows"
            of "macosx", "macos", "osx": "macosx"
            else: quit("arkham: unknown --os:" & os &
                       " (supported: linux, windows, macosx)", QuitFailure)
  case osC & "/" & cpuC
  of "linux/amd64": "x64"
  of "linux/arm64": "linux_arm64"
  of "macosx/arm64": "arm64"
  else:
    quit("arkham: unsupported --os/--cpu combination: " & osC & "/" & cpuC &
         " (supported: linux/amd64, linux/arm64, macosx/arm64)",
         QuitFailure)

proc run(input, output, arch: string) =
  # One shared tag pool across the main module and any foreign modules the
  # program model loads on demand, so tag ordinals (hence stmtKind/typeKind
  # decoding) line up across modules.
  let tags = createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  let code = case arch
             of "x64", "x86_64", "amd64": generateX64(buf, input, tags)
             of "arm64", "aarch64", "": generateA64(buf, input, tags)
             of "linux_arm64", "linux_aarch64": generateA64(buf, input, tags, linux = true)
             else: quit("arkham: unknown --arch:" & arch, QuitFailure)
  writeFile(output, code)

proc main() =
  var input, output, arch, os, cpu = ""
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if input.len == 0: input = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": output = val
      of "arch", "a": arch = val
      of "os": os = val
      of "cpu": cpu = val
      of "help", "h": quit(Usage, QuitSuccess)
    of cmdEnd: discard
  if input.len == 0: quit(Usage, QuitSuccess)
  if output.len == 0: output = input & ".asm.nif"
  if os.len > 0 or cpu.len > 0:
    if arch.len > 0:
      quit("arkham: --arch cannot be combined with --os/--cpu", QuitFailure)
    # Nimony semantics: an unset half defaults to the HOST platform.
    if os.len == 0: os = hostOS
    if cpu.len == 0: cpu = hostCPU
    arch = archOf(os, cpu)
  run(input, output, arch)

when isMainModule:
  main()
