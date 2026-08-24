#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## arkham translates a single Leng `.c.nif` file into typed `nifasm` NIF for the
## selected target (`--os`/`--cpu`: linux/amd64, windows/amd64, linux/arm64,
## macosx/arm64, embedded/arm32), which `nifasm` then type-checks, assembles and
## links. The backends are `codegen_x64` and `codegen_arm` over the shared
## `codegen_common`; `codegen_arm` serves BOTH Arm targets — AArch64 and the
## bare-metal Cortex-M — from one emitter over three machine models.

import std / [parseopt, syncio, strutils]
import nifcoreparse              # parseFromFile + nifcore
import lengdecl                  # createLengTagPool
import machine_m                  # ConsoleKind and the CMSDK UART defaults
import layout                    # the --layout: board file
import codegen_common            # (arkhamTempDbg: dumpTempStats)
import codegen_arm               # BOTH Arm targets: AArch64 (Darwin/Linux) and
                                # Cortex-M. One emitter, three machine models.
import codegen_x64               # x86-64 / Linux backend

const
  Version = "0.1.0"
  Usage = """arkham — native code generator for Leng """ & Version & """

Usage:
  arkham [options] file.c.nif

Options:
  -o:file, --output:file   output asm-NIF file (default: <input>.asm.nif)
  --os:SYMBOL              target OS: linux | windows | macosx | embedded
                           (default: host)
  --cpu:SYMBOL             target CPU: amd64 | arm64 | arm32 (default: host)
  --layout:FILE            cortex_m only: the BOARD — its memory regions, which
                           region each section lives in, the console, the stack
                           slots and their thread-local reservation, and the
                           heap. A `(layout …)` NIF tree; see doc/layout.md.
                           Forwarded into the asm-NIF so nifasm places segments
                           from the same description rather than reading the file
                           a second time
  --writesTo:WHERE         cortex_m only: what `write` is implemented as, and
                           with it how `exit` ends. `debugger` (default) traps to
                           a debug agent — QEMU, or a probe — which does the I/O
                           on the host and takes the exit status. `serial` writes
                           bytes to a CMSDK APB UART and ends by parking the core
                           on `wfi`, needing nothing attached but a wire.
                           `serial:<addr>` gives the port's address; bare `serial`
                           is MPS2's UART0 at 0x40004000
  -a:arch, --arch:arch     legacy combined form: arm64 | x64 | linux_arm64 |
                           win_x64 (cannot be mixed with --os/--cpu)
  -h, --help               show this help

Supported --os/--cpu combinations (same symbols as Nimony's flags):
  linux/amd64  windows/amd64  linux/arm64  macosx/arm64  embedded/arm32
  (embedded/arm32 is bare-metal Cortex-M4; see doc/cortex_m.md)
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
             # `arm32` is the canonical spelling, here and in nimony's platform
             # table, because next to `arm64` the bare word never says which one
             # it is. `arm` stays accepted for what is already written.
             of "arm32", "arm": "arm32"
             else: quit("arkham: unknown --cpu:" & cpu &
                        " (supported: amd64, arm64, arm32)", QuitFailure)
  let osC = case osN
            of "linux": "linux"
            of "windows": "windows"
            of "macosx", "macos", "osx": "macosx"
            # `embedded` — there is no OS, which is a target and not the
            # absence of one.
            #
            # NOT `standalone`: that is Nim's name for a different arrangement
            # (freestanding-with-a-`panicoverride`) that nothing here offers, so
            # using the word would promise it. NOT `none` either: nimony turns the
            # OS name into a `defined()` symbol, and `defined(none)` says nothing
            # about what is being built.
            of "embedded", "baremetal": "embedded"
            else: quit("arkham: unknown --os:" & os &
                       " (supported: linux, windows, macosx, embedded)", QuitFailure)
  case osC & "/" & cpuC
  of "linux/amd64": "x64"
  of "windows/amd64": "win_x64"
  of "linux/arm64": "linux_arm64"
  of "macosx/arm64": "arm64"
  of "embedded/arm32": "cortex_m"
  else:
    quit("arkham: unsupported --os/--cpu combination: " & osC & "/" & cpuC &
         " (supported: linux/amd64, windows/amd64, linux/arm64, macosx/arm64," &
         " embedded/arm32)",
         QuitFailure)

proc parseWritesTo(val: string; serialBase: var int64): machine_m.WritesToKind =
  ## `--writesTo:debugger` | `--writesTo:serial` | `--writesTo:serial:<addr>`.
  ##
  ## The address rides along because it is the only part a BOARD gets to decide:
  ## the register layout is CMSDK's, which is what ARM's own reference designs and
  ## QEMU's MPS2 have, and a part with a different UART needs its own `write`
  ## rather than a flag. `serial` alone means MPS2's UART0, which is what
  ## `qemu-system-arm -M mps2-an386 -serial` puts on stdout.
  let v = val.normalize
  if v == "debugger": return machine_m.wtDebugger
  if v == "serial": return machine_m.wtSerial
  if v.startsWith("serial:"):
    let a = val.substr(7).strip()
    try:
      serialBase = if a.startsWith("0x") or a.startsWith("0X"):
                   cast[int64](fromHex[uint64](a))
                 else: int64(parseBiggestUInt(a))
    except ValueError:
      quit("arkham: --writesTo:serial: not an address: " & a, QuitFailure)
    return machine_m.wtSerial
  quit("arkham: unknown --writesTo:" & val &
       " (supported: debugger, serial, serial:<addr>)", QuitFailure)

proc run(input, output, arch: string;
         writesTo: machine_m.WritesToKind; serialBase: int64;
         board: layout.Layout) =
  # One shared tag pool across the main module and any foreign modules the
  # program model loads on demand, so tag ordinals (hence stmtKind/typeKind
  # decoding) line up across modules.
  let tags = createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  let code = case arch
             of "x64", "x86_64", "amd64": generateX64(buf, input, tags)
             of "win_x64", "windows_x64": generateX64(buf, input, tags, windows = true)
             of "arm64", "aarch64", "": generateA64(buf, input, tags)
             of "linux_arm64", "linux_aarch64": generateA64(buf, input, tags, linux = true)
             of "cortex_m", "cortexm", "thumbm":
               generateM(buf, input, tags, writesTo, serialBase, board)
             else: quit("arkham: unknown --arch:" & arch, QuitFailure)
  writeFile(output, code)

proc main() =
  var input, output, arch, os, cpu = ""
  var writesTo = machine_m.wtDebugger
  var serialBase = machine_m.MpsUart0Base
  var writesToGiven = false
  var board = Layout()
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
      of "writesto":
        writesTo = parseWritesTo(val, serialBase)
        writesToGiven = true
      of "layout":
        board = parseLayout(val)
        let bad = layout.validate(board)
        if bad.len > 0: quit("arkham --layout: " & bad, QuitFailure)
      of "help", "h": quit(Usage, QuitSuccess)
      else:
        # An unknown option is an ERROR, not something to walk past. Silently
        # ignoring one is how a flag that was renamed keeps "working": a stale
        # `--console:serial` in a build script would have produced a debugger
        # image and no complaint, which is a worse outcome than either spelling.
        quit("arkham: unknown option --" & key &
             " (see --help)", QuitFailure)
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
  if writesToGiven and arch notin ["cortex_m", "cortexm", "thumbm"]:
    # Every other target is hosted: `write` is the OS's, and there is no
    # peripheral for this flag to name. Silence would be the wrong answer for the
    # same reason the memory-map flags refuse it.
    quit("arkham: --writesTo applies to the cortex_m target only", QuitFailure)
  # The layout's answer is the board's own, so it wins over the flag — and giving
  # both is a contradiction rather than a precedence question.
  if board.given:
    if writesToGiven:
      quit("arkham: --writesTo and --layout both say where `write` goes; the " &
           "layout is the board's own description, so say it there", QuitFailure)
    case board.writesTo
    of layout.wtDebugger: writesTo = machine_m.wtDebugger
    of layout.wtSerial:
      writesTo = machine_m.wtSerial
      serialBase = int64(board.serialAddress)
  run(input, output, arch, writesTo, serialBase, board)
  when defined(arkhamTempDbg): dumpTempStats()

when isMainModule:
  main()
