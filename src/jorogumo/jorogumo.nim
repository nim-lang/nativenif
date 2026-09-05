#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## jorogumo translates a Leng `.c.nif` MAIN module into one self-contained
## `.js` program (whole-program, like ithaqua: reachable declarations from
## every dependent module are pulled in through the embedded-index loader).
## There is no link step and no host import object — the emitted file runs on
## a bare `node file.js`.

import std / [parseopt, strutils]
import nifcoreparse
import "../arkham/core" / lengdecl
import jsenc, codegen_js

const
  Version = "0.1.0"
  Usage = """jorogumo — JavaScript code generator for Leng """ & Version & """

Usage:
  jorogumo [options] file.c.nif

Options:
  -o:file, --output:file   output js file (default: <input>.js)
  -m:N, --memory:N         linear memory in bytes (default: 64 MiB)
  -h, --help               show this help
"""

const DefaultMemBytes = 64 * 1024 * 1024  # §5: 64 MiB linear memory, host-overridable

proc generate(input, output: string; memBytes: int) =
  # One Leng tag pool for the input; `generateJs` builds its output in a buffer
  # with the jsnif pool. A buffer speaks one dialect, never both.
  let tags = lengdecl.createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  writeFile output, generateJs(buf, input, tags, memBytes)

proc main() =
  var input, output = ""
  var memBytes = DefaultMemBytes
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if input.len == 0: input = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": output = val
      of "memory", "m": memBytes = parseInt(val)
      of "help", "h": quit(Usage, QuitSuccess)
    of cmdEnd: discard
  if input.len == 0: quit(Usage, QuitSuccess)
  if output.len == 0: output = input & ".js"
  try:
    generate(input, output, memBytes)
  except JsGenError as e:
    # One line, not a stack trace: "this construct is not generated yet" is an
    # ordinary answer, and a caller (hastur, jsdiff) reads the exit code.
    quit "jorogumo: " & e.msg & "\n  in " & input, QuitFailure

when isMainModule:
  main()
