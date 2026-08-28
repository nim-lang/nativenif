#
#           Ithaqua — Leng → wasm32 code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## ithaqua translates a Leng `.c.nif` MAIN module into one self-contained
## `.wasm` binary (whole-program: reachable declarations from every dependent
## module are pulled in through the embedded-index loader and emitted into the
## same wasm module — there is no separate link step).

import std / [parseopt, syncio, strutils, envvars]
import nifcoreparse
import "../arkham/core"/lengdecl
import codegen_wasm

const
  Version = "0.1.0"
  Usage = """ithaqua — wasm32 code generator for Leng """ & Version & """

Usage:
  ithaqua [options] file.c.nif

Options:
  -o:file, --output:file   output wasm file (default: <input>.wasm)
  -h, --help               show this help
"""

proc run(input, output: string) =
  # One shared tag pool across the main module and any foreign modules the
  # program model loads on demand (same arrangement as arkham).
  let tags = createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  var code: seq[byte]
  if getEnv("ITHAQUA_HOST_IMPORTS").len > 0:
    # two passes: discover the bodyless-importc surface, then re-emit with
    # every discovered name pinned as an env import (the JS bridge contract)
    var externs: seq[(string, Cursor)] = @[]
    discard generateWasm(buf, input, tags, collectExterns = true,
                         externsOut = addr externs)
    code = generateWasm(buf, input, tags, hostImports = externs)
  else:
    code = generateWasm(buf, input, tags)
  var s = newString(code.len)
  for i, b in code: s[i] = char(b)
  writeFile(output, s)

proc main() =
  var input, output = ""
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if input.len == 0: input = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": output = val
      of "help", "h": quit(Usage, QuitSuccess)
    of cmdEnd: discard
  if input.len == 0: quit(Usage, QuitSuccess)
  if output.len == 0: output = input & ".wasm"
  run(input, output)

when isMainModule:
  main()
