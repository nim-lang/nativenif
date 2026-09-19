#
#           Jorogumo — Leng → JavaScript (the web back end's JS face)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## jorogumo translates a Leng `.c.nif` MAIN module into one self-contained
## `.js` program. It is the JavaScript renderer of the shared web back end
## (`src/web`): the same code generator ithaqua drives, printed as JS.
## There is no link step and no host import object — the emitted file runs on
## a bare `node file.js`.

import std / [parseopt, strutils]
import nifcoreparse
import "../arkham/core" / lengdecl
import "../web" / [webnif, codegen, jsrender]

const
  Version = "0.1.0"
  Usage = """jorogumo — JavaScript code generator for Leng """ & Version & """

Usage:
  jorogumo [options] file.c.nif

Options:
  -o:file, --output:file   output js file (default: <input>.js)
  -m:N, --memory:N         linear memory in bytes (default: 64 MiB)
  --target:node|browser    host the output runs on (default: node). `browser`
                           drops the Node `fs`/`process` face: output buffers
                           into __takeOutput(), nim_exit throws, and the export
                           surface lands on globalThis.NIF, not module.exports.
  --browser                shorthand for --target:browser
  -h, --help               show this help
"""

const
  DefaultMemBytes = 64 * 1024 * 1024  # §5: 64 MiB linear memory, host-overridable
  MaxMemBytes = 2 * 1024 * 1024 * 1024
    ## Addresses are Numbers, and the emitted arithmetic stays exact below 2^53
    ## — but `>>> 0` and the stack/heap boundary checks think in uint32. A
    ## memory above 2 GiB would silently alias through the 32-bit window, so
    ## the ceiling is stated, not discovered.

proc run(input, output: string; memBytes: int; browser: bool) =
  # One Leng tag pool for the input; `generate` builds its output in a buffer
  # with the web IR pool. A buffer speaks one dialect, never both.
  let tags = lengdecl.createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  var m: WebModule
  var tree = generate(buf, input, tags, wtJs, m)
  writeFile output, renderJs(tree, m, memBytes, ShadowStackSize, browser = browser)

proc main() =
  var input, output = ""
  var memBytes = DefaultMemBytes
  var browser = false
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if input.len == 0: input = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": output = val
      of "memory", "m": memBytes = parseInt(val)
      of "target":
        case val.normalize
        of "node", "": browser = false
        of "browser": browser = true
        else: quit "jorogumo: --target must be `node` or `browser`\n", QuitFailure
      of "browser": browser = true
      of "help", "h": quit(Usage, QuitSuccess)
    of cmdEnd: discard
  if input.len == 0: quit(Usage, QuitSuccess)
  if output.len == 0: output = input & ".js"
  if memBytes <= 0 or memBytes > MaxMemBytes:
    quit "jorogumo: --memory must be in 1.." & $MaxMemBytes & " bytes (2 GiB)\n", QuitFailure
  try:
    run(input, output, memBytes, browser)
  except WebGenError as e:
    # One line, not a stack trace: "this construct is not generated yet" is an
    # ordinary answer, and a caller (hastur, jsdiff) reads the exit code.
    quit "jorogumo: " & e.msg & "\n  in " & input, QuitFailure

when isMainModule:
  main()
