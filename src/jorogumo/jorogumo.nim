#
#           Jorogumo — the web back end: Leng → JavaScript / wasm32
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## jorogumo translates a Leng `.c.nif` MAIN module into ONE self-contained
## program for a web host: `jorogumo j` writes a `.js` file, `jorogumo w` a
## `.wasm` binary. One tool, because there is one back end (`src/web`): the
## same code generator lowers Leng to the web IR either way, and only the
## renderer differs. Whole-program on both: reachable declarations from every
## dependent module come in through the embedded-index loader, so there is no
## link step.

import std / [parseopt, strutils, syncio]
import nifcoreparse
import "../arkham/core" / lengdecl
import "../web" / [webnif, diag, codegen, jsrender, wasmrender]

const
  Version = "0.1.0"
  Usage = """jorogumo — the web back end for Leng """ & Version & """

Usage:
  jorogumo j [options] file.c.nif    JavaScript, for node or a browser
  jorogumo w [options] file.c.nif    wasm32

Options:
  -o:file, --output:file   output file (default: <input>.js / <input>.wasm)
  -h, --help               show this help

JavaScript (`j`) only:
  -m:N, --memory:N         linear memory in bytes (default: 64 MiB)
  --target:node|browser    host the output runs on (default: node). `browser`
                           drops the Node `fs`/`process` face: output buffers
                           into __takeOutput(), nim_exit throws, and the export
                           surface lands on globalThis.NIF, not module.exports.
  --browser                shorthand for --target:browser

wasm (`w`) only:
  --host-imports           a bodyless `importc` proc becomes an `env` import
                           the host page provides, instead of a refusal
  --export-all             also export every function as `dbg$<name>`, so a
                           host script can drive internals directly
"""

const
  DefaultMemBytes = 64 * 1024 * 1024  # §5: 64 MiB linear memory, host-overridable
  MaxMemBytes = 2 * 1024 * 1024 * 1024
    ## Addresses are Numbers, and the emitted arithmetic stays exact below 2^53
    ## — but `>>> 0` and the stack/heap boundary checks think in uint32. A
    ## memory above 2 GiB would silently alias through the 32-bit window, so
    ## the limit is stated, not discovered.

type
  Target = enum
    tJs = "j"
    tWasm = "w"

proc writeOut(path, content: string) =
  ## `writeFile` raises, and a failed write is an ordinary failure like any
  ## other here: one line naming the file, not a stack trace.
  try:
    writeFile path, content
  except:
    quitErr "jorogumo: cannot write " & path, QuitFailure

proc run(target: Target; input, output: string; memBytes: int; browser,
         hostImports, exportAll: bool) =
  # One Leng tag pool for the input; `generate` builds its output in a buffer
  # with the web IR pool. A buffer speaks one dialect, never both.
  let tags = lengdecl.createLengTagPool()
  var buf = parseFromFile(input, sharedTags = tags)
  var m = default(WebModule)
  case target
  of tJs:
    var tree = generate(buf, input, tags, wtJs, m)
    writeOut output, renderJs(tree, m, memBytes, ShadowStackSize,
                              browser = browser)
  of tWasm:
    var tree = generate(buf, input, tags, wtWasm, m, hostImports = hostImports)
    let code = renderWasm(tree, m, ShadowStackSize, exportAll = exportAll)
    var s = newString(code.len)
    for i, b in code: s[i] = char(b)
    writeOut output, s

proc main() =
  var input, output = ""
  var memBytes = DefaultMemBytes
  var browser = false
  var hostImports = false
  var exportAll = false
  var target = tJs
  var haveTarget = false
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      # The first argument names the RENDERER, and nothing else can: a `.c.nif`
      # input is not a target, and guessing one from the output's extension
      # would make a typo compile silently into the other language.
      if not haveTarget:
        case key.normalize
        of "j": target = tJs
        of "w": target = tWasm
        else:
          quitErr "jorogumo: first argument must be `j` (JavaScript) or `w` (wasm), got `" &
               key & "`\n" & Usage, QuitFailure
        haveTarget = true
      elif input.len == 0:
        input = key
    of cmdLongOption, cmdShortOption:
      # `normalize` folds case and underscores but keeps dashes, and the long
      # options here are spelled with one.
      case key.normalize.replace("-", "")
      of "output", "o": output = val
      of "memory", "m":
        try: memBytes = parseInt(val)
        except: quitErr "jorogumo: --memory wants a byte count, got `" & val & "`\n",
                     QuitFailure
      of "target":
        case val.normalize
        of "node", "": browser = false
        of "browser": browser = true
        else: quitErr "jorogumo: --target must be `node` or `browser`\n", QuitFailure
      of "browser": browser = true
      of "hostimports": hostImports = true
      of "exportall": exportAll = true
      of "help", "h": quitErr(Usage, QuitSuccess)
    of cmdEnd: discard
  if not haveTarget or input.len == 0: quitErr(Usage, QuitSuccess)
  # An option of the other renderer is a misunderstanding about what is being
  # built, not a detail to drop on the floor.
  if target == tWasm and (browser or memBytes != DefaultMemBytes):
    quitErr "jorogumo: --memory/--target are JavaScript options; a wasm module " &
         "sizes its memory from the static image and grows it at run time\n",
         QuitFailure
  if target == tJs and (hostImports or exportAll):
    quitErr "jorogumo: --host-imports/--export-all are wasm options\n", QuitFailure
  if output.len == 0: output = input & (if target == tJs: ".js" else: ".wasm")
  if memBytes <= 0 or memBytes > MaxMemBytes:
    quitErr "jorogumo: --memory must be in 1.." & $MaxMemBytes & " bytes (2 GiB)\n", QuitFailure
  # A refusal is one line, not a stack trace: "this construct is not generated
  # yet" is an ordinary answer, and a caller (hastur, the diff harnesses) reads
  # the exit code. `diag.refuse` prints it and quits at the site, so the file it
  # names has to be handed over first.
  setInputFile input
  run(target, input, output, memBytes, browser, hostImports, exportAll)

when isMainModule:
  main()
