#
#           The web back end — what it says when it refuses
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## A program the back end does not understand is an ordinary failure, not a
## broken invariant: the CLI reports it as one line and a coverage harness can
## ask "can you generate this?" without dying.
##
## `refuse` QUITS, it does not raise. Nimony's exceptions are bare error values
## — no message payload, no `CatchableError` to inherit from — so the two
## refusal channels that used to be `WebGenError` and `WasmRenderError` end
## here instead. The text is the CLI's, unchanged: the `\n  in <file>` tail the
## `except` clause used to append is why this module keeps the input file.

import std / [syncio]

proc quitErr*(msg: string; code = QuitFailure) {.noreturn.} =
  ## Every jorogumo diagnostic leaves through here, and it names the stream.
  ## Host Nim's `quit(msg)` writes to stderr; Nimony's `echo`es to stdout, and
  ## a refusal landing on stdout is one a harness reading the emitted module
  ## cannot tell from the module. This is the same line `quit(msg, code)`
  ## writes on host Nim, on the stream both builds then agree on.
  stderr.writeLine msg
  quit code

var gInputFile = ""

proc setInputFile*(f: string) {.inline.} = gInputFile = f
  ## The `.c.nif` every refusal names, set once by the driver before it
  ## generates. The refusal sites are deep in the code generator and the wasm
  ## renderer, neither of which is otherwise told what it is reading.

proc refuse*(msg: string) {.noreturn.} =
  quitErr "jorogumo: " & msg & "\n  in " & gInputFile
