#       ghast — the GPU device backend (Leng -> SPIR-V)
# (c) Copyright 2026 Andreas Rumpf
#
# See the file "license.txt", included in this distribution.

## `ghast` is the GPU code generator, scheduled by the `{.build(…).}` pragma as a
## DAG node: it consumes a `.gpu` module's Leng IR (`.c.nif`, paramStr 1) and
## produces a SPIR-V artifact (paramStr 2). "Built like a plugin, scheduled like
## a tool" — a standalone process decoupled by the NIF wire format, exactly like
## arkham<->nifasm on the CPU side.
##
## Pipeline (three modules, each a real stage):
##   1. parse the Leng IR with the nifcore Leng model (`nifcdecl`);
##   2. translate it to SPIR-V *as NIF* (`translate` -> a custom-tagged `spirv`
##      buffer), lowering each `proc` to a SPIR-V function;
##   3. render that NIF into real textual SPIR-V (`render`).
## The artifact is the rendered assembly; the intermediate NIF is also dumped
## next to it (`.spv.nif`) so it is inspectable and `render`'s CLI can re-run on
## it standalone.

import std / [os, syncio]
import "." / [translate, render]
import nifcore, nifcoreparse, nifcdecl

proc main() =
  if paramCount() < 2:
    quit "usage: ghast <module.c.nif> <out.spv>"
  let input = paramStr(1)
  let output = paramStr(2)

  # Parse the Leng IR; seed the tag pool so `cursorTagId` decodes to Leng enums.
  var buf = parseFromFile(input, sharedTags = createLengTagPool())
  var spv = translateModule(buf)

  # Dump the SPIR-V *as NIF* (inspectable; `render`'s CLI reads exactly this).
  writeFile(output & ".spv.nif", toString(spv))
  # The artifact itself is the rendered, real-syntax SPIR-V assembly.
  writeFile(output, renderSpirv(spv))

main()
