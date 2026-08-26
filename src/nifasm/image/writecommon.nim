#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## What every image writer needs before it can lay one out.
##
## The runtime stack-trace table (`doc/tracetable.md`) is reserved during
## emission and filled AFTER layout, because its rows carry final addresses —
## and each writer runs its own layout passes, so each fills the table itself.
## `appendTraceTable` reserves the space; `fillTraceTable` writes the bytes.

import "../core" / [context, sem, relocs, buffers]
import dwarf, tracetable

proc dwarfArchOf*(arch: Arch): DwarfArch {.inline.} =
  if arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}: dwA64 else: dwX64

proc appendTraceTable*(ctx: var GenContext) =
  ## Reserve the stack-trace table at the end of `.text` and define the label that
  ## addresses it. Only the SPACE is reserved here: the proc positions it records
  ## are still going to move under the jump shortener and the alignment pass, so
  ## the bytes are written by `fillTraceTable` once those are done. The size does
  ## not move — layout changes where a proc is, never how many there are or what
  ## they are called.
  ##
  ## Called for every target, from `assemble`, and only when something referenced
  ## the symbol: a program that never asks for a stack trace carries no table.
  if not ctx.traceUsed: return
  # Start the blob on an 8-byte boundary. A courtesy, not a guarantee: the layout
  # passes shift it by whatever they add or remove ahead of it, so the reader must
  # tolerate an unaligned table anyway — which it does, since every field is a
  # `u32` and both targets permit unaligned word loads.
  while (ctx.buf.data.len and 7) != 0: ctx.buf.data.add 0'u8
  ctx.buf.defineLabel(ctx.traceLabel)
  let n = traceTableSize(collectTraceProcs(ctx.unwind, dwarfArchOf(ctx.arch)))
  for i in 0 ..< n: ctx.buf.data.add 0'u8

proc fillTraceTable*(a: var GenContext) =
  ## Write the reserved table, now that every proc's final code position is known.
  ## Runs after each writer's layout passes and before it copies `a.buf.data` out.
  if not a.traceUsed: return
  var at = -1
  for ld in a.buf.labels:
    if ld.id == a.traceLabel: at = ld.position
  if at < 0: return
  let bytes = encodeTraceTable(collectTraceProcs(a.unwind, dwarfArchOf(a.arch)), at)
  # The reservation is computed from the same `collectTraceProcs`, so a mismatch
  # means a layout pass grew or dropped a proc between the two calls — silently
  # writing a truncated table would produce a stack trace with invented names.
  if at + bytes.len > a.buf.data.len:
    quit "nifasm: trace table outgrew its reservation (" & $bytes.len & " bytes at " & $at & ")"
  for i in 0 ..< bytes.len: a.buf.data[at + i] = bytes[i]
