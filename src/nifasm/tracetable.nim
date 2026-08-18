#
#           nifasm — the runtime stack-trace table
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `.eh_frame` tells a *debugger* how to walk our stack. This tells the *program
## itself* — it is what `getStackTrace()` reads.
##
## The two could have been one: a runtime unwinder that parses DWARF CFI is a
## known quantity. It is also a few hundred lines of state machine, in the
## standard library, that must run correctly while the program is already in
## trouble. Every fact it would recover is a constant here, because of the one
## property `src/arkham/design.md` states and `dwarf.nim` already leans on: *the
## frame is fixed*. SP is lowered once by the prologue and constant until the
## epilogue, so "where is my return address" is a per-PROC number, not a per-PC
## program. One `u32` per proc replaces the interpreter.
##
## Layout — one blob, everything inside it self-relative:
##
## ```
##   Header    magic 'NTRC' | version | count | entrySize
##   Entry[]   codeOff | codeLen | cfaOff | nameOff        (sorted by codeOff)
##   names     NUL-terminated, in entry order
## ```
##
## `codeOff` and `nameOff` are byte distances **from the start of the table**, not
## addresses. That is the whole reason this needs no relocation and no load-time
## fixup: the reader gets the table's address from `lea` (RIP-relative, so it is
## right under PIE, ASLR and every base the three object formats pick) and every
## other address is that plus an offset. An absolute-pointer table would have to
## be rebased by *something* on Windows, and would be a `.reloc` section nifasm
## does not otherwise need.
##
## `cfaOff` is the DWARF CFA offset in the proc's BODY: `CFA = SP + cfaOff`, and
## the return address sits at `CFA - 8` on x86-64. It is only valid past the
## prologue — which is exactly where every frame but the innermost is, and the
## innermost frame's seed comes from a `{.naked.}` proc that has no prologue at
## all. See `lib/std/stacktraces.nim` for the walk.

import std / algorithm

const
  TraceMagic* = 0x4352544E'u32   ## 'N','T','R','C' little-endian
  TraceVersion* = 1'u32
  TraceHeaderSize* = 16
  TraceEntrySize* = 16
  TraceInfoSymbol* = "arkham.traceinfo.0"
    ## The reserved label nifasm defines for the table. arkham lowers the
    ## `traceTable` intrinsic to a `lea` against it; nothing else may define it.

type
  TraceProc* = object
    ## One row, already reduced to the four numbers the runtime needs. The
    ## reduction itself lives in `dwarf.collectTraceProcs`, next to the
    ## `ProcUnwind` it reads — this module knows only the wire format, so arkham
    ## can import it for `TraceInfoSymbol` alone.
    codeOff*: int      ## proc start, as a byte position in the text image
    codeLen*: int
    cfaOff*: int       ## CFA = SP + this, anywhere past the prologue
    name*: string

proc traceTableSize*(procs: openArray[TraceProc]): int =
  ## Exactly what `encodeTraceTable` will produce. Needed separately because the
  ## table's SPACE is reserved before the layout passes run (so the label that
  ## addresses it moves with the code) while its CONTENT can only be written
  ## after them, when the proc positions are final.
  result = TraceHeaderSize + procs.len * TraceEntrySize
  for p in procs: result += p.name.len + 1

proc encodeTraceTable*(procs: openArray[TraceProc]; tableAt: int): seq[byte] =
  ## `tableAt` is the table's own byte position in the text image — the same
  ## coordinate system as `TraceProc.codeOff`, since every stored offset is a
  ## distance from the table to the thing it names.
  result = newSeqOfCap[byte](traceTableSize(procs))
  proc addU32(s: var seq[byte]; v: uint32) =
    s.add byte(v and 0xFF); s.add byte((v shr 8) and 0xFF)
    s.add byte((v shr 16) and 0xFF); s.add byte((v shr 24) and 0xFF)

  result.addU32 TraceMagic
  result.addU32 TraceVersion
  result.addU32 uint32(procs.len)
  result.addU32 uint32(TraceEntrySize)
  var nameOff = TraceHeaderSize + procs.len * TraceEntrySize
  for p in procs:
    result.addU32 cast[uint32](int32(p.codeOff - tableAt))
    result.addU32 uint32(p.codeLen)
    result.addU32 uint32(p.cfaOff)
    result.addU32 uint32(nameOff)
    nameOff += p.name.len + 1
  for p in procs:
    for ch in p.name: result.add byte(ch)
    result.add 0'u8
