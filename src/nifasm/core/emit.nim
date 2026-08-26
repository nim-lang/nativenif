#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The emit-time bookkeeping all three selectors share.
##
## Two rules that are the assembler's, not any target's: a proc's prologue
## records what it did to the CFA so a debugger can walk past a frame that keeps
## no frame pointer, and a branch never goes BACKWARD — a back-edge must be
## written as `(loop …)`, which is what keeps every emitted jump forward and the
## relaxation passes monotone.

import std / [sets]
import nifcore
import context, diagnostics, relocs, buffers
import "../image/dwarf"

proc checkForwardJump*(ctx: GenContext; label: LabelId; n: Cursor) =
  ## Enforce the finalir invariant: every `jmp`/`jcc`/`b`/`bcc` must target a label
  ## that is not yet defined (a forward jump). A back-edge to an already-defined local
  ## label is forbidden — loops must be structured as `(loop …)`, whose back-edge is
  ## emitted internally (bypassing this check). Only *local* labels are tracked
  ## (`ctx.definedLabels`), so branches/tail-calls to proc/rodata/gvar targets — which
  ## are never added — are never flagged.
  if lenient(): return    # ported code keeps its original jump structure
  if int(label) in ctx.definedLabels:
    error("backward jump to an already-defined label is forbidden; " &
          "express the back-edge as a (loop …) instead", n)

proc cfiStep*(ctx: var GenContext; cfaDelta: int32;
             savedRegs: openArray[int32] = []; ssizeSlot = false;
             floats = false; frameImm: int32 = 0) =
  ## Record one prologue instruction's effect on the unwind state. Called from
  ## the handlers that emit a push / a pair-store / the frame `sub`, and only
  ## while `inPrologue` — see `genInst` for what ends that run.
  ##
  ## `savedRegs` are in STORE order: the first lands at the new bottom of the
  ## frame (CFA − the offset this step establishes), each next one 8 bytes above.
  ## That one rule covers both a single `push` and a `stp` pair.
  ##
  ## `ssizeSlot` marks the frame `sub`, whose immediate nifasm only knows once
  ## the proc's slots are laid out; `pass2Proc` fills the CFA offset in then.
  if ctx.unwind.len == 0: return
  ctx.cfaOff += cfaDelta
  var saves: seq[CfiSave] = @[]
  for i in 0 ..< savedRegs.len:
    saves.add CfiSave(reg: savedRegs[i], isFloat: floats,
                      cfaOff: -ctx.cfaOff + int32(8 * i))
  ctx.unwind[^1].steps.add CfiStep(at: ctx.buf.data.len, cfaOff: ctx.cfaOff,
                                   saves: saves, ssizeSlot: ssizeSlot,
                                   frameImm: frameImm)
  ctx.prologueOp = true

proc shiftCodePositions*(ctx: var GenContext; at, by: int) =
  ## Rebase every recorded byte position `>= at` by `by` freshly inserted bytes
  ## (the `casejmp` NOP padding). A label/reloc exactly AT the insert point
  ## belongs to the code AFTER the padding (the next slot), so `>=` is right —
  ## which is also why a casejmp branch body must not define a label at its very
  ## end (see doc/instructions.md).
  for k in 0 ..< ctx.buf.relocs.len:
    if ctx.buf.relocs[k].position >= at: ctx.buf.relocs[k].position += by
  for k in 0 ..< ctx.buf.labels.len:
    if ctx.buf.labels[k].position >= at: ctx.buf.labels[k].position += by
  for k in 0 ..< ctx.buf.fixedRanges.len:      # a NESTED casejmp region inside a slot
    let (s, e) = ctx.buf.fixedRanges[k]
    ctx.buf.fixedRanges[k] = ((if s >= at: s + by else: s), (if e >= at: e + by else: e))
  for k in 0 ..< ctx.gvarSites.len:
    if ctx.gvarSites[k][0] >= at: ctx.gvarSites[k] = (ctx.gvarSites[k][0] + by, ctx.gvarSites[k][1])
  for k in 0 ..< ctx.ssizePatches.len:
    if ctx.ssizePatches[k].pos >= at: ctx.ssizePatches[k].pos += by
  for k in 0 ..< ctx.csizePatches.len:
    if ctx.csizePatches[k][0] >= at: ctx.csizePatches[k] = (ctx.csizePatches[k][0] + by, ctx.csizePatches[k][1])
  for k in 0 ..< ctx.tlvSites.len:
    if ctx.tlvSites[k][0] >= at: ctx.tlvSites[k] = (ctx.tlvSites[k][0] + by, ctx.tlvSites[k][1])
  # An EXTERNAL call's `bl` is not a reloc — its position is recorded per extproc and
  # patched at image layout — so it needs rebasing here too. Missing it left the `bl`
  # unpatched (a branch to itself) and wrote the IAT displacement over whatever had
  # moved into the stale slot, which for a pruned frame `add` was the epilogue's
  # `add sp, sp, #frame`.
  for e in 0 ..< ctx.extProcs.len:
    for k in 0 ..< ctx.extProcs[e].callSites.len:
      if ctx.extProcs[e].callSites[k] >= at: ctx.extProcs[e].callSites[k] += by
  for k in 0 ..< ctx.listRows.len:      # `--listing` byte ranges
    if ctx.listRows[k].start >= at: ctx.listRows[k].start += by
    if ctx.listRows[k].stop >= at: ctx.listRows[k].stop += by
  for k in 0 ..< ctx.unwind.len:        # `.symtab` / `.eh_frame` proc + CFI positions
    if ctx.unwind[k].start >= at: ctx.unwind[k].start += by
    if ctx.unwind[k].stop >= at: ctx.unwind[k].stop += by
    for s in 0 ..< ctx.unwind[k].steps.len:
      if ctx.unwind[k].steps[s].at >= at: ctx.unwind[k].steps[s].at += by
