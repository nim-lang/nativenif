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
