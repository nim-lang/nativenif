#
#           Arkham — register-pressure stress mode (`-d:arkhamStress`)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## An ARTIFICIAL REGISTER SHORTAGE, for testing.
##
## The golden corpus is a necessary but never sufficient gate: its fixtures are
## small hand-written programs that never reach the register pressure real code
## (nimony's own sources, `-d:release` / `-d:danger`) puts on the emitters. Every
## pool-dry bug this project has shipped was found by bootstrapping and none by
## the suite — the 2026-07-30 marshaller `takeHeld` exhaustions and a64
## `genAggrCopyStore` acquisition, the 2026-08-03 `produceIntoMem2`
## address-chain blow-up, `takeLvalStride`'s scratch held across a premat
## recursion, and `pickStagingScratch`'s missing callee-saved backstop. All of
## them are invisible until a pool actually runs out.
##
## This mode makes the SAME fixtures reach that regime by shrinking the register
## file instead of growing the programs: `ARKHAM_STRESS=k` keeps only the first
## `k` registers of each ALLOCATABLE pool. Nothing else changes, so each
## fixture's own `.exitcode`/`.output` stays the oracle. That is the point —
## the mode checks *totality* (no pool-dry `raiseAssert` / `quit`) **and**
## *correctness under maximum spilling* (the answers must still be right).
## A pure totality argument cannot check the second half: `formal/regproto.nif`
## proves the demand chain always has an enabled arm, but says nothing about
## whether the value that comes back through it is the right one — and the
## `takeLvalStride` index-borrow trap was exactly a wrong value, not a missing
## register.
##
## What is NOT shrunk, because it is not an allocation choice:
##  * the ABI — `intArgRegs`/`floatArgRegs`, `intRetReg`, `divRemReg` (idiv),
##    `shiftCountReg` (cl), `aggrByRefThreshold`. Shrinking those changes the
##    calling convention rather than the pressure, and the fixtures link against
##    a real libc.
##  * the reserved emitter bridges — x86-64's R11 (`StagingCandidates[0]`) and
##    xmm15, AArch64's x14/x15 and v31. They are withheld from the allocator
##    pools precisely so a transient is ALWAYS available; taking them away
##    removes the guarantee the emitters are written against, so a failure would
##    say nothing about the code as shipped.
##
## The floors below exist for the same reason — they mark the points where an
## exhaustion is a genuine "this machine is too small", not a bug:
##  * `CalleeSavedFloor = 2` — `pickStackArgBaseX64` asserts on a free
##    callee-saved register for a proc with stack params, and the allocator
##    reserves it up front; one more must remain for an ordinary survivor.
##  * `TempFloor = 1` — x86-64 ships exactly one (`R10`), so this is only a
##    real shrink on AArch64 (5 → 1).
##  * `FTempFloor = 1` — the float twin.
##
## The whole mode compiles to nothing without `-d:arkhamStress`, so a shipped
## arkham cannot be perturbed by a stray environment variable.

import machinedesc

const StressEnabled* = defined(arkhamStress)

const
  CalleeSavedFloor = 2
  TempFloor = 1
  FTempFloor = 1
  StagingFloor = 1        ## R11, the reserved bridge — never shrink past it

when StressEnabled:
  import std/[os, strutils]

  let stressKeep* = block:
    ## `ARKHAM_STRESS=k`: keep at most `k` registers per allocatable pool.
    ## Unset / empty / unparseable / `<= 0` leaves the mode dormant, so the
    ## `-d:arkhamStress` binary is a drop-in replacement when the variable is
    ## absent (which is what makes "same binary, k=0 vs k=1" a clean A/B).
    let s = getEnv("ARKHAM_STRESS").strip
    if s.len == 0: 0
    else:
      try: parseInt(s)
      except ValueError: 0
else:
  const stressKeep* = 0

proc stressActive*(): bool {.inline.} =
  when StressEnabled: stressKeep > 0
  else: false

when StressEnabled:
  proc keepFirst[T](pool: seq[T]; floorN: int): seq[T] =
    let n = max(floorN, min(stressKeep, pool.len))
    if n >= pool.len: pool else: pool[0 ..< n]

proc stressed*(md: MachineDesc): MachineDesc =
  ## The machine description arkham actually allocates against. Identity unless
  ## `-d:arkhamStress` is compiled in AND `ARKHAM_STRESS` names a positive `k`.
  ##
  ## The callee-saved *sets* are rebuilt from the shrunk seqs rather than left
  ## alone: a register arkham no longer allocates must also stop answering "yes"
  ## to `r in intCalleeSavedSet`, or `usedCallee`/`trySteal`/the survivor test
  ## would reason about registers the pools can never hand out. The consistent
  ## reading is "this machine has fewer callee-saved registers", not "some are
  ## hidden".
  result = md
  when StressEnabled:
    if stressKeep <= 0: return
    result.intCalleeSaved = keepFirst(md.intCalleeSaved, CalleeSavedFloor)
    result.intLocalTempRegs = keepFirst(md.intLocalTempRegs, 0)
    result.intTempRegs = keepFirst(md.intTempRegs, TempFloor)
    result.floatTempRegs = keepFirst(md.floatTempRegs, FTempFloor)
    result.floatCalleeSaved = keepFirst(md.floatCalleeSaved, 0)
    result.intCalleeSavedSet = {}
    for r in result.intCalleeSaved: result.intCalleeSavedSet.incl r
    result.floatCalleeSavedSet = {}
    for f in result.floatCalleeSaved: result.floatCalleeSavedSet.incl f

template stressLimit*(n: int): int =
  ## How many entries of a fixed emitter candidate array to consider — x86-64's
  ## `StagingCandidates`, whose head is the reserved R11 bridge. Truncating it
  ## is the sharpest lever on the exact class of bug this mode exists for: a
  ## staging register held across a recursion that itself needs staging (the
  ## `-d:danger` `cmpStringPtrs` blow-up) shows up at `k` = 2 instead of
  ## needing a nesting depth the corpus does not contain.
  when StressEnabled:
    (if stressKeep <= 0: n else: max(StagingFloor, min(stressKeep, n)))
  else:
    n
