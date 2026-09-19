#
#           Arkham — register-pressure stress mode (`-d:arkhamStress`)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## An ARTIFICIAL REGISTER SHORTAGE, for testing.
##
## The test corpus is small enough that no pool ever runs dry, so the emitters'
## pool-dry arms go untested. `ARKHAM_STRESS=k` makes the same fixtures reach
## that regime by shrinking the register file instead of growing the programs: it
## keeps only the first `k` registers of each ALLOCATABLE pool. Nothing else
## changes, so each fixture's own `.exitcode`/`.output` stays the oracle and the
## mode checks totality (no pool-dry assert) *and* correctness under spilling.
##
## What is NOT shrunk, because it is not an allocation choice: the ABI
## (`intArgRegs`, `intRetReg`, `divRemReg`, `shiftCountReg`, …), since the
## fixtures link against a real libc; and the reserved emitter bridges (x86-64's
## R11 and xmm15, AArch64's x14/x15 and v31), which are withheld from the pools
## precisely so a transient is always available — taking them away would break a
## guarantee the emitters are written against rather than test one.
##
## The floors mark where an exhaustion is a genuine "this machine is too small":
## `pickStackArgBaseX64` reserves a callee-saved register up front for a proc
## with stack params, so one more must remain for an ordinary survivor.
##
## The whole mode compiles to nothing without `-d:arkhamStress`, so a shipped
## arkham cannot be perturbed by a stray environment variable.

import std / [envvars, parseutils]
import machinedesc

const StressEnabled* = defined(arkhamStress)

proc envInt*(name: string): int =
  ## The integer the environment variable `name` holds; 0 when it is unset, empty
  ## or not a number. (`parseutils`, not `strutils.parseInt`: the latter raises,
  ## which under Nimony every caller would have to catch.)
  let s = getEnv(name)
  var v = BiggestInt(0)
  if s.len > 0 and parseBiggestInt(s, v) == s.len: result = int(v)
  else: result = 0

const
  CalleeSavedFloor = 2
  TempFloor = 1
  FTempFloor = 1
  StagingFloor = 1        ## R11, the reserved bridge — never shrink past it. NOTE that
                          ## `k=1` is therefore BELOW the emitter's measured demand of
                          ## two (see `StagingCandidates`): a k=1 x86-64 run tests a
                          ## machine arkham does not claim to serve, so its failures are
                          ## the demand statement, not findings. k=2 is the real floor.

when StressEnabled:
  import std/[os, strutils]


  let stressKeep* = block:
    ## `ARKHAM_STRESS=k`: keep at most `k` registers per allocatable pool. Unset /
    ## empty / unparseable / `<= 0` leaves the mode dormant, so a
    ## `-d:arkhamStress` binary is a drop-in replacement for the shipped one.
    envInt("ARKHAM_STRESS")
else:
  const stressKeep* = 0

when StressEnabled:
  let stressParkMemory* = getEnv("ARKHAM_STRESS_PARK").strip == "mem"
    ## `ARKHAM_STRESS_PARK=mem`: every call-argument PARK (`takeParked`) skips
    ## its two register tiers and waits in a spill slot.
    ##
    ## Shrinking the pools does not reach that tier on x86-64, and no fixture can:
    ## a park is needed only for an argument register a LATER argument is pinned
    ## to by the ISA — rcx for a shift count, rdx for a division — so at most two
    ## words park per call, and the survivor the planner reserves for the emitter
    ## plus the first pool temp answer them. The memory tier is the one that has
    ## to hold when a real program arrives with both dry, so the tester drives it
    ## from here, against each fixture's own `.exitcode`.
else:
  const stressParkMemory* = false

when StressEnabled:
  let stressLateMoves* = getEnv("ARKHAM_STRESS_MOVES").strip == "late"
    ## `ARKHAM_STRESS_MOVES=late`: no call-argument move that only MOVES goes
    ## early. A leaf, an aggregate word, a 64-bit scalar's word stays where it
    ## lives until phase 2, and the parallel-move resolver places all of them.
    ## The early move is an optimization the resolver must never depend on, and
    ## this is how the corpus holds it to that. A COMPUTED argument is still
    ## evaluated into its own register when that is correct: that is where the
    ## value core gets the register it needs under a starved pool, and parking
    ## it instead tests the value core's spill tier, not the resolver.
else:
  const stressLateMoves* = false

proc stressActive(): bool {.inline.} =
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
  ## The callee-saved *sets* are rebuilt from the shrunk seqs: a register arkham
  ## no longer allocates must also stop answering "yes" to `intCalleeSavedSet`, or
  ## `usedCallee`/`trySteal` would reason about registers the pools can never hand
  ## out. The reading is "this machine has fewer registers", not "some are hidden".
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
  ## brings a staging register held across a recursion that itself needs staging
  ## within reach of the corpus, which cannot nest deeply enough on its own.
  when StressEnabled:
    (if stressKeep <= 0: n else: max(StagingFloor, min(stressKeep, n)))
  else:
    n
