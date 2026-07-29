#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## THE one parameter/argument classifier (chibicc's `assign_lvar_offsets`):
## `planCall` walks a signature's slots left to right ONCE and returns a
## `CallPlan` stating where every argument travels and how much of the register
## file / stack-argument area the call occupies. The allocator (`allocCall` /
## `allocParams`) and both emitters (signature emission, prologue param moves,
## stack-param loads, call-site marshalling) all consume the SAME plan, so their
## register counting cannot drift — historically the ABI bug generator: one site
## forgetting the hidden result pointer, the eightbyte span of a by-value
## aggregate, or the skip rule reclassified a parameter and miscompiled the call.
##
## The plan serves both directions: the CALLER view (one slot per argument
## expression) and the CALLEE view (one slot per declared parameter) — they are
## the same classification by construction.
##
## `retByRef` is stated by the CALLER of `planCall`, not derived here: on x86-64
## a >16B aggregate result reserves the first integer arg register (rdi) for the
## hidden result pointer; on AArch64 the pointer travels in x8, off the argument
## file. (Note: `allocCall` currently reserves the first GPR for `hiddenPtr` on
## BOTH arches — harmless, marshalling reads the allocator's placement — and the
## plan reproduces whatever the site states, so such quirks stay site-local and
## visible instead of being silently re-derived differently in six places.)

import nifcore
import slots, machinedesc, programs

type
  ParamPlace* = object
    ## Where ONE parameter / argument is passed. An element of `CallPlan.args`.
    ord*: int            ## param NAME ordinal (decoupled from the register index)
    onStack*: bool       ## passed on the stack rather than in registers
    isFloat*: bool       ## a float (xmm / v-register if register-passed)
    isAgg*: bool         ## an aggregate (AMem slot)
    byRef*: bool         ## aggregate larger than the threshold → a single pointer
    words*: int          ## eightbytes occupied (1 for a scalar / pointer / float)
    gpFirst*: int        ## register-passed int/aggregate: first GPR index
                         ## (registers = intArgRegs[gpFirst ..< gpFirst+words])
    fpIndex*: int        ## register-passed float: SIMD register index
    byteOff*: int        ## stack-passed: byte offset within the stack-argument area

  CallPlan* = object
    ## One signature's complete ABI assignment, computed ONCE by `planCall` and
    ## consumed by the allocator and both emitters.
    args*: seq[ParamPlace]
    retByRef*: bool      ## the first integer arg register carries a hidden result
                         ## pointer (shifts every GPR index and name ordinal by one)
    gpUsed*: int         ## exclusive end of the `intArgRegs` slice holding incoming
                         ## values (the hidden pointer + every register-passed word)
    fpUsed*: int         ## SIMD argument registers consumed
    hasStackArgs*: bool  ## any argument is stack-passed
    stackBytes*: int     ## bytes of the stack-argument area (8-rounded slots)

proc planCall*(md: MachineDesc; slots: openArray[AsmSlot]; retByRef: bool): CallPlan =
  ## Classify `slots` (caller: one per argument expression; callee: one per
  ## declared parameter) against the target's argument registers. An aggregate
  ## that does not fit in the REMAINING integer arg registers goes ENTIRELY on
  ## the stack and consumes NO register (so a later, smaller arg can still take
  ## a free one). Stack offsets round each slot up to 8 bytes, matching nifasm's
  ## `alignedSize` (so the callee's load offset == the caller's `(arg)`).
  result = CallPlan(retByRef: retByRef)
  var gp = if retByRef: 1 else: 0
  var fp = 0
  var stackOff = 0
  var ord = if retByRef: 1 else: 0
  for s in slots:
    var pp = ParamPlace(ord: ord)
    if s.kind == AMem:
      pp.isAgg = true
      pp.byRef = s.size > md.aggrByRefThreshold
      pp.words = if pp.byRef: 1 else: (s.size + 7) div 8
      if gp + pp.words <= md.intArgRegs.len:
        pp.gpFirst = gp; gp += pp.words
      else:
        pp.onStack = true; pp.byteOff = stackOff
        stackOff += (if pp.byRef: 8 else: (s.size + 7) and not 7)
    elif s.kind == AFloat:
      pp.isFloat = true; pp.words = 1
      if fp < md.floatArgRegs.len:
        pp.fpIndex = fp; inc fp
      else:
        pp.onStack = true; pp.byteOff = stackOff; stackOff += 8
    else:                               # scalar int / pointer
      pp.words = 1
      if gp < md.intArgRegs.len:
        pp.gpFirst = gp; inc gp
      else:
        pp.onStack = true; pp.byteOff = stackOff; stackOff += 8
    if pp.onStack: result.hasStackArgs = true
    result.args.add pp
    inc ord
  result.gpUsed = gp
  result.fpUsed = fp
  result.stackBytes = stackOff

proc paramSlots*(prog: var Program; paramsSlot: Cursor): seq[AsmSlot] =
  ## The `AsmSlot` of every declared parameter, in order — the callee-side input
  ## to `planCall`. `paramsSlot` is the `(params (param :name pragmas T)…)` node
  ## (a DotToken for an empty signature → `@[]`).
  result = @[]
  if paramsSlot.kind != TagLit: return
  var pc = paramsSlot
  pc.into:
    while pc.hasMore:
      pc.into:                          # (param :name pragmas type)
        inc pc; skip pc                 # name, pragmas
        result.add slotOf(prog, pc)
        while pc.hasMore: skip pc

proc gprAt*(md: MachineDesc; pl: ParamPlace; k = 0): Reg {.inline.} =
  ## The k-th integer argument register of a register-passed place.
  md.intArgRegs[pl.gpFirst + k]
