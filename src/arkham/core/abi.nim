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
import asmslots, machinedesc, programs

type
  ParamPlace* = object
    ## Where ONE parameter / argument is passed. An element of `CallPlan.args`.
    ord*: int            ## param NAME ordinal (decoupled from the register index)
    onStack*: bool       ## passed on the stack rather than in registers
    isFloat*: bool       ## a float (xmm / v-register if register-passed)
    isAgg*: bool         ## an aggregate (AMem slot)
    byRef*: bool         ## aggregate larger than the threshold → a single pointer
    words*: int          ## target WORDS occupied. 1 for a pointer, a float, or a
                         ## by-ref aggregate; ceil(size/word) for a by-value
                         ## aggregate AND for a scalar wider than one word (an
                         ## `(i 64)` on a 32-bit target — a register pair)
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

proc planCall*(md: MachineDesc; slots: openArray[AsmSlot]; retByRef: bool;
               variadicFrom = -1): CallPlan =
  ## Classify `slots` (caller: one per argument expression; callee: one per
  ## declared parameter) against the target's argument registers. An aggregate
  ## that does not fit in the REMAINING integer arg registers goes ENTIRELY on
  ## the stack and consumes NO register (so a later, smaller arg can still take
  ## a free one). Stack offsets round each slot up to one target WORD, matching
  ## nifasm's `alignedSize` (so the callee's load offset == the caller's `(arg)`);
  ## on the 64-bit targets that word is the familiar eightbyte.
  let w = wordSize()
  result = CallPlan(retByRef: retByRef)
  var gp = if retByRef: 1 else: 0
  var fp = 0
  var stackOff = 0
  var ord = if retByRef: 1 else: 0
  var idx = 0
  for s in slots:
    var pp = ParamPlace(ord: ord)
    if variadicFrom >= 0 and idx >= variadicFrom:
      # Darwin AArch64: every argument past a `{.varargs.}` proc's declared
      # parameters travels on the stack, 8-byte slotted, no matter how many
      # argument registers are still free. This is the one place Apple's ABI
      # departs from AAPCS64 (which would keep filling x0–x7), and the callee —
      # libc's `open`/`printf`, compiled against Apple's rule — reads them from
      # there. Passing them in registers leaves it reading whatever the stack
      # happened to hold: `open`'s mode came out as garbage permission bits.
      pp.isFloat = s.kind == AFloat
      pp.isAgg = s.kind == AMem
      pp.byRef = pp.isAgg and s.size > md.aggrByRefThreshold
      pp.words = if pp.byRef or pp.isFloat: 1
                 else: max(1, (s.size + w - 1) div w)
      pp.onStack = true
      pp.byteOff = stackOff
      stackOff += (if pp.byRef or pp.isFloat: w else: (s.size + w - 1) and not (w - 1))
      result.hasStackArgs = true
      result.args.add pp
      inc ord
      inc idx
      continue
    inc idx
    if s.kind == AMem:
      pp.isAgg = true
      pp.byRef = s.size > md.aggrByRefThreshold
      pp.words = if pp.byRef: 1 else: (s.size + w - 1) div w
      if gp + pp.words <= md.intArgRegs.len:
        pp.gpFirst = gp; gp += pp.words
      else:
        pp.onStack = true; pp.byteOff = stackOff
        stackOff += (if pp.byRef: w else: (s.size + w - 1) and not (w - 1))
    elif s.kind == AFloat:
      pp.isFloat = true; pp.words = 1
      if fp < md.floatArgRegs.len:
        pp.fpIndex = fp; inc fp
      else:
        pp.onStack = true; pp.byteOff = stackOff; stackOff += w
    else:                               # scalar int / pointer
      # A scalar WIDER than one word travels in consecutive registers, exactly
      # as a by-value aggregate of the same size does — an `(i 64)` on a 32-bit
      # target is a register PAIR. On the 64-bit targets no scalar exceeds the
      # word, so this is `words = 1` there and the arm is unchanged.
      pp.words = max(1, (s.size + w - 1) div w)
      if gp + pp.words <= md.intArgRegs.len:
        pp.gpFirst = gp; gp += pp.words
      else:
        pp.onStack = true; pp.byteOff = stackOff
        stackOff += (s.size + w - 1) and not (w - 1)
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

proc isWideScalar*(pl: ParamPlace): bool {.inline.} =
  ## A non-aggregate that still spans several registers: a 64-bit integer on a
  ## 32-bit target. Passed like a by-value aggregate (consecutive words), but it
  ## is a VALUE — the emitters that ask `isAgg` to decide "copy bytes" must ask
  ## this too, and the ones that ask it to decide "how many registers" want
  ## `words` on its own.
  not pl.isAgg and not pl.isFloat and pl.words > 1

proc gprAt*(md: MachineDesc; pl: ParamPlace; k = 0): Reg {.inline.} =
  ## The k-th integer argument register of a register-passed place.
  md.intArgRegs[pl.gpFirst + k]
