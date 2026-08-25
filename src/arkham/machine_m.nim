#
#           Arkham — Cortex-M (ARMv7E-M / AAPCS32) backend machine model
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The Cortex-M register file and calling convention as the (arch-neutral)
## register allocator consumes it. The abstract `Reg` slots are reinterpreted as
## the Thumb GPRs: `R0`..`R12` are r0–r12 and the `SP` slot is sp, so the low
## thirteen slots are used and `R13`..`R30` stay unallocated — the same
## subsetting x86-64 does with `R16`..`R30`.
##
## The register file is the tightest of the three targets and that drives every
## choice below. AAPCS32 gives four argument registers (r0–r3), eight
## callee-saved (r4–r11), and exactly ONE non-argument caller-saved register
## (r12/IP) — which nifasm has already claimed as its own operand-folding
## scratch. So unlike AArch64, where seven volatiles are free for temporaries,
## there is no spare volatile here at all.

import slots, machinedesc
export machinedesc

const
  IP* = R12   ## AAPCS32's intra-procedure scratch — **nifasm's**, not arkham's.
              ## The assembler folds a non-register operand into a 3-operand
              ## form through it and materializes an indexed access with a
              ## displacement through it, at sites arkham cannot see. arkham must
              ## therefore never place a value here: it is absent from every pool
              ## below and listed in `ReservedRegs`.
  LR* = R14   ## the link register (hardware r14). Present only so `regName`
              ## renders it; arkham never allocates it.

  IntArgRegs*   = [R0, R1, R2, R3]   ## AAPCS32 argument registers; r0 also returns
  IntRet*       = R0

  ## Callee-saved homes for values that must survive a call. Four of AAPCS32's
  ## eight; the other four are dedicated below (r8 produce bridge, r9 hidden
  ## result pointer, r10/r11 staging bridges).
  ##
  ## Four is thin, and deliberately so: every one of the dedicated registers
  ## exists because the emitter needs a register it can ALWAYS take, and a
  ## "usually free" register is worth nothing to a path that must be total.
  ## x86-64 allocates from a comparable pool.
  IntCalleeSaved* = [R4, R5, R6, R7]

  ProduceBridge* = R8
    ## The third reserved scratch, beyond the two staging bridges: the Cortex-M
    ## stand-in for AArch64's x16 (IP0). Named for what it is USED for — staging a
    ## value on its way into memory — not for a claim on it: `bridgeRegs` lists all
    ## three, so a staging draw that finds r10/r11 busy reaches this one too.
    ##
    ## AArch64 borrows the assembler's own scratch for this. Cortex-M cannot —
    ## nifasm has claimed r12 for operand folding at sites arkham never sees, so
    ## a value left there dies to an instruction the code generator did not emit
    ## and cannot see. Hence a register of arkham's own, in no pool.
    ##
    ## Used where a value must be staged through a register with no bridge
    ## available: producing into a spilled slot, the re-representation of a cast
    ## whose value came back in memory, and the aggregate copy under total
    ## register exhaustion.

  IndirectResultReg* = R9
    ## Where a caller leaves `&result` for a callee returning an aggregate too
    ## wide to fit in registers — the Cortex-M stand-in for AArch64's x8.
    ##
    ## AAPCS32 would pass that pointer as a hidden FIRST argument, shifting every
    ## real parameter down one. Taking a register off the argument file instead
    ## keeps the AArch64 shape the shared emitter already implements, and is
    ## sound for the same reason it is sound there: arkham owns both sides of
    ## every call. r9 works precisely because it is in NO allocation pool — no
    ## proc ever writes it — so a callee-saved register is preserved across
    ## arbitrary nesting without anyone saving it.
    ##
    ## It costs one allocator home. The alternative, r0 with the x86-style
    ## argument shift, costs an argument register on every such call and needs
    ## `planCall`'s `retByRef` threaded through sites that currently pass false.

  ## EMPTY, and that is the whole answer to a register file this small.
  ##
  ## This pool is emitter SCRATCH, and scratch is drawn while a call's arguments
  ## are being staged. On x86-64 and AArch64 it is disjoint from the argument
  ## registers (r10 vs rdi…r9; x9–x15 vs x0–x7), so that is safe without anyone
  ## having to say so. Cortex-M's only volatiles ARE its four argument registers,
  ## and an overlapping pool means the allocator hands out r1 as a temp while r1
  ## already holds staged argument word 1 — which is exactly what happened: an
  ## aggregate argument was marshalled into r0/r1, then the NEXT argument's
  ## constructor took r1 as scratch and the callee read 1 where 10 belonged.
  ##
  ## With no volatile pool, temporaries come from the callee-saved homes
  ## (r4–r7). That costs a prologue save in procs that would otherwise be leaves
  ## and buys correctness that the register file cannot otherwise provide. A
  ## narrower fix — teaching the scratch picker which argument registers are
  ## currently staged — is the real answer, and belongs with the emitter rather
  ## than in this table.
  IntTempRegs*: array[0, Reg] = []
  IntLocalTempRegs*: array[0, Reg] = []

  ## Emitter "staging bridges", withheld from every pool so a transient can
  ## always be drawn: a folded memory operand the 3-operand ALU must load first,
  ## a global's address, and a produce-into-memory spill. Two are needed for the
  ## same reason AArch64 needs two — a `cmp` whose BOTH operands spilled to the
  ## stack has to load each into a register, and Thumb-2 has no memory-operand
  ## compare.
  ##
  ## These are CALLEE-saved registers used as scratch, which is a private
  ## convention: valid because arkham owns both sides of every call in a
  ## self-contained image. Calling arkham-generated code FROM C would violate
  ## AAPCS32 — that is an M6 concern, and the fix there is to save them in the
  ## prologue of any `exportc`'d proc.
  IntBridgeRegs* = [R10, R11]

  ## ── FPv4-SP (M5) ──────────────────────────────────────────────────────────
  ## Cortex-M4F's FPU is SINGLE PRECISION ONLY: s0–s31, no `.f64` instruction at
  ## all. A `float64` is therefore refused BY NAME rather than lowered through a
  ## softfloat library nobody asked for — see `rejectForThumbM`.
  ##
  ## Unlike the integer file this one is roomy, so the split follows AAPCS32's
  ## (s0–s15 caller-saved, s16–s31 callee-saved) and — crucially — keeps the
  ## temp pool DISJOINT from the argument registers. That is the property the
  ## integer side could not have (see `IntTempRegs`), and it is why float scratch
  ## needs no special care while a call's arguments are being staged.
  FloatArgRegs*      = [F0, F1, F2, F3, F4, F5, F6, F7]    ## s0–s7; s0 also returns
  FloatRet*          = F0
  FloatTempRegs*     = [F8, F9, F10, F11, F12, F13, F14, F15]   ## s8–s15, volatile
  FloatCalleeSaved*  = [F16, F17, F18, F19, F20, F21, F22, F23] ## s16–s23, saved

  ## s30 is nifasm's, s31 is the emitter's float staging bridge
  ## (`machine.FloatBridgeReg`), and s24–s29 are simply unused. nifasm needs one
  ## because `vcvt` between an integer and a float goes through the FPU: turning
  ## `(fcvtzs <gpr> <sreg>)` into machine code takes a float register to convert
  ## INTO, and the source may still be live. Same reasoning as r12/IP.

  ## Never allocate: nifasm's IP, the link register, sp, and the abstract slots
  ## that map to no Cortex-M register.
  ReservedRegs* = {R12, R13, R14, R15, R16..R30, SP, NoReg}

  ## What a call destroys under AAPCS32 — emitted as the proc's `(clobber …)` so
  ## the ABI is declared at the signature rather than re-derived at each site.
  ## r12 and lr are included: `bl` overwrites lr, and IP is scratch for everyone.
  ConvClobbersGpr* = [R0, R1, R2, R3]

  ## Every register withheld from all three pools, in the order the staging draw
  ## walks them: the two bridges first, then the produce bridge — so a site with
  ## its own claim on the latter (`takeProduceBridge`) still finds it free, and
  ## the draw reaches it only where it would otherwise have had nothing. The
  ## AArch64 twin is `machine.AtomicScratchRegs`, and both are read through
  ## `MachineDesc.bridgeRegs`.
  BridgeRegs* = [IntBridgeRegs[0], IntBridgeRegs[1], ProduceBridge]

  ## The Cortex-M machine description handed to the register allocator.
  cortexMMachine* = MachineDesc(
    arch: ThumbM,
    intRetReg: R0,
    divRemReg: NoReg,           # sdiv/udiv are 3-operand; the remainder is `mls`
    shiftCountReg: NoReg,       # Thumb-2 shifts take any register
    intArgRegs: @IntArgRegs,
    floatArgRegs: @FloatArgRegs,
    intTempRegs: @IntTempRegs,
    stagingBridgeReg: NoReg,    # like AArch64: the bridges are withheld from the
                                # pools instead (see IntBridgeRegs)
    intLocalTempRegs: @IntLocalTempRegs,
    intCalleeSaved: @IntCalleeSaved,
    floatTempRegs: @FloatTempRegs,
    floatCalleeSaved: @FloatCalleeSaved,
    intCalleeSavedSet: {R4..R7},
    floatCalleeSavedSet: {F16..F23},
    aggrByRefThreshold: 8,      # TWO words, matching `slots.classifyArg`'s `2*w`.
                                # These two decide the same thing and MUST agree:
                                # `planCall` reads the threshold while the
                                # classifier reads `2*w`, so a disagreement makes
                                # the caller pass by value what the callee reads
                                # as a pointer. (16 on both 64-bit targets — the
                                # same rule, stated in words.)
    linkReg: LR,
    framePtrReg: NoReg,         # Cortex-M addresses everything off SP: there is
                                # no fp/lr PAIR instruction to establish one with,
                                # and stack parameters are reached from SP once
                                # the prologue has finished lowering it.
    indirectResultReg: IndirectResultReg,
    produceBridge: ProduceBridge,
    bridgeRegs: @BridgeRegs,
    floatBridgeReg: F31,        # `machine.FloatBridgeReg`; s31 here
    abiFloatCalleeSaved: @FloatCalleeSaved,
    abiCalleeSaved: @IntCalleeSaved,
    intCallerSavedSet: {R0, R1, R2, R3},   # AAPCS32's four; r12 is volatile too,
                                           # but it is nifasm's (see `IP`)
    convClobbersGpr: @ConvClobbersGpr)

proc regNameM*(r: Reg): string =
  ## The asm-NIF spelling of a GPR slot. These are the tags nifasm's `MReg`
  ## enum accepts — `(r0)`..`(r12)`, `(sp)`, `(lr)` — which Cortex-M SHARES with
  ## the other targets rather than minting its own (see doc/instructions.md).
  case r
  of SP: "sp"
  of R14: "lr"
  of NoReg: "<noreg>"
  else:
    if ord(r) <= ord(R12): "r" & $ord(r)
    else: "<unmapped:" & $ord(r) & ">"

proc isAllocatableM*(r: Reg): bool {.inline.} =
  ## Whether arkham may place a value in `r`. Excludes nifasm's IP, the bridges'
  ## role is enforced by their absence from the pools rather than here.
  r notin ReservedRegs

# ── the ARMv7-M interrupt table ─────────────────────────────────────────────
# Slot numbers are ARCHITECTURAL, not a board's: the core reads word `n` of the
# table at `VTOR` when exception `n` is taken, and which exception that is, is
# fixed by ARMv7-M. So this table is the same on every Cortex-M part, and the
# names are CMSIS's, which is what a datasheet and a vendor header both use.
#
# Slots 0 and 1 are not here. Word 0 is the initial MSP — a value, not a handler
# — and word 1 is reset, which is the entry proc and not something a `{.interrupt
# .}` pragma may claim: an image has exactly one, arkham already knows which, and
# letting a second thing name it would produce two.
#
# EXTERNAL interrupts start at 16 and ARE board-specific — `TIM2_IRQn` is a
# number STM32 chose, not one arkham can know — so they are spelled by number,
# `IRQ0`..`IRQn`, and the board's own name for one belongs in a constant beside
# the handler rather than in this table.

const
  SystemInterrupts*: array[9, tuple[name: string, slot: int]] = [
    (name: "NMI", slot: 2),
    (name: "HardFault", slot: 3),
    (name: "MemManage", slot: 4),
    (name: "BusFault", slot: 5),
    (name: "UsageFault", slot: 6),
    (name: "SVCall", slot: 11),
    (name: "DebugMon", slot: 12),
    (name: "PendSV", slot: 14),
    (name: "SysTick", slot: 15)]

  FirstIrqSlot* = 16
    ## `IRQ0` is table word 16; slots 7–10 and 13 are Reserved and stay zero.

proc interruptSlot*(name: string): int =
  ## The table slot `name` denotes, or -1 if this target has no such interrupt.
  ## Case-sensitive on purpose: these are the CMSIS spellings, and accepting
  ## `systick` would invite `SYSTICK` and then a house style that differs from
  ## every datasheet the reader has open.
  for v in SystemInterrupts:
    if v.name == name: return v.slot
  if name.len > 3 and name[0 .. 2] == "IRQ":
    var n = 0
    for i in 3 ..< name.len:
      if name[i] notin {'0' .. '9'}: return -1
      n = n * 10 + (ord(name[i]) - ord('0'))
      if n > 495: return -1        # ARMv7-M allows at most 496 external interrupts
    return FirstIrqSlot + n
  return -1
