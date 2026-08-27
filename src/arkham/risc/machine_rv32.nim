#
#           Arkham — RV32IMAFD / ilp32d backend machine model
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 register file and calling convention as the (arch-neutral) register
## allocator consumes it. The abstract `Reg` slots map STRAIGHT onto the hardware
## numbering — `R0`..`R30` are `x0`..`x30` — with two exceptions that are worth
## reading before the table below:
##
##  * **`R2` is not allocatable**, because `x2` IS the stack pointer. asm-NIF
##    spells it `(sp)`, the `SP` slot renders to that, and `R2` therefore names a
##    register that already has an owner. It is in `ReservedRegs` rather than
##    quietly absent from the pools, so a `{.register: "x2".}` pin is refused by
##    name instead of producing a proc that walks over its own frame.
##  * **`x31` is not mapped at all.** No asm-NIF tag names it (`(x0)`..`(x30)`
##    are the whole file), which makes it nifasm's own transient — the RV32
##    counterpart of Thumb's `IP` and AArch64's `x16`, but stronger, because a
##    code generator cannot spell it even by mistake. See `rv32/regs.RvScratch`.
##
## After that the file is roomy, and that is the headline difference from
## Cortex-M. ilp32d gives eight integer argument registers and eight FP ones, and
## the temporaries `t0`–`t5` are DISJOINT from them — so the emitter's scratch
## pool cannot collide with a call's staged arguments, which is the collision
## that forced `machine_m.IntTempRegs` to be empty. RV32 needs no such sacrifice.

import ../core/[machinedesc]
export machinedesc

const
  Zero* = R0    ## `x0`: reads as zero, discards every write. Never allocated —
                ## a value placed here is not stored, it is deleted.
  RA*   = R1    ## `x1`, the link register: `jal` writes it, `ret` reads it.
  GP*   = R3    ## `x3`. Reserved by convention for a global pointer; nothing
                ## here establishes one, but a proc that clobbered it would break
                ## any object linked in that does.
  TP*   = R4    ## `x4`, the thread pointer. Same reasoning as `GP`.

  IntArgRegs*   = [R10, R11, R12, R13, R14, R15, R16, R17]   ## a0–a7
  IntRet*       = R10                                        ## a0

  ## Callee-saved homes for values that must survive a call: `s2`–`s11`.
  ##
  ## `s0`/`s1` (x8/x9) are deliberately absent. `s0` is the ABI's frame pointer
  ## and `s1` is left out with it so the pair stays available to a debugger's
  ## frame walk and to any hand-written `{.assembler.}` body that wants a fixed
  ## place to stand. Ten homes is already more than either Arm target offers, so
  ## the two cost nothing measurable.
  IntCalleeSaved* = [R18, R19, R20, R21, R22, R23, R24, R25, R26, R27]

  ## Caller-saved scratch: `t0`–`t3`. DISJOINT from the argument registers, which
  ## is the property Cortex-M could not have — there the only volatiles WERE the
  ## argument registers, so a temp drawn while staging a call destroyed an
  ## argument already in place. Here the two sets never meet and no analysis has
  ## to prove they don't.
  IntTempRegs*      = [R5, R6, R7, R28]
  IntLocalTempRegs* = [R5, R6, R7, R28]

  ## Emitter staging bridges: `t4`/`t5`, withheld from every pool so a transient
  ## can always be drawn — a folded memory operand the three-operand ALU must load
  ## first, a global's address, a produce-into-memory spill. TWO, which is exactly
  ## `EmitterBridgeDemand`: a `cmp` whose BOTH operands spilled has to load each
  ## into a register, and there is no memory-operand compare here either. Nothing
  ## in this emitter holds three at once any more, so two is the whole reservation
  ## and `ProduceBridge` below is one of these rather than a third.
  IntBridgeRegs* = [R29, R30]

  ProduceBridge* = R30
    ## The value-on-its-way-into-memory bridge — `t5`, the SECOND staging bridge
    ## rather than a third register of its own. `takeProduceBridge` prefers it and
    ## falls back to the other, so its own call sites still get the register they
    ## expect; what it no longer gets is a reservation nobody else may draw from.
    ##
    ## This target reserves TWO where both Arm targets reserve three, and that is a
    ## deliberate spend, not an oversight — `checkMachine` would reject it if
    ## `EmitterBridgeDemand` were still three. It was: an aggregate copy between two
    ## COMPUTED ends held a destination pointer, a source pointer and the word
    ## passing between them. `AggrEnd` tiering removed that shape (the source is a
    ## NAMED slot, addressed as `(mem name off)` for no register at all), the demand
    ## fell to two, and the third became slack.
    ##
    ## Spending it returns `t3` to `IntTempRegs`, which is where it came from: it
    ## was taken out of the pool earlier only to give this target the third bridge
    ## the untiered copy needed. On a 32-bit target with eight argument registers
    ## and ten callee-saved homes, the scarce class is exactly this one — the
    ## call-free volatiles — so the register is worth more there than idle.
    ##
    ## The cost is stated rather than hidden: with two bridges, `ARKHAM_STRESS=1`
    ## describes a machine below what the emitter claims (see `rv32StressLevel`).

  IndirectResultReg* = R9
    ## Where a caller leaves `&result` for a callee returning an aggregate too
    ## wide for registers — the RV32 stand-in for AArch64's `x8`.
    ##
    ## The real ilp32 convention passes that pointer as a hidden FIRST argument,
    ## shifting every real parameter down one. Taking `s1` off the file instead
    ## keeps the AArch64 shape the shared emitter already implements, and is sound
    ## for the same reason it is sound there: arkham owns both sides of every call
    ## in a self-contained image. `s1` works precisely because it is in NO pool —
    ## no proc ever writes it — so a callee-saved register survives arbitrary
    ## nesting without anyone saving it. Cortex-M makes this trade with `r9` and
    ## spells out the alternative's cost.

  ## ── the F/D file (ilp32d) ────────────────────────────────────────────────
  ## One physical file serves both precisions; the instruction's `fmt` field picks
  ## which. asm-NIF spells the two views `(dN)` and `(sN)`, which is AArch64's
  ## spelling and therefore what `AsmBuf.freg` already emits from a width — so the
  ## FP half of this target needed no new vocabulary at all.
  FloatArgRegs*     = [F10, F11, F12, F13, F14, F15, F16, F17]   ## fa0–fa7
  FloatRet*         = F10
  FloatTempRegs*    = [F0, F1, F2, F3, F4, F5, F6, F7]           ## ft0–ft7
  FloatCalleeSaved* = [F8, F9, F18, F19, F20, F21, F22, F23]     ## fs0–fs9
  FloatBridgeReg*   = F31
    ## `ft11`, the emitter's float staging bridge — withheld from every pool for
    ## the same reason `IntBridgeRegs` are.

  ## Never allocate: `x0` (which discards writes), the link register, the stack
  ## pointer under either spelling, the ABI's `gp`/`tp`, the frame-pointer pair,
  ## and the abstract slot that maps to no RV32 register.
  ReservedRegs* = {R0, R1, R2, R3, R4, R8, R9, SP, NoReg}

  ## What a call destroys, emitted as the proc's `(clobber …)` so the ABI is
  ## DECLARED at the signature rather than re-derived at every call site: `ra`,
  ## the temporaries, and the argument/return registers.
  ConvClobbersGpr* = [R1, R5, R6, R7, R10, R11, R12, R13, R14, R15, R16, R17,
                      R28, R29, R30]

  BridgeRegs* = [IntBridgeRegs[0], IntBridgeRegs[1]]

  ## The RV32 machine description handed to the register allocator.
  rv32Machine* = MachineDesc(
    arch: Rv32,
    intRetReg: IntRet,
    floatRetReg: FloatRet,
    divRemReg: NoReg,           # `div`/`rem` are three-operand and independent;
                                # nothing is implicitly clobbered
    shiftCountReg: NoReg,       # any register may carry a shift count
    intArgRegs: @IntArgRegs,
    floatArgRegs: @FloatArgRegs,
    intTempRegs: @IntTempRegs,
    stagingBridgeReg: NoReg,    # like both Arm targets: the bridges are withheld
                                # from the pools instead (see IntBridgeRegs)
    intLocalTempRegs: @IntLocalTempRegs,
    intCalleeSaved: @IntCalleeSaved,
    floatTempRegs: @FloatTempRegs,
    floatCalleeSaved: @FloatCalleeSaved,
    intCalleeSavedSet: {R18..R27},
    floatCalleeSavedSet: {F8, F9, F18..F23},
    aggrByRefThreshold: 8,      # TWO words, matching `slots.classifyArg`'s `2*w`.
                                # These two decide the same thing and MUST agree:
                                # `planCall` reads the threshold while the
                                # classifier reads `2*w`, so a disagreement makes
                                # the caller pass by value what the callee reads
                                # as a pointer.
    linkReg: RA,
    framePtrReg: NoReg,         # everything is addressed off SP. `s0` is the
                                # ABI's frame pointer, but nothing generated here
                                # establishes one, and a `BlockFrame` target
                                # re-derives the incoming-argument base from SP.
    indirectResultReg: IndirectResultReg,
    produceBridge: ProduceBridge,
    bridgeRegs: @BridgeRegs,
    atomicScratch: [NoReg, NoReg, NoReg],
      # No LL/SC triple. RV32 reserves two bridges (see `ProduceBridge`), and an
      # `lr.w`/`sc.w` retry loop needs THREE registers held across instructions the
      # allocator knows nothing about — so the day RV32 atomics are lowered, this
      # target has to reserve them explicitly rather than borrow the bridges.
      # `emitAtomicInstr2` refuses by name meanwhile, and `checkMachine` refuses a
      # partial triple.
    floatBridgeReg: FloatBridgeReg,
    memIntrinScratch: [R13, R14, R15],
    caps: {Float64, Freestanding, AcqRelExclusives, TwoAddrForms},
      # `Float64`: RV32D is in the baseline, both precisions in one file.
      # `AcqRelExclusives`: `lr.w`/`sc.w` CARRY their ordering in the `aq`/`rl`
      #   bits, which is exactly what the capability names — unlike ARMv7-M's
      #   `ldrex`/`strex`, which need `dmb` on either side. The capability is a
      #   statement about the ISA and stays true; whether this BACKEND can emit an
      #   atomic is a separate question, answered by `atomicScratch` above, which
      #   is empty. `emitAtomicInstr2` checks the reservation, not the capability,
      #   because a triple it does not hold is what actually stops it.
      # `TwoAddrForms`: the nifasm selector accepts the destructive `(op D S)`
      #   spelling and encodes it as `op rd, rd, rs`.
      #
      # NOT `CondSelect`: a conditional move is Zicond, not baseline, so a select
      #   lowers to the branch diamond Cortex-M already ships on.
      # NOT `RegOffsetMem`: there is ONE addressing mode, `base + imm12`. An index
      #   becomes an explicit add.
      # NOT `PcRelGlobalFold`: the fold is an `auipc` carrying `%pcrel_hi` plus a
      #   load carrying `%pcrel_lo` OF A LABEL POINTING BACK AT IT — a relocation
      #   pairing nothing here does yet.
      # NOT `SubwordExtend`: RV32I has no `sext.b`/`zext.h` (that is Zbb), so an
      #   extend is the shift pair, as on AArch64.
      # NOT `BitScanOps`: `clz`/`rbit`/`rev` are Zbb too.
      # NOT `FloatConvert`: the precision convert is spelled `fcvt.s.d`, which is
      #   not the `(fcvt …)` row AArch64 uses. A tag for it is outstanding.
      # NOT `SimdVector`: the V extension is not baseline and would not share
      #   AArch64's AdvSIMD spellings if it were.
      # NOT `TailCall`: deferred rather than blocked, for the first landing.
      # NOT `AllFlagBranches`: there are no flags AT ALL. The four conditions that
      #   fuse (`zf`/`nz`/`cf`/`nc`) are fewer than this capability's "any of the
      #   eight" and more than its absence's "the zero flag only", so neither arm
      #   of `asmproc.asmFlagOk` fits and the `{.assembler.}` flag path needs a
      #   third one before it is enabled here.
    frameStyle: BlockFrame,     # inherited verbatim from Cortex-M: SP lowered
                                # once, one store per saved register, no paired
                                # store to build a frame pointer with.
    immStyle: RvImm12,
    gprRangeText: "`x5`..`x7`, `x10`..`x30`",
    targetName: "RV32",
    abiFloatCalleeSaved: @FloatCalleeSaved,
    abiCalleeSaved: @IntCalleeSaved,
    intCallerSavedSet: {R1, R5, R6, R7, R10..R17, R28, R29, R30},
    convClobbersGpr: @ConvClobbersGpr)

proc regNameRv*(r: Reg): string =
  ## The asm-NIF spelling of a GPR slot. RV32 reuses AArch64's tags outright —
  ## `(x0)`..`(x30)` and `(sp)` — so this is AArch64's `regName` verbatim, which
  ## is the whole reason the register half of this target cost nothing.
  case r
  of SP: "sp"
  of NoReg: "<noreg>"
  else:
    if ord(r) <= ord(R30): "x" & $ord(r)
    else: "<unmapped:" & $ord(r) & ">"

proc isAllocatableRv*(r: Reg): bool {.inline.} =
  ## Whether arkham may place a value in `r`.
  r notin ReservedRegs

# ── interrupts ───────────────────────────────────────────────────────────────
# A RISC-V core does not read a table of ADDRESSES the way an M-profile one does.
# `mtvec` holds a base plus a two-bit MODE, and in vectored mode (mode 1) a trap
# with cause `c` jumps to `base + 4*c` — one WORD, which has to be an instruction
# and not a pointer. So this target's "vector table" is a run of `j handler`
# instructions, built by the image writer, and the slot numbers below are trap
# CAUSES rather than word indices into a table of addresses.
#
# Only the three MACHINE-mode interrupts are named. Supervisor and user modes do
# not exist in an image that never leaves M-mode, and the EXCEPTION causes (0..15
# of the non-interrupt half) are a different column of the same table reached
# through mode 0 — a handler for a misaligned load is a different kind of thing
# from a handler for a timer, and naming them here would make the two look alike.

const
  MachineInterrupts*: array[3, tuple[name: string, cause: int]] = [
    (name: "MachineSoftware", cause: 3),
    (name: "MachineTimer", cause: 7),
    (name: "MachineExternal", cause: 11)]
    ## The three standard M-mode interrupt causes. The names are the ones the
    ## privileged spec uses, not an abbreviation of them: `MTIP` is the bit, and
    ## a reader with the spec open is looking at the words.

  InterruptCauseCount* = 16
    ## How many words the trampoline table has. Sixteen because that is where the
    ## standard causes stop; a platform-specific interrupt above 15 would extend
    ## it, and nothing here has one.

proc interruptCauseRv*(name: string): int =
  ## The trap cause `name` denotes, or -1 if this target has no such interrupt.
  ## Case-sensitive for the same reason Cortex-M's is: these are the spec's
  ## spellings, and accepting `machinetimer` invites a house style that differs
  ## from the document the reader has open.
  for v in MachineInterrupts:
    if v.name == name: return v.cause
  return -1
