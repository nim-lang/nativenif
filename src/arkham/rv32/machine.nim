#
#           Arkham — RV32IM / ilp32 backend machine model
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 register file and calling convention as the (arch-neutral) register
## allocator consumes it.
##
## Slots `R0`..`R30` are `x0`..`x30`, one for one. `x31` is simply not
## representable — the abstract enum stops at `R30` — and at thirty registers
## that costs nothing, which is a sentence no other target in this tree gets to
## write.
##
## This is the roomiest machine here by a wide margin: eight argument registers,
## twelve callee-saved, five temporaries, and one addressing mode that reaches
## ±2 KB off any register. Almost every constraint the other backends are built
## around is simply absent — there is no fixed division register, no fixed shift
## count, no accumulator, no register pair, no `ldi`-capability class.
##
## What IS absent that the others have: **condition flags**. There is no status
## register, so a comparison is `slt` into a register or a two-register branch,
## and `caps` therefore carries no `AllFlagBranches` and no `CondSelect` — not
## because those are unimplemented but because the shapes they name do not exist.

import ../core/[machinedesc]
export machinedesc

const
  Zero* = R0    ## `x0`: reads as zero, discards writes. Named constantly and
                ## allocated never — it is why this target needs no `mov`, no
                ## `neg`, no `not` and no `nop` in its vocabulary.
  Ra* = R1      ## the link register `jal` writes
  Gp* = R3      ## the global pointer, reserved by the ABI even unused
  Tp* = R4      ## the thread pointer, likewise

  IntArgRegs* = [R10, R11, R12, R13, R14, R15, R16, R17]
    ## a0–a7. Eight, so the stack-argument path is reached far less often here
    ## than anywhere else — which is why refusing it in R4 costs so little.
  IntRet* = R10

  IntCalleeSaved* = [R8, R9, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27]
    ## s0–s11. Twelve, and each costs one `sw` and one `lw` rather than a push
    ## pair, so the planner has room the other backends do not.

  IntTempRegs* = [R5, R6, R7, R28]
    ## t0–t2 and t3, caller-saved. Disjoint from the argument registers, which
    ## the two 32-bit targets before this one could not manage — so scratch here
    ## never collides with staging a call.
  IntLocalTempRegs* = IntTempRegs
    ## A call-free local may be homed in the temp pool, as on AArch64 and for the
    ## same reason: there is scratch to spare, and taking a callee-saved register
    ## for a value that needs none starves the ones that do.

  StagingBridge* = R30
    ## t5, withheld from every pool so the emitter can always draw a transient.
  StagingBridge2* = R29
    ## t4, the second one — and it exists because a COMPARISON needs two
    ## registers live at the same moment.
    ##
    ## That was not obvious and the first draft of this file got it wrong. A
    ## three-operand ALU with a ±2 KB load/store off any register does mean a
    ## spilled operand can be loaded straight into the instruction that wants it,
    ## so one bridge covers arithmetic. But a branch here compares two REGISTERS —
    ## there is no `blti` and no flag to leave an answer in — so `x < 10` with `x`
    ## already in the bridge has nowhere to put the 10. Both operands are live
    ## across one instruction, and one bridge silently compared the constant with
    ## itself.
    ##
    ## Two is still the minimum: the second is live for exactly one instruction
    ## and nothing nests inside that window, because an operand that has to be
    ## COMPUTED is parked in a slot first.

  BridgeRegs* = [StagingBridge2, StagingBridge]

  ReservedRegs* = {R0, R1, R2, R3, R4, R29, R30, SP, NoReg}
    ## Never allocated: `zero`, `ra`, `sp`, `gp`, `tp` and the two bridges.

  ConvClobbersGpr* = [R1, R5, R6, R7, R10, R11, R12, R13, R14, R15, R16, R17,
                      R28, R29, R30]
    ## What a call destroys under ilp32: `ra`, `t0`–`t2`, `a0`–`a7` and `t3`–`t5`.
    ## Emitted as the proc's `(clobber …)` so the ABI is declared at the
    ## signature rather than re-derived at every call site.

  IntCallerSaved* = {R1, R5, R6, R7, R10 .. R17, R28, R29, R30}

  rv32Machine* = MachineDesc(
    arch: Rv32,
    intRetReg: IntRet,
    divRemReg: NoReg,           # `div` and `rem` are ordinary three-operand
                                # instructions; nothing is clobbered implicitly
    shiftCountReg: NoReg,       # and a variable shift takes any register
    intArgRegs: @IntArgRegs,
    floatArgRegs: @[],
    intTempRegs: @IntTempRegs,
    stagingBridgeReg: NoReg,    # like the Arm targets: the bridge is withheld
                                # from the pools rather than rescued out of one
    intLocalTempRegs: @IntLocalTempRegs,
    intCalleeSaved: @IntCalleeSaved,
    floatTempRegs: @[],
    floatCalleeSaved: @[],
    intCalleeSavedSet: {R8, R9, R18 .. R27},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 8,      # TWO words at w = 4, matching
                                # `slots.classifyArg`'s `2*w` — the two decide
                                # the same thing and must agree
    linkReg: Ra,
    framePtrReg: NoReg,         # SP addresses memory directly with a 12-bit
                                # signed offset, so no frame pointer is needed
                                # and none is established
    indirectResultReg: NoReg,   # ilp32 passes a hidden first pointer, as x86-64
                                # does — there is no dedicated register for it
    produceBridge: StagingBridge,
    bridgeRegs: @BridgeRegs,
    floatBridgeReg: NoFReg,
    caps: {},
                                # Empty, and every absence is a fact about the
                                # machine rather than a gap:
                                #   NOT CondSelect — no conditional move exists.
                                #   NOT TwoAddrForms — the ALU is three-operand,
                                #     so a destructive spelling would be a lie.
                                #   NOT AllFlagBranches — there are no FLAGS. A
                                #     condition is a branch or a register here,
                                #     never a thing between two instructions.
                                #   NOT SubwordExtend — `sext.b` is in the `B`
                                #     extension, not the base; RV32I does it with
                                #     `slli`+`srai`.
                                #   NOT RegOffsetMem, NOT PcRelGlobalFold — one
                                #     addressing mode, base plus offset.
                                #   NOT AcqRelExclusives — the `A` extension is
                                #     not assumed.
                                #   NOT Float64 — `ilp32` is soft float.
                                #   NOT Freestanding — this target is HOSTED,
                                #     which is what separates it from the other
                                #     two 32-bit ones.
                                #   NOT TailCall — a `jal` to another proc needs
                                #     the frame torn down first; R5.
    frameStyle: BlockFrame,     # SP lowered once, one store per saved register.
                                # Named for the shape rather than for a target,
                                # and this is the machine the name was written
                                # for: RISC-V has no paired store either.
    immStyle: Rv32Imm12,
    gprRangeText: "`x0`..`x30`",
    targetName: "RV32",
    abiFloatCalleeSaved: @[],
    abiCalleeSaved: @IntCalleeSaved,
    intCallerSavedSet: IntCallerSaved,
    convClobbersGpr: @ConvClobbersGpr)

proc regName*(r: Reg): string =
  ## The asm-NIF spelling, which is `xN` — not the ABI name. A diagnostic wants
  ## `a0`; the emitted tag has to be what `nifasm/rv32/regs` parses.
  case r
  of NoReg: "<noreg>"
  of SP: "sp"
  else:
    if ord(r) <= ord(R30): "x" & $ord(r) else: "<unmapped:" & $ord(r) & ">"

proc abiName*(r: Reg): string =
  ## What a DIAGNOSTIC should say: `a0` and `x10` are the same register and only
  ## one of them tells the reader what it is for.
  case r
  of R0: "zero"
  of R1: "ra"
  of R2, SP: "sp"
  of R3: "gp"
  of R4: "tp"
  of R5: "t0"
  of R6: "t1"
  of R7: "t2"
  of R8: "s0"
  of R9: "s1"
  of R10: "a0"
  of R11: "a1"
  of R12: "a2"
  of R13: "a3"
  of R14: "a4"
  of R15: "a5"
  of R16: "a6"
  of R17: "a7"
  of R18: "s2"
  of R19: "s3"
  of R20: "s4"
  of R21: "s5"
  of R22: "s6"
  of R23: "s7"
  of R24: "s8"
  of R25: "s9"
  of R26: "s10"
  of R27: "s11"
  of R28: "t3"
  of R29: "t4"
  of R30: "t5"
  else: regName(r)

proc `$`*(loc: Location): string =
  case loc.kind
  of Undef: "undef"
  of NoLoc: "noloc"
  of NeedsReg: "needsreg"
  of RegOrImm: "regorimm"
  of InReg: abiName(loc.r)
  of InRegPair:
    "{" & abiName(loc.r0) & (if loc.r1 != NoReg: "," & abiName(loc.r1) else: "") & "}"
  of InFReg: "<nofloat>"
  of NamedStack: "&" & loc.name
  of StackPtr: "*" & loc.ptrName
  of Mem: "[mem]"
  of Field:
    (case loc.base.kind
     of FbReg: "[" & abiName(loc.base.reg) & "]"
     of FbSlot: "&" & loc.base.sym
     of FbGlob: "@" & loc.base.sym
     of FbTvar: "%tvar:" & loc.base.sym
     of FbLval: "[lval]") & "." & loc.field
  of Glob: "@" & loc.name
  of Tvar: "%tvar:" & loc.name
  of Imm: "#" & $loc.ival
