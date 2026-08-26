#
#           Arkham — x86-64 / System V backend machine model
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## x86-64 / System V (Linux) backend register model: the shared register slots
## (`machinedesc.Reg`) reinterpreted as the x86-64 GPRs, the `regName` shim that
## renders them to AT&T-less x86 spellings, and the `x64Machine` description fed
## to the (arch-neutral) register allocator. x86-64 has 16 GPRs, so it uses only
## the low 16 `Reg` slots; the slot↔hardware mapping follows the ModRM encoding
## order (R0=rax, R1=rcx, …, R7=rdi, R8..R15=r8..r15).

import ../core/machinedesc

const
  RAX* = R0
  RCX* = R1
  RDX* = R2
  RBX* = R3
  RSP* = R4
  RBP* = R5
  RSI* = R6
  RDI* = R7
  # R8..R15 are the slots of the same name.

proc x64RegName*(r: Reg): string =
  case r
  of R0: "rax"
  of R1: "rcx"
  of R2: "rdx"
  of R3: "rbx"
  of R4: "rsp"
  of R5: "rbp"
  of R6: "rsi"
  of R7: "rdi"
  of R8: "r8"
  of R9: "r9"
  of R10: "r10"
  of R11: "r11"
  of R12: "r12"
  of R13: "r13"
  of R14: "r14"
  of R15: "r15"
  of SP: "rsp"
  else: "<noreg>"

const
  ## The GPRs a SysV call clobbers — the caller-saved volatiles arkham manages
  ## (rax + the arg registers + r10/r11). Emitted as the proc's `(clobber …)`.
  x64ClobbersGpr* = [RAX, RDI, RSI, RDX, RCX, R8, R9, R10, R11]

  ## System V AMD64 calling convention, as the arch-neutral allocator needs it.
  ##  * integer args:   rdi, rsi, rdx, rcx, r8, r9
  ##  * integer return: rax
  ##  * callee-saved:   rbx, r12–r15 (rbp/rsp reserved for the frame)
  ##  * volatile scratch arkham manages: r10, r11 (the non-arg caller-saved GPRs;
  ##    rax + the arg registers are reserved for return/argument shuffling, as on
  ##    AArch64 where x0–x7 are kept out of the temp pool)
  ##  * float: xmm0–7 args/return (unused by the v0 scalar path)
  x64Machine* = MachineDesc(
    arch: X86,
    intRetReg: RAX,
    divRemReg: RDX,                  # idiv clobbers rdx (remainder / sign-extend high half)
    shiftCountReg: RCX,              # x86 variable shift count must be in cl (rcx)
    intArgRegs: @[RDI, RSI, RDX, RCX, R8, R9],
    floatArgRegs: @[F0, F1, F2, F3, F4, F5, F6, F7],
    intTempRegs: @[R10],             # R11 is RESERVED as the staging bridge (see
                                     # StagingCandidates): an always-free caller-saved
                                     # GPR the emitter can grab to make mem←mem / spilled
                                     # value-position produce-into total, so the allocator's
                                     # `etmp` fallback is always emittable.
    stagingBridgeReg: R11,
    intLocalTempRegs: @[RDI, RSI, R8, R9],  # volatile homes a CALL-FREE local may use once the 5
                                     # callee-saved regs are exhausted (the analyser's `AllRegs`
                                     # interval test guarantees no call in the range, so these
                                     # caller-saved regs are not clobbered). Restricted to the arg
                                     # registers with NO fixed instruction role: rdx (idiv), rcx
                                     # (shift count), rax (return/mul/div), r10/r11 (emitter staging
                                     # + bridge) all have non-call uses and stay OUT. A persistent
                                     # leaf-param home in one of these is excluded in `allocParams`;
                                     # `pickStagingScratch` already routes staging around a live
                                     # local/param home (`regHoldsLiveLocal`).
    intCalleeSaved: @[RBX, R12, R13, R14, R15, RBP],
                                     # RBP last: arkham never sets up an rbp frame, so it is
                                     # a genuine 6th callee-saved home — but only reached
                                     # under full pressure, so the 5 ABI-conventional homes
                                     # keep their familiar assignments.
    floatTempRegs: @[F8, F9, F10, F11, F12, F13, F14],   # F15 RESERVED as the float
                                                         # staging bridge (FloatStagingBridge)
                                                         # — the SIMD twin of R11.
    floatCalleeSaved: @[],
    intCalleeSavedSet: {RBX, R12, R13, R14, R15, RBP},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 16,
    # ── roles ── x86-64 has none of these: the `call` pushes the return address
    # (no link register), arkham establishes no rbp frame, an indirect result is
    # a hidden FIRST argument rather than a register off the file, and the
    # emitter's always-free scratch is the single `stagingBridgeReg` above rather
    # than a withheld set. Stated rather than defaulted: `Reg`'s zero value is
    # `R0` — rax — so an omitted role would silently name a register in use.
    linkReg: NoReg,
    framePtrReg: NoReg,
    indirectResultReg: NoReg,
    produceBridge: NoReg,
    bridgeRegs: @[],
    floatBridgeReg: NoFReg,
    caps: {CondSelect, TailCall, Float64, SubwordExtend, RegOffsetMem,
           PcRelGlobalFold, TwoAddrForms, AllFlagBranches},
                                     # `codegen_x64` does not consult this set
                                     # yet — it predates the seam — so these say
                                     # what is true of the x86-64 vocabulary
                                     # rather than what any branch reads. No
                                     # AcqRelExclusives: x86 orders through the
                                     # `lock` prefix, not an LL/SC pair.
    frameStyle: PushFrame,
    immStyle: X86Imm32,
    gprRangeText: "`rax`..`r15`",
    targetName: "x86-64",
    abiFloatCalleeSaved: @[],
    abiCalleeSaved: @[RBX, R12, R13, R14, R15, RBP],
    intCallerSavedSet: {RAX, RDI, RSI, RDX, RCX, R8, R9, R10, R11},
    convClobbersGpr: @x64ClobbersGpr)

  WinShadowSpace* = 32
    ## Win64 requires the caller to reserve 32 bytes below the return address that
    ## the callee may spill its four register arguments into — present whether or
    ## not the callee has four parameters, and NOT part of the stack-argument area.
    ## So the 5th argument sits at `[rsp+32]`, not `[rsp+0]`. nifasm adds this base
    ## to an `(arg …)` offset of an extern call and reserves it in the frame; the
    ## constant is repeated there (`WinShadowSpace` in `assembler.nim`) because the
    ## two tools share no module.

  ## The Win64 calling convention, as the ABI planner (`abi.planCall`) consumes it —
  ## used ONLY to classify the arguments of a call to an `importc`'d Windows API, the
  ## sole foreign boundary of an otherwise self-contained image. Everything arkham
  ## generates on BOTH sides of a call keeps `x64Machine`'s SysV assignment, which is
  ## a valid private convention here: the Win64 callee-saved set (rbx, rbp, rdi, rsi,
  ## r12–r15) CONTAINS SysV's (rbx, r12–r15), so a value arkham parks across a call to
  ## kernel32 survives, and rdi/rsi — volatile under SysV, preserved under Win64 — are
  ## only ever homes for call-free locals.
  ##
  ## Only the argument registers differ from `x64Machine`; the temp/callee-saved pools
  ## describe the CALLER's own register file and are unchanged. Aggregate and float
  ## arguments are rejected by `emitWinExtproc` rather than modelled: Win64 passes an
  ## aggregate in a register only at size 1/2/4/8 (by reference otherwise — not the
  ## `> threshold` rule `planCall` implements) and indexes an SSE argument register
  ## POSITIONALLY, skipping the GPR of the same position. No Windows API arkham binds
  ## takes either.
  win64Machine* = MachineDesc(
    arch: X86,
    intRetReg: RAX,
    divRemReg: RDX,
    shiftCountReg: RCX,
    intArgRegs: @[RCX, RDX, R8, R9],
    floatArgRegs: @[F0, F1, F2, F3],
    intTempRegs: @[R10],
    stagingBridgeReg: R11,
    intLocalTempRegs: @[RDI, RSI, R8, R9],
    intCalleeSaved: @[RBX, R12, R13, R14, R15, RBP],
    floatTempRegs: @[F8, F9, F10, F11, F12, F13, F14],
    floatCalleeSaved: @[],
    intCalleeSavedSet: {RBX, R12, R13, R14, R15, RBP},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 8,
    # ── roles ── x86-64 has none of these: the `call` pushes the return address
    # (no link register), arkham establishes no rbp frame, an indirect result is
    # a hidden FIRST argument rather than a register off the file, and the
    # emitter's always-free scratch is the single `stagingBridgeReg` above rather
    # than a withheld set. Stated rather than defaulted: `Reg`'s zero value is
    # `R0` — rax — so an omitted role would silently name a register in use.
    linkReg: NoReg,
    framePtrReg: NoReg,
    indirectResultReg: NoReg,
    produceBridge: NoReg,
    bridgeRegs: @[],
    floatBridgeReg: NoFReg,
    caps: {CondSelect, TailCall, Float64, SubwordExtend, RegOffsetMem,
           PcRelGlobalFold, TwoAddrForms, AllFlagBranches},
                                     # `codegen_x64` does not consult this set
                                     # yet — it predates the seam — so these say
                                     # what is true of the x86-64 vocabulary
                                     # rather than what any branch reads. No
                                     # AcqRelExclusives: x86 orders through the
                                     # `lock` prefix, not an LL/SC pair.
    frameStyle: PushFrame,
    immStyle: X86Imm32,
    gprRangeText: "`rax`..`r15`",
    targetName: "x86-64",
    abiFloatCalleeSaved: @[],
    abiCalleeSaved: @[RBX, R12, R13, R14, R15, RBP],
    intCallerSavedSet: {RAX, RDI, RSI, RDX, RCX, R8, R9, R10, R11},
    convClobbersGpr: @x64ClobbersGpr)
