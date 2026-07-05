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

import machinedesc

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
    intCalleeSaved: @[RBX, R12, R13, R14, R15],
                                     # NOTE: RBP is free (arkham never sets up an rbp frame) and
                                     # was tried as a 6th callee-saved home — it helps, but under
                                     # precise live ranges it exposes a latent miscompile (a
                                     # value living in rbp across a call is clobbered; frame
                                     # push/pop of rbp is correct, so the fault is elsewhere —
                                     # likely a callee not preserving rbp or a nifasm mem/TLS
                                     # encoding path). Left out until that is root-caused.
    floatTempRegs: @[F8, F9, F10, F11, F12, F13, F14],   # F15 RESERVED as the float
                                                         # staging bridge (FloatStagingBridge)
                                                         # — the SIMD twin of R11.
    floatCalleeSaved: @[],
    intCalleeSavedSet: {RBX, R12, R13, R14, R15},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 16)

  ## The GPRs a SysV call clobbers — the caller-saved volatiles arkham manages
  ## (rax + the arg registers + r10/r11). Emitted as the proc's `(clobber …)`.
  x64ClobbersGpr* = [RAX, RDI, RSI, RDX, RCX, R8, R9, R10, R11]
