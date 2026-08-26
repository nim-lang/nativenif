#
#           Arkham — AVR (avr5) backend machine model
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The AVR register file and calling convention as the (arch-neutral) register
## allocator consumes it.
##
## **A `Reg` slot here is a register PAIR, not a register.** AVR has 32 8-bit
## registers; the machine's word — a pointer, an `int`, the thing a local lives
## in — is 16 bits. So slots `R0`..`R15` are the sixteen even-aligned pairs
## `r1:r0` .. `r31:r30`, and `R16`..`R30` stay unallocated, the same subsetting
## Cortex-M does with `R13`..`R30`.
##
## That is not a fiction imposed on the machine. `movw` copies a pair in one
## instruction, `adiw`/`sbiw` add and subtract a small constant on one, and the
## three pointer registers are pairs by construction. What the ISA does not
## provide is a 16-bit ALU: an add is `add`+`adc` on the halves, and the emitter
## writes both. See doc/internals/avr.md.
##
## Three operand restrictions shape every choice below, and none of them is
## uniform across the file:
##
##  * **`ldi` reaches only r16..r31**, i.e. slots `R8`..`R15`. A constant
##    destined for a low pair goes through a high one and a `movw`.
##  * **`adiw`/`sbiw` reach only the four upper pairs**, and only 0..63.
##  * **Memory is addressed only through X, Y and Z**, and only Y and Z have a
##    displaced form. Three address registers for the whole machine, one of them
##    the frame pointer — which is why the other two are bridges and not
##    candidates for anything else.

import ../core/[machinedesc]
export machinedesc

const
  # ── the pairs, by their AVR names ────────────────────────────────────────
  P0* = R0     ## r1:r0
  P2* = R1     ## r3:r2
  P4* = R2
  P6* = R3
  P8* = R4
  P10* = R5
  P12* = R6
  P14* = R7
  P16* = R8    ## r17:r16 — the lowest `ldi`-capable pair
  P18* = R9
  P20* = R10
  P22* = R11
  P24* = R12   ## r25:r24 — return value and first argument
  X* = R13     ## r27:r26
  Y* = R14     ## r29:r28 — the frame pointer
  Z* = R15     ## r31:r30

  MulResult* = P0
    ## `mul` writes r1:r0 and there is no form that writes anywhere else. That
    ## alone would make the pair unallocatable; r1 additionally has to hold ZERO,
    ## because every `sbc`-style borrow sequence reads it, so each `mul` is
    ## followed by a `clr r1`. AVR-GCC's convention, and there is no cheaper one.

  # ── calling convention ───────────────────────────────────────────────────
  IntArgRegs* = [P24, P22, P20, P18]
    ## AVR-GCC's, which allocates DOWNWARD from r25: a first word argument in
    ## r25:r24, a second in r23:r22, and so on. Four pairs, then the stack —
    ## which this backend refuses by name for now (M5).
  IntRet* = P24

  IntCalleeSaved* = [P2, P4, P6, P8, P10, P12, P14, P16]
    ## r2..r17: eight pairs, which is roomy compared to the other targets and is
    ## the whole reason this file can afford three dedicated registers.
    ##
    ## They are not free, though. Saving one costs two `push`es and two `pop`s —
    ## four instructions per pair — so the planner should still prefer a volatile
    ## for a call-free local, which is exactly what it does for x86-64 and why
    ## `Avr` groups with `X86` at that branch.

  IntTempRegs*: array[0, Reg] = []
  IntLocalTempRegs*: array[0, Reg] = []
    ## Empty, for Cortex-M's reason rather than x86-64's: every volatile pair
    ## this machine has is either an ARGUMENT register (P18..P24) or a bridge (X,
    ## Z). A temp drawn from an argument register collides with staging a call,
    ## and a temp drawn from a bridge defeats the point of having one. A local
    ## that must live in a register therefore takes a callee-saved pair or a
    ## stack slot — which is what AVR-GCC does too.

  StagingBridge* = X
    ## The pair the emitter can always take to hold an ADDRESS. Every non-frame
    ## memory access needs one, because there is no base-plus-offset operand and
    ## no SP-relative form: the address has to be in X, Y or Z, and Y is spoken
    ## for.
  ProduceBridge* = Z
    ## The second one, and the one used to stage a value on its way INTO memory.
    ## Always the last entry of `bridgeRegs`, as on the other targets.
    ##
    ## Z carries two further obligations that no other register can take: it is
    ## the only indirect-call target (`icall`) and the only flash pointer
    ## (`lpm`). Both are fine precisely BECAUSE it is a bridge — no value ever
    ## lives here, so nothing has to prove that using it is safe.

  BridgeRegs* = [StagingBridge, ProduceBridge]
    ## In the order a staging draw walks them, so a site with its own claim on
    ## the produce bridge still finds it free.
    ##
    ## Two is also the minimum, and for a reason particular to this machine: a
    ## 16-bit compare whose operands are both in memory has to load each one, and
    ## loading needs a POINTER pair as well as somewhere to put the byte. The two
    ## bridges supply four scratch bytes between them, which is enough for an
    ## address in one and a value in the halves of the other.

  ReservedRegs* = {R0, R13, R14, R15, R16..R30, SP, NoReg}
    ## Never allocated: r1:r0 (`mul`'s destination and the zero register), the
    ## two bridges, the frame pointer, and the abstract slots that map to no AVR
    ## pair.

  ConvClobbersGpr* = [P0, P18, P20, P22, P24, X, Z]
    ## What a call destroys, emitted as the proc's `(clobber …)` so the ABI is
    ## declared at the signature rather than re-derived at every call site.
    ## AVR-GCC's caller-saved set is r18–r27 and r30/r31, plus r1:r0; r2–r17 and
    ## Y are callee-saved, which is where a value that outlives a call belongs.

  IntCallerSaved* = {P0, P18, P20, P22, P24, X, Z}

  avrMachine* = MachineDesc(
    arch: Avr,
    intRetReg: IntRet,
    divRemReg: NoReg,           # there is no divide instruction of any kind
    shiftCountReg: NoReg,       # and no variable shift: a shift by n is n
                                # instructions, and by a register it is a loop
    intArgRegs: @IntArgRegs,
    floatArgRegs: @[],
    intTempRegs: @IntTempRegs,
    stagingBridgeReg: NoReg,    # like the Arm targets: the bridges are withheld
                                # from the pools instead (see `BridgeRegs`)
    intLocalTempRegs: @IntLocalTempRegs,
    intCalleeSaved: @IntCalleeSaved,
    floatTempRegs: @[],
    floatCalleeSaved: @[],
    intCalleeSavedSet: {P2, P4, P6, P8, P10, P12, P14, P16},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 4,      # TWO words, matching `slots.classifyArg`'s `2*w`
                                # at w = 2. The two decide the same thing and
                                # MUST agree: `planCall` reads the threshold
                                # while the classifier reads `2*w`, so a
                                # disagreement makes the caller pass by value
                                # what the callee reads as a pointer.
    linkReg: NoReg,             # `call` PUSHES the return address; there is no
                                # link register to hold it
    framePtrReg: Y,             # and not as a convenience: SP lives in the I/O
                                # space and cannot address memory, so Y is the
                                # only way to reach a stack slot
    indirectResultReg: NoReg,   # a hidden first argument, as on x86-64 — there
                                # is no register to spare for a dedicated one
    produceBridge: ProduceBridge,
    bridgeRegs: @BridgeRegs,
    floatBridgeReg: NoFReg,     # no FPU
    caps: {TwoAddrForms, Freestanding, AllFlagBranches},
                                # The ALU is destructive and two-operand, which
                                # is what `TwoAddrForms` says and the whole
                                # reason this backend is modelled on x86-64's.
                                #
                                # NOT CondSelect: no `cmov`/`csel`, so a select
                                # diamond lowers to a branch.
                                # NOT TailCall: `rjmp` to another proc would need
                                # the frame torn down first, which is five
                                # instructions here rather than one.
                                # NOT Float64, and no float at all.
                                # NOT SubwordExtend: sign-extending a byte is
                                # `clr`+`sbrc`+`com`, three instructions.
                                # NOT RegOffsetMem: there is no base+index form.
                                # NOT PcRelGlobalFold: a global's address is
                                # materialized absolutely, into a pointer pair.
                                # NOT AcqRelExclusives: no exclusives at all —
                                # this is a single-core 8-bit part, and an atomic
                                # section is `cli`/`sei`.
    frameStyle: AvrFrame,
    immStyle: AvrImm8,
    gprRangeText: "`r0`..`r31`",
    targetName: "AVR",
    abiFloatCalleeSaved: @[],
    abiCalleeSaved: @IntCalleeSaved,
    intCallerSavedSet: IntCallerSaved,
    convClobbersGpr: @ConvClobbersGpr)

proc regName*(r: Reg): string =
  ## The asm-NIF spelling of a pair slot: `rpN`, named by its LOW register, which
  ## is what `nifasm/avr/regs` parses.
  case r
  of NoReg: "<noreg>"
  of SP: "sp"
  else:
    if ord(r) <= ord(Z): "rp" & $(2 * ord(r)) else: "<unmapped:" & $ord(r) & ">"

proc lowName*(r: Reg): string =
  ## The low HALF of a pair, as an 8-bit register spelling. Every ALU instruction
  ## names one of these.
  "r" & $(2 * ord(r))

proc highName*(r: Reg): string = "r" & $(2 * ord(r) + 1)

proc `$`*(loc: Location): string =
  case loc.kind
  of Undef: "undef"
  of NoLoc: "noloc"
  of NeedsReg: "needsreg"
  of RegOrImm: "regorimm"
  of InReg: regName(loc.r)
  of InRegPair:
    "{" & regName(loc.r0) & (if loc.r1 != NoReg: "," & regName(loc.r1) else: "") & "}"
  of InFReg: "<nofloat>"
  of NamedStack: "&" & loc.name
  of StackPtr: "*" & loc.ptrName
  of Mem: "[mem]"
  of Field:
    (case loc.base.kind
     of FbReg: "[" & regName(loc.base.reg) & "]"
     of FbSlot: "&" & loc.base.sym
     of FbGlob: "@" & loc.base.sym
     of FbTvar: "%tvar:" & loc.base.sym
     of FbLval: "[lval]") & "." & loc.field
  of Glob: "@" & loc.name
  of Tvar: "%tvar:" & loc.name
  of Imm: "#" & $loc.ival
