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
    ## A third always-free scratch, beyond the two staging bridges: the
    ## Cortex-M stand-in for AArch64's x16 (IP0).
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

  ## The volatile scratch arkham manages. On AArch64 the argument registers are
  ## kept OUT of this pool because seven other volatiles exist; here they are the
  ## only volatiles there are, so — exactly as x86-64 does with its argument
  ## registers in `intLocalTempRegs` — they double as the temp pool. The
  ## analyser's `AllRegs` interval test is what makes that sound: a value homed
  ## in one of these provably has no call in its live range.
  ##
  ## r0 is EXCLUDED, as rax is on x86-64 and x0 on AArch64. The planner's
  ## "returned local lives in the return register" optimization depends on the
  ## return register being drawable ONLY by that local's home and by no temp; if
  ## it were an ordinary temp here, a temp could take it and the elision would
  ## silently stop happening.
  IntTempRegs* = [R1, R2, R3]

  ## Identical to `IntTempRegs`, as on AArch64: the bridges are already withheld
  ## by not appearing in either list, so there is nothing further to subtract.
  IntLocalTempRegs* = [R1, R2, R3]

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

  ## Never allocate: nifasm's IP, the link register, sp, and the abstract slots
  ## that map to no Cortex-M register.
  ReservedRegs* = {R12, R13, R14, R15, R16..R30, SP, NoReg}

  ## What a call destroys under AAPCS32 — emitted as the proc's `(clobber …)` so
  ## the ABI is declared at the signature rather than re-derived at each site.
  ## r12 and lr are included: `bl` overwrites lr, and IP is scratch for everyone.
  ConvClobbersGpr* = [R0, R1, R2, R3]

  ## The Cortex-M machine description handed to the register allocator.
  cortexMMachine* = MachineDesc(
    arch: ThumbM,
    intRetReg: R0,
    divRemReg: NoReg,           # sdiv/udiv are 3-operand; the remainder is `mls`
    shiftCountReg: NoReg,       # Thumb-2 shifts take any register
    intArgRegs: @IntArgRegs,
    floatArgRegs: @[],          # the FPv4-SP path is M5
    intTempRegs: @IntTempRegs,
    stagingBridgeReg: NoReg,    # like AArch64: the bridges are withheld from the
                                # pools instead (see IntBridgeRegs)
    intLocalTempRegs: @IntLocalTempRegs,
    intCalleeSaved: @IntCalleeSaved,
    floatTempRegs: @[],
    floatCalleeSaved: @[],
    intCalleeSavedSet: {R4..R7},
    floatCalleeSavedSet: {},
    aggrByRefThreshold: 8)      # TWO words, matching `slots.classifyArg`'s `2*w`.
                                # These two decide the same thing and MUST agree:
                                # `planCall` reads the threshold while the
                                # classifier reads `2*w`, so a disagreement makes
                                # the caller pass by value what the callee reads
                                # as a pointer. (16 on both 64-bit targets — the
                                # same rule, stated in words.)

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
