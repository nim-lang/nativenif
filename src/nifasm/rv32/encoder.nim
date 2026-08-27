# Nifasm - RV32IMAFD Binary Assembler
# A dependency-free encoder for the 32-bit RISC-V instruction set.

## Every instruction here is exactly four bytes, stored as ONE little-endian
## 32-bit word. That is the structural difference from `thumb/encoder.nim`, where
## a 32-bit encoding is two little-endian halfwords high-first, and it is why
## this module needs no `emitWide`/`emitNarrow` distinction and no relaxation
## between widths. (The C extension would reintroduce both; it is deliberately
## not part of the baseline — see doc/instructions.md.)
##
## Three things about RISC-V that the other two encoders here give no intuition
## for, and that every bug in this file has come from:
##
##  * **There are no condition flags.** `beq`/`bne`/`blt`/`bge`/`bltu`/`bgeu` each
##    take TWO source registers and compare them on the spot. A `cmp` followed by
##    a branch does not exist and cannot be encoded, so the instruction selector
##    fuses the pair — see `rv32/instr.nim`. `slt`/`sltu` are how a comparison
##    becomes a value instead of a jump.
##  * **Every immediate is 12 bits SIGN-extended**, in ALU ops and in memory
##    operands alike. A 32-bit constant is `lui`+`addi`, and because the `addi`
##    half is signed, the `lui` half must be rounded up when bit 11 of the low
##    part is set. `splitHiLo` is that rule, in one place, for the same reason
##    `patchThumbMovwMovtPair` is.
##  * **A PC-relative displacement measures from the instruction's own address**,
##    like AArch64 and unlike Thumb's PC+4. Branch and jump fields also drop the
##    low bit as implicit, which is why `jal` reaches ±1 MiB on 20 bits and a
##    branch ±4 KiB on 12.
##
## RV32D on a 32-bit machine has one asymmetry worth stating: `fmv.x.w`/`fmv.w.x`
## move 32 bits, and there is no `fmv.x.d` — a double cannot pass through a GPR
## at all, only through memory. `emitFmvXW` therefore takes no width.

import ../core/[buffers, relocs]

type
  Register* = enum
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31

  FloatRegister* = enum
    F0 = 0, F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14, F15,
    F16, F17, F18, F19, F20, F21, F22, F23, F24, F25, F26, F27, F28, F29, F30, F31

  BranchCond* = enum
    ## The six B-type conditions, valued as the `funct3` that encodes them. `Lt`
    ## and `Ge` are signed, `Ltu`/`Geu` unsigned; there is no encoding for `gt` or
    ## `le` in either signedness — those are the SAME instructions with the two
    ## source registers swapped, which the selector does rather than the encoder.
    Beq = 0, Bne = 1, Blt = 4, Bge = 5, Bltu = 6, Bgeu = 7

  FpWidth* = enum
    ## Which precision an FP instruction operates at, valued as the `fmt` field.
    ## Not a bit count, because `fmt` is what actually goes in the word — and the
    ## two spellings drifting apart is the sort of thing that produces a `.d`
    ## instruction reading half a register.
    FpS = 0    ## single, `.s`
    FpD = 1    ## double, `.d`

  RoundMode* = enum
    ## The `rm` field. Named rather than passed as a number because the choice is
    ## semantic: arithmetic rounds to nearest-even, but a float→int conversion
    ## must TRUNCATE to match what `(fcvtzs …)` means everywhere else in nifasm.
    RmRne = 0    ## round to nearest, ties to even
    RmRtz = 1    ## round toward zero — truncation, what `fcvtzs`/`fcvtzu` want
    RmRdn = 2
    RmRup = 3
    RmRmm = 4
    RmDyn = 7    ## take the mode from the `frm` CSR

const
  # ── the ilp32d ABI names ──────────────────────────────────────────────────
  # Aliases, not a second enum: `a0` IS `x10`, and two enums would let a proc
  # take one and be handed the other. The register file is AArch64's in asm-NIF
  # (`(x0)`..`(x30)`, `(sp)`), so these names appear only inside the assembler
  # and the runtime, where a datasheet or an ABI document is what is open.
  Zero* = X0    ## hardwired 0; writes are discarded
  Ra*   = X1    ## return address — `jal` writes it, `ret` is `jalr x0, 0(ra)`
  Sp*   = X2
  Gp*   = X3
  Tp*   = X4    ## thread pointer
  T0*   = X5
  T1*   = X6
  T2*   = X7
  S0*   = X8    ## also `fp`, though nothing generated here establishes one
  S1*   = X9
  A0*   = X10   ## first argument, and the integer return register
  A1*   = X11
  A2*   = X12
  A3*   = X13
  A4*   = X14
  A5*   = X15
  A6*   = X16
  A7*   = X17
  S2*   = X18
  S3*   = X19
  S4*   = X20
  S5*   = X21
  S6*   = X22
  S7*   = X23
  S8*   = X24
  S9*   = X25
  S10*  = X26
  S11*  = X27
  T3*   = X28
  T4*   = X29
  T5*   = X30
  T6*   = X31

  Fa0* = F10    ## first FP argument, and the FP return register under ilp32d
  Fa1* = F11

  # ── opcodes ───────────────────────────────────────────────────────────────
  OpLoad     = 0x03'u32
  OpLoadFp   = 0x07'u32
  OpMiscMem  = 0x0F'u32
  OpImm      = 0x13'u32
  OpAuipc    = 0x17'u32
  OpStore    = 0x23'u32
  OpStoreFp  = 0x27'u32
  OpAmo      = 0x2F'u32
  OpReg      = 0x33'u32
  OpLui      = 0x37'u32
  OpFp       = 0x53'u32
  OpBranch   = 0x63'u32
  OpJalr     = 0x67'u32
  OpJal      = 0x6F'u32
  OpSystem   = 0x73'u32

  MulDivFunct7 = 0x01'u32   ## the M extension shares OP; `funct7 = 1` selects it

proc invert*(c: BranchCond): BranchCond {.inline.} =
  ## The complementary condition. Every RISC-V branch pair differs in exactly bit
  ## 0 of `funct3` — `beq`/`bne`, `blt`/`bge`, `bltu`/`bgeu` — so the flip is one
  ## xor and there is no condition without an inverse (unlike Arm's `AL`).
  BranchCond(ord(c) xor 1)

proc rn(r: Register): uint32 {.inline.} = uint32(ord(r))
proc fn(f: FloatRegister): uint32 {.inline.} = uint32(ord(f))

# ── instruction formats ─────────────────────────────────────────────────────
# One packer per RISC-V format. Every caller below goes through these rather than
# assembling a word itself, so a field position is written down once.

proc word(dest: var Bytes; w: uint32) {.inline.} =
  ## One instruction: a single little-endian 32-bit word.
  dest.addUint32 w

proc encR(opcode, funct7, funct3, rd, rs1, rs2: uint32): uint32 {.inline.} =
  (funct7 shl 25) or (rs2 shl 20) or (rs1 shl 15) or (funct3 shl 12) or
  (rd shl 7) or opcode

proc encI(opcode, funct3, rd, rs1: uint32; imm: int32): uint32 {.inline.} =
  ## `imm` is 12 bits SIGNED. Out-of-range values are the caller's error to catch —
  ## `fitsImm12` is the predicate for that — because the only thing this could do
  ## about one is truncate it silently.
  ((cast[uint32](imm) and 0xFFF'u32) shl 20) or (rs1 shl 15) or (funct3 shl 12) or
  (rd shl 7) or opcode

proc encS(opcode, funct3, rs1, rs2: uint32; imm: int32): uint32 {.inline.} =
  let u = cast[uint32](imm)
  (((u shr 5) and 0x7F'u32) shl 25) or (rs2 shl 20) or (rs1 shl 15) or
  (funct3 shl 12) or ((u and 0x1F'u32) shl 7) or opcode

proc encU(opcode, rd, imm20: uint32): uint32 {.inline.} =
  ((imm20 and 0xFFFFF'u32) shl 12) or (rd shl 7) or opcode

proc fitsImm12*(v: int64): bool {.inline.} =
  ## Whether `v` rides along in an I-type or S-type immediate. THE predicate of
  ## this ISA: it decides every "can this constant fold into the instruction"
  ## question, in ALU ops and memory operands alike.
  v >= -2048 and v <= 2047

proc splitHiLo*(v: uint32): tuple[hi20: uint32, lo12: int32] =
  ## Split a 32-bit value into the `lui`/`auipc` upper part and the `addi` lower
  ## part such that reassembling them yields `v` exactly.
  ##
  ## The `+ 0x800` is the whole content of this function. `addi` sign-extends its
  ## 12-bit field, so a low part at or above 0x800 arrives as a NEGATIVE number
  ## and subtracts 0x1000 from the result; rounding the upper part up cancels
  ## that. Leaving it out is correct for every value whose low 12 bits are under
  ## 0x800 and wrong by exactly 4096 for the rest — which is why it passes a
  ## hand-written test and fails in the field.
  let hi = (v + 0x800'u32) shr 12
  let bits = (v - (hi shl 12)) and 0xFFF'u32
  # Sign-extend the 12 bits by hand. `int32(bits)` would be the VALUE 0..4095,
  # which is a different number from the one the instruction will compute.
  let lo = cast[int32](if (bits and 0x800'u32) != 0'u32: bits or 0xFFFFF000'u32
                       else: bits)
  (hi and 0xFFFFF'u32, lo)

# ── RV32I: upper immediates ─────────────────────────────────────────────────

proc emitLui*(dest: var Bytes; rd: Register; imm20: uint32) =
  dest.word encU(OpLui, rn(rd), imm20)

proc emitAuipc*(dest: var Bytes; rd: Register; imm20: uint32) =
  dest.word encU(OpAuipc, rn(rd), imm20)

# ── RV32I: register-immediate ALU ───────────────────────────────────────────

proc emitAddi*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 0, rn(rd), rn(rs1), imm)
proc emitSlti*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 2, rn(rd), rn(rs1), imm)
proc emitSltiu*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 3, rn(rd), rn(rs1), imm)
proc emitXori*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 4, rn(rd), rn(rs1), imm)
proc emitOri*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 6, rn(rd), rn(rs1), imm)
proc emitAndi*(dest: var Bytes; rd, rs1: Register; imm: int32) =
  dest.word encI(OpImm, 7, rn(rd), rn(rs1), imm)

proc emitSlli*(dest: var Bytes; rd, rs1: Register; sh: int) =
  ## Shift amounts are 5 bits on RV32; `sh` outside 0..31 has no encoding at all
  ## (RV64 widens the field to 6, which is why the assert names the width).
  assert sh >= 0 and sh < 32, "RV32 shift amount out of range: " & $sh
  dest.word encI(OpImm, 1, rn(rd), rn(rs1), int32(sh))
proc emitSrli*(dest: var Bytes; rd, rs1: Register; sh: int) =
  assert sh >= 0 and sh < 32, "RV32 shift amount out of range: " & $sh
  dest.word encI(OpImm, 5, rn(rd), rn(rs1), int32(sh))
proc emitSrai*(dest: var Bytes; rd, rs1: Register; sh: int) =
  ## `srai` differs from `srli` only in bit 30 of the word, which lands in the
  ## immediate field — hence `0x400 or sh` rather than a separate funct3.
  assert sh >= 0 and sh < 32, "RV32 shift amount out of range: " & $sh
  dest.word encI(OpImm, 5, rn(rd), rn(rs1), int32(0x400 or sh))

# ── RV32I: register-register ALU ────────────────────────────────────────────

proc emitAdd*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 0, rn(rd), rn(rs1), rn(rs2))
proc emitSub*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0x20, 0, rn(rd), rn(rs1), rn(rs2))
proc emitSll*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 1, rn(rd), rn(rs1), rn(rs2))
proc emitSlt*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 2, rn(rd), rn(rs1), rn(rs2))
proc emitSltu*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 3, rn(rd), rn(rs1), rn(rs2))
proc emitXor*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 4, rn(rd), rn(rs1), rn(rs2))
proc emitSrl*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 5, rn(rd), rn(rs1), rn(rs2))
proc emitSra*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0x20, 5, rn(rd), rn(rs1), rn(rs2))
proc emitOr*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 6, rn(rd), rn(rs1), rn(rs2))
proc emitAnd*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, 0, 7, rn(rd), rn(rs1), rn(rs2))

# ── RV32M ───────────────────────────────────────────────────────────────────
# `mulh`/`mulhu` are what make a 64-bit multiply possible on a 32-bit machine,
# and `div`/`rem` are what make Cortex-M's software divide helpers unnecessary
# for the 32-bit case. Division by zero does NOT trap here: it yields all-ones
# (or the dividend, for `rem`), which is a defined result and not a fault.

proc emitMul*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 0, rn(rd), rn(rs1), rn(rs2))
proc emitMulh*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 1, rn(rd), rn(rs1), rn(rs2))
proc emitMulhsu*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 2, rn(rd), rn(rs1), rn(rs2))
proc emitMulhu*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 3, rn(rd), rn(rs1), rn(rs2))
proc emitDiv*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 4, rn(rd), rn(rs1), rn(rs2))
proc emitDivu*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 5, rn(rd), rn(rs1), rn(rs2))
proc emitRem*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 6, rn(rd), rn(rs1), rn(rs2))
proc emitRemu*(dest: var Bytes; rd, rs1, rs2: Register) =
  dest.word encR(OpReg, MulDivFunct7, 7, rn(rd), rn(rs1), rn(rs2))

# ── RV32I: loads and stores ─────────────────────────────────────────────────
# One addressing mode, `base + imm12`, for every width. There is no index
# register and no scaling — which is exactly why `RegOffsetMem` is absent from
# the RV32 machine description and an indexed access becomes an explicit `add`.

proc emitLb*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpLoad, 0, rn(rd), rn(base), off)
proc emitLh*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpLoad, 1, rn(rd), rn(base), off)
proc emitLw*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpLoad, 2, rn(rd), rn(base), off)
proc emitLbu*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpLoad, 4, rn(rd), rn(base), off)
proc emitLhu*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpLoad, 5, rn(rd), rn(base), off)

proc emitSb*(dest: var Bytes; src, base: Register; off: int32) =
  dest.word encS(OpStore, 0, rn(base), rn(src), off)
proc emitSh*(dest: var Bytes; src, base: Register; off: int32) =
  dest.word encS(OpStore, 1, rn(base), rn(src), off)
proc emitSw*(dest: var Bytes; src, base: Register; off: int32) =
  dest.word encS(OpStore, 2, rn(base), rn(src), off)

# ── pseudo-instructions ─────────────────────────────────────────────────────
# Spelled out rather than left to call sites, because each is a place where the
# `x0` trick or the hi/lo split can be got wrong once instead of everywhere.

proc emitNop*(dest: var Bytes) =
  ## The canonical `nop` IS `addi x0, x0, 0` — not a distinct opcode. A decoder
  ## that prints anything else for `0x00000013` is disassembling, not decoding.
  dest.emitAddi(X0, X0, 0)

proc emitMv*(dest: var Bytes; rd, rs: Register) =
  if rd != rs: dest.emitAddi(rd, rs, 0)

proc emitLi*(dest: var Bytes; rd: Register; value: uint32) =
  ## Materialize a full 32-bit constant: one `addi` when it fits the signed 12-bit
  ## field, otherwise `lui`+`addi` — and the `addi` is skipped when the low part
  ## is zero, which is the common case for a page-aligned address.
  # `cast`, not a conversion: an address like 0x8010_0000 is a perfectly ordinary
  # RV32 constant and out of `int32`'s range, so converting it raises.
  let v = cast[int32](value)
  if fitsImm12(int64(v)):
    dest.emitAddi(rd, X0, v)
  else:
    let (hi20, lo12) = splitHiLo(value)
    dest.emitLui(rd, hi20)
    if lo12 != 0: dest.emitAddi(rd, rd, lo12)

proc emitNeg*(dest: var Bytes; rd, rs: Register) =
  dest.emitSub(rd, X0, rs)

proc emitNot*(dest: var Bytes; rd, rs: Register) =
  dest.emitXori(rd, rs, -1)

proc emitSeqz*(dest: var Bytes; rd, rs: Register) =
  ## `rd = (rs == 0)`. `sltiu rd, rs, 1` is true for exactly one unsigned value.
  dest.emitSltiu(rd, rs, 1)

proc emitSnez*(dest: var Bytes; rd, rs: Register) =
  ## `rd = (rs != 0)`. The mirror: anything above zero is unsigned-greater than it.
  dest.emitSltu(rd, X0, rs)

proc emitRet*(dest: var Bytes) =
  ## `jalr x0, 0(ra)` — jump to the link register, discard the new return address.
  dest.word encI(OpJalr, 0, rn(X0), rn(Ra), 0)

proc emitJalr*(dest: var Bytes; rd, base: Register; off: int32) =
  dest.word encI(OpJalr, 0, rn(rd), rn(base), off)

# ── fences and environment calls ────────────────────────────────────────────

proc emitFence*(dest: var Bytes; pred = 0xF'u32; succ = 0xF'u32) =
  ## `fence pred, succ`. The default is the full `fence rw, rw` — the barrier an
  ## atomic wants, and the RV32 counterpart of `dmb`. The bits are I,O,R,W from
  ## high to low in each nibble.
  dest.word encI(OpMiscMem, 0, rn(X0), rn(X0), int32((pred shl 4) or succ))

proc emitFenceI*(dest: var Bytes) =
  ## Instruction-stream fence: make previously written code visible to fetch.
  ## Zifencei, which is baseline for everything this targets.
  dest.word encI(OpMiscMem, 1, rn(X0), rn(X0), 0)

# ── CSR access ──────────────────────────────────────────────────────────────
# Zicsr. Needed before the first FP instruction and before the first trap, which
# is to say: needed by every image, not only by one that goes looking for a
# control register.

const
  CsrMstatus* = 0x300'i32
  CsrMtvec*   = 0x305'i32
  CsrMepc*    = 0x341'i32
  CsrMcause*  = 0x342'i32

  MstatusFsDirty* = 0x6000'u32
    ## `mstatus.FS = Dirty`. The FP unit comes out of reset with `FS = Off`, and
    ## while it is off EVERY floating-point instruction — including a plain
    ## `fmv.w.x` — raises an illegal-instruction exception. With no trap handler
    ## installed that is not a crash but a HANG, which is what makes it expensive
    ## to diagnose: the image simply stops, at an instruction that is spelled
    ## correctly and encoded correctly.
    ##
    ## Exactly the Cortex-M CPACR situation (see `arkham/cortexm/runtime`), and it
    ## wants the same answer: every image turns the FPU on in its reset path,
    ## because whether it will use a float is not known when that path is emitted.

proc emitCsrrw*(dest: var Bytes; rd: Register; csr: int32; rs1: Register) =
  dest.word encI(OpSystem, 1, rn(rd), rn(rs1), csr)
proc emitCsrrs*(dest: var Bytes; rd: Register; csr: int32; rs1: Register) =
  dest.word encI(OpSystem, 2, rn(rd), rn(rs1), csr)
proc emitCsrrc*(dest: var Bytes; rd: Register; csr: int32; rs1: Register) =
  dest.word encI(OpSystem, 3, rn(rd), rn(rs1), csr)

proc emitCsrw*(dest: var Bytes; csr: int32; rs: Register) =
  ## Write a CSR, discarding its old value. `rd = x0` is what makes the read side
  ## effect-free, which matters for the CSRs where a read is not free.
  dest.emitCsrrw(X0, csr, rs)
proc emitCsrs*(dest: var Bytes; csr: int32; rs: Register) =
  ## Set the bits of `rs` in a CSR, leaving the rest alone.
  dest.emitCsrrs(X0, csr, rs)
proc emitCsrr*(dest: var Bytes; rd: Register; csr: int32) =
  ## Read a CSR. `rs1 = x0` sets no bits, so the read is pure.
  dest.emitCsrrs(rd, csr, X0)

proc emitEnableFpu*(dest: var Bytes; scratch = T0) =
  ## Turn the FPU on: `mstatus.FS = Dirty`. See `MstatusFsDirty` for why this is
  ## not optional and why leaving it out hangs rather than faults.
  dest.emitLi(scratch, MstatusFsDirty)
  dest.emitCsrs(CsrMstatus, scratch)

proc emitEcall*(dest: var Bytes) =
  dest.word encI(OpSystem, 0, rn(X0), rn(X0), 0)

proc emitEbreak*(dest: var Bytes) =
  dest.word encI(OpSystem, 0, rn(X0), rn(X0), 1)

proc emitMret*(dest: var Bytes) =
  ## `mret` — return from a machine-mode trap. `SYSTEM` with funct12 = 0x302 and
  ## every register field zero, i.e. the whole word is 0x30200073.
  ##
  ## It restores the privilege the trap interrupted from `mstatus.MPP`, restores
  ## the interrupt-enable bit it saved in `mstatus.MPIE`, and jumps to `mepc`.
  ## None of that is what `ret` does: `ret` is `jalr x0, 0(ra)`, and `ra` in a
  ## handler holds whatever the interrupted code happened to leave there.
  dest.word encI(OpSystem, 0, rn(X0), rn(X0), 0x302)

proc emitSemihostCall*(dest: var Bytes) =
  ## The RISC-V semihosting sequence: `slli x0,x0,0x1f` / `ebreak` / `srai x0,x0,7`.
  ##
  ## Three instructions, and all three are load-bearing. The `ebreak` alone is an
  ## ordinary breakpoint; it is the two surrounding NOPs-that-are-not-`nop` — both
  ## write `x0`, so both are architecturally no-ops — that mark this particular
  ## `ebreak` as a semihosting request. A debugger or emulator recognizes the
  ## triple by its exact bytes, which is why nothing here may be "simplified" to
  ## a real `nop`.
  ##
  ## Operation number in `a0`, parameter block pointer in `a1`, result back in
  ## `a0` — the same protocol, and the same `SYS_*` numbers, as ARM semihosting.
  dest.emitSlli(X0, X0, 0x1F)
  dest.emitEbreak()
  dest.emitSrai(X0, X0, 7)

# ── RV32A: the atomic extension ─────────────────────────────────────────────
# `lr.w`/`sc.w` are the load-reserved / store-conditional pair the LL/SC atomic
# lowering already speaks, and unlike ARMv7-M's `ldrex`/`strex` they CARRY their
# ordering in the `aq`/`rl` bits — which is what `AcqRelExclusives` names.
# `sc.w` writes 0 to `rd` on success and non-zero on failure, the same sense as
# `strex`.

proc emitAmo(dest: var Bytes; funct5: uint32; rd, base, rs2: Register;
             aq, rl: bool) =
  let f7 = (funct5 shl 2) or (if aq: 2'u32 else: 0'u32) or (if rl: 1'u32 else: 0'u32)
  dest.word encR(OpAmo, f7, 2, rn(rd), rn(base), rn(rs2))

proc emitLrW*(dest: var Bytes; rd, base: Register; aq = true, rl = false) =
  ## `rs2` must be `x0` for `lr.w`: the field is not a source here.
  dest.emitAmo(0x02, rd, base, X0, aq, rl)

proc emitScW*(dest: var Bytes; rd, base, src: Register; aq = false, rl = true) =
  dest.emitAmo(0x03, rd, base, src, aq, rl)

proc emitAmoswapW*(dest: var Bytes; rd, base, src: Register; aq = true, rl = true) =
  dest.emitAmo(0x01, rd, base, src, aq, rl)
proc emitAmoaddW*(dest: var Bytes; rd, base, src: Register; aq = true, rl = true) =
  dest.emitAmo(0x00, rd, base, src, aq, rl)
proc emitAmoxorW*(dest: var Bytes; rd, base, src: Register; aq = true, rl = true) =
  dest.emitAmo(0x04, rd, base, src, aq, rl)
proc emitAmoandW*(dest: var Bytes; rd, base, src: Register; aq = true, rl = true) =
  dest.emitAmo(0x0C, rd, base, src, aq, rl)
proc emitAmoorW*(dest: var Bytes; rd, base, src: Register; aq = true, rl = true) =
  dest.emitAmo(0x08, rd, base, src, aq, rl)

# ── RV32F / RV32D ───────────────────────────────────────────────────────────
# One register file serves both precisions; the `fmt` field picks which, exactly
# as AArch64's `d`/`s` register views do. That is why asm-NIF can spell an RV32
# FP register with AArch64's tags and let the bound type supply the width.

proc emitFlw*(dest: var Bytes; rd: FloatRegister; base: Register; off: int32) =
  dest.word encI(OpLoadFp, 2, fn(rd), rn(base), off)
proc emitFsw*(dest: var Bytes; src: FloatRegister; base: Register; off: int32) =
  dest.word encS(OpStoreFp, 2, rn(base), fn(src), off)
proc emitFld*(dest: var Bytes; rd: FloatRegister; base: Register; off: int32) =
  dest.word encI(OpLoadFp, 3, fn(rd), rn(base), off)
proc emitFsd*(dest: var Bytes; src: FloatRegister; base: Register; off: int32) =
  dest.word encS(OpStoreFp, 3, rn(base), fn(src), off)

proc emitFpLoad*(dest: var Bytes; rd: FloatRegister; base: Register; off: int32;
                 w: FpWidth) =
  if w == FpS: dest.emitFlw(rd, base, off) else: dest.emitFld(rd, base, off)
proc emitFpStore*(dest: var Bytes; src: FloatRegister; base: Register; off: int32;
                  w: FpWidth) =
  if w == FpS: dest.emitFsw(src, base, off) else: dest.emitFsd(src, base, off)

proc encFp(funct5: uint32; w: FpWidth; rd, rs1, rs2, rm: uint32): uint32 {.inline.} =
  encR(OpFp, (funct5 shl 2) or uint32(ord(w)), rm, rd, rs1, rs2)

proc emitFadd*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth;
               rm = RmRne) =
  dest.word encFp(0x00, w, fn(rd), fn(rs1), fn(rs2), uint32(ord(rm)))
proc emitFsub*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth;
               rm = RmRne) =
  dest.word encFp(0x01, w, fn(rd), fn(rs1), fn(rs2), uint32(ord(rm)))
proc emitFmul*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth;
               rm = RmRne) =
  dest.word encFp(0x02, w, fn(rd), fn(rs1), fn(rs2), uint32(ord(rm)))
proc emitFdiv*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth;
               rm = RmRne) =
  dest.word encFp(0x03, w, fn(rd), fn(rs1), fn(rs2), uint32(ord(rm)))
proc emitFsqrt*(dest: var Bytes; rd, rs1: FloatRegister; w: FpWidth; rm = RmRne) =
  dest.word encFp(0x0B, w, fn(rd), fn(rs1), 0, uint32(ord(rm)))

proc emitFsgnj*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x04, w, fn(rd), fn(rs1), fn(rs2), 0)
proc emitFsgnjn*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x04, w, fn(rd), fn(rs1), fn(rs2), 1)
proc emitFsgnjx*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x04, w, fn(rd), fn(rs1), fn(rs2), 2)

proc emitFmv*(dest: var Bytes; rd, rs: FloatRegister; w: FpWidth) =
  ## An FP register-to-register move is `fsgnj rd, rs, rs` — copy `rs`, taking the
  ## sign from `rs` as well. There is no dedicated FP `mov` in the ISA.
  if rd != rs: dest.emitFsgnj(rd, rs, rs, w)

proc emitFneg*(dest: var Bytes; rd, rs: FloatRegister; w: FpWidth) =
  ## `fsgnjn rd, rs, rs` — copy `rs` with the sign INVERTED. Not an arithmetic
  ## subtract from zero, which would get `-0.0` and NaN wrong.
  dest.emitFsgnjn(rd, rs, rs, w)

proc emitFabs*(dest: var Bytes; rd, rs: FloatRegister; w: FpWidth) =
  dest.emitFsgnjx(rd, rs, rs, w)

proc emitFmin*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x05, w, fn(rd), fn(rs1), fn(rs2), 0)
proc emitFmax*(dest: var Bytes; rd, rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x05, w, fn(rd), fn(rs1), fn(rs2), 1)

# The comparisons write a GPR, not a flag — 1 or 0. This is the FP half of the
# same fact the header opens with, and it is why an `(fcmp)` followed by a branch
# fuses just as an integer `(cmp)` does.
proc emitFeq*(dest: var Bytes; rd: Register; rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x14, w, rn(rd), fn(rs1), fn(rs2), 2)
proc emitFlt*(dest: var Bytes; rd: Register; rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x14, w, rn(rd), fn(rs1), fn(rs2), 1)
proc emitFle*(dest: var Bytes; rd: Register; rs1, rs2: FloatRegister; w: FpWidth) =
  dest.word encFp(0x14, w, rn(rd), fn(rs1), fn(rs2), 0)

proc emitFcvtToInt*(dest: var Bytes; rd: Register; rs: FloatRegister; w: FpWidth;
                    signed: bool; rm = RmRtz) =
  ## `fcvt.w.s` / `fcvt.wu.s` / `fcvt.w.d` / `fcvt.wu.d`. The default rounding is
  ## TRUNCATION, because that is what `(fcvtzs …)` means — the `z` in the asm-NIF
  ## mnemonic is the rounding mode, and taking the FPU's dynamic mode here would
  ## make the result depend on whatever last wrote `frm`.
  dest.word encFp(0x18, w, rn(rd), fn(rs), (if signed: 0'u32 else: 1'u32),
                  uint32(ord(rm)))

proc emitFcvtFromInt*(dest: var Bytes; rd: FloatRegister; rs: Register; w: FpWidth;
                      signed: bool; rm = RmRne) =
  ## `fcvt.s.w` / `fcvt.s.wu` / `fcvt.d.w` / `fcvt.d.wu` — `scvtf`/`ucvtf`.
  dest.word encFp(0x1A, w, fn(rd), rn(rs), (if signed: 0'u32 else: 1'u32),
                  uint32(ord(rm)))

proc emitFcvtSD*(dest: var Bytes; rd, rs: FloatRegister; rm = RmRne) =
  ## double → single. The `fmt` field is the DESTINATION's and `rs2` the source's,
  ## which is the one place the two disagree.
  dest.word encFp(0x08, FpS, fn(rd), fn(rs), 1, uint32(ord(rm)))
proc emitFcvtDS*(dest: var Bytes; rd, rs: FloatRegister) =
  ## single → double. Exact, so the rounding mode is irrelevant and RNE is passed
  ## rather than DYN to keep the word independent of `frm`.
  dest.word encFp(0x08, FpD, fn(rd), fn(rs), 0, uint32(ord(RmRne)))

proc emitFmvXW*(dest: var Bytes; rd: Register; rs: FloatRegister) =
  ## Move the raw 32 bits of an FP register into a GPR. SINGLE precision only —
  ## RV32 has no `fmv.x.d`, because the GPR is 32 bits wide, so a double reaches
  ## integer registers through memory or not at all.
  dest.word encFp(0x1C, FpS, rn(rd), fn(rs), 0, 0)
proc emitFmvWX*(dest: var Bytes; rd: FloatRegister; rs: Register) =
  dest.word encFp(0x1E, FpS, fn(rd), rn(rs), 0, 0)

# ── branches and jumps ──────────────────────────────────────────────────────
# These take a `Buffer` rather than a `Bytes`, because a label target is a
# relocation and the patcher lives with the buffer. The word emitted here is a
# PLACEHOLDER whose register and condition fields are final and whose immediate
# is zero; `updateRelocDisplacements` fills the immediate in and reads the rest
# back out of the buffer.

proc emitBranch*(dest: var Buffer; cond: BranchCond; rs1, rs2: Register;
                 target: LabelId) =
  let pos = dest.data.len
  dest.data.word encR(OpBranch, 0, uint32(ord(cond)), 0, rn(rs1), rn(rs2))
  dest.addReloc(pos, target, rkRvBranch, 4)

proc emitJ*(dest: var Buffer; target: LabelId) =
  ## An unconditional jump: `jal x0, target` — the return address is written to
  ## `x0` and therefore discarded.
  let pos = dest.data.len
  dest.data.word encU(OpJal, rn(X0), 0)
  dest.addReloc(pos, target, rkRvJ, 4)

proc emitJal*(dest: var Buffer; target: LabelId) =
  ## A call: the same encoding with `rd = ra`, which is the only difference and
  ## the reason the two carry different relocation kinds.
  let pos = dest.data.len
  dest.data.word encU(OpJal, rn(Ra), 0)
  dest.addReloc(pos, target, rkRvJal, 4)

proc emitBranchFar*(dest: var Buffer; cond: BranchCond; rs1, rs2: Register;
                    target: LabelId) =
  ## A branch whose target may lie beyond B-type's ±4 KiB: the INVERTED condition
  ## jumping over a `jal`, which reaches ±1 MiB.
  ##
  ## The caller chooses this rather than the patcher discovering it, because a
  ## relaxation that GROWS an instruction would move every byte position after it
  ## — and `updateRelocDisplacements` runs after the layout is fixed, so it can
  ## only fail loudly (which it does). The x86 shortener gets away with the
  ## reverse direction: shrinking rebases positions the same way, but there is a
  ## fixpoint to iterate to.
  ##
  ## The short branch it emits is always in range: its target is the eight bytes
  ## it is skipping.
  let over = dest.createLabel()
  dest.emitBranch(invert(cond), rs1, rs2, over)
  dest.emitJ(target)
  dest.defineLabel(over)

proc emitLa*(dest: var Buffer; rd: Register; target: LabelId) =
  ## A label's address, PC-relative: `auipc rd, hi` + `addi rd, rd, lo`. Reaches
  ## ±2 GB, so unlike every branch above it needs no relaxation.
  let pos = dest.data.len
  dest.data.word encU(OpAuipc, rn(rd), 0)
  dest.data.word encI(OpImm, 0, rn(rd), rn(rd), 0)
  dest.addReloc(pos, target, rkRvAuipcAddi, 8)

proc emitLaAbs*(dest: var Buffer; rd: Register; target: LabelId) =
  ## A label's ABSOLUTE address: `lui rd, hi` + `addi rd, rd, lo`, with the
  ## section's load address folded in by the patcher through `Buffer.absBase`.
  ## Valid only where that address is fixed at link time, which on a firmware
  ## image it is.
  let pos = dest.data.len
  dest.data.word encU(OpLui, rn(rd), 0)
  dest.data.word encI(OpImm, 0, rn(rd), rn(rd), 0)
  dest.addReloc(pos, target, rkRvLuiAddi, 8)
