# Nifasm - RV32IM Binary Assembler
# A dependency-free encoder for the 32-bit RISC-V base plus the M extension.

## Every instruction is exactly four bytes, little-endian, which makes this the
## simplest encoder in the tree — and the immediates are where all of the
## difficulty went instead.
##
## **Six formats, four immediate scatterings.** R and U are straightforward. I
## and S carry twelve signed bits, split in S but contiguous in I. B and J are
## the ones to be careful with: their immediates are in HALFWORD units with bit 0
## implicit, and the bits are PERMUTED rather than merely shifted — bit 11 of a
## branch offset sits below the sign bit, in the field a careless reading gives
## to bit 4.
##
## **`x0` reads as zero and discards writes**, and that is why this file has no
## `mov`, no `neg`, no `not` and no `nop`. Each of them is one ordinary
## instruction against `x0`, so nothing has to be invented: `mv rd, rs` IS
## `addi rd, rs, 0`, `neg rd, rs` IS `sub rd, x0, rs`, `not rd, rs` IS
## `xori rd, rs, -1`, and `nop` IS `addi x0, x0, 0`.
##
## **There are no condition flags.** A comparison is `slt`/`sltu` into a register
## or a two-register `beq rs1, rs2, label`; there is no status register to test
## and no `cmp` instruction at all. That is the fact that decides the whole shape
## of this target's asm-NIF vocabulary — see doc/internals/rv32.md.

import ../core/[buffers, relocs]

type
  Register* = enum
    X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, X31

  Condition* = enum
    ## The six branches the hardware has. There is no "greater" and no "less or
    ## equal": each is the opposite one with the operands exchanged, which costs
    ## nothing because the exchange happens while selecting rather than while
    ## running.
    CondEq,      ## `beq`
    CondNe,      ## `bne`
    CondLt,      ## `blt`  — signed
    CondGe,      ## `bge`  — signed
    CondLtu,     ## `bltu` — unsigned
    CondGeu      ## `bgeu` — unsigned

const
  Zero* = X0    ## hardwired zero: reads 0, discards writes
  Ra* = X1      ## the link register `jal`/`jalr` write
  Sp* = X2
  Gp* = X3      ## the global pointer — reserved by the ABI even when unused
  Tp* = X4      ## the thread pointer, likewise

proc invert*(c: Condition): Condition =
  case c
  of CondEq: CondNe
  of CondNe: CondEq
  of CondLt: CondGe
  of CondGe: CondLt
  of CondLtu: CondGeu
  of CondGeu: CondLtu

proc funct3(c: Condition): uint32 =
  case c
  of CondEq: 0
  of CondNe: 1
  of CondLt: 4
  of CondGe: 5
  of CondLtu: 6
  of CondGeu: 7

# ── the six formats ─────────────────────────────────────────────────────────

proc r(x: Register): uint32 {.inline.} = uint32(ord(x))

proc rType(f7, rs2, rs1, f3, rd, op: uint32): uint32 =
  (f7 shl 25) or (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or (rd shl 7) or op

proc iType(imm: int32; rs1, f3, rd, op: uint32): uint32 =
  ((uint32(imm) and 0xFFF) shl 20) or (rs1 shl 15) or (f3 shl 12) or (rd shl 7) or op

proc sType(imm: int32; rs2, rs1, f3, op: uint32): uint32 =
  let u = uint32(imm)
  (((u shr 5) and 0x7F) shl 25) or (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or
    ((u and 0x1F) shl 7) or op

proc bType*(imm: int32; rs2, rs1, f3, op: uint32): uint32 =
  ## `imm[12|10:5]` above the registers and `imm[4:1|11]` below them. Bit 11
  ## crosses the two halves and bit 0 does not exist.
  let u = uint32(imm)
  (((u shr 12) and 1) shl 31) or (((u shr 5) and 0x3F) shl 25) or
    (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or
    (((u shr 1) and 0xF) shl 8) or (((u shr 11) and 1) shl 7) or op

proc uType(imm20, rd, op: uint32): uint32 =
  ((imm20 and 0xFFFFF) shl 12) or (rd shl 7) or op

proc jType*(imm: int32; rd, op: uint32): uint32 =
  ## `imm[20|10:1|11|19:12]` — the widest permutation in the instruction set.
  let u = uint32(imm)
  (((u shr 20) and 1) shl 31) or (((u shr 1) and 0x3FF) shl 21) or
    (((u shr 11) and 1) shl 20) or (((u shr 12) and 0xFF) shl 12) or
    (rd shl 7) or op

proc emit(dest: var Bytes; w: uint32) {.inline.} = dest.addUint32 w

proc fitsImm12*(v: int64): bool {.inline.} = v >= -2048 and v <= 2047
  ## Whether a constant rides in an `i`-suffixed form. Twelve SIGNED bits, and
  ## the same field for every one of them — which is why one predicate serves the
  ## whole instruction set here.

proc fitsBranch*(d: int): bool {.inline.} = d >= -4096 and d <= 4094 and (d and 1) == 0
proc fitsJal*(d: int): bool {.inline.} = d >= -1048576 and d <= 1048574 and (d and 1) == 0

# ── register-register ALU ───────────────────────────────────────────────────

const OpAlu = 0x33'u32

proc emitAdd*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 0, r(rd), OpAlu)
proc emitSub*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0x20, r(b), r(a), 0, r(rd), OpAlu)
proc emitSll*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 1, r(rd), OpAlu)
proc emitSlt*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 2, r(rd), OpAlu)
proc emitSltu*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 3, r(rd), OpAlu)
proc emitXor*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 4, r(rd), OpAlu)
proc emitSrl*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 5, r(rd), OpAlu)
proc emitSra*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0x20, r(b), r(a), 5, r(rd), OpAlu)
proc emitOr*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 6, r(rd), OpAlu)
proc emitAnd*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(0, r(b), r(a), 7, r(rd), OpAlu)

# The M extension. `div`/`rem` are here and `mulh` is not needed yet: a 32-bit
# product's high half only matters for a 64-bit multiply, which is R5.
proc emitMul*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(1, r(b), r(a), 0, r(rd), OpAlu)
proc emitDiv*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(1, r(b), r(a), 4, r(rd), OpAlu)
proc emitDivu*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(1, r(b), r(a), 5, r(rd), OpAlu)
proc emitRem*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(1, r(b), r(a), 6, r(rd), OpAlu)
proc emitRemu*(dest: var Bytes; rd, a, b: Register) = dest.emit rType(1, r(b), r(a), 7, r(rd), OpAlu)

# ── register-immediate ALU ──────────────────────────────────────────────────

const OpAluI = 0x13'u32

proc emitAddi*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 0, r(rd), OpAluI)
proc emitSlti*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 2, r(rd), OpAluI)
proc emitSltiu*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 3, r(rd), OpAluI)
proc emitXori*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 4, r(rd), OpAluI)
proc emitOri*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 6, r(rd), OpAluI)
proc emitAndi*(dest: var Bytes; rd, a: Register; imm: int64) =
  assert fitsImm12(imm)
  dest.emit iType(int32(imm), r(a), 7, r(rd), OpAluI)

proc emitSlli*(dest: var Bytes; rd, a: Register; n: int) =
  assert n in 0..31
  dest.emit iType(int32(n), r(a), 1, r(rd), OpAluI)
proc emitSrli*(dest: var Bytes; rd, a: Register; n: int) =
  assert n in 0..31
  dest.emit iType(int32(n), r(a), 5, r(rd), OpAluI)
proc emitSrai*(dest: var Bytes; rd, a: Register; n: int) =
  ## The arithmetic form is the logical one with bit 30 set — the shift AMOUNT is
  ## only five bits wide, so the rest of the immediate field is opcode space.
  assert n in 0..31
  dest.emit iType(int32(0x400 or n), r(a), 5, r(rd), OpAluI)

# ── the pseudo-instructions x0 makes real ───────────────────────────────────

proc emitMv*(dest: var Bytes; rd, rs: Register) = dest.emitAddi(rd, rs, 0)
proc emitNeg*(dest: var Bytes; rd, rs: Register) = dest.emitSub(rd, Zero, rs)
proc emitNot*(dest: var Bytes; rd, rs: Register) = dest.emitXori(rd, rs, -1)
proc emitNop*(dest: var Bytes) = dest.emitAddi(Zero, Zero, 0)
proc emitSeqz*(dest: var Bytes; rd, rs: Register) = dest.emitSltiu(rd, rs, 1)
  ## 1 when `rs` is zero. `sltu rd, rs, 1` is true exactly then, because unsigned.
proc emitSnez*(dest: var Bytes; rd, rs: Register) = dest.emitSltu(rd, Zero, rs)

# ── upper immediates ────────────────────────────────────────────────────────

proc emitLui*(dest: var Bytes; rd: Register; imm20: uint32) =
  dest.emit uType(imm20, r(rd), 0x37)
proc emitAuipc*(dest: var Bytes; rd: Register; imm20: uint32) =
  dest.emit uType(imm20, r(rd), 0x17)

proc splitHiLo*(v: uint32): tuple[hi: uint32; lo: int32] =
  ## The `lui`+`addi` split, with the compensation that makes it correct.
  ##
  ## `addi`'s immediate is SIGNED, so a low half above 0x7FF is a NEGATIVE
  ## addend and the upper half has to be one higher to make up for it. Splitting
  ## at bit 12 without the `+0x800` is wrong by exactly 0x1000 for a bit under
  ## half of all constants — which is frequent enough to look like a
  ## sign-extension bug somewhere else entirely.
  let hi = (v + 0x800) shr 12
  (hi and 0xFFFFF, cast[int32](v - (hi shl 12)))

proc liWords*(v: int64): int {.inline.} =
  ## How many words `emitLi` will take. A caller measuring a distance across a
  ## materialization has to know before emitting it.
  if fitsImm12(v): 1 else: 2

proc emitLi*(dest: var Bytes; rd: Register; v: int64) =
  if fitsImm12(v):
    dest.emitAddi(rd, Zero, v)
  else:
    let (hi, lo) = splitHiLo(uint32(v and 0xFFFFFFFF))
    dest.emitLui(rd, hi)
    dest.emitAddi(rd, rd, int64(lo))

proc emitLiWide*(dest: var Bytes; rd: Register; v: int64) =
  ## Always TWO words, whatever the value. A materialization whose operand is not
  ## known when it is emitted must not change size when it becomes known, or
  ## every position after it moves.
  let (hi, lo) = splitHiLo(uint32(v and 0xFFFFFFFF))
  dest.emitLui(rd, hi)
  dest.emitAddi(rd, rd, int64(lo))

# ── memory ──────────────────────────────────────────────────────────────────
# One addressing mode for the whole machine: a base register plus a 12-bit
# signed offset. No index, no scale, no PC-relative form. That uniformity is why
# this target needs only one emitter bridge where AVR needed three.

proc emitLw*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 2, r(rd), 0x03)
proc emitLh*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 1, r(rd), 0x03)
proc emitLhu*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 5, r(rd), 0x03)
proc emitLb*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 0, r(rd), 0x03)
proc emitLbu*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 4, r(rd), 0x03)

proc emitSw*(dest: var Bytes; src, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit sType(int32(off), r(src), r(base), 2, 0x23)
proc emitSh*(dest: var Bytes; src, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit sType(int32(off), r(src), r(base), 1, 0x23)
proc emitSb*(dest: var Bytes; src, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit sType(int32(off), r(src), r(base), 0, 0x23)

# ── control flow, no relocation ─────────────────────────────────────────────

proc emitJalr*(dest: var Bytes; rd, base: Register; off: int64) =
  assert fitsImm12(off)
  dest.emit iType(int32(off), r(base), 0, r(rd), 0x67)

proc emitRet*(dest: var Bytes) = dest.emitJalr(Zero, Ra, 0)
  ## `jalr x0, ra, 0` — jump to the link register and discard the new one.

proc emitEcall*(dest: var Bytes) = dest.emit 0x73'u32
proc emitEbreak*(dest: var Bytes) = dest.emit 0x100073'u32

# ── control flow, relocated ─────────────────────────────────────────────────
# Reach is generous compared with the other new targets: a branch carries 13
# signed bits (±4 KB) and `jal` carries 21 (±1 MB). A call further than that
# needs `auipc`+`jalr`, which is two instructions and therefore the code
# generator's business, not the assembler's.

proc emitBranch*(dest: var Buffer; cond: Condition; a, b: Register; target: LabelId) =
  let pos = dest.data.len
  dest.addReloc(pos, target, rkRvBranch, 4)
  dest.data.emit bType(0, r(b), r(a), funct3(cond), 0x63)

proc emitJal*(dest: var Buffer; rd: Register; target: LabelId) =
  let pos = dest.data.len
  dest.addReloc(pos, target, rkRvJal, 4)
  dest.data.emit jType(0, r(rd), 0x6F)

proc emitJ*(dest: var Buffer; target: LabelId) = dest.emitJal(Zero, target)
  ## An unconditional jump IS `jal x0, target`: the link register written is the
  ## one that discards.

proc emitCall*(dest: var Buffer; target: LabelId) = dest.emitJal(Ra, target)

proc emitLa*(dest: var Buffer; rd: Register; target: LabelId) =
  ## `lui`+`addi` carrying a label's ABSOLUTE address, patched once the layout is
  ## fixed. Fixed-size for the reason every such pair is: patching must never
  ## resize an instruction.
  ##
  ## Absolute rather than `auipc`-relative because this target's images are
  ## static and loaded at a known base — the same property Cortex-M's MOVW/MOVT
  ## pair relies on.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkRvAbsPair, 8)
  dest.data.emitLui(rd, 0)
  dest.data.emitAddi(rd, rd, 0)
