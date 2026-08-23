# Nifasm - Thumb-2 (ARMv7E-M) Binary Assembler
# A dependency-free encoder for the Cortex-M instruction set.

## Cortex-M is **Thumb-only**: there is no A32 state to fall back to, so every
## instruction here is either 16 or 32 bits wide and the two are interleaved
## freely. That variable width is the one structural difference from `arm64.nim`,
## where every encoder emits exactly 4 bytes:
##
##  * a branch's PC is `address_of_instruction + 4` REGARDLESS of the branch's own
##    width — Thumb's PC reads two halfwords ahead, not one instruction ahead. So
##    the displacement for a 32-bit `B.W` and a 16-bit `B` are computed the same
##    way, and neither matches x86 (from END of instruction) or AArch64 (from the
##    instruction's own address). See `relocs.calculateRelocDistance`.
##  * `emitWide`/`emitNarrow` say which form was chosen, because the relocation
##    patcher has to know how many bytes a site occupies before it can patch it.
##
## Halfword ORDER matters and is easy to get wrong: a 32-bit Thumb instruction is
## stored as two little-endian HALFWORDS, high halfword first — NOT as one
## little-endian 32-bit word. `0xF7FF 0xFFFE` is written `FF F7 FE FF`.

import std/[strutils]
import buffers, relocs

type
  Register* = enum
    R0 = 0, R1 = 1, R2 = 2, R3 = 3, R4 = 4, R5 = 5, R6 = 6, R7 = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12,
    SP = 13, LR = 14, PC = 15

  FloatRegister* = enum
    ## FPv4-SP single-precision registers. Cortex-M4F has s0–s31 (16 d-register
    ## pairs); the double-precision `d` view exists only on M7's FPv5-D16.
    S0 = 0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15,
    S16, S17, S18, S19, S20, S21, S22, S23, S24, S25, S26, S27, S28, S29, S30, S31

  Condition* = enum
    CondEQ = 0, CondNE = 1, CondHS = 2, CondLO = 3,
    CondMI = 4, CondPL = 5, CondVS = 6, CondVC = 7,
    CondHI = 8, CondLS = 9, CondGE = 10, CondLT = 11,
    CondGT = 12, CondLE = 13, CondAL = 14

type
  MemoryOperand* = object
    ## A resolved `[base, #offset]` or `[base, index, LSL #shift]` address.
    ## Thumb-2 has no RIP-relative form and no segment override, so this is the
    ## whole addressing vocabulary.
    base*: Register
    offset*: int32
    hasIndex*: bool
    index*: Register
    shift*: int        ## 0..3, the LSL applied to `index`

const
  IP* = R12   ## the AAPCS32 intra-procedure scratch register
  LowRegs* = {R0..R7}
    ## The registers the 16-bit encodings can name. Most Thumb-1-inherited forms
    ## are restricted to these, which is why `emitAddReg` and friends check
    ## membership before choosing a narrow form.

proc invert*(c: Condition): Condition =
  ## The complementary condition (EQ<->NE, LT<->GE, ...). AL has no inverse.
  assert c != CondAL
  Condition(ord(c) xor 1)

proc isLow*(r: Register): bool {.inline.} = r in LowRegs

# ── emission primitives ─────────────────────────────────────────────────────

proc emitNarrow*(dest: var Bytes; hw: uint16) {.inline.} =
  ## One 16-bit instruction, little-endian.
  dest.addUint16 hw

proc emitWide*(dest: var Bytes; hi, lo: uint16) {.inline.} =
  ## One 32-bit instruction as two little-endian halfwords, HIGH halfword first.
  ## Writing it as a single `addUint32` would swap them and encode a different
  ## instruction entirely.
  dest.addUint16 hi
  dest.addUint16 lo

proc reg(r: Register): uint16 {.inline.} = uint16(ord(r))

# ── the Thumb-2 modified immediate ──────────────────────────────────────────

proc encodeModifiedImm*(value: uint32; encoding: var uint32): bool =
  ## The "ThumbExpandImm" 12-bit immediate used by the 32-bit data-processing
  ## forms (i:imm3:imm8). It represents either a small value replicated across
  ## byte lanes, or an 8-bit value with its top bit set rotated to any position —
  ## the direct analogue of AArch64's `isLogicalImm`, and the reason a great many
  ## constants need no literal pool.
  ##
  ## Returns false when `value` is not representable, in which case the caller
  ## must fall back to MOVW/MOVT.
  # Form 1: 0000_00XY where the 12-bit field is 0000 xxxxxxxx (value < 256)
  if value < 256:
    encoding = value
    return true
  # Form 2..4: byte-replicated patterns.
  let b0 = value and 0xFF
  let b1 = (value shr 8) and 0xFF
  let b2 = (value shr 16) and 0xFF
  let b3 = (value shr 24) and 0xFF
  if b0 == b2 and b1 == 0 and b3 == 0 and b0 != 0:
    encoding = (0x1'u32 shl 8) or b0        # 0x00XY00XY
    return true
  if b1 == b3 and b0 == 0 and b2 == 0 and b1 != 0:
    encoding = (0x2'u32 shl 8) or b1        # 0xXY00XY00
    return true
  if b0 == b1 and b1 == b2 and b2 == b3 and b0 != 0:
    encoding = (0x3'u32 shl 8) or b0        # 0xXYXYXYXY
    return true
  # Form 5: an 8-bit value with bit 7 SET, rotated right by 8..31.
  for rot in 8 .. 31:
    let rotated = (value shl rot) or (value shr (32 - rot))
    if rotated < 0x100 and (rotated and 0x80) != 0:
      # `rotated` is the unrotated 8-bit constant; the field stores the amount
      # needed to rotate it back into place.
      encoding = (uint32(rot) shl 7) or (rotated and 0x7F)
      return true
  return false

proc isModifiedImm*(value: uint32): bool {.inline.} =
  var enc: uint32
  encodeModifiedImm(value, enc)

proc splitImm12(enc: uint32): tuple[i, imm3, imm8: uint16] {.inline.} =
  ## Scatter a 12-bit modified immediate into the i / imm3 / imm8 fields.
  (uint16((enc shr 11) and 0x1), uint16((enc shr 8) and 0x7), uint16(enc and 0xFF))

# ── moves ───────────────────────────────────────────────────────────────────

proc emitMovReg*(dest: var Bytes; rd, rm: Register) =
  ## MOV rd, rm. The 16-bit T1 form (`0100 0110 D rm rd`) reaches ALL 16
  ## registers via its split D:rd destination field, which is what lets a move
  ## involving sp/lr/pc still be two bytes.
  let d = (reg(rd) shr 3) and 0x1
  dest.emitNarrow 0x4600'u16 or (d shl 7) or (reg(rm) shl 3) or (reg(rd) and 0x7)

proc emitMovImm16*(dest: var Bytes; rd: Register; imm: uint16) =
  ## MOVW rd, #imm16 (T3). imm16 is scattered as imm4:i:imm3:imm8.
  let imm4 = uint16((imm shr 12) and 0xF)
  let i    = uint16((imm shr 11) and 0x1)
  let imm3 = uint16((imm shr 8) and 0x7)
  let imm8 = uint16(imm and 0xFF)
  dest.emitWide(0xF240'u16 or (i shl 10) or imm4,
                (imm3 shl 12) or (reg(rd) shl 8) or imm8)

proc emitMovt*(dest: var Bytes; rd: Register; imm: uint16) =
  ## MOVT rd, #imm16 — writes the TOP halfword, leaving the bottom one alone.
  let imm4 = uint16((imm shr 12) and 0xF)
  let i    = uint16((imm shr 11) and 0x1)
  let imm3 = uint16((imm shr 8) and 0x7)
  let imm8 = uint16(imm and 0xFF)
  dest.emitWide(0xF2C0'u16 or (i shl 10) or imm4,
                (imm3 shl 12) or (reg(rd) shl 8) or imm8)

proc emitMovImm32*(dest: var Bytes; rd: Register; value: uint32) =
  ## Materialize any 32-bit constant into `rd`, in the shortest form available:
  ## a narrow MOVS for a low register and a small value, a single wide MOV for a
  ## modified immediate, else MOVW (+ MOVT only when the top halfword is nonzero).
  ## No literal pool is involved, so nothing here depends on PC-relative reach.
  if value < 256 and rd.isLow:
    dest.emitNarrow 0x2000'u16 or (reg(rd) shl 8) or uint16(value)
    return
  var enc: uint32
  if encodeModifiedImm(value, enc):
    let (i, imm3, imm8) = splitImm12(enc)
    dest.emitWide(0xF04F'u16 or (i shl 10), (imm3 shl 12) or (reg(rd) shl 8) or imm8)
    return
  dest.emitMovImm16(rd, uint16(value and 0xFFFF))
  if (value shr 16) != 0:
    dest.emitMovt(rd, uint16((value shr 16) and 0xFFFF))

# ── data processing ─────────────────────────────────────────────────────────

proc emitDataImm(dest: var Bytes; op: uint16; rd, rn: Register; enc: uint32; s: bool) =
  let (i, imm3, imm8) = splitImm12(enc)
  dest.emitWide(0xF000'u16 or (i shl 10) or (op shl 5) or
                  (if s: 0x0010'u16 else: 0'u16) or reg(rn),
                (imm3 shl 12) or (reg(rd) shl 8) or imm8)

proc emitDataReg(dest: var Bytes; op: uint16; rd, rn, rm: Register; s: bool) =
  dest.emitWide(0xEA00'u16 or (op shl 5) or (if s: 0x0010'u16 else: 0'u16) or reg(rn),
                (reg(rd) shl 8) or reg(rm))

const
  OpAnd = 0x0'u16
  OpBic = 0x1'u16
  OpOrr = 0x2'u16
  OpOrn = 0x3'u16
  OpEor = 0x4'u16
  OpAdd = 0x8'u16
  OpAdc = 0xA'u16
  OpSbc = 0xB'u16
  OpSub = 0xD'u16
  OpRsb = 0xE'u16

proc emitAdd3*(dest: var Bytes; rd, rn, rm: Register; s = false) =
  ## ADD rd, rn, rm. The narrow T1 form takes three low registers.
  if not s and rd.isLow and rn.isLow and rm.isLow:
    dest.emitNarrow 0x1800'u16 or (reg(rm) shl 6) or (reg(rn) shl 3) or reg(rd)
  else:
    dest.emitDataReg(OpAdd, rd, rn, rm, s)

proc emitSub3*(dest: var Bytes; rd, rn, rm: Register; s = false) =
  if not s and rd.isLow and rn.isLow and rm.isLow:
    dest.emitNarrow 0x1A00'u16 or (reg(rm) shl 6) or (reg(rn) shl 3) or reg(rd)
  else:
    dest.emitDataReg(OpSub, rd, rn, rm, s)

proc emitAddsCarry*(dest: var Bytes; rd, rn, rm: Register) =
  ## ADDS — the flag-setting add that begins a 64-bit addition.
  dest.emitDataReg(OpAdd, rd, rn, rm, true)
proc emitAdcs*(dest: var Bytes; rd, rn, rm: Register) =
  ## ADCS — add with carry; the high half of a 64-bit addition (see M4).
  dest.emitDataReg(OpAdc, rd, rn, rm, true)
proc emitSubsCarry*(dest: var Bytes; rd, rn, rm: Register) =
  dest.emitDataReg(OpSub, rd, rn, rm, true)
proc emitSbcs*(dest: var Bytes; rd, rn, rm: Register) =
  dest.emitDataReg(OpSbc, rd, rn, rm, true)

proc emitAnd3*(dest: var Bytes; rd, rn, rm: Register) = dest.emitDataReg(OpAnd, rd, rn, rm, false)
proc emitOrr3*(dest: var Bytes; rd, rn, rm: Register) = dest.emitDataReg(OpOrr, rd, rn, rm, false)
proc emitEor3*(dest: var Bytes; rd, rn, rm: Register) = dest.emitDataReg(OpEor, rd, rn, rm, false)
proc emitBic3*(dest: var Bytes; rd, rn, rm: Register) = dest.emitDataReg(OpBic, rd, rn, rm, false)

proc emitAddImm*(dest: var Bytes; rd, rn: Register; imm: uint32) =
  ## ADD rd, rn, #imm. Prefers the narrow forms (ADDS rd,rn,#imm3 /
  ## ADD rd,#imm8 / ADD sp,#imm7*4), then the modified immediate, then the
  ## 12-bit plain ADDW which needs no immediate encoding at all.
  if rd == SP and rn == SP and imm < 512 and (imm and 3) == 0:
    dest.emitNarrow 0xB000'u16 or uint16(imm shr 2)
    return
  if rd.isLow and rn.isLow and imm < 8:
    dest.emitNarrow 0x1C00'u16 or (uint16(imm) shl 6) or (reg(rn) shl 3) or reg(rd)
    return
  if rd == rn and rd.isLow and imm < 256:
    dest.emitNarrow 0x3000'u16 or (reg(rd) shl 8) or uint16(imm)
    return
  var enc: uint32
  if encodeModifiedImm(imm, enc):
    dest.emitDataImm(OpAdd, rd, rn, enc, false)
    return
  if imm < 4096:
    # ADDW rd, rn, #imm12 — a plain 12-bit binary immediate, no expansion.
    let i = uint16((imm shr 11) and 0x1)
    let imm3 = uint16((imm shr 8) and 0x7)
    let imm8 = uint16(imm and 0xFF)
    dest.emitWide(0xF200'u16 or (i shl 10) or reg(rn),
                  (imm3 shl 12) or (reg(rd) shl 8) or imm8)
    return
  # Past 4095 there is no immediate form at all: the constant goes into IP (the
  # AAPCS32 scratch, which hosts no value) and the register form does the work.
  # A frame bigger than 4 KB is what gets here.
  assert rd != IP and rn != IP, "thumb2: emitAddImm needs IP as a scratch"
  dest.emitMovImm32(IP, imm)
  dest.emitAdd3(rd, rn, IP)

proc emitSubImm*(dest: var Bytes; rd, rn: Register; imm: uint32) =
  ## SUB rd, rn, #imm, mirroring `emitAddImm`'s form selection.
  if rd == SP and rn == SP and imm < 512 and (imm and 3) == 0:
    dest.emitNarrow 0xB080'u16 or uint16(imm shr 2)
    return
  if rd.isLow and rn.isLow and imm < 8:
    dest.emitNarrow 0x1E00'u16 or (uint16(imm) shl 6) or (reg(rn) shl 3) or reg(rd)
    return
  if rd == rn and rd.isLow and imm < 256:
    dest.emitNarrow 0x3800'u16 or (reg(rd) shl 8) or uint16(imm)
    return
  var enc: uint32
  if encodeModifiedImm(imm, enc):
    dest.emitDataImm(OpSub, rd, rn, enc, false)
    return
  if imm < 4096:
    let i = uint16((imm shr 11) and 0x1)
    let imm3 = uint16((imm shr 8) and 0x7)
    let imm8 = uint16(imm and 0xFF)
    dest.emitWide(0xF2A0'u16 or (i shl 10) or reg(rn),
                  (imm3 shl 12) or (reg(rd) shl 8) or imm8)
    return
  assert rd != IP and rn != IP, "thumb2: emitSubImm needs IP as a scratch"
  dest.emitMovImm32(IP, imm)
  dest.emitSub3(rd, rn, IP)

proc emitMul*(dest: var Bytes; rd, rn, rm: Register) =
  ## MUL rd, rn, rm (32-bit result). ARMv7-M always has this.
  dest.emitWide(0xFB00'u16 or reg(rn), 0xF000'u16 or (reg(rd) shl 8) or reg(rm))

proc emitUmull*(dest: var Bytes; rdLo, rdHi, rn, rm: Register) =
  ## UMULL rdLo, rdHi, rn, rm — the 64-bit unsigned product. The building block
  ## for 64-bit multiplication (M4) and for the high half of a widening multiply.
  dest.emitWide(0xFBA0'u16 or reg(rn), (reg(rdLo) shl 12) or (reg(rdHi) shl 8) or reg(rm))

proc emitSmull*(dest: var Bytes; rdLo, rdHi, rn, rm: Register) =
  dest.emitWide(0xFB80'u16 or reg(rn), (reg(rdLo) shl 12) or (reg(rdHi) shl 8) or reg(rm))

proc emitSdiv*(dest: var Bytes; rd, rn, rm: Register) =
  ## SDIV — present on ARMv7-M (Cortex-M3 and up), absent on ARMv6-M. Having it
  ## in hardware is a large part of why the backend targets M4 rather than M0.
  dest.emitWide(0xFB90'u16 or reg(rn), 0xF0F0'u16 or (reg(rd) shl 8) or reg(rm))

proc emitUdiv*(dest: var Bytes; rd, rn, rm: Register) =
  dest.emitWide(0xFBB0'u16 or reg(rn), 0xF0F0'u16 or (reg(rd) shl 8) or reg(rm))

proc emitMls*(dest: var Bytes; rd, rn, rm, ra: Register) =
  ## MLS rd, rn, rm, ra  =>  rd = ra - rn*rm. The remainder half of a division:
  ## ARMv7-M has no modulo instruction, so `a mod b` is `sdiv` then `mls`.
  dest.emitWide(0xFB00'u16 or reg(rn), (reg(ra) shl 12) or (reg(rd) shl 8) or 0x0010'u16 or reg(rm))

proc emitNeg*(dest: var Bytes; rd, rm: Register) =
  ## RSBS rd, rm, #0 — the 16-bit T1 negate, for low registers.
  if rd.isLow and rm.isLow:
    dest.emitNarrow 0x4240'u16 or (reg(rm) shl 3) or reg(rd)
  else:
    dest.emitDataImm(OpRsb, rd, rm, 0, true)

proc emitMvn*(dest: var Bytes; rd, rm: Register) =
  ## MVN rd, rm — bitwise NOT.
  if rd.isLow and rm.isLow:
    dest.emitNarrow 0x43C0'u16 or (reg(rm) shl 3) or reg(rd)
  else:
    dest.emitWide(0xEA6F'u16, (reg(rd) shl 8) or reg(rm))

# ── shifts ──────────────────────────────────────────────────────────────────

proc emitShiftImm(dest: var Bytes; op: uint16; rd, rm: Register; amount: int) =
  if rd.isLow and rm.isLow and amount < 32:
    let narrowOp = case op
                   of 0'u16: 0x0000'u16   # LSL
                   of 1'u16: 0x0800'u16   # LSR
                   else: 0x1000'u16       # ASR
    dest.emitNarrow narrowOp or (uint16(amount and 0x1F) shl 6) or (reg(rm) shl 3) or reg(rd)
  else:
    let imm3 = uint16((amount shr 2) and 0x7)
    let imm2 = uint16(amount and 0x3)
    dest.emitWide(0xEA4F'u16, (imm3 shl 12) or (reg(rd) shl 8) or (imm2 shl 6) or
                              (op shl 4) or reg(rm))

proc emitLslImm*(dest: var Bytes; rd, rm: Register; amount: int) = dest.emitShiftImm(0, rd, rm, amount)
proc emitLsrImm*(dest: var Bytes; rd, rm: Register; amount: int) = dest.emitShiftImm(1, rd, rm, amount)
proc emitAsrImm*(dest: var Bytes; rd, rm: Register; amount: int) = dest.emitShiftImm(2, rd, rm, amount)

proc emitShiftReg(dest: var Bytes; op: uint16; rd, rn, rm: Register) =
  dest.emitWide(0xFA00'u16 or (op shl 5) or reg(rn), 0xF000'u16 or (reg(rd) shl 8) or reg(rm))

proc emitLsl*(dest: var Bytes; rd, rn, rm: Register) = dest.emitShiftReg(0, rd, rn, rm)
proc emitLsr*(dest: var Bytes; rd, rn, rm: Register) = dest.emitShiftReg(1, rd, rn, rm)
proc emitAsr*(dest: var Bytes; rd, rn, rm: Register) = dest.emitShiftReg(2, rd, rn, rm)

# ── extends and byte reversal ───────────────────────────────────────────────

proc emitUxtb*(dest: var Bytes; rd, rm: Register) =
  if rd.isLow and rm.isLow: dest.emitNarrow 0xB2C0'u16 or (reg(rm) shl 3) or reg(rd)
  else: dest.emitWide(0xFA5F'u16, 0xF080'u16 or (reg(rd) shl 8) or reg(rm))
proc emitUxth*(dest: var Bytes; rd, rm: Register) =
  if rd.isLow and rm.isLow: dest.emitNarrow 0xB280'u16 or (reg(rm) shl 3) or reg(rd)
  else: dest.emitWide(0xFA1F'u16, 0xF080'u16 or (reg(rd) shl 8) or reg(rm))
proc emitSxtb*(dest: var Bytes; rd, rm: Register) =
  if rd.isLow and rm.isLow: dest.emitNarrow 0xB240'u16 or (reg(rm) shl 3) or reg(rd)
  else: dest.emitWide(0xFA4F'u16, 0xF080'u16 or (reg(rd) shl 8) or reg(rm))
proc emitSxth*(dest: var Bytes; rd, rm: Register) =
  if rd.isLow and rm.isLow: dest.emitNarrow 0xB200'u16 or (reg(rm) shl 3) or reg(rd)
  else: dest.emitWide(0xFA0F'u16, 0xF080'u16 or (reg(rd) shl 8) or reg(rm))

proc emitClz*(dest: var Bytes; rd, rm: Register) =
  dest.emitWide(0xFAB0'u16 or reg(rm), 0xF080'u16 or (reg(rd) shl 8) or reg(rm))
proc emitRbit*(dest: var Bytes; rd, rm: Register) =
  dest.emitWide(0xFA90'u16 or reg(rm), 0xF0A0'u16 or (reg(rd) shl 8) or reg(rm))
proc emitRev*(dest: var Bytes; rd, rm: Register) =
  if rd.isLow and rm.isLow: dest.emitNarrow 0xBA00'u16 or (reg(rm) shl 3) or reg(rd)
  else: dest.emitWide(0xFA90'u16 or reg(rm), 0xF080'u16 or (reg(rd) shl 8) or reg(rm))

# ── compares ────────────────────────────────────────────────────────────────

proc emitCmpReg*(dest: var Bytes; rn, rm: Register) =
  if rn.isLow and rm.isLow:
    dest.emitNarrow 0x4280'u16 or (reg(rm) shl 3) or reg(rn)
  else:
    dest.emitWide(0xEBB0'u16 or reg(rn), 0x0F00'u16 or reg(rm))

proc emitCmpImm*(dest: var Bytes; rn: Register; imm: uint32) =
  if rn.isLow and imm < 256:
    dest.emitNarrow 0x2800'u16 or (reg(rn) shl 8) or uint16(imm)
    return
  var enc: uint32
  if encodeModifiedImm(imm, enc):
    let (i, imm3, imm8) = splitImm12(enc)
    dest.emitWide(0xF1B0'u16 or (i shl 10) or reg(rn), (imm3 shl 12) or 0x0F00'u16 or imm8)
    return
  raise newException(ValueError, "thumb2: CMP immediate not encodable: " & $imm)

proc emitTstReg*(dest: var Bytes; rn, rm: Register) =
  if rn.isLow and rm.isLow: dest.emitNarrow 0x4200'u16 or (reg(rm) shl 3) or reg(rn)
  else: dest.emitWide(0xEA10'u16 or reg(rn), 0x0F00'u16 or reg(rm))

# ── loads and stores ────────────────────────────────────────────────────────

type
  MemWidth* = enum
    MemByte, MemHalf, MemWord

proc fitsLoadStoreImm*(offset: int32): bool {.inline.} =
  ## Whether `offset` fits an LDR/STR (immediate). The 32-bit forms take an
  ## unsigned 12-bit displacement or a T4 "negative offset" down to -255; beyond
  ## that the address has to be computed. `emitLoadStoreImm` RAISES rather than
  ## encode something else, so this is the check a caller must make first.
  offset >= -255 and offset < 4096

proc emitLoadStoreImm*(dest: var Bytes; rt, rn: Register; offset: int32;
                       width: MemWidth; isLoad: bool; signed = false) =
  ## LDR/STR (immediate) with a base register and a byte offset. Chooses the
  ## 16-bit form when everything fits (low registers, non-negative, correctly
  ## scaled offset), the 32-bit positive-offset form up to 4095, and the
  ## 32-bit T4 "negative offset" form for -255..-1.
  let scale = case width
              of MemByte: 0
              of MemHalf: 1
              of MemWord: 2
  if not signed and rt.isLow and rn.isLow and offset >= 0 and
     (offset and ((1'i32 shl scale) - 1)) == 0 and (offset shr scale) < 32:
    let base = case width
               of MemByte: (if isLoad: 0x7800'u16 else: 0x7000'u16)
               of MemHalf: (if isLoad: 0x8800'u16 else: 0x8000'u16)
               of MemWord: (if isLoad: 0x6800'u16 else: 0x6000'u16)
    dest.emitNarrow base or (uint16(offset shr scale) shl 6) or (reg(rn) shl 3) or reg(rt)
    return
  # SP-relative word access has its own 16-bit form with an 8-bit scaled offset.
  if not signed and width == MemWord and rt.isLow and rn == SP and
     offset >= 0 and (offset and 3) == 0 and (offset shr 2) < 256:
    dest.emitNarrow (if isLoad: 0x9800'u16 else: 0x9000'u16) or
                    (reg(rt) shl 8) or uint16(offset shr 2)
    return
  let sizeBits = case width
                 of MemByte: 0x0000'u16
                 of MemHalf: 0x0020'u16
                 of MemWord: 0x0040'u16
  let signBit = if signed: 0x0100'u16 else: 0'u16
  if offset >= 0 and offset < 4096:
    dest.emitWide(0xF880'u16 or sizeBits or signBit or (if isLoad: 0x0010'u16 else: 0'u16) or reg(rn),
                  (reg(rt) shl 12) or uint16(offset))
  elif offset < 0 and offset > -256:
    dest.emitWide(0xF800'u16 or sizeBits or signBit or (if isLoad: 0x0010'u16 else: 0'u16) or reg(rn),
                  (reg(rt) shl 12) or 0x0C00'u16 or uint16(-offset))
  else:
    raise newException(ValueError, "thumb2: load/store offset out of range: " & $offset)

proc emitLdr*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemWord, isLoad = true)
proc emitStr*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemWord, isLoad = false)
proc emitLdrb*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemByte, isLoad = true)
proc emitStrb*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemByte, isLoad = false)
proc emitLdrh*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemHalf, isLoad = true)
proc emitStrh*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemHalf, isLoad = false)
proc emitLdrsb*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemByte, isLoad = true, signed = true)
proc emitLdrsh*(dest: var Bytes; rt, rn: Register; offset: int32) =
  dest.emitLoadStoreImm(rt, rn, offset, MemHalf, isLoad = true, signed = true)

proc emitLoadStoreReg*(dest: var Bytes; rt, rn, rm: Register; width: MemWidth;
                       isLoad: bool; shift = 0; signed = false) =
  ## LDR/STR rt, [rn, rm, LSL #shift] — the scaled-index form.
  if not signed and shift == 0 and rt.isLow and rn.isLow and rm.isLow:
    let base = case width
               of MemByte: (if isLoad: 0x5C00'u16 else: 0x5400'u16)
               of MemHalf: (if isLoad: 0x5A00'u16 else: 0x5200'u16)
               of MemWord: (if isLoad: 0x5800'u16 else: 0x5000'u16)
    dest.emitNarrow base or (reg(rm) shl 6) or (reg(rn) shl 3) or reg(rt)
    return
  let sizeBits = case width
                 of MemByte: 0x0000'u16
                 of MemHalf: 0x0020'u16
                 of MemWord: 0x0040'u16
  let signBit = if signed: 0x0100'u16 else: 0'u16
  dest.emitWide(0xF800'u16 or sizeBits or signBit or (if isLoad: 0x0010'u16 else: 0'u16) or reg(rn),
                (reg(rt) shl 12) or (uint16(shift and 0x3) shl 4) or reg(rm))

proc emitPush*(dest: var Bytes; regs: set[Register]) =
  ## PUSH {regs}. The 16-bit T1 form covers r0–r7 plus LR; anything else needs
  ## the 32-bit STMDB form.
  var mask = 0'u16
  for r in regs: mask = mask or (1'u16 shl ord(r))
  if (mask and 0xBF00'u16) == 0 or (mask and not 0x40FF'u16) == 0:
    dest.emitNarrow 0xB400'u16 or (if LR in regs: 0x0100'u16 else: 0'u16) or (mask and 0xFF)
  else:
    dest.emitWide(0xE92D'u16, mask)

proc emitPop*(dest: var Bytes; regs: set[Register]) =
  ## POP {regs}. Popping directly into PC is the idiomatic Thumb return from a
  ## frame that pushed LR.
  var mask = 0'u16
  for r in regs: mask = mask or (1'u16 shl ord(r))
  if (mask and not 0x80FF'u16) == 0:
    dest.emitNarrow 0xBC00'u16 or (if PC in regs: 0x0100'u16 else: 0'u16) or (mask and 0xFF)
  else:
    dest.emitWide(0xE8BD'u16, mask)

# ── control flow ────────────────────────────────────────────────────────────

proc emitBx*(dest: var Bytes; rm: Register) =
  ## BX rm — branch and exchange. `bx lr` is the ordinary Thumb return.
  dest.emitNarrow 0x4700'u16 or (reg(rm) shl 3)

proc emitBlx*(dest: var Bytes; rm: Register) =
  ## BLX rm — an indirect call.
  dest.emitNarrow 0x4780'u16 or (reg(rm) shl 3)

proc emitRet*(dest: var Bytes) = dest.emitBx(LR)

proc emitNop*(dest: var Bytes) = dest.emitNarrow 0xBF00'u16

proc emitBkpt*(dest: var Bytes; imm: uint8) =
  ## BKPT #imm8. With imm8 = 0xAB this IS the ARM semihosting call on M-profile:
  ## operation in r0, parameter block in r1, result back in r0.
  dest.emitNarrow 0xBE00'u16 or uint16(imm)

proc emitWfi*(dest: var Bytes) = dest.emitWide(0xF3AF'u16, 0x8003'u16)

# ── branches with relocations ───────────────────────────────────────────────
# Every branch is emitted in its WIDE form and the displacement patched later.
# Choosing the narrow form up front would be a size optimization that the
# relocation pass cannot undo once a later branch has moved; `relocs` shrinks
# them afterwards if it wants to, exactly as it does for x86-64's jumps.

proc emitB*(dest: var Buffer; target: LabelId) =
  ## B.W target — unconditional, ±16 MB.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTB, 4)
  dest.data.emitWide(0xF000'u16, 0xB800'u16)

proc emitBl*(dest: var Buffer; target: LabelId) =
  ## BL target — a call, ±16 MB. Sets LR to the return address WITH the Thumb bit.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTBL, 4)
  dest.data.emitWide(0xF000'u16, 0xF800'u16)

proc emitBcond*(dest: var Buffer; cond: Condition; target: LabelId) =
  ## B<cond>.W target — ±1 MB, a narrower reach than the unconditional form
  ## because four of the displacement bits are spent on the condition.
  assert cond != CondAL
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTBcond, 4)
  dest.data.emitWide(0xF000'u16 or (uint16(ord(cond)) shl 6), 0x8000'u16)

proc emitAdr*(dest: var Buffer; rd: Register; target: LabelId) =
  ## ADR rd, target — PC-relative address materialization, ±4 KB. Emitted as
  ## ADD rd, pc, #imm12 and patched once the label's position is known.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTADR, 4)
  dest.data.emitWide(0xF20F'u16, (reg(rd) shl 8))

proc emitMovwMovtFunc*(dest: var Buffer; rd: Register; target: LabelId) =
  ## MOVW+MOVT rd, =target|1 — a CODE address, with the Thumb-state bit set.
  ## Use for anything that will be reached by `blx`/`bx`; `emitMovwMovtAbs` is
  ## for data and must NOT set it.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTMovwMovtFunc, 8)
  dest.data.emitMovImm16(rd, 0)
  dest.data.emitMovt(rd, 0)

proc emitMovwMovtAbs*(dest: var Buffer; rd: Register; target: LabelId) =
  ## MOVW+MOVT rd, =target — materialize a label's ABSOLUTE address, with no
  ## reach limit. What `emitAdr` cannot do beyond 4 KB, and what a bare-metal
  ## image can use freely because its load address is fixed at link time.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkTMovwMovt, 8)
  dest.data.emitMovImm16(rd, 0)
  dest.data.emitMovt(rd, 0)

# ── FPv4-SP (single precision) ──────────────────────────────────────────────
#
# Cortex-M4F's FPU is SINGLE PRECISION ONLY. The register file is s0–s31 and
# every operation below is `.f32`; there is no `.f64` form to fall back on, so a
# double must be refused rather than lowered (see `checkRegWidthM`).
#
# Every VFP instruction is 32-bit and encodes its register number SPLIT: the top
# four bits go in the instruction's `Vd`/`Vn`/`Vm` field and the low bit in a
# separate `D`/`N`/`M` bit — and, confusingly, the split is the OTHER way round
# for double-precision registers. `hi`/`lo` below name the two halves so the
# split is written once per operand rather than at each encoder.

template fHi(r: FloatRegister): uint16 = uint16(ord(r) shr 1)   ## the Vd/Vn/Vm field
template fLo(r: FloatRegister): uint16 = uint16(ord(r) and 1)   ## the D/N/M bit

proc emitVfpData(dest: var Bytes; base: uint16; op2: uint16;
                 sd, sn, sm: FloatRegister) =
  ## The three-operand `.f32` data-processing shape: `<op> Sd, Sn, Sm`.
  ## `base` carries bits 27..20 of the opcode, `op2` bit 6 (the add/sub bit).
  dest.emitWide(base or (fLo(sd) shl 6) or fHi(sn),
                (fHi(sd) shl 12) or 0x0A00'u16 or (fLo(sn) shl 7) or op2 or
                (fLo(sm) shl 5) or fHi(sm))

proc emitVadd*(dest: var Bytes; sd, sn, sm: FloatRegister) =
  dest.emitVfpData(0xEE30'u16, 0'u16, sd, sn, sm)
proc emitVsub*(dest: var Bytes; sd, sn, sm: FloatRegister) =
  dest.emitVfpData(0xEE30'u16, 0x0040'u16, sd, sn, sm)
proc emitVmul*(dest: var Bytes; sd, sn, sm: FloatRegister) =
  dest.emitVfpData(0xEE20'u16, 0'u16, sd, sn, sm)
proc emitVdiv*(dest: var Bytes; sd, sn, sm: FloatRegister) =
  dest.emitVfpData(0xEE80'u16, 0'u16, sd, sn, sm)

proc emitVfpUnary(dest: var Bytes; opc1: uint16; opc3: uint16;
                  sd, sm: FloatRegister) =
  ## The two-operand "other" group: `<op> Sd, Sm`, selected by `opc2` (bits
  ## 19..16) and `opc3` (bits 7..6). The two pairs differ ONLY in `opc3`:
  ## `vmov`/`vabs` share opc2 = 0 and `vneg`/`vsqrt` share opc2 = 1, so swapping
  ## an opc3 turns a negate into a square root — which is exactly as quiet as it
  ## sounds (`-3.0` came back as `1.732`).
  dest.emitWide(0xEEB0'u16 or (fLo(sd) shl 6) or opc1,
                (fHi(sd) shl 12) or 0x0A00'u16 or opc3 or (fLo(sm) shl 5) or fHi(sm))

proc emitVmovReg*(dest: var Bytes; sd, sm: FloatRegister) =
  if sd != sm: dest.emitVfpUnary(0x0'u16, 0x0040'u16, sd, sm)
proc emitVneg*(dest: var Bytes; sd, sm: FloatRegister) =
  dest.emitVfpUnary(0x1'u16, 0x0040'u16, sd, sm)
proc emitVabs*(dest: var Bytes; sd, sm: FloatRegister) =
  dest.emitVfpUnary(0x0'u16, 0x00C0'u16, sd, sm)
proc emitVsqrt*(dest: var Bytes; sd, sm: FloatRegister) =
  dest.emitVfpUnary(0x1'u16, 0x00C0'u16, sd, sm)

proc emitVcmp*(dest: var Bytes; sd, sm: FloatRegister) =
  ## VCMP.F32 — the QUIET compare (`vcmp`, not `vcmpe`): an unordered pair sets
  ## the flags without raising Invalid Operation, which is what `==`/`<` on a NaN
  ## must do.
  dest.emitVfpUnary(0x4'u16, 0x0040'u16, sd, sm)

proc emitVmrsApsr*(dest: var Bytes) =
  ## `VMRS APSR_nzcv, FPSCR` — move the FPU's comparison result into the integer
  ## flags. VCMP writes FPSCR, and the conditional branches read APSR, so every
  ## float compare is this pair; there is no float-condition branch.
  dest.emitWide(0xEEF1'u16, 0xFA10'u16)

proc emitVmovToFp*(dest: var Bytes; sn: FloatRegister; rt: Register) =
  ## `VMOV Sn, Rt` — the BIT PATTERN of a core register into an fp one.
  dest.emitWide(0xEE00'u16 or fHi(sn),
                (uint16(ord(rt)) shl 12) or 0x0A10'u16 or (fLo(sn) shl 7))

proc emitVmovFromFp*(dest: var Bytes; rt: Register; sn: FloatRegister) =
  ## `VMOV Rt, Sn` — and back.
  dest.emitWide(0xEE10'u16 or fHi(sn),
                (uint16(ord(rt)) shl 12) or 0x0A10'u16 or (fLo(sn) shl 7))

proc emitVcvtToF32*(dest: var Bytes; sd, sm: FloatRegister; signed: bool) =
  ## `VCVT.F32.S32` / `VCVT.F32.U32` — the integer in `sm`'s bit pattern to a
  ## float in `sd`. The source is an fp REGISTER: FPv4 converts in the FPU, so an
  ## integer has to be moved across with `VMOV` first.
  dest.emitVfpUnary(0x8'u16, (if signed: 0x00C0'u16 else: 0x0040'u16), sd, sm)

proc emitVcvtFromF32*(dest: var Bytes; sd, sm: FloatRegister; signed: bool) =
  ## `VCVT.S32.F32` / `VCVT.U32.F32`, rounding TOWARD ZERO — C's rule, and Leng's.
  dest.emitVfpUnary((if signed: 0xD'u16 else: 0xC'u16), 0x00C0'u16, sd, sm)

proc fitsVldrVstrImm*(offset: int32): bool {.inline.} =
  ## VLDR/VSTR take a WORD-scaled 8-bit displacement: +/-1020, and 4-aligned.
  ## Much narrower than the integer `ldr`'s 4095, so a float in a big frame needs
  ## its address computed where an integer would not.
  (offset and 3) == 0 and offset >= -1020 and offset <= 1020

proc emitVldrVstr*(dest: var Bytes; sd: FloatRegister; rn: Register;
                   offset: int32; isLoad: bool) =
  ## VLDR/VSTR `.32`. The displacement is a WORD offset in an 8-bit field, so the
  ## reach is ±1020 bytes and it must be 4-aligned — narrower than the integer
  ## `ldr`'s 4095, and a frame beyond it is an error rather than a wrong address.
  if (offset and 3) != 0:
    raise newException(ValueError, "thumb2: vldr/vstr offset not word-aligned: " & $offset)
  let u = if offset >= 0: 1'u16 else: 0'u16
  let mag = (if offset >= 0: offset else: -offset) shr 2
  if mag > 255:
    raise newException(ValueError, "thumb2: vldr/vstr offset out of range: " & $offset)
  dest.emitWide(0xED00'u16 or (u shl 7) or (fLo(sd) shl 6) or
                (if isLoad: 0x10'u16 else: 0'u16) or uint16(ord(rn)),
                (fHi(sd) shl 12) or 0x0A00'u16 or uint16(mag))

proc emitVldr*(dest: var Bytes; sd: FloatRegister; rn: Register; offset: int32) =
  dest.emitVldrVstr(sd, rn, offset, isLoad = true)
proc emitVstr*(dest: var Bytes; sd: FloatRegister; rn: Register; offset: int32) =
  dest.emitVldrVstr(sd, rn, offset, isLoad = false)

# ── disassembly aid ─────────────────────────────────────────────────────────

proc emitDsb*(dest: var Bytes) =
  ## DSB SY — every memory access before it completes before anything after it
  ## starts.
  dest.emitWide(0xF3BF'u16, 0x8F4F'u16)

proc emitIsb*(dest: var Bytes) =
  ## ISB SY — flush the pipeline. What makes a write to CPACR (enabling the FPU)
  ## visible to the instruction that follows rather than to whatever the core has
  ## already fetched.
  dest.emitWide(0xF3BF'u16, 0x8F6F'u16)

proc `$`*(r: Register): string =
  case r
  of SP: "sp"
  of LR: "lr"
  of PC: "pc"
  else: "r" & $ord(r)

proc `$`*(r: FloatRegister): string = "s" & $ord(r)
