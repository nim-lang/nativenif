# Nifasm - ARM64 Binary Assembler
# A dependency-free ARM64 assembler that emits binary instruction bytes


import ../core/[buffers, relocs]

type
  # ARM64 64-bit general purpose registers
  Register* = enum
    X0 = 0, X1 = 1, X2 = 2, X3 = 3, X4 = 4, X5 = 5, X6 = 6, X7 = 7,
    X8 = 8, X9 = 9, X10 = 10, X11 = 11, X12 = 12, X13 = 13, X14 = 14, X15 = 15,
    X16 = 16, X17 = 17, X18 = 18, X19 = 19, X20 = 20, X21 = 21, X22 = 22, X23 = 23,
    X24 = 24, X25 = 25, X26 = 26, X27 = 27, X28 = 28, X29 = 29, X30 = 30,
    SP = 31  # Stack pointer

  # ARM64 scalar floating-point / SIMD registers (Dn = 64-bit double view of Vn)
  FloatRegister* = enum
    D0 = 0, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12, D13, D14, D15,
    D16, D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31

  # ARM64 32-bit register variants
  Register32* = enum
    W0 = 0, W1 = 1, W2 = 2, W3 = 3, W4 = 4, W5 = 5, W6 = 6, W7 = 7,
    W8 = 8, W9 = 9, W10 = 10, W11 = 11, W12 = 12, W13 = 13, W14 = 14, W15 = 15,
    W16 = 16, W17 = 17, W18 = 18, W19 = 19, W20 = 20, W21 = 21, W22 = 22, W23 = 23,
    W24 = 24, W25 = 25, W26 = 26, W27 = 27, W28 = 28, W29 = 29, W30 = 30,
    WSP = 31  # Stack pointer (32-bit)

# Special register aliases
const
  LR* = X30  # Link Register
  FP* = X29  # Frame Pointer
  XZR* = 31  # Zero register (when used in certain contexts)

type
  # ARM64 condition codes (the `cond` field of B.cond/CSEL/CSINC/...)
  Condition* = enum
    CondEQ = 0, CondNE = 1, CondHS = 2, CondLO = 3,
    CondMI = 4, CondPL = 5, CondVS = 6, CondVC = 7,
    CondHI = 8, CondLS = 9, CondGE = 10, CondLT = 11,
    CondGT = 12, CondLE = 13, CondAL = 14

proc invert*(c: Condition): Condition =
  ## The complementary condition (EQ<->NE, LT<->GE, ...). AL has no inverse.
  assert c != CondAL
  Condition(ord(c) xor 1)

type
  # Memory operand for load/store instructions
  MemoryOperand* = object
    base*: Register
    offset*: int32
    hasIndex*: bool
    index*: Register
    shift*: int  # 0, 1, 2, or 3 (LSL #0, #1, #2, #3)

# ARM64 instruction encoding helpers
proc encodeReg(r: Register): uint32 =
  uint32(ord(r))

proc encodeReg32(r: Register32): uint32 =
  uint32(ord(r))

# MOV instruction - register to register
proc emitMov*(dest: var Bytes; rd, rn: Register) =
  ## Emit MOV instruction: MOV rd, rn (alias for ORR rd, XZR, rn)
  # ORR Xd, XZR, Xm: 1010 1010 000m mmmm 0000 00nn nnnd dddd
  # The Rn field (bits 9..5) must be XZR (31); leaving it 0 would make this
  # `ORR Xd, X0, Xm` (i.e. `Xd = X0 | Xm`), not a plain move.
  let instr = 0xAA000000'u32 or
              (encodeReg(rn) shl 16) or
              (0x1F'u32 shl 5) or
              (encodeReg(rd) shl 0)
  dest.addUint32(instr)

# MOV immediate (uses MOVZ)
proc emitMovImm*(dest: var Bytes; rd: Register; imm: uint16) =
  ## Emit MOV instruction: MOV rd, #imm (MOVZ)
  # MOVZ Xd, #imm: 1101 0010 100i iiii iiii iiii iiid dddd
  let instr = 0xD2800000'u32 or
              (uint32(imm) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# MOVK instruction (move with keep)
proc emitMovK(dest: var Bytes; rd: Register; imm: uint16; shift: uint8) =
  ## Emit MOVK instruction: MOVK rd, #imm, LSL #shift
  ## shift must be 0, 16, 32, or 48
  # MOVK Xd, #imm, LSL #shift: 1111 0010 100i iiii iiii iiii iiid dddd
  # The shift is encoded in bits 21-22: shift/16
  let hw = (shift div 16) and 0x3
  let instr = 0xF2800000'u32 or
              (uint32(hw) shl 21) or
              (uint32(imm) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# Load a 64-bit immediate value using MOVZ + MOVK
proc emitMovImm64*(dest: var Bytes; rd: Register; imm: uint64) =
  ## Emit instructions to load a 64-bit immediate value into a register
  ## Uses MOVZ for the first non-zero chunk and MOVK for subsequent chunks
  var first = true
  for shift in countup(0, 48, 16):
    let chunk = uint16((imm shr shift) and 0xFFFF)
    if chunk != 0 or first:
      if first:
        emitMovImm(dest, rd, chunk)
        first = false
      else:
        emitMovK(dest, rd, chunk, uint8(shift))

# The `sf` bit (bit 31) selects the 64-bit (Xd, sf=1) vs 32-bit (Wd, sf=0) form for
# the add/sub/mul data-processing encodings below. The base opcodes bake in sf=1; the
# 32-bit W-form (auto zero-extends the result into bits 32..63) is the same encoding
# with bit 31 cleared. Callers pass `w = true` for a 32-bit result.
const SfBit = 0x80000000'u32

# ADD instruction - register + register
proc emitAdd*(dest: var Bytes; rd, rn, rm: Register; w = false) =
  ## Emit ADD instruction: ADD rd, rn, rm  (Wd form when `w`)
  # ADD Xd, Xn, Xm: 1000 1011 000m mmmm 0000 00nn nnnd dddd
  var instr = 0x8B000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

proc emitAddShifted*(dest: var Bytes; rd, rn, rm: Register; shift: uint8) =
  ## Emit ADD (shifted register): ADD rd, rn, rm, LSL #shift
  # Same encoding as emitAdd with the imm6 shift-amount field (bits 10-15) set.
  let instr = 0x8B000000'u32 or
              (encodeReg(rm) shl 16) or
              ((uint32(shift) and 0x3F) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# ADD immediate
proc emitAddImm*(dest: var Bytes; rd, rn: Register; imm: uint16; w = false) =
  ## Emit ADD instruction: ADD rd, rn, #imm  (Wd form when `w`)
  # ADD Xd, Xn, #imm: 1001 0001 00ii iiii iiii iinn nnnd dddd
  var instr = 0x91000000'u32 or
              (uint32(imm) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

const ShBit12* = 0x00400000'u32
  ## The `sh` bit (22) of ADD/SUB (immediate): when set, the 12-bit immediate is
  ## shifted left by 12. Together, an unshifted and a shifted instruction encode any
  ## 24-bit value — which is how a frame larger than 4095 bytes is reserved (a single
  ## imm12 cannot hold it, and the frame size is only known at patch time).

proc emitAddImmShifted12*(dest: var Bytes; rd, rn: Register; imm: uint16) =
  ## `ADD rd, rn, #imm, LSL #12` — the high half of a 24-bit immediate.
  dest.addUint32(0x91000000'u32 or ShBit12 or
                 (uint32(imm) shl 10) or (encodeReg(rn) shl 5) or encodeReg(rd))

proc emitSubImmShifted12*(dest: var Bytes; rd, rn: Register; imm: uint16) =
  ## `SUB rd, rn, #imm, LSL #12` — the high half of a 24-bit immediate.
  dest.addUint32(0xD1000000'u32 or ShBit12 or
                 (uint32(imm) shl 10) or (encodeReg(rn) shl 5) or encodeReg(rd))

proc emitAddExtended*(dest: var Bytes; rd, rn, rm: Register; shift: uint8 = 0) =
  ## Emit ADD (extended register): ADD rd, rn|SP, rm, UXTX #shift.
  ## Unlike the shifted-register ADD (`emitAdd`/`emitAddShifted`), the extended form
  ## accepts the stack pointer as `rn` — register 31 there means SP, not XZR — so it is
  ## the only way to compute `dest = SP + rm` (e.g. the address of a stack array element
  ## with a register index). `UXTX #shift` is a full 64-bit add with an optional LSL
  ## (shift 0..4). ADD Xd, Xn|SP, Xm, UXTX #shift:
  ##   1000 1011 001m mmmm 011s ss nn nnnd dddd   (option=011=UXTX, imm3=shift)
  let instr = 0x8B200000'u32 or
              (encodeReg(rm) shl 16) or
              (0b011'u32 shl 13) or
              ((uint32(shift) and 0x7) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# SUB instruction - register - register
proc emitSub*(dest: var Bytes; rd, rn, rm: Register; w = false) =
  ## Emit SUB instruction: SUB rd, rn, rm  (Wd form when `w`)
  # SUB Xd, Xn, Xm: 1100 1011 000m mmmm 0000 00nn nnnd dddd
  var instr = 0xCB000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

# SUB immediate
proc emitSubImm*(dest: var Bytes; rd, rn: Register; imm: uint16; w = false) =
  ## Emit SUB instruction: SUB rd, rn, #imm  (Wd form when `w`)
  # SUB Xd, Xn, #imm: 1101 0001 00ii iiii iiii iinn nnnd dddd
  var instr = 0xD1000000'u32 or
              (uint32(imm) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

# MUL instruction
proc emitMul*(dest: var Bytes; rd, rn, rm: Register; w = false) =
  ## Emit MUL instruction: MUL rd, rn, rm (alias for MADD rd, rn, rm, XZR)  (Wd form when `w`)
  # MADD Xd, Xn, Xm, XZR: 1001 1011 000m mmmm 0111 11nn nnnd dddd
  var instr = 0x9B007C00'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

# SMULH / UMULH — 64×64→high-64 multiply (top half of the 128-bit product).
# Same 3-source data-processing family as MADD/MUL, with op31 = 010 (signed) /
# 110 (unsigned) and Ra = XZR.
proc emitSmulh*(dest: var Bytes; rd, rn, rm: Register) =
  ## SMULH rd, rn, rm: 1001 1011 010m mmmm 0111 11nn nnnd dddd
  let instr = 0x9B407C00'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitUmulh*(dest: var Bytes; rd, rn, rm: Register) =
  ## UMULH rd, rn, rm: 1001 1011 110m mmmm 0111 11nn nnnd dddd
  let instr = 0x9BC07C00'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# SDIV instruction (signed divide)
proc emitSdiv*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit SDIV instruction: SDIV rd, rn, rm
  # SDIV Xd, Xn, Xm: 1001 1010 110m mmmm 0000 11nn nnnd dddd
  let instr = 0x9AC00C00'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# UDIV instruction (unsigned divide)
proc emitUdiv*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit UDIV instruction: UDIV rd, rn, rm
  # UDIV Xd, Xn, Xm: 1001 1010 110m mmmm 0000 10nn nnnd dddd
  let instr = 0x9AC00800'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# Logical instructions
proc emitAnd*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit AND instruction: AND rd, rn, rm
  # AND Xd, Xn, Xm: 1000 1010 000m mmmm 0000 00nn nnnd dddd
  let instr = 0x8A000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitOrr*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit ORR instruction: ORR rd, rn, rm
  # ORR Xd, Xn, Xm: 1010 1010 000m mmmm 0000 00nn nnnd dddd
  let instr = 0xAA000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitEor*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit EOR instruction: EOR rd, rn, rm (XOR)
  # EOR Xd, Xn, Xm: 1100 1010 000m mmmm 0000 00nn nnnd dddd
  let instr = 0xCA000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# ── logical IMMEDIATE (the "bitmask immediate" encoding) ────────────────────
# AArch64's `and`/`orr`/`eor` take an immediate directly, but not an arbitrary
# one: the field is `N:immr:imms`, which denotes a pattern of `n` ones rotated
# right by `immr` inside an element of 2/4/8/16/32/64 bits, repeated to fill the
# register. Every mask a bitfield extraction produces — 0xff, 0xf, 0x7, 0x1ff,
# 0x3fff — is one, which is why the form exists and why materializing the
# constant into a register first (`mov b,#0xff; and x,b`) is pure waste.

proc encodeLogicalImm(value: uint64; encoding: var uint32): bool =
  ## Compute the `N:immr:imms` field (13 bits, N in bit 12) for the 64-bit
  ## logical-immediate forms, or return false when `value` is not representable.
  ## All-zeros and all-ones are the two excluded patterns — they need no mask.
  ##
  ## The classic derivation: the pattern repeats, so first find the smallest
  ## element size whose halves differ; within that element the value must be a
  ## contiguous run of ones (possibly wrapping), and `immr` is the rotation that
  ## brings it back to the low bits.
  if value == 0'u64 or value == not 0'u64: return false

  var size = 64
  while size > 2:
    size = size div 2
    let mask = (1'u64 shl size) - 1
    if (value and mask) != ((value shr size) and mask):
      size = size * 2
      break

  let mask = (not 0'u64) shr (64 - size)
  var v = value and mask

  proc trailingZeros(x: uint64): int =
    result = 0
    var t = x
    while (t and 1'u64) == 0'u64: (t = t shr 1; inc result)
  proc trailingOnes(x: uint64): int =
    result = 0
    var t = x
    while (t and 1'u64) == 1'u64: (t = t shr 1; inc result)
  proc leadingOnes(x: uint64): int =
    result = 0
    var t = x
    while result < 64 and (t and (1'u64 shl 63)) != 0'u64: (t = t shl 1; inc result)
  proc isShiftedMask(x: uint64): bool =
    ## `x` is a single contiguous run of ones (and non-zero).
    x != 0'u64 and ((x + (x and (not x + 1))) and x) == 0'u64

  var rot, runLen: int
  if isShiftedMask(v):
    rot = trailingZeros(v)
    runLen = trailingOnes(v shr rot)
  else:
    v = v or not mask                        # the run wraps: work on its complement
    if not isShiftedMask(not v): return false
    let clo = leadingOnes(v)
    rot = 64 - clo
    runLen = clo + trailingOnes(v) - (64 - size)

  let immr = uint32((size - rot) and (size - 1))
  var nimms = uint32(not (size - 1)) shl 1
  nimms = nimms or uint32(runLen - 1)
  let n = ((nimms shr 6) and 1) xor 1
  encoding = (n shl 12) or (immr shl 6) or (nimms and 0x3F'u32)
  result = true

proc isLogicalImm*(value: uint64): bool {.inline.} =
  var enc: uint32
  encodeLogicalImm(value, enc)

proc emitLogicalImm(dest: var Bytes; base: uint32; rd, rn: Register; value: uint64) =
  ## `<op> rd, rn, #value` — `base` carries sf+opc (see the three wrappers).
  var enc: uint32 = 0
  doAssert encodeLogicalImm(value, enc), "not a logical immediate: " & $value
  let instr = base or (enc shl 10) or (encodeReg(rn) shl 5) or encodeReg(rd)
  dest.addUint32(instr)

proc emitAndImm*(dest: var Bytes; rd, rn: Register; value: uint64) =
  ## AND Xd, Xn, #imm: 1001 0010 0Nrr rrrr ssss ssnn nnnd dddd
  emitLogicalImm(dest, 0x92000000'u32, rd, rn, value)

proc emitOrrImm*(dest: var Bytes; rd, rn: Register; value: uint64) =
  ## ORR Xd, Xn, #imm: 1011 0010 0Nrr rrrr ssss ssnn nnnd dddd
  emitLogicalImm(dest, 0xB2000000'u32, rd, rn, value)

proc emitEorImm*(dest: var Bytes; rd, rn: Register; value: uint64) =
  ## EOR Xd, Xn, #imm: 1101 0010 0Nrr rrrr ssss ssnn nnnd dddd
  emitLogicalImm(dest, 0xD2000000'u32, rd, rn, value)

# Shift instructions
proc emitLsl*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit LSL instruction: LSL rd, rn, rm (logical shift left)
  # LSLV Xd, Xn, Xm: 1001 1010 110m mmmm 0010 00nn nnnd dddd
  let instr = 0x9AC02000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitLslImm*(dest: var Bytes; rd, rn: Register; shift: uint8) =
  ## Emit LSL instruction: LSL rd, rn, #shift
  # UBFM Xd, Xn, #(-shift MOD 64), #(63-shift)
  let negShift = (64'u32 - uint32(shift)) and 0x3F
  let width = 63'u32 - uint32(shift)
  let instr = 0xD3400000'u32 or
              (negShift shl 16) or
              (width shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitLsr*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit LSR instruction: LSR rd, rn, rm (logical shift right)
  # LSRV Xd, Xn, Xm: 1001 1010 110m mmmm 0010 01nn nnnd dddd
  let instr = 0x9AC02400'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitLsrImm*(dest: var Bytes; rd, rn: Register; shift: uint8) =
  ## Emit LSR instruction: LSR rd, rn, #shift
  # UBFM Xd, Xn, #shift, #63
  let instr = 0xD3400000'u32 or
              (uint32(shift) shl 16) or
              (63'u32 shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitAsr*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit ASR instruction: ASR rd, rn, rm (arithmetic shift right)
  # ASRV Xd, Xn, Xm: 1001 1010 110m mmmm 0010 10nn nnnd dddd
  let instr = 0x9AC02800'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitAsrImm*(dest: var Bytes; rd, rn: Register; shift: uint8) =
  ## Emit ASR rd, rn, #shift — SBFM Xd, Xn, #shift, #63 (sign-extending).
  let instr = 0x93400000'u32 or
              (uint32(shift) shl 16) or
              (63'u32 shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# Compare instructions
proc emitCmp*(dest: var Bytes; rn, rm: Register) =
  ## Emit CMP instruction: CMP rn, rm (alias for SUBS XZR, rn, rm)
  # SUBS XZR, Xn, Xm: 1110 1011 000m mmmm 0000 00nn nnn1 1111
  let instr = 0xEB00001F'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5)
  dest.addUint32(instr)

proc emitCmpImm*(dest: var Bytes; rn: Register; imm: uint16) =
  ## Emit CMP instruction: CMP rn, #imm
  # SUBS XZR, Xn, #imm: 1111 0001 00ii iiii iiii iinn nnn1 1111
  let instr = 0xF100001F'u32 or
              (uint32(imm) shl 10) or
              (encodeReg(rn) shl 5)
  dest.addUint32(instr)

# NEG instruction
proc emitNeg*(dest: var Bytes; rd, rm: Register) =
  ## Emit NEG instruction: NEG rd, rm (alias for SUB rd, XZR, rm)
  # SUB Xd, XZR, Xm: 1100 1011 000m mmmm 0000 0011 111d dddd
  let instr = 0xCB0003E0'u32 or
              (encodeReg(rm) shl 16) or
              encodeReg(rd)
  dest.addUint32(instr)

# Data-processing (1 source): CLZ / RBIT / REV. All share the
# `sf 1 0 11010110 00000 000ooo Rn Rd` shape and differ only in the opcode field.
#   RBIT Xd, Xn : 1101 1010 1100 0000 0000 00nn nnnd dddd  (0xDAC00000)
#   REV  Xd, Xn : ... 0000 11..                            (0xDAC00C00)
#   CLZ  Xd, Xn : ... 0001 00..                            (0xDAC01000)
# The W-form clears the sf bit; REV's W-form is `REV32`-shaped (opcode 0b000010),
# so it is encoded separately rather than by clearing sf alone.
proc emitRbit*(dest: var Bytes; rd, rn: Register; w = false) =
  var instr = 0xDAC00000'u32 or (encodeReg(rn) shl 5) or encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

proc emitClz*(dest: var Bytes; rd, rn: Register; w = false) =
  var instr = 0xDAC01000'u32 or (encodeReg(rn) shl 5) or encodeReg(rd)
  if w: instr = instr and not SfBit
  dest.addUint32(instr)

proc emitRev*(dest: var Bytes; rd, rn: Register; w = false) =
  ## REV Xd, Xn (64-bit, opcode 0b000011) or REV Wd, Wn (32-bit, opcode 0b000010).
  let instr =
    if w: (0x5AC00800'u32 or (encodeReg(rn) shl 5) or encodeReg(rd))
    else: (0xDAC00C00'u32 or (encodeReg(rn) shl 5) or encodeReg(rd))
  dest.addUint32(instr)

# Load/Store instructions
proc emitLdr*(dest: var Bytes; rt: Register; rn: Register; offset: int32) =
  ## Emit LDR instruction: LDR rt, [rn, #offset]
  ## Offset must be 8-byte aligned and in range [0, 32760]
  let scaledOffset = offset div 8
  if scaledOffset < 0 or scaledOffset > 4095:
    raise newException(ValueError, "LDR offset out of range")
  # LDR Xt, [Xn, #offset]: 1111 1001 01ii iiii iiii iinn nnnt tttt
  let instr = 0xF9400000'u32 or
              (uint32(scaledOffset) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rt)
  dest.addUint32(instr)

proc emitLdrReg(dest: var Bytes; rt, rn, rm: Register; shift: int) =
  ## LDR rt, [rn, rm, LSL #shift] — register offset (shift 0 or 3 for 64-bit).
  let s = if shift == 3: 1'u32 else: 0'u32
  let instr = 0xF8606800'u32 or (s shl 12) or
              (encodeReg(rm) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt)
  dest.addUint32(instr)

proc emitStrReg(dest: var Bytes; rt, rn, rm: Register; shift: int) =
  ## STR rt, [rn, rm, LSL #shift] — register offset (shift 0 or 3 for 64-bit).
  let s = if shift == 3: 1'u32 else: 0'u32
  let instr = 0xF8206800'u32 or (s shl 12) or
              (encodeReg(rm) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt)
  dest.addUint32(instr)

proc emitLdrbReg*(dest: var Bytes; rt, rn, rm: Register) =
  ## LDRB Wt, [Xn, Xm] — zero-extending byte load, register offset (no scaling).
  dest.addUint32(0x38606800'u32 or
                 (encodeReg(rm) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitLoadStoreUImm*(dest: var Bytes; rt, rn: Register; offset: int32;
                        size, opc: int) =
  ## Sized load/store, unsigned-offset form `[rn, #offset]`. `size`: 0=byte,
  ## 1=half, 2=word, 3=dword. `opc`: 0=store, 1=load(zero-ext), 2=load(sign-ext
  ## to 64), 3=load(sign-ext to 32). The immediate is scaled by the access size.
  ## An offset the scaled-uimm12 form cannot encode (too large for the 12-bit
  ## field, unaligned, or negative — e.g. a field deep inside a large object)
  ## synthesizes the address into the reserved assembler scratch X17 first:
  ## X17 (IP1) is never register-allocated by arkham, and its veneer use at call
  ## sites cannot be live inside a single load/store lowering.
  let unit = 1'i32 shl size
  if (offset mod unit) == 0 and offset >= 0 and (offset div unit) <= 4095:
    let sc = uint32(offset div unit)
    let instr = 0x39000000'u32 or (uint32(size) shl 30) or (uint32(opc) shl 22) or
                (sc shl 10) or (encodeReg(rn) shl 5) or encodeReg(rt)
    dest.addUint32(instr)
  else:
    emitMovImm64(dest, X17, cast[uint64](int64(offset)))
    if rn == SP:
      emitAddExtended(dest, X17, rn, X17)
    else:
      emitAdd(dest, X17, rn, X17)
    let instr = 0x39000000'u32 or (uint32(size) shl 30) or (uint32(opc) shl 22) or
                (encodeReg(X17) shl 5) or encodeReg(rt)
    dest.addUint32(instr)

proc emitLoadStoreReg*(dest: var Bytes; rt, rn, rm: Register; size, opc, shift: int) =
  ## Sized load/store, register-offset form `[rn, rm, LSL #shift]`. Same size/opc
  ## coding as `emitLoadStoreUImm`. `shift>0` sets the scale (S) bit.
  let s = if shift > 0: 1'u32 else: 0'u32
  let instr = 0x38206800'u32 or (uint32(size) shl 30) or (uint32(opc) shl 22) or
              (s shl 12) or (encodeReg(rm) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt)
  dest.addUint32(instr)

proc emitStrbReg*(dest: var Bytes; rt, rn, rm: Register) =
  ## STRB Wt, [Xn, Xm] — store low byte, register offset (no scaling).
  dest.addUint32(0x38206800'u32 or
                 (encodeReg(rm) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitStr*(dest: var Bytes; rt: Register; rn: Register; offset: int32) =
  ## Emit STR instruction: STR rt, [rn, #offset]
  ## Offset must be 8-byte aligned and in range [0, 32760]
  let scaledOffset = offset div 8
  if scaledOffset < 0 or scaledOffset > 4095:
    raise newException(ValueError, "STR offset out of range")
  # STR Xt, [Xn, #offset]: 1111 1001 00ii iiii iiii iinn nnnt tttt
  let instr = 0xF9000000'u32 or
              (uint32(scaledOffset) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rt)
  dest.addUint32(instr)

# Branch instructions
proc emitB*(dest: var Buffer; target: LabelId) =
  ## Emit B instruction: B target (unconditional branch)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x14000000'u32)  # Placeholder
  dest.addReloc(pos, target, rkB, 4)

proc emitBL*(dest: var Buffer; target: LabelId) =
  ## Emit BL instruction: BL target (branch with link)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x94000000'u32)  # Placeholder
  dest.addReloc(pos, target, rkBL, 4)

proc emitBeq*(dest: var Buffer; target: LabelId) =
  ## Emit BEQ instruction: BEQ target (branch if equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000000'u32)  # Placeholder, condition=0000 (EQ)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBne*(dest: var Buffer; target: LabelId) =
  ## Emit BNE instruction: BNE target (branch if not equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000001'u32)  # Placeholder, condition=0001 (NE)
  dest.addReloc(pos, target, rkBNE, 4)

proc emitCbz*(dest: var Buffer; rt: Register; target: LabelId) =
  ## CBZ Xt, target — branch when Xt is zero. Reads no flags and sets none, so it
  ## replaces a `cmp Xt, #0` + `b.eq` pair outright. 64-bit form (sf=1).
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0xB4000000'u32 or encodeReg(rt))
  dest.addReloc(pos, target, rkCBZ, 4)

proc emitCbnz*(dest: var Buffer; rt: Register; target: LabelId) =
  ## CBNZ Xt, target — the non-zero twin of `emitCbz`. Differs only in bit 24, which
  ## is the bit `relocs.invertCondBytes` flips to turn one into the other.
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0xB5000000'u32 or encodeReg(rt))
  dest.addReloc(pos, target, rkCBNZ, 4)

# Signed ordering conditional branches. All B.cond share the imm19 patch
# (rkBEQ); the condition code is baked into the placeholder.
proc emitBlt*(dest: var Buffer; target: LabelId) =
  ## BLT target (branch if signed less than)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x5400000B'u32)  # condition=1011 (LT)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBle*(dest: var Buffer; target: LabelId) =
  ## BLE target (branch if signed less or equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x5400000D'u32)  # condition=1101 (LE)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBgt*(dest: var Buffer; target: LabelId) =
  ## BGT target (branch if signed greater than)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x5400000C'u32)  # condition=1100 (GT)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBge*(dest: var Buffer; target: LabelId) =
  ## BGE target (branch if signed greater or equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x5400000A'u32)  # condition=1010 (GE)
  dest.addReloc(pos, target, rkBEQ, 4)

# Unsigned ordering conditional branches (same imm19 patch as the signed ones).
proc emitBlo*(dest: var Buffer; target: LabelId) =
  ## BLO target (branch if unsigned less than / carry clear)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000003'u32)  # condition=0011 (LO/CC)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBls*(dest: var Buffer; target: LabelId) =
  ## BLS target (branch if unsigned lower or same)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000009'u32)  # condition=1001 (LS)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBhi*(dest: var Buffer; target: LabelId) =
  ## BHI target (branch if unsigned higher)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000008'u32)  # condition=1000 (HI)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitBhs*(dest: var Buffer; target: LabelId) =
  ## BHS target (branch if unsigned higher or same / carry set)
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x54000002'u32)  # condition=0010 (HS/CS)
  dest.addReloc(pos, target, rkBEQ, 4)

proc emitCsel*(dest: var Bytes; rd, rn, rm: Register; cond: Condition) =
  ## Emit CSEL instruction: CSEL rd, rn, rm, cond (rd = cond ? rn : rm)
  # CSEL Xd, Xn, Xm, cond: 1001 1010 100m mmmm cccc 00nn nnnd dddd
  let instr = 0x9A800000'u32 or
              (encodeReg(rm) shl 16) or
              (uint32(ord(cond)) shl 12) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitCset*(dest: var Bytes; rd: Register; cond: Condition) =
  ## Emit CSET instruction: CSET rd, cond (rd = cond ? 1 : 0)
  # Alias of CSINC Xd, XZR, XZR, invert(cond):
  # 1001 1010 100 11111 cccc 01 11111 ddddd
  let instr = 0x9A9F07E0'u32 or
              (uint32(ord(invert(cond))) shl 12) or
              encodeReg(rd)
  dest.addUint32(instr)

proc emitRet*(dest: var Bytes) =
  ## Emit RET instruction: RET (return, defaults to X30/LR)
  # RET: 1101 0110 0101 1111 0000 0000 0001 1110
  dest.addUint32(0xD65F03C0'u32)

proc emitNop*(dest: var Bytes) =
  ## Emit NOP instruction
  # NOP: 1101 0101 0000 0011 0010 0000 0001 1111
  dest.addUint32(0xD503201F'u32)

# SVC (supervisor call, syscall)
proc emitSvc*(dest: var Bytes; imm: uint16) =
  ## Emit SVC instruction: SVC #imm
  # SVC #imm: 1101 0100 000i iiii iiii iiii iiii 0001
  let instr = 0xD4000001'u32 or (uint32(imm) shl 5)
  dest.addUint32(instr)

# ADR instruction (load address)
proc emitAdr*(dest: var Buffer; rd: Register; target: LabelId) =
  ## Emit ADR instruction: ADR rd, target (load address of label)
  # ADR Xd, label: 0001 0000 00ii iiii iiii iiii iiii dddd
  # The immediate will be patched later via relocation
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x10000000'u32 or encodeReg(rd))  # Placeholder
  dest.addReloc(pos, target, rkADR, 4)

proc emitAdrLong*(dest: var Buffer; rd: Register; target: LabelId) =
  ## `rd = &target` for a target ANY distance up to ±16 MB away: `adr rd, .+lo`
  ## followed by `add|sub rd, rd, #hi, lsl #12` (see `rkADRADD`). Plain `emitAdr`
  ## reaches only ±1 MB, which a multi-megabyte `.text` — nimony's self-hosted
  ## `nimsem` is 2.5 MB — silently exceeded.
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x10000000'u32 or encodeReg(rd))                      # adr rd, 0
  dest.data.addUint32(0x91000000'u32 or (encodeReg(rd) shl 5) or encodeReg(rd))  # add rd, rd, #0
  dest.addReloc(pos, target, rkADRADD, 8)

# ADRP instruction (load page address)
proc emitAdrpAddGvar*(dest: var Bytes; rd: Register) =
  ## Placeholder `adrp rd, 0` + `add rd, rd, #0` for a __DATA/.bss global; the
  ## page and page-offset immediates are patched at link time (writeMachO).
  dest.addUint32(0x90000000'u32 or encodeReg(rd))                       # adrp rd, 0
  dest.addUint32(0x91000000'u32 or (encodeReg(rd) shl 5) or encodeReg(rd))  # add rd, rd, #0

proc emitAdrpGvarPage*(dest: var Bytes; rd: Register) =
  ## Placeholder `adrp rd, 0` (page only) for a __DATA/.bss global whose page OFFSET
  ## rides in a following folded `ldr`/`str` immediate instead of a separate `add`
  ## (see `gload`/`gstore`). The link-time patch fills the adrp page here and the
  ## scaled page-offset into the ldr/str at pos+4 — the same gvar site, detected by
  ## the pos+4 opcode.
  dest.addUint32(0x90000000'u32 or encodeReg(rd))                       # adrp rd, 0

proc emitAdrp(dest: var Buffer; rd: Register; target: LabelId) =
  ## Emit ADRP instruction: ADRP rd, target (load page address of label)
  # ADRP Xd, label: 1001 0000 00ii iiii iiii iiii iiii dddd
  # The immediate will be patched later via relocation
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x90000000'u32 or encodeReg(rd))  # Placeholder
  dest.addReloc(pos, target, rkADRP, 4)

# BR instruction (branch to register)
proc emitBr(dest: var Bytes; rn: Register) =
  ## Emit BR instruction: BR rn (unconditional branch to address in register)
  # BR Xn: 1101 0110 0001 1111 0000 00nn nnn0 0000
  let instr = 0xD61F0000'u32 or (encodeReg(rn) shl 5)
  dest.addUint32(instr)

proc emitBlr*(dest: var Bytes; rn: Register) =
  ## Emit BLR instruction: BLR rn (branch-with-link to address in register).
  ## Used for the macOS TLV thunk call (`blr x16`).
  # BLR Xn: 1101 0110 0011 1111 0000 00nn nnn0 0000
  let instr = 0xD63F0000'u32 or (encodeReg(rn) shl 5)
  dest.addUint32(instr)

# ── atomics (64-bit) ────────────────────────────────────────────────────────
# Load-/store-exclusive + acquire/release ordered loads/stores, plus the
# barrier/monitor-clear used to build the lock-free RMW loops arkham emits for
# the GCC `__atomic_*` builtins. All operate on the full 64-bit register; the
# pointer is `[Xn]` with no offset.

proc sizeFieldA64(bits: int): uint32 =
  ## The 2-bit access-size field in bits [31:30] of the load/store-exclusive and
  ## load-acquire/store-release encodings: 00=byte, 01=halfword, 10=word (Wt),
  ## 11=doubleword (Xt). Sizing the op to the lock word's width keeps an atomic on a
  ## sub-64-bit field from reading/writing (and locking) the adjacent bytes.
  (case bits
   of 8: 0'u32
   of 16: 1'u32
   of 32: 2'u32
   else: 3'u32) shl 30

proc emitLdaxr*(dest: var Bytes; rt, rn: Register; bits = 64) =
  ## LDAXR{B,H} Wt/Xt, [Xn] — load-acquire exclusive, sized to `bits`.
  dest.addUint32(0x085FFC00'u32 or sizeFieldA64(bits) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitStlxr*(dest: var Bytes; rs, rt, rn: Register; bits = 64) =
  ## STLXR{B,H} Ws, Wt/Xt, [Xn] — store-release exclusive (Ws ← 0 ok, 1 fail), sized.
  dest.addUint32(0x0800FC00'u32 or sizeFieldA64(bits) or (encodeReg(rs) shl 16) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitLdar*(dest: var Bytes; rt, rn: Register; bits = 64) =
  ## LDAR{B,H} Wt/Xt, [Xn] — load-acquire (non-exclusive), sized to `bits`.
  dest.addUint32(0x08DFFC00'u32 or sizeFieldA64(bits) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitStlr*(dest: var Bytes; rt, rn: Register; bits = 64) =
  ## STLR{B,H} Wt/Xt, [Xn] — store-release (non-exclusive), sized to `bits`.
  dest.addUint32(0x089FFC00'u32 or sizeFieldA64(bits) or (encodeReg(rn) shl 5) or encodeReg(rt))

proc emitDmbIsh*(dest: var Bytes) =
  ## DMB ISH — data memory barrier, inner shareable domain.
  dest.addUint32(0xD5033BBF'u32)

proc emitClrex*(dest: var Bytes) =
  ## CLREX — clear the local exclusive monitor.
  dest.addUint32(0xD5033F5F'u32)

proc emitYield*(dest: var Bytes) =
  ## YIELD — HINT #1, the spin-wait hint. Architecturally a NOP: a core that has
  ## nothing to do with it executes it as one, so this is safe on every AArch64
  ## implementation and needs no feature test.
  dest.addUint32(0xD503203F'u32)

# ── valgrind client request ────────────────────────────────────────────────

const
  VgPreamble = [0x93CC0D8C'u32,   # ror x12, x12, #3
                0x93CC358C'u32,   # ror x12, x12, #13
                0x93CCCD8C'u32,   # ror x12, x12, #51
                0x93CCF58C'u32]   # ror x12, x12, #61
    ## Valgrind's magic preamble, verbatim from `valgrind/valgrind.h`
    ## (`__SPECIAL_INSTRUCTION_PREAMBLE`, arm64). The four rotate counts sum to
    ## 3 + 13 + 51 + 61 = 128 ≡ 0 (mod 64), so x12 comes out of the sequence holding
    ## exactly what it went in with. That is not a coincidence to preserve carefully —
    ## it is the design: the whole request has to be a NO-OP on real hardware, because
    ## the same instruction bytes execute whether or not anyone is watching.
  VgMarker = 0xAA0A014A'u32       # orr x10, x10, x10
    ## The instruction valgrind actually keys on. Also a no-op (`x10 |= x10`), and also
    ## deliberately so.

proc emitVgClientRequest*(dest: var Bytes; rd, rargs: Register) =
  ## `D = valgrind_client_request(S)` — S holds the address of the 6-word request
  ## block, D receives valgrind's answer (or 0 if the sequence executed for real).
  ##
  ## Valgrind's protocol fixes the registers: x4 must hold the block's address and
  ## x3 the caller's default on entry, and x3 holds the result on exit. Both are
  ## saved and restored around the sequence.
  ##
  ## Under arkham's CURRENT planner that saving is dead weight — measured, not
  ## assumed: removing the x4 restore changes no observable result, because the ABI
  ## planner evaluates call arguments into temps and stages x0–x7 only immediately
  ## before the call, so nothing of the caller's is ever live in x3/x4 across an
  ## expression. The saving stays anyway, because that is a property of one pass in
  ## one repository and nothing states or checks it, while this encoder is reachable
  ## from hand-written asm-NIF as well. Five instructions in a build that exists to
  ## be slow and observed is the wrong place to spend an invariant.
  ##
  ## x14/x15/x16 do the staging precisely because arkham never hands them out (see
  ## `AtomicScratchRegs` in `arkham/machine.nim`): x14/x15 are the emitter's staging
  ## bridges, withheld from the temp pool, and x16 is in `ReservedRegs`. The same
  ## property that makes an atomic's LL/SC loop cheap makes this cheap — the clobber
  ## set cannot overlap anything the allocator owns, so nothing has to prove it.
  ##
  ## The order below is what makes every aliasing case come out right, and each step
  ## is load-bearing:
  ##
  ## * `rargs` is read through its SAVED copy when it happens to BE x3 or x4, so
  ##   staging the block address cannot destroy the value being staged;
  ## * the answer is parked in x15 BEFORE x3/x4 are restored, so restoring cannot
  ##   overwrite it;
  ## * `rd` is written LAST, so `rd` may legitimately be x3 or x4 — the allocator
  ##   picked it to hold the result, which means whatever was there is already dead.
  emitMov(dest, X16, X3)                    # save x3
  emitMov(dest, X14, X4)                    # save x4
  emitMovImm(dest, X3, 0)                   # default = 0 ⇒ "not under valgrind"
  let src = (if rargs == X3: X16 elif rargs == X4: X14 else: rargs)
  emitMov(dest, X4, src)                    # x4 = &request block
  for w in VgPreamble: dest.addUint32(w)
  dest.addUint32(VgMarker)
  emitMov(dest, X15, X3)                    # park the answer
  emitMov(dest, X3, X16)                    # restore x3
  emitMov(dest, X4, X14)                    # restore x4
  emitMov(dest, rd, X15)

# ── scalar double-precision floating point (ftype = 01) ─────────────────────
# Dn is the 64-bit (double) view of Vn. Single-precision (Sn) is a future
# addition; arkham emits doubles only for now.

proc encodeFReg(r: FloatRegister): uint32 {.inline.} = uint32(ord(r)) and 0x1F

# The scalar FP data-processing forms differ between double (ftype = 01) and
# single (ftype = 00) only in bit 22; the encoders below take the double base
# and clear it for single precision.
const FtypeBit = 0x00400000'u32           # bit 22 set = double
const FmovGprMask = 0x80400000'u32        # gpr<->fp also clears sf (bit 31) for single

proc fp2(base: uint32; single: bool): uint32 {.inline.} =
  if single: base and not FtypeBit else: base

proc emitFmov*(dest: var Bytes; rd, rn: FloatRegister; single = false) =   # FMOV d/s reg copy
  dest.addUint32(fp2(0x1E604000'u32, single) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFmovFromGpr*(dest: var Bytes; rd: FloatRegister; rn: Register; single = false) =  # FMOV Dd/Sd, Xn/Wn (bits)
  let base = if single: 0x9E670000'u32 and not FmovGprMask else: 0x9E670000'u32
  dest.addUint32(base or (encodeReg(rn) shl 5) or encodeFReg(rd))

proc emitFmovToGpr*(dest: var Bytes; rd: Register; rn: FloatRegister; single = false) =    # FMOV Xd/Wd, Dn/Sn (bits)
  let base = if single: 0x9E660000'u32 and not FmovGprMask else: 0x9E660000'u32
  dest.addUint32(base or (encodeFReg(rn) shl 5) or encodeReg(rd))

proc emitFadd*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E602800'u32, single) or (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFsub*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E603800'u32, single) or (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFmul*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E600800'u32, single) or (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFdiv*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E601800'u32, single) or (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFneg*(dest: var Bytes; rd, rn: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E614000'u32, single) or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFcmp*(dest: var Bytes; rn, rm: FloatRegister; single = false) =
  dest.addUint32(fp2(0x1E602000'u32, single) or (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5))

proc emitScvtf*(dest: var Bytes; rd: FloatRegister; rn: Register; single = false) =  # SCVTF Dd/Sd, Xn
  dest.addUint32(fp2(0x9E620000'u32, single) or (encodeReg(rn) shl 5) or encodeFReg(rd))

proc emitUcvtf*(dest: var Bytes; rd: FloatRegister; rn: Register; single = false) =  # UCVTF Dd/Sd, Xn
  dest.addUint32(fp2(0x9E630000'u32, single) or (encodeReg(rn) shl 5) or encodeFReg(rd))

proc emitFcvtzs*(dest: var Bytes; rd: Register; rn: FloatRegister; single = false) =  # FCVTZS Xd, Dn/Sn
  dest.addUint32(fp2(0x9E780000'u32, single) or (encodeFReg(rn) shl 5) or encodeReg(rd))

proc emitFcvtzu*(dest: var Bytes; rd: Register; rn: FloatRegister; single = false) =  # FCVTZU Xd, Dn/Sn
  dest.addUint32(fp2(0x9E790000'u32, single) or (encodeFReg(rn) shl 5) or encodeReg(rd))

proc emitFcvtToSingle*(dest: var Bytes; rd, rn: FloatRegister) =   # FCVT Sd, Dn (double→single)
  dest.addUint32(0x1E624000'u32 or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFcvtToDouble*(dest: var Bytes; rd, rn: FloatRegister) =   # FCVT Dd, Sn (single→double)
  dest.addUint32(0x1E22C000'u32 or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFldr*(dest: var Bytes; rt: FloatRegister; rn: Register; offset: int32; single = false) =
  ## LDR Dt/St, [Xn, #offset] — load a double/single (unsigned offset, scaled).
  let scale = if single: 4 else: 8
  let scaled = offset div scale
  if (offset mod scale) != 0 or scaled < 0 or scaled > 0xFFF:
    raise newException(ValueError, "FP LDR offset out of range")
  let base = if single: 0xBD400000'u32 else: 0xFD400000'u32
  dest.addUint32(base or (uint32(scaled) shl 10) or (encodeReg(rn) shl 5) or encodeFReg(rt))

proc emitFstr*(dest: var Bytes; rt: FloatRegister; rn: Register; offset: int32; single = false) =
  ## STR Dt/St, [Xn, #offset] — store a double/single (unsigned offset, scaled).
  let scale = if single: 4 else: 8
  let scaled = offset div scale
  if (offset mod scale) != 0 or scaled < 0 or scaled > 0xFFF:
    raise newException(ValueError, "FP STR offset out of range")
  let base = if single: 0xBD000000'u32 else: 0xFD000000'u32
  dest.addUint32(base or (uint32(scaled) shl 10) or (encodeReg(rn) shl 5) or encodeFReg(rt))

# ── AdvSIMD (NEON), 128-bit q-register forms ────────────────────────────────
# The FloatRegister names the v register; the arrangement (`.2d` vs `.4s`)
# follows the caller's `single` flag, exactly like the scalar fp emitters.

proc emitLdrQ*(dest: var Bytes; rt: FloatRegister; rn: Register; offset: int32) =
  ## LDR Qt, [Xn, #offset] — 128-bit load (unsigned offset, scaled by 16).
  let scaled = offset div 16
  if (offset and 15) != 0 or scaled < 0 or scaled > 0xFFF:
    raise newException(ValueError, "Q LDR offset out of range")
  dest.addUint32(0x3DC00000'u32 or (uint32(scaled) shl 10) or
                 (encodeReg(rn) shl 5) or encodeFReg(rt))

proc emitStrQ*(dest: var Bytes; rt: FloatRegister; rn: Register; offset: int32) =
  ## STR Qt, [Xn, #offset] — 128-bit store (unsigned offset, scaled by 16).
  let scaled = offset div 16
  if (offset and 15) != 0 or scaled < 0 or scaled > 0xFFF:
    raise newException(ValueError, "Q STR offset out of range")
  dest.addUint32(0x3D800000'u32 or (uint32(scaled) shl 10) or
                 (encodeReg(rn) shl 5) or encodeFReg(rt))

proc vec3(base2d, base4s: uint32; rd, rn, rm: FloatRegister; single: bool): uint32 {.inline.} =
  (if single: base4s else: base2d) or
    (encodeFReg(rm) shl 16) or (encodeFReg(rn) shl 5) or encodeFReg(rd)

proc emitVFadd*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  ## FADD Vd.2D, Vn.2D, Vm.2D / .4S
  dest.addUint32(vec3(0x4E60D400'u32, 0x4E20D400'u32, rd, rn, rm, single))

proc emitVFsub*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  ## FSUB Vd.2D, Vn.2D, Vm.2D / .4S
  dest.addUint32(vec3(0x4EE0D400'u32, 0x4EA0D400'u32, rd, rn, rm, single))

proc emitVFmul*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  ## FMUL Vd.2D, Vn.2D, Vm.2D / .4S
  dest.addUint32(vec3(0x6E60DC00'u32, 0x6E20DC00'u32, rd, rn, rm, single))

proc emitVFmla*(dest: var Bytes; rd, rn, rm: FloatRegister; single = false) =
  ## FMLA Vd.2D, Vn.2D, Vm.2D / .4S — Vd += Vn * Vm, lane-wise, fused.
  dest.addUint32(vec3(0x4E60CC00'u32, 0x4E20CC00'u32, rd, rn, rm, single))

proc emitVEor*(dest: var Bytes; rd, rn, rm: FloatRegister) =
  ## EOR Vd.16B, Vn.16B, Vm.16B — arrangement-blind bitwise xor.
  dest.addUint32(0x6E201C00'u32 or (encodeFReg(rm) shl 16) or
                 (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitVDup*(dest: var Bytes; rd, rn: FloatRegister; single = false) =
  ## DUP Vd.2D, Vn.D[0] / Vd.4S, Vn.S[0] — broadcast lane 0.
  let base = if single: 0x4E040400'u32 else: 0x4E080400'u32
  dest.addUint32(base or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitVAddv*(dest: var Bytes; rd, rn: FloatRegister; single = false) =
  ## Horizontal fp add of every lane of Vn into the scalar Rd.
  ## Double: FADDP Dd, Vn.2D. Single has 4 lanes and no one-step form:
  ## FADDP Vd.4S, Vn.4S, Vn.4S then FADDP Sd, Vd.2S — Vd doubles as the
  ## scratch, which stays correct when rd == rn.
  if single:
    dest.addUint32(0x6E20D400'u32 or (encodeFReg(rn) shl 16) or
                   (encodeFReg(rn) shl 5) or encodeFReg(rd))
    dest.addUint32(0x7E30D800'u32 or (encodeFReg(rd) shl 5) or encodeFReg(rd))
  else:
    dest.addUint32(0x7E70D800'u32 or (encodeFReg(rn) shl 5) or encodeFReg(rd))

proc emitFstpPre*(dest: var Bytes; rt1, rt2: FloatRegister; rn: Register; offset: int32) =
  ## STP Dt1, Dt2, [Xn, #offset]! — pre-indexed store pair of doubles.
  let scaled = offset div 8
  if (offset and 7) != 0 or scaled < -64 or scaled > 63:
    raise newException(ValueError, "FP STP offset out of range")
  dest.addUint32(0x6D800000'u32 or ((uint32(scaled) and 0x7F) shl 15) or
                 (encodeFReg(rt2) shl 10) or (encodeReg(rn) shl 5) or encodeFReg(rt1))

proc emitFldpPost*(dest: var Bytes; rt1, rt2: FloatRegister; rn: Register; offset: int32) =
  ## LDP Dt1, Dt2, [Xn], #offset — post-indexed load pair of doubles.
  let scaled = offset div 8
  if (offset and 7) != 0 or scaled < -64 or scaled > 63:
    raise newException(ValueError, "FP LDP offset out of range")
  dest.addUint32(0x6CC00000'u32 or ((uint32(scaled) and 0x7F) shl 15) or
                 (encodeFReg(rt2) shl 10) or (encodeReg(rn) shl 5) or encodeFReg(rt1))

# Stack operations
proc emitStp*(dest: var Bytes; rt1, rt2: Register; rn: Register; offset: int32) =
  ## Emit STP instruction: STP rt1, rt2, [rn, #offset]! (pre-index)
  ## Used for pushing pairs of registers to stack
  let scaledOffset = offset div 8
  if scaledOffset < -64 or scaledOffset > 63:
    raise newException(ValueError, "STP offset out of range")
  # STP Xt1, Xt2, [Xn, #offset]!: 1010 1001 10ii iiii itt tttnn nnnt tttt
  let instr = 0xA9800000'u32 or
              ((uint32(scaledOffset) and 0x7F) shl 15) or
              (encodeReg(rt2) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rt1)
  dest.addUint32(instr)

proc emitLdp*(dest: var Bytes; rt1, rt2: Register; rn: Register; offset: int32) =
  ## Emit LDP instruction: LDP rt1, rt2, [rn], #offset (post-index)
  ## Used for popping pairs of registers from stack
  let scaledOffset = offset div 8
  if scaledOffset < -64 or scaledOffset > 63:
    raise newException(ValueError, "LDP offset out of range")
  # LDP Xt1, Xt2, [Xn], #offset: 1010 1000 11ii iiii itt tttnn nnnt tttt
  let instr = 0xA8C00000'u32 or
              ((uint32(scaledOffset) and 0x7F) shl 15) or
              (encodeReg(rt2) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rt1)
  dest.addUint32(instr)

