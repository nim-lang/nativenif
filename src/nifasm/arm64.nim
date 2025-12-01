# Nifasm - ARM64 Binary Assembler
# A dependency-free ARM64 assembler that emits binary instruction bytes

import std/[strutils, tables]

import buffers, relocs

type
  # ARM64 64-bit general purpose registers
  Register* = enum
    X0 = 0, X1 = 1, X2 = 2, X3 = 3, X4 = 4, X5 = 5, X6 = 6, X7 = 7,
    X8 = 8, X9 = 9, X10 = 10, X11 = 11, X12 = 12, X13 = 13, X14 = 14, X15 = 15,
    X16 = 16, X17 = 17, X18 = 18, X19 = 19, X20 = 20, X21 = 21, X22 = 22, X23 = 23,
    X24 = 24, X25 = 25, X26 = 26, X27 = 27, X28 = 28, X29 = 29, X30 = 30,
    SP = 31  # Stack pointer

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
  let instr = 0xAA000000'u32 or
              (encodeReg(rn) shl 16) or
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
proc emitMovK*(dest: var Bytes; rd: Register; imm: uint16; shift: uint8) =
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

# ADD instruction - register + register
proc emitAdd*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit ADD instruction: ADD rd, rn, rm
  # ADD Xd, Xn, Xm: 1000 1011 000m mmmm 0000 00nn nnnd dddd
  let instr = 0x8B000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# ADD immediate
proc emitAddImm*(dest: var Bytes; rd, rn: Register; imm: uint16) =
  ## Emit ADD instruction: ADD rd, rn, #imm
  # ADD Xd, Xn, #imm: 1001 0001 00ii iiii iiii iinn nnnd dddd
  let instr = 0x91000000'u32 or
              (uint32(imm) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# SUB instruction - register - register
proc emitSub*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit SUB instruction: SUB rd, rn, rm
  # SUB Xd, Xn, Xm: 1100 1011 000m mmmm 0000 00nn nnnd dddd
  let instr = 0xCB000000'u32 or
              (encodeReg(rm) shl 16) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# SUB immediate
proc emitSubImm*(dest: var Bytes; rd, rn: Register; imm: uint16) =
  ## Emit SUB instruction: SUB rd, rn, #imm
  # SUB Xd, Xn, #imm: 1101 0001 00ii iiii iiii iinn nnnd dddd
  let instr = 0xD1000000'u32 or
              (uint32(imm) shl 10) or
              (encodeReg(rn) shl 5) or
              encodeReg(rd)
  dest.addUint32(instr)

# MUL instruction
proc emitMul*(dest: var Bytes; rd, rn, rm: Register) =
  ## Emit MUL instruction: MUL rd, rn, rm (alias for MADD rd, rn, rm, XZR)
  # MADD Xd, Xn, Xm, XZR: 1001 1011 000m mmmm 0111 11nn nnnd dddd
  let instr = 0x9B007C00'u32 or
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

# ADRP instruction (load page address)
proc emitAdrp*(dest: var Buffer; rd: Register; target: LabelId) =
  ## Emit ADRP instruction: ADRP rd, target (load page address of label)
  # ADRP Xd, label: 1001 0000 00ii iiii iiii iiii iiii dddd
  # The immediate will be patched later via relocation
  let pos = dest.data.getCurrentPosition()
  dest.data.addUint32(0x90000000'u32 or encodeReg(rd))  # Placeholder
  dest.addReloc(pos, target, rkADRP, 4)

# BR instruction (branch to register)
proc emitBr*(dest: var Bytes; rn: Register) =
  ## Emit BR instruction: BR rn (unconditional branch to address in register)
  # BR Xn: 1101 0110 0001 1111 0000 00nn nnn0 0000
  let instr = 0xD61F0000'u32 or (encodeReg(rn) shl 5)
  dest.addUint32(instr)

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

