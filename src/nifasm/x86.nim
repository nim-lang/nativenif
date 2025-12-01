# Nifasm - x86_64 Binary Assembler
# A dependency-free x86_64 assembler that emits binary instruction bytes

import std/tables

import buffers, relocs

type
  # x86_64 64-bit general purpose registers
  Register* = enum
    RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13, R14 = 14, R15 = 15

  # Addressing modes for ModR/M byte
  AddressingMode* = enum
    amIndirect = 0b00,        # Indirect memory addressing
    amIndirectDisp8 = 0b01,   # Indirect with 8-bit displacement
    amIndirectDisp32 = 0b10,  # Indirect with 32-bit displacement
    amDirect = 0b11           # Direct register addressing

  # Memory operand
  MemoryOperand* = object
    base*: Register
    index*: Register
    scale*: int  # 1, 2, 4, or 8
    displacement*: int32
    hasIndex*: bool
    useFsSegment*: bool  # Use FS segment register (for thread-local storage)

# REX prefix encoding
type RexPrefix* = object
  w*: bool  # 64-bit operand size
  r*: bool  # Extension of ModR/M reg field
  x*: bool  # Extension of SIB index field
  b*: bool  # Extension of ModR/M r/m field

proc encodeRex*(rex: RexPrefix): byte =
  result = 0x40  # Base REX prefix
  if rex.w: result = result or 0x08
  if rex.r: result = result or 0x04
  if rex.x: result = result or 0x02
  if rex.b: result = result or 0x01

proc needsRex*(reg: Register): bool =
  int(reg) >= 8

# ModR/M byte encoding
proc encodeModRM*(mode: AddressingMode; reg: int; rm: int): byte =
  byte((int(mode) shl 6) or ((reg and 0x07) shl 3) or (rm and 0x07))

# SIB byte encoding
proc encodeSIB*(scale: int; index: int; base: int): byte =
  let scaleBits =
    case scale
    of 1: 0b00
    of 2: 0b01
    of 4: 0b10
    of 8: 0b11
    else: 0b00
  byte((scaleBits shl 6) or ((index and 0x07) shl 3) or (base and 0x07))

proc emitMem(dest: var Bytes; reg: int; mem: MemoryOperand) =
  # Emit segment prefix if needed (FS = 0x64 for thread-local storage)
  if mem.useFsSegment:
    dest.add(0x64)  # FS segment override prefix

  # Emit ModRM (and SIB/Disp) for memory operand
  var modb = 0
  var rmb = int(mem.base) and 7
  var sib = false
  var dispSize = 0 # 0, 1, 4

  if mem.hasIndex or mem.base == RSP or mem.base == R12:
    sib = true
    rmb = 4 # SIB follows

  # Determine Mod and DispSize
  if mem.displacement == 0 and (mem.base != RBP and mem.base != R13):
    modb = 0b00 # Indirect
  elif mem.displacement >= -128 and mem.displacement <= 127:
    modb = 0b01 # Indirect + Disp8
    dispSize = 1
  else:
    modb = 0b10 # Indirect + Disp32
    dispSize = 4

  dest.add(encodeModRM(AddressingMode(modb), reg, rmb))

  if sib:
    var index = 4 # None (RSP)
    if mem.hasIndex:
      index = int(mem.index)
    dest.add(encodeSIB(mem.scale, index, int(mem.base)))

  if dispSize == 1:
    dest.add(byte(mem.displacement and 0xFF))
  elif dispSize == 4:
    dest.addt32(mem.displacement)

# Core MOV instruction implementations
proc emitMov*(dest: var Bytes; a, b: Register) =
  ## Emit MOV instruction: MOV a, b (move from b to a)
  ## Opcode 0x89: MOV r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x89: r/m is dest (a), reg is source (b)
  # REX.R extends reg (source), REX.B extends r/m (dest)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x89)  # MOV r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitMov*(dest: var Bytes; reg: Register; mem: MemoryOperand) =
  ## Emit MOV instruction: MOV reg, mem (load)
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x8B) # MOV r64, r/m64
  dest.emitMem(int(reg), mem)

proc emitMov*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit MOV instruction: MOV mem, reg (store)
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x89) # MOV r/m64, r64
  dest.emitMem(int(reg), mem)

proc emitMovImmToReg*(dest: var Bytes; reg: Register; imm: int64) =
  ## Emit MOV instruction: MOV reg, imm
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  # Use the special immediate-to-register MOV opcode
  let opcode = 0xB8 + (int(reg) and 0x07)
  dest.add(byte(opcode))

  # Add 64-bit immediate value
  dest.addt64(imm)

proc emitMovImmToReg32*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit MOV instruction: MOV reg, imm32 (sign-extended to 64-bit)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xC7)  # MOV r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension
  dest.addt32(imm)

# Arithmetic instructions
proc emitAdd*(dest: var Bytes; a, b: Register) =
  ## Emit ADD instruction: ADD a, b (a = a + b)
  ## Opcode 0x01: ADD r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x01: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x01)  # ADD r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitAdd*(dest: var Bytes; reg: Register; mem: MemoryOperand) =
  ## Emit ADD instruction: ADD reg, mem
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x03) # ADD r64, r/m64
  dest.emitMem(int(reg), mem)

proc emitAdd*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit ADD instruction: ADD mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x01) # ADD r/m64, r64
  dest.emitMem(int(reg), mem)

proc emitSub*(dest: var Bytes; a, b: Register) =
  ## Emit SUB instruction: SUB a, b (a = a - b)
  ## Opcode 0x29: SUB r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x29: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x29)  # SUB r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitSub*(dest: var Bytes; reg: Register; mem: MemoryOperand) =
  ## Emit SUB instruction: SUB reg, mem
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x2B) # SUB r64, r/m64
  dest.emitMem(int(reg), mem)

proc emitSub*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit SUB instruction: SUB mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x29) # SUB r/m64, r64
  dest.emitMem(int(reg), mem)

proc emitImul*(dest: var Bytes; a, b: Register) =
  ## Emit IMUL instruction: IMUL a, b (a = a * b, signed multiply)
  ## Opcode 0x0F 0xAF: IMUL r64, r/m64 - reg field is destination, r/m field is source
  var rex = RexPrefix(w: true)

  # For IMUL r64, r/m64: reg is dest (a), r/m is source (b)
  if needsRex(a): rex.r = true  # destination register extension
  if needsRex(b): rex.b = true  # source register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAF)  # IMUL r64, r/m64 opcode
  dest.add(encodeModRM(amDirect, int(a), int(b)))  # reg=dest(a), rm=source(b)

proc emitImulImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit IMUL instruction: IMUL reg, reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x69)  # IMUL r64, r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, int(reg), int(reg)))
  dest.addt32(imm)

# Additional arithmetic operations
proc emitMul*(dest: var Bytes; reg: Register) =
  ## Emit MUL instruction: MUL reg (unsigned multiply)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF7)  # MUL r/m64 opcode
  dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension

proc emitDiv*(dest: var Bytes; reg: Register) =
  ## Emit DIV instruction: DIV reg (unsigned divide)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF7)  # DIV r/m64 opcode
  dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension

proc emitIdiv*(dest: var Bytes; reg: Register) =
  ## Emit IDIV instruction: IDIV reg (signed divide)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF7)  # IDIV r/m64 opcode
  dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension

proc emitInc*(dest: var Bytes; reg: Register) =
  ## Emit INC instruction: INC reg (increment)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xFF)  # INC r/m64 opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension

proc emitInc*(dest: var Bytes; mem: MemoryOperand) =
  ## Emit INC instruction: INC mem
  var rex = RexPrefix(w: true)
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0xFF)
  dest.emitMem(0, mem)

proc emitDec*(dest: var Bytes; reg: Register) =
  ## Emit DEC instruction: DEC reg (decrement)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xFF)  # DEC r/m64 opcode
  dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension

proc emitDec*(dest: var Bytes; mem: MemoryOperand) =
  ## Emit DEC instruction: DEC mem
  var rex = RexPrefix(w: true)
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0xFF)
  dest.emitMem(1, mem)

proc emitNeg*(dest: var Bytes; reg: Register) =
  ## Emit NEG instruction: NEG reg (negate)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF7)  # NEG r/m64 opcode
  dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension

proc emitNeg*(dest: var Bytes; mem: MemoryOperand) =
  ## Emit NEG instruction: NEG mem
  var rex = RexPrefix(w: true)
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0xF7)
  dest.emitMem(3, mem)

proc emitCmp*(dest: var Bytes; a, b: Register) =
  ## Emit CMP instruction: CMP a, b (compare a with b, i.e., compute a - b and set flags)
  ## Opcode 0x39: CMP r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x39: r/m is first operand (a), reg is second operand (b)
  if needsRex(b): rex.r = true  # second operand register extension
  if needsRex(a): rex.b = true  # first operand register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x39)  # CMP r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=b, rm=a

proc emitCmp*(dest: var Bytes; reg: Register; mem: MemoryOperand) =
  ## Emit CMP instruction: CMP reg, mem
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x3B) # CMP r64, r/m64
  dest.emitMem(int(reg), mem)

proc emitCmp*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit CMP instruction: CMP mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x39) # CMP r/m64, r64
  dest.emitMem(int(reg), mem)

proc emitTest*(dest: var Bytes; a, b: Register) =
  ## Emit TEST instruction: TEST a, b (compute a AND b, set flags)
  ## Opcode 0x85: TEST r/m64, r64 - reg field is source, r/m field is destination
  ## Note: TEST is commutative, but we follow Intel convention
  var rex = RexPrefix(w: true)

  # For 0x85: r/m is first operand (a), reg is second operand (b)
  if needsRex(b): rex.r = true
  if needsRex(a): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x85)  # TEST r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=b, rm=a

# Arithmetic with immediate values
proc emitAddImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit ADD instruction: ADD reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # ADD r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension
  dest.addt32(imm)

proc emitSubImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit SUB instruction: SUB reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # SUB r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 5, int(reg)))  # /5 extension
  dest.addt32(imm)

proc emitAndImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit AND instruction: AND reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # AND r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension
  dest.addt32(imm)

proc emitOrImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit OR instruction: OR reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # OR r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension
  dest.addt32(imm)

proc emitXorImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit XOR instruction: XOR reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # XOR r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension
  dest.addt32(imm)

proc emitCmpImm*(dest: var Bytes; reg: Register; imm: int32) =
  ## Emit CMP instruction: CMP reg, imm32
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x81)  # CMP r/m64, imm32 opcode
  dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension
  dest.addt32(imm)

# Shift operations
proc emitShl*(dest: var Bytes; reg: Register; count: int) =
  ## Emit SHL instruction: SHL reg, count (shift left)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # SHL r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension
  else:
    dest.add(0xC1)  # SHL r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension
    dest.add(byte(count))

proc emitShr*(dest: var Bytes; reg: Register; count: int) =
  ## Emit SHR instruction: SHR reg, count (shift right)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # SHR r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 5, int(reg)))  # /5 extension
  else:
    dest.add(0xC1)  # SHR r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 5, int(reg)))  # /5 extension
    dest.add(byte(count))

proc emitSal*(dest: var Bytes; reg: Register; count: int) =
  ## Emit SAL instruction: SAL reg, count (shift arithmetic left)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # SAL r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension
  else:
    dest.add(0xC1)  # SAL r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension
    dest.add(byte(count))

proc emitSar*(dest: var Bytes; reg: Register; count: int) =
  ## Emit SAR instruction: SAR reg, count (shift arithmetic right)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # SAR r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension
  else:
    dest.add(0xC1)  # SAR r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension
    dest.add(byte(count))

# Rotate operations
proc emitRol*(dest: var Bytes; reg: Register; count: int) =
  ## Emit ROL instruction: ROL reg, count (rotate left)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # ROL r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension
  else:
    dest.add(0xC1)  # ROL r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension
    dest.add(byte(count))

proc emitRor*(dest: var Bytes; reg: Register; count: int) =
  ## Emit ROR instruction: ROR reg, count (rotate right)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # ROR r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension
  else:
    dest.add(0xC1)  # ROR r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension
    dest.add(byte(count))

proc emitRcl*(dest: var Bytes; reg: Register; count: int) =
  ## Emit RCL instruction: RCL reg, count (rotate left through carry)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # RCL r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension
  else:
    dest.add(0xC1)  # RCL r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension
    dest.add(byte(count))

proc emitRcr*(dest: var Bytes; reg: Register; count: int) =
  ## Emit RCR instruction: RCR reg, count (rotate right through carry)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  if count == 1:
    dest.add(0xD1)  # RCR r/m64, 1 opcode
    dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension
  else:
    dest.add(0xC1)  # RCR r/m64, imm8 opcode
    dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension
    dest.add(byte(count))

# Bit manipulation operations
proc emitNot*(dest: var Bytes; reg: Register) =
  ## Emit NOT instruction: NOT reg (bitwise not)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF7)  # NOT r/m64 opcode
  dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension

proc emitNot*(dest: var Bytes; mem: MemoryOperand) =
  ## Emit NOT instruction: NOT mem
  var rex = RexPrefix(w: true)
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0xF7)
  dest.emitMem(2, mem)

proc emitBsf*(dest: var Bytes; destReg, srcReg: Register) =
  ## Emit BSF instruction: BSF destReg, srcReg (bit scan forward)
  var rex = RexPrefix(w: true)

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBC)  # BSF r64, r/m64 opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitBsr*(dest: var Bytes; destReg, srcReg: Register) =
  ## Emit BSR instruction: BSR destReg, srcReg (bit scan reverse)
  var rex = RexPrefix(w: true)

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBD)  # BSR r64, r/m64 opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitBt*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit BT instruction: BT reg, bit (bit test)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBA)  # BT r/m64, imm8 opcode
  dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension
  dest.add(byte(bit))

proc emitBtc*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit BTC instruction: BTC reg, bit (bit test and complement)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBA)  # BTC r/m64, imm8 opcode
  dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension
  dest.add(byte(bit))

proc emitBtr*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit BTR instruction: BTR reg, bit (bit test and reset)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBA)  # BTR r/m64, imm8 opcode
  dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension
  dest.add(byte(bit))

proc emitBts*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit BTS instruction: BTS reg, bit (bit test and set)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xBA)  # BTS r/m64, imm8 opcode
  dest.add(encodeModRM(amDirect, 5, int(reg)))  # /5 extension
  dest.add(byte(bit))

# Floating point operations
# x87 FPU registers (ST0-ST7)
type FpuRegister* = enum
  ST0 = 0, ST1 = 1, ST2 = 2, ST3 = 3, ST4 = 4, ST5 = 5, ST6 = 6, ST7 = 7

# SSE/AVX registers (XMM0-XMM15)
type XmmRegister* = enum
  XMM0 = 0, XMM1 = 1, XMM2 = 2, XMM3 = 3, XMM4 = 4, XMM5 = 5, XMM6 = 6, XMM7 = 7,
  XMM8 = 8, XMM9 = 9, XMM10 = 10, XMM11 = 11, XMM12 = 12, XMM13 = 13, XMM14 = 14, XMM15 = 15

proc needsRex*(reg: XmmRegister): bool =
  int(reg) >= 8

# x87 FPU operations
proc emitFld*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FLD instruction: FLD reg (load floating point)
  dest.add(0xD9)  # FLD opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension

proc emitFst*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FST instruction: FST reg (store floating point)
  dest.add(0xDD)  # FST opcode
  dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension

proc emitFstp*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FSTP instruction: FSTP reg (store floating point and pop)
  dest.add(0xDD)  # FSTP opcode
  dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension

proc emitFadd*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FADD instruction: FADD reg (floating point add)
  dest.add(0xD8)  # FADD opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension

proc emitFsub*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FSUB instruction: FSUB reg (floating point subtract)
  dest.add(0xD8)  # FSUB opcode
  dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension

proc emitFmul*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FMUL instruction: FMUL reg (floating point multiply)
  dest.add(0xD8)  # FMUL opcode
  dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension

proc emitFdiv*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FDIV instruction: FDIV reg (floating point divide)
  dest.add(0xD8)  # FDIV opcode
  dest.add(encodeModRM(amDirect, 6, int(reg)))  # /6 extension

proc emitFcom*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FCOM instruction: FCOM reg (floating point compare)
  dest.add(0xD8)  # FCOM opcode
  dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension

proc emitFcomp*(dest: var Bytes; reg: FpuRegister) =
  ## Emit FCOMP instruction: FCOMP reg (floating point compare and pop)
  dest.add(0xD8)  # FCOMP opcode
  dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension

proc emitFsin*(dest: var Bytes) =
  ## Emit FSIN instruction: FSIN (sine)
  dest.add(0xD9)  # FSIN opcode
  dest.add(0xFE)  # /6 extension

proc emitFcos*(dest: var Bytes) =
  ## Emit FCOS instruction: FCOS (cosine)
  dest.add(0xD9)  # FCOS opcode
  dest.add(0xFF)  # /7 extension

proc emitFsqrt*(dest: var Bytes) =
  ## Emit FSQRT instruction: FSQRT (square root)
  dest.add(0xD9)  # FSQRT opcode
  dest.add(0xFA)  # /2 extension

proc emitFabs*(dest: var Bytes) =
  ## Emit FABS instruction: FABS (absolute value)
  dest.add(0xD9)  # FABS opcode
  dest.add(0xE1)  # /4 extension

proc emitFchs*(dest: var Bytes) =
  ## Emit FCHS instruction: FCHS (change sign)
  dest.add(0xD9)  # FCHS opcode
  dest.add(0xE0)  # /4 extension

# SSE operations
proc emitMovss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit MOVSS instruction: MOVSS destReg, srcReg (move scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # MOVSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x10)  # MOVSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitMovsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit MOVSD instruction: MOVSD destReg, srcReg (move scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # MOVSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x10)  # MOVSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitAddss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit ADDSS instruction: ADDSS destReg, srcReg (add scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # ADDSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x58)  # ADDSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitAddsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit ADDSD instruction: ADDSD destReg, srcReg (add scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # ADDSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x58)  # ADDSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitSubss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit SUBSS instruction: SUBSS destReg, srcReg (subtract scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # SUBSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5C)  # SUBSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitSubsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit SUBSD instruction: SUBSD destReg, srcReg (subtract scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # SUBSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5C)  # SUBSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitMulss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit MULSS instruction: MULSS destReg, srcReg (multiply scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # MULSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x59)  # MULSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitMulsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit MULSD instruction: MULSD destReg, srcReg (multiply scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # MULSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x59)  # MULSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitDivss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit DIVSS instruction: DIVSS destReg, srcReg (divide scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # DIVSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5E)  # DIVSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitDivsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit DIVSD instruction: DIVSD destReg, srcReg (divide scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # DIVSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5E)  # DIVSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitSqrtss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit SQRTSS instruction: SQRTSS destReg, srcReg (square root scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # SQRTSS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x51)  # SQRTSS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitSqrtsd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit SQRTSD instruction: SQRTSD destReg, srcReg (square root scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # SQRTSD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x51)  # SQRTSD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitComiss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit COMISS instruction: COMISS destReg, srcReg (compare scalar single precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2F)  # COMISS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitComisd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit COMISD instruction: COMISD destReg, srcReg (compare scalar double precision)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x66)  # COMISD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2F)  # COMISD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtss2sd*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit CVTSS2SD instruction: CVTSS2SD destReg, srcReg (convert single to double)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # CVTSS2SD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5A)  # CVTSS2SD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtsd2ss*(dest: var Bytes; destReg, srcReg: XmmRegister) =
  ## Emit CVTSD2SS instruction: CVTSD2SS destReg, srcReg (convert double to single)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # CVTSD2SS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x5A)  # CVTSD2SS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtsi2ss*(dest: var Bytes; destReg: XmmRegister; srcReg: Register) =
  ## Emit CVTSI2SS instruction: CVTSI2SS destReg, srcReg (convert integer to single)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # CVTSI2SS prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2A)  # CVTSI2SS opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtsi2sd*(dest: var Bytes; destReg: XmmRegister; srcReg: Register) =
  ## Emit CVTSI2SD instruction: CVTSI2SD destReg, srcReg (convert integer to double)
  var rex = RexPrefix()

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # CVTSI2SD prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2A)  # CVTSI2SD opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtss2si*(dest: var Bytes; destReg: Register; srcReg: XmmRegister) =
  ## Emit CVTSS2SI instruction: CVTSS2SI destReg, srcReg (convert single to integer)
  var rex = RexPrefix(w: true)

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF3)  # CVTSS2SI prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2D)  # CVTSS2SI opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCvtsd2si*(dest: var Bytes; destReg: Register; srcReg: XmmRegister) =
  ## Emit CVTSD2SI instruction: CVTSD2SI destReg, srcReg (convert double to integer)
  var rex = RexPrefix(w: true)

  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0xF2)  # CVTSD2SI prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x2D)  # CVTSD2SI opcode
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

# Atomic operations
# Lock prefix for atomic operations
proc emitLock*(dest: var Bytes) =
  ## Emit LOCK prefix for atomic operations
  dest.add(0xF0)

# Atomic exchange operations
proc emitXchg*(dest: var Bytes; a, b: Register) =
  ## Emit XCHG instruction: XCHG a, b (exchange)
  ## Opcode 0x87: XCHG r/m64, r64 - reg field is r64, r/m field is r/m64
  ## Note: XCHG is commutative, but we follow Intel convention
  var rex = RexPrefix(w: true)

  # For 0x87: r/m is first operand (a), reg is second operand (b)
  if needsRex(b): rex.r = true
  if needsRex(a): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x87)  # XCHG r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=b, rm=a

proc emitXchg*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit XCHG instruction: XCHG mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x87) # XCHG r/m64, r64
  dest.emitMem(int(reg), mem)

proc emitXadd*(dest: var Bytes; a, b: Register) =
  ## Emit XADD instruction: XADD a, b (exchange and add)
  ## Opcode 0x0F 0xC1: XADD r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For XADD: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xC1)  # XADD r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitXadd*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit XADD instruction: XADD mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(0xC1)
  dest.emitMem(int(reg), mem)

# Atomic compare and exchange
proc emitCmpxchg*(dest: var Bytes; a, b: Register) =
  ## Emit CMPXCHG instruction: CMPXCHG a, b (compare and exchange)
  ## Opcode 0x0F 0xB1: CMPXCHG r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For CMPXCHG: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xB1)  # CMPXCHG r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitCmpxchg*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit CMPXCHG instruction: CMPXCHG mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(0xB1)
  dest.emitMem(int(reg), mem)

# Atomic compare and exchange with 8-byte operand
proc emitCmpxchg8b*(dest: var Bytes; reg: Register) =
  ## Emit CMPXCHG8B instruction: CMPXCHG8B reg (compare and exchange 8 bytes)
  var rex = RexPrefix(w: true)

  if needsRex(reg): rex.b = true

  if rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xC7)  # CMPXCHG8B r/m64 opcode
  dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension

proc emitCmpxchg8b*(dest: var Bytes; mem: MemoryOperand) =
  ## Emit CMPXCHG8B instruction: CMPXCHG8B mem
  ## Note: With REX.W this is actually CMPXCHG16B on 64-bit processors
  var rex = RexPrefix(w: true)
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(0xC7)
  dest.emitMem(1, mem) # /1 extension

# Atomic bit operations
proc emitBtsAtomic*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit atomic BTS instruction: LOCK BTS reg, bit (atomic bit test and set)
  dest.emitLock()
  dest.emitBts(reg, bit)

proc emitBtrAtomic*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit atomic BTR instruction: LOCK BTR reg, bit (atomic bit test and reset)
  dest.emitLock()
  dest.emitBtr(reg, bit)

proc emitBtcAtomic*(dest: var Bytes; reg: Register; bit: int) =
  ## Emit atomic BTC instruction: LOCK BTC reg, bit (atomic bit test and complement)
  dest.emitLock()
  dest.emitBtc(reg, bit)


# Memory fence operations
proc emitMfence*(dest: var Bytes) =
  ## Emit MFENCE instruction: MFENCE (memory fence)
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAE)  # MFENCE opcode
  dest.add(0xF0)  # /6 extension

proc emitSfence*(dest: var Bytes) =
  ## Emit SFENCE instruction: SFENCE (store fence)
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAE)  # SFENCE opcode
  dest.add(0xF8)  # /7 extension

proc emitLfence*(dest: var Bytes) =
  ## Emit LFENCE instruction: LFENCE (load fence)
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAE)  # LFENCE opcode
  dest.add(0xE8)  # /5 extension

# Pause instruction for spin loops
proc emitPause*(dest: var Bytes) =
  ## Emit PAUSE instruction: PAUSE (pause for spin loops)
  dest.add(0xF3)  # PAUSE prefix
  dest.add(0x90)  # NOP opcode

# Memory ordering operations
proc emitClflush*(dest: var Bytes; reg: Register) =
  ## Emit CLFLUSH instruction: CLFLUSH reg (cache line flush)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAE)  # CLFLUSH opcode
  dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension

proc emitClflushopt*(dest: var Bytes; reg: Register) =
  ## Emit CLFLUSHOPT instruction: CLFLUSHOPT reg (cache line flush optimized)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x66)  # CLFLUSHOPT prefix
  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0xAE)  # CLFLUSHOPT opcode
  dest.add(encodeModRM(amDirect, 7, int(reg)))  # /7 extension

# Prefetch operations
proc emitPrefetchT0*(dest: var Bytes; reg: Register) =
  ## Emit PREFETCHT0 instruction: PREFETCHT0 reg (prefetch for all caches)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x18)  # PREFETCH opcode
  dest.add(encodeModRM(amDirect, 1, int(reg)))  # /1 extension

proc emitPrefetchT1*(dest: var Bytes; reg: Register) =
  ## Emit PREFETCHT1 instruction: PREFETCHT1 reg (prefetch for L2 cache)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x18)  # PREFETCH opcode
  dest.add(encodeModRM(amDirect, 2, int(reg)))  # /2 extension

proc emitPrefetchT2*(dest: var Bytes; reg: Register) =
  ## Emit PREFETCHT2 instruction: PREFETCHT2 reg (prefetch for L3 cache)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x18)  # PREFETCH opcode
  dest.add(encodeModRM(amDirect, 3, int(reg)))  # /3 extension

proc emitPrefetchNta*(dest: var Bytes; reg: Register) =
  ## Emit PREFETCHNTA instruction: PREFETCHNTA reg (prefetch non-temporal)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0x0F)  # Two-byte opcode prefix
  dest.add(0x18)  # PREFETCH opcode
  dest.add(encodeModRM(amDirect, 0, int(reg)))  # /0 extension


# Conditional set instructions
proc emitSetcc*(dest: var Bytes; code: byte; reg: Register) =
  ## Emit SETcc reg (set byte if condition)
  var rex = RexPrefix()
  if needsRex(reg): rex.b = true
  if rex.b: dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(code)
  dest.add(encodeModRM(amDirect, 0, int(reg))) # /0 extension not used but format needs reg in r/m field

proc emitSete*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x94, reg)
proc emitSetne*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x95, reg)
proc emitSetg*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x9F, reg)
proc emitSetge*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x9D, reg)
proc emitSetl*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x9C, reg)
proc emitSetle*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x9E, reg)
proc emitSeta*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x97, reg)
proc emitSetae*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x93, reg)
proc emitSetb*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x92, reg)
proc emitSetbe*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x96, reg)
proc emitSeto*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x90, reg)
proc emitSets*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x98, reg)
proc emitSetp*(dest: var Bytes; reg: Register) = dest.emitSetcc(0x9A, reg)

# Conditional move instructions
proc emitCmovcc*(dest: var Bytes; code: byte; destReg, srcReg: Register) =
  ## Emit CMOVcc destReg, srcReg
  var rex = RexPrefix(w: true)
  if needsRex(destReg): rex.r = true
  if needsRex(srcReg): rex.b = true

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(code)
  dest.add(encodeModRM(amDirect, int(destReg), int(srcReg)))

proc emitCmovcc*(dest: var Bytes; code: byte; destReg: Register; srcMem: MemoryOperand) =
  ## Emit CMOVcc destReg, mem
  var rex = RexPrefix(w: true)
  if needsRex(destReg): rex.r = true
  if needsRex(srcMem.base): rex.b = true
  if srcMem.hasIndex and needsRex(srcMem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x0F)
  dest.add(code)
  dest.emitMem(int(destReg), srcMem)

proc emitCmove*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x44, d, s)
proc emitCmove*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x44, d, s)

proc emitCmovne*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x45, d, s)
proc emitCmovne*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x45, d, s)

proc emitCmovg*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4F, d, s)
proc emitCmovg*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4F, d, s)

proc emitCmovge*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4D, d, s)
proc emitCmovge*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4D, d, s)

proc emitCmovl*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4C, d, s)
proc emitCmovl*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4C, d, s)

proc emitCmovle*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4E, d, s)
proc emitCmovle*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4E, d, s)

proc emitCmova*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x47, d, s)
proc emitCmova*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x47, d, s)

proc emitCmovae*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x43, d, s)
proc emitCmovae*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x43, d, s)

proc emitCmovb*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x42, d, s)
proc emitCmovb*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x42, d, s)

proc emitCmovbe*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x46, d, s)
proc emitCmovbe*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x46, d, s)

proc emitCmovo*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x40, d, s)
proc emitCmovo*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x40, d, s)

proc emitCmovno*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x41, d, s)
proc emitCmovno*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x41, d, s)

proc emitCmovs*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x48, d, s)
proc emitCmovs*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x48, d, s)

proc emitCmovns*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x49, d, s)
proc emitCmovns*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x49, d, s)

proc emitCmovp*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4A, d, s)
proc emitCmovp*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4A, d, s)

proc emitCmovnp*(dest: var Bytes; d, s: Register) = dest.emitCmovcc(0x4B, d, s)
proc emitCmovnp*(dest: var Bytes; d: Register; s: MemoryOperand) = dest.emitCmovcc(0x4B, d, s)

# Stack operations
proc emitPush*(dest: var Bytes; reg: Register) =
  ## Emit PUSH reg
  var rex = RexPrefix()
  if needsRex(reg): rex.b = true
  if rex.b: dest.add(encodeRex(rex))
  dest.add(byte(0x50 + (int(reg) and 7)))

proc emitPush*(dest: var Bytes; imm: int32) =
  ## Emit PUSH imm32
  if imm >= -128 and imm <= 127:
    dest.add(0x6A)
    dest.add(byte(imm and 0xFF))
  else:
    dest.add(0x68)
    dest.addt32(imm)

proc emitPop*(dest: var Bytes; reg: Register) =
  ## Emit POP reg
  var rex = RexPrefix()
  if needsRex(reg): rex.b = true
  if rex.b: dest.add(encodeRex(rex))
  dest.add(byte(0x58 + (int(reg) and 7)))

# Control flow instructions
proc emitRet*(dest: var Bytes) =
  ## Emit RET instruction
  dest.add(0xC3)

proc emitCall*(dest: var Buffer; target: LabelId) =
  ## Emit CALL instruction: CALL target (relative call)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0xE8)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkCall, 5)  # 1 byte opcode + 4 bytes displacement

proc emitJmp*(dest: var Buffer; target: LabelId) =
  ## Emit JMP instruction: JMP target (relative jump)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0xE9)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJmp, 5)  # 1 byte opcode + 4 bytes displacement

# Conditional jump instructions
proc emitJe*(dest: var Buffer; target: LabelId) =
  ## Emit JE instruction: JE target (jump if equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x84)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJe, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJne*(dest: var Buffer; target: LabelId) =
  ## Emit JNE instruction: JNE target (jump if not equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x85)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJne, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJg*(dest: var Buffer; target: LabelId) =
  ## Emit JG instruction: JG target (jump if greater)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8F)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJg, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJl*(dest: var Buffer; target: LabelId) =
  ## Emit JL instruction: JL target (jump if less)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8C)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJl, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJge*(dest: var Buffer; target: LabelId) =
  ## Emit JGE instruction: JGE target (jump if greater or equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8D)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJge, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJle*(dest: var Buffer; target: LabelId) =
  ## Emit JLE instruction: JLE target (jump if less or equal)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8E)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJle, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJa*(dest: var Buffer; target: LabelId) =
  ## Emit JA instruction: JA target (jump if above, unsigned)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x87)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJa, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJb*(dest: var Buffer; target: LabelId) =
  ## Emit JB instruction: JB target (jump if below, unsigned)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x82)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJb, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJae*(dest: var Buffer; target: LabelId) =
  ## Emit JAE instruction: JAE target (jump if above or equal, unsigned)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x83)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJae, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJbe*(dest: var Buffer; target: LabelId) =
  ## Emit JBE instruction: JBE target (jump if below or equal, unsigned)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x86)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJbe, 6)  # 2 bytes opcode + 4 bytes displacement

proc emitJo*(dest: var Buffer; target: LabelId) =
  ## Emit JO instruction: JO target (jump if overflow)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x80)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJo, 6)

proc emitJno*(dest: var Buffer; target: LabelId) =
  ## Emit JNO instruction: JNO target (jump if not overflow)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x81)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJno, 6)

proc emitJs*(dest: var Buffer; target: LabelId) =
  ## Emit JS instruction: JS target (jump if sign)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x88)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJs, 6)

proc emitJns*(dest: var Buffer; target: LabelId) =
  ## Emit JNS instruction: JNS target (jump if not sign)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x89)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJns, 6)

proc emitJp*(dest: var Buffer; target: LabelId) =
  ## Emit JP instruction: JP target (jump if parity)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8A)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJp, 6)

proc emitJnp*(dest: var Buffer; target: LabelId) =
  ## Emit JNP instruction: JNP target (jump if not parity)
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x0F)
  dest.data.add(0x8B)
  dest.data.addt32(0)  # Placeholder
  dest.addReloc(pos, target, rkJnp, 6)

proc emitJmpReg*(dest: var Bytes; reg: Register) =
  ## Emit JMP instruction: JMP reg (indirect jump)
  var rex = RexPrefix()

  if needsRex(reg): rex.b = true

  if rex.b:
    dest.add(encodeRex(rex))

  dest.add(0xFF)  # JMP r/m64 opcode
  dest.add(encodeModRM(amDirect, 4, int(reg)))  # /4 extension

# Bit manipulation instructions
proc emitAnd*(dest: var Bytes; a, b: Register) =
  ## Emit AND instruction: AND a, b (a = a AND b)
  ## Opcode 0x21: AND r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x21: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x21)  # AND r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitAnd*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit AND instruction: AND mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.r or rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0x21)
  dest.emitMem(int(reg), mem)

proc emitOr*(dest: var Bytes; a, b: Register) =
  ## Emit OR instruction: OR a, b (a = a OR b)
  ## Opcode 0x09: OR r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x09: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x09)  # OR r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitOr*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit OR instruction: OR mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.r or rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0x09)
  dest.emitMem(int(reg), mem)

proc emitXor*(dest: var Bytes; a, b: Register) =
  ## Emit XOR instruction: XOR a, b (a = a XOR b)
  ## Opcode 0x31: XOR r/m64, r64 - reg field is source, r/m field is destination
  var rex = RexPrefix(w: true)

  # For 0x31: r/m is dest (a), reg is source (b)
  if needsRex(b): rex.r = true  # source register extension
  if needsRex(a): rex.b = true  # destination register extension

  if rex.r or rex.b or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x31)  # XOR r/m64, r64 opcode
  dest.add(encodeModRM(amDirect, int(b), int(a)))  # reg=source(b), rm=dest(a)

proc emitXor*(dest: var Bytes; mem: MemoryOperand; reg: Register) =
  ## Emit XOR instruction: XOR mem, reg
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true
  if rex.r or rex.b or rex.x or rex.w: dest.add(encodeRex(rex))
  dest.add(0x31)
  dest.emitMem(int(reg), mem)

# Atomic arithmetic operations
proc emitAddAtomic*(dest: var Bytes; a, b: Register) =
  ## Emit atomic ADD instruction: LOCK ADD a, b (atomic add)
  dest.emitLock()
  dest.emitAdd(a, b)

proc emitSubAtomic*(dest: var Bytes; a, b: Register) =
  ## Emit atomic SUB instruction: LOCK SUB a, b (atomic subtract)
  dest.emitLock()
  dest.emitSub(a, b)

proc emitAndAtomic*(dest: var Bytes; a, b: Register) =
  ## Emit atomic AND instruction: LOCK AND a, b (atomic and)
  dest.emitLock()
  dest.emitAnd(a, b)

proc emitOrAtomic*(dest: var Bytes; a, b: Register) =
  ## Emit atomic OR instruction: LOCK OR a, b (atomic or)
  dest.emitLock()
  dest.emitOr(a, b)

proc emitXorAtomic*(dest: var Bytes; a, b: Register) =
  ## Emit atomic XOR instruction: LOCK XOR a, b (atomic xor)
  dest.emitLock()
  dest.emitXor(a, b)

# Atomic increment and decrement
proc emitIncAtomic*(dest: var Bytes; reg: Register) =
  ## Emit atomic INC instruction: LOCK INC reg (atomic increment)
  dest.emitLock()
  dest.emitInc(reg)

proc emitDecAtomic*(dest: var Bytes; reg: Register) =
  ## Emit atomic DEC instruction: LOCK DEC reg (atomic decrement)
  dest.emitLock()
  dest.emitDec(reg)

# System instructions
proc emitSyscall*(dest: var Bytes) =
  ## Emit SYSCALL instruction
  dest.add(0x0F)
  dest.add(0x05)

# NOP instruction
proc emitNop*(dest: var Bytes) =
  ## Emit NOP instruction
  dest.add(0x90)


proc emitLea*(dest: var Buffer; reg: Register; target: LabelId) =
  ## Emit LEA instruction: LEA reg, [RIP + target]
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0x48) # REX.W
  dest.data.add(0x8D) # LEA opcode
  dest.data.add(encodeModRM(amIndirect, int(reg), 5)) # Mod=00, Reg=reg, RM=101 (RIP-rel)
  dest.data.addt32(0) # Placeholder
  dest.addReloc(pos, target, rkLea, 7)

proc emitIatCall*(dest: var Buffer; iatSlot: int) =
  ## Emit indirect call through IAT: CALL [rip+disp32] where disp32 points to IAT entry
  ## The displacement will be patched later when IAT address is known
  let pos = dest.data.getCurrentPosition()
  dest.data.add(0xFF)  # CALL opcode
  dest.data.add(0x15)  # ModRM: [rip+disp32]
  dest.data.addt32(0)  # Placeholder displacement
  # Use LabelId to store IAT slot index (will be converted to IAT RVA later)
  dest.addReloc(pos, LabelId(iatSlot), rkIatCall, 6)

proc emitLea*(dest: var Bytes; reg: Register; mem: MemoryOperand) =
  ## Emit LEA instruction: LEA reg, mem
  var rex = RexPrefix(w: true)
  if needsRex(reg): rex.r = true
  if needsRex(mem.base): rex.b = true
  if mem.hasIndex and needsRex(mem.index): rex.x = true

  if rex.r or rex.b or rex.x or rex.w:
    dest.add(encodeRex(rex))

  dest.add(0x8D) # LEA r64, m
  dest.emitMem(int(reg), mem)
