# Nifasm - Relocation System
# A system for tracking and managing relocations in the instruction stream

import std/[tables]
import buffers

type
  # Label system for jump optimization
  LabelId* = distinct int

  # Label definition in the instruction stream
  LabelDef* = object
    id*: LabelId
    position*: int  # Position where label is defined

  # Types of instructions requiring relocation/patching
  # Since we intend to support mixed architectures ("fat binaries") we need to
  # combine x86 and ARM64 instruction types here for this to work out.
  RelocKind* = enum
    rkCall, rkJmp, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
    rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp, rkLea, rkIatCall
    rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP

  # Relocation entry for optimization and patching
  RelocEntry* = object
    position*: int        # Position in buffer where instruction starts
    target*: LabelId      # Target label ID (or IAT slot index for rkIatCall)
    kind*: RelocKind      # Type of relocation/instruction
    originalSize*: int    # Original instruction size in bytes

  # Buffer for accumulating instruction bytes
  Buffer* = object
    data*: Bytes
    relocs*: seq[RelocEntry]  # Track instructions needing relocation
    labels*: seq[LabelDef]    # Track label definitions
    nextLabelId*: int         # Next available label ID

# LabelId equality comparison
proc `==`*(a, b: LabelId): bool =
  int(a) == int(b)

proc initBuffer*(): Buffer =
  result = Buffer(data: initBytes(), relocs: @[], labels: @[], nextLabelId: 0)

# Label system functions
proc createLabel*(buf: var Buffer): LabelId =
  ## Create a new label ID
  result = LabelId(buf.nextLabelId)
  inc(buf.nextLabelId)

proc defineLabel*(buf: var Buffer; label: LabelId) =
  ## Define a label at the current position
  buf.labels.add(LabelDef(id: label, position: buf.data.len))

proc getLabelPosition*(buf: Buffer; label: LabelId): int =
  ## Get the position of a label definition
  for labelDef in buf.labels:
    if labelDef.id == label:
      return labelDef.position
  raise newException(ValueError, "Label not found")

# Relocation helper functions
proc addReloc*(buf: var Buffer; position: int; target: LabelId; kind: RelocKind; size: int) =
  ## Add a relocation entry to the buffer
  buf.relocs.add(RelocEntry(
    position: position,
    target: target,
    kind: kind,
    originalSize: size
  ))

proc getCurrentPosition*(buf: Bytes): int =
  ## Get the current position in the buffer
  buf.len

proc calculateRelocDistance*(fromPos: int; toPos: int; kind: RelocKind = rkJmp): int =
  ## Calculate the distance for a relative instruction
  ## For x86-64, the distance is calculated from after the entire instruction
  ## For ARM64, the distance is calculated from the start of the instruction
  case kind
  of rkCall, rkJmp: toPos - (fromPos + 5)  # x86: distance from after the complete instruction
  of rkLea: toPos - (fromPos + 7)  # LEA is 7 bytes: 48 8D xx disp32 (REX.W + opcode + ModRM + disp32)
  of rkIatCall: toPos - (fromPos + 6)  # IAT call is 6 bytes: FF 15 disp32
  of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
     rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp: toPos - (fromPos + 6)
  of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP:
    toPos - fromPos  # ARM64: distance from start of instruction (will be divided by 4 later)

# Jump optimization functions
proc updateRelocDisplacements*(buf: var Buffer) =
  ## Update all relocation displacements based on current label positions
  for reloc in buf.relocs:
    # Skip IAT calls - they are patched later when IAT address is known
    if reloc.kind == rkIatCall:
      continue
    let currentPos = reloc.position
    let targetPos = buf.getLabelPosition(reloc.target)
    let distance = calculateRelocDistance(currentPos, targetPos, reloc.kind)

    # Convert to signed 32-bit for proper encoding
    let signedDistance = int32(distance)

    # Check if we have enough space in the buffer
    let requiredSize =
      case reloc.kind
      of rkCall, rkJmp: currentPos + 5
      of rkLea: currentPos + 7
      of rkIatCall, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
         rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp:
        currentPos + 6
      of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP:
        currentPos + 4  # All ARM64 instructions are 4 bytes

    if requiredSize > buf.data.len:
      continue  # Skip this relocation if buffer is too small

    if reloc.kind == rkIatCall:
      # IAT call uses FF 15 [rip+disp32] - 6 bytes total
      # The displacement is at offset 2-5
      buf.data[currentPos + 2] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 3] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 5] = byte((signedDistance shr 24) and 0xFF)
      continue

    if reloc.kind == rkLea:
      # LEA instruction is 7 bytes: 48 8D 05 (ModRM=05) disp32
      # distance is from end of instruction.
      # RIP-relative: effective address = RIP + disp.
      # RIP is address of next instruction.
      # So distance calculation is correct (toPos - (currentPos + 7)).
      discard

    # Update the displacement in the instruction
    case reloc.kind
    of rkIatCall:
      # IAT call: FF 15 [rip+disp32] - displacement at offset 2-5
      buf.data[currentPos + 2] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 3] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 5] = byte((signedDistance shr 24) and 0xFF)
    of rkLea:
      # LEA uses 32-bit displacement (little-endian) at offset 3
      buf.data[currentPos + 3] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 5] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 6] = byte((signedDistance shr 24) and 0xFF)
    of rkCall:
      # CALL uses 32-bit displacement (little-endian)
      buf.data[currentPos + 1] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 2] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 3] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 24) and 0xFF)
    of rkJmp:
      # JMP uses 32-bit displacement (little-endian)
      buf.data[currentPos + 1] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 2] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 3] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 24) and 0xFF)
    of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
       rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp:
      # Conditional jumps use 32-bit displacement (little-endian)
      # Conditional jumps have 2-byte opcode, so displacement starts at +2
      buf.data[currentPos + 2] = byte(signedDistance and 0xFF)
      buf.data[currentPos + 3] = byte((signedDistance shr 8) and 0xFF)
      buf.data[currentPos + 4] = byte((signedDistance shr 16) and 0xFF)
      buf.data[currentPos + 5] = byte((signedDistance shr 24) and 0xFF)
    of rkB, rkBL:
      # ARM64 B/BL: 26-bit signed immediate, offset in instructions (divide distance by 4)
      let offsetInInstructions = distance div 4
      let imm26 = uint32(int32(offsetInInstructions) and 0x03FFFFFF)
      # Read existing instruction, preserve opcode bits (bits 31:26)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      let instr = (baseInstr and 0xFC000000'u32) or imm26
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)
    of rkBEQ, rkBNE:
      # ARM64 conditional branches: 19-bit signed immediate, offset in instructions
      let offsetInInstructions = distance div 4
      let imm19 = uint32(int32(offsetInInstructions) and 0x7FFFF)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      let instr = (baseInstr and 0xFF00001F'u32) or (imm19 shl 5)
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)
    of rkCBZ, rkCBNZ:
      # ARM64 compare and branch: 19-bit signed immediate, offset in instructions
      let offsetInInstructions = distance div 4
      let imm19 = uint32(int32(offsetInInstructions) and 0x7FFFF)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      let instr = (baseInstr and 0xFF00001F'u32) or (imm19 shl 5)
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)
    of rkTBZ, rkTBNZ:
      # ARM64 test bit and branch: 14-bit signed immediate, offset in instructions
      let offsetInInstructions = distance div 4
      let imm14 = uint32(int32(offsetInInstructions) and 0x3FFF)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      let instr = (baseInstr and 0xFFF8001F'u32) or (imm14 shl 5)
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)
    of rkADR:
      # ARM64 ADR: 21-bit signed immediate, byte offset from PC
      let imm21 = uint32(int32(distance) and 0x1FFFFF)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      # ADR encoding: immhi:immlo at bits 30:29 and 23:5
      let immlo = (imm21 and 0x03'u32) shl 29
      let immhi = (imm21 shr 2) shl 5
      let instr = (baseInstr and 0x9F00001F'u32) or immlo or immhi
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)
    of rkADRP:
      # ARM64 ADRP: 21-bit signed immediate (page address), offset in instructions
      # Page address = (offset_in_instructions * 4) and 0xFFFFF000
      let offsetInInstructions = distance div 4
      let pageOffset = (offsetInInstructions * 4) div 4096  # Page offset (12-bit aligned)
      let imm21 = uint32(int32(pageOffset) and 0x1FFFFF)
      let baseInstr = uint32(buf.data[currentPos]) or
                      (uint32(buf.data[currentPos + 1]) shl 8) or
                      (uint32(buf.data[currentPos + 2]) shl 16) or
                      (uint32(buf.data[currentPos + 3]) shl 24)
      # ADRP encoding: immhi:immlo at bits 30:29 and 23:5
      let immlo = (imm21 and 0x03'u32) shl 29
      let immhi = (imm21 shr 2) shl 5
      let instr = (baseInstr and 0x9F00001F'u32) or immlo or immhi
      buf.data[currentPos] = byte(instr and 0xFF)
      buf.data[currentPos + 1] = byte((instr shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte((instr shr 16) and 0xFF)
      buf.data[currentPos + 3] = byte((instr shr 24) and 0xFF)

proc canUseShortJump(distance: int): bool {.inline.} =
  ## Check if a jump can use 8-bit displacement
  distance >= -128 and distance <= 127

proc optimizeJumps*(buf: Buffer): Buffer =
  ## Optimize all jump instructions by creating a new optimized buffer
  var optimized = Buffer()

  # Copy all data to new buffer
  optimized.data = buf.data
  optimized.labels = buf.labels
  optimized.relocs = buf.relocs

  # Update all reloc displacements in the new buffer
  optimized.updateRelocDisplacements()

  # Try to optimize jumps by creating a new buffer with shorter instructions
  var changed = true
  var iterations = 0
  const maxIterations = 10

  while changed and iterations < maxIterations:
    changed = false
    inc(iterations)

    var newBuf = Buffer()
    newBuf.labels = optimized.labels # Copy labels, will update positions

    # Map label positions to indices for efficient update
    var posToLabels = initTable[int, seq[int]]()
    for idx, lab in optimized.labels:
      if not posToLabels.hasKey(lab.position):
        posToLabels[lab.position] = @[]
      posToLabels[lab.position].add(idx)

    var relocIndex = 0
    var i = 0
    var currentNewPos = 0

    while i < optimized.data.len:
      # Update labels at this position
      if posToLabels.hasKey(i):
        for labIdx in posToLabels[i]:
          newBuf.labels[labIdx].position = currentNewPos

      # Check if we're at a reloc instruction
      if relocIndex < optimized.relocs.len and optimized.relocs[relocIndex].position == i:
        let reloc = optimized.relocs[relocIndex]
        var addedBytes = 0
        # Skip IAT calls - they are patched later when IAT address is known
        if reloc.kind == rkIatCall:
          # Copy IAT call instruction as-is (6 bytes: FF 15 [rip+disp32])
          for j in 0..<6:
            if i + j < optimized.data.len:
              newBuf.data.add(optimized.data[i + j])
          addedBytes = 6
          newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          i += 6
          currentNewPos += 6
          inc(relocIndex)
          continue
        let targetPos = optimized.getLabelPosition(reloc.target)
        let distance = calculateRelocDistance(i, targetPos, reloc.kind)
        let originalSize =
          case reloc.kind
          of rkLea: 7
          of rkIatCall, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
             rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp: 6
          of rkCall, rkJmp: 5
          of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP:
            4  # All ARM64 instructions are 4 bytes

        # Check if we can use a short jump
        if reloc.kind == rkIatCall:
          # IAT call is fixed size: FF 15 [rip+disp32]
          newBuf.data.add(0xFF)  # CALL opcode
          newBuf.data.add(0x15)  # ModRM: [rip+disp32]
          newBuf.data.addt32(int32(distance))
          addedBytes = 6
          # Keep track of this relocation in the new buffer
          newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
        elif reloc.kind == rkLea:
          # LEA is fixed size, copy original bytes
          # The ModRM byte is at +2.
          newBuf.data.add(0x48)
          newBuf.data.add(0x8D)
          newBuf.data.add(optimized.data[i+2])
          newBuf.data.addt32(int32(distance))
          addedBytes = 7

          # Keep track of this relocation in the new buffer
          newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)

        elif reloc.kind in {rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP}:
          # ARM64 instructions are fixed size (4 bytes), copy as-is
          newBuf.data.add(optimized.data[i])
          newBuf.data.add(optimized.data[i + 1])
          newBuf.data.add(optimized.data[i + 2])
          newBuf.data.add(optimized.data[i + 3])
          addedBytes = 4
          # Keep track of this relocation in the new buffer
          newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)

        elif canUseShortJump(distance):
          case reloc.kind
          of rkCall:
            # CALL doesn't have 8-bit form, emit as 32-bit
            newBuf.data.add(0xE8)  # CALL opcode
            newBuf.data.addt32(int32(distance))
            addedBytes = 5
            newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          of rkJmp:
            # JMP with 8-bit displacement
            newBuf.data.add(0xEB)  # JMP rel8 opcode
            newBuf.data.add(byte(distance and 0xFF))
            addedBytes = 2
            changed = true
            # No need to track reloc for short jump
          of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
             rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp:
            # Conditional jumps with 8-bit displacement
            let shortOpcode =
              case reloc.kind
              of rkJe: 0x74
              of rkJne: 0x75
              of rkJg: 0x7F
              of rkJl: 0x7C
              of rkJge: 0x7D
              of rkJle: 0x7E
              of rkJa: 0x77
              of rkJb: 0x72
              of rkJae: 0x73
              of rkJbe: 0x76
              of rkJo: 0x70
              of rkJno: 0x71
              of rkJs: 0x78
              of rkJns: 0x79
              of rkJp: 0x7A
              of rkJnp: 0x7B
              else: 0x74  # Default to JE

            newBuf.data.add(byte(shortOpcode))
            newBuf.data.add(byte(distance and 0xFF))
            addedBytes = 2
            changed = true
          else:
            # ARM64 relocations should be handled earlier, this should never be reached
            raise newException(ValueError, "ARM64 relocation in x86 short jump path: " & $reloc.kind)
        else:
          # Use 32-bit displacement
          case reloc.kind
          of rkCall:
            newBuf.data.add(0xE8)  # CALL opcode
            newBuf.data.addt32(int32(distance))
            addedBytes = 5
            newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          of rkJmp:
            newBuf.data.add(0xE9)  # JMP rel32 opcode
            newBuf.data.addt32(int32(distance))
            addedBytes = 5
            newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          of rkIatCall:
            # IAT call: FF 15 [rip+disp32]
            newBuf.data.add(0xFF)  # CALL opcode
            newBuf.data.add(0x15)  # ModRM: [rip+disp32]
            newBuf.data.addt32(int32(distance))
            addedBytes = 6
            newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
             rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp:
            # Conditional jumps with 32-bit displacement
            newBuf.data.add(0x0F)  # Two-byte opcode prefix
            let longOpcode =
              case reloc.kind
              of rkJe: 0x84
              of rkJne: 0x85
              of rkJg: 0x8F
              of rkJl: 0x8C
              of rkJge: 0x8D
              of rkJle: 0x8E
              of rkJa: 0x87
              of rkJb: 0x82
              of rkJae: 0x83
              of rkJbe: 0x86
              of rkJo: 0x80
              of rkJno: 0x81
              of rkJs: 0x88
              of rkJns: 0x89
              of rkJp: 0x8A
              of rkJnp: 0x8B
              else: 0x84  # Default to JE
            newBuf.data.add(byte(longOpcode))
            newBuf.data.addt32(int32(distance))
            addedBytes = 6
            newBuf.addReloc(currentNewPos, reloc.target, reloc.kind, reloc.originalSize)
          else:
            # Unexpected relocation kind - should be handled earlier in the if-elif chain
            raise newException(ValueError, "Unexpected relocation kind in jump optimization: " & $reloc.kind)

        # Skip the original instruction bytes
        i += originalSize
        currentNewPos += addedBytes
        inc(relocIndex)
      else:
        # Copy non-reloc byte
        newBuf.data.add(optimized.data[i])
        i += 1
        currentNewPos += 1

    # Update labels at the very end
    if posToLabels.hasKey(i):
      for labIdx in posToLabels[i]:
        newBuf.labels[labIdx].position = currentNewPos

    # Update the optimized buffer
    optimized = newBuf

    # Update displacements for next iteration
    optimized.updateRelocDisplacements()

  return optimized

proc finalize*(buf: var Buffer) =
  ## Finalize the buffer by optimizing all jump instructions
  let optimized = buf.optimizeJumps()
  buf = optimized
