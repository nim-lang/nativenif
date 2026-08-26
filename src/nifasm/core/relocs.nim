# Nifasm - Relocation System
# A system for tracking and managing relocations in the instruction stream

import std/[tables, sets]
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
    rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP,
    rkADRADD
      ## AArch64 long-range address materialization: `adr rd, .+lo` followed by
      ## `add|sub rd, rd, #hi, lsl #12` — 8 bytes, reach ±16 MB. Plain `ADR` has a
      ## 21-bit signed field (±1 MB) and the patcher masked to it WITHOUT a range
      ## check, so a rodata reference from a proc further away silently wrapped and
      ## produced an address 2 MB (2^21) off. It stays a pure distance computation —
      ## `adr` supplies the PC — so unlike `adrp`+`add` it needs no page arithmetic
      ## and no knowledge of the section's final vaddr, which is why it can live here
      ## and serve Mach-O, ELF and PE alike.
    rkTB, rkTBL, rkTBcond, rkTADR, rkTMovwMovt, rkTMovwMovtFunc,
    rkAvrRjmp, rkAvrRcall, rkAvrBrcond, rkAvrJmp, rkAvrCall, rkAvrLdiAddr,
    rkRvBranch, rkRvJal, rkRvAbsPair
      ## RV32. Every instruction is four bytes, so unlike AVR nothing here is
      ## halved — but the immediates are PERMUTED rather than shifted, which is
      ## this target's own trap.
      ##
      ## `rkRvBranch` is B-format: `imm[12|10:5]` above the registers and
      ## `imm[4:1|11]` below them, in halfword units with bit 0 implicit. Bit 11
      ## crosses the two halves, in the field a careless reading gives to bit 4.
      ## ±4 KB. The condition rides in the word already in the buffer, so one
      ## kind serves all six.
      ##
      ## `rkRvJal` is J-format: `imm[20|10:1|11|19:12]`, ±1 MB, and the link
      ## register likewise stays in the buffer — so the same kind covers a jump
      ## (`rd` = x0) and a call (`rd` = ra).
      ##
      ## `rkRvAbsPair` is `lui`+`addi` carrying an absolute address, with the
      ## `+0x800` compensation `addi`'s SIGNED immediate forces. Two words, fixed
      ## size, the twin of Cortex-M's `rkTMovwMovt`.
      ## AVR. Flash is addressed in WORDS and everything `relocs` measures is in
      ## BYTES, so every displacement here is halved before it is encoded — a
      ## step with no analogue on the other targets, and one that fails silently
      ## if omitted, because a branch to half the intended distance still lands
      ## on a real instruction and runs.
      ##
      ## The PC is the NEXT word, so the displacement is `target - (pos + 2)`
      ## bytes. Reach is short and differs per form: `rkAvrRjmp`/`rkAvrRcall`
      ## carry 12 signed word bits (±4 KB), and `rkAvrBrcond` carries 7 (±128
      ## BYTES) — narrow enough that an ordinary loop body can outgrow it, which
      ## is why the selector must be prepared to invert the condition and branch
      ## over an `rjmp`. The condition itself is preserved from the word already
      ## in the buffer, so one kind covers all fourteen.
      ##
      ## `rkAvrJmp`/`rkAvrCall` are two words carrying an absolute 22-bit WORD
      ## address, which reaches all of flash and is therefore the default form.
      ##
      ## `rkAvrLdiAddr` is a pair of `ldi`s carrying a label's absolute DATA
      ## address, low half then high — the twin of `rkTMovwMovt`, fixed-size for
      ## the same reason: patching must never resize an instruction.
      ## Thumb-2 (Cortex-M). All four branch forms are 32-bit encodings stored as
      ## two little-endian HALFWORDS, high halfword first.
      ##
      ## Thumb's PC is `instruction_address + 4` regardless of the instruction's own
      ## width — two halfwords ahead, not one instruction ahead — so the displacement
      ## is `target - (pos + 4)`, matching NEITHER x86 (from the end of the
      ## instruction) nor AArch64 (from its start).
      ##
      ## `rkTB`/`rkTBL` reach ±16 MB via the S:I1:I2:imm10:imm11 encoding, where
      ## `I1 = NOT(J1 XOR S)` and `I2 = NOT(J2 XOR S)` — the sign-dependent J-bit
      ## inversion that makes these encodings notorious. `rkTBcond` spends four bits
      ## on the condition and so reaches only ±1 MB, and encodes S:J2:J1:imm6:imm11
      ## with NO inversion. The condition itself is preserved from the halfword
      ## already in the buffer, so one kind covers all 14 conditions.
      ##
      ## `rkTADR` is `ADD rd, PC, #imm12` against `Align(PC, 4)` (±4 KB, and the
      ## patcher swaps in the SUB form for a negative displacement). `rkTMovwMovt`
      ## is a MOVW+MOVT pair carrying a label's ABSOLUTE address — no reach limit,
      ## which a bare-metal image can rely on because its load address is fixed.
      ##
      ## `rkTMovwMovtFunc` is the same pair for a CODE address, and ORs in bit 0.
      ## That bit is the Thumb-state marker, not part of the address: `blx` to an
      ## even address switches the core to ARM state, which M-profile does not
      ## have, so the call takes a UsageFault — and with no handler installed the
      ## core simply locks up. A function pointer without it looks completely
      ## ordinary right up until it is called.

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
    absBase*: uint32          # Added to every ABSOLUTE relocation's target. A
                              # PC-relative branch needs no such thing, but a
                              # MOVW+MOVT pair carries a real ADDRESS, so it has
                              # to know where the section will be loaded. Zero for
                              # every target that has no absolute relocation.
    fixedRanges*: seq[(int, int)] # [start, end) byte ranges whose LAYOUT is frozen:
                              # a `casejmp` computed-goto region (`jmp base + idx*N`)
                              # relies on every slot keeping its exact byte size, so
                              # the jump optimizers must not delete, invert or shrink
                              # instructions inside — only patch displacements.

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
  ## Get the position of a label definition. A linear scan, which is fine for the
  ## one-off callers; anything that resolves EVERY reloc's target must build a
  ## `labelPositions` table instead — see it for why.
  for labelDef in buf.labels:
    if labelDef.id == label:
      return labelDef.position
  raise newException(ValueError, "Label not found")

proc labelPositions*(buf: Buffer): seq[int] =
  ## Every label's position, indexed by its id; `-1` for an id never defined (0 is a
  ## legal position — the first byte of the buffer — so the sentinel cannot be 0).
  ## `createLabel` hands ids out densely from 0, so this is an array, not a table.
  ##
  ## Exists because `getLabelPosition` is a linear scan over `buf.labels` and
  ## `updateRelocDisplacements` called it once per relocation: 106,810 relocs
  ## against 154,679 labels on a `nimsem` link, which was 40% of nifasm's entire
  ## run time. It is built at the point of use rather than cached in `Buffer`
  ## because the jump optimizers (`threadJumps`, `invertCondJumps`,
  ## `shortenX64Jumps`) rewrite label positions in place, and a stored table would
  ## have to be invalidated at each of them.
  ##
  ## FIRST definition wins, matching `getLabelPosition`'s scan order.
  var n = buf.nextLabelId
  for labelDef in buf.labels:                 # a buffer may carry ids minted elsewhere
    if int(labelDef.id) >= n: n = int(labelDef.id) + 1
  result = newSeq[int](n)
  for i in 0 ..< n: result[i] = -1
  for labelDef in buf.labels:
    let id = int(labelDef.id)
    if result[id] < 0: result[id] = labelDef.position

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

proc calculateRelocDistance(fromPos: int; toPos: int; kind: RelocKind = rkJmp): int =
  ## Calculate the distance for a relative instruction
  ## For x86-64, the distance is calculated from after the entire instruction
  ## For ARM64, the distance is calculated from the start of the instruction
  case kind
  of rkCall, rkJmp: toPos - (fromPos + 5)  # x86: distance from after the complete instruction
  of rkLea: toPos - (fromPos + 7)  # LEA is 7 bytes: 48 8D xx disp32 (REX.W + opcode + ModRM + disp32)
  of rkIatCall: toPos - (fromPos + 6)  # IAT call is 6 bytes: FF 15 disp32
  of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
     rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp: toPos - (fromPos + 6)
  of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP, rkADRADD:
    toPos - fromPos  # ARM64: distance from start of instruction (will be divided by 4 later)
  of rkTB, rkTBL, rkTBcond, rkTADR:
    toPos - (fromPos + 4)   # Thumb: PC reads two halfwords ahead of the instruction
  of rkTMovwMovt, rkTMovwMovtFunc:
    toPos                   # absolute: the patcher wants the target, not a distance
  of rkAvrRjmp, rkAvrRcall, rkAvrBrcond:
    toPos - (fromPos + 2)   # AVR: the PC is the next WORD; halved by the patcher
  of rkAvrJmp, rkAvrCall, rkAvrLdiAddr:
    toPos                   # absolute, like the Thumb pair above
  of rkRvBranch, rkRvJal:
    toPos - fromPos         # RV32: from the instruction's own address
  of rkRvAbsPair:
    toPos                   # absolute

proc patchAvrWord(buf: var Buffer; at: int; keep, bits: uint16) =
  ## Rewrite one AVR word in place, preserving every bit outside `keep`'s
  ## complement. Reading the word back rather than rebuilding it is what lets a
  ## single relocation kind serve all fourteen branch conditions and both
  ## `ldi` halves.
  let old = uint16(buf.data[at]) or (uint16(buf.data[at + 1]) shl 8)
  let w = (old and keep) or bits
  buf.data[at] = byte(w and 0xFF)
  buf.data[at + 1] = byte((w shr 8) and 0xFF)

proc patchAvrReloc(buf: var Buffer; at: int; kind: RelocKind; distance: int) =
  ## Every AVR displacement is a WORD count, so the byte distance is halved
  ## here — the one step that has no analogue on the other targets.
  case kind
  of rkAvrRjmp, rkAvrRcall:
    if (distance and 1) != 0:
      raise newException(ValueError, "AVR branch to an odd address: " & $distance)
    let off = distance div 2
    if off < -2048 or off > 2047:
      raise newException(ValueError,
        "AVR rjmp/rcall out of range: " & $distance & " bytes (limit ±4 KB); " &
        "the two-word `jmp`/`call` reaches all of flash")
    patchAvrWord(buf, at, 0xF000'u16, uint16(off) and 0x0FFF)
  of rkAvrBrcond:
    if (distance and 1) != 0:
      raise newException(ValueError, "AVR branch to an odd address: " & $distance)
    let off = distance div 2
    if off < -64 or off > 63:
      raise newException(ValueError,
        "AVR conditional branch out of range: " & $distance &
        " bytes (limit ±128); invert the condition and branch over an `rjmp`")
    # bits 9:3 are the displacement; the condition (bits 2:0 and 10) stays.
    patchAvrWord(buf, at, 0xFC07'u16, (uint16(off) and 0x7F) shl 3)
  of rkAvrJmp, rkAvrCall:
    # An absolute 22-bit WORD address, scattered across both words: k21..k17 in
    # bits 8:4 of the first, k16 in its bit 0, and k15..k0 in the second.
    let target = distance + int(buf.absBase)
    if (target and 1) != 0:
      raise newException(ValueError, "AVR call to an odd address: " & $target)
    let k = target div 2
    if k < 0 or k > 0x3FFFFF:
      raise newException(ValueError, "AVR jmp/call target out of flash: " & $target)
    patchAvrWord(buf, at, 0xFE0E'u16,
                 (uint16((k shr 17) and 0x1F) shl 4) or uint16((k shr 16) and 1))
    patchAvrWord(buf, at + 2, 0x0000'u16, uint16(k and 0xFFFF))
  of rkAvrLdiAddr:
    # Two `ldi`s carrying a DATA address: low half, then high. `absBase` is what
    # the image writer contributes once it knows where the section lands.
    let value = distance + int(buf.absBase)
    proc kBits(v: int): uint16 =
      ((uint16(v) shr 4) and 0xF) shl 8 or (uint16(v) and 0xF)
    patchAvrWord(buf, at, 0xF0F0'u16, kBits(value and 0xFF))
    patchAvrWord(buf, at + 2, 0xF0F0'u16, kBits((value shr 8) and 0xFF))
  else:
    raise newException(ValueError, "not an AVR relocation: " & $kind)

proc readRvWord(buf: Buffer; at: int): uint32 =
  uint32(buf.data[at]) or (uint32(buf.data[at + 1]) shl 8) or
    (uint32(buf.data[at + 2]) shl 16) or (uint32(buf.data[at + 3]) shl 24)

proc writeRvWord(buf: var Buffer; at: int; w: uint32) =
  buf.data[at] = byte(w and 0xFF)
  buf.data[at + 1] = byte((w shr 8) and 0xFF)
  buf.data[at + 2] = byte((w shr 16) and 0xFF)
  buf.data[at + 3] = byte((w shr 24) and 0xFF)

proc patchRvReloc(buf: var Buffer; at: int; kind: RelocKind; distance: int) =
  ## The immediate is REBUILT from the distance and OR'd back over the fields it
  ## owns, so the opcode, the registers and (for a branch) the condition survive
  ## from the placeholder. That is what lets one kind serve all six branches and
  ## both `jal` forms.
  case kind
  of rkRvBranch:
    if distance < -4096 or distance > 4094 or (distance and 1) != 0:
      raise newException(ValueError,
        "RV32 branch out of range or misaligned: " & $distance &
        " bytes (limit ±4 KB); invert the condition and jump over a `jal`")
    let u = uint32(distance)
    let old = readRvWord(buf, at)
    let imm = (((u shr 12) and 1) shl 31) or (((u shr 5) and 0x3F) shl 25) or
              (((u shr 1) and 0xF) shl 8) or (((u shr 11) and 1) shl 7)
    # Keep rs2, rs1, funct3 and the opcode; replace only the immediate fields.
    writeRvWord(buf, at, (old and 0x01FFF07F'u32) or imm)
  of rkRvJal:
    if distance < -1048576 or distance > 1048574 or (distance and 1) != 0:
      raise newException(ValueError,
        "RV32 `jal` out of range or misaligned: " & $distance &
        " bytes (limit ±1 MB); a longer call is `auipc`+`jalr`")
    let u = uint32(distance)
    let old = readRvWord(buf, at)
    let imm = (((u shr 20) and 1) shl 31) or (((u shr 1) and 0x3FF) shl 21) or
              (((u shr 11) and 1) shl 20) or (((u shr 12) and 0xFF) shl 12)
    writeRvWord(buf, at, (old and 0x00000FFF'u32) or imm)
  of rkRvAbsPair:
    # `lui rd, hi` then `addi rd, rd, lo`. The `+0x800` is the compensation
    # `addi`'s SIGNED immediate forces: a low half above 0x7FF is a NEGATIVE
    # addend, so the upper half has to be one higher to make up for it. Omitting
    # it is wrong by exactly 0x1000, for a bit under half of all addresses.
    let v = uint32(distance) + buf.absBase
    let hi = (v + 0x800) shr 12
    let lo = v - (hi shl 12)
    let oldHi = readRvWord(buf, at)
    writeRvWord(buf, at, (oldHi and 0x00000FFF'u32) or ((hi and 0xFFFFF) shl 12))
    let oldLo = readRvWord(buf, at + 4)
    writeRvWord(buf, at + 4, (oldLo and 0x000FFFFF'u32) or ((lo and 0xFFF) shl 20))
  else:
    raise newException(ValueError, "not an RV32 relocation: " & $kind)

# Jump optimization functions
proc updateRelocDisplacements*(buf: var Buffer) =
  ## Update all relocation displacements based on current label positions
  let labelPos = buf.labelPositions()   # O(1) per lookup; see `labelPositions`
  for reloc in buf.relocs:
    # Skip IAT calls - they are patched later when IAT address is known
    if reloc.kind == rkIatCall:
      continue
    let currentPos = reloc.position
    let t = int(reloc.target)
    if t < 0 or t >= labelPos.len or labelPos[t] < 0:
      raise newException(ValueError, "Label not found")   # as `getLabelPosition`
    let targetPos = labelPos[t]
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
      of rkADRADD:
        currentPos + 8  # `adr` + `add|sub` pair
      of rkTB, rkTBL, rkTBcond, rkTADR:
        currentPos + 4  # a 32-bit Thumb-2 encoding: two halfwords
      of rkTMovwMovt, rkTMovwMovtFunc:
        currentPos + 8  # MOVW + MOVT pair
      of rkAvrRjmp, rkAvrRcall, rkAvrBrcond:
        currentPos + 2  # one AVR word
      of rkAvrJmp, rkAvrCall, rkAvrLdiAddr:
        currentPos + 4  # two words: an absolute branch, or the `ldi` pair
      of rkRvBranch, rkRvJal:
        currentPos + 4
      of rkRvAbsPair:
        currentPos + 8  # `lui` + `addi`

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
    of rkADRADD:
      # ARM64 long-range address: `adr rd, .+lo` ; `add|sub rd, rd, #hi, lsl #12`.
      # Split the displacement into a 4096-granular part carried by the shifted
      # `add`/`sub` immediate and a remainder |lo| < 4096 that always fits ADR's
      # 21-bit signed field. Purely a distance computation — `adr` contributes the
      # PC — so no page arithmetic and no final-vaddr knowledge is needed.
      var hi = distance div 4096
      var lo = distance - hi * 4096          # Nim `div` truncates toward zero, so
      if lo < 0: lo += 4096; dec hi          # normalize to 0 <= lo < 4096
      let neg = hi < 0
      let mag = if neg: -hi else: hi
      if mag > 0xFFF:
        raise newException(ValueError,
          "AArch64 address materialization out of range: " & $distance &
          " bytes (limit ±16 MB)")
      let imm21 = uint32(int32(lo) and 0x1FFFFF)
      var adrInstr = uint32(buf.data[currentPos]) or
                     (uint32(buf.data[currentPos + 1]) shl 8) or
                     (uint32(buf.data[currentPos + 2]) shl 16) or
                     (uint32(buf.data[currentPos + 3]) shl 24)
      adrInstr = (adrInstr and 0x9F00001F'u32) or
                 ((imm21 and 0x03'u32) shl 29) or ((imm21 shr 2) shl 5)
      for i in 0 ..< 4:
        buf.data[currentPos + i] = byte((adrInstr shr (8 * i)) and 0xFF)
      # ADD/SUB (immediate), 64-bit, with `sh` (bit 22) set for the LSL #12 form.
      # The placeholder carries `rd`/`rn`; bit 30 selects SUB, so a negative
      # displacement only flips that bit.
      var addInstr = uint32(buf.data[currentPos + 4]) or
                     (uint32(buf.data[currentPos + 5]) shl 8) or
                     (uint32(buf.data[currentPos + 6]) shl 16) or
                     (uint32(buf.data[currentPos + 7]) shl 24)
      addInstr = (addInstr and 0xBF0003FF'u32) or 0x00400000'u32 or
                 (uint32(mag) shl 10)
      if neg: addInstr = addInstr or 0x40000000'u32
      for i in 0 ..< 4:
        buf.data[currentPos + 4 + i] = byte((addInstr shr (8 * i)) and 0xFF)
    of rkTB, rkTBL, rkTBcond:
      # Thumb-2 32-bit branches. Two little-endian HALFWORDS, high one first.
      #
      # B.W / BL share the S:I1:I2:imm10:imm11 layout with the sign-dependent
      # J-bit inversion (`I1 = NOT(J1 XOR S)`), so the J bits WRITTEN are
      # `J = NOT(I) XOR S`. B<cond>.W instead stores S:J2:J1:imm6:imm11 straight,
      # with no inversion and only ±1 MB of reach because four bits went to the
      # condition — which is read back out of the existing halfword here, so one
      # relocation kind serves all fourteen conditions.
      let wide = reloc.kind != rkTBcond
      let limit = if wide: 1 shl 24 else: 1 shl 20
      if distance < -limit or distance >= limit or (distance and 1) != 0:
        raise newException(ValueError,
          "Thumb branch out of range or misaligned: " & $distance &
          " bytes (limit ±" & $(limit div 1024 div 1024) & " MB)")
      let off = int32(distance) shr 1              # in halfwords
      let s0 = uint16((off shr 23) and 0x1)        # sign
      let imm11 = uint16(off and 0x7FF)
      var hi, lo: uint16
      if wide:
        let i1 = uint16((off shr 22) and 0x1)
        let i2 = uint16((off shr 21) and 0x1)
        let j1 = (not i1) and 0x1 xor s0
        let j2 = (not i2) and 0x1 xor s0
        let imm10 = uint16((off shr 11) and 0x3FF)
        hi = 0xF000'u16 or (s0 shl 10) or imm10
        lo = (if reloc.kind == rkTBL: 0xD000'u16 else: 0x9000'u16) or
             (j1 shl 13) or (j2 shl 11) or imm11
      else:
        let oldHi = uint16(buf.data[currentPos]) or (uint16(buf.data[currentPos + 1]) shl 8)
        let cond = (oldHi shr 6) and 0xF          # preserved from the placeholder
        let j1 = uint16((off shr 17) and 0x1)
        let j2 = uint16((off shr 18) and 0x1)
        let imm6 = uint16((off shr 11) and 0x3F)
        hi = 0xF000'u16 or (s0 shl 10) or (cond shl 6) or imm6
        lo = 0x8000'u16 or (j1 shl 13) or (j2 shl 11) or imm11
      buf.data[currentPos] = byte(hi and 0xFF)
      buf.data[currentPos + 1] = byte((hi shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte(lo and 0xFF)
      buf.data[currentPos + 3] = byte((lo shr 8) and 0xFF)
    of rkTADR:
      # ADR rd, label => ADD/SUB rd, PC, #imm12 against Align(PC, 4). The
      # placeholder carries `rd` in the low halfword; a negative displacement
      # selects the SUB form (T2) rather than negating an immediate that has no
      # sign bit. The alignment matters: PC is `pos + 4`, which is only
      # 4-aligned when the instruction itself is, so the addend is measured from
      # the ALIGNED value and the difference folded into the immediate.
      let pcAligned = ((currentPos + 4) div 4) * 4
      let target = currentPos + 4 + distance
      let delta = target - pcAligned
      if delta < -4095 or delta > 4095:
        raise newException(ValueError,
          "Thumb ADR out of range: " & $delta & " bytes (limit ±4 KB)")
      let mag = uint32(if delta < 0: -delta else: delta)
      let i = uint16((mag shr 11) and 0x1)
      let imm3 = uint16((mag shr 8) and 0x7)
      let imm8 = uint16(mag and 0xFF)
      let oldLo = uint16(buf.data[currentPos + 2]) or (uint16(buf.data[currentPos + 3]) shl 8)
      let rd = (oldLo shr 8) and 0xF
      let hi = (if delta < 0: 0xF2AF'u16 else: 0xF20F'u16) or (i shl 10)
      let lo = (imm3 shl 12) or (rd shl 8) or imm8
      buf.data[currentPos] = byte(hi and 0xFF)
      buf.data[currentPos + 1] = byte((hi shr 8) and 0xFF)
      buf.data[currentPos + 2] = byte(lo and 0xFF)
      buf.data[currentPos + 3] = byte((lo shr 8) and 0xFF)
    of rkTMovwMovt, rkTMovwMovtFunc:
      # MOVW rd, #lo16 ; MOVT rd, #hi16 — the label's ABSOLUTE address. `distance`
      # is the target position (see `calculateRelocDistance`); the section's load
      # address is added later by the image writer, which knows it.
      #
      # A CODE address additionally carries bit 0, the Thumb-state marker. See
      # `rkTMovwMovtFunc` — omitting it produces a pointer that faults only when
      # called, and on a core with no fault handler that is a silent lockup.
      let thumbBit = if reloc.kind == rkTMovwMovtFunc: 1'u32 else: 0'u32
      buf.data.patchThumbMovwMovtPair(currentPos,
                                      uint32(distance) + buf.absBase + thumbBit)
    of rkAvrRjmp, rkAvrRcall, rkAvrBrcond, rkAvrJmp, rkAvrCall, rkAvrLdiAddr:
      patchAvrReloc(buf, currentPos, reloc.kind, distance)
    of rkRvBranch, rkRvJal, rkRvAbsPair:
      patchRvReloc(buf, currentPos, reloc.kind, distance)
    of rkADR:
      # ARM64 ADR: 21-bit signed immediate, byte offset from PC
      if distance < -(1 shl 20) or distance >= (1 shl 20):
        raise newException(ValueError,
          "AArch64 ADR out of range: " & $distance & " bytes (limit ±1 MB)")
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

proc inFixedRange*(buf: Buffer; pos: int): bool {.inline.} =
  ## Whether byte position `pos` lies inside a layout-frozen `casejmp` region
  ## (see `fixedRanges`). Instructions there keep their exact size and position
  ## relative to the region start; the optimizers only patch their displacements.
  for (s, e) in buf.fixedRanges:
    if pos >= s and pos < e: return true
  false

proc isUncondJump(kind: RelocKind): bool {.inline.} =
  ## An unconditional PC-relative transfer that ALWAYS falls to its target and never
  ## returns: x86 `jmp` and AArch64 `b`. (Calls `rkCall`/`rkBL` return; conditional
  ## branches may fall through — neither is unconditional.)
  kind in {rkJmp, rkB, rkTB}

proc isThreadableBranch(kind: RelocKind): bool {.inline.} =
  ## A control transfer whose *target label* we may retarget to skip a jump hop:
  ## every conditional/unconditional branch on both arches. NOT calls (`rkCall`/`rkBL`,
  ## which return to the following instruction) and NOT address materialization
  ## (`rkLea`/`rkADR`/`rkADRP`), whose "target" is a data/code address, not a hop.
  kind in {rkJmp, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
           rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp,
           rkB, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ,
           rkTB, rkTBcond}

proc prunePositions(buf: var Buffer; deadPos: HashSet[int]): seq[int] =
  ## Delete the instruction starting at each position in `deadPos` (each MUST be the
  ## start of a reloc whose `originalSize` bytes are removed), then rebase every label
  ## and surviving reloc and drop the pruned relocs. Returns this step's old→new
  ## byte-position map (length `buf.data.len + 1`, indexed by the PRE-prune offset) so
  ## callers can compose it into a running map. Arch-agnostic: touches only positions.
  var relocByPos = initTable[int, int]()
  for i in 0 ..< buf.relocs.len: relocByPos[buf.relocs[i].position] = i
  let curLen = buf.data.len
  result = newSeq[int](curLen + 1)
  var newData = initBytes()
  var oldI = 0
  while oldI < curLen:
    result[oldI] = newData.len
    if oldI in deadPos:
      oldI += buf.relocs[relocByPos[oldI]].originalSize    # skip the whole instruction
    else:
      newData.add buf.data[oldI]
      inc oldI
  result[curLen] = newData.len
  for k in 0 ..< buf.labels.len:
    buf.labels[k].position = result[buf.labels[k].position]
  for k in 0 ..< buf.fixedRanges.len:      # no deletion happens INSIDE a fixed range
    buf.fixedRanges[k] = (result[buf.fixedRanges[k][0]], result[buf.fixedRanges[k][1]])
  var newRelocs: seq[RelocEntry] = @[]
  for r in buf.relocs:
    if r.position in deadPos: continue
    newRelocs.add RelocEntry(position: result[r.position], target: r.target,
                             kind: r.kind, originalSize: r.originalSize)
  buf.data = newData
  buf.relocs = newRelocs

proc threadJumps*(buf: var Buffer): seq[int] =
  ## Architecture-agnostic jump optimization on the `(relocs, labels, data)` model —
  ## no x86/AArch64 encoding knowledge, only byte positions and label ids. Two effects,
  ## iterated to a fixpoint (a prune can expose a fresh fall-through; a retarget can
  ## expose a fresh dead jump):
  ##
  ##  1. THREADING — a branch whose target label sits exactly on an UNCONDITIONAL jump
  ##     is retargeted to that jump's ultimate destination (chain-followed through
  ##     `jmp → jmp → …`, cycle-guarded). Pure `reloc.target` rewrite, no bytes move.
  ##     `jcc L; L: jmp M`  ⇒  `jcc M` (same semantics: taking the branch reached L only
  ##     to immediately jump to M).
  ##  2. DEAD-JUMP PRUNE — an unconditional jump whose (possibly retargeted) destination
  ##     is its own fall-through (the immediately following byte) is removed entirely:
  ##     `jmp L; L: …`  ⇒  `L: …`. Bytes are deleted and every later position rebased.
  ##
  ## Returns an old→new byte-position map (length `buf.data.len + 1`, indexed by the
  ## ORIGINAL offset) so the caller can remap external code offsets (gvar/`lea` patch
  ## sites, TLS-prologue entry), exactly like `shortenX64Jumps`. Run this BEFORE
  ## `shortenX64Jumps` (compose the two position maps) — threading first exposes more
  ## short-jump opportunities and removes jumps the shortener would otherwise relax.
  let origLen = buf.data.len
  # Composed old→new map, updated after each prune iteration (identity to start).
  result = newSeq[int](origLen + 1)
  for i in 0 .. origLen: result[i] = i

  var changed = true
  var guard = 0
  # Scratch tables, allocated once and cleared each iteration (their contents are
  # rebuilt from scratch every pass; only the backing storage is reused).
  var labelPos = initTable[int, int]()      # label id → byte position
  var uncondAt = initTable[int, int]()      # byte position → reloc index
  var deadPos = initHashSet[int]()          # positions of dead-jump instructions
  while changed and guard <= buf.relocs.len + 1:
    changed = false
    inc guard

    # Current label positions and the reloc index of any unconditional jump that
    # STARTS exactly at a given byte position (one instruction per position).
    labelPos.clear()
    for ld in buf.labels: labelPos[int(ld.id)] = ld.position
    uncondAt.clear()
    for i in 0 ..< buf.relocs.len:
      if isUncondJump(buf.relocs[i].kind):
        uncondAt[buf.relocs[i].position] = i

    # ── 1. THREADING: retarget every branch through unconditional-jump chains ──
    # `jcc L; L: jmp M`  ⇒  `jcc M`. Follow `jmp → jmp → …` to the ultimate target,
    # cycle-guarded (self-loop or hop count exceeding the reloc count = stop).
    for i in 0 ..< buf.relocs.len:
      if not isThreadableBranch(buf.relocs[i].kind): continue
      var dest = buf.relocs[i].target
      var hops = 0
      while hops <= buf.relocs.len:
        if not labelPos.hasKey(int(dest)): break
        let tp = labelPos[int(dest)]
        if not uncondAt.hasKey(tp): break
        let nxt = buf.relocs[uncondAt[tp]].target
        if int(nxt) == int(dest): break        # self-loop: stop
        dest = nxt
        inc hops
      if int(dest) != int(buf.relocs[i].target):
        buf.relocs[i].target = dest
        # not a byte change; loop again so a newly-exposed dead jump is pruned

    # ── 2. PRUNE: collect unconditional jumps to their own fall-through ──
    deadPos.clear()
    for i in 0 ..< buf.relocs.len:
      let r = buf.relocs[i]
      if isUncondJump(r.kind) and labelPos.hasKey(int(r.target)) and
         labelPos[int(r.target)] == r.position + r.originalSize and
         not inFixedRange(buf, r.position):    # a casejmp slot keeps its exact size
        deadPos.incl r.position
    if deadPos.len == 0: continue             # threading may still have changed targets

    # Drop the dead-jump bytes and compose this step's map into the running one.
    let iterMap = prunePositions(buf, deadPos)
    for o in 0 .. origLen: result[o] = iterMap[result[o]]
    changed = true

proc isInvertibleCond(kind: RelocKind): bool {.inline.} =
  ## A conditional branch whose sense we can flip in place — every x86 `jcc` (`0F 8x`
  ## long form) and the AArch64 conditional/compare/test-bit branches. Excludes
  ## unconditional jumps, calls and address materialization.
  kind in {rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
           rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp,
           rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ}

proc inverseCond(kind: RelocKind): RelocKind =
  ## The opposite-sense branch kind (RelocKind level; the encoded bytes are flipped by
  ## `invertCondBytes`). x86 pairs mirror the `0F 8x` opcode's low bit; AArch64 pairs
  ## mirror the B.cond `cond[0]` / CBZ·TBZ `op` bit.
  case kind
  of rkJe: rkJne
  of rkJne: rkJe
  of rkJg: rkJle
  of rkJle: rkJg
  of rkJl: rkJge
  of rkJge: rkJl
  of rkJa: rkJbe
  of rkJbe: rkJa
  of rkJb: rkJae
  of rkJae: rkJb
  of rkJo: rkJno
  of rkJno: rkJo
  of rkJs: rkJns
  of rkJns: rkJs
  of rkJp: rkJnp
  of rkJnp: rkJp
  of rkBEQ: rkBNE
  of rkBNE: rkBEQ
  of rkCBZ: rkCBNZ
  of rkCBNZ: rkCBZ
  of rkTBZ: rkTBNZ
  of rkTBNZ: rkTBZ
  else: kind                                    # unreachable (guarded by isInvertibleCond)

proc invertCondBytes(buf: var Buffer; pos: int; kind: RelocKind) =
  ## Arch-specific: flip the ENCODED condition of the branch at `pos` in place. The
  ## RelocKind carries the arch (x86 `rkJ*` vs AArch64 `rkB*`/`rkCB*`/`rkTB*`), so we
  ## dispatch on it — the only place in this pass that touches instruction encoding.
  case kind
  of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
     rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp:
    # x86 long form `0F 8x disp32`: the condition is the opcode's low bit (`8x`).
    buf.data[pos + 1] = buf.data[pos + 1] xor 1'u8
  of rkBEQ, rkBNE:
    # AArch64 B.cond: `cond` in bits 3:0; invert bit 0 (EQ↔NE). Little-endian byte 0.
    buf.data[pos] = buf.data[pos] xor 1'u8
  of rkCBZ, rkCBNZ, rkTBZ, rkTBNZ:
    # AArch64 CBZ/CBNZ and TBZ/TBNZ: the `op` bit sits at bit 24 → byte 3, bit 0.
    buf.data[pos + 3] = buf.data[pos + 3] xor 1'u8
  else: discard                                 # unreachable (guarded by isInvertibleCond)

proc invertCondJumps*(buf: var Buffer): seq[int] =
  ## Branch-inversion companion to `threadJumps`: fold `jcc L; jmp M; L:` into `jncc M`.
  ## When a conditional branch's fall-through is exactly an unconditional jump and the
  ## branch's own target is the byte immediately after that jump, invert the branch's
  ## condition, retarget it to the jump's destination, and delete the now-redundant
  ## jump. Net: two control instructions become one, no change in semantics.
  ##
  ## Pattern detection is arch-agnostic (positions, kinds, label ids); only the opcode
  ## flip in `invertCondBytes` is arch-specific. Iterated to a fixpoint (removing a jump
  ## can expose a fresh pattern). Returns a composed old→new byte-position map like
  ## `threadJumps`/`shortenX64Jumps`. Run AFTER `threadJumps` and BEFORE the x64
  ## shortener (inversion drops a `jmp rel32`, one fewer jump for the shortener to size).
  let origLen = buf.data.len
  result = newSeq[int](origLen + 1)
  for i in 0 .. origLen: result[i] = i

  var changed = true
  var guard = 0
  while changed and guard <= buf.relocs.len + 1:
    changed = false
    inc guard

    var labelPos = initTable[int, int]()        # label id → position
    for ld in buf.labels: labelPos[int(ld.id)] = ld.position
    var labelAt = initHashSet[int]()            # positions that carry a label
    for ld in buf.labels: labelAt.incl ld.position
    var uncondAt = initTable[int, int]()        # byte position → reloc index of a `jmp`/`b`
    for i in 0 ..< buf.relocs.len:
      if isUncondJump(buf.relocs[i].kind):
        uncondAt[buf.relocs[i].position] = i

    var deadPos = initHashSet[int]()            # unconditional jumps removed by inversion
    for i in 0 ..< buf.relocs.len:
      if not isInvertibleCond(buf.relocs[i].kind): continue
      let jccPos = buf.relocs[i].position
      if inFixedRange(buf, jccPos): continue    # a casejmp slot keeps its exact size
      let jmpPos = jccPos + buf.relocs[i].originalSize    # the branch's fall-through
      if not uncondAt.hasKey(jmpPos): continue            # fall-through is not a bare jump
      if jmpPos in deadPos: continue                       # jump already claimed this pass
      if inFixedRange(buf, jmpPos): continue               # jmp inside a frozen region
      let j = uncondAt[jmpPos]
      let afterJmp = jmpPos + buf.relocs[j].originalSize
      # The branch must target exactly the instruction after the jump (label `L`)…
      if not labelPos.hasKey(int(buf.relocs[i].target)): continue
      if labelPos[int(buf.relocs[i].target)] != afterJmp: continue
      # …and nothing may target the jump itself — else deleting it would silently
      # redirect that path to the fall-through instead of the jump's destination.
      if jmpPos in labelAt: continue
      # Flip the condition, steer the branch at the jump's target `M`, drop the jump.
      invertCondBytes(buf, jccPos, buf.relocs[i].kind)
      buf.relocs[i].kind = inverseCond(buf.relocs[i].kind)
      buf.relocs[i].target = buf.relocs[j].target
      deadPos.incl jmpPos

    if deadPos.len == 0: break
    when defined(nifasmDbgInvert):
      stderr.writeLine "nifasmDbgInvert: folded " & $deadPos.len & " jcc-over-jmp site(s)"
    let iterMap = prunePositions(buf, deadPos)
    for o in 0 .. origLen: result[o] = iterMap[result[o]]
    changed = true

proc finalize*(buf: var Buffer) =
  ## Patch every remaining (long-form) jump/branch/lea displacement from the final
  ## label positions. The rel32→rel8 shortener (`shortenX64Jumps`) — when the
  ## backend runs it — rewrites the buffer and patches the short jumps inline
  ## *before* this, leaving only the long forms it re-tracked for us to patch here.
  buf.updateRelocDisplacements()
