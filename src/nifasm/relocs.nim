# Nifasm - Relocation System
# A system for tracking and managing relocations in the instruction stream

import std/[tables, algorithm, sets]
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
  ## Whether a displacement fits x86's signed 8-bit (rel8) jump form.
  distance >= -128 and distance <= 127

proc isShrinkableX64(kind: RelocKind): bool {.inline.} =
  ## x86 `jmp rel32` (5B) and the `0F 8x` conditional jumps (6B) have a 2-byte
  ## rel8 form; `call` has no rel8 form, and `lea`/IAT-call/all ARM64 forms are
  ## fixed size — so only these shrink.
  kind in {rkJmp, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
           rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp}

proc longSizeOf(kind: RelocKind): int {.inline.} =
  case kind
  of rkCall, rkJmp: 5
  of rkLea: 7
  of rkIatCall: 6
  of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
     rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp: 6
  of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP: 4

proc shortJccOpcode(kind: RelocKind): byte =
  case kind
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
  else: 0x74  # unreachable (guarded by isShrinkableX64)

proc isUncondJump(kind: RelocKind): bool {.inline.} =
  ## An unconditional PC-relative transfer that ALWAYS falls to its target and never
  ## returns: x86 `jmp` and AArch64 `b`. (Calls `rkCall`/`rkBL` return; conditional
  ## branches may fall through — neither is unconditional.)
  kind in {rkJmp, rkB}

proc isThreadableBranch(kind: RelocKind): bool {.inline.} =
  ## A control transfer whose *target label* we may retarget to skip a jump hop:
  ## every conditional/unconditional branch on both arches. NOT calls (`rkCall`/`rkBL`,
  ## which return to the following instruction) and NOT address materialization
  ## (`rkLea`/`rkADR`/`rkADRP`), whose "target" is a data/code address, not a hop.
  kind in {rkJmp, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
           rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp,
           rkB, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ}

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
         labelPos[int(r.target)] == r.position + r.originalSize:
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
      let jmpPos = jccPos + buf.relocs[i].originalSize    # the branch's fall-through
      if not uncondAt.hasKey(jmpPos): continue            # fall-through is not a bare jump
      if jmpPos in deadPos: continue                       # jump already claimed this pass
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

proc shortenX64Jumps*(buf: var Buffer): seq[int] =
  ## Shrink x86 `jmp`/`jcc rel32` to `rel8` wherever the displacement fits a signed
  ## byte, rewriting `buf` in place. Returns an old→new byte-position map (length
  ## `buf.data.len + 1`, indexed by *original* offset) so the caller can remap any
  ## external code offsets it tracks — gvar/`lea` patch sites and the synthesized
  ## TLS-prologue entry — to the shortened layout.
  ##
  ## This is branch relaxation run *optimistically*: every shrinkable jump starts
  ## SHORT (the most compact possible layout), and we GROW back to long only the
  ## jumps whose displacement genuinely overflows rel8. Growing pushes later code
  ## apart, which can force further jumps to grow — so we iterate to a fixpoint.
  ## Growing is monotonic (a jump only ever goes short→long, never back), so it
  ## converges, and the result is *optimal*: the minimal set of long jumps, hence
  ## the maximal set of short ones. (The opposite, start-long-and-shrink, is also
  ## sound but suboptimal — it misses mutually-enabling pairs that each only fit
  ## once the other is short.) Each pass recomputes the layout in O(n log n) via a
  ## prefix-sum of the bytes saved so far + a binary search, so a big module costs
  ## O(passes · n log n) with passes typically 1–3.
  ##
  ## The final displacements are computed from the converged position map, so the
  ## emitted bytes are exact. Short jumps are patched inline and dropped from the
  ## reloc list; long forms are re-tracked at their new positions for
  ## `updateRelocDisplacements` to patch from the final labels.
  ##
  ## x86-only: `call`/`lea`/IAT-call and every ARM64 form keep their size. Intended
  ## for the static-ELF x64 path (no IAT call-site bookkeeping to invalidate).
  let oldLen = buf.data.len

  # Relocs in ascending position order — the layout/rebuild walks depend on it.
  var relocs = buf.relocs
  relocs.sort(proc (a, b: RelocEntry): int = cmp(a.position, b.position))

  # Old label position by id, for distance evaluation and final displacements.
  var labelPos = initTable[int, int]()
  for ld in buf.labels: labelPos[int(ld.id)] = ld.position

  # Every shrinkable jump starts short; non-shrinkable relocs are permanently long.
  var isShort = newSeq[bool](relocs.len)
  for i in 0 ..< relocs.len:
    isShort[i] = isShrinkableX64(relocs[i].kind)

  # Old reloc positions in ascending order (== relocs order, already sorted), for
  # the per-pass binary search.
  var relocPositions = newSeq[int](relocs.len)
  for i in 0 ..< relocs.len: relocPositions[i] = relocs[i].position

  # ── fixpoint: grow every short jump that overflows rel8, until none do ──
  var changed = true
  while changed:
    changed = false
    # Prefix savings: savPrefix[k] = bytes removed by relocs[0 ..< k] (those before
    # index k). newPos(p) = p − savings of all relocs at an old position < p, found
    # by binary-searching `relocPositions` for the count below p.
    var savPrefix = newSeq[int](relocs.len + 1)
    for i in 0 ..< relocs.len:
      savPrefix[i + 1] = savPrefix[i] +
        (if isShort[i]: longSizeOf(relocs[i].kind) - 2 else: 0)
    proc newPos(p: int): int =
      let below = lowerBound(relocPositions, p)   # # of relocs with position < p
      p - savPrefix[below]
    for i in 0 ..< relocs.len:
      if not isShort[i]: continue
      let dist = newPos(labelPos[int(relocs[i].target)]) -
                 (newPos(relocs[i].position) + 2)   # rel8 measured from 2-byte end
      if not canUseShortJump(dist):
        isShort[i] = false                          # overflow → grow back to long
        changed = true

  # ── pass A: the old→new position map for the converged decisions ──
  result = newSeq[int](oldLen + 1)
  var newLen = 0
  var oldI = 0
  var ri = 0
  while oldI < oldLen:
    result[oldI] = newLen
    if ri < relocs.len and relocs[ri].position == oldI:
      newLen += (if isShort[ri]: 2 else: longSizeOf(relocs[ri].kind))
      oldI += relocs[ri].originalSize
      inc ri
    else:
      newLen += 1
      oldI += 1
  result[oldLen] = newLen

  # ── pass B: rebuild the bytes; patch short jumps, re-track long relocs ──
  var newData = initBytes()
  var newRelocs: seq[RelocEntry] = @[]
  oldI = 0
  ri = 0
  while oldI < oldLen:
    if ri < relocs.len and relocs[ri].position == oldI:
      let r = relocs[ri]
      if isShrinkableX64(r.kind) and isShort[ri]:
        let newSelf = result[r.position]
        let newTgt = result[labelPos[int(r.target)]]
        let disp = newTgt - (newSelf + 2)
        newData.add(if r.kind == rkJmp: 0xEB'u8 else: shortJccOpcode(r.kind))
        newData.add(byte(disp and 0xFF))
      else:
        for j in 0 ..< r.originalSize: newData.add buf.data[oldI + j]
        newRelocs.add RelocEntry(position: result[r.position], target: r.target,
                                 kind: r.kind, originalSize: r.originalSize)
      oldI += r.originalSize
      inc ri
    else:
      newData.add buf.data[oldI]
      inc oldI

  for k in 0 ..< buf.labels.len:
    buf.labels[k].position = result[buf.labels[k].position]
  buf.data = newData
  buf.relocs = newRelocs

proc finalize*(buf: var Buffer) =
  ## Patch every remaining (long-form) jump/branch/lea displacement from the final
  ## label positions. The rel32→rel8 shortener (`shortenX64Jumps`) — when the
  ## backend runs it — rewrites the buffer and patches the short jumps inline
  ## *before* this, leaving only the long forms it re-tracked for us to patch here.
  buf.updateRelocDisplacements()
