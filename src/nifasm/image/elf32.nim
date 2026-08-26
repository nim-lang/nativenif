#
#           nifasm — ELF32 / EM_ARM image writer for bare-metal Cortex-M
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The Cortex-M counterpart of `elf.nim`. Deliberately a separate module rather
## than a widening of the ELF64 one: the two share field NAMES but not field
## ORDER, and conflating them is the classic way to produce a header that reads
## as garbage.
##
## The trap: `Elf32_Phdr` orders its fields
##   type, offset, vaddr, paddr, filesz, memsz, **flags**, align
## while `Elf64_Phdr` puts **flags** immediately after `type`. Nothing rejects a
## swapped pair — the loader just maps the wrong thing with the wrong
## permissions.
##
## What this writes is not a hosted executable but a FIRMWARE IMAGE: an interrupt
## table at the load address followed by code and rodata, with no interpreter, no
## dynamic section and no symbol resolution. QEMU's `-kernel` reads the program
## headers and copies each segment to its physical address; the M-profile core
## then resets by reading the interrupt table, so `e_entry` is advisory and the
## table is what actually decides where execution begins.

import ../core/buffers

type
  Elf32_Addr* = uint32
  Elf32_Off* = uint32
  Elf32_Half* = uint16
  Elf32_Word* = uint32

const
  ET_EXEC* = 2.Elf32_Half
  EM_ARM* = 40.Elf32_Half
  PT_LOAD* = 1.Elf32_Word
  PF_X* = 1.Elf32_Word
  PF_W* = 2.Elf32_Word
  PF_R* = 4.Elf32_Word

  EF_ARM_EABI_VER5* = 0x05000000.Elf32_Word
    ## `e_flags` for an EABI 5 object. Nothing in QEMU checks it, but a real
    ## toolchain's `readelf`/`gdb` reads the ABI version from here.

  Elf32EhdrSize* = 52
  Elf32PhdrSize* = 32

type
  Segment* = object
    ## One PT_LOAD region of the finished image.
    vaddr*: Elf32_Addr
    data*: seq[byte]      ## file-backed bytes
    memSize*: int         ## >= data.len; the excess is .bss, zeroed by the loader
    flags*: Elf32_Word

# ── Cortex-M memory map ─────────────────────────────────────────────────────
# These are the MPS2 (AN385/AN386/AN500) addresses, which the Cortex-M
# architecture also makes the conventional ones: the code region starts at 0 and
# the SRAM region at 0x20000000. A real STM32F4 or nRF52 differs only in how much
# of each it has, which is why the test images need no board-specific knowledge.

const
  FlashBase* = 0x00000000'u32
    ## Where the interrupt table must live out of reset (VTOR is 0 then). On MPS2
    ## this region is ZBT SRAM rather than real flash, so an image may write to it.
  FlashSize* = 0x00400000'u32
    ## 4 MB — the MPS2 ZBT SRAM block at 0. Also the smallest number that is not
    ## a bound on any part existing fixtures reach, which is what a DEFAULT owes:
    ## it must never be the reason something stops assembling.
  SramBase* = 0x20000000'u32
  SramSize* = 0x00010000'u32
    ## 64 KB. The MPS2 block here is far larger, but 64 KB is what the stack top
    ## has always implied and it is inside an STM32F407's 128 KB too.
  DefaultStackTop* = SramBase + SramSize

type
  MemoryMap* = object
    ## Where the image's two regions live on the target BOARD — a linker script,
    ## in the two lines of it a firmware image actually needs.
    ##
    ## Compiled-in constants were fine while every image ran on one QEMU machine.
    ## They stop being fine at the first real part: an STM32F407 has its flash at
    ## 0x08000000 and 128 KB of SRAM, an nRF52840 has 256 KB, and an image that
    ## overruns either is not a diagnostic today — it is an ELF that loads and a
    ## board that faults somewhere else entirely.
    ##
    ## The defaults are the MPS2 ones above, so an image built without any of this
    ## is byte-identical to one built before it existed.
    flashBase*, flashSize*: uint32
    ramBase*, ramSize*: uint32
    stackTop*: uint32
      ## The initial MSP — interrupt-table word 0. Defaults to the top of RAM; the
      ## stack grows DOWN from here while the globals grow UP from `ramBase`.
    given*: bool
      ## Any of the above was set explicitly. Only so that setting them for a
      ## target that has no use for them can be an error rather than silence.

proc defaultMemoryMap*(): MemoryMap =
  MemoryMap(flashBase: FlashBase, flashSize: FlashSize,
            ramBase: SramBase, ramSize: SramSize,
            stackTop: DefaultStackTop, given: false)

proc validate*(m: MemoryMap): string =
  ## `""` when the map describes a board that could exist. Checked once, where the
  ## flags were read, so a typo names itself instead of surfacing as an image that
  ## loads nowhere.
  if m.flashSize == 0: return "the flash region has size 0"
  if m.ramSize == 0: return "the RAM region has size 0"
  # uint32 arithmetic: a base plus a size that wraps past 4 GB is a typo, and the
  # containment tests below would silently pass for it.
  if m.flashBase.uint64 + m.flashSize.uint64 > 0x1_0000_0000'u64:
    return "the flash region runs past the end of the address space"
  if m.ramBase.uint64 + m.ramSize.uint64 > 0x1_0000_0000'u64:
    return "the RAM region runs past the end of the address space"
  if m.flashBase < m.ramBase + m.ramSize and m.ramBase < m.flashBase + m.flashSize:
    return "the flash and RAM regions overlap"
  # The initial MSP is the address the first push writes BELOW, so the top of RAM
  # is a legal value and `ramBase` itself is not: a stack with no room is a fault
  # on the entry proc's own prologue.
  if m.stackTop <= m.ramBase or m.stackTop > m.ramBase + m.ramSize:
    return "the stack top is outside the RAM region"
  return ""

proc initInterruptTable*(stackTop: uint32; resetHandler: uint32;
                         sizeInBytes = 8): seq[byte] =
  ## The two words an M-profile core reads at reset, in a table of `sizeInBytes`.
  ##
  ## Word 1 MUST have bit 0 set: it is the Thumb-state bit, not part of the
  ## address. Clearing it does not branch to an odd address, it takes a
  ## UsageFault on the first instruction — and since the fault handler slot is
  ## also empty at that point, the core locks up with no diagnostic.
  ##
  ## Every word past the second is left ZERO here; the caller fills the ones a
  ## handler claimed. A slot nobody claimed keeps that zero, which faults on the
  ## same INVSTATE rule and escalates to a lockup — deterministic and findable,
  ## which a branch into whatever follows a too-short table is not.
  result = newSeq[byte](max(sizeInBytes, 8))
  let entry = resetHandler or 1'u32
  for i in 0 ..< 4:
    result[i] = byte((stackTop shr (8 * i)) and 0xFF)
    result[4 + i] = byte((entry shr (8 * i)) and 0xFF)

proc writeElf32*(segments: openArray[Segment]; entry: uint32): seq[byte] =
  ## Serialize `segments` as an ET_EXEC ELF32 for EM_ARM.
  var out0 = initBytes()
  let phCount = segments.len
  var fileOff = Elf32EhdrSize + Elf32PhdrSize * phCount
  # Each segment's file offset must be congruent to its vaddr modulo the page
  # alignment. We use an alignment of 4, so keeping both 4-aligned suffices.
  var offsets: seq[int] = @[]
  for seg in segments:
    fileOff = (fileOff + 3) and not 3
    offsets.add fileOff
    fileOff += seg.data.len

  # ── ELF header ──
  out0.add 0x7F'u8
  out0.add byte(ord('E')); out0.add byte(ord('L')); out0.add byte(ord('F'))
  out0.add 1'u8            # EI_CLASS  = ELFCLASS32
  out0.add 1'u8            # EI_DATA   = ELFDATA2LSB
  out0.add 1'u8            # EI_VERSION
  for _ in 0 ..< 9: out0.add 0'u8
  out0.addUint16 uint16(ET_EXEC)
  out0.addUint16 uint16(EM_ARM)
  out0.addUint32 1'u32                      # e_version
  out0.addUint32 entry or 1'u32             # e_entry, Thumb bit set
  out0.addUint32 uint32(Elf32EhdrSize)      # e_phoff
  out0.addUint32 0'u32                      # e_shoff: no section headers
  out0.addUint32 uint32(EF_ARM_EABI_VER5)   # e_flags
  out0.addUint16 uint16(Elf32EhdrSize)
  out0.addUint16 uint16(Elf32PhdrSize)
  out0.addUint16 uint16(phCount)
  out0.addUint16 40'u16                     # e_shentsize
  out0.addUint16 0'u16                      # e_shnum
  out0.addUint16 0'u16                      # e_shstrndx
  assert out0.len == Elf32EhdrSize

  # ── program headers ── field ORDER differs from ELF64; see the module comment.
  for i, seg in segments.pairs:
    out0.addUint32 uint32(PT_LOAD)
    out0.addUint32 uint32(offsets[i])       # p_offset
    out0.addUint32 uint32(seg.vaddr)        # p_vaddr
    out0.addUint32 uint32(seg.vaddr)        # p_paddr — the LOAD address, which is
                                            # what `-kernel` copies to
    out0.addUint32 uint32(seg.data.len)     # p_filesz
    out0.addUint32 uint32(max(seg.memSize, seg.data.len))  # p_memsz
    out0.addUint32 seg.flags                # p_flags  <-- AFTER memsz on ELF32
    out0.addUint32 4'u32                    # p_align
  assert out0.len == Elf32EhdrSize + Elf32PhdrSize * phCount

  # ── segment contents ──
  for i, seg in segments.pairs:
    while out0.len < offsets[i]: out0.add 0'u8
    for b in seg.data: out0.add b

  result = newSeq[byte](out0.len)
  for i in 0 ..< out0.len: result[i] = out0[i]

const InterruptTableSize* = 8
  ## The SMALLEST table: the two words a cold core reads. An image whose module
  ## declares handlers gets a longer one — `assembler.interruptTableBytes`
  ## decides, and every address in that image is measured from its answer rather
  ## than from this. Still the default for `writeFirmware`, which serves the
  ## encoder self-test's hand-assembled images and has no handlers to place.

proc writeFirmware*(code: seq[byte]; entryOffset = 0; loadAddr = FlashBase;
                    stackTop = DefaultStackTop): seq[byte] =
  ## The single-segment case: a interrupt table followed by `code`, all in the code
  ## region.
  ##
  ## `entryOffset` is the reset handler's position WITHIN `code` — not within the
  ## image — so the caller can hand over a byte position straight out of its
  ## instruction buffer. Defaulting it to 0 means "the first thing emitted",
  ## which is right for a top-level statement sequence and wrong for anything
  ## with procs, where the entry is wherever its label landed.
  ##
  ## `code` must already have been laid out assuming it starts at
  ## `loadAddr + InterruptTableSize` — the caller emits it that way, so nothing is
  ## relocated here.
  let entry = loadAddr + uint32(InterruptTableSize + entryOffset)
  var image = initInterruptTable(stackTop, entry)
  image.add code
  result = writeElf32([Segment(vaddr: loadAddr, data: image,
                               memSize: image.len,
                               flags: PF_R or PF_W or PF_X)], entry)
