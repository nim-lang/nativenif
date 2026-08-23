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
## What this writes is not a hosted executable but a FIRMWARE IMAGE: a vector
## table at the load address followed by code and rodata, with no interpreter, no
## dynamic section and no symbol resolution. QEMU's `-kernel` reads the program
## headers and copies each segment to its physical address; the M-profile core
## then resets by reading the vector table, so `e_entry` is advisory and the
## table is what actually decides where execution begins.

import buffers

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
    ## Where the vector table must live out of reset (VTOR is 0 then). On MPS2
    ## this region is ZBT SRAM rather thanreal flash, so an image may write to it —
    ## which is what lets a first-cut image skip the flash→RAM `.data` copy.
  SramBase* = 0x20000000'u32
  DefaultStackTop* = 0x20010000'u32
    ## 64 KB into SRAM, growing down. Comfortably inside every MPS2 variant and
    ## inside an STM32F407's 128 KB too.

proc initVectorTable*(stackTop: uint32; resetHandler: uint32): seq[byte] =
  ## The two words an M-profile core reads at reset.
  ##
  ## Word 1 MUST have bit 0 set: it is the Thumb-state bit, not part of the
  ## address. Clearing it does not branch to an odd address, it takes a
  ## UsageFault on the first instruction — and since the fault handler slot is
  ## also empty at that point, the core locks up with no diagnostic.
  result = newSeq[byte](8)
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

const VectorTableSize* = 8
  ## The two words this writer emits: initial MSP and reset handler. Code is laid
  ## out assuming it starts this far above the load address.

proc writeFirmware*(code: seq[byte]; entryOffset = 0; loadAddr = FlashBase;
                    stackTop = DefaultStackTop): seq[byte] =
  ## The single-segment case: a vector table followed by `code`, all in the code
  ## region.
  ##
  ## `entryOffset` is the reset handler's position WITHIN `code` — not within the
  ## image — so the caller can hand over a byte position straight out of its
  ## instruction buffer. Defaulting it to 0 means "the first thing emitted",
  ## which is right for a top-level statement sequence and wrong for anything
  ## with procs, where the entry is wherever its label landed.
  ##
  ## `code` must already have been laid out assuming it starts at
  ## `loadAddr + VectorTableSize` — the caller emits it that way, so nothing is
  ## relocated here.
  let entry = loadAddr + uint32(VectorTableSize + entryOffset)
  var image = initVectorTable(stackTop, entry)
  image.add code
  result = writeElf32([Segment(vaddr: loadAddr, data: image,
                               memSize: image.len,
                               flags: PF_R or PF_W or PF_X)], entry)
