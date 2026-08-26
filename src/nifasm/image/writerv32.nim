#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 image: a static Linux ELF32 for `EM_RISCV`.
##
## This is the only NEW target in the tree that is hosted rather than bare metal,
## and it shows here as an absence — no vector table, no board file, no
## initializer image to copy, no startup code. The kernel maps the segments and
## jumps to `e_entry`; `.bss` is zeroed for us because a segment whose `p_memsz`
## exceeds its `p_filesz` is zero-filled by definition.
##
## **The two PT_LOADs must not share a page**, and that is the one thing this
## file exists to get right. Every header field can be correct — the
## `p_offset ≡ p_vaddr (mod p_align)` congruence included — and the program still
## dies at its first instruction, because two segments landing in one page have
## that page's permissions decided by whichever is mapped last. An R+X segment
## sharing a page with an RW one silently stops being executable, and the symptom
## is a SIGSEGV at the entry point with nothing in the image wrong.

import std / [strutils]

import "../core" / [context, relocs, buffers]
import elf32

const
  LoadBase* = 0x10000'u32
    ## Where a static ELF32 conventionally lands. Below the first page, which is
    ## kept unmapped so a null dereference faults.
  PageSize = 0x1000

proc writeRv32Image*(a: var GenContext; code: seq[byte]; entryOff: int): seq[byte] =
  finalize(a.bssBuf)

  var dataImage: seq[byte] = @[]
  if a.bssOffset > 0:
    dataImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  if a.bssSymInits.len > 0:
    quit "nifasm: RV32 globals initialized with another symbol's address are " &
         "not implemented yet (see R5 in doc/internals/rv32.md)"

  # The header's size depends on how many segments there are, and every address
  # below is measured from it — so the count has to be settled first. Getting
  # this backwards breaks the `p_offset ≡ p_vaddr (mod p_align)` congruence by
  # exactly one program header, and the loader refuses the file outright.
  let segCount = if dataImage.len > 0: 2 else: 1
  let off0 = Elf32EhdrSize + Elf32PhdrSize * segCount
  let codeVa = LoadBase + uint32(off0)
  let dataOff = (off0 + code.len + 3) and not 3
  # A whole page above the code, not merely past it — see the module header.
  let dataVa = LoadBase + uint32(PageSize) + uint32(dataOff)

  var segs = @[elf32.Segment(vaddr: codeVa, data: code, memSize: code.len,
                             flags: elf32.PF_R or elf32.PF_X)]
  if dataImage.len > 0:
    segs.add elf32.Segment(vaddr: dataVa, data: dataImage,
                           memSize: dataImage.len,
                           flags: elf32.PF_R or elf32.PF_W)

  # `entryTag = 0`: bit 0 of an ARM code address is the Thumb-state marker, and
  # here the same bit would name an odd address, which this machine cannot fetch
  # from at all.
  result = elf32.writeElf32(segs, entry = codeVa + uint32(entryOff),
                            machine = elf32.EM_RISCV, flags = 0,
                            entryTag = 0)

proc rv32CodeVa*(segCount: int): uint32 =
  ## Where the code will land. `absBase` needs it before the image is assembled —
  ## an `(adr …)` is a `lui`+`addi` pair carrying an ABSOLUTE address — so it is
  ## computed here rather than duplicated at the call site.
  LoadBase + uint32(Elf32EhdrSize + Elf32PhdrSize * segCount)
