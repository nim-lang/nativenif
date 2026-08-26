#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The bare-metal AVR firmware image: an ELF32 for `EM_AVR` with a reset vector
## at flash address 0 and the code behind it.
##
## Two things are unlike every other image writer here.
##
## **The reset vector is an INSTRUCTION, not an address.** An AVR core begins
## executing at flash address 0, so word 0 is a `jmp` to the entry proc rather
## than a pointer to it. That is why the vector costs four bytes of code and why
## every position below is measured from `ResetVectorBytes`.
##
## **Flash and data are different address spaces**, and the ELF says so the way
## the AVR toolchain has always said it: a data segment's `p_vaddr` carries the
## `0x800000` marker while its `p_paddr` — where the bytes actually SHIP — stays
## in flash. A loader that understands the convention copies from one to the
## other; a chip does not, which is why the startup code has to (M6), and why
## nothing here relies on it.

import std / [strutils]

import "../core" / [context, relocs, buffers]
import "../avr" / [encoder]
import elf32

const
  ResetVectorBytes* = 4
    ## One two-word `jmp`. A real part's vector table is longer — one entry per
    ## interrupt — but an entry no handler claimed would be a `jmp` to nowhere,
    ## which is worse than the absence of a table. Interrupts are M6.
  FlashSize* = 32 * 1024
    ## An ATmega328P. The limit is checked rather than assumed: an image larger
    ## than the part's flash otherwise produces an ELF that loads and a board
    ## that faults at the first byte that could not be placed.
  SramBase* = 0x0100
    ## Where an ATmega328P's SRAM begins — above the 32 registers, the 64 I/O
    ## registers and the 160 extended I/O registers, all of which are mapped into
    ## the same data space and none of which are memory.
  SramSize* = 2 * 1024
  DataVaddrMarker* = 0x800000'u32
    ## The AVR toolchain's convention for "this address is in the DATA space".
    ## Not part of the address; a loader subtracts it.

proc writeAvrImage*(a: var GenContext; code: seq[byte]; entryOff: int): seq[byte] =
  ## The finished firmware: `jmp <entry>` at address 0, then the code.
  ##
  ## `entryOff` is a byte offset within `code`, so the vector's target is
  ## `ResetVectorBytes + entryOff` — and the instruction wants that as a WORD
  ## address, which is the halving that runs through this whole target.
  finalize(a.bssBuf)

  var image: seq[byte] = @[]

  # The reset vector, assembled here rather than relocated: its target is known
  # exactly (the entry proc's position is already final) and it is the one
  # instruction in the image that no label refers to.
  let entryByte = ResetVectorBytes + entryOff
  if (entryByte and 1) != 0:
    quit "nifasm: the AVR entry point is at an odd address (" & $entryByte &
         "), which is not an instruction address"
  let entryWord = entryByte div 2
  if entryWord > 0x3FFFFF:
    quit "nifasm: the AVR entry point is past the reach of `jmp`"
  let w0 = 0x940C'u16 or (uint16((entryWord shr 17) and 0x1F) shl 4) or
           uint16((entryWord shr 16) and 1)
  let w1 = uint16(entryWord and 0xFFFF)
  image.add byte(w0 and 0xFF); image.add byte((w0 shr 8) and 0xFF)
  image.add byte(w1 and 0xFF); image.add byte((w1 shr 8) and 0xFF)

  image.add code

  if image.len > FlashSize:
    quit "nifasm: the image is " & $image.len & " bytes and this part's flash " &
         "holds " & $FlashSize

  # `.data`/`.bss` are M6: nothing allocates a global yet, and the operand parser
  # refuses one by name. When they arrive the initializer image goes here, as a
  # second segment whose `p_paddr` is its place in flash and whose `p_vaddr`
  # carries `DataVaddrMarker` — and the startup code copies between the two,
  # because on this machine nothing else will.
  if a.bssOffset > 0:
    quit "nifasm: AVR globals are not implemented yet (see M6 in " &
         "doc/internals/avr.md); this module declares " & $a.bssOffset & " bytes"

  # `entryTag = 0`: bit 0 of an ARM code address is the Thumb-state marker, and
  # the same bit here would name an odd address — see `writeElf32`.
  #
  # `entry = 0` rather than the entry proc's own address, and that is not a
  # shortcut: a real part reads no ELF header. It begins at flash 0, and the
  # `jmp` placed there above is what sends it to the entry proc. Declaring the
  # proc's address instead would work under a simulator that honours `e_entry`
  # and fail on silicon, which is the worse of the two.
  result = elf32.writeElf32(
    [elf32.Segment(vaddr: 0, data: image, memSize: image.len,
                   flags: elf32.PF_R or elf32.PF_X)],
    entry = 0, machine = elf32.EM_AVR, flags = elf32.EF_AVR_MACH_AVR5,
    entryTag = 0)
