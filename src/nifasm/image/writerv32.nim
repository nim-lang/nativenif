#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The bare-metal RV32 firmware image.
##
## A SIBLING of `writecortexm.nim` rather than a flag on it, because the two
## targets disagree about the one thing that module is organised around. An
## M-profile core resets by READING a vector table — word 0 the initial MSP, word
## 1 the reset address — and every offset in the Cortex-M writer is measured from
## that table. A RISC-V core resets to a fixed PC, establishes no stack pointer of
## its own, and reaches its handlers through the `mtvec` CSR, which in vectored
## mode holds JUMP INSTRUCTIONS rather than addresses. There is no table at the
## load address to measure anything from.
##
## What this writes today is the MINIMUM that makes a computed answer observable:
## one PT_LOAD segment holding the code, a second declaring the SRAM the globals
## occupy, and the absolute `lui`+`addi` pairs patched to point into it. Still
## outstanding, and what makes this "minimal" rather than "done":
##
##  * the `(layout …)` board description — regions come from constants here;
##  * the `mtvec` trampoline table built from `(interrupts …)`.

import std / [tables]

import "../core" / [context, sem, relocs, buffers]
import elf32

const
  Rv32LoadAddr* = 0x8000_0000'u32
    ## Where QEMU's `virt` board has RAM, and therefore where a `-kernel` image is
    ## loaded and entered. Not a "flash" address: `virt` has no separate code
    ## region, which is exactly why the layout file (P3) has to supply both
    ## regions rather than this constant guessing them.
  Rv32SramAddr* = 0x8010_0000'u32
    ## 1 MiB above the image, for the globals. Deliberately a DIFFERENT region
    ## from the code even though the board makes them the same memory: keeping
    ## them apart is what will keep the `.data` copy loop honest when it lands,
    ## the same argument `writeCortexMImage` makes for its file-less SRAM segment.
  Rv32SramSize* = 0x0010_0000'u32

proc writeRv32Image*(a: var GenContext; code: seq[byte];
                     entryOff: int): seq[byte] =
  ## The finished firmware: the code at the load address, plus a segment
  ## declaring the SRAM region the globals occupy at run time.
  ##
  ## The SRAM segment carries NO file bytes — `p_filesz` is 0 and only `p_memsz`
  ## is declared. On a real chip RAM holds nothing at reset and there is no loader
  ## to ask, so its contents must be established by the image itself. Declaring it
  ## file-backed would let QEMU place initialized globals for us and a broken
  ## startup path would then pass every fixture.
  finalize(a.bssBuf)

  if a.bssOffset.uint32 > Rv32SramSize:
    quit "nifasm: " & $a.bssOffset & " bytes of globals do not fit the " &
         $Rv32SramSize & "-byte SRAM region"

  # ── the initializer image ─────────────────────────────────────────────────
  # A chip's RAM holds nothing at reset and there is no loader to ask, so a
  # global that starts at 7 has to become a 7 in RAM by some instruction that
  # actually runs. The bytes travel in the image and the startup code copies
  # them; this builds the bytes.
  var bssImage: seq[byte] = @[]
  if a.bssOffset > 0:
    bssImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  var patched = code

  # Bake the address fields of a `const` blob that holds another symbol's address
  # — a vtable, an RTTI record, a `const` holding `addr other` — now that every
  # label has a position. The blob lives in the code segment at its own label and
  # each recorded field is a 4-byte ABSOLUTE address.
  #
  # No state bit is OR-ed into a proc's: that is Arm's Thumb marker, and a
  # function pointer read out of a table here is called through an ordinary
  # `jalr`, which wants the real (even) address.
  #
  # Without this the field stays whatever placeholder arkham reserved — zero —
  # and dereferencing it reads address 0. On Cortex-M that is the vector table
  # and the program merely computes nonsense; on a RISC-V `virt` board nothing is
  # mapped there at all, so it TRAPS into an unset `mtvec` and the image hangs.
  if a.rodataSymInits.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc, skRodata:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = Rv32LoadAddr + uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = Rv32SramAddr + uint32(it.sym.size)
      else: discard
      for i in 0 ..< it.size:
        if sitePos + i < patched.len:
          patched[sitePos + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # Every `(adr <global>)` and every global-address operand emitted a `lui`+`addi`
  # pair with zero immediates and recorded its position. Only now is there an
  # address to put in them: `sym.size` is the byte offset within .bss, assigned
  # as the gvar declarations were scanned.
  for (pos, sym) in a.gvarSites:
    if pos + 8 > patched.len: continue
    var bytes = initBytes()
    for i in 0 ..< 8: bytes.add patched[pos + i]
    bytes.patchRvLuiAddiPair(0, Rv32SramAddr + uint32(sym.size))
    for i in 0 ..< 8: patched[pos + i] = bytes[i]

  # A global whose initializer is another symbol's ADDRESS — a function pointer
  # table, a `const` holding `addr other` — cannot be a literal, because the
  # address is not known until the layout is. Without this the cell stays zero
  # and the first indirect call through it branches to address 0: a lockup with
  # nothing at the crash site to say which global was never filled.
  #
  # No state bit is OR-ed into a proc's address here. That is Arm's Thumb marker,
  # and on RISC-V an odd code address is simply misaligned.
  if a.bssSymInits.len > 0 and bssImage.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.bssSymInits:
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc, skRodata:
        if not labelPos.hasKey(it.sym.offset): continue
        targetVaddr = Rv32LoadAddr + uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = Rv32SramAddr + uint32(it.sym.size)
      else: continue
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # ── the .data / .bss cut ──────────────────────────────────────────────────
  # The cut is the HIGH-WATER MARK of the initialized bytes, not a partition of
  # the globals. Offsets were assigned as the gvar decls were scanned and every
  # `lui`/`addi` pair above has already been patched against them, so re-sorting
  # here is not available — and the scan order is not the declaration order
  # either. A zero global that lands between two initialized ones is therefore
  # COPIED rather than zeroed. That costs image bytes and never correctness: the
  # byte copied is the zero the image already holds for it.
  #
  # A zero-VALUED entry in `bssInits` does not raise the mark: whichever side of
  # the cut it lands on writes a zero there.
  var dataHigh = 0
  for it in a.bssInits:
    if it.val != 0: dataHigh = max(dataHigh, int(it.off) + it.size)
  for it in a.bssSymInits:
    dataHigh = max(dataHigh, int(it.off) + it.size)
  let ramSize = (a.bssOffset + 3) and not 3
  let dataInitSize = min((dataHigh + 3) and not 3, ramSize)
  let bssZeroSize = ramSize - dataInitSize

  # The initializer image is parked immediately after the code, word aligned so
  # the startup copy — which moves whole words — reads aligned on both sides.
  # There is no separate flash region on this board, so "after the code" is the
  # whole of the placement decision.
  let dataLoadOff = (patched.len + 3) and not 3
  let dataLoadAddr = Rv32LoadAddr + uint32(dataLoadOff)

  # Every number is known now, so fill in the sites the startup code left blank.
  for (pos, which) in a.mimgSites:
    if pos + 8 > patched.len: continue
    let v = case which
            of mikDataLoad: dataLoadAddr
            of mikDataVma: Rv32SramAddr
            of mikDataSize: uint32(dataInitSize)
            of mikBssSize: uint32(bssZeroSize)
            of mikHeapStart: Rv32SramAddr + uint32(ramSize)
            of mikHeapSize: 0'u32
            of mikNoinitStart: Rv32SramAddr + Rv32SramSize
            of mikNoinitSize: 0'u32
    var bytes = initBytes()
    for i in 0 ..< 8: bytes.add patched[pos + i]
    bytes.patchRvLuiAddiPair(0, v)
    for i in 0 ..< 8: patched[pos + i] = bytes[i]

  # The code, then the initializer image at its aligned offset.
  var image = patched
  while image.len < dataLoadOff: image.add 0'u8
  for i in 0 ..< dataInitSize:
    image.add (if i < bssImage.len: bssImage[i] else: 0'u8)

  let entry = Rv32LoadAddr + uint32(entryOff)
  var segs = @[Segment(vaddr: Rv32LoadAddr, data: image, memSize: image.len,
                       flags: PF_R or PF_W or PF_X)]
  if ramSize > 0:
    # NO file-backed bytes: `data` is empty and only `memSize` is declared. That
    # is what makes the copy loop LOAD-BEARING rather than decorative — QEMU's
    # `-kernel` would otherwise place the initialized globals itself, and a broken
    # copy would still pass every fixture in the corpus.
    segs.add Segment(vaddr: Rv32SramAddr, data: @[], memSize: ramSize,
                     flags: PF_R or PF_W)
  result = writeElf32(segs, entry, machine = EM_RISCV)
