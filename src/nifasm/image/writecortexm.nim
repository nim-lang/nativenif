#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The bare-metal Cortex-M firmware image: an ELF32 with the interrupt vector
## table at its head and `.data`'s initializer image parked in flash.
##
## The four numbers the startup code needs — where that image sits, where it
## belongs at run time, and how big `.data` and `.bss` are — are only known once
## the image is laid out, which is why arkham ASKS for them (`(mimg …)`) instead
## of computing them. They are patched into fixed-width MOVW/MOVT pairs here.

import std / [streams, os, tables, sets, algorithm, strutils]
import nifcore
import "../core" / [context, sem, relocs, buffers, diagnostics, modules, stackslots, listing]
import "../thumb/encoder" as thumb2
import "../thumb/board"
import elf32, dwarf, tracetable, writecommon

proc interruptTableBytes*(a: GenContext): int =
  ## The table's size, which is what every other layout number here is measured
  ## from. Known once the declarations have been read, which is before `absBase`
  ## is set and therefore before any address is computed.
  if a.interrupts.len == 0: return MinInterruptWords * 4
  var top = CoreInterruptWords
  for (slot, _) in a.interrupts:
    if slot + 1 > top: top = slot + 1
  result = top * 4

proc writeCortexMImage*(a: var GenContext; code: seq[byte];
                       entryOff: int; map: elf32.MemoryMap): seq[byte] =
  ## The finished firmware: a vector table, the code, and the `.data` initializer
  ## image all at the flash base, plus a second segment declaring the SRAM region
  ## the globals occupy at run time.
  ##
  ## The SRAM segment carries NO file bytes — `p_filesz` is 0 and only `p_memsz`
  ## is declared. Its contents are established by the image itself, in the startup
  ## code arkham emits at the top of the entry proc: copy `(datasize)` bytes from
  ## `(dataload)` to `(datavma)`, then zero `(bsssize)` bytes above them. That is
  ## what a real chip needs (RAM holds nothing at reset and there is no loader to
  ## ask), and it is also what makes the copy TESTED — a file-backed SRAM segment
  ## let QEMU's `-kernel` place the initialized globals itself, so a broken copy
  ## loop would pass every fixture in the corpus.
  finalize(a.bssBuf)
  var bssImage: seq[byte] = @[]
  if a.bssOffset > 0:
    bssImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  # The BOARD wins when there is one: the `--layout:` file is the description of
  # the part, and the flags are what it replaces. Their defaults would otherwise
  # look like an answer.
  var map = map
  var stacksBase = 0'u32
  var heapBase = 0'u32
  var noinitBase = 0'u32
  if a.board.given:
    map.flashBase = a.board.flashStart
    map.flashSize = a.board.flashSize
    map.ramBase = a.board.sramStart
    map.ramSize = a.board.sramSize
    # Inside the RAM region: globals from the base up (which is what every
    # `movw/movt` site is already patched against), then the heap, then the
    # stacks — which must start on a multiple of the SLOT SIZE, because a thread
    # finds its own slot by masking SP with it. That alignment is the reason the
    # stacks go last: rounding up wastes whatever is between them and the heap,
    # and nothing after them has to pay for it.
    #
    # `(noinit …)` comes off the FAR END first, before any of that is placed. It
    # has to be at a fixed address — the run that writes it and the run that reads
    # it are different runs — and the top of the region is the only end that does
    # not move when the globals or the heap change size. Aligned DOWN, so rounding
    # can only give the region more than was asked for, never less.
    let ramEnd = map.ramBase + map.ramSize
    noinitBase = if a.board.noinitSize > 0: (ramEnd - a.board.noinitSize) and not 7'u32
                 else: ramEnd
    let globalsEnd = map.ramBase + uint32((a.bssOffset + 3) and not 3)
    heapBase = (globalsEnd + 7) and not 7'u32
    let heapEnd = heapBase + a.board.heapSize
    stacksBase = (heapEnd + a.board.slotSize - 1) and not (a.board.slotSize - 1)
    let stacksEnd = stacksBase + uint32(a.board.slots) * a.board.slotSize
    if stacksEnd > noinitBase or stacksEnd < stacksBase or noinitBase < map.ramBase:
      quit "nifasm: the layout does not fit: " & $a.bssOffset & " bytes of globals, " &
           $a.board.heapSize & " of heap and " & $a.board.slots & " stack slot(s) of " &
           $a.board.slotSize & " reach 0x" & toHex(stacksEnd, 8) & ", past " &
           (if a.board.noinitSize > 0:
              "the noinit region at 0x" & toHex(noinitBase, 8) & " which is kept " &
              "back from the top of the "
            else: "the end of the ") &
           $map.ramSize & "-byte region at 0x" & toHex(map.ramBase, 8)
    # This image boots on ITS core's slot, and starts just below the slot's
    # thread-local reservation — which lives at the TOP, so the stack grows DOWN
    # away from it rather than into it.
    map.stackTop = stacksBase + uint32(a.board.core + 1) * a.board.slotSize -
                   a.board.tvarSize
  let bssVaddr = map.ramBase
  let codeVaddr = map.flashBase
  # NOT a constant any more: the table is two words when nothing handles an
  # exception and at least sixteen when something does, so every address below is
  # measured from this rather than from a fixed 8.
  let itBytes = a.interruptTableBytes
  # A global initialized with another SYMBOL's address — `var hook = twice`, `var
  # alias = addr counter` — is a relocation, not a constant, so it is baked here
  # once every label has a position. Without this the cell stays zero and the
  # first indirect call through it branches to address 0; the failure is a
  # lockup with nothing at the crash site to say which global was never filled.
  #
  # A proc's address carries the Thumb bit, for the same reason `rkTMovwMovtFunc`
  # does: `blx` to an even address asks for ARM state, which M-profile has none of.
  if a.bssSymInits.len > 0 and bssImage.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    let codeBase = codeVaddr + uint32(itBytes)
    for it in a.bssSymInits:
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc:
        if not labelPos.hasKey(it.sym.offset): continue
        targetVaddr = codeBase + uint32(labelPos[it.sym.offset]) + 1'u32
      of skRodata:
        if not labelPos.hasKey(it.sym.offset): continue
        targetVaddr = codeBase + uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = bssVaddr + uint32(it.sym.size)
      else: continue
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # The stack grows DOWN from `map.stackTop`, the globals UP from `map.ramBase`.
  # They share one RAM region, so say so when they would meet rather than letting
  # the first deep call frame quietly overwrite a global.
  if bssVaddr + uint32(a.bssOffset) > map.stackTop:
    quit "nifasm: " & $a.bssOffset & " bytes of globals at 0x" &
         toHex(bssVaddr, 8) & " reach the stack top at 0x" & toHex(map.stackTop, 8)

  var patched = code

  # Bake the symbol-address fields of a rodata blob — a vtable, an RTTI record, a
  # `const` holding `addr other` — now that every label has a position. The blob
  # lives in the code segment at its own label; each recorded field is a 4-byte
  # ABSOLUTE address, and a proc's carries the Thumb bit for the same reason
  # `rkTMovwMovtFunc` does: a function pointer read out of a table is called
  # through `blx` like any other.
  if a.rodataSymInits.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = codeVaddr + uint32(itBytes) +
                        uint32(labelPos[it.sym.offset]) + 1'u32   # Thumb bit
      of skRodata:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = codeVaddr + uint32(itBytes) +
                        uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = bssVaddr + uint32(it.sym.size)
      else: discard
      for i in 0 ..< it.size:
        if sitePos + i < patched.len:
          patched[sitePos + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # Patch every `(adr D <gvar>)` / indirect-call MOVW+MOVT pair with the global's
  # absolute address, now that the .bss layout is fixed. `sym.size` is its byte
  # offset within .bss — the same field the ELF64 and Mach-O backends read.
  for (pos, sym) in a.gvarSites:
    if pos + 8 > patched.len: continue
    var bytes = initBytes()
    for i in 0 ..< 8: bytes.add patched[pos + i]
    bytes.patchThumbMovwMovtPair(0, bssVaddr + uint32(sym.size))
    for i in 0 ..< 8: patched[pos + i] = bytes[i]

  # ── the .data / .bss split ────────────────────────────────────────────────
  # Everything above lives in ONE flat SRAM region, and every `movw/movt` site
  # just patched addresses it by offset from `bssVaddr`. That does not change.
  # What changes is where the region's INITIAL CONTENTS come from: a chip's RAM
  # holds nothing at reset, so the initialized part has to be a copy from flash
  # and the rest has to be zeroed — by the image itself, since there is no loader
  # to do it. `(dataload)`/`(datavma)`/`(datasize)`/`(bsssize)` are those four
  # numbers, and this is the only place that knows them.
  #
  # The cut is the HIGH-WATER MARK of the initialized bytes, not a partition of
  # the globals. Offsets were assigned as the gvar decls were scanned and every
  # `movw/movt` site above has already been patched against them, so re-sorting
  # here is not available — and the scan order is not the declaration order
  # either (arkham walks a table), so there is no order to exploit. A zero global
  # that lands between two initialized ones is therefore COPIED rather than
  # zeroed. That costs flash and never correctness: the byte copied is the zero
  # the image already holds for it. Assigning `.data` and `.bss` offsets from
  # separate cursors AT SCAN TIME is what would remove the waste.
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

  var image = elf32.initInterruptTable(map.stackTop,
                              codeVaddr + uint32(itBytes + entryOff), itBytes)
  # Every other word the module claimed. The Thumb bit for the same reason the
  # reset vector carries one: a branch to an even address asks for ARM state,
  # which M-profile does not have, and takes an INVSTATE UsageFault instead of
  # entering the handler.
  for (slot, sym) in a.interrupts:
    let target = codeVaddr + uint32(itBytes) +
                 uint32(a.buf.getLabelPosition(LabelId(sym.offset))) + 1'u32
    for i in 0 ..< 4:
      image[slot * 4 + i] = byte((target shr (8 * i)) and 0xFF)
  # The initializer image is appended AFTER the code, 4-aligned so the startup
  # copy — which moves whole words — reads aligned on both sides.
  let codeEnd = itBytes + patched.len
  let dataLoadOff = (codeEnd + 3) and not 3
  let dataLoadAddr = codeVaddr + uint32(dataLoadOff)

  # Now every number is known, so fill in the sites the startup code left blank.
  for (pos, which) in a.mimgSites:
    if pos + 8 > patched.len: continue
    let v = case which
            of mikDataLoad: dataLoadAddr
            of mikDataVma: bssVaddr
            of mikDataSize: uint32(dataInitSize)
            of mikBssSize: uint32(bssZeroSize)
            of mikHeapStart: heapBase
            of mikHeapSize: a.board.heapSize
            of mikNoinitStart: noinitBase
            of mikNoinitSize: a.board.noinitSize
    var bytes = initBytes()
    for i in 0 ..< 8: bytes.add patched[pos + i]
    bytes.patchThumbMovwMovtPair(0, v)
    for i in 0 ..< 8: patched[pos + i] = bytes[i]

  image.add patched
  while image.len < dataLoadOff: image.add 0'u8
  for i in 0 ..< dataInitSize:
    image.add (if i < bssImage.len: bssImage[i] else: 0'u8)

  # Nothing above bounds the image, and until now nothing did: an image larger
  # than the part's flash produced an ELF that loads and a board that faults
  # somewhere unrelated, at the first byte the loader could not place. Say it
  # here, where both numbers are known.
  if uint32(image.len) > map.flashSize:
    quit "nifasm: the image is " & $image.len & " bytes and the flash region at 0x" &
         toHex(map.flashBase, 8) & " holds " & $map.flashSize

  var segs = @[elf32.Segment(vaddr: codeVaddr, data: image, memSize: image.len,
                       flags: elf32.PF_R or elf32.PF_W or elf32.PF_X)]
  if ramSize > 0:
    # NO file-backed bytes: `data` is empty and only `memSize` is declared. That
    # is what makes the copy loop above LOAD-BEARING rather than decorative —
    # QEMU's `-kernel` would otherwise place the initialized globals itself and a
    # broken copy would still pass every fixture in the corpus.
    segs.add elf32.Segment(vaddr: bssVaddr, data: @[], memSize: ramSize,
                     flags: elf32.PF_R or elf32.PF_W)
  result = elf32.writeElf32(segs, codeVaddr + uint32(itBytes + entryOff))
