#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The PE/COFF writer for `win_x64`.
##
## `.pdata`/`.xdata` are not optional decoration here the way `.eh_frame` is on
## ELF: nothing generated keeps a frame pointer, and on Windows it is the OS
## itself — not just a debugger — that walks frames with them.

import std / [streams, os, tables, sets, algorithm, strutils]
import nifcore
import "../core" / [context, sem, relocs, buffers, diagnostics, modules, stackslots, listing]
import "../x64/encoder" as x86
import pe, dwarf, tracetable, writecommon

proc writeExe*(a: var GenContext; outfile: string) =
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)

  # Determine machine type based on architecture
  let machine =
    case a.arch
    of Arch.WinX64:
      pe.IMAGE_FILE_MACHINE_AMD64
    of Arch.WinA64:
      pe.IMAGE_FILE_MACHINE_ARM64
    else:
      pe.IMAGE_FILE_MACHINE_AMD64

  # Build dynlink info for external procs
  var dynlink: pe.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add pe.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add pe.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position

  # The `.data` image: every global's storage, with its statically known scalar
  # initializers already baked (`stdout = 1`, a string literal's bytes). Symbol
  # ADDRESS initializers can't be — they wait for the layout, below.
  var dataImage: seq[byte] = @[]
  if a.bssOffset > 0:
    dataImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  # Every absolute pointer the patch below writes, so `.reloc` can list it and the
  # image survives being loaded away from its preferred base.
  var absSites: seq[pe.AbsSite] = @[]
  for it in a.bssSymInits:
    absSites.add pe.AbsSite(inData: true, pos: it.off.int)
  for it in a.rodataSymInits:
    if labelPos.hasKey(it.labelId):
      absSites.add pe.AbsSite(inData: false, pos: labelPos[it.labelId] + it.blobOff)

  # The patch hook below runs inside `writePE`, so it cannot capture the `var
  # GenContext` itself — take the site lists it needs (cheap ref-counted seqs) and a
  # pointer to the code buffer, all of which ARE capturable.
  let codeBuf = addr a.buf
  let gvarSites = a.gvarSites
  let bssSymInits = a.bssSymInits
  let rodataSymInits = a.rodataSymInits

  proc symVaddr(lay: pe.PeLayout; sym: Symbol): uint64 =
    ## The runtime address of `sym`: a proc/rodata label sits in `.text`, a global in
    ## `.data`. (The `.bss` byte offset of a global is kept in `sym.size`.)
    case sym.kind
    of skProc, skRodata:
      if labelPos.hasKey(sym.offset):
        lay.imageBase + lay.textRva.uint64 + labelPos[sym.offset].uint64
      else: 0'u64
    of skGvar: lay.imageBase + lay.dataRva.uint64 + sym.size.uint64
    else: 0'u64

  proc patchAddrs(lay: pe.PeLayout) =
    ## Bake every address that only the final layout determines. The ELF twin of this
    ## lives in `writeElf`; both are driven by the same three site lists.
    # Each global's RIP-relative `lea` placeholder: a 7-byte instruction with a disp32
    # at +3, relative to the address of the NEXT instruction.
    for (pos, sym) in gvarSites:
      let instrRva = lay.textRva + uint32(pos)
      let targetRva = lay.dataRva + uint32(sym.size)
      let disp = int32(int64(targetRva) - int64(instrRva + 7))
      for i in 0 ..< 4:
        codeBuf[].data[pos + 3 + i] = byte((disp shr (8 * i)) and 0xFF)
    # Function-pointer hooks (`gExitFlush = nimNoopFlush`) — an absolute address in a
    # global's slot; without this the slot stays zero and the indirect call jumps to 0.
    for it in bssSymInits:
      let v = symVaddr(lay, it.sym)
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((v shr (8 * i)) and 0xFF)
    # The same, for an address embedded in a rodata blob (a vtable / RTTI record),
    # which lives in `.text` at its own label.
    for it in rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      let v = symVaddr(lay, it.sym)
      for i in 0 ..< it.size:
        if sitePos + i < codeBuf[].data.len:
          codeBuf[].data[sitePos + i] = byte((v shr (8 * i)) and 0xFF)

  # The synthesized process entry, if any (see `setupWinEntry`); otherwise the image
  # starts at the first byte of `.text`, which is the entry proc.
  let entryOff = if a.winEntryOffset >= 0: a.winEntryOffset.uint32 else: 0'u32

  # `.pdata`/`.xdata` from the same per-proc facts the ELF path encodes as
  # `.eh_frame`. Win64 has no frame pointer either, so this is what lets the OS
  # unwind at all — a backtrace, and any future SEH, both hang off it.
  writePE(a.buf, dataImage, a.bssOffset, entryOff, machine, outfile, dynlink,
          absSites, patchAddrs, (if a.debugInfo: a.unwind else: @[]))
