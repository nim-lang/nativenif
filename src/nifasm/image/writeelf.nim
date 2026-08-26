#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The ELF64 executable writer: layout, the branch-relaxation passes, and the
## non-loaded tables a debugger reads.
##
## Everything is placed HERE and nowhere earlier — `threadJumps`,
## `invertCondJumps`, `shortenX64Jumps` and the alignment pass each move code,
## and each hands back an old->new position map that the unwind rows, the
## listing rows and the gvar/adrp patch sites are carried through. That is why
## the trace table is filled at the end rather than where it was reserved.

import std / [streams, os, tables, sets, algorithm, strutils]
import nifcore
import "../core" / [context, sem, relocs, buffers, diagnostics, modules, stackslots, listing]
import "../x64/encoder" as x86
import "../arm64/encoder" as arm64
import elf, dwarf, tracetable, writecommon

proc writeElf*(a: var GenContext; outfile: string) =
  # Shorten x86 rel32 jumps to rel8 where they fit (static-ELF x64 only: no IAT
  # call-site bookkeeping to invalidate, and AArch64 forms are fixed-size). This
  # relays out `.text`, so remap every code byte-offset we still need afterwards:
  # the gvar `lea`/`adrp` patch sites and the synthesized entry stub.
  # Arch-agnostic jump threading + dead-jump prune runs FIRST (both arches): it removes
  # unconditional jumps to their own fall-through and threads branch chains, which also
  # exposes more rel8 opportunities for the x64 shortener below. Both passes return an
  # old→new position map; apply them in sequence to every external code offset we track
  # (gvar `lea`/`adrp` patch sites, the entry stub).
  block:
    let threadMap = threadJumps(a.buf)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (threadMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = threadMap[a.entryStubOffset]
    a.remapListing(threadMap)
    a.remapUnwind(threadMap)
  block:
    # `jcc L; jmp M; L:` ⇒ `jncc M` — folds a conditional branch and its fall-through
    # unconditional jump into one branch. Pattern detection is arch-agnostic (runs on
    # both arches); only the opcode flip inside is arch-specific.
    let invMap = invertCondJumps(a.buf)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (invMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = invMap[a.entryStubOffset]
    a.remapListing(invMap)
    a.remapUnwind(invMap)
  if a.arch == Arch.X64:
    # Code-alignment candidates, as LABEL IDS (stable across the layout passes):
    # every generated proc's entry + every loop head (= target of a backward
    # jmp/jcc, collected now — after shortening those jumps are patched inline
    # and no longer tracked). The shortener keeps any jump whose displacement a
    # pad would change in rel32 form; `alignCodeX64` then inserts the NOP pads
    # so entries and loop heads start on a 16-byte boundary (gcc pads ~2.7k NOPs
    # into the same workload; nifasm previously aligned nothing, which both
    # costs fetch bandwidth on hot loop heads and made wall-clock timings swing
    # with incidental layout shifts).
    var alignLabels: seq[int] = @[]
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc: alignLabels.add sym.offset
    for id in backwardBranchTargets(a.buf): alignLabels.add id
    let posMap = shortenX64Jumps(a.buf, alignLabels)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (posMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = posMap[a.entryStubOffset]
    a.remapListing(posMap)
    a.remapUnwind(posMap)
    let alignMap = alignCodeX64(a.buf, alignLabels)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (alignMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = alignMap[a.entryStubOffset]
    a.remapListing(alignMap)
    a.remapUnwind(alignMap)
  when defined(arkhamDbgReloc):
    block validateRelocs:
      var defined = initHashSet[int]()
      var labelPos = initTable[int, int]()
      for ld in a.buf.labels: (defined.incl int(ld.id); labelPos[int(ld.id)] = ld.position)
      var idToName = initTable[int, string]()
      var procRows: seq[(int, string)]
      for name, sym in a.rootScope.syms:
        if sym.offset >= 0: idToName[sym.offset] = name
        if sym.kind == skProc and labelPos.hasKey(sym.offset):
          procRows.add (labelPos[sym.offset], name)
      procRows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
      var bad = 0
      for r in a.buf.relocs:
        if not defined.contains(int(r.target)):
          inc bad
          var enc = "?"
          for (p, nm) in procRows:
            if p <= r.position: enc = nm else: break
          if bad <= 30:
            stderr.writeLine "MISSING LABEL: reloc pos=" & $r.position & " kind=" & $r.kind &
              " targetId=" & $int(r.target) & " targetName=" &
              idToName.getOrDefault(int(r.target), "<no-name>") & " in proc " & enc
      if bad > 0: stderr.writeLine "TOTAL MISSING LABELS: " & $bad
  finalize(a.buf)
  finalize(a.bssBuf)
  # `--symmap`: dump every generated proc's virtual address to stderr (the ELF
  # carries no symbol table), so a disassembler can locate a function by name.
  if a.symMap:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    let hdrBytes = 64 + 56 * 3
    var rows: seq[(int, string)]
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc and labelPos.hasKey(sym.offset):
        rows.add (0x400000 + hdrBytes + labelPos[sym.offset], a.nameOf(name))
    rows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
    for (va, name) in rows: stderr.writeLine "0x" & toHex(va, 6) & "  " & name
  if a.listing:
    # `.text` byte 0 lands right after the ELF header + the three program headers,
    # the same arithmetic `--symmap` above does.
    a.writeListing(a.listingPath, 0x400000 + 64 + 56 * 3)
  fillTraceTable(a)
  var code = a.buf.data
  let baseAddr = 0x400000.uint64
  let headersSize = 64 + (56 * 3)  # ELF header + 3 program headers
  let pageSize = 0x1000.uint64

  # Calculate addresses and sizes
  # The LOAD segment must start at file offset 0 to include headers
  # (some kernels like WSL require this for proper loading)
  let textOffset = 0.uint64  # Include headers in LOAD segment
  let textVaddr = baseAddr   # Segment starts at base address
  let textFileSize = headersSize.uint64 + code.len.uint64  # Headers + code
  let textMemSize = (textFileSize + pageSize - 1) and not (pageSize - 1)

  # Entry point is after the headers. When nifasm synthesized an entry stub — the
  # x86-64 FS-setup prologue (`setupTls`) or the AArch64 argc/argv/envp prologue
  # (`setupLinuxA64Entry`) — that stub is the real entry and tail-jumps to the
  # program's entry proc; otherwise the entry is the first byte of code (offset 0).
  let entryOff = if a.entryStubOffset >= 0: a.entryStubOffset.uint64 else: 0'u64
  let entryAddr = baseAddr + headersSize.uint64 + entryOff

  # .bss section comes after .text in memory
  let bssVaddr = textVaddr + textMemSize
  let bssSize = a.bssOffset.uint64

  # Patch each global's address into the placeholder instruction(s) now that both
  # segments' virtual addresses are known. The gvar's .bss byte offset is `sym.size`.
  for (pos, sym) in a.gvarSites:
    let instrVaddr = textVaddr + headersSize.uint64 + pos.uint64
    let targetVaddr = bssVaddr + sym.size.uint64
    if a.arch == Arch.LinuxA64:
      # AArch64: a PC-relative `adrp rd, page` + `add rd, rd, #pageoff` pair (the
      # placeholder carries the dest reg with zero immediates, so OR them in). Same
      # encoding as the Mach-O backend's gvar patch.
      let pageDiff = int64(targetVaddr and not 0xFFF'u64) -
                     int64(instrVaddr and not 0xFFF'u64)
      let pageOff = targetVaddr and 0xFFF'u64
      let adrpImm = pageDiff shr 12
      let immlo = uint32(adrpImm and 0x03) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      var adrp = uint32(code[pos]) or (uint32(code[pos+1]) shl 8) or
                 (uint32(code[pos+2]) shl 16) or (uint32(code[pos+3]) shl 24)
      adrp = adrp or immlo or immhi
      code[pos+0] = byte(adrp and 0xFF);          code[pos+1] = byte((adrp shr 8) and 0xFF)
      code[pos+2] = byte((adrp shr 16) and 0xFF); code[pos+3] = byte((adrp shr 24) and 0xFF)
      # pos+4 is `add rd, rd, #pageoff` (address-taking) OR a folded `ldr/str rt,
      # [x17, #pageoff]` (gload/gstore). Load/store unsigned-imm has bits[29:24]==0x39
      # and scales its imm12 by the access size (bits[31:30]); `add` uses the raw offset.
      var lo = uint32(code[pos+4]) or (uint32(code[pos+5]) shl 8) or
               (uint32(code[pos+6]) shl 16) or (uint32(code[pos+7]) shl 24)
      if ((lo shr 24) and 0x3F'u32) == 0x39'u32:
        let size = (lo shr 30) and 0x3'u32
        doAssert (pageOff and ((1'u64 shl size) - 1)) == 0,
          "gload/gstore: global page-offset not aligned to its access size"
        lo = lo or (uint32((pageOff shr size) and 0xFFF) shl 10)
      else:
        lo = lo or (uint32(pageOff and 0xFFF) shl 10)
      code[pos+4] = byte(lo and 0xFF);            code[pos+5] = byte((lo shr 8) and 0xFF)
      code[pos+6] = byte((lo shr 16) and 0xFF);   code[pos+7] = byte((lo shr 24) and 0xFF)
    else:
      # x86-64: a RIP-relative `lea` — 7 bytes with a disp32 at offset +3; RIP points
      # at the next instruction (+7).
      let disp = int32(int64(targetVaddr) - int64(instrVaddr + 7))
      code[pos + 3] = byte(disp and 0xFF)
      code[pos + 4] = byte((disp shr 8) and 0xFF)
      code[pos + 5] = byte((disp shr 16) and 0xFF)
      code[pos + 6] = byte((disp shr 24) and 0xFF)
  # Bake rodata symbol-address relocations (e.g. a vtable/RTTI const whose fields
  # are addresses of other consts or procs). The blob lives in `.text` at its
  # rodata label; write the resolved target vaddr into `code` at `label + blobOff`.
  # Same target-vaddr arithmetic as `bssSymInits`: a proc/rodata label sits at
  # `baseAddr + headers + labelPos`, a gvar at `bssVaddr + its .bss off`.
  if a.rodataSymInits.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      var targetVaddr = 0'u64
      case it.sym.kind
      of skProc, skRodata:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = baseAddr + headersSize.uint64 + labelPos[it.sym.offset].uint64
      of skGvar:
        targetVaddr = bssVaddr + it.sym.size.uint64
      else: discard
      for i in 0 ..< it.size:
        if sitePos + i < code.len:
          code[sitePos + i] = byte((targetVaddr shr (8 * i)) and 0xFF)
  let bssAlignedSize = if bssSize > 0: ((bssSize + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  let machine = case a.arch
    of Arch.X64, Arch.LinuxA64:
      if a.arch == Arch.X64: EM_X86_64 else: EM_AARCH64
    else:
      EM_X86_64  # fallback

  # ── debug info: `.symtab` (proc names) and `.eh_frame` (unwind) ─────────────
  # Both are METADATA: nothing the program executes reads either, and they exist so a
  # debugger can name a frame and walk past it — arkham keeps no frame pointer, so
  # without CFI even GDB's prologue heuristic loses the chain after a frame or two
  # (measured: `#2 0x0000000000000000 in ?? ()`).
  #
  # `.symtab`/`.strtab` sit past the last PT_LOAD and cost the running image nothing.
  # `.eh_frame` is the exception: it is `SHF_ALLOC` in a read-only PT_LOAD of its own,
  # because valgrind will not accept CFI it cannot map (see the segment comment below).
  # The cost is a few demand-paged read-only KB no execution path touches.
  #
  # Everything they need is already known here: the proc's final code range (the
  # layout passes above have remapped it), its NIF name, and the CFA states its
  # prologue passes through. See dwarf.nim for why that is only a handful of
  # bytes per proc — SP is constant inside an arkham frame.
  let procVaddrBase = baseAddr + headersSize.uint64
  var ehFrame: seq[byte] = @[]
  var symtab: seq[byte] = @[]
  var strtab: seq[byte] = @[]
  if a.debugInfo:
    # The image's entry, and — when a synthesized stub holds it — the entry PROC
    # the stub tail-jumps to; both are "nothing called me" frames for the FDEs.
    var entryOffs = @[int(entryOff)]
    if a.entrySym != nil:
      for ld in a.buf.labels:
        if int(ld.id) == a.entrySym.offset: entryOffs.add ld.position
    ehFrame = buildEhFrame(a.unwind,
                           (if a.arch == Arch.LinuxA64: dwA64 else: dwX64),
                           procVaddrBase, entryOffs)
    strtab.add 0'u8                                   # index 0 is the empty name
    symtab.setLen sizeof(Elf64_Sym)                   # index 0 is the null symbol
    for p in a.unwind:
      if p.stop <= p.start: continue
      var sym = Elf64_Sym(st_name: Elf64_Word(strtab.len),
                          st_info: (STB_GLOBAL shl 4) or STT_FUNC,
                          st_other: 0, st_shndx: 1,   # section 1 is `.text`
                          st_value: procVaddrBase + uint64(p.start),
                          st_size: uint64(p.stop - p.start))
      for ch in p.name: strtab.add byte(ch)
      strtab.add 0'u8
      let at = symtab.len
      symtab.setLen at + sizeof(Elf64_Sym)
      copyMem(addr symtab[at], addr sym, sizeof(Elf64_Sym))

  var ehdr = initHeader(entryAddr, machine)
  ehdr.e_phnum = 3  # Three program headers: .text, .bss and .eh_frame
  ehdr.e_phoff = 64  # Program headers start after ELF header

  # Build the initialized .bss image (constant static initializers — e.g. `stdout = 1`,
  # or a gvar's compile-time value) FIRST, so the data LOAD segment below can size its
  # file/mem extents to cover it. The on-disk image holds those bytes (the rest zero),
  # so the slots start initialized with no entry-time code (correct in a bundle).
  var bssImage: seq[byte]
  if (a.bssInits.len > 0 or a.bssSymInits.len > 0) and bssSize > 0:
    bssImage = newSeq[byte](bssSize.int)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)
    # Bake symbol-address initializers (function-pointer hooks etc.). The target's
    # absolute vaddr is known now that `.text` is finalized: a proc/rodata label
    # sits at `baseAddr + headers + labelPos`; a gvar at `bssVaddr + its .bss off`.
    if a.bssSymInits.len > 0:
      var labelPos = initTable[int, int]()
      for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
      for it in a.bssSymInits:
        var targetVaddr = 0'u64
        case it.sym.kind
        of skProc, skRodata:
          if labelPos.hasKey(it.sym.offset):
            targetVaddr = baseAddr + headersSize.uint64 + labelPos[it.sym.offset].uint64
        of skGvar:
          targetVaddr = bssVaddr + it.sym.size.uint64
        else: discard
        for i in 0 ..< it.size:
          if it.off.int + i < bssImage.len:
            bssImage[it.off.int + i] = byte((targetVaddr shr (8 * i)) and 0xFF)
  let bssFileSz = if bssImage.len > 0: bssSize else: 0'u64

  # THREE PT_LOADs, one per permission class:
  #
  #   R-X   headers + code       [0, textMemSize)
  #   RW-   data/bss             [textMemSize, +bssFileSz), zero-filled to bssAlignedSize
  #   R--   .eh_frame            page-aligned, so a debugger can MAP the unwind tables
  #
  # An earlier revision merged all three into ONE R+W+X segment, blaming the AArch64
  # kernel for applying the data segment's permissions to the whole range. That is no
  # longer reproducible (re-tested on Linux 6.12/AArch64: the split layout below loads
  # and runs correctly), and the merged shape cost two things worth having back.
  #
  # It gave up W^X: every code page was writable. And it made the image opaque to
  # valgrind, whose ELF reader classifies a mapping as the "text" map only when it is
  # R+X and *not* writable — so it skipped the object entirely and every frame of every
  # report came out as `???`, which is most of the value of running valgrind at all.
  #
  # `.eh_frame` gets its own read-only segment for the second half of that story:
  # valgrind refuses an `.eh_frame` whose section mapping it cannot place inside a
  # loaded segment ("Can't make sense of .eh_frame section mapping") and treats that as
  # a FATAL debug-info error, which takes `.symtab` down with it. So unlike `.symtab`
  # and `.strtab` — which stay in the unloaded tail, read from the file by section
  # header — the CFI has to be genuinely mapped. It costs a few demand-paged read-only
  # KB that nothing reads unless a debugger walks the stack.
  #
  # Each segment's p_offset is congruent to its p_vaddr modulo the page size, which is
  # what the kernel's mmap of the file requires: the first two are page multiples by
  # construction, and the third is page-aligned on both sides below.
  let ehSize = ehFrame.len.uint64
  let ehSegOff = (textMemSize + bssFileSz + pageSize - 1) and not (pageSize - 1)
  let ehVaddr = bssVaddr + bssAlignedSize

  var textPhdr = initPhdr(textOffset, textVaddr, textMemSize, textMemSize,
                          PF_R or PF_X)
  # `memsz > filesz` is the bss zero-fill tail; the segment is writable, so the kernel
  # accepts it.
  var bssPhdr = initPhdr(textMemSize, bssVaddr, bssFileSz, bssAlignedSize,
                         PF_R or PF_W)
  # Kept empty (filesz = memsz = 0) when there is no debug info: a PT_LOAD the kernel
  # ignores, so `e_phnum` — and with it `headersSize` — stays constant either way.
  var ehPhdr =
    if ehSize > 0: initPhdr(ehSegOff, ehVaddr, ehSize, ehSize, PF_R)
    else: initPhdr(0'u64, ehVaddr, 0'u64, 0'u64, PF_R)

  var f = newFileStream(outfile, fmWrite)
  defer: f.close()

  # Write ELF header
  f.write(ehdr)

  # Write program headers
  f.write(textPhdr)
  f.write(bssPhdr)
  f.write(ehPhdr)

  # Write .text section (code)
  if code.len > 0:
    f.writeData(code.rawData, code.len)
    # Pad to page boundary
    let padding = int(textMemSize - textFileSize)
    if padding > 0:
      var zeros = newSeq[byte](padding)
      f.writeData(unsafeAddr zeros[0], padding)

  # Write the initialized .bss image (constant static initializers), if any. The
  # remaining memsz beyond bssSize is zero-filled by the loader.
  if bssImage.len > 0:
    f.writeData(unsafeAddr bssImage[0], bssImage.len)

  if a.debugInfo:
    # `.text` and `.eh_frame` are `SHF_ALLOC` — they describe bytes that are LOADED
    # (the symbols point into the first, a debugger maps the second). `.symtab`,
    # `.strtab` and `.shstrtab` follow in the non-loaded tail, read straight from the
    # file by section header, then the section header table itself.
    var pos = uint64(f.getPosition())
    template pad8() =
      while (pos and 7) != 0:
        f.write 0'u8; inc pos
    # `.eh_frame` starts its own PT_LOAD, so it is padded to a PAGE, not to 8: the
    # kernel maps a segment from a page-aligned file offset, and `ehSegOff` above
    # computed that same boundary.
    while (pos and (pageSize - 1)) != 0:
      f.write 0'u8; inc pos
    let ehFrameOff = pos
    doAssert ehFrameOff == ehSegOff, "`.eh_frame` file offset disagrees with its PT_LOAD"
    if ehFrame.len > 0:
      f.writeData(unsafeAddr ehFrame[0], ehFrame.len); pos += ehFrame.len.uint64
    pad8()
    let symtabOff = pos
    if symtab.len > 0:
      f.writeData(unsafeAddr symtab[0], symtab.len); pos += symtab.len.uint64
    let strtabOff = pos
    if strtab.len > 0:
      f.writeData(unsafeAddr strtab[0], strtab.len); pos += strtab.len.uint64
    # `.shstrtab` — the section NAME strings, in the order the headers below use.
    var shstr: seq[byte] = @[]
    var shName: seq[uint32] = @[]
    shstr.add 0'u8
    for nm in [".text", ".eh_frame", ".symtab", ".strtab", ".shstrtab"]:
      shName.add uint32(shstr.len)
      for ch in nm: shstr.add byte(ch)
      shstr.add 0'u8
    let shstrOff = pos
    f.writeData(unsafeAddr shstr[0], shstr.len); pos += shstr.len.uint64
    pad8()
    let shoff = pos
    var shdrs: seq[Elf64_Shdr] = @[]
    shdrs.add initShdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
    shdrs.add initShdr(shName[0], SHT_PROGBITS, SHF_ALLOC or SHF_EXECINSTR,
                       baseAddr + headersSize.uint64, headersSize.uint64,
                       code.len.uint64, 0, 0, 16, 0)
    shdrs.add initShdr(shName[1], SHT_PROGBITS, SHF_ALLOC, ehVaddr, ehFrameOff,
                       ehFrame.len.uint64, 0, 0, 8, 0)
    # `sh_link` of a symtab is its string table; `sh_info` is the index of the
    # first non-local symbol — every symbol here is global, so that is 1.
    shdrs.add initShdr(shName[2], SHT_SYMTAB, 0, 0, symtabOff,
                       symtab.len.uint64, 4, 1, 8, uint64(sizeof(Elf64_Sym)))
    shdrs.add initShdr(shName[3], SHT_STRTAB, 0, 0, strtabOff,
                       strtab.len.uint64, 0, 0, 1, 0)
    shdrs.add initShdr(shName[4], SHT_STRTAB, 0, 0, shstrOff,
                       shstr.len.uint64, 0, 0, 1, 0)
    for sh in shdrs: f.write(sh)
    # Re-write the ELF header now that the section table's offset is known.
    ehdr.e_shoff = shoff
    ehdr.e_shnum = Elf64_Half(shdrs.len)
    ehdr.e_shstrndx = Elf64_Half(shdrs.len - 1)
    f.setPosition(0)
    f.write(ehdr)

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)
