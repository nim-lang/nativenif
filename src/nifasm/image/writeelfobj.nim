#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The ELF64 relocatable-object writer (`--emit-obj`, x86-64 Linux).
##
## A program that links a foreign object (`{.compile.}`, `{.link.}`) is finished
## by the SYSTEM linker, so nifasm hands it an object instead of an executable.
## The executable writer resolves every address itself; here each of those
## resolutions becomes a relocation instead:
##
## ==========================================  =================================
## what nifasm tracks                          relocation
## ==========================================  =================================
## a global's RIP-relative `lea`/`gload`       `R_X86_64_PC32` against `.data`
## (`gvarSites`)
## an extern's `call [rip+slot]` (`rkIatCall`)  `R_X86_64_GOTPCRELX` against the
##                                             undefined symbol
## a thread-local operand (`Bytes.tlsSites`)   `R_X86_64_TPOFF32` against `.tdata`
##                                             (`.tbss` without initializers)
## a symbol-address field in a rodata blob,    `R_X86_64_64`
## a global's initializer or a `dataConst`
## ==========================================  =================================
##
## There is no entry stub: crt's `_start` calls the global `main` (the program's
## entry proc) with argc/argv/envp in rdi/rsi/rdx, which is `main.0`'s own
## signature. And nifasm does not own the thread pointer — libc does. The
## program's thread-locals are one `.tdata` section, i.e. one module of the
## executable's static TLS block, reached through `R_X86_64_TPOFF32`.
##
## A rodata blob lives in `.text`, so its absolute address fields are text
## relocations: the object must be linked into a non-PIE executable.

import std / [tables, syncio]
import "../core" / [context, sem, relocs, buffers]
import elf, writecommon, writeelf

include compat2   # canRaise

const
  SecText = 1       # section indices, fixed
  SecData = 2
  SecTdata = 3
  SecRelaText = 4
  SecRelaData = 5
  SecSymtab = 6
  SecStrtab = 7
  SecNoteStack = 8
  SecShstrtab = 9

  SymText = 1       # the local symbols every object has, in `.symtab` order
  SymData = 2
  SymTls = 3

type
  ObjWriter = object
    syms: seq[Elf64_Sym]
    strtab: seq[byte]
    relaText: seq[Elf64_Rela]
    relaData: seq[Elf64_Rela]
    labelPos: Table[int, int]
    undef: Table[string, int]    # external name -> symbol index

proc addName(w: var ObjWriter; name: string): Elf64_Word =
  result = Elf64_Word(w.strtab.len)
  for ch in name: w.strtab.add byte(ch)
  w.strtab.add 0'u8

proc addSym(w: var ObjWriter; name: string; bindKind, typ: uint8; shndx: int;
            value, size: uint64): int =
  result = w.syms.len
  w.syms.add Elf64_Sym(st_name: (if name.len > 0: w.addName(name) else: 0),
                       st_info: (bindKind shl 4) or typ, st_other: 0,
                       st_shndx: Elf64_Half(shndx), st_value: value, st_size: size)

proc rela(offset: int; sym: int; typ: uint32; addend: int64): Elf64_Rela =
  Elf64_Rela(r_offset: Elf64_Addr(offset),
             r_info: (Elf64_Xword(sym) shl 32) or Elf64_Xword(typ),
             r_addend: Elf64_Sxword(addend))

proc target(w: ObjWriter; a: GenContext; sym: Symbol; found: var bool): (int, int64) =
  ## The section symbol and addend an absolute reference to `sym` resolves to: a
  ## proc or rodata label in `.text`, a global in `.data`.
  found = true
  result = (0, 0'i64)
  case sym.kind
  of skProc, skRodata:
    if sym.kind == skRodata and sym.dataConst:
      result = (SymData, int64(sym.size))
    elif w.labelPos.hasKey(sym.offset):
      result = (SymText, int64(w.labelPos.getOrDefault(sym.offset)))
    else:
      found = false
  of skGvar:
    result = (SymData, int64(sym.size))
  else:
    found = false

proc absReloc(w: var ObjWriter; a: GenContext; dest: var seq[Elf64_Rela];
              offset: int; sym: Symbol; size: int) =
  if size != 8:
    quit "nifasm: --emit-obj: a " & $size & "-byte symbol address is not supported"
  var found = false
  let (s, addend) = w.target(a, sym, found)
  if found: dest.add rela(offset, s, R_X86_64_64, addend)

proc undefSym(w: var ObjWriter; extName: string): int =
  result = w.undef.getOrDefault(extName, -1)
  if result < 0:
    result = w.addSym(extName, STB_GLOBAL, STT_NOTYPE, 0, 0, 0)
    w.undef[extName] = result

proc addBytes[T](dest: var seq[byte]; x: T) =
  let at = dest.len
  dest.setLen at + sizeof(T)
  copyMem(addr dest[at], unsafeAddr x, sizeof(T))

proc addSeq[T](dest: var seq[byte]; xs: seq[T]) =
  for x in xs: dest.addBytes x

proc alignTo(dest: var seq[byte]; alignment: int) =
  while dest.len mod alignment != 0: dest.add 0'u8

proc writeElfObject*(a: var GenContext; outfile: string) {.canRaise.} =
  if a.arch != Arch.X64:
    quit "nifasm: --emit-obj writes an ELF object for x86-64 only"
  # The thread-local sites were recorded by the encoder; the layout passes move
  # code, so take them out first and carry them through the same maps.
  var tlsSites = a.buf.data.tlsSites
  layoutCode(a, tlsSites)
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)
  var code = a.buf.data

  var w = ObjWriter()
  for ld in a.buf.labels: w.labelPos[int(ld.id)] = ld.position
  w.strtab.add 0'u8
  w.syms.add Elf64_Sym()                                           # index 0: null
  discard w.addSym("", STB_LOCAL, STT_SECTION, SecText, 0, 0)      # SymText
  discard w.addSym("", STB_LOCAL, STT_SECTION, SecData, 0, 0)      # SymData
  discard w.addSym("arkham.tls.0", STB_LOCAL, STT_TLS, SecTdata, 0,
                   uint64(a.tlsOffset))                            # SymTls
  # Every proc as a local function symbol, so a debugger and `perf` can name it.
  if a.debugInfo:
    for p in a.unwind:
      if p.stop > p.start:
        discard w.addSym(p.name, STB_LOCAL, STT_FUNC, SecText, uint64(p.start),
                         uint64(p.stop - p.start))
  let firstGlobal = w.syms.len
  if a.entrySym != nil and w.labelPos.hasKey(a.entrySym.offset):
    discard w.addSym("main", STB_GLOBAL, STT_FUNC, SecText,
                     uint64(w.labelPos.getOrDefault(a.entrySym.offset)), 0)

  # ── .text relocations ──────────────────────────────────────────────────────
  # A global's RIP-relative access: disp32 at +3, RIP at +7 (`emitLeaRipPlaceholder`
  # and `emitMovRipPlaceholder` are laid out alike), so A = offset - 4.
  for (pos, sym) in a.gvarSites:
    w.relaText.add rela(pos + 3, SymData, R_X86_64_PC32, int64(sym.size) - 4)
  # An extern's `call [rip+disp32]` (FF 15): the linker supplies the GOT slot, or
  # relaxes the call to a direct one.
  var extBySlot = initTable[int, string]()
  for ext in a.extProcs: extBySlot[ext.gotSlot] = ext.extName
  for r in a.buf.relocs:
    if r.kind == rkIatCall:
      let slot = int(r.target)
      if not extBySlot.hasKey(slot):
        quit "nifasm: --emit-obj: an external call through an unknown slot"
      let s = w.undefSym(extBySlot.getOrDefault(slot))
      w.relaText.add rela(r.position + 2, s, R_X86_64_GOTPCRELX, -4)
  # A thread-local's disp32 holds its offset in nifasm's block, which is its offset
  # in `.tdata` too: that is the addend.
  for pos in tlsSites:
    let off = int32(uint32(code[pos]) or (uint32(code[pos+1]) shl 8) or
                    (uint32(code[pos+2]) shl 16) or (uint32(code[pos+3]) shl 24))
    w.relaText.add rela(pos, SymTls, R_X86_64_TPOFF32, int64(off))
  # Symbol-address fields inside a rodata blob.
  for it in a.rodataSymInits:
    if w.labelPos.hasKey(it.labelId):
      w.absReloc(a, w.relaText, w.labelPos.getOrDefault(it.labelId) + it.blobOff,
                 it.sym, it.size)

  # ── .data image and relocations ────────────────────────────────────────────
  var dataImage = newSeq[byte](a.bssOffset)
  for it in a.bssInits:
    for i in 0 ..< it.size:
      if it.off.int + i < dataImage.len:
        dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)
  for it in a.bssSymInits:
    w.absReloc(a, w.relaData, int(it.off), it.sym, it.size)
  for it in a.rodataRebases:
    w.absReloc(a, w.relaData, it.owner.size + it.blobOff, it.target, 8)

  # ── .tdata: one thread's initial block ─────────────────────────────────────
  # Nim thread-locals rarely have initializers; without one the block is `.tbss`
  # and takes no bytes in the file.
  let tlsNoBits = a.tlsInits.len == 0
  var tdataImage = newSeq[byte](if tlsNoBits: 0 else: a.tlsOffset)
  for it in a.tlsInits:
    for i in 0 ..< it.size:
      if it.off.int + i < tdataImage.len:
        tdataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  # ── the file: header, section contents, then the section header table ───────
  var ehdr = initHeader(0, EM_X86_64)
  ehdr.e_type = ET_REL
  ehdr.e_phoff = 0
  ehdr.e_phnum = 0
  ehdr.e_phentsize = 0
  var f: seq[byte] = @[]
  f.addBytes ehdr
  f.alignTo 16
  let textOff = f.len
  for i in 0 ..< code.len: f.add code[i]
  f.alignTo 16
  let dataOff = f.len
  f.add dataImage
  f.alignTo 16
  let tdataOff = f.len
  f.add tdataImage
  f.alignTo 8
  let relaTextOff = f.len
  f.addSeq w.relaText
  let relaDataOff = f.len
  f.addSeq w.relaData
  let symtabOff = f.len
  f.addSeq w.syms
  let strtabOff = f.len
  f.add w.strtab
  var shstr: seq[byte] = @[0'u8]
  var shName: seq[uint64] = @[0'u64]
  for nm in [".text", ".data", (if tlsNoBits: ".tbss" else: ".tdata"), ".rela.text", ".rela.data", ".symtab",
             ".strtab", ".note.GNU-stack", ".shstrtab"]:
    shName.add uint64(shstr.len)
    for ch in nm: shstr.add byte(ch)
    shstr.add 0'u8
  let shstrOff = f.len
  f.add shstr
  f.alignTo 8
  let shoff = f.len

  var shdrs: seq[Elf64_Shdr] = @[]
  shdrs.add initShdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
  shdrs.add initShdr(shName[SecText], SHT_PROGBITS, SHF_ALLOC or SHF_EXECINSTR, 0,
                     uint64(textOff), uint64(code.len), 0, 0, 16, 0)
  shdrs.add initShdr(shName[SecData], SHT_PROGBITS, SHF_ALLOC or SHF_WRITE, 0,
                     uint64(dataOff), uint64(dataImage.len), 0, 0, 16, 0)
  shdrs.add initShdr(shName[SecTdata], (if tlsNoBits: SHT_NOBITS else: SHT_PROGBITS),
                     SHF_ALLOC or SHF_WRITE or SHF_TLS, 0, uint64(tdataOff),
                     uint64(a.tlsOffset), 0, 0, 16, 0)
  shdrs.add initShdr(shName[SecRelaText], SHT_RELA, SHF_INFO_LINK, 0,
                     uint64(relaTextOff), uint64(w.relaText.len * sizeof(Elf64_Rela)),
                     SecSymtab, SecText, 8, uint64(sizeof(Elf64_Rela)))
  shdrs.add initShdr(shName[SecRelaData], SHT_RELA, SHF_INFO_LINK, 0,
                     uint64(relaDataOff), uint64(w.relaData.len * sizeof(Elf64_Rela)),
                     SecSymtab, SecData, 8, uint64(sizeof(Elf64_Rela)))
  # `sh_info` of a symtab: the index of its first non-local symbol.
  shdrs.add initShdr(shName[SecSymtab], SHT_SYMTAB, 0, 0, uint64(symtabOff),
                     uint64(w.syms.len * sizeof(Elf64_Sym)), SecStrtab,
                     uint64(firstGlobal), 8, uint64(sizeof(Elf64_Sym)))
  shdrs.add initShdr(shName[SecStrtab], SHT_STRTAB, 0, 0, uint64(strtabOff),
                     uint64(w.strtab.len), 0, 0, 1, 0)
  # An empty `.note.GNU-stack` says the object does not need an executable stack.
  shdrs.add initShdr(shName[SecNoteStack], SHT_PROGBITS, 0, 0, uint64(shoff), 0,
                     0, 0, 1, 0)
  shdrs.add initShdr(shName[SecShstrtab], SHT_STRTAB, 0, 0, uint64(shstrOff),
                     uint64(shstr.len), 0, 0, 1, 0)
  f.addSeq shdrs
  ehdr.e_shoff = Elf64_Off(shoff)
  ehdr.e_shnum = Elf64_Half(shdrs.len)
  ehdr.e_shstrndx = Elf64_Half(SecShstrtab)
  copyMem(addr f[0], addr ehdr, sizeof(Elf64_Ehdr))
  try:
    writeFile(outfile, f)
  except:
    quit "nifasm: cannot write " & outfile
