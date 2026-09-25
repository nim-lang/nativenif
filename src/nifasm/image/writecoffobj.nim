#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The COFF relocatable-object writer (`--emit-obj`, x86-64 Windows).
##
## The Windows twin of `writeelfobj`: a program linked with the C runtime, or with
## a foreign object (`{.compile.}`, `{.link.}`), is finished by the SYSTEM linker,
## i.e. MinGW's gcc or clang, whose `.o` is exactly this format (`pe-x86-64`). Each
## address the PE writer resolves itself becomes a relocation instead:
##
## ==========================================  =================================
## what nifasm tracks                          relocation
## ==========================================  =================================
## a global's RIP-relative `lea`/`gload`       `REL32` against `.data`
## (`gvarSites`)
## an extern's `call [rip+slot]` (`rkIatCall`)  `REL32` against `__imp_<name>`
## of a named dll                              (the import library's IAT slot)
## an extern with no dll (libc, a foreign      rewritten to `addr32 call <name>`,
## object)                                     `REL32` against `<name>`
## the TLS index load (`arkham.tlsindex.0`)    `REL32` against the crt's
##                                             `_tls_index`
## the `main` stub's `.tls$` and `_tls_start`  `REL32` against both
## addresses (`winTlsSites`)
## a symbol-address field in a rodata blob,    `ADDR64`
## or a global's initializer
## a `.pdata` entry                            `ADDR32NB`
## ==========================================  =================================
##
## COFF relocations have no addend field: the addend is whatever the relocated
## field holds, so every site below is written with its offset in the section it
## is relative to.
##
## There is no entry stub and no TLS directory: the crt's `mainCRTStartup` calls the
## global `main` (`setupWinCrtMain`, an adapter from the Win64 convention to
## `main.0`'s), and the crt's `_tls_used` describes a template that the linker
## gathers from every object's `.tls$` sections. Its `_tls_index` is where the
## loader stores the TLS slot, which is what `arkham.tlsindex.0` names in a PE.
## The field is a DWORD there, so that one 64-bit `gload` becomes a 32-bit one.
##
## Where the program's `.tls$` lands in that template is the linker's business.
## `SECREL` is the relocation that says it, but GNU ld (2.36 at least) also gives
## a `SECREL` in loaded code a base relocation, which ASLR then applies to the
## offset. So the stub computes `&.tls$ - &_tls_start` from two RIP-relative
## `lea`s and stores it in a `.data` cell that every thread-local address adds
## (`winTlsDelta`).
##
## Why not always call through `__imp_<name>`: GNU ld synthesizes no `__imp_`
## pointer for a symbol defined in a static object, and libc functions come from
## either kind of library depending on the crt build. A direct call reaches both:
## an import library provides a `jmp [__imp_<name>]` thunk for every function.

import std / [tables, syncio, algorithm]
import "../core" / [context, sem, relocs, buffers]
import pe, writecommon

include compat2   # canRaise

const
  RelAddr64 = 0x0001'u16      # IMAGE_REL_AMD64_ADDR64
  RelAddr32Nb = 0x0003'u16    # IMAGE_REL_AMD64_ADDR32NB (an RVA)
  RelRel32 = 0x0004'u16       # IMAGE_REL_AMD64_REL32 (relative to the field's end)

  ScnCntCode = 0x00000020'u32
  ScnCntInitData = 0x00000040'u32
  ScnAlign4 = 0x00300000'u32
  ScnAlign16 = 0x00500000'u32
  ScnExecute = 0x20000000'u32
  ScnRead = 0x40000000'u32
  ScnWrite = 0x80000000'u32

  ClassExternal = 2'u8
  ClassStatic = 3'u8
  TypeFunction = 0x20'u16

  SymSize = 18                # a symbol table record, and an aux record
  TlsIndexName = "_tls_index"
  TlsStartName = "_tls_start"

type
  CoffReloc = object
    offset: uint32
    sym: int
    typ: uint16

  CoffSection = object
    name: string
    chars: uint32
    data: seq[byte]
    relocs: seq[CoffReloc]

  ObjSym = object
    name: string
    value: uint32
    section: int              # 1-based section number, 0 = undefined
    typ: uint16
    class: uint8

  ObjWriter = object
    secs: seq[CoffSection]
    syms: seq[ObjSym]         # after the section symbols (two records each)
    undef: Table[string, int]

proc le16(dest: var seq[byte]; x: uint16) =
  dest.add byte(x and 0xFF); dest.add byte(x shr 8)

proc le32(dest: var seq[byte]; x: uint32) =
  for i in 0 ..< 4: dest.add byte((x shr (8 * i)) and 0xFF)

proc put32(dest: var seq[byte]; at: int; x: uint32) =
  for i in 0 ..< 4: dest[at + i] = byte((x shr (8 * i)) and 0xFF)

proc put64(dest: var seq[byte]; at: int; x: uint64) =
  for i in 0 ..< 8: dest[at + i] = byte((x shr (8 * i)) and 0xFF)

proc sectionSym(sec: int): int {.inline.} =
  ## The symbol index of section `sec` (0-based): every section symbol comes first,
  ## with its one aux record.
  2 * sec

proc symIndex(w: ObjWriter; i: int): int {.inline.} =
  2 * w.secs.len + i

proc addSym(w: var ObjWriter; s: ObjSym): int =
  result = w.symIndex(w.syms.len)
  w.syms.add s

proc undefSym(w: var ObjWriter; name: string): int =
  result = w.undef.getOrDefault(name, -1)
  if result < 0:
    result = w.addSym(ObjSym(name: name, class: ClassExternal, typ: TypeFunction))
    w.undef[name] = result

proc addName(dest, strtab: var seq[byte]; name: string) =
  ## An 8-byte short name, or `0, offset` into the string table.
  if name.len <= 8:
    for ch in name: dest.add byte(ch)
    for i in name.len ..< 8: dest.add 0'u8
  else:
    dest.le32 0
    dest.le32 uint32(strtab.len)
    for ch in name: strtab.add byte(ch)
    strtab.add 0'u8

proc writeCoffObject*(a: var GenContext; outfile: string) {.canRaise.} =
  if a.arch != Arch.WinX64:
    quit "nifasm: --emit-obj writes a COFF object for x86-64 Windows only"
  # No layout passes, as for the PE: the positions the encoder recorded are final.
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)

  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position

  # The per-proc unwind records the PE writer turns into `.pdata`, plus the `main`
  # stub's own. A leaf (no pushes, no frame) needs none.
  var fns: seq[(int, int, seq[byte])] = @[]
  if a.debugInfo:
    for p in a.unwind:
      let ui = unwindInfoFor(p)
      if ui.len > 0: fns.add (p.start, p.stop, ui)
  if a.winEntryOffset >= 0:
    fns.add (a.winEntryOffset, a.winCrtMainEnd, a.winCrtMainUnwind)
  fns.sort(proc (x, y: (int, int, seq[byte])): int = cmp(x[0], y[0]))

  var w = ObjWriter()
  let secText = w.secs.len
  var code = newSeq[byte](a.buf.data.len)
  if code.len > 0: copyMem(addr code[0], a.buf.data.rawData, code.len)
  w.secs.add CoffSection(name: ".text", data: code,
                         chars: ScnCntCode or ScnExecute or ScnRead or ScnAlign16)
  let secData = w.secs.len
  w.secs.add CoffSection(name: ".data", data: newSeq[byte](a.bssOffset),
                         chars: ScnCntInitData or ScnRead or ScnWrite or ScnAlign16)
  var secTls = -1
  if a.tlsOffset > 0:
    # `.tls$` sorts between the crt's `.tls$AAA` (`_tls_start`) and `.tls$ZZZ`
    # (`_tls_end`), so it lands inside the template `_tls_used` describes.
    secTls = w.secs.len
    w.secs.add CoffSection(name: ".tls$", data: newSeq[byte](a.tlsOffset),
                           chars: ScnCntInitData or ScnRead or ScnWrite or ScnAlign16)
  var secXdata, secPdata = -1
  if fns.len > 0:
    secXdata = w.secs.len
    w.secs.add CoffSection(name: ".xdata", chars: ScnCntInitData or ScnRead or ScnAlign4)
    secPdata = w.secs.len
    w.secs.add CoffSection(name: ".pdata", chars: ScnCntInitData or ScnRead or ScnAlign4)

  template text: untyped = w.secs[secText].data
  template reloc(sec: int; at: int; s: int; t: uint16) =
    w.secs[sec].relocs.add CoffReloc(offset: uint32(at), sym: s, typ: t)

  proc target(sym: Symbol; found: var bool): (int, uint64) =
    ## The section and offset an absolute reference to `sym` resolves to: a proc or
    ## rodata label in `.text`, a global in `.data`.
    found = true
    result = (0, 0'u64)
    case sym.kind
    of skProc, skRodata:
      if labelPos.hasKey(sym.offset):
        result = (secText, uint64(labelPos.getOrDefault(sym.offset)))
      else:
        found = false
    of skGvar:
      result = (secData, uint64(sym.size))
    else:
      found = false

  # ── .data image ────────────────────────────────────────────────────────────
  for it in a.bssInits:
    for i in 0 ..< it.size:
      if it.off.int + i < w.secs[secData].data.len:
        w.secs[secData].data[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)
  for it in a.bssSymInits:
    if it.size != 8:
      quit "nifasm: --emit-obj: a " & $it.size & "-byte symbol address is not supported"
    var found = false
    let (s, off) = target(it.sym, found)
    if found:
      w.secs[secData].data.put64(int(it.off), off)
      reloc(secData, int(it.off), sectionSym(s), RelAddr64)

  # ── .text relocations ──────────────────────────────────────────────────────
  # A global's RIP-relative access: disp32 at +3, the instruction ends at +7, which
  # is the end of the field — exactly what REL32 is relative to.
  for (pos, sym) in a.gvarSites:
    if sym == a.winTlsIndexSym:
      # The crt's `_tls_index` is a DWORD; `mov r64, [rip+x]` → `mov r32, [rip+x]`
      # (zero-extending) by clearing REX.W. The REX byte stays, so the length does.
      if (text[pos] and 0xF8'u8) != 0x48'u8 or text[pos + 1] != 0x8B'u8:
        quit "nifasm: --emit-obj: the TLS index is read by an unexpected instruction"
      text[pos] = text[pos] and not 0x08'u8
      text.put32(pos + 3, 0)
      reloc(secText, pos + 3, w.undefSym(TlsIndexName), RelRel32)
    else:
      text.put32(pos + 3, uint32(sym.size))
      reloc(secText, pos + 3, sectionSym(secData), RelRel32)
  # An extern's `call [rip+disp32]` (FF 15): through the import library's IAT slot
  # when the extern names a dll, otherwise a direct call the linker binds.
  var extBySlot = initTable[int, int]()
  for i, ext in a.extProcs: extBySlot[ext.gotSlot] = i
  for r in a.buf.relocs:
    if r.kind == rkIatCall:
      let slot = int(r.target)
      if not extBySlot.hasKey(slot):
        quit "nifasm: --emit-obj: an external call through an unknown slot"
      let ext = a.extProcs[extBySlot.getOrDefault(slot)]
      let pos = r.position
      text.put32(pos + 2, 0)
      if ext.libOrdinal > 0:
        reloc(secText, pos + 2, w.undefSym("__imp_" & ext.extName), RelRel32)
      else:
        text[pos] = 0x67'u8                          # addr32 (a no-op prefix here)
        text[pos + 1] = 0xE8'u8                      # call rel32
        reloc(secText, pos + 2, w.undefSym(ext.extName), RelRel32)
  # The stub's `.tls$` and `_tls_start` addresses, whose difference it stores in
  # `winTlsDeltaSym` (a `gvarSites` entry above).
  let (tlsPos, startPos) = a.winTlsSites
  if tlsPos >= 0:
    text.put32(tlsPos + 3, 0)
    reloc(secText, tlsPos + 3, sectionSym(secTls), RelRel32)
    text.put32(startPos + 3, 0)
    reloc(secText, startPos + 3, w.undefSym(TlsStartName), RelRel32)
  # Symbol-address fields inside a rodata blob.
  for it in a.rodataSymInits:
    if labelPos.hasKey(it.labelId):
      if it.size != 8:
        quit "nifasm: --emit-obj: a " & $it.size & "-byte symbol address is not supported"
      var found = false
      let (s, off) = target(it.sym, found)
      if found:
        let at = labelPos.getOrDefault(it.labelId) + it.blobOff
        text.put64(at, off)
        reloc(secText, at, sectionSym(s), RelAddr64)

  # ── .tls$: one thread's initial block ──────────────────────────────────────
  if secTls >= 0:
    for it in a.tlsInits:
      for i in 0 ..< it.size:
        if it.off.int + i < w.secs[secTls].data.len:
          w.secs[secTls].data[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  # ── .xdata / .pdata ────────────────────────────────────────────────────────
  for (start, stop, ui) in fns:
    while w.secs[secXdata].data.len mod 4 != 0: w.secs[secXdata].data.add 0'u8
    let uiOff = w.secs[secXdata].data.len
    w.secs[secXdata].data.add ui
    for (v, s) in [(start, secText), (stop, secText), (uiOff, secXdata)]:
      reloc(secPdata, w.secs[secPdata].data.len, sectionSym(s), RelAddr32Nb)
      w.secs[secPdata].data.le32 uint32(v)

  # ── symbols ────────────────────────────────────────────────────────────────
  if a.winEntryOffset >= 0:
    discard w.addSym(ObjSym(name: "main", value: uint32(a.winEntryOffset),
                            section: secText + 1, typ: TypeFunction, class: ClassExternal))
  # Every proc as a local function symbol, so gdb and a profiler can name it.
  if a.debugInfo:
    for p in a.unwind:
      if p.stop > p.start:
        discard w.addSym(ObjSym(name: p.name, value: uint32(p.start),
                                section: secText + 1, typ: TypeFunction,
                                class: ClassStatic))

  # ── the file: header, section table, contents + relocations, symbols ───────
  const HeaderSize = 20
  const SectionHeaderSize = 40
  var f: seq[byte] = @[]
  var strtab: seq[byte] = @[0'u8, 0, 0, 0]           # the size, patched below
  var at = HeaderSize + SectionHeaderSize * w.secs.len
  var rawOff, relocOff: seq[int] = @[]
  for s in w.secs:
    at = (at + 3) and not 3
    rawOff.add(if s.data.len > 0: at else: 0)
    at += s.data.len
    at = (at + 3) and not 3
    relocOff.add(if s.relocs.len > 0: at else: 0)
    at += 10 * s.relocs.len
    if s.relocs.len > 0xFFFF:
      quit "nifasm: --emit-obj: section " & s.name & " has more than 65535 relocations"
  let symtabOff = at
  let nsyms = 2 * w.secs.len + w.syms.len

  f.le16 pe.IMAGE_FILE_MACHINE_AMD64
  f.le16 uint16(w.secs.len)
  f.le32 0                                           # TimeDateStamp: reproducible
  f.le32 uint32(symtabOff)
  f.le32 uint32(nsyms)
  f.le16 0                                           # no optional header
  f.le16 0                                           # Characteristics
  for i, s in w.secs:
    f.addName(strtab, s.name)
    f.le32 0                                         # VirtualSize
    f.le32 0                                         # VirtualAddress
    f.le32 uint32(s.data.len)
    f.le32 uint32(rawOff[i])
    f.le32 uint32(relocOff[i])
    f.le32 0                                         # PointerToLinenumbers
    f.le16 uint16(s.relocs.len)
    f.le16 0                                         # NumberOfLinenumbers
    f.le32 s.chars
  for i, s in w.secs:
    while f.len < rawOff[i]: f.add 0'u8
    f.add s.data
    if s.relocs.len > 0:
      while f.len < relocOff[i]: f.add 0'u8
      for r in s.relocs:
        f.le32 r.offset
        f.le32 uint32(r.sym)
        f.le16 r.typ
  while f.len < symtabOff: f.add 0'u8
  for i, s in w.secs:
    # The section symbol and its aux record (the section definition).
    f.addName(strtab, s.name)
    f.le32 0
    f.le16 uint16(i + 1)
    f.le16 0
    f.add ClassStatic
    f.add 1'u8
    f.le32 uint32(s.data.len)
    f.le16 uint16(s.relocs.len)
    f.le16 0                                         # NumberOfLinenumbers
    f.le32 0                                         # CheckSum
    f.le16 0                                         # Number (COMDAT only)
    f.add 0'u8                                       # Selection
    f.add [0'u8, 0, 0]
  for s in w.syms:
    f.addName(strtab, s.name)
    f.le32 s.value
    f.le16 uint16(s.section)
    f.le16 s.typ
    f.add s.class
    f.add 0'u8
  assert f.len == symtabOff + SymSize * nsyms
  strtab.put32(0, uint32(strtab.len))
  f.add strtab
  try:
    writeFile(outfile, f)
  except:
    quit "nifasm: cannot write " & outfile
