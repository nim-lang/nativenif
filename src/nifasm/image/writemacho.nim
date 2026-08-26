#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The Mach-O writer: a standalone `MH_EXECUTE` for arm64/macOS, and the
## relocatable `MH_OBJECT` (`--emit-obj`) that hands linking to the system
## linker when foreign `.o` files or frameworks are in play.
##
## Thread-locals and `dataConst` blobs are what make this more than a second
## ELF: a tvar goes through a TLV descriptor dyld resolves, and a pointer inside
## a writable const is a rebase opcode rather than a baked address.

import std / [tables, sets, algorithm]
import nifcore
import "../core" / [context, sem, relocs, listing]
import macho, writecommon

proc writeMachO*(a: var GenContext; outfile: string) =
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data

  # Determine CPU type based on architecture
  let (cputype, cpusubtype) = case a.arch
    of Arch.X64:
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)
    of Arch.A64, Arch.LinuxA64:
      (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    of Arch.WinX64, Arch.WinA64, Arch.CortexM:
      # Unreachable: Windows emits PE and Cortex-M emits a bare ELF32 firmware
      # image, so neither ever reaches the Mach-O writer. Covered so the case
      # stays exhaustive.
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)

  # Build dynlink info for external procs
  var dynlink: macho.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add macho.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add macho.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  var gsites: seq[(int, int)] = @[]   # resolve each global's final .bss offset now
  for (pos, sym) in a.gvarSites: gsites.add (pos, sym.size)

  # Thread-local storage (macOS TLV): one 24-byte descriptor per tvar, the
  # __thread_data init template, and the adrp+add sites referencing each
  # descriptor (carried by descriptor index).
  var tlv: macho.TlvInfo
  for sym in a.tlvSyms: tlv.descriptorOffsets.add sym.size
  tlv.threadData = a.tlvData
  for (pos, sym) in a.tlvSites: tlv.sites.add (pos, sym.offset)

  # Symbol-pointer fields of `dataConst` blobs (now in __DATA): resolve each to its
  # target's preferred vaddr and a dyld rebase. A target in __TEXT (a plain rodata
  # const or a proc) is located by its finalized label position; a target itself in
  # __DATA (another data const, or a gvar) by its `.bss`/__DATA offset.
  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
  var rebases: seq[macho.RodataRebase] = @[]
  for it in a.rodataRebases:
    let fieldOff = it.owner.size + it.blobOff
    case it.target.kind
    of skProc, skRodata:
      if it.target.kind == skRodata and it.target.dataConst:
        rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: true,
                                       targetOff: it.target.size)
      elif labelPos.hasKey(it.target.offset):
        rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: false,
                                       targetOff: labelPos[it.target.offset])
    of skGvar:
      rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: true,
                                     targetOff: it.target.size)
    else: discard

  # A GVAR whose initializer is a symbol ADDRESS (`(gvar :scheduler (proctype …)
  # trivialTick.0)` — a function-pointer hook, or a global pointing at another
  # global). Same treatment as the blob fields above: bake the target's preferred
  # vaddr and let dyld slide it. `writeElf` bakes these into its .bss image; this
  # path used to drop them, so on macOS every such global started as NULL and the
  # first call through it branched to 0.
  for it in a.bssSymInits:
    case it.sym.kind
    of skProc, skRodata:
      if it.sym.kind == skRodata and it.sym.dataConst:
        rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: true,
                                       targetOff: it.sym.size)
      elif labelPos.hasKey(it.sym.offset):
        rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: false,
                                       targetOff: labelPos[it.sym.offset])
    of skGvar:
      rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: true,
                                     targetOff: it.sym.size)
    else: discard

  # `--symmap`: dump every generated proc's virtual address (the Mach-O carries no
  # symbol table). Only `writeMachO` knows where __text lands, so hand it the rows.
  var symMapRows: seq[(int, string)] = @[]
  if a.symMap:
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc and labelPos.hasKey(sym.offset):
        symMapRows.add (labelPos[sym.offset], a.nameOf(name))
    symMapRows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
  if a.listing:
    # Only `writeMachO` knows where __text lands, so these rows stay __text-relative;
    # the header line says so.
    a.writeListing(a.listingPath, 0)

  # `LC_SYMTAB` + `__TEXT,__eh_frame` from the same per-proc facts the ELF path
  # encodes: proc names for lldb, and CFI so it can unwind a frame-pointer-less
  # stack. Both are debugger-only; `--no-debug-info` drops them.
  macho.writeMachO(code, a.bssOffset, cputype, cpusubtype, outfile, dynlink, gsites, tlv,
                   a.bssInits, rebases, symMapRows,
                   (if a.debugInfo: a.unwind else: @[]))

  # macOS arm64 requires code signing for all executables
  when defined(macosx):
    let codesignResult = execCmd("codesign -s - " & quoteShell(outfile))
    if codesignResult != 0:
      raise newException(OSError, "codesign failed with exit code " & $codesignResult)

proc machoName*(name: string): string =
  ## Mangle a nifasm symbol into a Mach-O symbol. macOS C ABI prefixes globals
  ## with `_`; nifasm's internal names (e.g. `foo.0.mod`) only need a stable,
  ## collision-free spelling, and `.` is valid in Mach-O symbol names.
  "_" & name

proc writeMachOObject*(a: var GenContext; outfile: string) =
  ## Emit a relocatable object instead of a standalone executable. Defined procs /
  ## globals become exported symbols, external `extproc` references become undefined
  ## symbols, and every fixup the executable path would resolve in-place (external
  ## calls, gvar `adrp`/`add`, symbol-address initializers) becomes a relocation the
  ## system linker resolves. The standalone `writeMachO` above is left untouched.
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data

  let (cputype, cpusubtype) = case a.arch
    of Arch.A64: (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    else:
      quit "nifasm: --emit-obj is only supported for macOS arm64"

  if a.tlvSyms.len > 0:
    quit "nifasm: --emit-obj does not yet support thread-local variables"

  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
  let dataRegionSize = a.bssOffset   # local copy: the nested procs below must not
                                     # capture the `var GenContext` param

  # --- symbol table: defined first, then undefined (Mach-O dysymtab ordering) ----
  var syms: seq[macho.MachOSym] = @[]
  var defIndex = initTable[string, int]()   # mangled name -> index in `syms`

  proc addDef(name: string; sec: macho.MachOSecKind; value: uint64): int =
    result = defIndex.getOrDefault(name, -1)
    if result < 0:
      result = syms.len
      defIndex[name] = result
      syms.add macho.MachOSym(name: name, sec: sec, value: value, defined: true)

  let mpool = a.pool   # capturable pool ref (the nested `defOf` cannot close over `a`)
  proc defOf(sym: Symbol): int =
    ## Ensure `sym` is in the table as a defined symbol; return its index (or -1 if
    ## it has no resolvable location, e.g. an un-emitted proc).
    case sym.kind
    of skProc:
      if labelPos.hasKey(sym.offset):
        addDef(machoName(poolSym(mpool, sym.name)), macho.moText, uint64(labelPos[sym.offset]))
      else: -1
    of skRodata:
      if sym.dataConst:
        (if sym.size < dataRegionSize: addDef(machoName(poolSym(mpool, sym.name)), macho.moData, uint64(sym.size)) else: -1)
      elif labelPos.hasKey(sym.offset):
        addDef(machoName(poolSym(mpool, sym.name)), macho.moText, uint64(labelPos[sym.offset]))
      else: -1
    of skGvar:
      # A data symbol must point inside the emitted `__data` region; a zero-size
      # region (`bssOffset == 0`) emits no `__data` section, so skip it then.
      if sym.size < dataRegionSize: addDef(machoName(poolSym(mpool, sym.name)), macho.moData, uint64(sym.size))
      else: -1
    else: -1

  # All generated procs (and data referenced below) become exported symbols. The
  # synthetic per-thread TLS block is an internal artifact (unused on arm64), never
  # a real exported global.
  for name in a.generatedSymbols:
    if name == "arkham.tls.0": continue
    let sym = a.rootScope.lookup(a.symIdOf(name))
    if sym != nil: discard defOf(sym)

  # An `_main` alias at the entry proc so the system crt can find it.
  if a.entrySym != nil and labelPos.hasKey(a.entrySym.offset):
    discard addDef("_main", macho.moText, uint64(labelPos[a.entrySym.offset]))

  # --- relocations ---------------------------------------------------------------
  # The reloc loops below also pull their *defined* targets into the table via
  # `defOf`. Mach-O requires every defined symbol to precede every undefined one,
  # so we gather all of these (and their relocs) BEFORE allocating any undef index.
  var textRels: seq[macho.MachORel] = @[]
  var dataRels: seq[macho.MachORel] = @[]

  # gvar references: the `adrp`/`add` pair → PAGE21 + PAGEOFF12 to the data symbol.
  for (pos, sym) in a.gvarSites:
    let si = defOf(sym)
    if si >= 0:
      textRels.add macho.MachORel(address: pos, symIdx: si, kind: macho.mrPage21)
      textRels.add macho.MachORel(address: pos + 4, symIdx: si, kind: macho.mrPageoff12)

  # Symbol-address pointer fields inside a rodata blob (in __text): 8-byte UNSIGNED.
  for (labelId, blobOff, sym, _) in a.rodataSymInits:
    let si = defOf(sym)
    if si >= 0 and labelPos.hasKey(labelId):
      textRels.add macho.MachORel(address: labelPos[labelId] + blobOff,
                                  symIdx: si, kind: macho.mrUnsigned)

  # Symbol-address initializers of globals (in __data): 8-byte UNSIGNED.
  for (off, sym, _) in a.bssSymInits:
    let si = defOf(sym)
    if si >= 0:
      dataRels.add macho.MachORel(address: int(off), symIdx: si, kind: macho.mrUnsigned)

  # `dataConst` symbol-pointer fields (in __data): 8-byte UNSIGNED to the target.
  for it in a.rodataRebases:
    let si = defOf(it.target)
    if si >= 0:
      dataRels.add macho.MachORel(address: it.owner.size + it.blobOff,
                                  symIdx: si, kind: macho.mrUnsigned)

  let nDefined = syms.len  # everything added so far is defined; undefs come next

  # Undefined symbols: one per external proc (deduplicated by external name).
  var undefIndex = initTable[string, int]()
  proc undefOf(extName: string): int =
    result = undefIndex.getOrDefault(extName, -1)
    if result < 0:
      result = syms.len
      undefIndex[extName] = result
      syms.add macho.MachOSym(name: extName, defined: false)

  # External calls: the BL placeholder at each call site → BRANCH26 to the undef sym.
  for ext in a.extProcs:
    let si = undefOf(ext.extName)
    for cs in ext.callSites:
      textRels.add macho.MachORel(address: cs, symIdx: si, kind: macho.mrBranch26)

  # --- __data image: the whole globals region, with constant initializers baked ---
  # (Symbol-address slots stay zero; their relocations above supply the address.)
  var dataImage: seq[byte] = @[]
  if a.bssOffset > 0:
    dataImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  macho.writeMachOObject(code, dataImage, syms, nDefined, textRels, dataRels,
                         cputype, cpusubtype, outfile)
