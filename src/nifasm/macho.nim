# Mach-O binary format writer for macOS

import std / [streams, os]

import buffers

type
  # Import info for dynamic linking
  ImportedLibInfo* = object
    name*: string
    ordinal*: int

  ExternalProcInfo* = object
    name*: string         # Internal name
    extName*: string      # External symbol name (e.g. "_write")
    libOrdinal*: int      # Which library (1-based)
    gotSlot*: int         # GOT slot index
    callSites*: seq[int]  # Positions of BL instructions that call this proc

  DynLinkInfo* = object
    libs*: seq[ImportedLibInfo]
    extProcs*: seq[ExternalProcInfo]

  MachO_Header* = object
    magic*: uint32
    cputype*: uint32
    cpusubtype*: uint32
    filetype*: uint32
    ncmds*: uint32
    sizeofcmds*: uint32
    flags*: uint32
    reserved*: uint32

  MachO_LoadCommand* = object
    cmd*: uint32
    cmdsize*: uint32

  MachO_Segment64* = object
    cmd*: uint32          # LC_SEGMENT_64
    cmdsize*: uint32
    segname*: array[16, char]
    vmaddr*: uint64
    vmsize*: uint64
    fileoff*: uint64
    filesz*: uint64
    maxprot*: uint32
    initprot*: uint32
    nsects*: uint32
    flags*: uint32

  MachO_Section64* = object
    sectname*: array[16, char]
    segname*: array[16, char]
    address*: uint64
    size*: uint64
    offset*: uint32
    align*: uint32
    reloff*: uint32
    nreloc*: uint32
    flags*: uint32
    reserved1*: uint32
    reserved2*: uint32
    reserved3*: uint32

  MachO_EntryPoint* = object
    cmd*: uint32          # LC_MAIN
    cmdsize*: uint32
    entryoff*: uint64
    stacksize*: uint64

  MachO_Symtab* = object
    cmd*: uint32          # LC_SYMTAB
    cmdsize*: uint32
    symoff*: uint32
    nsyms*: uint32
    stroff*: uint32
    strsize*: uint32

  MachO_CodeSignature* = object
    cmd*: uint32          # LC_CODE_SIGNATURE
    cmdsize*: uint32
    dataoff*: uint32
    datasize*: uint32

  MachO_DyLinker* = object
    cmd*: uint32          # LC_LOAD_DYLINKER
    cmdsize*: uint32
    name_offset*: uint32  # Offset to name string from start of load command

  MachO_DyLib* = object
    cmd*: uint32          # LC_LOAD_DYLIB
    cmdsize*: uint32
    name_offset*: uint32  # Offset to name string
    timestamp*: uint32
    current_version*: uint32
    compatibility_version*: uint32

  MachO_DyldInfo* = object
    cmd*: uint32          # LC_DYLD_INFO_ONLY
    cmdsize*: uint32
    rebase_off*: uint32
    rebase_size*: uint32
    bind_off*: uint32
    bind_size*: uint32
    weak_bind_off*: uint32
    weak_bind_size*: uint32
    lazy_bind_off*: uint32
    lazy_bind_size*: uint32
    export_off*: uint32
    export_size*: uint32

  MachO_DySymtab* = object
    cmd*: uint32          # LC_DYSYMTAB
    cmdsize*: uint32
    ilocalsym*: uint32
    nlocalsym*: uint32
    iextdefsym*: uint32
    nextdefsym*: uint32
    iundefsym*: uint32
    nundefsym*: uint32
    tocoff*: uint32
    ntoc*: uint32
    modtaboff*: uint32
    nmodtab*: uint32
    extrefsymoff*: uint32
    nextrefsyms*: uint32
    indirectsymoff*: uint32
    nindirectsyms*: uint32
    extreloff*: uint32
    nextrel*: uint32
    locreloff*: uint32
    nlocrel*: uint32

const
  DyldPath* = "/usr/lib/dyld"
  LibSystemPath* = "/usr/lib/libSystem.B.dylib"
  MH_MAGIC_64* = 0xFEEDFACF'u32
  MH_CIGAM_64* = 0xCFFAEDFE'u32  # Byte-swapped

  CPU_TYPE_ARM64* = 0x0100000C'u32
  CPU_TYPE_X86_64* = 0x01000007'u32

  CPU_SUBTYPE_ARM64_ALL* = 0x00000000'u32
  CPU_SUBTYPE_X86_64_ALL* = 0x00000003'u32

  MH_EXECUTE* = 0x2'u32
  MH_OBJECT* = 0x1'u32
  MH_NOUNDEFS* = 0x1'u32  # No undefined references
  MH_DYLDLINK* = 0x4'u32  # Dynamically linked
  MH_PIE* = 0x200000'u32  # Position-independent executable

  LC_SEGMENT_64* = 0x19'u32
  LC_MAIN* = 0x80000028'u32
  LC_UNIXTHREAD* = 0x05'u32
  LC_SYMTAB* = 0x02'u32
  LC_DYSYMTAB* = 0x0B'u32
  LC_CODE_SIGNATURE* = 0x1D'u32
  LC_LOAD_DYLINKER* = 0x0E'u32
  LC_LOAD_DYLIB* = 0x0C'u32
  LC_UUID* = 0x1B'u32
  LC_DYLD_INFO_ONLY* = 0x80000022'u32

  VM_PROT_READ* = 0x1'u32
  VM_PROT_WRITE* = 0x2'u32
  VM_PROT_EXECUTE* = 0x4'u32

  # Section flags
  S_ATTR_PURE_INSTRUCTIONS* = 0x80000000'u32
  S_ATTR_SOME_INSTRUCTIONS* = 0x00000400'u32

  # Section types for GOT
  S_NON_LAZY_SYMBOL_POINTERS* = 0x06'u32
  S_LAZY_SYMBOL_POINTERS* = 0x07'u32

  # Bind opcodes for LC_DYLD_INFO_ONLY
  BIND_OPCODE_DONE* = 0x00'u8
  BIND_OPCODE_SET_DYLIB_ORDINAL_IMM* = 0x10'u8
  BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM* = 0x40'u8
  BIND_OPCODE_SET_TYPE_IMM* = 0x50'u8
  BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB* = 0x72'u8
  BIND_OPCODE_DO_BIND* = 0x90'u8
  BIND_TYPE_POINTER* = 1'u8

proc initMachOHeader*(cputype, cpusubtype: uint32; ncmds, sizeofcmds: uint32; flags: uint32 = 0): MachO_Header =
  result.magic = MH_MAGIC_64
  result.cputype = cputype
  result.cpusubtype = cpusubtype
  result.filetype = MH_EXECUTE
  result.ncmds = ncmds
  result.sizeofcmds = sizeofcmds
  result.flags = flags
  result.reserved = 0

proc initSegment64*(segname: string; vmaddr, vmsize, fileoff, filesz: uint64;
                    maxprot, initprot: uint32; nsects: uint32): MachO_Segment64 =
  result.cmd = LC_SEGMENT_64
  result.cmdsize = uint32(sizeof(MachO_Segment64) + nsects.int * sizeof(MachO_Section64))
  result.segname = default(typeof(result.segname))
  for i, c in segname:
    if i < 16:
      result.segname[i] = c
  result.vmaddr = vmaddr
  result.vmsize = vmsize
  result.fileoff = fileoff
  result.filesz = filesz
  result.maxprot = maxprot
  result.initprot = initprot
  result.nsects = nsects
  result.flags = 0

proc initSection64*(sectname, segname: string; address, size: uint64;
                    offset: uint32; align: uint32; flags: uint32): MachO_Section64 =
  result.sectname = default(typeof(result.sectname))
  for i, c in sectname:
    if i < 16:
      result.sectname[i] = c
  result.segname = default(typeof(result.segname))
  for i, c in segname:
    if i < 16:
      result.segname[i] = c
  result.address = address
  result.size = size
  result.offset = offset
  result.align = align
  result.reloff = 0
  result.nreloc = 0
  result.flags = flags
  result.reserved1 = 0
  result.reserved2 = 0
  result.reserved3 = 0

proc initEntryPoint*(entryoff: uint64): MachO_EntryPoint =
  result.cmd = LC_MAIN
  result.cmdsize = uint32(sizeof(MachO_EntryPoint))
  result.entryoff = entryoff
  result.stacksize = 0

proc encodeReg(r: uint32): uint32 {.inline.} = r and 0x1F

proc generateBindInfo(extProcs: seq[ExternalProcInfo]; gotVmaddr: uint64; dataSegmentIndex: int): seq[byte] =
  ## Generate bind opcodes for external procs
  result = @[]
  var currentOffset = 0'u64
  for ext in extProcs:
    # BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (ordinal in low 4 bits)
    result.add(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM or uint8(ext.libOrdinal and 0xF))
    # BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (flags = 0)
    result.add(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM)
    # Symbol name (null terminated)
    for c in ext.extName:
      result.add(byte(c))
    result.add(0)
    # BIND_OPCODE_SET_TYPE_IMM (BIND_TYPE_POINTER = 1)
    result.add(BIND_OPCODE_SET_TYPE_IMM or BIND_TYPE_POINTER)
    # BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
    let gotOffset = uint64(ext.gotSlot * 8)
    result.add(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB or uint8(dataSegmentIndex))
    # ULEB128 encode the offset
    var offset = gotOffset
    while offset >= 0x80:
      result.add(byte((offset and 0x7F) or 0x80))
      offset = offset shr 7
    result.add(byte(offset and 0x7F))
    # BIND_OPCODE_DO_BIND
    result.add(BIND_OPCODE_DO_BIND)
  # BIND_OPCODE_DONE
  result.add(BIND_OPCODE_DONE)

proc writeMachO*(code: Bytes; bssSize: int;
                 cputype, cpusubtype: uint32; outfile: string;
                 dynlink: DynLinkInfo = DynLinkInfo()) =
  let pageSize = 0x4000.uint64  # 16KB page size for arm64 macOS
  let baseAddr = 0x100000000.uint64  # macOS default base address

  # Handle external procs - generate stubs and patch BL instructions
  var modifiedCode = code
  let hasExtProcs = dynlink.extProcs.len > 0
  let stubsOffset = code.len  # Stubs go after original code
  let stubSize = 12  # ADRP + LDR + BR = 3 * 4 bytes
  let gotSize = if hasExtProcs: dynlink.extProcs.len * 8 else: 0

  if hasExtProcs:
    # Reserve space for stubs (will be filled after we know GOT address)
    for i in 0..<dynlink.extProcs.len:
      # Placeholder stubs
      for j in 0..<stubSize:
        modifiedCode.add(0)

  # Calculate sizes
  let headerSize = sizeof(MachO_Header).uint64
  let codeSize = modifiedCode.len.uint64

  # Calculate load command sizes first (needed to determine code offset)
  let pageZeroSegSize = sizeof(MachO_Segment64)  # No sections in __PAGEZERO
  let textSegSize = sizeof(MachO_Segment64) + sizeof(MachO_Section64)
  # DATA segment is needed if we have bss OR external procs (for GOT)
  let needsData = bssSize > 0 or hasExtProcs
  let dataSegSize = if needsData: sizeof(MachO_Segment64) + sizeof(MachO_Section64) else: 0
  let linkeditSegSize = sizeof(MachO_Segment64)  # No sections in __LINKEDIT
  # LC_LOAD_DYLINKER: 12 bytes header + path string + padding to 8-byte boundary
  let dylinkerPathLen = DyldPath.len + 1  # +1 for null terminator
  let dylinkerSize = ((sizeof(MachO_DyLinker) + dylinkerPathLen + 7) and not 7)
  # LC_LOAD_DYLIB: 24 bytes header + path string + padding to 8-byte boundary
  let dylibPathLen = LibSystemPath.len + 1
  let dylibSize = ((sizeof(MachO_DyLib) + dylibPathLen + 7) and not 7)
  let dyldInfoSize = sizeof(MachO_DyldInfo)
  let symtabSize = sizeof(MachO_Symtab)
  let dysymtabSize = sizeof(MachO_DySymtab)
  let codeSignatureSize = sizeof(MachO_CodeSignature)  # Placeholder for codesign
  let entrySize = sizeof(MachO_EntryPoint)

  var hasData = needsData  # GOT goes in __DATA segment
  # PAGEZERO + TEXT + (DATA) + LINKEDIT + DYLD_INFO + SYMTAB + DYSYMTAB + DYLINKER + DYLIB + MAIN
  # = 9 commands without DATA, 10 with DATA
  let ncmds = if hasData: 10'u32 else: 9'u32
  let actualCmdsSize = pageZeroSegSize + textSegSize + dataSegSize + linkeditSegSize +
                       dyldInfoSize + symtabSize + dysymtabSize + dylinkerSize + dylibSize + entrySize
  # Reserve extra space for CODE_SIGNATURE that codesign will add
  let totalCmdsSpaceNeeded = actualCmdsSize + codeSignatureSize

  # Code starts after header and reserved command space, aligned to 16 bytes
  let codeFileOffset = (headerSize + totalCmdsSpaceNeeded.uint64 + 15) and not 15'u64

  # __TEXT segment starts at file offset 0 (includes header in segment)
  # The segment size includes header + commands + code, page-aligned
  let textSegmentFileSize = (codeFileOffset + codeSize + pageSize - 1) and not (pageSize - 1)

  # Virtual addresses
  let textVmaddr = baseAddr
  let textSectionVmaddr = textVmaddr + codeFileOffset  # Section starts after headers

  # DATA segment: GOT + bss (zero-initialized)
  let dataVmaddr = textVmaddr + textSegmentFileSize
  let gotVmaddr = dataVmaddr  # GOT at start of __DATA
  let totalDataSize = gotSize + bssSize
  let dataSize = if totalDataSize > 0: ((totalDataSize.uint64 + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  # __LINKEDIT segment comes after TEXT (and DATA if present)
  let linkeditVmaddr = if hasData: dataVmaddr + dataSize else: textVmaddr + textSegmentFileSize
  let linkeditFileoff = textSegmentFileSize

  # Generate bind info if we have external procs
  let bindInfo = if hasExtProcs:
    generateBindInfo(dynlink.extProcs, gotVmaddr.uint64, 2)  # segment index 2 = __DATA
  else:
    @[]

  # Linkedit contains: bind info + string table (1 byte null terminator)
  let linkeditFilesize = (if bindInfo.len > 0: uint64(bindInfo.len) + 8 else: 32.uint64)
  let linkeditVmsize = (linkeditFilesize + pageSize - 1) and not (pageSize - 1)

  # Create __PAGEZERO segment (reserves low memory, no file content)
  var pageZeroSegment = initSegment64("__PAGEZERO", 0, baseAddr, 0, 0,
                                       0, 0, 0)

  # Create TEXT segment with __text section
  # fileoff=0 means segment starts at beginning of file (includes header)
  var textSegment = initSegment64("__TEXT", textVmaddr, textSegmentFileSize, 0, textSegmentFileSize,
                                   VM_PROT_READ or VM_PROT_EXECUTE,
                                   VM_PROT_READ or VM_PROT_EXECUTE, 1)

  # Section flags: S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
  let textSectionFlags = S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS
  var textSection = initSection64("__text", "__TEXT", textSectionVmaddr, codeSize,
                                  uint32(codeFileOffset), 2, textSectionFlags)  # align 2^2 = 4

  # Create DATA segment with __got section (if we have external procs) or __bss (if only bss)
  var dataSegment: MachO_Segment64
  var dataSection: MachO_Section64

  if hasData:
    dataSegment = initSegment64("__DATA", dataVmaddr, dataSize, 0, 0,
                                 VM_PROT_READ or VM_PROT_WRITE,
                                 VM_PROT_READ or VM_PROT_WRITE, 1)

    if hasExtProcs:
      # __got section for non-lazy symbol pointers
      dataSection = initSection64("__got", "__DATA", dataVmaddr, uint64(gotSize),
                                  0, 3, S_NON_LAZY_SYMBOL_POINTERS)  # align 2^3 = 8
    else:
      # __bss section for zero-initialized data
      dataSection = initSection64("__bss", "__DATA", dataVmaddr, dataSize.uint64,
                                  0, 4, 0)

  # Create __LINKEDIT segment
  var linkeditSegment = initSegment64("__LINKEDIT", linkeditVmaddr, linkeditVmsize,
                                       linkeditFileoff, linkeditFilesize,
                                       VM_PROT_READ, VM_PROT_READ, 0)

  # Create LC_DYLD_INFO_ONLY
  var dyldInfo: MachO_DyldInfo
  dyldInfo.cmd = LC_DYLD_INFO_ONLY
  dyldInfo.cmdsize = uint32(sizeof(MachO_DyldInfo))
  dyldInfo.rebase_off = 0
  dyldInfo.rebase_size = 0
  if hasExtProcs:
    dyldInfo.bind_off = uint32(linkeditFileoff)
    dyldInfo.bind_size = uint32(bindInfo.len)
  else:
    dyldInfo.bind_off = 0
    dyldInfo.bind_size = 0
  dyldInfo.weak_bind_off = 0
  dyldInfo.weak_bind_size = 0
  dyldInfo.lazy_bind_off = 0
  dyldInfo.lazy_bind_size = 0
  dyldInfo.export_off = 0
  dyldInfo.export_size = 0

  # Create LC_SYMTAB (minimal, empty symbol table)
  var symtab: MachO_Symtab
  symtab.cmd = LC_SYMTAB
  symtab.cmdsize = uint32(sizeof(MachO_Symtab))
  let symtabOffset = linkeditFileoff + uint64(bindInfo.len)
  symtab.symoff = uint32(symtabOffset)
  symtab.nsyms = 0
  symtab.stroff = uint32(symtabOffset)
  symtab.strsize = 1  # At least 1 byte for null terminator

  # Create LC_DYSYMTAB (dynamic symbol table, minimal)
  var dysymtab: MachO_DySymtab
  dysymtab.cmd = LC_DYSYMTAB
  dysymtab.cmdsize = uint32(sizeof(MachO_DySymtab))
  # All fields 0 - no dynamic symbols

  # Create LC_LOAD_DYLINKER
  var dylinker: MachO_DyLinker
  dylinker.cmd = LC_LOAD_DYLINKER
  dylinker.cmdsize = uint32(dylinkerSize)
  dylinker.name_offset = uint32(sizeof(MachO_DyLinker))  # Name follows immediately

  # Create LC_LOAD_DYLIB for libSystem.B.dylib
  var dylib: MachO_DyLib
  dylib.cmd = LC_LOAD_DYLIB
  dylib.cmdsize = uint32(dylibSize)
  dylib.name_offset = uint32(sizeof(MachO_DyLib))  # Name follows immediately
  dylib.timestamp = 2  # Standard timestamp
  dylib.current_version = 0x050C6405'u32  # 1292.100.5 - standard libSystem version
  dylib.compatibility_version = 0x00010000'u32  # 1.0.0

  # Note: codesign will add LC_CODE_SIGNATURE - we reserve space for it in totalCmdsSize

  # Entry point command - file offset to the entry point
  let entryOff = codeFileOffset  # Entry point is at the start of __text section
  var entryPoint = initEntryPoint(entryOff)

  # Create header with MH_DYLDLINK and MH_PIE flags
  var header = initMachOHeader(cputype, cpusubtype, ncmds, uint32(actualCmdsSize),
                                MH_DYLDLINK or MH_NOUNDEFS or MH_PIE)

  var f = newFileStream(outfile, fmWrite)

  # Write header
  f.write(header)

  # Write __PAGEZERO segment command
  f.write(pageZeroSegment)

  # Write TEXT segment command
  f.write(textSegment)
  f.write(textSection)

  # Write DATA segment command (if needed)
  if hasData:
    f.write(dataSegment)
    f.write(dataSection)

  # Write __LINKEDIT segment command
  f.write(linkeditSegment)

  # Write LC_DYLD_INFO_ONLY command
  f.write(dyldInfo)

  # Write LC_SYMTAB command
  f.write(symtab)

  # Write LC_DYSYMTAB command
  f.write(dysymtab)

  # Write LC_LOAD_DYLINKER command
  f.write(dylinker)
  # Write dyld path with null terminator and padding
  var dylinkerPadding = newSeq[byte](dylinkerSize - sizeof(MachO_DyLinker))
  for i, c in DyldPath:
    dylinkerPadding[i] = byte(c)
  dylinkerPadding[DyldPath.len] = 0  # Null terminator
  f.writeData(unsafeAddr dylinkerPadding[0], dylinkerPadding.len)

  # Write LC_LOAD_DYLIB command for libSystem
  f.write(dylib)
  # Write libSystem path with null terminator and padding
  var dylibPadding = newSeq[byte](dylibSize - sizeof(MachO_DyLib))
  for i, c in LibSystemPath:
    dylibPadding[i] = byte(c)
  dylibPadding[LibSystemPath.len] = 0  # Null terminator
  f.writeData(unsafeAddr dylibPadding[0], dylibPadding.len)

  # Note: codesign will add LC_CODE_SIGNATURE here (we left space)

  # Write entry point command
  f.write(entryPoint)

  # Pad to code offset (includes reserved space for LC_CODE_SIGNATURE that codesign will add)
  let currentPos = headerSize + actualCmdsSize.uint64
  let paddingToCode = int(codeFileOffset - currentPos)
  if paddingToCode > 0:
    var zeros = newSeq[byte](paddingToCode)
    f.writeData(unsafeAddr zeros[0], paddingToCode)

  # Generate stubs and patch BL instructions if we have external procs
  if hasExtProcs:
    let stubsVmaddr = textSectionVmaddr + uint64(stubsOffset)
    for i, ext in dynlink.extProcs:
      let stubVmaddr = stubsVmaddr + uint64(i * stubSize)
      let gotEntryVmaddr = gotVmaddr + uint64(ext.gotSlot * 8)
      let stubFileOffset = stubsOffset + i * stubSize

      # Calculate page-relative offsets for ADRP + LDR
      let stubPage = stubVmaddr and not 0xFFF'u64
      let gotPage = gotEntryVmaddr and not 0xFFF'u64
      let pageDiff = int64(gotPage) - int64(stubPage)
      let pageOff = gotEntryVmaddr and 0xFFF'u64

      # ADRP x16, got_entry@PAGE
      let adrpImm = pageDiff shr 12
      let immlo = uint32((adrpImm and 0x03)) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      let adrpInstr = 0x90000010'u32 or immlo or immhi  # ADRP x16, ...
      modifiedCode[stubFileOffset + 0] = byte(adrpInstr and 0xFF)
      modifiedCode[stubFileOffset + 1] = byte((adrpInstr shr 8) and 0xFF)
      modifiedCode[stubFileOffset + 2] = byte((adrpInstr shr 16) and 0xFF)
      modifiedCode[stubFileOffset + 3] = byte((adrpInstr shr 24) and 0xFF)

      # LDR x16, [x16, got_entry@PAGEOFF]
      let ldrOffset = pageOff shr 3  # Scale by 8 for 64-bit load
      let ldrInstr = 0xF9400210'u32 or (uint32(ldrOffset) shl 10)  # LDR x16, [x16, #offset]
      modifiedCode[stubFileOffset + 4] = byte(ldrInstr and 0xFF)
      modifiedCode[stubFileOffset + 5] = byte((ldrInstr shr 8) and 0xFF)
      modifiedCode[stubFileOffset + 6] = byte((ldrInstr shr 16) and 0xFF)
      modifiedCode[stubFileOffset + 7] = byte((ldrInstr shr 24) and 0xFF)

      # BR x16
      let brInstr = 0xD61F0200'u32  # BR x16
      modifiedCode[stubFileOffset + 8] = byte(brInstr and 0xFF)
      modifiedCode[stubFileOffset + 9] = byte((brInstr shr 8) and 0xFF)
      modifiedCode[stubFileOffset + 10] = byte((brInstr shr 16) and 0xFF)
      modifiedCode[stubFileOffset + 11] = byte((brInstr shr 24) and 0xFF)

      # Patch all BL call sites to point to this stub
      for callSite in ext.callSites:
        let blVmaddr = textSectionVmaddr + uint64(callSite)
        let offset = int64(stubVmaddr) - int64(blVmaddr)
        let imm26 = (offset shr 2) and 0x03FFFFFF
        let blInstr = 0x94000000'u32 or uint32(imm26)
        modifiedCode[callSite + 0] = byte(blInstr and 0xFF)
        modifiedCode[callSite + 1] = byte((blInstr shr 8) and 0xFF)
        modifiedCode[callSite + 2] = byte((blInstr shr 16) and 0xFF)
        modifiedCode[callSite + 3] = byte((blInstr shr 24) and 0xFF)

  # Write code (including stubs if any)
  if modifiedCode.len > 0:
    f.writeData(modifiedCode.rawData, modifiedCode.len)
    # Pad to page boundary
    let totalWritten = codeFileOffset + codeSize
    let paddingToPage = int(textSegmentFileSize - totalWritten)
    if paddingToPage > 0:
      var zeros = newSeq[byte](paddingToPage)
      f.writeData(unsafeAddr zeros[0], paddingToPage)

  # Write __LINKEDIT content
  var linkeditData = newSeq[byte](linkeditFilesize.int)
  if hasExtProcs and bindInfo.len > 0:
    # Copy bind info
    for i, b in bindInfo:
      linkeditData[i] = b
  # Add null terminator for empty string table at the end
  linkeditData[^1] = 0
  f.writeData(unsafeAddr linkeditData[0], linkeditData.len)

  # BSS is not written to file (zero-initialized by loader)

  f.close()

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

