# Mach-O binary format writer for macOS

import std / [streams, os]

import buffers

type
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

proc writeMachO*(code: Bytes; bssSize: int; entryAddr: uint64;
                 cputype, cpusubtype: uint32; outfile: string) =
  let pageSize = 0x4000.uint64  # 16KB page size for arm64 macOS
  let baseAddr = 0x100000000.uint64  # macOS default base address

  # Calculate sizes
  let headerSize = sizeof(MachO_Header).uint64
  let codeSize = code.len.uint64

  # Calculate load command sizes first (needed to determine code offset)
  let pageZeroSegSize = sizeof(MachO_Segment64)  # No sections in __PAGEZERO
  let textSegSize = sizeof(MachO_Segment64) + sizeof(MachO_Section64)
  let dataSegSize = if bssSize > 0: sizeof(MachO_Segment64) + sizeof(MachO_Section64) else: 0
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

  var hasData = bssSize > 0
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

  # DATA segment: bss (zero-initialized)
  let dataVmaddr = textVmaddr + textSegmentFileSize
  let dataSize = if bssSize > 0: ((bssSize.uint64 + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  # __LINKEDIT segment comes after TEXT (and DATA if present)
  let linkeditVmaddr = if hasData: dataVmaddr + dataSize else: textVmaddr + textSegmentFileSize
  let linkeditFileoff = textSegmentFileSize
  # Minimal __LINKEDIT content: just empty space for code signature (will be filled by codesign)
  let linkeditFilesize = 32'u64  # Minimal size for symbol table data
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

  # Create DATA segment with __bss section (if needed)
  var dataSegment: MachO_Segment64
  var dataSection: MachO_Section64

  if hasData:
    dataSegment = initSegment64("__DATA", dataVmaddr, dataSize, 0, 0,
                                 VM_PROT_READ or VM_PROT_WRITE,
                                 VM_PROT_READ or VM_PROT_WRITE, 1)

    dataSection = initSection64("__bss", "__DATA", dataVmaddr, dataSize.uint64,
                                0, 4, 0)

  # Create __LINKEDIT segment
  var linkeditSegment = initSegment64("__LINKEDIT", linkeditVmaddr, linkeditVmsize,
                                       linkeditFileoff, linkeditFilesize,
                                       VM_PROT_READ, VM_PROT_READ, 0)

  # Create LC_DYLD_INFO_ONLY (minimal, no bindings needed for syscall-only code)
  var dyldInfo: MachO_DyldInfo
  dyldInfo.cmd = LC_DYLD_INFO_ONLY
  dyldInfo.cmdsize = uint32(sizeof(MachO_DyldInfo))
  # All offsets/sizes are 0 - no rebase, bind, weak_bind, lazy_bind, or exports
  dyldInfo.rebase_off = 0
  dyldInfo.rebase_size = 0
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
  symtab.symoff = uint32(linkeditFileoff)
  symtab.nsyms = 0
  symtab.stroff = uint32(linkeditFileoff)
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

  # Write code
  if code.len > 0:
    f.writeData(code.rawData, code.len)
    # Pad to page boundary
    let totalWritten = codeFileOffset + codeSize
    let paddingToPage = int(textSegmentFileSize - totalWritten)
    if paddingToPage > 0:
      var zeros = newSeq[byte](paddingToPage)
      f.writeData(unsafeAddr zeros[0], paddingToPage)

  # Write __LINKEDIT content (minimal: just a null byte for string table)
  var linkeditData = newSeq[byte](linkeditFilesize.int)
  linkeditData[0] = 0  # Null terminator for empty string table
  f.writeData(unsafeAddr linkeditData[0], linkeditData.len)

  # BSS is not written to file (zero-initialized by loader)

  f.close()

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

