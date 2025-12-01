# PE (Portable Executable) binary format writer for Windows

import std / [streams]

when not defined(windows):
  import std / os

import buffers, relocs

type
  # Import info for dynamic linking (same as macho.nim)
  ImportedLibInfo* = object
    name*: string
    ordinal*: int

  ExternalProcInfo* = object
    name*: string         # Internal name
    extName*: string      # External symbol name (e.g. "ExitProcess")
    libOrdinal*: int      # Which library (1-based)
    gotSlot*: int         # IAT slot index
    callSites*: seq[int]  # Positions of CALL instructions

  DynLinkInfo* = object
    libs*: seq[ImportedLibInfo]
    extProcs*: seq[ExternalProcInfo]

  # DOS Header (64 bytes)
  IMAGE_DOS_HEADER* = object
    e_magic*: uint16      # Magic number ("MZ")
    e_cblp*: uint16       # Bytes on last page of file
    e_cp*: uint16         # Pages in file
    e_crlc*: uint16       # Relocations
    e_cparhdr*: uint16    # Size of header in paragraphs
    e_minalloc*: uint16   # Minimum extra paragraphs needed
    e_maxalloc*: uint16   # Maximum extra paragraphs needed
    e_ss*: uint16         # Initial (relative) SS value
    e_sp*: uint16         # Initial SP value
    e_csum*: uint16       # Checksum
    e_ip*: uint16         # Initial IP value
    e_cs*: uint16         # Initial (relative) CS value
    e_lfarlc*: uint16     # File address of relocation table
    e_ovno*: uint16       # Overlay number
    e_res*: array[4, uint16]   # Reserved words
    e_oemid*: uint16      # OEM identifier
    e_oeminfo*: uint16    # OEM information
    e_res2*: array[10, uint16] # Reserved words
    e_lfanew*: uint32     # File address of PE header

  # COFF File Header (20 bytes)
  IMAGE_FILE_HEADER* = object
    Machine*: uint16
    NumberOfSections*: uint16
    TimeDateStamp*: uint32
    PointerToSymbolTable*: uint32
    NumberOfSymbols*: uint32
    SizeOfOptionalHeader*: uint16
    Characteristics*: uint16

  # Data Directory entry (8 bytes)
  IMAGE_DATA_DIRECTORY* = object
    VirtualAddress*: uint32
    Size*: uint32

  # Optional Header for PE32+ (64-bit) - 112 bytes + data directories
  IMAGE_OPTIONAL_HEADER64* = object
    Magic*: uint16
    MajorLinkerVersion*: uint8
    MinorLinkerVersion*: uint8
    SizeOfCode*: uint32
    SizeOfInitializedData*: uint32
    SizeOfUninitializedData*: uint32
    AddressOfEntryPoint*: uint32
    BaseOfCode*: uint32
    ImageBase*: uint64
    SectionAlignment*: uint32
    FileAlignment*: uint32
    MajorOperatingSystemVersion*: uint16
    MinorOperatingSystemVersion*: uint16
    MajorImageVersion*: uint16
    MinorImageVersion*: uint16
    MajorSubsystemVersion*: uint16
    MinorSubsystemVersion*: uint16
    Win32VersionValue*: uint32
    SizeOfImage*: uint32
    SizeOfHeaders*: uint32
    CheckSum*: uint32
    Subsystem*: uint16
    DllCharacteristics*: uint16
    SizeOfStackReserve*: uint64
    SizeOfStackCommit*: uint64
    SizeOfHeapReserve*: uint64
    SizeOfHeapCommit*: uint64
    LoaderFlags*: uint32
    NumberOfRvaAndSizes*: uint32
    DataDirectory*: array[16, IMAGE_DATA_DIRECTORY]

  # Section Header (40 bytes)
  IMAGE_SECTION_HEADER* = object
    Name*: array[8, byte]
    VirtualSize*: uint32
    VirtualAddress*: uint32
    SizeOfRawData*: uint32
    PointerToRawData*: uint32
    PointerToRelocations*: uint32
    PointerToLinenumbers*: uint32
    NumberOfRelocations*: uint16
    NumberOfLinenumbers*: uint16
    Characteristics*: uint32

  # Import Directory Entry (20 bytes)
  IMAGE_IMPORT_DESCRIPTOR* = object
    OriginalFirstThunk*: uint32  # RVA to ILT (Import Lookup Table)
    TimeDateStamp*: uint32
    ForwarderChain*: uint32
    Name*: uint32                # RVA to DLL name
    FirstThunk*: uint32          # RVA to IAT (Import Address Table)

const
  # DOS Header magic
  IMAGE_DOS_SIGNATURE* = 0x5A4D'u16  # "MZ"

  # PE Signature
  IMAGE_NT_SIGNATURE* = 0x00004550'u32  # "PE\0\0"

  # Machine types
  IMAGE_FILE_MACHINE_AMD64* = 0x8664'u16
  IMAGE_FILE_MACHINE_ARM64* = 0xAA64'u16

  # File characteristics
  IMAGE_FILE_EXECUTABLE_IMAGE* = 0x0002'u16
  IMAGE_FILE_LARGE_ADDRESS_AWARE* = 0x0020'u16

  # Optional header magic
  IMAGE_NT_OPTIONAL_HDR64_MAGIC* = 0x20B'u16  # PE32+

  # Subsystem
  IMAGE_SUBSYSTEM_WINDOWS_CUI* = 3'u16  # Console application
  IMAGE_SUBSYSTEM_WINDOWS_GUI* = 2'u16  # GUI application

  # DLL characteristics
  IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA* = 0x0020'u16
  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE* = 0x0040'u16
  IMAGE_DLLCHARACTERISTICS_NX_COMPAT* = 0x0100'u16
  IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE* = 0x8000'u16

  # Section characteristics
  IMAGE_SCN_CNT_CODE* = 0x00000020'u32
  IMAGE_SCN_CNT_INITIALIZED_DATA* = 0x00000040'u32
  IMAGE_SCN_CNT_UNINITIALIZED_DATA* = 0x00000080'u32
  IMAGE_SCN_MEM_DISCARDABLE* = 0x02000000'u32
  IMAGE_SCN_MEM_EXECUTE* = 0x20000000'u32
  IMAGE_SCN_MEM_READ* = 0x40000000'u32
  IMAGE_SCN_MEM_WRITE* = 0x80000000'u32

  # Data directory indices
  IMAGE_DIRECTORY_ENTRY_EXPORT* = 0
  IMAGE_DIRECTORY_ENTRY_IMPORT* = 1
  IMAGE_DIRECTORY_ENTRY_RESOURCE* = 2
  IMAGE_DIRECTORY_ENTRY_EXCEPTION* = 3
  IMAGE_DIRECTORY_ENTRY_SECURITY* = 4
  IMAGE_DIRECTORY_ENTRY_BASERELOC* = 5
  IMAGE_DIRECTORY_ENTRY_DEBUG* = 6
  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE* = 7
  IMAGE_DIRECTORY_ENTRY_GLOBALPTR* = 8
  IMAGE_DIRECTORY_ENTRY_TLS* = 9
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG* = 10
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT* = 11
  IMAGE_DIRECTORY_ENTRY_IAT* = 12
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT* = 13
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR* = 14

  # Alignment
  FILE_ALIGNMENT* = 0x200'u32    # 512 bytes
  SECTION_ALIGNMENT* = 0x1000'u32  # 4KB

  # Default image base for executables
  DEFAULT_IMAGE_BASE* = 0x140000000'u64  # 64-bit default

proc initDosHeader*(peHeaderOffset: uint32): IMAGE_DOS_HEADER =
  result.e_magic = IMAGE_DOS_SIGNATURE
  result.e_cblp = 0x90
  result.e_cp = 0x03
  result.e_cparhdr = 0x04
  result.e_maxalloc = 0xFFFF
  result.e_sp = 0xB8
  result.e_lfarlc = 0x40
  result.e_lfanew = peHeaderOffset

proc initFileHeader*(machine: uint16; numSections: uint16; optHeaderSize: uint16): IMAGE_FILE_HEADER =
  result.Machine = machine
  result.NumberOfSections = numSections
  result.TimeDateStamp = 0  # Can be set to current time
  result.PointerToSymbolTable = 0
  result.NumberOfSymbols = 0
  result.SizeOfOptionalHeader = optHeaderSize
  result.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_LARGE_ADDRESS_AWARE

proc initOptionalHeader64*(
  entryPoint: uint32;
  codeSize: uint32;
  imageBase: uint64;
  sizeOfImage: uint32;
  sizeOfHeaders: uint32;
  subsystem: uint16 = IMAGE_SUBSYSTEM_WINDOWS_CUI
): IMAGE_OPTIONAL_HEADER64 =
  result.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC
  result.MajorLinkerVersion = 14
  result.MinorLinkerVersion = 0
  result.SizeOfCode = codeSize
  result.SizeOfInitializedData = 0
  result.SizeOfUninitializedData = 0
  result.AddressOfEntryPoint = entryPoint
  result.BaseOfCode = SECTION_ALIGNMENT
  result.ImageBase = imageBase
  result.SectionAlignment = SECTION_ALIGNMENT
  result.FileAlignment = FILE_ALIGNMENT
  result.MajorOperatingSystemVersion = 6
  result.MinorOperatingSystemVersion = 0
  result.MajorSubsystemVersion = 6
  result.MinorSubsystemVersion = 0
  result.SizeOfImage = sizeOfImage
  result.SizeOfHeaders = sizeOfHeaders
  result.Subsystem = subsystem
  result.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA or
                              IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE or
                              IMAGE_DLLCHARACTERISTICS_NX_COMPAT or
                              IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
  result.SizeOfStackReserve = 0x100000  # 1MB
  result.SizeOfStackCommit = 0x1000     # 4KB
  result.SizeOfHeapReserve = 0x100000   # 1MB
  result.SizeOfHeapCommit = 0x1000      # 4KB
  result.NumberOfRvaAndSizes = 16

proc initSectionHeader*(
  name: string;
  virtualSize: uint32;
  virtualAddress: uint32;
  rawSize: uint32;
  rawAddress: uint32;
  characteristics: uint32
): IMAGE_SECTION_HEADER =
  for i in 0..<min(8, name.len):
    result.Name[i] = byte(name[i])
  result.VirtualSize = virtualSize
  result.VirtualAddress = virtualAddress
  result.SizeOfRawData = rawSize
  result.PointerToRawData = rawAddress
  result.Characteristics = characteristics

proc alignTo(value, alignment: uint32): uint32 =
  (value + alignment - 1) and not (alignment - 1)

proc writePE*(code: var Buffer; bssSize: int; entryOffset: uint32;
              machine: uint16; outfile: string;
              dynlink: DynLinkInfo = DynLinkInfo()) =
  ## Write a PE executable file
  let hasExtProcs = dynlink.extProcs.len > 0

  # DOS header size
  let dosHeaderSize = sizeof(IMAGE_DOS_HEADER).uint32
  # DOS stub - minimal stub that just exits (required for some PE loaders)
  # The stub goes from offset 64 to 127, PE signature at 128 (0x80)
  const dosStub: array[64, byte] = [
    # Simple DOS stub: push cs; pop ds; mov dx, msg; mov ah, 9; int 21h; mov ax, 4c01h; int 21h
    0x0E'u8, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,  # "This progr"
    0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,  # "am canno"
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,  # "t be run"
    0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,  # " in DOS "
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,  # "mode.\r\r\n"
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # "$" + padding
  ]
  let dosStubSize = uint32(dosStub.len)
  # PE signature at offset 128 (0x80) - standard location
  let peSignatureOffset = dosHeaderSize + dosStubSize
  let peSignatureSize = 4'u32

  # Headers after PE signature
  let fileHeaderSize = sizeof(IMAGE_FILE_HEADER).uint32
  let optHeaderSize = sizeof(IMAGE_OPTIONAL_HEADER64).uint32

  # Calculate number of sections
  var numSections = 1'u16  # .text
  if bssSize > 0:
    inc numSections  # .bss or .data
  if hasExtProcs:
    inc numSections  # .idata for imports
  inc numSections  # .reloc for ASLR support

  let sectionHeadersSize = uint32(numSections) * sizeof(IMAGE_SECTION_HEADER).uint32

  # Total headers size (aligned to file alignment)
  let headersSize = alignTo(
    peSignatureOffset + peSignatureSize + fileHeaderSize + optHeaderSize + sectionHeadersSize,
    FILE_ALIGNMENT
  )

  # .text section
  let textRva = SECTION_ALIGNMENT
  let textSize = uint32(code.data.len)
  let textRawSize = alignTo(textSize, FILE_ALIGNMENT)
  let textFileOffset = headersSize

  # Build import data if needed
  var idataBytes: seq[byte] = @[]
  var iatRva = 0'u32
  var iatSize = 0'u32
  var idataRva = 0'u32
  var idataSize = 0'u32

  if hasExtProcs:
    # Build import directory and tables
    # Structure:
    # - Import Directory Table (array of IMAGE_IMPORT_DESCRIPTOR, null-terminated)
    # - Import Lookup Table (ILT) - one per DLL
    # - Import Address Table (IAT) - one per DLL
    # - Hint/Name Table
    # - DLL names

    let numDlls = dynlink.libs.len
    let importDescSize = sizeof(IMAGE_IMPORT_DESCRIPTOR)

    # Calculate sizes
    var hintNameTableSize = 0
    for ext in dynlink.extProcs:
      hintNameTableSize += 2 + ext.extName.len + 1  # hint(2) + name + null
      if (hintNameTableSize mod 2) != 0:
        inc hintNameTableSize  # Padding

    var dllNamesSize = 0
    for lib in dynlink.libs:
      dllNamesSize += lib.name.len + 1

    let iltSize = (dynlink.extProcs.len + numDlls) * 8  # 8 bytes per entry + null terminators
    iatSize = uint32(iltSize)

    # Layout within .idata:
    # Offset 0: Import Directory Table
    # Offset X: ILT entries
    # Offset Y: IAT entries
    # Offset Z: Hint/Name Table
    # Offset W: DLL names

    let idtOffset = 0
    let idtSize = (numDlls + 1) * importDescSize  # +1 for null terminator
    let iltOffset = idtSize
    let iatOffset = iltOffset + iltSize
    let hintOffset = iatOffset + iltSize
    let dllNamesOffset = hintOffset + hintNameTableSize

    idataSize = uint32(dllNamesOffset + dllNamesSize)
    idataBytes = newSeq[byte](alignTo(idataSize, FILE_ALIGNMENT).int)

    # .idata section comes after .text
    idataRva = alignTo(textRva + textSize, SECTION_ALIGNMENT)
    iatRva = idataRva + uint32(iatOffset)

    # Build import directory entries
    var currentHintOffset = hintOffset
    var currentDllNameOffset = dllNamesOffset
    var currentIltOffset = iltOffset
    var currentIatOffset = iatOffset

    for libIdx, lib in dynlink.libs:
      # Write DLL name
      for c in lib.name:
        idataBytes[currentDllNameOffset] = byte(c)
        inc currentDllNameOffset
      idataBytes[currentDllNameOffset] = 0
      inc currentDllNameOffset

      # Import Directory entry
      let descOffset = idtOffset + libIdx * importDescSize
      let iltRva = idataRva + uint32(currentIltOffset)
      let iatRvaEntry = idataRva + uint32(currentIatOffset)
      let dllNameRva = idataRva + uint32(currentDllNameOffset - lib.name.len - 1)

      # Write descriptor fields (little-endian)
      # OriginalFirstThunk (ILT RVA)
      idataBytes[descOffset + 0] = byte(iltRva and 0xFF)
      idataBytes[descOffset + 1] = byte((iltRva shr 8) and 0xFF)
      idataBytes[descOffset + 2] = byte((iltRva shr 16) and 0xFF)
      idataBytes[descOffset + 3] = byte((iltRva shr 24) and 0xFF)
      # TimeDateStamp
      idataBytes[descOffset + 4] = 0
      idataBytes[descOffset + 5] = 0
      idataBytes[descOffset + 6] = 0
      idataBytes[descOffset + 7] = 0
      # ForwarderChain
      idataBytes[descOffset + 8] = 0xFF
      idataBytes[descOffset + 9] = 0xFF
      idataBytes[descOffset + 10] = 0xFF
      idataBytes[descOffset + 11] = 0xFF
      # Name RVA
      idataBytes[descOffset + 12] = byte(dllNameRva and 0xFF)
      idataBytes[descOffset + 13] = byte((dllNameRva shr 8) and 0xFF)
      idataBytes[descOffset + 14] = byte((dllNameRva shr 16) and 0xFF)
      idataBytes[descOffset + 15] = byte((dllNameRva shr 24) and 0xFF)
      # FirstThunk (IAT RVA)
      idataBytes[descOffset + 16] = byte(iatRvaEntry and 0xFF)
      idataBytes[descOffset + 17] = byte((iatRvaEntry shr 8) and 0xFF)
      idataBytes[descOffset + 18] = byte((iatRvaEntry shr 16) and 0xFF)
      idataBytes[descOffset + 19] = byte((iatRvaEntry shr 24) and 0xFF)

      # Write ILT and IAT entries for this DLL's imports
      for ext in dynlink.extProcs:
        if ext.libOrdinal == lib.ordinal:
          let hintNameRva = idataRva + uint32(currentHintOffset)

          # Write hint/name entry
          idataBytes[currentHintOffset] = 0  # Hint (low byte)
          idataBytes[currentHintOffset + 1] = 0  # Hint (high byte)
          for i, c in ext.extName:
            idataBytes[currentHintOffset + 2 + i] = byte(c)
          idataBytes[currentHintOffset + 2 + ext.extName.len] = 0
          currentHintOffset += 2 + ext.extName.len + 1
          if (currentHintOffset mod 2) != 0:
            inc currentHintOffset

          # Write ILT entry (8 bytes, RVA to hint/name)
          idataBytes[currentIltOffset + 0] = byte(hintNameRva and 0xFF)
          idataBytes[currentIltOffset + 1] = byte((hintNameRva shr 8) and 0xFF)
          idataBytes[currentIltOffset + 2] = byte((hintNameRva shr 16) and 0xFF)
          idataBytes[currentIltOffset + 3] = byte((hintNameRva shr 24) and 0xFF)
          idataBytes[currentIltOffset + 4] = 0
          idataBytes[currentIltOffset + 5] = 0
          idataBytes[currentIltOffset + 6] = 0
          idataBytes[currentIltOffset + 7] = 0
          currentIltOffset += 8

          # Write IAT entry (same as ILT, will be overwritten by loader)
          idataBytes[currentIatOffset + 0] = byte(hintNameRva and 0xFF)
          idataBytes[currentIatOffset + 1] = byte((hintNameRva shr 8) and 0xFF)
          idataBytes[currentIatOffset + 2] = byte((hintNameRva shr 16) and 0xFF)
          idataBytes[currentIatOffset + 3] = byte((hintNameRva shr 24) and 0xFF)
          idataBytes[currentIatOffset + 4] = 0
          idataBytes[currentIatOffset + 5] = 0
          idataBytes[currentIatOffset + 6] = 0
          idataBytes[currentIatOffset + 7] = 0
          currentIatOffset += 8

      # Null terminator for this DLL's ILT and IAT
      currentIltOffset += 8
      currentIatOffset += 8

  # Build .reloc section (minimal, for ASLR support)
  # Since we use RIP-relative addressing, we don't have absolute references to relocate
  # But Windows requires a valid .reloc section when DYNAMIC_BASE is set
  # Format: Base Relocation Block(s)
  #   - VirtualAddress (4 bytes): Page RVA
  #   - SizeOfBlock (4 bytes): Size including header
  #   - TypeOffset entries (2 bytes each)
  const relocBlockSize = 12'u32  # 8 byte header + 2 padding entries (4 bytes)
  var relocBytes: array[12, byte]
  # Block header for page 0x1000 (.text section)
  relocBytes[0] = byte(textRva and 0xFF)
  relocBytes[1] = byte((textRva shr 8) and 0xFF)
  relocBytes[2] = byte((textRva shr 16) and 0xFF)
  relocBytes[3] = byte((textRva shr 24) and 0xFF)
  # SizeOfBlock = 12
  relocBytes[4] = byte(relocBlockSize and 0xFF)
  relocBytes[5] = byte((relocBlockSize shr 8) and 0xFF)
  relocBytes[6] = byte((relocBlockSize shr 16) and 0xFF)
  relocBytes[7] = byte((relocBlockSize shr 24) and 0xFF)
  # Two padding entries (type 0 = IMAGE_REL_BASED_ABSOLUTE, offset 0)
  relocBytes[8] = 0
  relocBytes[9] = 0
  relocBytes[10] = 0
  relocBytes[11] = 0

  let relocSize = relocBlockSize
  let relocRawSize = alignTo(relocSize, FILE_ALIGNMENT)

  # Calculate final image size
  var sizeOfImage = textRva + alignTo(textSize, SECTION_ALIGNMENT)
  if hasExtProcs:
    sizeOfImage = idataRva + alignTo(idataSize, SECTION_ALIGNMENT)
  # Add .reloc section to image size
  let relocRva = sizeOfImage
  sizeOfImage = relocRva + alignTo(relocSize, SECTION_ALIGNMENT)
  if bssSize > 0:
    sizeOfImage += alignTo(uint32(bssSize), SECTION_ALIGNMENT)

  # Create headers
  var dosHeader = initDosHeader(peSignatureOffset)
  var fileHeader = initFileHeader(machine, numSections, uint16(optHeaderSize))
  var optHeader = initOptionalHeader64(
    textRva + entryOffset,
    textRawSize,
    DEFAULT_IMAGE_BASE,
    sizeOfImage,
    headersSize
  )

  # Set import directory in data directory
  if hasExtProcs:
    optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataRva
    optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idataSize
    optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = iatRva
    optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = iatSize

  # Set base relocation directory
  optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relocRva
  optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relocSize

  # Create section headers
  var textSection = initSectionHeader(
    ".text",
    textSize,
    textRva,
    textRawSize,
    textFileOffset,
    IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
  )

  var idataSection: IMAGE_SECTION_HEADER
  var idataFileOffset = 0'u32
  var idataRawSize = 0'u32
  if hasExtProcs:
    idataFileOffset = textFileOffset + textRawSize
    idataRawSize = alignTo(idataSize, FILE_ALIGNMENT)
    idataSection = initSectionHeader(
      ".idata",
      idataSize,
      idataRva,
      idataRawSize,
      idataFileOffset,
      IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    )

  # .reloc section (comes after .idata or .text)
  var relocFileOffset = textFileOffset + textRawSize
  if hasExtProcs:
    relocFileOffset = idataFileOffset + idataRawSize
  var relocSection = initSectionHeader(
    ".reloc",
    relocSize,
    relocRva,
    relocRawSize,
    relocFileOffset,
    IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_DISCARDABLE
  )

  # Write file
  var f = newFileStream(outfile, fmWrite)
  if f == nil:
    raise newException(IOError, "Failed to create file: " & outfile)

  # DOS Header (use writeData for explicit binary write)
  f.writeData(unsafeAddr dosHeader, sizeof(dosHeader))

  # DOS Stub
  f.writeData(unsafeAddr dosStub[0], dosStub.len)

  # PE Signature
  var peSignature = IMAGE_NT_SIGNATURE
  f.writeData(unsafeAddr peSignature, sizeof(peSignature))

  # File Header
  f.writeData(unsafeAddr fileHeader, sizeof(fileHeader))

  # Optional Header
  f.writeData(unsafeAddr optHeader, sizeof(optHeader))

  # Section Headers
  f.writeData(unsafeAddr textSection, sizeof(textSection))
  if hasExtProcs:
    f.writeData(unsafeAddr idataSection, sizeof(idataSection))
  f.writeData(unsafeAddr relocSection, sizeof(relocSection))

  # Padding to first section
  let currentPos = peSignatureOffset + peSignatureSize + fileHeaderSize + optHeaderSize + sectionHeadersSize
  let paddingToText = int(headersSize - currentPos)
  if paddingToText > 0:
    var zeros = newSeq[byte](paddingToText)
    f.writeData(unsafeAddr zeros[0], paddingToText)

  # Patch IAT call relocations to point to IAT entries
  if hasExtProcs:
    # Create a mapping from IAT slot index to IAT entry RVA
    var slotToRva: seq[uint32] = @[]
    var iatSlotIndex = 0
    for lib in dynlink.libs:
      for ext in dynlink.extProcs:
        if ext.libOrdinal == lib.ordinal:
          let iatEntryRva = iatRva + uint32(iatSlotIndex * 8)
          # Ensure slotToRva is large enough
          while slotToRva.len <= ext.gotSlot:
            slotToRva.add(0'u32)
          slotToRva[ext.gotSlot] = iatEntryRva
          inc iatSlotIndex
      # Account for null terminator after each library's IAT entries
      inc iatSlotIndex

    # Patch IAT call relocations
    for reloc in code.relocs:
      if reloc.kind == rkIatCall:
        let iatSlot = int(reloc.target)
        if iatSlot < slotToRva.len:
          let iatEntryRva = slotToRva[iatSlot]
          # For RIP-relative addressing: disp = (IAT_RVA) - (call_inst_end_RVA)
          let callInstEndRva = textRva + uint32(reloc.position + 6)
          let disp32 = int32(iatEntryRva) - int32(callInstEndRva)

          # Patch the displacement directly in the code buffer
          code.data[reloc.position + 2] = byte(disp32 and 0xFF)
          code.data[reloc.position + 3] = byte((disp32 shr 8) and 0xFF)
          code.data[reloc.position + 4] = byte((disp32 shr 16) and 0xFF)
          code.data[reloc.position + 5] = byte((disp32 shr 24) and 0xFF)

  # .text section
  if code.data.len > 0:
    f.writeData(code.data.rawData, code.data.len)
    let textPadding = int(textRawSize) - code.data.len
    if textPadding > 0:
      var zeros = newSeq[byte](textPadding)
      f.writeData(unsafeAddr zeros[0], textPadding)

  # .idata section
  if hasExtProcs and idataBytes.len > 0:
    f.writeData(unsafeAddr idataBytes[0], idataBytes.len)
    # Padding for .idata
    let idataPadding = int(idataRawSize) - idataBytes.len
    if idataPadding > 0:
      var zeros = newSeq[byte](idataPadding)
      f.writeData(unsafeAddr zeros[0], idataPadding)

  # .reloc section
  f.writeData(unsafeAddr relocBytes[0], relocBytes.len)
  # Padding for .reloc
  let relocPadding = int(relocRawSize) - relocBytes.len
  if relocPadding > 0:
    var zeros = newSeq[byte](relocPadding)
    f.writeData(unsafeAddr zeros[0], relocPadding)

  f.close()

  # On Windows, no need to set execute permission (it's in the PE headers)
  when defined(windows):
    discard
  else:
    # When cross-compiling, still useful to mark as executable
    let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
    setFilePermissions(outfile, perms)

