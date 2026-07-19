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

  TlvInfo* = object
    ## Thread-local storage (macOS TLV) layout produced by the assembler.
    descriptorOffsets*: seq[int]  # per tvar (descriptor index): byte offset in the per-thread region
    threadData*: seq[byte]        # __thread_data init template dyld copies per thread
    sites*: seq[(int, int)]       # (adrp position in .text, descriptor index) to patch with the descriptor address

  RodataRebase* = object
    ## One symbol-pointer field of a `dataConst` blob in __DATA. `fieldOff` is the
    ## pointer's byte offset within the .bss/__DATA region. The stored value is the
    ## target's preferred (un-slid) vaddr, which dyld then rebases by the load slide.
    fieldOff*: int          # byte offset of the 8-byte pointer within the __DATA region
    targetInData*: bool     # true: target lives in __DATA at `targetOff`; false: in __TEXT
    targetOff*: int         # __DATA region offset, or __TEXT code offset, of the target

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

  MachO_Nlist64* = object
    ## One symbol-table entry (symtab string-table index + type + section + value).
    n_strx*: uint32       # byte offset of the name in the string table
    n_type*: uint8        # N_SECT|N_EXT for a defined symbol, N_UNDF|N_EXT for undefined
    n_sect*: uint8        # 1-based section number (0 for undefined)
    n_desc*: uint16
    n_value*: uint64      # the symbol's address within the object (section addr + offset)

  MachO_RelocInfo* = object
    ## A scattered-free external relocation_info record (mach-o/reloc.h). `r_info`
    ## is the packed bitfield r_symbolnum:24,r_pcrel:1,r_length:2,r_extern:1,r_type:4.
    r_address*: int32     # offset of the fixup within its section
    r_info*: uint32

  # --- object-file (MH_OBJECT) emission ---------------------------------------
  # The assembler resolves all the semantics (symbol section/value, reloc target
  # indices) and hands these simple records to `writeMachOObject`, which keeps the
  # standalone-executable `writeMachO` path completely untouched.
  MachOSecKind* = enum
    moText, moData        # which output section a *defined* symbol lives in

  MachOSym* = object
    name*: string         # final Mach-O symbol name (already mangled by the caller)
    sec*: MachOSecKind    # only meaningful when `defined`
    value*: uint64        # section-relative offset (caller need not add the section base)
    defined*: bool        # false => undefined (an external reference ld must resolve)

  MachORelKind* = enum
    mrUnsigned            # 8-byte absolute pointer (ARM64_RELOC_UNSIGNED)
    mrBranch26            # BL/B target          (ARM64_RELOC_BRANCH26)
    mrPage21              # ADRP page            (ARM64_RELOC_PAGE21)
    mrPageoff12           # ADD/LDR low 12 bits  (ARM64_RELOC_PAGEOFF12)

  MachORel* = object
    address*: int         # offset of the fixup within its section
    symIdx*: int          # index into the symbol table handed to writeMachOObject
    kind*: MachORelKind

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
  MH_HAS_TLV_DESCRIPTORS* = 0x800000'u32  # Image has thread-local-variable descriptors dyld must set up

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
  S_REGULAR* = 0x00'u32

  # nlist_64 n_type bits (mach-o/nlist.h)
  N_EXT* = 0x01'u8        # external symbol
  N_UNDF* = 0x00'u8       # undefined
  N_SECT* = 0x0e'u8       # defined in section number n_sect

  # ARM64 relocation types (mach-o/arm64/reloc.h)
  ARM64_RELOC_UNSIGNED* = 0'u32
  ARM64_RELOC_BRANCH26* = 2'u32
  ARM64_RELOC_PAGE21* = 3'u32
  ARM64_RELOC_PAGEOFF12* = 4'u32

  # Section types for thread-local storage (macOS TLV)
  S_THREAD_LOCAL_REGULAR* = 0x11'u32       # __thread_data: initialized TLV template
  S_THREAD_LOCAL_ZEROFILL* = 0x12'u32      # __thread_bss: zero TLV template
  S_THREAD_LOCAL_VARIABLES* = 0x13'u32     # __thread_vars: TLV descriptors

  TlvBootstrapSym* = "__tlv_bootstrap"     # libSystem thunk dyld swaps into each descriptor

  # Bind opcodes for LC_DYLD_INFO_ONLY
  BIND_OPCODE_DONE* = 0x00'u8
  BIND_OPCODE_SET_DYLIB_ORDINAL_IMM* = 0x10'u8
  BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM* = 0x40'u8
  BIND_OPCODE_SET_TYPE_IMM* = 0x50'u8
  BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB* = 0x72'u8
  BIND_OPCODE_DO_BIND* = 0x90'u8
  BIND_TYPE_POINTER* = 1'u8

  # Rebase opcodes for LC_DYLD_INFO_ONLY. A rebase tells dyld to add the load slide
  # to an absolute pointer stored in a writable segment — exactly what a `const`
  # whose value is the address of another symbol needs on a PIE image.
  REBASE_OPCODE_DONE* = 0x00'u8
  REBASE_OPCODE_SET_TYPE_IMM* = 0x10'u8
  REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB* = 0x20'u8
  REBASE_OPCODE_DO_REBASE_IMM_TIMES* = 0x50'u8
  REBASE_TYPE_POINTER* = 1'u8

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

proc addPointerBind(result: var seq[byte]; libOrdinal: int; name: string;
                    dataSegmentIndex: int; dataOffset: uint64) =
  ## Emit one absolute-pointer bind of `name` (from dylib `libOrdinal`) at
  ## `dataOffset` within the data segment.
  result.add(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM or uint8(libOrdinal and 0xF))
  result.add(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM)
  for c in name: result.add(byte(c))
  result.add(0)
  result.add(BIND_OPCODE_SET_TYPE_IMM or BIND_TYPE_POINTER)
  result.add(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB or uint8(dataSegmentIndex))
  var offset = dataOffset
  while offset >= 0x80:
    result.add(byte((offset and 0x7F) or 0x80))
    offset = offset shr 7
  result.add(byte(offset and 0x7F))
  result.add(BIND_OPCODE_DO_BIND)

proc generateBindInfo(extProcs: seq[ExternalProcInfo]; dataSegmentIndex: int;
                      tlvDescriptorCount: int; tlvVarsDataOffset: uint64;
                      tlvLibOrdinal: int): seq[byte] =
  ## Generate bind opcodes: one per external proc (GOT slot) plus one per
  ## thread-local descriptor thunk (bound to `__tlv_bootstrap`, which dyld then
  ## overwrites with its own accessor while assigning the pthread key).
  result = @[]
  for ext in extProcs:
    addPointerBind(result, ext.libOrdinal, ext.extName, dataSegmentIndex,
                   uint64(ext.gotSlot * 8))
  for i in 0 ..< tlvDescriptorCount:
    # The thunk is the first word of the 24-byte descriptor.
    addPointerBind(result, tlvLibOrdinal, TlvBootstrapSym, dataSegmentIndex,
                   tlvVarsDataOffset + uint64(i * 24))
  result.add(BIND_OPCODE_DONE)

proc generateRebaseInfo(rebases: seq[RodataRebase]; dataSegmentIndex: int;
                        bssOff: uint64): seq[byte] =
  ## Emit one pointer rebase per `dataConst` symbol-pointer field. Each entry sets
  ## the segment+offset (within __DATA) of the 8-byte pointer and asks dyld to add
  ## the load slide to it. Offsets are relative to the __DATA segment start, so the
  ## field's __DATA-region offset is biased by `bssOff` (where the region sits in
  ## the segment, after the GOT/TLV sections).
  result = @[]
  if rebases.len == 0: return
  result.add(REBASE_OPCODE_SET_TYPE_IMM or REBASE_TYPE_POINTER)
  for rb in rebases:
    result.add(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB or uint8(dataSegmentIndex and 0xF))
    var off = bssOff + uint64(rb.fieldOff)
    while off >= 0x80:
      result.add(byte((off and 0x7F) or 0x80))
      off = off shr 7
    result.add(byte(off and 0x7F))
    result.add(REBASE_OPCODE_DO_REBASE_IMM_TIMES or 1'u8)
  result.add(REBASE_OPCODE_DONE)

proc writeMachO*(code: Bytes; bssSize: int;
                 cputype, cpusubtype: uint32; outfile: string;
                 dynlink: DynLinkInfo = DynLinkInfo();
                 gvarSites: seq[(int, int)] = @[];
                 tlv: TlvInfo = TlvInfo();
                 bssInits: seq[tuple[off: int64, val: int64, size: int]] = @[];
                 rebases: seq[RodataRebase] = @[]) =
  let pageSize = 0x4000.uint64  # 16KB page size for arm64 macOS
  let baseAddr = 0x100000000.uint64  # macOS default base address

  # Handle external procs - generate stubs and patch BL instructions
  var modifiedCode = code
  let hasExtProcs = dynlink.extProcs.len > 0

  # Thread-local storage (macOS TLV): N 24-byte descriptors in __thread_vars and
  # an 8-byte-padded init template in __thread_data, both file-backed in __DATA.
  let hasTlv = tlv.descriptorOffsets.len > 0
  # A gvar with a compile-time constant initializer (e.g. `g = 41.0`) needs its
  # bytes on disk; a plain zero-fill `__bss` would start it at 0. When present,
  # the bss region becomes file-backed and we write the init bytes below. A
  # `dataConst` rebase also needs a file-backed slot: dyld adds the slide to the
  # preferred vaddr we write there, so that vaddr must be real on-disk bytes.
  let hasBssInits = bssInits.len > 0 or rebases.len > 0
  let nTlv = tlv.descriptorOffsets.len
  let tvarsSize = nTlv * 24
  var threadData = tlv.threadData
  while (threadData.len and 7) != 0: threadData.add(0)
  let tdataSize = threadData.len
  # Stubs are ARM64 instructions (ADRP/LDR/BR) and must be 4-byte aligned. A
  # trailing rodata whose length is not a multiple of 4 (e.g. "hi\n") would
  # otherwise leave the stub section misaligned, corrupting both the stub
  # encodings and the BL targets computed from `stubsOffset`. Pad to align.
  while (modifiedCode.len and 3) != 0: modifiedCode.add(0)
  let stubsOffset = modifiedCode.len  # Stubs go after the (aligned) code
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
  # DATA segment is needed for GOT (external procs), TLV descriptors/data, or bss.
  # Its sections, in vm order: __got, __thread_vars, __thread_data, __bss.
  let needsData = bssSize > 0 or hasExtProcs or hasTlv
  var dataSectionCount = 0
  if hasExtProcs: inc dataSectionCount   # __got
  if hasTlv: inc dataSectionCount        # __thread_vars
  if hasTlv: inc dataSectionCount        # __thread_data
  if bssSize > 0: inc dataSectionCount   # __bss
  let dataSegSize = if needsData: sizeof(MachO_Segment64) + dataSectionCount * sizeof(MachO_Section64) else: 0
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

  # DATA segment byte layout (offsets within __DATA): __got, then the TLV
  # descriptors and init template, then bss. The GOT + TLV region is file-backed
  # (real bytes dyld binds/copies); bss is the zero-filled tail.
  let dataVmaddr = textVmaddr + textSegmentFileSize
  let gotVmaddr = dataVmaddr  # GOT at start of __DATA
  let gotOff = 0
  let tvarsOff = gotOff + gotSize          # 8-aligned: gotSize is a multiple of 8
  let tdataOff = tvarsOff + tvarsSize       # 8-aligned: 24 * nTlv
  let bssOff = tdataOff + tdataSize         # tdataSize padded to 8
  # File-backed portion of __DATA. Without TLV we keep the historical layout
  # (GOT/bss not file-backed: dyld binds the GOT, the loader zeroes bss). With
  # TLV, the GOT + descriptors + init template are real file bytes; the file
  # region is page-padded so __LINKEDIT stays page-aligned (its fileoff must be
  # congruent with its page-aligned vmaddr).
  # bss is file-backed (covering the whole __DATA content) when some gvars carry
  # static initializers; otherwise the historical layout applies (file-backed
  # GOT+TLV when TLV is present, fully zero-filled __DATA otherwise).
  let dataFileContentSize =
    if hasBssInits: bssOff + bssSize
    elif hasTlv: bssOff
    else: 0
  let dataFileSize = int((uint64(dataFileContentSize) + pageSize - 1) and not (pageSize - 1))
  let totalDataSize = bssOff + bssSize
  let dataSize = if totalDataSize > 0: ((totalDataSize.uint64 + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  # __LINKEDIT comes after TEXT and the file-backed part of DATA.
  let dataFileoff = textSegmentFileSize
  let linkeditVmaddr = if hasData: dataVmaddr + dataSize else: textVmaddr + textSegmentFileSize
  let linkeditFileoff = textSegmentFileSize + uint64(dataFileSize)

  # Rebase info: one entry per `dataConst` symbol-pointer field (segment 2 = __DATA),
  # so dyld slides the preferred target vaddr we bake into each slot.
  let rebaseInfo = generateRebaseInfo(rebases, 2, uint64(bssOff))

  # Bind info: external-proc GOT slots plus each TLV descriptor's __tlv_bootstrap
  # thunk. libSystem is the sole LC_LOAD_DYLIB, so its ordinal is 1.
  let bindInfo = if hasExtProcs or hasTlv:
    generateBindInfo(dynlink.extProcs, 2,  # segment index 2 = __DATA
                     nTlv, uint64(tvarsOff), 1)
  else:
    @[]

  # Linkedit contains: rebase info + bind info + string table (1 byte null term).
  let linkeditFilesize = (if rebaseInfo.len + bindInfo.len > 0:
                            uint64(rebaseInfo.len + bindInfo.len) + 8
                          else: 32.uint64)
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

  # Create DATA segment and its sections (__got, __thread_vars, __thread_data,
  # __bss — only those that are present), in vm order.
  var dataSegment: MachO_Segment64
  var dataSections: seq[MachO_Section64] = @[]

  if hasData:
    dataSegment = initSegment64("__DATA", dataVmaddr, dataSize, dataFileoff, uint64(dataFileSize),
                                 VM_PROT_READ or VM_PROT_WRITE,
                                 VM_PROT_READ or VM_PROT_WRITE, uint32(dataSectionCount))

    if hasExtProcs:
      # __got: non-lazy symbol pointers (file-backed only when TLV forces a
      # file-backed __DATA; otherwise dyld materializes it from bind info).
      let gotFileOff = if hasTlv or hasBssInits: uint32(dataFileoff + uint64(gotOff)) else: 0'u32
      dataSections.add initSection64("__got", "__DATA", dataVmaddr + uint64(gotOff),
                                     uint64(gotSize), gotFileOff, 3, S_NON_LAZY_SYMBOL_POINTERS)
    if hasTlv:
      # __thread_vars: the 24-byte TLV descriptors (file-backed).
      dataSections.add initSection64("__thread_vars", "__DATA", dataVmaddr + uint64(tvarsOff),
                                     uint64(tvarsSize), uint32(dataFileoff + uint64(tvarsOff)),
                                     3, S_THREAD_LOCAL_VARIABLES)
      # __thread_data: the per-thread init template dyld copies (file-backed).
      dataSections.add initSection64("__thread_data", "__DATA", dataVmaddr + uint64(tdataOff),
                                     uint64(tdataSize), uint32(dataFileoff + uint64(tdataOff)),
                                     3, S_THREAD_LOCAL_REGULAR)
    if bssSize > 0:
      # Globals region: zero-fill `__bss` (file offset 0) normally; a file-backed
      # `__data` carrying the init bytes when some gvars have static initializers.
      if hasBssInits:
        dataSections.add initSection64("__data", "__DATA", dataVmaddr + uint64(bssOff),
                                       uint64(bssSize), uint32(dataFileoff + uint64(bssOff)), 4, 0)
      else:
        dataSections.add initSection64("__bss", "__DATA", dataVmaddr + uint64(bssOff),
                                       uint64(bssSize), 0, 4, 0)

  # Create __LINKEDIT segment
  var linkeditSegment = initSegment64("__LINKEDIT", linkeditVmaddr, linkeditVmsize,
                                       linkeditFileoff, linkeditFilesize,
                                       VM_PROT_READ, VM_PROT_READ, 0)

  # Create LC_DYLD_INFO_ONLY. Linkedit layout: [rebase][bind][string table].
  var dyldInfo: MachO_DyldInfo
  dyldInfo.cmd = LC_DYLD_INFO_ONLY
  dyldInfo.cmdsize = uint32(sizeof(MachO_DyldInfo))
  if rebaseInfo.len > 0:
    dyldInfo.rebase_off = uint32(linkeditFileoff)
    dyldInfo.rebase_size = uint32(rebaseInfo.len)
  else:
    dyldInfo.rebase_off = 0
    dyldInfo.rebase_size = 0
  if bindInfo.len > 0:
    dyldInfo.bind_off = uint32(linkeditFileoff + uint64(rebaseInfo.len))
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
  let symtabOffset = linkeditFileoff + uint64(rebaseInfo.len + bindInfo.len)
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

  # Create header with MH_DYLDLINK and MH_PIE flags (plus the TLV-descriptors
  # flag so dyld sets up thread-local storage before running the program).
  var headerFlags = MH_DYLDLINK or MH_NOUNDEFS or MH_PIE
  if hasTlv: headerFlags = headerFlags or MH_HAS_TLV_DESCRIPTORS
  var header = initMachOHeader(cputype, cpusubtype, ncmds, uint32(actualCmdsSize),
                                headerFlags)

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
    for s in dataSections:
      f.write(s)

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

  # Patch gvar adrp+add sites with the global's __DATA/.bss address. The .bss
  # lives after the GOT and any TLV sections in __DATA; address is formed
  # page-relative to the adrp's PC (placeholders carry the dest reg with zero
  # immediates, so OR-in).
  if gvarSites.len > 0:
    let bssBaseVmaddr = dataVmaddr + uint64(bssOff)
    for (pos, gvarOff) in gvarSites:
      let gvarVmaddr = bssBaseVmaddr + uint64(gvarOff)
      let adrpVmaddr = textSectionVmaddr + uint64(pos)
      let pageDiff = int64(gvarVmaddr and not 0xFFF'u64) - int64(adrpVmaddr and not 0xFFF'u64)
      let pageOff = gvarVmaddr and 0xFFF'u64
      let adrpImm = pageDiff shr 12
      let immlo = uint32(adrpImm and 0x03) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      var adrp = uint32(modifiedCode[pos]) or (uint32(modifiedCode[pos+1]) shl 8) or
                 (uint32(modifiedCode[pos+2]) shl 16) or (uint32(modifiedCode[pos+3]) shl 24)
      adrp = adrp or immlo or immhi
      modifiedCode[pos+0] = byte(adrp and 0xFF)
      modifiedCode[pos+1] = byte((adrp shr 8) and 0xFF)
      modifiedCode[pos+2] = byte((adrp shr 16) and 0xFF)
      modifiedCode[pos+3] = byte((adrp shr 24) and 0xFF)
      # pos+4 is either `add rd, rd, #pageoff` (address-taking) or a folded
      # `ldr/str rt, [x17, #pageoff]` (gload/gstore). The load/store unsigned-imm
      # family has bits[29:24] == 0x39 and scales its imm12 by the access size
      # (bits[31:30]); `add` uses the raw 12-bit offset. Detect and encode accordingly.
      var lo = uint32(modifiedCode[pos+4]) or (uint32(modifiedCode[pos+5]) shl 8) or
               (uint32(modifiedCode[pos+6]) shl 16) or (uint32(modifiedCode[pos+7]) shl 24)
      if ((lo shr 24) and 0x3F'u32) == 0x39'u32:
        let size = (lo shr 30) and 0x3'u32
        doAssert (pageOff and ((1'u64 shl size) - 1)) == 0,
          "gload/gstore: global page-offset not aligned to its access size"
        lo = lo or (uint32((pageOff shr size) and 0xFFF) shl 10)
      else:
        lo = lo or (uint32(pageOff and 0xFFF) shl 10)
      modifiedCode[pos+4] = byte(lo and 0xFF)
      modifiedCode[pos+5] = byte((lo shr 8) and 0xFF)
      modifiedCode[pos+6] = byte((lo shr 16) and 0xFF)
      modifiedCode[pos+7] = byte((lo shr 24) and 0xFF)

  # Patch TLV adrp+add sites with the descriptor's __thread_vars address (same
  # page-relative encoding as gvars; each descriptor is 24 bytes).
  if tlv.sites.len > 0:
    let tvarsBaseVmaddr = dataVmaddr + uint64(tvarsOff)
    for (pos, descIdx) in tlv.sites:
      let descVmaddr = tvarsBaseVmaddr + uint64(descIdx * 24)
      let adrpVmaddr = textSectionVmaddr + uint64(pos)
      let pageDiff = int64(descVmaddr and not 0xFFF'u64) - int64(adrpVmaddr and not 0xFFF'u64)
      let pageOff = descVmaddr and 0xFFF'u64
      let adrpImm = pageDiff shr 12
      let immlo = uint32(adrpImm and 0x03) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      var adrp = uint32(modifiedCode[pos]) or (uint32(modifiedCode[pos+1]) shl 8) or
                 (uint32(modifiedCode[pos+2]) shl 16) or (uint32(modifiedCode[pos+3]) shl 24)
      adrp = adrp or immlo or immhi
      modifiedCode[pos+0] = byte(adrp and 0xFF)
      modifiedCode[pos+1] = byte((adrp shr 8) and 0xFF)
      modifiedCode[pos+2] = byte((adrp shr 16) and 0xFF)
      modifiedCode[pos+3] = byte((adrp shr 24) and 0xFF)
      var add = uint32(modifiedCode[pos+4]) or (uint32(modifiedCode[pos+5]) shl 8) or
                (uint32(modifiedCode[pos+6]) shl 16) or (uint32(modifiedCode[pos+7]) shl 24)
      add = add or (uint32(pageOff and 0xFFF) shl 10)
      modifiedCode[pos+4] = byte(add and 0xFF)
      modifiedCode[pos+5] = byte((add shr 8) and 0xFF)
      modifiedCode[pos+6] = byte((add shr 16) and 0xFF)
      modifiedCode[pos+7] = byte((add shr 24) and 0xFF)

  # Write code (including stubs if any)
  if modifiedCode.len > 0:
    f.writeData(modifiedCode.rawData, modifiedCode.len)
    # Pad to page boundary
    let totalWritten = codeFileOffset + codeSize
    let paddingToPage = int(textSegmentFileSize - totalWritten)
    if paddingToPage > 0:
      var zeros = newSeq[byte](paddingToPage)
      f.writeData(unsafeAddr zeros[0], paddingToPage)

  # Write the file-backed part of __DATA (GOT zeros, TLV descriptors, the
  # __thread_data init template). Only present when TLV forces a file-backed
  # __DATA; otherwise dataFileSize is 0 and the loader zero-fills __DATA.
  if dataFileSize > 0:
    var dataContent = newSeq[byte](dataFileSize)
    # [gotOff..) stays zero (dyld binds the GOT slots).
    # [tvarsOff..) the 24-byte descriptors: thunk=0 (bound to __tlv_bootstrap),
    # key=0 (filled by dyld), offset=per-thread byte offset.
    for i in 0 ..< nTlv:
      let descBase = tvarsOff + i * 24
      let off = uint64(tlv.descriptorOffsets[i])
      for b in 0 ..< 8:
        dataContent[descBase + 16 + b] = byte((off shr (8 * b)) and 0xFF)
    # [tdataOff..) the init template.
    for i, b in threadData:
      dataContent[tdataOff + i] = b
    # [bssOff..) constant static initializers; the rest of the region stays zero.
    for it in bssInits:
      for b in 0 ..< it.size:
        let idx = bssOff + it.off.int + b
        if idx < dataContent.len:
          dataContent[idx] = byte((it.val shr (8 * b)) and 0xFF)
    # `dataConst` symbol-pointer fields: store the target's PREFERRED (un-slid)
    # vaddr; the matching rebase opcode makes dyld add the load slide at runtime.
    # A target in __TEXT sits at `textSectionVmaddr + code offset`; one in __DATA at
    # `dataVmaddr + bssOff + region offset`.
    for rb in rebases:
      let targetVaddr =
        if rb.targetInData: dataVmaddr + uint64(bssOff) + uint64(rb.targetOff)
        else: textSectionVmaddr + uint64(rb.targetOff)
      let ptrIdx = bssOff + rb.fieldOff
      for b in 0 ..< 8:
        if ptrIdx + b < dataContent.len:
          dataContent[ptrIdx + b] = byte((targetVaddr shr (8 * b)) and 0xFF)
    f.writeData(unsafeAddr dataContent[0], dataContent.len)

  # Write __LINKEDIT content: rebase info, then bind info, then the (empty) string
  # table — matching the dyld_info offsets computed above.
  var linkeditData = newSeq[byte](linkeditFilesize.int)
  for i, b in rebaseInfo:
    linkeditData[i] = b
  for i, b in bindInfo:
    linkeditData[rebaseInfo.len + i] = b
  # Add null terminator for empty string table at the end
  linkeditData[^1] = 0
  f.writeData(unsafeAddr linkeditData[0], linkeditData.len)

  # BSS is not written to file (zero-initialized by loader)

  f.close()

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

proc alignUp(x, a: int): int {.inline.} = (x + a - 1) and not (a - 1)

proc encodeRelInfo(symIdx: int; kind: MachORelKind): uint32 =
  ## Pack relocation_info's second word. Every reloc nifasm emits is *external*
  ## (r_extern = 1): it references a symbol-table entry by index and lets ld supply
  ## the final value, so we never need section-relative (scattered) relocs.
  var pcrel, length, typ: uint32
  case kind
  of mrUnsigned:  pcrel = 0; length = 3; typ = ARM64_RELOC_UNSIGNED   # 8-byte pointer
  of mrBranch26:  pcrel = 1; length = 2; typ = ARM64_RELOC_BRANCH26
  of mrPage21:    pcrel = 1; length = 2; typ = ARM64_RELOC_PAGE21
  of mrPageoff12: pcrel = 0; length = 2; typ = ARM64_RELOC_PAGEOFF12
  result = (uint32(symIdx) and 0x00FFFFFF'u32) or (pcrel shl 24) or
           (length shl 25) or (1'u32 shl 27) or (typ shl 28)

proc writeMachOObject*(code: Bytes; dataImage: seq[byte];
                       syms: seq[MachOSym]; nDefined: int;
                       textRels, dataRels: seq[MachORel];
                       cputype, cpusubtype: uint32; outfile: string) =
  ## Emit a relocatable `MH_OBJECT` for the system linker to finish (the path used
  ## when the program links against foreign `.o`s / frameworks, e.g. Objective-C).
  ## Unlike `writeMachO` it does no address layout, GOT/stub synthesis, dyld bind
  ## info or codesigning — undefined symbols stay undefined and references become
  ## relocations. `syms` is ordered defined-first; `nDefined` splits the two halves.
  let hasData = dataImage.len > 0
  let nsects = if hasData: 2 else: 1

  # Load-command sizes (one segment with all sections, plus symtab + dysymtab).
  let segCmdSize = sizeof(MachO_Segment64) + nsects * sizeof(MachO_Section64)
  let sizeofcmds = segCmdSize + sizeof(MachO_Symtab) + sizeof(MachO_DySymtab)
  let ncmds = 3'u32
  let headerSize = sizeof(MachO_Header)
  let loadEnd = headerSize + sizeofcmds

  # File/VM layout. Text sits at vm address 0; data (when present) is 8-aligned and
  # its file gap equals its vm gap, so a symbol's vm value maps straight to its file
  # offset. Trailing tables (relocs, symtab, strtab) follow the section content.
  let textFileOff = loadEnd
  let afterText = textFileOff + code.len
  var dataFileOff = afterText
  var dataAddr = 0
  var afterData = afterText
  if hasData:
    dataFileOff = alignUp(afterText, 8)
    dataAddr = dataFileOff - textFileOff
    afterData = dataFileOff + dataImage.len
  let textRelOff = alignUp(afterData, 4)
  let dataRelOff = textRelOff + textRels.len * sizeof(MachO_RelocInfo)
  let afterRels = dataRelOff + dataRels.len * sizeof(MachO_RelocInfo)
  let symOff = alignUp(afterRels, 8)
  let strOff = symOff + syms.len * sizeof(MachO_Nlist64)
  let segFileSize = afterData - textFileOff
  let segMemSize = alignUp(segFileSize, 8)

  # String table: a leading NUL (index 0 = "unnamed"), then each name NUL-terminated.
  var strtab = @[0'u8]
  var strx = newSeq[uint32](syms.len)
  for i, s in syms:
    strx[i] = uint32(strtab.len)
    for c in s.name: strtab.add byte(c)
    strtab.add 0'u8

  # Header (MH_OBJECT: no flags, no MH_NOUNDEFS — undefined symbols are expected).
  var header = initMachOHeader(cputype, cpusubtype, ncmds, uint32(sizeofcmds), 0)
  header.filetype = MH_OBJECT

  # The single (unnamed) segment carries every section; ld re-segments by the
  # per-section segname (__TEXT / __DATA) at link time.
  var segment = initSegment64("", 0, uint64(segMemSize), uint64(textFileOff),
                              uint64(segFileSize),
                              VM_PROT_READ or VM_PROT_WRITE or VM_PROT_EXECUTE,
                              VM_PROT_READ or VM_PROT_WRITE or VM_PROT_EXECUTE,
                              uint32(nsects))

  var textSection = initSection64("__text", "__TEXT", 0, uint64(code.len),
                                  uint32(textFileOff), 2,
                                  S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS)
  textSection.reloff = uint32(textRelOff)
  textSection.nreloc = uint32(textRels.len)

  var dataSection: MachO_Section64
  if hasData:
    dataSection = initSection64("__data", "__DATA", uint64(dataAddr),
                                uint64(dataImage.len), uint32(dataFileOff), 3, S_REGULAR)
    dataSection.reloff = uint32(dataRelOff)
    dataSection.nreloc = uint32(dataRels.len)

  var symtab: MachO_Symtab
  symtab.cmd = LC_SYMTAB
  symtab.cmdsize = uint32(sizeof(MachO_Symtab))
  symtab.symoff = uint32(symOff)
  symtab.nsyms = uint32(syms.len)
  symtab.stroff = uint32(strOff)
  symtab.strsize = uint32(strtab.len)

  var dysymtab: MachO_DySymtab
  dysymtab.cmd = LC_DYSYMTAB
  dysymtab.cmdsize = uint32(sizeof(MachO_DySymtab))
  dysymtab.iextdefsym = 0
  dysymtab.nextdefsym = uint32(nDefined)
  dysymtab.iundefsym = uint32(nDefined)
  dysymtab.nundefsym = uint32(syms.len - nDefined)

  var f = newFileStream(outfile, fmWrite)

  f.write(header)
  f.write(segment)
  f.write(textSection)
  if hasData: f.write(dataSection)
  f.write(symtab)
  f.write(dysymtab)

  # Section content (we are now at `loadEnd` == textFileOff).
  if code.len > 0:
    f.writeData(code.rawData, code.len)
  if hasData:
    for _ in afterText ..< dataFileOff: f.write(0'u8)   # pad text→data
    f.writeData(unsafeAddr dataImage[0], dataImage.len)

  # Relocations.
  for _ in afterData ..< textRelOff: f.write(0'u8)
  for r in textRels:
    f.write(MachO_RelocInfo(r_address: int32(r.address),
                            r_info: encodeRelInfo(r.symIdx, r.kind)))
  for r in dataRels:
    f.write(MachO_RelocInfo(r_address: int32(r.address),
                            r_info: encodeRelInfo(r.symIdx, r.kind)))

  # Symbol table.
  for _ in afterRels ..< symOff: f.write(0'u8)
  for i, s in syms:
    var nl: MachO_Nlist64
    nl.n_strx = strx[i]
    if s.defined:
      nl.n_type = N_SECT or N_EXT
      nl.n_sect = if s.sec == moText: 1'u8 else: 2'u8
      nl.n_value = (if s.sec == moData: uint64(dataAddr) else: 0'u64) + s.value
    else:
      nl.n_type = N_UNDF or N_EXT
      nl.n_sect = 0
      nl.n_value = 0
    f.write(nl)

  # String table.
  f.writeData(unsafeAddr strtab[0], strtab.len)

  f.close()

