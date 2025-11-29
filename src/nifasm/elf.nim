
type
  Elf64_Addr* = uint64
  Elf64_Off* = uint64
  Elf64_Half* = uint16
  Elf64_Word* = uint32
  Elf64_Sword* = int32
  Elf64_Xword* = uint64
  Elf64_Sxword* = int64

  Elf64_Ehdr* = object
    e_ident*: array[16, byte]
    e_type*: Elf64_Half
    e_machine*: Elf64_Half
    e_version*: Elf64_Word
    e_entry*: Elf64_Addr
    e_phoff*: Elf64_Off
    e_shoff*: Elf64_Off
    e_flags*: Elf64_Word
    e_ehsize*: Elf64_Half
    e_phentsize*: Elf64_Half
    e_phnum*: Elf64_Half
    e_shentsize*: Elf64_Half
    e_shnum*: Elf64_Half
    e_shstrndx*: Elf64_Half

  Elf64_Phdr* = object
    p_type*: Elf64_Word
    p_flags*: Elf64_Word
    p_offset*: Elf64_Off
    p_vaddr*: Elf64_Addr
    p_paddr*: Elf64_Addr
    p_filesz*: Elf64_Xword
    p_memsz*: Elf64_Xword
    p_align*: Elf64_Xword

  Elf64_Shdr* = object
    sh_name*: Elf64_Word
    sh_type*: Elf64_Word
    sh_flags*: Elf64_Xword
    sh_addr*: Elf64_Addr
    sh_offset*: Elf64_Off
    sh_size*: Elf64_Xword
    sh_link*: Elf64_Word
    sh_info*: Elf64_Word
    sh_addralign*: Elf64_Xword
    sh_entsize*: Elf64_Xword

const
  EI_MAG0 = 0
  EI_MAG1 = 1
  EI_MAG2 = 2
  EI_MAG3 = 3
  EI_CLASS = 4
  EI_DATA = 5
  EI_VERSION = 6
  EI_OSABI = 7
  EI_ABIVERSION = 8

  ELFMAG0 = 0x7f.byte
  ELFMAG1 = 'E'.byte
  ELFMAG2 = 'L'.byte
  ELFMAG3 = 'F'.byte

  ELFCLASS64 = 2.byte
  ELFDATA2LSB = 1.byte
  EV_CURRENT = 1.byte
  ELFOSABI_SYSV = 0.byte # Or ELFOSABI_LINUX

  ET_EXEC = 2.Elf64_Half
  EM_X86_64 = 62.Elf64_Half

  PT_LOAD = 1.Elf64_Word
  PF_X* = 1.Elf64_Word
  PF_W* = 2.Elf64_Word
  PF_R* = 4.Elf64_Word

  # Section types
  SHT_NULL = 0.Elf64_Word
  SHT_PROGBITS = 1.Elf64_Word
  SHT_NOBITS = 8.Elf64_Word

  # Section flags
  SHF_WRITE = 1.Elf64_Xword
  SHF_ALLOC = 2.Elf64_Xword
  SHF_EXECINSTR = 4.Elf64_Xword

proc initHeader*(entry: uint64): Elf64_Ehdr =
  result.e_ident[EI_MAG0] = ELFMAG0
  result.e_ident[EI_MAG1] = ELFMAG1
  result.e_ident[EI_MAG2] = ELFMAG2
  result.e_ident[EI_MAG3] = ELFMAG3
  result.e_ident[EI_CLASS] = ELFCLASS64
  result.e_ident[EI_DATA] = ELFDATA2LSB
  result.e_ident[EI_VERSION] = EV_CURRENT
  result.e_ident[EI_OSABI] = ELFOSABI_SYSV
  result.e_ident[EI_ABIVERSION] = 0

  result.e_type = ET_EXEC
  result.e_machine = EM_X86_64
  result.e_version = 1
  result.e_entry = entry
  result.e_phoff = 64 # Immediately after header
  result.e_shoff = 0
  result.e_flags = 0
  result.e_ehsize = 64
  result.e_phentsize = 56 # sizeof(Elf64_Phdr)
  result.e_phnum = 1
  result.e_shentsize = 64
  result.e_shnum = 0
  result.e_shstrndx = 0

proc initPhdr*(offset, vaddr, filesz, memsz: uint64; flags: uint32): Elf64_Phdr =
  result.p_type = PT_LOAD
  result.p_flags = flags
  result.p_offset = offset
  result.p_vaddr = vaddr
  result.p_paddr = vaddr
  result.p_filesz = filesz
  result.p_memsz = memsz
  result.p_align = 0x1000

proc initShdr*(name, typ, flags, address, offset, size, link, info, addralign, entsize: uint64): Elf64_Shdr =
  result.sh_name = name.Elf64_Word
  result.sh_type = typ.Elf64_Word
  result.sh_flags = flags.Elf64_Xword
  result.sh_addr = address.Elf64_Addr
  result.sh_offset = offset.Elf64_Off
  result.sh_size = size.Elf64_Xword
  result.sh_link = link.Elf64_Word
  result.sh_info = info.Elf64_Word
  result.sh_addralign = addralign.Elf64_Xword
  result.sh_entsize = entsize.Elf64_Xword

