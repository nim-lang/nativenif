
import std / [parseopt, strutils, os]
import assembler
import elf32

const
  Version = "0.1.0"
  Usage = "nifasm - Native NIF Assembler " & Version & """

  (c) 2025 Andreas Rumpf

Usage:
  nifasm [options] file.nif

Options:
  --output:file, -o:file    specify output file name (default: file)
  --emit-obj, -c            emit a relocatable object (.o) for the system linker
                            instead of a standalone executable (macOS arm64 only)
  --symmap                  dump each generated proc's virtual address to stderr
                            (the static ELF carries no symbol table)
  --no-debug-info           omit the per-proc symbol names and unwind tables:
                            `.symtab`+`.eh_frame` (ELF), `LC_SYMTAB`+
                            `__TEXT,__eh_frame` (Mach-O), `.pdata`+`.xdata` (PE).
                            Nothing generated keeps a frame pointer, so these are
                            what lets a debugger — or, on Windows, the OS itself —
                            name a frame and walk past it. On ELF `.symtab`
                            costs only file size, while `.eh_frame` is mapped
                            read-only (valgrind rejects CFI it cannot map)
  --flash:ADDR              Cortex-M only: base of the code/rodata region
                            (default 0x00000000)
  --flash-size:N            its size; the finished image must fit (default 4M)
  --ram:ADDR                Cortex-M only: base of the SRAM region
                            (default 0x20000000)
  --ram-size:N              its size (default 64K)
  --stack-top:ADDR          initial MSP — vector-table word 0. Must lie inside
                            the RAM region (default: the top of it)
                            Sizes take a K/M/G suffix; addresses take 0x.
                            Together these are the two lines of linker script a
                            firmware image needs. An STM32F407, for instance, is
                            --flash:0x08000000 --flash-size:1M --ram-size:128K
  --listing:file            write one TSV row per asm-NIF instruction node —
                            vaddr, length, nesting depth, proc, and the node
                            rendered as NIF — for the FINISHED image, so an
                            execution profile joins to the source construct (and,
                            since a bound register renders as its variable name,
                            to the variable). Rows nest: attribute an address to
                            the deepest row containing it.
  --help, -h                show this help
  --version, -v             show version
"""

proc handleCmdLine() =
  var filename = ""
  var outfile = ""
  var symMap = false
  var emitObj = false
  var listing = ""
  var debugInfo = true
  var memMap = defaultMemoryMap()
  # `--stack-top` defaults to the top of RAM, so `--ram-size` moves it — but only
  # while it is still a default. Given explicitly, it stays where it was put no
  # matter which order the two flags arrive in.
  var stackTopGiven = false

  proc num(val, flag: string): uint32 =
    ## An address or a size. `0x` for hex, and a K/M/G suffix multiplies — the
    ## spellings a datasheet uses, since that is where the number is read off.
    var t = val.strip()
    var mult = 1'u64
    if t.len > 0:
      case t[^1]
      of 'k', 'K': mult = 1024'u64; t.setLen t.len - 1
      of 'm', 'M': mult = 1024'u64 * 1024; t.setLen t.len - 1
      of 'g', 'G': mult = 1024'u64 * 1024 * 1024; t.setLen t.len - 1
      else: discard
    var v: uint64
    try:
      v = if t.startsWith("0x") or t.startsWith("0X"): fromHex[uint64](t)
          else: parseBiggestUInt(t)
    except ValueError:
      quit "nifasm: " & flag & ": not a number: " & val
    v *= mult
    if v > 0xFFFF_FFFF'u64: quit "nifasm: " & flag & ": out of range: " & val
    memMap.given = true
    result = uint32(v)

  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if filename.len == 0: filename = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": outfile = val
      of "emit-obj", "emitobj", "c": emitObj = true
      of "symmap": symMap = true
      of "listing": listing = val
      of "no-debug-info", "nodebuginfo": debugInfo = false
      of "flash": memMap.flashBase = num(val, "--flash")
      of "flash-size", "flashsize": memMap.flashSize = num(val, "--flash-size")
      of "ram": memMap.ramBase = num(val, "--ram")
      of "ram-size", "ramsize": memMap.ramSize = num(val, "--ram-size")
      of "stack-top", "stacktop":
        memMap.stackTop = num(val, "--stack-top")
        stackTopGiven = true
      of "help", "h": quit(Usage, QuitSuccess)
      of "version", "v": quit(Version, QuitSuccess)
    of cmdEnd: assert false

  # The default stack top is the top of RAM, which `--ram` and `--ram-size` both
  # move — and either may be read after the other. So it is settled once, here,
  # when both are final; given explicitly it is not settled at all.
  if not stackTopGiven: memMap.stackTop = memMap.ramBase + memMap.ramSize
  let bad = validate(memMap)
  if bad.len > 0: quit "nifasm: " & bad

  if filename.len == 0: quit(Usage, QuitSuccess)
  if outfile.len == 0:
    outfile = filename.changeFileExt(if emitObj: "o" else: "")

  assemble(filename, outfile, symMap = symMap, emitObj = emitObj, listing = listing,
           debugInfo = debugInfo, memMap = memMap)

when isMainModule:
  handleCmdLine()
