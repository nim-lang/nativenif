
import std / [parseopt, strutils, os]
import assembler

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
                            name a frame and walk past it. They cost only file
                            size on ELF and Mach-O, where nothing loads them
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
      of "help", "h": quit(Usage, QuitSuccess)
      of "version", "v": quit(Version, QuitSuccess)
    of cmdEnd: assert false

  if filename.len == 0: quit(Usage, QuitSuccess)
  if outfile.len == 0:
    outfile = filename.changeFileExt(if emitObj: "o" else: "")

  assemble(filename, outfile, symMap = symMap, emitObj = emitObj, listing = listing,
           debugInfo = debugInfo)

when isMainModule:
  handleCmdLine()
