
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
  --help, -h                show this help
  --version, -v             show version
"""

proc handleCmdLine() =
  var filename = ""
  var outfile = ""
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if filename.len == 0: filename = key
    of cmdLongOption, cmdShortOption:
      case key.normalize
      of "output", "o": outfile = val
      of "help", "h": quit(Usage, QuitSuccess)
      of "version", "v": quit(Version, QuitSuccess)
    of cmdEnd: assert false

  if filename.len == 0: quit(Usage, QuitSuccess)
  if outfile.len == 0: outfile = filename.changeFileExt("")

  assemble(filename, outfile)

when isMainModule:
  handleCmdLine()
