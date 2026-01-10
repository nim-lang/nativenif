## NativeNif (c) 2026 Andreas Rumpf

import std / [assertions, syncio, tables, sets, intsets, strutils]
from std / os import changeFileExt, splitFile, extractFilename

import bitabs, lineinfos, nifstreams, nifcursors
import slots, analyser
import machine
import .. / nj / [model, kinds, blueprint]

type
  Context = object
    dest: TokenBuf
    intmSize, inConst, labels: int
    generatedTypes: HashSet[SymId]
    requestedSyms: HashSet[string]
    fields: Table[SymId, AsmSlot]
    types: Table[SymId, AsmSlot]
    locals: Table[SymId, Location]
    strings: Table[string, int]
    floats: Table[FloatId, int]
    vars: seq[SymId]
    returnLoc: Location
    exitProcLabel: int
    globals: Table[SymId, Location]
    rega: RegAllocator

proc initContext(intmSize: int): Context =
  result = Context(intmSize: intmSize, rega: initRegAllocator())

proc error(msg: string; n: Cursor) {.noreturn.} =
  write stdout, "[Error] "
  write stdout, msg
  writeLine stdout, toString(n, false)
  when defined(debug):
    writeStackTrace()
  quit 1

include register_allocator

proc generateNifasm*(m: sink Module; intmSize: int): TokenBuf =
  var c = initGenContext(m, intmSize)
  c.dest.buildTree StmtsT, NoLineInfo:
    var n = beginRead(m.stream)
    while n.kind != EofToken:
      trStmt c, c.dest, n
  result = move c.dest

# Helper to write to file
proc writeNifasm*(buf: TokenBuf; filename: string) =
  var s = nifstreams.createStream()
  for t in buf:
    s.add t
  s.add eofToken()
  writeFile filename, s.r