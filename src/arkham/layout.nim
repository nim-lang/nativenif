#
#           Arkham — the board layout file
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `arkham --layout:board.nif` — where this board's memory is, what its console
## is, and where the stacks and the heap go.
##
## It replaces a command-line namespace that could not have grown into this:
## regions are a LIST, a stack slot has a size and a thread-local reservation and
## a count, and none of that survives being flattened into `--flag:value` pairs.
##
## ONE reader. arkham parses the file and forwards it into the asm-NIF as a
## `(layout …)` declaration, so nifasm — which needs the regions to place
## segments — reads a tree it already has a vocabulary for instead of opening the
## file a second time. Two parsers of one file is two chances to disagree about
## what a region means, and the disagreement would surface as an image that loads
## at the wrong address.
##
## The file is in nifasm's tag vocabulary (`doc/instructions.md`), which is what
## makes that forwarding a splice rather than a translation.

import std / [strutils]
import nifcore, nifcoreparse
import "../nifasm" / [model, tagconv, tagpool, tags]

proc asmTag(n: Cursor): TagEnum = cast[TagEnum](uint32(resolvedTagId(n)))
  ## `resolvedTagId`, not `cursorTagId`: asm-NIF's vocabulary overflows the 9-bit
  ## tag field and the mnemonics past it carry their id in a leading child. Same
  ## reading as `assembler.tag`, and this file is in that same vocabulary.

var asmTags: TagPool = createAsmTagPool()

type
  RegionKind* = enum
    rkRom     ## holds what the image ships with — flash, or a ZBT SRAM at 0
    rkRam     ## holds nothing at reset

  Region* = object
    name*: string
    kind*: RegionKind
    origin*: uint32
    size*: uint32

  SectionKind* = enum
    ## NIF's and Nimony's own words, not the linker's. `gvar` covers the
    ## initialized globals AND the zeroed ones on purpose: whether a global ships
    ## with a value is not something a LAYOUT has an opinion about, and the split
    ## inside the region is the image writer's (see `doc/cortex_m.md` M6a).
    secCode, secConst, secGvar

  WritesToKind* = enum
    ## What `write` is implemented as. Both names say what must be ATTACHED,
    ## which is the thing that is actually got wrong.
    wtDebugger   ## trap to a debug agent, which does the I/O on the host
    wtSerial     ## drive a UART; nothing attached but a wire

  Layout* = object
    given*: bool                     ## a file was read at all
    regions*: seq[Region]
    place*: array[SectionKind, string]   ## section → region name ("" = unset)
    writesTo*: WritesToKind
    serialAddress*: uint32
    stacksRegion*: string
    slotCount*: int
    slotSize*: uint32                ## a POWER OF TWO — it is the mask a thread
                                     ## reaches its own TLS with
    tlsSize*: uint32                 ## reserved at the TOP of every slot
    heapRegion*: string
    heapSize*: uint32
    core*: int                       ## which slot this image boots on

proc regionByName*(l: Layout; name: string): int =
  for i, r in l.regions:
    if r.name == name: return i
  -1

proc fail(msg: string) {.noreturn.} =
  quit "arkham --layout: " & msg, QuitFailure

proc readSize(n: var Cursor): uint32 =
  ## `(bytes N)` / `(kilobytes N)` / `(megabytes N)`. A size is a TAGGED quantity
  ## because NIF has no `4K` literal and because a bare number in a layout file is
  ## exactly the place where a reader guesses the unit and is wrong.
  if n.kind != TagLit: fail "expected a size: (bytes N), (kilobytes N) or (megabytes N)"
  let t = tagToNifasmExpr(asmTag(n))
  var mult = 0'u64
  case t
  of BytesX: mult = 1'u64
  of KilobytesX: mult = 1024'u64
  of MegabytesX: mult = 1024'u64 * 1024
  else: fail "expected a size: (bytes N), (kilobytes N) or (megabytes N)"
  var got = 0'u64
  var seen = false
  n.into:
    if n.hasMore and n.kind == IntLit:
      got = uint64(n.intVal) * mult
      seen = true
      inc n
    while n.hasMore: skip n
  if not seen: fail "a size takes one integer"
  if got > 0xFFFF_FFFF'u64: fail "size out of range"
  result = uint32(got)

proc readStartAddress(n: var Cursor): uint32 =
  if n.kind != TagLit or tagToNifasmExpr(asmTag(n)) != StartAddressX:
    fail "expected (startAddress <address>)"
  var got = 0'u64
  var seen = false
  n.into:
    if n.hasMore and n.kind == IntLit:
      got = uint64(n.intVal); seen = true; inc n
    while n.hasMore: skip n
  if not seen: fail "(startAddress …) takes one address"
  if got > 0xFFFF_FFFF'u64: fail "origin out of range"
  result = uint32(got)

proc sectionOf(name: string): SectionKind =
  case name
  of "code": secCode
  of "const": secConst
  of "gvar": secGvar
  else: fail "unknown section `" & name & "` — expected code, const or gvar"

proc parseLayout*(path: string): Layout =
  ## Read and CHECK the file. Everything that can be wrong about a layout is
  ## wrong here, by name, and not later as an image that boots into nothing.
  result = Layout(given: true, writesTo: wtDebugger, slotCount: 1, core: 0)
  var buf = parseFromFile(path, sharedTags = asmTags)
  var n = beginRead(buf)
  if n.kind != TagLit or tagToNifasmDecl(asmTag(n)) != LayoutD:
    fail path & ": expected a (layout …) tree"
  n.into:
    while n.hasMore:
      if n.kind != TagLit: fail "expected a declaration inside (layout …)"
      let d = tagToNifasmDecl(asmTag(n))
      var e = n
      skip n
      case d
      of RegionD:
        var r = Region()
        e.into:
          if e.kind != Ident: fail "(region …) needs a name"
          r.name = e.strVal; inc e
          if e.kind != Ident: fail "(region …) needs `rom` or `ram`"
          case e.strVal
          of "rom": r.kind = rkRom
          of "ram": r.kind = rkRam
          else: fail "a region is `rom` or `ram`, not `" & e.strVal & "`"
          inc e
          r.origin = readStartAddress(e)
          r.size = readSize(e)
          while e.hasMore: skip e
        if result.regionByName(r.name) >= 0: fail "duplicate region `" & r.name & "`"
        result.regions.add r
      of PlaceD:
        var sec = secCode
        var reg = ""
        e.into:
          if e.kind != Ident: fail "(place …) needs a section name"
          sec = sectionOf(e.strVal); inc e
          if e.kind != Ident: fail "(place …) needs a region"
          reg = e.strVal; inc e
          while e.hasMore: skip e
        result.place[sec] = reg
      of WritesToD:
        e.into:
          if e.kind != Ident: fail "(writesTo …) needs `debugger` or `serial`"
          case e.strVal
          of "debugger": result.writesTo = wtDebugger; inc e
          of "serial":
            result.writesTo = wtSerial; inc e
            result.serialAddress = readStartAddress(e)
          else: fail "`write` goes to `debugger` or `serial`, not `" & e.strVal & "`"
          while e.hasMore: skip e
      of StacksD:
        e.into:
          if e.kind != Ident: fail "(stacks …) needs a region"
          result.stacksRegion = e.strVal; inc e
          if e.kind != TagLit or tagToNifasmExpr(asmTag(e)) != SlotsX:
            fail "(stacks …) needs (slots N)"
          var cnt = 0
          e.into:
            if e.hasMore and e.kind == IntLit: (cnt = int(e.intVal); inc e)
            while e.hasMore: skip e
          if cnt < 1: fail "(slots N) must be at least 1"
          result.slotCount = cnt
          result.slotSize = readSize(e)
          if e.kind != TagLit or tagToNifasmExpr(asmTag(e)) != TvarX:
            fail "(stacks …) needs (tvar <size>)"
          e.into:
            result.tlsSize = readSize(e)
            while e.hasMore: skip e
          while e.hasMore: skip e
      of HeapD:
        e.into:
          if e.kind != Ident: fail "(heap …) needs a region"
          result.heapRegion = e.strVal; inc e
          result.heapSize = readSize(e)
          while e.hasMore: skip e
      of CoreD:
        e.into:
          if e.hasMore and e.kind == IntLit: (result.core = int(e.intVal); inc e)
          while e.hasMore: skip e
      else:
        fail "unexpected `" & $d & "` inside (layout …)"
  endRead n

proc validate*(l: Layout): string =
  ## `""` when the layout describes a board that could exist. Separate from the
  ## parse so that every complaint is about the WHOLE file: "the stacks do not fit
  ## in sram" is not a statement any one row can make.
  if l.regions.len == 0: return "no regions"
  for i, r in l.regions:
    if r.size == 0: return "region `" & r.name & "` has size 0"
    if r.origin.uint64 + r.size.uint64 > 0x1_0000_0000'u64:
      return "region `" & r.name & "` runs past the end of the address space"
    for j in 0 ..< i:
      let o = l.regions[j]
      if r.origin < o.origin + o.size and o.origin < r.origin + r.size:
        return "regions `" & r.name & "` and `" & o.name & "` overlap"
  for s in SectionKind:
    if l.place[s].len == 0: return "no (place " & ($s).substr(3).toLowerAscii & " …)"
    if l.regionByName(l.place[s]) < 0:
      return "(place …) names region `" & l.place[s] & "`, which is not declared"
  for s in [secCode, secConst]:
    if l.regions[l.regionByName(l.place[s])].kind != rkRom:
      return "`" & ($s).substr(3).toLowerAscii & "` ships with the image, so it " &
             "must be placed in a `rom` region"
  if l.regions[l.regionByName(l.place[secGvar])].kind != rkRam:
    return "`gvar` must be placed in a `ram` region"
  if l.stacksRegion.len == 0: return "no (stacks …)"
  let si = l.regionByName(l.stacksRegion)
  if si < 0: return "(stacks …) names region `" & l.stacksRegion & "`, which is not declared"
  if l.regions[si].kind != rkRam: return "the stacks must be in a `ram` region"
  # THE constraint the whole TLS scheme rests on. A thread finds its own slot by
  # masking SP, so the slot size must be a power of two AND every slot must be
  # aligned to it — which is what makes `slotsBase` below a multiple of the size
  # rather than merely inside the region.
  if l.slotSize == 0 or (l.slotSize and (l.slotSize - 1)) != 0:
    return "the stack slot size must be a power of two — a thread reaches its " &
           "thread-locals by masking SP with it"
  if l.tlsSize >= l.slotSize:
    return "the thread-local reservation fills the whole stack slot"
  if l.core < 0 or l.core >= l.slotCount:
    return "(core " & $l.core & ") is outside the " & $l.slotCount & " slot(s) declared"
  if l.heapRegion.len > 0:
    let hi = l.regionByName(l.heapRegion)
    if hi < 0: return "(heap …) names region `" & l.heapRegion & "`, which is not declared"
    if l.regions[hi].kind != rkRam: return "the heap must be in a `ram` region"
    if l.heapSize == 0: return "the heap has size 0"
  return ""

