#
#           Arkham — the board layout file
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `arkham --layout:board.nif` — where this board's memory is, what its console
## is, and where the stacks, the heap and the region nothing initializes go.
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
  WritesToKind* = enum
    ## What `write` is implemented as. Both names say what must be ATTACHED,
    ## which is the thing that is actually got wrong.
    wtDebugger   ## trap to a debug agent, which does the I/O on the host
    wtSerial     ## drive a UART; nothing attached but a wire

  Layout* = object
    ## The board, and only what is not already implied by it.
    ##
    ## There is no row saying which section lives where. Code and constants go
    ## where the IMAGE is; mutable storage goes where nothing is. Those are the
    ## definitions of the two regions rather than choices about them, and a row
    ## restating a definition is only a chance to write it down wrong.
    given*: bool                     ## a file was read at all
    flashStart*, flashSize*: uint32  ## the region the image SHIPS IN. Named for
                                     ## the part, not for a permission: MPS2's
                                     ## region at 0 is ZBT SRAM and perfectly
                                     ## writable. What matters is that its
                                     ## contents survive reset.
    sramStart*, sramSize*: uint32    ## the region that holds NOTHING at reset
    writesTo*: WritesToKind
    serialAddress*: uint32
    slotCount*: int
    slotSize*: uint32                ## a POWER OF TWO — it is the mask a thread
                                     ## reaches its own thread-locals with
    tvarSize*: uint32                ## reserved at the TOP of every slot
    heapSize*: uint32                ## 0 when the file reserves no heap
    noinitSize*: uint32              ## bytes at the TOP of sram that the startup
                                     ## code leaves ALONE. 0 when the file keeps
                                     ## nothing back, which is the default: a
                                     ## region nothing initializes is a liability
                                     ## unless something means to read it.
    core*: int                       ## which slot this image boots on

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

proc parseLayout*(path: string): Layout =
  ## Read and CHECK the file. Everything that can be wrong about a layout is
  ## wrong here, by name, and not later as an image that boots into nothing.
  result = Layout(given: true, writesTo: wtDebugger, slotCount: 1, core: 0)
  var buf = parseFromFile(path, sharedTags = asmTags)
  var n = beginRead(buf)
  if n.kind != TagLit or tagToNifasmDecl(asmTag(n)) != LayoutD:
    fail path & ": expected a (layout …) tree"
  var sawFlash, sawSram, sawStacks = false
  n.into:
    while n.hasMore:
      if n.kind != TagLit: fail "expected a declaration inside (layout …)"
      let d = tagToNifasmDecl(asmTag(n))
      var e = n
      skip n
      case d
      of FlashD:
        e.into:
          result.flashStart = readStartAddress(e)
          result.flashSize = readSize(e)
          while e.hasMore: skip e
        sawFlash = true
      of SramD:
        e.into:
          result.sramStart = readStartAddress(e)
          result.sramSize = readSize(e)
          while e.hasMore: skip e
        sawSram = true
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
            result.tvarSize = readSize(e)
            while e.hasMore: skip e
          while e.hasMore: skip e
        sawStacks = true
      of HeapD:
        e.into:
          result.heapSize = readSize(e)
          while e.hasMore: skip e
      of NoinitD:
        e.into:
          result.noinitSize = readSize(e)
          while e.hasMore: skip e
      of CoreD:
        e.into:
          if e.hasMore and e.kind == IntLit: (result.core = int(e.intVal); inc e)
          while e.hasMore: skip e
      else:
        fail "unexpected `" & $d & "` inside (layout …)"
  endRead n
  if not sawFlash: fail "no (flash …): nothing says where the image ships"
  if not sawSram: fail "no (sram …): nothing says where mutable storage goes"
  if not sawStacks: fail "no (stacks …)"

proc validate*(l: Layout): string =
  ## `""` when the layout describes a board that could exist. Separate from the
  ## parse so that every complaint is about the WHOLE file: "the stacks do not fit
  ## in sram" is not a statement any one row can make.
  if l.flashSize == 0: return "the flash region has size 0"
  if l.sramSize == 0: return "the sram region has size 0"
  if l.flashStart.uint64 + l.flashSize.uint64 > 0x1_0000_0000'u64:
    return "the flash region runs past the end of the address space"
  if l.sramStart.uint64 + l.sramSize.uint64 > 0x1_0000_0000'u64:
    return "the sram region runs past the end of the address space"
  if l.flashStart < l.sramStart + l.sramSize and
     l.sramStart < l.flashStart + l.flashSize:
    return "the flash and sram regions overlap"
  # THE constraint the whole thread-local scheme rests on. A thread finds its own
  # slot by masking SP, so the slot size must be a power of two AND every slot
  # must be aligned to it — which is what lets the image writer place the stacks
  # on a multiple of the size rather than merely inside the region.
  if l.slotSize == 0 or (l.slotSize and (l.slotSize - 1)) != 0:
    return "the stack slot size must be a power of two — a thread reaches its " &
           "thread-locals by masking SP with it"
  if l.tvarSize >= l.slotSize:
    return "the thread-local reservation fills the whole stack slot"
  if l.core < 0 or l.core >= l.slotCount:
    return "(core " & $l.core & ") is outside the " & $l.slotCount & " slot(s) declared"
  # Whether everything FITS is deliberately not asked here: how many bytes of
  # globals the module has is a link-time fact, so nifasm owns that question and
  # answers it with all of the numbers rather than some of them. What is asked is
  # only the degenerate case, which no amount of link-time information could
  # rescue — and which would otherwise wrap `sramEnd - noinitSize` past zero and
  # be read as a region somewhere near the top of the address space.
  if l.noinitSize >= l.sramSize:
    return "the noinit region is " & $l.noinitSize & " bytes of a " & $l.sramSize &
           "-byte sram region, leaving nothing for the image to establish"
  return ""
