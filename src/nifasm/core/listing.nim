#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `--listing:FILE` — one TSV row per asm-NIF instruction node, for the FINISHED
## image.
##
## Rows are recorded as the selector emits, then carried through every
## post-emission layout pass (`threadJumps` / `invertCondJumps` /
## `shortenX64Jumps`), each of which hands back an old->new byte-position map.
## Without that remapping every row would name a pre-relaxation address and the
## join to an execution profile would be silently wrong — which is the whole
## point of the file.
##
## `withListingRow` is also where the three instruction selectors stop being one
## strongly connected component: it is the wrapper `genInst` used to be, and as
## a template each selector expands its own copy instead of routing the
## recursion through a shared dispatcher.

import std / [os, strutils, algorithm]
import nifcore, nifcoreparse
import context

const
  ListingTextCap* = 300
    ## `--listing` renders each instruction node as NIF; a compound node (a whole
    ## `(ite …)`, a `(prepare …)` with every argument) can be enormous and its
    ## deeper rows carry the detail anyway, so the text is capped.

proc remapListing*(ctx: var GenContext; posMap: seq[int]) =
  ## Carry the listing through one of the post-emission layout passes
  ## (`threadJumps` / `invertCondJumps` / `shortenX64Jumps`), each of which
  ## returns an old→new byte-position map. Same treatment `gvarSites` and
  ## `entryStubOffset` gets — without it every row would name a pre-relaxation
  ## address and the join to a profile would be silently wrong.
  ##
  ## Those passes DELETE code (a threaded-away jump, a folded `jcc`/`jmp` pair).
  ## A deleted byte's map entry is the position the deletion collapsed to, so such
  ## a row comes out empty (`start == stop`) and is dropped here: its instruction
  ## is not in the image any more.
  if not ctx.listing: return
  var keep = 0
  for k in 0 ..< ctx.listRows.len:
    let s = posMap[ctx.listRows[k].start]
    let e = posMap[ctx.listRows[k].stop]
    if e > s:
      ctx.listRows[keep] = ctx.listRows[k]
      ctx.listRows[keep].start = s
      ctx.listRows[keep].stop = e
      inc keep
  ctx.listRows.setLen keep

proc remapUnwind*(ctx: var GenContext; posMap: seq[int]) =
  ## The debug-info twin of `remapListing`: carry every recorded proc range and
  ## CFI step through one layout pass. A `.symtab` entry or an FDE that still
  ## names a pre-relaxation address is worse than none — GDB would attribute the
  ## crash to a neighbouring proc rather than admit it does not know.
  for k in 0 ..< ctx.unwind.len:
    ctx.unwind[k].start = posMap[ctx.unwind[k].start]
    ctx.unwind[k].stop = posMap[ctx.unwind[k].stop]
    for s in 0 ..< ctx.unwind[k].steps.len:
      ctx.unwind[k].steps[s].at = posMap[ctx.unwind[k].steps[s].at]

proc writeListing*(ctx: GenContext; path: string; textVaddr: int) =
  ## `--listing:FILE`: one TSV row per asm-NIF instruction node that survived into
  ## the image, as `vaddr<TAB>len<TAB>depth<TAB>proc<TAB>nif`, sorted by address
  ## then by depth. Rows NEST: a compound node (`ite`, `loop`, `prepare`) covers
  ## its children's bytes too, so a consumer attributing one address picks the row
  ## with the GREATEST depth that contains it — that is the node the bytes came
  ## from. The shallower rows are kept because the enclosing construct is often
  ## what you actually want to blame.
  ##
  ## `textVaddr` is the virtual address `.text` byte 0 lands at, so the addresses
  ## match `--symmap` and a disassembly of the finished image with no arithmetic
  ## on the consumer's side.
  var rows = ctx.listRows
  rows.sort(proc (x, y: ListingRow): int =
    result = cmp(x.start, y.start)
    if result == 0: result = cmp(x.depth, y.depth))
  var s = newStringOfCap(rows.len * 96)
  s.add "# nifasm --listing: vaddr\tlen\tdepth\tproc\tnif\n"
  s.add "# rows NEST; attribute an address to the DEEPEST row containing it.\n"
  s.add "# .text base 0x" & toHex(textVaddr, 6) &
        (if textVaddr == 0: " (addresses are __text-RELATIVE on this format)\n" else: "\n")
  for r in rows:
    s.add "0x" & toHex(textVaddr + r.start, 6)
    s.add '\t'; s.add $(r.stop - r.start)
    s.add '\t'; s.add $r.depth
    s.add '\t'; s.add r.procName
    s.add '\t'; s.add r.text
    s.add '\n'
  writeFile(path, s)
