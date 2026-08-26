#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The Cortex-M BOARD, as the assembler needs it: where this board's memory is,
## and which handler sits in which architectural vector slot.
##
## arkham forwards the `--layout:` file verbatim into the asm-NIF rather than
## nifasm reading it a second time, so what arrives here is a `(layout …)` tree
## and an `(interrupts …)` list — reduced to the few numbers PLACEMENT actually
## needs (`context.CortexMBoard`) and a table of slot -> handler the image
## writer bakes in with the Thumb bit set.

import nifcore
import "../core" / [context, cursors, diagnostics, model, tagconv, decls, modules, typesem]

const
  CoreInterruptWords* = 16
    ## Words 0..15: MSP, reset, and every ARCHITECTURAL exception through SysTick.
    ## A table is never shorter than this once it is a table at all, because those
    ## exceptions do not have to be enabled to be TAKEN — a fault reaching past the
    ## end of a shorter table would read whatever code follows and branch into it.
    ## A word no handler claimed stays zero, which faults, escalates, and locks the
    ## core up: deterministic, findable on a debugger, and not arbitrary execution.
  MinInterruptWords* = 2
    ## What an image with NO handler carries: the two words a cold core reads. The
    ## fault-slot argument above does not reach it — there is nothing to put in
    ## those slots, and every image ever built by this assembler has had two.

proc readLayoutSize(n: var Cursor): uint32 =
  ## `(bytes N)` — the only unit that reaches here. arkham normalizes
  ## `(kilobytes …)`/`(megabytes …)` away before forwarding, so this reader never
  ## multiplies and can never disagree with the one that did.
  if n.kind != TagLit or tagToNifasmExpr(n.tag) != BytesX:
    error("expected (bytes N) in (layout …)", n)
  var got = 0'u32
  n.into:
    if n.hasMore and n.kind == IntLit: (got = uint32(getInt(n)); inc n)
    while n.hasMore: skip n
  result = got

proc readLayoutStartAddress(n: var Cursor): uint32 =
  if n.kind != TagLit or tagToNifasmExpr(n.tag) != StartAddressX:
    error("expected (startAddress N) in (layout …)", n)
  var got = 0'u32
  n.into:
    if n.hasMore and n.kind == IntLit: (got = uint32(getInt(n)); inc n)
    while n.hasMore: skip n
  result = got

proc handleLayout*(n: var Cursor; ctx: var GenContext) =
  ## `(layout …)` — the board, as arkham read it out of the `--layout:` file.
  ##
  ## nifasm does not open that file. It reads this, which arkham produced from it
  ## with the sizes normalized: one description, one place it is interpreted, and
  ## no way for the two tools to disagree about where a region is.
  ##
  ## Nothing here says which section goes where, because nothing needs to: code
  ## and constants go in the region the image SHIPS IN, mutable storage in the one
  ## that holds nothing at reset. Those are what the two regions ARE.
  if ctx.arch != Arch.CortexM:
    error("(layout …) is a Cortex-M declaration", n)
  n.into:
   while n.hasMore:
    if n.kind != TagLit: error("expected a declaration inside (layout …)", n)
    let d = tagToNifasmDecl(n.tag)
    var e = n
    skip n
    case d
    of FlashD:
      e.into:
        ctx.board.flashStart = readLayoutStartAddress(e)
        ctx.board.flashSize = readLayoutSize(e)
        while e.hasMore: skip e
    of SramD:
      e.into:
        ctx.board.sramStart = readLayoutStartAddress(e)
        ctx.board.sramSize = readLayoutSize(e)
        while e.hasMore: skip e
    of StacksD:
      e.into:
        if e.kind == TagLit and tagToNifasmExpr(e.tag) == SlotsX:
          e.into:
            if e.hasMore and e.kind == IntLit: (ctx.board.slots = int(getInt(e)); inc e)
            while e.hasMore: skip e
        ctx.board.slotSize = readLayoutSize(e)
        if e.kind == TagLit and tagToNifasmExpr(e.tag) == TvarX:
          e.into:
            ctx.board.tvarSize = readLayoutSize(e)
            while e.hasMore: skip e
        while e.hasMore: skip e
    of HeapD:
      e.into:
        ctx.board.heapSize = readLayoutSize(e)
        while e.hasMore: skip e
    of NoinitD:
      e.into:
        ctx.board.noinitSize = readLayoutSize(e)
        while e.hasMore: skip e
    of CoreD:
      e.into:
        if e.hasMore and e.kind == IntLit: (ctx.board.core = int(getInt(e)); inc e)
        while e.hasMore: skip e
    else: error("unexpected declaration inside (layout …)", e)
  ctx.board.given = true

proc handleInterrupts*(n: var Cursor; ctx: var GenContext) =
  ## `(interrupts (irq N S)*)` — the Cortex-M interrupt table, as arkham resolved
  ## it.
  ##
  ## The SLOT is arkham's answer: which architectural entry a name denotes is a
  ## machine-model fact, so nothing here maps names. What this owns is the
  ## consequence — the table's size, and an address in each word it was given.
  ##
  ## Every handler is marked USED. Nothing in the program calls one — it is
  ## reached only through this table — so without that it is dropped by the same
  ## reachability walk that drops any unreferenced proc, and the image gets a
  ## table word pointing at a proc that was never emitted.
  if ctx.arch != Arch.CortexM:
    error("(interrupts …) is a Cortex-M declaration", n)
  # `into`, not a bare `inc`: `hasMore` on an unbounded cursor keeps reading into
  # the declaration's SIBLINGS, so the loop below ran on into the next `(proc …)`.
  n.into:
   while n.hasMore:
    if n.kind != TagLit or tagToNifasmDecl(n.tag) != IrqD:
      error("Expected (irq <slot> <handler>) in (interrupts …)", n)
    var e = n
    skip n
    e.into:
      if e.kind != IntLit: error("Expected an interrupt slot number", e)
      let slot = int(getInt(e))
      inc e
      if e.kind != Symbol: error("Expected a handler symbol in (irq …)", e)
      # Slots 0 and 1 are the image writer's: word 0 is the initial MSP, a value
      # and not a handler, and word 1 is reset, which IS the entry proc. A second
      # claim on either would be silently overwritten by the writer.
      if slot < 2:
        error("interrupt slot " & $slot & " is the image writer's (initial MSP, reset)", e)
      let name = getSym(e)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, e)
      if sym == nil: error("Unknown interrupt handler: " & name, e)
      ctx.markSymbolUsed(name)
      ctx.interrupts.add (slot, sym)
      inc e
