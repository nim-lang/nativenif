#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## A peephole pass over the FINISHED asm-NIF, run between the emitters and
## `render`.
##
## Why here and not in the emitters: the shapes below are produced by half a
## dozen unrelated paths (a store's rhs, an argument's marshalling, a `(var …)`
## initializer), each of which asks for a value in a register because that is
## almost always what it needs. Teaching every one of them the exception is six
## edits and a seventh path tomorrow; recognising the finished shape is one.
##
## Why it is safe: the pass rewrites the very NIF that nifasm then type-checks.
## It cannot produce a silent miscompile of the kind a bit-level peephole can —
## an operand it types wrongly is an assembly-time ERROR, naming the proc and
## the node. Every rule below is therefore stated as "this node is exactly that
## node with one operand substituted", never as a machine-level equivalence.
##
## The value table follows `shoggoth/trackers.nim`: facts are recorded per
## symbol and INVALIDATED at every point that could change them, and nothing is
## carried across a boundary where control flow could rejoin. This pass is the
## degenerate (straight-line) case of that — it never merges branches — so a
## fact lives only inside one sibling list, and the liveness question it needs
## is answered from the whole proc, not from the window.
##
## "From the whole PROC" is load-bearing and was not free: the scratch names are
## `tmpN.0`, and the counter behind them RESTARTS in every proc, so one SymId is
## every proc's `tmp0.0` at once. Answered from the whole buffer, `deadAfter`
## reads the next proc's `(rebind :tmp0.0 …)` — a definition, therefore benign —
## as proof that THIS proc's `tmp0.0` is dead, and folds away a store the value
## is still read from. `procLimit` is what confines the answer; see it for what
## that miscompiled.

import std / [tables, assertions]
import nifcore

when defined(arkhamPeepDbg):
  import std / syncio
  var dbgCand*, dbgPair*: int

type
  Occ = object
    pos: int         ## token index of a mention of the symbol
    benign: bool     ## a `(kill …)` operand or a definition — i.e. NOT a read

  Occs = Table[SymId, seq[Occ]]

proc collectOccs(buf: var TokenBuf; c: var Cursor; parentIsKill: bool; occs: var Occs) =
  ## Every mention of every symbol, in token order, tagged with whether it is a
  ## READ. `(kill x)` and a definition are not reads, and they are what lets a
  ## value be declared dead without a liveness analysis of our own: arkham kills
  ## each scratch binding at its last use, so the kill IS the liveness statement.
  case c.kind
  of Symbol:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c), benign: parentIsKill)
    inc c
  of SymbolDef:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c), benign: true)
    inc c
  of TagLit:
    let isKill = buf.tags.tagName(c.cursorTagId) == "kill"
    c.loopInto:
      collectOccs(buf, c, isKill, occs)
  else:
    inc c

proc deadAfter(occs: Occs; s: SymId; pos, limit: int): bool =
  ## Is `s` dead after token `pos`, asking only up to `limit` (the end of the
  ## enclosing proc)? True when its next mention there is not a read.
  ## Conservative by construction: an unknown symbol, one whose next mention is
  ## a plain operand, and one with no further mention IN THIS PROC all answer
  ## false.
  let lst = occs.getOrDefault(s)
  for o in lst:
    if o.pos > pos: return o.pos < limit and o.benign
  false                       # nothing follows: the binding outlives the proc's
                              # view here, so do not assume it is dead

proc movImmDest(buf: var TokenBuf; c: Cursor; dst: var SymId; imm: var Cursor): bool =
  ## Is `c` a `(mov <symbol> <immediate>)`? `imm` is left at the value node so the
  ## caller can copy it verbatim — an `(intlit)`, or `(nil)`, whose *type* is the
  ## whole point of copying rather than re-synthesizing it.
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore or b.kind != Symbol: return false
  dst = b.symId
  skip b
  if not b.hasMore: return false
  if b.kind == IntLit or b.kind == UIntLit or
     (b.kind == TagLit and buf.tags.tagName(b.cursorTagId) == "nil"):
    imm = b
    skip b
    result = not b.hasMore   # exactly two children
  else:
    result = false

proc immFoldable(imm: Cursor): bool =
  ## x86 carries an immediate into MEMORY only as a sign-extended imm32
  ## (`mov r/m64, imm32`), and whether a destination IS memory is not readable
  ## from the node: a bare symbol is a stack slot or a register home depending on
  ## a `(var …)` far above. So the width rule is applied unconditionally — a
  ## 64-bit constant keeps its materializing `mov`, which is one instruction
  ## either way. (Learned from nifasm: "Immediate too large for memory move".)
  case imm.kind
  of IntLit: imm.intVal >= low(int32).int64 and imm.intVal <= high(int32).int64
  of UIntLit: imm.intVal >= 0 and imm.intVal <= high(int32).int64
  else: true                       # `(nil)` is a zero

proc movFromSym(buf: var TokenBuf; c: Cursor; src: SymId; destNode: var Cursor): bool =
  ## Is `c` a `(mov <anything> src)` whose SOURCE is exactly the symbol `src`?
  ## `destNode` is left at the destination operand. "Exactly" matters: a source
  ## wrapped in a `(cast …)` is a different node and is left alone.
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore: return false
  destNode = b
  skip b
  if not b.hasMore or b.kind != Symbol or b.symId != src: return false
  skip b
  result = not b.hasMore

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            limit: int; folded: var int)

proc trNode(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            limit: int; folded: var int) =
  if c.kind == TagLit:
    # A `(proc …)` head is where the scratch-name counter restarts, so it is
    # also where the liveness question has to stop looking: everything inside
    # this subtree asks about `tmp0.0` and means THIS proc's.
    let inner =
      if buf.tags.tagName(c.cursorTagId) == "proc":
        cursorToPosition(buf, c) + subtreeWidth(c)
      else: limit
    dest.openTag c.cursorTagId
    c.loopInto:
      trList(buf, c, dest, occs, inner, folded)
    dest.closeTag()
  else:
    dest.addSubtree c
    inc c

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            limit: int; folded: var int) =
  ## One step of a sibling walk, with the one-node lookahead the rules need.
  var dst: SymId
  var immNode: Cursor
  if movImmDest(buf, c, dst, immNode):
    when defined(arkhamPeepDbg): inc dbgCand
    var la = c
    skip la
    var destNode: Cursor
    when defined(arkhamPeepDbg):
      if la.hasMore and movFromSym(buf, la, dst, destNode): inc dbgPair
    if la.hasMore and movFromSym(buf, la, dst, destNode) and
       immFoldable(immNode) and
       # PAST the consumer, not at it: the consumer's own source operand is a
       # mention of `dst`, and asking from its start position finds that one.
       deadAfter(occs, dst, cursorToPosition(buf, la) + subtreeWidth(la) - 1, limit):
      # `(mov D imm)` + `(mov X D)` with D dead ⇒ `(mov X imm)`. The scratch
      # register's `(rebind …)` above stays: it is a naming directive, costs no
      # machine code, and its `(kill …)` below still balances it.
      dest.openTag la.cursorTagId
      dest.addSubtree destNode
      dest.addSubtree immNode
      dest.closeTag()
      inc folded
      skip c                 # the materializing mov
      skip c                 # the consumer
      return
  trNode(buf, c, dest, occs, limit, folded)

proc peephole*(buf: var TokenBuf; immAnyDest: bool): int =
  ## Rewrite `buf` in place; returns the number of instructions removed.
  ##
  ## `immAnyDest` states that the target can carry an immediate into ANY `mov`
  ## destination. x86-64 can (`mov r/m, imm32`); AArch64 cannot — a store there
  ## is `str <reg>, [addr]` with no immediate form, so the constant has to reach
  ## a register regardless and folding would only move the work, not remove it.
  ## Since a bare-symbol destination is a stack slot or a register home depending
  ## on a `(var …)` far above, the two cannot be told apart HERE; the target
  ## answers for both.
  if not immAnyDest: return 0
  var occs = initTable[SymId, seq[Occ]]()
  block:
    var c = beginRead(buf)
    while c.hasMore:
      collectOccs(buf, c, false, occs)
    endRead c
  var res = createTokenBuf(buf.len, buf.pool, buf.tags)
  result = 0
  block:
    var c = beginRead(buf)
    while c.hasMore:
      trList(buf, c, res, occs, buf.len, result)
    endRead c
  buf = ensureMove res
  when defined(arkhamPeepDbg):
    stderr.writeLine "PEEP cand=" & $dbgCand & " pair=" & $dbgPair & " folded=" & $result
