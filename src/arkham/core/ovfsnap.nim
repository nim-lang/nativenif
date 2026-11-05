#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `(ovf)` as a VALUE: snapshot the flag right after each `keepovf`.
##
## Both backends read `(ovf)` straight off what the `keepovf` op just left
## behind: x64 the hardware OF/CF, AArch64 a predicate in staging bridges. That
## is only sound while nothing in between writes the flags or reuses the
## bridges, which holds for the shape `emitCond` was written for — an
## `(if (elif (ovf) …))` after the op — and not for a value use anywhere else:
## `result = overflowFlag()`, `true == overflowFlag()`, `(r, overflowFlag())`.
## Between the op and such a read there can be any code (a `cmp`, an `and`, a
## call), so reading the flag lazily at the use is wrong.
##
## So this pass does what the C backend does with its `_ovf` local. In a proc
## that reads `(ovf)` in any other shape, it declares one `bool` local, puts
##
##     (asgn ovfTmp (ovf))
##
## IMMEDIATELY after every `keepovf`, and replaces each `(ovf)` read with
## `ovfTmp`. The snapshot is the one `(ovf)` value a backend sees, and it comes
## straight after the op, so `emitCondValue` reads it as a `seto`/`setb` (x64)
## or a `cmp`+`cset` (AArch64) with nothing in between. A proc whose every
## `(ovf)` is already a branch condition is left exactly as it was.

import nifcore, nifcdecl

proc countBranchShape(c: Cursor; n: var int) =
  ## Count the `(ovf)` nodes `emitCond` reads FIRST in condition `c`, before it
  ## evaluates anything that could touch the flags:
  ## `C ::= (ovf) | (not C) | (and C _) | (or C _)`.
  if c.kind != TagLit: return
  case c.exprKind
  of OvfC: inc n
  of NotC, AndC, OrC:
    var cc = c
    inc cc                                    # the first operand
    countBranchShape(cc, n)
  else: discard

proc scanProc(n: Cursor; total, branch: var int) =
  ## Count every `(ovf)` under `n`, and collect the ones in branch shape: the
  ## condition of an `if`'s FIRST `elif` (a later `elif` runs after the earlier
  ## conditions' compares).
  var stack = @[n]
  while stack.len > 0:
    let cur = stack.pop()
    if cur.kind != TagLit: continue
    if cur.exprKind == OvfC:
      inc total
      continue
    if cur.stmtKind == IfS:
      var ic = cur
      inc ic
      if ic.kind == TagLit and ic.substructureKind == ElifU:
        var cond = ic
        inc cond
        countBranchShape(cond, branch)
    var ch = cur
    ch.into:
      while ch.hasMore:
        if ch.kind == TagLit: stack.add ch
        skip ch

proc needsSnapshot(procDecl: Cursor): bool =
  var total = 0
  var branch = 0
  scanProc(procDecl, total, branch)
  result = total > branch

proc copyHead(dest: var TokenBuf; c: Cursor) =
  dest.openTag c.cursorTagId
  let li = rawLineInfo(c)
  if li.file.isValid: dest.appendLineInfo li

proc addSnapshot(dest: var TokenBuf; tmp: SymId) =
  ## `(asgn tmp (ovf))`
  dest.openTag TagId(ord(AsgnS))
  dest.addSymUse tmp
  dest.openTag TagId(ord(OvfC)); dest.closeTag()
  dest.closeTag()

proc addTmpDecl(dest: var TokenBuf; tmp: SymId) =
  ## `(var :tmp . (bool) (false))`
  dest.openTag TagId(ord(VarS))
  dest.addSymDef tmp
  dest.addDotToken()
  dest.openTag TagId(ord(BoolT)); dest.closeTag()
  dest.openTag TagId(ord(FalseC)); dest.closeTag()
  dest.closeTag()

proc rewrite(dest: var TokenBuf; c: var Cursor; tmp: SymId; declHere: bool) =
  ## Copy the node at `c`, replacing every `(ovf)` with `tmp` and appending the
  ## snapshot after every `keepovf`. `declHere`: `c` is the proc body, which gets
  ## the declaration of `tmp` first.
  if c.kind != TagLit:
    dest.addSubtree c
    skip c
  elif c.exprKind == OvfC:
    dest.addSymUse tmp
    let li = rawLineInfo(c)
    if li.file.isValid: dest.appendLineInfo li
    skip c
  else:
    copyHead(dest, c)
    if declHere: dest.addTmpDecl tmp
    c.into:
      while c.hasMore:
        let isKeep = c.kind == TagLit and c.stmtKind == KeepovfS
        rewrite(dest, c, tmp, false)
        if isKeep: dest.addSnapshot tmp
    dest.closeTag()

proc rewriteProc(dest: var TokenBuf; c: var Cursor; tmp: SymId) =
  ## `(proc :name params rettype pragmas body)`: only the body changes.
  copyHead(dest, c)
  c.into:
    var i = 0
    while c.hasMore:
      if i == 4 and c.kind == TagLit: rewrite(dest, c, tmp, true)
      else: (dest.addSubtree c; skip c)
      inc i
  dest.closeTag()

proc freshLocal(pool: Pool): SymId =
  ## A local the module does not spell anywhere.
  var d = 0
  while pool.syms.getKeyId("ovf`snap." & $d) != SymId(0): inc d
  result = pool.symId("ovf`snap", d)

proc snapshotOvfValues*(buf: var TokenBuf) =
  ## The pass described at the top of this module, over a whole parsed module.
  ## A module without such a proc is not copied.
  var procs: seq[int] = @[]                   # top-level child indices to rewrite
  block scan:
    var c = beginRead(buf)
    if c.kind == TagLit and c.stmtKind == StmtsS:
      var cc = c
      var i = 0
      cc.into:
        while cc.hasMore:
          if cc.kind == TagLit and cc.stmtKind == ProcS and needsSnapshot(cc):
            procs.add i
          skip cc; inc i
    endRead c
  if procs.len == 0: return
  let tmp = freshLocal(buf.pool)
  var dest = createTokenBuf(buf.len + 16 * procs.len, sharedPool = buf.pool,
                            sharedTags = buf.tags)
  var c = beginRead(buf)
  copyHead(dest, c)
  var i = 0
  var k = 0
  c.into:
    while c.hasMore:
      if k < procs.len and procs[k] == i:
        rewriteProc(dest, c, tmp)
        inc k
      else:
        dest.addSubtree c; skip c
      inc i
  dest.closeTag()
  while c.hasMore:                            # whatever follows the root
    dest.addSubtree c; skip c
  endRead c
  buf = move dest
