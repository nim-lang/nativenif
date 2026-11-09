#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Which aggregate call results may be built IN PLACE: the planner's answer to
## "may the callee write its result straight into the destination?".
##
## A call whose result the ABI returns through a hidden pointer writes that
## result while it runs. Handing it the destination's address is therefore sound
## only when the callee cannot observe the destination before it returns — else
## it sees its own half-built result through an alias (`x.f = g(x.f)` with `g`
## taking a big parameter as `haddr`). The back ends already build into a
## SYMBOL destination (a local, a parameter, a global); this module finds the
## two path destinations that are just as safe:
##
## * A store `(asgn D.f (call …))` inside a `(construct D …)` region. The
##   region's rules (nimony's `doc/internals/multi_join_ir.md`) say nothing reads
##   `D` before the region ends and no raise leaves it half built. `shoggoth opt`
##   may have rewritten the body since, so what this relies on is re-checked:
##   the region has no early exit and holds no pointer into `D`, and the call
##   borrows nothing that overlaps `D`.
## * The pair `(var :t . T (call …)) (asgn LV t)`, adjacent (no raise check sits
##   between) and with `t` used nowhere else, where `LV` is a field/element path
##   into a local or parameter whose address never escapes, or into a region
##   destination as above. That is how nimony binds every call whose
##   destination is not a symbol. The planner homes `t` AT `LV` (a `Mem`
##   location), and the copy becomes nothing.
##
## Only direct calls to arkham's own procs qualify: their convention is the
## proc's `md` by construction, so this module does not re-derive one (an
## extern's or a `stdcall` target's is the back end's `callConvOf`).

import std / [tables, sets]
import nifcore, nifcdecl, nifcoreparse
import asmslots, machinedesc, programs, typenav

type
  InPlace* = object
    calls*: HashSet[int]       ## call positions that may build into their `Mem` destination
    homes*: Table[int, Cursor] ## a folded temp's decl position (its SymbolDef) → the
                               ## path it lives in
    elided*: HashSet[int]      ## the folded temps' `(asgn LV t)` positions: no code

  Scan = object
    buf: ptr TokenBuf
    prog: ptr Program
    tc: TypeCtx
    md: MachineDesc
    regions: seq[Cursor]       ## destinations of the enclosing regions that hold
    escaped: HashSet[SymId]
    uses: Table[SymId, int]
    res: InPlace

proc sameTree(a, b: Cursor): bool =
  if a.kind == Symbol and b.kind == Symbol: return a.symId == b.symId
  toString(a, includeLineInfo = false) == toString(b, includeLineInfo = false)

proc isVoidType(t: Cursor): bool {.inline.} =
  cursorIsNil(t) or t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

proc pos(s: Scan; n: Cursor): int {.inline.} = cursorToPosition(s.buf[], n)

# ── paths and borrows ───────────────────────────────────────────────────────

proc isPath(lv: Cursor): bool {.inline.} =
  lv.kind == TagLit and lv.exprKind in {DotC, AtC}

proc rootSym(lv: Cursor): SymId =
  var p = lv
  while p.kind == TagLit and p.exprKind in {DotC, AtC}: inc p
  if p.kind == Symbol: p.symId else: NoSymId

proc pathWithin(p, d: Cursor): bool =
  ## Is `p` the path `d`, or a field/element of it?
  var p = p
  while true:
    if sameTree(p, d): return true
    if p.kind == TagLit and p.exprKind in {DotC, AtC}:
      inc p                                       # the base
    else:
      return false

proc isCallNode(n: Cursor): bool {.inline.} =
  n.kind == TagLit and (n.exprKind == CallC or n.stmtKind == CallS)

proc isBorrowArg(n: Cursor): bool {.inline.} =
  ## A `(haddr X)` that is DIRECTLY an argument of a call: the location a `var` /
  ## const parameter borrows for that one call (nimony's `haddr` vs `addr`).
  n.kind == TagLit and n.exprKind == HaddrC

proc borrowsInto(n, d: Cursor): bool =
  ## Does `n` take an address that overlaps the path `d`?
  if n.kind != TagLit: return false
  if n.exprKind in {AddrC, HaddrC}:
    var x = n; inc x
    if pathWithin(x, d) or pathWithin(d, x): return true
  var c = n
  c.into:
    while c.hasMore:
      if borrowsInto(c, d): return true
      skip c
  false

proc borrowsRoot(n: Cursor; root: SymId): bool =
  if n.kind != TagLit: return false
  if n.exprKind in {AddrC, HaddrC}:
    var p = n; inc p
    if rootSym(p) == root: return true
  var c = n
  c.into:
    while c.hasMore:
      if borrowsRoot(c, root): return true
      skip c
  false

proc scanUses(s: var Scan; n: Cursor; callArg = false) =
  ## `uses` and `escaped` for one proc body. An address ESCAPES when it becomes a
  ## value that can outlive one call: every `(addr X)`, and a `haddr` that is not
  ## itself a call argument — the inliner binds a const parameter's `haddr` to a
  ## pointer local, which a later call can be handed.
  case n.kind
  of Symbol: s.uses[n.symId] = s.uses.getOrDefault(n.symId) + 1
  of TagLit:
    if n.exprKind in {AddrC, HaddrC} and not (callArg and isBorrowArg(n)):
      var p = n; inc p
      while p.kind == TagLit and p.exprKind in {DotC, AtC}: inc p
      if p.kind == Symbol: s.escaped.incl p.symId
    let isCall = isCallNode(n)
    var c = n
    c.into:
      var first = true
      while c.hasMore:
        s.scanUses(c, callArg = isCall and not first)
        first = false
        skip c
  else: discard

# ── regions ─────────────────────────────────────────────────────────────────

proc collectLabels(n: Cursor; labels: var seq[SymId]) =
  if n.kind != TagLit: return
  if n.stmtKind == LabS:
    var t = n; inc t
    if t.kind == SymbolDef: labels.add t.symId
  var c = n
  c.into:
    while c.hasMore:
      collectLabels(c, labels)
      skip c

proc leavesEarly(n: Cursor; labels: seq[SymId]; loops: int): bool =
  ## Can control leave the region anywhere but at its end?
  if n.kind != TagLit: return false
  case n.stmtKind
  of RetS, RaiseS: return true
  of JmpS:
    var t = n; inc t
    return t.kind != Symbol or t.symId notin labels
  of BreakS:
    return loops == 0
  else: discard
  let inner = if n.stmtKind in {WhileS, LoopS}: loops + 1 else: loops
  var c = n
  c.into:
    while c.hasMore:
      if leavesEarly(c, labels, inner): return true
      skip c
  false

proc pinsDest(n, d: Cursor; callArg = false): bool =
  ## Does the body hold an address overlapping `d` as a VALUE — anything but a
  ## call's direct `haddr` argument (which `borrowsInto` checks per call)?
  if n.kind != TagLit: return false
  if n.exprKind in {AddrC, HaddrC} and not (callArg and isBorrowArg(n)):
    var x = n; inc x
    if pathWithin(x, d) or pathWithin(d, x): return true
  let isCall = isCallNode(n)
  var c = n
  c.into:
    var first = true
    while c.hasMore:
      if pinsDest(c, d, callArg = isCall and not first): return true
      first = false
      skip c
  false

proc regionHolds(d, body: Cursor): bool =
  var labels: seq[SymId] = @[]
  collectLabels(body, labels)
  not leavesEarly(body, labels, 0) and not pinsDest(body, d)

proc inRegion(s: Scan; lv, call: Cursor): bool =
  for d in s.regions:
    if pathWithin(lv, d): return not borrowsInto(call, d)
  false

# ── the call ────────────────────────────────────────────────────────────────

proc byRefNative(s: var Scan; call: Cursor; retType: var Cursor): bool =
  ## A direct call to one of arkham's own procs whose result travels by reference.
  if not (call.kind == TagLit and call.exprKind == CallC): return false
  var target = call; inc target
  if target.kind != Symbol or isIndirectCallTarget(s.tc, target): return false
  let sym = target.symId
  var ct = default(CallTarget)
  if s.prog.callTarget.hasKey(sym): ct = s.prog.callTarget.getOrDefault(sym)
  elif isForeignSym(s.prog[], sym): ct = foreignCallTarget(s.prog[], sym)
  else: return false
  if ct.extern or ct.syscall or ct.foreignAbi or ct.indirect or
     ct.memIntrin.len > 0 or ct.bitBuiltin.len > 0:
    return false
  retType = ct.retType
  if isVoidType(retType): return false
  let slot = slotOf(s.prog[], retType)
  slot.kind == AMem and s.md.passesByRef(slot.size)

proc sameType(s: var Scan; lv, retType: Cursor): bool =
  sameTree(resolveType(s.prog[], s.tc.getType(lv)), resolveType(s.prog[], retType))

# ── the walk ────────────────────────────────────────────────────────────────

proc privateRoot(s: Scan; lv: Cursor): bool =
  let r = rootSym(lv)
  r != NoSymId and s.tc.symType[].hasKey(r) and r notin s.escaped

proc tryFold(s: var Scan; s1, s2: Cursor): bool =
  ## `(var :t . T (call …)) (asgn LV t)`, see the top.
  if s1.kind != TagLit or s1.stmtKind != VarS: return false
  if s2.kind != TagLit or s2.stmtKind != AsgnS: return false
  var c = s1
  var t = NoSymId
  var tPos = -1
  var init = default(Cursor)
  c.into:
    if c.kind == SymbolDef:
      t = c.symId; tPos = s.pos(c)
    skip c; skip c; skip c                        # name, pragmas, type
    if c.hasMore: init = c; skip c
    while c.hasMore: skip c
  if t == NoSymId or cursorIsNil(init): return false
  var lv, rhs = default(Cursor)
  c = s2
  c.into:
    lv = c; skip c
    rhs = c; skip c
    while c.hasMore: skip c
  if not (rhs.kind == Symbol and rhs.symId == t): return false
  if not isPath(lv): return false
  if s.uses.getOrDefault(t) != 1 or t in s.escaped: return false
  var rt = default(Cursor)
  if not s.byRefNative(init, rt): return false
  let ok = (s.privateRoot(lv) and not borrowsRoot(init, rootSym(lv))) or
           s.inRegion(lv, init)
  if not ok or not s.sameType(lv, rt): return false
  s.res.homes[tPos] = lv
  s.res.elided.incl s.pos(s2)
  s.res.calls.incl s.pos(init)
  true

proc walk(s: var Scan; n: Cursor)

proc walkList(s: var Scan; n: Cursor) =
  var c = n
  c.into:
    while c.hasMore:
      var next = c; skip next
      if next.hasMore and s.tryFold(c, next):
        skip c; skip c
      else:
        s.walk(c)
        skip c

proc walk(s: var Scan; n: Cursor) =
  if n.kind != TagLit: return
  case n.stmtKind
  of ProcS, TypeS: discard
  of StmtsS, ScopeS: s.walkList(n)
  of ConstructS:
    var c = n
    c.into:
      let d = c; skip c
      let holds = regionHolds(d, c)
      if holds: s.regions.add d
      while c.hasMore:
        s.walk(c)
        skip c
      if holds: discard s.regions.pop()
  of AsgnS:
    # A store of a call straight into a region field (nimony writes these when a
    # region's value is a call; `LowerCasts` may also have bound it to a temp,
    # which `tryFold` takes).
    var c = n
    var lv, rhs = default(Cursor)
    c.into:
      lv = c; skip c
      rhs = c; skip c
      while c.hasMore: skip c
    var rt = default(Cursor)
    if isPath(lv) and s.byRefNative(rhs, rt) and s.inRegion(lv, rhs) and
       s.sameType(lv, rt):
      s.res.calls.incl s.pos(rhs)
  else:
    var c = n
    c.into:
      while c.hasMore:
        if c.kind == TagLit and (c.stmtKind != NoStmt or
                                 (c.exprKind == NoExpr and c.typeKind == NoType)):
          s.walk(c)                               # a statement list a level down
        skip c

proc findInPlace*(buf: var TokenBuf; procDecl: Cursor; prog: var Program;
                  md: MachineDesc; tc: TypeCtx): InPlace =
  ## The in-place decisions for one proc body (see the top).
  result = default(InPlace)
  if md.arch == Avr: return                      # its value core builds into slots only
  var s = Scan(buf: addr buf, prog: addr prog, tc: tc, md: md)
  s.scanUses(procDecl)
  var c = procDecl
  c.into:
    skip c; skip c; skip c; skip c               # name, params, return type, pragmas
    while c.hasMore:
      s.walk(c)
      skip c
  result = move s.res
