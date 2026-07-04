#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 1 of code generation: analyse local-variable usage in a proc body.
##
## For every local we record how often it is defined/used (weighted so that
## uses inside loops count more) and whether its address is taken. We also
## decide, per local, whether it may use a volatile (caller-saved) register
## (`AllRegs`): it may iff *no call point lies within its live range*. A call
## clobbers caller-saved registers only at the call, so the constraint on a
## value is an interval test — does the value's live range contain a call? —
## not a whole-scope one. A local whose range ends before the first call, or
## starts after the last, is call-free even if the scope has calls elsewhere.
## Loop-carried locals (`declInLoop`) are live across the back-edge, so we use
## their enclosing loop's span as the interval (any call in the loop crosses).
## Locals live across a call go to callee-saved registers or the stack. The
## register allocator consumes this.
##
## Ported from `src/wip/native/analyser.nim` to the nifcore cursor API; keyed
## by symbol *name* (nifcore has no stable SymId for inline-short symbols).

import std / [tables, sets, assertions]
import nifcore
import nifcdecl
import slots

type
  VarInfo* = object
    defs*, usages*: int        ## how often the variable is defined / used
    weight*: int               ## usages, but loop bodies count `LoopWeight`×
    props*: VarProps
    freeAfter*: int            ## token position after which the variable is dead:
                               ## the end of the statement (at the var's own scope
                               ## level) containing its last use. A single, coarse,
                               ## post-dominating free point — so a use inside an
                               ## `if`/`while` frees after the whole construct.
    frameIdx*: int             ## index of the var's declaring scope frame
    declInLoop*: bool          ## declared inside a loop → not early-freed (a later
                               ## loop-body decl could reuse the reg across the back-edge)
    liveStart*: int            ## token position of the var's declaration: the start of
                               ## its (coarse) live range, paired with `freeAfter` as the
                               ## end. A call strictly after `liveStart` and at/before
                               ## `freeAfter` crosses the range.
    loopLo*, loopHi*: int      ## for `declInLoop` vars: span of the innermost enclosing
                               ## loop, used as the live interval instead of
                               ## `(liveStart, freeAfter]` (the value is carried across the
                               ## back-edge, so any call in the loop crosses it)

  ProcAnalysis* = object
    vars*: Table[string, VarInfo]
    hasCall*: bool
    clobbersDivReg*: bool       ## body contains a div/mod → rdx is clobbered, so a
                                ## leaf param must not be homed there (x86-64 only)
    clobbersShiftReg*: bool     ## body contains a variable shift → rcx (cl) is
                                ## clobbered, so a leaf param must not be homed there
    arg0RetConflict*: bool      ## the FIRST integer/pointer param is read in a `(ret …)`
                                ## value OFF the leftmost-projection spine — i.e. behind a
                                ## binop / call / indexed access, where a sibling sub-result
                                ## may be evaluated into the accumulator first. On AArch64
                                ## arg0 == the return register (x0), so such a param is
                                ## clobbered before its use unless relocated to callee-saved.
                                ## A pure `p` / `(deref p)` / `(dot p f)` / `(cast _ p)` chain
                                ## reads the param FIRST and is safe (the common getter); only
                                ## off-spine reads set this. Consumed by `allocParams` (gated
                                ## on `arg == intRetReg`, so a no-op on x86-64 where ret≠arg0).

  Context = object
    inLoops, inAddr, inAsgnTarget, inArrayIndex: int
    arg0Name: string           ## name of the FIRST integer/pointer param (the one homed in
                               ## the return register on AArch64); "" if none / aggregate
    res: ProcAnalysis
    callPositions: seq[int]    ## token position of every call point (incl. tvar thunk
                               ## accesses) — the points where caller-saved regs die. A
                               ## local may use `AllRegs` iff none of these fall in its
                               ## live interval. Recorded in source order; scanned linearly.
    divPositions: seq[int]     ## token position of every div/mod (clobbers rdx). An
                               ## `AllRegs` local additionally earns `DivRegOk` (rdx is a
                               ## legal home) iff none of these fall in its live interval.
    shiftPositions: seq[int]   ## token position of every *variable* shift (clobbers rcx);
                               ## the `ShiftRegOk` analog of `divPositions`.
    loopStack: seq[tuple[lo, hi: int]]  ## spans of the enclosing loops (`WhileS`), so a
                               ## var declared in a loop can record its loop's extent
    stmtEnd: seq[int]          ## per open scope frame: end position of the
                               ## statement it is currently processing
    buf: ptr TokenBuf          ## for cursor → token-position mapping
    tvars: HashSet[string]     ## thread-local var names: a reference acts like a call

const
  LoopWeight = 3   ## assume a loop body runs ~3× for weighting purposes

proc posOf(c: Context; cur: Cursor): int {.inline.} =
  cursorToPosition(c.buf[], cur)

template iterStmts(c: var Context; n: var Cursor; body: untyped) =
  ## Walk a statement list, recording each child statement's end position in the
  ## *current* scope frame (`stmtEnd[^1]`) — the granularity of a local's coarse
  ## `freeAfter`. A `stmts` is NOT a variable scope, so it shares the enclosing
  ## scope's frame; only `scope` / the proc body push one (`scopeFrame`). This is
  ## what keeps `freeAfter` measured at the variable's *scope* level: a use after a
  ## sibling `(stmts)` has closed is legal (a `stmts` does not bound lifetime) and
  ## is handled correctly, instead of indexing a popped frame.
  n.into:
    while n.hasMore:
      var e = n; skip e                   # end position of this child statement
      c.stmtEnd[^1] = posOf(c, e)
      body

template scopeFrame(c: var Context; body: untyped) =
  ## Push the `stmtEnd` frame for a variable scope (a `scope`, or the proc body) —
  ## the unit `freeAfter`/`frameIdx` are measured in, one per `openScope`.
  c.stmtEnd.add 0
  body
  discard c.stmtEnd.pop()

proc analyse(c: var Context; n: var Cursor)

proc analyseChildren(c: var Context; n: var Cursor) =
  n.into:
    while n.hasMore: analyse(c, n)

proc analyseVarDecl(c: var Context; n: var Cursor) =
  ## `(var :name pragmas type value)` (also gvar/tvar/const).
  let declPos = posOf(c, n)
  n.into:
    assert n.kind == SymbolDef
    let vn = symName(n); inc n
    skip n                       # pragmas
    skip n                       # type
    let hasValue = n.kind != DotToken
    let inLoop = c.inLoops > 0
    var vi = VarInfo(defs: ord(hasValue), freeAfter: c.stmtEnd[^1],
                     frameIdx: c.stmtEnd.high, declInLoop: inLoop, liveStart: declPos)
    if inLoop: (vi.loopLo = c.loopStack[^1].lo; vi.loopHi = c.loopStack[^1].hi)
    c.res.vars[vn] = vi
    if hasValue: analyse(c, n)   # analyse the initializer
    else: inc n                  # consume the `.`

proc resultSpineWalk(c: var Context; n: var Cursor; onSpine: bool) =
  ## Walk a `(ret …)` value to find whether `arg0Name` is read OFF the leftmost-projection
  ## spine. The spine is the chain of value-preserving projections from the ret root —
  ## `deref`, `dot` (its base), `cast`/`conv` (its operand) — which the emitter evaluates
  ## FIRST, so a param read there is consumed before any sibling can clobber its register.
  ## Any other node (binop, call, indexed `at`/`pat`, constructor …) evaluates siblings
  ## that may land in the accumulator before the param is read → off-spine. (Read-only:
  ## advances `n` past the subtree but records nothing in `vars`.)
  case n.kind
  of Symbol:
    if c.arg0Name.len > 0 and symName(n) == c.arg0Name and not onSpine:
      c.res.arg0RetConflict = true
    inc n
  of TagLit:
    if n.stmtKind == NoStmt:
      case n.exprKind
      of DerefC:                        # `(deref p)` — its pointer operand stays on-spine
        n.into:
          var first = true
          while n.hasMore: (resultSpineWalk(c, n, onSpine and first); first = false)
      of DotC:                          # `(dot base field [depth])` — only `base` is a value
        n.into:
          if n.hasMore: resultSpineWalk(c, n, onSpine)   # base keeps the spine
          while n.hasMore: skip n                          # field name + optional depth
      of CastC, ConvC:                  # `(cast/conv Type operand)` — operand keeps the spine
        n.into:
          if n.hasMore: skip n                             # the target type
          if n.hasMore: resultSpineWalk(c, n, onSpine)     # the operand keeps the spine
          while n.hasMore: skip n
      else:                             # binop / call / at / pat / oconstr / … : all off-spine
        n.into:
          while n.hasMore: resultSpineWalk(c, n, false)
    else: skip n
  else: inc n

proc analyse(c: var Context; n: var Cursor) =
  case n.kind
  of Symbol:
    let vn = symName(n)
    if c.res.vars.hasKey(vn):
      let e = addr c.res.vars[vn]
      if c.inAsgnTarget > 0: inc e.defs
      else: inc e.usages
      # each use counts; uses inside loops count `LoopWeight`× per nesting level
      inc e.weight, 1 + c.inLoops * LoopWeight
      # extend the (coarse) live range to the end of the enclosing statement at the
      # variable's OWN scope level — so a use nested in an `if`/`while`, or after a
      # sibling `(stmts)` has closed, keeps it live until after that construct (a
      # single, post-dominating free point). `frameIdx` indexes the variable's
      # *scope* frame (not a `(stmts)` frame), so it is always a live frame here.
      # `frameIdx` is the var's declaring scope frame. Usually it is still open, but a
      # desugared loop can declare a local inside the loop's `(scope)` (a pushed frame)
      # and still reference it after the scope closes — at the loop's exit label in the
      # ENCLOSING frame (e.g. a `for`-cursor used in the loop's continuation). The var
      # has escaped its lexical scope, so its live range extends into the outer frame;
      # clamp to the outermost still-open frame so we extend liveness (never free early)
      # rather than index a popped frame.
      let fi = min(e.frameIdx, c.stmtEnd.high)
      e.freeAfter = max(e.freeAfter, c.stmtEnd[fi])
      if (c.inAddr + c.inArrayIndex) > 0:
        # arrays / address-taken locals cannot live in a register
        e.props.incl AddrTaken
    elif vn in c.tvars:
      # A thread-local access lowers to the TLV thunk call (clobbers x0/lr), so
      # treat it like a call point: locals live across it must avoid the volatile
      # argument registers.
      c.callPositions.add posOf(c, n)
    inc n
  of IntLit, UIntLit, FloatLit, CharLit, StrLit, Ident, SymbolDef, DotToken:
    inc n
  of TagLit:
    case n.stmtKind
    of NoStmt:
      case n.exprKind
      of AtC, PatC:
        n.into:
          inc c.inArrayIndex
          analyse(c, n)                 # the array/base
          dec c.inArrayIndex
          # The index is a pure value at ANY nesting depth — it is read into a
          # register, never address-taken. Reset the whole addressing context
          # (incl. `inArrayIndex`, which is still set when this `(at)` is itself the
          # base of an enclosing `(at)`, e.g. the inner index of `a[i][j]`), else a
          # local used as a nested index gets wrongly forced onto the stack.
          let oldA = c.inAddr; let oldT = c.inAsgnTarget; let oldX = c.inArrayIndex
          c.inAddr = 0; c.inAsgnTarget = 0; c.inArrayIndex = 0
          analyse(c, n)                 # the index
          c.inAddr = oldA; c.inAsgnTarget = oldT; c.inArrayIndex = oldX
      of AddrC:
        n.into:
          inc c.inAddr
          while n.hasMore: analyse(c, n)
          dec c.inAddr
      of DerefC:
        # `(deref p)` READS the pointer `p` as a value (into a register) — even
        # inside `(addr …)`/index/assignment context: `&((*p).field)`, `(*p)[i]`,
        # and `*p = v` all only LOAD `p`, never take the address of the variable
        # `p`. So clear the addressing context for the operand; otherwise a hot
        # pointer local (e.g. a TLSF chunk cursor `c`) is wrongly marked AddrTaken
        # and spilled to the stack instead of getting a register. Mirrors the
        # `(at …)` index reset above.
        n.into:
          let oldA = c.inAddr; let oldT = c.inAsgnTarget; let oldX = c.inArrayIndex
          c.inAddr = 0; c.inAsgnTarget = 0; c.inArrayIndex = 0
          while n.hasMore: analyse(c, n)
          c.inAddr = oldA; c.inAsgnTarget = oldT; c.inArrayIndex = oldX
      of NoExpr:
        # `elif`/`else`/`of` carry a condition and a statement body, and a `kv` carries
        # an `(oconstr …)` field VALUE — recurse so uses and calls inside `if`/`case`
        # branches AND object-constructor fields are seen. Missing the `kv` value made an
        # oconstr field that reads a pre-computed temp (e.g. `Error(left: x1, right: x2)`
        # where `x1`/`x2` are `=dup` results) invisible to liveness, so the temp was
        # freed at its def and its register reused by the next field's temp → both fields
        # ended up the same value. Other NoExpr nodes (types, etc.) carry no locals.
        case n.substructureKind
        of ElifU, ElseU, OfU, KvU: analyseChildren(c, n)
        else: skip n
      of DivC, ModC:
        c.res.clobbersDivReg = true     # idiv/div clobbers rdx
        c.divPositions.add posOf(c, n)  # ... at THIS point: denies rdx-as-home across it
        analyseChildren(c, n)
      of ShlC, ShrC:
        # A *variable* shift needs the count in cl, clobbering rcx; a constant shift
        # does not. The count is the second operand (after the result type).
        var probe = n; probe.into:
          skip probe                    # result type
          skip probe                    # value
          if probe.kind notin {IntLit, UIntLit, CharLit}:
            c.res.clobbersShiftReg = true
            c.shiftPositions.add posOf(c, n)  # denies rcx-as-home across it
          while probe.hasMore: skip probe
        analyseChildren(c, n)
      else:
        analyseChildren(c, n)           # generic expression: recurse
    of ScopeS:                          # a variable scope: its own `stmtEnd` frame
      scopeFrame(c):
        iterStmts(c, n): analyse(c, n)
    of StmtsS:                          # statement grouping only — shares the scope frame
      iterStmts(c, n): analyse(c, n)
    of CallS:
      c.callPositions.add posOf(c, n)
      analyseChildren(c, n)
    of VarS, GvarS, TvarS, ConstS:
      analyseVarDecl(c, n)
    of AsgnS:
      n.into:
        inc c.inAsgnTarget
        analyse(c, n)                   # the lvalue
        dec c.inAsgnTarget
        analyse(c, n)                   # the rvalue
    of RetS:
      if c.arg0Name.len > 0 and not c.res.arg0RetConflict:
        var probe = n                   # read-only spine scan (separate cursor)
        probe.into:
          while probe.hasMore: resultSpineWalk(c, probe, onSpine = true)
      analyseChildren(c, n)             # normal usage/liveness accounting
    of ProcS, TypeS:
      skip n                            # nested decls: not our locals
    of WhileS:
      var e = n; skip e               # span of the whole loop, for declInLoop vars
      c.loopStack.add (lo: posOf(c, n), hi: posOf(c, e))
      n.into:
        inc c.inLoops
        while n.hasMore: analyse(c, n)
        dec c.inLoops
      discard c.loopStack.pop()
    else:
      analyseChildren(c, n)             # if/case/ret/... : recurse
  else:
    inc n

proc analyseParams(c: var Context; params: var Cursor) =
  ## `(params (param :name pragmas type) …)` or a DotToken.
  if params.kind != TagLit: return
  var first = true
  params.into:
    while params.hasMore:
      params.into:                      # (param …)
        assert params.kind == SymbolDef
        let vn = symName(params); inc params
        if first:
          c.arg0Name = vn               # the first param — homed in x0 (== ret reg) on a64
          first = false
        # Params are never early-freed (the allocator manages them separately), so
        # pin their live range to the whole proc. `freeAfter == high(int)` also marks
        # them as params for the `AllRegs` finalize, which skips them (allocParams
        # decides their homes from the proc-level `hasCall`, not `AllRegs`).
        c.res.vars[vn] = VarInfo(defs: 1, freeAfter: high(int))
        while params.hasMore: skip params   # pragmas, type
        # (rest consumed by into epilogue)

proc analyseProc*(buf: var TokenBuf; procDecl: Cursor;
                  tvars: HashSet[string] = initHashSet[string]()): ProcAnalysis =
  ## `procDecl` is at a `(proc name params rettype pragmas body)`. `tvars` names
  ## the module's thread-locals so their uses force a call-like analysis. `buf` is
  ## the buffer `procDecl` points into (for cursor → position mapping).
  var c = Context(tvars: tvars, buf: addr buf)
  var n = procDecl
  assert n.stmtKind == ProcS
  n.into:
    inc n                               # name (SymbolDef)
    analyseParams(c, n)                 # params
    skip n                              # return type
    skip n                              # pragmas
    scopeFrame(c):                      # the proc-body scope frame (its `stmts`
      iterStmts(c, n): analyse(c, n)    # shares it rather than pushing its own)
  c.res.hasCall = c.callPositions.len > 0
  # Grant `AllRegs` (volatile/caller-saved eligible) to every local whose live
  # interval contains no call point. The interval is `(liveStart, freeAfter]`
  # for ordinary locals, or the enclosing-loop span for loop-carried ones. The
  # check is conservative: `freeAfter` over-approximates the range end and a
  # call within it denies `AllRegs`, so a missed-but-live-across-call case is
  # impossible (the unsafe direction). Params (`freeAfter == high`) are skipped.
  for name, vi in mpairs c.res.vars:
    if vi.freeAfter == high(int): continue
    let lo = if vi.declInLoop: vi.loopLo else: vi.liveStart
    let hi = if vi.declInLoop: vi.loopHi else: vi.freeAfter
    var crosses = false
    for p in c.callPositions:
      if p > lo and p <= hi: (crosses = true; break)
    if not crosses:
      vi.props.incl AllRegs
      # A call-free local can go further: rdx/rcx have a *fixed* instruction role
      # (div/mod, variable shift) but are otherwise free. If no such instruction
      # falls in the interval, that register's role never overlaps this local's
      # life, so it is a legal extra home — the register-count generalization of
      # `AllRegs` (same interval test, per fixed-role register). The `regOccupied`
      # assertions in the allocator are the safety net if this analysis is wrong.
      var crossesDiv = false
      for p in c.divPositions:
        if p > lo and p <= hi: (crossesDiv = true; break)
      if not crossesDiv: vi.props.incl DivRegOk
      var crossesShift = false
      for p in c.shiftPositions:
        if p > lo and p <= hi: (crossesShift = true; break)
      if not crossesShift: vi.props.incl ShiftRegOk
  result = ensureMove c.res
