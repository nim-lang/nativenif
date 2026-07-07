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
                               ## its PRECISE last-use position (max token position over
                               ## the variable's occurrences), extended to the end of any
                               ## enclosing loop the declaration sits outside of (back-edge
                               ## safety — see `declLoopDepth`). Branches need no special
                               ## handling: freeing strictly after the textually-last use
                               ## means no control-flow path can read the value afterward.
    frameIdx*: int             ## index of the var's declaring scope frame
    declLoopDepth*: int        ## `loopStack.len` at the declaration: how many loops enclose
                               ## the decl. A use nested in a DEEPER loop (`loopStack.len`
                               ## greater) is carried across that loop's back-edge, so
                               ## `freeAfter` extends to `loopStack[declLoopDepth].hi` — the
                               ## outermost enclosing loop the decl is NOT inside.
    declInLoop*: bool          ## declared inside a loop → not early-freed (a later
                               ## loop-body decl could reuse the reg across the back-edge)
    liveStart*: int            ## token position of the var's declaration: the start of
                               ## its (coarse) live range, paired with `freeAfter` as the
                               ## end. A call strictly after `liveStart` and at/before
                               ## `freeAfter` crosses the range.
    lastUsePos*: int           ## PRECISE last-use position, tracked for ALL vars incl.
                               ## params (whose `freeAfter` is pinned to `high`).
    usedAfterCall*: bool       ## a use occurred while a call had already RETURNED
                               ## (`completedCalls > 0`) → the value must survive that call.
                               ## Disqualifies a param from `ArgResident`.
    argUnsafe*: bool           ## used as a call TARGET, or as a call ARGUMENT at an ABI
                               ## position ≠ its own param index, or in a non-clean call
                               ## (ordinals may shift). Disqualifies `ArgResident`.
    paramIdx*: int             ## a register param's 0-based ABI index (arg-GPR ordinal) in
                               ## a clean-signature proc; -1 for locals and non-clean procs.
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
    atomicPositions: seq[int]  ## token position of every call the emitter INLINES as an
                               ## atomic sequence (`emitAtomic2`). It clobbers only rax + its
                               ## arg regs (rdi/rsi/rdx), NOT the whole caller-saved file, so
                               ## it is NOT a full call point: it denies `AllRegs` (rdi/rsi
                               ## are clobbered) but a var crossing only atomics still earns
                               ## `R89Ok` (r8/r9 survive). Kept out of `callPositions`.
    atomicCalls: HashSet[string]  ## names classified as inlined atomics (see `atomicPositions`)
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
    cleanCallees: HashSet[string]  ## decl names of procs with a clean signature (all-scalar
                               ## GPR params, non-aggregate return). In a call to one, the
                               ## k-th argument lands in the k-th arg GPR — so a param passed
                               ## at its own index is a self-move. A call to anything else
                               ## (indirect, or an aggregate/float/retIndirect signature) can
                               ## shift ordinals, so param args there are `ArgResident`-unsafe.
    procIsClean: bool          ## the CURRENT proc has a clean signature: `paramIdx` is a
                               ## valid arg-GPR ordinal and there is no hidden rdi ret ptr.
    completedCalls: int        ## running count of calls whose args have been FULLY
                               ## processed (incremented AFTER the call subtree), in program
                               ## order. A param used while this is >0 executes after some
                               ## call RETURNED (its arg reg was clobbered) → it needs a
                               ## callee-saved home, so it cannot be `ArgResident`. A use
                               ## INSIDE a call's args sees the count not-yet-incremented for
                               ## that call, so a param consumed by the first call qualifies.

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
    var vi = VarInfo(defs: ord(hasValue), freeAfter: declPos,
                     frameIdx: c.stmtEnd.high, declInLoop: inLoop, liveStart: declPos,
                     declLoopDepth: c.loopStack.len, paramIdx: -1)
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
      # Extend the live range to this occurrence's PRECISE position — its own token
      # position, not the enclosing statement's end. Freeing strictly after the
      # textually-last use is safe for branches: no control-flow path can read the
      # value once we are past its last textual use, so an `if`/`case` needs no
      # post-dominating over-extension. The ONE exception is a loop back-edge: a use
      # nested in a loop the DECLARATION sits outside of is re-read on later
      # iterations, so the value is carried across that loop's back-edge. Extend to
      # the end of the OUTERMOST such loop (`loopStack[declLoopDepth]`, ordered
      # outer→inner) so the register stays reserved for the whole carried span.
      var hi = posOf(c, n)
      if c.loopStack.len > e.declLoopDepth:
        hi = max(hi, c.loopStack[e.declLoopDepth].hi)
      e.freeAfter = max(e.freeAfter, hi)
      e.lastUsePos = max(e.lastUsePos, hi)   # tracked even for params (freeAfter pinned to high)
      if c.completedCalls > 0: e.usedAfterCall = true  # used after a call returned → must survive it
      if (c.inAddr + c.inArrayIndex) > 0:
        # arrays / address-taken locals cannot live in a register
        e.props.incl AddrTaken
    elif vn in c.tvars:
      # A thread-local access lowers to the TLV thunk call (clobbers x0/lr), so
      # treat it like a call point: locals live across it must avoid the volatile
      # argument registers.
      c.callPositions.add posOf(c, n)
      inc c.completedCalls              # the thunk call clobbers the arg regs here and now
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
      # An inlined atomic (emitAtomic2) is NOT a real call: it clobbers only rax + its arg
      # regs. Record it as an atomic point (denies AllRegs, but leaves R89Ok) rather than a
      # full call point. The callee is the first child; an indirect (non-Symbol) target or an
      # unclassified name is conservatively a real call.
      var isAtomic = false
      if c.atomicCalls.len > 0:
        var probe = n
        probe.into:                       # the callee is the first child
          if probe.kind == Symbol: isAtomic = symName(probe) in c.atomicCalls
          while probe.hasMore: skip probe  # drain so `into` sees all children consumed
      if isAtomic: c.atomicPositions.add posOf(c, n)
      else: c.callPositions.add posOf(c, n)
      # ArgResident safety walk (peek only; the real accounting is analyseChildren below).
      # A param P may stay in its arg register across its consuming call only if that call
      # marshals it back to its OWN arg-GPR — a self-move no sibling arg clobbers. Peek the
      # call's shape: the callee (child 0) and each argument (children 1..). Disqualify a
      # param used as the CALLEE (an indirect target: its reg is needed AND the args
      # overwrite the arg regs), or passed at an ordinal ≠ its `paramIdx`, or in a call
      # whose callee is not a clean-signature proc (ordinals may shift — aggregate/float
      # params, retIndirect, or an indirect target of unknown shape).
      block argWalk:
        var probe = n
        probe.into:
          if not probe.hasMore: break argWalk
          let calleeSym = if probe.kind == Symbol: symName(probe) else: ""
          if calleeSym.len > 0 and c.res.vars.hasKey(calleeSym):
            c.res.vars[calleeSym].argUnsafe = true         # a param used as a call target
          let cleanCall = calleeSym.len > 0 and calleeSym in c.cleanCallees
          skip probe                                       # past the callee → arguments
          var ordinal = 0
          while probe.hasMore:
            if probe.kind == Symbol:
              let an = symName(probe)
              if c.res.vars.hasKey(an) and c.res.vars[an].paramIdx >= 0:
                # a bare param argument: safe ONLY as a same-ordinal self-move in a clean call
                if not (cleanCall and c.res.vars[an].paramIdx == ordinal):
                  c.res.vars[an].argUnsafe = true
            skip probe
            inc ordinal
      analyseChildren(c, n)
      inc c.completedCalls              # this call's args are fully built; it has "returned"
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
  var idx = 0                           # 0-based arg-GPR ordinal (valid only when procIsClean:
                                        # then every param is a single-GPR scalar)
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
        c.res.vars[vn] = VarInfo(defs: 1, freeAfter: high(int),
                                 paramIdx: (if c.procIsClean: idx else: -1))
        inc idx
        while params.hasMore: skip params   # pragmas, type
        # (rest consumed by into epilogue)

when defined(arkhamPeakLive):
  proc reportPeakLive(c: Context; pname: string; procStartPos, procEndPos: int) =
    ## Sweep every named local's coarse live interval and report the maximum number
    ## simultaneously alive — arkham's structural analogue of gcc's register-pressure
    ## count. A value occupies a register/slot over its interval, so the peak is the
    ## minimum registers a spill-free allocation would need. Params (`freeAfter ==
    ## high`) span the whole body; loop-carried locals use their loop span; others
    ## use `[liveStart, freeAfter]`. Inclusive containment: a value is alive at any
    ## point within its interval. Prints one greppable line per proc to stderr.
    type Iv = tuple[name: string, lo, hi: int]
    var ivs: seq[Iv] = @[]
    for name, vi in c.res.vars:
      var lo, hi: int
      if vi.freeAfter == high(int):
        lo = procStartPos; hi = procEndPos          # a param: live across the body
      elif vi.declInLoop:
        lo = vi.loopLo; hi = vi.loopHi              # loop-carried: whole loop span
      else:
        lo = vi.liveStart; hi = vi.freeAfter
      ivs.add (name, lo, hi)
    var pts: seq[int] = @[]                          # candidate points = interval endpoints
    for iv in ivs: (pts.add iv.lo; pts.add iv.hi)
    var peak = 0; var peakPt = 0
    for p in pts:
      var cnt = 0
      for iv in ivs:
        if iv.lo <= p and p <= iv.hi: inc cnt
      if cnt > peak: (peak = cnt; peakPt = p)
    var liveNames = ""
    for iv in ivs:
      if iv.lo <= peakPt and peakPt <= iv.hi:
        (if liveNames.len > 0: liveNames.add ' '; liveNames.add iv.name)
    stderr.write "PEAKLIVE proc=" & pname & " total=" & $ivs.len &
      " peak=" & $peak & " @pos=" & $peakPt & ": " & liveNames & "\n"
    # Per-member detail for the peak set: interval width + def/use counts. A narrow
    # interval that only overlaps `peakPt` by coarse `freeAfter` over-extension hints
    # at accounting inflation; a wide, heavily-used interval is a genuine co-live value.
    for iv in ivs:
      if iv.lo <= peakPt and peakPt <= iv.hi:
        let vi = c.res.vars[iv.name]
        stderr.write "    " & iv.name & " iv=[" & $iv.lo & "," & $iv.hi & "] w=" &
          $(iv.hi - iv.lo) & " defs=" & $vi.defs & " uses=" & $vi.usages &
          " allregs=" & $(AllRegs in vi.props) & "\n"
    # Cross-call pressure: the max simultaneously-live `allregs=false` intervals — the
    # callee-saved DEMAND (a cross-call var can ONLY use callee-saved without live-range
    # splitting). If this exceeds the callee-saved count (5, or 6 with rbp), the greedy
    # allocator MUST spill; if it does NOT, a spill means a bad greedy choice, not real
    # pressure. This is the number that decides which lever applies.
    var ccPeak = 0; var ccPt = 0
    for p in pts:
      var cnt = 0
      for iv in ivs:
        if iv.lo <= p and p <= iv.hi and (AllRegs notin c.res.vars[iv.name].props):
          inc cnt
      if cnt > ccPeak: (ccPeak = cnt; ccPt = p)
    var ccNames = ""
    for iv in ivs:
      if iv.lo <= ccPt and ccPt <= iv.hi and (AllRegs notin c.res.vars[iv.name].props):
        (if ccNames.len > 0: ccNames.add ' '; ccNames.add iv.name)
    stderr.write "  XCALLPEAK proc=" & pname & " crosscall-peak=" & $ccPeak &
      " @pos=" & $ccPt & ": " & ccNames & "\n"
    # The TRUE callee-saved demand under live-range splitting: max over each individual
    # CALL site of the values live ACROSS that specific call (lo < callPos < hi). A value
    # only needs preserving across the calls its range actually spans; two values crossing
    # DIFFERENT calls never contend for a callee-saved reg at the same call. If this is
    # <= 5, splitting removes EVERY spill (each var uses a volatile between calls, only the
    # <=5 spanning any one call need callee-saved). This is the number the fix must beat.
    var acrossPeak = 0; var acrossCall = 0
    for cp in c.callPositions:
      var cnt = 0
      for iv in ivs:
        if iv.lo < cp and cp < iv.hi: inc cnt    # strictly spans the call → live across it
      if cnt > acrossPeak: (acrossPeak = cnt; acrossCall = cp)
    stderr.write "  ACROSSCALL proc=" & pname & " max-live-across-one-call=" & $acrossPeak &
      " @call=" & $acrossCall & " (ncalls=" & $c.callPositions.len &
      " natomics=" & $c.atomicPositions.len & " atomicSet=" & $c.atomicCalls.len & ")\n"

proc analyseProc*(buf: var TokenBuf; procDecl: Cursor;
                  tvars: HashSet[string] = initHashSet[string]();
                  atomicCalls: HashSet[string] = initHashSet[string]();
                  cleanCallees: HashSet[string] = initHashSet[string]();
                  procIsClean = false): ProcAnalysis =
  ## `procDecl` is at a `(proc name params rettype pragmas body)`. `tvars` names
  ## the module's thread-locals so their uses force a call-like analysis. `atomicCalls`
  ## names calls the emitter inlines as an atomic sequence (a limited clobber — see
  ## `atomicPositions`); empty ⇒ every call is treated as a real call. `buf` is the
  ## buffer `procDecl` points into (for cursor → position mapping).
  var c = Context(tvars: tvars, atomicCalls: atomicCalls, cleanCallees: cleanCallees,
                  procIsClean: procIsClean, buf: addr buf)
  var n = procDecl
  assert n.stmtKind == ProcS
  when defined(arkhamPeakLive):
    let procStartPos = posOf(c, procDecl)
    var endCur = procDecl; skip endCur
    let procEndPos = posOf(c, endCur)
    var pname = "?"
  n.into:
    when defined(arkhamPeakLive):
      (if n.kind == SymbolDef: pname = symName(n))
    inc n                               # name (SymbolDef)
    analyseParams(c, n)                 # params
    skip n                              # return type
    skip n                              # pragmas
    scopeFrame(c):                      # the proc-body scope frame (its `stmts`
      iterStmts(c, n): analyse(c, n)    # shares it rather than pushing its own)
  c.res.hasCall = c.callPositions.len > 0 or c.atomicPositions.len > 0
  # Grant `AllRegs` (volatile/caller-saved eligible) to every local whose live
  # interval contains no call point. The interval is `(liveStart, freeAfter]`
  # for ordinary locals, or the enclosing-loop span for loop-carried ones. The
  # check is conservative: `freeAfter` over-approximates the range end and a
  # call within it denies `AllRegs`, so a missed-but-live-across-call case is
  # impossible (the unsafe direction). Params (`freeAfter == high`) are skipped.
  # An INLINED ATOMIC (`atomicPositions`) clobbers rdi/rsi (its args), so it too
  # denies `AllRegs`; but a var crossing ONLY atomics (no REAL call) still earns
  # the weaker `R89Ok` — r8/r9 survive an atomic and stay legal homes.
  for name, vi in mpairs c.res.vars:
    if vi.freeAfter == high(int): continue
    let lo = if vi.declInLoop: vi.loopLo else: vi.liveStart
    let hi = if vi.declInLoop: vi.loopHi else: vi.freeAfter
    var crossesRealCall = false
    for p in c.callPositions:
      if p > lo and p <= hi: (crossesRealCall = true; break)
    var crossesAtomic = false
    for p in c.atomicPositions:
      if p > lo and p <= hi: (crossesAtomic = true; break)
    if not crossesRealCall:
      # No real call in the interval → r8/r9 (atomic-safe) are legal homes even if an
      # atomic crosses. `AllRegs` (the full volatile pool, incl. rdi/rsi) needs the
      # STRONGER condition: no atomic either.
      vi.props.incl R89Ok
    if not (crossesRealCall or crossesAtomic):
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
  # ArgResident: a PARAM (freeAfter == high) may keep its incoming arg register instead of
  # a callee-saved home iff EVERY use of it executes before ANY call returns
  # (`not usedAfterCall`). Then no call clobbers the arg register while the param is live;
  # the call that consumes it (its last use is inside that call's args) clobbers the reg
  # anyway, and the param is dead afterward — so no value is lost. A same-position pass-
  # through makes the call-site marshal a self-move (elided); a different position stays
  # correct (one mov reading the still-resident value). Address-taken or unused params are
  # excluded. Only sound for register params; allocParams layers the fixed-role
  # (`clobbered`) and aggregate gating on top. Gated on `hasCall` (a leaf proc already
  # keeps its params in the arg registers via allocParams' plain leaf path).
  if c.res.hasCall and c.procIsClean:
    for name, vi in mpairs c.res.vars:
      if vi.freeAfter == high(int) and AddrTaken notin vi.props and
         vi.usages > 0 and not vi.usedAfterCall and not vi.argUnsafe:
        vi.props.incl ArgResident
  when defined(arkhamPeakLive):
    reportPeakLive(c, pname, procStartPos, procEndPos)
  result = ensureMove c.res
