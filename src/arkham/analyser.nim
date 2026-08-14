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
## A local DECLARED inside a loop has per-iteration lifetime (its scope ends
## within the iteration), so it is never loop-carried; only a local declared
## OUTSIDE a loop and used inside is carried, and its `freeAfter` extends over
## that loop's span (see `declLoopDepth`).
## Locals live across a call go to callee-saved registers or the stack. The
## register allocator consumes this.
##
## Ported from `src/wip/native/analyser.nim` to the nifcore cursor API; keyed
## by symbol *name* (nifcore has no stable SymId for inline-short symbols).

import std / [tables, sets, assertions, os, strutils]
import nifcore
import nifcdecl
import slots
import machinedesc   # `Reg`: the per-callee clobber sets that drive `survivorRegs`

let birthFilterEnv = getEnv("ARKHAM_BIRTH_FILTER")
  ## debug bisection toggle: "" = birth-point exemption everywhere (normal);
  ## "-" = disabled everywhere; else a comma-separated allowlist of proc names

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
    declInLoop*: bool          ## declared inside a loop — INFORMATIONAL only (census/
                               ## debug). A loop-body local has NO loop-carrying
                               ## semantics: its lifetime ends within the iteration (its
                               ## scope end), so every iteration re-creates it before any
                               ## use — reads of a previous iteration's value are illegal
                               ## IR. Loop-carrying exists only for vars declared OUTSIDE
                               ## a loop and used inside; `declLoopDepth`'s `freeAfter`
                               ## extension covers exactly those.
    liveStart*: int            ## token position of the var's declaration: the start of
                               ## its (coarse) live range, paired with `freeAfter` as the
                               ## end. A call strictly after `liveStart` and at/before
                               ## `freeAfter` crosses the range.
    lastUsePos*: int           ## PRECISE last-use position, tracked for ALL vars incl.
                               ## params (whose `freeAfter` is pinned to `high`).
    survivorRegs*: set[Reg]    ## the volatile registers that survive EVERY call this
                               ## value's live range crosses — i.e. that no crossed
                               ## callee destroys and no crossed call's argument
                               ## marshalling writes. A cross-call value homed in one
                               ## of these needs neither a callee-saved register (a
                               ## prologue push/pop) nor a stack slot; it is simply
                               ## resident. Empty unless the backend supplied per-callee
                               ## clobber sets, which makes the whole mechanism opt-in
                               ## per architecture. Meaningless when `AllRegs` is set
                               ## (nothing is crossed at all).
    usedAfterCall*: bool       ## a use occurred while a call had already RETURNED
                               ## (`completedCalls > 0`) → the value must survive that call.
                               ## Disqualifies a param from `ArgResident`.
    argUnsafe*: bool           ## used as a call TARGET, or as a call ARGUMENT at an ABI
                               ## position ≠ its own param index, or in a non-clean call
                               ## (ordinals may shift). Disqualifies `ArgResident`.
    paramIdx*: int             ## a register param's 0-based ABI index (arg-GPR ordinal) in
                               ## a clean-signature proc; -1 for locals and non-clean procs.
    initClass*: InitClass      ## shape of the decl initializer (see `InitClass`)
    initEndPos*: int           ## token position just PAST the decl initializer — the
                               ## point where the var's value is BORN. A call inside
                               ## the initializer (e.g. `let x = f(…)`) precedes the
                               ## birth, so it cannot clobber the value; 0 when no
                               ## initializer

  InitClass* = enum
    ## What a local's DECL initializer is, after peeling value-preserving wrappers
    ## (`cast`/`conv`/`suf`/`par`). Instrumentation for the mild-SSA survey
    ## (`-d:arkhamSSAStats`): a `defs == 1` local with a known-shape initializer is
    ## an SSA value whose content is statically evident at every use.
    icNone,       ## no initializer (`.`)
    icConst,      ## int/uint/char literal — rematerializable, foldable as imm
    icCopy,       ## a bare (possibly cast-wrapped) local symbol — copy-prop candidate
    icAddr,       ## `(addr …)` — an address computation, `lea`-rematerializable
    icCall,       ## a `(call …)` at the root: the var's home receives its FIRST
                  ## write only after the outermost call RETURNS (args marshal
                  ## through arg regs/etmps, never the destination), so the
                  ## initializer's own call(s) cannot clobber the value — see the
                  ## birth-point exemption in `analyseProc`
    icOther       ## anything else (binop, load, …)

  ProcAnalysis* = object
    vars*: Table[string, VarInfo]
    hasCall*: bool              ## a call exists — params cannot stay in clobbered arg
                                ## regs; AllRegs / ArgResident consult this, and the
                                ## fp/lr frame decision is this same question
    callPositions*: seq[int]    ## token positions of every call — the allocator's
                                ## caller-save cost model counts how many a var crosses
    callClobberAt*: seq[set[Reg]] ## index-aligned with `callPositions`: what the call at
                                ## that position destroys. Every append to one MUST append
                                ## to the other.
    clobbersDivReg*: bool       ## body contains a div/mod → rdx is clobbered, so a
                                ## leaf param must not be homed there (x86-64 only)
    clobbersBridgeReg*: bool    ## body contains an `(instr …)` row whose lowering claims
                                ## the staging bridge (x86-64 R11) as its own `work`
                                ## register. Those rows take it DIRECTLY — sealing keeps
                                ## the operand PICKS off it, but a value already homed
                                ## there is simply released (`releaseStaleName`), which
                                ## was sound only while nothing could be homed there.
                                ## `callerSaveRescue` is the one client that may draw the
                                ## bridge, and must not in such a proc.
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

  LoopFrame = object
    ## An enclosing `WhileS`, treated as `loop: (if cond: body else break)`: the
    ## condition and body form ONE loop body walked once, but the back-edge makes
    ## every point re-reachable from every other. Two consequences the linear walk
    ## cannot see textually, recovered here at the frame:
    ##  * liveness: a var used in the loop is live across the whole span (`lo..hi`);
    ##  * `usedAfterCall`: a param read anywhere in a loop that contains a call is
    ##    read again *after* that call via the back-edge — even a param used only in
    ##    the loop CONDITION, which textually precedes the body's call.
    lo, hi: int                ## token span of the whole loop (the `declLoopDepth`
                               ## back-edge extension for OUTSIDE-declared vars)
    sawCall: bool              ## a real call point occurred within this loop (any depth)
    usedParams: HashSet[string] ## names of params read within this loop (any depth); on
                               ## loop exit, if `sawCall`, each is flagged `usedAfterCall`

  ClobberSite = object
    ## A fixed-role-register clobber (div/mod → rdx, variable shift → rcx) at token
    ## position `pos`, inside the scope-level statement starting at `stmtStart`.
    ## The statement start matters because operand EVALUATION order differs from
    ## token order: in `bitand(mask, shl(1, n))` the mask's textually-last use
    ## precedes the shl's tokens, yet its value is consumed by the AND *after* the
    ## shift executed — so a local whose interval merely touches the statement
    ## containing the clobber must be denied the fixed-role home.
    pos: int
    stmtStart: int

  Context = object
    inLoops, inAddr, inAsgnTarget, inArrayIndex: int
    inCold: int                ## depth of enclosing COLD blocks: a branch body that ends
                               ## in a diverging call (`panic`, `raiseIndexError3`, an
                               ## `assert`'s failure arm). Every bounds check has one, so
                               ## without this a variable's `weight` — the allocator's
                               ## only notion of hotness — counts its appearance in the
                               ## check's ERROR message as heavily as its use in the loop
                               ## the check guards, and the index/length of a hot loop
                               ## looks hotter than it is while a variable used ONLY on a
                               ## panic path looks worth a register. Uses in here add
                               ## nothing to `weight` (they still count for `usages` and
                               ## liveness — the value is genuinely read on that path).
    arg0Name: string           ## name of the FIRST integer/pointer param (the one homed in
                               ## the return register on AArch64); "" if none / aggregate
    res: ProcAnalysis
    callPositions: seq[int]    ## token position of every call point (incl. tvar thunk
                               ## accesses) — the points where caller-saved regs die. A
                               ## local may use `AllRegs` iff none of these fall in its
                               ## live interval. Recorded in source order; scanned linearly.
    divPositions: seq[ClobberSite]   ## every div/mod (clobbers rdx). An `AllRegs` local
                               ## additionally earns `DivRegOk` (rdx is a legal home) iff
                               ## none of these overlaps its live interval.
    shiftPositions: seq[ClobberSite] ## every *variable* shift (clobbers rcx);
                               ## the `ShiftRegOk` analog of `divPositions`.
    loopStack: seq[LoopFrame]  ## the enclosing loops (`WhileS`), innermost last — so a var
                               ## declared/used in a loop can record its loop's extent, and a
                               ## loop's back-edge liveness is resolved when its frame is popped
    stmtEnd: seq[int]          ## per open scope frame: end position of the
                               ## statement it is currently processing
    stmtStart: seq[int]        ## per open scope frame: START position of that same
                               ## statement — `ClobberSite.stmtStart` comes from here
    buf: ptr TokenBuf          ## for cursor → token-position mapping
    tvars: HashSet[string]     ## thread-local var names: a reference acts like a call
    cleanCallees: HashSet[string]  ## decl names of procs with a clean signature (all-scalar
                               ## GPR params, non-aggregate return). In a call to one, the
                               ## k-th argument lands in the k-th arg GPR — so a param passed
                               ## at its own index is a self-move. A call to anything else
                               ## (indirect, or an aggregate/float/retIndirect signature) can
                               ## shift ordinals, so param args there are `ArgResident`-unsafe.
    callClobbers: Table[SymId, set[Reg]] ## per DIRECT callee, what a call to it destroys
                               ## at the call site: the callee's own register footprint
                               ## plus the argument registers the marshalling writes.
                               ## A callee absent from the table destroys everything
                               ## (`volatileRegs`), which is what arkham assumed for
                               ## every call before callsite-specific lists existed.
    volatileRegs: set[Reg]     ## the caller-saved pool of the target machine; `{}` turns
                               ## the survivor analysis off entirely.
    divergingClobbers: set[Reg] ## registers a DIVERGING call's argument marshalling may
                               ## write — the argument registers. Subtracted from
                               ## `survivorRegs` for any value whose range spans one.
    callClobberAt: seq[set[Reg]] ## aligned with `callPositions`: what the call at that
                               ## position destroys. Kept parallel rather than folded into
                               ## a tuple so the existing position loops stay untouched.
    noReturnCallees: HashSet[SymId] ## pool ids of `(attr "noreturn")` procs. A call to
                               ## one is NOT a call point for liveness: it never returns, so
                               ## nothing textually after it is reachable *through* it and no
                               ## value has to survive it. See `sawNoReturnCall`.
    noReturnPositions: seq[int] ## token position of every DIVERGING call. Kept out of
                               ## `callPositions` (they deny nothing for `AllRegs`), but
                               ## still consulted for the fixed-role registers: `DivRegOk`
                               ## and `ShiftRegOk` say "rdx/rcx is a legal home", and those
                               ## have their own interval tests whose precision was only
                               ## ever exercised on call-free ranges. Keeping them strict
                               ## confines this relaxation to the callee-saved question.
    sawNoReturnCall: bool      ## at least one diverging call was seen. `hasCall` must still
                               ## be true: the frame code uses it to keep rsp 16-aligned at
                               ## the call, and the call really is executed on the cold path.
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
      c.stmtStart[^1] = posOf(c, n)
      c.stmtEnd[^1] = posOf(c, e)
      body

template scopeFrame(c: var Context; body: untyped) =
  ## Push the `stmtEnd` frame for a variable scope (a `scope`, or the proc body) —
  ## the unit `freeAfter`/`frameIdx` are measured in, one per `openScope`.
  c.stmtEnd.add 0
  c.stmtStart.add 0
  body
  discard c.stmtEnd.pop()
  discard c.stmtStart.pop()

proc analyse(c: var Context; n: var Cursor)

proc analyseChildren(c: var Context; n: var Cursor) =
  n.into:
    while n.hasMore: analyse(c, n)

proc analyseInstr(c: var Context; n: var Cursor) =
  ## `(instr SYM …)`, in either value or statement position. A `(haddr d)`
  ## operand is a two-address row's DESTINATION: the front end spelled it `var d`,
  ## and `haddr` says the callee wants d's LOCATION, not a pointer value. A
  ## register IS a location, so — unlike a real `(addr d)` — this must not mark d
  ## address-taken and force it onto the stack. Keeping the two tags apart in Leng
  ## is what makes that distinction available here at all.
  ##
  ## Purely syntactic, so no access to the row table is needed: `haddr` is only
  ## ever inserted for a `var`/`out` parameter, and on an intrinsic a `var`
  ## parameter IS the inout operand (`doc/intrinsics.md` §4.1).
  n.into:
    skip n                              # the callee symbol
    while n.hasMore:
      if n.kind == TagLit and n.exprKind == HaddrC:
        n.into:
          while n.hasMore: analyse(c, n)   # a read+write of the local, not an escape
      else:
        analyse(c, n)

proc classifyInit(n: Cursor): InitClass =
  ## Peel value-preserving wrappers (`cast`/`conv`/`suf`/`par` — the same set
  ## `isConstShiftCount` peels), then classify the initializer core.
  var c = n
  while c.kind == TagLit:
    case c.exprKind
    of CastC, ConvC:                       # `(cast TARGET value)` — skip the target type
      var t = c; inc t; skip t; c = t
    of SufC, ParC:                         # `(suf value "type")` / `(par value)`
      var t = c; inc t; c = t
    else: break
  case c.kind
  of IntLit, UIntLit, CharLit: icConst
  of Symbol: icCopy
  of TagLit:
    if c.stmtKind == CallS: icCall
    elif c.exprKind == AddrC: icAddr
    else: icOther
  else: icOther

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
                     declLoopDepth: c.loopStack.len, paramIdx: -1,
                     initClass: (if hasValue: classifyInit(n) else: icNone))
    c.res.vars[vn] = vi
    if hasValue:
      analyse(c, n)              # analyse the initializer
      c.res.vars[vn].initEndPos = posOf(c, n)   # the value's birth point
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

proc markArgParamsUnsafe(c: var Context; n0: Cursor; ordinal: int; cleanCall: bool) =
  ## Recursively disqualify from `ArgResident` every PARAM read ANYWHERE inside a call
  ## argument at ABI position `ordinal`. Keeping such a param in its incoming arg register
  ## is unsound whenever that register is overwritten by the marshalling of arg[paramIdx]
  ## before this argument is computed — i.e. `paramIdx != ordinal` (a same-ordinal
  ## self-move is the one safe shape: it reads the register just before overwriting it).
  ## A NON-clean call (aggregate/float/retIndirect may shift ABI ordinals) makes any use
  ## unsafe. Crucially this sees THROUGH `dot`/`deref`/`cast`/… wrappers, so a closure env
  ## `p0.0` (rdi) read as `env->field` for arg1 — while arg0 targets rdi — is caught, not
  ## only a bare/wrapped param passed directly (e.g. `mmap(nil, cast(size), …)`).
  var n = n0
  case n.kind
  of Symbol:
    let an = symName(n)
    if c.res.vars.hasKey(an) and c.res.vars[an].paramIdx >= 0:
      if (not cleanCall) or c.res.vars[an].paramIdx != ordinal:
        c.res.vars[an].argUnsafe = true
  of TagLit:
    if n.stmtKind == NoStmt:
      n.into:
        while n.hasMore: (markArgParamsUnsafe(c, n, ordinal, cleanCall); skip n)
  else: discard

proc isImmLeaf*(n: Cursor): bool =
  ## True when an operand is a compile-time immediate: a bare int/uint/char
  ## literal, possibly wrapped in `cast`/`conv`/`suf`/`par`. Such an operand
  ## materializes AT ITS POINT OF USE and so holds no register across a sibling
  ## subtree — which is what lets the consumer evaluate the other operand
  ## straight into the destination.
  ##
  ## The wrappers are not decoration. A front-end spells a typed literal
  ## `(suf 511u "u32")` and an unsigned-normalized one `(cast (u 64) (suf 4
  ## "i64"))`; a bare `kind in {IntLit,…}` test sees a `TagLit` and says no.
  var c = n
  while c.kind == TagLit:
    case c.exprKind
    of CastC, ConvC:                       # `(cast TARGET value)` — skip the target type
      var t = c; inc t; skip t; c = t
    of SufC, ParC:                         # `(suf value "type")` / `(par value)`
      var t = c; inc t; c = t
    else: break
  result = c.kind in {IntLit, UIntLit, CharLit}

proc isConstShiftCount*(n: Cursor): bool {.inline.} =
  ## A shift count that is an immediate assembles as an `imm8` shift (`sar r, 4`),
  ## so — unlike a runtime count — it need NOT occupy `cl` and does not clobber
  ## `rcx`.
  isImmLeaf(n)

proc endsDiverging(c: Context; branch: Cursor): bool =
  ## True when this `(elif …)`/`(else …)`/`(of …)`'s BODY ends in a call that never
  ## returns — the shape of every bounds check, `assert` and `raiseIndexError3` guard.
  ## Trailing `(stmts …)`/`(scope …)` wrappers are transparent (hexer's inliner adds a
  ## scope per splice), so the walk descends to the genuinely last statement.
  result = false
  if branch.kind != TagLit: return
  var cur = branch
  var guard = 0
  while guard < 64:
    inc guard
    if cur.kind != TagLit: return false
    if cur.stmtKind == CallS:
      let callee = sub(cur)
      return callee.kind == Symbol and callee.symId in c.noReturnCallees
    # descend to the LAST child: the branch's body, then through the `(stmts …)` /
    # `(scope …)` wrappers hexer's inliner adds, to the genuinely last statement.
    var probe = sub(cur)
    if not probe.hasMore: return false
    var last = probe
    while probe.hasMore: (last = probe; skip probe)
    cur = last

proc analyse(c: var Context; n: var Cursor) =
  case n.kind
  of Symbol:
    let vn = symName(n)
    if c.res.vars.hasKey(vn):
      let e = addr c.res.vars[vn]
      if c.inAsgnTarget > 0: inc e.defs
      else: inc e.usages
      # each use counts; uses inside loops count `LoopWeight`× per nesting level —
      # and a use on a COLD path (a branch that ends in a diverging call) counts for
      # nothing, loop or not.
      if c.inCold == 0: inc e.weight, 1 + c.inLoops * LoopWeight
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
      # Record a PARAM read against every enclosing loop: if that loop turns out to
      # contain a call, the back-edge makes this a use-after-call (resolved at pop),
      # even when the read textually precedes the call (a loop-CONDITION param).
      if e.freeAfter == high(int) and c.loopStack.len > 0:
        c.loopStack[^1].usedParams.incl vn
      if (c.inAddr + c.inArrayIndex) > 0:
        # arrays / address-taken locals cannot live in a register
        e.props.incl AddrTaken
    elif vn in c.tvars:
      # A thread-local access lowers to the TLV thunk call (clobbers x0/lr), so
      # treat it like a call point: locals live across it must avoid the volatile
      # argument registers.
      c.callPositions.add posOf(c, n)
      # `callClobberAt` is index-aligned with `callPositions`; EVERY append to one
      # must append to the other or the survivor analysis attributes one call's
      # clobbers to another. The thunk is opaque here, so it destroys everything.
      c.callClobberAt.add c.volatileRegs
      if c.loopStack.len > 0: c.loopStack[^1].sawCall = true
      inc c.completedCalls              # the thunk call clobbers the arg regs here and now
    inc n
  of IntLit, UIntLit, FloatLit, CharLit, StrLit, Ident, SymbolDef, DotToken:
    inc n
  of TagLit:
    case n.stmtKind
    of InstrS:                          # a two-address row: a statement, not a value
      c.res.clobbersBridgeReg = true    # see the expression case below
      analyseInstr(c, n)
    of NoStmt:
      case n.exprKind
      of PatC:
        # `(pat p i)` is POINTER indexing, and BOTH operands are plain value reads:
        # `p` is loaded into a register and scaled, exactly like `(deref p)` below.
        # The emitter has always known this — `lvalUsesReg` says "the pointer is a
        # VALUE" for `PatC` and "the base is an lvalue" for `AtC` — but the analyser
        # lumped the two together, so every pointer indexed with `p[i]` was marked
        # `AddrTaken` and forced onto the STACK. That is why `hasKey`'s `sroa.7`, the
        # seq DATA pointer, is stored and reloaded once per probe iteration: 26.7 M
        # executed instructions in the hasKey microbenchmark, per proc.
        n.into:
          let oldA = c.inAddr; let oldT = c.inAsgnTarget; let oldX = c.inArrayIndex
          c.inAddr = 0; c.inAsgnTarget = 0; c.inArrayIndex = 0
          while n.hasMore: analyse(c, n)
          c.inAddr = oldA; c.inAsgnTarget = oldT; c.inArrayIndex = oldX
      of AtC:
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
      of AddrC, HaddrC:
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
        of ElifU, ElseU, OfU:
          # The BODY is the last child. When it ends in a diverging call the whole
          # branch is a cold guard — the shape every bounds check, `assert` and
          # `raiseIndexError3` has — so its uses must not inflate `weight`. The
          # CONDITION is not cold: it runs on the hot path.
          #
          # A general per-branch DISCOUNT (halve the weight per conditional level, the
          # standard static-profile guess) was built here too and MEASURED NEGATIVE:
          # nifbench −0.013 % (noise), nimsem **+0.56 %**. Do not re-add it.
          let cold = endsDiverging(c, n)
          when defined(arkhamColdDbg):
            if cold: stderr.writeLine "COLDBLOCK"
          n.into:
            var idx = 0
            var last = 0
            block:                         # how many children (1 for `else`, 2 otherwise)
              var probe = n
              while probe.hasMore: (inc last; skip probe)
            while n.hasMore:
              let isBody = idx == last - 1
              if isBody and cold: inc c.inCold
              analyse(c, n)
              if isBody and cold: dec c.inCold
              inc idx
        of KvU: analyseChildren(c, n)
        else: skip n
      of InstrC:
        # Which registers the row claims is the EMITTER's table (`atomicRegClaims`);
        # all the allocator needs to know is that some row in this body may take the
        # bridge, so the one client allowed to draw it must not here.
        c.res.clobbersBridgeReg = true
        analyseInstr(c, n)
      of DivC, ModC:
        c.res.clobbersDivReg = true     # idiv/div clobbers rdx
        c.divPositions.add ClobberSite(pos: posOf(c, n), stmtStart: c.stmtStart[^1])
        analyseChildren(c, n)
      of ShlC, ShrC:
        # A *variable* shift needs the count in cl, clobbering rcx; a constant shift
        # does not. The count is the second operand (after the result type).
        var probe = n; probe.into:
          skip probe                    # result type
          skip probe                    # value
          if not isConstShiftCount(probe):
            c.res.clobbersShiftReg = true
            c.shiftPositions.add ClobberSite(pos: posOf(c, n), stmtStart: c.stmtStart[^1])
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
      # Every `(call …)` is a real call point now that the atomics are `(instr …)`.
      # They used to need an exception here — an inlined atomic clobbers a handful of
      # registers, not the caller-saved file — and modelling that took a name set, a
      # second position list and a weaker variant property. As instructions they take
      # only registers the allocator never hands out, so there is nothing to model.
      #
      # EXCEPT a diverging callee (`(attr "noreturn")`: panic, raiseAssert, the
      # bound-check failure path). Control never comes back from it, so no value
      # has to survive it, no loop back-edge re-reaches through it, and no arg
      # register is clobbered "for" any later use. Keeping such a position in
      # `callPositions` denied `AllRegs` to every local whose interval merely
      # SPANS the cold guard, which pushed the whole proc onto callee-saved
      # registers — three pushes, three pops and a frame in `nifcore.kind`, whose
      # real body is a load and a mask. `hasCall` still becomes true (below), so
      # the alignment pad at the call is unchanged.
      var noReturnCall = false
      block:
        # `sub`, not `into`: this is a read-only peek at child 0 and `into`
        # asserts that its body consumed every child.
        let probe = sub(n)
        if probe.hasMore and probe.kind == Symbol:
          noReturnCall = probe.symId in c.noReturnCallees
      if noReturnCall:
        c.sawNoReturnCall = true
        c.noReturnPositions.add posOf(c, n)
      else:
        c.callPositions.add posOf(c, n)
        # What THIS call destroys. An unresolved target (indirect, foreign without a
        # summary, or a module compiled before the summaries existed) answers with the
        # whole caller-saved set — the pre-existing assumption for every call.
        block:
          var cl = c.volatileRegs
          let probe = sub(n)
          if probe.hasMore and probe.kind == Symbol and c.callClobbers.hasKey(probe.symId):
            cl = c.callClobbers[probe.symId]
          c.callClobberAt.add cl
        if c.loopStack.len > 0: c.loopStack[^1].sawCall = true
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
            markArgParamsUnsafe(c, probe, ordinal, cleanCall)
            skip probe
            inc ordinal
      analyseChildren(c, n)
      if not noReturnCall or defined(arkhamStrictNoReturn):
        inc c.completedCalls            # this call's args are fully built; it has "returned"
        # A diverging call never returns, so nothing executes "after it returned" —
        # a param read later is reached only on the path that skipped it.
        # (…which is true of the MACHINE but not of `rb`; see the `arkhamStrictNoReturn`
        # note at the `AllRegs` interval test. `ArgResident` needs the same gate, or a
        # param stays in its arg register across a marshal that killed its binding.)
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
      # Treat `while cond: body` as `loop: (if cond: body else break)` — condition and
      # body are one loop body under a back-edge (no prepass; the traversal just reads it
      # that way). Walk it as usual, then resolve the back-edge at the frame.
      var e = n; skip e               # span of the whole loop (back-edge extension)
      c.loopStack.add LoopFrame(lo: posOf(c, n), hi: posOf(c, e))
      n.into:
        inc c.inLoops
        while n.hasMore: analyse(c, n)
        dec c.inLoops
      let frame = c.loopStack.pop()
      # Back-edge resolution: a param read anywhere in a loop that contains a call is
      # re-read after that call on the next iteration → it cannot stay in its incoming
      # arg register across the loop. Flag it; the ArgResident gate then denies it.
      if frame.sawCall:
        for pnm in frame.usedParams: c.res.vars[pnm].usedAfterCall = true
      # Propagate to the enclosing loop: its back-edge re-reaches this whole sub-loop.
      if c.loopStack.len > 0:
        if frame.sawCall: c.loopStack[^1].sawCall = true
        for pnm in frame.usedParams: c.loopStack[^1].usedParams.incl pnm
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
    ## high`) span the whole body; others use `[liveStart, freeAfter]` (loop-body
    ## locals have per-iteration lifetime, so the precise interval is exact). Inclusive containment: a value is alive at any
    ## point within its interval. Prints one greppable line per proc to stderr.
    type Iv = tuple[name: string, lo, hi: int]
    var ivs: seq[Iv] = @[]
    for name, vi in c.res.vars:
      var lo, hi: int
      if vi.freeAfter == high(int):
        lo = procStartPos; hi = procEndPos          # a param: live across the body
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
      " @call=" & $acrossCall & " (ncalls=" & $c.callPositions.len & ")\n"

proc analyseProc*(buf: var TokenBuf; procDecl: Cursor;
                  tvars: HashSet[string] = initHashSet[string]();
                  cleanCallees: HashSet[string] = initHashSet[string]();
                  procIsClean = false;
                  noReturnCallees: HashSet[SymId] = initHashSet[SymId]();
                  callClobbers: Table[SymId, set[Reg]] = initTable[SymId, set[Reg]]();
                  volatileRegs: set[Reg] = {};
                  divergingClobbers: set[Reg] = {}): ProcAnalysis =
  ## `procDecl` is at a `(proc name params rettype pragmas body)`. `tvars` names
  ## the module's thread-locals so their uses force a call-like analysis. `buf` is the
  ## buffer `procDecl` points into (for cursor → position mapping).
  ##
  ## `callClobbers`/`volatileRegs` drive `VarInfo.survivorRegs` — the per-callee clobber
  ## information that lets a cross-call value stay in a volatile. Both default to empty,
  ## which reproduces the old "every call destroys every caller-saved register" model.
  var c = Context(tvars: tvars, cleanCallees: cleanCallees,
                  noReturnCallees: noReturnCallees,
                  callClobbers: callClobbers, volatileRegs: volatileRegs,
                  divergingClobbers: divergingClobbers,
                  procIsClean: procIsClean, buf: addr buf)
  var n = procDecl
  assert n.stmtKind == ProcS
  when defined(arkhamPeakLive):
    let procStartPos = posOf(c, procDecl)
    var endCur = procDecl; skip endCur
    let procEndPos = posOf(c, endCur)
  var pname = "?"
  n.into:
    (if n.kind == SymbolDef: pname = symName(n))
    inc n                               # name (SymbolDef)
    analyseParams(c, n)                 # params
    skip n                              # return type
    skip n                              # pragmas
    scopeFrame(c):                      # the proc-body scope frame (its `stmts`
      iterStmts(c, n): analyse(c, n)    # shares it rather than pushing its own)
  c.res.hasCall = c.callPositions.len > 0 or c.sawNoReturnCall
  c.res.callPositions = c.callPositions
  c.res.callClobberAt = c.callClobberAt
  # Grant `AllRegs` (volatile/caller-saved eligible) to every local whose live
  # interval `(liveStart, freeAfter]` contains no call point. Loop-body locals
  # need no special span: their lifetime is per-iteration, and an OUTSIDE-
  # declared local used in a loop already had `freeAfter` extended over that
  # loop (`declLoopDepth`), so a value carried across a back-edge keeps every
  # call of that loop inside its interval. The check is conservative:
  # `freeAfter` over-approximates the range end and a call within it denies
  # `AllRegs`, so a missed-but-live-across-call case is impossible (the unsafe
  # direction).
  #
  # PARAMS take part too, on `lastUsePos` instead of `freeAfter`: their `freeAfter`
  # is pinned to `high` because the allocator, not the scope walk, manages their
  # storage — that pin says "never early-freed", not "live to the end". Their live
  # range starts at proc entry (`lo` stays 0 — every call position is > 0), so the
  # test reduces to "the last use precedes the first call", which is exactly the
  # condition under which a param may stay in its incoming argument register.
  # `lastUsePos` already carries the loop back-edge extension (a use inside a loop
  # reaches to the loop's end), so a param re-read across a back-edge that spans a
  # call is denied here, structurally.
  for name, vi in mpairs c.res.vars:
    let isParam = vi.freeAfter == high(int)
    # Birth-point exemption: a `let x = f(…)` initializer's own call precedes the
    # value's existence — x's home receives its FIRST write from the call's result,
    # after it returned — so it must not deny `AllRegs`. Only sound for a ROOT call
    # (`icCall`): any other initializer shape may stage a partial value in the
    # destination (the fused emitters thread the dest into subexpressions), which a
    # later embedded call would clobber. Loop-carried vars keep their loop span.
    # `initEndPos - 1`, not `initEndPos`: the cursor position just past the
    # initializer subtree can COINCIDE with the next statement's own token
    # position, and a call there is after the birth — it must still deny. Only
    # calls strictly INSIDE the initializer (p < initEndPos) are exempt.
    let birthOk = birthFilterEnv.len == 0 or
                  (birthFilterEnv != "-" and pname in birthFilterEnv.split(','))
    let lo = if vi.initClass == icCall and birthOk: vi.initEndPos - 1
             else: vi.liveStart
    let hi = if isParam: vi.lastUsePos else: vi.freeAfter
    var crossesCall = false
    # …and, in the same sweep, which volatiles survive all of them. `AllRegs` answers
    # "does this value cross a call at all"; `survivorRegs` answers the finer question
    # the allocator actually wants once the answer is yes — WHICH registers the crossed
    # calls leave alone. Almost every call in Leng is static, so most crossings subtract
    # a small named set rather than the whole caller-saved file.
    var surv = c.volatileRegs
    for i in 0 ..< c.callPositions.len:
      let p = c.callPositions[i]
      if p > lo and p <= hi:
        crossesCall = true
        if i < c.callClobberAt.len: surv = surv - c.callClobberAt[i]
    # A DIVERGING call is not a call point — nothing after it is reachable through it,
    # which is the whole reason `noReturnPositions` is kept apart. Its ARGUMENT
    # MARSHALLING is still emitted, though, and that is a real write: `releaseArgDest`
    # kills the binding on each argument register it overwrites, and arkham's binding
    # table is linear, so a later read of a still-live value homed there falls back to
    # a raw `(reg)` of the wrong type. nifasm catches it (`cannot store the non-zero
    # integer … into the pointer-typed destination`, `rawLineInfo`), which is exactly
    # the failure mode a bounds-checked leaf produces. Machine-state-wise this is pure
    # pessimism; it is the same limitation `-d:arkhamStrictNoReturn` documents.
    if c.divergingClobbers != {}:
      for p in c.noReturnPositions:
        if p > lo and p <= hi:
          surv = surv - c.divergingClobbers
          break
    vi.survivorRegs = surv
    when defined(arkhamStrictNoReturn):
      # EXPERIMENT: also deny `AllRegs` across a DIVERGING call. Machine-state-wise
      # that is pure pessimism — a call that never returns clobbers nothing anyone can
      # observe. It is arkham's BINDING TABLE that cannot express it: `releaseArgDest`
      # emits `(kill nm)` for each arg register the marshalling overwrites, `rb` is
      # linear and has no notion of "this path is not taken", so the name is gone for
      # the rest of the proc and every later read of that still-live local falls back
      # to a raw `(reg)`.
      for p in c.noReturnPositions:
        if p > lo and p <= hi: (crossesCall = true; break)
    # `usedAfterCall` is the same fact reached by counting completed calls rather
    # than comparing positions. Redundant with the interval test above, kept as the
    # belt-and-braces gate on the param path (it is what `ArgResident` has always
    # used, and the two disagreeing would mean one of them is wrong).
    if isParam and vi.usedAfterCall: crossesCall = true
    if not crossesCall:
      vi.props.incl AllRegs
      # A param's fixed-role eligibility (rdx/rcx) is decided per-proc in
      # `allocParams` from `clobbersDivReg`/`clobbersShiftReg`, not from these
      # per-variable props — leave them off rather than grant something unread.
      if isParam: continue
      # `DivRegOk`/`ShiftRegOk` claim rdx/rcx are free of their INSTRUCTION role across
      # the range. They used to also deny a diverging call in the interval, because
      # granting it to a bounds-checked `[]=` (whose panic is diverging) tripped the
      # allocator's own clobber check on rcx. That was the binding table, not the
      # machine: the panic's marshalling had to `(kill …)` the home, and every later
      # read of the still-live local went raw. `restoreBindings` (codegen_x64) now
      # re-establishes those names after the diverging call, so the strict test is no
      # longer needed — and rdx/rcx are 2 of the 4 GPRs arkham is short of against gcc.
      # `-d:arkhamStrictDivAcrossPanic` restores the old behaviour.
      var crossesDiverging = false
      when defined(arkhamStrictDivAcrossPanic):
        for p in c.noReturnPositions:
          if p > lo and p <= hi: (crossesDiverging = true; break)
      # A call-free local can go further: rdx/rcx have a *fixed* instruction role
      # (div/mod, variable shift) but are otherwise free. If no such instruction
      # falls in the interval, that register's role never overlaps this local's
      # life, so it is a legal extra home — the register-count generalization of
      # `AllRegs` (same interval test, per fixed-role register). The `regOccupied`
      # assertions in the allocator are the safety net if this analysis is wrong.
      # `s.pos > lo and hi >= s.stmtStart`, not the naive `s.pos <= hi`: a local
      # whose textually-last use precedes the clobber INSIDE the same statement
      # (operand of an instruction whose other operand subtree holds the div/shift,
      # e.g. `bitand(mask, shl(1, n))`) is still consumed AFTER the clobber
      # executes, so touching the clobber's statement at all denies the home.
      var crossesDiv = crossesDiverging
      for s in c.divPositions:
        if s.pos > lo and hi >= s.stmtStart: (crossesDiv = true; break)
      if not crossesDiv: vi.props.incl DivRegOk
      var crossesShift = crossesDiverging
      for s in c.shiftPositions:
        if s.pos > lo and hi >= s.stmtStart: (crossesShift = true; break)
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
  #
  # No synthetic call is INJECTED before a body, so the analysed IR is the whole story
  # about what runs before a param's first use: a global's runtime initializer is an
  # `(asgn …)` in the module's init proc, emitted by hexer and analysed like any other
  # statement.
  #
  # (Loop back-edge liveness for `usedAfterCall` is already resolved structurally at each
  # `WhileS` frame — see `LoopFrame` — so a param read only in a loop CONDITION whose body
  # contains a call is correctly flagged here without any post-pass.)
  if c.res.hasCall and c.procIsClean:
    for name, vi in mpairs c.res.vars:
      if vi.freeAfter == high(int) and AddrTaken notin vi.props and
         vi.usages > 0 and not vi.usedAfterCall and not vi.argUnsafe:
        vi.props.incl ArgResident
  when defined(arkhamPeakLive):
    reportPeakLive(c, pname, procStartPos, procEndPos)
  when defined(arkhamSSAStats):
    # The mild-SSA census: a local with `defs == 1` AND a decl initializer is an
    # SSA value (its one def is the decl, which dominates every use by scoping).
    # `defs == 1` without an initializer means one assignment SOMEWHERE — not
    # necessarily dominating — so those are tallied separately (`asgn1`).
    var nLocals, nSSA, nSSAUse1, nConst, nCopy, nAddrI, nLoopSSA, nAsgn1 = 0
    var nBirthFlip = 0    # denied AllRegs ONLY by call(s) inside the own initializer
    for name, vi in c.res.vars:
      if vi.freeAfter == high(int): continue      # params: homed by allocParams
      inc nLocals
      if AllRegs notin vi.props and vi.initEndPos > 0:
        var crosses = false
        for p in c.callPositions:
          if p >= vi.initEndPos and p <= vi.freeAfter: (crosses = true; break)
        if not crosses: inc nBirthFlip
      if vi.defs == 1:
        if vi.initClass == icNone:
          inc nAsgn1
        else:
          inc nSSA
          if vi.usages == 1: inc nSSAUse1
          if vi.declInLoop: inc nLoopSSA
          case vi.initClass
          of icConst: inc nConst
          of icCopy: inc nCopy
          of icAddr: inc nAddrI
          else: discard
    if nLocals > 0:
      stderr.write "SSASTATS proc=" & pname & " locals=" & $nLocals &
        " ssa=" & $nSSA & " (const=" & $nConst & " copy=" & $nCopy &
        " addr=" & $nAddrI & " use1=" & $nSSAUse1 & " inloop=" & $nLoopSSA &
        ") asgn1=" & $nAsgn1 & " birthflip=" & $nBirthFlip & "\n"
  result = ensureMove c.res
