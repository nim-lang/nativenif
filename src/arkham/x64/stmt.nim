#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Statements: the walk over a proc body, and the two shapes worth recognising
## before emitting one.
##
## `tryEmitCmov` folds a select diamond into a conditional move; `tryEmitCaseJmp`
## turns a dense `case` into a jump table. Both are attempts — they decline and
## leave the ordinary path to it — which is what keeps the recogniser honest
## about the cases it does not handle.
##
## `scanCondFusions` runs once per proc, ahead of emission: it finds the bools
## that are only ever branched on, so the compare's answer can travel in the
## flags and the `setcc` that would materialise them never happens.

import std / [assertions, tables, sets, algorithm]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, constdata,
                    mirrors, select, exprpred]
import machine as machine_x64
import emit, mem, aggr, value, frame

const CaseJmpMinBranches* = 4
  ## Below this the cmp/je chain is at most 3 compares — cheaper than the
  ## dispatch preamble (mov+sub+cmp+ja+imul+lea+add+jmp).

proc genStmt2*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {})
proc condFuseSym(g: CodeGen; c: Cursor): string

proc genVarDecl2*(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = cursorToPosition(g.buf[], cc)         # SymbolDef pos (aux key, matches allocVarDecl)
    if declPos in g.condFuse.decl:
      # The bool this declares is consumed by a fused branch and never materialized
      # (`scanCondFusions`), so it needs neither a declaration nor a register home.
      while cc.hasMore: skip cc
      return
    let nm = symName(cc); inc cc
    skip cc                                              # pragmas
    let declaredCur = cc; skip cc                        # type (`.` when shoggoth omitted it)
    let typeCur = g.declType(declaredCur, cc)            # infer from the initializer
    g.symType[nm] = typeCur                              # record the type for getType (conds)
    if nm in g.plan.aliasedCasts:
      # Identity-cast value alias (see `allocVarDecl`): `nm` has NO home of its own — its
      # `symPos` points at the source `c1`, so every use resolves to `c1`'s live register
      # and field/deref uses auto-emit `(cast T nm→c1)`. Emit NEITHER a decl NOR a store
      # (a decl would rebind the register away from the still-live `c1`). Keep only the
      # type record above so `getType`/cond helpers see `nm`'s (cast) type.
      while cc.hasMore: skip cc
    else:
      let loc = g.plan.homeOfSym(nm)
      let hasVal = cc.hasMore and cc.kind != DotToken
      # ── A register home whose value comes STRAIGHT FROM A CALL is declared AFTER
      # the call, not before it. Declaring first binds the register to a value that
      # does not exist yet; if that register is also an argument register (and on
      # x64 every volatile local home is one — `intLocalTempRegs` is rdi/rsi/r8/r9)
      # the marshaller must then `(kill …)` the binding to load the argument, the
      # result is written back RAW, and the local is live-and-UNBOUND for the rest
      # of its range. 559 bindings per nifbench build were stillborn that way — all
      # of them in rdi or rsi, argument 0 and 1 — and it is why `isBound` cannot be
      # made the whole authority for the emitter's temp filter (`regFreeForTemp`).
      #
      # Restricted to a ROOT-LEVEL call: nothing of this var is live in the register
      # while the call is set up (the value only exists once the result settles), so
      # leaving it unbound across the call is safe and no seal is needed. Any other
      # initializer keeps the old order, where the binding protects the partial
      # value from a nested temp pick.
      let callInit = hasVal and cc.kind == TagLit and cc.exprKind == CallC and
                     loc.kind == InReg
      if not callInit:
        case loc.kind
        of InReg: g.emRegLocalVar(nm, loc.r, typeCur)
        of InRegPair:
          raiseAssert "arkham x64n: InRegPair is a param home, not a local: " & nm
        of InFReg: g.emFRegLocalVar(nm, loc.f, loc.typ.size * 8)   # float local in an xmm
        of NamedStack:
          g.emTypedStackVar(nm, typeCur)
          if typeCur.kind == Symbol: g.varType[nm] = typeCur.symId  # aggregate field layout
        else: raiseAssert "arkham x64n: var home " & $loc.kind
      if hasVal:
        # Same-width cast/copy inheritance (see `allocVarDecl`): when the value is just
        # another local homed on THIS var's register, `emRegLocalVar` above already renamed
        # the register from the source to `nm` via a zero-machine-code `(rebind)` — the
        # value is in place, so the store is a no-op reg→reg move to skip entirely.
        var skipInit = false
        if loc.kind == InReg:
          let srcSym = copyCastSrcSym(cc)
          if srcSym.kind == Symbol:
            let sh = g.plan.locationOfSym(symName(srcSym), cursorToPosition(g.buf[], srcSym))
            if sh.kind == InReg and sh.r == loc.r: skipInit = true
        if not skipInit: g.genStore2(cc, loc)  # the one general store path
        if callInit:
          # The result is in the register now; bind the name to it. `emRegLocalVar`
          # emits only the `(var :nm (reg) T)` declaration — no machine code — so
          # this costs nothing and gives the value a name for the rest of its range.
          g.emRegLocalVar(nm, loc.r, typeCur)
      elif callInit:
        g.emRegLocalVar(nm, loc.r, typeCur)   # unreachable (callInit implies hasVal)
      while cc.hasMore: skip cc

proc emitCaseTest2*(g: var CodeGen; selReg: Reg; c: var Cursor; lBody: string; signed: bool) =
  ## One `case` BranchRange against `selReg`; jump to `lBody` on a match. The gate
  ## (`caseRangeModeled`) guarantees small-immediate bounds, so every `cmp` folds the
  ## bound inline (no scratch register — the pure emitter cannot borrow one).
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()                        # match iff lo <= sel <= hi
      g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit lo)
      g.emJcc(if signed: JlX64 else: JbX64, lSkip)
      g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit hi)
      g.emJcc(if signed: JgX64 else: JaX64, lSkip)
      g.emJmp(lBody)
      g.emLab(lSkip)
  else:
    g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit branchImm(c))
    g.emJcc(JeX64, lBody)

proc cmovTagFor(jccTag: X64Inst): X64Inst =
  ## The `cmov<cc>` whose condition matches `jccTag` (taken when the relation holds):
  ## `cmov<cc> D, S` performs `D = cc ? S : D`.
  case jccTag
  of JeX64:  CmoveX64
  of JneX64: CmovneX64
  of JlX64:  CmovlX64
  of JleX64: CmovleX64
  of JgX64:  CmovgX64
  of JgeX64: CmovgeX64
  of JbX64:  CmovbX64
  of JbeX64: CmovbeX64
  of JaX64:  CmovaX64
  of JaeX64: CmovaeX64
  else: raiseAssert "arkham x64: no cmov for " & $jccTag

proc readsReg(g: var CodeGen; n: Cursor; r: Reg): bool =
  ## Does expression `n` read a symbol whose home is register `r`? A
  ## register-homed local cannot be reached any other way (no memory aliases it),
  ## so scanning the symbols is exact.
  result = false
  if n.kind == Symbol:
    let l = g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
    result = l.kind == InReg and l.r == r
  elif n.kind == TagLit:
    var c = n
    c.into:
      while c.hasMore:
        if not result and g.readsReg(c, r): result = true
        skip c

proc tryEmitCmov(g: var CodeGen; c: Cursor): bool =
  ## Lower a select diamond (see `matchSelectDiamond`) branchlessly to
  ## `cmp; cmov<cc> DST, A` — no forward jumps, no label. Returns false for anything
  ## that does not fit; the caller then falls back to branch lowering.
  var sd: SelectDiamond
  if not g.matchSelectDiamond(c, sd): return false
  # ── emit: THEN→scratch → ELSE→DST → cmp (sets flags) → cmov DST, scratch ──
  # The COMPARE MUST BE LAST. Materializing a value is not flag-neutral: a store
  # of a sub-64-bit scalar re-normalizes with `shl reg,32; shr reg,32`, and `shr`
  # writes ZF. With the compare first, `(mov tag 15)(shl tag 32)(shr tag 32)` made
  # the following `cmovne` read the SHR's flags instead of the compare's and take
  # the THEN value unconditionally (`sem.nim`'s `tag = TagId(FalseTagId)`, whose
  # `TagId` is 32-bit — a silent wrong-branch miscompile in the self-hosted
  # compiler). The old order rested on "both stores are pure `mov`", which only
  # held for 64-bit destinations. (The a64 twin is unaffected: its stores are
  # `movz`/`movk` and its sign/zero-extends are `sbfm`/`ubfm`, none of which
  # touch NZCV.)
  #
  # Emitting the values first is correct only when the condition neither reads
  # DST — it is overwritten by the ELSE store before the compare — nor calls,
  # which would clobber the volatile staging register holding the THEN value.
  # Both are rare; they simply keep the branch lowering.
  if subtreeHasCallE(sd.a) or subtreeHasCallE(sd.b): return false
  if g.readsReg(sd.a, sd.dst.r) or g.readsReg(sd.b, sd.dst.r): return false
  let rT = g.pickStagingSealed("a cmov then-value", g.selectStagingSlot(sd), avoid = sd.dst.r)
  g.genStore2(sd.thenRhs, regLoc(rT, sd.dst.typ))
  g.genStore2(sd.elseRhs, sd.dst)
  let ct = cmovTagFor(g.emitScalarCmpE(sd.a, sd.b, sd.ek, whenTrue = true))
  g.ab.tree ct: (g.emReg sd.dst.r; g.emReg rT)
  g.giveBack rT
  return true

proc tryEmitCaseJmp(g: var CodeGen; c: Cursor): bool =
  ## Lower a DENSE `case` as a computed goto (`(casejmp …)`, see nifasm): the
  ## branch bodies become uniform NOP-padded slots and the dispatch is
  ## `jmp base + (sel-lo)*N` — no compare chain, no lookup table, no memory
  ## load. Fits when every of-branch has exactly ONE value, the values cover
  ## [lo, hi] with no gaps, and there are at least `CaseJmpMinBranches` of
  ## them. A non-match (sel < lo or > hi, one unsigned compare after the
  ## rebase) falls to else / the end. Returns false when the shape doesn't
  ## fit; the caller then uses the compare-chain lowering.
  var vals: seq[(int64, Cursor)] = @[]          # (branch value, body stmts cursor)
  var elseAt = c
  var hasElse = false
  var probe = sub(c)
  skip probe                                    # the selector expression
  while probe.hasMore:
    case probe.substructureKind
    of OfU:
      var b = sub(probe)                        # at the (ranges …) child
      var r = sub(b)
      var nvals = 0
      var v = 0'i64
      while r.hasMore:
        if r.kind == TagLit and r.substructureKind == RangeU:
          return false                          # a lo..hi range: not a single slot
        v = branchImm(r)
        inc nvals
      if nvals != 1: return false               # `of 1, 3:` would need body duplication
      skip b                                    # past (ranges …) → the body stmts
      vals.add (v, b)
      skip probe
    of ElseU:
      hasElse = true; elseAt = probe; skip probe
    else: skip probe
  if vals.len < CaseJmpMinBranches: return false
  vals.sort(proc (x, y: (int64, Cursor)): int = cmp(x[0], y[0]))
  for i in 1 ..< vals.len:                      # exactly dense: k, k+1, k+2, …
    if vals[i][0] != vals[i-1][0] + 1: return false  # a gap (or duplicate) breaks slot arithmetic
  let lo = vals[0][0]
  let hi = vals[^1][0]
  if lo < low(int32).int64 or hi > high(int32).int64: return false  # sub/cmp fold imm32
  # ── shape fits: emit ──
  let lEnd = g.freshLabel()
  let lElse = if hasElse: g.freshLabel() else: lEnd
  var cc = c
  cc.into:
    var selLoc = needsReg(ScalarSlot)           # a GPR, the callee's choice
    g.emitValue2(cc, selLoc); skip cc           # selector → its location
    while cc.hasMore: skip cc                   # bodies are emitted from `vals`
    # The slot index is COMPUTED IN PLACE (sub + imul destroy it), so it never
    # uses a live local's home register: copy/load the selector into a sealed
    # staging register first.
    var idx: Reg
    if selLoc.kind == InReg:
      idx = g.pickStagingSealed("casejmp index", ScalarSlot, avoid = selLoc.r)
      g.movReg(idx, selLoc.r)
      g.freeVal(selLoc)                         # selector dead after the copy
    else:
      idx = g.pickStagingSealed("casejmp index", ScalarSlot)
      g.emitLoadLoc(selLoc, idx)
    if lo != 0: g.binImm(SubX64, idx, lo)       # rebase to 0-based slot index
    # One UNSIGNED compare catches both sides: sel < lo wraps to a huge value.
    g.ab.tree CmpX64: (g.emReg idx; g.ab.intLit hi - lo)
    g.emJcc(JaX64, lElse)
    let base = g.pickStagingSealed("casejmp base", AddrSlot)
    var released = false
    g.ab.tree CasejmpX64:
      g.emReg idx
      g.emReg base
      for (v, body) in vals:
        g.ab.tree StmtsX64:
          if not released:
            # idx/base are dead once the indirect jump ran. Release them as slot
            # 0's first (zero-byte) statements: the `(kill)`s unbind sequentially
            # for the whole rest of the stream, and unsealing here keeps the R11
            # staging bridge available to spills inside the slot bodies (the
            # `produceIntoMem2` totality guarantee).
            g.giveBack base
            g.giveBack idx
            released = true
          g.genStmt2(body)                      # the branch body (a stmts node)
          g.emJmp(lEnd)                         # every slot ends in a terminating jump
    if hasElse:
      g.emLab(lElse)
      var e = elseAt
      e.into:
        while e.hasMore: (g.genStmt2(e); skip e)
  g.emLab(lEnd)
  result = true

proc emReturnHere(g: var CodeGen): bool =
  ## Return from HERE — `(popframe) (ret)` — instead of branching to the shared
  ## epilogue at the proc's tail. True when it did; `mayReturnHereE` owns the policy
  ## and `core/exprpred` the knobs, so both backends answer it the same way.
  ##
  ## `framePop`'s `(kill …)`s are NOT replayed here, and must not be: they exist
  ## because the shared epilogue is emitted LAST and may retire every binding, while
  ## whatever follows this site still reads its own names.
  if not g.mayReturnHereE(): return false
  g.ab.keyword PopframeX64
  g.ab.keyword RetX64
  true

proc listFlags(flags: set[StmtFlag]; rest: Cursor): set[StmtFlag] =
  ## What one child of a straight-line `stmts`/`scope` inherits from the list itself;
  ## `rest` is the cursor just PAST that child. The a64 twin, rule for rule.
  ##
  ## Only the last child inherits anything — control leaves every other one sideways —
  ## and "last" means "nothing after it emits CODE", not "no sibling follows". BOTH
  ## flags ask that: a `TailStmt` fall-through into the epilogue survives anything that
  ## emits no bytes just as a `TailPos` tail call does, and the shape that makes the
  ## difference is common — `rawDealloc` ends in an empty `(stmts .)` (its compiled-out
  ## `vgTracking` block), which under the syntactic test hid the `ret` before it.
  if restEmitsNoCodeE(rest): flags else: {}

proc armFlags(flags: set[StmtFlag]; rest: Cursor): set[StmtFlag] =
  ## What the last statement of an `if`/`case` ARM inherits from the compound itself.
  ## `TailStmt` deliberately does not travel here — a `ret` in an arm must still jump
  ## over the sibling arms — but `TailPos` does: a tail call never comes back, so the
  ## jump it would skip is dead either way.
  if TailPos in flags and restEmitsNoCodeE(rest): {TailPos} else: {}

proc genStmt2*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {}) =
  if c.kind == DotToken: return                 # an empty statement (e.g. `(stmts .)`)
  # `flags` is OUR tail position; children get whatever `listFlags`/`armFlags` says
  # travels to them, which for every nested compound is nothing at all — so a
  # mid-body `ret` still jumps.
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.genStmt2(cc, listFlags(flags, nx)); skip cc
  of ScopeS:
    # Forward Leng's scope to nifasm as a `(scope …)`: a `(stmts …)` with a
    # RECLAIMABLE slot arena. Every `(s)` slot declared inside is freed when it
    # closes, so sibling scopes — the arms of an `ite`, consecutive blocks —
    # share the same frame bytes and the prologue reserves the PEAK instead of
    # the sum. Leng's scope is exactly where a local's life ends, so it is the
    # boundary to forward; without this every slot a proc ever needed lived for
    # the whole proc.
    #
    # nifasm's arena is purely lexical (save `stackSize`, restore it at the
    # close) and touches no symbol table, so names, labels and bindings are
    # unaffected — only the offsets are. What the boundary DOES require is that
    # a slot declared inside is never read after it, which is Leng's own rule
    # for a local. The one arkham-minted slot that outlives its decl's scope is
    # the caller-save `csave` cell, and that one is declared in the prologue
    # for exactly this reason (see `planer.addSpillTemp`).
    g.ab.tree ScopeX64:
      g.enterScope()
      var cc = c
      cc.into:
        # A scope's kills trail its last statement but emit no bytes, so a tail
        # fall-through into the epilogue survives the boundary.
        while cc.hasMore:
          var nx = cc; skip nx
          g.genStmt2(cc, listFlags(flags, nx)); skip cc
      g.exitScope()
  of VarS, ConstS: g.genVarDecl2(c)    # a local const = an immutable var with a literal init
  of CallS:
    var d = dontCare                   # a statement call: result unused
    # A bare call at the END of a void proc is a tail call, and it is the shape the
    # `(ret (call …))` encoding cannot reach: a void proc has no `ret` for shoggoth's
    # fold to splice the call into, so `deallocBigChunk(a, c)` as the last statement of
    # `rawDealloc` came out `call`+`jmp epilogue` where gcc emits one `jmp`. In a
    # self-hosted nimsem that shape occurs 1,093 times against the 113 `(ret (call …))`
    # sites the encoding does find.
    #
    # `emitCall2` still decides — an external target, an outgoing stack argument, an
    # argument holding one of OUR frame's addresses — and emits an ordinary call when it
    # declines, which is why nothing here depends on the answer.
    g.emitCall2(c, d, tail = TailPos in flags and g.retIsVoid and
                             not g.frameIsAddressable)
    g.freeVal(d)
  of InstrS:
    var d = dontCare
    g.emitInstr2(c, d)
    g.freeVal(d)
  of BreakS:
    assert g.loopEnds.len > 0, "arkham x64n: `break` outside a loop"
    g.emJmp(g.loopEnds[^1])
  of AsgnS:
    var cc = c
    cc.into:
      let asgnPos = cursorToPosition(g.buf[], c)
      if asgnPos in g.condFuse.cmp:
        # `scanCondFusions` marked this: the bool is read only by the branch that
        # follows, so emit the COMPARE and stop. `emitCondE` takes the branch off the
        # flags — no `setcc`, no `and $1`, no `test`. Five instructions become two.
        let b = symName(cc); skip cc
        var op = cc
        let ek = op.exprKind
        var aC, bC: Cursor
        op.into:
          aC = op; skip op
          bC = op; skip op
          while op.hasMore: skip op
        g.condFuse.tag[b] = g.emitScalarCmpE(aC, bC, ek, whenTrue = true)
        while cc.hasMore: skip cc
        return
      if asgnPos in g.condFuse.link:
        # A chain LINK: `b2 = b1` or `b2 = not b1`, both single-use. Emits nothing —
        # just move the pending tag to the new name, inverted once per `not`.
        let b2 = symName(cc); skip cc
        var t = cc
        var negations = 0
        while t.kind == TagLit and t.exprKind == NotC:
          inc t; inc negations
        let src = symName(t)
        var tag = g.condFuse.tag[src]
        for _ in 1 .. negations: tag = invertJcc(tag)
        g.condFuse.tag.del src
        g.condFuse.tag[b2] = tag
        while cc.hasMore: skip cc
        return
      if cc.kind == Symbol:
        let lhsCur = cc                                     # for asLoc (global/tvar)
        var dst = g.plan.locationOfSym(symName(cc), cursorToPosition(g.buf[], cc)); skip cc  # local lvalue; a global → Undef
        if dst.kind == NoLoc:                               # module-level global / threadvar
          var lc = lhsCur
          dst = g.asLoc(lc)                                 # Glob/Tvar with precise type
        elif dst.kind == InReg and g.varType.hasKey(symName(lhsCur)):
          # A by-ref aggregate param whose POINTER is register-homed: the assignment's
          # destination is the pointee, not the pointer. An `InReg` home says nothing
          # about that (its `typ` is the pointer's), so reclassify to the `Mem` lvalue
          # form — every aggregate path already reaches a bare Symbol through
          # `aggrAddrInto`/`emLvalAddr2`'s InReg case. Without this the store fell into
          # the scalar arm and a whole-aggregate copy moved the POINTER (the params
          # aliased from then on) — the register twin of the pre-`StackPtr` bug.
          dst = memLoc(lhsCur, g.exprSlot(lhsCur))
        g.genStore2(cc, dst)                       # the one general store path
      else:
        # A memory store through a complex lvalue (dot/deref/at).
        let lhsCur = cc
        # `x.f = x.f <op> v` first: the read-modify-write folds into ONE
        # `(op (mem x.f) v)` and skips the load, the temp and the store back.
        if not g.tryRmwStore2(lhsCur):
          var rhsCur = cc; skip rhsCur                      # past the lhs → the rhs value
          g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot))   # the one general store path
      while cc.hasMore: skip cc
  of WhileS:
    let lEnd = g.freshLabel()
    g.loopEnds.add lEnd
    g.emitLoop:
      var cc = c
      cc.into:
        let condC = cc; skip cc
        g.emitCondE(condC, lEnd, whenTrue = false)     # forward exit when cond is false
        while cc.hasMore: (g.genStmt2(cc); skip cc)     # body
    g.emLab(lEnd)
    discard g.loopEnds.pop()
  of IfS:
    # A cond fused by `scanCondFusions` has no materialized bool for `tryEmitCmov` to
    # select on — the answer is in the flags and only `emitCondE` knows how to spend it.
    let fusedSym = g.condFuseSym(c)
    let isFused = fusedSym.len > 0 and g.condFuse.tag.hasKey(fusedSym)
    if isFused or not g.tryEmitCmov(c):  # branchless select diamond, else fall through
      let lEnd = g.freshLabel()
      var cc = c
      cc.into:
        while cc.hasMore:
          case cc.substructureKind
          of ElifU:
            let lNext = g.freshLabel()
            var peek = cc; skip peek
            let isLastBranch = not peek.hasMore   # no `elif`/`else` follows this branch
            var bc = cc
            bc.into:
              let condC = bc; skip bc
              g.emitCondE(condC, lNext, whenTrue = false)
              while bc.hasMore:
                var nb = bc; skip nb
                # The arm's LAST statement inherits the `if`'s own tail position — see
                # `armFlags` for which half of it travels here.
                g.genStmt2(bc, armFlags(flags, nb)); skip bc
              # The skip-to-merge jump exists only to hop over later branches; the last
              # branch has none, so it falls through `lNext` (empty) into `lEnd`.
              #
              # When the `if` ITSELF is in tail position, `lEnd` is the epilogue —
              # nothing between them emits a byte (`TailPos` was carried past exactly
              # those statements) — so the arm can RETURN instead of branching to a
              # branch. This is the single hottest forward jump in the allocator:
              # `rawDealloc`'s hot arm jumped to the epilogue 768,932 times per run,
              # and gcc emits a `ret` there because it duplicates its epilogue into
              # each arm rather than sharing one.
              if not isLastBranch:
                if not (TailPos in flags and g.emReturnHere()): g.emJmp(lEnd)
            g.emLab(lNext)
          of ElseU:
            var bc = cc
            bc.into:
              while bc.hasMore:
                var nb = bc; skip nb
                g.genStmt2(bc, armFlags(flags, nb)); skip bc
          else: discard
          skip cc
      g.emLab(lEnd)
  of RetS:
    var cc = c
    cc.into:
      let hasVal = cc.hasMore and cc.kind != DotToken
      if g.isEntryProc and not g.prog.windows:
        # The Linux entry proc terminates the process: its return value is the
        # exit status. (The Windows entry returns normally — see emProcessExit.)
        if hasVal:
          var v = needsReg(ScalarSlot)
          g.emitValue2(cc, v)
          g.emProcessExit(v)
          g.freeVal(v)
        else:
          g.emProcessExit(immLoc(0, ScalarSlot))
      else:
        var tailed = false
        if g.retAggrSym != NoTypeSym:                          # aggregate return
          var srcName: string
          if cc.kind == Symbol:
            srcName = symName(cc)                          # a named local aggregate
          else:
            # An inline aggregate VALUE returned by value (`$`'s `(ret (oconstr
            # string …))`, or a memory lvalue): materialize it into a synthetic temp
            # via the general store path (mirrors the aggregate call-argument
            # marshalling), then marshal that temp out by the ABI below.
            let pos = cursorToPosition(g.buf[], cc)
            srcName = synth("rettmp") & $pos & ".0"
            var tcur = cc
            if cc.exprKind in {OconstrC, AconstrC}: inc tcur   # the constructed type
            else: tcur = g.getType(cc)
            g.emTypedStackVar(srcName, tcur)
            g.varType[srcName] = g.retAggrSym
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)))
          if g.retIndirect:                                # >16B: copy through the hidden ptr
            g.copyStructThroughPtr2(srcName, g.retAggrSym, g.indirectReg)
            g.movReg(RAX, g.indirectReg)                   # SysV: return the buffer pointer in rax
          else:
            g.releaseRetRegs()
            g.structToRegs(srcName, g.retAggrSym, x64RetRegs)  # ≤16B → rax:rdx
        elif hasVal and cc.kind == TagLit and cc.exprKind == CallC and
             not g.retIsFloat:
          # `(ret (call …))` — the tail-call encoding. Leng binds every call and
          # forbids nesting them, so a call sitting directly under a `ret` is not an
          # expression that happens to be there: it is the producer saying
          # "tail-call this". Hand it to `emitCall2`, which marshals the arguments
          # exactly as for an ordinary call and then pops the frame and jumps.
          #
          # It may still decline — an external target, an outgoing stack argument, a
          # by-reference result — in which case it emitted an ordinary call and left
          # the value in `d`, and we return through the epilogue as usual.
          var d = needsReg(g.valueSlot(cc))
          g.emitCall2(cc, d, tail = true)
          if not g.tailCallEmitted:
            g.place2(d, g.md.intRetReg)
            g.freeVal(d)
          tailed = g.tailCallEmitted
        elif hasVal:                                       # scalar / float result → ret reg
          let retPos = cursorToPosition(g.buf[], cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(FloatRet, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)))
          else:
            g.genStore2(cc, regLoc(g.md.intRetReg, ScalarSlot))
        # The epilogue (framePop + ret) is emitted ONCE at the proc tail by
        # emitProcBody2; a `ret` that is NOT the tail cannot fall through into the
        # statements that follow it (e.g. a mid-proc `if cond: return x`), so it either
        # RETURNS HERE or jumps to that shared copy.
        # A tail `ret` falls straight through the (zero-byte) scope kills into the
        # epilogue, so it needs neither and does not force the shared label.
        # A TAIL CALL has left the proc for good: nothing after it is reachable.
        #
        # Returning here is `(popframe) (ret)`, and `(popframe)` is what makes it
        # possible at all: the frame's shape — how many callee-saved pushes, whether a
        # frame `sub` exists — is final only AFTER the body is emitted, and this site is
        # inside the body. nifasm replays the prologue it has already assembled, so
        # nothing is guessed and the teardown is byte-identical to the shared one (the
        # same guarantee the tail-call encoding rests on).
        #
        # It trades one `jmp` per EXECUTION for the epilogue's bytes per SITE. On
        # alloc_bench the jump to the epilogue is the single hottest forward branch —
        # 768,932 executions in `rawDealloc` alone, and 2.48 M against gcc's 2,267 for
        # the whole program, because gcc duplicates its `ret` into each arm and falls
        # through. `framePop`'s `(kill …)`s are NOT replayed here, and must not be: they
        # exist because the shared epilogue is emitted last and can retire every binding,
        # while a sibling arm after this one still reads its own names.
        if TailStmt notin flags and not tailed:
          if not g.emReturnHere():
            g.emJmp(g.retLabel2); g.retLabelUsed2 = true
      while cc.hasMore: skip cc
  of CaseS:
    # A dense single-value case lowers to the computed-goto dispatch (issue #32);
    # anything else falls through to the compare-chain lowering below.
    if g.tryEmitCaseJmp(c): return
    # `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`. Mirrors the
    # legacy genCase: selector → a register live across ALL range tests; a non-match
    # falls through to else (or the end); bodies are emitted AFTER the test chain, so
    # each ends in a jmp to lEnd. (Leng `case` has no fall-through.)
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      var selLoc = needsReg(ScalarSlot)                  # held across ALL range tests
      g.emitValue2(cc, selLoc); skip cc
      # The selector must live in a GPR across the whole test chain. `emitValue2`
      # may leave it spilled (NamedStack) or homed in a tvar/global; in that case
      # load it into a sealed staging register for the duration of the tests.
      var selReg: Reg
      var ownSelReg = false
      if selLoc.kind == InReg:
        selReg = selLoc.r
      else:
        selReg = g.pickStagingSealed("case selector", selLoc.typ)
        g.emitLoadLoc(selLoc, selReg)
        ownSelReg = true
      var bodies: seq[(string, Cursor)] = @[]
      var elseBody = cc
      var hasElse = false
      while cc.hasMore:                                   # emit every of-branch test chain
        case cc.substructureKind
        of OfU:
          let lBody = g.freshLabel()
          var branch = cc
          skip cc
          branch.into:
            branch.into:                                  # into (ranges …)
              while branch.hasMore: g.emitCaseTest2(selReg, branch, lBody, signed)
            bodies.add (lBody, branch)                    # branch now at the body stmts
            skip branch                                   # drain past the body
        of ElseU:
          elseBody = cc; hasElse = true; skip cc
        else: skip cc
      if ownSelReg: g.giveBack(selReg)                    # release the staging reg we loaded into
      else: g.freeVal(selLoc)                             # selector dead after the tests
      # EMISSION ORDER MUST FOLLOW LENG ORDER. The emitter's binding state is a
      # single linear walk while every liveness question (`freeAfter`, and hence
      # "may this register be taken for a staging temp") is keyed on the Leng token
      # POSITION. Emitting the `else` body — which is Leng-LAST — before the
      # of-bodies retires every binding whose last use lies inside an of-branch, and
      # the of-bodies then read a register nothing keeps for them any more. So the
      # non-match jumps FORWARD over the bodies to the else, which is emitted last.
      let lElse = if hasElse: g.freshLabel() else: lEnd
      g.emJmp(lElse)
      for idx in 0 ..< bodies.len:
        g.emLab(bodies[idx][0])
        # The arm inherits the case's own tail position, whole: its body is the last
        # thing before `lEnd`, so there is no "rest" to ask about.
        g.genStmt2(bodies[idx][1], flags * {TailPos})     # body (a stmts node)
        # only the last body may fall through, and only when no else follows it
        if idx < bodies.len - 1 or hasElse:
          if not (TailPos in flags and g.emReturnHere()): g.emJmp(lEnd)
      if hasElse:
        g.emLab(lElse)
        var e = elseBody
        e.into:
          while e.hasMore:
            var ne = e; skip ne
            g.genStmt2(e, armFlags(flags, ne)); skip e
    g.emLab(lEnd)
  of LabS:                                                # `(lab :name)` — a goto target
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:                                                # `(jmp name)` — unconditional goto
    var cc = c
    cc.into:
      g.emJmp(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of KeepovfS:
    # `(keepovf (op type a b) dest)` — an overflow-checked arithmetic store: emit the
    # plain `dest = a op b` (like AsgnS, value FIRST), which leaves the hardware
    # overflow/carry flag set; the `(ovf)` test that MUST immediately follow reads it
    # (see emitCond2). The result store is a flag-preserving `mov`, so the flag is
    # still live at the test. Record the op's signedness so that test picks `jo` (OF,
    # signed) vs `jb` (CF, unsigned).
    var cc = c
    cc.into:
      let kPos = cursorToPosition(g.buf[], c)
      var opCur = cc                                        # the (op …) value
      # The `(ovf)` that follows reads the flag THIS op sets: emit it even when
      # constant-foldable (the allocator suppressed the fold at this position too).
      g.noFoldPos = cursorToPosition(g.buf[], opCur)
      block:
        var opTy = opCur; inc opTy                          # past the op tag → its result type
        g.ovfSigned = isSignedType(opTy)
        # The hardware OF/CF reflects overflow at the OP's width, but arkham keeps int
        # locals in 64-bit registers, so a sub-64-bit `keepovf` would need a narrow op
        # (or a sign-extend/compare) for its `(ovf)` to be correct. Native-width (`int`
        # = `(i -1)`, and `(i 64)`/`(u 64)`) is exact; reject narrower widths loudly
        # rather than silently miss overflow.
        if intTypeWidth(opTy) < 64:
          raiseAssert "arkham x64n: keepovf for sub-64-bit type not yet supported " &
                      "(width " & $intTypeWidth(opTy) & ")"
      skip cc                                               # advance to dest
      if cc.kind == Symbol:
        let lhsCur = cc
        var dst = g.plan.locationOfSym(symName(cc), cursorToPosition(g.buf[], cc)); skip cc
        if dst.kind == NoLoc:
          var lc = lhsCur
          dst = g.asLoc(lc)
        g.genStore2(opCur, dst)
      else:
        let lhsCur = cc; skip cc
        g.genStore2(opCur, memLoc(lhsCur, ScalarSlot))
      g.noFoldPos = -1
      while cc.hasMore: skip cc
  else: raiseAssert "arkham x64n: genStmt2 " & $c.stmtKind

proc condFuseSym(g: CodeGen; c: Cursor): string =
  ## The bool symbol an `(if …)`'s FIRST branch tests, when that branch's condition is
  ## a bare symbol — the only shape `scanCondFusions` fuses.
  result = ""
  if c.kind != TagLit or c.stmtKind != IfS: return
  var cc = c
  cc.into:
    if cc.hasMore and cc.substructureKind == ElifU:
      var bc = cc
      bc.into:
        if bc.hasMore:
          # Peel `(not …)`: `emitCondE` lowers it by flipping `whenTrue` and recursing,
          # so the symbol underneath still reaches the fused-flags path. Worth peeling —
          # `(if (elif (not b) …))` is where the HOT sites are (`allocatedSize` alone is
          # 17.7 M), because hexer inlines `>`/`>=` as `not (le …)` / `not (lt …)`.
          var t = bc
          var guard = 0
          while t.kind == TagLit and t.exprKind == NotC and guard < 8:
            inc t                       # → the negated operand
            inc guard
          if t.kind == Symbol: result = symName(t)
        while bc.hasMore: skip bc
    while cc.hasMore: skip cc

proc scanCondFusions(g: var CodeGen; body: Cursor) =
  ## A materialized bool that is branched on straight away costs FIVE instructions:
  ##
  ##     (test `sroa.8 `sroa.8)     ← the compare
  ##     (setg `x.0h149)            ← materialize 0/1
  ##     (and `x.0h149 1)           ← `setcc` writes ONE byte; clear the rest
  ##     (test `x.0h149 `x.0h149)   ← …and the consumer looks at it again
  ##     (je `L92.0)
  ##
  ## where `(test `sroa.8 `sroa.8) (jle `L92.0)` says the same thing. The shape is
  ## hexer's INLINER: a one-expression `proc <(a, b: int): bool` becomes a
  ## declaration, a `(scope …)` holding `(asgn b (lt …))` and the inlined body's
  ## return label, and then the branch. **328 of the 511 `setcc`+`and` sites in a
  ## nifbench build are exactly this**, and in the finished image all five
  ## instructions are adjacent.
  ##
  ## Marked here, acted on in `genStmt2`/`emitCondE`. The compare stays exactly where
  ## it is — moving it to the branch would name operands whose scope has closed — and
  ## only the ANSWER travels, in the flags. That is sound because `setcc` never writes
  ## flags, and because this pass only fuses when every statement between the two
  ## emits no machine code: an unreferenced `(lab …)`, a value-less declaration, a
  ## `(scope …)` boundary (whose `(kill …)`s are metadata).
  g.condFuse.resetPlan()
  # Referenced labels first: a `(lab :L)` that some `(jmp L)` targets is a JOIN, so
  # the flags arriving there are whatever the other path left.
  var jumpTargets = initHashSet[string]()
  var symCount = initCountTable[string]()
    ## Every `Symbol` occurrence in the body, by name. A `SymbolDef` is a different
    ## kind and does not count, so the fusable bool — one `(asgn b …)` target and one
    ## `(elif b …)` condition — is exactly the name with a count of 2. That is a
    ## stronger and cheaper test than asking the analyser for `usages`/`defs`/
    ## `AddrTaken`: with both occurrences accounted for, there is no third.
  block:
    var stack = @[body]
    while stack.len > 0:
      var cur = stack.pop()
      if cur.kind != TagLit: continue
      if cur.stmtKind == JmpS:
        var jc = cur
        jc.into:
          if jc.hasMore and jc.kind == Symbol: jumpTargets.incl symName(jc)
          while jc.hasMore: skip jc
        continue
      var ch = cur
      ch.into:
        while ch.hasMore:
          if ch.kind == TagLit: stack.add ch
          elif ch.kind == Symbol: symCount.inc symName(ch)
          skip ch

  var pendingSym = ""          # a candidate `(asgn b <cmp>)` seen, nothing emitted since
  var pendingPos = -1
  var copyPos: seq[int] = @[]  # the chain links behind `pendingSym`
  var chainDecls: seq[string] = @[]
  var declPos = initTable[string, int]()

  proc walk(g: var CodeGen; n: Cursor) =
    var c = n
    c.into:
      while c.hasMore:
        if c.kind != TagLit:                 # a bare operand, not a statement
          pendingSym = ""
          skip c
          continue
        let pos = cursorToPosition(g.buf[], c)
        case c.stmtKind
        of StmtsS, ScopeS:
          walk(g, c)                       # transparent: emits no code of its own
          skip c
          continue
        of LabS:
          var lc = c
          var nm = ""
          lc.into:
            if lc.hasMore and lc.kind == Symbol: nm = symName(lc)
            while lc.hasMore: skip lc
          if nm in jumpTargets: pendingSym = ""     # a join point: flags are not ours
          skip c
          continue
        of VarS, ConstS:
          # A value-less declaration emits nothing; one with an initializer does.
          var vc = c
          var nm = ""
          var symDefPos = -1
          var hasVal = false
          vc.into:
            if vc.hasMore:
              # The SAME key `genVarDecl2` uses: the SymbolDef's position, not the
              # statement's.
              symDefPos = cursorToPosition(g.buf[], vc)
              nm = (if vc.kind == SymbolDef: symName(vc) else: "")
              skip vc
            if vc.hasMore: skip vc                  # pragmas
            if vc.hasMore: skip vc                  # type
            hasVal = vc.hasMore and vc.kind != DotToken
            while vc.hasMore: skip vc
          if hasVal: pendingSym = ""
          elif nm.len > 0: declPos[nm] = symDefPos
          skip c
          continue
        of AsgnS:
          var ac = c
          var lhs = ""
          var isCmp = false
          var copyOf = ""            # rhs is `b` or `(not b)` — a chain LINK
          ac.into:
            if ac.hasMore and ac.kind == Symbol: (lhs = symName(ac); skip ac)
            if ac.hasMore:
              if ac.kind == TagLit and ac.exprKind in {EqC, NeqC, LtC, LeC}:
                var op = ac
                op.into:
                  isCmp = op.hasMore and not g.isFloatExpr(op)
                  while op.hasMore: skip op
              else:
                var t = ac
                var guard = 0
                while t.kind == TagLit and t.exprKind == NotC and guard < 8:
                  inc t; inc guard
                if t.kind == Symbol: copyOf = symName(t)
            while ac.hasMore: skip ac
          if lhs.len > 0 and isCmp and symCount[lhs] == 2:
            pendingSym = lhs; pendingPos = pos
            copyPos.setLen 0                 # a fresh chain head: drop any aborted chain
            chainDecls = @[lhs]
          elif lhs.len > 0 and copyOf.len > 0 and copyOf == pendingSym and
               symCount[lhs] == 2:
            # `b2 = b1` / `b2 = not b1`, both single-use: the answer is still only in
            # the flags. hexer renames the result bool once per inlined splice, so this
            # link is what connects `isValid`'s `(eq …)` to the caller's branch.
            copyPos.add pos
            pendingSym = lhs
            chainDecls.add lhs
          else:
            pendingSym = ""
          skip c
          continue
        of IfS:
          let s = g.condFuseSym(c)
          if s.len > 0 and s == pendingSym:
            g.condFuse.cmp.incl pendingPos
            for p in copyPos: g.condFuse.link.incl p
            for nm in chainDecls:
              if declPos.hasKey(nm): g.condFuse.decl.incl declPos[nm]
          else:
            when defined(arkhamFuseDbg):
              if s.len > 0:
                stderr.writeLine "FUSEMISS " & g.curProcName & " cond=" & s &
                  " pending=" & pendingSym & " count=" & $symCount[s]
          pendingSym = ""; copyPos.setLen 0; chainDecls.setLen 0
          walk(g, c)                       # the branches themselves still get scanned
          skip c
          continue
        else:
          pendingSym = ""
          walk(g, c)
          skip c

  walk(g, body)

proc emitProcBody2*(g: var CodeGen; info: ProcInfo; frameHasCall: bool) =
  ## The pure-emitter twin of `emitProcBody`, run ONCE (no plan pass). Reuses the
  ## shared signature / frame / param-settling / scope machinery; only the value
  ## core (`genStmt2`/`emitValue2`) differs.
  ##
  ## Body-buffer model (chibicc's trick): the BODY is emitted into a side buffer
  ## first; the prologue — whose shape (callee-saved pushes, alignment pad, the
  ## `(s)` region `sub`) is only final once the body is known — is written after
  ## it, into the main buffer, and the body appended. This is what lets the
  ## merged value core mint spill slots and draw callee-saved temps INLINE
  ## during emission. Only `stackArgBaseReg`'s identity is fixed up front (the
  ## body's stack-param loads name it).
  g.pickStackArgBaseX64(g.plan.hasStackParams)
  # Seal the base so inline callee-saved temp draws during the body cannot take
  # it (its pushes/loads are written into the prologue after the body).
  if g.stackArgBaseReg != NoReg: g.plan.seal {g.stackArgBaseReg}
  # Per-proc reset of the RAW-home reservation. `narrowHomes` asks `rawHomeRegs` — the
  # registers whose occupant `rb` genuinely cannot see — instead of the whole-proc
  # `regHoldsHome` union; see `regFreeForTemp` for the four fixes that made that sound.
  # `ARKHAM_NH` narrows it to named procs, which is how each remaining miscompile was
  # BISECTED (the failure is a run-time segfault, not a nifasm error, so it can only be
  # localized by building the program with the filter on for a subset of procs).
  g.rawHomeRegs = {}
  if g.stackArgBaseReg != NoReg: g.rawHomeRegs.incl g.stackArgBaseReg
  when not defined(arkhamNoNarrowHomes): g.narrowHomes = nhEnabledFor(g.curProcName)
  var side = g.ab.sideBuf()
  swap(g.ab, side)                        # emit into the side buffer; `side` holds main
  g.enterScope()
  if g.retIndirect:
    # The hidden result pointer arrives in rdi. Save it into the callee-saved
    # `indirectReg` for the duration of the body. In the DECLARATIVE path the
    # signature binds rdi to `paramName(0)`, so it must be read by name (a raw
    # `(reg rdi)` use of a bound register is rejected) and the binding killed. But a
    # NON-declarative proc (float/≤16B-aggregate-result param forces an empty
    # signature) never emits that binding, so there `p0.0` is undefined — read the
    # raw arg register instead, mirroring how non-declarative params are moved.
    if isDeclarativeAbi(g.prog, info.decl):
      g.ab.tree MovX64: (g.emReg g.indirectReg; g.ab.sym paramName(0))
      g.ab.tree KillX64: g.ab.sym paramName(0)
    else:
      g.movReg(g.indirectReg, g.md.intArgRegs[0])
    # Name it, for the same reason the relocated parameters above are named: unnamed,
    # it was the last big block of raw register operands (564 of the 742 left after
    # `emitParamMoves` was fixed) — every `(mov (mem (at (cast (aptr (u 64)) (rbx))k))
    # …)` writing the result buffer out. It has no `symPos` entry, so it was not even
    # in the `regHoldsHome` union; only `rawHomeRegs` reserved it. `framePop` kills the
    # binding before the pops (`indirectReg` is RBX, always a frame register here).
    if g.retAggrSym != NoTypeSym:
      g.emRegAggrPtrVar(synth("retptr.0"), g.indirectReg, g.retAggrSym)
    else:
      g.rawHomeRegs.incl g.indirectReg
  g.emitParamMoves(info.decl)
  g.emitStackParamLoadsX64(info.decl)               # via stackArgBaseReg, regs now free
  g.retLabel2 = g.freshLabel()                       # shared epilogue for mid-proc `ret`
  g.retLabelUsed2 = false
  g.binNormSuppressPos = -1                          # no store-fused normalize elision pending
  var c = info.decl
  c.into:
    inc c; skip c; skip c; skip c                    # name, params, ret, pragmas
    # The whole body is in tail position: after it, control reaches the epilogue.
    # The LINUX entry proc ends in an exit syscall (no epilogue jump), so it gets
    # no flags at all; the Windows entry returns like any other proc.
    let bodyFlags: set[StmtFlag] =
      if info.isEntry and not g.prog.windows: {} else: {TailStmt, TailPos}
    if c.stmtKind == StmtsS:
      g.condFuse.tag.clear()
      g.scanCondFusions(c)
      g.genStmt2(c, bodyFlags)
    while c.hasMore: skip c
  g.exitScope()
  if g.retLabelUsed2: g.emLab(g.retLabel2)           # a non-tail `ret` lands here
  if info.isEntry and not g.prog.windows:
    g.emProcessExit(immLoc(0, ScalarSlot))    # fell off the end of `main` ⇒ exit(0)
  swap(g.ab, side)                        # back to the main buffer; `side` holds the body
  when defined(arkhamHomeDbg):
    var inReg = 0
    for pos in g.plan.symPos.values:
      if g.plan.planned(pos).kind == InReg: inc inReg
    if g.plan.homesDirty: rebuildHomes(g.plan)
    var maskN = 0
    for r in g.plan.homeRegs: inc maskN
    stderr.writeLine "HOMEDBG proc=" & g.curProcName & " regHomedSyms=" & $inReg &
                     " maskSize=" & $maskN
  # The body is emitted — `plan.usedCallee` / `hasStackVars` are final. Finalize the
  # frame and write the prologue, then splice the body after it.
  g.computeFrameX64(info.isEntry, frameHasCall)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl)
    g.ab.tree StmtsX64:
      g.framePush()
      # Capture the incoming stack-args base (rsp after the pushes) BEFORE the frame
      # `sub`s move rsp — stack params are then loaded relative to it, after the `(s)`
      # region exists and `emitParamMoves` has freed the arg registers. RAW register
      # operands: this text is written AFTER the body was emitted (body-buffer model),
      # so `emReg`/`binImm` would render whatever binding the reg carries post-body —
      # a name that, in program order, is not bound yet at this point.
      if g.stackArgBaseReg != NoReg:
        g.ab.tree MovX64: (g.ab.rawReg g.stackArgBaseReg; g.ab.rawReg RSP)
        g.ab.tree AddX64:
          g.ab.rawReg g.stackArgBaseReg
          g.ab.intLit g.framePushBytesX64().int64
      g.emitFrameSub()
      # The PLANNER's spill slots — the `csave` cells of caller-saved homes. They
      # belong here and not where they are decided: a save slot must not sit inside
      # the decl's scope, because arkham emits by a textual walk and a sibling branch
      # saves through the same slot (see `planer.addSpillTemp`). The value core's own
      # `etmp`/`eftmp`/`held` are NOT in this list: those are declared where they are
      # minted, which is a statement position in every case.
      for st in g.plan.spillTemps:
        g.declSpillSlot(st.name, st.typ, st.isFloat)
      g.ab.append side                                 # the body
      if not info.isEntry:
        g.framePop()
        g.ab.keyword RetX64
