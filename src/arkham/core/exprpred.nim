#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Syntactic questions about an expression, asked before emitting it.
##
## Is it foldable into an operand, does it read this register, does it contain a
## call, which fixed registers will it clobber? Together with the caller-save
## rescue that reads the last of them: what has to be spilled around a call, and
## where each spilled value goes.

import std / [tables, assertions, algorithm]

import nifcore, nifcdecl
import asmslots, machinedesc, analyser, planer, programs, abi
import "../risc/machine_m"
import regbind, context


# ── fused value core: syntactic operand predicates (shared by both backends) ─
# Ports of the allocator's private Builder predicates; these become the only
# copies once the allocator's expression walk is deleted.

proc commutativeExpr*(ek: LengExpr): bool {.inline.} =
  ## Integer ops for which `a op b == b op a` (so the heavier operand may be
  ## evaluated first and the lighter one folded after). `sub` is handled too —
  ## via a `neg` after the swap — but is NOT commutative, so it is separate.
  ek in {AddC, MulC, BitandC, BitorC, BitxorC}

proc isMemLeaf(n: Cursor): bool {.inline.} =
  ## A foldable memory-load operand: a `dot`/`deref`/`at`/`pat` addressing
  ## chain in value position (folds as `op reg, [mem]` instead of pinning a
  ## register across a sibling — operands are pure, hexer un-nests calls).
  n.kind == TagLit and n.exprKind in {DotC, DerefC, AtC, PatC}

proc isFoldableLeaf*(g: var CodeGen; n: Cursor): bool =
  ## A value needing NO register held across a sibling subtree: an immediate,
  ## or a function-local symbol read (folds as its reg / stack-home operand).
  case n.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n)).kind in {InReg, NamedStack}
  else: false

proc symInReg*(g: var CodeGen; n: Cursor; reg: Reg): bool {.inline.} =
  ## Is `n` a symbol homed in `reg`? (Forbids a Sethi–Ullman swap whose
  ## rhs-into-dest evaluation would clobber a lhs homed in dest.)
  if n.kind != Symbol: return false
  let h = g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
  h.kind == InReg and h.r == reg

proc exprReadsRegImpl(g: var CodeGen; n: var Cursor; reg: Reg): bool =
  if n.kind == Symbol:
    let h = g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
    inc n
    return h.kind == InReg and h.r == reg
  elif n.kind == TagLit:
    n.into:
      while n.hasMore:
        if g.exprReadsRegImpl(n, reg): return true
  else:
    inc n
  return false

proc exprReadsReg*(g: var CodeGen; n: Cursor; reg: Reg): bool =
  ## True iff the subtree at `n` reads a symbol homed in `reg` — the guard for
  ## computing a binop's left operand straight into a pinned `dest` register.
  var c = n
  g.exprReadsRegImpl(c, reg)

proc lvalueGlobalBase*(g: var CodeGen; n: Cursor): bool =
  ## Does the lvalue chain `n` (a `dot`/`at` over a symbol) bottom out at a
  ## module-level global aggregate? Such a base needs its address materialized
  ## into a scratch register. A `deref`/`pat` base is a pointer VALUE, not a
  ## global lvalue, so it stops the search. (Fused port of the allocator's
  ## private `lvalueGlobalBase`.)
  var c = n
  case c.kind
  of Symbol: result = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc
  of TagLit:
    case c.exprKind
    of DotC, AtC:
      var cc = c
      cc.into:
        result = g.lvalueGlobalBase(cc)
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc fixedRegsClobberedBy*(g: var CodeGen; n: Cursor): set[Reg] =
  ## Registers this expression is FORCED to overwrite because the ISA pins
  ## them: `cl` (rcx) for a runtime shift count, rdx (+rax) for `idiv`. An
  ## already-marshalled call argument sitting in one of them is destroyed with
  ## no diagnostic, so the fused call marshaller parks such arguments off
  ## their ABI register. Empty on AArch64. (Fused port of the allocator's
  ## `fixedRegsClobberedBy`.)
  result = {}
  if g.md.shiftCountReg == NoReg and g.md.divRemReg == NoReg: return
  var stack = @[n]
  while stack.len > 0:
    var c = stack.pop()
    if c.kind != TagLit: continue
    case c.exprKind
    of ShlC, ShrC:
      if g.md.shiftCountReg != NoReg:
        var count = c; inc count                 # tag → result type
        skip count                               # result type → lhs
        skip count                               # lhs → count
        if count.hasMore and not isConstShiftCount(count):
          result.incl g.md.shiftCountReg
    of DivC, ModC:
      if g.md.divRemReg != NoReg:
        result.incl g.md.divRemReg
        if g.md.intRetReg != NoReg: result.incl g.md.intRetReg
    else: discard
    var ch = c
    ch.into:
      while ch.hasMore:
        stack.add ch
        skip ch

proc subtreeHasCall*(n: Cursor): bool =
  ## Does this expression subtree contain a CALL? Read-only. An `(at base idx)`
  ## whose INDEX calls — a bounds check, say — evaluates the base FIRST and
  ## reads it back AFTER the call, so the base's scratch must be a callee-saved
  ## survivor rather than a volatile the call clobbers. (Fused port of the
  ## allocator's `subtreeHasCall`.)
  if n.kind != TagLit: return false
  if n.exprKind == CallC: return true
  var cc = n
  cc.into:
    while cc.hasMore:
      if subtreeHasCall(cc): return true
      skip cc
  return false

# ── caller-save rescue (see `Plan.callerSaveHomes`) ─────────────────────

proc callerSaveSetAt*(g: var CodeGen): seq[tuple[reg: Reg, name: string]] =
  ## The caller-saved locals currently BOUND to a register — the ones this call is
  ## about to clobber. The trigger is live binding, not the coarse `freeAfter`
  ## interval: a value live across a control-flow merge is still bound at a call in a
  ## predecessor branch, which an interval test under-approximates. The allocator only
  ## hands out a caller-saved home to a value that is valid wherever it is bound, so
  ## "save whenever bound" is always well-defined. Sorted for deterministic output.
  if g.plan.callerSaveHomes.len == 0: return
  for reg, name in g.rb.gprBindings:
    if g.plan.callerSaveHomes.hasKey(name):
      result.add (reg: reg, name: name)
  result.sort(proc (a, b: tuple[reg: Reg, name: string]): int = cmp(ord(a.reg), ord(b.reg)))

proc callerSaveSlotName*(varName: string): string {.inline.} =
  ## ONE permanent slot per caller-saved value, declared with the value itself. A
  ## per-call slot inside the call's own `(scope …)` does not work: the call's result
  ## binding is created in that scope and consumed after it closes.
  "csave." & varName

proc pairFieldReg*(g: var CodeGen; c: Cursor): Reg =
  ## If `c` is `(dot S f)` and `S` is a register-homed ≤16B by-value aggregate
  ## whose field `f` is a full 8-byte ABI word, return that word's register.
  ## Otherwise `NoReg` — the caller uses the memory path.
  result = NoReg
  if c.kind != TagLit or c.exprKind != DotC: return
  var cc = c
  cc.into:
    if cc.kind != Symbol: return
    let base = symName(cc)
    let home = g.plan.homeOfSym(base)
    if home.kind != InRegPair: return
    skip cc
    if cc.kind != Symbol: return
    let field = symName(cc)
    let tn = g.varType.getOrDefault(base, NoTypeSym)
    if tn == NoTypeSym: return
    for f in aggrLayout(g.prog, tn):
      if f.name == field:
        if f.size == 8 and (f.off and 7) == 0:
          result = pairWord(home, f.off div 8)
        return

proc isFoldableMemLeaf*(g: var CodeGen; n: Cursor): bool {.inline.} =
  ## `isMemLeaf`, except a field of a register-homed ≤16B aggregate: that field
  ## IS a GPR, so folding it as `[mem]` would address a stack slot that does
  ## not exist.
  isMemLeaf(n) and g.pairFieldReg(n) == NoReg

# ── tail-position rewrites: the policy both backends share ──────────────────
# The two rewrites themselves are per-backend (the tags differ), but WHETHER to
# take them is one decision and belongs in one place.

proc mayReturnHere*(g: var CodeGen): bool =
  ## May a site inside the body RETURN — `(popframe) (ret)` — instead of branching to
  ## the proc's shared epilogue?
  ##
  ## `(popframe)` is what makes it possible at all: the frame's shape (how many
  ## callee-saved saves, whether a frame `sub` exists) is final only AFTER the body is
  ## emitted, and nifasm replays the prologue it has already assembled — so nothing is
  ## guessed and the teardown is identical to the shared one. Hence the `TailCall`
  ## capability: `doc/instructions.md` gives `(popframe)` to exactly the targets that
  ## have it (x86-64 and AArch64), and Cortex-M / RV32 have neither yet.
  ##
  ## The entry proc has no epilogue to replay — it ends in an exit syscall.
  if g.isEntryProc: return false
  TailCall in g.md.caps

proc emitsNoCode*(n: Cursor): bool =
  ## A statement that produces no machine code, and therefore does not end another
  ## statement's tail position: a `.` hole (what copyprop leaves where it deleted a
  ## binding) and the empty `(stmts …)`/`(scope …)` wrappers a `when`-compiled-out
  ## block leaves behind.
  ##
  ## Asking this rather than "is it the last child" is not a refinement, it is the
  ## whole difference: the allocator's `rawDealloc` ends in an empty `(stmts .)` — the
  ## `vgTracking` block — so its final `deallocBigChunk(a, c)` is the second-to-last
  ## child and no tail-position test phrased on the child list can see it.
  if n.kind == DotToken: return true
  if n.kind != TagLit: return false
  if n.stmtKind notin {StmtsS, ScopeS}: return false
  var it = n
  it.into:
    while it.hasMore:
      if not emitsNoCode(it): return false
      skip it
  true

proc restEmitsNoCode*(n: Cursor): bool =
  ## Is everything from `n` to the end of its statement list code-free? `n` is the
  ## cursor just past the statement being asked about.
  var it = n
  while it.hasMore:
    if not emitsNoCode(it): return false
    skip it
  true

proc addrRootIsOurs(g: var CodeGen; n: Cursor): bool =
  ## Does the address expression `n` bottom out at a symbol THIS proc owns storage
  ## for — a local or a by-value parameter — rather than at a `deref` of a pointer
  ## somebody else owns?
  ##
  ## Walking the base chain is the whole test: `(dot (deref p) f)` reaches OUR frame
  ## only through `p`, which is a pointer VALUE, so the `deref` stops the search;
  ## `(dot x f)` on a local `x` does not. A module-level global has no allocator
  ## location (`locationOfSym` answers `NoLoc`), which is what tells the two apart.
  var c = n
  var guard = 0
  while c.kind == TagLit and guard < 40:
    inc guard
    case c.exprKind
    of DerefC, PatC: return false          # through a pointer: not our storage
    of DotC, AtC, ParC, BaseobjC:
      inc c                                 # → the base
    of CastC, ConvC:
      inc c; skip c                         # → past the target type, to the operand
    else: return false
  if c.kind != Symbol: return false
  g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind != NoLoc

proc tailCallLeaksFrame*(g: var CodeGen; args: openArray[Cursor]): bool =
  ## Would tail-calling with these arguments hand the callee a pointer into the frame
  ## we are about to give back?
  ##
  ## A tail call is `(popframe)` and then a `jmp`: our slots are released BEFORE the
  ## callee runs, and the callee's own frame starts where ours was. An argument that is
  ## the address of one of our locals therefore points at memory the callee immediately
  ## reuses — the callee writes through it and corrupts its own frame instead. Nothing
  ## else about a tail call is unsafe, and no other operand shape can carry such an
  ## address: hexer un-nests, so an argument is a leaf or an address expression.
  ##
  ## This is a SYNTACTIC test, and it is not an escape analysis: a pointer laundered
  ## through a local (`let p = addr x; f(p)`) is not caught here. That shape does not
  ## occur in a self-hosted nimsem (0 of the 133 `(ret (call …))` sites and 303 of the
  ## 1,396 void tail-position calls carry a direct one, all of them syntactic), and
  ## catching it needs the address analysis arkham does not have. Stated so nobody
  ## reads this as a proof.
  for a in args:
    var stack = @[a]
    while stack.len > 0:
      let n = stack.pop()
      if n.kind != TagLit: continue
      if n.exprKind in {AddrC, HaddrC}:
        var inner = n; inc inner
        if inner.hasMore and g.addrRootIsOurs(inner): return true
      var it = n
      it.into:
        while it.hasMore:
          if it.kind == TagLit: stack.add it
          skip it
  false

proc sameTree*(a, b: Cursor): bool =
  ## Structural equality of two expression subtrees, ignoring the sparse line-info
  ## suffixes (they are not iterated as children). The nifcore twin of nimony's
  ## `sameTrees`, which lives in `nimony_model` and is not on arkham's import path.
  ##
  ## Used to recognize a read-modify-write: `(asgn L (add T L v))` is one only if the
  ## `L` under the `add` is the SAME location as the assignment's target, and "same"
  ## here has to mean same tokens — arkham has no value numbering to appeal to. That
  ## is sound because hexer un-nests, so an lvalue's embedded values are symbol or
  ## immediate loads: two identical trees name one location at one program point.
  if a.hasMore != b.hasMore: return false
  if not a.hasMore: return true
  let ka = a.kind
  if ka != b.kind: return false
  case ka
  of TagLit:
    if cursorTagId(a) != cursorTagId(b): return false
    var ca = childCursor(a)
    var cb = childCursor(b)
    while ca.hasMore and cb.hasMore:
      if not sameTree(ca, cb): return false
      skip ca
      skip cb
    result = ca.hasMore == cb.hasMore
  of Symbol, SymbolDef: result = symId(a) == symId(b)
  of IntLit:            result = intVal(a) == intVal(b)
  of UIntLit:           result = uintVal(a) == uintVal(b)
  of FloatLit:          result = floatVal(a) == floatVal(b)
  of StrLit, Ident:     result = strId(a) == strId(b)
  of CharLit:           result = charLit(a) == charLit(b)
  else:                 result = true

proc calleeParamSlots*(g: var CodeGen; fsym: string; tgt: CallTarget): seq[AsmSlot] =
  ## The DECLARED parameter slots of a call target, from its `(proctype …)`
  ## signature — empty when the target carries none (an indirect call built
  ## without one, an intrinsic).
  ##
  ## The call site needs these because an argument expression's own type and the
  ## parameter's declared type may differ in width, and it is the CALLEE that
  ## decides the ABI. On a target where every scalar is one register that
  ## difference is invisible; where a scalar can span two, it is the difference
  ## between staging one register and staging two.
  result = @[]
  discard fsym
  if cursorIsNil(tgt.sigType): return
  var q = tgt.sigType
  if q.kind != TagLit: return
  var slots: seq[AsmSlot] = @[]
  q.into:                    # (proctype . <params> <ret> <pragmas>) — see procSigType
    skip q                             # the name slot a proctype does not have
    if q.hasMore:
      if q.kind == TagLit: slots = paramSlots(g.prog, q)
      skip q
    while q.hasMore: skip q
  result = slots