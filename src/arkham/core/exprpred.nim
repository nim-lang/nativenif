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

proc isFoldableLeafE*(g: var CodeGen; n: Cursor): bool =
  ## A value needing NO register held across a sibling subtree: an immediate,
  ## or a function-local symbol read (folds as its reg / stack-home operand).
  case n.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n)).kind in {InReg, NamedStack}
  else: false

proc symInRegE*(g: var CodeGen; n: Cursor; reg: Reg): bool {.inline.} =
  ## Is `n` a symbol homed in `reg`? (Forbids a Sethi–Ullman swap whose
  ## rhs-into-dest evaluation would clobber a lhs homed in dest.)
  if n.kind != Symbol: return false
  let h = g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
  h.kind == InReg and h.r == reg

proc exprReadsRegImplE(g: var CodeGen; n: var Cursor; reg: Reg): bool =
  if n.kind == Symbol:
    let h = g.plan.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
    inc n
    return h.kind == InReg and h.r == reg
  elif n.kind == TagLit:
    n.into:
      while n.hasMore:
        if g.exprReadsRegImplE(n, reg): return true
  else:
    inc n
  return false

proc exprReadsRegE*(g: var CodeGen; n: Cursor; reg: Reg): bool =
  ## True iff the subtree at `n` reads a symbol homed in `reg` — the guard for
  ## computing a binop's left operand straight into a pinned `dest` register.
  var c = n
  g.exprReadsRegImplE(c, reg)

proc lvalueGlobalBaseE*(g: var CodeGen; n: Cursor): bool =
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
        result = g.lvalueGlobalBaseE(cc)
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc fixedRegsClobberedByE*(g: var CodeGen; n: Cursor): set[Reg] =
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

proc subtreeHasCallE*(n: Cursor): bool =
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
      if subtreeHasCallE(cc): return true
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