#
#           Arkham — native AArch64 code generator for NIFC
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 2: register allocation.
##
## Every value-producing position in a proc body gets a `Location`, looked up
## by `cursorToPosition` (the `SymId→position` mapping for locals is kept
## *inside* the allocator — that is its job). This module assigns the
## long-lived storage: parameters (ABI pre-coloring) and locals (scope-based).
## Per-expression temporaries are filled into the same `locs` table by the
## code generator as it walks the tree (it borrows registers via `borrowReg`
## / `giveBack`); see codegen. There is no Sethi–Ullman numbering — registers
## are handed out in the natural traversal order.
##
## Strategy for locals (after `analyser`):
##  * address-taken / aggregate / float (v1)        → stack slot
##  * confined to a call-free scope (`AllRegs`)      → a volatile temp register
##  * otherwise (may be live across a call)          → a callee-saved register
##  * out of registers                               → stack slot
## A register is returned to its pool when its scope closes (sibling scopes
## reuse it); the union of callee-saved registers ever used drives the
## prologue/epilogue.

import std / [tables, sets, assertions]
import nifcore, nifcdecl, slots, machinedesc, analyser, programs, typenav

type
  ExprAux* = object
    ## Per-expression-position selection decisions the pure emitter must replay
    ## that don't fit in the result `Location` (kept in `RegAlloc.aux`, sparse —
    ## only ops with arch constraints get an entry). Part of the value-core
    ## rewrite (see `codegen2_design.md`): once the allocator assigns every value
    ## position a result `Location` (in `locs`) plus this aux, codegen becomes a
    ## pure consumer and the plan/replay seam goes away.
    scratch*: seq[Reg]                ## extra GPRs reserved for this op (idiv RDX, a
                                      ## non-pow2 stride temp, an address scratch…)
    fscratch*: seq[FReg]              ## extra SIMD scratch reserved for this op
    swapped*: bool                    ## operands evaluated in swapped (Sethi–Ullman) order
    foldB*: bool                      ## operand B stays a folded memory operand (no load)
    aliasRhs*: bool                   ## dest register aliases the rhs operand: the emitter
                                      ## must not place lhs into dest first (`s = a - s`)

  RegAlloc* = object
    locs*: seq[Location]              ## indexed by cursorToPosition. Currently filled
                                      ## for symbol defs; the rewrite fills it for EVERY
                                      ## value-producing position (its result location).
    aux*: Table[int, ExprAux]         ## pos → per-op selection aux (see `ExprAux`)
    exprUnsupported*: bool             ## value-core rewrite (transition gate): the expr
                                      ## walk produced something the v1 pure emitter does
                                      ## not handle yet — a temp spill, or a memory-homed
                                      ## result/var. The backend then routes this proc to
                                      ## the legacy reactive emitter. Shrinks to never-set
                                      ## as the new emitter's coverage grows.
    symPos*: Table[string, int]       ## local/param name → its def position
    usedCallee*: set[Reg]             ## callee-saved GPRs to save in prologue
    usedCalleeF*: set[FReg]           ## callee-saved SIMD regs (v8–v15) to save in prologue
    frameSize*: int                   ## bytes of stack frame for spilled slots
    hasStackVars*: bool               ## proc has nifasm-managed `(s)` aggregate vars
    spillTemps*: seq[tuple[name: string; typ: AsmSlot; isFloat: bool]]
                                      ## value-core totality: `etmp`/`ftmp` slots the
                                      ## allocator synthesized when the register pool
                                      ## was exhausted (reserveTmp/reserveFTmp). The
                                      ## emitter DECLARES each `(var :etmpN.0 (s) T)`
                                      ## in the prologue and PRODUCES the spilled value
                                      ## position into it via a staging register.
    sealed*: set[Reg]                 ## registers pinned to an in-flight ABI
                                      ## call (args being marshalled, x8 result,
                                      ## values live through the call): never
                                      ## allocate to or steal from these

  Builder = object
    ra: RegAlloc
    buf: ptr TokenBuf
    an: ptr ProcAnalysis
    prog: ptr Program                 ## program (for cross-module type resolution / sizing)
    tc: TypeCtx                       ## shared NIFC type navigator (`getType`/`exprSlot`) —
                                      ## the same one the emitter uses, so the allocator no
                                      ## longer hand-rolls per-form type dispatch
    md: MachineDesc                   ## target register file + ABI (arch-neutral driver)
    freeVol, freeCallee: set[Reg]
    freeVolF: set[FReg]               ## caller-saved SIMD/FP scratch pool (v16–v31)
    freeCalleeF: set[FReg]            ## callee-saved SIMD pool (v8–v15)
    scopeVars: seq[seq[string]]       ## register-eligible locals per open scope
                                      ## (steal candidates; freed by current loc)
    pendingFree: seq[tuple[pos: int; name: string]]  ## locals to free at their
                                      ## coarse `freeAfter` position (last-use end)
    freedSyms: HashSet[string]        ## locals already early-freed: skipped by
                                      ## `trySteal` (dead) and `closeScope` (no re-free)
    allocExprs: bool                  ## value-core rewrite: also assign `locs[pos]` for
                                      ## expressions (not just var defs). Off by default so
                                      ## the legacy reactive emitter sees the unchanged
                                      ## (symbol-only) `locs`; the new pure emitter turns it
                                      ## on. See `codegen2_design.md` / `allocValue`.
    tmpSpills: int                    ## fresh expression-temp spill-slot counter (when the
                                      ## scratch pool is exhausted during the expr walk)
    retFloatBits: int                 ## value-core rewrite: 0 = the proc returns int/void;
                                      ## 32/64 = a float return (the value goes to xmm0)
    retIndirect: bool                 ## the proc returns a >16B aggregate via a hidden
                                      ## result pointer (rdi in, parked in a callee-saved reg)
    atScratch: HashSet[int]           ## value-core: `(at …)` positions needing a scratch GPR
                                      ## (non-SIB element stride); sized by the codegen

proc posOf(b: Builder; c: Cursor): int {.inline.} =
  cursorToPosition(b.buf[], c)

# ── physical register pools ────────────────────────────────────────────────

proc takeReg(b: var Builder; pool: var set[Reg]; cands: openArray[Reg]): Reg =
  ## Take the first free, non-sealed register from `cands`. A sealed register
  ## is committed to an in-flight ABI call and must never be h(re)allocated.
  for r in cands:
    if r in pool and r notin b.ra.sealed:
      excl pool, r
      return r
  result = NoReg

proc takeFReg(b: var Builder; pool: var set[FReg]; cands: openArray[FReg]): FReg =
  ## Take the first free SIMD register from `cands` out of `pool`.
  for f in cands:
    if f in pool:
      excl pool, f
      return f
  result = NoFReg

proc spill(b: var Builder; slot: AsmSlot): Location =
  b.ra.frameSize += align(max(slot.size, 1), 8)
  result = stackLoc(-b.ra.frameSize, slot)

proc allocStorage(b: var Builder; slot: AsmSlot; props: VarProps): Location =
  ## Decide where one local/param lives. Records reg use for scope freeing.
  if slot.isFloat:
    # A float local lives only in a callee-saved register (saved in the prologue),
    # or it spills. The volatile float pool (v16–v31 on arm64, xmm8–15 on x64) is
    # reserved as the emitter's expression scratch — handing it to a long-lived
    # local starves that scratch (`out of SIMD scratch` on arm64, an unbound-pool
    # register reaching `emFReg` on x64). Unlike the integer side, there is no spare
    # volatile pool to lend out: every volatile xmm is needed to evaluate float
    # trees. So `AllRegs` is moot for floats. On x86-64 there are NO callee-saved
    # xmm regs at all (SysV), so a float local always spills there — exactly the
    # behavior before precise `AllRegs`, when the empty callee pool forced a spill.
    if AddrTaken in props: return b.spill(slot)
    let f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    if f == NoFReg: return b.spill(slot)
    b.ra.usedCalleeF.incl f
    return fregLoc(f, slot)
  if AddrTaken in props or not slot.inRegClass:
    return b.spill(slot)
  var r: Reg
  if AllRegs in props:
    # A call-free local could legally live in a caller-saved volatile. Prefer a
    # callee-saved home (one prologue push/pop, then resident); fall back to a
    # volatile temp only from `intLocalTempRegs` — the subset of the scratch pool
    # the target can spare as a local home (empty on x86-64, where R10/R11 are the
    # emitter's own staging scratch; the full pool on AArch64). When that subset is
    # empty or exhausted, spill rather than steal the emitter's scratch.
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
    if r == NoReg: r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
  else:
    # may be live across a call → must be callee-saved (or stack)
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
  if r == NoReg: return b.spill(slot)
  if r in b.md.intCalleeSavedSet: b.ra.usedCallee.incl r
  result = regLoc(r, slot)

proc giveBack(b: var Builder; r: Reg) {.inline.} =
  if r in b.md.intCalleeSavedSet: b.freeCallee.incl r
  elif r != NoReg: b.freeVol.incl r

proc giveBackF(b: var Builder; f: FReg) {.inline.} =
  if f in b.md.floatCalleeSavedSet: b.freeCalleeF.incl f
  elif f != NoFReg: b.freeVolF.incl f

proc weightOf(b: Builder; name: string): int {.inline.} =
  b.an.vars.getOrDefault(name).weight

# ── scope-based walk that allocates locals ──────────────────────────────────

proc flushFree(b: var Builder; curpos: int) =
  ## Return to the pool the registers of locals whose coarse last-use end position
  ## (`freeAfter`) has been passed, so a later local in the same scope can reuse
  ## them — the early-free that keeps live ranges short. Freed by the var's
  ## *current* location (an evicted var frees nothing). Idempotent w.r.t.
  ## `closeScope`, which skips already-freed names.
  var i = 0
  while i < b.pendingFree.len:
    if b.pendingFree[i].pos <= curpos:
      let name = b.pendingFree[i].name
      let loc = b.ra.locs[b.ra.symPos[name]]
      if loc.kind == InReg: b.giveBack loc.r
      elif loc.kind == InFReg: b.giveBackF loc.f
      b.freedSyms.incl name
      b.pendingFree.del i              # swap-remove; order is irrelevant
    else: inc i

proc openScope(b: var Builder) = b.scopeVars.add @[]
proc closeScope(b: var Builder) =
  ## Return registers to the pool, keyed by each var's *current* location —
  ## so a var that was evicted to the stack (its reg stolen by a hotter one)
  ## frees nothing, and the thief frees the register when its own scope ends.
  ## Already early-freed vars are skipped (their reg may now belong to a reuser).
  for v in b.scopeVars.pop():
    if v in b.freedSyms: continue
    let loc = b.ra.locs[b.ra.symPos[v]]
    if loc.kind == InReg: b.giveBack loc.r
    elif loc.kind == InFReg: b.giveBackF loc.f

proc record(b: var Builder; pos: int; name: string; loc: Location) =
  b.ra.symPos[name] = pos
  b.ra.locs[pos] = loc

proc trySteal(b: var Builder; curName: string; curSlot: AsmSlot;
              curProps: VarProps; fallback: Location): Location =
  ## `curName` wanted a register but the pool was empty (`fallback` is a stack
  ## slot). Evict the lowest-weight live local that holds a usable register, if
  ## it is strictly colder than `curName`; that local moves to `fallback` and
  ## `curName` takes its register. Returns `curName`'s chosen location.
  let curW = b.weightOf(curName)
  let calleeOnly = AllRegs notin curProps   # cross-call var needs callee-saved
  var bestV = ""
  var bestW = curW
  var bestReg = NoReg
  for scope in b.scopeVars:
    for v in scope:
      if v in b.freedSyms: continue             # already dead (early-freed)
      let vloc = b.ra.locs[b.ra.symPos[v]]
      if vloc.kind != InReg: continue
      if vloc.r in b.ra.sealed: continue        # pinned to an in-flight ABI call
      if calleeOnly and vloc.r notin b.md.intCalleeSavedSet: continue
      let vw = b.weightOf(v)
      if vw < bestW:
        bestW = vw; bestV = v; bestReg = vloc.r
  if bestReg == NoReg: return fallback      # nothing colder to steal from
  # evict the victim to the (current's) stack slot; current takes its register
  let vpos = b.ra.symPos[bestV]
  # The victim moves to a nifasm-managed `(s)` slot, addressed by its own name
  # (offsets are nifasm's job). `fallback`'s numeric offset is irrelevant now.
  b.ra.locs[vpos] = namedStackLoc(bestV, b.ra.locs[vpos].typ)
  b.ra.hasStackVars = true
  if bestReg in b.md.intCalleeSavedSet: b.ra.usedCallee.incl bestReg
  result = regLoc(bestReg, curSlot)

proc stealForTmp(b: var Builder; slot: AsmSlot): Location =
  ## The GPR pool is empty while a *computed temporary* needs a register. A temp
  ## is needed right now, so it outranks any live local: evict the lowest-weight
  ## live local holding a non-sealed GPR to its stack home and hand the temp that
  ## register. The eviction is a uniform single-home rewrite of `ra.locs` (one
  ## home per symbol) — sound across every control-flow path, so it can't recur
  ## the cross-branch reactive-eviction bug. `dontCare` if nothing is stealable.
  var bestW = high(int)
  var bestV = ""
  for scope in b.scopeVars:
    for v in scope:
      if v in b.freedSyms: continue
      let vloc = b.ra.locs[b.ra.symPos[v]]
      if vloc.kind != InReg: continue
      if vloc.r in b.ra.sealed: continue        # pinned to an in-flight ABI call
      let vw = b.weightOf(v)
      if vw < bestW: bestW = vw; bestV = v
  if bestV.len == 0: return dontCare
  let vpos = b.ra.symPos[bestV]
  let r = b.ra.locs[vpos].r
  b.ra.locs[vpos] = namedStackLoc(bestV, b.ra.locs[vpos].typ)
  b.ra.hasStackVars = true
  if r in b.md.intCalleeSavedSet: b.ra.usedCallee.incl r
  result = regLoc(r, slot, isTemp = true)

proc stealFForTmp(b: var Builder; slot: AsmSlot): Location =
  ## SIMD twin of `stealForTmp`: evict the lowest-weight float-register local to
  ## its stack home and give a computed float temporary that register.
  var bestW = high(int)
  var bestV = ""
  for scope in b.scopeVars:
    for v in scope:
      if v in b.freedSyms: continue
      let vloc = b.ra.locs[b.ra.symPos[v]]
      if vloc.kind != InFReg: continue
      let vw = b.weightOf(v)
      if vw < bestW: bestW = vw; bestV = v
  if bestV.len == 0: return dontCare
  let vpos = b.ra.symPos[bestV]
  let f = b.ra.locs[vpos].f
  b.ra.locs[vpos] = namedStackLoc(bestV, b.ra.locs[vpos].typ)
  b.ra.hasStackVars = true
  if f in b.md.floatCalleeSavedSet: b.ra.usedCalleeF.incl f
  result = fregLoc(f, slot, isTemp = true)

# ── expression allocation (value-core rewrite; gated by `allocExprs`) ──────────
# Mirrors codegen's genVal/gen DECISIONS, recording each value position's result
# Location in `ra.locs` (+ `ra.aux`) instead of emitting; the pure emitter reads
# them back. See `codegen2_design.md`. Currently: integer leaves + binary
# arithmetic. TODO: div/mod (RDX clobber), calls, addressing, floats,
# Sethi–Ullman reorder, totality spill. Arch quirks go behind `b.md.arch == X86`.

let ScalarSlot = AsmSlot(cls: AInt, size: 8, align: 8)

proc floatSlot(bits: int): AsmSlot {.inline.} =
  AsmSlot(cls: AFloat, size: bits div 8, align: bits div 8)

proc sameReg(a, c: Location): bool {.inline.} =
  a.kind == InReg and c.kind == InReg and a.r == c.r

proc reserveTmp(b: var Builder; slot: AsmSlot): Location =
  ## A scratch GPR for a computed expression temporary: the volatile temp pool
  ## first, then callee-saved, then a nifasm-managed spill slot when both are
  ## empty (so allocation is total — the emitter sees a foldable `NamedStack`).
  var r = b.takeReg(b.freeVol, b.md.intTempRegs)
  if r == NoReg:
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
    if r == NoReg:
      # pool exhausted: steal a register from the coldest live local (the
      # discussed design — undo a local's register assignment, demote it to its
      # stack home). Total and branch-safe by the single-home rewrite.
      let stolen = b.stealForTmp(slot)
      if stolen.kind == InReg: return stolen
      # genuinely nothing stealable (all GPRs sealed / already on stack): a last-ditch
      # `(s)` spill slot. The emitter declares it (`spillTemps`) and PRODUCES the value
      # position into it through a staging register (`produceIntoMem2`) — `isTemp` marks
      # it as a produce-into slot, distinct from a symbol's stack home left for folding.
      let nm = "etmp" & $b.tmpSpills & ".0"; inc b.tmpSpills
      b.ra.hasStackVars = true
      b.ra.spillTemps.add (name: nm, typ: slot, isFloat: false)
      return namedStackLoc(nm, slot, isTemp = true)
    if r in b.md.intCalleeSavedSet: b.ra.usedCallee.incl r
  result = regLoc(r, slot, isTemp = true)

proc releaseTmp(b: var Builder; loc: Location) {.inline.} =
  if loc.kind == InReg and loc.isTemp: b.giveBack loc.r

proc reserveFTmp(b: var Builder; slot: AsmSlot): Location =
  ## A scratch SIMD register for a computed float temporary — the SIMD twin of
  ## `reserveTmp`: the volatile float pool (xmm8–15) first, then callee-saved
  ## (empty on x86-64), then a spill slot which marks the proc `exprUnsupported`
  ## (the v1 pure emitter has no float spill path yet).
  var f = b.takeFReg(b.freeVolF, b.md.floatTempRegs)
  if f == NoFReg:
    f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    if f == NoFReg:
      let stolen = b.stealFForTmp(slot)
      if stolen.kind == InFReg: return stolen
      # `eftmp` (NOT `ftmp`): the emitter's `bindFTmp` scratch names are `ftmpN.0`, so a
      # spill slot named `ftmpN.0` would COLLIDE (a `(var (s))` decl vs a `(rebind)` reg
      # binding under the same symbol). The int side is already disambiguated (`etmp`
      # spill vs `tmp` bind); mirror it for floats.
      let nm = "eftmp" & $b.tmpSpills & ".0"; inc b.tmpSpills
      b.ra.hasStackVars = true
      b.ra.spillTemps.add (name: nm, typ: slot, isFloat: true)
      return namedStackLoc(nm, slot, isTemp = true)
    if f in b.md.floatCalleeSavedSet: b.ra.usedCalleeF.incl f
  result = fregLoc(f, slot, isTemp = true)

proc releaseFTmp(b: var Builder; loc: Location) {.inline.} =
  if loc.kind == InFReg and loc.isTemp: b.giveBackF loc.f

proc symLoc(b: var Builder; name: string): Location

proc isFloatVal(b: var Builder; n: Cursor): bool =
  ## Does value `n` have float type? One call to the shared type navigator — the
  ## SAME classification the emitter uses — replacing the old best-effort form-ladder
  ## (which missed float globals and re-derived types by hand).
  b.tc.exprSlot(n).cls == AFloat

proc symLoc(b: var Builder; name: string): Location =
  ## A symbol reference reads where the symbol is stored. A module-level
  ## global/proc is not in `symPos`; the emitter resolves those (Glob / `lea`), so
  ## return `dontCare` and let it.
  let p = b.ra.symPos.getOrDefault(name, -1)
  if p >= 0: b.ra.locs[p] else: dontCare

proc resolveDest(b: var Builder; dest: var Location; natural: Location) =
  ## Resolve a *leaf* destination constraint against the value's `natural`
  ## location (an immediate / a symbol's home).
  case dest.kind
  of Undef: dest = natural
  of NeedsReg:
    dest = (if natural.kind == InReg: natural else: b.reserveTmp(natural.typ))
  of RegOrImm:
    dest = (if natural.kind in {InReg, Imm}: natural else: b.reserveTmp(natural.typ))
  else: discard                              # fixed InReg/InFReg/NamedStack/…: keep

proc allocValue(b: var Builder; n: var Cursor; dest: var Location)
proc allocFValue(b: var Builder; n: var Cursor; dest: var Location)
proc allocLvalue2(b: var Builder; n: var Cursor; globBase = dontCare; isStore = false)
proc allocCall(b: var Builder; n: var Cursor; dest: var Location; hiddenPtr = false)
proc allocConstr(b: var Builder; n: var Cursor)
proc allocStore(b: var Builder; n: var Cursor; dst: Location; auxPos: int)
proc releaseLvalTemps(b: var Builder; n: Cursor)

proc regOccupied(b: var Builder; reg: Reg): bool

proc isFoldableLeaf(b: var Builder; n: Cursor): bool =
  ## A value needing NO register held across a sibling subtree: an immediate, or a
  ## function-local symbol read (folds as its reg / stack home operand). A computed
  ## expr, a string literal, or a global (each needs a load into a temp) is not.
  case n.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: b.symLoc(symName(n)).kind in {InReg, NamedStack}
  else: false

proc commutativeExpr(ek: NifcExpr): bool {.inline.} =
  ## Integer ops for which `a op b == b op a` (so the heavier operand may be
  ## evaluated first and the lighter one folded after). `sub` is handled too — via a
  ## `neg` after the swap — but is NOT commutative, so it is listed separately.
  ek in {AddC, MulC, BitandC, BitorC, BitxorC}

proc symInReg(b: var Builder; n: Cursor; reg: Reg): bool {.inline.} =
  ## Is `n` a symbol whose home register is `reg`? (Used to forbid a Sethi–Ullman
  ## swap whose rhs-into-dest evaluation would clobber a lhs homed in dest.)
  n.kind == Symbol and (let h = b.symLoc(symName(n)); h.kind == InReg and h.r == reg)

proc isMemLeaf(n: Cursor): bool {.inline.} =
  ## A foldable memory-load operand: a `dot`/`deref`/`at`/`pat` addressing chain in
  ## value position. The emitter folds it as `op reg, [mem]` (emLvalAddr2) instead of
  ## loading it into a held register, so in a Sethi–Ullman swap the load happens AFTER
  ## the computed sibling — never pinning a register across it (and one fewer mov).
  ## Operands are pure (hexer un-nests calls) so reordering the load is observation-
  ## preserving. A memory-load operand of a typed op has the op's width (NIFC widens
  ## via an explicit `conv`, which is not a mem leaf), so the `op reg, [mem]` fold is
  ## always size-consistent.
  n.kind == TagLit and n.exprKind in {DotC, DerefC, AtC, PatC}

proc allocBin(b: var Builder; n: var Cursor; dest: var Location) =
  ## Binary-arith node. When the left operand is a foldable leaf and the right is a
  ## computed (register-needing) subtree, a **Sethi–Ullman swap** evaluates the
  ## right operand *first*, straight into the result register, then folds the leaf
  ## left operand — so a right-nested chain (`a-(b-(c-…))`, `x0+(x1+(x2+…))`)
  ## collapses to O(1) live registers and never exhausts the pool. For `sub` the
  ## swap is completed with a `neg` (`a-b == -(b)+a`). Otherwise the original
  ## left-into-register / right-folded order is kept.
  let pos = b.posOf(n)
  let ek = n.exprKind                        # the op (a variable shift needs the count in cl)
  # Peek both operands to decide a Sethi–Ullman swap.
  var lhsC, rhsC: Cursor
  block:
    var cc = n
    cc.into:
      skip cc                                # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc              # drain the copy (into asserts rem == 0)
  let lhsMem = isMemLeaf(lhsC)
  let swap = ek notin {ShlC, ShrC} and (commutativeExpr(ek) or ek == SubC) and
             (b.isFoldableLeaf(lhsC) or lhsMem) and
             not (b.isFoldableLeaf(rhsC) or isMemLeaf(rhsC)) and
             not (dest.kind == InReg and b.symInReg(lhsC, dest.r))
  if swap:
    var acc = dest
    if acc.kind != InReg: acc = b.reserveTmp(ScalarSlot)
    n.into:
      skip n                                 # result type
      skip n                                 # left (folded after — see below)
      allocValue(b, n, acc)                  # right → the accumulator register
      while n.hasMore: skip n
    var lLoc = dontCare                       # left folds as its own operand (no temp)
    if lhsMem:
      # The left is a memory load: place its address regs AFTER the right subtree (so
      # they don't pin a register across it), record a `Mem` location (the emitter
      # folds it via emLvalAddr2), then free the address temps — they die with the fold.
      var lc = lhsC
      allocLvalue2(b, lc)
      releaseLvalTemps(b, lhsC)
      lLoc = memLoc(lhsC, ScalarSlot)
      b.ra.locs[b.posOf(lhsC)] = lLoc
    else:
      var lc = lhsC
      allocValue(b, lc, lLoc)
    b.ra.aux[pos] = ExprAux(swapped: true, foldB: lLoc.kind in {NamedStack, Mem})
    b.ra.locs[pos] = acc
    dest = acc            # propagate the result reg to the caller's var so it can free it
    return
  var lDest = needsReg(ScalarSlot)
  var rDest = dontCare
  n.into:
    skip n                                   # result type
    allocValue(b, n, lDest)                  # left → a register
    if ek in {ShlC, ShrC} and b.md.shiftCountReg != NoReg and
       n.kind notin {IntLit, UIntLit, CharLit}:
      # x86 variable shift: the count must be in cl. Bail if cl (rcx) holds a live
      # symbol (a 4th arg-reg param) — the new path cannot evict it.
      if b.regOccupied(b.md.shiftCountReg): b.ra.exprUnsupported = true
      rDest = regLoc(b.md.shiftCountReg, ScalarSlot)
    allocValue(b, n, rDest)                  # right → wherever (may fold) / cl for var shift
  # Result placement. A fixed dest (the var/store target, or an InReg the caller
  # pinned) is kept — destination-passing computes straight into it. Otherwise the
  # left operand's register is reused IN PLACE only when it is a *dead temp* (x86
  # RMW `dest := dest op rhs`); a live local's home is never grabbed (it would
  # clobber the local), and a fresh temp is taken while `rDest` is still held so it
  # can't land on the rhs register (which would break a non-commutative `sub`).
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: dest = lDest
    else: dest = b.reserveTmp(ScalarSlot)
  else: discard
  if dest.kind != InReg: b.ra.exprUnsupported = true   # memory-result binop: v1 emitter gap
  # Destination-passing hazard: a *fixed* dest (an asgn/store target) that aliases
  # the rhs register would be clobbered when the emitter places lhs into dest before
  # the op (`dest := lhs; dest op= rhs`). Safe when dest == lhs (in-place RMW). For a
  # commutative op the emitter folds it to `dest op= lhs` (no lhs move); for `sub` it
  # computes `dest := dest - lhs; neg dest`. (Var-decl inits never hit this — a fresh
  # home can't alias a still-live operand — so only `s = a - s`-shaped asgns do.) A
  # variable shift can't be rewritten this way (the count needs cl), so it still bails.
  let aliasRhs = dest.kind == InReg and rDest.kind == InReg and dest.r == rDest.r and
                 not sameReg(dest, lDest)
  if aliasRhs and ek in {ShlC, ShrC}: b.ra.exprUnsupported = true
  b.releaseTmp(rDest)
  if not sameReg(dest, lDest): b.releaseTmp(lDest)
  b.ra.aux[pos] = ExprAux(foldB: rDest.kind in {NamedStack, Mem},
                          aliasRhs: aliasRhs and ek notin {ShlC, ShrC})
  b.ra.locs[pos] = dest

proc allocFBin(b: var Builder; n: var Cursor; dest: var Location) =
  ## Float binary arith `(op (f N) a b)` (add/sub/mul/div) — the SIMD twin of
  ## `allocBin`. SSE is destructive 2-operand, so `a` computes straight into the
  ## result register `dest` (resolved to a concrete xmm here) and the op is
  ## `dest := dest op b`; `b` folds in place when it is a float local already in a
  ## register, else it draws a fresh SIMD temp. The result is always destination-
  ## passed (the gate restricts float ops to var-init / ret), so `dest` is never a
  ## standalone temp.
  let pos = b.posOf(n)
  let ek = n.exprKind
  # Peek operands to decide a Sethi–Ullman swap (the SIMD twin of `allocBin`): when
  # the left operand is a foldable float leaf (a local read) and the right is a
  # computed subtree, evaluate the right first straight into the result register,
  # then fold the left — collapsing a right-nested commutative chain to O(1) live
  # xmm registers. Restricted to commutative ops (add/mul): float `sub`/`div` would
  # need a sign-flip the simple fold can't express.
  var lhsC, rhsC: Cursor
  var fslotPeek = floatSlot(64)
  block:
    var cc = n
    cc.into:
      fslotPeek = slotOf(b.prog[], cc); skip cc # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc                  # drain the copy
  proc foldableFloatLeaf(b: var Builder; c: Cursor): bool =
    c.kind == Symbol and b.symLoc(symName(c)).kind in {InFReg, NamedStack}
  let lHome = (if lhsC.kind == Symbol: b.symLoc(symName(lhsC)) else: dontCare)
  let swap = ek in {AddC, MulC} and b.foldableFloatLeaf(lhsC) and
             not b.foldableFloatLeaf(rhsC) and
             not (dest.kind == InFReg and lHome.kind == InFReg and lHome.f == dest.f)
  if swap:
    var acc = dest
    if acc.kind != InFReg: acc = b.reserveFTmp(fslotPeek)
    n.into:
      skip n                                    # result float type
      skip n                                    # left (folded after)
      allocFValue(b, n, acc)                    # right → the accumulator register
      while n.hasMore: skip n
    var fsc: seq[FReg] = @[]                     # an fscratch to load a spilled left
    if lHome.kind == NamedStack:
      let lt = b.reserveFTmp(fslotPeek); b.releaseFTmp(lt)
      if lt.kind == InFReg: fsc = @[lt.f]
      else: b.ra.exprUnsupported = true
    b.ra.aux[pos] = ExprAux(swapped: true, fscratch: fsc)
    b.ra.locs[pos] = acc
    dest = acc            # propagate the result reg to the caller's var so it can free it
    return
  var fslot = floatSlot(64)
  n.into:
    fslot = slotOf(b.prog[], n); skip n        # result float type → its precise slot
    if dest.kind != InFReg: dest = b.reserveFTmp(fslot)
    var lDest = dest                            # a → the result register (destructive)
    allocFValue(b, n, lDest)
    # b: fold an in-place float local, else a fresh SIMD temp the emitter releases.
    if n.kind == Symbol and b.symLoc(symName(n)).kind == InFReg:
      var rDest = b.symLoc(symName(n))
      # Destination-passing hazard: folding `b` from a register that is also `dest`
      # would compute `dest op dest` (after `a` clobbered `dest`). Bail to legacy
      # (whose latent same-reg behaviour is the proven path) rather than miscompile.
      if dest.kind == InFReg and rDest.f == dest.f: b.ra.exprUnsupported = true
      allocFValue(b, n, rDest)
    else:
      var rDest = b.reserveFTmp(fslot)
      allocFValue(b, n, rDest)
      b.releaseFTmp(rDest)
    while n.hasMore: skip n
  b.ra.locs[pos] = dest

proc allocFValue(b: var Builder; n: var Cursor; dest: var Location) =
  ## Float value (the SIMD twin of `allocValue` / mirrors codegen's `genIntoF`):
  ## the result lands in an xmm register (`dest`, resolved to a concrete InFReg).
  ## Slice 1: float literal, float local read, float add/sub/mul/div.
  let pos = b.posOf(n)
  case n.kind
  of FloatLit:
    if dest.kind != InFReg:
      dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
    # The bit pattern is materialized through a scratch GPR (fmovq/d xmm ← gpr);
    # reserve one and record it for the emitter (single-use → released at once).
    let g = b.reserveTmp(ScalarSlot)
    b.releaseTmp(g)
    if g.kind == InReg: b.ra.aux[pos] = ExprAux(scratch: @[g.r])
    else: b.ra.exprUnsupported = true
    b.ra.locs[pos] = dest
    inc n
  of Symbol:
    let home = b.symLoc(symName(n))
    case home.kind
    of InFReg:
      if dest.kind != InFReg: dest = home        # Undef dest: use the home in place
      # else keep the caller's dest; the emitter moves home → dest
    of NamedStack:
      # a spilled / address-taken float `(s)` slot: load it into a SIMD register
      # (the emitter reads the home from locationOfSym and emits a movsd from the slot).
      if dest.kind != InFReg: dest = b.reserveFTmp(home.typ)
    else:
      # a module-level float global / tvar: not yet handled by the pure emitter.
      if dest.kind != InFReg: dest = b.reserveFTmp(floatSlot(64))
      b.ra.exprUnsupported = true
    b.ra.locs[pos] = dest
    inc n
  of TagLit:
    case n.exprKind
    of AddC, SubC, MulC, DivC:
      allocFBin(b, n, dest); return              # records locs[pos] itself
    of ConvC:
      # A conversion whose RESULT is float. An INT source is `cvtsi2sd` (the operand
      # in a GPR temp the emitter extends first); a FLOAT source is a precision /
      # copy convert. (`cast`-to-float bit-reinterpret is deferred to legacy.)
      if dest.kind != InFReg:
        dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
      let resDest = dest
      var srcF = false
      block:
        var t = n; inc t; skip t                 # tag, target type → source expr
        srcF = b.isFloatVal(t)
      n.into:
        skip n                                   # target float type
        if srcF:
          b.ra.exprUnsupported = true            # float→float precision: deferred to legacy
          var fd = resDest
          allocFValue(b, n, fd)
        else:
          var gd = needsReg(ScalarSlot)          # int operand → a GPR temp
          allocValue(b, n, gd)
          b.releaseTmp(gd)
        while n.hasMore: skip n
      b.ra.locs[pos] = resDest
      return
    of DerefC, DotC, AtC, PatC:
      # A float lvalue in value position → load `[addr]` into an xmm. The embedded
      # base/index values are placed by allocLvalue2; the result lands in `dest`.
      if dest.kind != InFReg:
        dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
      let resDest = dest
      let lvCopy = n                               # for releaseLvalTemps after the load
      allocLvalue2(b, n)                          # embedded base/index regs; advances past
      releaseLvalTemps(b, lvCopy)                  # index/pointer temps die with the load
      b.ra.locs[pos] = resDest
      return
    of CallC:
      # A float-result call: the result arrives in xmm0; `dest` (the float home / a
      # SIMD temp) receives it. allocCall places the args (float → xmm0–7).
      if dest.kind != InFReg:
        dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
      allocCall(b, n, dest); return              # records locs[pos] itself
    of SufC, ParC:                               # `(suf v "type")` / `(par v)` wrapper
      n.into:
        allocFValue(b, n, dest)
        while n.hasMore: skip n
      b.ra.locs[pos] = dest
      return
    else:
      if dest.kind != InFReg: dest = b.reserveFTmp(floatSlot(64))
      b.ra.exprUnsupported = true; skip n
      b.ra.locs[pos] = dest
  else:
    if dest.kind != InFReg: dest = b.reserveFTmp(floatSlot(64))
    b.ra.exprUnsupported = true; inc n
    b.ra.locs[pos] = dest

proc allocCall(b: var Builder; n: var Cursor; dest: var Location; hiddenPtr = false) =
  ## A call: each scalar/pointer argument is allocated into its ABI integer argument
  ## register (rdi…r9), each float argument into its SIMD argument register (xmm0–7);
  ## the result lands in the return register (rax, or xmm0 for a float result) or a
  ## destination-passed home. Aggregate args / >N args still bail (exprUnsupported).
  let pos = b.posOf(n)
  var intIdx = if hiddenPtr: 1 else: 0         # rdi reserved for a >16B aggregate result ptr
  var fIdx = 0
  n.into:
    skip n                                     # callee symbol
    while n.hasMore:
      # The argument's ABI class is just its type — one `exprSlot`, the SAME navigator
      # the emitter uses. No per-form ladder: a struct var and an `(oconstr …)`/`(aconstr …)`
      # are both `AMem` and share this branch; only *building* the value differs, and that
      # is `allocStore`'s job, not the call's.
      let argSlot = b.tc.exprSlot(n)
      if argSlot.cls == AMem:
        # An aggregate argument: by-value ≤threshold consumes ceil(size/8) integer arg
        # registers (the emitter marshals its words); by-reference (>threshold) consumes
        # one (a pointer). A symbol is read in place; a constructor is built into a
        # synthetic temp through the one general store path.
        let words = if argSlot.size <= b.md.aggrByRefThreshold: (argSlot.size + 7) div 8 else: 1
        if intIdx + words > b.md.intArgRegs.len: b.ra.exprUnsupported = true
        if n.kind == Symbol:
          skip n                                # no per-value allocation — emitter reads the slot
        else:                                   # oconstr/aconstr: build into a synthetic aggregate temp
          b.ra.hasStackVars = true
          allocStore(b, n, namedStackLoc("", argSlot), b.posOf(n))  # advances n
        intIdx += words
      elif argSlot.cls == AFloat:               # float argument → xmm{fIdx}
        if fIdx < b.md.floatArgRegs.len:
          var ad = fregLoc(b.md.floatArgRegs[fIdx], floatSlot(64))
          allocFValue(b, n, ad)
        else:
          b.ra.exprUnsupported = true           # >8 float args (stack) — gap
          var ad = dontCare
          allocFValue(b, n, ad)
        inc fIdx
      elif intIdx < b.md.intArgRegs.len:        # integer/pointer argument → rdi…r9
        var ad = regLoc(b.md.intArgRegs[intIdx], ScalarSlot)
        allocValue(b, n, ad)
        inc intIdx
      else:
        # 7th+ integer arg → caller stack. Compute into a scratch register; the
        # emitter stores it to the outgoing slot `(mem (rsp) (arg pN))`. The temp is
        # dead after that store, so release it (each stack arg reuses it in turn).
        var ad = needsReg(ScalarSlot)
        allocValue(b, n, ad)
        b.releaseTmp(ad)
        inc intIdx
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(b.md.intRetReg, ScalarSlot, isTemp = true)   # int result in rax
  else: discard                                # fixed dest (InReg / InFReg): emitter moves the
                                               # result (rax / xmm0) into it
  b.ra.locs[pos] = dest

proc allocCond(b: var Builder; n: var Cursor) =
  ## Allocate operand homes for a branch condition (`if`/`while`). A comparison
  ## `(op a b)` (no type child) puts `a` in a register — `cmp` needs a register
  ## lhs — and `b` wherever it lies (a small immediate / register, folded by the
  ## emitter); the comparison yields flags, so no result location is recorded. A
  ## plain boolean value is forced into a register (the emitter tests it `!= 0`).
  ## `and`/`or`/`not` short-circuit trees recurse (each sub-condition's operands
  ## are allocated and freed in turn — single-use temps, so linear allocation
  ## matches the conditional emit order).
  if n.kind == TagLit and n.exprKind in {AndC, OrC, NotC}:
    n.into:
      while n.hasMore: allocCond(b, n)
  elif n.kind == TagLit and n.exprKind in {EqC, NeqC, LtC, LeC}:
    var fcmp = false
    block:
      var t = n; inc t                         # tag → first operand (no type child)
      fcmp = b.isFloatVal(t)
    if fcmp:
      # A FLOAT comparison `(op a b)`: both operands go to xmm registers (`comisd`
      # has no GPR/immediate operand). The compare yields flags only — no result loc.
      var lDest = dontCare
      var rDest = dontCare
      n.into:
        allocFValue(b, n, lDest)
        allocFValue(b, n, rDest)
        while n.hasMore: skip n
      b.releaseFTmp(rDest)
      b.releaseFTmp(lDest)
    else:
      var lhsC, rhsC: Cursor
      block:
        var cc = n
        cc.into:
          lhsC = cc; skip cc                   # comparison has NO type child
          rhsC = cc; skip cc
          while cc.hasMore: skip cc
      if isMemLeaf(lhsC) and not isMemLeaf(rhsC):
        # left is a memory load, right is not → fold the LEFT as `cmp [mem], rreg/imm`
        # (x86 allows a memory destination); the right goes to a reg or immediate (only
        # one memory operand). Avoids loading the left into a held register.
        n.into:
          let lPos = b.posOf(n)
          let lhsLval = n                      # release its base/index temps AFTER the rhs
          var lc = n
          allocLvalue2(b, lc)
          b.ra.locs[lPos] = memLoc(n, ScalarSlot)
          skip n
          var rDest = regOrImm(ScalarSlot)
          allocValue(b, n, rDest)              # right → reg / imm (not memory)
          # The emitter materializes the rhs value FIRST, then the lhs mem-base
          # pointer (prematLval2 in the cmp-[mem],rreg path). So the lhs base temps
          # must stay LIVE across the rhs allocation — otherwise the rhs reuses the
          # lhs base's register and the later base materialization clobbers the rhs
          # value (a wrong / mistyped cmp operand).
          releaseLvalTemps(b, lhsLval)
          b.releaseTmp(rDest)
          while n.hasMore: skip n
      else:
        var lDest = needsReg(ScalarSlot)
        n.into:
          allocValue(b, n, lDest)              # left → a register
          if isMemLeaf(n):
            # right is a memory load → fold it as `cmp lreg, [mem]` (no held register).
            # Its address regs are placed here and die with the compare.
            let rPos = b.posOf(n)
            var rc = n
            allocLvalue2(b, rc)
            releaseLvalTemps(b, n)
            b.ra.locs[rPos] = memLoc(n, ScalarSlot)
            skip n
          else:
            var rDest = dontCare
            allocValue(b, n, rDest)            # right → reg / imm (folded)
            b.releaseTmp(rDest)
          while n.hasMore: skip n
        b.releaseTmp(lDest)
  else:
    var d = needsReg(ScalarSlot)
    allocValue(b, n, d)
    b.releaseTmp(d)

proc allocLvalue2(b: var Builder; n: var Cursor; globBase = dontCare; isStore = false) =
  ## Walk an lvalue subtree (the target of a load / store / `addr`), allocating its
  ## embedded VALUES — a `deref`'s pointer, a computed index — into registers (their
  ## homes, recorded in `locs`); stack-var / field names and immediate indices need
  ## no allocation. Advances `n` past the whole lvalue. v1 slice: stack-var field
  ## access (`dot`) and pointer `deref` of a symbol; module-level global aggregate
  ## bases (`(at M …)`).
  ##
  ## A global aggregate base needs its address materialized into a register before
  ## the operand. `globBase` (passed by the consumer) names that register: for a
  ## LOAD / `addr` it is the access *result* register (free until the load lands, so
  ## reused — no extra temp, normal lifecycle); for a STORE it is a scratch the
  ## caller reserved and holds across the rhs. A `dontCare` (e.g. a float load whose
  ## result is an xmm) reserves an own GPR temp instead.
  case n.kind
  of Symbol:
    let nm = symName(n)
    if b.symLoc(nm).kind == Undef:           # a module-level global aggregate base
      let pos = b.posOf(n)
      if globBase.kind == InReg: b.ra.locs[pos] = globBase
      else:
        let t = b.reserveTmp(ScalarSlot)     # fallback (float load): own GPR temp
        if t.kind == InReg: b.ra.locs[pos] = t
        else: b.ra.exprUnsupported = true
    inc n                                    # stack-var / pointer / global base name
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        allocLvalue2(b, n, globBase, isStore) # base (a stack var, deref, or global)
        while n.hasMore: skip n              # field name (+ any extras)
    of DerefC:
      n.into:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)                  # the pointer → a register (its home)
        while n.hasMore: skip n
    of AtC:
      let atPos = b.posOf(n)
      n.into:
        allocLvalue2(b, n, globBase, isStore) # base (stack array, deref, or global)
        if n.kind in {IntLit, UIntLit}: skip n   # immediate index — folds, no scratch
        else:
          var idx = needsReg(ScalarSlot)
          allocValue(b, n, idx)             # register index → a register (folds via scale)
        while n.hasMore: skip n
      if atPos in b.atScratch:
        # Non-SIB element stride: reserve a scratch GPR for nifasm's 3-operand `(at
        # base idx scratch)`, recorded in aux. Held until the access has consumed the
        # address; `releaseLvalTemps` frees it (uniformly for load and store, alongside
        # the index/pointer temps) so there is no double-free.
        let t = b.reserveTmp(ScalarSlot)
        if t.kind == InReg:
          b.ra.aux[atPos] = ExprAux(scratch: @[t.r])
        else: b.ra.exprUnsupported = true
    of PatC:
      n.into:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)                  # the pointer → a register (its home)
        if n.kind in {IntLit, UIntLit}: skip n   # immediate index
        else:
          var idx = needsReg(ScalarSlot)
          allocValue(b, n, idx)             # register index → a register (folds via scale)
        while n.hasMore: skip n
    else:
      b.ra.exprUnsupported = true; skip n    # computed base: later slice
  else:
    inc n

proc lvalueGlobalBase(b: var Builder; n: Cursor): bool =
  ## Does the lvalue chain `n` (a `dot`/`at` over a symbol) bottom out at a
  ## module-level global aggregate? Such a base needs its address materialized into
  ## a scratch register. A `deref`/`pat` base is a pointer VALUE, not a global
  ## lvalue, so it stops the search. Read-only (never advances the caller's cursor).
  var c = n
  case c.kind
  of Symbol: result = b.symLoc(symName(c)).kind == Undef
  of TagLit:
    case c.exprKind
    of DotC, AtC:
      var cc = c
      cc.into:
        result = lvalueGlobalBase(b, cc)
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc releaseLvalTemps(b: var Builder; n: Cursor) =
  ## Release the scratch GPRs an lvalue's address computation reserved: a computed
  ## index (`at`/`pat`), a computed pointer (`deref`/`pat`), and a non-SIB-stride
  ## `(at …)` scratch (`aux[atPos]`). These are dead once the load/store that
  ## addresses through them has consumed the address — pinning them for the rest of
  ## the proc exhausts the pool over many accesses. Called by the LOAD consumer right
  ## after `allocLvalue2`, and by the STORE path after the rhs (where they had to be
  ## held). `releaseTmp` is a no-op on a symbol's home (non-temp), so a pointer/index
  ## that is just a param/local read frees nothing; a GLOBAL base reuses the access
  ## *result* register and sits at a Symbol position — not recursed — so it survives.
  var c = n
  if c.kind != TagLit: return
  case c.exprKind
  of DotC:
    var cc = c
    cc.into:
      releaseLvalTemps(b, cc)                 # base
      while cc.hasMore: skip cc
  of DerefC:
    var cc = c
    cc.into:
      b.releaseTmp(b.ra.locs[b.posOf(cc)])    # the pointer value
      while cc.hasMore: skip cc
  of AtC:
    let atPos = b.posOf(c)
    var cc = c
    cc.into:
      releaseLvalTemps(b, cc)                 # base (by-value: does not advance cc)
      skip cc                                 # → the index operand
      if cc.kind notin {IntLit, UIntLit}:
        b.releaseTmp(b.ra.locs[b.posOf(cc)])  # the computed index
      while cc.hasMore: skip cc
    if b.ra.aux.hasKey(atPos) and b.ra.aux[atPos].scratch.len > 0:
      b.giveBack b.ra.aux[atPos].scratch[0]
  of PatC:
    var cc = c
    cc.into:
      b.releaseTmp(b.ra.locs[b.posOf(cc)])    # the pointer value
      skip cc
      if cc.kind notin {IntLit, UIntLit}:
        b.releaseTmp(b.ra.locs[b.posOf(cc)])  # the computed index
      while cc.hasMore: skip cc
  else: discard

proc regOccupied(b: var Builder; reg: Reg): bool =
  ## Is fixed register `reg` the persistent home of some symbol? Used to bail a
  ## fixed-register instruction (idiv→rdx, variable shift→rcx) to legacy when the
  ## register holds a live param (only a 3rd/4th arg-reg param of a leaf proc lands
  ## there; locals draw from the temp/callee pools). Conservative: a now-dead param
  ## still shows its home, so this may bail a safe case — fine (legacy evicts it).
  if reg == NoReg: return false
  for name, pos in b.ra.symPos:
    let loc = b.ra.locs[pos]
    if loc.kind == InReg and loc.r == reg: return true
  false

proc divRemOccupied(b: var Builder): bool {.inline.} = b.regOccupied(b.md.divRemReg)

proc allocDivMod(b: var Builder; n: var Cursor; dest: var Location) =
  ## x86 `idiv`/`div`: dividend → rax, divisor → a register (no immediate form),
  ## quotient → rax, remainder → rdx (clobbered). Modeled only when rdx is free
  ## (`divRemOccupied`) — else bail to legacy, which reactively evicts rdx. The
  ## result register (rax quotient or rdx remainder) is moved to `dest`, or `dest`
  ## is left as that register when the caller pinned none.
  let pos = b.posOf(n)
  let wantRem = n.exprKind == ModC
  if b.divRemOccupied(): b.ra.exprUnsupported = true
  var aDest = regLoc(b.md.intRetReg, ScalarSlot)    # dividend → rax (fixed)
  var dDest = needsReg(ScalarSlot)                   # divisor → some register
  n.into:
    skip n                                           # result type
    allocValue(b, n, aDest)
    allocValue(b, n, dDest)
    while n.hasMore: skip n
  # The divisor must not alias rax (the dividend) or rdx (clobbered). `reserveTmp`
  # never hands those out; a symbol divisor homed there (a param) would — bail.
  if dDest.kind == InReg and (dDest.r == b.md.intRetReg or dDest.r == b.md.divRemReg):
    b.ra.exprUnsupported = true
  b.releaseTmp(dDest)
  let resReg = if wantRem: b.md.divRemReg else: b.md.intRetReg
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(resReg, ScalarSlot, isTemp = true)
  else: discard                                      # fixed dest: emitter moves result → it
  b.ra.locs[pos] = dest

proc forceRegDest(b: var Builder; dest: var Location) =
  ## Ensure a value's `dest` is a register: a `NeedsReg`/`RegOrImm` constraint becomes
  ## a fresh temp typed as requested; `Undef`/`dontCare` a generic scalar temp; a fixed
  ## reg is kept. A spilled temp (pool exhausted) marks the proc exprUnsupported.
  case dest.kind
  of NeedsReg, RegOrImm: dest = b.reserveTmp(dest.typ)
  of Undef: dest = b.reserveTmp(ScalarSlot)
  else: discard
  if dest.kind != InReg: b.ra.exprUnsupported = true

proc allocValue(b: var Builder; n: var Cursor; dest: var Location) =
  let pos = b.posOf(n)
  case n.kind
  of IntLit:
    b.resolveDest(dest, immLoc(intVal(n), ScalarSlot)); inc n
  of UIntLit:
    b.resolveDest(dest, immLoc(cast[int64](uintVal(n)), ScalarSlot)); inc n
  of CharLit:
    b.resolveDest(dest, immLoc(int64(ord(charLit(n))), ScalarSlot)); inc n
  of Symbol:
    let natural = b.symLoc(symName(n))
    if natural.kind == Undef: b.forceRegDest(dest)   # a global/tvar: load into a register
    else: b.resolveDest(dest, natural)               # a function-local: its home
    inc n
  of StrLit:
    b.forceRegDest(dest); inc n                # string literal → a reg (lea of rodata)
  of TagLit:
    case n.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      allocBin(b, n, dest); return           # records locs[pos] itself
    of DivC, ModC:
      allocDivMod(b, n, dest); return        # records locs[pos] itself
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC:
      # A comparison / and/or/not used as a 0/1 VALUE: the result needs a register;
      # the operands are placed by allocCond. The backend gates this to alias-safe
      # positions (var-init / ret), so a fixed `dest` (a fresh home / rax) never
      # aliases an operand — the emitter writes it directly.
      case dest.kind
      of Undef, NeedsReg, RegOrImm: dest = b.reserveTmp(ScalarSlot)
      else: discard
      if dest.kind != InReg: b.ra.exprUnsupported = true
      let resDest = dest
      allocCond(b, n)                        # places operands; advances past the cond
      b.ra.locs[pos] = resDest
      return
    of CastC, ConvC:
      # A conversion whose RESULT is integer/pointer. A FLOAT source (`conv`) is
      # `cvttsd2si`: the operand goes to an xmm, the int result to `dest` (a GPR).
      # Otherwise an int↔int / ptr reinterpret computes straight into `dest`
      # (identity); the emitter re-represents in place.
      var srcF = false
      block:
        var t = n; inc t; skip t               # tag, target type → source expr
        srcF = b.isFloatVal(t)
      if srcF:
        if n.exprKind != ConvC: b.ra.exprUnsupported = true  # float-bit reinterpret cast: legacy
        b.forceRegDest(dest)                   # int result in a GPR
        let resDest = dest
        n.into:
          skip n                               # target type
          var fd = dontCare                    # operand → an xmm (home or temp)
          allocFValue(b, n, fd)
          b.releaseFTmp(fd)
          while n.hasMore: skip n
        b.ra.locs[pos] = resDest
      else:
        n.into:
          skip n                               # target type
          allocValue(b, n, dest)               # inner → dest (identity)
          while n.hasMore: skip n
        b.ra.locs[pos] = dest
      return
    of DerefC, DotC, AtC, PatC:
      # An addressing expr in VALUE position → load `[addr]` into a register. The
      # embedded base/index values are placed by allocLvalue2; the load lands in a
      # fresh temp (or the dest-passed home / arg reg). A `NeedsReg`/`RegOrImm` dest
      # carries the precise type (e.g. `(aptr u8)`) — keep it so a store to a typed
      # slot type-checks (a generic i64 temp would mismatch).
      case dest.kind
      of NeedsReg, RegOrImm: dest = b.reserveTmp(dest.typ)
      of Undef: dest = b.reserveTmp(ScalarSlot)
      else: discard
      if dest.kind != InReg: b.ra.exprUnsupported = true
      let resDest = dest
      let lvCopy = n                          # for releaseLvalTemps after the load
      # A destination-passed FIXED register (a register-homed local's home) is NOT a temp
      # taken out of the pool, so the index/base allocation below could `stealForTmp` it —
      # stealing the very register this load's result lands in, aliasing the result with one
      # of its own indices (different types ⇒ a `(mov res[ptr], (mem (at … res[i64])))` that
      # nifasm rejects). Seal it across the address allocation so the steal picks another.
      let sealedHere = resDest.isTemp == false and resDest.r notin b.ra.sealed
      if sealedHere: b.ra.sealed.incl resDest.r
      allocLvalue2(b, n, resDest)             # embedded base/index regs; a global base
      if sealedHere: b.ra.sealed.excl resDest.r
      releaseLvalTemps(b, lvCopy)             # index/pointer temps die with the load
      b.ra.locs[pos] = resDest                #   reuses resDest (free until the load lands)
      return
    of AddrC:
      # `(addr lvalue)` → a pointer in a register. Place any embedded base/index
      # values of the lvalue; the result address lands in dest (typed precisely).
      #
      # IDENTITY `&(deref p)` == p: when p is a register-homed symbol and the
      # destination is a transient temp (not a fixed home that we must move into),
      # the address result simply IS p's register — no temp, no copy, no spill. It is
      # kept NON-temp so a consuming binop won't reuse it in place (allocBin reuses
      # only dead temps), leaving p intact across the use.
      var identityHome = dontCare
      if dest.kind in {NeedsReg, RegOrImm, Undef}:
        var inner = n; inc inner
        if inner.kind == TagLit and inner.exprKind == DerefC:
          var p = inner; inc p
          if p.kind == Symbol and b.symLoc(symName(p)).kind == InReg:
            identityHome = b.symLoc(symName(p))
      if identityHome.kind == InReg:
        n.into:
          let lvCopy = n
          allocLvalue2(b, n)                 # place p (sets locs[p]); no result temp
          releaseLvalTemps(b, lvCopy)
          while n.hasMore: skip n
        b.ra.locs[pos] = identityHome
        return
      case dest.kind
      of NeedsReg, RegOrImm: dest = b.reserveTmp(dest.typ)
      of Undef: dest = b.reserveTmp(ScalarSlot)
      else: discard
      if dest.kind != InReg: b.ra.exprUnsupported = true
      let resDest = dest
      n.into:
        let lvCopy = n                       # the lvalue inside (addr …)
        allocLvalue2(b, n, resDest)          # a global base reuses resDest (the lea dest)
        releaseLvalTemps(b, lvCopy)          # index/pointer temps die with the address calc
        while n.hasMore: skip n
      b.ra.locs[pos] = resDest
      return
    of CallC:
      allocCall(b, n, dest); return          # records locs[pos] itself
    of NegC, BitnotC:
      # Unary in-place op (`(neg T x)` / `(bitnot T x)`): the operand computes into the
      # result register; the emitter applies neg/not in place.
      b.forceRegDest(dest)
      var res = dest
      n.into:
        skip n                               # result type
        allocValue(b, n, res)                # operand → res (in place)
        while n.hasMore: skip n
      b.ra.locs[pos] = res
      return
    of SufC, ParC:
      # Wrapper `(suf v "type")` / `(par v)`: unwrap; `dest` passes through to the value.
      n.into:
        allocValue(b, n, dest)
        while n.hasMore: skip n
      b.ra.locs[pos] = dest
      return
    of TrueC:
      b.resolveDest(dest, immLoc(1, ScalarSlot)); skip n
    of FalseC, NilC:
      b.resolveDest(dest, immLoc(0, ScalarSlot)); skip n
    of SizeofC:
      var t = n; var sz = 0'i64
      t.into:
        sz = typeSizeAlign(b.prog[], t)[0].int64
        while t.hasMore: skip t
      b.resolveDest(dest, immLoc(sz, ScalarSlot)); skip n
    else:
      # not modeled yet: reserve a register for the result and skip the subtree
      # (the legacy emitter still handles these forms; no var decls nest inside
      # an expression, so skipping is safe for declaration discovery).
      b.resolveDest(dest, b.reserveTmp(ScalarSlot)); skip n
  else:
    inc n
  b.ra.locs[pos] = dest

proc allocConstr(b: var Builder; n: var Cursor) =
  ## `(oconstr T (kv field value)+)` — allocate each field's value into a register
  ## (a SIMD temp for a float field) the emitter then stores to the field. Each is
  ## single-use (store + free), so the temps recycle. Advances `n` past the oconstr.
  n.into:
    skip n                                     # the constructed type
    while n.hasMore:
      n.into:                                  # (kv field value [depth])
        skip n                                 # field name
        if n.hasMore:
          if b.isFloatVal(n):
            var d = dontCare
            allocFValue(b, n, d)
            b.releaseFTmp(d)
          else:
            var d = needsReg(ScalarSlot)
            allocValue(b, n, d)
            b.releaseTmp(d)
        while n.hasMore: skip n                 # optional inherited-depth INTLIT

proc allocAconstr(b: var Builder; n: var Cursor) =
  ## `(aconstr ArrayT e0 e1 …)` — allocate each (bare) element value into a register
  ## (a SIMD temp for a float element); each is single-use (store + free), so the temps
  ## recycle. Advances `n` past the aconstr. The array twin of `allocConstr`.
  n.into:
    skip n                                     # the array type
    while n.hasMore:
      if b.isFloatVal(n):
        var d = dontCare
        allocFValue(b, n, d)
        b.releaseFTmp(d)
      else:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)
        b.releaseTmp(d)

proc allocStore(b: var Builder; n: var Cursor; dst: Location; auxPos: int) =
  ## Allocator twin of the emitter's `genStore2`: place the homes/temps needed to
  ## store value `n` into `dst`, advancing `n` past the value. The ONE path every
  ## caller (var-init, asgn, return value, call argument) routes through — an
  ## aggregate dispatches like the emitter (oconstr/aconstr build, symbol copy, call
  ## result); a scalar/float computes into its register home (destination-passing) or
  ## a temp the emitter stores; a global reserves an address scratch. Scratch temps
  ## land in `aux[auxPos]`.
  if dst.kind == NamedStack and dst.typ.kind == AMem:    # aggregate destination
    if n.kind == TagLit and n.exprKind == OconstrC:
      allocConstr(b, n)                                  # object: place each field value
    elif n.kind == TagLit and n.exprKind == AconstrC:
      allocAconstr(b, n)                                 # array: place each element value
    elif n.kind == TagLit and n.exprKind == CallC:       # call-returned aggregate
      var d = dontCare
      allocCall(b, n, d, hiddenPtr = dst.typ.size > b.md.aggrByRefThreshold)
    elif n.kind == Symbol:                               # whole-aggregate copy
      skip n
      let t = b.reserveTmp(ScalarSlot); b.releaseTmp(t)  # one word-transfer scratch
      if t.kind == InReg: b.ra.aux[auxPos] = ExprAux(scratch: @[t.r])
      else: b.ra.exprUnsupported = true
    else:
      b.ra.exprUnsupported = true; skip n
  elif dst.kind == Undef:                                # module-level global / threadvar
    # The emitter resolves the destination to a `Glob`/`Tvar` with a precise slot; the
    # allocator only needs the right scratch. A float global stores `movss/movsd [&g], xmm`
    # (the rhs goes to an xmm); a scalar/pointer global stores through a GPR. An aggregate
    # global initializer (a `(s)`-built oconstr/array) is not handled on this path.
    if n.kind == TagLit and n.exprKind in {OconstrC, AconstrC}:
      b.ra.exprUnsupported = true; skip n
    else:
      let addrT = b.reserveTmp(ScalarSlot)               # &g address temp (Tvar ignores it)
      if b.isFloatVal(n):
        var d = dontCare
        allocFValue(b, n, d)
        b.releaseFTmp(d)
      else:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)
        b.releaseTmp(d)
      b.releaseTmp(addrT)
      if addrT.kind == InReg: b.ra.aux[auxPos] = ExprAux(scratch: @[addrT.r])
      else: b.ra.exprUnsupported = true
  elif dst.kind == InFReg:                               # float register home: dest-passing
    var d = dst
    allocFValue(b, n, d)
  elif dst.kind == InReg:                                # scalar register home: dest-passing
    var d = dst
    allocValue(b, n, d)
  elif dst.kind == NamedStack:                           # spilled scalar / float `(s)` slot
    if dst.typ.isFloat:
      var d = b.reserveFTmp(dst.typ)
      allocFValue(b, n, d)
      b.releaseFTmp(d)
    else:
      var d = needsReg(dst.typ)
      allocValue(b, n, d)
      b.releaseTmp(d)
  elif dst.kind == Mem:                                  # store through a complex lvalue (dot/deref/at)
    # Place the lvalue's embedded base/index regs, then the rhs. An AGGREGATE constructor
    # builds field-by-field into the address (placed like a slot store); a FLOAT rhs goes
    # to an xmm; an integer rhs to a register. A global aggregate base needs an address
    # scratch, reserved before the lhs and held across the rhs, then recorded in `aux`.
    let lhsCur = dst.cur
    let hasGlob = lvalueGlobalBase(b, lhsCur)
    var scratch = dontCare
    if hasGlob: scratch = b.reserveTmp(ScalarSlot)
    var lc = lhsCur
    allocLvalue2(b, lc, scratch, isStore = true)         # lhs operands (on a copy)
    if n.kind == TagLit and n.exprKind == OconstrC:
      allocConstr(b, n)                                  # build through the lvalue address
    elif n.kind == TagLit and n.exprKind == AconstrC:
      allocAconstr(b, n)                                 # build array through the lvalue address
    elif b.isFloatVal(n):
      var rdest = dontCare
      allocFValue(b, n, rdest)
      b.releaseFTmp(rdest)
    else:
      var rdest = needsReg(ScalarSlot)
      allocValue(b, n, rdest)
      b.releaseTmp(rdest)
    releaseLvalTemps(b, lhsCur)                          # free the held index/pointer + `(at)` scratch
    if hasGlob:
      b.releaseTmp(scratch)
      if scratch.kind == InReg: b.ra.aux[auxPos] = ExprAux(scratch: @[scratch.r])
      else: b.ra.exprUnsupported = true
  else:
    b.ra.exprUnsupported = true; skip n

proc allocVarDecl(b: var Builder; n: var Cursor) =
  n.into:
    let pos = b.posOf(n)
    assert n.kind == SymbolDef
    let name = symName(n); inc n
    skip n                                   # pragmas
    let slot = slotOf(b.prog[], n); skip n  # type (resolves named types)
    var valCur = n                           # remember the initializer (for allocExprs)
    let hasValue = n.hasMore
    if hasValue: skip n                       # value (analysed in pass 1)
    if slot.kind == AMem:
      # an aggregate (object/array/named type): a nifasm-managed `(s)` stack
      # var, addressed by name — arkham does not register-allocate it. (No
      # early `return` here: that would skip the `into` epilogue and desync.)
      b.record(pos, name, namedStackLoc(name, slot))
      b.ra.hasStackVars = true
      if b.allocExprs and hasValue:
        var vc = valCur
        allocStore(b, vc, namedStackLoc(name, slot), pos)   # the one general store path
    else:
      let props = b.an.vars.getOrDefault(name).props
      var loc = b.allocStorage(slot, props)
      if loc.kind == OnStack and AddrTaken notin props and
         slot.inRegClass and not slot.isFloat:
        loc = b.trySteal(name, slot, props, loc)  # hot var evicts a colder one
      if loc.kind == OnStack:
        # A spilled (or address-taken) scalar — integer/pointer (`(s) (i 64)`) or
        # float (`(s) (f N)`) — lives in a nifasm-managed slot addressed by name,
        # same frame as aggregates, so nifasm computes the offset. (Floats don't
        # participate in `trySteal` eviction yet; they spill directly here.)
        loc = namedStackLoc(name, slot)
        b.ra.hasStackVars = true
      b.record(pos, name, loc)
      b.scopeVars[^1].add name
      # Register the coarse early-free, unless declared in a loop (a later loop-body
      # decl could reuse the reg across the back-edge). Stored by name so the flush
      # frees the var's *current* reg (it may have been evicted to the stack).
      let vi = b.an.vars.getOrDefault(name)
      if loc.kind == InReg and not vi.declInLoop:
        b.pendingFree.add (pos: vi.freeAfter, name: name)
      if b.allocExprs and hasValue:
        var vc = valCur
        allocStore(b, vc, loc, pos)            # the one general store path

proc walk(b: var Builder; n: var Cursor) =
  case n.stmtKind
  of ProcS, TypeS:
    skip n                                   # nested decls allocate separately
  of VarS, GvarS, TvarS, ConstS:
    allocVarDecl(b, n)
  of ScopeS:                                 # only a `scope` opens a fresh scope
    openScope(b)
    n.into:
      while n.hasMore:
        walk(b, n)
        flushFree(b, b.posOf(n))             # free locals dead as of this boundary
    closeScope(b)
  of StmtsS:                                  # a statement list — NOT a fresh scope
    n.into:
      while n.hasMore:
        walk(b, n)
        flushFree(b, b.posOf(n))
  of RetS:
    if b.allocExprs:
      n.into:
        let retPos = b.posOf(n)
        if n.hasMore and n.kind != DotToken:
          if b.retFloatBits > 0:                         # float result → xmm0 (general store)
            allocStore(b, n, fregLoc(b.md.floatArgRegs[0], floatSlot(b.retFloatBits)), retPos)
          elif n.kind == Symbol and b.symLoc(symName(n)).kind == NamedStack and
               b.symLoc(symName(n)).typ.kind == AMem:
            # An aggregate return marshals OUT (≤16B → structToRegs; >16B → through the
            # hidden result pointer, needing one word-transfer scratch) — the inverse of a
            # store-into-destination, so it stays here rather than in `allocStore`.
            if b.retIndirect:
              let t = b.reserveTmp(ScalarSlot); b.releaseTmp(t)
              if t.kind == InReg: b.ra.aux[retPos] = ExprAux(scratch: @[t.r])
              else: b.ra.exprUnsupported = true
            skip n
          else:                                          # scalar/pointer result → ret reg
            allocStore(b, n, regLoc(b.md.intRetReg, ScalarSlot), retPos)
        else:
          while n.hasMore: skip n              # void return
    else:
      skip n
  of CallS:
    if b.allocExprs:
      var d = dontCare                         # a statement call: result unused
      allocValue(b, n, d)
    else:
      if n.kind == TagLit:
        n.into:
          while n.hasMore: walk(b, n)
      else: inc n
  of AsgnS:
    if b.allocExprs:
      let asgnPos = b.posOf(n)
      n.into:
        if n.kind == Symbol:
          let dst = b.symLoc(symName(n))         # local home; a global / tvar → Undef
          skip n                                 # lhs (not a value-read)
          allocStore(b, n, dst, asgnPos)         # the one general store path
        else:
          # A memory store through a complex lvalue (dot/deref/at).
          let lhsCur = n
          skip n                                 # advance past the lhs to the rhs
          allocStore(b, n, memLoc(lhsCur, ScalarSlot), asgnPos)  # the one general store path
        while n.hasMore: skip n
    else:
      n.into:
        while n.hasMore: walk(b, n)
  of WhileS:
    if b.allocExprs:
      n.into:
        allocCond(b, n)                        # loop condition
        while n.hasMore: walk(b, n)            # body (a `(stmts …)` node)
    else:
      n.into:
        while n.hasMore: walk(b, n)
  of IfS:
    if b.allocExprs:
      n.into:
        while n.hasMore:
          case n.substructureKind
          of ElifU:
            n.into:
              allocCond(b, n)
              while n.hasMore: walk(b, n)       # branch body
          of ElseU:
            n.into:
              while n.hasMore: walk(b, n)
          else: skip n
    else:
      n.into:
        while n.hasMore: walk(b, n)
  of CaseS:
    if b.allocExprs:
      n.into:
        var sel = needsReg(ScalarSlot)
        allocValue(b, n, sel)                  # selector → a register (live across all tests)
        while n.hasMore:
          case n.substructureKind
          of OfU:
            n.into:
              skip n                            # (ranges …) — immediate bounds, no alloc
              while n.hasMore: walk(b, n)       # branch body
          of ElseU:
            n.into:
              while n.hasMore: walk(b, n)
          else: skip n
        b.releaseTmp(sel)                       # the selector is dead after the tests
    else:
      n.into:
        while n.hasMore: walk(b, n)
  else:
    if n.kind == TagLit:
      n.into:
        while n.hasMore: walk(b, n)          # recurse (var decls may nest)
    else:
      inc n

proc allocParams(b: var Builder; params: var Cursor; hasCall: bool) =
  if params.kind != TagLit: return
  var intIdx = 0
  var fidx = 0
  params.into:
    while params.hasMore:
      params.into:
        let pos = b.posOf(params)
        assert params.kind == SymbolDef
        let name = symName(params); inc params
        skip params                          # pragmas
        let slot = slotOf(b.prog[], params); skip params  # type (resolves named)
        # Classify an aggregate param: ≤16B by-value (a `(s)` stack home filled
        # from its GPR(s)) vs >16B by-reference (a pointer, like a scalar).
        var aggrSmall = false
        var aggrByRef = false
        var aggrWords = 0
        if slot.kind == AMem:
          let sz = slot.size                  # filled by slotOf (named or inline)
          if sz >= 1 and sz <= b.md.aggrByRefThreshold: (aggrSmall = true; aggrWords = (sz + 7) div 8)
          else: aggrByRef = true
        if aggrSmall:
          # (No early `continue`/`return`: that skips the `into` epilogue.)
          b.record(pos, name, namedStackLoc(name, slot))
          b.ra.hasStackVars = true
          intIdx += aggrWords
        else:
          # `effSlot` is the in-register value: the scalar itself, or (by-ref) a
          # pointer to the aggregate copy.
          let effSlot = if aggrByRef: AsmSlot(cls: AUInt, size: 8, align: 8) else: slot
          let props = b.an.vars.getOrDefault(name).props
          var loc: Location
          if effSlot.isFloat:
            # A float parameter arrives in v{fidx}. In a leaf proc it stays
            # there; if the proc makes calls it moves to a callee-saved register
            # (v8–v15) so it survives them; if address-taken it spills to a slot.
            # Either way the incoming register is consumed, so `fidx` advances in
            # lockstep with emitParamMoves (the >8-float case is still TODO).
            if fidx < b.md.floatArgRegs.len:
              if AddrTaken in props:
                loc = b.spill(effSlot)           # address taken → must be on the stack
              elif hasCall:
                let f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
                if f != NoFReg:
                  b.ra.usedCalleeF.incl f
                  loc = fregLoc(f, effSlot)
                else:
                  loc = b.spill(effSlot)
              else:
                loc = fregLoc(b.md.floatArgRegs[fidx], effSlot)
              inc fidx
            else:
              loc = b.spill(effSlot)             # >8 float args: stack-passed (TODO)
          elif not effSlot.inRegClass:
            loc = b.spill(effSlot)
          elif intIdx < b.md.intArgRegs.len:
            let arg = b.md.intArgRegs[intIdx]
            # A leaf param would normally stay in its arg register, but if that
            # register is a fixed-instruction scratch the body clobbers (rdx for
            # div/mod, rcx for a variable shift), it must move to a callee-saved
            # home that survives the clobber. Treat it like a cross-call param.
            let clobbered = (arg == b.md.divRemReg and b.an.clobbersDivReg) or
                            (arg == b.md.shiftCountReg and b.an.clobbersShiftReg)
            if AddrTaken in props and not aggrByRef:
              loc = b.spill(effSlot)           # address taken → must be on the stack
            elif hasCall or aggrByRef or clobbered:
              # Live across a call (the incoming arg reg is volatile), or a by-ref
              # pointer that must survive repeated field loads in the body: give
              # it a callee-saved home so the prologue can `mov home, argReg`.
              let r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
              if r != NoReg:
                b.ra.usedCallee.incl r
                loc = regLoc(r, effSlot)
              else:
                loc = b.spill(effSlot)
            else:
              loc = regLoc(arg, effSlot)       # leaf proc: stay in the arg reg
            inc intIdx
          else:
            # The 9th integer/pointer parameter onward arrives on the caller's
            # stack (AAPCS64). arkham gives it a callee-saved register home that
            # the prologue loads from the incoming arg slot before SP is lowered
            # for locals, so it survives the whole proc. Address-taken or
            # out-of-register stack params aren't supported yet.
            if AddrTaken in props:
              raiseAssert "arkham v1: address-taken >8th parameter"
            let r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
            if r == NoReg:
              raiseAssert "arkham v1: out of callee-saved registers for >8th parameter"
            b.ra.usedCallee.incl r
            loc = regLoc(r, effSlot)
            inc intIdx
          if loc.kind == OnStack and slot.kind != AMem:
            # An address-taken scalar param (integer or float): a nifasm `(s)`
            # slot the prologue fills from the incoming arg register (int or SIMD;
            # see emitParamMoves).
            loc = namedStackLoc(name, effSlot)
            b.ra.hasStackVars = true
          b.record(pos, name, loc)

proc allocateProc*(buf: var TokenBuf; procDecl: Cursor; an: ProcAnalysis;
                   prog: var Program; md: MachineDesc; tc: TypeCtx;
                   presealed: set[Reg] = {}; allocExprs = false;
                   atScratch: HashSet[int] = initHashSet[int]()): RegAlloc =
  ## Allocate storage for the params and locals of `procDecl`. `md` describes the
  ## target register file + ABI. `presealed` registers are reserved for the whole
  ## proc (never allocated/stolen). `prog` is taken by `var` because resolving a
  ## cross-module type may load a module. `allocExprs` (value-core rewrite) also
  ## assigns `locs[pos]` to expressions — off by default so the legacy reactive
  ## emitter sees the unchanged symbol-only `locs`. `atScratch` lists the `(at …)`
  ## positions (computed by the codegen, which can size strides) that need a scratch
  ## GPR for a non-SIB element stride.
  var b = Builder(buf: addr buf, an: addr an, prog: addr prog, tc: tc, md: md,
                  allocExprs: allocExprs, atScratch: atScratch)
  b.ra.locs = newSeq[Location](buf.len)
  b.ra.aux = initTable[int, ExprAux]()
  b.ra.symPos = initTable[string, int]()
  b.ra.sealed = presealed
  for r in md.intTempRegs: b.freeVol.incl r
  for r in md.intCalleeSaved: b.freeCallee.incl r
  for f in md.floatTempRegs: b.freeVolF.incl f
  for f in md.floatCalleeSaved: b.freeCalleeF.incl f
  var n = procDecl
  assert n.stmtKind == ProcS
  b.openScope()
  n.into:
    inc n                                    # name
    allocParams(b, n, an.hasCall)            # params
    if n.kind == TagLit:                      # a float return goes to xmm0 (value-core)
      let rtSlot = slotOf(prog, n)
      if rtSlot.isFloat: b.retFloatBits = rtSlot.size * 8
    elif n.kind == Symbol:                    # a named-type return; >16B aggregate → hidden ptr
      let rtSlot = slotOf(prog, n)
      if rtSlot.kind == AMem and rtSlot.size > md.aggrByRefThreshold: b.retIndirect = true
    skip n                                   # return type
    skip n                                   # pragmas
    walk(b, n)                               # body
  b.closeScope()
  result = ensureMove b.ra

# ── lookup API (used by codegen) ────────────────────────────────────────────

proc locationOfSym*(ra: RegAlloc; name: string): Location {.inline.} =
  ## Storage of a local/param by name; `Undef` if unknown.
  let p = ra.symPos.getOrDefault(name, -1)
  if p >= 0: ra.locs[p] else: dontCare

# ── sealing (driven by codegen during ABI call marshalling) ─────────────────
# Before codegen places an argument in `xN` (or `x8` for an indirect result),
# it seals that register so any scratch borrow or steal during the rest of the
# call setup cannot clobber the committed value; it unseals after the call.

proc seal*(ra: var RegAlloc; r: Reg) {.inline.} = ra.sealed.incl r
proc unseal*(ra: var RegAlloc; r: Reg) {.inline.} = ra.sealed.excl r
proc seal*(ra: var RegAlloc; regs: set[Reg]) {.inline.} = ra.sealed = ra.sealed + regs
proc unseal*(ra: var RegAlloc; regs: set[Reg]) {.inline.} = ra.sealed = ra.sealed - regs
proc isSealed*(ra: RegAlloc; r: Reg): bool {.inline.} = r in ra.sealed
