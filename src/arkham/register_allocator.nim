#
#           Arkham — native AArch64 code generator for Leng
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

import std / [tables, sets, assertions, os]

let callerSaveDisabled = existsEnv("ARKHAM_NO_CALLERSAVE")
  ## measurement toggle: `ARKHAM_NO_CALLERSAVE=1` reverts the caller-save rescue to a
  ## plain spill, so the spill delta can be A/B compared. Off (feature on) by default.
let copyInheritDisabled = existsEnv("ARKHAM_NO_COPYINHERIT")
  ## measurement toggle: `ARKHAM_NO_COPYINHERIT=1` disables same-width cast/copy home
  ## inheritance (`allocVarDecl`), so the eliminated reg→reg moves can be A/B compared.
import nifcore, nifcdecl, slots, machinedesc, analyser, programs, typenav

var gArkhamCurProc* = ""   # debug: the proc arkham is currently allocating (for asserts)

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
    heldSlot*: seq[string]            ## parallel to `scratch`: when a survivor scratch
                                      ## could not get a callee-saved reg (`reserveHeld
                                      ## Scratch` totality backstop), `scratch[i]` is
                                      ## `NoReg` and this names its spill slot; the
                                      ## emitter re-derives the address into a transient
                                      ## at use (see `heldScratchReg`). "" ⇒ `scratch[i]`
                                      ## is a real register.
    fscratch*: seq[FReg]              ## extra SIMD scratch reserved for this op
    swapped*: bool                    ## operands evaluated in swapped (Sethi–Ullman) order
    foldB*: bool                      ## operand B stays a folded memory operand (no load)
    aliasRhs*: bool                   ## dest register aliases the rhs operand: the emitter
                                      ## must not place lhs into dest first (`s = a - s`)

  LocSpan* = object
    ## Position-indexed `Location` storage for ONE proc. Token positions are
    ## ABSOLUTE module-buffer offsets (`cursorToPosition`), but a proc only ever
    ## touches positions inside its own contiguous subtree span `[base, base+data.len)`.
    ## Sizing to the SPAN instead of the whole module (the old `newSeq(buf.len)`)
    ## makes per-proc allocation O(procTokens) rather than O(moduleTokens): with the
    ## module-sized array, every one of a module's hundreds of procs re-allocated and
    ## zeroed a full ~buf.len array of ~130-byte `Location`s — GBs of pure memory
    ## traffic, ~91% of arkham's runtime. Indexing subtracts `base`, so all existing
    ## `locs[pos]` call sites are unchanged.
    base*: int
    data*: seq[Location]

  RegAlloc* = object
    locs*: LocSpan                    ## indexed by cursorToPosition. Currently filled
                                      ## for symbol defs; the rewrite fills it for EVERY
                                      ## value-producing position (its result location).
    aux*: Table[int, ExprAux]         ## pos → per-op selection aux (see `ExprAux`)
    symPos*: Table[string, int]       ## local/param name → its def position. This IS the
                                      ## local→cursor-pos mapping: every local read resolves
                                      ## through `locs[symPos[name]]` (the emitter late-binds via
                                      ## `locationOfSym`), so undoing a local's register is a
                                      ## single-point rewrite that every use sees — no scattered
                                      ## snapshots to reconcile.
    usedCallee*: set[Reg]             ## callee-saved GPRs to save in prologue
    usedCalleeF*: set[FReg]           ## callee-saved SIMD regs (v8–v15) to save in prologue
    frameSize*: int                   ## bytes of stack frame for spilled slots
    hasStackVars*: bool               ## proc has nifasm-managed `(s)` aggregate vars
    hasStackParams*: bool             ## proc receives ≥1 parameter on the stack — the
                                      ## allocator reserved a callee-saved reg for the
                                      ## emitter's `stackArgBaseReg` (single source of
                                      ## truth; the emitter must NOT re-classify)
    callerSaveHomes*: Table[string, int]
                                      ## x64: cross-call LOCALS that, under callee-saved
                                      ## pressure, were given a CALLER-SAVE volatile home
                                      ## (R8/R9 — atomic-safe) instead of spilling. Maps the
                                      ## var name → its coarse `freeAfter`. At each call the
                                      ## emitter brackets the ones still live-across with a
                                      ## `(scope …)` save/restore (the reg's value survives
                                      ## in a reclaimable typed slot). Beats a spill's
                                      ## reload-per-use: register-resident between calls.
    aliasedCasts*: HashSet[string]    ## identity-cast value aliases (`let c2 = cast[T](c1)`,
                                      ## c1 LIVE): `c2` has NO home of its own — its `symPos`
                                      ## points at `c1`'s decl, so it resolves to `c1`'s live
                                      ## register. The emitter emits neither a decl nor a store
                                      ## for these (uses auto-cast via the deref handler).
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
    tc: TypeCtx                       ## shared Leng type navigator (`getType`/`exprSlot`) —
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
    retAggr: bool                     ## the proc returns an aggregate (≤16B in regs OR
                                      ## >16B via the hidden ptr) — drives the `RetS` marshal
    retAggrSlot: AsmSlot              ## the aggregate return type's slot (AMem); used to
                                      ## allocate an inline `(ret (oconstr …))` value
    atScratch: HashSet[int]           ## value-core: `(at …)` positions needing a scratch GPR
                                      ## (non-SIB element stride); sized by the codegen

proc initLocSpan(base, len: int): LocSpan {.inline.} =
  ## Zero-inits `len` `Location`s (kind `Undef`, ordinal 0 — an unwritten position).
  LocSpan(base: base, data: newSeq[Location](len))

proc `[]`*(s: LocSpan; pos: int): lent Location {.inline.} = s.data[pos - s.base]
proc `[]`*(s: var LocSpan; pos: int): var Location {.inline.} = s.data[pos - s.base]
proc `[]=`*(s: var LocSpan; pos: int; v: Location) {.inline.} = s.data[pos - s.base] = v

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
    if b.md.arch == X86:
      # x86-64: PREFER the volatile `intLocalTempRegs` and fall back to callee-saved.
      # A call-free local is unconstrained (any register, no prologue push/pop); taking a
      # scarce callee-saved reg for it starves the cross-call locals — which have NO other
      # option — into spills (a register-class priority inversion). Reserve callee-saved
      # for the values that can only use it. (Gated to x86: this exercises volatile-reg
      # local homes far more, and the x64 emitter has the matching narrowing-mov / reused-
      # register retype support — see codegen_x64/assembler; the AArch64 path does not yet,
      # so it keeps the callee-saved-first order it was validated with.)
      r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
      if r == NoReg: r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
    else:
      r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
      if r == NoReg: r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
    # Still nothing? A local whose interval crosses no variable shift / no div may
    # additionally home in the shift-count / div-rem register: their fixed role
    # never overlaps this local's life (guaranteed by the interval test that set
    # `ShiftRegOk`/`DivRegOk`; asserted at the div/shift emission sites). This is the
    # per-fixed-role-register generalization of `AllRegs` — more homes for the hot,
    # call-free leaf functions that are otherwise spill-bound.
    if r == NoReg and ShiftRegOk in props and b.md.shiftCountReg != NoReg:
      r = b.takeReg(b.freeVol, [b.md.shiftCountReg])
    if r == NoReg and DivRegOk in props and b.md.divRemReg != NoReg:
      r = b.takeReg(b.freeVol, [b.md.divRemReg])
  elif b.md.arch == X86 and R89Ok in props and b.md.atomicSafeTempRegs.len > 0:
    # Live across an INLINED ATOMIC but no REAL call (so not `AllRegs`: an atomic
    # clobbers its arg regs rdi/rsi). The atomic-safe volatile temps (r8/r9) survive
    # its limited clobber, so PREFER them and reserve the scarce callee-saved pool for
    # values that cross a real call — which have no volatile option (mirrors the x86
    # `AllRegs` volatile-first policy; the priority-inversion guard).
    r = b.takeReg(b.freeVol, b.md.atomicSafeTempRegs)
    if r == NoReg: r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
  else:
    # may be live across a real call → must be callee-saved (or stack)
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
  if r == NoReg:
    when defined(arkhamSpillDbg):
      stderr.writeLine "SPILL allregs=" & $(AllRegs in props) &
        " homesUsed=" & $(b.freeCallee.card + b.freeVol.card) &
        " callee=" & $(5 - b.freeCallee.card) & "/5 vol=" & $b.freeVol.card & "free"
    return b.spill(slot)
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

proc rangeLen(b: Builder; name: string): int {.inline.} =
  ## Length (in token positions) of a local's live interval — its register-occupancy
  ## span. Used ONLY as a tie-breaker among equal-`weight` steal candidates. `high(int)`
  ## for a param (`freeAfter == high`): live across the whole body, so among equals a
  ## param is the longest-lived and thus the preferred victim.
  let vi = b.an.vars.getOrDefault(name)
  if vi.freeAfter == high(int): return high(int)
  let lo = if vi.declInLoop: vi.loopLo else: vi.liveStart
  let hi = if vi.declInLoop: vi.loopHi else: vi.freeAfter
  max(1, hi - lo)

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

proc coldestVictim(b: var Builder; maxW, ceilLen: int; calleeOnly, wantFloat: bool): string =
  ## The coldest live register-resident local whose register may be stolen: a non-sealed
  ## GPR (`calleeOnly` restricts to the callee-saved set) or — `wantFloat` — a SIMD
  ## register. "Coldest" = lowest `weight`; **ties broken by the LONGER live range** — an
  ## equal-use var that occupies its register for a longer span drains the pool more, so
  ## among equals it is the better spill victim (`tweaks.md` tweak 1). The ceiling
  ## `(maxW, ceilLen)` is the caller's own coldness: a candidate qualifies iff strictly
  ## colder than it in that (weight, then length) order. "" when nothing is stealable.
  var bestW = maxW
  var bestLen = ceilLen               # meaningful only for an equal-`bestW` candidate
  result = ""
  for scope in b.scopeVars:
    for v in scope:
      if v in b.freedSyms: continue             # already dead (early-freed)
      let vloc = b.ra.locs[b.ra.symPos[v]]
      if wantFloat:
        if vloc.kind != InFReg: continue
      else:
        if vloc.kind != InReg: continue
        if vloc.r in b.ra.sealed: continue      # pinned to an in-flight ABI call
        if calleeOnly and vloc.r notin b.md.intCalleeSavedSet: continue
      let vw = b.weightOf(v)
      if vw < bestW or (vw == bestW and b.rangeLen(v) > bestLen):
        bestW = vw; bestLen = b.rangeLen(v); result = v

proc demoteToStack(b: var Builder; victim: string) =
  ## Undo `victim`'s optimistic register assignment: move it to a nifasm-managed `(s)`
  ## slot addressed by its own name (offsets are nifasm's job). A single-point rewrite
  ## of `locs[symPos[victim]]` — and because every use reads through `symPos` (the
  ## emitter late-binds via `locationOfSym`), every use, walked or not, sees the new
  ## home. Sound across every control-flow path: the home is memory everywhere.
  let vpos = b.ra.symPos[victim]
  b.ra.locs[vpos] = namedStackLoc(victim, b.ra.locs[vpos].typ)
  b.ra.hasStackVars = true

proc trySteal(b: var Builder; curName: string; curSlot: AsmSlot;
              curProps: VarProps; fallback: Location): Location =
  ## `curName` wanted a register but the pool was empty (`fallback` is a stack
  ## slot). Evict the lowest-weight live local that holds a usable register, if
  ## it is strictly colder than `curName`; that local moves to `fallback` and
  ## `curName` takes its register. Returns `curName`'s chosen location.
  let calleeOnly = AllRegs notin curProps   # cross-call var needs callee-saved
  let bestV = b.coldestVictim(b.weightOf(curName), b.rangeLen(curName),
                              calleeOnly, wantFloat = false)
  if bestV.len == 0: return fallback        # nothing colder to steal from
  # evict the victim to its stack slot; current takes its register
  let bestReg = b.ra.locs[b.ra.symPos[bestV]].r
  b.demoteToStack(bestV)
  if bestReg in b.md.intCalleeSavedSet: b.ra.usedCallee.incl bestReg
  result = regLoc(bestReg, curSlot)

# A computed temporary NEVER steals a live local. codegen.c proves ~2 registers
# suffice for all computation; temps draw from the volatile/callee-saved scratch the
# pool still has free, and when none is free they spill to their OWN `(s)` slot
# (`reserveTmp` below) — single-use, branch-safe, no local touched. The ONLY undo of a
# register assignment is local→memory (`trySteal` / `reserveHeldScratch`), decided while
# allocating locals; that is the whole "we optimistically gave a local a register, then
# found we have too many, so we undo it" story, and it can never collide with a temp.

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
      # pool exhausted (every free reg holds a live local): spill THIS temp to its own
      # `(s)` slot. A temp is single-use, so the spill is local, uniform and branch-safe
      # — NO live local is touched (temps never steal locals). The emitter declares it
      # (`spillTemps`) and PRODUCES the value position into it through a staging register
      # (`produceIntoMem2`); `isTemp` marks it a produce-into slot, distinct from a
      # symbol's stack home left for folding.
      let nm = "etmp" & $b.tmpSpills & ".0"; inc b.tmpSpills
      b.ra.hasStackVars = true
      b.ra.spillTemps.add (name: nm, typ: slot, isFloat: false)
      return namedStackLoc(nm, slot, isTemp = true)
    if r in b.md.intCalleeSavedSet: b.ra.usedCallee.incl r
  result = regLoc(r, slot, isTemp = true)

proc releaseTmp(b: var Builder; loc: Location) {.inline.} =
  if loc.kind == InReg and loc.isTemp: b.giveBack loc.r

proc heldSpillSlot(b: var Builder): Location =
  ## A fresh callee-saved-safe spill slot for a survivor scratch (the totality backstop
  ## of `reserveHeldScratch`). Like `reserveTmp`'s `etmp`, but a survivor home: its value
  ## (a re-derivable address) lives here across a call and the emitter re-derives it.
  let nm = "held" & $b.tmpSpills & ".0"; inc b.tmpSpills
  b.ra.hasStackVars = true
  b.ra.spillTemps.add (name: nm, typ: AsmSlot(cls: AInt, size: 8, align: 8), isFloat: false)
  namedStackLoc(nm, ScalarSlot, isTemp = true)

proc reserveHeldScratch(b: var Builder; what: string; canSpill = false): Location =
  ## A SURVIVOR scratch: a register that must outlive a call and/or stay off the R11
  ## staging bridge (a &global / aggregate-arg address marshalled THROUGH the bridge,
  ## or held across a ≤16B-result call) — so it cannot come from caller-saved emit-time
  ## staging (the stride/aggr-copy answer); it must be a CALLEE-SAVED pool register.
  ## Take a free callee-saved reg, else UNDO a local's optimistic assignment: demote the
  ## coldest callee-saved-homed local to memory and take its register (the same local→
  ## memory undo as `trySteal`, sound by the single-home rewrite).
  ##
  ## TOTALITY (the by-construction guarantee): if the callee-saved pool is genuinely
  ## exhausted — no free reg AND every callee-saved reg holds another live survivor, so
  ## there is no local to demote — and the CALLER opted in with `canSpill`, this returns a
  ## SPILL SLOT (`NamedStack`, isTemp) instead of failing. The survivor's value lives in
  ## memory across the call (memory is call-clobber-safe by definition) and the emitter
  ## re-derives it into a transient at each use (every survivor here holds a re-derivable
  ## address — a `&global`/`&slot`), mirroring `reserveTmp`'s `etmp` fallback. `canSpill`
  ## is opt-in so only consumers that actually implement the slot reload (`heldRef` +
  ## emit-side re-derive, e.g. the aggregate-global-store) ever receive a slot; the rest
  ## (which cannot exhaust the pool, since they hold no scratch across a call) keep the
  ## loud assert as a not-yet-wired marker rather than silently mis-reading `NoReg`.
  when defined(arkhamForceSpillAggrGlob):
    if canSpill: return b.heldSpillSlot()   # TEST-ONLY: exercise the re-derive emit path
  var r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
  if r != NoReg:
    b.ra.usedCallee.incl r
    return regLoc(r, ScalarSlot, isTemp = true)
  let victim = b.coldestVictim(high(int), low(int), calleeOnly = true, wantFloat = false)
  if victim.len == 0:
    if canSpill: return b.heldSpillSlot()   # totality backstop (wired consumer)
    raiseAssert "arkham: out of registers for " & what & " (nothing to spill)"
  r = b.ra.locs[b.ra.symPos[victim]].r
  b.demoteToStack(victim)
  b.ra.usedCallee.incl r
  result = regLoc(r, ScalarSlot, isTemp = true)

proc reserveFTmp(b: var Builder; slot: AsmSlot): Location =
  ## A scratch SIMD register for a computed float temporary — the SIMD twin of
  ## `reserveTmp`: the volatile float pool (xmm8–15) first, then callee-saved
  ## (empty on x86-64), then a spill slot the emitter PRODUCES the value into
  ## through a staging xmm (`produceIntoFMem2`).
  var f = b.takeFReg(b.freeVolF, b.md.floatTempRegs)
  if f == NoFReg:
    f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    if f == NoFReg:
      # pool exhausted: spill THIS float temp to its own slot (no local evicted).
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

proc heldRef(loc: Location): (Reg, string) {.inline.} =
  ## Split a `reserveHeldScratch` result into the `(scratch reg, heldSlot name)` pair
  ## the emitter's `aux` carries: a real callee-saved reg → `(reg, "")`; the totality
  ## spill-slot backstop → `(NoReg, slotName)`. The emitter re-derives the address into
  ## a transient when the slot form is present (see `heldScratchReg`).
  if loc.kind == InReg: (loc.r, "") else: (NoReg, loc.name)

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

proc copyCastSrcSym*(n: Cursor): Cursor =
  ## If `n` is a bare `Symbol`, or a `(cast T sym)` / `(conv T sym)` relabel, return a
  ## cursor at the inner `Symbol`; otherwise return a cursor whose `.kind != Symbol`
  ## (the caller filters on that). Spots `let c2 = c1` / `let c2 = cast[T](c1)` whose
  ## value is just another local — a candidate for register-home inheritance. The
  ## same-width / liveness / register-class safety gates live at the two call sites.
  if n.kind == Symbol: return n
  if n.kind == TagLit and n.exprKind in {CastC, ConvC}:
    var t = n; inc t          # past the tag
    skip t                    # past the target type
    return t                  # at the inner expr (a `Symbol` iff a plain relabel)
  return n

proc isFoldableLeaf(b: var Builder; n: Cursor): bool =
  ## A value needing NO register held across a sibling subtree: an immediate, or a
  ## function-local symbol read (folds as its reg / stack home operand). A computed
  ## expr, a string literal, or a global (each needs a load into a temp) is not.
  case n.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: b.symLoc(symName(n)).kind in {InReg, NamedStack}
  else: false

proc initHasCallImpl(n: var Cursor): bool =
  ## Advances `n` past the subtree; true iff it contains a call anywhere. A var whose
  ## initializer contains a call is NOT defined before that call — it is produced BY it —
  ## so it must not get a caller-save home (the emitter would save an undefined register).
  if n.kind == TagLit:
    if n.exprKind == CallC: return true         # the "call" tag → CallC (in any context)
    n.into:
      while n.hasMore:
        if initHasCallImpl(n): return true      # each recursion consumes one child
  else:
    inc n
  return false

proc initHasCall(n: Cursor): bool =
  var c = n
  initHasCallImpl(c)

proc callsCrossed(b: Builder; vi: VarInfo): int =
  ## How many real calls the var's coarse live range spans — the number of save/restore
  ## pairs a caller-save home would cost. Mirrors the cross-call test in `analyser`.
  let lo = if vi.declInLoop: vi.loopLo else: vi.liveStart
  let hi = if vi.declInLoop: vi.loopHi else: vi.freeAfter
  for p in b.an.callPositions:
    if lo < p and p <= hi: inc result

proc commutativeExpr(ek: LengExpr): bool {.inline.} =
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
  ## preserving. A memory-load operand of a typed op has the op's width (Leng widens
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
       not isConstShiftCount(n):
      # x86 variable shift: the count must be in cl. cl (rcx) must be free here — a
      # LIVE symbol homed in it would be clobbered. `freeVol` membership is the ground
      # truth for "free": a `ShiftRegOk` local homed in rcx is, by construction, dead
      # before any variable shift (its interval excludes every shift position), so
      # flushFree has already returned rcx to the pool by this statement. A stale
      # `regOccupied` (static-home) test would false-positive on that dead home.
      # allocParams likewise relocates an rcx-homed param when the body has any
      # variable shift (`clobbersShiftReg`), so a param never lingers here either.
      if b.md.shiftCountReg notin b.freeVol:
        raiseAssert "arkham: variable shift while the count register holds a live local"
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
    elif rDest.kind == InReg and rDest.isTemp and lDest.kind == InReg and
         ek notin {ShlC, ShrC}:
      # Recycle the dead RHS temp as the result. The op consumes rhs, so its register
      # is free the instant the op emits — reusing it here means we DON'T take a third
      # register (or, when the pool is down to r10, an `etmp` spill) for `dest` while
      # rhs sits idle. This is the "free the operand before reserving dest" recycling:
      # the emitter's `aliasRhs` path computes `dest := rhs op lhs` (commutative) or
      # `dest := (dest - lhs); neg` (sub) — both need lhs InReg (guaranteed here; a temp
      # lhs already took the RMW branch above, so this lhs is a non-temp register home).
      # Not for shifts: rhs is the cl count and must stay put.
      dest = rDest
    else: dest = b.reserveTmp(ScalarSlot)
  else: discard
  # (A memory-homed dest — a demoted local or a spilled `etmp` — is fine: the
  # emitter computes into a staging register and stores back; see emitBin2.)
  # Destination-passing hazard: a *fixed* dest (an asgn/store target) that aliases
  # the rhs register would be clobbered when the emitter places lhs into dest before
  # the op (`dest := lhs; dest op= rhs`). Safe when dest == lhs (in-place RMW). For a
  # commutative op the emitter folds it to `dest op= lhs` (no lhs move); for `sub` it
  # computes `dest := dest - lhs; neg dest`. (Var-decl inits never hit this — a fresh
  # home can't alias a still-live operand — so only `s = a - s`-shaped asgns do.) A
  # variable shift can't be rewritten this way (the count needs cl) — placing lhs
  # into dest first would clobber the count, so it fails loudly (no silent miscompile).
  let aliasRhs = dest.kind == InReg and rDest.kind == InReg and dest.r == rDest.r and
                 not sameReg(dest, lDest)
  if aliasRhs and ek in {ShlC, ShrC}:
    raiseAssert "arkham: variable shift whose destination aliases the count register"
  if not sameReg(dest, rDest): b.releaseTmp(rDest)   # dest may BE rDest (recycled) — keep it live
  if not sameReg(dest, lDest): b.releaseTmp(lDest)
  b.ra.aux[pos] = ExprAux(foldB: rDest.kind in {NamedStack, Mem},
                          aliasRhs: aliasRhs and ek notin {ShlC, ShrC})
  b.ra.locs[pos] = dest

proc allocFBin(b: var Builder; n: var Cursor; dest: var Location) =
  ## Float binary arith `(op (f N) a b)` (add/sub/mul/div) — the SIMD twin of
  ## `allocBin`. SSE is destructive 2-operand, so `a` computes straight into the
  ## result register `dest` (resolved to a concrete xmm here) and the op is
  ## `dest := dest op b`; `b` folds in place when it is a float local already in a
  ## register, else it draws a fresh SIMD temp.
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
      else: raiseAssert "arkham: out of SIMD scratch for a spilled float operand"
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
      # would compute `dest op dest` (after `a` clobbered `dest`) — wrong UNLESS the
      # operands are the same symbol (`x op x`: `a` left dest == x, so the fold is
      # exact). Fail loudly rather than miscompile.
      if dest.kind == InFReg and rDest.f == dest.f and
         not (lhsC.kind == Symbol and symName(lhsC) == symName(n)):
        raiseAssert "arkham: float operand fold aliases the destination register"
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
    # The bit pattern is materialized through a scratch GPR (fmovq/d xmm ← gpr); the
    # emitter draws that GPR from its staging set (x64 R11 bridge / a64 takeBridge) —
    # it is purely transient (load-imm → fmov → release), never a survivor that needs
    # an allocator-pool register, so no `auxScratch` is reserved here.
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
      # a module-level float global / tvar read: load it into a SIMD register
      # (the emitter resolves the global address and emits a movss/movsd).
      if dest.kind != InFReg: dest = b.reserveFTmp(b.tc.exprSlot(n))
    b.ra.locs[pos] = dest
    inc n
  of TagLit:
    case n.exprKind
    of AddC, SubC, MulC, DivC:
      allocFBin(b, n, dest); return              # records locs[pos] itself
    of NegC:
      # float negation `(neg (f N) x)`: the operand lands in the result xmm, the
      # emitter flips its sign in place. Mirrors the float-unary shape used by a64.
      if dest.kind != InFReg:
        dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
      let resDest = dest
      n.into:
        skip n                                   # result float type
        var fd = resDest
        allocFValue(b, n, fd)                    # operand → the accumulator xmm
        while n.hasMore: skip n
      b.ra.locs[pos] = resDest
      return
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
          var fd = resDest                       # float→float precision convert (emFcvt)
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
    of InfC, NeginfC, NanC:                      # +inf / -inf / NaN — a leaf value node
      # No sub-expression to place; like a FloatLit, just reserve the result xmm.
      # The emitter loads the IEEE-754 bit pattern through a transient staging GPR.
      if dest.kind != InFReg:
        dest = b.reserveFTmp(if dest.typ.kind == AFloat: dest.typ else: floatSlot(64))
      b.ra.locs[pos] = dest
      skip n
      return
    else:
      raiseAssert "arkham: float expression not supported: " & $n.exprKind
  else:
    raiseAssert "arkham: float value kind not supported: " & $n.kind

type
  ParamPlace* = object
    ## Where one SysV-AMD64 parameter / argument is passed. Produced by
    ## `classifyParamsX64`; consumed by the signature, prologue, callee stack-loads,
    ## the call allocator and the call-site marshaller so they cannot disagree.
    ord*: int            ## param NAME ordinal (decoupled from the register index)
    onStack*: bool       ## passed on the stack rather than in registers
    isFloat*: bool       ## a float (xmm if register-passed)
    isAgg*: bool         ## an aggregate (AMem slot)
    byRef*: bool         ## aggregate larger than the threshold → a single pointer
    words*: int          ## eightbytes occupied (1 for a scalar / pointer / float)
    gpFirst*: int        ## register-passed int/aggregate: first GPR index
                         ## (registers = intArgRegs[gpFirst ..< gpFirst+words])
    fpIndex*: int        ## register-passed float: xmm index
    byteOff*: int        ## stack-passed: byte offset within the stack-argument area

proc classifyParamsX64*(md: MachineDesc; slots: openArray[AsmSlot];
                        retByRef: bool): seq[ParamPlace] =
  ## THE one SysV-AMD64 parameter classifier (chibicc's `assign_lvar_offsets`):
  ## walk params/args left to right, assigning each to argument registers or the
  ## stack. An aggregate that does not fit in the REMAINING integer arg registers
  ## goes ENTIRELY on the stack and consumes NO register (so a later, smaller arg
  ## can still take a free one). `retByRef` reserves rdi/ord 0 for the hidden
  ## >16B-return pointer. Stack offsets round each slot up to 8 bytes, matching
  ## nifasm's `alignedSize` (so the callee's load offset == the caller's `(arg)`).
  result = @[]
  var gp = if retByRef: 1 else: 0
  var fp = 0
  var stackOff = 0
  var ord = if retByRef: 1 else: 0
  for s in slots:
    var pp = ParamPlace(ord: ord)
    if s.kind == AMem:
      pp.isAgg = true
      pp.byRef = s.size > md.aggrByRefThreshold
      pp.words = if pp.byRef: 1 else: (s.size + 7) div 8
      if gp + pp.words <= md.intArgRegs.len:
        pp.gpFirst = gp; gp += pp.words
      else:
        pp.onStack = true; pp.byteOff = stackOff
        stackOff += (if pp.byRef: 8 else: (s.size + 7) and not 7)
    elif s.kind == AFloat:
      pp.isFloat = true; pp.words = 1
      if fp < md.floatArgRegs.len:
        pp.fpIndex = fp; inc fp
      else:
        pp.onStack = true; pp.byteOff = stackOff; stackOff += 8
    else:                               # scalar int / pointer
      pp.words = 1
      if gp < md.intArgRegs.len:
        pp.gpFirst = gp; inc gp
      else:
        pp.onStack = true; pp.byteOff = stackOff; stackOff += 8
    result.add pp
    inc ord

proc allocCall(b: var Builder; n: var Cursor; dest: var Location; hiddenPtr = false) =
  ## A call: each scalar/pointer argument is allocated into its ABI integer argument
  ## register (rdi…r9), each float argument into its SIMD argument register (xmm0–7);
  ## the result lands in the return register (rax, or xmm0 for a float result) or a
  ## destination-passed home. More arguments than the ABI registers hold fail loudly.
  let pos = b.posOf(n)
  var intIdx = if hiddenPtr: 1 else: 0         # rdi reserved for a >16B aggregate result ptr
  var fIdx = 0
  n.into:
    # An INDIRECT call's target is a fn-ptr EXPRESSION (vtable/method-table load), or a
    # Symbol naming a proc-typed LOCAL/param (a fn-ptr value): allocate it into a register
    # HELD across the args + the call (the emitter declares a proctype var bound to it and
    # `prepare`s through that). A direct call's proc-decl symbol is just skipped.
    let indirect = isIndirectCallTarget(b.tc, n)
    var fnptrTd: Location
    if indirect:
      fnptrTd = needsReg(ScalarSlot)
      allocValue(b, n, fnptrTd)                # fn-ptr target → a held register (advances n)
    else:
      skip n                                   # callee symbol
    while n.hasMore:
      # The argument's ABI class is just its type — one `exprSlot`, the SAME navigator
      # the emitter uses. No per-form ladder: a struct var and an `(oconstr …)`/`(aconstr …)`
      # are both `AMem` and share this branch; only *building* the value differs, and that
      # is `allocStore`'s job, not the call's.
      let argSlot = b.tc.exprSlot(n)
      if argSlot.cls == AMem:
        # An aggregate argument: a ≤threshold by-value one consumes ceil(size/8) integer
        # arg registers, a >threshold by-reference one a single pointer register — UNLESS
        # it doesn't fit in the remaining arg registers, in which case it is passed on the
        # stack (classifyParamsX64's rule). A stack-passed aggregate is marshalled through
        # `gprWords` reserved callee-saved scratch GPRs (one per eightbyte) that the
        # emitter then writes to the outgoing stack slots; reserve them HELD first so the
        # value build routes around them, stash them in aux, and DON'T advance `intIdx`.
        let argPos = b.posOf(n)
        let byRef = argSlot.size > b.md.aggrByRefThreshold
        let gprWords = if byRef: 1 else: (argSlot.size + 7) div 8
        let fits = intIdx + gprWords <= b.md.intArgRegs.len
        var dst: seq[Location] = @[]
        if not fits:
          # A stack-passed arg means this proc reserves an outgoing-argument area in its
          # frame (the fixed-frame model — nifasm's scanStackArgArea), so it needs the
          # frame `sub sp`. Flag it like a stack local.
          b.ra.hasStackVars = true
          for _ in 0 ..< gprWords: dst.add b.reserveHeldScratch("a stack aggregate-arg word")
        var addrReg = NoReg
        var hasAddr = false
        if n.kind == Symbol:
          skip n                                # no per-value allocation — emitter reads the slot
        elif n.kind == TagLit and n.exprKind in {DotC, DerefC, AtC, PatC}:
          # An aggregate LVALUE arg: the emitter marshals STRAIGHT from its address (no
          # copy temp). Reserve the address scratch (held) so it can't alias one of the
          # lvalue's embedded base/index regs (`aggrAddrInto` writes it after them).
          # `canSpill`: under genuine pressure this returns a slot (NoReg) — the address is
          # re-derivable, so the emitter re-`lea`s it into a transient (see `aggrArgAddr`).
          let addrT = b.reserveHeldScratch("an aggregate-arg address", canSpill = true)
          let rc = n
          allocLvalue2(b, n)                    # advances n past the lvalue (embedded regs)
          releaseLvalTemps(b, rc)
          b.releaseTmp(addrT)
          let (ar, _) = heldRef(addrT); addrReg = ar  # NoReg ⇒ spilled (emitter re-derives)
          hasAddr = true
        else:                                   # oconstr/aconstr: build into a synthetic aggregate temp
          b.ra.hasStackVars = true
          allocStore(b, n, namedStackLoc("", argSlot), argPos)  # advances n
        # Stash the per-arg scratch at `argPos` (the emitter reads it there): the stack
        # marshalling words FIRST, then the lvalue address LAST (`scratch[^1]`). A non-SIB
        # `(at …)`/`(pat …)` already left its stride scratch at `scratch[0]`, untouched.
        var sc: seq[Reg] = @[]
        for d in dst: sc.add d.r
        if hasAddr: sc.add addrReg              # lvalue address LAST (NoReg ⇒ spilled); see `aggrArgAddr`
        if sc.len > 0:
          if b.ra.aux.hasKey(argPos):
            for r in sc: b.ra.aux[argPos].scratch.add r
          else:
            b.ra.aux[argPos] = ExprAux(scratch: sc)
        for d in dst: b.releaseTmp(d)           # held only to keep the value build off them
        if fits: intIdx += gprWords
      elif argSlot.cls == AFloat:               # float argument → xmm{fIdx}
        if fIdx >= b.md.floatArgRegs.len:
          raiseAssert "arkham: more than 8 float call arguments (stack-passed TODO)"
        var ad = fregLoc(b.md.floatArgRegs[fIdx], floatSlot(64))
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
        # A stack-passed arg means this proc reserves an outgoing-argument area in its
        # frame, so it needs the frame `sub sp` (see the fixed-frame note above).
        b.ra.hasStackVars = true
        var ad = needsReg(ScalarSlot)
        allocValue(b, n, ad)
        b.releaseTmp(ad)
        inc intIdx
    if indirect: b.releaseTmp(fnptrTd)         # the held fn-ptr target reg, dead after the call
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

proc reserveAtScratch(b: var Builder; atPos: int; idxReg: Reg) =
  ## Reserve the GPR for nifasm's 3-operand `(at base idx scratch)` non-SIB stride form
  ## (recorded in `aux[atPos]`). The hard invariant is scratch ≠ BASE (`scratch = base +
  ## idx*stride` aliases catastrophically otherwise). It holds because the base is a live
  ## local whose register is out of the pool, so `reserveTmp` (which draws from the
  ## remaining pool and never evicts a local) can never hand out the base register. nifasm
  ## also flags a scratch==base collision at assemble time (`at_scratch_base_collision`).
  ##
  ## scratch == INDEX is permitted: x86 tolerates it (`mov scratch,idx` is a no-op, then
  ## `idx*stride`, then `base+scratch`), and under real pressure it is the ONLY option, so
  ## forbidding it would spill the scratch to memory — illegal for a stride register. The
  ## AArch64 assembler computes the stride into a reserved scratch (X16) precisely so
  ## scratch==idx stays correct there too. (`idxReg` is accepted for documentation/future
  ## tuning; the reservation itself only needs the base invariant.)
  discard idxReg
  let t = b.reserveTmp(ScalarSlot)
  if t.kind == InReg:
    b.ra.aux[atPos] = ExprAux(scratch: @[t.r])
  else: raiseAssert "arkham: out of registers for an index stride scratch"

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
      elif b.md.arch == X86 and not isStore:
        # A transient global base for a LOAD (e.g. a float field read whose result is an
        # xmm, so the GPR address can't be the result reg): the emitter sources the
        # address from emit-time STAGING (the R11 bridge), so reserve no survivor pool
        # register here — leave the position unresolved as the marker.
        b.ra.locs[pos] = dontCare
      else:
        let t = b.reserveHeldScratch("a global base address")  # survivor (held across rhs / a64)
        b.ra.locs[pos] = t
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
      var idxReg = NoReg                        # the register index (if any)
      n.into:
        allocLvalue2(b, n, globBase, isStore) # base (stack array, deref, or global)
        if n.kind in {IntLit, UIntLit}: skip n   # immediate index — folds, no scratch
        else:
          var idx = needsReg(ScalarSlot)
          allocValue(b, n, idx)             # register index → a register (folds via scale)
          if idx.kind == InReg: idxReg = idx.r
        while n.hasMore: skip n
      if atPos in b.atScratch and b.md.arch == Arm64:
        reserveAtScratch(b, atPos, idxReg)     # x64 picks it from emit-time staging instead
    of PatC:
      let patPos = b.posOf(n)
      var idxReg = NoReg
      n.into:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)                  # the pointer → a register (its home)
        if n.kind in {IntLit, UIntLit}: skip n   # immediate index
        else:
          var idx = needsReg(ScalarSlot)
          allocValue(b, n, idx)             # register index → a register (folds via scale)
          if idx.kind == InReg: idxReg = idx.r
        while n.hasMore: skip n
      if patPos in b.atScratch and b.md.arch == Arm64:
        reserveAtScratch(b, patPos, idxReg)    # x64 picks it from emit-time staging instead

    of BaseobjC:                             # `(baseobj BaseT depth lvalue)` — transparent base
      n.into:
        skip n                               # base type
        skip n                               # depth
        allocLvalue2(b, n, globBase, isStore)  # the inner lvalue (its embedded values)
        while n.hasMore: skip n
    of AconstrC, OconstrC:
      # A constructor used as an lvalue base — e.g. `[a, b][i]` (`(at (aconstr …) idx)`).
      # Materialize it into a synthetic stack temp (`aggtmp<pos>`, built by the emitter),
      # then index/field-access that temp. Allocate the constructor's element/field VALUES
      # like a store into a synthetic aggregate slot (mirrors the aggregate call-arg path).
      b.ra.hasStackVars = true
      allocStore(b, n, namedStackLoc("", b.tc.exprSlot(n)), b.posOf(n))  # advances n
    else:
      raiseAssert "arkham: computed lvalue base not supported: " & $n.exprKind
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
  of BaseobjC:                               # transparent: free the inner lvalue's temps
    var cc = c
    cc.into:
      skip cc; skip cc                       # base type, depth
      releaseLvalTemps(b, cc)                # the inner lvalue
      while cc.hasMore: skip cc
  else: discard

proc divRemOccupied(b: var Builder): bool {.inline.} =
  ## Is the div/rem register (rdx) holding a LIVE value at a div/mod? `freeVol`
  ## membership is the truth: a `DivRegOk` local homed in rdx is dead before any
  ## div (its interval excludes every div position) and already returned by
  ## flushFree, so a static-home `regOccupied` would false-positive on it. NoReg
  ## (RISC) never joins `freeVol`, hence the explicit guard.
  b.md.divRemReg != NoReg and b.md.divRemReg notin b.freeVol

proc allocDivMod(b: var Builder; n: var Cursor; dest: var Location) =
  ## x86 `idiv`/`div`: dividend → rax, divisor → a register (no immediate form),
  ## quotient → rax, remainder → rdx (clobbered; `allocParams` keeps live locals
  ## out of it — see `regOccupied`). The result register (rax quotient or rdx
  ## remainder) is moved to `dest`, or `dest` is left as that register when the
  ## caller pinned none.
  let pos = b.posOf(n)
  let wantRem = n.exprKind == ModC
  if b.divRemOccupied():
    raiseAssert "arkham: div/mod while the remainder register holds a live local"
  var aDest = regLoc(b.md.intRetReg, ScalarSlot)    # dividend → rax (fixed)
  var dDest = needsReg(ScalarSlot)                   # divisor → some register
  n.into:
    skip n                                           # result type
    allocValue(b, n, aDest)
    allocValue(b, n, dDest)
    while n.hasMore: skip n
  # The divisor must not alias rax (the dividend) or rdx (clobbered). `reserveTmp`
  # never hands those out, and a param homed there was relocated (`regOccupied`).
  if dDest.kind == InReg and (dDest.r == b.md.intRetReg or dDest.r == b.md.divRemReg):
    raiseAssert "arkham: div/mod divisor aliases rax/rdx"
  b.releaseTmp(dDest)
  let resReg = if wantRem: b.md.divRemReg else: b.md.intRetReg
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(resReg, ScalarSlot, isTemp = true)
  else: discard                                      # fixed dest: emitter moves result → it
  b.ra.locs[pos] = dest

proc allocDivModRisc(b: var Builder; n: var Cursor; dest: var Location) =
  ## RISC `div`/`mod` (`md.divRemReg == NoReg`, e.g. AArch64 sdiv/udiv): no fixed
  ## register, no immediate/memory divisor form. Both operands take registers; the
  ## result reuses the dividend's register when it is a dead temp (a 2-operand
  ## `sdiv dest, dest, divisor`), else a fresh temp. `mod` is lowered by the emitter
  ## to `dest - (dest div b)*b` using a staging-bridge quotient temp — no extra
  ## allocator scratch is reserved.
  let pos = b.posOf(n)
  var lDest = needsReg(ScalarSlot)            # dividend → a register (becomes dest)
  var rDest = needsReg(ScalarSlot)            # divisor → a register (no imm/mem form)
  n.into:
    skip n                                    # result type
    allocValue(b, n, lDest)
    allocValue(b, n, rDest)
    while n.hasMore: skip n
  b.releaseTmp(rDest)
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: dest = lDest
    else: dest = b.reserveTmp(ScalarSlot)
  else: discard
  if not sameReg(dest, lDest): b.releaseTmp(lDest)
  b.ra.locs[pos] = dest

proc forceRegDest(b: var Builder; dest: var Location) =
  ## Ensure a value's `dest` is a register: a `NeedsReg`/`RegOrImm` constraint becomes
  ## a fresh temp typed as requested (keeping the precise type, so a store to a typed
  ## slot type-checks); `Undef`/`dontCare` a generic scalar temp; a fixed reg is kept.
  ## When the pool is exhausted `reserveTmp` falls back to a spilled `etmp` slot the
  ## emitter produces into via a staging register (`produceIntoMem2`).
  case dest.kind
  of NeedsReg, RegOrImm: dest = b.reserveTmp(dest.typ)
  of Undef: dest = b.reserveTmp(ScalarSlot)
  else: discard

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
    else: b.resolveDest(dest, natural)               # a function-local: its home (frozen)
    inc n
  of StrLit:
    b.forceRegDest(dest); inc n                # string literal → a reg (lea of rodata)
  of TagLit:
    case n.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      allocBin(b, n, dest); return           # records locs[pos] itself
    of DivC, ModC:
      if b.md.divRemReg == NoReg:
        allocDivModRisc(b, n, dest); return  # RISC: plain ALU, no fixed regs
      allocDivMod(b, n, dest); return        # records locs[pos] itself
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC:
      # A comparison / and/or/not used as a 0/1 VALUE: the result needs a register;
      # the operands are placed by allocCond. The backend gates this to alias-safe
      # positions (var-init / ret), so a fixed `dest` (a fresh home / rax) never
      # aliases an operand — the emitter writes it directly.
      case dest.kind
      of Undef, NeedsReg, RegOrImm: dest = b.reserveTmp(ScalarSlot)
      else: discard
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
        if n.exprKind != ConvC:                # `(cast int float)` = bit reinterpret, not cvttsd2si
          raiseAssert "arkham: float bit-reinterpret cast not supported yet"
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
        # The "compute straight into dest" identity assumes the emitter's
        # re-representation leaves the register's bits alone. That holds for a
        # same-width relabel, but a NARROWING int↔int cast emits a destructive
        # `shl/shr` (extendTo) on the result register. When the operand is a
        # register-homed symbol, its home is FROZEN for the whole scope and the
        # variable outlives the cast — so narrowing in place corrupts it (e.g.
        # `cast[uint32](q)` inside `bigDivisor * cast[uint32](q)` zeroed q's own
        # upper 32 bits). Detect a register-homed symbol under a strict narrowing
        # and force a fresh temp so the emitter copies-then-narrows, leaving the
        # source intact.
        block:
          var innerC = n; inc innerC           # tag → target type
          let tgtSize = slotOf(b.prog[], innerC).size
          skip innerC                          # target type → inner expr
          if innerC.kind == Symbol:
            let sh = b.symLoc(symName(innerC))
            # A register OR stack home is frozen for the symbol's scope: aliasing the
            # cast result to it and narrowing in place (a reg `shl/shr`, or a
            # load-narrow-STORE-BACK for a stack slot) corrupts the live variable.
            if sh.kind in {InReg, NamedStack} and tgtSize < sh.typ.size:
              b.forceRegDest(dest)             # do not alias the frozen source home
        n.into:
          skip n                               # target type
          allocValue(b, n, dest)               # inner → dest (fresh temp or identity)
          while n.hasMore: skip n
        b.ra.locs[pos] = dest
      return
    of DerefC, DotC, AtC, PatC:
      # An addressing expr in VALUE position → load `[addr]` into a register. The
      # embedded base/index values are placed by allocLvalue2; the load lands in a
      # fresh temp (or the dest-passed home / arg reg). A `NeedsReg`/`RegOrImm` dest
      # carries the precise type (e.g. `(aptr u8)`) — `forceRegDest` keeps it so a
      # store to a typed slot type-checks (a generic i64 temp would mismatch).
      b.forceRegDest(dest)
      let resDest = dest
      let lvCopy = n                          # for releaseLvalTemps after the load
      # A destination-passed FIXED register (an arg reg / a register-homed local's home) is
      # NOT a temp taken out of the pool, so the index/base allocation below could `reserveTmp`
      # it — landing this load's result on the same register as one of its own indices
      # (different types ⇒ a `(mov res[ptr], (mem (at … res[i64])))` that nifasm rejects).
      # Seal it across the address allocation so the index temp picks another.
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
        # The address IS p's register; reflect that in `dest` so a wrapping consumer
        # (e.g. `(cast (ptr T) (addr (deref p)))`) reads the resolved location and not
        # the still-`NeedsReg` constraint it passed in (every allocValue path leaves
        # `dest` = the resolved location on return — this identity path must too).
        dest = identityHome
        b.ra.locs[pos] = identityHome
        return
      b.forceRegDest(dest)
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
    of FalseC:
      b.resolveDest(dest, immLoc(0, ScalarSlot)); skip n
    of NilC:
      # nil is a 0 of the `(nil)` type (a null pointer), NOT an `(i 64)` 0: carry the
      # nil slot so the emitter binds the register / emits the immediate as `(nil)`.
      b.resolveDest(dest, immLoc(0, b.tc.exprSlot(n))); skip n
    of OvfC:
      # The overflow flag — always false (arkham uses wrapping arithmetic, see the
      # `keepovf`/emitValue2 handling), so the `(if (ovf) …)` handlers are dead.
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

proc allocSingleUse(b: var Builder; n: var Cursor) =
  ## Allocate a single-use value (a constructor field/element, a store rhs) into a
  ## transient register — a SIMD temp for a float — and release it right away: the
  ## emitter stores it and the next value reuses the register.
  if b.isFloatVal(n):
    var d = dontCare
    allocFValue(b, n, d)
    b.releaseFTmp(d)
  else:
    var d = needsReg(ScalarSlot)
    allocValue(b, n, d)
    b.releaseTmp(d)

proc allocConstr(b: var Builder; n: var Cursor) =
  ## `(oconstr T (kv field value)+)` — allocate each field's value into a register
  ## (a SIMD temp for a float field) the emitter then stores to the field. Each is
  ## single-use (store + free), so the temps recycle. Every field — scalar, float, or
  ## a nested aggregate (`oconstr`/`aconstr`) — routes through the ONE `allocStore` as a
  ## `Field` destination, exactly like any other store; `allocStore`'s `Field` case
  ## dispatches on the field's slot (a nested aggregate recurses into `allocConstr`).
  ## Advances `n` past the oconstr.
  n.into:
    skip n                                     # the constructed type
    while n.hasMore:
      if n.kind == TagLit and n.exprKind == OconstrC:
        allocConstr(b, n)                       # nested inherited-base sub-object
      elif n.substructureKind == KvU:
        n.into:                                # (kv field value [depth])
          skip n                               # field name
          if n.hasMore:
            allocStore(b, n, fieldLoc("", "", "", b.tc.exprSlot(n)), b.posOf(n))
          while n.hasMore: skip n              # optional inherited-depth INTLIT
      else:                                    # leading bare inherited-base value (vtable ptr)
        allocStore(b, n, fieldLoc("", "", "", b.tc.exprSlot(n)), b.posOf(n))

proc allocAconstr(b: var Builder; n: var Cursor) =
  ## `(aconstr ArrayT e0 e1 …)` — allocate each (bare) element value into a register
  ## (a SIMD temp for a float element); each is single-use (store + free), so the temps
  ## recycle. A nested AGGREGATE element (an inner array/object constructor) routes
  ## through `allocStore` as an aggregate `Field` destination, exactly like a nested
  ## `oconstr` field (`allocConstr`) — so it recurses. Advances `n` past the aconstr.
  ## The array twin of `allocConstr`.
  n.into:
    skip n                                     # the array type
    while n.hasMore:
      if b.tc.exprSlot(n).kind == AMem:        # aggregate element: build into the element address
        allocStore(b, n, fieldLoc("", "", "", b.tc.exprSlot(n)), b.posOf(n))
      else:
        b.allocSingleUse(n)

proc isAggrCopySrc(c: Cursor): bool =
  ## An aggregate-valued source that is COPIED (not produced): a symbol or a memory lvalue.
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc allocAggrCopy(b: var Builder; n: var Cursor; dstIsMem: bool; dstCur: Cursor;
                   auxPos: int) =
  ## Allocator twin of `genAggrCopyStore`: the ONE whole-aggregate copy reservation for
  ## every (destination × source) form. Reserve the two held address scratches the
  ## emitter's `aggrAddrLoc`/`aggrAddrInto` consume — `[dstAddr, srcAddr]` — then place
  ## each lvalue's embedded base/index regs transiently (a `Mem` destination and a
  ## memory-lvalue source; freed after their address is leas'd, so they never co-live). A
  ## bare symbol needs none. The dst/src stride-scratch aux live at THEIR own positions
  ## (≠ auxPos), so they never collide with these. Advances `n` past the source.
  ##
  ## The per-field copy register is NOT reserved from the pool: it is the always-available
  ## staging bridge (R11 / x14–x15), picked at emit (`genAggrCopyStore`) — live only during
  ## the final copy loop, after both addresses are already in `dstAddr`/`srcAddr`, so the
  ## bridge is free then. This keeps the whole-aggregate copy's pool need at TWO GPRs (not
  ## three), so it still fits when a proc with several register-homed live params crosses an
  ## aggregate copy (e.g. a setter `[]=(addr deepLvalue, key, Obj(…, field: aggrCopy))`).
  ##
  ## Register-pressure ordering: `srcAddr` is reserved only from the source onward, so it is
  ## not held while the DST lvalue address is computed — keeping the peak simultaneous hold
  ## at `dstAddr + base/index/stride` then `dstAddr + srcAddr`, never both lvalues' temps.
  # x64 picks the two address scratches from emit-time staging (`genAggrCopyStore`), like
  # the stride scratch — so they never starve when locals fill the pool. a64 (large volatile
  # pool, only two staging bridges) keeps reserving them from the pool.
  let useAux = b.md.arch == Arm64
  var dstAddr, srcAddr = dontCare
  if useAux: dstAddr = b.reserveTmp(ScalarSlot)
  if dstIsMem:
    var dc = dstCur
    allocLvalue2(b, dc, dontCare, isStore = true)
    releaseLvalTemps(b, dstCur)
    b.ra.hasStackVars = true
  if useAux: srcAddr = b.reserveTmp(ScalarSlot)
  if n.kind == TagLit and n.exprKind in {DotC, DerefC, AtC, PatC}:
    let rc = n
    allocLvalue2(b, n)                                   # advances n past the lvalue
    releaseLvalTemps(b, rc)
  else:
    skip n                                               # a bare symbol
  if useAux:
    b.releaseTmp(srcAddr); b.releaseTmp(dstAddr)
    if dstAddr.kind != InReg or srcAddr.kind != InReg:
      raiseAssert "arkham: out of registers for an aggregate copy"
    b.ra.aux[auxPos] = ExprAux(scratch: @[dstAddr.r, srcAddr.r])

proc allocStore(b: var Builder; n: var Cursor; dst: Location; auxPos: int) =
  ## Allocator twin of the emitter's `genStore2`. A whole-aggregate COPY (symbol/lvalue
  ## source into an aggregate destination) goes through the ONE `allocAggrCopy`;
  ## constructors/calls/baseobj PRODUCE into the destination; a scalar/float computes into
  ## its register home or a temp. Scratch temps land in `aux[auxPos]`.
  block:                                                 # the ONE whole-aggregate copy path
    let dstAggr =
      case dst.kind
      of NamedStack, Glob: dst.typ.kind == AMem
      of Mem: b.tc.exprSlot(dst.cur).kind == AMem
      of Undef: b.tc.exprSlot(n).kind == AMem            # module-level global: classify by rhs
      else: false                                        # Field recurses via its own branch
    if dstAggr and isAggrCopySrc(n):
      allocAggrCopy(b, n, dst.kind == Mem,
                    (if dst.kind == Mem: dst.cur else: default(Cursor)), auxPos)
      return
  if n.kind == TagLit and n.exprKind in {ConvC, CastC} and
     b.tc.exprSlot(n).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (e.g. `Path(s)`
    # for `Path = distinct string`) is a no-op at the byte level — allocate/store the
    # underlying operand into the same destination. (A scalar conv has a non-AMem slot
    # and is handled by the scalar paths below.)
    n.into:
      skip n                                             # the target type
      allocStore(b, n, dst, auxPos)                      # the operand → same dest (advances n)
      while n.hasMore: skip n
    return
  if dst.kind == NamedStack and dst.typ.kind == AMem:    # aggregate destination
    if n.kind == TagLit and n.exprKind == OconstrC:
      allocConstr(b, n)                                  # object: place each field value
    elif n.kind == TagLit and n.exprKind == AconstrC:
      allocAconstr(b, n)                                 # array: place each element value
    elif n.kind == TagLit and n.exprKind == CallC:       # call-returned aggregate
      var d = dontCare
      allocCall(b, n, d, hiddenPtr = dst.typ.size > b.md.aggrByRefThreshold)
    elif n.kind == TagLit and n.exprKind == BaseobjC:    # object→base slice
      # Build the (derived) inner value into a temp like a nested aggregate (recurse);
      # the base-prefix copy scratch is picked at emit (a sealed staging reg), no aux.
      n.into:
        skip n                                           # base type
        skip n                                           # depth
        allocStore(b, n, namedStackLoc("", b.tc.exprSlot(n)), b.posOf(n))
        while n.hasMore: skip n
    else:
      raiseAssert "arkham: aggregate store rhs not supported: " & $n.exprKind &
        " in proc " & gArkhamCurProc & " (dst.size=" & $dst.typ.size & ")"
  elif dst.kind == Undef:                                # module-level global / threadvar
    # The emitter resolves the destination to a `Glob`/`Tvar` with a precise slot; the
    # allocator only needs the right scratch. The destination type is unknown here, so
    # classify by the RHS: an AGGREGATE store builds/copies through the global's address
    # (the emitter's `Glob`+`AMem` branch), a scalar/float stores `[&g] ← reg/xmm`.
    if b.tc.exprSlot(n).kind == AMem:                    # aggregate global store
      let rhsSlot = b.tc.exprSlot(n)
      if n.kind == TagLit and n.exprKind == CallC and
         rhsSlot.size > b.md.aggrByRefThreshold:
        # >16B call result: &g goes straight into rdi (the hidden result ptr) — no
        # address temp; allocCall accounts for the hidden pointer argument.
        var d = dontCare
        allocCall(b, n, d, hiddenPtr = true)
      else:
        let addrT = b.reserveHeldScratch("an aggregate global &g", canSpill = true)  # &g held across rhs
        if n.kind == TagLit and n.exprKind == OconstrC:
          allocConstr(b, n)                              # build field-by-field through &g
        elif n.kind == TagLit and n.exprKind == AconstrC:
          allocAconstr(b, n)
        elif n.kind == TagLit and n.exprKind == CallC:   # ≤16B result in rax:rdx
          var d = dontCare
          allocCall(b, n, d, hiddenPtr = false)
        else:
          raiseAssert "arkham: aggregate global store rhs not supported: " & $n.exprKind
        b.releaseTmp(addrT)
        let (sreg, sslot) = heldRef(addrT)              # reg, or a spill-slot name (totality backstop)
        b.ra.aux[auxPos] = ExprAux(scratch: @[sreg], heldSlot: @[sslot])
    else:
      # No survivor scratch for the &g address: the emitter re-`lea`s it into a transient
      # staging register right before the store (no call between the lea and the store),
      # so it never needs to survive the rhs in a callee-saved register.
      b.allocSingleUse(n)
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
  elif dst.kind == Field:                                # a field within an aggregate
    # Mirror the emitter's `genFieldStore2`: a nested aggregate field builds into a
    # synthetic temp (the emitter copies it through the field address); a scalar/float
    # field's value goes into a single-use temp the emitter stores to the field operand.
    if dst.typ.kind == AMem:
      b.ra.hasStackVars = true
      allocStore(b, n, namedStackLoc("", dst.typ), b.posOf(n))
    else:
      b.allocSingleUse(n)
  elif dst.kind == Mem:                                  # store through a complex lvalue (dot/deref/at)
    # Place the lvalue's embedded base/index regs, then the rhs. An AGGREGATE constructor
    # builds field-by-field into the address (placed like a slot store); a FLOAT rhs goes
    # to an xmm; an integer rhs to a register. A global aggregate base needs an address
    # scratch, reserved before the lhs and held across the rhs, then recorded in `aux`.
    let lhsCur = dst.cur
    let hasGlob = lvalueGlobalBase(b, lhsCur)
    var scratch = dontCare
    if hasGlob: scratch = b.reserveHeldScratch("a global address")
    var lc = lhsCur
    allocLvalue2(b, lc, scratch, isStore = true)         # lhs operands (on a copy)
    if n.kind == TagLit and n.exprKind == OconstrC:
      allocConstr(b, n)                                  # build through the lvalue address
    elif n.kind == TagLit and n.exprKind == AconstrC:
      allocAconstr(b, n)                                 # build array through the lvalue address
    else:
      b.allocSingleUse(n)
    releaseLvalTemps(b, lhsCur)                          # free the held index/pointer + `(at)` scratch
    if hasGlob:
      b.releaseTmp(scratch)
      b.ra.aux[auxPos] = ExprAux(scratch: @[scratch.r])
  else:
    raiseAssert "arkham: store destination not supported: " & $dst.kind

proc allocVarDecl(b: var Builder; n: var Cursor) =
  n.into:
    let pos = b.posOf(n)
    assert n.kind == SymbolDef
    let name = symName(n); inc n
    skip n                                   # pragmas
    let typeIsOmitted = n.kind == DotToken
    var slot = slotOf(b.prog[], n); skip n  # type (resolves named types)
    var valCur = n                           # remember the initializer (for allocExprs)
    let hasValue = n.hasMore and n.kind != DotToken   # `.` = explicitly uninitialized
    if n.hasMore: skip n                      # value (analysed in pass 1)
    # Shoggoth's SROA can emit a var with an OMITTED type (`.`) — e.g.
    # `(var :sroa.. . . (addr x))`, a pointer. An empty type otherwise classifies
    # as `AMem size 0` and misroutes to the aggregate-store path; infer the slot
    # from the initializer instead (an lvalue `addr` → a precise `(ptr T)`). The
    # emitter follows the recorded Location, so this one fix keeps both in sync.
    if typeIsOmitted and hasValue:
      slot = b.tc.exprSlot(valCur)
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
      # ── same-width cast/copy home inheritance ──────────────────────────────────
      # `let c2 = cast[T](c1)` / `let c2 = c1`, where the relabel is SAME-WIDTH and `c1`
      # is a single-def register-homed local whose LAST touch is this initializer: `c2`
      # occupies `c1`'s register directly. The store then collapses to a zero-machine-code
      # `(rebind)` (the emitter renames the register from c1 to c2 — see `genVarDecl2`),
      # eliminating a reg→reg `mov`. Gated to x86 (the emitter's same-reg skip is wired
      # there) and to a source whose register CLASS already covers c2's lifetime: a
      # callee-saved home always does; a volatile home only for a call-free c2 (`AllRegs`).
      var inheritSrc = ""                       # non-empty ⇒ this var inherits `inheritSrc`'s reg
      if not copyInheritDisabled and b.md.arch == X86 and hasValue and
         AddrTaken notin props and slot.inRegClass and not slot.isFloat and
         not b.an.vars.getOrDefault(name).declInLoop:
        let srcSym = copyCastSrcSym(valCur)
        if srcSym.kind == Symbol:
          let srcName = symName(srcSym)
          let sh = b.symLoc(srcName)
          let svi = b.an.vars.getOrDefault(srcName)
          if sh.kind == InReg and not sh.typ.isFloat and sh.typ.size == slot.size and
             svi.defs == 1 and svi.lastUsePos <= b.posOf(srcSym) and
             not svi.declInLoop and
             (sh.r in b.md.intCalleeSavedSet or AllRegs in props):
            inheritSrc = srcName
      # NOTE: identity-cast value ALIASING (the c1-LIVE case) was reverted — it produced
      # nifasm-rejected `cmp (ptr object) (ptr object)` on the allocator (a value use of an
      # aliased cast lost its precise pointer type). Only the c1-DEAD transfer below remains.
      var aliasSrc = ""
      discard aliasSrc                      # aliasing reverted (see note); always empty now
      # Optimistically give the local a register; demote a colder one to memory if the
      # register class is full (`trySteal`, the only undo). A spilled / address-taken
      # scalar lives in a nifasm-managed `(s)` slot addressed by name.
      var loc =
        if aliasSrc.len > 0: dontCare                                 # c2 is a pure view of c1
        elif inheritSrc.len > 0: regLoc(b.symLoc(inheritSrc).r, slot) # c2 takes c1's reg
        else: b.allocStorage(slot, props)
      if inheritSrc.len > 0:
        # Transfer the register's free obligation from the (now-dead) source to this var:
        # drop the source's pending early-free and mark it freed so `closeScope` skips it;
        # THIS var's own `pendingFree`/`scopeVars` entries below then solely own the reg.
        var k = 0
        while k < b.pendingFree.len:
          if b.pendingFree[k].name == inheritSrc: b.pendingFree.del k
          else: inc k
        b.freedSyms.incl inheritSrc
      # Caller-save rescue: a cross-call scalar that `allocStorage` could not home in a
      # callee-saved reg (the pool is full) would otherwise SPILL — reloaded at every use.
      # Instead give it an atomic-safe caller-save volatile (R8/R9): register-resident
      # between calls, and the emitter brackets each crossed call with a `(scope …)`
      # save/restore. Restricted to the atomic-safe pool so a var that also crosses an
      # INLINED atomic (which clobbers rdi/rsi/rdx but not r8/r9) stays sound without a
      # per-atomic-crossing analysis. Tried BEFORE `trySteal` so it evicts nothing.
      let vi0 = b.an.vars.getOrDefault(name)
      if not callerSaveDisabled and
         loc.kind == OnStack and b.md.arch in {X86, Arm64} and AddrTaken notin props and
         slot.inRegClass and not slot.isFloat and
         AllRegs notin props and R89Ok notin props and
         hasValue and vi0.defs == 1 and vi0.freeAfter != high(int) and
         not initHasCall(valCur) and
         vi0.weight > 2 * callsCrossed(b, vi0):
        # COST MODEL: a caller-save home pays 2 memory ops (save+restore) per crossed
        # call but makes every USE a register read instead of a spill reload. So it only
        # wins when the (loop-weighted) use count exceeds twice the calls crossed —
        # otherwise a plain spill (reload-per-use) is cheaper. Without this gate a var
        # that crosses several calls but is used once REGRESSED the alloc module (+8 mem).
        # SOUNDNESS: give a caller-save home ONLY to a var whose value is provably valid
        # at EVERY call it is bound across — else the emitter's save reads a register that
        # holds no defined value yet (nifasm rejects reading a clobbered reg, and there is
        # nothing valid to save). Guarantee: single-def (`defs == 1`), non-whole-proc
        # (`freeAfter != high`), and its initialiser contains NO call (`not initHasCall`).
        # Then the var is defined synchronously at its decl, before any subsequent call,
        # and never rewritten — valid at every crossed call. This excludes: a `result` var
        # (declared empty → assigned late), a `var x = f(…)` (defined BY the call it would
        # be saved around — dead before it; the call may be nested in an `(elif…)`), and
        # any var rewritten past a control-flow merge.
        let r = b.takeReg(b.freeVol, b.md.atomicSafeTempRegs)
        if r != NoReg:
          loc = regLoc(r, slot)
          b.ra.callerSaveHomes[name] = vi0.freeAfter
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
      if aliasSrc.len > 0:
        b.ra.symPos[name] = b.ra.symPos[aliasSrc]   # c2 resolves to c1's LIVE home (no own reg)
        b.ra.aliasedCasts.incl name                 # emitter emits neither decl nor store for it
      else:
        b.record(pos, name, loc)
        b.scopeVars[^1].add name
      # Register the coarse early-free, unless declared in a loop (a later loop-body
      # decl could reuse the reg across the back-edge). Stored by name so the flush
      # frees the var's *current* reg (it may have been evicted to the stack).
      let vi = b.an.vars.getOrDefault(name)
      if loc.kind == InReg and not vi.declInLoop:
        b.pendingFree.add (pos: vi.freeAfter, name: name)
      if b.allocExprs and hasValue and inheritSrc.len == 0 and aliasSrc.len == 0:
        var vc = valCur
        allocStore(b, vc, loc, pos)            # the one general store path
      # (an inherited/aliased var needs no store: its value is already in c1's register)

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
          elif b.retAggr:
            # An aggregate return marshals OUT (≤16B → structToRegs; >16B → copy through
            # the hidden result pointer) — the inverse of a store-into-destination, so it
            # stays here rather than in `allocStore`. No scratch is reserved here: the
            # marshalling runs at the `ret`, crosses no call, and draws its transient
            # registers from the emit-time staging pool (see `copyStructThroughPtr2`).
            if n.kind == Symbol:                         # a named local aggregate
              skip n
            else:
              # An inline aggregate VALUE returned by value (`(ret (oconstr …))` /
              # memory lvalue): allocate its field-value temps like a store into a
              # synthetic aggregate slot.
              b.ra.hasStackVars = true
              allocStore(b, n, namedStackLoc("", b.retAggrSlot), retPos)
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
  of KeepovfS:
    # `(keepovf (op type a b) dest)` — overflow-checked arithmetic store. arkham
    # uses wrapping arithmetic (the overflow flag is ignored), so allocate it like
    # an `asgn` whose rhs is the op and whose lhs is `dest` (the SECOND child).
    if b.allocExprs:
      let kPos = b.posOf(n)
      n.into:
        var opCur = n                          # the (op …) value
        skip n                                 # advance to dest
        if n.kind == Symbol:
          let dst = b.symLoc(symName(n)); skip n
          allocStore(b, opCur, dst, kPos)
        else:
          let lhsCur = n; skip n
          allocStore(b, opCur, memLoc(lhsCur, ScalarSlot), kPos)
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
  # On x86-64 a >16B by-ref aggregate return takes the first integer arg register
  # (rdi) as the hidden result pointer, so real params start at rsi — skip GPR 0
  # to stay in lockstep with the signature / emitParamMoves / emitStackParamLoads.
  # AArch64 passes the hidden pointer in x8 (off the arg-register file), so no skip.
  var intIdx = if b.retIndirect and b.md.arch == X86: 1 else: 0
  var fidx = 0
  # Scalar cross-call register params (1..6) that took a callee-saved home, in
  # allocation order. A stack-passed param (7th+) MUST have a register home — it
  # is loaded from the incoming stack slot in the prologue before rsp is lowered,
  # when a local slot is not yet addressable — so when callee-saved registers run
  # out it evicts one of these to its stack slot and reuses the register. A
  # register param spills cleanly (its value arrives in an arg register that
  # emitParamMoves stores into the slot once the frame is set up).
  var spillableRegParams: seq[tuple[pos: int; name: string; r: Reg; effSlot: AsmSlot]] = @[]
  params.into:
    while params.hasMore:
      params.into:
        let pos = b.posOf(params)
        assert params.kind == SymbolDef
        let name = symName(params); inc params
        skip params                          # pragmas
        let slot = slotOf(b.prog[], params); skip params  # type (resolves named)
        # Classify an aggregate param (matching `classifyParamsX64` / `emitParamMoves`):
        #  * ≤16B by-value that FITS the remaining arg registers → REGISTER-passed
        #    (`aggrSmall`): a `(s)` stack home filled from its GPR word(s), consuming
        #    `aggrWords` arg registers.
        #  * ≤16B by-value that does NOT fit → STACK-passed (`aggrStack`): the bytes arrive
        #    in the incoming stack-arg area (copied into the `(s)` home by
        #    `emitStackParamLoadsX64`), consuming NO arg register — the SysV skip rule, so a
        #    later smaller param may still take a free GPR. Same home shape as `aggrSmall`.
        #  * >16B → by-REFERENCE (`aggrByRef`): a pointer (in a reg, or on the stack if none
        #    is free), like a scalar.
        var aggrSmall = false
        var aggrStack = false
        var aggrByRef = false
        var aggrWords = 0
        if slot.kind == AMem:
          let sz = slot.size                  # filled by slotOf (named or inline)
          if sz >= 1 and sz <= b.md.aggrByRefThreshold:
            aggrWords = (sz + 7) div 8
            if intIdx + aggrWords <= b.md.intArgRegs.len: aggrSmall = true   # register-passed
            else: aggrStack = true                                          # stack-passed (0 GPRs)
          else:
            aggrByRef = true
        if aggrSmall or aggrStack:
          # (No early `continue`/`return`: that skips the `into` epilogue.) Both home the
          # aggregate in its own `(s)` slot; only a register-passed one consumes GPRs.
          b.record(pos, name, namedStackLoc(name, slot))
          b.ra.hasStackVars = true
          if aggrSmall: intIdx += aggrWords
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
                            (arg == b.md.shiftCountReg and b.an.clobbersShiftReg) or
                            # AArch64: x0 is BOTH arg0 and the return register. A param homed
                            # in x0 that the result expression reads off the projection spine
                            # is clobbered by a sibling sub-result landing in the accumulator
                            # before that read — give it a callee-saved home. (No-op on x86-64,
                            # where intRetReg=rax is never an arg register.)
                            (arg == b.md.intRetReg and b.an.arg0RetConflict)
            # An ArgResident param crosses no call (its consuming call is the first in
            # the proc and its last use) → it may STAY in its incoming arg register even
            # though the proc has calls: no prologue save, and same-position passing makes
            # the marshal a self-move. Excludes by-ref aggregates (their pointer must
            # survive repeated field loads) and fixed-role-clobbered arg regs (rdx/rcx).
            # Both arches: keep an ArgResident param in its incoming arg register. On x64
            # the emitter binds the param's arg reg to `regLocal` and must `kill` that dead
            # binding after the first call (`flushArgResidentParams`); on a64 a param in an
            # arg reg (x0–x7) is read RAW (no `regLocal` binding — see a64 `emReg`), so there
            # is no lingering binding to flush.
            let stayInArg = ArgResident in props and not aggrByRef and not clobbered
            if AddrTaken in props and not aggrByRef:
              loc = b.spill(effSlot)           # address taken → must be on the stack
            elif (hasCall or aggrByRef or clobbered) and not stayInArg:
              # Live across a call (the incoming arg reg is volatile), or a by-ref
              # pointer that must survive repeated field loads in the body: give
              # it a callee-saved home so the prologue can `mov home, argReg`.
              let r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
              if r != NoReg:
                b.ra.usedCallee.incl r
                loc = regLoc(r, effSlot)
                if not aggrByRef:
                  # Evictable in favour of a later stack param (a by-ref aggregate's
                  # slot would need its aggregate type, not the pointer — skip those).
                  spillableRegParams.add (pos: pos, name: name, r: r, effSlot: effSlot)
              elif aggrByRef and spillableRegParams.len > 0:
                # No free callee-saved register for the by-ref POINTER. A spilled
                # pointer (OnStack) has no consistent representation across the
                # prologue / body field-access / call sites, so instead evict a colder
                # scalar register param to its stack slot (emitParamMoves fills it from
                # the incoming arg register) and reuse its register — the pointer stays
                # InReg, which every consumer already handles.
                let victim = spillableRegParams.pop()
                b.record(victim.pos, victim.name,
                         namedStackLoc(victim.name, victim.effSlot))
                b.ra.hasStackVars = true
                loc = regLoc(victim.r, effSlot)   # victim.r already in usedCallee
              else:
                loc = b.spill(effSlot)
            else:
              loc = regLoc(arg, effSlot)       # leaf proc: stay in the arg reg
              b.freeVol.excl arg               # persistent home → not lendable to a call-free local
            inc intIdx
          else:
            # The 9th integer/pointer parameter onward arrives on the caller's
            # stack (AAPCS64). arkham gives it a callee-saved register home that
            # the prologue loads from the incoming arg slot before SP is lowered
            # for locals, so it survives the whole proc. Address-taken or
            # out-of-register stack params aren't supported yet.
            if AddrTaken in props:
              raiseAssert "arkham v1: address-taken >8th parameter"
            var r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
            if r == NoReg and spillableRegParams.len > 0:
              # No free callee-saved register: evict an earlier scalar register
              # param to its stack slot and reuse its register for this stack param.
              let victim = spillableRegParams.pop()
              b.record(victim.pos, victim.name,
                       namedStackLoc(victim.name, victim.effSlot))
              b.ra.hasStackVars = true
              r = victim.r                        # already in usedCallee
            if r == NoReg:
              # Totality: no callee-saved reg and nothing colder to evict — home this
              # stack param in its OWN `(s)` slot. The prologue loads it from the incoming
              # arg area into the slot through a staging bridge (`emitStackParamLoadsX64`),
              # so no register is held; correct by construction, never a hard fail.
              loc = namedStackLoc(name, effSlot)
              b.ra.hasStackVars = true
            else:
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
  # Make the scalar register-homed params visible to `coldestVictim`: a proc whose
  # params all take callee-saved homes (every reg param crosses a call) would
  # otherwise leave `reserveHeldScratch`/`trySteal` with no register-resident LOCAL
  # to evict — the callee-saved pool is full but nothing in `scopeVars` holds it.
  # These params demote cleanly (`demoteToStack` → NamedStack scalar slot, which
  # `emitParamMoves` fills from the incoming arg register). by-ref aggregate params
  # are EXCLUDED (not in `spillableRegParams`): demoting their pointer to a
  # NamedStack slot would make `emitParamMoves` take its aggregate-by-value branch.
  # A param already popped+demoted for a >8th stack param is now NamedStack, so
  # `coldestVictim` skips it (it tests `vloc.kind == InReg`) — harmless to list.
  for p in spillableRegParams:
    b.scopeVars[^1].add p.name

proc seedPools(b: var Builder) =
  ## Fill the four register pools to their full target capacity. As locals are
  ## declared and params placed, their registers leave the pool; temps draw from
  ## what remains.
  b.freeVol = {}; b.freeCallee = {}; b.freeVolF = {}; b.freeCalleeF = {}
  for r in b.md.intTempRegs: b.freeVol.incl r
  # Call-free locals may also draw from `intLocalTempRegs` (the arg registers with
  # no fixed instruction role). `reserveTmp` still filters on `intTempRegs` so these
  # never serve as emitter transient scratch; only `allocStorage`'s `AllRegs` fall-
  # back (which filters on `intLocalTempRegs`) can hand them to a local. A leaf param
  # that persistently occupies one is removed from this pool in `allocParams`.
  for r in b.md.intLocalTempRegs: b.freeVol.incl r
  # The fixed-role registers (rdx = div/rem, rcx = shift count) also join `freeVol`
  # so a `DivRegOk`/`ShiftRegOk` local can be homed there. They are handed out ONLY
  # via those props' candidate list in `allocStorage` (never in `intLocalTempRegs`
  # nor `intTempRegs`), so no ordinary local/temp draws them; and the interval
  # analysis guarantees their fixed role never overlaps such a local (asserted by
  # `divRemOccupied`/`regOccupied` at the div/shift sites). `NoReg` on RISC (a64).
  if b.md.divRemReg != NoReg: b.freeVol.incl b.md.divRemReg
  if b.md.shiftCountReg != NoReg: b.freeVol.incl b.md.shiftCountReg
  # Caller-save home candidates (x64 R8/R9 — already here via `intLocalTempRegs`; a64 x6/x7
  # — arg regs NOT otherwise in a pool). Drawn ONLY by the caller-save rescue, which filters
  # on `atomicSafeTempRegs`, so no ordinary local/temp/AllRegs allocation reaches them.
  for r in b.md.atomicSafeTempRegs: b.freeVol.incl r
  for r in b.md.intCalleeSaved: b.freeCallee.incl r
  for f in b.md.floatTempRegs: b.freeVolF.incl f
  for f in b.md.floatCalleeSaved: b.freeCalleeF.incl f

proc allocateProc*(buf: var TokenBuf; procDecl: Cursor; an: ProcAnalysis;
                   prog: var Program; md: MachineDesc; tc: TypeCtx;
                   presealed: set[Reg] = {}; allocExprs = false;
                   atScratch: HashSet[int] = initHashSet[int]()): RegAlloc =
  ## Allocate storage for the params, locals and (when `allocExprs`) the expression
  ## temporaries of `procDecl` in a SINGLE walk over the tree. The model (codegen.c +
  ## optimistic locals):
  ##   * Expression temporaries and addressing scratch draw from the volatile/callee-
  ##     saved registers the pool still has free, and spill to their OWN `(s)` slot when
  ##     none is free. A temp NEVER takes a live local's register — codegen.c shows ~2
  ##     registers suffice for all computation, so a temp is always servable.
  ##   * LOCALS are assigned to registers OPTIMISTICALLY as they are declared. The only
  ##     undo of a register assignment is local→memory: when we find we have too many
  ##     locals for a register (a hotter local arrives, or a survivor scratch needs a
  ##     callee-saved reg), `trySteal`/`reserveHeldScratch` demote a colder local with
  ##     `demoteToStack` — a single-point `locs[symPos[name]]` rewrite that every use
  ##     sees (the emitter late-binds local reads via `locationOfSym`). Sound across all
  ##     control flow because the demoted local lives in memory everywhere.
  ## Because temps and locals never contend for the same register, there is no temp-vs-
  ## local collision class to reason about — the simple, effective solution.
  ##
  ## `md` describes the target register file + ABI. `presealed` registers are
  ## reserved for the whole proc. `prog` is `var` because resolving a cross-module
  ## type may load a module. `atScratch` lists the `(at …)` positions needing a
  ## non-SIB stride scratch GPR.
  var b = Builder(buf: addr buf, an: addr an, prog: addr prog, tc: tc, md: md,
                  atScratch: atScratch)
  b.allocExprs = allocExprs
  # `locs` only ever holds positions inside THIS proc's contiguous subtree span, so
  # size it to that span (base = the proc's first token position) rather than the whole
  # module. Sizing to `buf.len` re-allocated+zeroed a module-sized array for every proc
  # — O(procs × moduleTokens), ~91% of arkham's runtime on big modules. See `LocSpan`.
  let procStart = cursorToPosition(buf, procDecl)
  var procEndCur = procDecl; skip procEndCur
  let procEnd = cursorToPosition(buf, procEndCur)
  b.ra = RegAlloc(locs: initLocSpan(procStart, procEnd - procStart),
                  aux: initTable[int, ExprAux](),
                  symPos: initTable[string, int]())
  b.ra.sealed = presealed
  b.scopeVars = @[]; b.pendingFree = @[]; b.freedSyms = initHashSet[string]()
  b.tmpSpills = 0
  b.seedPools()
  var n = procDecl
  assert n.stmtKind == ProcS
  b.openScope()
  block:
    var nm = procDecl; inc nm                # step past the (proc tag → name
    if nm.kind in {Symbol, SymbolDef}: gArkhamCurProc = symName(nm)
  n.into:
    inc n                                    # name → params slot
    # Classify the RESULT before allocating params: a >16B by-ref aggregate return
    # is passed via a hidden result pointer that (on x86-64) occupies the first
    # integer argument register and shifts every real param down one. `allocParams`
    # must count argument registers from the same base as the signature
    # (`emitParamsAndResult`) and `emitParamMoves`, so `b.retIndirect` has to be
    # known first (peeked from a copy — `allocParams` advances `n` past params).
    block:
      var rt = n
      skip rt                                # params → return type
      if rt.kind == TagLit:                  # a float return goes to xmm0 (value-core)
        let rtSlot = slotOf(prog, rt)
        if rtSlot.isFloat: b.retFloatBits = rtSlot.size * 8
      elif rt.kind == Symbol:                # named-type return; aggregate → regs / hidden ptr
        let rtSlot = slotOf(prog, rt)
        if rtSlot.kind == AMem:
          b.retAggr = true
          b.retAggrSlot = rtSlot
          if rtSlot.size > md.aggrByRefThreshold: b.retIndirect = true
    # If any parameter is stack-passed, the emitter needs a callee-saved register for the
    # incoming-args base (`stackArgBaseReg`) that survives the frame `sub`s. It is picked
    # at emit time from the callee-saved regs the body did NOT use — so reserve one here,
    # up front, or a body that uses every callee-saved register would leave none and the
    # base would be `NoReg` (a `(mem (<noreg>) …)` stack-param load). We only need to
    # GUARANTEE one stays free; which one is the emitter's choice (any unused callee-saved).
    block:
      var pc = n                             # at the params slot
      var slots: seq[AsmSlot] = @[]
      if pc.kind == TagLit:
        pc.into:
          while pc.hasMore:
            pc.into:
              inc pc; skip pc                # name, pragmas
              slots.add slotOf(b.prog[], pc)
              while pc.hasMore: skip pc
      var anyStack = false
      for pl in classifyParamsX64(b.md, slots, b.retIndirect):
        if pl.onStack: (anyStack = true; break)
      b.ra.hasStackParams = anyStack           # single source of truth for the emitter
      if anyStack:
        # Reserve a callee-saved reg the body cannot use, for the emitter's
        # `stackArgBaseReg`. Skip any SEALED reg (e.g. `RBX` presealed for a >16B-return
        # hidden pointer) — excluding that one reserves nothing extra, leaving the base
        # `NoReg` under full callee-saved pressure.
        for r in b.md.intCalleeSaved:
          if r in b.freeCallee and r notin b.ra.sealed: (b.freeCallee.excl r; break)
    allocParams(b, n, an.hasCall)            # advances n past params → return type
    skip n                                    # return type
    skip n                                    # pragmas
    walk(b, n)                                # body
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
