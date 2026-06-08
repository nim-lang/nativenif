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
import nifcore, nifcdecl, slots, machinedesc, analyser, programs

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
    sealed*: set[Reg]                 ## registers pinned to an in-flight ABI
                                      ## call (args being marshalled, x8 result,
                                      ## values live through the call): never
                                      ## allocate to or steal from these

  Builder = object
    ra: RegAlloc
    buf: ptr TokenBuf
    an: ptr ProcAnalysis
    prog: ptr Program                 ## program (for cross-module type resolution / sizing)
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
    # Floats in a call-free region use caller-saved scratch (v16–v31); those
    # live across a call use callee-saved (v8–v15), saved in the prologue.
    # Address-taken floats fall back to a (codegen-unsupported) slot.
    if AddrTaken in props: return b.spill(slot)
    var f: FReg
    if AllRegs in props:
      f = b.takeFReg(b.freeVolF, b.md.floatTempRegs)
      if f == NoFReg: f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    else:
      f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    if f == NoFReg: return b.spill(slot)
    if f in b.md.floatCalleeSavedSet: b.ra.usedCalleeF.incl f
    return fregLoc(f, slot)
  if AddrTaken in props or not slot.inRegClass:
    return b.spill(slot)
  var r: Reg
  if AllRegs in props:
    # A call-free local could legally live in a caller-saved volatile, but the
    # integer temp pool (r10/r11 on x86-64) IS codegen's scratch pool for
    # addressing/staging — handing those two to long-lived locals starves scratch
    # and forces per-use eviction (reload on every reference). So prefer a
    # callee-saved home (one prologue push/pop, then resident) and only fall back
    # to a volatile temp when the callee-saved pool is exhausted.
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
    if r == NoReg: r = b.takeReg(b.freeVol, b.md.intTempRegs)
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
      let nm = "etmp" & $b.tmpSpills & ".0"; inc b.tmpSpills
      b.ra.hasStackVars = true
      b.ra.exprUnsupported = true              # v1 pure emitter has no spill path yet
      return namedStackLoc(nm, slot)
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
      let nm = "ftmp" & $b.tmpSpills & ".0"; inc b.tmpSpills
      b.ra.hasStackVars = true
      b.ra.exprUnsupported = true
      return namedStackLoc(nm, slot)
    if f in b.md.floatCalleeSavedSet: b.ra.usedCalleeF.incl f
  result = fregLoc(f, slot, isTemp = true)

proc releaseFTmp(b: var Builder; loc: Location) {.inline.} =
  if loc.kind == InFReg and loc.isTemp: b.giveBackF loc.f

proc symLoc(b: var Builder; name: string): Location

proc isFloatVal(b: var Builder; n: Cursor): bool =
  ## Best-effort: does value `n` have float type? (For routing a conversion's operand
  ## to the SIMD vs GPR side without a full `getType`.) A float literal; a symbol homed
  ## in an xmm (a float local/param); a float-typed arith / conversion (its type child
  ## is `(f N)`); a wrapper over such. A float global (home Undef) is not detected — but
  ## those are gated out anyway.
  case n.kind
  of FloatLit: true
  of Symbol:
    let h = b.symLoc(symName(n))
    h.kind == InFReg or (h.kind == NamedStack and h.typ.isFloat)
  of TagLit:
    case n.exprKind
    of AddC, SubC, MulC, DivC, NegC, ConvC, CastC:
      var t = n; inc t                          # tag → type child (result/target type)
      slotOf(b.prog[], t).kind == AFloat
    of SufC, ParC:
      var t = n; inc t
      b.isFloatVal(t)
    else: false
  else: false

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

proc regOccupied(b: var Builder; reg: Reg): bool

proc allocBin(b: var Builder; n: var Cursor; dest: var Location) =
  ## Binary-arith node: left into a register, right wherever it lies (a memory
  ## operand stays folded — `foldB`); the result honours `dest` (destination-
  ## passing) or reuses the left register in place (x86 destructive 2-operand RMW).
  let pos = b.posOf(n)
  let ek = n.exprKind                        # the op (a variable shift needs the count in cl)
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
  # the op (`dest := lhs; dest op= rhs`). Safe when dest == lhs (in-place RMW). Bail
  # to the legacy reactive path otherwise. (Var-decl inits never hit this — a fresh
  # home can't alias a still-live operand — so only `s = a - s`-shaped asgns do.)
  if dest.kind == InReg and rDest.kind == InReg and dest.r == rDest.r and
     not sameReg(dest, lDest):
    b.ra.exprUnsupported = true
  b.releaseTmp(rDest)
  if not sameReg(dest, lDest): b.releaseTmp(lDest)
  b.ra.aux[pos] = ExprAux(foldB: rDest.kind in {NamedStack, Mem})
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

proc allocCall(b: var Builder; n: var Cursor; dest: var Location) =
  ## A call: each argument is allocated into its ABI argument register, the result
  ## into the return register (or a destination-passed home). The v1 emitter only
  ## handles ≤(#arg regs) scalar args with no value live across the call — the
  ## backend's `procModeled2`/`callModeled2` gate enforces the rest (syscall vs
  ## direct, no nested calls / aggregates / floats), so here we just place.
  let pos = b.posOf(n)
  var argIdx = 0
  n.into:
    skip n                                     # callee symbol
    while n.hasMore:
      if argIdx < b.md.intArgRegs.len:
        var ad = regLoc(b.md.intArgRegs[argIdx], ScalarSlot)
        allocValue(b, n, ad)
      else:
        b.ra.exprUnsupported = true            # 7th+ arg (stack) — v1 emitter gap
        var ad = dontCare
        allocValue(b, n, ad)
      inc argIdx
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(b.md.intRetReg, ScalarSlot, isTemp = true)   # result in rax
  else: discard                                # fixed dest: emitter moves rax → it
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
      var lDest = needsReg(ScalarSlot)
      var rDest = dontCare
      n.into:
        allocValue(b, n, lDest)                # left → a register
        allocValue(b, n, rDest)                # right → reg / imm (folded)
        while n.hasMore: skip n
      b.releaseTmp(rDest)
      b.releaseTmp(lDest)
  else:
    var d = needsReg(ScalarSlot)
    allocValue(b, n, d)
    b.releaseTmp(d)

proc allocLvalue2(b: var Builder; n: var Cursor) =
  ## Walk an lvalue subtree (the target of a load / store / `addr`), allocating its
  ## embedded VALUES — a `deref`'s pointer, a computed index — into registers (their
  ## homes, recorded in `locs`); stack-var / field names and immediate indices need
  ## no allocation. Advances `n` past the whole lvalue. v1 slice: stack-var field
  ## access (`dot`) and pointer `deref` of a symbol; `at`/`pat`/computed bases bail.
  case n.kind
  of Symbol:
    inc n                                    # a stack-var / pointer base name — no alloc
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        allocLvalue2(b, n)                   # base (a stack var, or a `deref`)
        while n.hasMore: skip n              # field name (+ any extras)
    of DerefC:
      n.into:
        var d = needsReg(ScalarSlot)
        allocValue(b, n, d)                  # the pointer → a register (its home)
        while n.hasMore: skip n
    of AtC:
      n.into:
        allocLvalue2(b, n)                   # base (a stack array, or a deref)
        if n.kind in {IntLit, UIntLit}: skip n   # immediate index — folds, no scratch
        else:
          var idx = needsReg(ScalarSlot)
          allocValue(b, n, idx)             # register index → a register (folds via scale)
        while n.hasMore: skip n
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
      allocLvalue2(b, n)                      # embedded base/index regs; advances past
      b.ra.locs[pos] = resDest
      return
    of AddrC:
      # `(addr lvalue)` → a pointer in a register. Place any embedded base/index
      # values of the lvalue; the result address lands in dest (typed precisely).
      case dest.kind
      of NeedsReg, RegOrImm: dest = b.reserveTmp(dest.typ)
      of Undef: dest = b.reserveTmp(ScalarSlot)
      else: discard
      if dest.kind != InReg: b.ra.exprUnsupported = true
      let resDest = dest
      n.into:
        allocLvalue2(b, n)
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
        if slot.isFloat:
          # A float local: a register home (xmm) receives the initializer directly
          # (destination-passing); a spilled / address-taken float `(s)` slot gets it
          # computed into a SIMD temp the emitter then stores.
          if loc.kind == InFReg:
            var d = loc
            allocFValue(b, valCur, d)
          else:
            var d = b.reserveFTmp(slot)
            allocFValue(b, valCur, d)
            b.releaseFTmp(d)
        elif loc.kind == InReg:
          # Destination-passing: allocate the initializer to compute directly into the
          # local's register home. The home is already taken from the pool (above), so
          # the initializer's transient temps draw from what remains — matching execution.
          var d = loc
          allocValue(b, valCur, d)
        else:
          # A stack-homed scalar (spilled / address-taken): compute the initializer into
          # a register, then the emitter stores it to the `(s)` slot (genVarDecl2).
          var d = needsReg(slot)
          allocValue(b, valCur, d)
          b.releaseTmp(d)

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
        if n.hasMore and n.kind != DotToken:
          if b.retFloatBits > 0:
            var d = fregLoc(b.md.floatArgRegs[0], floatSlot(b.retFloatBits))  # → xmm0
            allocFValue(b, n, d)
          else:
            var d = regLoc(b.md.intRetReg, ScalarSlot)   # return value → the ABI ret reg
            allocValue(b, n, d)
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
          let home = b.symLoc(symName(n))
          skip n                               # lhs (not a value-read)
          if home.kind == InFReg:
            # A register-homed FLOAT local: the rhs computes directly into its xmm.
            var dest = home
            allocFValue(b, n, dest)
          elif home.kind == NamedStack and home.typ.isFloat:
            # A spilled float local: compute the rhs into a SIMD temp; the emitter
            # stores it to the `(s) (f N)` slot.
            var d = b.reserveFTmp(home.typ)
            allocFValue(b, n, d)
            b.releaseFTmp(d)
          elif home.kind == InReg:
            # A register-homed local: destination-passing — the rhs computes directly
            # into the lhs home.
            var dest = home
            allocValue(b, n, dest)
          elif home.kind == NamedStack and home.typ.kind != AMem:
            # A stack-homed scalar local: compute the rhs into a register; the emitter
            # stores it to the `(s)` slot. (An aggregate `(s)` slot needs a struct
            # copy, not a scalar mov — bail to legacy.)
            var d = needsReg(home.typ)
            allocValue(b, n, d)
            b.releaseTmp(d)
          elif home.kind == Undef:
            # A module-level global / tvar store: the rhs into a register, plus an
            # address scratch temp (a Glob is `&g` then `mov [addr], v`; a Tvar resolves
            # to FS:[off] and ignores it). The address temp is recorded in `aux` for the
            # emitter, held across the rhs so it can't be reused.
            let addrT = b.reserveTmp(ScalarSlot)
            var d = needsReg(ScalarSlot)
            allocValue(b, n, d)
            b.releaseTmp(d)
            b.releaseTmp(addrT)
            if addrT.kind == InReg: b.ra.aux[asgnPos] = ExprAux(scratch: @[addrT.r])
            else: b.ra.exprUnsupported = true
          else:
            b.ra.exprUnsupported = true        # aggregate `(s)` store: legacy
            var t = dontCare
            allocValue(b, n, t)
        else:
          # A memory store through a complex lvalue (dot/deref): place the lvalue's
          # embedded base/index regs, then the rhs into a REGISTER (nifasm has no
          # immediate-to-memory `mov`, so an immediate is loaded into a temp first).
          allocLvalue2(b, n)                   # lhs address operands; advances past lhs
          var rdest = needsReg(ScalarSlot)
          allocValue(b, n, rdest)              # rhs value → a register
          b.releaseTmp(rdest)
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
            if AddrTaken in props and not aggrByRef:
              loc = b.spill(effSlot)           # address taken → must be on the stack
            elif hasCall or aggrByRef:
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
                   prog: var Program; md: MachineDesc;
                   presealed: set[Reg] = {}; allocExprs = false): RegAlloc =
  ## Allocate storage for the params and locals of `procDecl`. `md` describes the
  ## target register file + ABI. `presealed` registers are reserved for the whole
  ## proc (never allocated/stolen). `prog` is taken by `var` because resolving a
  ## cross-module type may load a module. `allocExprs` (value-core rewrite) also
  ## assigns `locs[pos]` to expressions — off by default so the legacy reactive
  ## emitter sees the unchanged symbol-only `locs`.
  var b = Builder(buf: addr buf, an: addr an, prog: addr prog, md: md,
                  allocExprs: allocExprs)
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
