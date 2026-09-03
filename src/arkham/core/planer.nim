#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 2: THE PLAN — where every value in a proc body belongs.
##
## The unit this module deals in is a POSITION, not a variable. `locs` maps a
## token position (`cursorToPosition`) to the `Location` the value produced there
## belongs in; `planned` is the whole read side, `recordValue` the whole write
## side, and neither mentions a name. A local's name is an ALIAS for the position
## of its declaration (`symPos`), which is why `homeOfSym`/`locationOfSym` are a
## convenience layer over `planned` rather than a parallel mechanism, and why
## undoing a home (a steal, `demoteToStack`) is a single-point rewrite that every
## use sees.
##
## That shape is the point, because the module does not yet plan everything.
## `planStmt` walks statements and plans what they DECLARE — parameters (ABI
## pre-coloring) and locals (scope-based). Expression positions are left `Undef`,
## and the emitter picks their temps itself as it walks (`takeTmp`/`pickStaging`,
## threading `dest: var Location`).
##
## PHASE A and PHASE B. Those two halves are named, so which one a call site belongs
## to is visible without reading the body:
##
##   phase A (here)              `getSym(name, …)`   `freeSym(name)`
##   phase B (the backends)      `getExpr(pos, …)`   `freeExpr(pos)`
##
## Same register pools, different key — and the key IS the phase, since a declaration
## has a name and an expression has only a position. The dependency runs ONE WAY:
## phase B reads homes phase A settled, and can never perturb them. That is what keeps
## the classic instruction-selection-vs-register-allocation ordering hazard out of the
## design rather than merely managed. `getSym` may be undone (`demoteToStack`, a steal)
## and so releases by NAME, reading the home current at release time; nothing can undo
## a `getExpr`, so `freeExpr` is strict. Anything phase B needs that WOULD perturb
## homes has to be hoisted ahead of phase A as a demand — a count or a flag, which
## commutes — never as a placement; `stackArgBaseReg`'s callee-saved reservation in
## `allocateProc` and the `presealed` set are the two existing examples.
##
## Phase B lives in codegen_x64/codegen_arm today, next to the pool it draws from
## (`takeHeld`), and it already has a home of its own there: `emitLvalWalk` is a pure
## pick-and-record walk with no emission in it. Moving it here means a `planValue`
## twin to `planStmt` that recurses into the value positions this walk skips, calling
## `recordValue`. Nothing downstream has to change to allow it: the storage is already
## sized to the proc's whole token span, and both sides of the API already speak
## positions.
##
## One thing this module deliberately does NOT answer: whether a value whose home
## is a stack slot is ALSO still in a register. That is a property of the emission
## walk, not of the plan — which register a value passes through is phase B's
## choice — so it lives in `RegBind`'s `RegMapping` and reaches the read side as a
## third answer to `locationOfSym`, next to `callerSaveActive` and `segs`. What
## the plan contributes is the one whole-proc fact the map cannot derive:
## `aliasable`, the locals a store through a pointer could write.
##
## `planned(pos) == Undef` means the planner has NO answer there and the emitter
## decides for itself. Keep that permanent. It is what lets this module stay
## deliberately incomplete — any expression whose planning turns out hairy simply
## stays `Undef` — so every position phase B takes over is a strict improvement and
## never a new obligation. Losing that escape valve is how the emitter grew a second
## register allocator inside itself once before (`borrowEmergency`, removed in
## `a5b8fd1`): two authorities over registers, and every bugfix patching the seam.
##
## There is no Sethi–Ullman numbering — registers are handed out in the natural
## traversal order.
##
## Strategy for the locals it does plan (after `analyser`):
##  * address-taken / aggregate / float (v1)        → stack slot
##  * confined to a call-free scope (`AllRegs`)      → a volatile temp register
##  * otherwise (may be live across a call)          → a callee-saved register
##  * out of registers                               → stack slot
## A register is returned to its pool when its scope closes (sibling scopes
## reuse it); the union of callee-saved registers ever used drives the
## prologue/epilogue.

import std / [tables, sets, assertions, os, strutils]

let copyInheritDisabled = existsEnv("ARKHAM_NO_COPYINHERIT")
  ## measurement toggle: `ARKHAM_NO_COPYINHERIT=1` disables same-width cast/copy home
  ## inheritance (`allocVarDecl`), so the eliminated reg→reg moves can be A/B compared.
import nifcore, nifcdecl, asmslots, machinedesc, analyser, programs, typenav
import abi
export abi         # CallPlan / planCall / ParamPlace: the one ABI classifier the
                   # allocator and both emitters consume (see abi.nim)

var gArkhamCurProc* = ""   # debug: the proc arkham is currently allocating (for asserts)

type
  ExprAux* = object
    ## Per-expression-position scratch memo (kept in `Plan.aux`, sparse).
    ## Written by the a64 fused lvalue walk (`emitLvalWalk`) for the `(at base
    ## idx scratch)` non-scale stride register; read back by `emLvalAddr2` and
    ## the lvalue release helpers.
    scratch*: seq[Reg]                ## extra GPRs reserved for this op (a
                                      ## non-pow2 stride temp, an address scratch…)

  LocSeg* = object
    ## One stretch of a local's live range and where its value is over that
    ## stretch. The allocator produces none of these yet — a local has one home
    ## for its whole range — but `locationOfSym` is already asked position-wise,
    ## so producing them is an addition rather than a rewrite of every consumer.
    fromPos*: int
    loc*: Location

  LocSpan = object
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

  Plan* = object
    locs: LocSpan                     ## indexed by cursorToPosition. Currently filled
                                      ## for symbol defs; the rewrite fills it for EVERY
                                      ## value-producing position (its result location).
    aux*: Table[int, ExprAux]         ## pos → per-op selection aux (see `ExprAux`)
    segs*: Table[string, seq[LocSeg]] ## name → where its value lives, per stretch of its
                                      ## range, sorted by `fromPos`. EMPTY today: one home
                                      ## per local, so `locationOfSym` falls through to
                                      ## `symPos`/`locs` below and answers the same
                                      ## everywhere. The split-range allocator fills this.
    symPos*: Table[string, int]       ## local/param name → its def position. This IS the
                                      ## local→cursor-pos mapping: every local read resolves
                                      ## through `locs[symPos[name]]` (the emitter late-binds via
                                      ## `locationOfSym`), so undoing a local's register is a
                                      ## single-point rewrite that every use sees — no scattered
                                      ## snapshots to reconcile.
    usedCallee*: set[Reg]             ## callee-saved GPRs to save in prologue
    usedCalleeF*: set[FReg]           ## callee-saved SIMD regs (v8–v15) to save in prologue
    hasStackVars*: bool               ## proc has nifasm-managed `(s)` aggregate vars
    hasStackParams*: bool             ## proc receives ≥1 parameter on the stack — the
                                      ## allocator reserved a callee-saved reg for the
                                      ## emitter's `stackArgBaseReg` (single source of
                                      ## truth; the emitter must NOT re-classify)
    aliasable*: HashSet[string]       ## locals whose ADDRESS is taken. They are the ones
                                      ## a store through a pointer — or a callee handed
                                      ## that pointer — can write behind the emitter's
                                      ## back, so no store-forwarding mirror may ever be
                                      ## kept for them (`RegMapping` in regbind.nim). Every
                                      ## OTHER memory-homed local is alias-immune by
                                      ## definition, which is what makes the mirror map's
                                      ## invalidation a matter of registers and stores
                                      ## rather than of a points-to analysis.
    aliasedCasts*: HashSet[string]    ## identity-cast value aliases (`let c2 = cast[T](c1)`,
                                      ## c1 LIVE): `c2` has NO home of its own — its `symPos`
                                      ## points at `c1`'s decl, so it resolves to `c1`'s live
                                      ## register. The emitter emits neither a decl nor a store
                                      ## for these (uses auto-cast via the deref handler).
    spillTemps*: seq[tuple[name: string; typ: AsmSlot; isFloat: bool]]
                                      ## The `(s)` slots the PROLOGUE declares, queued
                                      ## because they are decided before or apart from
                                      ## the point their `(var …)` may stand: a
                                      ## caller-saved home's `csave` cell, and the wide
                                      ## `etmp` of a 32-bit target. See `addSpillTemp`.
                                      ## The value core's own totality slots
                                      ## (`etmp`/`eftmp`/`held`, minted at register
                                      ## exhaustion) are NOT here — `declSpillSlot`
                                      ## declares each where it is minted.
    sealed*: set[Reg]                 ## registers pinned to an in-flight ABI
                                      ## call (args being marshalled, x8 result,
                                      ## values live through the call): never
                                      ## allocate to or steal from these
    callerSaveHomes*: Table[string, int]
                                      ## name → `freeAfter` for each local given a CALLER-SAVED
                                      ## home: a value that crosses a call but lives in a
                                      ## volatile register, with the emitter bracketing every
                                      ## crossed call with a save/restore. The third option
                                      ## between "callee-saved" and "memory" — see
                                      ## `callerSaveRescue` for why it is sound in an argument
                                      ## register and `design.md` for the partition it respects.
    callerSaveActive*: Table[string, Location]
                                      ## installed by the emitter for the duration of ONE call's
                                      ## marshalling: while a caller-saved value sits in its save
                                      ## slot, every read of it must come FROM that slot, because
                                      ## marshalling is about to overwrite the register. This is
                                      ## the rule that removes the parallel-copy hazard.
    divRegClobbered*: bool            ## body contains a div/mod (rdx) / a variable shift (rcx).
    shiftRegClobbered*: bool          ## Copied from the analyser so the EMITTER can decide whether
                                      ## the fixed-role volatiles are usable as expression temps —
                                      ## `pickTempReg` has no `ProcAnalysis` of its own.
    homeRegs*: set[Reg]               ## cache: every GPR some `symPos` entry is homed in.
    homeFRegs*: set[FReg]             ## Homes are immutable once emission starts, but the
    homesDirty*: bool                 ## pre-pass mutates them (record/demote/alias) — each
                                      ## mutation sets `homesDirty`; `regHoldsHome` rebuilds
                                      ## lazily. Without this cache every register-freeness
                                      ## query scanned ALL of `symPos`, turning emission
                                      ## quadratic in proc size (30s+ on inliner-fattened
                                      ## procs).

  Builder = object
    plan: Plan
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
    inheritedHomes: HashSet[string]   ## locals that took over a dead source local's register
                                      ## (`allocVarDecl`'s copy/cast home inheritance). Their
                                      ## initializing store is NOT allocated — the value is
                                      ## already in the register — so their home must STAY
                                      ## `InReg` or the emitter would emit a store whose rhs
                                      ## has no recorded location. Hence: never a steal victim.
    retFloatBits: int                 ## value-core rewrite: 0 = the proc returns int/void;
                                      ## 32/64 = a float return (the value goes to xmm0)
    retIndirect: bool                 ## the proc returns a >16B aggregate via a hidden
                                      ## result pointer (rdi in, parked in a callee-saved reg)
    retAggr: bool                     ## the proc returns an aggregate (≤16B in regs OR
                                      ## >16B via the hidden ptr) — drives the `RetS` marshal
    retAggrSlot: AsmSlot              ## the aggregate return type's slot (AMem); used to
                                      ## allocate an inline `(ret (oconstr …))` value
    returnedVar: string               ## name of the local the proc returns via `(ret <sym>)`
                                      ## (empty if none / multiple / non-symbol return). A
                                      ## call-free such local prefers the return register as
                                      ## its home so the trailing `mov intRet, result` — and,
                                      ## when it is the only callee-saved user, the frame —
                                      ## fall away.

proc initLocSpan(base, len: int): LocSpan {.inline.} =
  ## Zero-inits `len` `Location`s (kind `Undef`, ordinal 0 — an unwritten position).
  LocSpan(base: base, data: newSeq[Location](len))

proc `[]`(s: LocSpan; pos: int): lent Location {.inline.} = s.data[pos - s.base]
proc `[]`(s: var LocSpan; pos: int): var Location {.inline.} = s.data[pos - s.base]
proc `[]=`(s: var LocSpan; pos: int; v: Location) {.inline.} = s.data[pos - s.base] = v

proc planned*(plan: Plan; pos: int): Location {.inline.} =
  ## THE plan for the value produced at token position `pos`.
  ##
  ## `Undef` means the planner has no answer there and the emitter decides for
  ## itself. Today that is EVERY expression position: `planStmt` records only
  ## declarations, so the emitter picks expression temps as it walks
  ## (`takeTmp`/`pickStaging`, threading `dest: var Location`). Filling those
  ## positions in is the extension this shape exists for — the read side, the
  ## storage (`locs`, sized to the proc's whole token span) and the write side
  ## (`recordValue`) already take a bare position and never ask for a name.
  ##
  ## Note that both emitters ALREADY ask this about EXPRESSION positions, not just
  ## about declarations: a fused lvalue walk asks for the base, index and stride
  ## registers of an `(at …)` by position, and an intrinsic asks where its operands
  ## landed. The read side is therefore already what it needs to be — it is the
  ## write side for those positions that sits in the wrong module (`getExpr`, and
  ## `planAtEmitTime` class 1).
  plan.locs[pos]

proc planAtEmitTime*(plan: var Plan; pos: int; loc: Location) {.inline.} =
  ## The raw write for an expression position, from the backends. Named rather than
  ## left as a bare table write so the worklist is one grep, and so the plan's storage
  ## can stay private.
  ##
  ## Its callers are NOT all the same kind of thing, and the difference is the whole
  ## review question for this module. Three classes:
  ##
  ##  1. a PLACEMENT — `getExpr` and `emitLvalWalk`'s global base decide where a value
  ##     will go before anything is emitted. Real phase B, in the wrong module; a
  ##     `planValue` pass subsumes exactly these.
  ##  2. a WRITE-BACK of a resolution — `prematAddrVal2` and the intrinsic operand
  ##     loops hand `emitValue2` a `NeedsReg`/`RegOrImm` and store the concrete answer
  ##     back. The decision was already made; this only records how it came out.
  ##  3. a scoped MATERIALIZATION — `reloadMemBase2`/`restoreMemBase2` lend a spilled
  ##     home to a staging register for the length of one addressing mode and put it
  ##     back. A peephole, not an allocation. It stays at emit time whatever else moves.
  ##
  ## Only (1) migrates. Confusing (3) for (1) is how the emitter grows a second
  ## register allocator, so ask which class a new call belongs to before adding one.
  plan.locs[pos] = loc

proc rebuildHomes*(plan: var Plan) =
  ## Recompute `homeRegs`/`homeFRegs` from `symPos`/`locs`. Runs at most once per
  ## pre-pass mutation (in practice: once per proc, on the first freeness query).
  plan.homeRegs = {}
  plan.homeFRegs = {}
  for pos in plan.symPos.values:
    let loc = plan.planned(pos)
    case loc.kind
    of InReg: plan.homeRegs.incl loc.r
    of InRegPair:
      plan.homeRegs.incl loc.r0
      if loc.r1 != NoReg: plan.homeRegs.incl loc.r1
    of InFReg: plan.homeFRegs.incl loc.f
    else: discard
  plan.homesDirty = false

proc posOf(b: Builder; c: Cursor): int {.inline.} =
  cursorToPosition(b.buf[], c)

proc homeOf(b: Builder; name: string): Location {.inline.} =
  ## The planner-side twin of `homeOfSym`: resolve a name to its position, then ask
  ## the plan. Not "look up a name in a name table" — the name table holds POSITIONS
  ## (`symPos`), and this is the one place inside the builder that follows the alias.
  ## `NoLoc` for a module-level symbol, which has no entry (the emitter resolves it).
  let p = b.plan.symPos.getOrDefault(name, -1)
  if p >= 0: b.plan.planned(p) else: noLoc

# ── physical register pools ────────────────────────────────────────────────

proc takeReg(b: var Builder; pool: var set[Reg]; cands: openArray[Reg]): Reg =
  ## Take the first free, non-sealed register from `cands`. A sealed register
  ## is committed to an in-flight ABI call and must never be h(re)allocated.
  for r in cands:
    if r in pool and r notin b.plan.sealed:
      excl pool, r
      return r
  result = NoReg

proc takeReg(b: var Builder; pool: var set[Reg]; cands: set[Reg]): Reg =
  ## `takeReg` over an unordered candidate set: picks the lowest free, non-sealed
  ## slot. For a candidate pool with no ABI preference order (`callerSaveHomeCandidates`)
  ## the choice among equals is arbitrary anyway.
  for r in cands:
    if r in pool and r notin b.plan.sealed:
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

proc spillTo(b: var Builder; name: string; slot: AsmSlot): Location =
  ## A value that must live in memory: its nifasm-managed `(s)` slot, addressed
  ## by its own name (nifasm computes the offset). This states the final home
  ## outright — the former `OnStack` placeholder that every caller had to convert
  ## is gone. The caller still decides `hasStackVars` (a steal may re-home the
  ## value in a register before the decision is final).
  namedStackLoc(name, slot)

proc fixedRoleOk(b: Builder; r: Reg; props: VarProps): bool {.inline.} =
  ## May a value with these props be homed in `r`?
  ##
  ## `getSym` hands out the div/rem and shift-count registers ONLY to a value
  ## whose live range is interval-proved free of the instruction that claims them
  ## (`DivRegOk` / `ShiftRegOk`) — an `idiv` destroys rdx and a variable shift's count
  ## destroys rcx, neither of which names the register as an operand the emitter could
  ## see. Every OTHER path that assigns a register has to ask the same question, and
  ## two did not: the copy-inherit transfer and `trySteal`. `AllRegs` is not the same
  ## proof — it says the range crosses no CALL — so a call-free value could inherit a
  ## register that a shift in its own range then clobbers:
  ##
  ##   (var :`desugar.3 (rcx) (u 64))   … s[i], inherited rcx from a dead ShiftRegOk local
  ##   (and `desugar.3 7)               … the shift count, computed IN PLACE on it
  ##   (shl `tmp61.0 `desugar.3)
  ##   (mov `tmp62.0 (rcx)) (shr `tmp62.0 3)   … reads the char back — now `char and 7`
  ##
  ## nifasm cannot catch that: every operand is well-typed and the register is bound.
  ## It is `parseutils.rawParseInt` under register pressure, i.e. every integer literal
  ## in every NIF file parsed as garbage.
  (r != b.md.shiftCountReg or ShiftRegOk in props) and
  (r != b.md.divRemReg or DivRegOk in props)

proc getSym(b: var Builder; name: string; slot: AsmSlot; props: VarProps): Location =
  ## PHASE A acquire: decide where one declared local/param lives, and take the
  ## register for it. Paired with `freeSym`.
  ##
  ## The phase shows in the KEY: this door is named — a declaration has a name, and
  ## the plan entry it writes gets a `symPos` alias so every later use resolves through
  ## it. That alias is what makes phase A's one undo (`demoteToStack`) a single-point
  ## rewrite. `getExpr`/`freeExpr` in the backends are the phase-B twins: same pools,
  ## keyed by POSITION, and with no undo — by the time they run, everything this door
  ## decided is final.
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
    if AddrTaken in props: return b.spillTo(name, slot)
    var f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
    if f != NoFReg:
      b.plan.usedCalleeF.incl f
      return fregLoc(f, slot)
    if slot.size == 16 and AllRegs in props:
      # A 128-bit VECTOR local — the loop vectorizer's `(f 128)` values. The
      # rule above would spill every one of them on x86-64, where the
      # callee-saved float pool is empty, and a spilled vector value has no
      # lowering at all: the SSE rows address registers, not memory. `AllRegs`
      # is precisely "never live across a call", which is the condition under
      # which a caller-saved register is safe to hand to a local — so the
      # volatile pool can be lent out here and only here. It is NOT recorded in
      # `usedCalleeF`: a caller-saved register needs no prologue save. The
      # emitter's own float scratch shrinks by one per vector local; when it
      # runs dry the vector rows fail loudly ("out of SIMD registers") rather
      # than miscompiling.
      f = b.takeFReg(b.freeVolF, b.md.floatTempRegs)
      if f != NoFReg: return fregLoc(f, slot)
    return b.spillTo(name, slot)
  if AddrTaken in props or not slot.inRegClass:
    return b.spillTo(name, slot)
  var r = NoReg
  if AllRegs in props:
    # A call-free local could legally live in a caller-saved volatile.
    if b.md.arch == X86:
      # x86-64: PREFER the volatile `intLocalTempRegs` and fall back to callee-saved.
      # A call-free local is unconstrained (any register, no prologue push/pop); taking a
      # scarce callee-saved reg for it starves the cross-call locals — which have NO other
      # option — into spills (a register-class priority inversion). Reserve callee-saved
      # for the values that can only use it.
      r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
      # The fixed-role volatiles come BEFORE the callee-saved fallback, not after
      # it. `ShiftRegOk`/`DivRegOk` are the same interval proof as `AllRegs` but
      # per register — this value's life never overlaps rcx's shift-count role /
      # rdx's div-rem role — so they are free homes, while a callee-saved register
      # costs a push and a pop in a prologue that may run millions of times. The
      # old order reached them only once the callee-saved pool was ALSO dry, which
      # for a leaf proc (where every value is `AllRegs`) meant it never reached
      # them at all: `rawLineInfo`, a leaf, pushed all six callee-saved registers
      # while rcx and rdx sat free.
      if r == NoReg and ShiftRegOk in props and b.md.shiftCountReg != NoReg:
        r = b.takeReg(b.freeVol, [b.md.shiftCountReg])
      if r == NoReg and DivRegOk in props and b.md.divRemReg != NoReg:
        r = b.takeReg(b.freeVol, [b.md.divRemReg])
      if r == NoReg: r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
    else:
      # AArch64: VOLATILES FIRST, callee-saved as the fallback — for `AllRegs` values,
      # which is the branch we are in. `AllRegs` means the live range contains no call
      # point, so a volatile is free for this value while a callee-saved register costs
      # a `stp`/`ldp` pair in a prologue that may run millions of times: `nifcore.
      # leaveScope` was ten instructions of work behind six stack accesses, and a proc
      # whose whole body is `return f(x)` saved a pair to hold `f`'s result across
      # nothing. In a LEAF the win is the whole prologue — every value there is
      # `AllRegs`, so one that fits in the volatile pool needs no callee-saved PAIR
      # saved at all (a `stp`, an `ldp`, and the `sub`/`add sp` when a frame is forced).
      # That leaf rule used to be a branch of its own; volatiles-first for every
      # `AllRegs` value subsumes it exactly.
      #
      # Only `AllRegs` values reach here; a value that DOES cross a call takes the
      # `else` below and still gets callee-saved first, so the two never compete —
      # which is what the earlier volatile-first attempt (reverted for regressing
      # rawAlloc/rawDealloc) could not say, having applied to both. Falling back keeps
      # the register count identical, so no LOCAL spills that did not spill before.
      #
      # What it does change is which pool is left over for the EMITTER's scratch: a
      # call-free local now sits in x9–x13, where `pickTempReg` looks first, instead of
      # in x19+, which it reaches only as a fallback. Under `k=3` stress that is enough
      # to turn `tests/arkham/atomic_cas_regpressure` from "one local spilled, the CAS
      # got its third operand register" into the emitter's documented out-of-registers
      # assert — a totality gap (see `arkhamStressA64Known`), never a wrong answer.
      r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
      if r == NoReg: r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
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
  else:
    # may be live across a real call → must be callee-saved (or stack)
    r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
  if r == NoReg:
    when defined(arkhamSpillDbg):
      # How many call points does this value's interval actually cross, and how
      # many uses pay for the spill? A cross-call value with FEW crossings and
      # MANY uses is what a caller-saved home (volatile reg + save/restore at
      # the crossing) would win big on — arkham has no such option today.
      let vi = b.an.vars.getOrDefault(name)
      let lo = vi.liveStart
      let hi = if vi.freeAfter == high(int): vi.lastUsePos else: vi.freeAfter
      var crossed = 0
      for p in b.an.callPositions:
        if p > lo and p <= hi: inc crossed
      stderr.writeLine "SPILL proc=" & gArkhamCurProc & " var=" & name &
        " allregs=" & $(AllRegs in props) &
        " crossed=" & $crossed & " weight=" & $vi.weight &
        " span=" & $(hi - lo) &
        " callee=" & $(5 - b.freeCallee.card) & "/5 vol=" & $b.freeVol.card & "free"
    return b.spillTo(name, slot)
  if r in b.md.intCalleeSavedSet: b.plan.usedCallee.incl r
  result = regLoc(r, slot)

proc giveBack(b: var Builder; r: Reg) {.inline.} =
  if r in b.md.intCalleeSavedSet: b.freeCallee.incl r
  elif r != NoReg: b.freeVol.incl r

proc giveBackF(b: var Builder; f: FReg) {.inline.} =
  if f in b.md.floatCalleeSavedSet: b.freeCalleeF.incl f
  elif f != NoFReg: b.freeVolF.incl f

proc freeSym(b: var Builder; name: string) =
  ## PHASE A release: return whatever registers `name` currently occupies. The
  ## counterpart of `getSym`, and it takes the NAME rather than the register on
  ## purpose — that is not a convenience, it is the correctness rule.
  ##
  ## Between the `getSym` and here, a steal may have moved `name` to the stack
  ## (`demoteToStack`); the register it was given now belongs to the thief, which will
  ## release it when its OWN range ends. So the release has to read the home that is
  ## current AT RELEASE TIME, and a demoted var must free nothing. Taking a `Reg`
  ## argument would let a caller pass the stale one and silently double-free it into
  ## the pool. Both callers (`flushFree`, `closeScope`) had this ladder open-coded.
  let loc = b.homeOf(name)
  case loc.kind
  of InReg: b.giveBack loc.r
  of InRegPair:
    b.giveBack loc.r0
    if loc.r1 != NoReg: b.giveBack loc.r1
  of InFReg: b.giveBackF loc.f
  else: discard

proc weightOf(b: Builder; name: string): int {.inline.} =
  b.an.vars.getOrDefault(name).weight

proc rangeLen(b: Builder; name: string): int {.inline.} =
  ## Length (in token positions) of a local's live interval — its register-occupancy
  ## span. Used ONLY as a tie-breaker among equal-`weight` steal candidates. `high(int)`
  ## for a param (`freeAfter == high`): live across the whole body, so among equals a
  ## param is the longest-lived and thus the preferred victim.
  let vi = b.an.vars.getOrDefault(name)
  if vi.freeAfter == high(int): return high(int)
  max(1, vi.freeAfter - vi.liveStart)

# ── scope-based statement walk that plans declarations ──────────────────────

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
      b.freeSym name
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
    b.freeSym v

proc recordValue(b: var Builder; pos: int; loc: Location) {.inline.} =
  ## Plan the value produced AT `pos` into `loc`. This is the position-keyed
  ## primitive every other recording form is built on, and it needs no name —
  ## which is the point: an expression has a position and no name, so this is the
  ## call an expression-homing planner makes. See `planned` for the read side.
  b.plan.locs[pos] = loc

proc recordSym(b: var Builder; pos: int; name: string; loc: Location) =
  ## `recordValue` plus a NAME ALIAS for that position. A local's home is not a
  ## different kind of thing from an expression's — it is the same plan entry with
  ## a name pointing at it, which is why undoing one (`demoteToStack`, a steal) is
  ## a single-point rewrite that every use sees.
  b.recordValue(pos, loc)
  b.plan.symPos[name] = pos
  b.plan.homesDirty = true

proc coldestVictim(b: var Builder; maxW, ceilLen, thiefDepth: int;
                   calleeOnly, wantFloat: bool): string =
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
      if v in b.inheritedHomes: continue        # its store was never allocated; must stay InReg
      let vloc = b.homeOf(v)
      if wantFloat:
        if vloc.kind != InFReg: continue
      else:
        if vloc.kind != InReg: continue
        if vloc.r in b.plan.sealed: continue      # pinned to an in-flight ABI call
        if calleeOnly and vloc.r notin b.md.intCalleeSavedSet: continue
      let vw = b.weightOf(v)
      if vw < bestW or (vw == bestW and b.rangeLen(v) > bestLen):
        bestW = vw; bestLen = b.rangeLen(v); result = v

proc addSpillTemp*(plan: var Plan; name: string; typ: AsmSlot; isFloat = false) =
  ## Queue a spill slot for the PROLOGUE to declare. For the planner's own slots
  ## only — a `csave` cell, and the wide `etmp` of a 32-bit target. The value core
  ## declares its `etmp`/`eftmp`/`held` where it mints them (`declSpillSlot`), which
  ## is always a statement position; queueing those too meant a slot whose only
  ## declaration site was a loop running AFTER `emitFrameSub`, so `hasStackVars` had
  ## to be set from HERE or the frame `sub` went missing. That is still why the flag
  ## is set here: a queued slot's own declaration is too late to set it.
  ##
  ## (What that cost: invisible while every spill temp was minted under register
  ## exhaustion, which no proc reaches without stack vars of its own; the caller-saved
  ## save slot is the first one a register-only proc can have, and it produced a proc
  ## with a slot and NO frame — every save writing below `rsp`.)
  plan.spillTemps.add (name: name, typ: typ, isFloat: isFloat)
  plan.hasStackVars = true                     # see above: the decl is too late to set it
  when defined(arkhamSpillDbg):
    stderr.writeLine "SPILLTEMP proc=" & gArkhamCurProc & " name=" & name &
      " float=" & $isFloat

proc demoteToStack(b: var Builder; victim: string) =
  ## Undo `victim`'s optimistic register assignment: move it to a nifasm-managed `(s)`
  ## slot addressed by its own name (offsets are nifasm's job). A single-point rewrite
  ## of `locs[symPos[victim]]` — and because every use reads through `symPos` (the
  ## emitter late-binds via `locationOfSym`), every use, walked or not, sees the new
  ## home. Sound across every control-flow path: the home is memory everywhere.
  let vpos = b.plan.symPos[victim]
  b.plan.callerSaveHomes.del victim     # its home is memory now: nothing to save/restore
  b.plan.locs[vpos] = namedStackLoc(victim, b.plan.planned(vpos).typ)
  b.plan.hasStackVars = true
  b.plan.homesDirty = true

proc trySteal(b: var Builder; curName: string; curSlot: AsmSlot;
              curProps: VarProps; fallback: Location): Location =
  ## `curName` wanted a register but the pool was empty (`fallback` is a stack
  ## slot). Evict the lowest-weight live local that holds a usable register, if
  ## it is strictly colder than `curName`; that local moves to `fallback` and
  ## `curName` takes its register. Returns `curName`'s chosen location.
  let calleeOnly = AllRegs notin curProps   # cross-call var needs callee-saved
  let thiefDepth = b.an.vars.getOrDefault(curName).declLoopDepth
  # NOT loop-carried-aware. `weight` counts STATIC uses × loop depth, so a loop
  # COUNTER read twice in the condition (every iteration, unconditionally) looks
  # colder than a body temp read five times under a guard, and `addTree`'s counter
  # duly ends up on the stack — 28.6 M executed instructions. Both repairs measured
  # WORSE: refusing such a victim outright is nifbench −0.21 % / nimsem **+3.44 %**,
  # and merely PREFERRING another is nifbench **+0.17 %**. The victim `weight` picks
  # really is the coldest one available; the alternative is hotter still.
  let bestV = b.coldestVictim(b.weightOf(curName), b.rangeLen(curName), thiefDepth,
                              calleeOnly, wantFloat = false)
  if bestV.len == 0:
    when defined(arkhamHomeTrace):
      let vi = b.an.vars.getOrDefault(curName)
      stderr.writeLine "HOMETRACE nosteal proc=" & gArkhamCurProc & " loser=" & curName &
        "(w=" & $vi.weight & ",u=" & $vi.usages & ",d=" & $vi.defs &
        ",len=" & $b.rangeLen(curName) & ",dld=" & $vi.declLoopDepth & ")"
    return fallback                          # nothing colder to steal from
  let bestReg = b.homeOf(bestV).r
  if not b.fixedRoleOk(bestReg, curProps):
    # The victim holds rdx/rcx under its OWN interval proof; this value has no such
    # proof, so taking the register would put it across the div/shift that claims it.
    # Declining costs one spill — `coldestVictim` is not re-run for a second choice,
    # since a fixed-role victim is rare enough not to be worth the extra pass.
    return fallback
  # evict the victim to its stack slot; current takes its register
  b.demoteToStack(bestV)
  when defined(arkhamHomeTrace):
    stderr.writeLine "HOMETRACE steal proc=" & gArkhamCurProc & " thief=" & curName &
      "(w=" & $b.weightOf(curName) & ",len=" & $b.rangeLen(curName) & ",dld=" & $b.an.vars.getOrDefault(curName).declLoopDepth &
      ",u=" & $b.an.vars.getOrDefault(curName).usages & ")" &
      " victim=" & bestV & "(w=" & $b.weightOf(bestV) & ",len=" & $b.rangeLen(bestV) &
      ",u=" & $b.an.vars.getOrDefault(bestV).usages &
      ",dld=" & $b.an.vars.getOrDefault(bestV).declLoopDepth & ")"
  if bestReg in b.md.intCalleeSavedSet: b.plan.usedCallee.incl bestReg
  result = regLoc(bestReg, curSlot)

# A computed temporary NEVER steals a live local. codegen.c proves ~2 registers
# suffice for all computation; temps draw from the volatile/callee-saved scratch the
# pool still has free, and when none is free they spill to their OWN `(s)` slot
# (`reserveTmp` below) — single-use, branch-safe, no local touched. The ONLY undo of a
# register assignment is local→memory (`trySteal` / `reserveHeldScratch`), decided while
# allocating locals; that is the whole "we optimistically gave a local a register, then
# found we have too many, so we undo it" story, and it can never collide with a temp.

let callerSaveOn = not existsEnv("ARKHAM_NO_CALLERSAVE")
  ## ON by default (2026-08-15). The historical blocker — a segfault in a natively
  ## built nimsem — no longer reproduces: `hastur boot` (full native self-host,
  ## stages converging byte-identical), the whole tester corpus + both stress runs,
  ## `hastur native` and the nifbench checksum oracle are all green with the rescue
  ## enabled. The likeliest killed-in-the-meantime culprit is the by-ref-aggregate
  ## register-pointer store bug (a whole-aggregate `asgn` to a register-homed by-ref
  ## param copied the POINTER, silently aliasing the params — see the AsgnS
  ## reclassification in both emitters). `ARKHAM_NO_CALLERSAVE=1` is the off switch
  ## for A/B measurement; the bisect knobs below still work.
let csBisectMod = (if existsEnv("ARKHAM_CS_MOD"): parseInt(getEnv("ARKHAM_CS_MOD")) else: 0)
let csBisectRem = (if existsEnv("ARKHAM_CS_REM"): parseInt(getEnv("ARKHAM_CS_REM")) else: 0)
proc readCsProcList(): HashSet[string] =
  ## `ARKHAM_CS_PROCS=<file>` restricts the rescue to the `proc=` names listed one per
  ## line in that file — the bisect axis the hash knob only approximates. arkham runs
  ## one process per module, so a global counter cannot bisect; an explicit name set
  ## can, and `-d:arkhamCallerSaveDbg`'s `CSVAR` lines are exactly the candidate list
  ## to halve. Empty (unset) = no restriction.
  result = initHashSet[string]()
  if existsEnv("ARKHAM_CS_PROCS"):
    for line in lines(getEnv("ARKHAM_CS_PROCS")):
      let t = line.strip()
      if t.len > 0: result.incl t

let csOnlyProcs = readCsProcList()
let csIgnoreCost = existsEnv("ARKHAM_CS_ALL")
  ## Drop the `weight > 2 * crossings` gate: rescue EVERY cross-call value that
  ## qualifies structurally. Measurement knob — it answers whether the cost model or
  ## the mechanism is what limits the payoff.
  ## Bisect knob: with `ARKHAM_CS_MOD=N ARKHAM_CS_REM=r` the rescue fires only in procs
  ## whose name hashes to `r mod N`, so a miscompile can be halved down to one proc.
  ## See `callerSaveRescue` for what the rescue does and why it is sound.

proc initHasCallImpl(n: var Cursor): bool =
  ## Advances `n` past the subtree; true iff it contains a call anywhere.
  if n.kind == TagLit:
    if n.exprKind == CallC: return true
    n.into:
      while n.hasMore:
        if initHasCallImpl(n): return true    # each recursion consumes one child
  else:
    inc n
  return false

proc initHasCall(n: Cursor): bool =
  ## A var whose initializer contains a call is not defined *before* that call — it is
  ## produced BY it. Such a var must never get a caller-saved home: the emitter's save
  ## would read a register that holds nothing yet, and the call's own result is what
  ## defines it. (`initEndPos` alone does not catch this: the decl's register is live
  ## from the decl, and the defining call sits after it.)
  var c = n
  initHasCallImpl(c)

proc callsCrossedAfterInit(b: Builder; vi: VarInfo): int =
  ## Calls the value crosses ONCE IT EXISTS — counted from `initEndPos`, the position
  ## its value is born at, not from its declaration. A call inside the initializer
  ## (`let x = f(…)`) therefore does not count: the register holds nothing to save
  ## there, and the value is produced by that very call.
  for p in b.an.callPositions:
    if p > vi.initEndPos and p <= vi.freeAfter: inc result

proc callerSaveRescue(b: var Builder; name: string; slot: AsmSlot;
                      props: VarProps; valCur: Cursor; hasValue: bool;
                      fallback: Location): Location =
  ## The third option between "callee-saved register" and "memory".
  ##
  ## `getSym` gives a value that crosses a call the callee-saved pool or the
  ## stack — and 90 % of arkham's spills take the stack while 6-7 VOLATILE registers
  ## sit free, because a volatile is clobbered by the call. A caller-saved home closes
  ## that: the value lives in a volatile and the emitter brackets each crossed call
  ## with a save/restore, so it is register-resident everywhere else.
  ##
  ## SOUNDNESS in an ARGUMENT register. `design.md` forbids homing a value that is
  ## *merely live across* a call in an argument register: marshalling would clobber it,
  ## and repairing that in general needs a parallel-copy with cycle breaking. A
  ## caller-saved value is never live in its register across the call — it is stored
  ## before marshalling begins and reloaded after the call returns. The one residual
  ## hazard, that this value is itself the SOURCE of an argument to the same call, is
  ## closed by `Plan.callerSaveActive`: inside the call window every read resolves
  ## to the save slot. So the partition still holds where the design needs it, and no
  ## shuffle analysis appears.
  ##
  ## VALIDITY. Save whenever bound (the emitter uses live bindings, not the coarse
  ## interval, so a value bound across a control-flow merge is still saved). That is
  ## only well-defined if the register holds a defined value at EVERY call it is bound
  ## across, hence: single-def, a bounded interval, and crossings counted from
  ## `initEndPos`. This excludes a `result` var (declared empty, assigned late) and
  ## `var x = f(…)` (born from the call it would be saved around).
  ##
  ## COST. Two memory ops per crossed call against one register read per use, so it
  ## pays only when `weight > 2 * crossings`; below that a plain spill is cheaper.
  if not callerSaveOn or b.md.arch != X86: return fallback
  if csOnlyProcs.len > 0 and gArkhamCurProc notin csOnlyProcs: return fallback
  if csBisectMod > 0:
    var h = 0
    for ch in gArkhamCurProc: h = (h * 131 + int(ch)) and 0x3fffffff
    if h mod csBisectMod != csBisectRem: return fallback
  if AddrTaken in props or not slot.inRegClass or slot.isFloat: return fallback
  if AllRegs in props: return fallback          # not a cross-call value; already handled
  if not hasValue or initHasCall(valCur): return fallback
  let vi = b.an.vars.getOrDefault(name)
  if vi.defs != 1 or vi.freeAfter == high(int): return fallback
  let crossings = b.callsCrossedAfterInit(vi)
  if crossings == 0: return fallback
  if not csIgnoreCost and vi.weight <= 2 * crossings: return fallback
  # NEVER the staging bridge (r11). An earlier revision handed it out FIRST (gated
  # only against `(instr …)` rows via `clobbersBridgeReg`), reasoning that it is the
  # one volatile with no ABI role — but the gate covered only the STATIC bridge
  # claims. The emitter also grabs the bridge REACTIVELY under register pressure
  # (`produceIntoMem2`, the mem-base reload staging, the aggregate-copy transfer):
  # those sites `releaseStaleName(R11)` and write it raw, because the bridge's whole
  # contract is "always free for the emitter" — a contract a rescued value homed
  # there silently violates. The corpus never had enough simultaneous pressure to
  # hit the combination; a shoggoth-unswitched `nifbuilder` (duplicated loops, every
  # pool dry) did: the bridge grab dropped the rescued local's binding and its next
  # read reached `emReg` as a raw r11 — the checker catching a real clobber.
  # A home must come from a pool the emitter treats as allocatable, full stop.
  #
  # The argument registers are fine: a rescued value is stored to its `csave` slot
  # and its reads redirected there before any marshalling writes them
  # (`emCallerSaveOpen`), which is the mechanism's whole point.
  var r = b.takeReg(b.freeVol, b.md.intLocalTempRegs)
  if r == NoReg: return fallback
  b.plan.callerSaveHomes[name] = vi.freeAfter
  # The save slot is declared in the PROLOGUE, not at the decl. arkham emits by a
  # textual walk, so a binding made inside one branch is still live when the sibling
  # branch is emitted, and the sibling's calls save through this slot too. A slot
  # declared inside the decl's scope would be reclaimed for the sibling's own locals —
  # the save would then corrupt an unrelated variable. (Saving a value the sibling
  # path never defined is harmless in itself: it is dead there, so the reload is dead
  # too. Aliasing the slot is what was fatal.)
  b.plan.addSpillTemp("csave." & name, slot)
  result = regLoc(r, slot)

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
proc allocVarDecl(b: var Builder; n: var Cursor) =
  n.into:
    let pos = b.posOf(n)
    assert n.kind == SymbolDef
    let name = symName(n); inc n
    skip n                                   # pragmas
    let typeIsOmitted = n.kind == DotToken
    var slot = slotOf(b.prog[], n); skip n  # type (resolves named types)
    var valCur = n                           # remember the initializer (slot inference)
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
      b.recordSym(pos, name, namedStackLoc(name, slot))
      b.plan.hasStackVars = true
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
      # In-loop decls qualify like any other: loop-body locals have per-iteration
      # lifetime (no loop-carrying semantics), so the back-edge revives nothing —
      # c1's decl re-writes the shared register only after c2's previous-iteration
      # value is already dead.
      var inheritSrc = ""                       # non-empty ⇒ this var inherits `inheritSrc`'s reg
      if not copyInheritDisabled and b.md.arch == X86 and hasValue and
         AddrTaken notin props and slot.inRegClass and not slot.isFloat:
        let srcSym = copyCastSrcSym(valCur)
        if srcSym.kind == Symbol:
          let srcName = symName(srcSym)
          let sh = b.homeOf(srcName)
          let svi = b.an.vars.getOrDefault(srcName)
          if sh.kind == InReg and not sh.typ.isFloat and sh.typ.size == slot.size and
             svi.defs == 1 and svi.lastUsePos <= b.posOf(srcSym) and
             (sh.r in b.md.intCalleeSavedSet or AllRegs in props) and
             b.fixedRoleOk(sh.r, props):
            inheritSrc = srcName
      # NOTE: identity-cast value ALIASING (the c1-LIVE case) was reverted — it produced
      # nifasm-rejected `cmp (ptr object) (ptr object)` on the allocator (a value use of an
      # aliased cast lost its precise pointer type). Only the c1-DEAD transfer below remains.
      var aliasSrc = ""
      discard aliasSrc                      # aliasing reverted (see note); always empty now
      # Optimistically give the local a register; demote a colder one to memory if the
      # register class is full (`trySteal`, the only undo). A spilled / address-taken
      # scalar lives in a nifasm-managed `(s)` slot addressed by name.
      # Return-register homing (AArch64): the returned local, when call-free (`AllRegs`),
      # prefers the return register x0 — so `(ret result)` marshals to a no-op `mov x0, x0`
      # and, when x0 is then the only would-be callee-saved home, no frame is pushed.
      # Self-guarding: `intRetReg` is in `freeVol` only while genuinely free (a persistent
      # leaf param in x0 was removed by `allocParams`), so this falls through to the normal
      # home whenever x0 is taken. Nothing else draws x0 (it is outside every temp/local
      # candidate list), so reserving it here cannot starve the emitter's scratch.
      #
      # Only in a proc that makes NO call. `AllRegs` says this local's own interval
      # crosses no call, which is not the same thing: the EMITTER uses x0 as argument 0
      # and as the call result wherever a call appears, and `emReg` renders a bound
      # register by the variable's name — so `f(handle)` in another branch came out as
      # `mov canRaise.0, handle` / `mov x.129, canRaise.0` across the call, which nifasm
      # rejects (osproc's `close`, 6 modules of `nimony n` on nimsem). In a call-free
      # proc x0 has no second role, and that is exactly where the payoff is anyway —
      # eliding the trailing `mov` and, with it, the frame.
      let takeRet = b.md.arch in {Arm64, ThumbM, Rv32} and name.len > 0 and name == b.returnedVar and
                    AllRegs in props and not b.an.hasCall and
                    not slot.isFloat and AddrTaken notin props and
                    slot.inRegClass and b.md.intRetReg in b.freeVol
      var loc =
        if aliasSrc.len > 0: dontCare                                 # c2 is a pure view of c1
        elif inheritSrc.len > 0: regLoc(b.homeOf(inheritSrc).r, slot) # c2 takes c1's reg
        elif takeRet:
          excl b.freeVol, b.md.intRetReg
          regLoc(b.md.intRetReg, slot)
        else: b.getSym(name, slot, props)
      if inheritSrc.len > 0:
        # Transfer the register's free obligation from the (now-dead) source to this var:
        # drop the source's pending early-free and mark it freed so `closeScope` skips it;
        # THIS var's own `pendingFree`/`scopeVars` entries below then solely own the reg.
        var k = 0
        while k < b.pendingFree.len:
          if b.pendingFree[k].name == inheritSrc: b.pendingFree.del k
          else: inc k
        b.freedSyms.incl inheritSrc
        # Pin the home: `allocStore` is skipped below (the value is already in the
        # register), so a later `trySteal` evicting THIS var to the stack would leave
        # the emitter emitting a store whose rhs position has no recorded location.
        b.inheritedHomes.incl name
      if loc.kind == NamedStack:
        # Tried BEFORE `trySteal` because it evicts nothing: it draws a volatile the
        # cross-call value could not otherwise use, instead of taking a callee-saved
        # register away from a colder value that has no third option either.
        loc = b.callerSaveRescue(name, slot, props, valCur, hasValue, loc)
      if loc.kind == NamedStack and AddrTaken notin props and
         slot.inRegClass and not slot.isFloat:
        loc = b.trySteal(name, slot, props, loc)  # hot var evicts a colder one
      if loc.kind == NamedStack:
        b.plan.hasStackVars = true
      when defined(arkhamSSAStats):
        if loc.kind == NamedStack and AddrTaken notin props and
           slot.inRegClass and not slot.isFloat:
          # a register-eligible scalar that ended in memory = a PRESSURE spill
          let svi = b.an.vars.getOrDefault(name)
          stderr.write "SSASPILL proc=" & gArkhamCurProc & " var=" & name &
            " defs=" & $svi.defs & " uses=" & $svi.usages &
            " init=" & $svi.initClass & " weight=" & $svi.weight &
            " inloop=" & $svi.declInLoop & "\n"
      if aliasSrc.len > 0:
        b.plan.symPos[name] = b.plan.symPos[aliasSrc]   # c2 resolves to c1's LIVE home (no own reg)
        b.plan.aliasedCasts.incl name                 # emitter emits neither decl nor store for it
        b.plan.homesDirty = true
      else:
        b.recordSym(pos, name, loc)
        b.scopeVars[^1].add name
      # Register the coarse early-free. In-loop decls participate too: a loop-body
      # local's lifetime is per-iteration (no loop-carrying semantics — its scope
      # ends within the iteration), so once the walk passes its last use the
      # register is genuinely reusable. A later same-body decl that takes it is
      # itself per-iteration, and this var's decl re-executing on the next
      # iteration overwrites only dead values. An OUTSIDE-declared var used in the
      # loop is protected by its `freeAfter` extension over the whole loop span.
      # Stored by name so the flush frees the var's *current* reg (it may have
      # been evicted to the stack). Float homes participate like integer ones:
      # the callee-saved SIMD pool is only 8 wide, and the vectorizer's
      # per-iteration `(f 128)` temps drain it without the early-free.
      let vi = b.an.vars.getOrDefault(name)
      if loc.kind in {InReg, InFReg}:
        b.pendingFree.add (pos: vi.freeAfter, name: name)

proc planStmt(b: var Builder; n: var Cursor) =
  ## Walk the STATEMENTS of a body and plan what they declare. There is deliberately
  ## no `planValue` twin yet: an expression position gets no plan entry, and the
  ## emitter picks its temps itself as it walks (see `planned`). Adding one means
  ## recursing into the value positions this pass currently skips over and calling
  ## `recordValue` — the storage, the write side and the read side already take a
  ## bare position, so it is an addition here rather than a change everywhere.
  case n.stmtKind
  of ProcS, TypeS:
    skip n                                   # nested decls allocate separately
  of VarS, GvarS, TvarS, ConstS:
    allocVarDecl(b, n)
  of ScopeS:                                 # only a `scope` opens a fresh scope
    openScope(b)
    n.into:
      while n.hasMore:
        planStmt(b, n)
        flushFree(b, b.posOf(n))             # free locals dead as of this boundary
    closeScope(b)
  of StmtsS:                                  # a statement list — NOT a fresh scope
    n.into:
      while n.hasMore:
        planStmt(b, n)
        flushFree(b, b.posOf(n))
  of RetS:
    skip n
  of CallS, InstrS:
    if n.kind == TagLit:
      n.into:
        while n.hasMore: planStmt(b, n)
    else: inc n
  of AsgnS, KeepovfS, WhileS, IfS, CaseS:
    n.into:
      while n.hasMore: planStmt(b, n)
  else:
    if n.kind == TagLit:
      n.into:
        while n.hasMore: planStmt(b, n)          # recurse (var decls may nest)
    else:
      inc n

proc allocParams(b: var Builder; params: var Cursor; hasCall: bool) =
  if params.kind != TagLit: return
  # THE plan: every register/stack decision below reads it — no local counting.
  # On x86-64 a >16B by-ref aggregate return takes the first integer arg register
  # (rdi) as the hidden result pointer, so real params start at rsi — in lockstep
  # with the signature / emitParamMoves / emitStackParamLoads. AArch64 passes the
  # hidden pointer in x8 (off the arg-register file), so no skip.
  let plan = planCall(b.md, paramSlots(b.prog[], params),
                      retByRef = b.retIndirect and b.md.arch == X86)
  var pIdx = 0
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
      let pl = plan.args[pIdx]
      inc pIdx
      params.into:
        let pos = b.posOf(params)
        assert params.kind == SymbolDef
        let name = symName(params); inc params
        skip params                          # pragmas
        # The param type's POOL ID: what a `StackPtr` home carries, and the key the
        # layout API (`canHomeInRegPair` here) takes. `default(SymId)` for a param
        # whose type is not a named symbol — an inline structural type, which has no
        # nominal identity to look up.
        let typeSym = if params.kind == Symbol: params.symId else: default(SymId)
        let slot = slotOf(b.prog[], params); skip params  # type (resolves named)
        # An aggregate param, per the plan:
        #  * ≤16B by-value that FITS the remaining arg registers → REGISTER-passed
        #    (`aggrSmall`): each ABI eightbyte in a GPR, like a scalar — UNLESS the
        #    address is taken or a field is sub-word (then a `(s)` stack home filled
        #    from those GPRs, the old always-stack path).
        #  * ≤16B by-value that does NOT fit → STACK-passed (`aggrStack`): the bytes arrive
        #    in the incoming stack-arg area (copied into the `(s)` home by
        #    `emitStackParamLoadsX64`), consuming NO arg register — the SysV skip rule, so a
        #    later smaller param may still take a free GPR. Same home shape as `aggrSmall`.
        #  * >16B → by-REFERENCE (`aggrByRef`): a pointer (in a reg, or on the stack if none
        #    is free), like a scalar.
        let aggrSmall = pl.isAgg and not pl.byRef and not pl.onStack
        let aggrStack = pl.isAgg and not pl.byRef and pl.onStack
        let aggrByRef = pl.isAgg and pl.byRef
        if aggrSmall:
          let props = b.an.vars.getOrDefault(name).props
          var pairOk = AddrTaken notin props and typeSym != default(SymId) and
                       canHomeInRegPair(b.prog[], typeSym)
          var r0 = NoReg
          var r1 = NoReg
          if pairOk:
            for k in 0 ..< pl.words:
              let arg = b.md.gprAt(pl, k)
              let clobbered = (arg == b.md.divRemReg and b.an.clobbersDivReg) or
                              (arg == b.md.shiftCountReg and b.an.clobbersShiftReg) or
                              (arg == b.md.intRetReg and b.an.arg0RetConflict)
              let stayInArg = (ArgResident in props and not clobbered) or
                              (AllRegs in props and not clobbered)
              var r: Reg
              if (hasCall or clobbered) and not stayInArg:
                r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
                if r == NoReg:
                  pairOk = false
                  break
                b.plan.usedCallee.incl r
              else:
                r = arg
                b.freeVol.excl arg
              if k == 0: r0 = r else: r1 = r
            if not pairOk:
              if r0 != NoReg:
                b.giveBack r0
                b.plan.usedCallee.excl r0
              if r1 != NoReg:
                b.giveBack r1
                b.plan.usedCallee.excl r1
              r0 = NoReg; r1 = NoReg
          if pairOk:
            b.recordSym(pos, name, regPairLoc(r0, r1, slot))
          else:
            b.recordSym(pos, name, namedStackLoc(name, slot))
            b.plan.hasStackVars = true
        elif aggrStack and b.md.arch == X86:
          # (No early `continue`/`return`: that skips the `into` epilogue.) These home the
          # aggregate in its own `(s)` slot; only a register-passed one consumes GPRs.
          # A stack-passed by-value aggregate keeps a slot home ONLY on x86-64, where
          # `emitStackParamLoadsX64` COPIES the incoming stack bytes into it. On AArch64
          # a stack-passed by-value aggregate instead gets a POINTER home in a register
          # (below, like a by-ref aggregate): `emitStackParamLoads` computes `&incoming`
          # with `Lea` and the body reads fields through it — no copy.
          b.recordSym(pos, name, namedStackLoc(name, slot))
          b.plan.hasStackVars = true
        else:
          # `effSlot` is the in-register value: the scalar itself, or a pointer — to
          # the aggregate copy (by-ref), or to the incoming stack bytes (a64 stack-passed
          # by-value aggregate, `aggrStack`; on x86-64 those took the slot path above).
          let effSlot = if aggrByRef or aggrStack: addrSlot() else: slot
          # `viaPtr` names the spill shape for those two: the value is the AGGREGATE,
          # but a memory home holds only its ADDRESS. `spillTo` would say `NamedStack`,
          # which every consumer reads as "the slot IS the value" — `StackPtr` says the
          # extra load outright, and carries the pointee's type so no side table has to.
          let viaPtr = aggrByRef or aggrStack
          template memHome(): Location =
            if viaPtr: stackPtrLoc(name, typeSym, slot) else: b.spillTo(name, effSlot)
          let props = b.an.vars.getOrDefault(name).props
          var loc: Location
          if effSlot.isFloat:
            # A float parameter arrives in v{fpIndex}. In a leaf proc it stays
            # there; if the proc makes calls it moves to a callee-saved register
            # (v8–v15) so it survives them; if address-taken it spills to a slot.
            # (The >8-float / stack-passed case is still TODO.)
            if not pl.onStack:
              if AddrTaken in props:
                loc = b.spillTo(name, effSlot)   # address taken → must be on the stack
              elif hasCall:
                let f = b.takeFReg(b.freeCalleeF, b.md.floatCalleeSaved)
                if f != NoFReg:
                  b.plan.usedCalleeF.incl f
                  loc = fregLoc(f, effSlot)
                else:
                  loc = b.spillTo(name, effSlot)
              else:
                loc = fregLoc(b.md.floatArgRegs[pl.fpIndex], effSlot)
            else:
              loc = b.spillTo(name, effSlot)     # >8 float args: stack-passed (TODO)
          elif not effSlot.inRegClass:
            if effSlot.kind == AMem:
              raiseAssert "arkham: unsupported parameter slot (zero-size aggregate): " & name
            loc = b.spillTo(name, effSlot)
          elif not pl.onStack:
            # (`aggrStack` is stack-passed by definition — never register-home it,
            # even if an arg register looks free: AAPCS64 stopped filling registers
            # once this composite spilled to the stack.)
            let arg = b.md.gprAt(pl)
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
            # The general form of the same argument: `AllRegs` on a PARAM means the
            # analyser proved its last use precedes the FIRST call, so no call has
            # marshalled anything into its arg register while it is live, and the
            # ABI partitioning design.md calls load-bearing still holds — the param
            # is dead by the time any marshalling starts. (`ArgResident` is the older,
            # narrower rule: it additionally allows the last use to sit *inside* the
            # first call's own arguments, which the position test here denies.)
            # `flushArgResidentParams` kills the lingering binding after that call,
            # and it is already fed from `loc.r == argReg`, not from the prop.
            # A by-ref aggregate's POINTER is excluded from `ArgResident` because it
            # "must survive repeated field loads" — but a field load through it does
            # not write it, so what it actually has to survive is a CALL, and
            # `AllRegs` says there is none. Hence `aggrByRef` blocks only the older
            # rule. (`emitParamMoves` already elides the relocation move when the
            # home IS the incoming register.)
            let stayInArg = (ArgResident in props and not aggrByRef and not clobbered) or
                            (AllRegs in props and not clobbered)
            if AddrTaken in props and not aggrByRef:
              loc = memHome()                  # address taken → must be on the stack
            elif (hasCall or aggrByRef or clobbered) and not stayInArg:
              # Live across a call (the incoming arg reg is volatile), or a by-ref
              # pointer that must survive repeated field loads in the body:
              # a callee-saved home the prologue fills with `mov home, argReg`.
              let r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
              if r != NoReg:
                b.plan.usedCallee.incl r
                loc = regLoc(r, effSlot)
                if not aggrByRef:
                  # Evictable in favour of a later stack param (a by-ref aggregate's
                  # slot would need its aggregate type, not the pointer — skip those).
                  spillableRegParams.add (pos: pos, name: name, r: r, effSlot: effSlot)
              elif aggrByRef and spillableRegParams.len > 0:
                # No free register for the by-ref POINTER. Prefer evicting a colder
                # scalar register param to its stack slot (emitParamMoves fills it
                # from the incoming arg register) and reusing its register — the
                # pointer stays InReg, which every consumer already handles.
                let victim = spillableRegParams.pop()
                b.recordSym(victim.pos, victim.name,
                         namedStackLoc(victim.name, victim.effSlot))
                b.plan.hasStackVars = true
                loc = regLoc(victim.r, effSlot)
              else:
                # Totality: no callee-saved reg and nothing colder to evict. A
                # by-ref POINTER homes in an 8-byte `(s)` slot — a `StackPtr`, whose
                # `typ` is the AGGREGATE it points at. emitParamMoves stores the
                # incoming arg register there; field access / `aggrAddr*` load it back.
                loc = memHome()
            else:
              loc = regLoc(arg, effSlot)       # leaf proc: stay in the arg reg
              b.freeVol.excl arg               # persistent home → not lendable to a call-free local
          else:
            # The 9th integer/pointer parameter onward arrives on the caller's
            # stack (AAPCS64). arkham gives it a callee-saved register home that
            # the prologue loads from the incoming arg slot before SP is lowered
            # for locals, so it survives the whole proc.
            if AddrTaken in props and not aggrByRef:
              # Address taken → the value must live in memory: its own `(s)` slot,
              # which `emitStackParamLoads` fills from the incoming arg area exactly
              # as it does for the register-pressure totality case below. (A by-ref
              # aggregate's "address" is the incoming pointer itself, so that one
              # keeps a register home like its register-passed twin.)
              loc = memHome()
              b.plan.hasStackVars = true
            else:
              var r = b.takeReg(b.freeCallee, b.md.intCalleeSaved)
              if r == NoReg and spillableRegParams.len > 0:
                # No free callee-saved register: evict an earlier scalar register
                # param to its stack slot and reuse its register for this stack param.
                let victim = spillableRegParams.pop()
                b.recordSym(victim.pos, victim.name,
                         namedStackLoc(victim.name, victim.effSlot))
                b.plan.hasStackVars = true
                r = victim.r                        # already in usedCallee
              if r == NoReg:
                # Totality: no callee-saved reg and nothing colder to evict — home this
                # stack param in its OWN `(s)` slot. The prologue loads it from the incoming
                # arg area into the slot through a staging bridge (`emitStackParamLoadsX64`),
                # so no register is held; correct by construction, never a hard fail.
                loc = memHome()
                b.plan.hasStackVars = true
              else:
                b.plan.usedCallee.incl r
                loc = regLoc(r, effSlot)
          if loc.kind in {NamedStack, StackPtr}:
            # An address-taken / spilled param's `(s)` slot: the prologue fills it
            # from the incoming arg register (int or SIMD; see emitParamMoves).
            b.plan.hasStackVars = true
          b.recordSym(pos, name, loc)
  # Make the scalar register-homed params visible to `coldestVictim`: a proc whose
  # params all take callee-saved homes (every reg param crosses a call) would
  # otherwise leave `reserveHeldScratch`/`trySteal` with no register-resident LOCAL
  # to evict — the callee-saved pool is full but nothing in `scopeVars` holds it.
  # These params demote cleanly (`demoteToStack` → NamedStack scalar slot, which
  # `emitParamMoves` fills from the incoming arg register). by-ref aggregate params
  # are EXCLUDED (not in `spillableRegParams`): `demoteToStack` rebuilds the home as
  # `namedStackLoc(victim, <its current typ>)`, and for a by-ref pointer that is the
  # POINTER's slot — "the slot IS an 8-byte scalar", which is not what the pointer's
  # readers mean. Lifting this now only needs `demoteToStack` to produce a `StackPtr`
  # (pointee type + aggregate slot) instead; before that kind existed the shape was
  # inexpressible, and the ban was the only way to stay correct.
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
  # never serve as emitter transient scratch; only `getSym`'s `AllRegs` fall-
  # back (which filters on `intLocalTempRegs`) can hand them to a local. A leaf param
  # that persistently occupies one is removed from this pool in `allocParams`.
  for r in b.md.intLocalTempRegs: b.freeVol.incl r
  # The fixed-role registers (rdx = div/rem, rcx = shift count) also join `freeVol`
  # so a `DivRegOk`/`ShiftRegOk` local can be homed there. They are handed out ONLY
  # via those props' candidate list in `getSym` (never in `intLocalTempRegs`
  # nor `intTempRegs`), so no ordinary local/temp draws them; and the interval
  # analysis guarantees their fixed role never overlaps such a local (asserted by
  # `divRemOccupied`/`regOccupied` at the div/shift sites). `NoReg` on RISC (a64).
  if b.md.divRemReg != NoReg: b.freeVol.incl b.md.divRemReg
  if b.md.shiftCountReg != NoReg: b.freeVol.incl b.md.shiftCountReg
  if b.md.stagingBridgeReg != NoReg: b.freeVol.incl b.md.stagingBridgeReg
  # AArch64: the integer return register (x0) joins the pool too, drawn ONLY by the
  # returned local's home (an explicit `[intRetReg]` candidate — never by
  # `intLocalTempRegs`/`intTempRegs`, which exclude it, nor by any temp). `allocParams`
  # removes it again if a leaf param persistently occupies it, so it is available for the
  # returned local exactly when x0 is otherwise free. Homing a call-free returned local
  # there elides the trailing `mov x0, result` (and the whole frame when it is the only
  # callee-saved user). Not on x86-64: there rax IS an ordinary scratch/temp register.
  # Cortex-M answers like AArch64 — r0 is its return register and is likewise kept
  # out of both temp pools, so the same "drawn only by the returned local" property
  # holds.
  if b.md.arch in {Arm64, ThumbM, Rv32} and b.md.intRetReg != NoReg:
    b.freeVol.incl b.md.intRetReg
  for r in b.md.intCalleeSaved: b.freeCallee.incl r
  for f in b.md.floatTempRegs: b.freeVolF.incl f
  for f in b.md.floatCalleeSaved: b.freeCalleeF.incl f

proc findReturnedVarImpl(n: var Cursor): string =
  ## First bare local returned by a `(ret <sym>)` anywhere in the subtree, or "".
  ## Advances `n` past the subtree (mirrors `exprReadsRegImpl`'s early-return walk).
  if n.kind == TagLit:
    if n.stmtKind == RetS:
      var r = n
      inc r                                  # into the ret → its value
      if r.kind == Symbol: return symName(r)
    n.into:
      while n.hasMore:
        let s = findReturnedVarImpl(n)
        if s.len > 0: return s
  else:
    inc n
  return ""

proc findReturnedVar(body: Cursor): string =
  var c = body
  findReturnedVarImpl(c)

proc allocateProc*(buf: var TokenBuf; procDecl: Cursor; an: ProcAnalysis;
                   prog: var Program; md: MachineDesc; tc: TypeCtx;
                   presealed: set[Reg] = {}): Plan =
  ## Allocate storage for the params and locals of `procDecl` in a SINGLE walk
  ## over the tree (the decl-only pre-pass of the fused value core; expression
  ## temporaries are decided at emission). The model (codegen.c + optimistic
  ## locals):
  ##   * LOCALS are assigned to registers OPTIMISTICALLY as they are declared. The only
  ##     undo of a register assignment is local→memory: when we find we have too many
  ##     locals for a register (a hotter local arrives, or a survivor scratch needs a
  ##     callee-saved reg), `trySteal` demotes a colder local with
  ##     `demoteToStack` — a single-point `locs[symPos[name]]` rewrite that every use
  ##     sees (the emitter late-binds local reads via `locationOfSym`). Sound across all
  ##     control flow because the demoted local lives in memory everywhere.
  ##   * Expression temporaries draw from the emit-time pick pools (`takeTmp` &
  ##     friends in the backends) and never contend with locals for a register,
  ##     so there is no temp-vs-local collision class to reason about.
  ##
  ## `md` describes the target register file + ABI. `presealed` registers are
  ## reserved for the whole proc. `prog` is `var` because resolving a cross-module
  ## type may load a module.
  var b = Builder(buf: addr buf, an: addr an, prog: addr prog, tc: tc, md: md)
  # `locs` only ever holds positions inside THIS proc's contiguous subtree span, so
  # size it to that span (base = the proc's first token position) rather than the whole
  # module. Sizing to `buf.len` re-allocated+zeroed a module-sized array for every proc
  # — O(procs × moduleTokens), ~91% of arkham's runtime on big modules. See `LocSpan`.
  let procStart = cursorToPosition(buf, procDecl)
  var procEndCur = procDecl; skip procEndCur
  let procEnd = cursorToPosition(buf, procEndCur)
  b.plan = Plan(locs: initLocSpan(procStart, procEnd - procStart),
                  aux: initTable[int, ExprAux](),
                  symPos: initTable[string, int]())
  b.plan.sealed = presealed
  b.plan.divRegClobbered = an.clobbersDivReg
  b.plan.shiftRegClobbered = an.clobbersShiftReg
  # The alias set, straight from the analyser's per-var props: the emitter's
  # store-forwarding mirrors need it, and it is a whole-proc fact, so it is copied
  # once here rather than re-derived per query (see `Plan.aliasable`).
  for name, vi in an.vars:
    if AddrTaken in vi.props: b.plan.aliasable.incl name
  b.scopeVars = @[]; b.pendingFree = @[]; b.freedSyms = initHashSet[string]()
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
      let plan = planCall(b.md, paramSlots(b.prog[], n), b.retIndirect)
      b.plan.hasStackParams = plan.hasStackArgs  # single source of truth for the emitter
      if plan.hasStackArgs:
        # Reserve a callee-saved reg the body cannot use, for the emitter's
        # `stackArgBaseReg`. Skip any SEALED reg (e.g. `RBX` presealed for a >16B-return
        # hidden pointer) — excluding that one reserves nothing extra, leaving the base
        # `NoReg` under full callee-saved pressure.
        for r in b.md.intCalleeSaved:
          if r in b.freeCallee and r notin b.plan.sealed: (b.freeCallee.excl r; break)
    # The emitter's SURVIVOR scratch, reserved on the same principle one line up.
    #
    # A handful of emit steps need a register that outlives a call — a global's base
    # address held across a calling index, an aggregate `&g` held across the rhs that
    # fills it, an atomic's operand. `pickHeldReg` draws those from the callee-saved
    # registers the body did not use, and when the body used them all it returns
    # `NoReg`. That was survivable only because `takeHeld` then took a SECOND chance
    # that bypassed the home union and judged by `rb.isBound` — which does not see a
    # parameter's home, so it handed out live parameters (see `emitParamMoves`).
    #
    # With that hole closed the guarantee has to come from here, which is where it
    # belonged: out of registers is the allocator's problem, not a second allocator's
    # (design.md, "Out of registers is an ERROR, not a second allocator"). Reserving
    # one register up front costs a local home and makes `trySteal` spill the coldest
    # local — one allocator, one set of rules about who gets displaced.
    #
    # Only for a proc that CALLS: a survivor is by definition a value that must cross
    # a call, so a leaf proc can never need one, and leaves are where the register
    # budget is tightest.
    if an.hasCall:
      for r in b.md.intCalleeSaved:
        if r in b.freeCallee and r notin b.plan.sealed: (b.freeCallee.excl r; break)
    allocParams(b, n, an.hasCall)            # advances n past params → return type
    skip n                                    # return type
    skip n                                    # pragmas
    # A scalar-returning proc: find the local it returns so its var-decl can prefer the
    # return register as home (only when call-free and the register is free — see the
    # var-decl path). An aggregate/float/indirect return marshals differently.
    if not b.retAggr and b.retFloatBits == 0 and not b.retIndirect:
      b.returnedVar = findReturnedVar(n)
    planStmt(b, n)                                # body
  b.closeScope()
  result = ensureMove b.plan

# ── lookup API (used by codegen) ────────────────────────────────────────────
#
# A Location belongs to a POSITION. `planned` is that question and the whole of
# it; the two name-keyed lookups below are a convenience layer over it, because a
# local's name is an alias for the position of its declaration (`symPos`). Keeping
# it in that order is what lets an expression — which has a position and no name —
# be planned by exactly the same machinery.

proc homeOfSym*(plan: Plan; name: string): Location {.inline.} =
  ## The DECLARED STORAGE of a local/param — the one place its value lives when it
  ## is not in flight. `NoLoc` if the name is not an allocator-known local/param (a
  ## module-level symbol or a synthesized slot).
  ##
  ## Ask this when the question is about the storage itself: addressing a stack
  ## slot, deciding whether a name has a slot to spill to, saving and restoring it
  ## around a call. Ask `locationOfSym` instead when the question is "where is this
  ## VALUE, here" — see there.
  ##
  ## A caller-saved value inside an open call window reads from its SAVE SLOT, not
  ## from its register: the save has already run and ABI marshalling is about to
  ## overwrite the register — possibly while marshalling an argument whose source
  ## is this very value. Redirecting here covers every read uniformly, which is
  ## why no shuffle/cycle-breaking analysis is needed (`design.md` "How this deals
  ## with the ABI").
  if plan.callerSaveActive.len > 0:
    let act = plan.callerSaveActive.getOrDefault(name, noLoc)
    if act.kind != NoLoc: return act
  let p = plan.symPos.getOrDefault(name, -1)
  if p >= 0: plan.planned(p) else: noLoc      # the name is an alias for that position

proc locationOfSym*(plan: Plan; name: string; pos: int): Location {.inline.} =
  ## Where the VALUE of `name` is at token position `pos`.
  ##
  ## Today every local has exactly one location for its whole live range, so this
  ## answers the same as `homeOfSym` — `segs` is always empty. The two are
  ## nevertheless different questions, and separating them is the point: an
  ## allocator that splits a live range (a volatile between calls, the save slot
  ## across one) makes the answer depend on WHERE it is asked, and every site that
  ## asks it has to be a site that knows where it is. The sites that genuinely
  ## want the storage keep asking `homeOfSym`, and stay right.
  ##
  ## Segments are sorted by `fromPos` and cover the range from there to the next
  ## one; a position before the first segment means the value is not live yet,
  ## which is the declared home by construction.
  if plan.callerSaveActive.len > 0:
    let act = plan.callerSaveActive.getOrDefault(name, noLoc)
    if act.kind != NoLoc: return act
  if plan.segs.len > 0 and plan.segs.hasKey(name):
    let s = plan.segs[name]
    if s.len > 0:
      var i = s.len - 1
      while i > 0 and s[i].fromPos > pos: dec i
      if s[i].fromPos <= pos: return s[i].loc
  let p = plan.symPos.getOrDefault(name, -1)
  if p >= 0: plan.planned(p) else: noLoc      # the name is an alias for that position

# ── sealing (driven by codegen during ABI call marshalling) ─────────────────
# Before codegen places an argument in `xN` (or `x8` for an indirect result),
# it seals that register so any scratch borrow or steal during the rest of the
# call setup cannot clobber the committed value; it unseals after the call.

when defined(arkhamBindTrace):
  var dbgRegSite*: Table[int, string] = initTable[int, string]()
    ## TEMP DIAGNOSTIC: per-register stack trace of the last bind/seal.

proc seal*(plan: var Plan; r: Reg) {.inline.} =
  plan.sealed.incl r
  when defined(arkhamBindTrace): dbgRegSite[ord(r)] = getStackTrace()
proc unseal*(plan: var Plan; r: Reg) {.inline.} = plan.sealed.excl r
proc seal*(plan: var Plan; regs: set[Reg]) {.inline.} =
  plan.sealed = plan.sealed + regs
  when defined(arkhamBindTrace):
    for r in regs: dbgRegSite[ord(r)] = getStackTrace()
proc unseal*(plan: var Plan; regs: set[Reg]) {.inline.} = plan.sealed = plan.sealed - regs
proc isSealed*(plan: Plan; r: Reg): bool {.inline.} = r in plan.sealed
