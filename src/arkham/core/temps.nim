#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Emit-time temporaries: which register the value core may use right now.
##
## The allocator has already placed every named local; this is what is left over
## for the transient values an expression tree needs. A register is a candidate
## only if nothing live is in it, which is a question about the binding tables,
## the mirror map and the plan at once — hence `tempCensus`, which exists to
## make a pool-dry failure say WHY rather than just that.

import std / [tables, sets, assertions, algorithm, strutils, os]
import symparser
import nifcore, nifcdecl
import asmslots, machinedesc, analyser, planer, programs, abi
import "../arm/machine_m"
import layout, asmbuf, typenav, regbind, context
import diag, asmcommon, typeutil, constdata, mirrors, select


# ── emit-time temp allocation (step-3 merged value core) ─────────────────────
# The merged emitter DECIDES expression registers at the point of emission
# (vmgen-style dest threading) instead of reading a pre-pass plan. Register
# freeness is DERIVED per pick from the live state the emitter already owns —
# RegBind bindings, the pre-pass homes (symPos, immutable per proc), and the
# call seals — the same filter discipline `pickStagingScratch` has always used.
# No second pool-set state machine, hence no walk-synchronization invariant.
# Homes for named locals/params remain the decl-only allocator pre-pass.

proc regHoldsHome*(g: var CodeGen; r: Reg): bool =
  ## A named local/param is homed in `r` (a pre-pass decision, immutable for the
  ## whole proc — steals/demotes resolve before emission starts). Served from the
  ## cached mask: a full `symPos` scan per query made emission quadratic in proc size.
  if g.plan.homesDirty: rebuildHomes(g.plan)
  r in g.plan.homeRegs

proc fregHoldsHome*(g: var CodeGen; f: FReg): bool =
  ## The SIMD twin of `regHoldsHome`.
  if g.plan.homesDirty: rebuildHomes(g.plan)
  f in g.plan.homeFRegs

when not defined(arkhamNoNarrowHomes):
  let nhRegs = getEnv("ARKHAM_NH_REGS", "*")
    ## `ARKHAM_NH_REGS`: which registers the narrow filter may NEWLY admit (ones the
    ## `regHoldsHome` union would refuse). "*" = all; otherwise a comma-separated list
    ## of `Reg` names. Bisecting the crash down to one register inside one proc.
  proc nhRegAllowed*(r: Reg; isHome: bool): bool =
    if not isHome: return true            # not a home at all — nothing to decide
    if nhRegs == "*": return true
    for it in nhRegs.split(','):
      if it == $r: return true
    false
else:
  proc nhRegAllowed*(r: Reg; isHome: bool): bool {.inline.} = not isHome

proc regFreeForTemp*(g: var CodeGen; r: Reg): bool =
  ## May the merged emitter hand `r` out as an expression temp right now? Not
  ## picked-but-unbound (the reserve→bind gap), not pinned to an in-flight call
  ## (sealed), not a live accumulator, not carrying any named binding (a local
  ## in scope or a temp in flight), not a home.
  ##
  ## The reservation it asks about is `rawHomeRegs`, NOT the old whole-proc
  ## `regHoldsHome` union — the union was the largest single reason a temp fell
  ## through to a callee-saved register (`-d:arkhamTempDbg`: 3.05 of the ~5.75
  ## volatiles refused at each fall-through, ahead of a live binding at 1.51 and the
  ## reserve->bind gap at 1.12), and the pushes those fall-throughs cause were 3.82 %
  ## of all executed instructions.
  ##
  ## Retiring it took four fixes, and each one was a place where a LIVE value sat in a
  ## register carrying no `rb` binding, so `isBound` answered "free":
  ##
  ##  1. a by-reference aggregate param had NO declaration at all — its pointer was
  ##     `mov`'d into the home and every field access named the bare register
  ##     (`emRegAggrPtrVar` + `emPtrFieldMemSym`);
  ##  2. a RELOCATED param's home was left unbound on purpose, "for the epilogue
  ##     pops" — and a nimony `var T` is a plain `(ptr T)`, so that was MOST pointer
  ##     params (`emRegLocalVar` in `emitParamMoves`; `framePop` kills before popping);
  ##  3. the hidden indirect-result pointer (`synth("retptr.0")`);
  ##  4. a DIVERGING call's marshalling `(kill …)`s a still-live home, because `rb` is
  ##     linear and cannot say "this path is not taken" (`restoreBindings`).
  ##
  ## Raw pointer operands per nifbench build: **2956 -> 45**, and the 45 are the fixed
  ## rdi/rsi/rdx of the self-contained `mem*` sequences, which allocate no temps.
  ## `-d:arkhamNoNarrowHomes` restores the union; `-d:arkhamHomeAudit` prints every
  ## register the narrow filter admits that the union would refuse, and `ARKHAM_NH` /
  ## `ARKHAM_NH_REGS` narrow it to named procs / registers, which is how each of the
  ## four shapes above was bisected out of a whole-program segfault.
  ## A MIRROR binding does not occupy the register (`RegMapping` rule 1: an
  ## observation, never a reservation). It is a value that also still lives in
  ## memory, so handing the register out costs nothing but the forwarding — and
  ## the taker's own `bindTemp`/`(rebind …)` retires the mirror as it writes.
  ## Refusing it here would make forwarding able to cause an out-of-registers,
  ## which is the one thing this must never do.
  result = r notin g.pickedRegs and not g.plan.isSealed(r) and not g.rb.isAccum(r) and
    (not g.rb.isBound(r) or g.rb.isMirror(r)) and
    (if g.narrowHomes: r notin g.rawHomeRegs and nhRegAllowed(r, g.regHoldsHome(r))
     else: not g.regHoldsHome(r))
  when defined(arkhamHomeAudit):
    # Every register the narrow filter ADMITS but the old union would have refused:
    # each one must be a home whose symbol is provably not live here, i.e. `rb` would
    # have told us. Printing the symbol names living there is how the missing raw-home
    # shapes were enumerated (a `(ptr object)` param read raw is the classic one).
    if result and g.narrowHomes and g.regHoldsHome(r):
      var who = ""
      for name, pos in g.plan.symPos:
        let l = g.plan.planned(pos)
        if l.kind == InReg and l.r == r:
          who.add (if who.len > 0: "," else: "") & name & ":" & $l.typ.kind &
                  (if l.typ.size > 0: "/" & $l.typ.size else: "")
      stderr.writeLine "HOMEAUDIT " & g.curProcName & " " & $r & " admits [" & who & "]"

template forEachVolatileTempCand(g: var CodeGen; r, body: untyped) =
  ## The volatile GPRs `pickTempReg` may hand out, in preference order, BEFORE the
  ## callee-saved fallback. `intTempRegs` is `r10` ALONE on x86-64, so the second
  ## simultaneously-live expression temp went straight to a callee-saved register —
  ## a push and a pop in a prologue that may run millions of times — while rdi, rsi,
  ## r8, r9, rcx and rdx sat idle. Measured: `tokenWidth`, a CALL-FREE leaf, pushes
  ## rbx and r12 for `tmp2`/`tmp4` with five volatiles free; its push/pop is 28.8 %
  ## of its own executed instructions.
  ##
  ## SAFETY is the same class as `r10`'s, not a new one. `r10` is itself a
  ## caller-saved register in `x64ClobbersGpr`, so "an expression temp does not
  ## survive a call" is already a load-bearing invariant of this pool (a temp that
  ## must outlive a call comes from `pickHeldReg`, callee-saved only). Adding more
  ## volatiles cannot break an invariant the first candidate already relies on, and
  ## `regFreeForTemp` still refuses anything picked, sealed (an in-flight call's
  ## marshalling), bound, accumulating, or hosting a named home.
  ##
  ## The two FIXED-ROLE volatiles are the exception, and they are gated on the
  ## analyser's whole-proc facts: rdx is destroyed by `idiv`, rcx by a variable
  ## shift (and by `rep movs`, which only ever runs inside a call — where no temp
  ## is live anyway). A proc that contains neither has no second use for them.
  block:
    for r in g.md.intTempRegs: body            # r10
    for r in g.md.intLocalTempRegs: body       # rdi, rsi, r8, r9 — no fixed role
    if g.md.divRemReg != NoReg and not g.plan.divRegClobbered:
      let r = g.md.divRemReg; body
    if g.md.shiftCountReg != NoReg and not g.plan.shiftRegClobbered:
      let r = g.md.shiftCountReg; body
    # R11, the staging bridge, is NOT here — TRIED AND REVERTED. Adding it last (only
    # where the alternative is a callee-saved push and pop) looks free, because
    # `pickStagingScratch` has a callee-saved totality backstop of its own. It is not:
    # `tests/arkham/addr_chain_depth` then dies with "no staging register available
    # for a late memory-load address in proc chain.0", because that backstop asks
    # `regFreeForTemp`, which refuses every callee-saved register via `regHoldsHome`.
    # So the union blocks the temp pool AND the staging fallback; R11 only becomes
    # spare once register-homed params carry an `rb` binding. One root cause, two
    # symptoms — see `regFreeForTemp`.

proc tempCensus*(g: var CodeGen): string =
  ## Why every candidate was refused, in `pickTempReg`'s own order — the temp-pool
  ## twin of `stagingCensus`. `pickTempReg` returning `NoReg` means the register
  ## file is FULL, and "genuinely full" and "a filter is too coarse" want opposite
  ## fixes; only naming the refusing filter per register tells them apart.
  result = ""
  forEachVolatileTempCand(g, r):
    result.add "\n    " & $r & ": "
    if r in g.pickedRegs: result.add "picked (reserve->bind gap)"
    elif g.plan.isSealed(r): result.add "sealed (in-flight call)"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBound(r): result.add "bound " & g.rb.boundName(r)
    elif g.regHoldsHome(r): result.add "HOME UNION (per-proc, not liveness)"
    else: result.add "FREE (unreachable)"
  for r in g.md.intCalleeSaved:
    result.add "\n    " & $r & ": "
    if r in g.pickedRegs: result.add "picked (reserve->bind gap)"
    elif g.plan.isSealed(r): result.add "sealed (in-flight call)"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBound(r): result.add "bound " & g.rb.boundName(r)
    elif g.regHoldsHome(r): result.add "HOME UNION (per-proc, not liveness)"
    else: result.add "FREE (unreachable)"

when defined(arkhamTempDbg):
  ## `-d:arkhamTempDbg`: when `pickTempReg` falls through the WHOLE volatile pool and
  ## takes a callee-saved register — a push and a pop — which filter refused each
  ## volatile? "Out of registers" and "a filter is too coarse" need opposite fixes,
  ## and only this tells them apart. It is what showed that `regHoldsHome` (the
  ## per-proc union) refuses 3.05 of the ~5.75 candidates at every fall-through.
  ## `arkham.nim` calls `dumpTempStats` once per module at exit.
  var tempRefusals*: array[5, int]   ## picked, sealed, accum, bound, home
  var tempFallbacks*: int
  var tempVolatileHits*: int
  proc dumpTempStats*() =
    stderr.writeLine "TEMPSTATS volatileHits=" & $tempVolatileHits &
      " calleeFallbacks=" & $tempFallbacks &
      " refusedBy picked=" & $tempRefusals[0] & " sealed=" & $tempRefusals[1] &
      " accum=" & $tempRefusals[2] & " bound=" & $tempRefusals[3] &
      " home=" & $tempRefusals[4]

proc pickTempReg*(g: var CodeGen): Reg =
  ## An expression-temp GPR: the volatile temp pool first, then a callee-saved
  ## register (recorded in `plan.usedCallee` so the prologue saves it — the frame
  ## is finalized AFTER body emission in the merged core). `NoReg` when every
  ## candidate is live; the caller then mints a spill slot (`mintSpillName` +
  ## the backend's produce-into path), keeping temp allocation total exactly
  ## like the old `reserveTmp` fallback.
  forEachVolatileTempCand(g, r):
    if regFreeForTemp(g, r):
      when defined(arkhamTempDbg): inc tempVolatileHits
      return r
  when defined(arkhamTempDbg):
    # Charge each refused volatile to the FIRST filter that rejected it — the order
    # `regFreeForTemp` itself evaluates them in.
    inc tempFallbacks
    forEachVolatileTempCand(g, r):
      if r in g.pickedRegs: inc tempRefusals[0]
      elif g.plan.isSealed(r): inc tempRefusals[1]
      elif g.rb.isAccum(r): inc tempRefusals[2]
      elif g.rb.isBound(r): inc tempRefusals[3]
      elif g.regHoldsHome(r): inc tempRefusals[4]
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r):
      g.plan.usedCallee.incl r
      return r
  NoReg

proc tempPoolDry*(g: var CodeGen): bool =
  ## Would `pickTempReg` fail right now? Same census, no side effect — it must
  ## not mark a callee-saved register `usedCallee` (that would add a push/pop for
  ## a register we then decline to take). For callers that can serve a value from
  ## its existing home and only want a temp when one is genuinely free.
  forEachVolatileTempCand(g, r):
    if regFreeForTemp(g, r): return false
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r): return false
  true

proc pickFTempReg*(g: var CodeGen): FReg =
  ## The SIMD twin of `pickTempReg`: volatile float pool first, then the
  ## callee-saved float pool (empty on x86-64 SysV).
  for f in g.md.floatTempRegs:
    if f notin g.pickedFRegs and not g.rb.isSealedF(f) and
       (g.rb.boundFName(f).len == 0 or g.rb.isFMirror(f)) and
       not g.rb.isBoundFTmp(f) and not g.fregHoldsHome(f):
      if f in g.md.floatCalleeSavedSet: g.plan.usedCalleeF.incl f
      return f
  NoFReg

proc pickHeldReg*(g: var CodeGen): Reg =
  ## A SURVIVOR scratch: must outlive a call, so callee-saved only. `NoReg`
  ## when the callee-saved file is fully live — the caller either spills the
  ## (re-derivable) value to a `heldN.0` slot or fails loudly; demoting a local
  ## mid-emission is impossible in the merged core (its uses are already
  ## emitted), and the corpus needed that demotion exactly once.
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r):
      g.plan.usedCallee.incl r
      return r
  NoReg

proc mintSpillName*(g: var CodeGen; prefix: string): string =
  ## A fresh emit-time spill-slot name (`etmp`/`eftmp`/`held` + counter). The
  ## backend declares the `(var :name (s) T)` inline at first use — mid-body
  ## slot decls are legal nifasm (the aggtmp constructor temps already rely on
  ## that) — and flags `plan.hasStackVars` so the frame `sub` is emitted when the
  ## prologue is finalized.
  result = synth(prefix) & $g.emitTmpSpills & ".0"
  inc g.emitTmpSpills
  g.plan.hasStackVars = true