#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The single owner of the emitter's register-binding state: which physical
## register currently carries which typed nifasm name, whether that binding is
## a transient scratch temp or a scope-tracked local, whether it is
## pointer-typed, plus the scope stacks that drive the end-of-scope `kill`s and
## the seal sets a staging pick must route around.
##
## The fields are deliberately NOT exported: every mutation goes through the
## transition procs below, each of which updates ALL the tables involved as one
## atomic step. The historic bug pattern this closes (see the bugfix taxonomy
## behind `design.md`) was an ad-hoc `regLocal.del` that forgot `boundTemps`,
## or a rebind that left `regBindPtr` stale — the tables could only be kept
## consistent by discipline at every one of ~40 mutation sites.
##
## Emission stays in the backends: the `(rebind …)`/`(var …)`/`(kill …)`
## asm-NIF trees are arch-tagged and need the type emitters, so a REMOVING
## transition *returns* the name whose `(kill …)` the caller must emit (or a
## bool when the caller already knows the name). A returned name is a real
## obligation — dropping it desynchronizes nifasm's binding checker from this
## table, which nifasm then reports on the next use of the register.
##
## MODEL: proofs/arkham_bindings.tla — `bindTemp`/`killTemp`/`StartEmit`
## correspond to `bindScratch`/`takeScratch`/`resetProc`. The transitions here
## preserve that model's semantics; they only centralize the bookkeeping.
##
## It also owns the `RegMapping` (below): which registers still MIRROR a value
## that lives in memory. That belongs here and nowhere else for the reason the
## paragraph above gives — a mirror dies the moment its register is rebound, and
## a table that has to be invalidated by hand at every one of the ~40 mutation
## sites is precisely the bug class this module exists to close. Keeping it in
## the same object makes the invalidation part of each transition instead.

import std / [tables, assertions]
import machinedesc, asmslots

type
  MirrorKind* = enum
    ## What a register still holds a copy of. Both are OBSERVATIONS about a
    ## register the emitter has already released — never a claim on it.
    MirrorValue        ## `r` holds the VALUE of the memory-homed symbol `name`
    MirrorAddr         ## `r` holds `&name` (a global / thread-local / slot address)

  Mirror* = object
    name*: string      ## the symbol whose value/address this register mirrors
    slot*: AsmSlot     ## the width+class it was mirrored at (`MirrorValue`)
    kind*: MirrorKind

  RegMapping* = object
    ## THE store-forwarding table: "the value of `x` is still in a register,
    ## even though `x`'s home is a stack slot".
    ##
    ## Three rules make it sound, and all three are structural rather than
    ## discipline:
    ##
    ## 1. **An entry is an observation, never a reservation.** A mirrored
    ##    register stays fully allocatable; every freeness filter must answer
    ##    exactly as it did before (`regFreeForTemp`/`regHoldsLiveLocal` consult
    ##    `isMirror` for that). Handing the register out simply drops the entry.
    ##    So forwarding can never cause an out-of-registers — see design.md on
    ##    why the emitter must not grow a second allocator.
    ## 2. **An entry keeps its nifasm binding alive.** The register still carries
    ##    the `tmpN.0` name it was bound with, so a read of it is a typed,
    ##    checked symbol (`emReg`), and any code that writes the register without
    ##    going through a transition is REJECTED by nifasm's binding checker
    ##    instead of silently clobbering the mirror. The taker kills the name
    ##    (`releaseStaleName`) exactly as it already does for a dead param.
    ## 3. **An entry is created only where the value provably cannot be modified
    ##    again by its previous owner** — i.e. at the release point of a store's
    ##    source register, not at an arbitrary point mid-expression.
    ##
    ## Invalidation is the whole game. Register events are free (they are the
    ## transitions below). The rest is the emitters' obligation, and it is
    ## deliberately coarse: a store to `name` re-keys it, a CALL or an `(instr)`
    ## row clears everything, and every label DEFINITION clears everything —
    ## which is what makes structured control flow a non-issue, since arkham
    ## emits no merge point that is not a label (`emLab`).
    mirror: Table[Reg, Mirror]
    ofVal: Table[string, Reg]         ## name → the GPR mirroring its value
    ofAddr: Table[string, Reg]        ## name → the GPR mirroring its address
    fmirror: Table[FReg, Mirror]      ## the SIMD twin (float values)
    fofVal: Table[string, FReg]

  RegBind* = object
    regLocal: Table[Reg, string]      ## reg → the named local/param/temp bound to it
                                      ## (`emReg` emits the name, not the raw `(reg)`)
    boundTemps: set[Reg]              ## regs whose `regLocal` entry is a transient
                                      ## scratch temp (`bindScratch`), NOT a steal-able
                                      ## local; released by `takeScratch`
    regBindPtr: set[Reg]              ## regs whose current binding is POINTER-typed:
                                      ## a `(nil)` value only fits such a binding
                                      ## (x64 `emitValue2` NilC consults this)
    fregLocal: Table[FReg, string]    ## the SIMD twin of `regLocal`
    boundFTmps: set[FReg]             ## the SIMD twin of `boundTemps`
    tmpBindCount: int                 ## per-proc fresh-name counter for `tmpN.0`
    ftmpBindCount: int                ## per-proc fresh-name counter for `ftmpN.0`
    scopeLocals: seq[seq[tuple[name: string, reg: Reg]]]
                                      ## per-scope register locals to `kill` on exit
    scopeFLocals: seq[seq[tuple[name: string, f: FReg]]]
    liveAccums: set[Reg]              ## arg/return regs holding an in-flight expression
                                      ## accumulator (a genInto target that is not a
                                      ## named local, so absent from `regLocal`); a
                                      ## staging pick must avoid these
    sealedF: set[FReg]                ## SIMD arg regs pinned to an in-flight value (a
                                      ## float arg being marshalled, a held staging reg);
                                      ## the float analogue of `liveAccums`/`plan.sealed`
    m: RegMapping                     ## store-forwarding mirrors (see `RegMapping`).
                                      ## Every transition below drops the entries its
                                      ## register invalidates — that coupling is the
                                      ## reason this lives here and not beside `Plan`.

# ── the mirror map ──────────────────────────────────────────────────────────
# Kept ahead of the transitions so each of them can drop what it invalidates.

proc dropMirror*(rb: var RegBind; r: Reg): string {.discardable.} =
  ## `r` is being written / rebound / handed out: whatever it mirrored is gone,
  ## and so is the binding the mirror was keeping alive. Returns the name whose
  ## `(kill …)` the caller must emit, "" when `r` held no mirror.
  ##
  ## The three callers that may DISCARD it are the ones that follow with a
  ## `(rebind …)`, which auto-kills the tenant on the nifasm side; every other
  ## caller owes the kill, exactly like `takeBinding`'s result.
  result = ""
  let e = rb.m.mirror.getOrDefault(r)
  if e.name.len > 0:
    case e.kind
    of MirrorValue:
      if rb.m.ofVal.getOrDefault(e.name, NoReg) == r: rb.m.ofVal.del e.name
    of MirrorAddr:
      if rb.m.ofAddr.getOrDefault(e.name, NoReg) == r: rb.m.ofAddr.del e.name
    rb.m.mirror.del r
    result = rb.regLocal.getOrDefault(r, "")
    rb.regLocal.del r
    rb.regBindPtr.excl r

proc dropFMirror*(rb: var RegBind; f: FReg): string {.discardable.} =
  result = ""
  let e = rb.m.fmirror.getOrDefault(f)
  if e.name.len > 0:
    if rb.m.fofVal.getOrDefault(e.name, NoFReg) == f: rb.m.fofVal.del e.name
    rb.m.fmirror.del f
    result = rb.fregLocal.getOrDefault(f, "")
    rb.fregLocal.del f

proc dropMirrorsOf*(rb: var RegBind; name: string): tuple[gprs, fprs: seq[string]] {.discardable.} =
  ## `name` was STORED to (or went out of scope): every register mirroring its
  ## VALUE is stale. Its ADDRESS is not — an object does not move — so `ofAddr`
  ## survives a store and ends only at a register event or a whole-map clear.
  result = (gprs: newSeq[string](), fprs: newSeq[string]())
  let r = rb.m.ofVal.getOrDefault(name, NoReg)
  if r != NoReg:
    let dead = rb.dropMirror(r)
    if dead.len > 0: result.gprs.add dead
  let f = rb.m.fofVal.getOrDefault(name, NoFReg)
  if f != NoFReg:
    let dead = rb.dropFMirror(f)
    if dead.len > 0: result.fprs.add dead

proc takeMirrors*(rb: var RegBind): tuple[gprs, fprs: seq[string]] =
  ## Every mirror dies. The emitters call this at each point where what a use
  ## reads no longer follows from the instructions just emitted: a label
  ## DEFINITION (hence every merge point and every back edge — arkham emits no
  ## merge that is not a label, which is what makes structured control flow a
  ## non-issue here), a call, an `(instr …)` row. Returns the names to `(kill …)`.
  ## Total and cheap: a missing invalidation is a miscompile, so forgetting is
  ## the default and remembering is the special case.
  result = (gprs: newSeq[string](), fprs: newSeq[string]())
  for r in rb.m.mirror.keys:
    let nm = rb.regLocal.getOrDefault(r, "")
    if nm.len > 0:
      result.gprs.add nm
      rb.regLocal.del r
      rb.regBindPtr.excl r
  for f in rb.m.fmirror.keys:
    let nm = rb.fregLocal.getOrDefault(f, "")
    if nm.len > 0:
      result.fprs.add nm
      rb.fregLocal.del f
  rb.m.mirror.clear()
  rb.m.ofVal.clear()
  rb.m.ofAddr.clear()
  rb.m.fmirror.clear()
  rb.m.fofVal.clear()

proc clearMirrors*(rb: var RegBind) =
  ## `takeMirrors` for the per-proc reset, where there is no buffer left to emit
  ## a `(kill …)` into and the bindings die with the proc anyway.
  rb.m.mirror.clear()
  rb.m.ofVal.clear()
  rb.m.ofAddr.clear()
  rb.m.fmirror.clear()
  rb.m.fofVal.clear()

proc mirrorValue*(rb: var RegBind; r: Reg; name: string; slot: AsmSlot) =
  ## `r` still carries the value just stored into `name`'s stack home. The caller
  ## has released `r` — it is allocatable again — but did NOT kill its binding,
  ## which is what keeps the register readable as a typed name and makes any
  ## unsanctioned write to it a nifasm error rather than a silent clobber.
  ##
  ## The caller must have retired whatever `r` and `name` mirrored before
  ## (`dropMirror` / `dropMirrorsOf`) and emitted those `(kill …)`s; the asserts
  ## below are that contract, not a defensive fallback.
  assert not rb.m.mirror.hasKey(r), "arkham: mirrorValue over a live mirror"
  assert rb.regLocal.hasKey(r), "arkham: mirrorValue on an unbound register"
  assert not rb.m.ofVal.hasKey(name), "arkham: two value mirrors of " & name
  rb.boundTemps.excl r                  # a mirror is not a temp in flight
  rb.m.mirror[r] = Mirror(name: name, slot: slot, kind: MirrorValue)
  rb.m.ofVal[name] = r

proc mirrorFValue*(rb: var RegBind; f: FReg; name: string; slot: AsmSlot) =
  assert not rb.m.fmirror.hasKey(f), "arkham: mirrorFValue over a live mirror"
  assert rb.fregLocal.hasKey(f), "arkham: mirrorFValue on an unbound register"
  assert not rb.m.fofVal.hasKey(name), "arkham: two value mirrors of " & name
  rb.boundFTmps.excl f
  rb.m.fmirror[f] = Mirror(name: name, slot: slot, kind: MirrorValue)
  rb.m.fofVal[name] = f

proc mirrorAddr*(rb: var RegBind; r: Reg; name: string; slot: AsmSlot) =
  ## `r` still holds `&name` — the materialized address of a global / thread-local
  ## whose access would otherwise re-derive it (`adrp`+`add` on AArch64, a TLV call
  ## for a Darwin thread-local). Unlike a value mirror this survives a STORE to
  ## `name`: the object does not move. Only a register event or a whole-map clear
  ## ends it.
  assert not rb.m.mirror.hasKey(r), "arkham: mirrorAddr over a live mirror"
  assert rb.regLocal.hasKey(r), "arkham: mirrorAddr on an unbound register"
  assert not rb.m.ofAddr.hasKey(name), "arkham: two address mirrors of " & name
  rb.boundTemps.excl r
  rb.m.mirror[r] = Mirror(name: name, slot: slot, kind: MirrorAddr)
  rb.m.ofAddr[name] = r

proc sameShape(a, b: AsmSlot): bool {.inline.} =
  ## Is a value mirrored at slot `a` usable where slot `b` is wanted? Width and
  ## class must agree exactly: a narrower store leaves the register's high bits
  ## undefined, and a class change would rename the value under a type nifasm
  ## checks. (The two are the SAME `AsmSlot` in the common case — both come from
  ## the symbol's own home — so this only ever rejects an unusual consumer.)
  a.cls == b.cls and a.size == b.size

proc valueMirror*(rb: RegBind; name: string; want: AsmSlot): Reg =
  ## The GPR still holding `name`'s value, or `NoReg`.
  result = rb.m.ofVal.getOrDefault(name, NoReg)
  if result != NoReg and not sameShape(rb.m.mirror[result].slot, want):
    result = NoReg

proc fvalueMirror*(rb: RegBind; name: string; want: AsmSlot): FReg =
  result = rb.m.fofVal.getOrDefault(name, NoFReg)
  if result != NoFReg and not sameShape(rb.m.fmirror[result].slot, want):
    result = NoFReg

proc addrMirror*(rb: RegBind; name: string): Reg =
  rb.m.ofAddr.getOrDefault(name, NoReg)

# `r` carries a mirror binding and NOTHING else: still allocatable (every freeness
# filter must let it through — rule 1), but its stale name has to be killed
# (`releaseStaleName`) before the new owner writes it.
proc isMirror*(rb: RegBind; r: Reg): bool {.inline.} = rb.m.mirror.hasKey(r)
proc isFMirror*(rb: RegBind; f: FReg): bool {.inline.} = rb.m.fmirror.hasKey(f)
proc mirrorCount*(rb: RegBind): int {.inline.} = rb.m.mirror.len + rb.m.fmirror.len

# ── queries ─────────────────────────────────────────────────────────────────

proc boundName*(rb: RegBind; r: Reg): string {.inline.} =
  ## The name bound to `r`, or "" when `r` is raw.
  rb.regLocal.getOrDefault(r, "")

proc isBound*(rb: RegBind; r: Reg): bool {.inline.} = rb.regLocal.hasKey(r)
proc isBoundTemp*(rb: RegBind; r: Reg): bool {.inline.} = r in rb.boundTemps
proc isPtrBound*(rb: RegBind; r: Reg): bool {.inline.} = r in rb.regBindPtr

proc boundFName*(rb: RegBind; f: FReg): string {.inline.} =
  rb.fregLocal.getOrDefault(f, "")

proc isBoundFTmp*(rb: RegBind; f: FReg): bool {.inline.} = f in rb.boundFTmps

iterator gprBindings*(rb: RegBind): (Reg, string) =
  for r, name in rb.regLocal: yield (r, name)

# ── GPR transitions ─────────────────────────────────────────────────────────

proc freshTmpName*(rb: var RegBind; prefix = "tmp"): string =
  ## A fresh per-proc scratch-binding name (`tmpN.0`; `fntmp` for an indirect
  ## call target), in arkham's synthetic namespace (see `SynthMark`).
  result = synth(prefix) & $rb.tmpBindCount & ".0"
  inc rb.tmpBindCount

proc bindScratch*(rb: var RegBind; r: Reg; name: string; isPtr: bool) =
  ## `r` now carries the transient scratch binding `name` (the caller emitted the
  ## `(rebind …)`, which auto-kills any previous tenant on the nifasm side).
  rb.dropMirror r
  rb.regLocal[r] = name
  rb.boundTemps.incl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r

proc takeScratch*(rb: var RegBind; r: Reg): string =
  ## Release a scratch binding made by `bindScratch`: returns the name whose
  ## `(kill …)` the caller must emit, or "" when `r` carries no temp binding
  ## (safe on every `giveBack`, whether or not the reg was a bound temp).
  ##
  ## A MIRROR binding is released here too, and it must be: a mirror is a temp
  ## binding that was handed back without being killed, so every ordinary release
  ## path has to be able to end it — otherwise `regLocal` keeps a name no entry
  ## tracks and `emReg` would emit it for an unrelated value. The sites that WANT
  ## to leave a mirror behind therefore do not go through `giveBack`; they call
  ## the backend's mirror-release helper instead.
  result = ""
  if r in rb.boundTemps or rb.m.mirror.hasKey(r):
    result = rb.regLocal.getOrDefault(r, "")
    rb.dropMirror r
    rb.regLocal.del r
    rb.boundTemps.excl r
    rb.regBindPtr.excl r

proc takeBinding*(rb: var RegBind; r: Reg): string =
  ## Remove WHATEVER binding `r` carries (local, param or temp): returns the name
  ## whose `(kill …)` the caller must emit, or "". Also clears a stale
  ## `regBindPtr` bit even when no binding exists.
  result = rb.regLocal.getOrDefault(r, "")
  if result.len > 0: rb.regLocal.del r
  rb.dropMirror r
  rb.boundTemps.excl r
  rb.regBindPtr.excl r

proc takeBindingIf*(rb: var RegBind; r: Reg; name: string): bool =
  ## Remove `r`'s binding only when it still IS `name` (it may have been rebound
  ## to a later tenant meanwhile, which already released this one). Returns
  ## whether it was removed — the caller emits `(kill name)` on true.
  result = rb.regLocal.getOrDefault(r, "") == name
  if result:
    rb.regLocal.del r
    rb.dropMirror r
    rb.boundTemps.excl r
    rb.regBindPtr.excl r

proc bindLocal*(rb: var RegBind; r: Reg; name: string; isPtr: bool) =
  ## `r` becomes the register home of the named local `name` for the current
  ## scope (the caller emitted the `(var :name (reg) T)` decl, after killing the
  ## previous tenant via `takeBinding`).
  assert rb.scopeLocals.len > 0, "arkham: bindLocal outside any scope"
  rb.dropMirror r
  rb.dropMirrorsOf name
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r
  rb.scopeLocals[^1].add (name: name, reg: r)

proc bindParam*(rb: var RegBind; r: Reg; name: string) =
  ## `r` carries the register-resident parameter `name` (bound by the proc
  ## signature itself, so there is no decl to emit and no scope entry — the
  ## binding dies at the param's last use or the first call, not at scope exit).
  rb.dropMirror r
  rb.dropMirrorsOf name
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  rb.regBindPtr.excl r

proc rebindLocal*(rb: var RegBind; r: Reg; name: string; isPtr: bool) =
  ## Re-establish `r`'s binding to the already-declared local `name` (the caller
  ## emitted the zero-machine-code `(rebind …)`, which auto-kills the transient
  ## tenant). No scope entry — the local's declaring scope already tracks it.
  ## Keeps `regBindPtr` in sync with the retype (the pre-RegBind code left it
  ## stale here, so a pointer-temp retyped to `(i 64)` kept its nil-fits bit).
  rb.dropMirror r
  rb.dropMirrorsOf name
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r

# ── float transitions (the SIMD twins) ──────────────────────────────────────

proc freshFTmpName*(rb: var RegBind): string =
  result = synth("ftmp") & $rb.ftmpBindCount & ".0"
  inc rb.ftmpBindCount

proc bindFScratch*(rb: var RegBind; f: FReg; name: string) =
  rb.dropFMirror f
  rb.fregLocal[f] = name
  rb.boundFTmps.incl f

proc takeFScratch*(rb: var RegBind; f: FReg): string =
  ## Returns the name to `(kill …)`, or "" when `f` carries no temp binding.
  ## Releases a mirror binding too — see `takeScratch` for why every ordinary
  ## release path must be able to end one.
  result = ""
  if f in rb.boundFTmps or rb.m.fmirror.hasKey(f):
    result = rb.fregLocal.getOrDefault(f, "")
    rb.dropFMirror f
    rb.fregLocal.del f
    rb.boundFTmps.excl f

proc bindFLocal*(rb: var RegBind; f: FReg; name: string) =
  assert rb.scopeFLocals.len > 0, "arkham: bindFLocal outside any scope"
  rb.dropFMirror f
  rb.dropMirrorsOf name
  rb.fregLocal[f] = name
  rb.boundFTmps.excl f
  rb.scopeFLocals[^1].add (name: name, f: f)

proc takeFBindingIf*(rb: var RegBind; f: FReg; name: string): bool =
  result = rb.fregLocal.getOrDefault(f, "") == name
  if result:
    rb.fregLocal.del f
    rb.dropFMirror f
    rb.boundFTmps.excl f

# ── scopes ──────────────────────────────────────────────────────────────────

proc enterScope*(rb: var RegBind) =
  rb.scopeLocals.add @[]
  rb.scopeFLocals.add @[]

proc exitScope*(rb: var RegBind): tuple[gprs, fprs: seq[string]] =
  ## Close the current scope: unbind every register local declared in it that is
  ## STILL bound to its register (one whose register was rebound to a later local
  ## was already killed at that rebind). Returns the names whose `(kill …)` the
  ## caller must emit, in declaration order.
  result = (gprs: newSeq[string](), fprs: newSeq[string]())
  for it in rb.scopeLocals.pop():
    rb.dropMirrorsOf it.name          # its home is dead; nothing may forward from it
    if rb.takeBindingIf(it.reg, it.name): result.gprs.add it.name
  for it in rb.scopeFLocals.pop():
    rb.dropMirrorsOf it.name
    if rb.takeFBindingIf(it.f, it.name): result.fprs.add it.name

# ── accumulator / SIMD seals (staging picks must route around these) ────────

proc sealAccum*(rb: var RegBind; r: Reg) {.inline.} = rb.liveAccums.incl r
proc unsealAccums*(rb: var RegBind; rs: set[Reg]) {.inline.} =
  rb.liveAccums = rb.liveAccums - rs
proc isAccum*(rb: RegBind; r: Reg): bool {.inline.} = r in rb.liveAccums

proc sealF*(rb: var RegBind; f: FReg) {.inline.} = rb.sealedF.incl f
proc unsealF*(rb: var RegBind; f: FReg) {.inline.} = rb.sealedF.excl f
proc isSealedF*(rb: RegBind; f: FReg): bool {.inline.} = f in rb.sealedF

# ── per-proc reset ──────────────────────────────────────────────────────────

proc resetProc*(rb: var RegBind) =
  ## Fresh per-proc state: all bindings, scope stacks, seals and name counters.
  ## MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla — every
  ## per-proc table must be reset here or RegisterBindingsMatchLoc breaks.
  rb.regLocal.clear()
  rb.boundTemps = {}
  rb.regBindPtr = {}
  rb.fregLocal.clear()
  rb.boundFTmps = {}
  rb.scopeLocals = @[]
  rb.scopeFLocals = @[]
  rb.tmpBindCount = 0
  rb.ftmpBindCount = 0
  rb.liveAccums = {}
  rb.sealedF = {}
  rb.clearMirrors()
