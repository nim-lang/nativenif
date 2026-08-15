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

import std / [tables, assertions]
import machinedesc

type
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
  rb.regLocal[r] = name
  rb.boundTemps.incl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r

proc takeScratch*(rb: var RegBind; r: Reg): string =
  ## Release a scratch binding made by `bindScratch`: returns the name whose
  ## `(kill …)` the caller must emit, or "" when `r` carries no temp binding
  ## (safe on every `giveBack`, whether or not the reg was a bound temp).
  result = ""
  if r in rb.boundTemps:
    result = rb.regLocal[r]
    rb.regLocal.del r
    rb.boundTemps.excl r
    rb.regBindPtr.excl r

proc takeBinding*(rb: var RegBind; r: Reg): string =
  ## Remove WHATEVER binding `r` carries (local, param or temp): returns the name
  ## whose `(kill …)` the caller must emit, or "". Also clears a stale
  ## `regBindPtr` bit even when no binding exists.
  result = rb.regLocal.getOrDefault(r, "")
  if result.len > 0: rb.regLocal.del r
  rb.boundTemps.excl r
  rb.regBindPtr.excl r

proc takeBindingIf*(rb: var RegBind; r: Reg; name: string): bool =
  ## Remove `r`'s binding only when it still IS `name` (it may have been rebound
  ## to a later tenant meanwhile, which already released this one). Returns
  ## whether it was removed — the caller emits `(kill name)` on true.
  result = rb.regLocal.getOrDefault(r, "") == name
  if result:
    rb.regLocal.del r
    rb.boundTemps.excl r
    rb.regBindPtr.excl r

proc bindLocal*(rb: var RegBind; r: Reg; name: string; isPtr: bool) =
  ## `r` becomes the register home of the named local `name` for the current
  ## scope (the caller emitted the `(var :name (reg) T)` decl, after killing the
  ## previous tenant via `takeBinding`).
  assert rb.scopeLocals.len > 0, "arkham: bindLocal outside any scope"
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r
  rb.scopeLocals[^1].add (name: name, reg: r)

proc bindParam*(rb: var RegBind; r: Reg; name: string) =
  ## `r` carries the register-resident parameter `name` (bound by the proc
  ## signature itself, so there is no decl to emit and no scope entry — the
  ## binding dies at the param's last use or the first call, not at scope exit).
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  rb.regBindPtr.excl r

proc rebindLocal*(rb: var RegBind; r: Reg; name: string; isPtr: bool) =
  ## Re-establish `r`'s binding to the already-declared local `name` (the caller
  ## emitted the zero-machine-code `(rebind …)`, which auto-kills the transient
  ## tenant). No scope entry — the local's declaring scope already tracks it.
  ## Keeps `regBindPtr` in sync with the retype (the pre-RegBind code left it
  ## stale here, so a pointer-temp retyped to `(i 64)` kept its nil-fits bit).
  rb.regLocal[r] = name
  rb.boundTemps.excl r
  if isPtr: rb.regBindPtr.incl r else: rb.regBindPtr.excl r

# ── float transitions (the SIMD twins) ──────────────────────────────────────

proc freshFTmpName*(rb: var RegBind): string =
  result = synth("ftmp") & $rb.ftmpBindCount & ".0"
  inc rb.ftmpBindCount

proc bindFScratch*(rb: var RegBind; f: FReg; name: string) =
  rb.fregLocal[f] = name
  rb.boundFTmps.incl f

proc takeFScratch*(rb: var RegBind; f: FReg): string =
  ## Returns the name to `(kill …)`, or "" when `f` carries no temp binding.
  result = ""
  if f in rb.boundFTmps:
    result = rb.fregLocal[f]
    rb.fregLocal.del f
    rb.boundFTmps.excl f

proc bindFLocal*(rb: var RegBind; f: FReg; name: string) =
  assert rb.scopeFLocals.len > 0, "arkham: bindFLocal outside any scope"
  rb.fregLocal[f] = name
  rb.boundFTmps.excl f
  rb.scopeFLocals[^1].add (name: name, f: f)

proc takeFBindingIf*(rb: var RegBind; f: FReg; name: string): bool =
  result = rb.fregLocal.getOrDefault(f, "") == name
  if result:
    rb.fregLocal.del f
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
    if rb.takeBindingIf(it.reg, it.name): result.gprs.add it.name
  for it in rb.scopeFLocals.pop():
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
