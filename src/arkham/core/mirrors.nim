#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Store forwarding: the target-neutral half of the mirror map.
##
## After `mov [x], r` the value is in TWO places, and reading `x` back can use
## the register instead of the memory. The map records that, and — more
## importantly — every way it can stop being true: the register is rewritten,
## the memory is written by something else, a call clobbers it, or the name goes
## out of scope. Getting the invalidation right is the whole content here.

import std / [tables, sets, assertions, algorithm, strutils, os]
import symparser
import nifcore, nifcdecl
import asmslots, machinedesc, analyser, planer, programs, abi
import "../arm/machine_m"
import layout, asmbuf, typenav, regbind, context
import diag, asmcommon, typeutil, constdata


# ── store forwarding: the target-neutral half of the mirror map ─────────────
#
# The map itself lives in `RegBind` (see `RegMapping` there for the three rules
# that make it sound). What is here is the part that has to EMIT — a retired
# mirror owes a `(kill …)` — plus the two predicates that decide whether a value
# may be mirrored at all.

let forwardingOff* = existsEnv("ARKHAM_NO_FORWARD")
  ## A/B switch for the store-forwarding mirrors, in the shape the other measured
  ## optimizations use (`ARKHAM_NO_COPYINHERIT`, `ARKHAM_NO_CALLERSAVE`): with it
  ## set, no mirror is ever created and every read of a memory-homed value goes
  ## back to its slot.

proc emKill*(g: var CodeGen; name: string) {.inline.} =
  ## `(kill name)`. `KillX64` and `KillA64` are two spellings of ONE tag id, so
  ## the tree is identical on both targets and this needs no arch dispatch.
  g.ab.tree KillX64: g.ab.sym name

proc killMirror*(g: var CodeGen; r: Reg) =
  ## Retire `r`'s mirror and kill the binding it was keeping alive.
  let dead = g.rb.dropMirror(r)
  if dead.len > 0: g.emKill dead

proc killFMirror*(g: var CodeGen; f: FReg) =
  let dead = g.rb.dropFMirror(f)
  if dead.len > 0: g.emKill dead

proc killMirrorsOf*(g: var CodeGen; name: string) =
  ## `name` has been STORED to: whatever mirrored its value is stale now.
  let dead = g.rb.dropMirrorsOf(name)
  for nm in dead.gprs: g.emKill nm
  for nm in dead.fprs: g.emKill nm

proc killAllMirrors*(g: var CodeGen) =
  ## Every mirror dies. Called where what a use reads stops following from the
  ## instructions just emitted: a label DEFINITION (so every merge point and
  ## every back edge — arkham emits no merge that is not a label), a call, an
  ## `(instr …)` row, an inline sequence that writes memory.
  if g.rb.mirrorCount == 0: return
  let dead = g.rb.takeMirrors()
  for nm in dead.gprs: g.emKill nm
  for nm in dead.fprs: g.emKill nm

proc mirrorableReg*(g: CodeGen; r: Reg): bool {.inline.} =
  ## May `r` hold a mirror? ONLY the emitter's own temp pool and staging bridge.
  ##
  ## This is the one restriction that makes the whole mechanism safe rather than
  ## merely careful. A mirror is silently wrong the moment something writes the
  ## register without going through a `RegBind` transition, and most registers
  ## have structural RAW uses (ABI argument marshalling, the syscall registers,
  ## a frame push) that no transition sees. The pool and the bridge are the two
  ## classes where that cannot happen: `emReg` ASSERTS that every use of them is
  ## a typed binding, so every write to one is a `bindTemp`/`rebind` — and those
  ## drop the mirror. Machine-checked, not argued.
  r in g.md.intTempRegs or (g.md.stagingBridgeReg != NoReg and r == g.md.stagingBridgeReg)

proc mirrorableFReg*(g: CodeGen; f: FReg): bool {.inline.} =
  ## The SIMD twin: `emFReg` carries the same assert for `floatTempRegs`.
  f in g.md.floatTempRegs

proc mayMirror*(g: CodeGen; name: string): bool =
  ## May the value of the memory-homed `name` be forwarded from a register?
  ##
  ## Not when its ADDRESS IS TAKEN: a store through any pointer, and any callee
  ## handed one, can write it without naming it, and arkham has no points-to
  ## analysis to bound that. Every other memory-homed local is alias-immune by
  ## definition — which is exactly why this filter, and not a store classifier,
  ## is what keeps the invalidation rules finite (see `Plan.aliasable`).
  ##
  ## Not inside an open caller-save window either: there the authority on where a
  ## value is, is `callerSaveActive` (its save slot), and a second answer to the
  ## same question is how that mechanism's parallel-copy hazard would come back.
  name.len > 0 and not forwardingOff and
  name notin g.plan.aliasable and g.plan.callerSaveActive.len == 0

proc forwardOf*(g: CodeGen; home: Location): Location =
  ## Where the value of a memory home ACTUALLY is right now: a register that
  ## still mirrors it, or the home itself.
  ##
  ## The IMMEDIATE-READ door. The register comes back unowned (`isTemp = false`,
  ## not reserved), so the caller must consume it in the instruction it is about
  ## to emit and must not hold it across anything that could allocate — a mirror
  ## register IS allocatable, and the next `takeTmp` may hand out exactly it.
  ## Anything that lets the location ESCAPE to a caller uses `takeForwarded`.
  result = home
  if home.kind != NamedStack or forwardingOff: return
  if g.plan.callerSaveActive.len > 0: return    # the window owns this question
  let r = g.rb.valueMirror(home.name, home.typ)
  if r != NoReg: result = regLoc(r, home.typ)

proc takeForwarded*(g: var CodeGen; home: Location): Location =
  ## The OWNERSHIP-TRANSFER door: hand the mirroring register to the consumer as
  ## its own temp, exactly as if it had called `takeTmp` and loaded the value —
  ## minus the load. `isTemp` plus the `pickedRegs` reservation are what make
  ## that equivalence exact: the register is held for as long as the value is
  ## live and released by the consumer's own `freeVal`, so register pressure is
  ## what the unforwarded path would have had anyway. (Which is also why this is
  ## not the "reservation" `RegMapping` rule 1 forbids: the reservation belongs
  ## to the consumer's value, not to the mirror.)
  ##
  ## This is the door for every site whose `Location` outlives the next emitted
  ## instruction. The alternative — handing out an unowned register — is wrong in
  ## a way worth naming, because it looks right: the consumer holds the location,
  ## evaluates the OTHER operand, that evaluation legitimately takes the (free!)
  ## mirror register, and the held location now names a different value.
  ## `tests/arkham/float_special_values` compared a constant with itself.
  result = home
  if home.kind != NamedStack or forwardingOff: return
  if g.plan.callerSaveActive.len > 0: return
  let r = g.rb.valueMirror(home.name, home.typ)
  if r == NoReg or r in g.pickedRegs or g.plan.isSealed(r): return
  g.pickedRegs.incl r
  result = regLoc(r, home.typ, isTemp = true)

proc forwardFOf*(g: CodeGen; home: Location): Location =
  ## The SIMD twin of `forwardOf`.
  result = home
  if home.kind != NamedStack or forwardingOff: return
  if g.plan.callerSaveActive.len > 0: return
  let f = g.rb.fvalueMirror(home.name, home.typ)
  if f != NoFReg: result = fregLoc(f, home.typ)

proc takeFForwarded*(g: var CodeGen; home: Location): Location =
  ## The SIMD twin of `takeForwarded`.
  result = home
  if home.kind != NamedStack or forwardingOff: return
  if g.plan.callerSaveActive.len > 0: return
  let f = g.rb.fvalueMirror(home.name, home.typ)
  if f == NoFReg or f in g.pickedFRegs or g.rb.isSealedF(f): return
  g.pickedFRegs.incl f
  result = fregLoc(f, home.typ, isTemp = true)

proc mirrorStored*(g: var CodeGen; r: Reg; dst: Location): bool =
  ## `r` has just written its value into `dst`'s stack slot and is being
  ## released. Give the REGISTER back but keep the FACT: `dst`'s value is still
  ## in `r`, so the next read of it can be served from the register instead of
  ## reloading the slot — the store-forwarding this map exists for.
  ##
  ## Returns false when nothing may be mirrored here, and the caller then
  ## releases `r` the ordinary way. The conditions are all necessary:
  ##  * a mirrorable register (pool/bridge only — `mirrorableReg` is the whole
  ##    safety argument);
  ##  * a bound temp, since a mirror is read back BY ITS NAME;
  ##  * a binding whose type is the slot's type, or the register does not hold
  ##    what the slot holds (a wider binding means the store truncated).
  if dst.kind != NamedStack or not g.mayMirror(dst.name): return false
  if not g.mirrorableReg(r) or not g.rb.isBoundTemp(r): return false
  let bt = g.tmpBindTyp.getOrDefault(r)
  if bt.cls != dst.typ.cls or bt.size != dst.typ.size or bt.size == 0: return false
  # The store below this one already invalidated `dst.name` (`emitStoreLoc` /
  # `emScalarStore` are where that happens), so this normally finds nothing. It is
  # here anyway because `mirrorValue`'s one-mirror-per-name invariant is enforced
  # by an assert, and an assert is not a mechanism in a build without them.
  g.killMirrorsOf dst.name
  g.pickedRegs.excl r
  g.plan.unseal {r}
  g.rb.mirrorValue(r, dst.name, bt)
  true

proc mirrorAddrStored*(g: var CodeGen; r: Reg; asmName: string): bool =
  ## `r` holds `&asmName` and is being released with the address still in it.
  ## Keep it: on AArch64 a global's address costs `adrp`+`add` EVERY time it is
  ## needed (there is no PC-relative memory operand), so the second access to the
  ## same global in a straight-line region becomes a single `mov` off this.
  ##
  ## Unlike a value mirror this one survives a store to the global — an object
  ## does not move — so only a register event or a whole-map clear ends it.
  ##
  ## The caller owes the same proof `mirrorStored` gets for free from the store:
  ## that `r` still holds what it says. That is why this is NOT called from the
  ## address materialization but from the release of an lvalue whose address
  ## registers were provably only READ (see `freeLvalTemps2`'s `addrIntact`): the
  ## load form `mov base, [base]` reuses the base register as its destination,
  ## and a mirror created there would name the loaded value.
  if forwardingOff or asmName.len == 0: return false
  if not g.mirrorableReg(r) or not g.rb.isBoundTemp(r): return false
  if g.rb.addrMirror(asmName) != NoReg: return false     # already mirrored elsewhere
  g.pickedRegs.excl r
  g.plan.unseal {r}
  g.rb.mirrorAddr(r, asmName, addrSlot())
  true

proc mirrorFStored*(g: var CodeGen; f: FReg; dst: Location): bool =
  ## The SIMD twin. It matters more than its GPR sibling on x86-64: SysV has no
  ## callee-saved xmm at all, so `getSym` gives EVERY float local a stack home
  ## and every read of one is a reload.
  if dst.kind != NamedStack or not g.mayMirror(dst.name): return false
  if not g.mirrorableFReg(f) or not g.rb.isBoundFTmp(f): return false
  if dst.typ.size == 0: return false
  g.killMirrorsOf dst.name                       # see the GPR twin
  g.pickedFRegs.excl f
  g.rb.mirrorFValue(f, dst.name, dst.typ)
  true

proc paramName*(idx: int): string {.inline.} =
  ## The asm-NIF symbol for positional call parameter `idx`. nifasm scopes a
  ## symbol by its full name, so the ordinal has to live in the *name*: `p.0`
  ## and `p.1` are two names for the same thing to a reader and buy nothing
  ## here, whereas `pN.0` is unambiguous. `SynthMark` keeps the whole family out
  ## of the Leng namespace — see its doc comment for the bug that proved it must.
  result = synth("p") & $idx & ".0"

proc operandInReg*(g: var CodeGen; operand: Cursor; dest: Reg): bool =
  ## Does the (peeked, not consumed) `operand` resolve to a register-resident
  ## local whose home register is `dest`? The accumulator codegen evaluates a
  ## binary op's left operand into `dest`; if the *right* operand lives in `dest`
  ## that would clobber it before use, so the caller must save it first. Only
  ## a bare register symbol can alias — a literal has no register, and a nested
  ## expression is materialized into a fresh scratch (never a live local's home).
  result = false
  if operand.kind == Symbol:
    let loc = g.plan.locationOfSym(symName(operand), cursorToPosition(g.buf[], operand))
    result = loc.kind == InReg and loc.r == dest