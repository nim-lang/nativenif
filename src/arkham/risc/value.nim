#
#           Arkham — native Arm code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3: code generation. Walks a Leng module, runs the analyser + register
## allocator per proc, and emits typed asm-NIF that `nifasm` type-checks,
## assembles and links.
##
## ONE emitter, three targets: AArch64/Darwin, AArch64/Linux (`a64Linux`), and
## bare-metal Cortex-M (`thumbM`). They share the asm-NIF vocabulary by
## design — `add3`, `cmp`, `beq`, `ldr`, `adr` mean the same thing on all
## three — so what actually varies is the register file (`md`), the word size
## (`slots.setTargetWord`), and which features the target simply does not have,
## every one of which is refused BY NAME rather than mis-emitted.
##
## That is why there is no separate `codegen_m`: a second emitter would have had
## to reimplement the register-binding protocol, which is the part with a formal
## model behind it (`proofs/arkham_bindings.tla`).
##
## All asm-NIF tags are emitted through nifasm's own enums (`A64Inst` /
## `NifasmDecl`, see asmbuf) — the single source of truth for the vocabulary.
##
## ABI: AAPCS64. Integer/pointer arguments and the integer return go in x0–x7 /
## x0 (NGRN). Aggregates ≤16 bytes pack into GPRs; aggregates >16 bytes are
## passed by reference (a pointer to a caller copy); large aggregate results use
## the x8 indirect-result register. v1 implements the scalar (int/pointer) path
## end-to-end; floats (HFAs in v0–v7), stack-passed args, and aggregate value
## codegen `raiseAssert` for now.

import std / [assertions, tables, sets, strformat, strutils]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, constdata,
                    mirrors, temps, exprpred, typenav, regbind, abi,
                    layout]
import machine_a64 as machine
from machine_m as machine_m import nil
  # Fully qualified: `machine_m` names its own `LR`/`IP`/`IntCalleeSaved` for the
  # Cortex-M register file, every one of which would collide with `machine`'s
  # AArch64 spelling of the same idea. Which target a name refers to should be
  # visible at the use site, not decided by import order.
export typenav   # SymCat / SymInfo / getType / exprSlot; re-exported so the
                 # backends' `g.lookupSym(...).cat` keeps resolving
export regbind   # the emitter's register-binding state (`g.rb`) — the single
                 # owner of reg<->name bindings, see regbind.nim
                                 # nifasm: the bitmask-immediate predicate, so
                                 # arkham folds exactly the constants it can encode
import emit, mem, aggr
                                 # `nifasm/thumb2` so the two cannot drift apart


# When the backend targets Linux (`g.a64Linux`), an `importc`'d libc function
# recognised as a syscall (see `programs.collect` / `LinuxSyscalls`) is emitted as
# a `(syproc …)` and invoked inline via a `(svc 0)` marker (number in x8, args
# x0–x5, result x0) instead of a Darwin dynamic `extcall`, so nifasm's static ELF
# backend serves it without a dynamic linker. `LinuxA64ExitNr` and the table live
# in `programs`; AArch64 uses the asm-generic unistd numbers (write=64 not 1).

# The `CodeGen` state object and the Leng type/lvalue analysis live in
# `codegen_common`; this module is the AArch64 instruction-selection backend.

# ── low-level emit helpers ──────────────────────────────────────────────────

# ── scratch register pool (volatile temps not held by a local) ──────────────

# ── SIMD/FP scratch pool + emit helpers (double precision) ──────────────────

# `bits` (32 or 64) selects the s/d register view; nifasm reads the operand tag
# to pick single- vs double-precision encodings.
# The GPR side of an `fmov` bitcast is a VALUE, so it goes through `emReg` like
# every other value operand — a bound register by its checked name, a raw tag
# otherwise, and the unbound-scratch assertion in between.
#
# It used to be spelled by name on Cortex-M and RAW on AArch64, and the split was
# not arkham's choice at all: nifasm's AArch64 handlers for `fmov`/`scvtf`/
# `fcvtzs` read that operand with `parseRegisterA64`, which accepts a register
# TAG and nothing else, while the Thumb-2 handlers have always gone through the
# operand parser and taken either. So the emitter carried a branch to satisfy an
# asymmetry one level down, and the value check had a hole on the target with the
# larger register file. Both handlers now use `parseGprA64` — the resolving form,
# which additionally rejects a raw use of a BOUND register — and the only
# difference in the output is that such a register is named where it used to be
# spelled raw, which nifasm resolves back to the same register.
# ── expressions: target-into-register ───────────────────────────────────────

proc marshalStackAggrArg(g: var CodeGen; a: Cursor; paramNm: string)    # defined below
# ── 64-bit scalars on Cortex-M (M4) ─────────────────────────────────────────
# Defined in the INCLUDED `codegen_m64.nim` at the end of this file, because
# they need the whole value core they dispatch out of. Every one of these is a
# no-op on the 64-bit targets: `isWideSlot` is false there by construction, so
# not one of the call sites below can fire.
proc emitWideAsLoc(g: var CodeGen; c: Cursor; dest: var Location)
proc emitWideIntoLoc(g: var CodeGen; c: Cursor; dst: Location)
proc emitWideCmp(g: var CodeGen; aC, bC: Cursor; ek: LengExpr;
                  whenTrue: bool): RiscInst
proc emitWideToNarrow(g: var CodeGen; innerC, targetC: Cursor;
                      dest: var Location)
proc wideRet*(g: var CodeGen; c: Cursor)
proc wideValueIntoTemp*(g: var CodeGen; valC: Cursor): string
# MODEL: the `pickStaging` action in proofs/arkham_bindings.tla — only ever returns a
# register with no live owner (the `Free` guard); staging on an occupied reg breaks
# NoSharedRegister. Change this ⇒ re-check that action.

# MODEL: the `steal` action in proofs/arkham_bindings.tla — the evicted victim must move
# to a stack slot (loc→Stack, binding cleared) or LiveLocalsHaveHomes / RegisterBindingsMatchLoc
# break. Change this ⇒ re-check that action.
# MODEL: a staging register handed out for a *held* value must be tracked, not raw (see
# proofs/arkham_bindings.tla NoSharedRegister) — hence the total `borrowTmp` below, not a
# bare `pickStaging`; two raw staging values would otherwise collide on one register.

# ── indexed/global/nested array address emission (premat-before-tree two-pass) ─
# A memory operand tree (`(mem (at …))`) is emitted inside an already-open asm-NIF
# tree, so any helper instruction needed to form an embedded value — a global's
# address, a computed index, a stride scratch — must be emitted BEFORE that tree
# opens, or it would land *inside* the operand and corrupt the asm-NIF. The two
# passes split exactly that concern: `prematAccess` (pass 1) materializes every
# embedded value into a register as a preceding statement; `emAccessAddr` (pass 2)
# re-emits the address tree consuming those registers in the same traversal order.
# Mirrors the x86-64 backend (codegen_x64); the nifasm A64 `(at)` parser folds the
# resulting `base + idx*scale` / `(at base idx scratch)` from the element type.

# ── floating-point expressions (single + double precision) ──────────────────
# `bits` (32/64) is the value's precision, threaded top-down: it selects s/d
# register views and single/double instructions. A bare literal has no inherent
# width, so it adopts the contextual `bits`.

# MODEL: the init-home seal in proofs/arkham_bindings.tla (`beginInit` seals the home;
# ValueConsistency). The `sealHome` below protects a register-local home while its own
# value is built — without it a steal evicts the home and the write lands in a stale reg.
# ── calls ────────────────────────────────────────────────────────────────────

# ── statements ──────────────────────────────────────────────────────────────

# ── AAPCS64 small-aggregate (≤16B) marshalling ──────────────────────────────
# A ≤16-byte aggregate travels in 1–2 consecutive GPRs. The transfer is purely
# POSITIONAL — eightbyte i is the 8 bytes at offset 8·i — and never consults the
# field layout, so an object, a tuple, an array and a field packing that straddles
# the eightbyte boundary all marshal alike. A trailing PARTIAL eightbyte (an
# aggregate whose size is not a multiple of 8) goes through `loadAggrTail` /
# `storeAggrTail`, which touch exactly the aggregate's own bytes. The >16-byte
# by-reference / x8-indirect paths still `raiseAssert`. Layout/size live in
# slots.nim so the register allocator shares them.

# ── named register locals (typed nifasm vars; transient scratch stays `(xN)`) ─

# ── control flow: labels + goto ─────────────────────────────────────────────

# ── the atomic rows (`{.intrinsic: "AtomicX".}` → AArch64 LL/SC loops) ─────────
# AArch64 has no lock prefix: every read-modify-write is a load-exclusive /
# store-exclusive retry loop, and the acquire/release forms (`ldaxr`/`stlxr`)
# carry the ordering. Memory ordering is always that strong form, so the
# memory-order operands are not evaluated (see `evaluatedOperands`).
#
# An atomic arrives as `(instr …)`, so its operands are wherever the ALLOCATOR put
# them and the sequence assumes no ABI; the three registers it takes for itself are
# `AtomicScratchRegs`, which the allocator never hands out. See `emitAtomicInstr2`.

# ── mem* intrinsics: inline copies (no libc) ─────────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers inline. memcpy/memmove copy 8-byte
# words then a byte tail (a byte loop of the 1.4 MB token block was the whole
# bif gap on AArch64). A compile-time memcpy of 0..64 bytes unrolls. Result
# lands in x0 (memcpy/memmove/memset return dest, memcmp the first byte
# difference).

# ── case statement ──────────────────────────────────────────────────────────

# ── proc emission ────────────────────────────────────────────────────────────


# ════════════════════════════════════════════════════════════════════════════
#  Fused value core (`*2`) — the AArch64 twin of codegen_x64.nim's emit*2
#  family. The destination is threaded as a parameter (constraint in, resolved
#  location out); every register decision is made inline at the point of
#  emission (machine `aarch64MachineN`). Transient scratch the emitter needs
#  (a folded memory operand a64 must load, a global address temp, a
#  produce-into-memory spill) comes from the reserved staging bridges
#  x14/x15/v31 (`IntBridgeRegs`/`FloatBridgeReg`), withheld from the pick
#  pools so one is always free.
# ════════════════════════════════════════════════════════════════════════════

proc genStore2*(g: var CodeGen; rhs: Cursor; dst: Location)
proc prematLval2*(g: var CodeGen; c: Cursor)
proc genConstr2*(g: var CodeGen; c: Cursor; dst: Location)
proc genAconstr2*(g: var CodeGen; c: Cursor; dst: Location)

# ── fused value core (step 3): decide-and-emit overloads ─────────────────────
# The destination is a threaded parameter (constraint in, resolved location
# out) instead of the allocator's per-position plan — the a64 twin of the x64
# fused core. Old locs-reading procs stay live until genProc2 flips.
proc emitValue2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFValue2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitBin2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitMod2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFBin*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondValue2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCond*(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitScalarCmp*(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool; fuseBranchTo = ""): RiscInst
proc emitMemLoad2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitAddr2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCast2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCall2*(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false;
               tail = false)
proc emitInstr2*(g: var CodeGen; c: Cursor; dest: var Location)
proc produceIntoMem2*(g: var CodeGen; c: Cursor; dst: Location)
proc produceIntoFMem2*(g: var CodeGen; c: Cursor; dst: Location)
proc storeReg2*(g: var CodeGen; dst: Location; src: Reg)


# ── staging bridges (always free; reserved out of the allocator pool) ────────

# ── fused value core: emit-time destination protocol (step 3, a64 twin) ──────
# Lazy-bind lifecycle identical to x64's: `takeTmp` RESERVES (pickedRegs flag
# guards the reserve→bind gap; the consumer binds on materialization);
# `freeVal` releases. Pool dry → mint an `etmp` slot (declared by the
# post-body prologue). The a64-only rule: intrinsic/atomic operands must
# NEVER fall back to the bridges — the atomics own x14/x15/x16.

# ── scalar Location → register / register → Location ─────────────────────────

proc place2*(g: var CodeGen; src: Location; dest: Reg) =
  ## `dest ← <scalar Location src>`. The pure-emit analogue of `emitLoad`: a
  ## global/threadvar address is formed straight into `dest` (no borrowed temp),
  ## a complex lvalue routes through the `*2` address machinery.
  ##
  ## `dest` is about to be WRITTEN, so whatever it mirrored is stale — and a
  ## memory `src` may still be in a register, which turns the load into a move.
  ## The invalidation is the half that is not optional.
  let src = g.forwardOf(src)
  if src.kind == InReg and src.r == dest: (g.killMirror(dest); return)  # already there
  g.killMirror(dest)
  case src.kind
  of InReg: g.movReg(dest, src.r)
  of Imm: g.placeImm(dest, src)
  of NamedStack:
    # The slot carries its own type, so nifasm sizes this load by it: a narrow local
    # comes back `ldrsb`/`ldrb`-extended into arkham's canonical 64-bit form, whether
    # arkham stored it or a callee holding `ptr int8` wrote the one byte.
    g.emScalarLoad(dest, src.name)
  of Glob:
    if g.globalIsGvarSlot(src.name):
      # Fold the page offset into the load: `adrp x17, g@PAGE ; ldr dest, [x17, g@PAGEOFF]`
      # (one `add` fewer than the address-then-deref below). nifasm sizes it from the
      # gvar's own scalar type.
      g.ab.tree GloadA64: (g.emReg dest; g.ab.sym g.prog.gvarRefName(src.name))
    else:
      # A read-only `const` (rodata label, no page-offset site): form the address, deref.
      # The deref is typed `(ptr <its declared type>)` so it yields the PRECISE type —
      # `dest` is bound to the *value* type, so a bare `(mem dest)` would drop a pointer
      # level (harmless for a scalar, but a POINTER const would load `object` where
      # `(ptr object)` is wanted; nifasm is strict). Cast in the deref rather than spend
      # a bridge.
      g.emAdr(dest, g.prog.gvarRefName(src.name))
      var pt = g.prog.ptrTypeOf(g.globalDeclType(src.name))
      g.ab.tree MovA64:
        g.emReg dest
        g.ab.tree MemX:
          g.ab.tree CastX: (g.genTypeBody(pt); g.emReg dest)
  of Tvar:
    # Address, then deref — and the deref is typed `(ptr <its declared type>)` for the
    # same reason the `const` arm above casts: `dest` is bound to the *value* type, so
    # a bare `(mem dest)` drops a pointer level and a POINTER threadvar would load
    # `object` where `(ptr object)` is wanted.
    if g.a64Linux: g.emAdr(dest, src.name)
    else: g.genTlvAddr(src.name, dest)
    var pt = g.prog.ptrTypeOf(g.globalDeclType(src.name))
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree MemX:
        g.ab.tree CastX: (g.genTypeBody(pt); g.emReg dest)
  of Mem:
    let wr = g.pairFieldReg(src.cur)
    if wr != NoReg:
      g.movReg(dest, wr)
      return
    # `dest` is written by the load below and nothing else, so as long as the ADDRESS
    # does not read it, it is a legal home for a re-derivable global base the premat
    # would otherwise have no register for (see `lateGlobalBase`).
    let spare = if g.exprReadsReg(src.cur, dest): NoReg else: dest
    let savedSpare = g.lateBaseSpare
    g.lateBaseSpare = spare
    g.prematLval2(src.cur)
    g.lateBaseSpare = savedSpare
    g.ab.tree MovA64: (g.emReg dest; g.ab.tree MemX: g.emLvalAddr2(src.cur))
    g.unbindLvalTemps2(src.cur)
  else: raiseAssert "arkham a64n: place2 src " & $src.kind

proc placeF2(g: var CodeGen; src: Location; dest: FReg; bits: int) =
  ## `dest ← <float Location src>`.
  case src.kind
  of InFReg: g.fmovF(dest, src.f, bits)
  of NamedStack: g.emFloatScalarLoad(dest, src.name, bits)
  of Glob:
    let b = g.takeBridge(); g.emAdr(b, g.prog.gvarRefName(src.name))
    g.emFLoad(dest, b, bits); g.dropBridge b
  of Mem:
    g.prematLval2(src.cur)
    g.ab.tree FldrA64: (g.emFReg(dest, bits); g.ab.tree MemX: g.emLvalAddr2(src.cur))
    g.unbindLvalTemps2(src.cur)
  else: raiseAssert "arkham a64n: placeF2 src " & $src.kind

proc storeReg2*(g: var CodeGen; dst: Location; src: Reg) =
  ## `<scalar Location dst> ← src` (integer/pointer).
  case dst.kind
  of InReg: g.movReg(dst.r, src)
  of NamedStack: g.emScalarStore(dst.name, src)
  of Glob:
    if g.globalIsGvarSlot(dst.name):
      # Fold: `adrp x17, g@PAGE ; str src, [x17, g@PAGEOFF]` — no bridge, no address `add`.
      g.ab.tree GstoreA64: (g.emReg src; g.ab.sym g.prog.gvarRefName(dst.name))
    else:
      let b = g.takeBridge(g.globalAddrSlot(dst.name)); g.emAdr(b, g.prog.gvarRefName(dst.name))
      g.ab.tree MovA64:
        g.ab.tree MemX: g.emReg b
        g.emReg src
      g.dropBridge b
  of Tvar:
    let b = g.takeBridge(g.globalAddrSlot(dst.name))
    g.genTlvAddr(dst.name, b)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emReg b
      g.emReg src
    g.dropBridge b
  of Mem:
    let wr = g.pairFieldReg(dst.cur)
    if wr != NoReg:
      g.movReg(wr, src)
      return
    g.prematLval2(dst.cur)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emLvalAddr2(dst.cur)
      g.emReg src
    g.unbindLvalTemps2(dst.cur)
  else: raiseAssert "arkham a64n: storeReg2 dst " & $dst.kind

# ── lvalue addressing (mirrors x64 emLvalAddr2/prematLval2/unbindLvalTemps2) ──

proc reloadMemBase2*(g: var CodeGen; pos: int) =
  ## A deref/at/pat base or register index the allocator spilled (NamedStack/Mem)
  ## must be in a register for `[reg]` addressing: load it into a bridge, repoint
  ## its location, and park the home so `restoreMemBase2` puts it back. (A register-
  ## homed base returns immediately — no steal can move it under us anymore.)
  let loc = g.plan.planned(pos)
  if loc.kind notin {NamedStack, Mem}: return
  # A bridge, but never the LAST one while there is another answer. Any register
  # with no live binding serves just as well — the reload dies with the operand —
  # and `pickStagingA64` finds those the whole-proc home union hides. Taking the
  # last bridge here is what leaves a step with no alternative holding nothing:
  # under a 64-bit lowering (which juggles pairs) this is reached with one already
  # gone, and on the `cortex-m 64` corpus it was the last over-budget take left.
  var s = NoReg
  if g.liveBridges() + 1 < g.distinctBridges():
    s = g.tryTakeBridge(loc.typ)
  if s == NoReg:
    s = g.pickStagingA64()
    if s != NoReg:
      g.pickedRegs.incl s
      g.bindTemp(s, loc.typ)
    else:
      # Nothing in the pools either: now the last bridge is the right answer, and
      # this operand genuinely has no other.
      s = g.tryTakeBridge(loc.typ, lastResort = true)
      if s == NoReg:
        raiseAssert "arkham a64n: no register to reload a spilled memory base in proc " &
                    g.curProcName
  g.place2(loc, s)
  g.savedHomes[pos] = loc
  g.plan.planAtEmitTime(pos, regLoc(s, loc.typ))

proc prematAddrVal2*(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue base/index value `c` into a register for the enclosing
  ## `(mem …)`. A register-homed base materializes in place; a genuinely spilled base
  ## (`NamedStack`/`Mem`) is brought into a bridge by `reloadMemBase2`. Scoped to the
  ## lvalue tree (NOT general `emitValue2`). The destination was decided by
  ## `emitLvalue2` (`resolveLvalVal`) and parked in the memo; thread it.
  let pos = g.posOf(c)
  var d = g.plan.planned(pos)
  g.emitValue2(c, d)
  g.plan.planAtEmitTime(pos, d)
  g.reloadMemBase2(pos)

proc raiseForIndexedBase*(g: var CodeGen; c: Cursor; lateBase: bool) =
  ## I2/I3: the honest bridge demand of an `(at …)` / `(pat …)` address chain.
  ##
  ## TWO only when both ends really need a bridge of their own — a computed index
  ## AND a base that must be reloaded into one. It is one otherwise, and saying two
  ## unconditionally is not merely pessimistic: this chain is reached with two
  ## bridges already held (`foldRhs2`'s load destination plus `produceIntoMem2`'s
  ## produce bridge), so an unconditional two made every such composition look like
  ## it needed four of three.
  ##
  ## A LATE base costs no bridge here. It is materialized after the index, by which
  ## point `emLvalGlobalBase`'s cascade has a staging-pool register, a freed bridge,
  ## or the caller's `lateBaseSpare` — the load destination the consumer is about to
  ## overwrite anyway — to put it in.
  ##
  ## Under-stating this is SAFE in the sense that matters: `tryTakeBridge` refuses a
  ## take past the declaration, so a chain that turns out to want two where one was
  ## declared fails at the declaration rather than silently.
  var idx = c
  skip idx                                   # the base; `idx` now names the index
  let idxComputed = idx.kind notin {IntLit, UIntLit}
  if idxComputed and not lateBase:
    g.bridgeRaise(bdTwoInRegs, "an indexed lvalue with a spilled base and a computed index")

proc prematLval2*(g: var CodeGen; c: Cursor) =
  # A `(mem …)` whose base AND index both spilled reloads each into a bridge
  # (`reloadMemBase2`), and an `(at …)` stride scratch that found the pools dry
  # takes one that lives until the operand is emitted (`bindStrideScratch`). Both
  # outlive this proc — the consumer's `freeLvalTemps2` releases them — so the
  # demand is the enclosing STEP's, and this is where it becomes known.
  ## Materialize an lvalue's embedded values (a deref pointer, an index, a global
  ## base address) into their allocated registers BEFORE the consuming `(mem …)`/
  ## `(lea …)` tree opens.
  if c.kind == Symbol:
    let loc = g.plan.planned(g.posOf(c))
    if loc.kind == InReg and g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:
      # a module-level global aggregate base: `lea reg, &g` into the address register
      # the walk reserved (fused: a lazy-bound pick — bind it here, at
      # materialization; pre-fuse it was bound by the caller).
      #
      # Ask the address mirrors BEFORE binding, because binding retires them: when
      # the walk's pick landed on the very register that still holds `&g` — which is
      # exactly what happens for a run of accesses to the same global, since a
      # mirror leaves its register allocatable — the materialization is already
      # done and costs NOTHING. Otherwise `emGlobalAddr` still turns the `adrp`+`add`
      # into a `mov` off the mirroring register.
      let already = g.lookupSym(symName(c)).cat == scGlobal and
                    g.rb.addrMirror(g.prog.gvarRefName(symName(c))) == loc.r
      if loc.isTemp and not g.rb.isBoundTemp(loc.r): g.bindTemp(loc.r, ScalarSlot)
      if not already: g.emGlobalAddr(loc.r, symName(c))
    elif g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:
      # A global base with no allocated register (`lateGlobalBase`): derive `&g` here.
      # The caller ordered this AFTER the index, so nothing between this point and the
      # consuming `(mem …)` tree can clobber a volatile — any register with no live
      # binding will do, and taking one leaves both bridges for the operand reloads
      # that have no other answer. A bridge only if even that finds nothing.
      # `freeLvalTemps2` drops it with the rest of the lvalue's temps either way
      # (`dropBridge` is `unbindTemp`, which also clears the reserve flag).
      var s = g.pickStagingA64()
      var borrowed = false
      if s != NoReg:
        g.pickedRegs.incl s
        g.bindTemp(s, ScalarSlot)
      else:
        s = g.tryTakeBridge()
        if s == NoReg and g.lateBaseSpare != NoReg:
          # Nothing free and both bridges are staging. The caller named one register
          # it is about to OVERWRITE anyway — `place2`'s load destination, which it
          # only offers after proving this address does not read it. `&g` goes there
          # and the load consuming it reads `[s + idx]` back into `s`. Without this
          # the shape `x op globalArray[i]` has no third register to stand in and the
          # compilation stops outright; a set literal's membership test is exactly
          # that shape, and inlining puts one inside an enclosing binary operator.
          #
          # BORROWED, not taken: the register stays the caller's, so the matching
          # `unbindLvalTemps2` must not release it (it is still holding the loaded
          # value the caller is about to consume).
          s = g.lateBaseSpare
          borrowed = true
        elif s == NoReg:
          s = g.takeBridge()                              # asserts: genuinely nothing left
      g.emGlobalAddr(s, symName(c))
      let gpos = g.posOf(c)
      g.lvalGlobBase[gpos] = s
      if borrowed: g.lateBaseBorrowedAt.incl gpos
    else:
      let home = g.plan.homeOfSym(symName(c))
      if home.kind == StackPtr:                # the slot holds &aggregate: load it first
        let s = g.takeBridge()
        g.emScalarLoad(s, home.ptrName)
        g.lvalGlobBase[g.posOf(c)] = s
    return
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.prematLval2(cc)
        while cc.hasMore: skip cc
    of DerefC:
      var cc = c
      cc.into:
        g.prematAddrVal2(cc)                              # the pointer → its reg (follow steals)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      var recycle = NoReg
      cc.into:
        let baseCur = cc
        # A re-derivable global base with no allocated register goes LAST: the index
        # is what it would otherwise have to survive, and deriving `&g` after it needs
        # no survivor at all (`lateGlobalBase`).
        let late = g.lateGlobalBase(baseCur) or g.lateSpilledBase(baseCur)
        g.raiseForIndexedBase(cc, late)
        if not late: g.prematLval2(cc)
        skip cc                                           # base
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
          recycle = g.strideRecycle(cc, baseCur)          # last-resort stride scratch
        if late: g.prematLval2(baseCur)
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(atPos) and g.plan.aux[atPos].scratch.len > 0:
        g.bindStrideScratch(atPos, recycle)
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      var recycle = NoReg
      cc.into:
        let baseCur = cc
        # A SPILLED base pointer goes last, exactly as a global's address does in
        # `AtC` above: reloading it is one `ldr` from a fixed frame offset, so
        # materializing it before the index only buys a bridge held across the
        # index's whole evaluation. `PatC` never had this arm, and it is the one
        # composition `tightCompositions` still counted.
        let late = g.lateSpilledBase(baseCur)
        g.raiseForIndexedBase(cc, late)
        if not late: g.prematAddrVal2(cc)                 # the pointer → its reg
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
          recycle = g.strideRecycle(cc, baseCur)          # last-resort stride scratch
        if late: g.prematAddrVal2(baseCur)
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(patPos) and g.plan.aux[patPos].scratch.len > 0:
        g.bindStrideScratch(patPos, recycle)
    of BaseobjC:                                          # transparent: materialize inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                                 # base type, depth
        g.prematLval2(cc)
        while cc.hasMore: skip cc
    of AconstrC, OconstrC:
      # An aggregate CONSTRUCTOR in lvalue position (`[a, b][i]`): build it into a
      # stack slot here, before the consuming `(mem …)` tree opens, and let
      # `emLvalAddr2` address that slot. A constructor has no address of its own.
      let home = g.inlineAggrHome(c)
      if not g.varType.hasKey(home):
        let t = g.getType(c)
        g.emTypedStackVar(home, t)
        if t.kind == Symbol: g.varType[home] = t.symId
        g.genStore2(c, namedStackLoc(home, g.exprSlot(c)))
    else: discard

# ── memory loads / address-of ────────────────────────────────────────────────

proc aggrAddrInto*(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool) =
  ## THE address-of any lvalue into register `dest`: `&(deref p)`
  ## is `p`; a global/threadvar leas its absolute address; a `baseobj` is the inner
  ## lvalue's address (base at offset 0); anything else leas the `emLvalAddr2` subtree.
  ## `doBind` names a fresh temp `dest`. Shared by `(addr …)` / aggregate marshalling /
  ## aggregate copy.
  if lv.kind == TagLit and lv.exprKind == DerefC:
    var p: Cursor
    block:
      var dd = lv
      dd.into:
        p = dd; skip dd
        while dd.hasMore: skip dd
    var pLoc = g.plan.planned(g.posOf(p))    # the CALLER's walk decided p's spot
    g.emitValue2(p, pLoc)
    g.plan.planAtEmitTime(g.posOf(p), pLoc)
    if doBind:
      g.bindTemp(dest, AsmSlot(cls: AUInt, size: wordSize(), align: wordAlign(),
                              typ: g.getType(p)))
    g.place2(pLoc, dest)
    if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
  elif lv.kind == TagLit and lv.exprKind == BaseobjC:
    var inner: Cursor
    block:
      var bc = lv
      bc.into:
        skip bc; skip bc                                  # base type, depth
        inner = bc
        while bc.hasMore: skip bc
    if inner.kind == TagLit and inner.exprKind == DerefC:
      var p: Cursor
      block:
        var dd = inner
        dd.into:
          p = dd; skip dd
          while dd.hasMore: skip dd
      var pLoc = g.plan.planned(g.posOf(p))  # the CALLER's walk decided p's spot
      g.emitValue2(p, pLoc)
      g.plan.planAtEmitTime(g.posOf(p), pLoc)
      if doBind: g.bindTemp(dest, aslot)
      g.place2(pLoc, dest)
      if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
    else:
      if doBind: g.bindTemp(dest, aslot)
      g.prematLval2(inner)
      g.ab.tree LeaA64: (g.emReg dest; g.emLvalAddr2(inner))
      g.unbindLvalTemps2(inner)
  elif lv.kind == Symbol and g.lookupSym(symName(lv)).cat in {scGlobal, scTvar}:
    if doBind: g.bindTemp(dest, aslot)
    var lc = lv
    let loc = g.asLoc(lc)
    case loc.kind
    of Glob: g.emGlobalAddr(dest, loc.name)
    of Tvar:
      if g.a64Linux: g.emAdr(dest, loc.name)
      else: g.genTlvAddr(loc.name, dest)
    else: raiseAssert "arkham a64n: &sym resolved to " & $loc.kind
  elif lv.kind == Symbol:                               # a LOCAL aggregate var
    let home = g.plan.locationOfSym(symName(lv), cursorToPosition(g.buf[], lv))
    if doBind: g.bindTemp(dest, aslot)
    case home.kind
    of NamedStack:
      g.ab.tree LeaA64:
        g.emReg dest
        g.ab.sym home.name
    of StackPtr: g.emScalarLoad(dest, home.ptrName)     # the slot already IS the address
    of InReg: g.movReg(dest, home.r)                    # by-ref aggregate param: reg holds &it
    of InRegPair:
      raiseAssert "arkham a64n: aggrAddr of InRegPair local " & symName(lv)
    else: raiseAssert "arkham a64n: aggrAddr of local " & symName(lv) & " home " & $home.kind
  else:
    # The lvalue's embedded picks come from the CALLER's `emitLvalue2` walk
    # (and the caller frees them with `freeLvalTemps2`) — x64's contract.
    if doBind: g.bindTemp(dest, aslot)
    var bound: seq[Reg] = @[]
    g.bindLvalGlobalBases(lv, bound)                    # bind any UNBOUND global-base reg first
    g.prematLval2(lv)
    g.ab.tree LeaA64: (g.emReg dest; g.emLvalAddr2(lv))
    g.unbindLvalTemps2(lv)
    for r in bound: g.unbindTemp(r)

# ── integer arithmetic ───────────────────────────────────────────────────────

proc foldRhs2(g: var CodeGen; op: RiscInst; dest: Reg; rhsLoc: Location; rhsC: Cursor;
              w32 = false) =
  ## `dest = dest op rhs`, materializing the rhs as a64 needs (no memory operand; a
  ## large/non-add immediate goes through a bridge). `dest` already holds the lhs.
  ## `w32` selects the 32-bit W-form tag for add/sub/mul (see wForm/emitBin2).
  case rhsLoc.kind
  of Imm:
    if op in {AddA64, SubA64} and rhsLoc.ival >= 0 and rhsLoc.ival <= 0xFFFF:
      g.binImm(op, dest, rhsLoc.ival, w32)
    elif op in {LslA64, LsrA64, AsrA64} and rhsLoc.ival >= 0 and rhsLoc.ival <= 63:
      # arm64 shifts take an immediate count natively (`lsl x, x, #n`), same form
      # `extendTo` already emits — so a constant shift amount folds in place rather
      # than being materialized into a bridge register (`mov b, #n; lsl x, b`).
      g.binImm(op, dest, rhsLoc.ival)
    elif op == MulA64 and rhsLoc.ival >= 2 and (rhsLoc.ival and (rhsLoc.ival - 1)) == 0:
      var k = 0'i64
      var t = rhsLoc.ival
      while t > 1: (t = t shr 1; inc k)
      g.binImm(LslA64, dest, k)
    elif op in {AndA64, OrrA64, EorA64} and g.logicalImmOk(rhsLoc.ival):
      g.binImm(op, dest, rhsLoc.ival)
    else:
      let b = g.takeBridge(avoid = dest)
      g.movImm(b, rhsLoc.ival)
      g.binReg(op, dest, b, w32)
      g.dropBridge b
  of InReg:
    g.binReg(op, dest, rhsLoc.r, w32)
  of NamedStack, Mem, Glob, Tvar:
    let b = g.takeBridge(avoid = dest)
    g.place2(rhsLoc, b)
    g.binReg(op, dest, b, w32)
    g.dropBridge b
  else: raiseAssert "arkham a64n: foldRhs2 " & $rhsLoc.kind


proc foldRhs3(g: var CodeGen; op: RiscInst; dest, rn: Reg; rhsLoc: Location; rhsC: Cursor;
              w32 = false) =
  ## `dest = rn op rhs` — the 3-operand twin of `foldRhs2`. `rn` holds the left
  ## source (a live local's register, distinct from `dest`); nothing is moved into
  ## `dest` first. Materializes the rhs exactly as `foldRhs2` does.
  case rhsLoc.kind
  of Imm:
    if op in {AddA64, SubA64} and rhsLoc.ival >= 0 and rhsLoc.ival <= 0xFFFF:
      g.binImm3(op, dest, rn, rhsLoc.ival, w32)
    elif op in {LslA64, LsrA64, AsrA64} and rhsLoc.ival >= 0 and rhsLoc.ival <= 63:
      g.binImm3(op, dest, rn, rhsLoc.ival)
    elif op == MulA64 and rhsLoc.ival >= 2 and (rhsLoc.ival and (rhsLoc.ival - 1)) == 0:
      var k = 0'i64
      var t = rhsLoc.ival
      while t > 1: (t = t shr 1; inc k)
      g.binImm3(LslA64, dest, rn, k)
    elif op in {AndA64, OrrA64, EorA64} and g.logicalImmOk(rhsLoc.ival):
      g.binImm3(op, dest, rn, rhsLoc.ival)
    else:
      let b = g.takeBridge(avoid = dest)
      g.movImm(b, rhsLoc.ival)
      g.binReg3(op, dest, rn, b, w32)
      g.dropBridge b
  of InReg:
    g.binReg3(op, dest, rn, rhsLoc.r, w32)
  of NamedStack, Mem, Glob, Tvar:
    let b = g.takeBridge(avoid = dest)
    g.place2(rhsLoc, b)
    g.binReg3(op, dest, rn, b, w32)
    g.dropBridge b
  else: raiseAssert "arkham a64n: foldRhs3 " & $rhsLoc.kind

# ── float arithmetic ─────────────────────────────────────────────────────────

# ── calls ────────────────────────────────────────────────────────────────────

proc emitMemIntrin2*(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Inline `mem*` copy. The allocator placed the 3 args in x0/x1/x2 (a normal
  ## int-arg call); during this leaf intrinsic the free arg registers x3/x4/x5 are the
  ## loop scratch (raw, caller-saved). Result → x0 (moved to its home by emitCall2).
  ## A compile-time memcpy of 0..64 bytes unrolls into sized loads/stores.
  var unroll = false
  var nUnroll = 0'i64
  if builtin == "memcpy" and argCurs.len >= 3:
    let (ok, n) = g.tryConstFold(argCurs[2])
    if ok and n >= 0 and n <= 64:
      unroll = true
      nUnroll = n
  let nArgs = if unroll: 2 else: min(3, argCurs.len)
  for idx in 0 ..< nArgs:
    var aD = regLoc(g.md.intArgRegs[idx], ScalarSlot)
    g.emitValue2(argCurs[idx], aD)                       # → x0 / x1 / x2 directly
    g.unbindTemp(aD.r)                                   # used raw below
  # The three ARGUMENT registers, read off the machine rather than written as
  # slot literals: `a0`/`a1`/`a2` are `x0`/`x1`/`x2` on Arm and `x10`/`x11`/`x12`
  # on RISC-V, where those literals name `zero`, `ra` and `sp` instead.
  let (dst, src, n) = (g.md.intArgRegs[0], g.md.intArgRegs[1], g.md.intArgRegs[2])
  let (i, b, b2) = (g.md.memIntrinScratch[0], g.md.memIntrinScratch[1],
                    g.md.memIntrinScratch[2])
  if unroll:
    if nUnroll > 0:
      g.copyAggr(dst, src, int(nUnroll), i)
    g.movReg(g.md.intRetReg, dst)
    return
  case builtin
  of "memcpy", "memmove":
    let done = g.freshLabel()
    if builtin == "memmove":
      let fwd = g.freshLabel()
      g.ab.tree CmpA64: (g.emReg dst; g.emReg src)
      g.emBr(BlsA64, fwd)
      g.movReg(i, n)
      g.emitLoop:
        g.ab.tree CmpA64: (g.emReg i; g.ab.intLit 0)
        g.emBr(BeqA64, done)
        g.binImm(SubA64, i, 1)
        g.emLdrb(b, src, i); g.emStrb(b, dst, i)
      g.emLab(fwd)
    # Word bulk + byte tail. `i` counts quadwords, then bytes; `b2` is n div 8.
    let tail = g.freshLabel()
    g.movReg(b2, n)
    g.binImm(LsrA64, b2, 3)                              # quadwords = n div 8
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.emReg i; g.emReg b2)
      g.emBr(BhsA64, tail)
      g.emLoadQwordAt(b, src, i)
      g.emStoreQwordAt(dst, i, b)
      g.binImm(AddA64, i, 1)
    g.emLab(tail)
    g.binImm(LslA64, i, 3)                               # i = n and not 7, now bytes
    g.emitLoop:
      g.ab.tree CmpA64: (g.emReg i; g.emReg n)
      g.emBr(BhsA64, done)
      g.emLdrb(b, src, i); g.emStrb(b, dst, i)
      g.binImm(AddA64, i, 1)
    g.emLab(done)
    g.movReg(g.md.intRetReg, dst)
  of "memset":
    let done = g.freshLabel()
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.emReg i; g.emReg n)
      g.emBr(BhsA64, done)
      g.emStrb(src, dst, i)                              # store low byte of `val` (in x1)
      g.binImm(AddA64, i, 1)
    g.emLab(done)
    g.movReg(g.md.intRetReg, dst)
  of "memcmp":
    let diff = g.freshLabel()
    let equal = g.freshLabel(); let done = g.freshLabel()
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.emReg i; g.emReg n)
      g.emBr(BhsA64, equal)
      g.emLdrb(b, dst, i); g.emLdrb(b2, src, i)          # dst=pa, src=pb
      g.ab.tree CmpA64: (g.emReg b; g.emReg b2)
      g.emBr(BneA64, diff)
      g.binImm(AddA64, i, 1)
    g.emLab(diff)
    g.movReg(g.md.intRetReg, b); g.binReg(SubA64, g.md.intRetReg, b2)
    g.emBr(BA64, done)
    g.emLab(equal)
    g.movImm(g.md.intRetReg, 0)
    g.emLab(done)
  else: raiseAssert "arkham a64n: unsupported mem intrinsic: " & builtin

# ── Cortex-M atomics: LDREX/STREX, and the barrier is a separate instruction ──
# ARMv7-M has the exclusive pair and NOTHING else: no acquire/release form of a
# load or a store (that is ARMv8-M), and no 64-bit exclusive pair at all. So an
# atomic here is three things the AArch64 lowering gets for free from its
# opcodes — a `dmb` in front, the retry loop, and a `dmb` behind — and a 64-bit
# cell is refused by name rather than split into two claims, which would be two
# atoms and not one.
#
# The scratch is `bridgeRegs` (r10/r11/r8), which is the same choice AArch64
# makes (x14/x15/x16): the sequence needs exactly three registers nothing else
# may hold — the observed value, the value to store, and the status — and those
# three are the ones the allocator never assigns.

# ── stores ───────────────────────────────────────────────────────────────────

proc storeScalar2*(g: var CodeGen; dst, v: Location) =
  ## Move a just-computed scalar `v` into a scalar home `dst`, releasing `v` if a temp.
  case dst.kind
  of InReg: g.place2(v, dst.r)
  of InFReg:
    let bits = dst.typ.size * 8
    if v.kind in {NamedStack, Mem, Glob}: g.placeF2(v, dst.f, bits)
    elif v.kind == InFReg and v.f != dst.f:
      g.fmovF(dst.f, v.f, bits)
      if v.isTemp: g.unbindFTmp(v.f)
  of NamedStack:
    let bits = dst.typ.size * 8
    # Decided by `memToMemBridgeDemand`, executed here — see the x86-64 twin.
    let need = memToMemBridgeDemand(g.md, dst, v)
    if dst.typ.isFloat:
      if need.fregs > 0:
        let fs = g.takeFBridge(bits)
        g.placeF2(v, fs, bits)
        g.emFloatScalarStore(dst.name, fs, bits)
        g.dropFBridge()
      elif v.kind == InFReg:
        g.emFloatScalarStore(dst.name, v.f, bits)
        # The register still holds what the slot now holds: keep that instead of
        # killing the binding, and the next read of `dst` comes from the register.
        if v.isTemp and not g.mirrorFStored(v.f, dst): g.unbindFTmp(v.f)
      else: raiseAssert "arkham a64n: float scalar store rhs " & $v.kind
    else:
      if need.gprs > 0:
        let b = g.takeBridge(need.slot)
        if v.kind == Imm: g.placeImm(b, v) else: g.place2(v, b)
        g.emScalarStore(dst.name, b)
        g.dropBridge b
      elif v.kind == InReg:
        g.emScalarStore(dst.name, v.r)
        if v.isTemp and not g.mirrorStored(v.r, dst): g.unbindTemp(v.r)
      else: raiseAssert "arkham a64n: scalar store rhs " & $v.kind
  else: raiseAssert "arkham a64n: scalar store dst " & $dst.kind

# ── aggregates ───────────────────────────────────────────────────────────────

proc aggrArgAddr*(g: var CodeGen; a: Cursor; dst: Reg) =
  ## Put the ADDRESS of an aggregate call-argument SOURCE into `dst` (a usable scratch
  ## register). Mirrors the register-marshalling source dispatch — a symbol local/global,
  ## a by-ref param pointer already in a register, an lvalue, or an `oconstr`/`aconstr`
  ## built into a temp — but yields an address, which the stack-passed path reads through.
  if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
    g.aggrAddrInto(a, dst, addrSlot(), doBind = false)
  elif a.kind == Symbol:
    case g.lookupSym(symName(a)).cat
    of scGlobal: g.emGlobalAddr(dst, symName(a))
    of scTvar: g.genTlvAddr(symName(a), dst)
    else:
      let home = symName(a)
      let hl = g.plan.locationOfSym(home, cursorToPosition(g.buf[], a))
      if hl.kind == InReg: g.movReg(dst, hl.r)          # by-ref param: pointer already in a reg
      elif hl.kind == StackPtr: g.emScalarLoad(dst, hl.ptrName)   # its slot holds the pointer
      elif hl.kind == InRegPair:
        # A ≤16B by-value aggregate the allocator kept in a GPR PAIR — it has no
        # address at all, so there is nothing to `lea`. Give it one: a slot of its own,
        # written from the pair.
        #
        # The fall-through used to emit `lea dst, <name>` for this, naming a `(s)` var
        # that was never declared, because a pair home declares none — the eightbytes
        # ARE the fields and every other reader gets at them positionally
        # (`aggrWordsToFromRegs` returns early on `InRegPair` for exactly that reason).
        # nifasm caught it as "Unknown or invalid symbol". `semos.runEval` is the shape
        # that reaches it: its `sourceDir: string` is pair-homed, and the
        # `runProgram(…)` call it feeds needs NINE argument words, so that one argument
        # is marshalled onto the outgoing stack — the one path that wants an address.
        #
        # No extra scratch: `dst` is the bridge being filled, so take the slot's address
        # into it first and store the pair words THROUGH it. And no partial tail to
        # worry about — `canHomeInRegPair` admits only 8/16-byte aggregates whose every
        # field is a full 8-byte word at an 8-byte offset, so whole eightbytes are exact.
        let ptyp = g.getType(a)
        if ptyp.kind != Symbol:
          raiseAssert "arkham a64: register-pair aggregate of non-nominal type: " & home
        let slot = synth("pairaddr") & $g.posOf(a) & ".0"
        g.emStackVar(slot, ptyp.symId)
        g.ab.tree LeaA64: (g.emReg dst; g.ab.sym slot)
        for k in 0 ..< aggrWordCount(g.prog, ptyp.symId):
          g.ab.tree MovA64: (g.emWordThroughPtr(dst, k); g.emReg pairWord(hl, k))
      else: g.ab.tree LeaA64: (g.emReg dst; g.ab.sym home)
  else:                                                 # oconstr/aconstr → build into a temp, then &temp
    let pos = g.posOf(a)
    let home = synth("aggtmp") & $pos & ".0"
    g.emTypedStackVar(home, g.getType(a))
    g.varType[home] = g.getType(a).symId
    g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
    g.ab.tree LeaA64: (g.emReg dst; g.ab.sym home)

proc marshalStackAggrArg(g: var CodeGen; a: Cursor; paramNm: string) =
  ## Write an aggregate call argument that did NOT fit the integer arg registers to its
  ## outgoing stack slot(s) `(mem (sp) (arg paramNm [k]))`. The fixed frame keeps SP
  ## constant, so the source is read and the slots written at stable offsets — no
  ## held-scratch survivors across a `sub sp`. A >16B aggregate passes ONE pointer word;
  ## a ≤16B by-value one passes its eightbytes (a FULL eightbyte as a raw `(u 64)` word,
  ## a trailing PARTIAL eightbyte through `loadAggrTail` — exact bytes, no over-read).
  ##
  ## Both staging bridges are live here (the source address and the word carrier), so
  ## the one tail shape that needs a third scratch — a 3/5/6/7-byte aggregate, which has
  ## neither a single covering load nor a full word to borrow from — is refused rather
  ## than silently mis-marshalled. It takes a call with 8+ integer arguments to reach.
  g.bridgeStep("a stack-passed aggregate argument", bdTwoInRegs)
  let tcur = g.getType(a)
  if tcur.kind != Symbol:
    raiseAssert "arkham a64: aggregate stack-arg of non-nominal type"
  let tn = tcur.symId
  let sz = aggrByteSize(g.prog, tn)
  let byRef = sz > g.md.aggrByRefThreshold
  let src = g.takeBridge()
  g.aggrArgAddr(a, src)                                 # &source (by-value) / the pointer (by-ref)
  if byRef:
    g.ab.tree MovA64:
      g.ab.tree MemX: (g.emReg SP; g.ab.tree ArgX: g.ab.sym paramNm)
      g.emReg src
  else:
    let w = g.takeBridge(avoid = src)
    let mw = wordSize()          # the ABI marshalling word (see aggrWordCount)
    for i in 0 ..< aggrWordCount(g.prog, tn):
      if sz - i * mw >= mw:
        g.ab.tree MovA64: (g.emReg w; g.emWordThroughPtr(src, i))
      else:
        if i == 0 and sz notin {1, 2, 4}:
          raiseAssert "arkham arm: " & $sz & "-byte aggregate stack-arg ABI unsupported"
        g.loadAggrTail(w, src, sz, i * mw)
      g.ab.tree MovA64:
        g.ab.tree MemX:
          g.emReg SP
          g.ab.tree ArgX: (g.ab.sym paramNm; g.ab.intLit i.int64)
        g.emReg w
    g.dropBridge w
  g.dropBridge src

proc genNestedAggrField(g: var CodeGen; dst: Location; valC, fty: Cursor) =
  ## Materialize an aggregate field value `valC` (a nested `oconstr`/`aconstr`, an
  ## aggregate symbol, …) of declared field type `fty` into the sub-aggregate at field
  ## `dst`: build it into a synthetic temp through the general `genStore2` (which
  ## recurses for deeper nesting) WITHOUT holding a bridge, then copy that temp through
  ## the field address. Computing the field pointer AFTER the recursive build keeps only
  ## two bridges live at once (the field ptr + the word-transfer temp), so nesting is
  ## not depth-bounded by the bridge count.
  if fty.kind != Symbol:
    raiseAssert "arkham a64n: nested aggregate field of non-nominal type"
  let ntn = fty.symId
  let pos = g.posOf(valC)
  let tmpName = synth("nctmp") & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, slotOf(g.prog, fty)))   # build (no bridge held)
  # The field pointer and the word temp are live together; the source inside
  # `flatCopyToPtr2` is a NAMED slot and costs no register (`AggrEnd`), which is
  # what took this step from three bridges to two.
  g.withBridges(bdTwoInRegs, "a nested-aggregate field copy"):
    let fptr = g.takeBridge()
    g.emFieldAddr(dst, fptr)
    let tmp = g.takeBridge(avoid = fptr)
    g.flatCopyToPtr2(tmpName, aggrByteSize(g.prog, ntn), fptr, tmp)
    g.dropBridge tmp
    g.dropBridge fptr

proc genFieldStore2*(g: var CodeGen; dst: Location; valC: Cursor) =
  ## Store value `valC` into the aggregate-field destination `dst` — the `Field` case of
  ## `genStore2`, and the ONE per-field store behind `genConstr2`. A scalar/float/pointer
  ## field emits its value into the field operand (a POINTER field reinterprets a scalar
  ## via `(cast (ptr …) reg)` for nifasm's strict typing); a nested aggregate field
  ## recurses through `genNestedAggrField`. No per-field special-casing at the call site.
  if dst.typ.kind == AMem:                              # nested aggregate field
    let ftyCur = g.fieldTypeByName(dst.aggrType, dst.field)
    g.genNestedAggrField(dst, valC, ftyCur)
  else:                                                 # scalar / float / pointer field
    var v: Location
    if g.isFloatExpr(valC):
      # Seed the rhs target with the FIELD's slot rather than leaving it
      # `dontCare` — the same lesson as the `Mem` destination in `genStore2`,
      # which this path had not learned. A float LITERAL picks its bit pattern
      # from the destination slot (`emitFValue2`) and the `fstr` below takes its
      # width from `v.typ`; with neither known both default to 64, so a
      # `float32` field gets the DOUBLE pattern written EIGHT bytes wide, over
      # whatever field follows it. `dst.typ` is the field's own slot here (the
      # `AMem` case returned above), so the destination type is the authority.
      v = (if dst.typ.kind == AFloat: Location(kind: Undef, typ: dst.typ)
           else: dontCare)
      g.emitFValue2(valC, v)
    else:
      v = needsReg(g.valueSlot(valC))                   # single-use (allocSingleUse's shape)
      g.emitValue2(valC, v)
    if v.kind == InFReg or v.typ.isFloat:               # float field
      let bits = if v.typ.size == 4: 32 else: 64
      var fr = NoFReg
      var fb = false
      if v.kind == InFReg: fr = v.f
      else:                                             # eftmp spill (pool-dry) → bridge
        fr = g.takeFBridge(bits); g.placeF2(v, fr, bits); fb = true
      g.ab.tree FstrA64: (g.emFieldOperand(dst); g.emFReg(fr, bits))
      if fb: g.dropFBridge()
      elif v.isTemp: g.unbindFTmp(v.f)
    else:
      var fty = resolveType(g.prog, g.fieldTypeByName(dst.aggrType, dst.field))
      var vr = NoReg
      var vb = NoReg
      if v.kind == InReg: vr = v.r
      else:                                             # etmp spill (pool-dry) → bridge
        vb = g.takeBridge(v.typ); g.place2(v, vb); vr = vb
      g.ab.tree MovA64:
        g.emFieldOperand(dst)
        if isPtrType(fty):
          g.ab.tree CastX:
            g.genTypeBody(fty)
            g.emReg vr
        else: g.emReg vr
      if vb != NoReg: g.dropBridge vb
      elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)

proc constrFieldStores*(g: var CodeGen; c: Cursor; base: Location) =
  ## The ONE field-store loop behind `genConstr2`/`genConstrIntoLval2`/nested fields:
  ## walk `(oconstr T child*)` and store each value into its field via the uniform
  ## `genStore2`. `base` names the destination aggregate — a stack slot (`NamedStack`)
  ## or an lvalue subtree (`Mem`, pre-materialized by the caller).
  ##
  ## A child is one of: a `(kv field value)`; a nested `(oconstr BaseT …)` (an
  ## INHERITED base sub-object — recurse, storing the base's fields BY NAME into the
  ## same destination, since nifasm flattens inherited fields); or a leading BARE
  ## value (the inherited base's positional initializer — the RTTI/vtable header at
  ## offset 0; `aggrLayout` lists base fields first). Mirrors the leng C backend.
  var base = base
  var loaded = NoReg
  if base.kind == StackPtr:
    loaded = g.takeBridge()
    g.emScalarLoad(loaded, base.ptrName)
    base = regLoc(loaded, ScalarSlot)
  var tc = c; inc tc                                    # the constructed type symbol
  let typeSym = tc.symId
  var cc = c
  cc.into:
    skip cc                                             # the constructed type
    var posIdx = 0                                      # positional (inherited-base) value index
    template storeField(field: string; valC: Cursor) =
      let fSlot = g.fieldSlotByName(typeSym, field)
      let fdst =
        case base.kind
        of NamedStack: fieldLoc(typeSym, field, base.name, fSlot)
        of InReg:      fieldLocReg(typeSym, field, base.r, fSlot)
        of Mem:        fieldLocLval(typeSym, field, base.cur, fSlot)
        else: raiseAssert "arkham a64n: bad oconstr base " & $base.kind
      g.genStore2(valC, fdst)
    while cc.hasMore:
      if cc.kind == TagLit and cc.exprKind == OconstrC:
        g.constrFieldStores(cc, base)                  # nested inherited-base sub-object
      elif cc.substructureKind == KvU:
        var kv = cc
        kv.into:
          let field = symName(kv); inc kv
          storeField(field, kv)
          while kv.hasMore: skip kv                     # optional inherited-depth INTLIT
      else:                                             # leading bare inherited-base value
        storeField(aggrLayout(g.prog, typeSym)[posIdx].name, cc)
        inc posIdx
      skip cc
  if loaded != NoReg: g.dropBridge loaded

template aconstrElemStores*(g: var CodeGen; c: Cursor; destOp, addrOp: untyped) =
  block:
    var tc = c; inc tc
    let elemTyRaw = innerType(g.prog, resolveType(g.prog, tc))  # nominal element type
    let elemSlot = slotOf(g.prog, elemTyRaw)
    let et = resolveType(g.prog, elemTyRaw)
    let etIsPtr = isPtrType(et)
    var cc = c
    cc.into:
      skip cc
      var i = 0
      while cc.hasMore:
        let valC = cc
        if elemSlot.kind == AMem:                       # nested aggregate element
          let ntn = elemTyRaw.symId
          let pos = g.posOf(valC)
          let tmpName = synth("nctmp") & $pos & ".0"
          g.emTypedStackVar(tmpName, elemTyRaw)
          g.varType[tmpName] = ntn
          g.genStore2(valC, namedStackLoc(tmpName, elemSlot))  # build (no bridge held)
          g.withBridges(bdTwoInRegs, "an `aconstr` aggregate element copy"):
            let eptr = g.takeBridge()
            g.ab.tree LeaA64: (g.emReg eptr; addrOp(i))   # &element[i]
            let tmp = g.takeBridge(avoid = eptr)
            g.flatCopyToPtr2(tmpName, aggrByteSize(g.prog, ntn), eptr, tmp)
            g.dropBridge tmp
            g.dropBridge eptr
          inc i
          skip cc
          continue
        if g.isWideSlot(elemSlot):
          # A 64-bit array element. `destOp(i)` is an `(at …)` operand typed with
          # the ELEMENT type, and a 64-bit-typed move is not one this target has
          # — the eight bytes go through the element's address instead. The value
          # is produced FIRST, because it may contain a call and the address
          # register would not survive one.
          let wnm = g.wideValueIntoTemp(valC)
          let ew = g.takeBridge()
          g.ab.tree LeaA64: (g.emReg ew; addrOp(i))
          g.wideCopyToAddr(wnm, ew)
          g.dropBridge ew
          inc i
          skip cc
          continue
        var v: Location
        if g.isFloatExpr(valC):
          # The ELEMENT's slot, not `dontCare`: `elemSlot` is the authority
          # for a float literal's bit pattern and for the `fstr` width below,
          # so an unseeded `[1.5'f32, …]` initializer wrote the double
          # pattern and every element read back as 0.0.
          v = (if elemSlot.kind == AFloat: Location(kind: Undef, typ: elemSlot)
               else: dontCare)
          g.emitFValue2(valC, v)
        else:
          v = needsReg(ScalarSlot)
          g.emitValue2(valC, v)
        if v.kind == InFReg or v.typ.isFloat:
          let bits = if v.typ.size == 4: 32 else: 64
          var fr = NoFReg
          var fb = false
          if v.kind == InFReg: fr = v.f
          else:                                         # eftmp spill (pool-dry) → bridge
            fr = g.takeFBridge(bits); g.placeF2(v, fr, bits); fb = true
          g.ab.tree FstrA64: (destOp(i); g.emFReg(fr, bits))
          if fb: g.dropFBridge()
          elif v.isTemp: g.unbindFTmp(v.f)
        else:
          var etc = et
          var vr = NoReg
          var vb = NoReg
          if v.kind == InReg: vr = v.r
          else:                                         # etmp spill (pool-dry) → bridge
            vb = g.takeBridge(v.typ); g.place2(v, vb); vr = vb
          g.ab.tree MovA64:
            destOp(i)
            if etIsPtr:
              g.ab.tree CastX:
                g.genTypeBody(etc)
                g.emReg vr
            else: g.emReg vr
          if vb != NoReg: g.dropBridge vb
          elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
        inc i
        skip cc

proc genConstr2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## `dst` is the destination aggregate's own location — a `NamedStack` slot, or a
  ## `StackPtr` whose pointer `constrFieldStores` loads into a base register. (It used
  ## to take the NAME and rebuild a `NamedStack` from it, which erased the difference
  ## and left the pointer case to a predicate re-derived downstream.)
  g.constrFieldStores(c, dst)

proc genAconstr2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## Emit `(aconstr ArrayT e0 e1 …)` into the aggregate destination `dst`. The array
  ## twin of `genConstr2`, and it takes the same `Location` for the same reason: a
  ## `NamedStack` slot IS the array, while a `StackPtr` slot holds a POINTER to it (a
  ## by-ref aggregate param whose pointer the allocator could not keep in a register).
  ## Addressing `(at name idx)` in the second case would write the elements over the
  ## pointer's own 8 bytes and on up the stack, so load the pointer and store through
  ## it — exactly what `constrFieldStores` does for the `oconstr` twin.
  if dst.kind == StackPtr:
    let base = g.takeBridge()
    g.emScalarLoad(base, dst.ptrName)
    var atc = c; inc atc                                # the array type
    let elemTy = innerType(g.prog, resolveType(g.prog, atc))
    template destThroughPtr(i) = g.emPtrElemMem(base, elemTy, i)
    template elemAddrThroughPtr(i) = g.emPtrElemAt(base, elemTy, i)
    g.aconstrElemStores(c, destThroughPtr, elemAddrThroughPtr)
    g.dropBridge base
  else:
    template destInSlot(i) = g.emAggrElemMem(dst.name, i)
    template elemAddrInSlot(i) = g.emAggrElemAt(dst.name, i)
    g.aconstrElemStores(c, destInSlot, elemAddrInSlot)

proc genConstrIntoLval2*(g: var CodeGen; c: Cursor; lhs: Cursor) =
  g.prematLval2(lhs)
  g.constrFieldStores(c, memLoc(lhs, ScalarSlot))            # base = the lvalue subtree
  g.unbindLvalTemps2(lhs)

proc genAconstrIntoLval2*(g: var CodeGen; c: Cursor; lhs: Cursor) =
  g.prematLval2(lhs)
  template dest(i) = g.emLvalElemMem(lhs, i)
  template elemAddr(i) = g.emLvalElemAt(lhs, i)
  g.aconstrElemStores(c, dest, elemAddr)
  g.unbindLvalTemps2(lhs)

proc genBaseobj2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## `(baseobj BaseType depth value)` — an object→base up-conversion (slicing). The base
  ## sub-object is laid out FIRST (offset 0), so the base view is the value's prefix: build
  ## the (derived) `value` into a synthetic temp, then copy the BaseType fields into the
  ## aggregate destination `dst`. Mirror of the x64 path (a64 copies field-by-field).
  assert dst.kind == NamedStack, "arkham a64n: baseobj into " & $dst.kind
  var cc = c
  cc.into:
    let baseTy = cc; skip cc                              # base type (a Symbol)
    skip cc                                               # depth — ignored
    let valC = cc
    let pos = g.posOf(valC)
    let derivedTy = g.getType(valC)
    let dtmp = synth("botmp") & $pos & ".0"
    g.emTypedStackVar(dtmp, derivedTy)
    g.varType[dtmp] = derivedTy.symId
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)))  # build derived
    # The base view is the derived value's PREFIX (base fields first, offset 0), so a
    # flat copy of `sizeof(BaseType)` bytes is exact — and unlike a per-field copy it
    # stays correct when a base field is itself an aggregate.
    g.withBridges(bdTwoInRegs, "a `baseobj` prefix copy"):
      let dptr = g.takeBridge()
      g.ab.tree LeaA64: (g.emReg dptr; g.ab.sym dst.name)
      let tmp = g.takeBridge(avoid = dptr)
      g.flatCopyToPtr2(dtmp, aggrByteSize(g.prog, baseTy.symId), dptr, tmp)
      g.dropBridge tmp
      g.dropBridge dptr
    while cc.hasMore: skip cc

proc aggrAddrLoc*(g: var CodeGen; loc: Location; dest: Reg) =
  ## Address of an aggregate DESTINATION location into the (bound) `dest` — the dst twin
  ## of `aggrAddrInto`.
  case loc.kind
  of NamedStack:
    g.ab.tree LeaA64:
      g.emReg dest
      g.ab.sym loc.name
  of StackPtr: g.emScalarLoad(dest, loc.ptrName)   # the slot already holds the address
  of Glob: g.emGlobalAddr(dest, loc.name)
  of Tvar: g.genTlvAddr(loc.name, dest)
  of Mem: g.aggrAddrInto(loc.cur, dest, addrSlot(), doBind = false)
  else: raiseAssert "arkham a64n: aggrAddrLoc of " & $loc.kind

proc genAggrCopyStore*(g: var CodeGen; rhs: Cursor; dst: Location; size: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce BOTH sides to an address in a register
  ## (`aggrAddrLoc`/`aggrAddrInto`), then `copyAggr`. The allocator reserved
  ## `[dstAddr, srcAddr]`; the per-field transfer register is a staging bridge (x14/x15),
  ## taken here — both addresses are already in `a[0]`/`a[1]`, so a bridge is free — sparing
  ## a pool GPR so the copy fits under high register pressure.
  g.bridgeStep("a whole-aggregate copy", bdTwoInRegs)
  # Emit-time picks: pool temp, else callee-saved survivor, else a staging
  # bridge — the copy crosses no call, so even a bridge-backed address is safe
  # and the acquisition is total. (When both bridges serve as addresses, the
  # transfer register falls back to the produce bridge x16 below.)
  let srcPair =
    if rhs.kind == Symbol: g.plan.homeOfSym(symName(rhs)) else: noLoc
  if dst.kind == InRegPair or srcPair.kind == InRegPair:
    var tn = NoTypeSym
    if rhs.kind == Symbol: tn = g.varType.getOrDefault(symName(rhs), NoTypeSym)
    if tn == NoTypeSym and not cursorIsNil(dst.typ.typ) and dst.typ.typ.kind == Symbol:
      tn = dst.typ.typ.symId
    if tn == NoTypeSym:
      let t = g.getType(rhs)
      if t.kind == Symbol: tn = t.symId
    let nwords = aggrWordCount(g.prog, tn)
    if dst.kind == InRegPair and srcPair.kind == InRegPair:
      for i in 0 ..< nwords:
        let d = pairWord(dst, i)
        let s = pairWord(srcPair, i)
        if d != s: g.movReg(d, s)
    elif dst.kind == InRegPair:
      let addrR = g.takeBridge()
      if rhs.kind == Symbol:
        g.aggrAddrInto(rhs, addrR, addrSlot(), doBind = true)
      else:
        g.emitLvalue2(rhs)
        g.aggrAddrInto(rhs, addrR, addrSlot(), doBind = true)
        g.freeLvalTemps2(rhs)
      for i in 0 ..< nwords:
        g.ab.tree MovA64:
          g.emReg pairWord(dst, i)
          g.emWordThroughPtr(addrR, i)
      g.dropBridge addrR
    else:
      # src InRegPair → memory dest
      let addrR = g.takeBridge()                 # already bound by `takeBridge`
      # A `Mem` destination's embedded base/index values — and the a64 stride scratch
      # a non-scale element size needs — are decided by the lvalue WALK, exactly as in
      # the general copy path below. Without it `aggrAddrLoc` re-emits the address tree
      # with nothing reserved, and a 16-byte element (`s[i] = e` on a `seq[HashEntry]`)
      # has no addressing scale to fold into: nifasm rejects the 2-operand `(at …)`.
      if dst.kind == Mem: g.emitLvalue2(dst.cur)
      g.aggrAddrLoc(dst, addrR)
      if dst.kind == Mem: g.freeLvalTemps2(dst.cur)
      for i in 0 ..< nwords:
        g.ab.tree MovA64:
          g.emWordThroughPtr(addrR, i)
          g.emReg pairWord(srcPair, i)
      g.dropBridge addrR
    return
  var a0, a1: Reg
  var h0 = dontCare
  var h1 = dontCare
  var b0 = NoReg
  var b1 = NoReg
  block:
    var r = g.pickTempReg()
    if r == NoReg: r = g.pickHeldReg()
    # Before a bridge: any register with no LIVE binding (`pickStagingA64`). The copy
    # crosses no call, so a caller-saved one is as good as a survivor — and every
    # bridge left free here is one the two addresses' own materialization can use.
    if r == NoReg: r = g.pickStagingA64()
    if r != NoReg:
      g.pickedRegs.incl r; h0 = regLoc(r, ScalarSlot, isTemp = true); a0 = r
    else:
      b0 = g.takeBridge(); a0 = b0
  if dst.kind == Mem:
    g.emitLvalue2(dst.cur)                 # pick the dst lvalue's embedded values
  g.bindTemp(a0, ScalarSlot); g.aggrAddrLoc(dst, a0)             # &dst
  if dst.kind == Mem: g.freeLvalTemps2(dst.cur)
  # The SOURCE register is reserved only NOW, after `&dst` is in `a0`. Reserving
  # both up front used to hand the two bridges out before either address was
  # materialized — and materializing a `Mem` destination whose base or index is
  # itself spilled needs a bridge of its own (`reloadMemBase2`), which was then
  # gone. Deferring costs nothing: `a1` is not read until `&rhs` is emitted, and
  # any bridge the destination borrowed is back by then.
  block:
    var r = g.pickTempReg()
    if r == NoReg: r = g.pickHeldReg()
    if r == NoReg: r = g.pickStagingA64()
    if r != NoReg:
      g.pickedRegs.incl r; h1 = regLoc(r, ScalarSlot, isTemp = true); a1 = r
    else:
      b1 = g.takeBridge(avoid = b0); a1 = b1
  g.bindTemp(a1, ScalarSlot)
  if rhs.kind == TagLit:
    g.emitLvalue2(rhs)                     # pick the src lvalue's embedded values
  g.aggrAddrInto(rhs, a1, addrSlot(), doBind = false)  # &rhs
  if rhs.kind == TagLit: g.freeLvalTemps2(rhs)
  var tmp: Reg
  if b0 != NoReg and b1 != NoReg:
    tmp = g.takeProduceBridge(addrSlot())   # both staging bridges gone: r8/x16 serves
  else:
    tmp = g.takeBridge(addrSlot())
  g.copyAggr(a0, a1, size, tmp)
  g.dropBridge tmp                   # unbind (uniform for a bridge or x16)
  g.unbindTemp(a1); g.unbindTemp(a0)
  g.freeVal(h1); g.freeVal(h0)

proc genStore2*(g: var CodeGen; rhs: Cursor; dst: Location) =
  ## The general destination-passing store: emit `rhs` so its value lands at `dst`. An
  ## aggregate COPY goes through the ONE `genAggrCopyStore`; constructors/calls/baseobj
  ## PRODUCE per-form; a scalar/float destination through `storeScalar2`.
  g.bridgeStep("`genStore2`")                           # I1 + I2
  # A `Mem` destination's `typ` is often the dont-care `ScalarSlot` (the lvalue
  # subtree is the authority, not the Location), so its width is read off the
  # subtree — otherwise a 64-bit `obj.field` store looks like a word one.
  let dstIsWide = (if dst.kind == Mem: g.isWideExpr(dst.cur)
                   else: g.isWideSlot(dst.typ))
  if dstIsWide or g.isWideExpr(rhs):
    if dst.kind == InReg:
      # The one register destination a wide value can legitimately have is the
      # ABI result register — `(ret …)` routes through here. Everything else
      # would be a 64-bit value asked to fit in 32 bits.
      if dst.r == g.md.intRetReg: g.wideRet(rhs)
      else:
        raiseAssert "arkham cortex-m: 64-bit value into register " & $dst.r
    else:
      g.emitWideIntoLoc(rhs, dst)
    return
  let (dstAggr, aggrSize) = g.dstAggrInfo(dst)
  if dstAggr and isAggrCopySrc(rhs):                         # the ONE whole-aggregate copy path
    g.genAggrCopyStore(rhs, dst, aggrSize)
    return
  if rhs.kind == TagLit and rhs.exprKind in {ConvC, CastC} and
     g.exprSlot(rhs).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (`Path(s)` for
    # `Path = distinct string`) is byte-transparent — store its underlying operand into
    # the same destination (allocator twin in `allocStore`).
    var inner = rhs
    inner.into:
      skip inner                                             # the target type
      g.genStore2(inner, dst)                        # the operand → same dest
      while inner.hasMore: skip inner
    return
  if dst.kind in {NamedStack, StackPtr} and dst.typ.kind == AMem:
    # `StackPtr` reaches its aggregate through the slot's pointer; `NamedStack` IS it.
    let dstVar = (if dst.kind == StackPtr: dst.ptrName else: dst.name)
    let tn = (if dst.kind == StackPtr: dst.pointeeType else: g.varType[dstVar])
    if rhs.kind == TagLit and rhs.exprKind == OconstrC: g.genConstr2(rhs, dst)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.genAconstr2(rhs, dst)
    elif rhs.kind == TagLit and rhs.exprKind == CallC:
      if aggrByteSize(g.prog, tn) > 2 * wordSize():   # the same rule as `retIndirect`
        if dst.kind == StackPtr:
          g.emScalarLoad(g.indirectResultReg, dst.ptrName)
        else:
          g.ab.tree LeaA64: (g.emReg g.indirectResultReg; g.ab.sym dstVar)
        var d = dontCare
        g.emitCall2(rhs, d, hiddenPtr = true)            # the callee writes through x8
      else:
        var d = dontCare
        g.emitCall2(rhs, d)                              # ≤16B result in x0:x1
        g.regsToStruct(dstVar, tn, 0)
    elif rhs.kind == TagLit and rhs.exprKind == BaseobjC:
      g.genBaseobj2(rhs, dst)                              # object→base slice
    else: raiseAssert "arkham a64n: aggregate store rhs " & $rhs.exprKind
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AMem:
    # Aggregate store into a GLOBAL or a THREADVAR: address it into a pointer scratch
    # and build/copy the aggregate THROUGH that pointer — `oconstr` field-by-field
    # (InReg base), a symbol by whole-aggregate copy, a call by its ABI (>16B → &g as
    # the hidden result ptr x8; ≤16B → the result regs x0:x1 stored through &g). The
    # &g address temp is a callee-saved survivor picked at emission (`takeHeld`), so
    # it also outlives the macOS TLV thunk behind a threadvar's `(adr …)`.
    if rhs.kind == TagLit and rhs.exprKind == CallC and
       dst.typ.size > g.md.aggrByRefThreshold:
      g.emAdr(g.indirectResultReg, dst.name)        # wide result: &g is the hidden ptr
      var d = dontCare
      g.emitCall2(rhs, d, hiddenPtr = true)
    else:
      # The &g address scratch, held across the build: a callee-saved survivor
      # (a call rhs clobbers every volatile).
      var heldLoc = g.takeHeld("an aggregate global &g")
      let addrT = heldLoc.r
      g.bindTemp(addrT, ScalarSlot)
      # Materialize &g BEFORE anything else, the call rhs included: the value the
      # callee leaves in x0:x1 is exactly what a threadvar's TLV thunk would use as
      # its own argument and result register.
      g.emAdr(addrT, dst.name)
      if rhs.kind == TagLit and rhs.exprKind == OconstrC:
        g.constrFieldStores(rhs, regLoc(addrT, dst.typ))
      elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
        var atc = rhs; inc atc                            # the array type
        let elemTy = innerType(g.prog, resolveType(g.prog, atc))
        template dest(i) = g.emPtrElemMem(addrT, elemTy, i)  # element i through &g
        template elemAddr(i) = g.emPtrElemAt(addrT, elemTy, i)
        g.aconstrElemStores(rhs, dest, elemAddr)
      elif rhs.kind == TagLit and rhs.exprKind == CallC:  # ≤16B result in x0:x1
        var d = dontCare
        g.emitCall2(rhs, d)
        g.regsToStructThroughPtr(addrT, g.getType(rhs).symId, 0)
      else: raiseAssert "arkham a64n: aggregate global store rhs " & $rhs.exprKind
      g.unbindTemp(addrT)
      g.freeVal(heldLoc)
  elif dst.kind in {Glob, Tvar}:                             # scalar/float/pointer global/tvar
    if dst.typ.kind == AFloat:
      # `dst.typ` is the global's own float slot and the `bits` below already
      # trusts it; the VALUE has to trust it too, or a float literal builds
      # the double pattern and `emFStore` writes its low half — `gf = 3.5'f32`
      # on a `float32` global stored 0.0.
      var fv = Location(kind: Undef, typ: dst.typ)
      g.emitFValue2(rhs, fv)
      let bits = if dst.typ.size == 4: 32 else: 64
      var fr = NoFReg
      var fb = false
      if fv.kind == InFReg: fr = fv.f
      else:                                              # eftmp spill (pool-dry) → bridge
        fr = g.takeFBridge(bits); g.placeF2(fv, fr, bits); fb = true
      let b = g.takeBridge()
      if dst.kind == Glob: g.emAdr(b, dst.name) else: g.genTlvAddr(dst.name, b)
      g.emFStore(fr, b, bits)
      g.dropBridge b
      if fb: g.dropFBridge()
      elif fv.kind == InFReg and fv.isTemp: g.unbindFTmp(fv.f)
    else:
      var v = needsReg(g.valueSlot(rhs))                 # single-use rhs (allocSingleUse's shape)
      g.emitValue2(rhs, v)
      var vb = NoReg
      var vr: Reg
      if v.kind == InReg: vr = v.r
      else: (vb = g.takeBridge(); g.place2(v, vb); vr = vb)
      g.storeReg2(dst, vr)
      if vb != NoReg: g.dropBridge vb
      elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
  elif dst.kind == Mem:                                      # store through complex lvalue
    let wr = g.pairFieldReg(dst.cur)
    if wr != NoReg:
      var v = regLoc(wr, if dst.typ.size > 0: dst.typ else: ScalarSlot)
      g.emitValue2(rhs, v)
      return
    let lhs = dst.cur
    # A global aggregate base in the lvalue needs an address scratch, held across the
    # rhs; bind it so prematLval2's `lea scratch, &g` emits a checked name. Only
    # a CONSTRUCTOR build holds `&g` across the rhs (a scalar store emits the rhs
    # FIRST, so its global base is a plain walk pick — no survivor needed).
    var globScratch = NoReg
    var globHeld = dontCare
    if (rhs.kind == TagLit and rhs.exprKind in {OconstrC, AconstrC}) and
       g.lvalueGlobalBase(lhs):
      globHeld = g.takeHeld("a global address")
      globScratch = globHeld.r
    if globScratch != NoReg: g.bindTemp(globScratch, ScalarSlot)
    let globBaseLoc = (if globScratch != NoReg: regLoc(globScratch, ScalarSlot)
                       else: dontCare)
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genConstrIntoLval2(rhs, lhs)
      g.freeLvalTemps2(lhs)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genAconstrIntoLval2(rhs, lhs)
      g.freeLvalTemps2(lhs)
    else:
      var v: Location
      if g.isFloatExpr(rhs):
        # Seed the rhs target with the DESTINATION's slot rather than leaving it
        # `dontCare`. Two things downstream read a width that `dontCare` does not
        # carry: a float LITERAL picks its bit pattern from the destination slot
        # (`emitFValue2`), and the `fstr` below takes its width from `v.typ`. With
        # neither known both defaulted to 64, so `a[0] = 1.0'f32` on a
        # `float32` element wrote the DOUBLE pattern, eight bytes wide, over its
        # neighbour — and read back as 0.0 because the low half of `1.0` is zero.
        #
        # The destination type is the authority here, exactly as it is for a
        # conversion's target type (see the same lesson recorded in
        # `codegen_x64.emitCast2`).
        let lhsSlot = g.exprSlot(lhs)
        v = (if lhsSlot.kind == AFloat: Location(kind: Undef, typ: lhsSlot)
             else: dontCare)
        g.emitFValue2(rhs, v)                            # rhs value FIRST
      else:
        v = needsReg(ScalarSlot)
        g.emitValue2(rhs, v)
      # lvalue picks AFTER the rhs: the live rhs value is a bound temp, so the
      # picks cannot land on it. `isStore=false`: the rhs is done, nothing must
      # survive it — the walk takes an ordinary temp for a global base.
      g.emitLvalue2(lhs, globBaseLoc, isStore = false)
      let floatRhs = v.kind == InFReg or (v.kind in {NamedStack, Mem} and v.typ.isFloat)
      g.prematLval2(lhs)
      if floatRhs:
        let bits = if v.typ.size == 4: 32 else: 64
        var fr = NoFReg
        if v.kind != InFReg: (fr = g.takeFBridge(bits); g.placeF2(v, fr, bits))
        else: fr = v.f
        g.ab.tree FstrA64:
          g.ab.tree MemX: g.emLvalAddr2(lhs)
          g.emFReg(fr, bits)
        if v.kind != InFReg: g.dropFBridge()
        elif v.isTemp: g.unbindFTmp(v.f)
      else:
        var dstTy = resolveType(g.prog, g.getType(lhs))
        let dstPtr = isPtrType(dstTy)
        var vr = NoReg
        var vBridge = NoReg
        if v.kind == Imm:
          discard
        elif v.kind == InReg: vr = v.r
        else: (vBridge = g.takeBridge(v.typ); g.place2(v, vBridge); vr = vBridge)
        g.ab.tree MovA64:
          g.ab.tree MemX: g.emLvalAddr2(lhs)
          if v.kind == Imm: g.emImm(v)
          elif dstPtr:
            g.ab.tree CastX:
              g.genTypeBody(dstTy)
              g.emReg vr
          else: g.emReg vr
        if vBridge != NoReg: g.dropBridge vBridge
        elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
      g.unbindLvalTemps2(lhs)
      # A STORE: the `(mem …)` was the destination operand, so every register in
      # the address was only read and a global base still holds `&g` — keep it as
      # an address mirror for the next access to the same global.
      g.freeLvalTemps2(lhs, addrIntact = true)
    if globScratch != NoReg: g.unbindTemp(globScratch)
    g.freeVal(globHeld)
  elif dst.kind == Field:                                    # a field within an aggregate
    g.genFieldStore2(dst, rhs)
  else:                                                      # scalar / float register or `(s)` slot
    # Dest threading: a register home receives the rhs DIRECTLY (the store
    # collapses); a slot home takes a single-use temp then stores. Never
    # thread a NamedStack dest into emitValue2 — leaves would emit nothing.
    if dst.kind == InFReg:
      var v = dst
      g.emitFValue2(rhs, v)
      g.storeScalar2(dst, v)
    elif dst.kind == InReg:
      var v = dst
      g.emitValue2(rhs, v)
      g.storeScalar2(dst, v)
    elif dst.typ.isFloat:
      var v = g.takeFTmp(dst.typ)                # carry the precise (f N) width
      g.emitFValue2(rhs, v)
      g.storeScalar2(dst, v)
      g.freeVal(v)
    else:
      var v = needsReg(dst.typ)
      g.emitValue2(rhs, v)
      g.storeScalar2(dst, v)
      g.freeVal(v)

# ── fused value core (step 3): implementations ──────────────────────────────

proc emitLeafImm*(g: var CodeGen; dest: var Location; natural: Location) =
  ## FUSED literal leaf: resolve the constraint against the immediate; a
  ## register destination gets it materialized (binding a fresh temp first).
  ##
  ## A Leng literal carries no type of its own — `42` and `'a'` are typed by where
  ## they go — so the callers hand one over as a dont-care slot. Take the type from
  ## the DESTINATION when it has one, or the temp minted below is bound `(i 64)`
  ## and a `(c 8)` value loses its range and signedness on the way in.
  var natural = natural
  if cursorIsNil(natural.typ.typ) and not cursorIsNil(dest.typ.typ):
    natural.typ = dest.typ
  g.resolveDest(dest, natural)
  if dest.kind == InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.placeImm(dest.r, natural)
  elif dest.kind == NamedStack and dest.spillTemp:
    # `needsReg` under a dry pool minted an etmp slot: the literal MUST be
    # stored into it (silently skipping it hands the consumer's reload
    # garbage) — through the produce bridge, like produceIntoMem2.
    let s = g.takeProduceBridge(dest.typ)
    g.placeImm(s, natural)
    g.storeReg2(dest, s)
    g.unbindTemp(s)

proc produceIntoMem2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## FUSED totality bridge: `dst` is an `(s)` spill slot (`etmpN.0`, minted when
  ## `takeTmp` found the pools dry). Produce into the reserved produce bridge
  ## x16 (never allocator-assigned), then store to the slot.
  ##
  ## x16 is handed to `emitValue2` for the WHOLE node, so it is live for the
  ## node's entire evaluation — the old claim that it is "not held across the
  ## recursion, so deep chains reuse it level-by-level" holds only for a leaf and
  ## for a load. For a COMBINING node it is false: `emitBin2` computes its
  ## accumulator here and then evaluates the other operand, which re-enters this
  ## proc and would scribble on the partial. That is a silent miscompile — it
  ## returned a pointer where a sum was expected (`addr_chain_depth`).
  ##
  ## The invariant is therefore "x16 is FREE on entry", and it is the CALLER's to
  ## keep: a step that would hold its partial here across a sibling recursion must
  ## not put it here in the first place — see `emitBin2`'s swap suppression.
  ##
  ## What this side CAN do is stop the register looking free while it is not. The
  ## destination is threaded into `emitValue2` UNBOUND (a leaf may produce raw into
  ## it, and only then is it bound for the store), so a nested draw testing
  ## `isBoundTemp` would have called it free and handed it out. `pickedRegs` is the
  ## reserve→bind gap's existing guard everywhere else in this emitter, and it is
  ## what the draw now consults too.
  let s = g.produceBridge                                 # x16 (IP0) / r8
  g.pickedRegs.incl s                                     # reserved until `unbindTemp`
  # Stage at the canonical 64-bit width for a sub-word INTEGER destination. arkham
  # keeps every scalar full-width in a register (a narrowing is an explicit extend,
  # never the move), the `(s)` slot is declared `(i 64)` regardless, and the store
  # into it is sized by the SLOT either way — so this changes no machine code. Bound
  # at the narrow destination width instead, the move that brings the value in was a
  # narrowing reg→reg move (`(mov (u 32)bridge (u 64)zi`, `cast[uint32](zi)` spilled
  # in `toDecimal64`), which nifasm rejects. Same rule, same reason, as `emitCast2`.
  var slot = dst.typ
  if slot.cls in {ABool, AInt, AUInt} and slot.size < 8: slot = ScalarSlot
  var d = regLoc(s, slot, isTemp = true)
  g.emitValue2(c, d)
  if not g.rb.isBoundTemp(s): g.bindTemp(s, slot)         # a leaf produced raw: bind for the store
  g.storeReg2(dst, s)
  g.unbindTemp(s)

proc produceIntoFMem2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## The SIMD twin: produce into the float bridge (v31), then store.
  let bits = dst.typ.size * 8
  let fs = g.md.floatBridgeReg
  var d = fregLoc(fs, dst.typ, isTemp = true)
  g.emitFValue2(c, d)
  if not g.rb.isBoundFTmp(fs): g.bindFTmp(fs, bits)
  g.emFloatScalarStore(dst.name, fs, bits)
  g.unbindFTmp(fs)

proc emitValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED decide-and-emit (a64): resolve `dest` against `c`, emit, return the
  ## resolved location. Callers route float-typed values to `emitFValue2`.
  g.bridgeStep("`emitValue2`")                          # I1 + I2
  if g.isWideExpr(c):
    # A 64-bit value on a 32-bit target has no register to be resolved into: it
    # is eight bytes at an address, and `codegen_m64` is the arm that knows how
    # to put them there.
    g.emitWideAsLoc(c, dest)
    return
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest)
    return
  let pos = g.posOf(c)                            # for the keepovf no-fold guard
  case c.kind
  of IntLit: g.emitLeafImm(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.emitLeafImm(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.emitLeafImm(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  of Symbol:
    # THE read side of store forwarding: a value whose home is a stack slot may
    # still be in the register that stored it there. Which door depends on where
    # the location GOES — an unconstrained `dest` is returned to the caller, which
    # may emit more code before consuming it, so the register is handed over
    # (`takeForwarded`, released by the caller's `freeVal` like any temp); a FIXED
    # destination is served by the very next instruction, where the cheaper
    # unowned read is enough and leaves the mirror alive for later reads.
    let symHome = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    let home = (if dest.kind in {Undef, NeedsReg, RegOrImm}: g.takeForwarded(symHome)
                else: g.forwardOf(symHome))
    if home.kind != NoLoc:
      g.resolveDest(dest, home)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      if dest.kind == InReg and dest.isTemp and home.kind == InReg and
         home.r == dest.r and g.rb.isMirror(dest.r):
        # The accumulator IS the register still mirroring this value — the load is
        # already done. Take the register over from the mirror (a `(rebind …)`,
        # zero machine code): the consumer may now write it in place, and a mirror
        # the consumer overwrites is the one way this map goes wrong.
        g.bindTemp(dest.r, dest.typ)
      if dest.kind == InReg and not (home.kind == InReg and home.r == dest.r):
        if dest.isTemp and not g.rb.isBoundTemp(dest.r):
          g.bindTemp(dest.r, dest.typ)
        g.place2(home, dest.r)
    else:
      g.forceRegDest(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      let si = g.lookupSym(symName(c))
      if si.cat == scProc:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        g.emAdr(dest.r, si.asmName)
      else:
        var cc = c
        let loc = g.asLoc(cc)
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, loc.typ)
        g.place2(loc, dest.r)
  of StrLit:
    g.forceRegDest(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let nm = "msg." & $g.rodata.len & "." & g.prog.thisModuleSuffix
    # NUL-terminated: a literal's address alone does not say whether the callee reads
    # it as a `cstring` or as a length-carrying `string` payload. See the x86-64 twin.
    g.rodata.add (nm, strVal(c) & '\0')
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.emAdr(dest.r, nm)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitBin2(c, dest)
    of ModC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitMod2(c, dest)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC: g.emitCondValue2(c, dest)
    of DerefC, DotC, AtC, PatC: g.emitMemLoad2(c, dest)
    of AddrC, HaddrC: g.emitAddr2(c, dest)
    of CastC, ConvC: g.emitCast2(c, dest)
    of CallC: g.emitCall2(c, dest)
    of InstrC: g.emitInstr2(c, dest)
    of NegC, BitnotC:
      block:
        let (isConst, cval) =
          (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
        if isConst:
          g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
          return
      g.forceRegDest(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      var resType, inner: Cursor
      block:
        var cc = c
        cc.into:
          resType = cc; skip cc                   # result type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      var iv = dest                               # dest-thread into the operand
      g.emitValue2(inner, iv)
      if dest.kind == InReg:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r) and
           not (iv.kind == InReg and iv.r == dest.r):
          g.bindTemp(dest.r, dest.typ)
        if iv.kind == InReg and iv.r != dest.r: g.movReg(dest.r, iv.r)
        elif iv.kind != InReg: g.place2(iv, dest.r)
        g.emNeg(dest.r)
        if c.exprKind == BitnotC: g.binImm(SubA64, dest.r, 1)  # ~a = -a - 1
        g.normalizeUnaryWidth(resType, dest.r)
        if not (iv.kind == InReg and iv.r == dest.r): g.freeVal(iv)
    of SufC, ParC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitValue2(inner, dest)
    of TrueC: g.emitLeafImm(dest, immLoc(1, ScalarSlot))
    of FalseC: g.emitLeafImm(dest, immLoc(0, ScalarSlot))
    of NilC:
      g.resolveDest(dest, immLoc(0, g.exprSlot(c)))
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      if dest.kind == InReg:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        g.ab.tree MovA64: (g.emReg dest.r; g.ab.nilValue())
    of SizeofC:
      var t = c; var sz = 0'i64
      t.into:
        sz = typeSizeAlign(g.prog, t)[0].int64
        while t.hasMore: skip t
      g.emitLeafImm(dest, immLoc(sz, ScalarSlot))
    else: raiseAssert "arkham a64n: emitValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emitValue2(fused) kind " & $c.kind

# ── fused value core: unconverted-proc stubs (die as each case lands) ────────
proc emitDivPow2(g: var CodeGen; c, resTypeC, lhsC: Cursor; k: int;
                 dest: var Location) =
  ## `x div 2^k` without a divide. `udiv`/`sdiv` are 8–12 cycles and unpipelined on
  ## the A76-class cores this targets, and `nifcore.leaveScope` — ten instructions
  ## of work, run once per subtree the whole toolchain walks — spent one of them
  ## dividing a byte count by `sizeof(NifToken)`.
  ##
  ## Unsigned is one `lsr`. Signed needs the round-toward-zero fixup: `asr` alone
  ## rounds toward MINUS INFINITY, so `-1 div 2` would come out -1 instead of 0.
  ## Bias by 2^k-1 first, but only when the value is negative — which `asr #63`
  ## (all ones or all zeros) turns into a branchless mask.
  ##
  ## Both work at the full 64-bit register width whatever the type's own width is,
  ## because a sub-64-bit value is already canonically extended into the register
  ## (the invariant `normalizeBinWidth` maintains), and both `lsr` and `asr` of a
  ## canonical value leave a canonical one.
  let signed = isSignedType(resolveType(g.prog, resTypeC))
  var acc = dest
  if acc.kind != InReg: acc = g.takeTmp(g.binResultSlot(resTypeC))
  if acc.kind == NamedStack and acc.spillTemp:
    g.produceIntoMem2(c, acc)                            # pools dry: whole node via x16
    dest = acc
    return
  let rD = acc.r
  var ldst = acc
  g.emitValue2(lhsC, ldst)                               # dividend → the accumulator
  if acc.isTemp and not g.rb.isBoundTemp(rD): g.bindTemp(rD, acc.typ)
  g.retypeBinDest(rD, resTypeC, inheritedOperand = false)
  if signed:
    let t = g.takeBridge(avoid = rD)
    g.binImm3(AsrA64, t, rD, 63)                         # t := x < 0 ? -1 : 0
    g.binImm3(LsrA64, t, t, 64 - k)                      # t := x < 0 ? 2^k-1 : 0
    g.binReg(AddA64, rD, t)                              # x += bias
    g.dropBridge t
    g.binImm(AsrA64, rD, k)
  else:
    g.binImm(LsrA64, rD, k)
  dest = acc

proc emitModPow2(g: var CodeGen; c, resTypeC, lhsC: Cursor; k: int;
                 dest: var Location) =
  ## `x mod 2^k` for an UNSIGNED `x` — one `and` with the low-k mask, in place of a
  ## divide, a multiply and a subtract. `2^k-1` is a run of ones, hence always a
  ## valid AArch64 logical immediate for k in 1..63.
  ##
  ## Signed is deliberately NOT here: `-3 mod 2` is -1, which the mask does not
  ## give, and the correction sequence is long enough that it stops being an
  ## obvious win over `sdiv`+`msub`.
  var acc = dest
  if acc.kind != InReg: acc = g.takeTmp(g.binResultSlot(resTypeC))
  if acc.kind == NamedStack and acc.spillTemp:
    g.produceIntoMem2(c, acc)
    dest = acc
    return
  let rD = acc.r
  var ldst = acc
  g.emitValue2(lhsC, ldst)
  if acc.isTemp and not g.rb.isBoundTemp(rD): g.bindTemp(rD, acc.typ)
  g.retypeBinDest(rD, resTypeC, inheritedOperand = false)
  g.binImm(AndA64, rD, (1'i64 shl k) - 1)
  dest = acc

proc emitBin2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 binary-arith: the shared allocBin policy decided inline
  ## (Sethi–Ullman swap, dest passthrough, rhs recycling, aliasRhs), emitted
  ## with the a64 non-destructive 3-op / W-form machinery.
  g.bridgeStep("a binary op with a spilled result", bdTwoInRegs)
  let op = g.binA64Op(c)
  let ek = c.exprKind
  var lhsC, rhsC, resTypeC: Cursor
  block:
    var cc = c
    cc.into:
      resTypeC = cc; skip cc                             # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  checkArithResultType(g.prog, resTypeC, lengInfo(c))
  if ek == DivC:
    let k = g.pow2Log(rhsC)
    if k > 0:
      g.emitDivPow2(c, resTypeC, lhsC, k, dest)
      return
  let lhsMem = g.isFoldableMemLeaf(lhsC)
  let swap = ek notin {ShlC, ShrC} and (commutativeExpr(ek) or ek == SubC) and
             (g.isFoldableLeaf(lhsC) or lhsMem) and
             not (g.isFoldableLeaf(rhsC) or g.isFoldableMemLeaf(rhsC)) and
             not (dest.kind == InReg and g.symInReg(lhsC, dest.r))
  if swap:
    var acc = dest
    # The accumulator ends up holding the RESULT, so it is bound at the result's
    # own type — an `(i 64)` dont-care would throw the value's range away.
    if acc.kind != InReg: acc = g.takeTmp(g.binResultSlot(resTypeC))
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoMem2(c, acc)                          # pools dry: whole node via x16
      dest = acc
      return
    let rD = acc.r
    var rdst = acc
    g.emitValue2(rhsC, rdst)                             # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundTemp(rD): g.bindTemp(rD, acc.typ)
    # Same retype the general path does below: the accumulator may be a named
    # local's home whose declared type is not the type of the value now landing
    # in it (an integer computed into a `(ptr …)` local under an enclosing cast).
    g.retypeBinDest(rD, resTypeC, inheritedOperand = false)
    var lLoc = dontCare                                  # the leaf lhs: its natural place
    if lhsMem:
      g.emitLvalue2(lhsC)                                # pick embedded base/index regs
      lLoc = memLoc(lhsC, ScalarSlot)
    else:
      g.resolveLvalVal(lhsC, lLoc)
    let foldOp = if op == SubA64: AddA64 else: op
    if op == SubA64:
      g.emNeg(rD)                       # rD := -rhs
    g.foldRhs2(foldOp, rD, lLoc, lhsC)                   # bridges serve Imm/slot/Mem lhs
    if lhsMem: g.freeLvalTemps2(lhsC)
    g.normalizeBinWidth(resTypeC, rD, op)
    dest = acc
    return
  var lDest = needsReg(g.binResultSlot(resTypeC))
  if dest.kind == InReg and ek notin {ShlC, ShrC} and
     not g.isFoldableLeaf(lhsC) and
     (g.isFoldableLeaf(rhsC) or g.isFoldableMemLeaf(rhsC)) and
     not g.exprReadsReg(lhsC, dest.r) and not g.exprReadsReg(rhsC, dest.r):
    lDest = dest                                         # compute lhs straight into dest
  g.emitValue2(lhsC, lDest)
  # The lhs partial is LIVE in `lDest` across the rhs evaluation, which recurses
  # into arbitrary emission — see the x86-64 twin for the failure this prevents.
  # A bound temp is already excluded from every pick; a fixed destination carries
  # no binding, so say what it is holding.
  let lSeal = lDest.kind == InReg and not g.plan.isSealed(lDest.r) and
              not g.rb.isBoundTemp(lDest.r)
  if lSeal: g.plan.seal {lDest.r}
  var rDest = dontCare
  if ek == DivC: rDest = needsReg(g.valueSlot(rhsC))     # sdiv/udiv need a register rhs
  g.emitValue2(rhsC, rDest)
  if lSeal: g.plan.unseal {lDest.r}                        # the partial is consumed below
  var res = dest
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: res = lDest # in-place on the dead lhs temp
    elif rDest.kind == InReg and rDest.isTemp and lDest.kind == InReg and
         ek notin {ShlC, ShrC, DivC}:
      res = rDest                                        # recycle the dead rhs temp
    else: res = g.takeTmp(g.binResultSlot(resTypeC))
  else: discard
  let aliasRhs = res.kind == InReg and rDest.kind == InReg and res.r == rDest.r and
                 not (lDest.kind == InReg and res.kind == InReg and lDest.r == res.r)
  if aliasRhs and ek in {ShlC, ShrC}:
    raiseAssert "arkham: variable shift whose destination aliases the count register"
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:                      # incl. a takeTmp-dry etmp slot
    resStaging = g.takeBridge(res.typ)
    rD = resStaging
  else:
    assert res.kind == InReg, "arkham a64n: bin result " & $res.kind
    rD = res.r
  let reusedLhs = lDest.kind == InReg and lDest.r == rD
  let reusedRhs = rDest.kind == InReg and rDest.r == rD
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(rD):
    g.bindTemp(rD, res.typ)
  g.retypeBinDest(rD, resTypeC, reusedLhs or reusedRhs)
  let w32 = op in {AddA64, SubA64, MulA64} and not aliasRhs and isUnsigned32(resTypeC)
  if aliasRhs:
    assert lDest.kind == InReg, "arkham a64n: aliasRhs lhs " & $lDest.kind
    if op in {UdivA64, SdivA64}:
      # `dest := rhs op lhs` below relies on the op being commutative (or, for
      # `sub`, fixable by a following `neg`). Division is neither: computing
      # `512 div x` where `x div 512` was asked for is silently wrong. Move the
      # divisor out of the destination first and emit the operands in order.
      let b = g.takeBridge(avoid = rD)
      g.movReg(b, rD)                                    # b := rhs (the divisor)
      g.place2(lDest, rD)                                # dest := lhs
      g.binReg(op, rD, b)                                # dest := lhs div rhs
      g.dropBridge b
    else:
      g.binReg(op, rD, lDest.r)                          # dest := rhs op lhs
      if op == SubA64:
        g.emNeg(rD)                     # dest := lhs - rhs
  elif lDest.kind == InReg and lDest.r != rD and op in ThreeOpA64:
    g.foldRhs3(op, rD, lDest.r, rDest, rhsC, w32)        # dest := lhs op rhs (no mov)
  else:
    g.place2(lDest, rD)                                  # dest := lhs
    g.foldRhs2(op, rD, rDest, rhsC, w32)                 # dest op= rhs
  if not w32:
    g.normalizeBinWidth(resTypeC, rD, op)
  if not reusedRhs: g.freeVal(rDest)
  if not reusedLhs: g.freeVal(lDest)
  if resStaging != NoReg:
    g.storeReg2(res, resStaging)
    g.dropBridge resStaging
  dest = res

proc emitMod2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(mod T a b)` → `dest = a - (a div b)*b` (allocDivModRisc's placement
  ## decided inline).
  g.bridgeStep("a `mod` with a spilled result", bdTwoInRegs)
  var rt, divC, dvsC: Cursor
  block:
    var cc = c
    cc.into:
      rt = cc; skip cc
      divC = cc; skip cc
      dvsC = cc; skip cc
      while cc.hasMore: skip cc
  let signed = isSignedType(rt)
  if not signed:
    let k = g.pow2Log(dvsC)
    if k > 0:
      g.emitModPow2(c, rt, divC, k, dest)
      return
  var lD = needsReg(g.valueSlot(divC))
  g.emitValue2(divC, lD)
  var rD0 = needsReg(g.valueSlot(dvsC))
  g.emitValue2(dvsC, rD0)
  var dvsReg: Reg
  var dvsBridge = NoReg
  if rD0.kind == InReg:
    dvsReg = rD0.r
  else:                                                  # pool-dry etmp divisor: bridge reload
    dvsBridge = g.takeBridge(rD0.typ)
    g.place2(rD0, dvsBridge)
    dvsReg = dvsBridge
  var res = dest
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lD.kind == InReg and lD.isTemp: res = lD          # reuse the dead dividend temp
    else: res = g.takeTmp(g.binResultSlot(rt))
  else: discard
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:
    resStaging = g.takeBridge(res.typ); rD = resStaging
  else:
    assert res.kind == InReg, "arkham a64n: mod result " & $res.kind
    rD = res.r
  let reusedDiv = lD.kind == InReg and lD.r == rD
  if res.kind == InReg and res.isTemp and not reusedDiv and not g.rb.isBoundTemp(rD):
    g.bindTemp(rD, res.typ)
  g.place2(lD, rD)                                       # dest := a
  # `a mod b` needs THREE live registers — a, b and the quotient — and this one
  # expression can already be holding both bridges: one staging a memory result,
  # one reloading a spilled divisor. The budget is two, so when they are gone the
  # quotient comes from the callee-saved file instead (`pickHeldReg` records it,
  # so the prologue saves it). `toDecimal64`'s `q mod 2 != 0` at `-d:danger` is
  # the case: the compare's own staging plus the mod's leaves nothing.
  let qBridge = g.tryTakeBridge(avoid = rD)
  let qTmp = if qBridge == NoReg: g.takeTmp(ScalarSlot) else: dontCare
  if qBridge != NoReg or qTmp.kind == InReg:
    let q = if qBridge != NoReg: qBridge else: qTmp.r
    g.movReg(q, rD)                                      # q := a
    g.binReg(if signed: SdivA64 else: UdivA64, q, dvsReg)# q := a div b
    g.binReg(MulA64, q, dvsReg)                          # q := (a div b)*b
    g.binReg(SubA64, rD, q)                              # dest := a - q
    if qBridge != NoReg: g.dropBridge qBridge
    else: g.freeVal(qTmp)
  else:
    # Nothing left to hold the quotient in: no bridge (this one expression can
    # already own both — one staging a memory result, one reloading a spilled
    # divisor), no volatile temp, no callee-saved survivor. `toDecimal64`'s
    # `q mod 2 != 0` at `-d:danger` reaches exactly that.
    #
    # Three values are live — a, b, the quotient — but only until the multiply:
    # after `q*b` the DIVISOR is dead, so park `a` in the spill slot `takeTmp`
    # just handed us and let b's register carry it back. Costs a store and a
    # load on a path that would otherwise not compile at all. It requires that
    # register to be OURS, which it is whenever the divisor was staged rather
    # than read out of a local's home.
    let dvsOwned = dvsBridge != NoReg or (rD0.kind == InReg and rD0.isTemp)
    if not dvsOwned:
      raiseAssert "arkham a64n: no register for a `mod` quotient in proc " &
                  g.curProcName & ", picked: " & $g.pickedRegs
    g.storeReg2(qTmp, rD)                                # slot := a
    g.binReg(if signed: SdivA64 else: UdivA64, rD, dvsReg)  # rD := a div b
    g.binReg(MulA64, rD, dvsReg)                         # rD := (a div b)*b
    g.place2(qTmp, dvsReg)                               # b's reg := a (b now dead)
    g.binReg(SubA64, dvsReg, rD)                         # := a - (a div b)*b
    g.movReg(rD, dvsReg)
    g.freeVal(qTmp)
  if dvsBridge != NoReg: g.dropBridge dvsBridge
  else: g.freeVal(rD0)
  if not reusedDiv: g.freeVal(lD)
  if resStaging != NoReg:
    g.storeReg2(res, resStaging)
    g.dropBridge resStaging
  dest = res
proc emitFBin*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 float binary-arith (allocFBin's policy inline).
  let op = fbinA64Op(c.exprKind)
  let ek = c.exprKind
  var lhsC, rhsC: Cursor
  var fslot = defaultFloatSlot()
  block:
    var cc = c
    cc.into:
      fslot = slotOf(g.prog, cc); skip cc              # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let lHome = (if lhsC.kind == Symbol: g.plan.locationOfSym(symName(lhsC), cursorToPosition(g.buf[], lhsC)) else: noLoc)
  let swap = ek in {AddC, MulC} and g.foldableFloatLeaf(lhsC) and
             not g.foldableFloatLeaf(rhsC) and
             not (dest.kind == InFReg and lHome.kind == InFReg and lHome.f == dest.f)
  if swap:
    var acc = dest
    if acc.kind != InFReg: acc = g.takeFTmp(fslot)
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoFMem2(c, acc); dest = acc; return
    let bits = if fslot.size == 4: 32 else: 64      # the OP's width, never the temp's
    var rdst = acc
    rdst.typ = fslot                                  # a literal operand materializes at it
    g.emitFValue2(rhsC, rdst)                          # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundFTmp(acc.f): g.bindFTmp(acc.f, bits)
    if lHome.kind == InFReg:
      g.fbin(op, acc.f, lHome.f, bits)
    else:                                              # spilled float local: bridge load
      let lt = g.takeFBridge(bits)
      g.emFloatScalarLoad(lt, lHome.name, bits)
      g.fbin(op, acc.f, lt, bits)
      g.dropFBridge()
    dest = acc
    return
  if dest.kind != InFReg: dest = g.takeFTmp(fslot)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let res = dest
  # The width is the operation's, from its result type, not the temp's the
  # consumer passed (see the x64 twin: a generic 8-byte temp made a float32
  # multiply a double op over a single-materialized literal).
  let bits = if fslot.size == 4: 32 else: 64
  var lD = res
  lD.typ = fslot
  g.emitFValue2(lhsC, lD)                              # a → the result register
  if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f, bits)
  if rhsC.kind == Symbol and g.plan.locationOfSym(symName(rhsC), cursorToPosition(g.buf[], rhsC)).kind == InFReg:
    let rHome = g.plan.locationOfSym(symName(rhsC), cursorToPosition(g.buf[], rhsC))
    if rHome.f == res.f and
       not (lhsC.kind == Symbol and symName(lhsC) == symName(rhsC)):
      raiseAssert "arkham: float operand fold aliases the destination register"
    g.fbin(op, res.f, rHome.f, bits)                   # in-place local fold
  else:
    var rD = g.takeFTmp(fslot)
    g.emitFValue2(rhsC, rD)
    if rD.kind == InFReg:
      g.fbin(op, res.f, rD.f, bits)
      g.freeVal(rD)
    else:                                              # eftmp-spilled rhs: bridge fold
      let fs2 = g.takeFBridge(bits)
      g.emFloatScalarLoad(fs2, rD.name, bits)
      g.fbin(op, res.f, fs2, bits)
      g.dropFBridge()
  dest = res

proc emitFValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 SIMD value: resolve `dest` (a v-register / eftmp slot) and
  ## materialize the float value there.
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let f64 = defaultFloatSlot()
  case c.kind
  of FloatLit:
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
      if dest.kind == NamedStack:
        g.produceIntoFMem2(c, dest); return
    let bits = if dest.typ.size == 4: 32 else: 64
    if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
    let gpr = g.takeBridge()
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest.f, gpr, bits)
    g.dropBridge gpr
  of Symbol:
    var home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == NoLoc:                             # a module-level float global / tvar
      var cc = c
      home = g.asLoc(cc)
    # store forwarding, the float half — see `emitValue2` for the two doors
    home = (if dest.kind != InFReg: g.takeFForwarded(home) else: g.forwardFOf(home))
    case home.kind
    of InFReg:
      if dest.kind != InFReg:
        dest = home                                    # use the home in place
      elif home.f != dest.f:
        let bits = if dest.typ.size == 4: 32 else: 64
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
        g.fmovF(dest.f, home.f, bits)
      elif dest.isTemp and g.rb.isFMirror(dest.f):
        # the accumulator IS the mirroring register: take it over (see the GPR twin)
        g.bindFTmp(dest.f, if dest.typ.size == 4: 32 else: 64)
    else:
      if dest.kind != InFReg:
        dest = g.takeFTmp(if home.typ.kind == AFloat: home.typ else: g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
      g.placeF2(home, dest.f, bits)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC: g.emitFBin(c, dest)
    of NegC:
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc
          inner = cc; skip cc
          while cc.hasMore: skip cc
      var iv = dest                                    # dest-thread into the operand
      g.emitFValue2(inner, iv)
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
      g.ensureFAccum2(dest.f, iv, bits)
      g.ab.tree FnegA64: g.emFReg(dest.f, bits)
    of InfC, NeginfC, NanC:
      # `inf` / `-inf` / `nan` have no `fmov` immediate encoding (a64's 8-bit
      # float immediate covers only normal values), so they travel the same
      # route as any other float literal: bit pattern into a bridge GPR, then
      # `fmov` across.
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
      let gpr = g.takeBridge()
      g.movImm(gpr, specialFloatBits(c.exprKind, bits))
      g.fmovFromGpr(dest.f, gpr, bits)
      g.dropBridge gpr
    of ConvC, CastC: g.emitCast2(c, dest)
    of CallC: g.emitCall2(c, dest)
    of InstrC: g.emitInstr2(c, dest)             # a vector row / float intrinsic
    of DotC, AtC, DerefC, PatC:
      # float lvalue load → fldr res, [addr]
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      g.emitLvalue2(c)                                 # pick embedded base/index
      g.prematLval2(c)
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
      g.ab.tree FldrA64:
        g.emFReg(dest.f, bits)
        g.ab.tree MemX: g.emLvalAddr2(c)
      g.unbindLvalTemps2(c)
      g.freeLvalTemps2(c)
    of SufC, ParC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitFValue2(inner, dest)
    else: raiseAssert "arkham a64n: emitFValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emitFValue2(fused) kind " & $c.kind
proc emitScalarCmp*(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool; fuseBranchTo = ""): RiscInst =
  ## FUSED integer `cmp`: operands resolve dontCare (a home / immediate stays
  ## put; a computed subtree takes a temp) and the bridges serve everything
  ## else — 075b051's stackHomeSlot / placeImmTyped bridge typing preserved.
  ##
  ## `fuseBranchTo` names the label a conditional branch would jump to next. Given
  ## one, an `== 0` / `!= 0` (`nil` included — it is the same zero) is emitted as a
  ## single `cbz`/`cbnz` instead of `cmp`+`b.eq`, and `NoA64Inst` comes back to say
  ## the branch is already emitted. Only equality fuses: AArch64 has no
  ## compare-and-branch for the ordering conditions.
  g.bridgeStep("a `cmp` with both operands spilled", bdTwoInRegs)
  var aC = aC0
  var bC = bC0
  if g.isWideExpr(aC) or g.isWideExpr(bC):
    return g.emitWideCmp(aC, bC, ek, whenTrue)
  let signed = not (g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC))
  result =
    case ek
    of EqC:  (if whenTrue: BeqA64 else: BneA64)
    of NeqC: (if whenTrue: BneA64 else: BeqA64)
    of LtC:  (if whenTrue: (if signed: BltA64 else: BloA64) else: (if signed: BgeA64 else: BhsA64))
    of LeC:  (if whenTrue: (if signed: BleA64 else: BlsA64) else: (if signed: BgtA64 else: BhiA64))
    else: raiseAssert "arkham a64n: cond " & $ek
  if isCmpImmLeaf(aC) and not isCmpImmLeaf(bC):
    # `cmp`'s first operand must be a register, so a literal there is first
    # materialised into a bridge. Leng has no `>`/`>=` — they ARE `<`/`<=` with
    # the operands exchanged — so `0 <= i` reaches us as `(le 0 i)` and every
    # lower-bound check paid that materialisation. Exchange and mirror instead.
    swap(aC, bC)
    result = mirrorBranch(result)
  template cmpBridgeSlot(loc: Location; opC: Cursor): AsmSlot =
    if isPtrType(resolveType(g.prog, g.getType(opC))): g.exprSlot(opC)
    else: loc.typ
  template placeCmpOperand(loc: Location; opC: Cursor; bridge: Reg) =
    if loc.kind == Imm: g.placeImmTyped(bridge, loc, g.getType(opC))
    else: g.place2(loc, bridge)
  var aD = dontCare
  var aMem = false
  if g.isFoldableMemLeaf(aC):
    g.emitLvalue2(aC)                                # fold the lhs load via a bridge
    aD = memLoc(aC, ScalarSlot)
    aMem = true
  else:
    g.emitValue2(aC, aD)
  var aReg = NoReg
  var aBridge = NoReg
  if aD.kind == InReg: aReg = aD.r
  else:
    aBridge = g.takeBridge(cmpBridgeSlot(aD, aC))
    placeCmpOperand(aD, aC, aBridge)
    aReg = aBridge
  var bD = dontCare
  var bMem = false
  if g.isFoldableMemLeaf(bC):
    g.emitLvalue2(bC)
    bD = memLoc(bC, ScalarSlot)
    bMem = true
  else:
    g.emitValue2(bC, bD)
  var fused = false
  if bD.kind == Imm and bD.ival == 0 and ek in {EqC, NeqC} and fuseBranchTo.len > 0:
    # `x == 0` / `x != 0` against a label: one `cbz`/`cbnz`, no flags involved.
    # `result` already carries the sense (`whenTrue` folded in) and, for a swapped
    # `0 == x`, the mirror — and mirroring leaves BeqA64/BneA64 alone, so reading
    # it here is exactly reading "branch when equal / when not equal".
    g.ab.tree (if result == BeqA64: CbzA64 else: CbnzA64):
      g.emReg aReg
      g.ab.sym fuseBranchTo
    fused = true
  elif bD.kind == Imm and bD.ival >= 0 and bD.ival <= 0xFFFF:
    g.ab.tree CmpA64: (g.emReg aReg; g.emImm(bD))
  else:
    var bReg = NoReg
    var bBridge = NoReg
    if bD.kind == InReg: bReg = bD.r
    else:
      bBridge = g.takeBridge(cmpBridgeSlot(bD, bC), avoid = aReg)
      placeCmpOperand(bD, bC, bBridge)
      bReg = bBridge
    g.ab.tree CmpA64: (g.emReg aReg; g.emReg bReg)
    if bBridge != NoReg: g.dropBridge bBridge
  if bMem: g.freeLvalTemps2(bC)
  else: g.freeVal(bD)
  if aBridge != NoReg: g.dropBridge aBridge
  if aMem: g.freeLvalTemps2(aC)
  else: g.freeVal(aD)
  if fused: result = NoA64Inst

proc emitCond*(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## FUSED branch test — the a64 twin of x64's emitCond.
  if c.kind == TagLit and c.exprKind == OvfC:
    case g.ovfMode
    of OvfSign:
      g.ab.tree CmpA64: (g.emReg g.ovfReg; g.ab.intLit 0)
      g.emBr(if whenTrue: BltA64 else: BgeA64, toLabel)
    of OvfCmpLo:
      g.ab.tree CmpA64: (g.emReg g.ovfReg; g.emReg g.ovfReg2)
      g.emBr(if whenTrue: BloA64 else: BhsA64, toLabel)
    of OvfNeqZero:
      g.ab.tree CmpA64: (g.emReg g.ovfReg; g.ab.intLit 0)
      g.emBr(if whenTrue: BneA64 else: BeqA64, toLabel)
    of OvfNone:
      raiseAssert "arkham a64n: (ovf) with no preceding keepovf"
    for r in g.ovfBridges: g.dropBridge r
    g.ovfBridges = @[]
    g.ovfMode = OvfNone
    return
  if c.kind == TagLit and c.exprKind in {AndC, OrC, NotC}:
    let ek = c.exprKind
    var aC, bC: Cursor
    block:
      var cc = c
      cc.into:
        if cc.hasMore: (aC = cc; skip cc)
        if cc.hasMore: (bC = cc; skip cc)
        while cc.hasMore: skip cc
    case ek
    of NotC: g.emitCond(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCond(aC, lSkip, false)
        g.emitCond(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCond(aC, toLabel, false)
        g.emitCond(bC, toLabel, false)
    else:
      if whenTrue:
        g.emitCond(aC, toLabel, true)
        g.emitCond(bC, toLabel, true)
      else:
        let lSkip = g.freshLabel()
        g.emitCond(aC, lSkip, true)
        g.emitCond(bC, toLabel, false)
        g.emLab(lSkip)
    return
  if c.kind == TagLit and c.exprKind in {EqC, NeqC, LtC, LeC}:
    let ek = c.exprKind
    var aC, bC: Cursor
    block:
      var cc = c
      cc.into:
        aC = cc; skip cc
        bC = cc; skip cc
        while cc.hasMore: skip cc
    if g.isFloatExpr(aC):
      let fbits = g.floatBits(aC)
      let tag =
        case ek
        of EqC:  (if whenTrue: BeqA64 else: BneA64)
        of NeqC: (if whenTrue: BneA64 else: BeqA64)
        of LtC:  (if whenTrue: BloA64 else: BhsA64)
        of LeC:  (if whenTrue: BlsA64 else: BhiA64)
        else: raiseAssert "arkham a64n: float cond " & $ek
      # Both operands are seeded with the compare's OWN float slot rather
      # than `dontCare`. `emitFValue2` picks a float LITERAL's bit pattern
      # from the destination slot, so an unseeded one builds the DOUBLE
      # pattern — and the `fcmp` below, correctly `fbits` wide, then reads
      # the wrong half of it. That is why `f > 1.4'f32` compared garbage
      # while `f > g` with a `float32` variable was right: only the literal
      # operand had no width to go on. Same lesson as the `Mem` destination
      # in `genStore2` and the field destination in `genFieldStore2`.
      let cmpSlot = g.exprSlot(aC)
      let seed = (if cmpSlot.kind == AFloat: Location(kind: Undef, typ: cmpSlot)
                  else: dontCare)
      var fa = seed
      g.emitFValue2(aC, fa)
      var fb = seed
      g.emitFValue2(bC, fb)
      assert fa.kind == InFReg and fb.kind == InFReg, "arkham a64n: float cmp operands"
      g.ab.tree FcmpA64: g.emFReg(fa.f, fbits); g.emFReg(fb.f, fbits)
      g.emBr(tag, toLabel)
      g.freeVal(fb)
      g.freeVal(fa)
      return
    let tag = g.emitScalarCmp(aC, bC, ek, whenTrue, fuseBranchTo = toLabel)
    if tag != NoA64Inst: g.emBr(tag, toLabel)      # NoA64Inst: fused into a cbz/cbnz
    return
  # A bare truthiness test — `if flag`, `while p` — is a zero test, so it is a
  # `cbz`/`cbnz` too and never needs the flags.
  var v = needsReg(g.valueSlot(c))
  g.emitValue2(c, v)
  let zTag = if whenTrue: CbnzA64 else: CbzA64
  if v.kind == InReg:
    g.ab.tree zTag: (g.emReg v.r; g.ab.sym toLabel)
    g.freeVal(v)
  else:                                            # pool-dry etmp bool: bridge reload
    let b = g.takeBridge(v.typ)
    g.place2(v, b)
    g.ab.tree zTag: (g.emReg b; g.ab.sym toLabel)
    g.dropBridge b

proc emitCondValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED comparison as a 0/1 VALUE: the result temp is reserved and bound
  ## before the condition emits, so operand picks cannot land on it.
  case dest.kind
  of Undef, NeedsReg, RegOrImm: dest = g.takeTmp(ScalarSlot)
  else: discard
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  assert res.kind == InReg, "arkham a64n: cond-value result " & $res.kind
  if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
  let lEnd = g.freshLabel()
  g.movImm(res.r, 1)
  g.emitCond(c, lEnd, whenTrue = true)
  g.movImm(res.r, 0)
  g.emLab(lEnd)
  dest = res
proc emitMemLoad2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED addressing expr in VALUE position → load `[addr]` into a register.
  let wr = g.pairFieldReg(c)
  if wr != NoReg:
    g.forceRegDest(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let res = dest
    # A POINTER field keeps its real type (`valueSlot`'s rule), exactly as the memory
    # path below does: a `dontCare` destination arrives as the generic `(i 64)`
    # `ScalarSlot`, and a `(cmp thatTemp (nil))` — the null test on a `seq`'s `data`
    # word, read out of a by-value ≤16B aggregate held in a register pair — is a type
    # error against it.
    var bindSlot = res.typ
    if g.slotIsPointer(g.exprSlot(c)): bindSlot = g.exprSlot(c)
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, bindSlot)
    if res.r != wr: g.movReg(res.r, wr)
    dest = res
    return
  g.forceRegDest(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.plan.isSealed(res.r)
  if sealedHere: g.plan.seal {res.r}
  g.emitLvalue2(c, globBase = res)              # picks; a global base reuses the result reg
  if sealedHere: g.plan.unseal {res.r}
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    # an array / flexarray lvalue DECAYS to its address
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, ScalarSlot)
    g.prematLval2(c)
    g.ab.tree LeaA64: (g.emReg res.r; g.emLvalAddr2(c))
    g.unbindLvalTemps2(c)
  else:
    var bindSlot = res.typ
    if g.slotIsPointer(g.exprSlot(c)): bindSlot = g.exprSlot(c)
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, bindSlot)
    g.prematLval2(c)
    g.ab.tree MovA64:
      g.emReg res.r
      g.ab.tree MemX: g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)
  g.freeLvalTemps2(c)
  dest = res

proc emitAddr2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(addr lvalue)` → a pointer in a register; identity `&(deref p)`
  ## with a register-homed `p` and a transient dest is `p`'s register itself.
  var lv: Cursor
  block:
    var cc = c
    cc.into:
      lv = cc; skip cc
      while cc.hasMore: skip cc
  if dest.kind in {NeedsReg, RegOrImm, Undef}:
    if lv.kind == TagLit and lv.exprKind == DerefC:
      var p = lv; inc p
      if p.kind == Symbol:
        let home = g.plan.locationOfSym(symName(p), cursorToPosition(g.buf[], p))
        if home.kind == InReg:
          dest = home                           # the address IS p's register
          return
  g.forceRegDest(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  # Same stale-scalar-in-arg-reg hole as the x64 twin: `&stackAgg` dest-threaded
  # into x0 while a dead bool/int local is still bound there.
  if res.kind == InReg and not res.isTemp and g.rb.isBound(res.r) and
     not g.rb.isBoundTemp(res.r) and not g.rb.isPtrBound(res.r):
    g.releaseStaleName(res.r)
  g.emitLvalue2(lv, globBase = res)             # a global base reuses the lea dest
  g.aggrAddrInto(lv, res.r, g.exprSlot(c),
                 doBind = res.isTemp or not g.rb.isBound(res.r))
  g.freeLvalTemps2(lv)
  dest = res

proc emitCast2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(conv|cast Type inner)` — the a64 twin: bit-reinterprets use fmov,
  ## a pointer-typed literal spells its cast out (075b051's placeImmTyped).
  let isCast = c.exprKind == CastC
  var targetCur, tc, inner: Cursor
  block:
    var cc = c
    cc.into:
      targetCur = cc
      tc = resolveType(g.prog, cc); skip cc
      inner = cc; skip cc
      while cc.hasMore: skip cc
  if g.isWideExpr(inner) and not g.isWideExpr(c) and
     not g.isFloatExpr(c):
    # The NARROWING direction: `int32(x64)` / `cast[uint](x64)`. The widening one
    # and wide→wide are produced by `emitWideAsLoc`, which `emitValue2` reached
    # before this proc; `float(x64)` is not a narrowing at all and is refused a
    # few lines down (`isWideSlot` is about INTEGERS, so a 64-bit float does not
    # answer to it and would otherwise fall in here).
    g.emitWideToNarrow(inner, targetCur, dest)
    return
  if g.isFloatExpr(c):                          # → float result
    if g.isWideExpr(inner):
      # `float32(someInt64)` — the mirror of the float→int64 case. FPv4-SP
      # converts FROM a 32-bit integer only, and narrowing the source first
      # would be silently wrong for anything past 2^31.
      lengError c, "arkham cortex-m: converting a 64-bit integer to a float needs " &
        "a runtime routine this backend does not provide — FPv4-SP converts from " &
        "32 bits (see M5 in doc/cortex_m.md)", lengInfo(c)
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ
                        else: defaultFloatSlot())
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoFMem2(c, dest); return
    let res = dest
    let dstBits = if res.typ.size == 4: 32 else: 64
    if g.isFloatExpr(inner):
      var fv = dontCare
      g.emitFValue2(inner, fv)
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f, dstBits)
      let srcBits = g.floatBits(inner)
      if srcBits == dstBits:
        g.ensureFAccum2(res.f, fv, dstBits)
      else:
        if fv.kind == InFReg: g.emFcvt(res.f, fv.f, dstBits, srcBits)
        else:
          let b = g.takeFBridge(srcBits)
          g.placeF2(fv, b, srcBits)
          g.emFcvt(res.f, b, dstBits, srcBits)
          g.dropFBridge()
        g.freeVal(fv)
    else:
      var iv = needsReg(ScalarSlot)
      g.emitValue2(inner, iv)
      var ivReg: Reg
      var ivBridge = NoReg
      if iv.kind == InReg: ivReg = iv.r
      else:
        ivBridge = g.takeBridge(iv.typ)
        g.place2(iv, ivBridge)
        ivReg = ivBridge
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f, dstBits)
      let (srcW, srcSigned) = g.srcWidthSigned(inner)
      if isCast:
        g.fmovFromGpr(res.f, ivReg, dstBits)
      else:
        g.extendTo(ivReg, srcW, srcSigned)
        g.fcvtI2F(if srcSigned: ScvtfA64 else: UcvtfA64, res.f, ivReg, dstBits)
      if ivBridge != NoReg: g.dropBridge ivBridge
      else: g.freeVal(iv)
    dest = res
    return
  if g.isFloatExpr(inner):                      # float → int/ptr
    g.forceRegDest(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let res = dest
    var fv = dontCare
    g.emitFValue2(inner, fv)
    assert fv.kind == InFReg, "arkham a64n: float→int operand " & $fv.kind
    let fbits = if fv.typ.size == 4: 32 else: 64
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
    if isCast:
      g.fmovToGpr(res.r, fv.f, fbits)
    else:
      g.fcvtF2I(if isSignedType(tc): FcvtzsA64 else: FcvtzuA64, res.r, fv.f, fbits)
      if not isPtrType(tc):
        let targetW = intTypeWidth(tc)
        if targetW < 64: g.extendTo(res.r, targetW, signed = isSignedType(tc))
    g.freeVal(fv)
    dest = res
    return
  # ── int↔int / pointer reinterpret. Narrowing over a frozen symbol home
  # forces a fresh temp (copy-then-narrow, source intact).
  block:
    if inner.kind == Symbol:
      let sh = g.plan.locationOfSym(symName(inner), cursorToPosition(g.buf[], inner))
      var tgc = targetCur
      if sh.kind in {InReg, NamedStack} and slotOf(g.prog, tgc).size < sh.typ.size:
        g.forceRegDest(dest)
      elif sh.kind == InReg and dest.kind in {Undef, NeedsReg, RegOrImm} and
           (isPtrType(tc) or g.slotIsPointer(sh.typ)):
        # A pointer-ness change over a register-homed local, with no destination
        # of our own: without a temp the value would be threaded up in the
        # SYMBOL's home and the re-representation below would `rebindLocalAs`
        # that home — retyping the local itself for the rest of its scope. A
        # later use at its declared type then fails the binding checker. The
        # x64 twin carries the measured repro.
        g.forceRegDest(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    # The destination is an `(s)` SPILL slot: the pools were dry when the guard above
    # forced a register. Stage the WHOLE node through the produce bridge — that
    # re-enters here with a fixed REGISTER destination, so the re-representation
    # really happens — and store the converted value. Falling through instead
    # threaded the slot down as the INNER's destination and bailed out at the
    # spilled guard below, dropping the conversion. Same shape as the two float
    # arms above; `produceIntoMem2`'s x16-is-free contract is the caller's, as there.
    g.produceIntoMem2(c, dest); return
  if dest.kind in {NamedStack, Mem}:
    # a memory-home destination: compute into a temp, re-represent, store
    var tmp = needsReg(dest.typ)
    g.emitCast2(c, tmp)
    if tmp.kind == InReg:
      g.storeReg2(dest, tmp.r)
      g.freeVal(tmp)
    else:
      let b = g.takeBridge(tmp.typ)
      g.place2(tmp, b)
      g.storeReg2(dest, b)
      g.dropBridge b
    return
  # Pre-retype a register-homed named dest to the INNER's type while the inner
  # emits, and put the target type back after the extend below. The register
  # genuinely HOLDS the inner's value until `extendTo` converts it, so a `(u 8)`
  # local receiving an `(i 64)` value is a narrowing move nifasm rejects — rightly:
  # the narrowing is the `lsl`/`lsr` pair that follows, not the move. Zero machine
  # code; only the declared type moves. Mirrors the x86-64 twin.
  var preRetyped = ""
  if dest.kind == InReg and not dest.isTemp:
    let nm = g.rb.boundName(dest.r)
    var st = g.getType(inner)
    if nm.len > 0 and bindTypeDiffers(g.prog, st, targetCur):
      g.rebindLocalAs(nm, dest.r, st)
      preRetyped = nm
  var iv = dest                                 # identity: thread dest down
  if iv.kind == Undef:
    # An unconstrained dest could resolve to the inner's memory home — but the
    # cast re-represents (rebind/extend) in a REGISTER. Demand reg-or-imm: a
    # foldable literal stays an Imm (returned above), a memory home loads.
    iv = regOrImm(dest.typ)
  if iv.typ.cls in {ABool, AInt, AUInt} and iv.typ.size < 8 and not isPtrType(tc) and
     (iv.kind in {NeedsReg, RegOrImm} or
      (iv.kind == InReg and iv.isTemp and not g.rb.isBoundTemp(iv.r))):
    # An int↔int re-representation happens IN a register and is FINISHED by the
    # explicit `extendTo` below, so the register that receives the source must be
    # bound at the canonical 64-bit width. Binding it at the TARGET's narrow width
    # instead made the move that brings the (64-bit) source in a narrowing reg→reg
    # move — `(mov u16tmp i64local)` — which nifasm rejects, even though the very
    # next `lsl`/`lsr` pair is what performs the narrowing.
    iv.typ = ScalarSlot
  g.emitValue2(inner, iv)
  dest = iv
  if dest.kind == Imm:
    # A folded constant reinterprets freely, but a narrowing cast must keep only
    # the target width (`cast[byte](4000)` → 160), else a later `(mov (u 8) 4000)`
    # fails nifasm's literal-fits-width check.
    if not isPtrType(tc):
      let tw = intTypeWidth(tc)
      if tw < 64:
        dest.ival = truncateImm(dest.ival, tw, isSignedType(tc))
    return
  if dest.kind == NamedStack and dest.spillTemp:
    # The INNER settled in an `(s)` spill slot: the pools ran dry resolving it, and
    # the value came back in memory. The re-representation is an INSTRUCTION, so it
    # has nowhere to happen there — this used to just `return`, and the cast became
    # a no-op. Stage it: load the slot into the produce bridge, convert, store back.
    # x16 is free by the same argument that let it be used a moment ago: reaching
    # here means `emitValue2` routed the inner through `produceIntoMem2`, which took
    # and released it.
    let s = g.takeProduceBridge(ScalarSlot)    # canonical 64-bit: the extend narrows
    var rl = regLoc(s, ScalarSlot, isTemp = true)
    g.emScalarLoad(s, dest.name)
    g.reReprCast2(rl, inner, targetCur, tc, isCast, "")
    g.emScalarStore(dest.name, s)
    g.unbindTemp(s)
    return
  assert dest.kind == InReg, "arkham a64n: cast result " & $dest.kind
  g.reReprCast2(dest, inner, targetCur, tc, isCast, preRetyped)

proc emitCall2*(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false;
               tail = false) =
  ## FUSED a64 call: allocCall's placements decided inline. No parking on
  ## AArch64 (no ISA-pinned clobber registers); scalar args dest-thread
  ## straight into their ABI registers, aggregate sources reach their words
  ## via `aggrAddrInto`/`structToRegs`, the result settles from x0/v0.
  ##
  ## `tail` marks a call in `(ret (call …))` position. Leng requires calls to be
  ## bound and forbids nesting them, so that shape is not an expression the
  ## backend gets to second-guess — it is the producer saying "tail-call this",
  ## and the legality question (nothing of ours may outlive the frame) was
  ## answered there. Here it means only: after the arguments are in place, undo
  ## the prologue and BRANCH. The callee then returns to our caller with our
  ## return value already in the return register, so nothing is bound afterwards
  ## and nothing follows.
  ##
  ## `(popframe)` rather than an inline teardown because arkham does not know its
  ## own frame yet: `usedCallee`/`hasStackVars` are final only after the whole
  ## body is emitted (a mid-body last-resort register pick still adds a prologue
  ## pair — in nimsem that happens in 2273 of 3906 procs). nifasm has assembled
  ## the prologue by the time it reaches the marker and can simply reverse it.
  discard hiddenPtr                            # the x8 hidden pointer is set by the caller
  g.tailCallEmitted = false                    # BEFORE the mem-intrinsic early return
                                               # below: a stale `true` from an earlier
                                               # call would make `RetS` skip the epilogue
  # Every store-forwarding mirror dies at a call, and BEFORE the marshalling: the
  # callee clobbers the volatiles a mirror lives in, and — for a value whose
  # address escaped — could write the slot itself. (Address-taken locals are never
  # mirrored, so only the clobber is load-bearing; clearing the whole map anyway
  # costs a call-free straight-line region nothing.)
  g.killAllMirrors()
  var argCurs: seq[Cursor] = @[]
  var fsym = ""
  var targetCur: Cursor
  var indirect = false
  block:
    var fc = c
    fc.into:
      targetCur = fc
      indirect = isIndirectCallTarget(g.typeCtx, fc)
      if not indirect: fsym = symName(fc)
      skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  var tgt: CallTarget
  var fnptrReg = NoReg
  var fnTargetName = ""
  var fnptrLoc = dontCare
  if indirect:
    let proctype = g.proctypeOfTarget(targetCur)
    let declarative = isDeclarativeAbi(g.prog, proctype)
    var retType = proctype
    block:
      var q = proctype
      q.into:
        skip q; skip q
        retType = q
        while q.hasMore: skip q
    fnptrLoc = needsReg(ScalarSlot)
    g.emitValue2(targetCur, fnptrLoc)          # fn-ptr target → a held register
    if fnptrLoc.kind != InReg:
      # `needsReg` is a REQUEST, not a guarantee: with every held register taken the
      # value core answers with a spill slot instead. `blr` needs a register, so bring
      # it back into a bridge. Reachable once a proc is under real pressure — a
      # stack-passed parameter costs a callee-saved register for the incoming-args
      # base, which is what first drove `deps.buildGraph` over the edge.
      let r = g.takeBridge()
      g.place2(fnptrLoc, r)
      fnptrLoc = regLoc(r, ScalarSlot, isTemp = true)
    fnptrReg = fnptrLoc.r
    if targetCur.kind == Symbol and g.rb.boundName(fnptrReg) == symName(targetCur):
      tgt = CallTarget(declarative: declarative, asmName: symName(targetCur),
                       retType: retType, sigType: proctype)
    else:
      let nm = g.rb.freshTmpName("fntmp")
      g.ab.tree RebindA64:
        g.ab.symDef nm
        var pc = proctype
        g.genTypeBody(pc)
        g.ab.rawReg fnptrReg
      g.rb.bindScratch(fnptrReg, nm, isPtr = false)
      fnTargetName = nm
      tgt = CallTarget(declarative: declarative, asmName: nm, retType: retType,
                       sigType: proctype)
  else:
    if not g.callTarget.hasKey(fsym):
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        var d = si.decl
        var proctype: Cursor
        d.into:
          inc d; skip d
          proctype = resolveType(g.prog, d)
          while d.hasMore: skip d
        g.callTarget[fsym] = CallTarget(declarative: isDeclarativeAbi(g.prog, proctype),
          indirect: true, asmName: fsym, retType: g.indirectRetType(si.decl))
      else:
        g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    tgt = g.callTarget[fsym]
    if tgt.memIntrin.len > 0:
      g.emitMemIntrin2(argCurs, tgt.memIntrin)   # (fused arg emission inside)
      if not (dest.kind == InReg and not dest.isTemp):
        dest = regLoc(g.md.intRetReg, ScalarSlot, isTemp = true)
      elif dest.r != g.md.intRetReg:
        g.movReg(dest.r, g.md.intRetReg)
      return
    if tgt.bitBuiltin.len > 0:
      raiseAssert "arkham a64n: bit builtin not yet implemented: " & tgt.bitBuiltin
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: ScalarSlot
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let resultByRef = hasResult and resSlot.kind == AMem and resSlot.size > 16
  # A tail call is a DIRECTIVE, not a shape to be validated — whether anything of
  # ours may outlive the frame was decided by whoever wrote `(ret (call …))`. What
  # is checked here is only what arkham cannot MECHANICALLY do: an outgoing stack
  # argument is written at `[sp, …]` and `(popframe)` moves SP out from under it;
  # an external/syscall/indirect target does not reach the plain `b`; and a >16B
  # result travels through a hidden pointer that is not ours to forward yet.
  # Declining is silent and costs nothing — the call is emitted as an ordinary one.
  # `indirect` is the local the target resolution above set — the `CallTarget`
  # built for an indirect call does not carry the flag, so `tgt.indirect` is not
  # the thing to ask. An indirect tail call is refused because the pointer lives in
  # a register `(popframe)` may restore out from under the branch.
  # A target without `TailCall` declines unconditionally: `(tailcall)`/`(popframe)`
  # are AArch64-only tags (`A64Inst`), so the Thumb-2 selector has no spelling for either and
  # the prologue it builds is not the one `(popframe)` knows how to walk back.
  var doTail = tail and TailCall in g.md.caps and
               not indirect and not tgt.extern and not tgt.syscall and
               not tgt.indirect and not resultByRef and
               tgt.memIntrin.len == 0 and tgt.bitBuiltin.len == 0
  var heldArgs: seq[Location] = @[]

  proc settleCallResult(g: var CodeGen; dest: var Location) =
    if not hasResult or resultByRef: return
    if resultIsFloat:
      let rbits = if resSlot.size == 4: 32 else: 64
      if dest.kind != InFReg:
        dest = g.takeFTmp(resSlot)             # the float pool excludes v0
      if dest.kind == InFReg:
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, rbits)
        if dest.f != g.md.floatRetReg: g.fmovF(dest.f, g.md.floatRetReg, rbits)
      else:
        g.emFloatScalarStore(dest.name, g.md.floatRetReg, rbits)
    elif resSlot.kind == AMem or g.isWideSlot(resSlot):
      discard        # ≤16B aggregate / 64-bit scalar result: caller reads x0:x1
    else:
      case dest.kind
      of Undef, NeedsReg, RegOrImm:
        dest = regLoc(g.md.intRetReg, resSlot, isTemp = true)   # x0 itself is raw-usable
      of InReg:
        if dest.r != g.md.intRetReg:
          if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, resSlot)
          g.movReg(dest.r, g.md.intRetReg)
      of NamedStack, Mem:
        g.storeReg2(dest, g.md.intRetReg)
      else: raiseAssert "arkham a64n: call result dest " & $dest.kind

  if tgt.declarative:
    var callArgSlots: seq[AsmSlot] = @[]
    let declSlots = g.calleeParamSlots(fsym, tgt)
    for j, a in argCurs:
      var s = g.exprSlot(a)
      # THE ABI follows the CALLEE's declaration, not the argument expression's
      # type. They can disagree in WIDTH — Leng leaves the C truncation of
      # `exit(x + y)` (an `int64` sum into a `cint` parameter) implicit — and on
      # a target where a scalar can span two registers that disagreement is an
      # ABI mismatch, not a rounding detail: the caller would stage two words
      # where the callee declared one. Only the width is taken; the CLASS stays
      # the expression's, so an aggregate or a float argument is untouched.
      if j < declSlots.len and s.kind notin {AMem, AFloat} and
         declSlots[j].kind notin {AMem, AFloat} and declSlots[j].size != s.size:
        s.size = declSlots[j].size
        s.align = declSlots[j].align
      callArgSlots.add s
    let plan = planCall(g.md, callArgSlots, retByRef = false)
    if doTail:
      for pa in plan.args:
        if pa.onStack: (doTail = false; break)
    # Every 64-bit argument is produced into a stack slot BEFORE the `(prepare …)`
    # block opens. Inside it, arguments are staged straight into r0–r3, and a
    # 64-bit `div`/`mod` is a `bl` to the module's divider — which clobbers
    # exactly those registers. Producing the value first turns the marshalling
    # into loads, which clobber nothing.
    var wideArgSlots = newSeq[string](argCurs.len)
    for j in 0 ..< argCurs.len:
      if plan.args[j].isWideScalar or g.isWideExpr(argCurs[j]):
        wideArgSlots[j] = g.wideValueIntoTemp(argCurs[j])
    # From here to the `(call)` marker, an argument that has been staged is LIVE in
    # its ABI register: nothing else may take it, and on Cortex-M — whose only
    # volatiles are these four — the last-resort scratch draw would otherwise be
    # entitled to. Each argument's register is claimed BEFORE its own evaluation,
    # not after: the value lands there at the end of that evaluation, and a draw
    # made during it would be handing out the destination.
    #
    # Leng calls are FLAT — an argument is never itself a call — so this is one
    # window per call and not a stack of them.
    g.stagedArgs = {}
    g.ab.tree PrepareA64:
      g.ab.sym tgt.asmName
      var stackArgs: seq[int] = @[]
      for j in 0 ..< argCurs.len:
        let a = argCurs[j]
        let pl = plan.args[j]
        if not pl.onStack and not pl.isFloat:
          for k in 0 ..< max(pl.words, 1): g.stagedArgs.incl g.md.gprAt(pl, k)
        var tn = NoTypeSym
        if pl.isAgg:
          let tcur = g.getType(a)
          if tcur.kind != Symbol:
            raiseAssert "arkham a64: aggregate call-arg of non-nominal type"
          tn = tcur.symId
        if pl.onStack:
          stackArgs.add j
          continue
        if pl.isAgg:
          if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
            # The address is consumed within THIS arg's own marshalling (any
            # embedded call runs during the premat, before the lea writes it),
            # so a pool temp serves when no callee-saved survivor is free, and
            # a bridge serves when both pools are dry — never a hard failure.
            var srcAddr: Reg
            var addrBridge = NoReg
            var hr = g.pickHeldReg()
            if hr == NoReg: hr = g.pickTempReg()
            if hr != NoReg:
              g.pickedRegs.incl hr
              heldArgs.add regLoc(hr, ScalarSlot, isTemp = true)
              srcAddr = hr
            else:
              addrBridge = g.takeBridge()
              srcAddr = addrBridge
            g.emitLvalue2(a)                 # pick embedded base/index regs
            g.aggrAddrInto(a, srcAddr, addrSlot(), doBind = true)
            if pl.byRef: g.movReg(g.md.gprAt(pl), srcAddr)
            else: g.marshalAggrFromAddr(srcAddr, tn, pl.gpFirst)
            if addrBridge != NoReg: g.dropBridge addrBridge
            else: g.unbindTemp(srcAddr)
            g.freeLvalTemps2(a)
          else:
            var home = ""
            var isGlobal = false
            var isTvar = false
            if a.kind == Symbol:
              case g.lookupSym(symName(a)).cat
              of scGlobal: isGlobal = true
              of scTvar: (isGlobal = true; isTvar = true)
              else: home = symName(a)
            else:
              let p = g.posOf(a)
              home = synth("aggtmp") & $p & ".0"
              g.emTypedStackVar(home, g.getType(a))
              g.varType[home] = tn
              g.genStore2(a, namedStackLoc(home, callArgSlots[j]))
            let hh = g.plan.homeOfSym(home)
            if pl.byRef:
              if isTvar: g.genTlvAddr(symName(a), g.md.gprAt(pl))
              elif isGlobal: g.emGlobalAddr(g.md.gprAt(pl), symName(a))
              elif hh.kind == InReg:
                g.movReg(g.md.gprAt(pl), hh.r)
              elif hh.kind == StackPtr:
                # Forwarding a by-ref param whose own pointer spilled: pass the pointer
                # the slot HOLDS. (`lea &slot` would pass the address OF the pointer —
                # what this arm did before the home could say so.)
                g.emScalarLoad(g.md.gprAt(pl), hh.ptrName)
              else: g.ab.tree LeaA64: (g.emReg g.md.gprAt(pl); g.ab.sym home)
            else:
              if isGlobal: g.globalToRegs(symName(a), tn, pl.gpFirst, isTvar)
              else: g.structToRegs(home, tn, pl.gpFirst)
          if pl.byRef:
            g.ab.tree MovA64:
              g.ab.tree ArgX: g.ab.sym paramName(j)
              g.emReg g.md.gprAt(pl)
          else:
            for k in 0 ..< pl.words:
              g.ab.tree MovA64:
                g.ab.tree ArgX: (g.ab.sym paramName(j); g.ab.intLit k.int64)
                g.emReg g.md.gprAt(pl, k)
        elif g.isWideExpr(a) and not pl.isWideScalar:
          g.wideArgTruncated(wideArgSlots[j], g.md.gprAt(pl))
          g.ab.tree MovA64:
            g.ab.tree ArgX: g.ab.sym paramName(j)
            g.emReg g.md.gprAt(pl)
        elif pl.isWideScalar:
          # Two consecutive argument registers, filled from the value's eight
          # bytes and then bound as `(arg pN 0)` / `(arg pN 1)` — the same shape
          # a two-eightbyte aggregate uses, because it is the same ABI question.
          g.wideArgToRegs(wideArgSlots[j], pl.gpFirst)
          for k in 0 ..< pl.words:
            g.ab.tree MovA64:
              g.ab.tree ArgX: (g.ab.sym paramName(j); g.ab.intLit k.int64)
              g.emReg g.md.gprAt(pl, k)
        else:
          var aD = regLoc(g.md.gprAt(pl), ScalarSlot)
          g.emitValue2(a, aD)                  # → its ABI register directly
          # Release the temp binding so the arg register is referenced RAW where it
          # can be. Where it CANNOT — the allocator also homes plain locals in the
          # volatile arg registers, and nifasm insists a bound register be named —
          # the name carries the local's own type, and a wider one marshalling into
          # a sub-width param is the ABI truncation `movTypeOk`'s `narrowingArg` arm
          # admits (memfiles' `close`, where `canRaise` lives in x0 and is dead
          # across the `raiseOSError(cint)` it stages). That arm was x86-64-only
          # until the rule was unified — this path would have been rejected here.
          g.unbindTemp(aD.r)
          g.ab.tree MovA64:
            g.ab.tree ArgX: g.ab.sym paramName(j)
            g.emReg aD.r
      for j in stackArgs:
        let a = argCurs[j]
        if g.exprSlot(a).kind == AMem:
          g.marshalStackAggrArg(a, paramName(j))
        elif g.isWideExpr(a):
          g.wideArgToStack(wideArgSlots[j], paramName(j))
        else:
          var aD = needsReg(g.valueSlot(a))
          g.emitValue2(a, aD)
          var srcReg: Reg
          var srcBridge = NoReg
          if aD.kind == InReg: srcReg = aD.r
          else:
            srcBridge = g.takeBridge(aD.typ)
            g.place2(aD, srcBridge)
            srcReg = srcBridge
          g.ab.tree MovA64:
            g.ab.tree MemX:
              g.emReg SP
              g.ab.tree ArgX: g.ab.sym paramName(j)
            g.emReg srcReg
          if srcBridge != NoReg: g.dropBridge srcBridge
          g.freeVal(aD)
      # Every argument is in place; the call itself clobbers all four, so from the
      # marker on nobody's claim survives.
      g.stagedArgs = {}
      if tgt.syscall and Freestanding notin g.md.caps:
        g.ab.tree SvcA64: g.ab.intLit 0
      elif doTail:
        # The arguments are in their ABI registers; from here nothing of ours is
        # live, so undo the prologue and branch. `(popframe)` is inside the
        # prepare block on purpose: it must follow the last `(arg …)` store and
        # precede the branch, and it touches only SP and callee-saved registers —
        # never x0–x7, where the arguments now sit.
        g.ab.keyword PopframeA64
        g.ab.keyword TailcallA64
        g.tailCallEmitted = true
      else:
        # On Cortex-M a "syscall" is an ordinary `bl` to the semihosting shim
        # `emitSemihostRuntime` emitted under the same name — there is no trap
        # instruction to reach an OS with, because there is no OS.
        g.ab.keyword CallA64
      if not doTail and hasResult and not resultByRef and not resultIsFloat and
         resSlot.kind != AMem and not g.isWideSlot(resSlot):
        g.ab.tree MovA64:
          g.emReg g.md.intRetReg
          g.ab.tree ResX: g.ab.sym synth("ret.0")
    if fnTargetName.len > 0:
      g.ab.tree KillA64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    if not doTail: g.settleCallResult(dest)
  else:
    var intIdx = 0
    var fIdx = 0
    # This path produces each argument INTO its physical register rather than
    # through an `(arg …)` binding, so a value is live there from its own
    # evaluation until the call. The claim is the whole marshalling, taken up
    # front: `intIdx` only says how far it has got, and a draw made partway
    # through must not take a register a later argument is about to be produced
    # into either.
    g.stagedArgs = {}
    for r in g.md.intArgRegs: g.stagedArgs.incl r
    # Apple's AArch64 ABI passes a `{.varargs.}` call's VARIADIC tail on the stack,
    # 8-byte slotted, even while x2–x7 sit idle — the one place it departs from
    # AAPCS64, and libc is compiled to that rule. `open(path, flags, 0o666)` put the
    # mode in x2, so every file arkham created got whatever the stack happened to
    # hold as its permission bits: `nifbench.scratch.bif` came out mode 0355 and the
    # next read of it failed. Linux/AAPCS64 keeps filling registers, so this is
    # Darwin-only.
    #
    # The values are still produced into the argument registers the tail WOULD have
    # taken — those are caller-saved and this callee never reads them — and moved
    # down to the outgoing area once every argument is evaluated. Reserving late
    # matters: an argument may load a local out of an `(s)` slot, and those are
    # SP-relative, so SP must not have moved yet.
    let variadicFrom = if tgt.isVarargs and not g.a64Linux: tgt.fixedParams else: -1
    var varTail: seq[tuple[r: Reg; f: FReg; off: int]] = @[]
    for idx in 0 ..< argCurs.len:
      let a = argCurs[idx]
      let isVariadic = variadicFrom >= 0 and idx >= variadicFrom
      if isVariadic:
        let off = varTail.len * 8
        if g.exprSlot(a).kind == AMem:
          # C's default argument promotions never produce one, and guessing the
          # HFA/indirect split would miscompile silently.
          raiseAssert "arkham a64: aggregate in the variadic tail of " & tgt.asmName
        elif g.isFloatExpr(a):
          var fD = fregLoc(g.md.floatArgRegs[fIdx], defaultFloatSlot())
          g.emitFValue2(a, fD)                 # promoted to double by the front end
          varTail.add (NoReg, g.md.floatArgRegs[fIdx], off)
          inc fIdx
        else:
          var aD = regLoc(g.md.intArgRegs[intIdx], ScalarSlot)
          g.emitValue2(a, aD)
          varTail.add (g.md.intArgRegs[intIdx], NoFReg, off)
          inc intIdx
      elif g.isFloatExpr(a):
        # The argument's OWN float width, not a fixed 8. AAPCS64 passes a `float`
        # in the low half of `v0`-`v7` and a `double` in the whole register, so a
        # register-to-register move is right either way and this looked harmless —
        # but `emitFValue2` picks a LITERAL's bit pattern from the destination
        # slot's width. With the width hardcoded to 8 a `float32` literal was
        # materialized as the `double` pattern, whose low 32 bits (the half the
        # callee reads with `fmov s, s`) are zero for every value with an empty
        # mantissa tail: `a[0] = 1.0'f32` stored 0.0.
        #
        # It stayed hidden because it needs a REAL call with a float32 literal
        # argument — a small proc gets inlined and the literal folded — which is
        # why it surfaced through `seq[float32]`'s out-of-line `[]=` instantiation
        # rather than in any direct call.
        var fSlot = g.exprSlot(a)
        if fSlot.kind != AFloat:
          fSlot = defaultFloatSlot()
        var fD = fregLoc(g.md.floatArgRegs[fIdx], fSlot)
        g.emitFValue2(a, fD)
        inc fIdx
      elif g.exprSlot(a).kind == AMem:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham a64: aggregate call-arg of non-nominal type"
        let tn = tcur.symId
        let sz = aggrByteSize(g.prog, tn)
        if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
          # Same totality chain as the proc-pointer marshaller above: survivor,
          # else pool temp, else bridge (the address dies within this arg).
          var srcAddr: Reg
          var addrBridge = NoReg
          var hr = g.pickHeldReg()
          if hr == NoReg: hr = g.pickTempReg()
          if hr != NoReg:
            g.pickedRegs.incl hr
            heldArgs.add regLoc(hr, ScalarSlot, isTemp = true)
            srcAddr = hr
          else:
            addrBridge = g.takeBridge()
            srcAddr = addrBridge
          g.emitLvalue2(a)                   # pick embedded base/index regs
          g.aggrAddrInto(a, srcAddr, addrSlot(), doBind = true)
          if sz > 16:
            g.movReg(g.md.intArgRegs[intIdx], srcAddr); inc intIdx
          else:
            g.marshalAggrFromAddr(srcAddr, tn, intIdx)
            intIdx += aggrWordCount(g.prog, tn)
          if addrBridge != NoReg: g.dropBridge addrBridge
          else: g.unbindTemp(srcAddr)
          g.freeLvalTemps2(a)
        else:
          var home = ""
          var isGlobal = false
          var isTvar = false
          if a.kind == Symbol:
            case g.lookupSym(symName(a)).cat
            of scGlobal: isGlobal = true
            of scTvar: (isGlobal = true; isTvar = true)
            else: home = symName(a)
          else:
            let pos = g.posOf(a)
            home = synth("aggtmp") & $pos & ".0"
            g.emTypedStackVar(home, tcur)
            g.varType[home] = tn
            g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
          let hh = g.plan.homeOfSym(home)
          if sz > 16:
            if isTvar: g.genTlvAddr(symName(a), g.md.intArgRegs[intIdx])
            elif isGlobal: g.emGlobalAddr(g.md.intArgRegs[intIdx], symName(a))
            elif hh.kind == InReg:
              g.movReg(g.md.intArgRegs[intIdx], hh.r)
            elif hh.kind == StackPtr:
              g.emScalarLoad(g.md.intArgRegs[intIdx], hh.ptrName)   # the slot holds &aggregate
            else: g.ab.tree LeaA64: (g.emReg g.md.intArgRegs[intIdx]; g.ab.sym home)
            inc intIdx
          else:
            let nw = aggrWordCount(g.prog, tn)
            if isGlobal: g.globalToRegs(symName(a), tn, intIdx, isTvar)
            else: g.structToRegs(home, tn, intIdx)
            intIdx += nw
      elif g.isWideExpr(a):
        # Same rule as the declarative path: the value first, the staging after.
        let wnm = g.wideValueIntoTemp(a)
        g.wideArgToRegs(wnm, intIdx)
        intIdx += 2                       # no declaration to narrow against here
      else:
        var aD = regLoc(g.md.intArgRegs[intIdx], ScalarSlot)
        g.emitValue2(a, aD)                    # → its ABI register directly
        inc intIdx
    # Drop the variadic tail into a freshly reserved outgoing area at [sp+0…]. The
    # frame nifasm sizes has no room for it (that reservation is driven by a callee's
    # DECLARED signature, and a Darwin extern declares none), so carve it here and
    # give it back straight after the call — 16-aligned, as the ABI requires SP to be.
    var varArea = 0
    if varTail.len > 0:
      varArea = (varTail.len * 8 + 15) and not 15
      g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.intLit varArea)
      for it in varTail:
        if it.r != NoReg:
          g.ab.tree MovA64:
            g.ab.tree MemX: (g.emReg SP; g.ab.intLit it.off)
            g.emReg it.r
        else:
          g.ab.tree FstrA64:
            g.ab.tree MemX: (g.emReg SP; g.ab.intLit it.off)
            g.emFReg(it.f, 64)
    g.ab.tree PrepareA64:
      g.ab.sym tgt.asmName
      if doTail:
        g.ab.keyword PopframeA64
        g.ab.keyword TailcallA64
        g.tailCallEmitted = true
      else:
        g.ab.keyword (if tgt.extern: ExtcallA64 else: CallA64)
    g.stagedArgs = {}                # the call clobbers them; no claim survives
    if varArea > 0:
      g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.intLit varArea)
    # The call CLOBBERS every volatile register, so a scratch name still bound to an
    # argument register is stale from here on. The general call path unbinds each one
    # as it copies the value into its `(arg …)` slot; this path produces INTO the
    # physical registers, so the binding has to survive until the call — but no
    # further. Left bound, `emReg` keeps spelling it: in `memfiles.open` a `(u 16)`
    # `mode_t` temp stayed on x2 and a later `mmap` argument came out as
    # `(mov tmp54.0 x.2)` — an `(i 32)` into a `(u 16)` name, which nifasm rejects.
    for i in 0 ..< intIdx: g.unbindTemp(g.md.intArgRegs[i])
    for i in 0 ..< fIdx: g.unbindFTmp(g.md.floatArgRegs[i])
    if fnTargetName.len > 0:
      g.ab.tree KillA64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    if not doTail: g.settleCallResult(dest)

when declared(FldrqOp):
  # STAGED, INERT until the shared `lib/intrinsics` table carries the AdvSIMD rows.
  # `instrTargetOf` resolves an `(instr …)` through `intrinsicOpByName`, so without
  # those rows a `{.instruction: "fldrq".}` declaration cannot even be spelled and
  # nothing below is reachable. Compiling it anyway is what broke the build: this
  # repo must build against the intrinsic table as it stands today. The guard flips
  # the whole path on by itself the moment the rows land — no edit here.
  const VecOps = {FldrqOp, FstrqOp, VfaddOp, VfsubOp, VfmulOp, VfmlaOp, VdupOp,
                  VaddvOp}

  template Vec128Slot(): AsmSlot = AsmSlot(cls: AFloat, size: 16, align: 16)

  proc vecHomeF(g: var CodeGen; a: Cursor): FReg =
    ## A 128-bit vector operand: the vectorizer spells every one as a plain local,
    ## and a local of type `(f 128)` lives in a SIMD register or fails loudly at
    ## its declaration (`genVarDecl2`), so the home lookup here cannot miss.
    if a.kind != Symbol:
      lengError a, "a 128-bit vector operand must be a plain local"
    let home = g.plan.locationOfSym(symName(a), cursorToPosition(g.buf[], a))
    if home.kind != InFReg:
      lengError a, "128-bit vector local `" & symName(a) &
                "` has no SIMD register home"
    result = home.f

  proc vecLaneBits(g: var CodeGen; a: Cursor): int =
    ## The trailing lane-width knob: an int LITERAL, read here and folded into the
    ## emitted instruction — never evaluated into a register (see `ptLaneBits`).
    if a.kind != IntLit or int(intVal(a)) notin {32, 64}:
      lengError a, "a vector op's lane-bits operand must be the literal 32 or 64"
    result = int(intVal(a))

  proc vecByteOff(g: var CodeGen; a: Cursor): int =
    ## A vector load/store's byte-offset operand: an int literal, multiple of 16.
    if a.kind != IntLit or (int(intVal(a)) and 15) != 0 or intVal(a) < 0:
      lengError a, "a vector load/store offset must be a non-negative literal multiple of 16"
    result = int(intVal(a))

  proc emitVecInstr2(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                     argCurs: seq[Cursor]; dest: var Location) =
    ## The AdvSIMD rows. Vector VALUES are `(f 128)` locals homed in SIMD
    ## registers; the ops read those homes directly and write the destination
    ## register in place — there is no 128-bit register-register move anywhere,
    ## by construction (`vfmla`'s tie is asserted, not repaired with a copy).
    ##
    ## The nifasm tags carry an explicit trailing lane-bits literal because a
    ## 128-bit binding names the register without naming a lane width.
    case op
    of FstrqOp:
      # (instr fstrq p off v) — statement position, no result.
      let off = g.vecByteOff(argCurs[1])
      let vf = g.vecHomeF(argCurs[2])
      var pd = g.takeInstrReg(g.exprSlot(argCurs[0]), false)
      g.emitValue2(argCurs[0], pd)
      g.ab.tree FstrqA64:
        g.ab.tree MemX:
          g.emReg pd.r
          if off != 0: g.ab.intLit off
        g.emFReg(vf, 64)
      g.freeVal(pd)
    of FldrqOp:
      let off = g.vecByteOff(argCurs[1])
      var pd = g.takeInstrReg(g.exprSlot(argCurs[0]), false)
      g.emitValue2(argCurs[0], pd)
      if dest.kind != InFReg:
        dest = g.takeFTmp(Vec128Slot)
        if dest.kind == NamedStack:
          lengError c, "out of SIMD registers for a 128-bit vector value"
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, 128)
      g.ab.tree FldrqA64:
        g.emFReg(dest.f, 64)
        g.ab.tree MemX:
          g.emReg pd.r
          if off != 0: g.ab.intLit off
      g.freeVal(pd)
    of VdupOp:
      let bits = g.vecLaneBits(argCurs[1])
      var fv = dontCare
      g.emitFValue2(argCurs[0], fv)
      if dest.kind != InFReg:
        dest = g.takeFTmp(Vec128Slot)
        if dest.kind == NamedStack:
          lengError c, "out of SIMD registers for a 128-bit vector value"
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, 128)
      var srcF = NoFReg
      var viaBridge = false
      if fv.kind == InFReg:
        srcF = fv.f
      else:                                        # an eftmp spill (float pool dry)
        srcF = g.takeFBridge(bits)
        g.placeF2(fv, srcF, bits)
        viaBridge = true
      g.ab.tree VdupA64:
        g.emFReg(dest.f, 64)
        g.emFReg(srcF, bits)
        g.ab.intLit bits
      if viaBridge: g.dropFBridge()
      elif fv.kind == InFReg and fv.isTemp and fv.f != dest.f: g.unbindFTmp(fv.f)
    of VaddvOp:
      # scalar = horizontal add of every lane — the reduction epilogue. The
      # result is an ORDINARY scalar float (an `(f W)` value in the float pool),
      # so it composes with the surrounding scalar expression tree.
      let bits = g.vecLaneBits(argCurs[1])
      let srcF = g.vecHomeF(argCurs[0])
      if dest.kind != InFReg:
        dest = g.takeFTmp(AsmSlot(cls: AFloat, size: bits div 8, align: bits div 8))
        if dest.kind == NamedStack:
          lengError c, "out of SIMD registers for a vaddv result"
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
      g.ab.tree VaddvA64:
        g.emFReg(dest.f, bits)
        g.emFReg(srcF, 64)
        g.ab.intLit bits
    of VfmlaOp:
      # dest = acc + a*b, fused, accumulating IN PLACE (tie = 0): the vectorizer
      # spells every use as `acc = vfmla(acc, a, b, bits)`, so the destination IS
      # the accumulator's home and the machine op needs no 128-bit copy.
      let bits = g.vecLaneBits(argCurs[3])
      let accF = g.vecHomeF(argCurs[0])
      if dest.kind != InFReg or dest.f != accF:
        lengError c, "vfmla accumulates in place: spell it `acc = vfmla(acc, a, b, bits)`"
      g.ab.tree VfmlaA64:
        g.emFReg(accF, 64)
        g.emFReg(g.vecHomeF(argCurs[1]), 64)
        g.emFReg(g.vecHomeF(argCurs[2]), 64)
        g.ab.intLit bits
    of VfaddOp, VfsubOp, VfmulOp:
      let bits = g.vecLaneBits(argCurs[2])
      let aF = g.vecHomeF(argCurs[0])
      let bF = g.vecHomeF(argCurs[1])
      if dest.kind != InFReg:
        dest = g.takeFTmp(Vec128Slot)
        if dest.kind == NamedStack:
          lengError c, "out of SIMD registers for a 128-bit vector value"
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, 128)
      let tag = case op
                of VfaddOp: VfaddA64
                of VfsubOp: VfsubA64
                else: VfmulA64
      g.ab.tree tag:
        g.emFReg(dest.f, 64)
        g.emFReg(aF, 64)
        g.emFReg(bF, 64)
        g.ab.intLit bits
    else:
      raiseAssert "arkham a64n: not a vector op: " & IntrinsicNames[op]

proc emitInstr2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 `(instr SYM X*)`: operand placement inline (pool → survivor,
  ## never a bridge — the atomics own x14/x15/x16); resolved operand Locations
  ## go to the `plan.locs` memo so `emitAtomicInstr2` reads them unchanged.
  ##
  ## An intrinsic row may write memory (the atomics), claim registers of its own
  ## and run an LL/SC retry loop — none of which the mirror map models. It clears,
  ## like a call.
  g.killAllMirrors()
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  block:
    var fc = c
    fc.into:
      fsym = symName(fc); skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if row.isFlagRead or row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` is a flag instruction; flags " &
              "are only legal inside an `{.assembler.}` proc, where the body — " &
              "not the allocator — decides what runs between the compare and " &
              "the branch", lengInfo(c)
  if not g.hasHereLowering(row.targets):
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no " &
              g.md.targetName & " lowering — " &
              "guard the call with a `when`"
  when declared(VecOps):                         # see the staging guard above
    if tgt.op in VecOps and SimdVector notin g.md.caps:
      # The rows below are AArch64 AdvSIMD spellings, and nothing makes them
      # neutral. A target without them must be told so here, at the one place
      # that knows which op was asked for — the alternative is that the day the
      # intrinsic table carries these rows, every load/store target starts
      # emitting `(vfadd …)` because it was not named in a branch.
      lengError c, "`" & IntrinsicNames[tgt.op] & "` is a 128-bit vector " &
                "operation and " & g.md.targetName & " has no SIMD vocabulary"
    if tgt.op in VecOps:
      g.emitVecInstr2(c, tgt.op, argCurs, dest)
      return
  if row.inoutOperand >= 0:
    # A two-address row: the destination operand IS its home, so nothing is
    # placed for it; the sources are evaluated as usual and given back after.
    var ops: seq[Location] = @[]
    var i = 0
    for a in argCurs:
      if i != row.inoutOperand:
        var d = Location(kind: RegOrImm, typ: ScalarSlot)
        g.emitValue2(a, d)
        g.plan.planAtEmitTime(cursorToPosition(g.buf[], a), d)
        ops.add d
      inc i
    g.emitInoutInstr2(c, tgt.op, argCurs)
    for d in ops:
      if d.kind == InReg: g.freeVal d
    dest = Location(kind: Undef)                # no value: nothing consumes this
    return
  if row.isVoidResult and row.evaluatedOperands == 0 and row.arity > 0 and
     not tgt.op.isAtomic:
    # `not isAtomic` is load-bearing: a fence is also a void row whose only
    # operand is an unevaluated memory-order knob, and it belongs to the atomic
    # sequence path further down, which knows what a fence lowers to.
    # A row with no result whose operands the INSTRUCTION encodes: `bkpt #imm8`.
    # Taken here for the same reason `isNullaryVoid` is — everything below is
    # written around a first operand that needs a register, and this one must
    # NOT get one: there is no register form of the comment field.
    case tgt.op
    of BkptOp:
      var immC = argCurs[0]
      if immC.kind notin {IntLit, UIntLit}:
        lengError immC, "`bkpt` takes a literal immediate — the instruction " &
                  "encodes it, so there is no register form to compute one into",
                  lengInfo(c)
      let v = (if immC.kind == IntLit: intVal(immC) else: cast[int64](uintVal(immC)))
      if v < 0 or v > 255:
        lengError immC, "`bkpt` takes an 8-bit immediate (0..255); " & $v &
                  " does not fit the instruction", lengInfo(c)
      g.ab.tree BkptM: g.ab.intLit v
    else:
      raiseAssert "arkham arm: no lowering for the void intrinsic `" &
                  IntrinsicNames[tgt.op] & "`"
    dest = Location(kind: Undef)
    return
  if row.isNullaryVoid:
    # No operands to place, no result to home, nothing to free — and taken here
    # because everything below is written around `argCurs[0]` existing. `dest`
    # stays `Undef`: the node yields no value.
    case tgt.op
    of SemihostOp:
      # The three-instruction RISC-V semihosting request. nifasm emits all three
      # from this one keyword — the outer two are architectural no-ops whose only
      # job is to make the middle `ebreak` recognisable as a semihosting call, so
      # they are not separable and there is nothing here to give an operand to.
      # a0/a1 were set by the `{.assembler.}` body that names them.
      g.ab.keyword SemihostRv
    of CpuRelaxOp:
      # `yield` is HINT #1: architecturally a NOP, so it needs no feature test,
      # and it writes no register, no flag and no memory. Nothing to tell the
      # allocator about. Both Arm profiles have it and both SPELL it `yield`, and
      # the buffer interns a tag by its spelling — so one tag serves both, and
      # the `MInst` twin was only ever a second Nim name for the same string.
      g.ab.keyword YieldA64
    else:
      raiseAssert "arkham arm: no lowering for the nullary intrinsic `" &
                  IntrinsicNames[tgt.op] & "`"
    dest = Location(kind: Undef)
    return
  # Resolve the result FIRST and seal it, so an operand pick cannot land on it.
  var res = Location(kind: Undef)
  if not row.isVoidResult:
    case dest.kind
    of NeedsReg, RegOrImm: dest = g.takeInstrReg(dest.typ, tgt.op.isAtomic)
    of Undef: dest = g.takeInstrReg(ScalarSlot, tgt.op.isAtomic)
    else: discard
    res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.plan.isSealed(res.r)
  if sealedHere: g.plan.seal {res.r}
  var ops: seq[Location] = @[]
  block:
    var i = 0
    for a in argCurs:
      if i >= row.evaluatedOperands: break     # trailing memory-order knobs
      # No immediate atomics on a64 (the LL/SC loops have no spare scratch to
      # materialize one — the allocator's atomicValueMayBeImm was x86-only).
      var d = g.takeInstrReg(g.exprSlot(a), tgt.op.isAtomic)
      g.emitValue2(a, d)
      g.plan.planAtEmitTime(cursorToPosition(g.buf[], a), d)
      ops.add d
      inc i
  if sealedHere: g.plan.unseal {res.r}
  if tgt.op.isAtomic:
    g.emitAtomicInstr2(c, tgt.op, argCurs, res)
    for d in ops:
      if not (res.kind == InReg and d.kind == InReg and d.r == res.r): g.freeVal(d)
    return
  if tgt.op.isVolatile:
    # ONE access, at exactly the pointee's width, and no more of a lowering than
    # that: a volatile access is the one place where "the same value, fetched
    # differently" is the wrong answer.
    #
    # The width comes from the TYPE at the call site, not from `tgt.argBits`,
    # which reads the first declared parameter — here a `ptr T`, whose own bits
    # say nothing about the cell.
    #
    # And it comes from the POINTER, not from the value or the result. Those agree
    # whenever the source went through `volatileStore[T](dest: ptr T; val: T)`, so
    # this only ever differs for hand-written asm-NIF — where the pointer is still
    # the one operand that cannot be wrong about the cell it addresses.
    var ptrTyp = g.getType(argCurs[0])
    ptrTyp = g.prog.resolveType(ptrTyp)
    let cellTyp =
      if ptrTyp.kind == TagLit and ptrTyp.typeKind in {LengType.PtrT, LengType.AptrT}:
        g.prog.innerType(ptrTyp)
      elif tgt.op == VolatileLoadOp: g.getType(c)
      else: g.getType(argCurs[1])
    let cell = slotOf(g.prog, cellTyp)
    if cell.kind == AMem or cell.kind == AFloat or cell.size > wordSize() or
       cell.size notin {1, 2, 4, 8}:
      lengError c, "a volatile access must be ONE machine access, and a " &
                $cell.size & "-byte cell is not one on this target — no " &
                "widening, no splitting into halves, because for a device " &
                "register the difference is what the device sees",
                lengInfo(c)
    var pt = g.prog.ptrTypeOf(cellTyp)
    # The base is `(cast (ptr T) <reg>)` rather than a bare `(mem <reg> 0)`,
    # which nifasm reads as a plain machine word: the cast is what sizes the
    # access, and a sub-word cell without it is silently widened.
    if tgt.op == VolatileLoadOp:
      g.ab.tree MovA64:
        g.emReg res.r
        g.ab.tree MemX:
          g.ab.tree CastX: (g.genTypeBody(pt); g.emReg ops[0].r)
          g.ab.intLit 0
    else:
      g.ab.tree MovA64:
        g.ab.tree MemX:
          g.ab.tree CastX: (g.genTypeBody(pt); g.emReg ops[0].r)
          g.ab.intLit 0
        g.emReg ops[1].r
    for d in ops:
      if not (res.kind == InReg and d.kind == InReg and d.r == res.r): g.freeVal(d)
    dest = res
    return
  if tgt.op in {HeapStartOp, HeapSizeOp, NoinitStartOp, NoinitSizeOp}:
    # Before the generic tail, which reads `argCurs[0]`: these take no operands.
    #
    # Link-time constants: nifasm knows where the layout put each region, and the
    # runtime cannot compute either — a firmware image has no OS to ask. Same
    # shape as `(dataload)`: a MOVW/MOVT pair the image writer patches.
    let isHeap = tgt.op in {HeapStartOp, HeapSizeOp}
    if Freestanding notin g.md.caps:
      lengError c, "`" & IntrinsicNames[tgt.op] & "` is a region a BOARD LAYOUT " &
                "reserved; a hosted target has an OS to ask for memory instead",
                lengInfo(c)
    if not g.board.given:
      lengError c, "`" & IntrinsicNames[tgt.op] & "` needs a board layout — pass " &
                "`--layout:<file>` so there IS a reserved region to name",
                lengInfo(c)
    if isHeap and g.board.heapSize == 0:
      lengError c, "the board layout reserves no heap, so `" &
                IntrinsicNames[tgt.op] & "` has nothing to answer with",
                lengInfo(c)
    if not isHeap and g.board.noinitSize == 0:
      lengError c, "the board layout keeps nothing back from the startup code, " &
                "so `" & IntrinsicNames[tgt.op] & "` has nothing to answer with — " &
                "add a `(noinit …)` row",
                lengInfo(c)
    g.ab.tree MovA64:
      g.emReg res.r
      g.ab.keyword (case tgt.op
                    of HeapStartOp: HeapstartX
                    of HeapSizeOp: HeapsizeX
                    of NoinitStartOp: NoinitstartX
                    else: NoinitsizeX)
    dest = res
    return
  if res.kind != InReg:
    raiseAssert "arkham a64n: intrinsic result is not in a register"
  let a0 = g.plan.planned(cursorToPosition(g.buf[], argCurs[0]))
  let aliasesA0 = a0.kind == InReg and a0.r == res.r
  if res.isTemp and not aliasesA0 and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  var src = res.r
  if a0.kind == InReg: src = a0.r
  else: g.place2(a0, res.r)
  let bits = if tgt.argBits in {8, 16, 32}: 32 else: 64
  case tgt.op
  of ClzPinnedOp, ClzOp:
    g.ab.tree ClzA64: (g.emReg res.r; g.emReg src; g.ab.intLit bits)
  of RbitOp:
    g.ab.tree RbitA64: (g.emReg res.r; g.emReg src; g.ab.intLit bits)
  of CtzOp:
    g.ab.tree RbitA64: (g.emReg res.r; g.emReg src; g.ab.intLit bits)
    g.ab.tree ClzA64: (g.emReg res.r; g.emReg res.r; g.ab.intLit bits)
  of RevOp, BswapOp:
    g.ab.tree RevA64: (g.emReg res.r; g.emReg src; g.ab.intLit bits)
    if tgt.argBits == 16:
      g.binImm(LsrA64, res.r, 16)
  of VgClientRequestOp:
    # `(vgreq D S)` — one node, because valgrind only recognizes its request
    # sequence when the instructions arrive INTACT and adjacent. Emitting the
    # rotates and the `orr x10, x10, x10` marker as ordinary instructions would
    # expose them to exactly the passes that are right about everything else: the
    # marker is a provable no-op and the rotates cancel, so a peephole would be
    # correct to delete the lot, and would silently turn every request into
    # nothing. Handing nifasm the whole sequence as one opcode puts it out of
    # reach of the optimizer instead of asking the optimizer to make an exception.
    #
    # The encoder stages x3/x4 through x14/x15/x16, which the allocator never hands
    # out — the same reason an atomic's LL/SC loop needs no clobber analysis — so
    # only their stale NAMES have to go, exactly as `emitAtomicInstr2` does.
    for r in g.md.bridgeRegs: g.releaseStaleName(r)
    g.ab.tree VgreqA64: (g.emReg res.r; g.emReg src)
  else:
    raiseAssert "arkham a64n: no lowering for intrinsic `" & IntrinsicNames[tgt.op] & "`"
  for d in ops:
    if d.kind == InReg and d.r != res.r: g.freeVal(d)
  dest = res

# ── var declarations ─────────────────────────────────────────────────────────

# ── case test ────────────────────────────────────────────────────────────────

# ── conditional-move (branchless select) ─────────────────────────────────────

# ── statement dispatch ───────────────────────────────────────────────────────

# ── proc emission / driver (pure-emit path) ──────────────────────────────────


# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. The two-pass seam
# below must reset every per-proc table (regLocal/boundTemps/freeTmp + the ra.locs snapshot)
# or RegisterBindingsMatchLoc and replay completeness break.
# ── driver ──────────────────────────────────────────────────────────────────

const
  SemiWrite* = 5           ## SYS_WRITE:  r1 = &{handle, buf, len}
  SemiOpen* = 1            ## SYS_OPEN:   r1 = &{&name, mode, namelen}
  SemiOpenModeW* = 4       ## the "w" mode; `:tt` opened with it is the console
  SemiTtyBase* = "`shtty.0"    ## the `:tt` device name, in rodata
  SemiTtyHandleBase* = "`shwh.0"   ## the cached console handle, one `.bss` word
  SemiExitExtended* = 0x20 ## SYS_EXIT_EXTENDED: r1 = &{reason, status}
  SemiBkpt* = 0xAB         ## the `bkpt` immediate that IS the semihosting call
  AdpStoppedApplicationExit* = 0x20026

# The 64-bit-integer lowering (Cortex-M, M4). INCLUDED here, at the end, so it
# sees the whole value core it dispatches out of and back into.
#
#           Arkham — 64-bit integers on a 32-bit target (Cortex-M, M4)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## INCLUDED by `codegen_arm.nim` — not a module of its own, because it is one
## more emitter arm rather than a second code generator, and it needs the whole
## `*2` value core it dispatches out of and back into.
##
## ## `int` is 32 bits on this target
##
## Nimony maps `int` to the target's width, so under `--cpu:arm32` it is a
## 32-bit type (`nifconfig.nim` takes `bits` from the CPU table). NOTHING here
## is on the path of ordinary integer code: this file serves values declared
## explicitly 64-bit, which is why `isWideSlot` asks about a SIZE and never
## about a type's name. The `tests/arkham/` corpus is misleading on the point —
## it was authored for x86-64 and AArch64, where `int` WAS 64 bits, so every
## `int` in it arrives here as `(i 64)`. That makes it a good stress test and a
## bad model of a firmware image.
##
## ## Why 64-bit values live in MEMORY
##
## The obvious lowering is a register PAIR, and on a target with a normal
## register file it is the right one. Cortex-M is not that target: the arkham
## machine model gets four allocatable homes (r4–r7) and an EMPTY volatile temp
## pool, because on this ABI the only caller-saved registers ARE the argument
## registers, and emitter scratch is drawn while a call's arguments are staged
## (see `machine_m.nim`). A pair allocator would be competing for two of four
## homes per live 64-bit value, and every consumer in the shared value core
## (`place2`, `storeReg2`, `freeVal`, the binding protocol with a formal model
## behind it) would have to grow a second-register case.
##
## So a 64-bit value here is EIGHT BYTES AT AN ADDRESS, and the ops read and
## write it a word at a time. `slots.inRegClass` already says as much — a
## 64-bit scalar fails it on a 32-bit target, so the allocator gives every such
## local a stack home without being told anything new. What this file adds is
## the arithmetic.
##
## The cost is real (an `int64` `x + y` is 6 instructions instead of 2) and it
## is the price of the target's register file, not of the representation. What
## it buys is that the ONE thing a 64-bit lowering must never do — produce a
## plausible wrong number — cannot happen by a register running out.
##
## ## The addressing contract
##
## Each half is spelled `(cast (u 32) (mem <base> <byte offset>))`. The cast is
## load-bearing: the slot's own type is `(i 64)`, and without saying otherwise
## the access would be a 64-bit-typed one that nifasm refuses (`checkRegWidthM`)
## — refuses, note, rather than silently truncating, which is why an arm this
## file forgets shows up as a type error and not as a wrong answer.
##
## ## Flags across a carry chain
##
## `adds`/`adcs` (and `subs`/`sbcs`) are separated here by loads and stores of
## the operand halves. That is sound because `emitLoadStoreImm` on this target
## only ever encodes an LDR/STR — it never materializes an out-of-range offset
## through an arithmetic instruction, it raises — and neither does nifasm's own
## fold of a memory operand into IP. A memory operand carrying an INDEX would
## break that (`emitMemAccessM` computes `base+index` into IP with an `add`), so
## every `WideRef` below is base+displacement and never an indexed one.


# ── scratch ─────────────────────────────────────────────────────────────────

# ── the two halves as operands ──────────────────────────────────────────────

# ── minting and resolving ───────────────────────────────────────────────────

proc emitWideInto(g: var CodeGen; c0: Cursor; dst: WideRef)
proc wideLvalRef(g: var CodeGen; c: Cursor; scratch: var Reg): WideRef =
  ## The eight bytes an lvalue expression denotes: `(deref p)`, `(dot o f)`,
  ## `(at a i)`. The address goes into a scratch register; the caller frees it.
  scratch = g.takeWideRegs(1, "a 64-bit lvalue address")[0]
  g.emitLvalue2(c)
  g.aggrAddrInto(c, scratch, addrSlot(), doBind = false)
  g.freeLvalTemps2(c)
  baseWide(scratch)

proc wideValueSlot(g: var CodeGen; c: Cursor): WideRef =
  ## The eight bytes of ANY 64-bit expression, **in a stack slot**.
  ##
  ## Never a register-relative reference, even when the value already has an
  ## address. A staging bridge is scratch, not a survivor: it does not outlive a
  ## call, and the operand evaluated AFTER this one may contain one — `gs[i] +
  ## f()` would then add through a pointer the callee had overwritten. Paying a
  ## two-word copy for a global or an lvalue is the price of that not being
  ## possible; a plain stack home (which is where every 64-bit local already
  ## lives) costs nothing.
  let cc = stripParens(c)
  if cc.kind == Symbol:
    let home = g.plan.locationOfSym(symName(cc), g.posOf(cc))
    if home.kind == NamedStack: return slotWide(home.name)
  let nm = g.mintWideSlot()
  result = slotWide(nm)
  g.emitWideInto(cc, result)

# ── narrow ↔ wide ───────────────────────────────────────────────────────────

proc emitNarrowValueInto(g: var CodeGen; c: Cursor; dest: Reg) =
  ## Emit a NON-wide expression so its value lands in `dest`.
  var v = needsReg(g.valueSlot(c))
  g.emitValue2(c, v)
  g.place2(v, dest)
  g.freeVal(v)

proc wideFromNarrowExpr(g: var CodeGen; dst: WideRef; c: Cursor; signed: bool) =
  ## Widen a NARROWER expression to the 64-bit value at `dst`.
  ##
  ## The source's own width matters as much as its signedness: a `(i 16)` arrives
  ## in a register in its CANONICAL (sign-extended) form, so widening it as
  ## unsigned — which a `cast` does — has to re-normalize the low 32 bits first
  ## or the value is already wrong before the high word is chosen. `cast[int64](
  ## int16(64536))` is 64536, not -1000, and the difference survives into the
  ## answer.
  let t = g.takeWideRegs(1, "a 64-bit widening operand")[0]
  g.emitNarrowValueInto(c, t)
  let (srcW, _) = g.srcWidthSigned(c)
  if srcW < wordBits(): g.extendTo(t, srcW, signed)
  g.wideFromNarrow(dst, t, signed)
  g.dropWideRegs(@[t])

# ── arithmetic ──────────────────────────────────────────────────────────────

proc wideShift(g: var CodeGen; dst, a: WideRef; amount: Cursor; ek: LengExpr;
               signed: bool) =
  ## `dst = a shl/shr n` for a RUNTIME shift count. Branching on `n >= 32` rather
  ## than the branchless mask sequence: this costs two forward branches and saves
  ## two of the four scratch registers, which on this register file is the better
  ## trade — and `asr`'s big-shift case needs a conditional term either way.
  let rs = g.takeWideRegs(4, "a 64-bit shift")
  let (n, lo, hi, t) = (rs[0], rs[1], rs[2], rs[3])
  g.emitNarrowValueInto(amount, n)
  g.wideLoad(lo, a, 0)
  g.wideLoad(hi, a, 1)
  let lBig = g.freshLabel()
  let lEnd = g.freshLabel()
  g.ab.tree CmpA64: (g.emReg n; g.ab.intLit 32)
  g.emBr(BhsA64, lBig)
  # 0 .. 31 — `x shr 32` on Thumb-2's register-shift forms is 0, which is what
  # makes the n = 0 case (a shift by the full width of the other half) correct
  # without a third arm.
  g.movImm(t, 32)
  g.ab.tree Sub3A64: (g.emReg t; g.emReg t; g.emReg n)         # t = 32 - n
  case ek
  of ShlC:
    g.ab.tree Lsl3A64: (g.emReg hi; g.emReg hi; g.emReg n)
    g.ab.tree Lsr3A64: (g.emReg t; g.emReg lo; g.emReg t)
    g.ab.tree Orr3A64: (g.emReg hi; g.emReg hi; g.emReg t)
    g.ab.tree Lsl3A64: (g.emReg lo; g.emReg lo; g.emReg n)
  else:
    g.ab.tree Lsl3A64: (g.emReg t; g.emReg hi; g.emReg t)
    g.ab.tree Lsr3A64: (g.emReg lo; g.emReg lo; g.emReg n)
    g.ab.tree Orr3A64: (g.emReg lo; g.emReg lo; g.emReg t)
    if signed:
      g.ab.tree Asr3A64: (g.emReg hi; g.emReg hi; g.emReg n)
    else:
      g.ab.tree Lsr3A64: (g.emReg hi; g.emReg hi; g.emReg n)
  g.emBr(BA64, lEnd)
  g.emLab(lBig)                                                # 32 .. 63
  g.ab.tree Sub3A64: (g.emReg n; g.emReg n; g.ab.intLit 32)
  case ek
  of ShlC:
    g.ab.tree Lsl3A64: (g.emReg hi; g.emReg lo; g.emReg n)
    g.movImm(lo, 0)
  else:
    if signed:
      g.ab.tree Asr3A64: (g.emReg lo; g.emReg hi; g.emReg n)
      g.ab.tree Asr3A64: (g.emReg hi; g.emReg hi; g.ab.intLit 31)
    else:
      g.ab.tree Lsr3A64: (g.emReg lo; g.emReg hi; g.emReg n)
      g.movImm(hi, 0)
  g.emLab(lEnd)
  g.wideStore(dst, 0, lo)
  g.wideStore(dst, 1, hi)
  g.dropWideRegs(rs)

# ── comparison ──────────────────────────────────────────────────────────────

proc emitWideCmp(g: var CodeGen; aC, bC: Cursor; ek: LengExpr;
                  whenTrue: bool): RiscInst =
  ## The 64-bit twin of `emitScalarCmp`: emit the compare, return the branch
  ## that means "the condition holds".
  ##
  ## Equality goes through xor/or rather than the borrow chain, because after a
  ## 64-bit `subs`/`sbcs` the Z flag describes the HIGH word alone — `beq` there
  ## would call `0x1_00000000` equal to `0x2_00000000`. The ordered conditions
  ## read only N/V (signed) or C (unsigned), which the chain does carry, and
  ## `<=` is `>=` with the operands exchanged for the same reason: `ble` reads Z.
  let signed = not (g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC))
  if ek in {EqC, NeqC}:
    let aw = g.wideValueSlot(aC)
    let bw = g.wideValueSlot(bC)
    let rs = g.takeWideRegs(2, "a 64-bit equality test")
    g.wideLoad(rs[0], aw, 0)
    g.ab.tree Eor3A64: (g.emReg rs[0]; g.emReg rs[0]; g.emWideWord(bw, 0))
    g.wideLoad(rs[1], aw, 1)
    g.ab.tree Eor3A64: (g.emReg rs[1]; g.emReg rs[1]; g.emWideWord(bw, 1))
    g.ab.tree Orr3A64: (g.emReg rs[0]; g.emReg rs[0]; g.emReg rs[1])
    g.ab.tree CmpA64: (g.emReg rs[0]; g.ab.intLit 0)
    g.dropWideRegs(rs)
    return if ek == EqC: (if whenTrue: BeqA64 else: BneA64)
           else: (if whenTrue: BneA64 else: BeqA64)
  # `a < b` is the borrow out of `a - b`; `a <= b` is `b >= a`.
  let swapped = ek == LeC
  let lhsC = if swapped: bC else: aC
  let rhsC = if swapped: aC else: bC
  let lw = g.wideValueSlot(lhsC)
  let rw = g.wideValueSlot(rhsC)
  let t = g.takeWideRegs(1, "a 64-bit compare")[0]
  g.wideLoad(t, lw, 0)
  g.ab.tree Subs3M: (g.emReg t; g.emReg t; g.emWideWord(rw, 0))
  g.wideLoad(t, lw, 1)                        # a load never disturbs the flags
  g.ab.tree Sbcs3M: (g.emReg t; g.emReg t; g.emWideWord(rw, 1))
  g.dropWideRegs(@[t])
  # After the chain: "borrow" == lhs < rhs. `swapped` already turned `a <= b`
  # into `b < a`, so the answer for `<=` is the NEGATION of what we test.
  let lt = if signed: BltA64 else: BloA64
  let ge = if signed: BgeA64 else: BhsA64
  if swapped: (if whenTrue: ge else: lt)
  else:       (if whenTrue: lt else: ge)

# ── the wide producer ───────────────────────────────────────────────────────

proc wideCallInto(g: var CodeGen; c: Cursor; dst: WideRef)

proc emitWideInto(g: var CodeGen; c0: Cursor; dst: WideRef) =
  ## Produce the 64-bit value of `c` into the eight bytes at `dst`. THE entry
  ## point: every wide expression form is one arm here, and a form with no arm
  ## is refused by name rather than routed to the 32-bit emitter, which would
  ## compute the low word and call it the answer.
  ##
  ## A NARROWER expression asked for in 64 bits (`f(x32)` where `f` declares an
  ## `int64` parameter) is widened by its OWN signedness. Literals are excluded
  ## from that shortcut and keep their two-halves arm: a literal is materialized
  ## by `movImm`, which is a 32-bit move here, so `4294967296` would widen from a
  ## truncated 0.
  let c = stripParens(c0)
  let isLiteral = c.kind in {IntLit, UIntLit, CharLit} or
                  (c.kind == TagLit and
                   c.exprKind in {TrueC, FalseC, NilC, SizeofC})
  if not isLiteral and g.isFloatExpr(c):
    # `int64(someFloat)`. FPv4-SP converts to a 32-bit integer and no wider, so
    # this needs a runtime routine to be RIGHT for anything past 2^31 — and a
    # `vcvt` plus a sign-extend would be quietly wrong exactly there. Refused by
    # name; `int32(f)` is the conversion this core has.
    lengError c, "arkham cortex-m: converting a float to a 64-bit integer needs a " &
      "runtime routine this backend does not provide — FPv4-SP converts to 32 " &
      "bits (see M5 in doc/cortex_m.md)", lengInfo(c)
  if not isLiteral and not g.isWideExpr(c):
    let sgn = isSignedType(resolveType(g.prog, g.getType(c)))
    g.wideFromNarrowExpr(dst, c, sgn)
    return
  case c.kind
  of IntLit, UIntLit, CharLit:
    let v = case c.kind
            of IntLit: intVal(c)
            of UIntLit: cast[int64](uintVal(c))
            else: int64(ord(charLit(c)))
    let t = g.takeWideRegs(1, "a 64-bit literal")[0]
    g.movImm(t, v and 0xFFFF_FFFF'i64)
    g.wideStore(dst, 0, t)
    g.movImm(t, (v shr 32) and 0xFFFF_FFFF'i64)
    g.wideStore(dst, 1, t)
    g.dropWideRegs(@[t])
  of Symbol:
    var scratch: Reg
    let src = g.wideSymRef(c, scratch)
    g.wideCopy(dst, src)
    if scratch != NoReg: g.unbindTemp(scratch)
  of TagLit:
    case c.exprKind
    of SufC, ParC:
      var inner = c
      inner.into:
        g.emitWideInto(inner, dst)
        skip inner
        while inner.hasMore: skip inner
    of TrueC:  g.wideStoreImm(dst, 0, 1); g.wideStoreImm(dst, 1, 0)
    of FalseC, NilC:
      let t = g.takeWideRegs(1, "a 64-bit zero")[0]
      g.movImm(t, 0)
      g.wideStore(dst, 0, t)
      g.wideStore(dst, 1, t)
      g.dropWideRegs(@[t])
    of SizeofC:
      var t = c
      var sz = 0'i64
      t.into:
        sz = typeSizeAlign(g.prog, t)[0].int64
        while t.hasMore: skip t
      g.wideStoreImm(dst, 0, sz)
      g.wideStoreImm(dst, 1, 0)
    of DerefC, DotC, AtC, PatC:
      var scratch: Reg
      let src = g.wideLvalRef(c, scratch)
      g.wideCopy(dst, src)
      if scratch != NoReg: g.unbindTemp(scratch)
    of AddC, SubC, MulC, DivC, ModC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (isConst, cval) = g.tryConstFold(c)
      if isConst and g.posOf(c) != g.noFoldPos:
        let t = g.takeWideRegs(1, "a folded 64-bit constant")[0]
        g.movImm(t, cval and 0xFFFF_FFFF'i64)
        g.wideStore(dst, 0, t)
        g.movImm(t, (cval shr 32) and 0xFFFF_FFFF'i64)
        g.wideStore(dst, 1, t)
        g.dropWideRegs(@[t])
        return
      var resTypeC, aC, bC: Cursor
      block:
        var cc = c
        cc.into:
          resTypeC = cc; skip cc
          aC = cc; skip cc
          bC = cc; skip cc
          while cc.hasMore: skip cc
      let ek = c.exprKind
      let signed = isSignedType(resolveType(g.prog, resTypeC))
      if ek in {ShlC, ShrC}:
        let aw = g.wideValueSlot(aC)
        g.wideShift(dst, aw, bC, ek, signed)
        return
      let aw = g.wideValueSlot(aC)
      let bw = g.wideValueSlot(bC)
      case ek
      of AddC: g.wideCarryChain(Adds3M, Adcs3M, dst, aw, bw)
      of SubC: g.wideCarryChain(Subs3M, Sbcs3M, dst, aw, bw)
      of BitandC: g.wideWordwise(And3A64, dst, aw, bw)
      of BitorC:  g.wideWordwise(Orr3A64, dst, aw, bw)
      of BitxorC: g.wideWordwise(Eor3A64, dst, aw, bw)
      of MulC: g.wideMul(dst, aw, bw)
      of DivC: g.wideDivMod(dst, aw, bw, signed, wantRem = false)
      of ModC: g.wideDivMod(dst, aw, bw, signed, wantRem = true)
      else: raiseAssert "arkham cortex-m: wide binop " & $ek
    of NegC, BitnotC:
      var resTypeC, innerC: Cursor
      block:
        var cc = c
        cc.into:
          resTypeC = cc; skip cc
          innerC = cc; skip cc
          while cc.hasMore: skip cc
      discard resTypeC
      let aw = g.wideValueSlot(innerC)
      if c.exprKind == NegC: g.wideNeg(dst, aw) else: g.wideNot(dst, aw)
    of CastC, ConvC:
      var targetC, innerC: Cursor
      block:
        var cc = c
        cc.into:
          targetC = cc; skip cc
          innerC = cc; skip cc
          while cc.hasMore: skip cc
      if g.isWideExpr(innerC):
        let src = g.wideValueSlot(innerC)
        g.wideCopy(dst, src)
      elif g.isFloatExpr(innerC):
        lengError c, "arkham cortex-m: converting a float to a 64-bit integer needs " &
          "a runtime routine this backend does not provide — FPv4-SP converts to " &
          "32 bits (see M5 in doc/cortex_m.md)", lengInfo(c)
      else:
        # Widening a narrower value: the SOURCE's signedness decides the high
        # word, not the target's. `uint32(x).int64` must be zero-extended even
        # though `int64` is signed, and `int32(x).uint64` sign-extended even
        # though `uint64` is not — this is the one place where taking the
        # target's sign produces a number wrong by 2^32 that nothing downstream
        # can tell.
        #
        # …and a `cast` is unsigned regardless. `cast` is a REINTERPRETATION of
        # the source's bits, so it zero-extends where `conv` sign-extends; this
        # is `reReprCast2`'s `(not isCast) and srcSigned`, stated again because
        # the wide path does its own widening.
        let it = g.getType(innerC)
        let signedSrc = isSignedType(resolveType(g.prog, it))
        g.wideFromNarrowExpr(dst, innerC, (c.exprKind != CastC) and signedSrc)
    of CallC: g.wideCallInto(c, dst)
    of AddrC, HaddrC, InstrC:
      lengError c, "arkham cortex-m: `" & $c.exprKind &
        "` producing a 64-bit value is not supported", lengInfo(c)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC:
      # A bool widened to 64 bits: emit the 0/1 and zero-extend it.
      g.wideFromNarrowExpr(dst, c, signed = false)
    else:
      lengError c, "arkham cortex-m: 64-bit expression `" & $c.exprKind &
        "` is not supported", lengInfo(c)
  else:
    raiseAssert "arkham cortex-m: 64-bit expression kind " & $c.kind

# ── calls, parameters and returns ───────────────────────────────────────────
#
# A 64-bit scalar travels EXACTLY like a two-word by-value aggregate: two
# consecutive argument registers (`abi.planCall` now sizes a scalar's `words`
# from its slot), or eight bytes of the outgoing stack area, and r0:r1 for a
# result. That is not AAPCS32 — which would even-align the register pair and
# make `f(int32, int64)` use r2:r3 — and it does not have to be: a firmware
# image has nothing to link against, so arkham owns both sides of every call.
# The rule that DOES matter is that the two sides agree, and they agree by
# reading the same `CallPlan`.

proc wideCallInto(g: var CodeGen; c: Cursor; dst: WideRef) =
  ## A 64-bit call result: raw out of r0:r1, straight into memory.
  ##
  ## `dst` must be a SLOT. An address in a register is not a survivor across the
  ## call that just happened — see `wideValueSlot` — so a register-relative
  ## destination lands in a temp and is copied afterwards.
  var d = dontCare
  g.emitCall2(c, d)
  let lo = g.md.intRetReg
  let hi = g.md.intArgRegs[1]
  if dst.kind == wrSlot:
    g.wideStore(dst, 0, lo)
    g.wideStore(dst, 1, hi)
  else:
    let tmp = slotWide(g.mintWideSlot())
    g.wideStore(tmp, 0, lo)
    g.wideStore(tmp, 1, hi)
    g.wideCopy(dst, tmp)

proc emitWideIntoLoc(g: var CodeGen; c: Cursor; dst: Location) =
  ## Produce a 64-bit value into a resolved destination `Location` — the
  ## `genStore2` arm for wide values.
  if dst.kind == NamedStack:
    g.emitWideInto(c, slotWide(dst.name))
    return
  # Anything addressed through a register: compute the VALUE first (its
  # evaluation may contain a call, which the address register would not
  # survive), then take the address and copy.
  let tmp = slotWide(g.mintWideSlot())
  g.emitWideInto(c, tmp)
  let a = g.takeWideRegs(1, "a 64-bit destination address")[0]
  case dst.kind
  of Field: g.emFieldAddr(dst, a)          # &(base.field), however the base is addressed
  of Glob, Tvar, Mem, StackPtr: g.aggrAddrLoc(dst, a)
  else: raiseAssert "arkham cortex-m: 64-bit value into location kind " & $dst.kind
  g.wideCopy(baseWide(a), tmp)
  g.dropWideRegs(@[a])

proc emitWideAsLoc(g: var CodeGen; c: Cursor; dest: var Location) =
  ## The `emitValue2` arm: a 64-bit value has no register to be resolved into,
  ## so it lands in a temp slot and `dest` names that slot.
  ##
  ## `spillTemp` is deliberately FALSE. It means "the emitter must produce into
  ## this through a staging register", and the value is already there. A consumer
  ## that is not wide-aware will try to `mov` the slot into a 32-bit register,
  ## which nifasm rejects as a type mismatch — loudly, and before anything runs.
  if dest.kind == NamedStack and not dest.spillTemp:
    g.emitWideInto(c, slotWide(dest.name))
    return
  let w = g.wideValueSlot(c)
  dest = namedStackLoc(w.name, WideSlot)

proc wideRet*(g: var CodeGen; c: Cursor) =
  ## `return <64-bit>` — the value into r0:r1.
  let src = g.wideValueSlot(c)
  g.wideLoad(g.md.intRetReg, src, 0)
  g.wideLoad(g.md.intArgRegs[1], src, 1)

# ── the narrowing direction ─────────────────────────────────────────────────

proc emitWideToNarrow(g: var CodeGen; innerC, targetC: Cursor;
                      dest: var Location) =
  ## `(conv (i 32) <64-bit>)` and friends: the low word IS the answer, then
  ## re-normalized to the target's own width so a sub-word result stays
  ## canonically extended in its register.
  let src = g.wideValueSlot(innerC)
  g.forceRegDest(dest)
  if dest.kind != InReg:
    # The pools were dry, so `dest` is a produce-into slot. Stage through the
    # produce bridge, which exists for exactly this.
    let b = g.produceBridge
    g.bindTemp(b, ScalarSlot)
    g.wideLoad(b, src, 0)
    let tslot = slotOf(g.prog, targetC)
    g.extendTo(b, tslot.size * 8, tslot.kind == AInt)
    g.storeReg2(dest, b)
    g.unbindTemp(b)
    return
  if dest.isTemp and not g.rb.isBoundTemp(dest.r):
    g.bindTemp(dest.r, slotOf(g.prog, targetC))
  g.wideLoad(dest.r, src, 0)
  let tslot = slotOf(g.prog, targetC)
  g.extendTo(dest.r, tslot.size * 8, tslot.kind == AInt)

proc wideValueIntoTemp*(g: var CodeGen; valC: Cursor): string =
  ## Produce a 64-bit value into a stack slot and hand back the slot's NAME.
  ##
  ## The name rather than a `WideRef` because the callers are in the shared part
  ## of the emitter, above this include, where the type is not in scope yet — and
  ## because the value has to exist BEFORE its destination address is computed
  ## (its evaluation may contain a call, which a staging bridge does not survive).
  g.wideValueSlot(valC).name

# ── 64-bit division ─────────────────────────────────────────────────────────
#
# ARMv7E-M has `sdiv`/`udiv` for 32 bits and nothing for 64, and a firmware
# image has no `libgcc` to borrow `__aeabi_ldivmod` from. So the image carries
# its own: a restoring shift-subtract divider, emitted ONCE per module and only
# when something divides.
#
# The routines are called with a bare `(bl)` and read their arguments raw out of
# r0–r3, like the semihosting shims — arkham owns both sides, and a `(prepare)`
# block would only restate an ABI that is fixed here. What that DOES cost is the
# frame: `bl` overwrites lr, so a proc that looked like a leaf until it divided
# has to be told (see `helperCalls`).
