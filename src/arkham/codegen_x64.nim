#
#           Arkham — x86-64 / System V (Linux) code generator for NIFC
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3 (x86-64 backend). A first, scalar-integer code generator: it shares the
## front-end (`codegen_common`: the `CodeGen` state, the NIFC type/lvalue
## analysis) and the (arch-neutral) register allocator with the AArch64 backend,
## and emits System V / Linux asm-NIF that `nifasm` assembles+links to an ELF
## executable. Process exit is lowered to the Linux `exit` syscall (rax=60), so
## the produced binaries run without libc.
##
## v0 scope (mirrors arkham's AArch64 v1): integer/pointer scalars held in
## registers, arithmetic / bitops, `while`, comparisons, and a `main` that
## `exit`s. Floats, aggregates, memory lvalues, parameters, `if`/`case`, div/mod
## and shifts `raiseAssert` for now.

import std / [assertions, tables, sets]
import nifcore, nifcdecl
import slots, machinedesc, analyser, register_allocator, programs
import asmbuf, codegen_common, machine_x64

const TlsBlockName = "arkham.tls.0"
  ## The static block FS points at (see `emitTlsSetup`); a tvar lives at
  ## `FS:[offset]`, i.e. `&arkham.tls.0 + offset`. Distinct basename so nifasm's
  ## scope keys it uniquely.

# ── scratch register pool ────────────────────────────────────────────────────

let ScalarSlot = AsmSlot(cls: AInt, size: 8, align: 8)
  ## The placeholder slot for a register/immediate dont-care result: the old `Val`
  ## carried no type at all, and no consumer of an `InReg`/`Imm` value reads `.typ`.
  ## As a scratch-binding type it carries no cursor, so `bindTemp` falls back to
  ## `(i 64)`. A `let` (not `const`) because `AsmSlot` now holds a `Cursor`.

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot)
proc unbindTemp(g: var CodeGen; r: Reg)

proc emReg(g: var CodeGen; r: Reg) {.inline.} =
  ## A value register operand. If `r` currently hosts a named local, emit the
  ## local's *name* (a typed symbol nifasm type-checks); otherwise the raw `(reg)`
  ## tag (a transient scratch register).
  if g.regLocal.hasKey(r): g.ab.sym g.regLocal[r]
  else:
    # The volatile scratch pool (r10/r11) is the ONLY register class the allocator
    # hands out for arbitrary computed values; every such hand-out — pool, steal, and
    # staging — is now `bindTemp`'d to a checked name (see `borrowTmp`/`pickStaging`/
    # the spill paths), so a *raw* pool register reaching here means an unbound scratch
    # slipped past the binder: the silent-clobber hole this work closes. Every OTHER
    # register has an irreducible structural raw use and is allowed: rax/rdi/rsi/rdx/
    # r8/r9 are the syscall + call-argument / return ABI registers; rcx is the 4th call
    # arg; rsp/rbp are the frame/segment bases; rbx/r12–r15 are callee-saved param
    # homes. (The fixed rcx/rdx/rsi/r8 scratch *inside* the self-contained atomics /
    # mem* / byte-copy loops is nonetheless bound there, for extra checker coverage.)
    assert r notin g.md.intTempRegs,
      "arkham x64: unbound scratch-pool register reached emReg: " & x64RegName(r)
    g.ab.reg r

proc initFreeTmp(g: var CodeGen) =
  g.freeTmp = {}
  for r in g.md.intTempRegs: g.freeTmp.incl r
  g.freeFTmp = {}
  for f in g.md.floatTempRegs: g.freeFTmp.incl f
  for name, pos in g.ra.symPos:               # registers held by a local/param
    let loc = g.ra.locs[pos]
    if loc.kind == InReg: g.freeTmp.excl loc.r
    elif loc.kind == InFReg: g.freeFTmp.excl loc.f

proc tryBorrowTmp(g: var CodeGen; typ: AsmSlot): Reg =
  ## Like `borrowTmp` but returns `NoReg` when the scratch pool is exhausted
  ## (instead of failing). The caller then spills the value to a stack slot. The
  ## reg-or-`NoReg` outcome is recorded/replayed like any borrow decision. A real
  ## register is `bindTemp`'d to a typed name (`typ`) so `emReg` emits a checked
  ## symbol; the caller releases it via `freeTemp`/`giveBack`.
  result = NoReg
  if not g.ab.planning:                          # emit pass: replay the planned decision
    result = g.borrowLog[g.borrowIdx]; inc g.borrowIdx
  else:
    for r in g.md.intTempRegs:                    # plan pass: real pool allocation
      if r in g.freeTmp and not g.ra.isSealed(r) and not g.regLocal.hasKey(r):
        # `not regLocal.hasKey`: a volatile temp can be a register-local's home (the
        # allocator falls back to r10/r11 when callee-saved is exhausted). Handing
        # that register out as scratch would clobber the live local. Skip it; the
        # caller then steals a bound local properly or falls back to a clean
        # caller-saved staging reg.
        excl g.freeTmp, r
        result = r
        break
    g.borrowLog.add result                        # the chosen reg, or NoReg (exhausted)
  if result != NoReg: g.bindTemp(result, typ)     # typed name ⇒ emReg emits a symbol

# Order in which a codegen-time steal looks for a victim register-local: prefer
# volatile temps (R10/R11 — call-free locals the allocator put there, the common
# case), then callee-saved. Fixed order ⇒ the plan and emit passes pick the same
# victim deterministically.
const StealOrder = [R10, R11, RBX, R12, R13, R14, R15]

proc emScalarStackVar(g: var CodeGen; name: string)
proc emTypedStackVar(g: var CodeGen; name: string; t: Cursor)
proc emStackMem(g: var CodeGen; name: string)
proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg

proc recordEviction(g: var CodeGen; r: Reg): StealEvent =
  ## Plan-pass: evict the register-local currently in `r` to a fresh stack slot,
  ## mutating the allocator's view so every later `locationOfSym(victim)` reads the
  ## slot (`g.ra.locs` is snapshot/restored across the two passes). Returns the
  ## event for the caller to record in its replay table. Caller guarantees
  ## `regLocal.hasKey(r)`.
  let bindName = g.regLocal[r]                    # the local CURRENTLY homed in `r`
  # Resolve `bindName` to its `symPos` key (the name `ra.locs` is keyed by). `regLocal`
  # is the point-in-time tenant map (set at the local's `(var … (reg))`, cleared on kill),
  # so it already names the *right* local — crucial because `ra.locs` is a static,
  # per-symbol map where two locals with disjoint live ranges legitimately share a
  # register (the allocator frees it at scope close and reassigns it — e.g. rawAlloc's
  # small-path `c: ptr SmallChunk` and big-path `c: ptr BigChunk` in the other `if` arm,
  # both `InReg(r)`). A reverse scan over `ra.locs` couldn't tell which is the tenant here.
  # For a register-passed param `bindName` is the ABI alias `pN.0` (not a `symPos` key);
  # `aliasToDecl` maps it back to the param's decl name. Otherwise the binding name IS the
  # decl name.
  let victim = g.aliasToDecl.getOrDefault(bindName, bindName)
  let typ = g.ra.locationOfSym(victim).typ
  let slot = "evict" & $g.spillCount & ".0"; inc g.spillCount
  # The victim has a live value to save IFF it is already materialized — a declared
  # local or a settled param (`symType` is populated for both, in walk order, so this
  # is identical in plan and emit). A future local whose home register was reused from a
  # just-dead local and stolen *before* its own decl has nothing of its own here, and the
  # register's stale binding (`bindName`) belongs to that dead tenant — saving it would
  # write a different type into the victim's slot. Recorded so replay matches.
  let live = g.symType.hasKey(victim)
  g.ra.locs[g.ra.symPos[victim]] = namedStackLoc(slot, typ)
  g.ra.hasStackVars = true
  g.regLocal.del r
  result = StealEvent(victim: victim, bindName: bindName, slot: slot, reg: r, typ: typ, live: live)

proc replayEviction(g: var CodeGen; ev: StealEvent) =
  ## Emit-pass: re-apply a recorded eviction — declare the slot, store the victim's
  ## live value, kill its register binding, repoint its location to the slot.
  # Type the eviction slot from the PLAN-recorded slot type (`ev.typ`), not a re-query
  # of the mutable `symType` (which is unset when the victim was evicted before its own
  # decl → it would wrongly fall back to `(i 64)` for a pointer). A pointer keeps its
  # `(ptr T)` (else nifasm's strict store/reload rejects the typed value and later
  # deref/field access is illegal); other scalars stay the 64-bit `(i 64)` form.
  if not cursorIsNil(ev.typ.typ) and isPtrType(resolveType(g.prog, ev.typ.typ)):
    var tc = ev.typ.typ
    g.emTypedStackVar(ev.slot, tc)               # (var :evictN.0 (s) (ptr …))
  else:
    g.emScalarStackVar(ev.slot)                  # (var :evictN.0 (s) (i 64))
  if ev.live:                                    # only a materialized victim has a value
    g.ab.tree MovX64:                            # store the victim's live value
      g.emStackMem(ev.slot)
      g.emReg ev.reg                             # bound ⇒ emits its binding name
  if g.regLocal.getOrDefault(ev.reg, "") == ev.bindName:
    g.ab.tree KillX64: g.ab.sym ev.bindName      # release the register binding
  g.ra.locs[g.ra.symPos[ev.victim]] = namedStackLoc(ev.slot, ev.typ)
  g.regLocal.del ev.reg

# MODEL: the `steal` action in proofs/arkham_bindings.tla — the evicted victim must move
# to a stack slot (loc→Stack, binding cleared) or LiveLocalsHaveHomes / RegisterBindingsMatchLoc
# break. Change this ⇒ re-check that action.
proc stealReg(g: var CodeGen; logIdx: int): Reg =
  ## `freeTmp` is exhausted. Evict a register-bound local that is *not* in flight
  ## (not sealed, not a live accumulator) to a fresh stack slot and hand its
  ## register over as scratch — the codegen-side analogue of the allocator's
  ## `trySteal`, but driven by codegen's own scratch demand. The eviction is
  ## decided in the plan pass and replayed (with the spill store) in the emit
  ## pass, keyed by the borrow-log index, so both passes stay byte-consistent.
  if g.ab.planning:
    var vreg = NoReg
    for r in StealOrder:
      if g.regLocal.hasKey(r) and r notin g.boundTemps and
         not g.ra.isSealed(r) and r notin g.liveAccums:
        vreg = r; break
    if vreg == NoReg: return NoReg                 # nothing safe to steal
    g.stealEvents[logIdx] = g.recordEviction(vreg)
    result = vreg
  else:
    if logIdx notin g.stealEvents: return NoReg
    let ev = g.stealEvents[logIdx]
    g.replayEviction(ev)
    result = ev.reg

# MODEL: the `fixedUse` action in proofs/arkham_bindings.tla — a fixed-register clobber must
# evict a live local first (loc→Stack) and never a sealed in-flight value.
proc evictFixedReg(g: var CodeGen; r: Reg) =
  ## A fixed-physical-register instruction is about to clobber `r` (idiv → RDX,
  ## byteCopyConst → RCX): registers the ISA forces an instruction to overwrite,
  ## which — in a leaf proc — can still hold a live parameter (params occupy their
  ## ABI arg registers RDI/RSI/RDX/RCX/R8/R9). If so, evict that local to a stack
  ## slot here, for the rest of the proc, so the clobber cannot destroy it — the
  ## *targeted* analogue of `stealReg` (which frees *some* pooled reg for scratch).
  ## Decided in the plan pass, replayed (with the spill store) in the emit pass,
  ## keyed by call order (`fixedEvictSeq`) since the two passes walk identically. A
  ## register pinned to an in-flight ABI call (sealed) is left to its owner.
  let key = g.fixedEvictSeq; inc g.fixedEvictSeq
  if g.ab.planning:
    if not g.regLocal.hasKey(r) or r in g.boundTemps or g.ra.isSealed(r): return
    g.fixedEvicts[key] = g.recordEviction(r)
  else:
    if key in g.fixedEvicts: g.replayEviction(g.fixedEvicts[key])

proc borrowTmp(g: var CodeGen; typ: AsmSlot): Reg =
  result = g.tryBorrowTmp(typ)                    # binds on a pool hit
  if result == NoReg:
    # The plan pass just logged `NoReg` (it is at `borrowLog.len-1`); the emit
    # pass replayed it (`borrowIdx-1`). Steal at that same logical position.
    let idx = if g.ab.planning: g.borrowLog.len - 1 else: g.borrowIdx - 1
    result = g.stealReg(idx)
    if result == NoReg:
      # Pool empty AND no register-bound local to evict. This happens when the
      # allocator reserved the volatile temps (r10/r11) for locals that are not
      # yet bound at this point in the walk (e.g. an early global-store whose
      # scratch need precedes every local's decl, so `regLocal` is empty) — the
      # reserved register isn't in `regLocal`, so `stealReg` can't see it. Fall
      # back to a free caller-saved register, exactly as a spill's `pickStaging`
      # does: a transient, clobberable scratch. The pick is a deterministic
      # function of the per-pass-identical state (sealed / liveAccums / live
      # locals), so the plan and emit passes agree without a borrow-log entry —
      # `stealReg` recorded no `stealEvent`, so both passes reach this fallback.
      # Sealing stops a nested borrow from reusing it; `giveBack` unseals.
      result = g.pickStagingScratch()
      if result == NoReg:
        raiseAssert "arkham x64 v0: out of registers (no local to steal for scratch)"
      g.ra.seal result
    g.bindTemp(result, typ)                        # steal / staging-fallback reg → typed name

proc giveBack(g: var CodeGen; r: Reg) {.inline.} =
  ## Release a transient register obtained during premat / value evaluation. Its
  ## scratch binding (`bindTemp`) is `(kill)`'d first; then a staging register
  ## (caller-saved, sealed while it held an address/index so a sibling pick couldn't
  ## reuse it) is unsealed; a real scratch-pool register (R10/R11) is also returned to
  ## the pool. Unbinding/unsealing a reg that carries neither is a harmless no-op.
  if r == NoReg: return
  g.unbindTemp(r)
  g.ra.unseal {r}
  if r in g.md.intTempRegs: g.freeTmp.incl r

proc wantReg(g: var CodeGen; dest: var Location): Reg =
  ## Resolve a register-requiring destination to a concrete writable GPR for an
  ## operation that computes a *fresh* value (an address, a coercion) and so always
  ## needs its own register — unlike `gen`'s `NeedsReg` arm, which may leave a value
  ## resident in place. A fixed `InReg` dest is used as-is (the caller owns it); a
  ## `NeedsReg` ("your choice") dest borrows a scratch temp and is written back as
  ## the concrete `InReg` it resolved to (`isTemp = true`, so the caller `giveBack`s).
  case dest.kind
  of InReg: result = dest.r
  of NeedsReg:
    result = g.borrowTmp(ScalarSlot)
    dest = regLoc(result, dest.typ, isTemp = true)
  else: raiseAssert "arkham x64: wantReg cannot resolve dest kind " & $dest.kind

# ── SSE / floating-point scratch pool + emit helpers ─────────────────────────
# x86-64 floats live in xmm0..xmm15 (the FReg slots F0..F15). The register operand
# is always `(xmmN)`; the precision is carried by the instruction tag (movss vs
# movsd, addss vs addsd, …), unlike AArch64 where `(sN)`/`(dN)` encode it.

const FloatRet = F0    # xmm0: SysV scalar-float return + first float argument

proc bindFTmp(g: var CodeGen; f: FReg)
proc unbindFTmp(g: var CodeGen; f: FReg)

proc emFReg(g: var CodeGen; f: FReg) {.inline.} =
  ## A float value register operand. If `f` currently hosts a named float local /
  ## scratch temp, emit its *name* (a typed symbol nifasm checks); otherwise the raw
  ## `(xmmN)` tag. The SIMD twin of `emReg`: the xmm8–15 scratch pool is the only
  ## register class the allocator hands out for arbitrary computed floats, and every
  ## such hand-out — pool temp (`bindFTmp`) and register-local (`emFRegLocalVar`) —
  ## is bound, so a *raw* pool register reaching here is an unbound scratch slipping
  ## past the binder. The xmm0–7 arg/return/staging registers have structural raw
  ## uses (ABI float args, the float return, a spill's transient `pickFStaging`).
  if g.fregLocal.hasKey(f): g.ab.sym g.fregLocal[f]
  else:
    assert f notin g.md.floatTempRegs,
      "arkham x64: unbound float scratch-pool register reached emFReg: xmm" & $ord(f)
    g.ab.xmmReg f

proc bindFTmp(g: var CodeGen; f: FReg) =
  ## Give scratch xmm register `f` a typed nifasm name `ftmpN.0` via `(rebind …)`, so
  ## every later `emFReg f` emits a checked symbol the binding checker sees rather than
  ## a raw `(xmmN)`. The SIMD twin of `bindTemp`: the name counter bumps in BOTH passes
  ## (names replay identically) and the `(rebind …)` tree auto-no-ops in the plan pass.
  ## The precision is a generic `(f 64)` — the operand carries no width to nifasm (the
  ## instruction tag selects movss/movsd), so the binding type is just a placeholder.
  let name = "ftmp" & $g.ftmpBindCount & ".0"; inc g.ftmpBindCount
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.ab.floatType(64)
    g.ab.xmmReg f
  g.fregLocal[f] = name
  g.boundFTmps.incl f

proc unbindFTmp(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## `fregLocal`/`boundFTmps` entries. A no-op when `f` carries no temp binding.
  if f in g.boundFTmps:
    g.ab.tree KillX64: g.ab.sym g.fregLocal[f]
    g.fregLocal.del f
    g.boundFTmps.excl f

proc tryBorrowFTmp(g: var CodeGen): FReg =
  ## Like `borrowFTmp` but returns `NoFReg` when the SIMD scratch pool is
  ## exhausted (instead of failing), so the caller can spill to a float stack
  ## slot — the float analogue of `tryBorrowTmp`. The reg-or-`NoFReg` outcome is
  ## recorded/replayed through `borrowLogF` like any borrow decision. A real register
  ## is `bindFTmp`'d to a typed name so `emFReg` emits a checked symbol; the caller
  ## releases it via `giveBackF`.
  result = NoFReg
  if not g.ab.planning:                          # emit pass: replay the planned decision
    result = g.borrowLogF[g.borrowIdxF]; inc g.borrowIdxF
  else:
    for f in g.md.floatTempRegs:                  # plan pass: real pool allocation
      if f in g.freeFTmp:
        excl g.freeFTmp, f
        result = f
        break
    g.borrowLogF.add result                       # the chosen reg, or NoFReg (exhausted)
  if result != NoFReg: g.bindFTmp(result)         # typed name ⇒ emFReg emits a symbol

proc borrowFTmp(g: var CodeGen): FReg =
  ## A SIMD scratch register from the pool. Asserts on exhaustion: callers that
  ## use this (rather than `tryBorrowFTmp` + a spill path) only ever need one or
  ## two transient temps whose deep sub-expressions recurse through the now-total
  ## `genFBin`, so the pool cannot be empty at the borrow point in practice.
  result = g.tryBorrowFTmp()
  if result == NoFReg:
    raiseAssert "arkham x64 v0: out of SIMD scratch registers"

proc giveBackF(g: var CodeGen; f: FReg) {.inline.} =
  g.unbindFTmp(f)                                 # release the scratch binding (if any)
  if f in g.md.floatTempRegs: g.freeFTmp.incl f

proc fmovF(g: var CodeGen; d, s: FReg; bits: int) =                # movss/movsd d, s
  if d == s: return
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fmovFromGpr(g: var CodeGen; d: FReg; s: Reg; bits: int) =     # movfd/movfq xmm ← gpr
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fmovToGpr(g: var CodeGen; d: Reg; s: FReg; bits: int) =       # movfd/movfq gpr ← xmm
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc fbin(g: var CodeGen; op32, op64: X64Inst; d, s: FReg; bits: int) =  # d = d op s
  let op = if bits == 32: op32 else: op64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fcvtI2F(g: var CodeGen; d: FReg; s: Reg; bits: int) =         # cvtsi2ss/sd xmm ← gpr
  let op = if bits == 32: Cvtsi2ssX64 else: Cvtsi2sdX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fcvtF2I(g: var CodeGen; d: Reg; s: FReg; bits: int) =         # cvttss2si/sd2si gpr ← xmm
  let op = if bits == 32: Cvttss2siX64 else: Cvttsd2siX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc emFcvt(g: var CodeGen; d, s: FReg; dstBits, srcBits: int) =   # precision convert
  if dstBits == srcBits: (g.fmovF(d, s, dstBits); return)
  let op = if dstBits == 32: Cvtsd2ssX64 else: Cvtss2sdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

# A spilled float scalar lives in an `(s) (f N)` stack slot (x64 has no callee-
# saved xmm registers, so a float that must survive a call has nowhere else to
# go). It is loaded/stored with movss/movsd against `(mem (rsp) name)`.
proc emFloatStackVar(g: var CodeGen; name: string; bits: int) =
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.floatType(bits)
  g.ab.close()

proc emFloatScalarLoad(g: var CodeGen; dest: FReg; name: string; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.emFReg dest
    g.ab.tree MemX: (g.ab.reg RSP; g.ab.sym name)

proc emFloatScalarStore(g: var CodeGen; name: string; src: FReg; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.ab.tree MemX: (g.ab.reg RSP; g.ab.sym name)
    g.emFReg src

# ── low-level emit helpers ───────────────────────────────────────────────────

proc movImm(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovX64: g.emReg d; g.ab.intLit v

proc movReg(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovX64: g.emReg d; g.emReg s

proc binReg(g: var CodeGen; op: X64Inst; d, s: Reg) =      # d op= s
  g.ab.tree op: g.emReg d; g.emReg s

proc binImm(g: var CodeGen; op: X64Inst; d: Reg; v: int64) =  # d op= imm
  g.ab.tree op: g.emReg d; g.ab.intLit v

proc extendTo(g: var CodeGen; dest: Reg; width: int; signed: bool) =
  ## Normalize the low `width` bits of `dest` to its full 64-bit register form
  ## (sign- or zero-extended). No-op for 64-bit. Done with the `shl #(64-w);
  ## sar|shr #(64-w)` shift pair (immediate shifts), matching the A64 backend —
  ## arkham keeps every scalar 64-bit-wide in a register, so widths are normalized
  ## explicitly rather than relying on sized loads.
  if width <= 0 or width >= 64: return
  let sh = int64(64 - width)
  g.binImm(ShlX64, dest, sh)
  g.binImm(if signed: SarX64 else: ShrX64, dest, sh)

proc emLab(g: var CodeGen; name: string) =
  g.ab.tree LabX64: g.ab.symDef name

proc emJmp(g: var CodeGen; name: string) =
  g.ab.tree JmpX64: g.ab.sym name

proc emJcc(g: var CodeGen; tag: X64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name

proc emSyscall(g: var CodeGen) = g.ab.keyword SyscallX64

proc freshLabel(g: var CodeGen): string =
  ## The plan pass emits no labels (all `ab` writes no-op), so it must not consume
  ## label names either — only the emit pass advances the counter. Both passes then
  ## walk identically and the emit pass numbers labels exactly as a single pass would.
  result = "L" & $g.labelCount & ".0"
  if not g.ab.planning: inc g.labelCount

# ── expressions ──────────────────────────────────────────────────────────────

proc gen(g: var CodeGen; c: var Cursor; dest: var Location)
proc genInto(g: var CodeGen; c: var Cursor; dest: Reg)
proc genCall(g: var CodeGen; c: var Cursor)
proc genAddr(g: var CodeGen; c: var Cursor; dest: var Location)
proc emitCondJump(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool)
proc genVal(g: var CodeGen; c: var Cursor): Location
proc emitPatAddr(g: var CodeGen; c: var Cursor; dest: Reg)
proc forceReg(g: var CodeGen; dest: var Location)
proc genTypeBody(g: var CodeGen; c: var Cursor)
proc emitGlobalInits(g: var CodeGen)
proc framePop(g: var CodeGen)
proc killFrameRegLocals(g: var CodeGen)
proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int)
proc genConstr(g: var CodeGen; c: var Cursor; dstPtr: Reg)
proc genStore(g: var CodeGen; c: var Cursor; dst: Location)
proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg
proc place(g: var CodeGen; v: Location; dest: Reg)
proc genBin(g: var CodeGen; c: var Cursor; destLoc: var Location; op: X64Inst; immOk: bool)
proc refsReg(g: var CodeGen; c: Cursor; r: Reg): bool

proc binArithOp(c: Cursor): tuple[op: X64Inst, immOk: bool, isBin: bool] =
  ## Map a binary-arith rvalue to its x86 opcode (and whether an immediate folds),
  ## for routing a memory-destination assignment through `genBin`. `isBin = false`
  ## for div/mod (rax:rdx, no memory dest) and any non-arith expression.
  if c.kind != TagLit: return (AddX64, false, false)
  case c.exprKind
  of AddC: (AddX64, true, true)
  of SubC: (SubX64, true, true)
  of MulC: (ImulX64, false, true)
  of BitandC: (AndX64, true, true)
  of BitorC: (OrX64, true, true)
  of BitxorC: (XorX64, true, true)
  of ShlC: (ShlX64, true, true)
  of ShrC:
    var tc = c; inc tc                            # result-type child → signedness
    ((if isSignedType(tc): SarX64 else: ShrX64), true, true)
  else: (AddX64, false, false)

# ── named local variables (nifasm type-checks them; raw scratch stays `(reg)`) ─

proc emRegLocalVar(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Declare `(var :name (reg) type)` and bind `r` to `name` for the rest of its
  ## scope, so subsequent uses emit the typed name instead of `(reg)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register. The kill lands at this rebind,
  # past the dead var's coarse free point, hence on its post-dominating path.
  if g.regLocal.hasKey(r):
    g.ab.tree KillX64: g.ab.sym g.regLocal[r]
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.reg r                                   # the concrete register (the binding)
  # arkham keeps scalars 64-bit in registers and handles width/signedness via
  # explicit extends, so an int/uint/bool/char local is declared as plain
  # `(i 64)` (a logical `i8`/`u8` would mismatch a 64-bit `mov`, and nifasm also
  # rejects an `i`↔`u` move); a pointer keeps its `(ptr T)` so deref/field typing
  # works. Signed-vs-unsigned comparisons still pick `jb`/`jl` from the slot.
  let rt = resolveType(g.prog, typeCur)
  if isPtrType(rt):
    var tc = typeCur
    g.genTypeBody(tc)
  else: g.ab.intType(64)
  g.ab.close()
  g.regLocal[r] = name
  g.freeTmp.excl r                               # a local's home is no longer scratch
  g.scopeLocals[^1].add (name: name, reg: r)

proc emFRegLocalVar(g: var CodeGen; name: string; f: FReg; bits: int) =
  ## Declare a float register local: bind xmm `f` to `name` via `(rebind …)` for the
  ## rest of its scope, so subsequent uses emit the typed name instead of `(xmmN)`.
  ## The SIMD twin of `emRegLocalVar`. `rebind` kills `f`'s prior tenant itself (an
  ## earlier, now-dead local the allocator reassigned the register to), so no manual
  ## kill is needed first.
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.xmmReg f
  g.fregLocal[f] = name
  g.freeFTmp.excl f                              # a local's home is no longer scratch
  g.scopeFLocals[^1].add (name: name, f: f)

proc enterScope(g: var CodeGen) =
  g.scopeLocals.add @[]
  g.scopeFLocals.add @[]

proc exitScope(g: var CodeGen) =
  ## `kill` each register local declared in the closing scope so the allocator's
  ## register reuse in a sibling scope rebinds cleanly (nifasm forbids binding a
  ## still-live register). Skip any whose register was already rebound to a later
  ## local (already killed at that rebind).
  for it in g.scopeLocals.pop():
    if g.regLocal.getOrDefault(it.reg, "") == it.name:
      g.ab.tree KillX64: g.ab.sym it.name
      g.regLocal.del it.reg
  for it in g.scopeFLocals.pop():
    if g.fregLocal.getOrDefault(it.f, "") == it.name:
      g.ab.tree KillX64: g.ab.sym it.name
      g.fregLocal.del it.f

# ── stack-slot declarations + memory operands (x86 addressing) ───────────────
# nifasm keeps field names / element types, so a memory operand stays symbolic:
#  * a spilled/address-taken scalar or aggregate is a `(var :name (s) T)` slot,
#    addressed `(mem (rsp) name)` / `(mem (dot (rsp) name field))`;
#  * a pointer in a register is dereferenced `(mem reg)`.
# Storing an immediate to memory is unimplemented in nifasm, so callers
# materialize the value into a register first.

proc emStackVar(g: var CodeGen; name, typeName: string) =
  ## `(var :name (s) typeName)` — a nifasm-managed aggregate stack slot.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.sym typeName
  g.ab.close()

proc emScalarStackVar(g: var CodeGen; name: string) =
  ## `(var :name (s) (i 64))` — a spilled/address-taken scalar's 8-byte slot.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc emTypedStackVar(g: var CodeGen; name: string; t: Cursor) =
  ## `(var :name (s) T)` with `T` the value's actual NIFC type. Use this (not the
  ## generic `(i 64)` slot) for a homed/spilled scalar whose type matters to
  ## nifasm — e.g. a pointer param that the body later derefs, where an `(i 64)`
  ## slot would both reject the typed store and forbid the deref (nifasm is strict).
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  var tc = t
  if tc.kind == Symbol: g.ab.sym symName(tc)
  else: g.genTypeBody(tc)
  g.ab.close()

proc emBindType(g: var CodeGen; typ: AsmSlot) =
  ## Emit the NIFC type for a scratch binding: the slot's own type when known, else
  ## the generic `(i 64)` (a register/immediate dont-care placeholder carries no
  ## cursor). Mirrors `emTypedStackVar`'s type emission.
  if cursorIsNil(typ.typ):
    g.ab.intType(64)
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(reg)` the binding
  ## checker can't see. The name counter bumps in BOTH passes (so names replay
  ## identically); the `(rebind …)` tree auto-no-ops in the plan pass. `boundTemps`
  ## records that `r`'s `regLocal` entry is a temp, NOT a steal-able local, so
  ## `stealReg`/`evictFixedReg` leave it alone. Released by `unbindTemp`.
  let name = "tmp" & $g.tmpBindCount & ".0"; inc g.tmpBindCount
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.emBindType(typ)
    g.ab.reg r
  g.regLocal[r] = name
  g.boundTemps.incl r

proc unbindTemp(g: var CodeGen; r: Reg) =
  ## Release a scratch binding made by `bindTemp`: `(kill)` the name and drop the
  ## `regLocal`/`boundTemps` entries. A no-op when `r` carries no temp binding (so it
  ## is safe on every `giveBack`, whether or not the reg was a bound temp).
  if r in g.boundTemps:
    g.ab.tree KillX64: g.ab.sym g.regLocal[r]
    g.regLocal.del r
    g.boundTemps.excl r

template withFixed(g: var CodeGen; r: Reg; body: untyped) =
  ## Bracket a hardcoded use of a fixed ABI/ISA register `r` (atomics, mem*,
  ## byte-copy, the aggregate-result pointer) with a typed binding, so its `emReg`
  ## operands inside `body` are checked names instead of a raw `(reg)` that bypasses
  ## nifasm's binder. Like `bindTemp`/`unbindTemp` it is zero machine code. The bind
  ## kills `r`'s prior tenant, so a later raw use of a value wrongly left there
  ## becomes a build error rather than a silent clobber.
  g.bindTemp(r, ScalarSlot)
  body
  g.unbindTemp(r)

proc emStackMem(g: var CodeGen; name: string) =       # (mem (rsp) name)
  g.ab.tree MemX:
    g.ab.reg RSP
    g.ab.sym name

proc emFieldMem(g: var CodeGen; base, field: string) =   # (mem (dot (rsp) base field))
  for fi in aggrLayout(g.prog, g.varType[base]):  # v0: only full 8-byte fields
    if fi.name == field:
      if fi.size != 8:
        raiseAssert "arkham x64 v0: sub-word field not supported: " & base & "." & field
      break
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.reg RSP
      g.ab.sym base
      g.ab.sym field

proc fieldOffset(g: var CodeGen; base, field: string): int =
  for fi in aggrLayout(g.prog, g.varType[base]):
    if fi.name == field: return fi.off
  raiseAssert "arkham x64: field not found: " & base & "." & field

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string)

proc loadOperandReg(g: var CodeGen; v: Location; tmps: var seq[Reg]): Reg =
  ## Materialize `v` into a register for a single memory-operand instruction
  ## (`emAccessAddr`). Such a register is transient — it lives only for the one
  ## load/store/cmp the operand feeds, with no calls in between — so when the
  ## scratch pool is exhausted a caller-saved staging register is safe, keeping
  ## indexed/global access total under register pressure.
  if v.kind == InReg:
    if v.isTemp: tmps.add v.r
    return v.r
  result = g.tryBorrowTmp(v.typ)   # bind the scratch to the value's PRECISE type
  if result != NoReg: tmps.add result
  else:
    result = g.pickStaging()
    g.ra.seal result          # hold it so a sibling base/index pick can't reuse it
    g.bindTemp(result, v.typ) # checked name for the held value (`giveBack` unbinds)
    tmps.add result           # `giveBack` unseals it after the operand is consumed
  g.place(v, result)

proc atNeedsScratch(g: var CodeGen; atNode: Cursor): bool =
  ## Does this `(at base idx)` level need an explicit scratch register? x86 can fold
  ## `base + idx*scale` into one operand only for scale ∈ {1,2,4,8} and a single
  ## index; a register index whose element stride is anything else (a multi-
  ## dimensional array's outer dimension, stride = the inner array's size) cannot
  ## fold, so arkham hands nifasm a scratch and nifasm computes `base + idx*stride`
  ## into it (the `(at base idx scratch)` 3-operand form). An immediate index always
  ## folds to a displacement → never needs one. This is the x86 SIB rule; the arm64
  ## backend's analogue always returns true (it materializes every indexed address).
  let stride = typeSizeAlign(g.prog, resolveType(g.prog, g.getType(atNode)))[0]
  if stride in [1, 2, 4, 8]: return false
  var n = atNode
  var idxIsReg = false
  n.into:
    skip n                                      # the array base
    idxIsReg = n.kind != IntLit                 # a non-literal index lives in a register
    while n.hasMore: skip n
  result = idxIsReg

proc atGlobalRooted(g: var CodeGen; n: Cursor): bool =
  ## Does this `dot`/`at` lvalue chain bottom out at a module-level global aggregate?
  ## Only then can the value-core scratch pre-pass size the element stride via
  ## `getType` (a local base's type isn't in `symType` during the pre-pass). A
  ## `deref`/`pat` base is a pointer value, not a global lvalue, so it stops here.
  var c = n
  case c.kind
  of Symbol: result = g.lookupSym(symName(c)).cat == scGlobal
  of TagLit:
    case c.exprKind
    of DotC, AtC:
      var cc = c
      cc.into:
        result = g.atGlobalRooted(cc)
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc collectAtScratch(g: var CodeGen; n: Cursor; res: var HashSet[int]) =
  ## Pre-pass (value core): record every global-rooted `(at …)` position whose
  ## element stride is not a SIB scale, so the allocator reserves it a scratch GPR
  ## (`(at base idx scratch)` 3-operand form). Walks `n`'s whole subtree.
  var c = n
  if c.kind == TagLit:
    if c.exprKind == AtC and g.atGlobalRooted(c) and g.atNeedsScratch(c):
      res.incl cursorToPosition(g.buf[], c)
    var cc = c
    cc.into:
      while cc.hasMore: (g.collectAtScratch(cc, res); skip cc)

proc prematAccess(g: var CodeGen; n: var Cursor; tmps: var seq[Reg]; regs: var seq[Reg]) =
  ## PASS 1 of address emission. Walk the NIFC lvalue subtree `n` and materialize
  ## every embedded VALUE — a deref'd pointer, a computed array index, a global's
  ## address — into a register NOW, emitting the load as an ordinary preceding
  ## statement (this runs at statement level, before the consuming instruction tree
  ## is opened). Registers are appended to `regs` in traversal order; `emAccessAddr`
  ## (pass 2) consumes them in that exact order, so no helper instruction ever lands
  ## *inside* the address operand tree (which would be corrupt asm-NIF — a `(dot
  ## (mov …) …)`). Borrowed scratch is pushed to `tmps` for the caller to free
  ## after pass 2. `n` is fully advanced (over its own copy at the call site).
  case n.kind
  of Symbol:
    let nm = symName(n); inc n
    let loc = g.ra.locationOfSym(nm)
    if loc.kind notin {NamedStack, InReg}:
      # A global aggregate base: materialize its address into a register. (The
      # address lives only for the one load/store/cmp this operand feeds, so a
      # transient caller-saved staging register is safe when the pool is empty.)
      let si = g.lookupSym(nm)
      if si.cat != scGlobal:
        raiseAssert "arkham x64 v0: unsupported lvalue base: " & nm
      var r = g.tryBorrowTmp(ScalarSlot)
      if r != NoReg: tmps.add r
      else:
        r = g.pickStaging()
        g.ra.seal r             # hold the base addr so the index pick can't reuse it
        g.bindTemp(r, ScalarSlot)  # the global's address (a base; `giveBack` unbinds)
        tmps.add r              # `giveBack` unseals it after the operand is consumed
      g.emGlobalAddr(r, nm)
      regs.add r
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        g.prematAccess(n, tmps, regs)            # base (recursive)
        skip n                                   # field name
        while n.hasMore: skip n                  # depth selector
    of AtC:
      let needsScratch = g.atNeedsScratch(n)
      n.into:
        g.prematAccess(n, tmps, regs)            # array base (recursive)
        if n.kind == IntLit: inc n               # immediate index stays inline
        else: regs.add g.loadOperandReg(g.genVal(n), tmps)  # computed index → reg
        if needsScratch:                         # non-scale stride: supply a scratch reg
          var s = g.tryBorrowTmp(ScalarSlot)               # nifasm computes base+idx*stride into it
          if s != NoReg: tmps.add s
          else:
            s = g.pickStaging()
            g.ra.seal s
            g.bindTemp(s, ScalarSlot)  # `(at)` stride scratch (`giveBack` unbinds)
            tmps.add s
          regs.add s
        while n.hasMore: skip n
    of DerefC:
      n.into:
        regs.add g.loadOperandReg(g.genVal(n), tmps)  # the pointer → a register
        while n.hasMore: skip n                  # (cppref)?
    of PatC:
      # `(pat base idx)` — pointer indexing. Unlike `at`, the base is a pointer
      # VALUE (a cast/add expression, not an lvalue chain): evaluate it into a
      # register here (an array/flexarray field decays to its address). The element
      # type is carried into pass 2 as a `(cast (aptr elem) base)`, so nifasm strides
      # the index by the element size — pat is `at` over a typed pointer base.
      let needsScratch = g.atNeedsScratch(n)
      n.into:
        let baseTy = resolveType(g.prog, g.getType(n))
        if baseTy.typeKind in {NifcType.ArrayT, NifcType.FlexarrayT}:
          var r = g.tryBorrowTmp(ScalarSlot)
          if r != NoReg: tmps.add r
          else:
            r = g.pickStaging(); g.ra.seal r; g.bindTemp(r, ScalarSlot); tmps.add r
          var bd = regLoc(r, ScalarSlot); g.genAddr(n, bd)   # base ← &field
          regs.add r
        else:
          regs.add g.loadOperandReg(g.genVal(n), tmps)       # base ← the pointer value
        if n.kind == IntLit: inc n               # immediate index stays inline
        else: regs.add g.loadOperandReg(g.genVal(n), tmps)   # computed index → reg
        if needsScratch:                         # non-scale stride: supply a scratch reg
          var s = g.tryBorrowTmp(ScalarSlot)
          if s != NoReg: tmps.add s
          else:
            s = g.pickStaging(); g.ra.seal s; g.bindTemp(s, ScalarSlot); tmps.add s
          regs.add s
        while n.hasMore: skip n
    else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.exprKind
  else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.kind

proc emAccessAddr(g: var CodeGen; n: var Cursor; regs: openArray[Reg]; ri: var int) =
  ## PASS 2: re-emit the lvalue subtree `n` as a nifasm address expression so
  ## nifasm collapses the chain to `base+offset` (+ index*scale) from the declared
  ## types. Emits ONLY register / stack-symbol / immediate leaves — every embedded
  ## value was already loaded into a register by `prematAccess`, consumed here from
  ## `regs` (same traversal order) — so this pass emits no instruction of its own.
  ## A stack var contributes `(rsp) name`; a register-resident pointer its register.
  case n.kind
  of Symbol:
    let nm = symName(n); inc n
    let loc = g.ra.locationOfSym(nm)
    case loc.kind
    of NamedStack: (g.ab.reg RSP; g.ab.sym nm)   # a stack var: rsp + slot offset
    of InReg:
      if g.varType.hasKey(nm):
        # a by-reference aggregate: the register holds a pointer; type it with a
        # cast so a `(dot …)` / `(at …)` can compute the field/element offset.
        g.ab.tree CastX:
          g.ab.ptrType: g.ab.sym g.varType[nm]
          g.emReg loc.r
      else:
        g.emReg loc.r                              # a plain pointer in a register
    else:
      # global aggregate: its address was materialized into regs[ri] by pass 1.
      let r = regs[ri]; inc ri
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                        # enter (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg r
  of TagLit:
    case n.exprKind
    of DotC:
      g.ab.tree DotX:
        n.into:
          g.emAccessAddr(n, regs, ri)            # base (recursive)
          let field = symName(n); inc n          # field name (offset is nifasm's job)
          g.ab.sym field                         # nifasm sizes the access by field type
          while n.hasMore: skip n                # depth selector
    of AtC:
      let needsScratch = g.atNeedsScratch(n)
      g.ab.tree AtX:
        n.into:
          g.emAccessAddr(n, regs, ri)            # array base (recursive)
          if n.kind == IntLit: (g.ab.intLit intVal(n); inc n)
          else: (g.emReg regs[ri]; inc ri; skip n)  # pre-loaded computed index
          if needsScratch:                       # 3rd operand: arkham-supplied scratch
            g.emReg regs[ri]; inc ri             #   nifasm computes base+idx*stride into it
          while n.hasMore: skip n
    of DerefC:
      # The deref'd pointer is in a register (pre-loaded). Type it as `(ptr
      # Pointee)` so an enclosing `(dot …)`/`(at …)` can compute the field/element
      # offset (a bare register carries no pointee type — nifasm couldn't size the
      # access). `getType` yields the pointee (its `fieldType` handles inheritance).
      var pointee = g.getType(n)                  # deref result = the pointee type
      n.into:
        g.ab.tree CastX:
          g.ab.ptrType:
            if pointee.kind == Symbol: g.ab.sym symName(pointee)
            else: g.genTypeBody(pointee)
          g.emReg regs[ri]; inc ri                # the pointer (pre-loaded)
        skip n                                    # skip the pointer value subtree
        while n.hasMore: skip n                   # (cppref)?
    of PatC:
      # `(pat base idx)` → `(at (cast (aptr elem) base) idx)`: the base pointer was
      # pre-loaded into a register; emit it as a typed `aptr` so nifasm strides the
      # index by the element size (mirrors `emitPatAddr`'s lea operand).
      let needsScratch = g.atNeedsScratch(n)
      g.ab.tree AtX:
        n.into:
          var elem = innerType(g.prog, resolveType(g.prog, g.getType(n)))
          g.ab.tree CastX:
            g.ab.aptrType:
              if elem.kind == Symbol: g.ab.sym symName(elem)
              else: g.genTypeBody(elem)
            g.emReg regs[ri]; inc ri              # the base pointer (pre-loaded)
          skip n                                   # skip the base value subtree
          if n.kind == IntLit: (g.ab.intLit intVal(n); inc n)
          else: (g.emReg regs[ri]; inc ri; skip n) # pre-loaded computed index
          if needsScratch: (g.emReg regs[ri]; inc ri)
          while n.hasMore: skip n
    else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.exprKind
  else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.kind

proc prematLoc(g: var CodeGen; loc: Location; tmps: var seq[Reg]): seq[Reg] =
  ## Pre-materialize the values embedded in a memory operand's access chain (see
  ## `prematAccess`), as statements emitted BEFORE the consuming instruction tree.
  ## A `NamedStack` (spilled scalar / synthetic spill) has no chain → no work.
  ## Call this first, then emit the operand with the returned registers via
  ## `emMemOperandLoc` / `emAccessAddr`, and free `tmps` afterwards.
  result = @[]
  if loc.kind == Mem:
    var c = loc.cur
    g.prematAccess(c, tmps, result)

proc emMemOperandLoc(g: var CodeGen; loc: Location; regs: openArray[Reg]; ri: var int) =
  ## `(mem <addr>)` for a memory `Location`. `NamedStack` is a by-name slot →
  ## `(mem (rsp) name)`; `Mem` re-emits its lvalue subtree (pass 2) so nifasm folds
  ## the chain. Embedded values were pre-loaded by `prematLoc`/`prematAccess`.
  case loc.kind
  of NamedStack: g.emStackMem(loc.name)
  of Mem:
    var nn = loc.cur
    g.ab.tree MemX:
      g.emAccessAddr(nn, regs, ri)
  else: raiseAssert "arkham x64: emMemOperandLoc on non-memory location " & $loc.kind

template withMemOperand(g: var CodeGen; loc: Location; body: untyped) =
  ## The memory-operand prelude shared by every load/store/RMW that folds a
  ## `Location`: pre-load the values embedded in its access chain (`prematLoc`,
  ## emitted as statements BEFORE the consuming instruction), run `body` with the
  ## injected `regs`/`ri` threading them through `emMemOperandLoc`, then free the
  ## borrowed temps. Only the inner `ab.tree` differs across call sites.
  block:
    var tmps: seq[Reg]
    let regs {.inject.} = g.prematLoc(loc, tmps)
    var ri {.inject.} = 0
    body
    for t in tmps: g.giveBack t

proc scalarMemMov(g: var CodeGen; loc: Location; reg: Reg; load: bool) =
  ## The one GPR scalar memory move over every lvalue kind, both directions:
  ## `load` → `reg ← <loc>`; else `<loc> ← reg`. Load and store are mirror images
  ## — the value register and the memory operand swap order in the `(mov …)` — apart
  ## from `Glob`: a store borrows a separate address temp (it must not clobber
  ## `reg`), whereas a load reuses `reg` itself as the address scratch.
  case loc.kind
  of InReg:
    if load: g.movReg(reg, loc.r) else: g.movReg(loc.r, reg)
  of Tvar:                                        # nifasm resolves a tvar to FS:[off]
    g.ab.tree MovX64:
      if load: (g.emReg reg; g.ab.sym loc.name)
      else:    (g.ab.sym loc.name; g.emReg reg)
  of Glob:
    if load:                                       # &g into reg, then deref it
      g.emGlobalAddr(reg, loc.name)
      g.ab.tree MovX64:
        g.emReg reg
        g.ab.tree MemX: g.emReg reg
    else:                                          # &g into a temp, then store
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries
      # the global's PRECISE type — a store of a typed pointer value into a pointer
      # global would otherwise mismatch a generic `(i 64)` mem (nifasm is strict).
      var pSlot = ScalarSlot
      if not cursorIsNil(loc.typ.typ):
        pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
      let p = g.borrowTmp(pSlot)
      g.emGlobalAddr(p, loc.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg p
        g.emReg reg
      g.giveBack p
  of NamedStack, Mem:                             # rsp slot / folded access chain
    g.withMemOperand(loc):
      g.ab.tree MovX64:
        if load: (g.emReg reg; g.emMemOperandLoc(loc, regs, ri))
        else:    (g.emMemOperandLoc(loc, regs, ri); g.emReg reg)
  else: raiseAssert "arkham x64: scalarMemMov on location kind " & $loc.kind

proc emitLoadLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← <scalar Location>` (the one scalar load, over every lvalue kind).
  g.scalarMemMov(loc, dest, load = true)

proc emitStoreLoc(g: var CodeGen; loc: Location; src: Reg) =
  ## `<scalar Location> ← src` (GPR). The store counterpart of `emitLoadLoc`.
  g.scalarMemMov(loc, src, load = false)

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &global` — RIP-relative `lea` (nifasm resolves the gvar to a
  ## `.bss`/`.data` address). x86-64 has no typed RIP-relative memory operand, so
  ## a global is always accessed by first materializing its address.
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym name)

proc binMem(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location) =
  ## `dest op= <memory operand>` — x86 folds a memory source into the ALU op.
  g.withMemOperand(loc):
    g.ab.tree op:
      g.emReg dest
      g.emMemOperandLoc(loc, regs, ri)

proc binMemReg(g: var CodeGen; op: X64Inst; dest: Location; src: Reg) =
  ## `<memory operand> op= src` — an ALU op run IN PLACE on memory (the symmetric
  ## counterpart of `binMem`). `dest` is the one memory operand, so the source is a
  ## register. Used for an augmented assignment to a stack slot (`add [slot], reg`).
  g.withMemOperand(dest):
    g.ab.tree op:
      g.emMemOperandLoc(dest, regs, ri)
      g.emReg src

proc binMemImm(g: var CodeGen; op: X64Inst; dest: Location; v: int64) =
  ## `<memory operand> op= imm` — in-place ALU op with an immediate source
  ## (`add [slot], 4`). nifasm encodes the `0x81 /ext` memory-immediate form.
  g.withMemOperand(dest):
    g.ab.tree op:
      g.emMemOperandLoc(dest, regs, ri)
      g.ab.intLit v

proc emitAddrLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← &<Location>`.
  case loc.kind
  of NamedStack:                              # (lea dest (rsp) name)
    g.ab.tree LeaX64: (g.emReg dest; g.ab.reg RSP; g.ab.sym loc.name)
  of Glob: g.emGlobalAddr(dest, loc.name)     # &global → RIP-relative lea
  of Tvar:
    # &threadvar = FS base + the tvar's offset. nifasm owns the offset; arkham owns
    # the FS base — the static block `arkham.tls.0` it points FS at (emitTlsSetup),
    # i.e. the base of the TLS array. A single `lea dest, (base) tvar` folds the
    # offset nifasm knows into the lea displacement: one scratch register, and no
    # pointer arithmetic (a tvar's address is a single-element `ptr`, on which
    # nifasm — by design — forbids `add`/`sub`).
    if loc.name notin g.tvarNames:
      raiseAssert "arkham x64: address-of a foreign thread-local (module-system TODO): " & loc.name
    let base = g.borrowTmp(ScalarSlot)
    g.emGlobalAddr(base, TlsBlockName)                    # base ← &arkham.tls.0 (FS base)
    g.ab.tree LeaX64:                                     # dest ← base + tvar.offset = &tvar
      g.emReg dest
      g.emReg base
      g.ab.sym loc.name
    g.giveBack base
  of Mem:
    var nn = loc.cur
    if nn.kind == TagLit and nn.exprKind == DerefC:   # &(deref p) == p
      nn.into:
        g.genInto(nn, dest)
        while nn.hasMore: skip nn
    else:                                     # &(dot …)/&arr[idx] — re-emit the chain
      g.withMemOperand(loc):                   # nifasm computes base+offset (+ index scale)
        g.ab.tree LeaX64:
          g.emReg dest
          g.emAccessAddr(nn, regs, ri)         # `nn` (pass 2) re-walks the chain
  else: raiseAssert "arkham x64: emitAddrLoc on location kind " & $loc.kind

proc addrOfLoc(g: var CodeGen; loc: Location): (Reg, bool) =
  ## `&loc` in a register. A register-resident value already IS its address (a
  ## by-reference aggregate param) and is returned as-is; else borrow a temp.
  if loc.kind == InReg: return (loc.r, false)
  let r = g.borrowTmp(ScalarSlot)
  g.emitAddrLoc(loc, r)
  result = (r, true)

proc floatMemMov(g: var CodeGen; loc: Location; reg: FReg; bits: int; load: bool) =
  ## The one SIMD scalar memory move, both directions: `load` → `reg ← <loc>`; else
  ## `<loc> ← reg`. The float twin of `scalarMemMov`; floats occur only as InFReg /
  ## NamedStack / Mem (no Tvar/Glob), and the `Mem` arm is the mirror-image swap.
  case loc.kind
  of InFReg:
    if load: g.fmovF(reg, loc.f, bits) else: g.fmovF(loc.f, reg, bits)
  of NamedStack:
    if load: g.emFloatScalarLoad(reg, loc.name, bits)
    else:    g.emFloatScalarStore(loc.name, reg, bits)
  of Mem:
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.withMemOperand(loc):
      g.ab.tree op:
        if load: (g.emFReg reg; g.emMemOperandLoc(loc, regs, ri))
        else:    (g.emMemOperandLoc(loc, regs, ri); g.emFReg reg)
  else: raiseAssert "arkham x64: floatMemMov on location kind " & $loc.kind

proc emitLoadFLoc(g: var CodeGen; loc: Location; dest: FReg; bits: int) =
  ## `dest ← <float Location>`.
  g.floatMemMov(loc, dest, bits, load = true)

proc emitStoreFLoc(g: var CodeGen; loc: Location; src: FReg; bits: int) =
  ## `<float Location> ← src`.
  g.floatMemMov(loc, src, bits, load = false)

proc place(g: var CodeGen; v: Location; dest: Reg) =
  ## Materialize `v` into `dest`, releasing any owned scratch it occupied.
  case v.kind
  of Imm: g.movImm(dest, v.ival)
  of InReg:
    g.movReg(dest, v.r)
    if v.isTemp and v.r != dest: g.giveBack v.r
  of NamedStack, Mem: g.emitLoadLoc(v, dest)
  else: raiseAssert "arkham x64 v0: cannot place a value of kind " & $v.kind

proc forceReg(g: var CodeGen; dest: var Location) =
  ## Ensure `dest` is in a register, mutating it IN PLACE: an immediate / memory
  ## operand is loaded into a fresh borrowed temp (`isTemp = true`, so a later
  ## `freeTemp` releases it); a value already in a register keeps its location and
  ## its `isTemp` flag untouched. The temp-ness travels on the `Location` itself —
  ## no `(reg, owns)` tuple to thread back.
  case dest.kind
  of InReg: discard
  of Imm:
    let t = g.borrowTmp(dest.typ); g.movImm(t, dest.ival)
    dest = regLoc(t, dest.typ, isTemp = true)
  of NamedStack, Mem:
    let t = g.borrowTmp(dest.typ); g.emitLoadLoc(dest, t)   # precise type (e.g. a ptr field)
    dest = regLoc(t, dest.typ, isTemp = true)
  else: raiseAssert "arkham x64 v0: cannot force a value of kind " & $dest.kind & " into a register"

proc freeTemp(g: var CodeGen; loc: Location) {.inline.} =
  ## Release `loc`'s register iff it is a borrowed temp; a no-op on every persistent
  ## location (a register-resident local, a stack slot, an immediate, …) — like
  ## vmgen's `freeTemp`. The single release point replacing the old `if owns:
  ## giveBack`. Handles both GPR (`InReg`) and SIMD (`InFReg`) temps.
  if loc.isTemp:
    case loc.kind
    of InReg: g.giveBack loc.r
    of InFReg: g.giveBackF loc.f
    else: discard

const StagingCandidates = [RAX, RDI, RSI, RDX, RCX, R8, R9]

const FloatStagingCandidates = {F0, F1, F2, F3, F4, F5, F6, F7}
  ## The SIMD registers `pickFStaging` may hand out as a float spill's transient
  ## staging reg (xmm0–7 — disjoint from the xmm8–15 scratch pool). A `genIntoF`
  ## accumulator that lands in one of these (a float-arg-register target) is an
  ## in-flight value with no named-local binding, so it is added to `sealedF` for
  ## its lifetime — the SIMD analogue of `liveAccums` guarding a GPR accumulator.

proc releaseStaleName(g: var CodeGen; r: Reg) =
  ## A register about to be reused as raw scratch/staging must carry no stale
  ## named-local binding. A dead parameter often lingers in `regLocal` under its
  ## signature name `pN.0` (with its original type); `emReg` would then wrongly
  ## emit that typed name for the new value (e.g. `(mov p1.0 <ptr>)` where p1.0 is
  ## the i64 `start` param → nifasm strict-type mismatch). `(kill)` the binding and
  ## drop it so `emReg` falls back to the raw `(reg)` tag (untyped scratch).
  if r != NoReg and g.regLocal.hasKey(r):
    if not g.ab.planning: g.ab.tree KillX64: g.ab.sym g.regLocal[r]
    g.regLocal.del r

proc regHoldsLiveLocal(g: var CodeGen; r: Reg): bool =
  ## True if a local/param is currently allocated to register `r` (per the
  ## allocator's view). A *param* can sit in a caller-saved arg register (e.g.
  ## `p0.0` in rdi), so staging must not clobber it just because it's caller-saved.
  for name, pos in g.ra.symPos:
    let loc = g.ra.locs[pos]
    if loc.kind == InReg and loc.r == r: return true

# MODEL: the `pickStaging` action in proofs/arkham_bindings.tla — only ever returns a
# register with no live owner (the `Free` guard); staging on an occupied reg breaks
# NoSharedRegister. Change this ⇒ re-check that action.
proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## The first non-sealed caller-saved GPR that is not the scratch pool (r10/r11,
  ## exhausted by the time we get here), not a live local/param home (a param may
  ## live in its caller-saved arg register), not a live expression accumulator
  ## (`liveAccums` — e.g. rax holding the return value while a deep right operand
  ## spills), and not `avoid`. Clobbering it transiently is then safe; any stale
  ## (dead-param) name binding on it is released first so `emReg` emits the raw
  ## `(reg)` rather than the dead param's typed name. Returns `NoReg` when none is
  ## free (the genuinely-out-of-registers case). The scan order is fixed, so the
  ## plan and emit passes return the same register from the same state.
  for r in StagingCandidates:
    if r != avoid and not g.ra.isSealed(r) and r notin g.liveAccums and
       r notin g.boundTemps and not g.regHoldsLiveLocal(r):
      # `r notin boundTemps`: a register holding a live scratch temp (`bindTemp`'d)
      # must not be handed out as staging — that would clobber the temp's value.
      g.releaseStaleName(r)
      return r
  return NoReg

proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## A transient compute register for a spill (see `pickStagingScratch`).
  result = g.pickStagingScratch(avoid)
  if result == NoReg:
    raiseAssert "arkham x64: no staging register available for a spill"

proc regHoldsLiveFLoc(g: var CodeGen; f: FReg): bool =
  ## True if a float local/param currently lives in SIMD register `f` (per the
  ## allocator's view). A leaf-proc float param sits in its incoming arg register
  ## (xmm0–7), so the float staging pick must not clobber it.
  for name, pos in g.ra.symPos:
    let loc = g.ra.locs[pos]
    if loc.kind == InFReg and loc.f == f: return true

proc pickFStaging(g: var CodeGen; avoid: FReg = NoFReg): FReg =
  ## The float analogue of `pickStagingScratch`: the first SIMD arg register
  ## (xmm0–7) that is not the scratch pool (xmm8–15, exhausted by the time we get
  ## here), not an in-flight float arg / held staging reg (`sealedF`), not a live
  ## float local/param home, and not `avoid`. Clobbering it transiently is then
  ## safe. The scan order is fixed, so the plan and emit passes return the same
  ## register from the same state. `NoFReg` only when every xmm0–7 is occupied —
  ## the genuinely-out-of-float-registers case.
  for f in g.md.floatArgRegs:
    if f != avoid and f notin g.sealedF and not g.regHoldsLiveFLoc(f):
      return f
  return NoFReg

proc spillComputed(g: var CodeGen; c: var Cursor): Location =
  ## The scratch pool is exhausted: materialize `c`'s value into a fresh `(s)` slot
  ## via a transient staging register, and hand it back as a *foldable memory
  ## operand* (a `NamedStack` location) — which every value consumer (`binMem`/
  ## `place`/`forceReg`) already handles. This is what makes register allocation
  ## total: a deep
  ## expression spills instead of failing. The staging reg is sealed across the
  ## recursive eval so the inner walk can't clobber the value being built; that
  ## inner `genInto` is itself total (genBin's pool-exhausted path spills its left
  ## operand and reuses the staging reg as its own `dest` rather than consuming a
  ## fresh staging reg per level), so spill nesting no longer cascades and this
  ## path is reached only at isolated spill points (the divisor / the lighter
  ## operand of an SU swap), never recursively.
  let slotName = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let slot = g.exprSlot(c)                       # the value's PRECISE type/slot (incl. ptr pointee)
  # A POINTER needs its precise type end to end (the staging reg, the slot, and a later
  # deref are all strict ptr→ptr). An INTEGER lives 64-bit in a register — arkham
  # realizes its sub-word width via explicit extends, never by a narrowing `mov` — so
  # typing the staging reg `(i 32)` here would make the inner `genInto` emit a rejected
  # narrowing `(mov i32 i64)`. Keep integers at `(i 64)` (the sized mem↔reg rule still
  # truncates the store / extends the load). Mirrors genVarDecl's spilled-scalar branch.
  let isPtr = not cursorIsNil(slot.typ) and isPtrType(resolveType(g.prog, slot.typ))
  let regSlot = if isPtr: slot else: ScalarSlot
  let stage = g.pickStaging()
  g.ra.seal stage
  g.bindTemp(stage, regSlot)                     # checked name, ptr-precise / i64 for ints
  if isPtr: g.emTypedStackVar(slotName, slot.typ)         # (var :spill.N (s) (ptr …))
  else: g.emScalarStackVar(slotName)                      # (var :spill.N (s) (i 64))
  g.genInto(c, stage)                            # compute the value into the staging reg
  g.ab.tree MovX64:                              # store it to the slot
    g.emStackMem(slotName)
    g.emReg stage
  g.giveBack(stage)                              # unbind + unseal
  result = namedStackLoc(slotName, regSlot)


proc rebindLocalAs(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Re-establish register `r`'s binding to the named local `name`, retyped to
  ## `typeCur`, via a zero-machine-code `(rebind …)`. `rebind` auto-kills the transient
  ## tenant `r` currently carries, so no manual `kill` is needed. The scope already
  ## tracks `name` (declared by `emRegLocalVar`), so `scopeLocals` is NOT touched. Type
  ## emission mirrors `emRegLocalVar`: a pointer keeps its precise `(ptr …)`, every
  ## other scalar is the generic `(i 64)` register form.
  g.ab.tree RebindX64:
    g.ab.symDef name
    if isPtrType(resolveType(g.prog, typeCur)):
      var t = typeCur
      g.genTypeBody(t)
    else:
      g.ab.intType(64)
    g.ab.reg r
  g.regLocal[r] = name
  g.boundTemps.excl r

proc coerceThroughCast(g: var CodeGen; tc: Cursor; c: var Cursor; srcSlot: AsmSlot; dest: Reg) =
  ## Re-represent a coercion `(cast/conv tc <source at c>)` into `dest` — the ONE
  ## mechanism for every coercion whose source and target differ in representation
  ## (int↔ptr, ptr↔int, ptr↔ptr). arkham computes addresses as untyped values in GPRs
  ## while nifasm is strictly nominal, so the only real work is a *reinterpret* of
  ## `dest`'s bits from the SOURCE type to `tc` (plus a real zero-extend when a narrow
  ## int becomes a pointer). nifasm's `rebind` IS that reinterpret — a checked, named,
  ## zero-machine-code retype — so the value is computed straight into `dest` and its
  ## binding flipped across the cast, with NO runtime `mov`:
  ##   rebind dest → source type  (free) · genInto source → dest · rebind dest → tc (free)
  ## Consumes the source at `c`.
  ##
  ## In-place is unsafe only when the SOURCE reads `dest` — a pointer self-update
  ## `p = cast[ptr T](add … p …)` — because rebinding `dest` to the source type kills
  ## the very binding the source needs. `refsReg` is the same self-clobber check
  ## genBin's operand-swap uses. That (and a raw, unbound ABI accumulator, which must
  ## not be bound across a call in the source) falls back to a scratch register + a
  ## single `(cast tc s)` store.
  let destName = if g.regLocal.hasKey(dest): g.regLocal[dest] else: ""
  let isTemp = dest in g.boundTemps
  let isLocal = destName.len > 0 and not isTemp
  let selfRef = isLocal and g.refsReg(c, dest)
  if (isLocal or isTemp) and not selfRef:
    g.bindTemp(dest, srcSlot)                     # view dest as the SOURCE type (free)
    g.genInto(c, dest)                            # source value → dest, types match
    if isPtrType(tc) and srcSlot.kind in {AInt, AUInt} and srcSlot.size < 8:
      g.extendTo(dest, srcSlot.size * 8, signed = false)
    if isLocal: g.rebindLocalAs(destName, dest, tc)   # restore the named local, retyped (free)
    else: g.bindTemp(dest, slotOf(g.prog, tc))        # a temp: retype to the target (free)
  else:
    # Scratch path (a self-referential source that reads `dest`, or a raw unbound ABI
    # accumulator): compute the source into `s` (typed by the SOURCE), then a single
    # `(cast tc s)` store into `dest`. A named-local `dest` is already sealed by the
    # enclosing `genInto`, so the source cannot evict it — store straight to it.
    let s = g.borrowTmp(srcSlot)
    g.genInto(c, s)
    if isPtrType(tc) and srcSlot.kind in {AInt, AUInt} and srcSlot.size < 8:
      g.extendTo(s, srcSlot.size * 8, signed = false)
    var tcc = tc
    g.ab.tree MovX64:
      g.emReg dest
      g.ab.tree CastX:                              # the NIFC cast, preserved
        g.genTypeBody(tcc)
        g.emReg s
    g.giveBack s

proc genVal(g: var CodeGen; c: var Cursor): Location =
  ## The dont-care evaluator: produce `c`'s value wherever it naturally lives — a
  ## literal as an `Imm`, a register-resident local in place (`InReg`, not owned),
  ## a memory operand as a foldable `NamedStack`/`Mem` — materializing any
  ## *computed* value into a scratch register (`InReg`, owned), or (when the pool
  ## is exhausted) a spill slot. The counterpart of `gen(…, InReg dest)`.
  # A compile-time-constant expression collapses to one lazy `Imm` — never emitted,
  # folded into the consuming instruction (see `tryConstFold`).
  block:
    let (isConst, cv) = g.tryConstFold(c)
    if isConst:
      skip c
      return immLoc(cv, ScalarSlot)
  case c.kind
  of IntLit:
    result = immLoc(intVal(c), ScalarSlot); inc c
  of UIntLit:
    result = immLoc(cast[int64](uintVal(c)), ScalarSlot); inc c
  of CharLit:
    result = immLoc(int64(ord(charLit(c))), ScalarSlot); inc c
  of Symbol:
    let si = g.lookupSym(symName(c))
    if si.cat == scProc:                        # proc as a value → its code address
      let t = g.borrowTmp(ScalarSlot)
      g.ab.tree LeaX64: (g.emReg t; g.ab.sym si.asmName)
      inc c
      return regLoc(t, ScalarSlot, isTemp = true)
    let loc = g.asLoc(c)
    case loc.kind
    of InReg: result = regLoc(loc.r, loc.typ, isTemp = false)
    of NamedStack: result = loc                 # foldable spilled scalar in place
    of Glob, Tvar:                              # load through its address into a scratch
      let t = g.borrowTmp(loc.typ); g.emitLoadLoc(loc, t)   # precise type (e.g. a ptr global)
      result = regLoc(t, loc.typ, isTemp = true)
    else: raiseAssert "arkham x64 v0: operand of kind " & $loc.kind
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC:                       # a memory lvalue used as a value
      result = g.asLoc(c)                        # a foldable `Mem` operand
    of PatC:                                     # pointer indexing → eager element load
      let t = g.borrowTmp(ScalarSlot); g.genInto(c, t)
      result = regLoc(t, ScalarSlot, isTemp = true)
    of AddrC:                                    # &lvalue → a value of precise pointer type
      let slot = g.exprSlot(c)                    # (ptr <elem>), not a generic i64 scalar
      let t = g.borrowTmp(slot); g.genInto(c, t)
      result = regLoc(t, slot, isTemp = true)
    of NilC:                                      # nil → the immediate 0, foldable as `cmp ptr, 0`
      result = immLoc(0, ScalarSlot); skip c
    of CallC:                                     # call result → a temp typed by the navigated RETURN type
      let slot = g.exprSlot(c)                     # getType → callTarget.retType (e.g. a `(ptr T)`)
      let useSlot = if slot.kind == AMem: ScalarSlot else: slot   # aggregate returns go elsewhere
      let t = g.borrowTmp(useSlot); g.genInto(c, t)
      result = regLoc(t, useSlot, isTemp = true)
    of CastC, ConvC:
      # A cast/conv whose RESULT is a pointer must produce a precisely-ptr-typed value
      # (via the preserved NIFC cast — `coerceThroughCast`). A NON-pointer target delegates
      # to `genInto`→`genCoerce` below, which itself routes a pointer SOURCE through the
      # same helper, so ptr→int is handled there too.
      var probe = c; inc probe                    # peek the target type (do not consume c)
      if isPtrType(resolveType(g.prog, probe)):
        let slot = slotOf(g.prog, probe)          # (ptr T) slot — binds the result precisely
        let sPtr = g.borrowTmp(slot)
        c.into:
          var tcc = resolveType(g.prog, c); skip c   # render target; advance past the type
          g.coerceThroughCast(tcc, c, g.exprSlot(c), sPtr)
          while c.hasMore: skip c
        result = regLoc(sPtr, slot, isTemp = true)
      else:
        let t = g.tryBorrowTmp(ScalarSlot)
        if t == NoReg: result = g.spillComputed(c)
        else:
          g.genInto(c, t)
          result = regLoc(t, ScalarSlot, isTemp = true)
    else:
      let t = g.tryBorrowTmp(ScalarSlot)                  # a computed value → a scratch reg…
      if t == NoReg: result = g.spillComputed(c)  # …or a spill slot if exhausted
      else:
        g.genInto(c, t)
        result = regLoc(t, ScalarSlot, isTemp = true)
  else:
    let t = g.tryBorrowTmp(ScalarSlot)
    if t == NoReg: result = g.spillComputed(c)
    else:
      g.genInto(c, t)
      result = regLoc(t, ScalarSlot, isTemp = true)

proc gen(g: var CodeGen; c: var Cursor; dest: var Location) =
  ## The single value/destination entry point. `dest` says where `c`'s value must
  ## go; every value-producing call can route through here instead of picking one
  ## of `genInto` / `genIntoF` / `genVal` / a hand-rolled store by hand:
  ##   * `InReg` / `InFReg` → into that register (the int / float worker);
  ##   * `Undef` → the dont-care target: pick the cheapest home and write the
  ##     chosen `Location` back through `dest` (its `var`-out channel);
  ##   * `NamedStack` / `Mem` → store the computed value at that memory operand.
  ## `Imm`/`OnStack` are not destinations.
  case dest.kind
  of InReg: g.genInto(c, dest.r)
  of InFReg: g.genIntoF(c, dest.f, dest.typ.size * 8)
  of Undef: dest = g.genVal(c)
  of NeedsReg:
    # "must be a GPR, my choice": evaluate where the value naturally lives, then
    # ensure it occupies a register — a register-resident local stays in place (no
    # allocation, `isTemp = false`); an immediate / memory / computed value is
    # materialized into a borrowed scratch reg. The concrete `InReg` (carrying its
    # `isTemp` flag, so the caller knows whether to `freeTemp`) is written back.
    dest = g.genVal(c)
    g.forceReg(dest)
  of RegOrImm:
    # "a GPR or an immediate, not memory": an immediate / register-local stays as
    # is; a memory operand is loaded into a scratch reg (so it can be the source of
    # an `op [mem], b`). The concrete `Imm`/`InReg` is written back.
    dest = g.genVal(c)
    if dest.kind notin {Imm, InReg}: g.forceReg(dest)
  of NamedStack, Mem, Glob, Tvar:
    if dest.typ.isFloat:
      let bits = dest.typ.size * 8
      let f = g.borrowFTmp()
      g.genIntoF(c, f, bits)
      g.emitStoreFLoc(dest, f, bits)
      g.giveBackF f
    else:
      # A binary-arith rvalue routes through `genBin`, which runs the op in place
      # on the slot for an augmented assignment (`add [slot], b`) and otherwise
      # computes-in-register-then-stores. Everything else stores the value directly.
      let (op, immOk, isBin) = binArithOp(c)
      let destIsPtr = not cursorIsNil(dest.typ.typ) and isPtrType(dest.typ.typ)
      if isBin:
        g.genBin(c, dest, op, immOk)
      else:
        var v = g.genVal(c)
        if v.kind == Imm and destIsPtr:
          # nil / a literal into a POINTER slot: materialize through a ptr-typed
          # scratch so the store is ptr→ptr — `(mov rPtr 0)` adapts the literal to the
          # pointer (compatible(ptr,intlit)), then `(mov [slot] rPtr)` is strictly typed.
          let r = g.borrowTmp(dest.typ)
          g.movImm(r, v.ival)
          g.emitStoreLoc(dest, r)
          g.giveBack r
        else:
          g.forceReg(v)
          g.emitStoreLoc(dest, v.r)
          g.freeTemp(v)
  else: raiseAssert "arkham x64: gen() cannot target dest kind " & $dest.kind

proc commutativeOp(op: X64Inst): bool {.inline.} =
  ## Integer ops for which `a op b == b op a`, so Sethi–Ullman may evaluate the
  ## heavier operand first and fold the lighter one. (sub/shl/shr/div/mod are
  ## position-sensitive and stay in source order.)
  op in {AddX64, ImulX64, AndX64, OrX64, XorX64}

const SuCallWeight = 1000          # a call dominates demand → sorts first

proc suWeight(c: Cursor): int =
  ## Sethi–Ullman register label of the subtree at `c`: an estimate of how many
  ## registers evaluating it needs, used to decide which operand of a commutative
  ## op to evaluate first. Reads a *copy* of the cursor (never advances `c`). Only
  ## the integer arithmetic/logic tree is modeled precisely; memory loads and
  ## anything unmodeled count as leaves (weight 1); a call gets a large weight.
  var c = c
  if c.kind != TagLit:
    return 1                                   # IntLit / Symbol / StrLit leaf
  case c.exprKind
  of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC, DivC, ModC:
    var la = 1
    var lb = 1
    c.into:
      skip c                                   # result type
      la = suWeight(c); skip c                 # left
      lb = suWeight(c); skip c                 # right
    result = if la == lb: la + 1 else: max(la, lb)
  of NegC, BitnotC, ConvC, CastC:
    var w = 1
    c.into:
      skip c                                   # type child
      if c.hasMore: w = suWeight(c)
      while c.hasMore: skip c                  # operand (+ trailing tokens)
    result = max(w, 1)
  of NotC:                                     # boolean not has NO type child
    var w = 1
    c.into:
      if c.hasMore: w = suWeight(c)
      while c.hasMore: skip c
    result = max(w, 1)
  of CallC:
    result = SuCallWeight
  else:
    result = 1                                 # Dot/At/Deref/Addr/comparisons/…

proc hasCall(c: Cursor): bool =
  ## True if the subtree at `c` contains a call (atomics lower through the call
  ## path too). Reordering two *pure* operands is observation-preserving; a call
  ## anywhere disables the Sethi–Ullman swap. Reads a copy of the cursor.
  var c = c
  if c.kind != TagLit: return false
  if c.exprKind == CallC: return true
  result = false
  c.into:
    while c.hasMore:
      if not result and hasCall(c): result = true
      skip c

proc refsReg(g: var CodeGen; c: Cursor; r: Reg): bool =
  ## Does evaluating the subtree at `c` read register `r`? True when any symbol
  ## in it is register-resident with home `r`. Keeps the operand swap sound:
  ## evaluating the heavy operand into `dest` first must not clobber a register
  ## the light operand still needs. Reads a copy of the cursor.
  var c = c
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    return loc.kind == InReg and loc.r == r
  if c.kind != TagLit: return false
  result = false
  c.into:
    while c.hasMore:
      if not result and g.refsReg(c, r): result = true
      skip c

proc accessBaseSym(c: Cursor): string =
  ## The innermost base symbol of a `(dot|at|deref …)` access chain, or "".
  var n = c
  while n.kind == TagLit and n.exprKind in {DotC, AtC, DerefC}:
    inc n                                      # descend to the access's base
  result = if n.kind == Symbol: symName(n) else: ""

proc isComputedOperand(g: var CodeGen; c: Cursor): bool =
  ## Mirrors `genVal`: the operand kinds it materializes into a fresh register
  ## (and would spill on pool exhaustion), as opposed to those it reads in place
  ## (literal, register/stack local, memory lvalue). genBin intercepts these so a
  ## deep right operand spills without pinning `dest`.
  case c.kind
  of IntLit, UIntLit, CharLit, Symbol: result = false
  of TagLit:
    if c.exprKind in {DotC, AtC, DerefC}:
      # A stack/pointer access folds in place (rsp- or register-relative), but a
      # *global*-based access needs its address `lea`'d into a register first —
      # not free under pressure. Treat it as computed so genBin frees `dest` via
      # the spill path before materializing it.
      let b = accessBaseSym(c)
      result = b.len > 0 and g.lookupSym(b).cat == scGlobal
    else:
      result = true
  else: result = true

proc emitShiftByReg(g: var CodeGen; op: X64Inst; dest, count: Reg) =
  ## `dest = dest <shift> count` — x86 mandates the shift count in CL. Move it into RCX
  ## (a checked name via `bindTemp`), then `op dest, cl`. RCX may hold a live param in a
  ## leaf proc, so evict it first; `dest` is the value being shifted (never RCX here).
  ## Shared by the normal combine and the pool-exhausted `spillOperandAround` path.
  if count == RCX:
    g.ab.tree op: (g.emReg dest; g.emReg RCX)    # already in CL (its name is RCX-bound)
    return
  g.evictFixedReg(RCX)
  g.movReg(RCX, count)
  g.bindTemp(RCX, ScalarSlot)
  g.ab.tree op: (g.emReg dest; g.emReg RCX)
  g.unbindTemp(RCX)

proc spillOperandAround(g: var CodeGen; c: var Cursor; dest: Reg; op: X64Inst) =
  ## Pool-exhausted evaluation of genBin's right operand that keeps register
  ## allocation TOTAL. The left operand is already in `dest`; spill it to a fresh
  ## slot so `dest` is free, evaluate the (possibly deep) right operand into `dest`
  ## — the recursion reuses `dest`, never pinning a register per nesting level —
  ## then reassemble `dest = a op b` with a single transient staging reg taken only
  ## here, after the recursion has fully unwound (so it never nests → one reg covers
  ## any depth). Evaluation order a-before-b is preserved (correct for impure
  ## operands too). `c` is consumed past the right operand.
  let slotA = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let slotLoc = namedStackLoc(slotA, AsmSlot(cls: AInt, size: 8, align: 8))
  g.emScalarStackVar(slotA)
  g.ab.tree MovX64:                            # store a → slotA (free dest)
    g.emStackMem(slotA)
    g.emReg dest
  g.genInto(c, dest)                           # b → dest (recursion reuses dest)
  let s = g.pickStaging(avoid = dest)          # transient; recursion done → never nests
  g.bindTemp(s, ScalarSlot)                    # checked name for `b` while it is live
  g.movReg(s, dest)                            # s = b
  g.emitLoadLoc(slotLoc, dest)                 # dest = a (reload)
  if op in {ShlX64, ShrX64, SarX64, SalX64}:
    g.emitShiftByReg(op, dest, s)              # variable shift: count must reach CL
  else:
    g.binReg(op, dest, s)                      # dest = a op b
  g.unbindTemp(s)

proc genBinReg(g: var CodeGen; c: var Cursor; dest: Reg; op: X64Inst; immOk: bool) =
  ## `dest = a op b` into a REGISTER accumulator, x86's destructive form: `a` into
  ## `dest`, then `dest op= b`, with `b` folded as an immediate / memory / register
  ## operand. (The memory-destination in-place case lives in `genBin`.)
  ## For a commutative op whose RIGHT operand needs strictly more registers than
  ## the left (Sethi–Ullman), the operands are swapped: the heavier one is
  ## evaluated into `dest` first and the lighter folded after — so a right-nested
  ## chain like `1+(2+(4+…))` collapses into `dest` with no scratch temp (and
  ## therefore never spills). The swap is taken only when both operands are pure
  ## (no call, so reordering is observation-preserving) and the light operand does
  ## not read `dest` (which the heavy evaluation overwrites first). If instead `b`
  ## lives in `dest`, it is saved before `a` overwrites it.
  ##
  ## When `b` is a computed operand that must occupy a register and the scratch
  ## pool is exhausted, `spillOperandAround` takes over: it spills the just-computed
  ## `a` (in `dest`) to a slot, evaluates `b` into the freed `dest`, and reassembles
  ## — so even a deep NON-commutative right-nest (`a-(b-(c-…))`, which SU can't
  ## reorder) allocates with O(1) live registers and O(depth) slots instead of
  ## asserting. Register allocation is total.
  # `dest` accumulates the result across both operand evaluations; seal it so a
  # scratch steal during the right operand can't evict it (if `dest` is a
  # register-local). A scratch `dest` is not a steal candidate anyway, so this
  # only matters — and is only ever a no-op otherwise — for local-reg targets.
  let destWasSealed = g.ra.isSealed(dest)
  g.ra.seal dest
  defer:
    if not destWasSealed: g.ra.unseal {dest}
  c.into:
    skip c                                    # result type; c at a
    var aPeek = c
    var bPeek = c; skip bPeek                  # bPeek at b
    var other: Location                       # the operand folded into dest last
    var combined = false                      # the spill path emits its own combine
    if commutativeOp(op) and suWeight(bPeek) > suWeight(aPeek) and
       not hasCall(aPeek) and not hasCall(bPeek) and not g.refsReg(aPeek, dest):
      g.genInto(bPeek, dest)                   # heavier operand (b) → dest first
      other = g.genVal(c)                      # lighter operand (a) folded after
      skip c                                   # consume b in the real cursor
    elif g.operandInReg(bPeek, dest):
      let saved = g.borrowTmp(ScalarSlot)
      g.movReg(saved, dest)                   # preserve b before `a` clobbers dest
      g.genInto(c, dest)                      # a → dest
      skip c                                  # consume b
      other = regLoc(saved, ScalarSlot, isTemp = true)
    else:
      g.genInto(c, dest)                      # a → dest; c now at b
      if g.isComputedOperand(c):              # b must be materialized into a register
        let t = g.tryBorrowTmp(ScalarSlot)
        if t == NoReg:                         # pool exhausted → total spill path
          g.spillOperandAround(c, dest, op)
          combined = true
        else:
          g.genInto(c, t)                      # b → scratch temp
          other = regLoc(t, ScalarSlot, isTemp = true)
      else:
        other = g.genVal(c)                    # b is a leaf / memory / in-place value
    if not combined:
      if immOk and other.kind == Imm and other.ival >= 0 and other.ival <= 0xFFFF:
        g.binImm(op, dest, other.ival)
      elif op in {ShlX64, ShrX64, SarX64, SalX64}:
        g.forceReg(other)                       # x86 variable shift → count must reach CL
        g.emitShiftByReg(op, dest, other.r)
        g.freeTemp(other)
      elif other.kind in {NamedStack, Mem}:
        g.binMem(op, dest, other)             # fold the memory operand: op dest, [mem]
      else:
        g.forceReg(other)
        g.binReg(op, dest, other.r)
        g.freeTemp(other)

# Ops with a memory-DESTINATION encoding (`op [mem], reg/imm`): x86 has these for
# add/sub/and/or/xor, but NOT imul or the shifts (they require a register dest).
const MemDestOps = {AddX64, SubX64, AndX64, OrX64, XorX64}

proc augmentedSlot(g: var CodeGen; c: Cursor; dest: Location): bool =
  ## `(op TYPE a b)` where `dest` is the stack slot of a local and `a` is that same
  ## local — an augmented assignment `x = x op b`. `[dest]` then already holds `a`,
  ## so the op can run in place (`op [dest], b`) with no reload/store of `a`. Limited
  ## to a `NamedStack` slot whose name matches the symbol `a` (a register-resident
  ## local needs no memory dest; a `Mem` access chain is not compared here).
  if dest.kind != NamedStack: return false
  var cc = c
  inc cc                                          # descend past the op tag → at TYPE
  skip cc                                         # → at a
  result = cc.kind == Symbol and symName(cc) == dest.name

proc genBin(g: var CodeGen; c: var Cursor; destLoc: var Location; op: X64Inst; immOk: bool) =
  ## `dest = a op b` with a flexible destination. A register (or `NeedsReg`) dest
  ## routes to the register accumulator `genBinReg`. A *memory* dest takes the
  ## in-place path for an augmented assignment `x = x op b` (`op [slot], b`, with
  ## `b` a register-or-immediate so x86's one-memory-operand rule holds); any other
  ## memory dest falls back to computing in a register and storing — identical to
  ## the previous `gen()` memory path.
  if destLoc.kind in {NamedStack, Mem, Glob, Tvar}:
    if op in MemDestOps and g.augmentedSlot(c, destLoc):
      c.into:
        skip c                                    # TYPE
        skip c                                    # a (== dest; already in [dest])
        var b = regOrImm(ScalarSlot)
        g.gen(c, b)                               # b → register or immediate
        if b.kind == Imm and b.ival >= low(int32) and b.ival <= high(int32):
          g.binMemImm(op, destLoc, b.ival)        # op [slot], imm
        else:
          g.forceReg(b)                           # large imm / register source
          g.binMemReg(op, destLoc, b.r)           # op [slot], reg
          g.freeTemp(b)
    else:                                          # compute in a register, then store
      var v = g.genVal(c)
      g.forceReg(v)
      g.emitStoreLoc(destLoc, v.r)
      g.freeTemp(v)
    return
  let dest = g.wantReg(destLoc)
  g.genBinReg(c, dest, op, immOk)

proc materializeCond(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## A comparison/logic used as a 0/1 value: assume true, jump over the reset.
  let lEnd = g.freshLabel()
  g.movImm(dest, 1)
  g.emitCondJump(c, lEnd, whenTrue = true)
  g.movImm(dest, 0)
  g.emLab(lEnd)

proc genDivMod(g: var CodeGen; c: var Cursor; dest: Reg; signed, wantRemainder: bool) =
  ## x86 division: dividend in RAX, divisor in a register; quotient → RAX,
  ## remainder → RDX. nifasm's `(idiv|div (rdx)(rax) src)` emits the cqo / xor-rdx
  ## itself. RAX/RDX are never live locals (not in the allocator's pool), so
  ## clobbering them is safe; the divisor lives in a borrowed temp (idiv has no
  ## immediate form). RAX is never a local home, but RDX is an ABI arg register, so
  ## in a leaf proc it may hold a live parameter — evict it before `cqo`/idiv writes
  ## RDX. (A no-op once nothing live remains there: a second div sees RDX free.)
  g.evictFixedReg(RDX)
  c.into:
    skip c                                    # result type
    g.genInto(c, RAX)                          # dividend → rax
    g.ra.seal RAX                              # protect it while materializing the divisor
    var divisor = needsReg(ScalarSlot)         # "a register, your choice" for the divisor
    g.gen(c, divisor)                          # divisor → that register (idiv has no imm form)
    g.ra.unseal {RAX}
    let op = if signed: IdivX64 else: DivX64
    # The divisor is a checked name either way now — a register-local via its own
    # binding, a borrowed temp via `bindTemp`'s `(rebind …)`. `emReg` emits that name,
    # so the idiv operand is never a raw `(reg)`.
    g.ab.tree op:
      g.ab.reg RDX                             # (rdx): high half of the dividend
      g.ab.reg RAX                             # (rax): low half
      g.emReg divisor.r                        # divisor, by its bound name
    g.freeTemp(divisor)
  g.movReg(dest, if wantRemainder: RDX else: RAX)

# ── floating-point expressions (single + double precision) ──────────────────
# `bits` (32/64) is the value's precision, threaded top-down: it selects movss vs
# movsd / addss vs addsd, etc. A bare literal has no inherent width, so it adopts
# the contextual `bits`.

proc genFReg(g: var CodeGen; c: var Cursor; bits: int): Location =
  ## A float operand in an xmm register, returned as an `InFReg` `Location`: a float
  ## local stays in place (`isTemp = false`), anything else is materialized into a
  ## borrowed SIMD temp (`isTemp = true`) the caller releases with `freeTemp`. `.f`
  ## is the register.
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InFReg:
      inc c
      return fregLoc(loc.f, loc.typ)
  let f = g.borrowFTmp()
  g.genIntoF(c, f, bits)
  result = fregLoc(f, AsmSlot(cls: AFloat, size: bits div 8, align: bits div 8), isTemp = true)

proc spillFOperandAround(g: var CodeGen; c: var Cursor; dest: FReg;
                         op32, op64: X64Inst; bits: int) =
  ## Pool-exhausted evaluation of genFBin's right operand, keeping float register
  ## allocation TOTAL — the SIMD mirror of `spillOperandAround`. `a` is already in
  ## `dest`; spill it to a fresh `(s) (f N)` slot so `dest` is free, evaluate the
  ## (possibly deep) right operand into `dest` — the recursion reuses `dest`, never
  ## pinning a SIMD temp per nesting level — then reassemble `dest = a op b` with a
  ## single transient staging xmm (xmm0–7) taken only here, after the recursion has
  ## fully unwound (so it never nests → one reg covers any depth). Operand order
  ## a-before-b is preserved, and `a op b` is computed (not `b op a`), so this is
  ## correct for the non-commutative `sub`/`div` too. `c` is consumed past `b`.
  let slotA = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  g.emFloatStackVar(slotA, bits)               # (var :spill.N (s) (f N))
  g.emFloatScalarStore(slotA, dest, bits)      # [slotA] = a  (free dest)
  g.genIntoF(c, dest, bits)                     # b → dest (recursion reuses dest)
  let s = g.pickFStaging(avoid = dest)          # transient; recursion done → never nests
  if s == NoFReg:
    raiseAssert "arkham x64: no SIMD staging register available for a float spill"
  g.emFloatScalarLoad(s, slotA, bits)           # s = a (reload)
  g.fbin(op32, op64, s, dest, bits)             # s = a op b   (correct operand order)
  g.fmovF(dest, s, bits)                        # dest = a op b

proc genFBin(g: var CodeGen; c: var Cursor; dest: FReg; op32, op64: X64Inst; bits: int) =
  ## `(op (f N) a b)` → `dest = a op b` (addss/sd, subss/sd, mulss/sd, divss/sd).
  ## `a` goes into `dest`; `b` is folded in place (a float local), evaluated into a
  ## borrowed SIMD temp, or — when the scratch pool is exhausted — spilled via
  ## `spillFOperandAround`, which keeps allocation total for arbitrarily deep
  ## right-nested float expressions (the SIMD analogue of `genBinReg`).
  c.into:
    skip c                                    # result float type
    g.genIntoF(c, dest, bits)                  # a → dest
    var inPlace = NoFReg                        # b an in-place float local? fold directly
    if c.kind == Symbol:
      let loc = g.ra.locationOfSym(symName(c))
      if loc.kind == InFReg: inPlace = loc.f
    if inPlace != NoFReg:
      g.fbin(op32, op64, dest, inPlace, bits)
      inc c                                    # consume b
    else:
      let fr = g.tryBorrowFTmp()               # b → a SIMD scratch temp …
      if fr == NoFReg:
        g.spillFOperandAround(c, dest, op32, op64, bits)   # … or spill (total)
      else:
        g.genIntoF(c, fr, bits)
        g.fbin(op32, op64, dest, fr, bits)
        g.giveBackF fr

proc genConvToF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## `(conv (f N) Expr)` — int→float (cvtsi2ss/sd) or float→float (cvt precision).
  c.into:
    skip c                                    # target float type
    if g.isFloatExpr(c):
      let srcBits = g.floatBits(c)
      if srcBits == bits:
        g.genIntoF(c, dest, bits)              # same precision: copy
      else:
        let sf = g.genFReg(c, srcBits)
        g.emFcvt(dest, sf.f, bits, srcBits)    # precision convert
        g.freeTemp(sf)
    else:
      let (srcW, srcSigned) = g.srcWidthSigned(c)
      let tmp = g.borrowTmp(ScalarSlot)
      g.genInto(c, tmp)                          # int value → GPR
      g.extendTo(tmp, srcW, srcSigned)           # normalize to its full int value
      g.fcvtI2F(dest, tmp, bits)                 # cvtsi2ss/sd (signed; u64 edge: TODO)
      g.giveBack tmp
    while c.hasMore: skip c

proc genCastToF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## `(cast (f N) Expr)` — reinterpret an integer's bits as a float (or copy a
  ## same-precision float unchanged).
  c.into:
    skip c                                    # target float type
    if g.isFloatExpr(c):
      g.genIntoF(c, dest, bits)
    else:
      let tmp = g.borrowTmp(ScalarSlot)
      g.genInto(c, tmp)                          # integer bit pattern → GPR
      g.fmovFromGpr(dest, tmp, bits)             # reinterpret as float
      g.giveBack tmp
    while c.hasMore: skip c

proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## Evaluate a `bits`-wide float expression into the SIMD register `dest`.
  # While `dest` holds the value being built, a deep sub-operand may exhaust the
  # SIMD scratch pool and spill — its transient `pickFStaging` register must not
  # clobber `dest`. The xmm8–15 pool is never a staging candidate, but an xmm0–7
  # accumulator (a float-arg-register target) IS and is no named local, so record
  # it in `sealedF` for the duration. Save/restore via the `protect` flag so a
  # nested `genIntoF` into the same reg keeps it protected exactly once.
  let protect = dest in FloatStagingCandidates and dest notin g.sealedF
  if protect: g.sealedF.incl dest
  defer:
    if protect: g.sealedF.excl dest
  case c.kind
  of FloatLit:
    let tmp = g.borrowTmp(ScalarSlot)                     # materialize the bit pattern via a GPR
    if bits == 32:
      g.movImm(tmp, int64(cast[uint32](float32(floatVal(c)))))
    else:
      g.movImm(tmp, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest, tmp, bits)
    g.giveBack tmp
    inc c
  of Symbol:
    let loc = g.asLoc(c)
    g.emitLoadFLoc(loc, dest, bits)
  of TagLit:
    case c.exprKind
    of AddC: g.genFBin(c, dest, AddssX64, AddsdX64, bits)
    of SubC: g.genFBin(c, dest, SubssX64, SubsdX64, bits)
    of MulC: g.genFBin(c, dest, MulssX64, MulsdX64, bits)
    of DivC: g.genFBin(c, dest, DivssX64, DivsdX64, bits)
    of NegC:
      # No scalar SSE negate; flip the sign bit by subtracting from +0.0.
      c.into:
        skip c                                # result type
        let sf = g.genFReg(c, bits)
        let zero = g.borrowFTmp()
        let z = g.borrowTmp(ScalarSlot); g.movImm(z, 0)
        g.fmovFromGpr(zero, z, bits); g.giveBack z   # zero ← +0.0
        g.fbin(SubssX64, SubsdX64, zero, sf.f, bits) # 0 - x
        g.fmovF(dest, zero, bits)
        g.giveBackF zero
        g.freeTemp(sf)
        while c.hasMore: skip c
    of ConvC: g.genConvToF(c, dest, bits)
    of CastC: g.genCastToF(c, dest, bits)
    of CallC:
      g.genCall(c)                            # float result lands in xmm0 …
      g.fmovF(dest, FloatRet, bits)           # … move it to the destination
    of DotC, AtC, DerefC:                      # float field / element / deref: dest ← [mem]
      let loc = g.asLoc(c); g.emitLoadFLoc(loc, dest, bits)
    else: raiseAssert "arkham x64 v0: float expression not supported: " & $c.exprKind
  else:
    raiseAssert "arkham x64 v0: float operand not supported: " & $c.kind

proc genCoerce(g: var CodeGen; c: var Cursor; dest: Reg; isCast: bool) =
  ## `(conv Type Expr)` / `(cast Type Expr)`: evaluate `Expr` into `dest`, then
  ## re-represent it in `Type`'s 64-bit register form. Widening extends from the
  ## *source* width (conv follows the source signedness; cast zero-extends the
  ## bits); narrowing/equal truncates to the target width and extends per the
  ## *target*; an int→ptr target zero-extends a narrower source. Integer/char/
  ## bool/pointer only (no floats in x64 v0).
  c.into:
    let tc = resolveType(g.prog, c)           # resolve named types / enums
    let targetSigned = isSignedType(tc)
    let targetW = intTypeWidth(tc)
    let targetPtr = isPtrType(tc)
    skip c                                    # target type
    # NB: NONE of the branches below may `return` from inside this `c.into` block — a
    # mid-block return skips the template's outer-`rem` restoration, corrupting the
    # caller's cursor (it happens to be tolerable at statement position, but a cast at
    # OPERAND position — e.g. `(add (cast (u 64) p) k)` — then overruns). Every path
    # falls through to the single trailing `while c.hasMore: skip c`.
    let srcSlot2 = g.exprSlot(c)
    let srcIsPtr = not cursorIsNil(srcSlot2.typ) and isPtrType(resolveType(g.prog, srcSlot2.typ))
    if g.isFloatExpr(c):
      # float source → integer/pointer target (`dest` is a GPR).
      let fbits = g.floatBits(c)
      let sf = g.genFReg(c, fbits)
      if isCast:
        g.fmovToGpr(dest, sf.f, fbits)        # reinterpret the float's bits
      else:
        g.fcvtF2I(dest, sf.f, fbits)          # cvtt* (truncate toward zero)
        if targetW < 64 and not targetPtr:
          g.extendTo(dest, targetW, signed = targetSigned)
      g.freeTemp(sf)
    elif targetPtr or srcIsPtr:
      # Any coercion that crosses representations — int→ptr (NIFC encodes Nim pointer
      # arithmetic as `(cast ptr (add (u 64) …))`), ptr→int (`(sub (cast (u 64) p) k)`),
      # or ptr→ptr (different pointee) — reinterprets through the preserved NIFC cast.
      # One branch for every pointer direction; `coerceThroughCast` is the mechanism.
      g.coerceThroughCast(tc, c, srcSlot2, dest)
      if not targetPtr and targetW < 64:           # ptr→narrow int: extend the result
        g.extendTo(dest, targetW, signed = targetSigned)
    else:
      let (srcW, srcSigned) = g.srcWidthSigned(c)
      g.genInto(c, dest)                        # value → dest
      if targetPtr:
        if srcW < 64: g.extendTo(dest, srcW, signed = false)   # int→ptr: zero-extend
      elif srcW < targetW:                      # widening int→int
        g.extendTo(dest, srcW, signed = (not isCast) and srcSigned)
      else:                                     # narrowing or equal width
        g.extendTo(dest, targetW, signed = targetSigned)
    while c.hasMore: skip c

proc emitPatAddr(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `dest ← &(pat base idx)` — pointer indexing. Unlike `dot`/`at`/`deref` (whose
  ## bases fold into a single nifasm memory operand), a `pat` base is a pointer
  ## *value* that must live in a register: an array/flexarray field decays to its
  ## address, a real pointer is loaded. Base (and a non-immediate index) are
  ## materialized into registers *before* the `lea` opens, so no helper instruction
  ## lands inside its operand tree; the `lea dest, (at (cast (aptr elem) base) idx)`
  ## then lets nifasm stride the index by the element size.
  c.into:
    let baseTyC = g.getType(c)
    let baseTy = resolveType(g.prog, baseTyC)
    var elem = innerType(g.prog, baseTy)
    let isArr = baseTy.typeKind in {NifcType.ArrayT, NifcType.FlexarrayT}
    # A real pointer base now lives in a precisely-typed slot (see genVarDecl), so the
    # base reg must match it on load: type it by the base's own pointer type. An
    # array/flexarray decays to its address via `lea` (lenient), so a generic slot is
    # fine there.
    let baseReg = g.borrowTmp(if isArr: ScalarSlot else: slotOf(g.prog, baseTyC))
    if isArr:
      var bd = regLoc(baseReg, ScalarSlot)      # decay into the pre-borrowed base reg
      g.genAddr(c, bd)                           # baseReg ← &field
    else:
      g.genInto(c, baseReg)                     # baseReg ← the pointer value
    var idxImm = false
    var idxV = 0'i64
    var idxReg = NoReg
    if c.kind == IntLit: (idxImm = true; idxV = intVal(c); inc c)
    elif c.kind == UIntLit: (idxImm = true; idxV = cast[int64](uintVal(c)); inc c)
    else: (idxReg = g.borrowTmp(ScalarSlot); g.genInto(c, idxReg))
    g.ab.tree LeaX64:
      g.emReg dest
      g.ab.tree AtX:
        g.ab.tree CastX:
          g.ab.aptrType:
            if elem.kind == Symbol: g.ab.sym symName(elem)
            else: g.genTypeBody(elem)
          g.emReg baseReg
        if idxImm: g.ab.intLit idxV
        else: g.emReg idxReg
    if idxReg != NoReg: g.giveBack idxReg
    g.giveBack baseReg
    while c.hasMore: skip c

# MODEL: the init-home seal in proofs/arkham_bindings.tla (`beginInit` seals the home;
# ValueConsistency). The `sealHome` below protects a register-local home while its own
# value is built — without it a steal evicts the home and the write lands in a stale reg.
proc genInto(g: var CodeGen; c: var Cursor; dest: Reg) =
  # A compile-time-constant expression is a single `mov dest, imm` — fold it here
  # (before any seal/accumulator bookkeeping, so the early return needs no cleanup)
  # rather than walking the tree into runtime arithmetic (see `tryConstFold`).
  block:
    let (isConst, cv) = g.tryConstFold(c)
    if isConst:
      g.movImm(dest, cv); skip c; return
  # While `dest` holds the value being built, a deep sub-operand may exhaust the
  # scratch pool and spill — its transient staging register must not clobber
  # `dest`. The scratch pool (r10/r11) is never a staging candidate, but a caller-
  # saved accumulator (rax = the return value, or a call-argument register) IS, and
  # is no named local — so record it as a live accumulator for the duration.
  # Save/restore (not unconditional excl) so a nested `genInto` into the same reg
  # (SU swap / operandInReg) keeps it protected.
  let protect = dest in StagingCandidates and dest notin g.liveAccums
  if protect: g.liveAccums.incl dest
  # Protect a register-local *home* (a callee-saved RBX/R12–R15) from a codegen-time
  # *steal* during the build of its own value: the result lands in `dest`, so an
  # initializer/rvalue whose scratch demand evicts `dest` mid-build would make the
  # final write target a stale, evicted register. `liveAccums` only guards arg/return
  # regs; `stealReg` can still evict a callee-saved home, so seal it here. Save/restore
  # so a nested `genInto` into the same reg keeps it sealed.
  let sealHome = g.regLocal.hasKey(dest) and not g.ra.isSealed(dest)
  if sealHome: g.ra.seal dest
  case c.kind
  of IntLit, UIntLit, CharLit:
    g.place(g.genVal(c), dest)               # literal → immediate
  of Symbol:
    # A symbol's value loads straight into `dest`: `emitLoadLoc` reuses `dest` as
    # the address scratch for a global/tvar, so this needs NO extra scratch register
    # (unlike routing through `genVal`, which borrows a fresh temp). That keeps a
    # struct copy whose source is `(deref globalPtr)` total when both scratch
    # registers already hold the copy's dest/src addresses.
    let si = g.lookupSym(symName(c))
    if si.cat == scProc:
      g.place(g.genVal(c), dest)             # a proc value is its code address (lea)
    else:
      g.emitLoadLoc(g.asLoc(c), dest)
  of StrLit:                                 # string literal → rodata + RIP-relative lea
    let nm = "msg." & $g.rodata.len
    if not g.ab.planning: g.rodata.add (nm, strVal(c))   # plan pass emits no rodata
    inc c
    g.ab.tree LeaX64:
      g.emReg dest
      g.ab.sym nm                            # `(lea dest msg.N)` → nifasm RIP-relative
  of TagLit:
    # The binary-op arms hand `genBin` a flexible destination; for `genInto` it is
    # always the fixed target register `dest`, wrapped here as an `InReg` constraint.
    var bd = regLoc(dest, ScalarSlot)
    case c.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (op, immOk, _) = binArithOp(c)      # one opcode table (shared with gen())
      g.genBin(c, bd, op, immOk)
    of DivC, ModC:
      let wantRemainder = c.exprKind == ModC
      var tc = c; inc tc                      # the result-type child
      g.genDivMod(c, dest, signed = isSignedType(tc), wantRemainder = wantRemainder)
    of NegC:
      c.into:
        skip c                                # type
        g.genInto(c, dest)
        g.ab.tree NegX64: g.emReg dest
    of BitnotC:
      c.into:
        skip c                                # type
        g.genInto(c, dest)
        g.ab.tree NotX64: g.emReg dest        # x86 has a real `not`
    of NotC:                                  # boolean not: a ∈ {0,1} → a xor 1
      c.into:
        g.genInto(c, dest)
        g.binImm(XorX64, dest, 1)
    of EqC, NeqC, LtC, LeC, AndC, OrC:
      g.materializeCond(c, dest)
    of ConvC: g.genCoerce(c, dest, isCast = false)
    of CastC: g.genCoerce(c, dest, isCast = true)
    of DotC, AtC, DerefC:                     # field / element / pointer load: dest ← [mem]
      g.place(g.genVal(c), dest)
    of PatC:                                  # pointer index: &elem into dest, then load in place
      # Peek the element type BEFORE emitPatAddr consumes the cursor. A SUB-WORD
      # scalar element (char / u8 / u16 / u32 / bool) must be loaded at its own
      # width: a plain `(mem dest)` is sized by dest's 8-byte slot and OVER-READS
      # (e.g. `s[0]` on an SSO string returned the 8 packed bytes, not the char).
      # Wrap the deref in `(cast (ptr elem) dest)` so nifasm emits the right
      # movzx/movsx. A 64-bit / pointer element keeps the plain 8-byte deref.
      var probe = c
      inc probe                                 # step to the base (do not consume c)
      let elem = innerType(g.prog, resolveType(g.prog, g.getType(probe)))
      let eslot = slotOf(g.prog, elem)
      g.emitPatAddr(c, dest)
      if eslot.kind in {AInt, AUInt, ABool} and eslot.size < 8:
        g.ab.tree MovX64:
          g.emReg dest
          g.ab.tree MemX:
            g.ab.tree CastX:
              g.ab.ptrType:
                if elem.kind == Symbol: g.ab.sym symName(elem)
                else: (var et = elem; g.genTypeBody(et))
              g.emReg dest
      else:
        g.ab.tree MovX64: (g.emReg dest; g.ab.tree MemX: g.emReg dest)
    of AddrC:                                 # (addr lvalue) → dest ← &lvalue
      c.into:
        var ad = regLoc(dest, ScalarSlot)     # into the fixed genInto target
        g.genAddr(c, ad)
        while c.hasMore: skip c               # (cppref)?
    of CallC:
      g.genCall(c)
      g.movReg(dest, RAX)
    of TrueC: g.movImm(dest, 1); skip c       # boolean / nil literals → immediate
    of FalseC: g.movImm(dest, 0); skip c
    of NilC: g.movImm(dest, 0); skip c
    of SufC, ParC:                            # `(suf v "type")` / `(par v)` wrap one value
      c.into:
        g.genInto(c, dest)
        while c.hasMore: skip c                # the type suffix / trailing tokens
    of SizeofC:                               # compile-time constant: the type's byte size
      c.into:
        g.movImm(dest, typeSizeAlign(g.prog, c)[0].int64)
        while c.hasMore: skip c
    else: raiseAssert "arkham x64 v0: expression not supported: " & $c.exprKind
  else: raiseAssert "arkham x64 v0: operand not supported: " & $c.kind
  if sealHome: g.ra.unseal {dest}
  if protect: g.liveAccums.excl dest

proc genAddr(g: var CodeGen; c: var Cursor; dest: var Location) =
  ## `dest ← &lvalue`. Parse the addressing mode once, then form the address into
  ## the destination register (`dest` may be a fixed `InReg` or a flexible
  ## `NeedsReg` the op resolves and writes back). `pat` (pointer indexing) can't
  ## fold into a single memory operand — its base pointer needs a register — so it
  ## is formed eagerly by `emitPatAddr`.
  let r = g.wantReg(dest)
  if c.kind == TagLit and c.exprKind == PatC:
    g.emitPatAddr(c, r)
  else:
    let loc = g.asLoc(c)
    g.emitAddrLoc(loc, r)

# ── conditions / branches ────────────────────────────────────────────────────

proc cmpOperandUnsigned(g: var CodeGen; c: Cursor): bool =
  ## Does comparison/`case` operand `c` carry an unsigned (or char) type? This
  ## drives the unsigned-vs-signed condition code. A bare signed literal is
  ## ambiguous (→ false, let the other operand decide); a `UIntLit`/`CharLit` is
  ## unsigned; every other operand is typed through `getType` — so unsigned
  ## *fields*, array elements, derefs, casts, computed expressions, and an unsigned
  ## symbol in *either* operand position are all detected, not just a bare unsigned
  ## symbol in the first position (the old check missed all of these → a wrong
  ## signed compare, e.g. `5 < UINT64_MAX` computed as `5 < -1`).
  case c.kind
  of UIntLit, CharLit: result = true
  of IntLit: result = false
  else: result = not isSignedType(resolveType(g.prog, g.getType(c)))

proc cmpJccTag(ek: NifcExpr; whenTrue, signed: bool): X64Inst =
  ## The `jcc` opcode for a NIFC comparison `ek`, taken when the condition is
  ## `whenTrue`. `signed` selects signed vs unsigned ordering for `<`/`<=`; a float
  ## compare passes `signed = false`, since `comisd` sets CF/ZF like an unsigned
  ## compare (so ordered `<`/`<=` map to below / below-or-equal).
  case ek
  of EqC:  (if whenTrue: JeX64 else: JneX64)
  of NeqC: (if whenTrue: JneX64 else: JeX64)
  of LtC:  (if whenTrue: (if signed: JlX64 else: JbX64)
            else:        (if signed: JgeX64 else: JaeX64))
  of LeC:  (if whenTrue: (if signed: JleX64 else: JbeX64)
            else:        (if signed: JgX64 else: JaX64))
  else: raiseAssert "arkham x64 v0: condition not supported: " & $ek

proc emitCmpBranch(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## `c` is a comparison `(op a b)` (NO type child): `cmp a, b` then a `jcc` to
  ## `toLabel` when the condition is true/false. Ordering signedness comes from
  ## the first operand's slot (an unsigned operand → an unsigned condition).
  let ek = c.exprKind
  var tag: X64Inst
  c.into:
    if g.isFloatExpr(c):
      # `comisd a, b` sets CF/ZF like an unsigned compare (NaN makes </<= spuriously
      # true, but NIFC's compares assume non-NaN, matching the A64 backend) — so the
      # tag is the unsigned one (`signed = false`).
      let fbits = g.floatBits(c)
      tag = cmpJccTag(ek, whenTrue, signed = false)
      let fa = g.genFReg(c, fbits)
      let fb = g.genFReg(c, fbits)
      let op = if fbits == 32: ComissX64 else: ComisdX64
      g.ab.tree op: g.emFReg fa.f; g.emFReg fb.f
      g.freeTemp(fb)
      g.freeTemp(fa)
    else:
      # Unsigned if EITHER operand has an unsigned/char type (a comparison is
      # unsigned as a whole; a literal on one side is ambiguous and defers to the
      # other). Peek both before consuming `a`.
      var bPeek = c; skip bPeek
      let unsigned = g.cmpOperandUnsigned(c) or g.cmpOperandUnsigned(bPeek)
      tag = cmpJccTag(ek, whenTrue, signed = not unsigned)
      var av = g.genVal(c); g.forceReg(av)        # a must be in a register for cmp
      let ar = av.r
      # `a` is now live in `ar` across `b`'s evaluation; seal it so a scratch
      # steal during `b` cannot evict it (it may be a register-local).
      let arWasSealed = g.ra.isSealed(ar)
      g.ra.seal ar
      var bv = g.genVal(c)
      var bTmps: seq[Reg] = @[]
      # `b` need not occupy a register: x86 `cmp` folds a small immediate or a
      # memory operand directly (`cmp ar, imm` / `cmp ar, [mem]`), like `binMem`.
      # But a large/negative immediate that `cmp` can't take inline must be loaded
      # into a register BEFORE the `(cmp …)` tree opens — emitting the load `(mov)`
      # *inside* the tree would corrupt it into a `(cmp ar (mov …))` operand. `ar`
      # stays sealed across this load so the borrowed temp can't be `ar`.
      if bv.kind == Imm and not (bv.ival >= 0 and bv.ival <= 0xFFFF):
        g.forceReg(bv)                            # load the wide immediate into a reg
        if bv.isTemp: bTmps.add bv.r              # tracked here; clear the flag so the
        bv = regLoc(bv.r, ScalarSlot, isTemp = false)  # cmp tree below won't re-add it
      if not arWasSealed: g.ra.unseal {ar}
      let bRegs = g.prematLoc(bv, bTmps)        # load any embedded values FIRST
      var bri = 0
      g.ab.tree CmpX64:
        g.emReg ar
        if bv.kind == Imm:
          g.ab.intLit bv.ival
        elif bv.kind == InReg:
          g.emReg bv.r
          if bv.isTemp: bTmps.add bv.r
        else:                                     # NamedStack/Mem
          g.emMemOperandLoc(bv, bRegs, bri)       # cmp ar, [mem] — folded, no extra reg
      for t in bTmps: g.giveBack t
      g.freeTemp(av)
  g.emJcc(tag, toLabel)

proc emitCondJump(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## Short-circuit conditional jump (and/or/not, comparisons, plain bool value).
  if c.kind == TagLit:
    case c.exprKind
    of AndC:
      c.into:
        if whenTrue:
          let lSkip = g.freshLabel()
          g.emitCondJump(c, lSkip, false)
          g.emitCondJump(c, toLabel, true)
          g.emLab(lSkip)
        else:
          g.emitCondJump(c, toLabel, false)
          g.emitCondJump(c, toLabel, false)
      return
    of OrC:
      c.into:
        if whenTrue:
          g.emitCondJump(c, toLabel, true)
          g.emitCondJump(c, toLabel, true)
        else:
          let lSkip = g.freshLabel()
          g.emitCondJump(c, lSkip, true)
          g.emitCondJump(c, toLabel, false)
          g.emLab(lSkip)
      return
    of NotC:
      c.into:
        g.emitCondJump(c, toLabel, not whenTrue)
      return
    of EqC, NeqC, LtC, LeC:
      g.emitCmpBranch(c, toLabel, whenTrue)
      return
    else: discard
  # plain boolean value: branch on `v != 0` / `v == 0`
  var v = g.genVal(c); g.forceReg(v)
  g.ab.tree CmpX64: (g.emReg v.r; g.ab.intLit 0)
  g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
  g.freeTemp(v)

# ── calls ─────────────────────────────────────────────────────────────────────

# Linux syscalls are recognised in `programs.collect` (the `LinuxSyscalls` table)
# and emitted as `(syproc …)` declarations whose proctype puts args in the syscall
# ABI registers (arg4 → r10, not the C ABI's rcx) and declares the kernel's
# clobbers (rcx, r11). A call site then uses the ordinary declarative `(prepare …)`
# path with a `(syscall)` marker — see `emitSyproc` and `genCall`.

# ── atomic builtins (GCC `__atomic_*` → x86 lock-prefixed instructions) ──────
# x86-64 has a strong memory model: a plain aligned `mov` is already an atomic
# load/store, `xchg` with memory is implicitly locked, and an RMW that returns the
# old value uses `lock xadd` / a `lock cmpxchg` retry loop. The `memorder` arg is
# ignored (all sequences are at least acquire/release), matching the A64 backend.
# Inside a sequence there are no calls, so RAX/RCX/RDX (not in the allocator pool)
# are free scratch; the result lands in RAX (the integer return register).

proc genReg(g: var CodeGen; c: var Cursor): Location =
  ## Evaluate `c` into *some* register via the `NeedsReg` constraint — `gen` writes
  ## back the concrete `InReg`: a register-resident value in place, else a borrowed
  ## scratch (`isTemp = true`) the caller releases with `freeTemp`. `.r` is the reg.
  result = needsReg(ScalarSlot)
  g.gen(c, result)

proc emMemAt(g: var CodeGen; p: Reg) =        # `(mem p)` — dereference the pointer in p
  g.ab.tree MemX: g.emReg p

proc genAtomicXadd(g: var CodeGen; pReg, val: Reg; returnNew, sub: bool) =
  ## `lock xadd [p], val` (val ← old). For `sub`, negate val first so memory is
  ## decremented. `returnNew` recomputes old±delta into rax; otherwise returns old.
  if returnNew: g.bindTemp(RDX, ScalarSlot); g.movReg(RDX, val)  # save the original delta
  if sub:
    g.ab.tree NegX64: g.emReg val             # val ← -val
  g.ab.tree LockX64:
    g.ab.tree XaddX64:
      g.emMemAt pReg
      g.emReg val                              # val ← old; [p] += val
  if returnNew:
    let op = if sub: SubX64 else: AddX64
    g.ab.tree op: g.emReg val; g.emReg RDX     # new = old ± delta
    g.unbindTemp(RDX)
  g.movReg(RAX, val)

proc genAtomicLoopRmw(g: var CodeGen; pReg, val: Reg; op: X64Inst) =
  ## `rax = [p]; loop: rdx = rax op val; lock cmpxchg [p], rdx; jne loop`. There
  ## is no lock-fetch form for and/or/xor that yields the old value, so spin on
  ## cmpxchg. Result (old) ends up in rax.
  let lab = g.freshLabel()
  g.ab.tree MovX64: (g.emReg RAX; g.emMemAt pReg)   # rax = [p]
  g.withFixed(RDX):
    g.emLab(lab)
    g.movReg(RDX, RAX)
    g.ab.tree op: g.emReg RDX; g.emReg val           # rdx = rax op val (the new value)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt pReg
        g.emReg RDX                                   # if [p]==rax: [p]=rdx else rax=[p]
    g.emJcc(JneX64, lab)                              # retry until cmpxchg succeeds

proc genAtomicValReg(g: var CodeGen; c: var Cursor; pointee: Cursor): Reg =
  ## The value operand of an atomic store/exchange, materialized into a scratch reg
  ## typed for the precisely-typed memory location it lands in. The authoritative type
  ## is the POINTER's `pointee` (= `[p]`'s type), NOT the value expression's own slot
  ## (which is i64/intlit for `nil`, a `0`, or a computed address): a POINTER pointee
  ## keeps its precise `(ptr …)` type (the `(mem p)` operand is ptr-typed and nifasm is
  ## strict — a generic i64 reg would be rejected), an INTEGER stays i64 (arkham's
  ## 64-bit-int model; sub-word width via extends). Consumes `c`; caller `giveBack`s.
  let isPtr = not cursorIsNil(pointee) and isPtrType(resolveType(g.prog, pointee))
  result = g.borrowTmp(if isPtr: slotOf(g.prog, pointee) else: ScalarSlot)
  g.genInto(c, result)

proc genAtomic(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower one `__atomic_*` builtin; `c` is at the first argument. Result → rax.
  case builtin
  of "__atomic_load_n":                        # (ptr, memorder) → *ptr
    let p = g.genReg(c); skip c
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt p.r)
    g.freeTemp(p)
  of "__atomic_store_n":                        # (ptr, val, memorder) → void
    let pointee = innerType(g.prog, resolveType(g.prog, g.getType(c)))
    let p = g.genReg(c)
    let v = g.genAtomicValReg(c, pointee); skip c   # typed by [p]'s pointee
    g.ab.tree MovX64: (g.emMemAt p.r; g.emReg v)
    g.giveBack v
    g.freeTemp(p)
  of "__atomic_clear":                          # (ptr, memorder) → void; *ptr = 0
    let p = g.genReg(c); skip c
    g.withFixed(RDX):
      g.movImm(RDX, 0)
      g.ab.tree MovX64: (g.emMemAt p.r; g.emReg RDX)
    g.freeTemp(p)
  of "__atomic_thread_fence":                   # (memorder) → void
    skip c
    g.ab.keyword MfenceX64
  of "__atomic_signal_fence":                   # (memorder) → void; compiler barrier only
    skip c
  of "__atomic_exchange_n":                     # (ptr, val, memorder) → old
    let pointee = innerType(g.prog, resolveType(g.prog, g.getType(c)))
    let p = g.genReg(c)
    let v = g.genAtomicValReg(c, pointee); skip c    # typed by [p]'s pointee
    g.ab.tree XchgX64: (g.emMemAt p.r; g.emReg v)    # v ↔ [p] (locked); v ← old
    g.movReg(RAX, v)
    g.giveBack v
    g.freeTemp(p)
  of "__atomic_fetch_add", "__atomic_fetch_sub",
     "__atomic_add_fetch", "__atomic_sub_fetch",
     "__atomic_fetch_and", "__atomic_fetch_or", "__atomic_fetch_xor":
    let p = g.genReg(c)
    let v = g.genReg(c); skip c
    case builtin
    of "__atomic_fetch_add": g.genAtomicXadd(p.r, v.r, returnNew = false, sub = false)
    of "__atomic_fetch_sub": g.genAtomicXadd(p.r, v.r, returnNew = false, sub = true)
    of "__atomic_add_fetch": g.genAtomicXadd(p.r, v.r, returnNew = true, sub = false)
    of "__atomic_sub_fetch": g.genAtomicXadd(p.r, v.r, returnNew = true, sub = true)
    of "__atomic_fetch_and": g.genAtomicLoopRmw(p.r, v.r, AndX64)
    of "__atomic_fetch_or":  g.genAtomicLoopRmw(p.r, v.r, OrX64)
    of "__atomic_fetch_xor": g.genAtomicLoopRmw(p.r, v.r, XorX64)
    else: discard
    g.freeTemp(v)
    g.freeTemp(p)
  of "__atomic_test_and_set":                   # (ptr, memorder) → bool (old != 0)
    let p = g.genReg(c); skip c
    let lSkip = g.freshLabel()
    g.withFixed(RDX):
      g.movImm(RDX, 1)
      g.ab.tree XchgX64: (g.emMemAt p.r; g.emReg RDX)   # rdx ← old; [p] = 1
      g.movImm(RAX, 0)
      g.ab.tree CmpX64: (g.emReg RDX; g.ab.intLit 0)
      g.emJcc(JeX64, lSkip)
    g.movImm(RAX, 1)
    g.emLab(lSkip)
    g.freeTemp(p)
  of "__atomic_compare_exchange_n":             # (ptr, exp_ptr, des, weak, succ, fail) → bool
    let p = g.genReg(c)
    let ep = g.genReg(c)
    g.bindTemp(RCX, g.exprSlot(c))               # type rcx by the desired value (e.g. a ptr)
    g.genInto(c, RCX)                            # desired → rcx (non-pool scratch)
    skip c; skip c; skip c                       # weak, success order, failure order
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt ep.r)   # rax = *exp (the comparand)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt p.r
        g.emReg RCX                              # if [p]==rax: [p]=rcx,ZF=1 else rax=[p],ZF=0
    g.unbindTemp(RCX)
    let lFail = g.freshLabel()
    let lDone = g.freshLabel()
    g.emJcc(JneX64, lFail)
    g.movImm(RAX, 1); g.emJmp(lDone)             # success → 1
    g.emLab(lFail)
    g.ab.tree MovX64: (g.emMemAt ep.r; g.emReg RAX)   # *exp = actual old value (rax)
    g.movImm(RAX, 0)                             # failure → 0
    g.emLab(lDone)
    g.freeTemp(ep)
    g.freeTemp(p)
  else:
    raiseAssert "arkham x64 v0: unsupported atomic builtin: " & builtin

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers to a short inline byte loop. Sizes are
# runtime values; the result lands in RAX (memcpy/memmove/memset return dest,
# memcmp the first byte difference). Unlike the AArch64 backend these can't use
# the 2-register scratch pool (it can't hold dst+src+n+i+b at once), so — like the
# atomics — they evaluate operands into fixed caller-saved registers (rdi/rsi/rdx/
# rcx/r8): free scratch since a mem* sequence contains no calls.

proc emByteAt(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 8)) base) idx))` — the byte at `base[idx]`. The cast
  ## types the raw register as a byte-array pointer so nifasm sizes the access to
  ## one byte (a load zero-extends into the 64-bit register, a store writes the
  ## low byte only — see `intMemAccess` in the assembler).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg base
      g.emReg idx

proc emLoadByte(g: var CodeGen; dest, base, idx: Reg) =
  g.ab.tree MovX64: (g.emReg dest; g.emByteAt(base, idx))

proc emStoreByte(g: var CodeGen; base, idx, src: Reg) =
  g.ab.tree MovX64: (g.emByteAt(base, idx); g.emReg src)

proc emCmpReg(g: var CodeGen; a, b: Reg) =
  g.ab.tree CmpX64: (g.emReg a; g.emReg b)

proc genMemIntrinBody(g: var CodeGen; builtin: string) =
  ## The inline `mem*` loop, assuming the args are already loaded (dst→rdi,
  ## src/val→rsi, n→rdx) and rsi/rdx/rcx are bound to checked names. Result → RAX.
  ## Shared by the legacy `genMemIntrin` (reactive `genInto` arg-load) and the
  ## value-core `emitMemIntrin2` (args placed by `emitValue2` into the ABI regs).
  ## The dest pointer (rdi) and the byte/result (rax) stay raw — irreducible ABI regs.
  case builtin
  of "memcpy":                                 # (dst, src, n) → dst
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)                      # i >= n (unsigned) → done
    g.emLoadByte(RAX, RSI, RCX)                # b = src[i]
    g.emStoreByte(RDI, RCX, RAX)               # dst[i] = b
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(done)
    g.movReg(RAX, RDI)                         # memcpy returns dest
  of "memmove":                                # (dst, src, n) → dst; overlap-safe
    let fwd = g.freshLabel()
    let bwd = g.freshLabel()
    let done = g.freshLabel()
    g.emCmpReg(RDI, RSI)
    g.emJcc(JbeX64, fwd)                        # dst <= src → forward copy is safe
    # backward: i = n; while i != 0: i -= 1; dst[i] = src[i]
    g.movReg(RCX, RDX)                          # i = n
    g.emLab(bwd)
    g.ab.tree CmpX64: (g.emReg RCX; g.ab.intLit 0)
    g.emJcc(JeX64, done)
    g.binImm(SubX64, RCX, 1)
    g.emLoadByte(RAX, RSI, RCX)
    g.emStoreByte(RDI, RCX, RAX)
    g.emJmp(bwd)
    # forward: i = 0; while i < n: dst[i] = src[i]; i += 1
    g.emLab(fwd)
    g.movImm(RCX, 0)
    let fwdLoop = g.freshLabel()
    g.emLab(fwdLoop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)
    g.emLoadByte(RAX, RSI, RCX)
    g.emStoreByte(RDI, RCX, RAX)
    g.binImm(AddX64, RCX, 1)
    g.emJmp(fwdLoop)
    g.emLab(done)
    g.movReg(RAX, RDI)
  of "memset":                                 # (dst, val, n) → dst
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)
    g.emStoreByte(RDI, RCX, RSI)               # dst[i] = low byte of val
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(done)
    g.movReg(RAX, RDI)
  of "memcmp":                                 # (a, b, n) → first byte difference
    g.bindTemp(R8, ScalarSlot)                 # the second byte (held across the loop)
    let loop = g.freshLabel()
    let diff = g.freshLabel()
    let equal = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, equal)                     # ran off the end, no diff → 0
    g.emLoadByte(RAX, RDI, RCX)                # ba = a[i] (zero-extended, 0..255)
    g.emLoadByte(R8, RSI, RCX)                 # bb = b[i]
    g.emCmpReg(RAX, R8)
    g.emJcc(JneX64, diff)
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(diff)                              # bytes are 0..255 → signed sub gives sign
    g.binReg(SubX64, RAX, R8)                  # rax = ba - bb
    g.emJmp(done)
    g.emLab(equal)
    g.movImm(RAX, 0)
    g.emLab(done)
    g.unbindTemp(R8)
  else:
    raiseAssert "arkham x64 v0: unsupported mem intrinsic: " & builtin
  g.unbindTemp(RCX); g.unbindTemp(RDX); g.unbindTemp(RSI)

proc genMemIntrin(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Legacy reactive path: bind the scratch, evaluate the 3 args via `genInto` into
  ## rdi/rsi/rdx, then run the inline loop. `c` is at the first arg; consumes all.
  g.bindTemp(RSI, ScalarSlot); g.bindTemp(RDX, ScalarSlot); g.bindTemp(RCX, ScalarSlot)
  g.genInto(c, RDI); g.genInto(c, RSI); g.genInto(c, RDX)   # dst, src/val, n
  g.genMemIntrinBody(builtin)

# ── by-value aggregate marshalling (SysV) ────────────────────────────────────
# A ≤16-byte aggregate of full 8-byte fields travels in 1–2 GPRs (word i ↔ the
# field at byte offset 8·i); a >16-byte aggregate is passed/returned by reference
# (a pointer). This is self-consistent arkham↔arkham — NOT strict SysV, which
# would pass a >16B argument as a stack copy (MEMORY class) and return it via a
# hidden pointer in the first integer arg. A ≤16B result travels in rax:rdx.

const x64RetRegs = [RAX, RDX]   # SysV ≤16B aggregate result: rax (word 0), rdx (word 1)

proc emStackAddr(g: var CodeGen; dest: Reg; name: string) =   # dest ← &stackvar
  g.ab.tree LeaX64: (g.emReg dest; g.ab.reg RSP; g.ab.sym name)

proc freshAggrTemp(g: var CodeGen; typeName: string): string =
  ## Declare a fresh nifasm-managed aggregate stack slot `(var :ctmp.N (s) T)`
  ## and return its name — a place to materialize an inline constructor whose
  ## result an aggregate-by-value ABI then reads from memory.
  result = "ctmp." & $g.spillCount & ".0"; inc g.spillCount
  g.ra.hasStackVars = true   # ensure the proc reserves its `(s)` slot region (ssize);
                             # without this an aggregate-temp-only proc skips the
                             # `sub rsp, ssize` and the slot overlaps the return address
  g.emStackVar(result, typeName)
  g.varType[result] = typeName

proc emPtrFieldMem(g: var CodeGen; ptrReg: Reg; typeName, field: string) =
  ## `(mem (dot (cast (ptr T) reg) field))` — a field through a register holding a
  ## pointer to the aggregate (a >16B by-ref param / the indirect-result buffer).
  ## The cast types the bare register so nifasm can compute the field offset.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym typeName
        g.emReg ptrReg
      g.ab.sym field

proc emAggrFieldMem(g: var CodeGen; base, field: string) =
  ## Field memory operand for aggregate `base`: a `(s)` stack struct → direct dot;
  ## a pointer in a register (a by-ref param) → through the pointer.
  let loc = g.ra.locationOfSym(base)
  case loc.kind
  of NamedStack: g.emFieldMem(base, field)
  of InReg:      g.emPtrFieldMem(loc.r, g.varType[base], field)
  else:
    # a synthetic nifasm `(s)` slot (e.g. a constructor temp) is rsp-relative by
    # name, just like a `NamedStack` var — the allocator simply doesn't track it.
    if g.varType.hasKey(base): g.emFieldMem(base, field)
    else: raiseAssert "arkham x64 v0: aggregate base neither stack nor pointer: " & base

proc genConstr(g: var CodeGen; c: var Cursor; dstPtr: Reg) =
  ## The single destination-passing constructor emitter: materialize
  ## `(oconstr T (kv field value)*)` into the aggregate `dstPtr` points at,
  ## storing each field at its offset. The constructed type is read from the
  ## constructor itself, so every caller (var-init, assignment, call argument)
  ## just supplies a destination address. Consumes `c`.
  assert c.exprKind == OconstrC,
    "arkham x64 v0: runtime (aconstr …) not supported (constant arrays go to rodata)"
  var tc = c; inc tc                           # the constructed type symbol
  let typeName = symName(tc)
  let objTy = resolveType(g.prog, tc)          # the (object …) body, for field types
  c.into:
    skip c                                     # the constructed type
    while c.hasMore:
      assert c.substructureKind == KvU, "arkham x64 v0: oconstr expects (kv …)"
      c.into:
        let field = symName(c); inc c
        var v = g.genVal(c); g.forceReg(v)
        # The store must respect nifasm's strong typing: a scalar value (an
        # immediate / address computed in a GPR, e.g. `nil`→0 or `(addr const)`)
        # going into a POINTER field is reinterpreted with a `(cast (ptr …) reg)`
        # so the field's declared pointee type is preserved (a bare i64 register
        # into a `(ptr T)` field is rejected). Non-pointer fields store directly.
        var fty = resolveType(g.prog, fieldType(g.prog, objTy, field))
        g.ab.tree MovX64:
          g.emPtrFieldMem(dstPtr, typeName, field)
          if isPtrType(fty):
            g.ab.tree CastX:
              g.genTypeBody(fty)
              g.emReg v.r
          else:
            g.emReg v.r
        g.freeTemp(v)
        while c.hasMore: skip c                 # optional inherited-depth INTLIT

proc transferAggrWords(g: var CodeGen; varName, typeName: string;
                       regs: openArray[Reg]; toRegs: bool) =
  ## Move an aggregate between memory and the GPRs that carry it, one register per
  ## 8-byte word (the by-value aggregate ABI). `toRegs` picks the direction —
  ## `regs[i] ← word i` (load) or `word i ← regs[i]` (store) — the only difference
  ## being the `(mov …)` operand order.
  let lay = aggrLayout(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham x64 v0: sub-word-packed aggregate ABI unsupported"
    g.ab.tree MovX64:
      if toRegs: (g.emReg regs[i]; g.emAggrFieldMem(varName, fn))
      else:      (g.emAggrFieldMem(varName, fn); g.emReg regs[i])

proc structToRegs(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## aggregate → regs[i] (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeName, regs, toRegs = true)

proc aggrIsGlobal(g: var CodeGen; name: string): bool {.inline.} =
  ## True when `name` is a module-level global aggregate (RIP-relative), as opposed
  ## to a stack var / by-ref param / synthetic temp. Globals are not in `varType`
  ## and the register allocator has no slot for them (`Undef`), so they must be
  ## addressed via `emGlobalAddr`, not `emStackAddr` / the rsp-relative field forms.
  not g.varType.hasKey(name) and g.ra.locationOfSym(name).kind == Undef

proc marshalAggrArg(g: var CodeGen; name, tn: string; idx: var int; sealedHere: var set[Reg]) =
  ## Marshal an aggregate call argument — a named var, a module-level global, OR an
  ## inline-constructor temp, all addressed by `name` — into the SysV integer arg
  ## registers. By reference (`aggrByRef`): a pointer to it in one reg (a by-ref param
  ## is already that pointer → `mov`; a stack var / temp → `lea`; a global →
  ## RIP-relative `lea`). Otherwise by value: its `nw` words, read from a stack var via
  ## `structToRegs` or from a global through its address. Each consumed arg register is
  ## sealed into `sealedHere` and `idx` advanced. Shared by both aggregate-argument
  ## branches of `genCall`.
  if g.aggrByRef(tn):
    assert idx < g.md.intArgRegs.len, "arkham x64 v0: >6 args (stack TODO)"
    let ar = g.md.intArgRegs[idx]
    let loc = g.ra.locationOfSym(name)
    if loc.kind == InReg: g.movReg(ar, loc.r)   # already a pointer (by-ref param)
    elif g.aggrIsGlobal(name): g.emGlobalAddr(ar, name)  # &global → RIP-relative lea
    else: g.emStackAddr(ar, name)               # stack var / constructor temp → lea
    g.ra.seal ar; sealedHere.incl ar
    inc idx
  else:
    let nw = aggrWordCount(g.prog, tn)
    assert idx + nw <= g.md.intArgRegs.len, "arkham x64 v0: aggregate arg exceeds GPRs"
    let argRegs = g.md.intArgRegs[idx ..< idx + nw]
    if g.aggrIsGlobal(name):
      # A global aggregate by value: lea its address once, then read each 8-byte word
      # through that pointer (the rsp-relative field forms `structToRegs` uses cannot
      # address a global).
      let base = g.borrowTmp(ScalarSlot); g.emGlobalAddr(base, name)
      let lay = aggrLayout(g.prog, tn)
      for i in 0 ..< nw:
        let fn = fieldAtOffset(lay, i * 8)
        if fn.len == 0: raiseAssert "arkham x64 v0: sub-word-packed aggregate ABI unsupported"
        g.ab.tree MovX64: (g.emReg argRegs[i]; g.emPtrFieldMem(base, tn, fn))
      g.giveBack base
    else:
      g.structToRegs(name, tn, argRegs)
    for k in 0 ..< nw:
      g.ra.seal g.md.intArgRegs[idx + k]; sealedHere.incl g.md.intArgRegs[idx + k]
    idx += nw

proc regsToStruct(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## regs[i] → aggregate (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeName, regs, toRegs = false)

proc copyStructThroughPtr(g: var CodeGen; srcVar, typeName: string; ptrReg: Reg) =
  ## field-wise copy of aggregate `srcVar` → the memory `ptrReg` points at.
  for f in aggrLayout(g.prog, typeName):
    let t = g.borrowTmp(ScalarSlot)
    g.ab.tree MovX64: (g.emReg t; g.emAggrFieldMem(srcVar, f.name))
    g.ab.tree MovX64: (g.emPtrFieldMem(ptrReg, typeName, f.name); g.emReg t)
    g.giveBack t

proc indirectRetType(g: var CodeGen; gvarDecl: Cursor): Cursor =
  ## The return-type cursor of a function-pointer variable's proctype, for the
  ## declarative call path's `retIsVoid`/result handling. NIFC's
  ## `(proctype Empty Params RetType Pragmas)` always carries the RetType node — a
  ## `.` (DotToken, `retIsVoid`-true) / `(void)` for a void proc — so it is simply
  ## the third child.
  var d = gvarDecl
  result = gvarDecl                             # overwritten below (always a proctype here)
  d.into:
    inc d; skip d                               # name, pragmas
    let pt = resolveType(g.prog, d)             # the (proctype …) body
    assert pt.kind == TagLit and pt.typeKind == ProctypeT,
           "arkham: indirect call through a non-proctype value"
    var q = pt                                  # consume a copy; `result` keeps a cursor
    q.into:
      skip q                                    # Empty (the proc-name slot)
      skip q                                    # Params
      result = q                                # RetType (`.` / `(void)` / a real type)
      while q.hasMore: skip q                   # drain RetType + Pragmas
    while d.hasMore: skip d

proc genBitBuiltin(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower a GCC bit builtin; `c` is at the single integer argument (consumed).
  ## Result → RAX (the call-return register the surrounding expression reads).
  let v = g.genReg(c)                          # x → temp reg; advances c past the arg
  case builtin
  of "__builtin_ctzll", "__builtin_ctz":
    # count trailing zeros == index of the least-significant set bit == BSF.
    # (x == 0 is UB in C and is never reached: nimony callers guard the zero case.)
    g.ab.tree BsfX64: (g.emReg RAX; g.emReg v.r)
  else:
    # clz/popcount/bswap have no consumer in the current corpus; lower them when one
    # appears (clz ⇒ `63 - bsr`, popcount ⇒ `popcnt`, bswap ⇒ `bswap`).
    raiseAssert "arkham x64 v0: bit builtin not yet implemented: " & builtin
  g.freeTemp(v)

proc aggrLvalueType(g: var CodeGen; nm: string): string =
  ## The named aggregate type of an aggregate-typed lvalue symbol — a local/temp
  ## stack var or by-ref param (tracked in `varType`) OR a module-level global/tvar
  ## (read from its decl) — or "" if `nm` is not a (named) aggregate. Lets `genCall`
  ## marshal a global aggregate by value just like a local one.
  if g.varType.hasKey(nm): return g.varType[nm]
  let si = g.lookupSym(nm)
  if si.cat in {scGlobal, scTvar}:
    var d = si.decl
    d.into:
      inc d; skip d                              # name, pragmas
      if d.kind == Symbol and slotOf(g.prog, resolveType(g.prog, d)).kind == AMem:
        result = symName(d)                      # the global's named aggregate type
      while d.hasMore: skip d                    # drain type (+ initializer)

proc genCall(g: var CodeGen; c: var Cursor) =
  ## `(call f arg…)`. The C `exit` extern lowers to the Linux exit syscall; a
  ## declarative user proc uses the SysV register ABI via a `(prepare …)` block
  ## (args → rdi/rsi/…, result ← rax). Each committed arg register is sealed so
  ## marshalling can't clobber it.
  c.into:
    let fsym = symName(c); inc c
    if not g.callTarget.hasKey(fsym):
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        # The callee is a *variable* holding a function pointer. Its proctype is a
        # full signature, so it has the same typing as a direct call and goes
        # through the SAME declarative `(prepare …)` path — only the call
        # instruction differs (nifasm emits an indirect `call` when the prepare
        # target is a function-pointer variable).
        g.callTarget[fsym] = CallTarget(declarative: true, indirect: true,
                                        asmName: fsym, retType: g.indirectRetType(si.decl))
      else:
        # A call into another module: resolve its signature from the owning
        # module's embedded index and cache it. nifasm auto-imports the foreign
        # `<module>.s.nif` and links the definition.
        g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    let tgt = g.callTarget[fsym]
    if tgt.atomic.len > 0:                     # GCC `__atomic_*` builtin → inline
      g.genAtomic(c, tgt.atomic)               # consumes the args; result in rax
    elif tgt.memIntrin.len > 0:                # C mem* intrinsic → inline byte loop
      g.genMemIntrin(c, tgt.memIntrin)         # consumes the args; result in rax
    elif tgt.bitBuiltin.len > 0:               # GCC bit builtin (ctz/…) → inline bsf/…
      g.genBitBuiltin(c, tgt.bitBuiltin)       # consumes the arg; result in rax
    elif tgt.declarative and not tgt.extern:
      var sealedHere: set[Reg] = {}
      var argCurs: seq[Cursor] = @[]           # one cursor per argument expression
      while c.hasMore: (argCurs.add c; skip c)
      let nReg = min(argCurs.len, g.md.intArgRegs.len)
      let nStack = argCurs.len - nReg          # 7th+ args go through the stack
      g.ab.tree PrepareX64:
        g.ab.sym tgt.asmName
        # Phase 1 — register args → rdi…r9, each bound to the callee's param and
        # sealed so later marshalling can't clobber it. Evaluated before rsp moves.
        for idx in 0 ..< nReg:
          var a = argCurs[idx]
          if g.isFloatExpr(a): raiseAssert "arkham x64 v0: float call argument"
          let ar = g.md.intArgRegs[idx]
          g.genInto(a, ar)
          g.ab.tree MovX64:                    # bind it to the callee's param p.idx
            g.ab.tree ArgX: g.ab.sym paramName(idx)
            g.emReg ar
          g.ra.seal ar; sealedHere.incl ar
        # Phase 2 — reserve the outgoing stack area (`csize` keeps rsp 16-aligned),
        # then evaluate each stack arg into a reused temp and store it; nifasm
        # resolves `(arg p.k)` to its byte offset. x64 has only two scratch GPRs,
        # so args are materialized one at a time rather than all held at once —
        # hence the evaluation happens after the `sub rsp`, which is fine for the
        # literals/register locals the flattener leaves (an rsp-relative stack
        # local would read at the wrong offset and is rejected below).
        if nStack > 0:
          g.ab.tree SubX64: g.ab.reg RSP; g.ab.keyword CsizeX
          for k in 0 ..< nStack:
            let idx = nReg + k
            var a = argCurs[idx]
            if g.isFloatExpr(a): raiseAssert "arkham x64 v0: float call argument"
            if a.kind == Symbol and
               g.ra.locationOfSym(symName(a)).kind in {NamedStack, OnStack}:
              raiseAssert "arkham x64 v0: rsp-relative local as a stack call argument"
            let t = g.borrowTmp(ScalarSlot)
            g.genInto(a, t)
            g.ab.tree MovX64:
              g.ab.tree MemX:
                g.ab.reg RSP
                g.ab.tree ArgX: g.ab.sym paramName(idx)
              g.emReg t
            g.giveBack t
        if tgt.syscall: g.emSyscall()           # `(syscall)`: kernel trap, no `call`
        else: g.ab.keyword CallX64
        if nStack > 0:
          g.ab.tree AddX64: g.ab.reg RSP; g.ab.keyword CsizeX
        if not retIsVoid(tgt.retType):
          g.ab.tree MovX64:
            g.emReg RAX
            g.ab.tree ResX: g.ab.sym "ret.0"
      g.ra.unseal sealedHere
    else:
      # Non-declarative ABI: marshal args by hand (aggregates / by-ref), then a
      # bare `(prepare f (call))` (the callee's signature is empty). The scalar
      # result lands in rax (read by the CallC path in `genInto`).
      var idx = 0
      var fidx = 0
      var sealedHere: set[Reg] = {}
      var sealedFHere: set[FReg] = {}
      while c.hasMore:
        if g.isFloatExpr(c):
          # A float argument goes in xmm{fidx}. Float-arg evaluation normally
          # scratches only xmm8–15 (disjoint from xmm0–7), but a *deep* float arg
          # can spill via `spillFOperandAround`, whose `pickFStaging` reaches into
          # xmm0–7 — so seal each placed arg to keep a later arg's spill from
          # clobbering it (the SIMD analogue of sealing the GPR arg registers).
          assert fidx < g.md.floatArgRegs.len, "arkham x64 v0: >8 float args (stack TODO)"
          let fr = g.md.floatArgRegs[fidx]
          g.genIntoF(c, fr, g.floatBits(c))
          g.sealedF.incl fr; sealedFHere.incl fr
          inc fidx
        elif c.kind == Symbol and g.aggrLvalueType(symName(c)).len > 0:
          let vn = symName(c)
          g.marshalAggrArg(vn, g.aggrLvalueType(vn), idx, sealedHere)
          inc c
        elif c.kind == TagLit and c.exprKind in {OconstrC, AconstrC}:
          # An inline aggregate constructor: build it into a temp slot, then
          # marshal that temp like any aggregate var (by value in GPRs, or by
          # reference) — no constructor-specific ABI logic.
          var tc = c; inc tc                    # the constructed type
          let tn = symName(tc)
          let tmpName = g.freshAggrTemp(tn)
          let p = g.borrowTmp(ScalarSlot); g.emStackAddr(p, tmpName)
          g.genConstr(c, p)                     # consumes the constructor
          g.giveBack p
          g.marshalAggrArg(tmpName, tn, idx, sealedHere)
        else:
          assert idx < g.md.intArgRegs.len, "arkham x64 v0: >6 integer args (stack TODO)"
          let ar = g.md.intArgRegs[idx]
          g.genInto(c, ar)
          g.ra.seal ar; sealedHere.incl ar
          inc idx
      g.ab.tree PrepareX64:
        g.ab.sym tgt.asmName
        g.ab.keyword CallX64
      g.ra.unseal sealedHere
      g.sealedF = g.sealedF - sealedFHere

# ── whole-aggregate copy (struct assignment / copy-init) ─────────────────────

proc byteCopyConst(g: var CodeGen; dst, src: Reg; size: int) =
  ## `dst[0..<size] ← src[0..<size]`, `size` a compile-time constant (the same
  ## inline byte loop as `memcpy`). Used for whole-aggregate assignment / copy-
  ## init; `dst`/`src` stay live. RAX (never a local home) and RCX are free scratch
  ## for the byte value / loop counter — but RCX is an ABI arg register, so in a leaf
  ## proc it can hold a live parameter: evict it first so the loop counter can't
  ## destroy it. (`dst`/`src` are `aggrAddr` temps, never RAX/RCX.)
  g.evictFixedReg(RCX)
  g.withFixed(RCX):                             # loop counter → a checked name
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                            # i = 0
    g.emLab(loop)
    g.ab.tree CmpX64: (g.emReg RCX; g.ab.intLit size)
    g.emJcc(JaeX64, done)                       # i >= size (unsigned) → done
    g.emLoadByte(RAX, src, RCX)                 # b = src[i]
    g.emStoreByte(dst, RCX, RAX)                # dst[i] = b
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(done)

proc aggrAddr(g: var CodeGen; c: var Cursor): (Reg, bool) =
  ## Address of an aggregate lvalue (consumes it). A by-reference aggregate param
  ## (InReg) already *is* the address; otherwise borrow a temp and `genAddr`.
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InReg:
      result = (loc.r, false); inc c; return
  var d = needsReg(ScalarSlot)                  # let genAddr pick the address register
  g.genAddr(c, d)
  result = (d.r, d.isTemp)

proc genStore(g: var CodeGen; c: var Cursor; dst: Location) =
  ## Destination-passing store: emit expression `c` so its value lands at `dst`,
  ## consuming `c`. An aggregate is built/copied in place; every scalar and float
  ## store goes through the unified `gen`, which selects register vs memory vs the
  ## float path purely from `dst`'s kind/type. Callers (`genAsgn`, var-init) just
  ## hand it a `dst`.
  if dst.typ.kind == AMem:                       # aggregate destination
    let (dp, downs) = g.addrOfLoc(dst)
    if c.kind == TagLit and c.exprKind in {OconstrC, AconstrC}:
      g.genConstr(c, dp)                          # build the aggregate in place
    else:                                         # copy from another aggregate lvalue
      let (sp, sowns) = g.aggrAddr(c)
      g.byteCopyConst(dp, sp, dst.typ.size)
      if sowns: g.giveBack sp
    if downs: g.giveBack dp
  else:                                           # scalar / float → the one entry point
    var d = dst; g.gen(c, d)

# ── statements ─────────────────────────────────────────────────────────────────

proc genStmt(g: var CodeGen; c: var Cursor)

proc genVarDecl(g: var CodeGen; c: var Cursor) =
  c.into:
    let name = symName(c); inc c
    skip c                                    # pragmas
    g.symType[name] = c                       # record the type for getType
    let typeCur = c
    skip c                                    # type
    let loc = g.ra.locationOfSym(name)
    case loc.kind
    of InReg:
      g.emRegLocalVar(name, loc.r, typeCur)   # (var :name (reg) type) — typed for nifasm
      if c.hasMore and c.kind != DotToken:
        var d = loc; g.gen(c, d)              # init value → the local's register
    of InFReg:                                # float local in an xmm register
      g.emFRegLocalVar(name, loc.f, loc.typ.size * 8)  # (rebind :name (f bits) (xmmN))
      if c.hasMore and c.kind != DotToken:
        var d = loc; g.gen(c, d)
    of NamedStack:
      if loc.typ.kind == AFloat:              # a spilled float scalar
        let bits = loc.typ.size * 8
        g.emFloatStackVar(name, bits)
        if c.hasMore and c.kind != DotToken:
          let f = g.borrowFTmp()
          g.genIntoF(c, f, bits)
          g.emFloatScalarStore(name, f, bits)
          g.giveBackF f
      elif loc.typ.kind == AMem:              # an aggregate stack object
        g.ab.open NifasmDecl.VarD             # (var :name (s) <type>)
        g.ab.symDef name
        g.ab.keyword SO
        var tc = typeCur                      # named type ref, or inline structural type
        if tc.kind == Symbol: g.ab.sym symName(tc)
        else: g.genTypeBody(tc)               # e.g. an inline `(array (i N) len)`
        g.ab.close()
        if tc.kind == Symbol: g.varType[name] = symName(tc)  # object field-offset lookups
        if c.hasMore and c.kind != DotToken:
          if c.kind == TagLit and c.exprKind == CallC:
            # receive an aggregate return value into this var's slot (the callee
            # writes it, so this can't go through the generic `genStore`).
            assert tc.kind == Symbol, "arkham x64 v0: call-returned aggregate needs a named type"
            let typeName = symName(tc)
            if g.aggrByRef(typeName):
              # >16B: hand the callee a pointer to this var via rdi; it writes there.
              g.emStackAddr(RDI, name)
              g.genCall(c)
            else:
              g.genCall(c)                     # result in rax:rdx
              g.regsToStruct(name, typeName, x64RetRegs)
          else:                                # construct in place / copy from an lvalue
            g.genStore(c, namedStackLoc(name, loc.typ))
      else:                                   # a spilled / address-taken scalar
        # A pointer's slot must carry its PRECISE type: nifasm is strict, so a later
        # load `(mov ptrTmp (mem name))` / deref of a generic `(i 64)` slot is rejected
        # (the value's precise type doesn't match an i64 slot). Integers keep the
        # generic 8-byte slot (the sized mem↔reg rule tolerates width differences).
        if isPtrType(resolveType(g.prog, typeCur)):
          g.emTypedStackVar(name, typeCur)    # (var :name (s) (ptr …))
        else:
          g.emScalarStackVar(name)            # (var :name (s) (i 64))
        if c.hasMore and c.kind != DotToken:
          var d = loc; g.gen(c, d)            # init value → the slot (NamedStack store)
    else: raiseAssert "arkham x64 v0: local '" & name & "' has location " & $loc.kind
    while c.hasMore: skip c

proc genAsgn(g: var CodeGen; c: var Cursor) =
  c.into:
    let dst = g.asLoc(c)                        # lhs → the destination location ("fills")
    g.genStore(c, dst)                          # rhs value into it ("binds")
    while c.hasMore: skip c

proc genWhile(g: var CodeGen; c: var Cursor) =
  let lStart = g.freshLabel()
  let lEnd = g.freshLabel()
  g.loopEnds.add lEnd
  c.into:
    let condStart = c
    skip c                                    # `c` → first body statement
    g.emLab(lStart)
    var cond = condStart
    g.emitCondJump(cond, lEnd, whenTrue = false)
    while c.hasMore: genStmt(g, c)
    g.emJmp(lStart)
  g.emLab(lEnd)
  discard g.loopEnds.pop()

proc genBreak(g: var CodeGen; c: var Cursor) =
  assert g.loopEnds.len > 0, "arkham x64 v0: `break` outside a loop"
  g.emJmp(g.loopEnds[^1])
  skip c

# ── if / case ────────────────────────────────────────────────────────────────

proc genActionStmts(g: var CodeGen; c: var Cursor) =
  ## The body of an `(elif … body)` / `(else body)` / case branch — a `(stmts …)`
  ## list (not a fresh scope) or a single statement.
  if c.stmtKind == StmtsS:
    c.into:
      while c.hasMore: genStmt(g, c)
  else:
    genStmt(g, c)

proc emitChain(g: var CodeGen; c: var Cursor; lEnd: string) =
  if not c.hasMore: return
  case c.substructureKind
  of ElifU:
    var branch = c
    skip c                                    # `c` → the rest of the chain
    let lNext = g.freshLabel()
    branch.into:
      g.emitCondJump(branch, lNext, whenTrue = false)
      g.genActionStmts(branch)
      g.emJmp(lEnd)
    g.emLab(lNext)
    g.emitChain(c, lEnd)
  of ElseU:
    c.into:
      g.genActionStmts(c)
  else:
    skip c

proc genIf(g: var CodeGen; c: var Cursor) =
  let lEnd = g.freshLabel()
  c.into:
    g.emitChain(c, lEnd)
  g.emLab(lEnd)


proc cmpImm(g: var CodeGen; selReg: Reg; v: int64) =
  ## `cmp selReg, v` — immediate when small, else via a scratch register.
  if v >= 0 and v <= 0xFFFF:
    g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit v)
  else:
    let tmp = g.borrowTmp(ScalarSlot)
    g.movImm(tmp, v)
    g.ab.tree CmpX64: (g.emReg selReg; g.emReg tmp)
    g.giveBack tmp

proc emitRangeTest(g: var CodeGen; selReg: Reg; c: var Cursor;
                   lBody: string; signed: bool) =
  ## One `BranchRange` against `selReg`; jump to `lBody` on a match.
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()              # match iff lo <= sel <= hi
      g.cmpImm(selReg, lo)
      g.emJcc(if signed: JlX64 else: JbX64, lSkip)
      g.cmpImm(selReg, hi)
      g.emJcc(if signed: JgX64 else: JaX64, lSkip)
      g.emJmp(lBody)
      g.emLab(lSkip)
  else:
    g.cmpImm(selReg, branchImm(c))
    g.emJcc(JeX64, lBody)

proc genCase(g: var CodeGen; c: var Cursor) =
  ## `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`. Selector
  ## → a register; each branch's tests jump to its body; a non-match falls through
  ## to `else` (or the end). NIFC `case` has no fall-through, so bodies end in a jmp.
  let lEnd = g.freshLabel()
  c.into:
    let signed = not g.cmpOperandUnsigned(c)          # selector type drives test signedness
    var sel = g.genVal(c); g.forceReg(sel)            # selector, live across all tests
    let selReg = sel.r
    var bodies: seq[(string, Cursor)] = @[]
    var elseBody = c
    var hasElse = false
    while c.hasMore:
      case c.substructureKind
      of OfU:
        let lBody = g.freshLabel()
        var branch = c
        skip c
        branch.into:                          # branch → (ranges …) then StmtList
          assert branch.substructureKind == RangesU, "arkham x64: case `of` needs `ranges`"
          branch.into:
            while branch.hasMore:
              g.emitRangeTest(selReg, branch, lBody, signed)
          bodies.add (lBody, branch)
          skip branch
      of ElseU:
        elseBody = c; hasElse = true; skip c
      else: skip c
    g.freeTemp(sel)
    if hasElse:
      elseBody.into:
        g.genActionStmts(elseBody)
    g.emJmp(lEnd)
    for (lBody, bc) in bodies:
      g.emLab(lBody)
      var body = bc
      g.genActionStmts(body)
      g.emJmp(lEnd)
  g.emLab(lEnd)

proc genStmt(g: var CodeGen; c: var Cursor) =
  if c.kind == DotToken:                       # an empty statement (e.g. `(stmts .)`)
    inc c; return
  case c.stmtKind
  of ScopeS:                                  # only `scope` is a fresh scope
    g.enterScope()                            # register locals here `kill` at close
    c.into:
      while c.hasMore: genStmt(g, c)
    g.exitScope()
  of StmtsS:                                  # a statement list — not a fresh scope
    c.into:
      while c.hasMore: genStmt(g, c)
  of VarS, GvarS, TvarS, ConstS:
    genVarDecl(g, c)
  of CallS:
    genCall(g, c)
  of AsgnS:
    genAsgn(g, c)
  of WhileS:
    genWhile(g, c)
  of IfS:
    genIf(g, c)
  of CaseS:
    genCase(g, c)
  of BreakS:
    genBreak(g, c)
  of RetS:
    # The Linux entry must terminate the process; a normal proc returns in rax.
    if g.isEntryProc:
      c.into:
        if c.hasMore and c.kind != DotToken: g.genInto(c, RDI)  # exit code → rdi
        else: g.movImm(RDI, 0)
        while c.hasMore: skip c                # void `(ret .)` → drop the `.`
      g.movImm(RAX, LinuxX64ExitNr)
      g.emSyscall()
    else:
      c.into:
        if c.hasMore and c.kind != DotToken:
          if g.retIndirect:
            # >16B: copy the result into the caller's buffer (parked in rbx) and
            # return its address in rax (SysV: the hidden pointer is also returned).
            assert c.kind == Symbol, "arkham x64 v0: aggregate ret value must be a local"
            g.copyStructThroughPtr(symName(c), g.retAggrName, g.indirectReg)
            g.movReg(RAX, g.indirectReg)
            inc c
          elif g.retAggrName.len > 0:         # ≤16B aggregate → rax:rdx
            assert c.kind == Symbol, "arkham x64 v0: aggregate ret value must be a local"
            g.structToRegs(symName(c), g.retAggrName, x64RetRegs)
            inc c
          elif g.retIsFloat:
            g.genIntoF(c, FloatRet, g.retFloatBits)   # float result in xmm0
          else:
            g.genInto(c, RAX)
        while c.hasMore: skip c               # void `(ret .)` → drop the `.`
      g.killFrameRegLocals()                  # release locals bound to popped regs
      g.framePop()                            # restore callee-saved before returning
      g.ab.keyword RetX64
  of LabS:                                    # `(lab :name)` — a goto target
    c.into:
      g.emLab(symName(c)); inc c
      while c.hasMore: skip c
  of JmpS:                                     # `(jmp name)` — unconditional goto
    c.into:
      g.emJmp(symName(c)); inc c
      while c.hasMore: skip c
  else:
    raiseAssert "arkham x64 v0: statement not supported: " & $c.stmtKind

# ── type + proc + module emission ───────────────────────────────────────────
# genTypeBody/genType emit nifasm `NifasmType` tags (arch-neutral). TODO: share
# with codegen_a64 by lifting these into codegen_common.

proc genPointee(g: var CodeGen; c: var Cursor) =
  ## Emit a pointer's pointee / element type. A *named* type is referenced by
  ## symbol rather than inlined: this breaks the infinite recursion of
  ## self-referential types (a `(ptr T)` field inside `T`) and lets nifasm
  ## resolve — and auto-import across modules — the type declaration by name.
  if c.kind == Symbol:
    g.ab.sym symName(c); inc c
  else:
    g.genTypeBody(c)

proc emitParamsAndResult(g: var CodeGen; c: var Cursor; byRef: bool): int =
  ## Emit the SysV `(params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (rax) T))?`
  ## of a signature, consuming the params slot and the return type at `c`, and return
  ## the parameter count. `byRef` selects how a *named* type is emitted: by reference
  ## (`genPointee`, so a self-referential proctype can't recurse forever) or inline
  ## (`genTypeBody`). Shared by `genProctypeSig` and the declarative `emitSignature`.
  var idx = 0
  g.ab.tree ParamsD:
    if c.kind == TagLit:                        # (params (param …) …)
      c.into:
        while c.hasMore:
          c.into:                               # (param :name pragmas type)
            inc c                               # name → positional pN.0
            skip c                              # pragmas
            g.ab.tree ParamD:
              g.ab.symDef paramName(idx)
              if idx < g.md.intArgRegs.len: g.ab.reg g.md.intArgRegs[idx]
              else: g.ab.keyword SO             # 7th+ → stack-passed
              if byRef: g.genPointee(c) else: g.genTypeBody(c)
            while c.hasMore: skip c
          inc idx
    else:
      skip c                                    # no params slot
  g.ab.tree ResultD:                            # c now at the return type
    if retIsVoid(c):
      skip c
    else:
      g.ab.symDef "ret.0"
      g.ab.reg RAX
      if byRef: g.genPointee(c) else: g.genTypeBody(c)
  result = idx

proc emitAbiClobber(g: var CodeGen; numArgRegs: int) =
  ## `(clobber …)` listing the volatile GPRs EXCEPT the first `numArgRegs` integer
  ## arg registers — they hold live params on entry, and nifasm treats a declared
  ## clobber as clobbered there, so listing them would stop the body/callee reading
  ## its own params.
  var paramRegs: set[Reg] = {}
  for i in 0 ..< min(numArgRegs, g.md.intArgRegs.len): paramRegs.incl g.md.intArgRegs[i]
  g.ab.tree ClobberD:
    for r in x64ClobbersGpr:
      if r notin paramRegs: g.ab.reg r

const X64SyscallArgRegs = [RDI, RSI, RDX, R10, R8, R9]
  ## The x86-64 Linux syscall argument registers. Identical to the C ABI EXCEPT
  ## arg4: the kernel takes it in r10, not rcx (rcx is destroyed by the `syscall`
  ## instruction). Placing it in the syproc's param decl moves the r10 mapping into
  ## nifasm, so arkham marshals args through the normal C-ABI staging registers and
  ## never has to emit a raw r10 (which its scratch-pool guard forbids).

proc emitSyproc(g: var CodeGen; sp: SyscallProc) =
  ## Emit a `(syproc :name (params …) (result …)? (clobber (rcx) (r11)) NR)` decl:
  ## the syscall's proctype with params bound to the syscall ABI registers and the
  ## registers the `syscall` instruction clobbers. It carries the x86-64 number and
  ## emits no code — the inline `(syscall)` marker at each call site reads it.
  var c = sp.decl
  c.into:
    inc c                                        # name
    var pc = c; skip c                           # params slot; c → return type
    g.ab.tree SyprocD:
      g.ab.symDef sp.asmName
      var idx = 0
      g.ab.tree ParamsD:
        if pc.kind == TagLit:                    # (params (param …) …)
          pc.into:
            while pc.hasMore:
              pc.into:                           # (param :name pragmas type)
                inc pc                           # name → positional pN.0
                skip pc                          # pragmas
                if idx >= X64SyscallArgRegs.len:
                  raiseAssert "arkham x64: syscall with more than 6 arguments"
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  g.ab.reg X64SyscallArgRegs[idx]
                  g.genTypeBody(pc)
                while pc.hasMore: skip pc
              inc idx
      g.ab.tree ResultD:                         # c at the return type
        if not retIsVoid(c):
          g.ab.symDef "ret.0"
          g.ab.reg RAX
          g.genTypeBody(c)
      g.ab.tree ClobberD:                        # x86-64 `syscall` destroys rcx, r11
        g.ab.reg RCX
        g.ab.reg R11
      g.ab.intLit sp.sysNr.int64
    while c.hasMore: skip c                       # drain the importc decl's pragmas + body

proc genProctypeSig(g: var CodeGen; c: var Cursor) =
  ## Lower a NIFC `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
  ## signature `(proctype (params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (rax)
  ## T))? (clobber …))` — the SysV ABI assignment, identical in shape to a
  ## declarative proc's signature, so nifasm can resolve an *indirect* `(prepare …)`
  ## call through a function pointer against it. A function pointer is still 8 bytes
  ## (nifasm sizes `ProcT` as a pointer); the signature is metadata for call sites.
  ## Param/result types are emitted BY REFERENCE (`genPointee`) for named types so a
  ## self-referential closure/continuation signature can't recurse forever.
  g.ab.proctypeType:
    c.into:
      skip c                                    # the Empty slot (a proc has its name here)
      # Param/result types BY REFERENCE so a self-referential closure signature
      # can't recurse forever. One reg per param; the clobber spares those regs.
      let numParams = g.emitParamsAndResult(c, byRef = true)
      while c.hasMore: skip c                    # pragmas
      g.emitAbiClobber(numParams)               # mirrors `emitSignature`

proc genTypeBody(g: var CodeGen; c: var Cursor) =
  ## Translate a NIFC type at `c` into asm-NIF, advancing past it. Named types
  ## are inlined; object field pragmas are dropped. v0: int/uint/bool/ptr + objects.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, symName(c))
    d.into:
      inc d; skip d                           # name, type-pragmas
      g.genTypeBody(d)
    inc c
  of TagLit:
    case c.typeKind
    of IT:
      var t = c; inc t
      g.ab.intType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of UT:
      var t = c; inc t
      g.ab.uintType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of CT:
      var t = c; inc t
      g.ab.charType(if t.kind == IntLit: int(intVal(t)) else: 8); skip c
    of FT:
      var t = c; inc t
      g.ab.floatType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of BoolT:
      g.ab.boolType(); skip c
    of VoidT:
      g.ab.voidType(); skip c
    of PtrT:
      g.ab.ptrType:
        c.into: g.genPointee(c)               # pointee (named → by-reference)
    of AptrT:                                 # pointer to (array of) — a scalar ptr
      g.ab.aptrType:
        c.into: g.genPointee(c)               # element type (named → by-reference)
    of FlexarrayT:                            # variable-length array tail (last fld)
      g.ab.flexarrayType:
        c.into: g.genTypeBody(c)              # element type
    of ProctypeT:
      # A function pointer (8 bytes). Emit its full ABI signature — not an opaque
      # `(ptr (void))` — so nifasm can type-check and resolve an indirect call
      # `(prepare <fnptr> … (call))` against it. Recursion through self-referential
      # closure/continuation param types is broken by `genProctypeSig`'s
      # by-reference (`genPointee`) type emission.
      g.genProctypeSig(c)
    of ArrayT:
      c.into:
        g.ab.arrayType:
          g.genTypeBody(c)
          if c.kind == IntLit: (g.ab.intLit intVal(c); inc c)
          else: raiseAssert "arkham x64 v0: array length must be a literal"
    of ObjectT:
      c.into:
        # Inheritance: a Symbol base is emitted by reference (so nifasm resolves
        # it and lays the base out first); a `.` means no base. Keeping the base
        # lets nifasm compute inherited-field offsets — the `(cast (ptr Derived)
        # x).baseField` idiom (Nim's allocator) depends on it.
        var baseName = ""
        if c.kind == Symbol: baseName = symName(c)
        skip c                                # inheritance slot (`.` or base sym)
        g.ab.objectType:
          if baseName.len > 0: g.ab.sym baseName
          while c.hasMore:
            c.into:                           # (fld :name pragmas type)
              let fn = symName(c); inc c
              skip c                          # field pragmas (dropped)
              g.ab.fldDef(fn):
                g.genTypeBody(c)
    of EnumT:                                 # an enum is just its base integer type
      c.into:
        g.genTypeBody(c)                      # (enum <base> (efld …)…) → <base>
        while c.hasMore: skip c               # efld declarations (dropped)
    else:
      raiseAssert "arkham x64 v0: type not supported: " & $c.typeKind
  else:
    raiseAssert "arkham x64 v0: malformed type"

proc genType(g: var CodeGen; name: string; decl: Cursor) =
  ## `(type :name <body>)` — nifasm's stack-slot allocator consults it for field
  ## offsets.
  var c = decl
  c.into:
    inc c                                     # name
    skip c                                    # type-pragmas
    g.ab.tree TypeD:
      g.ab.symDef name
      g.genTypeBody(c)

proc numIncomingArgRegs(g: var CodeGen; decl: Cursor): int =
  ## How many leading integer arg registers carry incoming values: a hidden
  ## result pointer (>16B return) + one per scalar / by-ref-aggregate param + one
  ## per 8-byte word of a ≤16B by-value aggregate param. These hold live values on
  ## entry, so they're excluded from the clobber set (a clobbered register can't
  ## be read — and a named local bound to one would be rejected).
  result = if g.retIndirect: 1 else: 0
  var c = decl
  inc c; inc c                                # head → name → params
  if c.kind != TagLit: return
  c.into:
    while c.hasMore:
      var tn = ""
      c.into:                                 # (param :name pragmas type)
        inc c; skip c                         # name, pragmas
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = symName(c)
        while c.hasMore: skip c
      if tn.len > 0:
        if g.aggrByRef(tn): inc result
        else: result += aggrWordCount(g.prog, tn)
      else: inc result

proc emitSignature(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## `(params)/(result)/(clobber)`. Declarative procs state the SysV register ABI
  ## — positional `p.i` params in rdi/rsi/… and an rax result — so nifasm
  ## cross-checks every call site; the clobber set is always the convention's.
  if declarative:
    var c = decl
    c.into:
      inc c                                   # name → params slot
      discard g.emitParamsAndResult(c, byRef = false)  # types inline (concrete proc)
      while c.hasMore: skip c                 # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  # `numIncomingArgRegs` (not the param *count*) — it accounts for an aggregate
  # spanning several GPRs and a float consuming none.
  g.emitAbiClobber(g.numIncomingArgRegs(decl))

proc emitParamMoves(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## Settle each register-passed parameter into its allocated home. A param the
  ## allocator left in its incoming arg register becomes the named local `p.i`
  ## (x64 refers to a bound register by name); one the allocator relocated to a
  ## callee-saved register (because it lives across a call) is `mov`'d there as a
  ## *raw* register — never a named local, so the epilogue can `pop` that
  ## callee-saved reg without a "kill it first" binding conflict. Stack-passed
  ## params (7th+) are handled by `emitStackParamLoadsX64`.
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # no parameters
  var idx = if g.retIndirect: 1 else: 0       # rdi = hidden result ptr for a >16B return
  var fidx = 0                                # float params consume xmm0–7, not GPRs
  c.into:
    while c.hasMore:
      var nm = ""
      var tn = ""                             # non-empty → an aggregate param type
      var typeCur = c
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        g.symType[nm] = c                     # record the param's type for getType
        typeCur = c
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = symName(c)
        while c.hasMore: skip c
      let loc = g.ra.locationOfSym(nm)
      if tn.len > 0 and loc.kind == NamedStack:
        # ≤16B by-value aggregate: declare its `(s)` home, fill from its GPR word(s).
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        let nw = aggrWordCount(g.prog, tn)
        g.regsToStruct(nm, tn, g.md.intArgRegs[idx ..< idx + nw])
        idx += nw
      elif tn.len > 0 and loc.kind == InReg:
        # >16B by-reference aggregate: a pointer homed like a scalar; field
        # accesses route through it (recorded in varType).
        g.varType[nm] = tn
        g.movReg(loc.r, g.md.intArgRegs[idx])
        inc idx
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming xmm{fidx}; if the
        # allocator gave it a (callee-saved-equivalent) home, move it there. SysV has
        # no callee-saved xmm, so a float crossing a call instead spills (next branch).
        g.fmovF(loc.f, g.md.floatArgRegs[fidx], loc.typ.size * 8)
        inc fidx
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming xmm arg register into it so `addr`/loads/stores work.
        assert fidx < g.md.floatArgRegs.len, "arkham x64 v0: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, g.md.floatArgRegs[fidx], bits)
        inc fidx
      elif idx < g.md.intArgRegs.len:           # register-passed scalar parameter
        let argReg = g.md.intArgRegs[idx]
        if loc.kind == InReg and loc.r == argReg:
          if declarative:
            g.regLocal[argReg] = paramName(idx) # the signature binds it as `pN.0`
            g.aliasToDecl[paramName(idx)] = nm  # so recordEviction recovers the decl name
          else:
            # no signature binding (empty params) → bind the param's own name to
            # its arg register so the body can refer to it by name.
            g.emRegLocalVar(nm, argReg, typeCur)
            g.regLocal[argReg] = nm
        elif loc.kind == InReg:
          # Relocated to a callee-saved home. In the declarative path the signature
          # binds argReg to `pN.0`, so the relocation move must *read* it by name
          # (a raw `(reg)` use of a bound register is rejected); the binding is then
          # killed so the now-dead arg register is free for reuse. The
          # non-declarative path has no binding, so it moves the raw register.
          if declarative:
            g.ab.tree MovX64: (g.emReg loc.r; g.ab.sym paramName(idx))
            g.ab.tree KillX64: g.ab.sym paramName(idx)
          else:
            g.movReg(loc.r, argReg)
        elif loc.kind == NamedStack and loc.typ.kind != AFloat:
          # an address-taken scalar param: declare its `(s)` slot and spill the
          # incoming argument register into it so `addr`/loads/stores work. In the
          # declarative path the arg reg is bound to `pN.0`, so the value must be
          # referenced by that name (a raw `(reg)` is rejected as "bound"); in the
          # non-declarative path there is no binding, so the raw register is used.
          # Type the slot with the param's real type (e.g. a pointer) — a generic
          # `(i 64)` slot would reject the typed store and forbid a later deref.
          g.emTypedStackVar(nm, typeCur)        # (var :nm (s) <param type>)
          g.ab.tree MovX64:
            g.emStackMem(nm)
            if declarative: g.ab.sym paramName(idx) else: g.ab.reg argReg
          # The param now lives in its stack slot; release the arg-register binding
          # so the now-free register can be reused (else a later raw `(reg)` use is
          # rejected as still bound to `pN.0`). Mirrors the relocate branch above.
          if declarative: g.ab.tree KillX64: g.ab.sym paramName(idx)
        else:
          raiseAssert "arkham x64 v0: spilled / float parameter: " & nm
        inc idx
      # else: stack-passed (7th+) — loaded by emitStackParamLoadsX64.

# ── stack frame: callee-saved save/restore + incoming stack parameters ───────
# x86-64 has no pair store, so each used callee-saved GPR is a single `push`/`pop`.
# Frames are needed when the proc uses a callee-saved register (for a cross-call
# local or a stack-param home). Saved registers stay RAW (`(rbx)`), never named
# locals, so the epilogue can pop them without nifasm's bound-register guard.

proc computeFrameX64(g: var CodeGen; isEntry, hasCall: bool) =
  g.frameRegs = @[]
  for r in g.md.intCalleeSaved:
    if r in g.ra.usedCallee: g.frameRegs.add r
  # SysV requires rsp ≡ 0 (mod 16) at a `call`. The kernel enters the entry with
  # rsp ≡ 0; a normal callee is entered with rsp ≡ 8 (the caller's pushed return
  # address). Each saved reg is 8 bytes, so after the pushes the parity may be
  # wrong — pad with an extra 8 when this proc itself makes a call.
  g.framePad = 0
  if hasCall:
    let entryBias = if isEntry: 0 else: 8
    if (entryBias + 8 * g.frameRegs.len) mod 16 != 0: g.framePad = 8
  g.hasFrame = g.frameRegs.len > 0 or g.framePad > 0

proc framePushBytesX64(g: CodeGen): int =
  ## Bytes between the current rsp (after the callee-saved pushes, before the pad)
  ## and the caller's first stack argument: the return address (8) plus each saved
  ## register (8). Used to address incoming stack params.
  8 + 8 * g.frameRegs.len

proc framePush(g: var CodeGen) =
  for r in g.frameRegs:
    g.ab.tree PushX64: g.ab.reg r                          # raw push

proc killFrameRegLocals(g: var CodeGen) =
  ## Before an explicit-`ret` `framePop`, release any register-local bound to a
  ## callee-saved register the epilogue is about to `pop` raw — nifasm forbids a
  ## raw use of a still-bound register, and at a return every local is dead. The
  ## binding is dropped so the trailing `exitScope` does not double-kill it.
  ## (A second `ret` reached on another path that needs the same callee register
  ## bound is the pre-existing multi-`ret` limitation — out of scope here.)
  for r in g.frameRegs:
    if g.regLocal.hasKey(r):
      g.ab.tree KillX64: g.ab.sym g.regLocal[r]
      g.regLocal.del r

proc framePop(g: var CodeGen) =
  # Release the nifasm-managed `(s)` slot region first (reverse of the prologue,
  # which lowered rsp by the pad then the `(ssize)` block), then the alignment pad
  # and the callee-saved registers.
  if g.ra.hasStackVars:
    g.ab.tree AddX64: g.ab.reg RSP; g.ab.keyword SsizeX
  if g.framePad > 0: g.binImm(AddX64, RSP, g.framePad.int64)
  for i in countdown(g.frameRegs.high, 0):
    g.ab.tree PopX64: g.ab.reg g.frameRegs[i]             # raw pop, reverse order

proc emitStackParamLoadsX64(g: var CodeGen; decl: Cursor) =
  ## Load the 7th+ integer/pointer parameters from the caller's outgoing argument
  ## area into their allocated (callee-saved) register homes. Emitted right after
  ## `framePush` and before the alignment pad, so each arg sits at the statically
  ## known offset `framePushBytes + k*8` from the current rsp.
  var c = decl
  inc c; inc c                                # → params slot
  if c.kind != TagLit: return
  let base = g.framePushBytesX64()
  var idx = 0
  var stackOrd = 0
  c.into:
    while c.hasMore:
      var nm = ""
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c
        while c.hasMore: skip c
      if idx >= g.md.intArgRegs.len:
        let loc = g.ra.locationOfSym(nm)
        assert loc.kind == InReg,
          "arkham x64 v0: stack parameter without a register home: " & nm
        g.ab.tree MovX64:                     # home ← [rsp + base + stackOrd*8]
          g.emReg loc.r                       # raw callee-saved reg
          g.ab.tree MemX:
            g.ab.reg RSP
            g.ab.intLit (base + stackOrd * 8)
        inc stackOrd
      inc idx

# ── thread-local storage ─────────────────────────────────────────────────────
# nifasm accesses an x86-64 thread-local as `FS:[off]` (it resolves a tvar symbol
# to a displacement-only FS-segment memory operand). nifasm (the linker) owns the
# unified per-thread block `arkham.tls.0` across all bundled modules and points FS
# at it via `arch_prctl(ARCH_SET_FS, &block)` in the entry prologue it synthesizes;
# arkham only references the block for `&tvar`. Nim thread-locals have no
# initializers, so the block is plain zeroed `.bss`.

proc genTvar(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(tvar :name <type> <intlit>?)`. nifasm allocates the FS offset; the
  ## optional literal is carried (parsed but unused on x64 — `emitTlsSetup` stores
  ## non-zero initializers at runtime since `.bss` defaults to zero).
  var c = decl
  c.into:                                         # (tvar SymbolDef VarPragmas Type Value?)
    inc c; skip c                                 # name, pragmas
    g.ab.open NifasmDecl.TvarD
    g.ab.symDef name
    g.genTypeBody(c)                              # type
    if c.kind == IntLit:
      g.ab.intLit intVal(c)
    elif c.kind != DotToken:
      raiseAssert "arkham x64: thread-local initializer must be an integer literal: " & name
    g.ab.close()
    while c.hasMore: skip c


proc emitProcBody(g: var CodeGen; info: ProcInfo; declarative: bool) =
  ## Emit one proc's `(proc …)` (signature + body). Run twice by `genProc`: once
  ## in planning mode (emission suppressed, scratch decisions recorded), once for
  ## real (decisions replayed). Reads the per-proc `ret*`/frame state set up by
  ## `genProc`; touches only state `genProc` resets between the two passes.
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsX64:
      g.enterScope()                          # the proc body's scope
      g.framePush()                           # save the used callee-saved GPRs
      g.emitStackParamLoadsX64(info.decl)      # incoming 7th+ args → their reg homes
      if g.framePad > 0:                      # 16-byte alignment for outgoing calls
        g.binImm(SubX64, RSP, g.framePad.int64)
      if g.ra.hasStackVars:                   # reserve nifasm-managed `(s)` slots so
        g.ab.tree SubX64: g.ab.reg RSP; g.ab.keyword SsizeX  # they sit above rsp (call-safe)
      if g.retIndirect: g.movReg(g.indirectReg, RDI)   # park the hidden result ptr
      g.emitParamMoves(info.decl, declarative)         # settle register params
      # The thread-local FS base is set up by nifasm (the linker owns the unified
      # `arkham.tls.0` block across all bundled modules); see the entry prologue it
      # synthesizes. arkham just references the block for `&tvar` / `FS:[off]`.
      if info.isEntry: g.emitGlobalInits()    # run module-level var initializers
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c         # name, params, return type, pragmas
        if c.stmtKind == StmtsS:
          genStmt(g, c)
      g.exitScope()                           # `kill` the proc's register locals
      # Fallthrough terminator: the entry exits the process; a normal proc
      # restores its frame and returns.
      if info.isEntry:
        g.movImm(RAX, 60); g.movImm(RDI, 0); g.emSyscall()
      else:
        g.framePop()
        g.ab.keyword RetX64

# ── value-core rewrite: the PURE emitter (consumes precomputed locs/aux) ───────
# Single-pass: the register allocator (allocExprs=true) has already assigned every
# value position a Location in `g.ra.locs` (+ `aux`); this code only emits bytes,
# making NO register decisions — so there is no plan/replay seam. See
# `codegen2_design.md`. Coverage so far: leaf integer procs (params/locals/ret,
# integer leaves + binary arithmetic). A proc that uses anything else routes to the
# legacy reactive `emitProcBody` (per-proc opt-in via `procModeled2`). As coverage
# grows the legacy path shrinks, then deletes.

proc valModeled2(g: var CodeGen; c: Cursor): bool
proc fvalModeled2(g: var CodeGen; c: Cursor): bool
proc lvalModeled2(g: var CodeGen; c: Cursor): bool =
  ## Is lvalue `c` an addressing target the v1 slice can emit (a load / store / addr)?
  ## A function-local base symbol (stack var or reg pointer), a `dot` field over such
  ## a base or a `deref`, or a pointer `deref` of a modeled value. (at/pat: later.)
  case c.kind
  of Symbol: g.lookupSym(symName(c)).cat == scNone     # a function-local base
  of TagLit:
    case c.exprKind
    of DotC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore: (if not g.lvalModeled2(cc): ok = false); skip cc   # base
        while cc.hasMore: skip cc
      ok
    of DerefC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc    # pointer
        while cc.hasMore: skip cc
      ok
    of AtC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore: (if not g.lvalModeled2(cc): ok = false); skip cc   # array base
        if cc.hasMore:
          if cc.kind notin {IntLit, UIntLit}:                            # register index
            if not g.valModeled2(cc): ok = false
            elif g.atNeedsScratch(c): ok = false                         # non-pow2 stride: later slice
          skip cc
        while cc.hasMore: skip cc
      ok
    of PatC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc    # pointer
        if cc.hasMore:
          if cc.kind notin {IntLit, UIntLit}:                            # register index
            if not g.valModeled2(cc): ok = false
            elif g.atNeedsScratch(c): ok = false                         # non-pow2 stride: later slice
          skip cc
        while cc.hasMore: skip cc
      ok
    else: false
  else: false

proc valModeled2(g: var CodeGen; c: Cursor): bool =
  ## Is value `c` within the new emitter's coverage? (Reads a copy; consumes nothing.)
  case c.kind
  of IntLit, UIntLit, CharLit, StrLit: true
  of Symbol: g.lookupSym(symName(c)).cat in {scNone, scGlobal, scTvar}  # local or global read (not proc)
  of TagLit:
    case c.exprKind
    of TrueC, FalseC, NilC, SizeofC: true              # compile-time / immediate leaves
    of NegC, BitnotC, SufC, ParC:                      # unary in-place / wrapper
      var ok = true
      var cc = c
      cc.into:
        if c.exprKind in {NegC, BitnotC}: skip cc       # result type
        if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc
        while cc.hasMore: skip cc
      ok
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      var ok = true
      var cc = c
      cc.into:
        skip cc                                          # result type
        if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc   # lhs
        if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc   # rhs
        while cc.hasMore: skip cc
      ok
    of DerefC, DotC, AtC, PatC: g.lvalModeled2(c)       # addressing read: load [addr]
    of AddrC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore:
          if cc.kind == Symbol and g.lookupSym(symName(cc)).cat == scGlobal:
            discard                                       # &global → RIP-relative lea
          elif not g.lvalModeled2(cc): ok = false
        while cc.hasMore: skip cc
      ok
    of CastC, ConvC:
      # int↔int (widen/narrow), ptr↔ptr (reinterpret), or a FLOAT→int `conv`
      # (cvttsd2si). A float TARGET is the float family (fvalModeled2); a float→int
      # `cast` (movq) and MIXED int↔ptr need legacy — gated out so the new path never
      # miscompiles a type.
      var ok = true
      var cc = c
      cc.into:
        let tgtPtr = isPtrType(resolveType(g.prog, cc))
        let tgtFloat = slotOf(g.prog, cc).kind == AFloat
        skip cc                                                 # target type
        if tgtFloat: ok = false                                 # float TARGET → fvalModeled2
        elif cc.hasMore:
          if g.isFloatExpr(cc):
            # float SOURCE → int target: `conv` = cvttsd2si (NEW); a `cast` (movq) or a
            # pointer target are deferred to legacy.
            if c.exprKind != ConvC or tgtPtr: ok = false
            elif not g.fvalModeled2(cc): ok = false
          elif isPtrType(resolveType(g.prog, g.getType(cc))) != tgtPtr: ok = false  # int↔ptr: later
          elif not g.valModeled2(cc): ok = false
          skip cc
        while cc.hasMore: skip cc
      ok
    else: false
  else: false

proc fvalModeled2(g: var CodeGen; c: Cursor): bool =
  ## A FLOAT value the new emitter handles (slice 1): a float literal, a float
  ## local/param read (in an xmm register — a spilled float bails via
  ## `exprUnsupported` at allocation), or a float add/sub/mul/div over modeled
  ## float operands. A float global / nested call / conversion is still legacy.
  case c.kind
  of FloatLit: true
  of Symbol: g.lookupSym(symName(c)).cat == scNone        # a function-local float
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC:
      var ok = true
      var cc = c
      cc.into:
        skip cc                                           # result float type
        if cc.hasMore: (if not g.fvalModeled2(cc): ok = false); skip cc   # lhs
        if cc.hasMore: (if not g.fvalModeled2(cc): ok = false); skip cc   # rhs
        while cc.hasMore: skip cc
      ok
    of ConvC:
      # conversion TO float: an INT source is cvtsi2sd (NEW). A float source (precision
      # convert) and a `cast` bit-reinterpret are deferred to legacy.
      var ok = true
      var cc = c
      cc.into:
        skip cc                                  # target float type
        if cc.hasMore:
          if g.isFloatExpr(cc): ok = false       # float→float precision: later
          elif not g.valModeled2(cc): ok = false # int→float
          skip cc
        while cc.hasMore: skip cc
      ok
    of SufC, ParC:
      var ok = true
      var cc = c
      cc.into:
        if cc.hasMore: (if not g.fvalModeled2(cc): ok = false); skip cc
        while cc.hasMore: skip cc
      ok
    else: false
  else: false

proc callModeled2(g: var CodeGen; c: Cursor): bool =
  ## Is this `(call …)` within the new emitter's coverage? A declarative direct or
  ## syscall target (NOT indirect / atomic / mem* / bit-builtin), a scalar-or-void
  ## result, and ≤(#arg regs) scalar args with no nested call (`valModeled2` rejects
  ## CallC, so an arg cannot itself be a call ⇒ nothing lives across the call).
  if c.kind != TagLit or c.exprKind != CallC: return false
  var ok = true
  var fc = c
  fc.into:
    if fc.kind != Symbol:
      ok = false
    else:
      let fsym = symName(fc); inc fc
      if not g.callTarget.hasKey(fsym):                  # resolve + cache (mirrors genCall)
        let si = g.lookupSym(fsym)
        if si.cat in {scGlobal, scTvar}:
          g.callTarget[fsym] = CallTarget(declarative: true, indirect: true,
            asmName: fsym, retType: g.indirectRetType(si.decl))
        else:
          g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
      let tgt = g.callTarget[fsym]
      if not (tgt.declarative and not tgt.extern and tgt.atomic.len == 0 and
              tgt.memIntrin.len == 0 and tgt.bitBuiltin.len == 0 and not tgt.indirect):
        ok = false
      if (not retIsVoid(tgt.retType)) and
         slotOf(g.prog, tgt.retType).kind notin {AInt, AUInt, ABool}:
        ok = false                                       # float / aggregate result: v1 gap
      var argc = 0
      while fc.hasMore:
        if not g.valModeled2(fc): ok = false             # scalar-int args, no nested call
        inc argc; skip fc
      if argc > g.md.intArgRegs.len: ok = false          # 7th+ (stack) args: v1 gap
  ok

proc smallCmpImm(c: Cursor): bool =
  ## A comparison operand the `cmp` emitter can fold inline without a scratch
  ## register — a small non-negative immediate (or any non-immediate operand,
  ## which folds as a register / memory). A wide/negative immediate would need a
  ## pre-load the v1 allocator does not reserve, so it bails the proc to legacy.
  case c.kind
  of IntLit: (let v = intVal(c); v >= 0 and v <= 0xFFFF)
  of UIntLit: (let v = cast[int64](uintVal(c)); v >= 0 and v <= 0xFFFF)
  else: true

proc caseBranchValSmall(c: Cursor): bool =
  ## A `case` BranchValue the new emitter's range tests can fold into `cmp` without a
  ## scratch register — a small non-negative integer/char literal (same window as
  ## `smallCmpImm`). Symbol enum consts / wrapped forms bail the proc to legacy.
  case c.kind
  of IntLit: (let v = intVal(c); v >= 0 and v <= 0xFFFF)
  of UIntLit: (let v = cast[int64](uintVal(c)); v >= 0 and v <= 0xFFFF)
  of CharLit: (let v = int64(ord(charLit(c))); v >= 0 and v <= 0xFFFF)
  else: false

proc caseRangeModeled(c: Cursor): bool =
  ## A BranchRange of a `case` `of`: `(range lo hi)` of small literals, or a single
  ## small literal. (Avoids `branchImm`, which asserts on unsupported forms.)
  if c.kind == TagLit and c.substructureKind == RangeU:
    var ok = true
    var cc = c
    cc.into:
      while cc.hasMore:
        if not caseBranchValSmall(cc): ok = false
        skip cc
    ok
  else: caseBranchValSmall(c)

proc condModeled2(g: var CodeGen; c: Cursor): bool =
  ## A branch condition the new emitter handles: a comparison (`eq`/`neq`/`lt`/`le`)
  ## over modeled, fold-able operands; an `and`/`or`/`not` short-circuit tree over
  ## modeled sub-conditions; or a plain modeled boolean value.
  if c.kind == TagLit:
    case c.exprKind
    of EqC, NeqC, LtC, LeC:
      var ok = true
      var cc = c
      var isFloat = false
      block:
        var fc = c
        fc.into:
          isFloat = fc.hasMore and g.isFloatExpr(fc)
          while fc.hasMore: skip fc
      cc.into:
        if isFloat:                                       # float compare → comisd, no imm fold
          if cc.hasMore: (if not g.fvalModeled2(cc): ok = false); skip cc
          if cc.hasMore: (if not g.fvalModeled2(cc): ok = false); skip cc
        else:
          if cc.hasMore:
            if not (g.valModeled2(cc) and smallCmpImm(cc)): ok = false
            skip cc
          if cc.hasMore:
            if not (g.valModeled2(cc) and smallCmpImm(cc)): ok = false
            skip cc
        while cc.hasMore: skip cc
      return ok
    of AndC, OrC, NotC:
      var ok = true
      var cc = c
      cc.into:
        while cc.hasMore:
          if not g.condModeled2(cc): ok = false
          skip cc
      return ok
    else: discard
  g.valModeled2(c)

proc divModModeled2(g: var CodeGen; c: Cursor): bool =
  ## A `(div|mod T a b)` the new emitter handles: integer operands that are
  ## themselves modeled and not a nested div / call — so rax/rdx stay single-use
  ## (no value live across the idiv). The allocator additionally bails (to legacy)
  ## when rdx is a live parameter home (`divRemOccupied`).
  if c.kind != TagLit or c.exprKind notin {DivC, ModC}: return false
  var ok = true
  var cc = c
  cc.into:
    skip cc                                             # result type
    if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc
    if cc.hasMore: (if not g.valModeled2(cc): ok = false); skip cc
    while cc.hasMore: skip cc
  ok

proc stmtModeled2(g: var CodeGen; c: Cursor): bool =
  case c.stmtKind
  of StmtsS, ScopeS:
    var ok = true
    var cc = c
    cc.into:
      while cc.hasMore:
        if not g.stmtModeled2(cc): ok = false
        skip cc
    ok
  of VarS:
    var ok = true
    var cc = c
    cc.into:
      skip cc; skip cc                                   # name, pragmas
      let s = slotOf(g.prog, cc)
      skip cc                                            # type
      let hasInit = cc.hasMore and cc.kind != DotToken
      if s.kind == AFloat:
        # A float local (slice 1): its register home receives a modeled float init;
        # a spilled float home routes to legacy via `exprUnsupported` at allocation.
        if hasInit and not g.fvalModeled2(cc): ok = false
      elif s.kind == AMem:
        if hasInit: ok = false                           # aggregate initializer: later slice
      elif not s.inRegClass: ok = false
      elif ok and hasInit:
        # var-init is alias-safe for a comparison-as-value (a fresh home can't be an
        # operand) so `condModeled2` is allowed here, but NOT in asgn-rhs / call-args.
        if not (g.valModeled2(cc) or g.callModeled2(cc) or g.divModModeled2(cc) or
                g.condModeled2(cc)): ok = false
      while cc.hasMore: skip cc
    ok
  of RetS:
    var ok = true
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isFloatExpr(cc):
          if not g.fvalModeled2(cc): ok = false          # float return → xmm0
        elif not (g.valModeled2(cc) or g.callModeled2(cc) or g.divModModeled2(cc) or
                g.condModeled2(cc)): ok = false           # ret value: rax never an operand
      while cc.hasMore: skip cc
    ok
  of CallS: g.callModeled2(c)
  of AsgnS:
    var ok = true
    var floatLhs = false
    var cc = c
    cc.into:
      if cc.kind == Symbol:
        if g.lookupSym(symName(cc)).cat notin {scNone, scGlobal, scTvar}: ok = false  # local or global store
        elif g.isFloatExpr(cc):
          # A float store: only a LOCAL float (a float global store is a later slice).
          if g.lookupSym(symName(cc)).cat != scNone: ok = false
          else: floatLhs = true
      elif not g.lvalModeled2(cc): ok = false           # complex lvalue (dot/deref store)
      skip cc                                            # lhs
      if cc.hasMore:
        if floatLhs:
          if not g.fvalModeled2(cc): ok = false
        elif not (g.valModeled2(cc) or g.callModeled2(cc) or g.divModModeled2(cc)): ok = false
      while cc.hasMore: skip cc
    ok
  of WhileS:
    var ok = true
    var cc = c
    cc.into:
      if cc.hasMore:
        if not g.condModeled2(cc): ok = false
        skip cc
      while cc.hasMore:
        if not g.stmtModeled2(cc): ok = false
        skip cc
    ok
  of IfS:
    var ok = true
    var cc = c
    cc.into:
      while cc.hasMore:
        case cc.substructureKind
        of ElifU:
          var bc = cc
          bc.into:
            if bc.hasMore:
              if not g.condModeled2(bc): ok = false
              skip bc
            while bc.hasMore:
              if not g.stmtModeled2(bc): ok = false
              skip bc
        of ElseU:
          var bc = cc
          bc.into:
            while bc.hasMore:
              if not g.stmtModeled2(bc): ok = false
              skip bc
        else: ok = false
        skip cc
    ok
  of BreakS: true                                       # a jump to the loop-exit label
  of CaseS:
    var ok = true
    var cc = c
    cc.into:
      if cc.hasMore:                                     # selector
        if not g.valModeled2(cc): ok = false
        skip cc
      while cc.hasMore:
        case cc.substructureKind
        of OfU:
          var branch = cc
          branch.into:
            if branch.substructureKind == RangesU:
              var ranges = branch
              ranges.into:
                while ranges.hasMore:
                  if not caseRangeModeled(ranges): ok = false   # small-imm bounds only
                  skip ranges
            else: ok = false
            skip branch                                  # past (ranges …)
            while branch.hasMore:
              if not g.stmtModeled2(branch): ok = false  # branch body
              skip branch
        of ElseU:
          var eb = cc
          eb.into:
            while eb.hasMore:
              if not g.stmtModeled2(eb): ok = false
              skip eb
        else: ok = false
        skip cc
    ok
  else: false

proc procModeled2(g: var CodeGen; decl: Cursor): bool =
  ## Conservative: the new emitter handles this whole proc (scalar-int params, a
  ## scalar-int/void return, and a body of var/ret over integer arithmetic).
  var ok = true
  var c = decl
  c.into:
    inc c                                                # name
    if c.kind == TagLit:                                 # (params …)
      var p = c
      p.into:
        while p.hasMore:
          var pp = p
          pp.into:
            skip pp; skip pp                             # name, pragmas
            let s = slotOf(g.prog, pp)
            # A float param is allowed (slice 1): in a leaf proc it stays in its xmm
            # arg register; if it spills (non-leaf / address-taken) the body's read
            # routes the proc to legacy via `exprUnsupported`.
            if s.kind == AMem or not s.inRegClass: ok = false
            while pp.hasMore: skip pp
          skip p
    skip c                                               # params
    if not (c.kind == DotToken or
            (c.kind == TagLit and c.typeKind in {NifcType.IT, NifcType.UT, NifcType.CT, NifcType.FT})):
      ok = false                                         # scalar-int / float / void return only
    skip c                                               # return type
    skip c                                               # pragmas
    if ok:
      ok = (c.stmtKind == StmtsS) and g.stmtModeled2(c)
    while c.hasMore: skip c
  result = ok

proc place2(g: var CodeGen; src: Location; dest: Reg) =
  ## Materialize `src` into register `dest` (no-op when it is already there).
  case src.kind
  of InReg: (if src.r != dest: g.movReg(dest, src.r))
  of Imm: g.movImm(dest, src.ival)
  of NamedStack, Mem, Glob, Tvar: g.emitLoadLoc(src, dest)
  else: raiseAssert "arkham x64n: place2 src " & $src.kind

proc emitValue2(g: var CodeGen; c: Cursor)
proc emitFValue2(g: var CodeGen; c: Cursor)
proc emitFMemLoad2(g: var CodeGen; c: Cursor)
proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitCondValue2(g: var CodeGen; c: Cursor)
proc emitMemLoad2(g: var CodeGen; c: Cursor)
proc emitAddr2(g: var CodeGen; c: Cursor)
proc emitCast2(g: var CodeGen; c: Cursor)
proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor)

proc emitBin2(g: var CodeGen; c: Cursor) =
  ## Emit a binary-arith node into its precomputed result register, replaying the
  ## allocator's operand placement (`aux.foldB` ⇒ the rhs stays a memory operand).
  let pos = cursorToPosition(g.buf[], c)
  let res = g.ra.locs[pos]
  let (op, immOk, isBin) = binArithOp(c)
  assert isBin, "arkham x64n: emitBin2 on a non-bin node"
  var lhsC, rhsC: Cursor
  block:
    var cc = c
    cc.into:
      skip cc                                            # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let aux = g.ra.aux.getOrDefault(pos)
  if aux.swapped:
    # Sethi–Ullman: the rhs was evaluated first into the result register; the leaf
    # lhs folds after. Commutative → `dest op= lhs`; `sub` → `neg dest; dest += lhs`
    # (`a - b == -(b) + a`, with `b` already in dest).
    assert res.kind == InReg, "arkham x64n: bin(swapped) result " & $res.kind
    let rD = res.r
    g.emitValue2(rhsC)                                   # rhs → rD (it binds rD if a temp)
    let lhsLoc = g.ra.locs[cursorToPosition(g.buf[], lhsC)]
    let foldOp = if op == SubX64: AddX64 else: op        # sub folds as add (after neg)
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # rD := -rhs
    case lhsLoc.kind                                     # rD := rD <foldOp> lhs
    of Imm: g.binImm(foldOp, rD, lhsLoc.ival)
    of InReg: g.binReg(foldOp, rD, lhsLoc.r)
    of NamedStack: g.binMem(foldOp, rD, lhsLoc)          # spilled scalar slot (no access chain)
    of Mem: g.binMemLval2(foldOp, rD, lhsC)              # folded memory load: op rD, [addr]
    else: raiseAssert "arkham x64n: bin(swapped) lhs " & $lhsLoc.kind
    return
  g.emitValue2(lhsC)                                     # materialize sub-results first
  g.emitValue2(rhsC)
  let lhsLoc = g.ra.locs[cursorToPosition(g.buf[], lhsC)]
  let rhsLoc = g.ra.locs[cursorToPosition(g.buf[], rhsC)]
  assert res.kind == InReg, "arkham x64n: bin result " & $res.kind
  let rD = res.r
  let reusedLhs = lhsLoc.kind == InReg and lhsLoc.r == rD   # in-place RMW on the left temp
  if res.isTemp and not reusedLhs: g.bindTemp(rD, res.typ)
  let aliasRhs = aux.aliasRhs
  if aliasRhs:
    # `dest` already holds the rhs value (it aliases the rhs register). A commutative
    # op folds straight in (`dest op= lhs`); `sub` computes `dest -= lhs` then negates.
    assert lhsLoc.kind == InReg, "arkham x64n: aliasRhs lhs " & $lhsLoc.kind
    g.binReg(op, rD, lhsLoc.r)                           # dest := rhs op lhs
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # dest := lhs - rhs
  else:
    g.place2(lhsLoc, rD)                                 # dest := lhs
    case rhsLoc.kind                                     # dest op= rhs
    of Imm: g.binImm(op, rD, rhsLoc.ival)
    of InReg: g.binReg(op, rD, rhsLoc.r)
    of NamedStack, Mem: g.binMem(op, rD, rhsLoc)
    else: raiseAssert "arkham x64n: bin rhs " & $rhsLoc.kind
  if rhsLoc.kind == InReg and rhsLoc.isTemp: g.unbindTemp(rhsLoc.r)
  if lhsLoc.kind == InReg and lhsLoc.isTemp and not reusedLhs: g.unbindTemp(lhsLoc.r)

proc emitMemIntrin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core `mem*` intrinsic: allocCall placed the 3 args in rdi/rsi/rdx (a
  ## normal int-arg call), so just emit them, bind the loop scratch (rsi/rdx/rcx),
  ## and run the shared inline loop. Result → rax (moved to its home by emitCall2).
  let s = AsmSlot(cls: AInt, size: 8, align: 8)
  for idx in 0 ..< min(3, argCurs.len):
    g.emitValue2(argCurs[idx])                  # → rdi / rsi / rdx
  g.bindTemp(RSI, s); g.bindTemp(RDX, s); g.bindTemp(RCX, s)
  g.genMemIntrinBody(builtin)

proc emitAtomic2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core `__atomic_*` builtin: allocCall placed the args in the ABI integer
  ## registers (ptr→rdi, val/exp→rsi, des→rdx, …), so emit them, then the inline
  ## lock-prefixed sequence using those registers (the register-parameterized
  ## `genAtomicXadd`/`genAtomicLoopRmw` helpers, shared with the legacy path).
  ## Result → rax (moved to its home by emitCall2). Pointer args stay raw ABI regs.
  for a in argCurs: g.emitValue2(a)                  # → rdi / rsi / rdx / …
  case builtin
  of "__atomic_load_n":                              # (ptr, mo) → *ptr
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt RDI)
  of "__atomic_store_n":                             # (ptr, val, mo) → void
    g.ab.tree MovX64: (g.emMemAt RDI; g.emReg RSI)
  of "__atomic_fetch_add": g.genAtomicXadd(RDI, RSI, returnNew = false, sub = false)
  of "__atomic_fetch_sub": g.genAtomicXadd(RDI, RSI, returnNew = false, sub = true)
  of "__atomic_add_fetch": g.genAtomicXadd(RDI, RSI, returnNew = true, sub = false)
  of "__atomic_sub_fetch": g.genAtomicXadd(RDI, RSI, returnNew = true, sub = true)
  of "__atomic_fetch_and": g.genAtomicLoopRmw(RDI, RSI, AndX64)
  of "__atomic_fetch_or":  g.genAtomicLoopRmw(RDI, RSI, OrX64)
  of "__atomic_fetch_xor": g.genAtomicLoopRmw(RDI, RSI, XorX64)
  of "__atomic_exchange_n":                          # (ptr, val, mo) → old
    g.ab.tree XchgX64: (g.emMemAt RDI; g.emReg RSI)  # rsi ↔ [rdi] (locked); rsi ← old
    g.movReg(RAX, RSI)
  of "__atomic_thread_fence": g.ab.keyword MfenceX64
  of "__atomic_signal_fence": discard                # compiler barrier only
  of "__atomic_compare_exchange_n":                  # (ptr, exp_ptr, des, weak, succ, fail) → bool
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt RSI)   # rax = *exp (the comparand)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt RDI
        g.emReg RDX                                  # if [rdi]==rax: [rdi]=rdx,ZF=1 else rax=[rdi]
    let lFail = g.freshLabel()
    let lDone = g.freshLabel()
    g.emJcc(JneX64, lFail)
    g.movImm(RAX, 1); g.emJmp(lDone)                 # success → 1
    g.emLab(lFail)
    g.ab.tree MovX64: (g.emMemAt RSI; g.emReg RAX)   # *exp = actual old value (rax)
    g.movImm(RAX, 0)                                 # failure → 0
    g.emLab(lDone)
  else:
    raiseAssert "arkham x64n: unsupported atomic builtin: " & builtin

proc emitCall2(g: var CodeGen; c: Cursor) =
  ## Emit a call. The allocator placed each argument in its ABI register (integer →
  ## rdi…r9, float → xmm0–7) and the result in rax / xmm0 (or a dest-passed home).
  ## Two ABIs: the DECLARATIVE one (all-scalar-int params) binds each arg via
  ## `(arg pN)` inside the prepare and reads `(res ret.0)`; the NON-DECLARATIVE one
  ## (float param/return — and later aggregates) evaluates args into raw ABI registers
  ## and emits a bare `(prepare f (call))`, reading the result from rax / xmm0 raw.
  let pos = cursorToPosition(g.buf[], c)
  let resLoc = g.ra.locs[pos]
  var argCurs: seq[Cursor] = @[]
  var fsym = ""
  block:
    var fc = c
    fc.into:
      fsym = symName(fc); inc fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  if not g.callTarget.hasKey(fsym):                 # resolve + cache (post-flip: no gate prepass)
    let si = g.lookupSym(fsym)
    if si.cat in {scGlobal, scTvar}:
      g.callTarget[fsym] = CallTarget(declarative: true, indirect: true,
        asmName: fsym, retType: g.indirectRetType(si.decl))
    else:
      g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
  let tgt = g.callTarget[fsym]
  if tgt.memIntrin.len > 0:                          # C mem* intrinsic → inline loop
    g.emitMemIntrin2(argCurs, tgt.memIntrin)
    if resLoc.kind == InReg and resLoc.r != RAX: g.movReg(resLoc.r, RAX)
    return
  if tgt.atomic.len > 0:                             # __atomic_* builtin → inline sequence
    g.emitAtomic2(argCurs, tgt.atomic)
    if resLoc.kind == InReg and resLoc.r != RAX: g.movReg(resLoc.r, RAX)
    return
  let isSyscall = tgt.syscall
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: AsmSlot(cls: AInt, size: 8, align: 8)
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let resultByRef = hasResult and resSlot.kind == AMem and resSlot.size > g.md.aggrByRefThreshold
  if tgt.declarative:
    g.ab.tree PrepareX64:
      g.ab.sym tgt.asmName
      for idx in 0 ..< argCurs.len:
        g.emitValue2(argCurs[idx])                  # compute into its arg reg / a scratch
        let aloc = g.ra.locs[cursorToPosition(g.buf[], argCurs[idx])]
        if idx < g.md.intArgRegs.len:                # register arg → rdi…r9
          g.ab.tree MovX64:
            g.ab.tree ArgX: g.ab.sym paramName(idx)
            g.emReg aloc.r
        else:                                        # 7th+ stack arg → (mem (rsp) (arg pN))
          g.ab.tree MovX64:                          #   (its value is in a scratch temp,
            g.ab.tree MemX:                          #    bound by emitValue2 — we unbind it)
              g.ab.reg RSP
              g.ab.tree ArgX: g.ab.sym paramName(idx)
            g.emReg aloc.r
          if aloc.kind == InReg and aloc.isTemp: g.unbindTemp(aloc.r)
      if isSyscall: g.emSyscall()
      else: g.ab.keyword CallX64
      if hasResult:
        g.ab.tree MovX64:
          g.emReg RAX
          g.ab.tree ResX: g.ab.sym "ret.0"
    if hasResult and resLoc.kind == InReg and resLoc.r != RAX:
      g.movReg(resLoc.r, RAX)
  else:
    # Non-declarative: each arg is evaluated straight into its raw ABI register (float →
    # xmm{n}, integer → the GPR); an aggregate arg is marshalled into consecutive GPRs
    # (by-value ≤16B) or passed as a pointer (by-ref). The intIdx/fIdx counting mirrors
    # allocCall so an aggregate's register range matches. (No reactive sealing; like the
    # declarative path this relies on hexer's un-nesting leaving args simple.)
    var intIdx = if resultByRef: 1 else: 0               # rdi = hidden result ptr (set by the caller)
    for idx in 0 ..< argCurs.len:
      let a = argCurs[idx]
      var aggrSz = -1
      if a.kind == Symbol:
        let h = g.ra.locationOfSym(symName(a))
        if h.kind == NamedStack and h.typ.kind == AMem: aggrSz = h.typ.size
      if aggrSz >= 0:
        let tn = g.varType[symName(a)]
        if aggrSz <= g.md.aggrByRefThreshold:             # by-value: words → GPRs
          let words = (aggrSz + 7) div 8
          g.structToRegs(symName(a), tn, g.md.intArgRegs[intIdx ..< intIdx + words])
          intIdx += words
        else:                                             # by-reference: &arg → one GPR
          g.emStackAddr(g.md.intArgRegs[intIdx], symName(a))
          inc intIdx
      elif g.isFloatExpr(a):
        g.emitValue2(a)                                   # → its xmm arg register
      else:
        g.emitValue2(a)                                   # → its GPR arg register
        inc intIdx
    g.ab.tree PrepareX64:
      g.ab.sym tgt.asmName
      if isSyscall: g.emSyscall()
      else: g.ab.keyword CallX64
    if hasResult:
      if resultIsFloat:
        if resLoc.kind == InFReg:
          if resLoc.isTemp: g.bindFTmp(resLoc.f)
          if resLoc.f != FloatRet:
            g.fmovF(resLoc.f, FloatRet, (if resLoc.typ.size == 4: 32 else: 64))
      elif resLoc.kind == InReg and resLoc.r != RAX:
        g.movReg(resLoc.r, RAX)

proc emitDivMod2(g: var CodeGen; c: Cursor) =
  ## Emit x86 `idiv`/`div`: the allocator pinned the dividend to rax and the divisor
  ## to a register; nifasm's `(idiv|div (rdx)(rax) src)` emits the cqo / rdx-zero
  ## itself. The result (rax quotient / rdx remainder) is moved to its home if the
  ## allocator did not place it there directly.
  let pos = cursorToPosition(g.buf[], c)
  let res = g.ra.locs[pos]
  let wantRem = c.exprKind == ModC
  var tc, divC, dvsC: Cursor
  block:
    var cc = c
    cc.into:
      tc = cc; skip cc                                  # result type
      divC = cc; skip cc                                # dividend
      dvsC = cc; skip cc                                # divisor
      while cc.hasMore: skip cc
  let signed = isSignedType(resolveType(g.prog, tc))
  g.emitValue2(divC)                                    # dividend → rax (pinned)
  g.emitValue2(dvsC)                                    # divisor → its register
  let dvsLoc = g.ra.locs[cursorToPosition(g.buf[], dvsC)]
  assert dvsLoc.kind == InReg, "arkham x64n: idiv divisor " & $dvsLoc.kind
  let op = if signed: IdivX64 else: DivX64
  g.ab.tree op:
    g.ab.reg g.md.divRemReg                             # (rdx): high half / remainder
    g.ab.reg g.md.intRetReg                             # (rax): low half / quotient
    g.emReg dvsLoc.r                                    # divisor, by its bound name
  if dvsLoc.isTemp: g.unbindTemp(dvsLoc.r)
  let resReg = if wantRem: g.md.divRemReg else: g.md.intRetReg
  if res.kind == InReg and res.r != resReg: g.movReg(res.r, resReg)

proc emitValue2(g: var CodeGen; c: Cursor) =
  ## Ensure `c`'s value is materialized at its precomputed `locs[pos]`. A leaf whose
  ## location is a register is moved there (the allocator placed it via destination-
  ## passing / a `NeedsReg` reservation); a leaf left as `Imm` / in its own home stays
  ## put (the consumer folds or reads it). A computed node runs its op into its result.
  let dst = g.ra.locs[cursorToPosition(g.buf[], c)]
  if dst.kind == InFReg:                                 # a float value → the SIMD path
    g.emitFValue2(c); return
  # A leaf the allocator forced into a *scratch temp* (e.g. an immediate operand
  # under a `NeedsReg` constraint) must bind that register so `emReg` emits a
  # checked name, not a raw r10/r11. The consuming op (`emitBin2`/`emitCond2`)
  # unbinds it when it folds the operand. Computed nodes bind their own result.
  if dst.kind == InReg and dst.isTemp and c.kind in {IntLit, UIntLit, CharLit}:
    g.bindTemp(dst.r, dst.typ)
  case c.kind
  of IntLit:
    if dst.kind == InReg: g.movImm(dst.r, intVal(c))
  of UIntLit:
    if dst.kind == InReg: g.movImm(dst.r, cast[int64](uintVal(c)))
  of CharLit:
    if dst.kind == InReg: g.movImm(dst.r, int64(ord(charLit(c))))
  of Symbol:
    if dst.kind == InReg:
      let home = g.ra.locationOfSym(symName(c))
      if home.kind != Undef:                            # a function-local
        if dst.isTemp: g.bindTemp(dst.r, dst.typ)        # stack-homed local → loaded into a temp
        g.place2(home, dst.r)
      else:
        let si = g.lookupSym(symName(c))
        if si.cat == scProc:                             # a proc as a value → its code pointer
          if dst.isTemp: g.bindTemp(dst.r, dst.typ)
          g.ab.tree LeaX64: (g.emReg dst.r; g.ab.sym si.asmName)  # RIP-relative &proc
        else:                                            # a module-level global / tvar: load it
          var cc = c
          let loc = g.asLoc(cc)                          # Glob/Tvar with the global's precise type
          if dst.isTemp: g.bindTemp(dst.r, loc.typ)      # type the temp as the global (precision)
          g.place2(loc, dst.r)
  of StrLit:                                            # string literal → rodata + RIP lea
    if dst.kind == InReg:
      let nm = "msg." & $g.rodata.len
      g.rodata.add (nm, strVal(c))
      if dst.isTemp: g.bindTemp(dst.r, dst.typ)
      g.ab.tree LeaX64: (g.emReg dst.r; g.ab.sym nm)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC: g.emitBin2(c)
    of DivC, ModC: g.emitDivMod2(c)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC: g.emitCondValue2(c)
    of DerefC, DotC, AtC, PatC: g.emitMemLoad2(c)
    of AddrC: g.emitAddr2(c)
    of CastC, ConvC: g.emitCast2(c)
    of CallC: g.emitCall2(c)
    of NegC, BitnotC:                                   # unary in-place: operand in res, then op
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc                                       # result type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitValue2(inner)
      let res = g.ra.locs[cursorToPosition(g.buf[], c)]
      let iv = g.ra.locs[cursorToPosition(g.buf[], inner)]
      if res.kind == InReg:
        if res.isTemp and (iv.kind != InReg or iv.r != res.r): g.bindTemp(res.r, res.typ)
        if iv.kind == InReg and iv.r != res.r: g.movReg(res.r, iv.r)
        if c.exprKind == NegC:
          g.ab.tree NegX64: g.emReg res.r
        else:
          g.ab.tree NotX64: g.emReg res.r
    of SufC, ParC:                                      # wrapper → the inner value
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitValue2(inner)
    of TrueC:
      if dst.kind == InReg: (if dst.isTemp: g.bindTemp(dst.r, dst.typ)); g.movImm(dst.r, 1)
    of FalseC, NilC:
      if dst.kind == InReg: (if dst.isTemp: g.bindTemp(dst.r, dst.typ)); g.movImm(dst.r, 0)
    of SizeofC:
      if dst.kind == InReg:
        var t = c; var sz = 0'i64
        t.into:
          sz = typeSizeAlign(g.prog, t)[0].int64
          while t.hasMore: skip t
        if dst.isTemp: g.bindTemp(dst.r, dst.typ)
        g.movImm(dst.r, sz)
    else: raiseAssert "arkham x64n: emitValue2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitValue2 kind " & $c.kind

proc fbinOps(ek: NifcExpr): (X64Inst, X64Inst) =
  ## (32-bit, 64-bit) SSE instruction pair for a float binary-arith node.
  case ek
  of AddC: (AddssX64, AddsdX64)
  of SubC: (SubssX64, SubsdX64)
  of MulC: (MulssX64, MulsdX64)
  of DivC: (DivssX64, DivsdX64)
  else: raiseAssert "arkham x64n: fbinOps " & $ek

proc emitFBin2(g: var CodeGen; c: Cursor) =
  ## Emit a float binary-arith node (the SIMD twin of `emitBin2`). `a` is
  ## materialized straight into the precomputed result register (`locs[pos]`, a
  ## destination-passed xmm); `b` either folds in place (a float local already in a
  ## register) or is materialized into its SIMD temp; then `res = res op b`.
  let pos = cursorToPosition(g.buf[], c)
  let res = g.ra.locs[pos]
  assert res.kind == InFReg, "arkham x64n: float bin result " & $res.kind
  let (op32, op64) = fbinOps(c.exprKind)
  let bits = if res.typ.size == 4: 32 else: 64
  var lhsC, rhsC: Cursor
  block:
    var cc = c
    cc.into:
      skip cc                                            # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let aux = g.ra.aux.getOrDefault(pos)
  if aux.swapped:
    # Sethi–Ullman: the rhs was evaluated first into the result register; the leaf
    # float lhs (a local read) folds after. Commutative only, so `res op= lhs`.
    g.emitFValue2(rhsC)                                  # rhs → res (binds res if a temp)
    let lhome = g.ra.locationOfSym(symName(lhsC))
    if lhome.kind == InFReg:
      g.fbin(op32, op64, res.f, lhome.f, bits)
    else:                                                # spilled: load into the fscratch, fold
      let lt = aux.fscratch[0]
      g.bindFTmp(lt)
      g.emFloatScalarLoad(lt, lhome.name, bits)
      g.fbin(op32, op64, res.f, lt, bits)
      g.unbindFTmp(lt)
    return
  g.emitFValue2(lhsC)                                    # a → res (== result reg)
  let rhsLoc = g.ra.locs[cursorToPosition(g.buf[], rhsC)]
  if rhsLoc.kind == InFReg and not rhsLoc.isTemp:        # in-place float local: fold directly
    g.fbin(op32, op64, res.f, rhsLoc.f, bits)
  else:
    g.emitFValue2(rhsC)                                  # b → its SIMD temp
    g.fbin(op32, op64, res.f, rhsLoc.f, bits)
    if rhsLoc.isTemp: g.unbindFTmp(rhsLoc.f)

proc emitFValue2(g: var CodeGen; c: Cursor) =
  ## Ensure `c`'s FLOAT value is materialized at its precomputed `locs[pos]` (an
  ## xmm register). The SIMD twin of `emitValue2`; mirrors `genIntoF`.
  let pos = cursorToPosition(g.buf[], c)
  let dst = g.ra.locs[pos]
  assert dst.kind == InFReg, "arkham x64n: emitFValue2 dst " & $dst.kind
  let bits = if dst.typ.size == 4: 32 else: 64
  case c.kind
  of FloatLit:
    if dst.isTemp: g.bindFTmp(dst.f)
    let gpr = g.ra.aux[pos].scratch[0]                   # scratch GPR for the bit pattern
    g.bindTemp(gpr, AsmSlot(cls: AInt, size: 8, align: 8))
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dst.f, gpr, bits)
    g.unbindTemp(gpr)
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    case home.kind
    of InFReg:
      if home.f != dst.f:
        if dst.isTemp: g.bindFTmp(dst.f)
        g.fmovF(dst.f, home.f, bits)
    of NamedStack:                                       # spilled float: load from its slot
      if dst.isTemp: g.bindFTmp(dst.f)
      g.emFloatScalarLoad(dst.f, home.name, bits)
    else: raiseAssert "arkham x64n: float symbol home " & $home.kind
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC: g.emitFBin2(c)
    of ConvC, CastC: g.emitCast2(c)                       # conversion TO float (emitCast2 handles InFReg)
    of CallC: g.emitCall2(c)                              # float-result call → xmm0 → res
    of DerefC, DotC, AtC, PatC: g.emitFMemLoad2(c)        # float lvalue load → movsd res, [addr]
    of SufC, ParC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitFValue2(inner)
    else: raiseAssert "arkham x64n: emitFValue2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitFValue2 kind " & $c.kind

proc emLvalAddr2(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (the operand of a `(mem …)` /
  ## `(lea …)`), reading any embedded value register from its pre-allocated `locs`.
  ## v1 slice: a stack-var base (`(rsp) name`), a `dot` field over such a base or a
  ## `deref`, and a pointer `deref` (`(cast (ptr pointee) ptrReg)`).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm)
    if loc.kind == Undef:
      # a module-level global aggregate base: its address is in the pre-assigned base
      # register (materialized by prematLval2). Type it `(cast (ptr globalType) reg)`
      # so the enclosing dot/at can compute the field/element offset.
      let baseReg = g.ra.locs[cursorToPosition(g.buf[], c)]
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                             # (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg baseReg.r
    elif loc.kind == InReg and g.varType.hasKey(nm):
      # a >16B by-reference aggregate param: a pointer in a register — type it via
      # `(cast (ptr T) reg)` so the enclosing dot/at can compute the field offset.
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym g.varType[nm]
        g.emReg loc.r
    else:                                               # a `(s)` stack-var base
      g.ab.reg RSP
      g.ab.sym nm
  of TagLit:
    case c.exprKind
    of DotC:
      g.ab.tree DotX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                    # base (stack var or deref)
          g.ab.sym symName(cc); skip cc                 # field name
          while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      g.ab.tree AtX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                    # base (stack array)
          case cc.kind                                  # index (nifasm scales it)
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else:                                         # register index (pre-loaded by premat)
            g.emReg g.ra.locs[cursorToPosition(g.buf[], cc)].r
          skip cc
          if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
            g.emReg g.ra.aux[atPos].scratch[0]          # 3-operand form: non-SIB stride scratch
          while cc.hasMore: skip cc
    of DerefC:
      var pointee = g.getType(c)                        # deref result = the pointee type
      var cc = c
      cc.into:
        let pReg = g.ra.locs[cursorToPosition(g.buf[], cc)]
        g.ab.tree CastX:
          g.ab.ptrType:
            if pointee.kind == Symbol: g.ab.sym symName(pointee)
            else: g.genTypeBody(pointee)
          g.emReg pReg.r                                # the pointer, by its bound name
        while cc.hasMore: skip cc
    of PatC:                                            # pointer index: (at (cast (aptr E) p) idx)
      var elem = g.getType(c)                           # element / pointee type
      g.ab.tree AtX:
        var cc = c
        cc.into:
          let pReg = g.ra.locs[cursorToPosition(g.buf[], cc)]
          g.ab.tree CastX:
            g.ab.aptrType:
              if elem.kind == Symbol: g.ab.sym symName(elem)
              else: g.genTypeBody(elem)
            g.emReg pReg.r                              # the pointer, by its bound name
          skip cc                                       # past pointer
          case cc.kind                                  # index
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else:                                         # register index (pre-loaded by premat)
            g.emReg g.ra.locs[cursorToPosition(g.buf[], cc)].r
          skip cc
          while cc.hasMore: skip cc
    else: raiseAssert "arkham x64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emLvalAddr2 kind " & $c.kind

proc prematLval2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue's embedded values (a `deref` pointer, an index, a global
  ## base's address) into their allocated registers BEFORE the consuming `(mem …)` /
  ## `(lea …)` tree opens (an emit-inside-the-tree would corrupt it). For a stack /
  ## register-pointer symbol base this is a no-op.
  if c.kind == Symbol:
    # A module-level global aggregate base: `lea baseReg, &global`. The base register
    # (the access result for a load/addr, or a store scratch) was assigned by the
    # allocator and is already bound by the caller — see emitMemLoad2 / emitAddr2.
    let loc = g.ra.locs[cursorToPosition(g.buf[], c)]
    if loc.kind == InReg and g.ra.locationOfSym(symName(c)).kind == Undef:
      g.emGlobalAddr(loc.r, symName(c))
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
        g.emitValue2(cc)                                # the pointer → its register
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.prematLval2(cc); skip cc                      # base
        if cc.kind notin {IntLit, UIntLit}: g.emitValue2(cc)  # register index → its reg
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        # bind the non-SIB stride scratch so `(at … scratch)` names a checked temp
        g.bindTemp(g.ra.aux[atPos].scratch[0], AsmSlot(cls: AInt, size: 8, align: 8))
    of PatC:
      var cc = c
      cc.into:
        g.emitValue2(cc); skip cc                       # the pointer → its register
        if cc.kind notin {IntLit, UIntLit}: g.emitValue2(cc)  # register index → its reg
        while cc.hasMore: skip cc
    else: discard

proc unbindLvalTemps2(g: var CodeGen; c: Cursor) =
  ## Release any scratch temp an lvalue's embedded value was loaded into (e.g. a
  ## stack-homed pointer reloaded for a `deref`/`pat`), AFTER the consuming
  ## (mem …)/(lea …) instruction. A reg-homed base sits in its own home (not a temp)
  ## ⇒ no-op. The load/store RESULT temp is separate (the consumer unbinds it).
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc)                          # base
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc); skip cc                 # base
        if cc.kind notin {IntLit, UIntLit}:             # register index temp
          let il = g.ra.locs[cursorToPosition(g.buf[], cc)]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.unbindTemp(g.ra.aux[atPos].scratch[0])        # the non-SIB stride scratch
    of DerefC:
      var cc = c
      cc.into:
        let ploc = g.ra.locs[cursorToPosition(g.buf[], cc)]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        while cc.hasMore: skip cc
    of PatC:
      var cc = c
      cc.into:
        let ploc = g.ra.locs[cursorToPosition(g.buf[], cc)]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        skip cc                                          # pointer
        if cc.kind notin {IntLit, UIntLit}:             # register index temp
          let il = g.ra.locs[cursorToPosition(g.buf[], cc)]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
    else: discard

proc emitMemLoad2(g: var CodeGen; c: Cursor) =
  ## Load the scalar at lvalue `c` into its pre-allocated result register:
  ## `mov res, (mem <addr>)`.
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  assert res.kind == InReg, "arkham x64n: mem-load result " & $res.kind
  if res.isTemp: g.bindTemp(res.r, res.typ)             # bind first: a global base leas &g
  g.prematLval2(c)                                       #   into res before the (mem …) tree
  g.ab.tree MovX64:
    g.emReg res.r
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)                                  # release embedded base/index temps

proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor) =
  ## `dest op= [<lvalue c>]` — fold a memory-load operand into an ALU op via the
  ## value-core address machinery (prematLval2 / emLvalAddr2 / unbindLvalTemps2), no
  ## borrowTmp. The mirror of emitMemLoad2 with an ALU op in place of the load `mov`.
  g.prematLval2(c)
  g.ab.tree op:
    g.emReg dest
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)

proc emitFMemLoad2(g: var CodeGen; c: Cursor) =
  ## Load the FLOAT scalar at lvalue `c` into its pre-allocated xmm result:
  ## `movsd res, (mem <addr>)` (movss for f32). The SIMD twin of `emitMemLoad2`.
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  assert res.kind == InFReg, "arkham x64n: float mem-load result " & $res.kind
  let bits = if res.typ.size == 4: 32 else: 64
  g.prematLval2(c)
  if res.isTemp: g.bindFTmp(res.f)                        # consumer unbinds
  g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
    g.emFReg res.f
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)                                   # release embedded base/index temps

proc emitAddr2(g: var CodeGen; c: Cursor) =
  ## `(addr lvalue)` → a pointer in the result register. `&(deref p) == p` (identity);
  ## otherwise `lea res, <addr-of-lvalue>`.
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  assert res.kind == InReg, "arkham x64n: addr result " & $res.kind
  var lv: Cursor
  block:
    var cc = c
    cc.into:
      lv = cc; skip cc
      while cc.hasMore: skip cc
  if lv.kind == TagLit and lv.exprKind == DerefC:
    # &(deref p) == p — produce the pointer directly into res
    var p: Cursor
    block:
      var dd = lv
      dd.into:
        p = dd; skip dd
        while dd.hasMore: skip dd
    g.emitValue2(p)
    let pLoc = g.ra.locs[cursorToPosition(g.buf[], p)]
    if res.isTemp: g.bindTemp(res.r, res.typ)
    g.place2(pLoc, res.r)
    if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != res.r: g.unbindTemp(pLoc.r)
  elif lv.kind == Symbol and g.lookupSym(symName(lv)).cat in {scGlobal, scTvar}:
    # &global / &threadvar (no stack base / embedded value to materialize).
    if res.isTemp: g.bindTemp(res.r, res.typ)
    var lc = lv
    let loc = g.asLoc(lc)                                # Glob/Tvar with the global's precise type
    case loc.kind
    of Glob: g.emGlobalAddr(res.r, loc.name)            # &global → RIP-relative lea
    of Tvar:
      # &threadvar = FS base + the tvar's offset. Reuse `res` as the base scratch:
      # `lea res, &arkham.tls.0` then `lea res, (res) tvar` folds nifasm's offset in
      # (no extra register — mirrors emitAddrLoc's Tvar arm without a borrowed temp).
      if loc.name notin g.tvarNames:
        raiseAssert "arkham x64: address-of a foreign thread-local (module-system TODO): " & loc.name
      g.emGlobalAddr(res.r, TlsBlockName)
      g.ab.tree LeaX64: (g.emReg res.r; g.emReg res.r; g.ab.sym loc.name)
    else: g.emitAddrLoc(loc, res.r)
  else:
    if res.isTemp: g.bindTemp(res.r, res.typ)           # bind first: a global base leas &g
    g.prematLval2(lv)                                    #   into res before the (lea …) tree
    g.ab.tree LeaX64:
      g.emReg res.r
      g.emLvalAddr2(lv)
    g.unbindLvalTemps2(lv)                               # release embedded base/index temps

proc emitCast2(g: var CodeGen; c: Cursor) =
  ## `(conv|cast Type inner)` over integer/pointer (no float source/target — gated out):
  ## the inner computes into the result register (dest-passing); then re-represent it in
  ## the target's 64-bit register form. A pointer target is a reinterpret (only a narrow
  ## int source gets zero-extended); an integer target widens (sign per conv/source, zero
  ## per cast) or narrows/truncates to the target width.
  let isCast = c.exprKind == CastC
  var tc, inner: Cursor
  block:
    var cc = c
    cc.into:
      tc = resolveType(g.prog, cc); skip cc              # target type
      inner = cc; skip cc
      while cc.hasMore: skip cc
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  if res.kind == Imm:
    # An identity int↔int / ptr-reinterpret cast over a folded immediate: the
    # allocator left the value as an `Imm` (the consumer folds it), so nothing to
    # emit — re-representing a constant is a no-op at this width.
    return
  if res.kind == InFReg:
    # conversion TO float (`conv (f N) inner`): int source → cvtsi2sd (operand in a
    # GPR temp, extended to its source width first); float source → precision convert.
    let dstBits = if res.typ.size == 4: 32 else: 64
    if g.isFloatExpr(inner):
      g.emitFValue2(inner)                              # operand → res (dest-passed)
      if res.isTemp: g.bindFTmp(res.f)                  # (consumer unbinds; rare — float→float deferred)
      g.emFcvt(res.f, res.f, dstBits, g.floatBits(inner))
    else:
      g.emitValue2(inner)
      let iv = g.ra.locs[cursorToPosition(g.buf[], inner)]
      assert iv.kind == InReg, "arkham x64n: int→float operand " & $iv.kind
      if res.isTemp: g.bindFTmp(res.f)                  # spilled-float result temp; consumer unbinds
      let (srcW, srcSigned) = g.srcWidthSigned(inner)
      g.extendTo(iv.r, srcW, srcSigned)                 # normalize to the full int value
      g.fcvtI2F(res.f, iv.r, dstBits)
      if iv.isTemp: g.unbindTemp(iv.r)
    return
  if g.isFloatExpr(inner):
    # FLOAT source → int/ptr target: cvttsd2si (truncate toward zero), then a narrow
    # integer target gets extended. The operand was placed in an xmm by the allocator.
    g.emitFValue2(inner)
    let fv = g.ra.locs[cursorToPosition(g.buf[], inner)]
    assert fv.kind == InFReg, "arkham x64n: float→int operand " & $fv.kind
    if res.isTemp: g.bindTemp(res.r, res.typ)
    g.fcvtF2I(res.r, fv.f, (if fv.typ.size == 4: 32 else: 64))
    if not isPtrType(tc):
      let targetW = intTypeWidth(tc)
      if targetW < 64: g.extendTo(res.r, targetW, signed = isSignedType(tc))
    if fv.isTemp: g.unbindFTmp(fv.f)
    return
  g.emitValue2(inner)
  let iv = g.ra.locs[cursorToPosition(g.buf[], inner)]
  if res.isTemp and (iv.kind != InReg or iv.r != res.r): g.bindTemp(res.r, res.typ)
  if iv.kind == InReg and iv.r != res.r: g.movReg(res.r, iv.r)
  elif iv.kind == Imm: g.movImm(res.r, iv.ival)
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if isPtrType(tc):
    if srcW < 64: g.extendTo(res.r, srcW, signed = false)   # int→ptr: zero-extend narrow
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW:
      g.extendTo(res.r, srcW, signed = (not isCast) and srcSigned)   # widen
    else:
      g.extendTo(res.r, targetW, signed = isSignedType(tc))          # narrow / equal

proc genAggrCopy2(g: var CodeGen; dstVar, srcVar, typeName: string; tmp: Reg) =
  ## Whole-aggregate copy `dstVar ← srcVar`, one 8-byte word at a time through the
  ## allocator-provided scratch GPR `tmp`. Both operands address by name via
  ## emAggrFieldMem (a stack `(s)` slot's dot form, or a by-ref param's pointer).
  let lay = aggrLayout(g.prog, typeName)
  let words = (aggrByteSize(g.prog, typeName) + 7) div 8   # real size (not the ≤16B ABI count)
  g.bindTemp(tmp, ScalarSlot)
  for i in 0 ..< words:
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham x64n: sub-word-packed aggregate copy unsupported"
    g.ab.tree MovX64: (g.emReg tmp; g.emAggrFieldMem(srcVar, fn))
    g.ab.tree MovX64: (g.emAggrFieldMem(dstVar, fn); g.emReg tmp)
  g.unbindTemp(tmp)

proc copyStructThroughPtr2(g: var CodeGen; srcVar, typeName: string; ptrReg, tmp: Reg) =
  ## Field-wise copy `srcVar` → the memory `ptrReg` points at, through the allocator-
  ## provided scratch `tmp` (the >16B aggregate hidden-result-pointer return). The
  ## pure-emit twin of `copyStructThroughPtr`.
  g.bindTemp(tmp, ScalarSlot)
  for f in aggrLayout(g.prog, typeName):
    g.ab.tree MovX64: (g.emReg tmp; g.emAggrFieldMem(srcVar, f.name))
    g.ab.tree MovX64: (g.emPtrFieldMem(ptrReg, typeName, f.name); g.emReg tmp)
  g.unbindTemp(tmp)

proc emLvalFieldMem(g: var CodeGen; lhs: Cursor; field: string) =
  ## `(mem (dot <lvalue address> field))` — a field within the aggregate addressed by
  ## the lvalue `lhs` (a `dot`/`at`/`deref` chain). The lvalue's embedded value
  ## registers must already be materialized (`prematLval2`).
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.emLvalAddr2(lhs)
      g.ab.sym field

proc genConstrIntoLval2(g: var CodeGen; c: Cursor; lhs: Cursor) =
  ## Emit `(oconstr T (kv field value)*)` straight into the memory aggregate addressed
  ## by lvalue `lhs` (e.g. `n->chunks[0] = (p, size)`). The address-targeted twin of
  ## `genConstr2`: materialize the lvalue's embedded regs once, then store each field
  ## value at `(dot <lhs> field)`. A pointer field is reinterpreted via `(cast (ptr …))`.
  var tc = c; inc tc                                    # the constructed type symbol
  let objTy = resolveType(g.prog, tc)
  g.prematLval2(lhs)                                     # the lvalue's base/index regs, once
  var cc = c
  cc.into:
    skip cc                                             # the constructed type
    while cc.hasMore:
      var kv = cc
      kv.into:
        let field = symName(kv); inc kv
        let valC = kv
        g.emitValue2(valC)
        let v = g.ra.locs[cursorToPosition(g.buf[], valC)]
        if v.kind == InFReg:                            # float field
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.emLvalFieldMem(lhs, field)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          var fty = resolveType(g.prog, fieldType(g.prog, objTy, field))
          g.ab.tree MovX64:
            g.emLvalFieldMem(lhs, field)
            if isPtrType(fty):
              g.ab.tree CastX: (g.genTypeBody(fty); g.emReg v.r)
            else:
              g.emReg v.r
          if v.isTemp: g.unbindTemp(v.r)
        while kv.hasMore: skip kv                        # optional inherited-depth INTLIT
      skip cc
  g.unbindLvalTemps2(lhs)                                # release the lvalue's base/index temps

proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string) =
  ## Emit `(oconstr T (kv field value)*)` into the stack aggregate `dstVar`: each
  ## value was placed in a register temp by the allocator (a SIMD temp for a float
  ## field); store it at the field's offset. A scalar going into a POINTER field is
  ## reinterpreted via `(cast (ptr …) reg)` for nifasm's strict typing.
  var tc = c; inc tc                                    # the constructed type symbol
  let objTy = resolveType(g.prog, tc)
  var cc = c
  cc.into:
    skip cc                                             # the constructed type
    while cc.hasMore:
      var kv = cc
      kv.into:
        let field = symName(kv); inc kv
        let valC = kv
        g.emitValue2(valC)
        let v = g.ra.locs[cursorToPosition(g.buf[], valC)]
        if v.kind == InFReg:                            # float field
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.emAggrFieldMem(dstVar, field)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          var fty = resolveType(g.prog, fieldType(g.prog, objTy, field))
          g.ab.tree MovX64:
            g.emAggrFieldMem(dstVar, field)
            if isPtrType(fty):
              g.ab.tree CastX: (g.genTypeBody(fty); g.emReg v.r)
            else:
              g.emReg v.r
          if v.isTemp: g.unbindTemp(v.r)
        while kv.hasMore: skip kv                        # optional inherited-depth INTLIT
      skip cc

proc genVarDecl2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = cursorToPosition(g.buf[], cc)         # SymbolDef pos (aux key, matches allocVarDecl)
    let nm = symName(cc); inc cc
    skip cc                                              # pragmas
    let typeCur = cc; skip cc                            # type
    g.symType[nm] = typeCur                              # record the type for getType (conds)
    let loc = g.ra.locationOfSym(nm)
    let hasVal = cc.hasMore and cc.kind != DotToken
    case loc.kind
    of InReg: g.emRegLocalVar(nm, loc.r, typeCur)
    of InFReg: g.emFRegLocalVar(nm, loc.f, loc.typ.size * 8)   # float local in an xmm
    of NamedStack:
      g.emTypedStackVar(nm, typeCur)
      if typeCur.kind == Symbol: g.varType[nm] = symName(typeCur)  # aggregate field layout
    else: raiseAssert "arkham x64n: var home " & $loc.kind
    if hasVal and loc.kind == NamedStack and loc.typ.kind == AMem:
      # An aggregate var with an initializer: a constructor builds it field-by-field
      # into the slot (copy-init / call-returned aggregate are later slices).
      let valC = cc
      if valC.kind == TagLit and valC.exprKind == OconstrC:
        g.genConstr2(valC, nm)
      elif valC.kind == Symbol:                          # copy-init `var b = a`
        g.genAggrCopy2(nm, symName(valC), g.varType[nm], g.ra.aux[declPos].scratch[0])
      elif valC.kind == TagLit and valC.exprKind == CallC:  # call-returned aggregate
        let tn = g.varType[nm]
        if g.aggrByRef(tn):                              # >16B: pass &var as the hidden result ptr
          g.emStackAddr(RDI, nm)
          g.emitCall2(valC)                              # the callee writes through rdi
        else:
          g.emitCall2(valC)                              # ≤16B result in rax:rdx
          g.regsToStruct(nm, tn, x64RetRegs)
      else: raiseAssert "arkham x64n: aggregate var init " & $valC.exprKind
    elif hasVal:
      let valC = cc
      g.emitValue2(valC)
      let v = g.ra.locs[cursorToPosition(g.buf[], valC)]
      case loc.kind
      of InReg: g.place2(v, loc.r)                       # dest-passed ⇒ usually a no-op
      of InFReg:                                         # float: dest-passed into loc.f
        if v.kind == InFReg and v.f != loc.f:
          g.fmovF(loc.f, v.f, loc.typ.size * 8)
      of NamedStack:
        # A stack-homed scalar: the allocator computed the initializer into a register
        # (an integer GPR, or a SIMD temp for a spilled float); store it to the `(s)`
        # slot and release the temp.
        if v.kind == InReg:
          g.emitStoreLoc(loc, v.r)
          if v.isTemp: g.unbindTemp(v.r)
        elif v.kind == InFReg:                           # spilled float init
          g.emFloatScalarStore(nm, v.f, loc.typ.size * 8)
          if v.isTemp: g.unbindFTmp(v.f)
        else: raiseAssert "arkham x64n: stack var init " & $v.kind
      else: discard
    while cc.hasMore: skip cc

proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## Emit a branch test, jumping to `toLabel` when the condition holds (`whenTrue`):
  ## a short-circuit `and`/`or`/`not` tree, a `cmp`/`jcc` for a comparison `(op a b)`,
  ## or `cmp v, 0` for a plain boolean value. Operand locations were pre-assigned by
  ## `allocCond`; the short-circuit forms mirror the legacy `emitCondJump`.
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
    of NotC:
      g.emitCond2(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCond2(aC, lSkip, false)                  # a false ⇒ whole `and` false: skip
        g.emitCond2(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCond2(aC, toLabel, false)                # either false ⇒ jump
        g.emitCond2(bC, toLabel, false)
    else:                                              # OrC
      if whenTrue:
        g.emitCond2(aC, toLabel, true)                 # either true ⇒ jump
        g.emitCond2(bC, toLabel, true)
      else:
        let lSkip = g.freshLabel()
        g.emitCond2(aC, lSkip, true)                   # a true ⇒ whole `or` true: skip
        g.emitCond2(bC, toLabel, false)
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
      # FLOAT comparison: `comisd a, b` (comiss for f32) sets CF/ZF like an unsigned
      # compare (NIFC assumes non-NaN), so the jcc tag is the unsigned one. Both
      # operands were placed in xmm registers by the allocator.
      let fbits = g.floatBits(aC)
      let tag = cmpJccTag(ek, whenTrue, signed = false)
      g.emitFValue2(aC)
      g.emitFValue2(bC)
      let aLoc = g.ra.locs[cursorToPosition(g.buf[], aC)]
      let bLoc = g.ra.locs[cursorToPosition(g.buf[], bC)]
      assert aLoc.kind == InFReg and bLoc.kind == InFReg, "arkham x64n: float cmp operands"
      g.ab.tree (if fbits == 32: ComissX64 else: ComisdX64):
        g.emFReg aLoc.f; g.emFReg bLoc.f
      g.emJcc(tag, toLabel)
      if bLoc.isTemp: g.unbindFTmp(bLoc.f)
      if aLoc.isTemp: g.unbindFTmp(aLoc.f)
      return
    let unsigned = g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC)
    let tag = cmpJccTag(ek, whenTrue, signed = not unsigned)
    let aLoc0 = g.ra.locs[cursorToPosition(g.buf[], aC)]
    let bLoc0 = g.ra.locs[cursorToPosition(g.buf[], bC)]
    if aLoc0.kind != Mem: g.emitValue2(aC)               # lhs: a folded memory load stays put
    if bLoc0.kind != Mem: g.emitValue2(bC)               # rhs: ditto
    let aLoc = g.ra.locs[cursorToPosition(g.buf[], aC)]
    let bLoc = g.ra.locs[cursorToPosition(g.buf[], bC)]
    if aLoc.kind == Mem:                                 # left folded: cmp [addr], rreg/imm
      g.prematLval2(aC)
      g.ab.tree CmpX64:
        g.ab.tree MemX: g.emLvalAddr2(aC)
        case bLoc.kind
        of Imm: g.ab.intLit bLoc.ival
        of InReg: g.emReg bLoc.r
        else: raiseAssert "arkham x64n: cmp(memlhs) rhs " & $bLoc.kind
      g.unbindLvalTemps2(aC)
    else:
      assert aLoc.kind == InReg, "arkham x64n: cmp lhs " & $aLoc.kind
      case bLoc.kind
      of Imm:
        g.ab.tree CmpX64: (g.emReg aLoc.r; g.ab.intLit bLoc.ival)
      of InReg:
        g.ab.tree CmpX64: (g.emReg aLoc.r; g.emReg bLoc.r)
      of NamedStack:                                     # spilled scalar slot: cmp reg, [rsp+slot]
        g.withMemOperand(bLoc):                          #   (no access chain → no borrowTmp)
          g.ab.tree CmpX64:
            g.emReg aLoc.r
            g.emMemOperandLoc(bLoc, regs, ri)
      of Mem:                                            # folded memory load: cmp reg, [addr]
        g.prematLval2(bC)
        g.ab.tree CmpX64:
          g.emReg aLoc.r
          g.ab.tree MemX: g.emLvalAddr2(bC)
        g.unbindLvalTemps2(bC)
      else: raiseAssert "arkham x64n: cmp rhs " & $bLoc.kind
    g.emJcc(tag, toLabel)
    if bLoc.kind == InReg and bLoc.isTemp: g.unbindTemp(bLoc.r)
    if aLoc.kind == InReg and aLoc.isTemp: g.unbindTemp(aLoc.r)
  else:
    g.emitValue2(c)
    let v = g.ra.locs[cursorToPosition(g.buf[], c)]
    assert v.kind == InReg, "arkham x64n: bool cond " & $v.kind
    g.ab.tree CmpX64: (g.emReg v.r; g.ab.intLit 0)
    g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
    if v.isTemp: g.unbindTemp(v.r)

proc emitCondValue2(g: var CodeGen; c: Cursor) =
  ## A comparison / and/or/not used as a 0/1 VALUE: assume 1, then clear to 0 unless
  ## the condition holds (mirrors legacy `materializeCond`). The result register
  ## (`locs[pos]`) is a fresh home / rax in the gated positions — never a comparison
  ## operand — so writing `1` into it before the `cmp` cannot clobber an operand.
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  assert res.kind == InReg, "arkham x64n: cond-value result " & $res.kind
  if res.isTemp: g.bindTemp(res.r, res.typ)            # consumer unbinds (rare dontCare dest)
  let lEnd = g.freshLabel()
  g.movImm(res.r, 1)
  g.emitCond2(c, lEnd, whenTrue = true)                # cond true ⇒ jump over the reset
  g.movImm(res.r, 0)
  g.emLab(lEnd)

proc emitCaseTest2(g: var CodeGen; selReg: Reg; c: var Cursor; lBody: string; signed: bool) =
  ## One `case` BranchRange against `selReg`; jump to `lBody` on a match. The gate
  ## (`caseRangeModeled`) guarantees small-immediate bounds, so every `cmp` folds the
  ## bound inline (no scratch register — the pure emitter cannot borrow one).
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()                        # match iff lo <= sel <= hi
      g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit lo)
      g.emJcc(if signed: JlX64 else: JbX64, lSkip)
      g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit hi)
      g.emJcc(if signed: JgX64 else: JaX64, lSkip)
      g.emJmp(lBody)
      g.emLab(lSkip)
  else:
    g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit branchImm(c))
    g.emJcc(JeX64, lBody)

proc genStmt2(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return                 # an empty statement (e.g. `(stmts .)`)
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore: (g.genStmt2(cc); skip cc)
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore: (g.genStmt2(cc); skip cc)
    g.exitScope()
  of VarS: g.genVarDecl2(c)
  of CallS: g.emitCall2(c)
  of BreakS:
    assert g.loopEnds.len > 0, "arkham x64n: `break` outside a loop"
    g.emJmp(g.loopEnds[^1])
  of AsgnS:
    var cc = c
    cc.into:
      let asgnPos = cursorToPosition(g.buf[], c)
      if cc.kind == Symbol:
        let lhsCur = cc                                     # captured for asLoc (global/tvar)
        let dst = g.ra.locationOfSym(symName(cc)); skip cc # local lvalue (reg or `(s)` slot)
        if dst.kind == NamedStack and dst.typ.kind == AMem:
          if cc.kind == TagLit and cc.exprKind == OconstrC:
            g.genConstr2(cc, symName(lhsCur))              # `b = T(field: …)`: build in place
          else:
            # whole-aggregate assignment `b = a` (rhs is another aggregate lvalue)
            g.genAggrCopy2(symName(lhsCur), symName(cc), g.varType[symName(lhsCur)],
                           g.ra.aux[asgnPos].scratch[0])
        else:
          g.emitValue2(cc)                                  # rhs computed into a reg / dst home
          let v = g.ra.locs[cursorToPosition(g.buf[], cc)]
          case dst.kind
          of InReg: g.place2(v, dst.r)                      # dest-passed ⇒ usually a no-op
          of InFReg:                                        # float reg home: rhs dest-passed
            if v.kind == InFReg and v.f != dst.f:
              g.fmovF(dst.f, v.f, dst.typ.size * 8)
          of NamedStack:                                    # stack-homed scalar: store + free
            if v.kind == InReg:
              g.emitStoreLoc(dst, v.r)
              if v.isTemp: g.unbindTemp(v.r)
            elif v.kind == InFReg:                          # spilled float: store to its slot
              g.emFloatScalarStore(dst.name, v.f, dst.typ.size * 8)
              if v.isTemp: g.unbindFTmp(v.f)
            else: raiseAssert "arkham x64n: stack asgn rhs " & $v.kind
          of Undef:                                         # a module-level global / tvar store
            assert v.kind == InReg, "arkham x64n: global store rhs " & $v.kind
            var lc = lhsCur
            let loc = g.asLoc(lc)                           # Glob/Tvar with precise type
            case loc.kind
            of Tvar:                                        # nifasm resolves FS:[off]
              g.ab.tree MovX64:
                g.ab.sym loc.name
                g.emReg v.r
            of Glob:                                        # &g into the address temp, then store
              let addrT = g.ra.aux[asgnPos].scratch[0]
              g.bindTemp(addrT, loc.typ)
              g.emGlobalAddr(addrT, loc.name)
              g.ab.tree MovX64:
                g.ab.tree MemX: g.emReg addrT
                g.emReg v.r
              g.unbindTemp(addrT)
            else: raiseAssert "arkham x64n: global store loc " & $loc.kind
            if v.isTemp: g.unbindTemp(v.r)
          else: raiseAssert "arkham x64n: asgn lhs home " & $dst.kind
      else:
        # A memory store through a complex lvalue (dot/deref/at): materialize the lvalue's
        # embedded base regs, compute the rhs, then `mov (mem <addr>), rhs` — `movsd` for a
        # float rhs (in an xmm), else `mov` for an integer/immediate rhs.
        let lhs = cc
        # A global aggregate base reserved an address scratch (aux); bind it so
        # prematLval2's `lea scratch, &g` emits a checked name. The allocator held it
        # across the rhs, so it survives until the store below (unbound after).
        let globScratch = if g.ra.aux.hasKey(asgnPos): g.ra.aux[asgnPos].scratch[0] else: NoReg
        if globScratch != NoReg: g.bindTemp(globScratch, AsmSlot(cls: AInt, size: 8, align: 8))
        var rhsCur = lhs
        skip rhsCur                                         # past the lhs → the rhs value
        if rhsCur.kind == TagLit and rhsCur.exprKind == OconstrC:
          # aggregate constructor stored through the lvalue (`n->chunks[0] = (p, sz)`):
          # build it field-by-field directly into the addressed memory.
          g.genConstrIntoLval2(rhsCur, lhs)                 # does its own premat/unbind
        else:
          g.prematLval2(lhs)
          g.emitValue2(rhsCur)                              # rhs value
          let v = g.ra.locs[cursorToPosition(g.buf[], rhsCur)]
          if v.kind == InFReg:                              # float store
            let bits = if v.typ.size == 4: 32 else: 64
            g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
              g.ab.tree MemX: g.emLvalAddr2(lhs)
              g.emFReg v.f
            if v.isTemp: g.unbindFTmp(v.f)
          else:
            g.ab.tree MovX64:
              g.ab.tree MemX: g.emLvalAddr2(lhs)
              case v.kind
              of Imm: g.ab.intLit v.ival
              of InReg: g.emReg v.r
              else: raiseAssert "arkham x64n: store rhs " & $v.kind
            if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
          g.unbindLvalTemps2(lhs)                          # release embedded base/index temps
        if globScratch != NoReg: g.unbindTemp(globScratch)
      while cc.hasMore: skip cc
  of WhileS:
    let lStart = g.freshLabel()
    let lEnd = g.freshLabel()
    g.loopEnds.add lEnd
    var cc = c
    cc.into:
      let condC = cc; skip cc
      g.emLab(lStart)
      g.emitCond2(condC, lEnd, whenTrue = false)
      while cc.hasMore: (g.genStmt2(cc); skip cc)
      g.emJmp(lStart)
    g.emLab(lEnd)
    discard g.loopEnds.pop()
  of IfS:
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      while cc.hasMore:
        case cc.substructureKind
        of ElifU:
          let lNext = g.freshLabel()
          var bc = cc
          bc.into:
            let condC = bc; skip bc
            g.emitCond2(condC, lNext, whenTrue = false)
            while bc.hasMore: (g.genStmt2(bc); skip bc)
            g.emJmp(lEnd)
          g.emLab(lNext)
        of ElseU:
          var bc = cc
          bc.into:
            while bc.hasMore: (g.genStmt2(bc); skip bc)
        else: discard
        skip cc
    g.emLab(lEnd)
  of RetS:
    var cc = c
    cc.into:
      let hasVal = cc.hasMore and cc.kind != DotToken
      if g.isEntryProc:
        # the Linux entry terminates the process: return value → exit code in rdi.
        if hasVal:
          g.emitValue2(cc)
          g.place2(g.ra.locs[cursorToPosition(g.buf[], cc)], RDI)
        else: g.movImm(RDI, 0)
        g.movImm(RAX, LinuxX64ExitNr); g.emSyscall()
      elif g.retAggrName.len > 0:                          # aggregate return
        if g.retIndirect:                                  # >16B: copy through the hidden ptr
          let tmp = g.ra.aux[cursorToPosition(g.buf[], cc)].scratch[0]
          g.copyStructThroughPtr2(symName(cc), g.retAggrName, g.indirectReg, tmp)
          g.movReg(RAX, g.indirectReg)                     # SysV: return the buffer pointer in rax
        else:
          g.structToRegs(symName(cc), g.retAggrName, x64RetRegs)  # ≤16B → rax:rdx
      elif hasVal:
        g.emitValue2(cc)
        let v = g.ra.locs[cursorToPosition(g.buf[], cc)]
        if v.kind == InFReg:                              # float return → xmm0
          if v.f != FloatRet: g.fmovF(FloatRet, v.f, v.typ.size * 8)
        else:
          g.place2(v, g.md.intRetReg)
        # epilogue (framePop + ret) is emitted by emitProcBody2's terminator
      while cc.hasMore: skip cc
  of CaseS:
    # `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`. Mirrors the
    # legacy genCase: selector → a register live across ALL range tests; a non-match
    # falls through to else (or the end); bodies are emitted AFTER the test chain, so
    # each ends in a jmp to lEnd. (NIFC `case` has no fall-through.)
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      g.emitValue2(cc); skip cc                          # selector → its register
      let selLoc = g.ra.locs[cursorToPosition(g.buf[], selC)]
      assert selLoc.kind == InReg, "arkham x64n: case selector " & $selLoc.kind
      let selReg = selLoc.r
      var bodies: seq[(string, Cursor)] = @[]
      var elseBody = cc
      var hasElse = false
      while cc.hasMore:                                   # emit every of-branch test chain
        case cc.substructureKind
        of OfU:
          let lBody = g.freshLabel()
          var branch = cc
          skip cc
          branch.into:
            branch.into:                                  # into (ranges …)
              while branch.hasMore: g.emitCaseTest2(selReg, branch, lBody, signed)
            bodies.add (lBody, branch)                    # branch now at the body stmts
            skip branch                                   # drain past the body
        of ElseU:
          elseBody = cc; hasElse = true; skip cc
        else: skip cc
      if selLoc.isTemp: g.unbindTemp(selReg)              # selector dead after the tests
      if hasElse:
        var e = elseBody
        e.into:
          while e.hasMore: (g.genStmt2(e); skip e)
      g.emJmp(lEnd)
      for (lBody, bc) in bodies:
        g.emLab(lBody)
        g.genStmt2(bc)                                    # body (a stmts node)
        g.emJmp(lEnd)
    g.emLab(lEnd)
  of LabS:                                                # `(lab :name)` — a goto target
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:                                                # `(jmp name)` — unconditional goto
    var cc = c
    cc.into:
      g.emJmp(symName(cc)); skip cc
      while cc.hasMore: skip cc
  else: raiseAssert "arkham x64n: genStmt2 " & $c.stmtKind

proc emitProcBody2(g: var CodeGen; info: ProcInfo; declarative: bool) =
  ## The pure-emitter twin of `emitProcBody`, run ONCE (no plan pass). Reuses the
  ## shared signature / frame / param-settling / scope machinery; only the value
  ## core (`genStmt2`/`emitValue2`) differs.
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsX64:
      g.enterScope()
      g.framePush()
      g.emitStackParamLoadsX64(info.decl)
      if g.framePad > 0: g.binImm(SubX64, RSP, g.framePad.int64)
      if g.ra.hasStackVars:
        g.ab.tree SubX64: (g.ab.reg RSP; g.ab.keyword SsizeX)
      if g.retIndirect: g.movReg(g.indirectReg, RDI)
      g.emitParamMoves(info.decl, declarative)
      if info.isEntry: g.emitGlobalInits()
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c                    # name, params, ret, pragmas
        if c.stmtKind == StmtsS: g.genStmt2(c)
        while c.hasMore: skip c
      g.exitScope()
      if info.isEntry:
        g.movImm(RAX, 60); g.movImm(RDI, 0); g.emSyscall()
      else:
        g.framePop()
        g.ab.keyword RetX64

proc recordVarType(g: var CodeGen; c: Cursor) =
  ## `(param :nm . type)` / `(var :nm pragmas type …)` → record `symType[nm] = type`.
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc                                    # pragmas
      g.symType[nm] = cc                         # type
    while cc.hasMore: skip cc

proc recordSymTypes(g: var CodeGen; c: Cursor) =
  ## Pre-pass: populate `symType` for every local var decl so `getType` works during
  ## gating (`procModeled2`), before emission fills them in incrementally. Recurses
  ## statement containers; nested proc/type decls are allocated separately.
  if c.kind != TagLit: return
  case c.stmtKind
  of VarS, GvarS, TvarS, ConstS: g.recordVarType(c)
  of ProcS, TypeS: discard
  else:
    var cc = c
    cc.into:
      while cc.hasMore:
        g.recordSymTypes(cc)
        skip cc

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. The two-pass seam
# below must reset every per-proc table (regLocal/boundTemps/freeTmp + the ra.locs snapshot)
# or RegisterBindingsMatchLoc and replay completeness break.
proc genProc(g: var CodeGen; info: ProcInfo) =
  # Unlike A64 (where a thread-local goes through a TLV-descriptor thunk call), x64
  # reads/writes a tvar directly as an FS-segment operand — no call — so tvar
  # accesses must NOT mark the proc non-leaf. Hence the empty tvar set here.
  let an = analyseProc(g.buf[], info.decl)
  g.varType.clear()                           # reuse the backing storage across procs
  g.symType.clear()
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.regLocal.clear()                          # per-proc named-local bindings
  g.aliasToDecl.clear()                       # per-proc param ABI alias → decl name
  g.boundTemps = {}                           # per-proc scratch-temp bindings
  g.scopeLocals = @[]
  g.fregLocal.clear()                         # per-proc float named-local bindings
  g.boundFTmps = {}
  g.scopeFLocals = @[]
  g.spillCount = 0
  g.tmpBindCount = 0
  g.ftmpBindCount = 0
  g.loopEnds = @[]                            # per-proc loop-exit label stack (while/break)
  # Aggregate return convention (before allocation): a named object ≤16B → rax:rdx;
  # >16B → a hidden pointer the caller passes in rdi, parked in a callee-saved reg
  # (rbx) for the proc's lifetime and written through on `ret`.
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                    # head → name → params, skip → ret type
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrName = symName(rc)
      g.retIndirect = g.aggrByRef(g.retAggrName)
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true                       # float return → xmm0
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  let preseal = if g.retIndirect: {RBX} else: {}
  block:                                          # pre-fill symType so getType works in the gate
    var pc = info.decl
    pc.into:
      inc pc                                      # name
      if pc.kind == TagLit:                       # (params …)
        var p = pc
        p.into:
          while p.hasMore: (g.recordVarType(p); skip p)
      skip pc                                      # params
      skip pc                                      # ret type
      skip pc                                      # pragmas
      if pc.stmtKind == StmtsS: g.recordSymTypes(pc)
      while pc.hasMore: skip pc                    # drain (body + any trailing)
  # THE FLIP (value-core rewrite): the new pure-emit path is now the ONLY path. The
  # `procModeled2` gate and the `exprUnsupported`→legacy fallback are gone — every proc
  # is allocated with `allocExprs=true` and emitted by `emitProcBody2`. Constructs the
  # new path does not yet handle raiseAssert / miscompile; the tests that exercise them
  # are quarantined in `arkhamKnownUnsupported` (tester) until their family is ported.
  # The legacy reactive core (`emitProcBody`/`gen…`) stays in-tree (still reached by
  # `emitGlobalInits`) until that too is ported and the whole seam is deleted.
  const useNew = true
  var atScratch = initHashSet[int]()
  if useNew: g.collectAtScratch(info.decl, atScratch)   # global-rooted non-SIB `(at)` strides
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, x64Machine, preseal,
                      allocExprs = useNew, atScratch = atScratch)
  when defined(arkhamTracePath):
    stderr.writeLine "[arkham] " & info.asmName & ": NEW"
  when defined(arkhamDumpLocs):
    block:
      let dbg = allocateProc(g.buf[], info.decl, an, g.prog, x64Machine, preseal, allocExprs = true)
      stderr.writeLine "=== allocValue locs ==="
      for pos in 0 ..< dbg.locs.len:
        let l = dbg.locs[pos]
        if l.kind == Undef: continue
        var s = "  pos " & $pos & " : " & $l.kind
        case l.kind
        of InReg: s.add " r=" & $l.r
        of Imm: s.add " imm=" & $l.ival
        of NamedStack, Glob, Tvar: s.add " " & l.name
        else: discard
        if dbg.aux.hasKey(pos): s.add "   [foldB=" & $dbg.aux[pos].foldB & "]"
        stderr.writeLine s
  if g.retIndirect:
    g.indirectReg = RBX
    g.ra.usedCallee.incl RBX                   # saved/restored like any callee reg
  g.initFreeTmp()
  g.computeFrameX64(info.isEntry, an.hasCall)
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  if useNew:
    # Pure-emit path: the allocator already assigned every value position; emit once.
    g.ab.planning = false
    g.regLocal.clear(); g.aliasToDecl.clear(); g.boundTemps = {}; g.scopeLocals = @[]
    g.fregLocal.clear(); g.boundFTmps = {}; g.scopeFLocals = @[]
    g.spillCount = 0; g.tmpBindCount = 0; g.ftmpBindCount = 0
    when defined(arkhamDbgProc):
      block:
        var pc = info.decl; inc pc
        stderr.writeLine "DBG emit proc " & symName(pc)
    g.emitProcBody2(info, declarative)
    return
  # Single walk, two modes. The plan pass runs `emitProcBody` with emission
  # suppressed (`ab.planning`), so every scratch borrow is decided and recorded
  # in `borrowLog`/`borrowLogF` (with the real pool + ABI seals) while no bytes
  # are produced; the emit pass replays those decisions verbatim. Because the
  # walk and its register decisions are identical, the emit pass reproduces the
  # exact bytes a single inline-borrow pass would have — provably byte-identical.
  # (Spill-on-exhaustion and control-flow/cmov planning build on this seam.)
  # The plan pass no longer touches `labelCount`/`rodata` (see `freshLabel` /
  # the StrLit case), so the emit pass numbers labels exactly as a single pass
  # would — no snapshot/restore of those is needed.
  let sealedSnapshot = g.ra.sealed
  # A codegen-time steal evicts a local by mutating `g.ra.locs` mid-walk; snapshot
  # it so the emit pass starts from the same allocation the plan pass saw and
  # re-applies the (identically replayed) evictions itself.
  let locsSnapshot = g.ra.locs
  g.stealEvents.clear()
  g.fixedEvicts.clear(); g.fixedEvictSeq = 0
  g.borrowLog.setLen 0; g.borrowLogF.setLen 0
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.ab.planning = true
  g.emitProcBody(info, declarative)
  g.ab.planning = false
  g.ra.locs = locsSnapshot                     # undo plan-pass evictions for the emit pass
  # Reset the per-proc emission state the plan pass dirtied, so the emit pass
  # reproduces a single-pass result. (The `ret*`/frame fields were fixed in setup
  # above and stay constant across the two passes.)
  g.ra.sealed = sealedSnapshot
  g.varType.clear()
  g.symType.clear()
  g.regLocal.clear()
  g.boundTemps = {}
  g.scopeLocals = @[]
  g.fregLocal.clear()
  g.boundFTmps = {}
  g.scopeFLocals = @[]
  g.loopEnds = @[]
  g.initFreeTmp()
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.fixedEvictSeq = 0                          # replay the same eviction sequence
  g.spillCount = 0
  g.tmpBindCount = 0
  g.ftmpBindCount = 0
  g.emitProcBody(info, declarative)            # emit for real, replaying the plan

proc genGlobal(g: var CodeGen; name: string; decl: Cursor) =
  ## `(gvar :name <type>)` — a zero-initialized `.bss` global (also `const`); any
  ## initializer is run at program entry by `emitGlobalInits`.
  var c = decl
  let isConst = c.stmtKind == ConstS
  c.into:                                       # (gvar SymbolDef VarPragmas Type Value?)
    inc c                                       # name
    skip c                                      # pragmas
    let typeCur = c
    skip c                                      # type
    let hasValue = c.hasMore and c.kind != DotToken
    if isConst and hasValue:
      # A true `const`: a read-only data blob in `.text` (no `.bss`, no entry-time
      # init — emitGlobalInits skips ConstS).
      var bytes = ""
      constToBytes(g.prog, typeCur, c, bytes)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
    else:
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                         # type
      # A compile-time constant SCALAR initializer is laid out as *static data*:
      # emit the constant's bits as the gvar's value, so nifasm initializes the
      # (writable) `.bss` slot from the on-disk image. Correct even for a foreign
      # module's gvar in a bundle (its entry-time `emitGlobalInits` never runs) and
      # for a `var` later mutated (a read-only rodata blob would fault). Other
      # (runtime) initializers are still stored at entry by `emitGlobalInits`.
      if hasValue and isConstScalarInit(c):
        g.ab.intLit cast[int64](constLitBits(c))
      g.ab.close()
    while c.hasMore: skip c                      # value (also handled at entry, if runtime)

proc emitGlobalInits(g: var CodeGen) =
  ## At program entry, store each global's initializer (if any) into its slot.
  for name, decl in g.globals:
    var c = decl
    if c.stmtKind == ConstS: continue           # emitted as a rodata data blob
    c.into:
      inc c; skip c                             # name, pragmas
      let gslot = slotOf(g.prog, c)             # the global's declared type
      skip c                                    # type
      # A constant-scalar initializer was laid out as static data (see genGlobal),
      # so there is no entry-time store to emit for it here.
      if c.hasMore and c.kind != DotToken and not isConstScalarInit(c):
        if gslot.kind == AFloat:                 # float global → movss/movsd [&g], xmm
          let gbits = if gslot.size == 4: 32 else: 64
          let fv = g.borrowFTmp()
          g.genIntoF(c, fv, gbits)
          let p = g.borrowTmp(ScalarSlot)
          g.emGlobalAddr(p, name)
          let op = if gbits == 32: MovssX64 else: MovsdX64
          g.ab.tree op:
            g.ab.tree MemX: g.emReg p
            g.emFReg fv
          g.giveBack p
          g.giveBackF fv
        elif gslot.kind == AMem:                 # aggregate global (e.g. a `string`):
          g.genStore(c, globLoc(name, gslot))    # build/copy in place at &global
        else:
          let v = g.borrowTmp(ScalarSlot)
          g.genInto(c, v)                          # evaluate the initializer
          let p = g.borrowTmp(ScalarSlot)
          g.emGlobalAddr(p, name)
          g.ab.tree MovX64:
            g.ab.tree MemX: g.emReg p
            g.emReg v
          g.giveBack p
          g.giveBack v
      while c.hasMore: skip c

proc generateX64*(buf: var TokenBuf; inputPath: string; tags: TagPool): string =
  ## Compile a parsed NIFC module to x86-64 / Linux asm-NIF text.
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: x64Machine)
  g.ab.renderReg = x64RegName                 # render register slots as x86 names
  g.prog = collect(buf, inputPath, tags)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
  g.ab.tree StmtsX64:
    g.ab.tree ArchD: g.ab.ident "x64"
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    # `arkham.tls.0` (the per-thread block FS points at) is owned and emitted by
    # nifasm, the linker — one unified block sized for ALL bundled modules' tvars,
    # plus the entry-prologue `arch_prctl` that sets FS. arkham only references it.
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)
    for sp in g.prog.syscalls:                  # one `(syproc …)` per used syscall
      g.emitSyproc(sp)
    for info in g.prog.procs:
      genProc(g, info)
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
