#
#           Arkham — x86-64 / System V (Linux) code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3 (x86-64 backend). A first, scalar-integer code generator: it shares the
## front-end (`codegen_common`: the `CodeGen` state, the Leng type/lvalue
## analysis) and the (arch-neutral) register allocator with the AArch64 backend,
## and emits System V / Linux asm-NIF that `nifasm` assembles+links to an ELF
## executable. Process exit is lowered to the Linux `exit` syscall (rax=60), so
## the produced binaries run without libc.
##
## v0 scope (mirrors arkham's AArch64 v1): integer/pointer scalars held in
## registers, arithmetic / bitops, `while`, comparisons, and a `main` that
## `exit`s. Floats, aggregates, memory lvalues, parameters, `if`/`case`, div/mod
## and shifts `raiseAssert` for now.

import std / [assertions, tables, sets, os, algorithm, strutils]
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
  let nm = g.rb.boundName(r)
  if nm.len > 0: g.ab.sym nm
  else:
    # The volatile scratch pool (r10/r11) is the ONLY register class the allocator
    # hands out for arbitrary computed values; every such hand-out — pool, steal, and
    # staging — is now `bindTemp`'d to a checked name (see `pickStaging`/the spill
    # paths), so a *raw* pool register reaching here means an unbound scratch
    # slipped past the binder: the silent-clobber hole this work closes. Every OTHER
    # register has an irreducible structural raw use and is allowed: rax/rdi/rsi/rdx/
    # r8/r9 are the syscall + call-argument / return ABI registers; rcx is the 4th call
    # arg; rsp/rbp are the frame/segment bases; rbx/r12–r15 are callee-saved param
    # homes. (The fixed rcx/rdx/rsi/r8 scratch *inside* the self-contained mem* /
    # byte-copy loops is nonetheless bound there, for extra checker coverage.)
    assert r notin g.md.intTempRegs and r != R11,
      "arkham x64: unbound scratch/bridge register reached emReg: " & x64RegName(r) &
      " — every value/address-carrying R10/R11 use must be a typed binding (pickStagingSealed/bindTemp)"
    g.ab.reg r

proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg
proc stagingCensus(g: var CodeGen; avoid: Reg): string

let AddrSlot = AsmSlot(cls: AUInt, size: 8, align: 8)
  ## The binding type for a staging register that holds a raw machine address / word
  ## (a pointer the consumer always `(cast (aptr T) …)`s before dereferencing, or a
  ## whole eightbyte copied verbatim). A well-typed `(u 64)` — NOT an untyped escape:
  ## nifasm still tracks the register and rejects a raw reuse; the cast supplies the
  ## element type at the point of the actual load/store.

proc giveBack(g: var CodeGen; r: Reg) {.inline.} =
  ## Release a transient register obtained during premat / value evaluation. Its
  ## scratch binding (`bindTemp`) is `(kill)`'d first; then a staging register
  ## (caller-saved, sealed while it held an address/index so a sibling pick couldn't
  ## reuse it) is unsealed. Unbinding/unsealing a reg that carries neither is a
  ## harmless no-op.
  if r == NoReg: return
  g.unbindTemp(r)
  g.ra.unseal {r}

proc pickStagingSealed(g: var CodeGen; what: string; slot: AsmSlot; avoid: Reg = NoReg): Reg =
  ## A transient caller-saved staging register, sealed so a nested pick cannot
  ## reuse it until `giveBack` releases it; fails loudly when none is free (the
  ## reserved R11 bridge makes that near-impossible). `avoid` keeps the pick off a
  ## register the caller still needs live (e.g. an accumulator that is not a bound
  ## temp, so `pickStagingScratch`'s own filters would not otherwise exclude it).
  result = g.pickStagingScratch(avoid)
  if result == NoReg:
    # Report WHY each candidate was unavailable: "out of registers" is otherwise
    # indistinguishable from "one filter is wrong / a seal was never released",
    # and those need opposite fixes.
    raiseAssert "arkham x64n: no staging register for " & what &
                " in proc " & g.curProcName & g.stagingCensus(avoid)
  g.ra.seal result
  g.bindTemp(result, slot)

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
  let nm = g.rb.boundFName(f)
  if nm.len > 0: g.ab.sym nm
  else:
    assert f notin g.md.floatTempRegs,
      "arkham x64: unbound float scratch-pool register reached emFReg: xmm" & $ord(f)
    g.ab.xmmReg f

proc bindFTmp(g: var CodeGen; f: FReg) =
  ## Give scratch xmm register `f` a typed nifasm name `ftmpN.0` via `(rebind …)`, so
  ## every later `emFReg f` emits a checked symbol the binding checker sees rather than
  ## a raw `(xmmN)`. The SIMD twin of `bindTemp`.
  ## The precision is a generic `(f 64)` — the operand carries no width to nifasm (the
  ## instruction tag selects movss/movsd), so the binding type is just a placeholder.
  let name = g.rb.freshFTmpName()
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.ab.floatType(64)
    g.ab.xmmReg f
  g.rb.bindFScratch(f, name)

proc unbindFTmp(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## binding. A no-op when `f` carries no temp binding. Also clears the fused
  ## core's reserve flag (see `unbindTemp`).
  g.pickedFRegs.excl f
  let dead = g.rb.takeFScratch(f)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead

proc fmovF(g: var CodeGen; d, s: FReg; bits: int) =                # movss/movsd d, s
  if d == s: return
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fmovFromGpr(g: var CodeGen; d: FReg; s: Reg; bits: int) =     # movfd/movfq xmm ← gpr
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emFReg d; g.emReg s

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
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
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


proc flushArgResidentParams(g: var CodeGen) =
  ## Called right after the FIRST call/syscall in a proc. Every `ArgResident` param
  ## (kept in its incoming arg register) is dead by now — the analyser guarantees it is
  ## never used after any call returns — and the call just clobbered its register. Kill
  ## the lingering `regLocal` name binding so a later RAW reuse of that arg register (an
  ## exit syscall, a fresh marshal) emits `(reg)` rather than the dead param's typed name
  ## (which would be a nifasm type mismatch, e.g. i32 argc reused as a 64-bit syscall arg).
  if g.argResidentFlushed or g.argResidentParams.len == 0: return
  g.argResidentFlushed = true
  for (r, name) in g.argResidentParams:
    # Only kill if the register STILL holds this param. If it was rebound to a scratch
    # temp meanwhile (e.g. an indirect-call fn-ptr), that rebind already released the
    # param binding — killing the current tenant here would be a double / wrong kill.
    if g.rb.takeBindingIf(r, name):
      g.ab.tree KillX64: g.ab.sym name
  g.argResidentParams.setLen 0

proc releaseStaleName(g: var CodeGen; r: Reg)

proc releaseArgDest(g: var CodeGen; r: Reg; valueSym: string) =
  ## An argument value is about to be MATERIALIZED into argument register `r`. Any name
  ## still bound to `r` is stale — the marshalling overwrites the register — and `emReg`
  ## would write the new value under that stale name, whose type generally does not admit
  ## it. THREE shapes reach here, all nifasm type errors:
  ##
  ## * an `ArgResident` param (one that kept its incoming arg register): its binding
  ##   carries the param's PRECISE ABI type, so `(mov p1.0 92)` into an `(i 8)` param is
  ##   rejected. This is exactly what `flushArgResidentParams` guards against — but that
  ##   flush only runs AFTER the first call, too late for that call's OWN arguments.
  ## * a leftover `bindTemp` scratch, e.g. the `(nil)`-typed binding a nil argument left
  ##   on an arg register: a later `(u 64)` word marshalled through it does not fit.
  ## * an ordinary register-homed LOCAL. `intLocalTempRegs` on x86-64 IS the argument
  ##   register set (rdi/rsi/r8/r9), so a call-free local routinely homes in one — e.g. a
  ##   `(ptr T)` local in rdi, then `(mov <that name> (mem …))` of an integer argument.
  ##   This shape is the reason the doc above used to say "two".
  ##
  ## All three are dead here by construction, and for the same reason: the allocator hands
  ## a caller-saved register to another value only when nothing live occupies it, and it
  ## homes a local in one only under `AllRegs` — the analyser's proof that the local's
  ## live range crosses NO call. This IS a call. So the value being built cannot read the
  ## bound name either, which is what makes killing it before `emitValue2` safe. Skipped
  ## when the value IS that symbol, which legitimately reads through the name.
  let bound = g.rb.boundName(r)
  if bound.len == 0 or bound == valueSym: return
  if g.rb.isBoundTemp(r):
    g.unbindTemp(r)                                 # kills the name, drops the binding
    return
  for i in 0 ..< g.argResidentParams.len:
    if g.argResidentParams[i].r == r and g.argResidentParams[i].name == bound:
      g.releaseStaleName(r)
      g.argResidentParams.del i
      return
  g.releaseStaleName(r)                             # a register-homed local, dead at a call

proc emLab(g: var CodeGen; name: string) =
  g.ab.tree LabX64: g.ab.symDef name

proc emJmp(g: var CodeGen; name: string) =
  g.ab.tree JmpX64: g.ab.sym name

proc emJcc(g: var CodeGen; tag: X64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name

template emitLoop(g: var CodeGen; body: untyped) =
  ## Structured infinite loop `(loop (stmts …))`: nifasm emits the back-edge INTERNALLY,
  ## so no backward `jmp` reaches the asm-NIF (keeps the "every jmp forward, back-edges
  ## are loops" invariant). `body` must jump FORWARD to a break/exit label defined AFTER
  ## the loop (a condition-false or `break` exit).
  g.ab.tree LoopX64:
    g.ab.tree StmtsX64:
      body

proc emSyscall(g: var CodeGen) = g.ab.keyword SyscallX64

proc freshLabel(g: var CodeGen): string =
  result = "L" & $g.labelCount & ".0"
  inc g.labelCount

# ── expressions ──────────────────────────────────────────────────────────────

proc genTypeBody(g: var CodeGen; c: var Cursor)
proc framePop(g: var CodeGen)
proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg
# value-core emitters (defined far below) used by the shared memory-move helpers
# (`scalarMemMov`/`floatMemMov`) to emit a folded access chain:
proc prematLval2(g: var CodeGen; c: Cursor; asBase = false)
proc emLvalAddr2(g: var CodeGen; c: Cursor)
proc unbindLvalTemps2(g: var CodeGen; c: Cursor)

# ── fused value core (step 3): decide-and-emit overloads ─────────────────────
# These carry the destination as a threaded parameter (constraint in, resolved
# location out); every register decision is made inline at the point of
# emission.
proc emitValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitBin2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitDivMod2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondE(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitScalarCmpE(g: var CodeGen; aC, bC: Cursor; ek: LengExpr;
                    whenTrue: bool): X64Inst
proc emitMemLoad2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitAddr2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCast2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCall2(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false)
proc emitInstr2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitLvalue2(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false)
proc freeLvalTemps2(g: var CodeGen; c: Cursor)
proc resolveLvalVal(g: var CodeGen; c: Cursor; dest: var Location)

proc binArithOp(c: Cursor): tuple[op: X64Inst, isBin: bool] =
  ## Map a binary-arith rvalue to its x86 opcode. `isBin = false` for div/mod
  ## (rax:rdx, no memory dest) and any non-arith expression.
  if c.kind != TagLit: return (AddX64, false)
  case c.exprKind
  of AddC: (AddX64, true)
  of SubC: (SubX64, true)
  of MulC: (ImulX64, true)
  of BitandC: (AndX64, true)
  of BitorC: (OrX64, true)
  of BitxorC: (XorX64, true)
  of ShlC: (ShlX64, true)
  of ShrC:
    var tc = c; inc tc                            # result-type child → signedness
    ((if isSignedType(tc): SarX64 else: ShrX64), true)
  else: (AddX64, false)

# ── named local variables (nifasm type-checks them; raw scratch stays `(reg)`) ─

proc emRegLocalVar(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Declare `(var :name (reg) type)` and bind `r` to `name` for the rest of its
  ## scope, so subsequent uses emit the typed name instead of `(reg)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register. The kill lands at this rebind,
  # past the dead var's coarse free point, hence on its post-dominating path.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.reg r                                   # the concrete register (the binding)
  # arkham keeps scalars 64-bit in registers and handles width/signedness via
  # explicit extends, so an int/uint/bool/char local is declared as plain
  # `(i 64)` (a logical `i8`/`u8` would mismatch a 64-bit `mov`, and nifasm also
  # rejects an `i`↔`u` move); a pointer keeps its `(ptr T)` so deref/field typing
  # works. Signed-vs-unsigned comparisons still pick `jb`/`jl` from the slot.
  let rt = resolveType(g.prog, typeCur)
  let isPtr = isPtrType(rt)                    # a ptr binding admits `(nil)` (see `NilC`)
  if isPtr:
    var tc = typeCur
    g.genTypeBody(tc)
  else:
    g.ab.intType(64)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr)

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
  g.rb.bindFLocal(f, name)

proc enterScope(g: var CodeGen) =
  g.rb.enterScope()

proc exitScope(g: var CodeGen) =
  ## `kill` each register local declared in the closing scope so the allocator's
  ## register reuse in a sibling scope rebinds cleanly (nifasm forbids binding a
  ## still-live register). Skip any whose register was already rebound to a later
  ## local (already killed at that rebind).
  let dead = g.rb.exitScope()
  for name in dead.gprs:
    g.ab.tree KillX64: g.ab.sym name
  for name in dead.fprs:
    g.ab.tree KillX64: g.ab.sym name

# ── stack-slot declarations + memory operands (x86 addressing) ───────────────
# nifasm keeps field names / element types, so a memory operand stays symbolic:
#  * a spilled/address-taken scalar or aggregate is a `(var :name (s) T)` slot,
#    addressed `(mem (rsp) name)` / `(mem (dot (rsp) name field))`;
#  * a pointer in a register is dereferenced `(mem reg)`.
# Storing an immediate to memory is unimplemented in nifasm, so callers
# materialize the value into a register first.

proc emStackVar(g: var CodeGen; name, typeName: string) =
  ## `(var :name (s) typeName)` — a nifasm-managed aggregate stack slot.
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.sym typeName
  g.ab.close()

proc emScalarStackVar(g: var CodeGen; name: string) =
  ## `(var :name (s) (i 64))` — a spilled/address-taken scalar's 8-byte slot.
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc emTypedStackVar(g: var CodeGen; name: string; t: Cursor) =
  ## `(var :name (s) T)` with `T` the value's actual Leng type. Use this (not the
  ## generic `(i 64)` slot) for a homed/spilled scalar whose type matters to
  ## nifasm — e.g. a pointer param that the body later derefs, where an `(i 64)`
  ## slot would both reject the typed store and forbid the deref (nifasm is strict).
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  if isNilValue(t):                          # a spilled nil → `(s) (nil)` (8-byte, align 8)
    g.ab.keyword SO
    g.ab.nilValue()
    g.ab.close()
    return
  let sa = stackSlotAlign(g.prog, t)
  if sa > 8:                                  # over-aligned slot → `(s (align N))`
    g.ab.tree X64Flag.SO:
      g.ab.tree AlignX: g.ab.intLit sa.int64
  else:
    g.ab.keyword SO                           # ordinary 8-granular slot → `(s)`
  var tc = t
  if tc.kind == Symbol: g.ab.sym symName(tc)
  else: g.genTypeBody(tc)
  g.ab.close()

proc emBindType(g: var CodeGen; typ: AsmSlot) =
  ## Emit the Leng type for a scratch binding: the slot's own type when known, else
  ## the generic `(i 64)` (a register/immediate dont-care placeholder carries no
  ## cursor). Mirrors `emTypedStackVar`'s type emission.
  if isNilSlot(typ):
    g.ab.nilValue()                  # `(nil)` — a null pointer, not an `(i 64)` 0
  elif cursorIsNil(typ.typ):
    g.ab.intType(64)
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(reg)` the binding
  ## checker can't see. The binding is recorded as a temp, not a named local.
  ## Released by `unbindTemp`.
  let name = g.rb.freshTmpName()
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.emBindType(typ)
    g.ab.reg r
  let isPtr = isNilSlot(typ) or
              (not cursorIsNil(typ.typ) and isPtrType(resolveType(g.prog, typ.typ)))
  g.rb.bindScratch(r, name, isPtr)

proc unbindTemp(g: var CodeGen; r: Reg) =
  ## Release a scratch binding made by `bindTemp`: `(kill)` the name and drop the
  ## binding. A no-op when `r` carries no temp binding (so it is safe on every
  ## `giveBack`, whether or not the reg was a bound temp). Also clears the fused
  ## core's reserve flag, so every legacy release site frees a `takeTmp` pick.
  g.pickedRegs.excl r
  let dead = g.rb.takeScratch(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead

proc emStackMem(g: var CodeGen; name: string) =       # (mem (rsp) name)
  g.ab.tree MemX:
    g.ab.reg RSP
    g.ab.sym name

proc emFieldMem(g: var CodeGen; base, field: string) =   # (mem (dot (rsp) base field))
  # A sub-word field (e.g. a `cint`) is fine: nifasm sizes the `(mem (dot …))` access
  # from the field's declared type (a 4-byte mov for a 32-bit field, sign/zero-extended
  # on load). A field-by-field aggregate copy (copyStructThroughPtr2 / genConstr2)
  # therefore handles packed structs; the word-by-word path (genAggrCopy2) keeps its
  # own `fieldAtOffset` guard for genuinely word-misaligned packing.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.reg RSP
      g.ab.sym base
      g.ab.sym field

proc emAggrElemMem(g: var CodeGen; base: string; idx: int) =  # (mem (at (rsp) base idx))
  ## Element `idx` of the stack array `base`; nifasm folds the constant `idx*elemSize`
  ## into the displacement (an immediate index needs no stride scratch) and sizes the
  ## access from the array's element type.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.reg RSP
      g.ab.sym base
      g.ab.intLit idx

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string)

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

proc atIndexIsReg(g: var CodeGen; atNode: Cursor): bool =
  ## Whether the index of an `(at base idx)` / `(pat ptr idx)` lives in a register (any
  ## non-literal) rather than an immediate that folds to a displacement.
  var n = atNode
  result = false
  n.into:
    skip n                                       # the array base (at) / pointer (pat)
    if n.hasMore: result = n.kind notin {IntLit, UIntLit}
    while n.hasMore: skip n

proc scalarMemMov(g: var CodeGen; loc: Location; reg: Reg; load: bool) =
  ## The one GPR scalar memory move over every lvalue kind, both directions:
  ## `load` → `reg ← <loc>`; else `<loc> ← reg`. Load and store are mirror images
  ## — the value register and the memory operand swap order in the `(mov …)` — apart
  ## from `Glob`: a store stages a separate address temp (it must not clobber
  ## `reg`), whereas a load reuses `reg` itself as the address scratch.
  case loc.kind
  of InReg:
    if load: g.movReg(reg, loc.r) else: g.movReg(loc.r, reg)
  of Tvar:                                        # nifasm resolves a tvar to FS:[off]
    g.ab.tree MovX64:
      if load: (g.emReg reg; g.ab.sym loc.name)
      else:    (g.ab.sym loc.name; g.emReg reg)
  of Glob:
    if load:                                       # &g into a typed staging temp, then deref
      # The address temp is `(ptr <globalType>)` so the `(mem p)` deref yields the
      # global's PRECISE type. Reusing `reg` (bound to the *value* type) as the address
      # drops a pointer level — harmless for a scalar global (`addrWidthMove` tolerates
      # it), but a POINTER global would then load `object` where `(ptr object)` is wanted
      # (nifasm is strict). Mirror the store branch below.
      var pSlot = ScalarSlot
      if not cursorIsNil(loc.typ.typ):
        pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
      let p = g.pickStagingSealed("a global load address", pSlot)
      g.emGlobalAddr(p, loc.name)
      g.ab.tree MovX64:
        g.emReg reg
        g.ab.tree MemX: g.emReg p
      g.giveBack p
    else:                                          # &g into a staging temp, then store
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries
      # the global's PRECISE type — a store of a typed pointer value into a pointer
      # global would otherwise mismatch a generic `(i 64)` mem (nifasm is strict).
      var pSlot = ScalarSlot
      if not cursorIsNil(loc.typ.typ):
        pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
      let p = g.pickStagingSealed("a global store address", pSlot)
      g.emGlobalAddr(p, loc.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg p
        g.emReg reg
      g.giveBack p
  of NamedStack:                                  # spilled scalar / synthetic spill slot
    g.ab.tree MovX64:
      if load: (g.emReg reg; g.emStackMem(loc.name))
      else:    (g.emStackMem(loc.name); g.emReg reg)
  of Mem:
    # A folded access chain: materialize the embedded base/index values (statements
    # BEFORE the consuming `mov`), emit the chain as one nifasm address operand,
    # then release the address temps — the value-core lvalue machinery.
    g.prematLval2(loc.cur)
    g.ab.tree MovX64:
      if load:
        g.emReg reg
        g.ab.tree MemX: g.emLvalAddr2(loc.cur)
      else:
        g.ab.tree MemX: g.emLvalAddr2(loc.cur)
        g.emReg reg
    g.unbindLvalTemps2(loc.cur)
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
  ## a global is always accessed by first materializing its address. An importc/
  ## exportc gvar is referenced by its bare C name (cross-module linkage).
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym g.prog.gvarRefName(name))

proc emTvarAddr(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &threadvar` — the FS base block address plus the tvar's FS offset, folded
  ## into one `lea` (nifasm resolves the tvar symbol to that offset). x86-64 has no
  ## FS-relative `lea`, so the address is `&arkham.tls.0 + offset`. Mirror of the Tvar
  ## arm of `aggrAddrInto`; used to marshal a thread-local aggregate call argument.
  ##
  ## `name` may be a FOREIGN tvar (declared in another bundled module — e.g. a closure
  ## environment threadvar): nifasm whole-program-links, so its lea offset resolver
  ## (`lookupWithAutoImport`) imports the foreign `(tvar …)` decl and allocates its FS
  ## offset in the SAME unified `arkham.tls.0` block. Local and foreign emit identically.
  g.emGlobalAddr(dest, TlsBlockName)                # dest ← FS base block
  g.ab.tree LeaX64: (g.emReg dest; g.emReg dest; g.ab.sym name)  # dest += tvar FS offset

proc emSymAddr(g: var CodeGen; dest: Reg; dst: Location) =
  ## `dest ← &dst` for a module-level symbol destination — a global (RIP-relative lea)
  ## or a thread-local (FS base + offset). The ONE address-of behind every aggregate
  ## store into either, so the build-through-pointer logic dispatches only on the RHS
  ## kind, never on global-vs-threadvar.
  case dst.kind
  of Glob: g.emGlobalAddr(dest, dst.name)
  of Tvar: g.emTvarAddr(dest, dst.name)
  else: raiseAssert "arkham x64n: emSymAddr on " & $dst.kind

proc emSymAddrByName(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &name` for a module-level symbol, dispatching global vs thread-local by the
  ## symbol's CATEGORY — the lvalue-base twin of `emSymAddr` (which takes a resolved
  ## `Location`). `locationOfSym` returns `NoLoc` for both a global and a tvar (neither is
  ## a local), so the lvalue-base path can't tell them apart by storage; the category can.
  if g.lookupSym(name).cat == scTvar: g.emTvarAddr(dest, name)
  else: g.emGlobalAddr(dest, name)

proc binMem(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location) =
  ## `dest op= [rsp+slot]` — x86 folds a `NamedStack` memory source into the ALU op.
  ## (A `Mem` access chain folds through `binMemLval2` instead.)
  assert loc.kind == NamedStack, "arkham x64: binMem on location kind " & $loc.kind
  g.ab.tree op:
    g.emReg dest
    g.emStackMem(loc.name)

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
  of Tvar:                                        # nifasm resolves a tvar to FS:[off]
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.ab.tree op:
      if load: (g.emFReg reg; g.ab.sym loc.name)
      else:    (g.ab.sym loc.name; g.emFReg reg)
  of Glob:
    # &g into a typed staging GPR, then movss/movsd through it. The address temp is
    # `(ptr <floatType>)` so the `(mem p)` deref yields the float's precise width.
    var pSlot = ScalarSlot
    if not cursorIsNil(loc.typ.typ):
      pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
    let p = g.pickStagingSealed("a global float address", pSlot)
    g.emGlobalAddr(p, loc.name)
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.ab.tree op:
      if load:
        g.emFReg reg
        g.ab.tree MemX: g.emReg p
      else:
        g.ab.tree MemX: g.emReg p
        g.emFReg reg
    g.giveBack p
  of Mem:
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.prematLval2(loc.cur)
    g.ab.tree op:
      if load:
        g.emFReg reg
        g.ab.tree MemX: g.emLvalAddr2(loc.cur)
      else:
        g.ab.tree MemX: g.emLvalAddr2(loc.cur)
        g.emFReg reg
    g.unbindLvalTemps2(loc.cur)
  else: raiseAssert "arkham x64: floatMemMov on location kind " & $loc.kind

proc emitStoreFLoc(g: var CodeGen; loc: Location; src: FReg; bits: int) =
  ## `<float Location> ← src`.
  g.floatMemMov(loc, src, bits, load = false)

const StagingCandidates = [R11, RAX, RDI, RSI, RDX, RCX, R8, R9]
  ## Registers `pickStagingScratch` may hand out as a transient compute register for a
  ## spill / mem←mem bridge. R11 is FIRST and is the RESERVED bridge: it is kept out of
  ## the allocator's temp pool (`intTempRegs`), so it is never a live local/temp home —
  ## always pickable. That guarantees `pickStaging` never fails, which is what makes the
  ## value-core `produceIntoMem2` total (every spilled value position has a staging reg).
  ## The ABI caller-saved regs follow as extra staging slots for nested staging (each
  ## guarded by `liveAccums`/`regHoldsLiveLocal`/`sealed` so a live value is never hit).

const FloatStagingBridge = F15
  ## The reserved float staging bridge — kept out of `floatTempRegs` so it is always
  ## free for `pickFStaging` to hand out, making `produceIntoFMem2` total (the SIMD
  ## twin of R11 in `StagingCandidates`).

proc releaseStaleName(g: var CodeGen; r: Reg) =
  ## A register about to be reused as raw scratch/staging must carry no stale
  ## named-local binding. A dead parameter often lingers in `regLocal` under its
  ## signature name `pN.0` (with its original type); `emReg` would then wrongly
  ## emit that typed name for the new value (e.g. `(mov p1.0 <ptr>)` where p1.0 is
  ## the i64 `start` param → nifasm strict-type mismatch). `(kill)` the binding and
  ## drop it so `emReg` falls back to the raw `(reg)` tag (untyped scratch).
  if r != NoReg:
    let dead = g.rb.takeBinding(r)               # also clears a stale pointer-typed bit
    if dead.len > 0:
      g.ab.tree KillX64: g.ab.sym dead

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
  ## free (the genuinely-out-of-registers case).
  for r in StagingCandidates:
    if r != avoid and not g.ra.isSealed(r) and not g.rb.isAccum(r) and
       not g.rb.isBoundTemp(r) and not g.regHoldsLiveLocal(r):
      # not `isBoundTemp`: a register holding a live scratch temp (`bindTemp`'d)
      # must not be handed out as staging — that would clobber the temp's value.
      g.releaseStaleName(r)
      return r
  return NoReg

proc stagingCensus(g: var CodeGen; avoid: Reg): string =
  ## Why every staging candidate was unavailable. "Out of registers" is otherwise
  ## indistinguishable from "a filter is wrong / a seal was never released", and
  ## those need opposite fixes.
  result = ""
  for r in StagingCandidates:
    result.add "\n    " & $r & ": "
    if r == avoid: result.add "avoid"
    elif g.ra.isSealed(r): result.add "sealed"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBoundTemp(r): result.add "boundTemp " & g.rb.boundName(r)
    elif g.regHoldsLiveLocal(r): result.add "live local " & g.rb.boundName(r)
    else: result.add "FREE (unreachable)"

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
  ## float local/param home, and not `avoid`. Clobbering it transiently is then safe.
  ## `FloatStagingBridge` (xmm15) is tried FIRST and is the RESERVED float bridge:
  ## it is kept out of the allocator's float temp pool (`floatTempRegs`), so it is
  ## never a live float local/temp home — always pickable. That guarantees
  ## `pickFStaging` never fails, making `produceIntoFMem2` total (every spilled float
  ## value position has a staging xmm). The arg registers follow for nested staging.
  if FloatStagingBridge != avoid and not g.rb.isSealedF(FloatStagingBridge):
    return FloatStagingBridge
  for f in g.md.floatArgRegs:
    if f != avoid and not g.rb.isSealedF(f) and not g.regHoldsLiveFLoc(f):
      return f
  return NoFReg

proc pickFStagingSealed(g: var CodeGen; what: string; avoid: FReg = NoFReg): FReg =
  ## A transient staging xmm, sealed (`sealF`) so a nested pick cannot reuse it;
  ## the caller releases it with `g.rb.unsealF`. Fails loudly when none is free.
  ## The float twin of `pickStagingSealed`.
  result = g.pickFStaging(avoid)
  if result == NoFReg: raiseAssert "arkham x64n: no staging xmm for " & what
  g.rb.sealF result

# ── fused value core: emit-time destination protocol (step 3) ────────────────
# The merged emitter decides registers at the point of emission: `dest` flows
# down as a constraint (dontCare / needsReg / regOrImm / a fixed location) and
# comes back resolved — vmgen's dest threading. The temp lifecycle keeps the
# LAZY-BIND convention the emitter bodies already follow: `takeTmp` RESERVES a
# register (the `pickedRegs` flag makes it invisible to every freeness filter,
# so a nested pick can't steal a reserved accumulator), and the consumer binds
# it (`bindTemp`, which emits the `(rebind …)`) only when it materializes a
# value into it — exactly the allocator's reserve→(bind…unbind)→release shape,
# so the ported decision code keeps its structure and the serial staging-
# bridge reuse of deep spill chains keeps working. `freeVal` releases: clears
# the pick flag and unbinds if bound. An exhausted pool mints an `etmpN.0`
# spill slot (declared by the prologue, which the body-buffer model writes
# after the body), keeping temp allocation total.

proc takeTmp(g: var CodeGen; slot: AsmSlot): Location =
  ## Reserve an expression-temp GPR (lazy-bound by its consumer); an `etmp`
  ## spill-slot Location when the pools are dry (the produce-into path
  ## materializes into it via the staging bridge).
  let r = g.pickTempReg()
  if r == NoReg:
    let nm = g.mintSpillName("etmp")
    g.ra.spillTemps.add (name: nm, typ: slot, isFloat: false)
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedRegs.incl r
  result = regLoc(r, slot, isTemp = true)

proc takeFTmp(g: var CodeGen; slot: AsmSlot): Location =
  ## The SIMD twin of `takeTmp` (an `eftmp` slot when the float pools are dry).
  let f = g.pickFTempReg()
  if f == NoFReg:
    let nm = g.mintSpillName("eftmp")
    g.ra.spillTemps.add (name: nm, typ: slot, isFloat: true)
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedFRegs.incl f
  result = fregLoc(f, slot, isTemp = true)

proc takeHeld(g: var CodeGen; what: string; canSpill = false): Location =
  ## A SURVIVOR scratch (outlives a call / stays off the staging bridge):
  ## callee-saved only. Demoting a local mid-emission is impossible in the
  ## merged core (its uses are already emitted), so exhaustion either spills
  ## the (re-derivable) survivor to a `heldN.0` slot (`canSpill` consumers
  ## re-derive at each use) or fails loudly.
  let r = g.pickHeldReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, ScalarSlot, isTemp = true)
  if canSpill:
    let nm = g.mintSpillName("held")
    g.ra.spillTemps.add (name: nm, typ: AsmSlot(cls: AInt, size: 8, align: 8),
                         isFloat: false)
    return namedStackLoc(nm, ScalarSlot, spillTemp = true)
  raiseAssert "arkham x64n: out of registers for " & what &
              " in proc " & g.curProcName & " (nothing to spill)"

proc freeVal(g: var CodeGen; loc: Location) {.inline.} =
  ## Release a reserved/resolved temp — the emit-time `releaseTmp`: clear the
  ## pick flag and, if a consumer bound it, `(kill)` the binding so the
  ## freeness filters see the register free again. A no-op for every other
  ## location kind (a home, an immediate, a slot).
  if loc.kind == InReg and loc.isTemp:
    g.pickedRegs.excl loc.r
    g.unbindTemp(loc.r)
  elif loc.kind == InFReg and loc.isTemp:
    g.pickedFRegs.excl loc.f
    g.unbindFTmp(loc.f)

proc resolveDestE(g: var CodeGen; dest: var Location; natural: Location) =
  ## Resolve a LEAF destination constraint against the value's natural
  ## location (an immediate / a symbol's home) — the emit-time twin of the
  ## allocator's `resolveDest`. A fresh temp is bound (caller must not rebind).
  case dest.kind
  of Undef: dest = natural
  of NeedsReg:
    dest = (if natural.kind == InReg: natural else: g.takeTmp(natural.typ))
  of RegOrImm:
    dest = (if natural.kind in {InReg, Imm}: natural else: g.takeTmp(natural.typ))
  else: discard                              # fixed InReg/InFReg/NamedStack/…: keep

proc forceRegDestE(g: var CodeGen; dest: var Location) =
  ## Ensure a value's `dest` is a register (or, pool-dry, an etmp slot the
  ## produce-into path serves) — the emit-time twin of `forceRegDest`.
  case dest.kind
  of NeedsReg, RegOrImm: dest = g.takeTmp(dest.typ)
  of Undef: dest = g.takeTmp(ScalarSlot)
  else: discard

proc rebindLocalAs(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Re-establish register `r`'s binding to the named local `name`, retyped to
  ## `typeCur`, via a zero-machine-code `(rebind …)`. `rebind` auto-kills the transient
  ## tenant `r` currently carries, so no manual `kill` is needed. The scope already
  ## tracks `name` (declared by `emRegLocalVar`), so `scopeLocals` is NOT touched. Type
  ## emission mirrors `emRegLocalVar`: a pointer keeps its precise `(ptr …)`, every
  ## other scalar is the generic `(i 64)` register form.
  let isPtr = isPtrType(resolveType(g.prog, typeCur))
  g.ab.tree RebindX64:
    g.ab.symDef name
    if isPtr:
      var t = typeCur
      g.genTypeBody(t)
    else:
      g.ab.intType(64)
    g.ab.reg r
  g.rb.rebindLocal(r, name, isPtr)

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

proc cmpJccTag(ek: LengExpr; whenTrue, signed: bool): X64Inst =
  ## The `jcc` opcode for a Leng comparison `ek`, taken when the condition is
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

# Linux syscalls are recognised in `programs.collect` (the `LinuxSyscalls` table)
# and emitted as `(syproc …)` declarations whose proctype puts args in the syscall
# ABI registers (arg4 → r10, not the C ABI's rcx) and declares the kernel's
# clobbers (rcx, r11). A call site then uses the ordinary declarative `(prepare …)`
# path with a `(syscall)` marker — see `emitSyproc` and `emitCall2`.

# ── the atomic rows (`{.intrinsic: "AtomicX".}` → x86 lock-prefixed sequences) ──
# x86-64 has a strong memory model: a plain aligned `mov` is already an atomic
# load/store, `xchg` with memory is implicitly locked, and an RMW that returns the
# old value uses `lock xadd` / a `lock cmpxchg` retry loop. The memory-order
# operands are not evaluated at all (see `evaluatedOperands`): every sequence here
# is at least acquire/release, which satisfies whichever order was asked for.
#
# An atomic arrives as `(instr …)`, so its operands are wherever the ALLOCATOR put
# them and the sequence must not assume an ABI. The only registers it takes for
# itself are `rax` — architecturally required as `cmpxchg`'s comparand — and `r11`,
# the reserved staging bridge, as the working register. Those two are precisely the
# GPRs the allocator never hands out, which is the point: an atomic's clobber set
# cannot overlap a live value, so nothing upstream has to prove that it doesn't.
# The `work` register also removes every aliasing question — the caller's `p`, `val`
# and destination registers may coincide freely, because the sequence reads them
# and writes only its own.

proc emMemAt(g: var CodeGen; p: Reg; pointee: Cursor) =
  ## `(mem (cast (ptr T) p))` — dereference `p` typed as `ptr T` so nifasm sizes the
  ## access to T's width. The atomic memory operand MUST carry the pointee type: an
  ## untyped `(mem p)` defaults to a 64-bit access, so an atomic on a sub-64-bit lock
  ## word (e.g. a `uint32` field) would read/WRITE 8 bytes and clobber the adjacent
  ## field — the same width bug `intMemAccess` fixed for plain `cmp [mem],imm`.
  g.ab.tree MemX:
    g.ab.tree CastX:
      var t = pointee
      g.ab.ptrType: g.genTypeBody(t)
      g.emReg p

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers to a short inline byte loop. Sizes are
# runtime values; the result lands in RAX (memcpy/memmove/memset return dest,
# memcmp the first byte difference). Unlike the AArch64 backend these can't use
# the 2-register scratch pool (it can't hold dst+src+n+i+b at once), so they
# evaluate operands into fixed caller-saved registers (rdi/rsi/rdx/
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

proc genRepMovsFwd(g: var CodeGen; nReg: Reg) =
  ## ASCENDING block copy of `nReg` BYTES from `[rsi]` to `[rdi]`: `rep movsq` for the
  ## 8-byte bulk, `rep movsb` for the ≤7-byte tail.
  ##
  ## The string instructions take their operands implicitly and DESTROY rdi, rsi and rcx
  ## (both pointers advance past the copied block, rcx ends at 0), so the caller must
  ## have saved anything it still needs — `nReg` must therefore not be one of them.
  ## nifasm records the same clobber set (see `RepmovsbX64` in the assembler), and the
  ## register mirror is dropped here so no cached value survives the copy. DF is 0
  ## throughout an arkham program (SysV guarantees it at entry and at every call, and
  ## arkham never emits `std`), so `movs` always steps upward.
  ##
  ## Quadword bulk + byte tail rather than a lone `rep movsb`: without ERMSB the byte
  ## form moves one byte per iteration, and the two extra `mov`s plus a possibly
  ## zero-count second `rep` are cheap next to that. (On ERMSB/FSRM parts a bare
  ## `rep movsb` would edge it out; not worth a CPU-feature split here.)
  g.movReg(RCX, nReg)
  g.binImm(ShrX64, RCX, 3)                     # quadwords = n div 8
  g.ab.keyword RepmovsqX64
  g.movReg(RCX, nReg)
  g.binImm(AndX64, RCX, 7)                     # tail bytes = n mod 8
  g.ab.keyword RepmovsbX64

proc genMemIntrinBody(g: var CodeGen; builtin: string) =
  ## The inline `mem*` loop, assuming the args are already loaded (dst→rdi,
  ## src/val→rsi, n→rdx) and rsi/rdx/rcx are bound to checked names. Result → RAX.
  ## Shared by the legacy `genMemIntrin` (reactive `genInto` arg-load) and the
  ## value-core `emitMemIntrin2` (args placed by `emitValue2` into the ABI regs).
  ## The dest pointer (rdi) and the byte/result (rax) stay raw — irreducible ABI regs.
  case builtin
  of "memcpy":                                 # (dst, src, n) → dst
    g.movReg(RAX, RDI)                         # the return value, BEFORE `movs` eats rdi
    g.genRepMovsFwd(RDX)
  of "memmove":                                # (dst, src, n) → dst; overlap-safe
    # An ascending copy is safe unless the destination starts strictly INSIDE the
    # source block — i.e. it is safe when `dst <= src` (the classic case) and also
    # when `dst >= src + n` (disjoint; very common, e.g. shifting a block UP in a
    # seq). Only a genuinely overlapping `src < dst < src+n` needs the descending
    # copy, and that one keeps the byte loop: `rep movs` would run downward only
    # with DF=1, and arkham deliberately never emits `std` (SysV requires DF clear
    # at entry and at every call boundary, so setting it would have to be undone on
    # every path out — including the ones an exit or a trap takes).
    g.bindTemp(R8, ScalarSlot)
    g.movReg(R8, RDI)                          # saved dest: `rep movs` destroys rdi
    let fwd = g.freshLabel()
    let done = g.freshLabel()
    g.emCmpReg(RDI, RSI)
    g.emJcc(JbeX64, fwd)                       # dst <= src → ascending is safe
    g.movReg(RAX, RSI)
    g.binReg(AddX64, RAX, RDX)                 # rax = src + n
    g.emCmpReg(RDI, RAX)
    g.emJcc(JaeX64, fwd)                       # dst >= src+n → disjoint, ascending is safe
    # backward: i = n; while i != 0: i -= 1; dst[i] = src[i]
    g.movReg(RCX, RDX)                         # i = n
    g.emitLoop:
      g.ab.tree CmpX64: (g.emReg RCX; g.ab.intLit 0)
      g.emJcc(JeX64, done)
      g.binImm(SubX64, RCX, 1)
      g.emLoadByte(RAX, RSI, RCX)
      g.emStoreByte(RDI, RCX, RAX)
    g.emLab(fwd)
    g.genRepMovsFwd(RDX)
    g.emLab(done)
    g.movReg(RAX, R8)                          # memmove returns dest
    g.unbindTemp(R8)
  of "memset":                                 # (dst, val, n) → dst
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emitLoop:
      g.emCmpReg(RCX, RDX)
      g.emJcc(JaeX64, done)
      g.emStoreByte(RDI, RCX, RSI)             # dst[i] = low byte of val
      g.binImm(AddX64, RCX, 1)
    g.emLab(done)
    g.movReg(RAX, RDI)
  of "memcmp":                                 # (a, b, n) → first byte difference
    g.bindTemp(R8, ScalarSlot)                 # the second byte (held across the loop)
    let diff = g.freshLabel()
    let equal = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emitLoop:
      g.emCmpReg(RCX, RDX)
      g.emJcc(JaeX64, equal)                   # ran off the end, no diff → 0
      g.emLoadByte(RAX, RDI, RCX)              # ba = a[i] (zero-extended, 0..255)
      g.emLoadByte(R8, RSI, RCX)               # bb = b[i]
      g.emCmpReg(RAX, R8)
      g.emJcc(JneX64, diff)
      g.binImm(AddX64, RCX, 1)
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

# ── by-value aggregate marshalling (SysV) ────────────────────────────────────
# A ≤16-byte aggregate of full 8-byte fields travels in 1–2 GPRs (word i ↔ the
# field at byte offset 8·i); a >16-byte aggregate is passed/returned by reference
# (a pointer). This is self-consistent arkham↔arkham — NOT strict SysV, which
# would pass a >16B argument as a stack copy (MEMORY class) and return it via a
# hidden pointer in the first integer arg. A ≤16B result travels in rax:rdx.

const x64RetRegs = [RAX, RDX]   # SysV ≤16B aggregate result: rax (word 0), rdx (word 1)

proc emStackAddr(g: var CodeGen; dest: Reg; name: string) =   # dest ← &stackvar
  g.ab.tree LeaX64: (g.emReg dest; g.ab.reg RSP; g.ab.sym name)

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

proc emWordThroughPtr(g: var CodeGen; p: Reg; idx: int)   # defined below

proc transferAggrWords(g: var CodeGen; varName, typeName: string;
                       regs: openArray[Reg]; toRegs: bool) =
  ## Move an aggregate between memory and the GPRs that carry it, one register per
  ## 8-byte ABI eightbyte (the by-value aggregate ABI). `toRegs` picks the direction
  ## — `regs[i] ← word i` (load) or `word i ← regs[i]` (store).
  ##
  ## EVERY eightbyte (full OR a trailing partial one) is moved as a RAW `(u 64)` word:
  ## the slot's address goes into the R11 staging bridge (a by-ref aggregate already has
  ## its pointer in a reg) and `emWordThroughPtr` reads/writes the whole 8 bytes. A raw
  ## word is what makes fields PACKED into one eightbyte (e.g. `{int32; int32}` or a
  ## partial `{int16; int16}`) all transfer — a field-TYPED per-field move would carry
  ## only the field at the eightbyte boundary and silently drop the rest. It also
  ## subsumes the old pointer-field `(cast (ptr T) reg)` dance.
  ##
  ## Reading/writing the WHOLE 8 bytes of a trailing partial eightbyte is sound because
  ## the aggregate's storage is always rounded up to a multiple of 8 (`alignedSize`): the
  ## bytes past the partial are this slot's own padding (the register side's extra high
  ## bytes are dead — only the aggregate's real bytes are ever consumed).
  let loc = g.ra.locationOfSym(varName)
  var baseReg = NoReg
  var addrTmp = NoReg
  if loc.kind == InReg:
    baseReg = loc.r                                    # a by-ref aggregate's pointer
  else:
    addrTmp = g.pickStaging()                          # R11 bridge ← &slot
    g.bindTemp(addrTmp, AddrSlot)                       # typed+tracked (giveBack unbinds)
    # The source may be a local stack slot OR a module-level global / `const` / tvar
    # (e.g. `return NoNifLineInfo`, a global const aggregate). `locationOfSym` is
    # NamedStack for a local and `NoLoc` for a module-level symbol — whose address is
    # RIP-relative (global/const) or FS+off (tvar), NEVER rsp-relative `emStackAddr`.
    if loc.kind == NamedStack: g.emStackAddr(addrTmp, varName)
    else: g.emSymAddrByName(addrTmp, varName)
    baseReg = addrTmp
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    g.ab.tree MovX64:
      if toRegs: (g.emReg regs[i]; g.emWordThroughPtr(baseReg, i))
      else: (g.emWordThroughPtr(baseReg, i); g.emReg regs[i])
  if addrTmp != NoReg: g.giveBack addrTmp

proc structToRegs(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## aggregate → regs[i] (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeName, regs, toRegs = true)

proc regsToStruct(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## regs[i] → aggregate (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeName, regs, toRegs = false)

proc globalToRegs(g: var CodeGen; name, typeName: string; regs: openArray[Reg]) =
  ## Read a GLOBAL aggregate's words into the by-value ABI arg GPRs `regs[i] ← word i`.
  ## The global is RIP-relative (no stack slot), so its address goes into the staging
  ## bridge and each word is read through that pointer — a FULL eightbyte as a raw
  ## `(u 64)` word (handles packed fields), a trailing PARTIAL eightbyte field-typed.
  ## The read-side twin of `regsToStructThroughPtr`, for a global passed by value as a
  ## call argument (`equalStrings(s, "")` where `s` is a global `string`).
  let p = g.pickStagingSealed("a global aggregate call-arg address", AddrSlot)
  g.emGlobalAddr(p, name)
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(p, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(p, typeName, fn))
  g.giveBack p

proc tvarToRegs(g: var CodeGen; name, typeName: string; regs: openArray[Reg]) =
  ## Read a THREAD-LOCAL aggregate's words into the by-value ABI arg GPRs
  ## `regs[i] ← word i`. Like `globalToRegs`, but the address is the FS-relative
  ## thread-var address (`emTvarAddr`) rather than a RIP-relative global.
  let p = g.pickStagingSealed("a thread-local aggregate call-arg address", AddrSlot)
  g.emTvarAddr(p, name)
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(p, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(p, typeName, fn))
  g.giveBack p

proc indirectRetType(g: var CodeGen; gvarDecl: Cursor): Cursor =
  ## The return-type cursor of a function-pointer variable's proctype, for the
  ## declarative call path's `retIsVoid`/result handling. Leng's
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

# ── whole-aggregate copy (struct assignment / copy-init) ─────────────────────

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
  ## the count of integer arg registers consumed (for the clobber set). `byRef`
  ## selects how a *named* type is emitted: by reference (`genPointee`, so a
  ## self-referential proctype can't recurse forever) or inline (`genTypeBody`).
  ## Shared by `genProctypeSig` and `emitSignature`.
  ##
  ## A >16B by-ref aggregate RETURN is modelled as a synthetic leading pointer
  ## param `paramName(0)` in rdi — chibicc's hidden return pointer (`push_args`'s
  ## `gp++`). Real params then shift to rsi… naturally; the result slot stays empty
  ## (the value travels through the pointer, not rax).
  var retC = c
  skip retC                                     # params slot → return type
  var retByRef = false
  if not retIsVoid(retC):
    let rs = slotOf(g.prog, retC)
    retByRef = rs.kind == AMem and rs.size > g.md.aggrByRefThreshold
  # THE plan (see abi.nim): register indices and name ordinals below read it —
  # a param's NAME ordinal advances by exactly 1 per param, decoupled from the
  # GPR index (a stack/float param consumes 0 GPRs, an aggregate several).
  let plan = planCall(g.md, paramSlots(g.prog, c), retByRef)
  var pIdx = 0
  g.ab.tree ParamsD:
    if retByRef:                                # synthetic hidden result pointer in rdi
      g.ab.tree ParamD:
        g.ab.symDef paramName(0)
        g.ab.reg g.md.intArgRegs[0]
        g.ab.ptrType:
          var rc = retC
          if byRef: g.genPointee(rc) else: g.genTypeBody(rc)
    if c.kind == TagLit:                        # (params (param …) …)
      c.into:
        while c.hasMore:
          let pl = plan.args[pIdx]
          inc pIdx
          c.into:                               # (param :name pragmas type)
            inc c                               # name → positional pN.0
            skip c                              # pragmas
            if pl.isFloat:
              raiseAssert "arkham x64: float param in signature not yet supported"
            if pl.isAgg:
              # An aggregate param. Its NAME is `paramName(pl.ord)`; the body never
              # reads it by name (the prologue moves it into a stack home / pointer
              # reg raw), so it is emitted with the `(regs …)` location, which nifasm
              # treats as ABI-only — NOT bound — so a raw `(reg)` consumption stays
              # legal. A >16B aggregate travels by-ref as a pointer in ONE GPR; a
              # ≤16B by-value aggregate spans `pl.words` consecutive GPRs (one per
              # eightbyte). `(arg pN k)` at a call site selects word k.
              g.ab.tree ParamD:
                g.ab.symDef paramName(pl.ord)
                if not pl.onStack:
                  g.ab.tree RegsD:
                    for k in 0 ..< pl.words: g.ab.reg g.md.gprAt(pl, k)
                else:
                  g.ab.keyword SO              # doesn't fit → entirely on the stack
                if pl.byRef:
                  g.ab.ptrType:
                    if byRef: g.genPointee(c) else: g.genTypeBody(c)
                else:
                  if byRef: g.genPointee(c) else: g.genTypeBody(c)
            else:
              g.ab.tree ParamD:
                g.ab.symDef paramName(pl.ord)
                if not pl.onStack: g.ab.reg g.md.gprAt(pl)
                else: g.ab.keyword SO           # past the arg registers → stack-passed
                if byRef: g.genPointee(c) else: g.genTypeBody(c)
            while c.hasMore: skip c
    else:
      skip c                                    # no params slot
  g.ab.tree ResultD:                            # c now at the return type
    if retIsVoid(c) or retByRef:
      skip c                                    # void, or returned via the hidden pointer
    else:
      let rs = slotOf(g.prog, c)
      if rs.kind == AFloat:
        raiseAssert "arkham x64: float result in signature not yet supported"
      if rs.kind == AMem:
        # A ≤16B by-value aggregate result travels in rax:rdx with an EMPTY result slot
        # (like a >16B by-ref result): the callee marshals it into rax:rdx and the caller
        # reads those raw after the call — no `(res ret.0)` binding to declare here.
        skip c
      else:
        g.ab.symDef "ret.0"
        g.ab.reg RAX
        if byRef: g.genPointee(c) else: g.genTypeBody(c)
  result = plan.gpUsed

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
  ## Lower a Leng `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
  ## signature `(proctype (params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (rax)
  ## T))? (clobber …))` — the SysV ABI assignment, identical in shape to a
  ## declarative proc's signature, so nifasm can resolve an *indirect* `(prepare …)`
  ## call through a function pointer against it. A function pointer is still 8 bytes
  ## (nifasm sizes `ProcT` as a pointer); the signature is metadata for call sites.
  ## Param/result types are emitted BY REFERENCE (`genPointee`) for named types so a
  ## self-referential closure/continuation signature can't recurse forever.
  ##
  ## The signature mirrors `emitSignature` EXACTLY — including its declarative split.
  ## A DECLARATIVE proctype (all single-GPR scalar params + scalar/void result) states
  ## the positional `pN.0`/`ret.0` ABI so an indirect `(prepare …)` is cross-checked
  ## via `(arg pN)`/`(res ret.0)`. A NON-declarative one (a float/aggregate param or an
  ## aggregate return — e.g. a CPS continuation `proc(c): Continuation`) emits EMPTY
  ## `(params)`/`(result)`, exactly as a non-declarative concrete proc does, so nifasm
  ## requires no per-param bindings and the call site marshals args into raw ABI
  ## registers itself. Without this, a call through such a fn-ptr fails nifasm's
  ## "Missing argument: p0.0" check.
  let declarative = isDeclarativeAbi(g.prog, c)
  g.ab.proctypeType:
    if declarative:
      c.into:
        skip c                                  # the Empty slot (a proc has its name here)
        let numParams = g.emitParamsAndResult(c, byRef = true)
        while c.hasMore: skip c                  # pragmas
        g.emitAbiClobber(numParams)             # mirrors `emitSignature`
    else:
      g.ab.keyword ParamsD
      g.ab.keyword ResultD
      g.emitAbiClobber(0)                       # a call destroys every volatile GPR
      skip c                                     # advance past the whole proctype node

proc genTypeBody(g: var CodeGen; c: var Cursor) =
  ## Translate a Leng type at `c` into asm-NIF, advancing past it. Named types
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
            if c.kind == TagLit and c.typeKind == UnionT:
              # An object VARIANT's union part: `(union (object …branch)+)`. Each branch
              # is an object whose fields are sequential; branches overlap (nifasm lays
              # the union out as max branch size). Emit it through — `genTypeBody`
              # recurses on each branch object.
              g.ab.unionType:
                c.into:
                  while c.hasMore: g.genTypeBody(c)
            else:
              c.into:                         # (fld :name pragmas type)
                let fn = symName(c); inc c
                skip c                        # field pragmas (dropped)
                g.ab.fldDef(fn):
                  g.genTypeBody(c)
    of EnumT:                                 # an enum is just its base integer type
      c.into:
        g.genTypeBody(c)                      # (enum <base> (efld …)…) → <base>
        while c.hasMore: skip c               # efld declarations (dropped)
    of VarargsT:
      # A C `{.varargs.}` importc marker materialises as a synthetic trailing
      # param `(param :vanon . . (varargs))` — e.g. posix `open`/`fcntl`. It owns
      # no storage of its own; the variadic slot is just one ABI/syscall register
      # wide. Emit it as a 64-bit uint so the param maps to exactly one register
      # (`emitSyproc` then binds it to the next syscall arg reg). `skip` drains the
      # whole `(varargs …)` node, with or without a recorded element type.
      g.ab.uintType(64); skip c
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
  var c = decl
  inc c; inc c                                # head → name → params
  # Only register-passed integer/aggregate params (and the hidden result pointer)
  # occupy incoming GPRs; a stack-passed param consumes none, a float uses an xmm.
  result = planCall(g.md, paramSlots(g.prog, c), g.retIndirect).gpUsed

proc emitSignature(g: var CodeGen; decl: Cursor) =
  ## Emit `(params …) (result …)? (clobber …)`. A FULL-signature proc (scalar /
  ## aggregate params, void / scalar / >16B by-ref result) states the complete SysV
  ## register ABI — positional `p.i` params in rdi/rsi/…, a hidden result pointer in
  ## rdi for a >16B return, an rax result — so nifasm knows the full layout (incl.
  ## stack-passed args) and cross-checks every call site. A proc whose boundary is NOT
  ## yet modelled in the typed signature (float params/results, ≤16B by-value aggregate
  ## results) emits an EMPTY `(params)/(result)`; its caller marshals arguments into
  ## raw ABI registers manually.
  if isDeclarativeAbi(g.prog, decl):
    var c = decl
    c.into:
      inc c                                 # name → params slot
      discard g.emitParamsAndResult(c, byRef = false)  # types inline (concrete proc)
      while c.hasMore: skip c               # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  # `numIncomingArgRegs` (not the param *count*) — it accounts for an aggregate
  # spanning several GPRs and a float consuming none.
  g.emitAbiClobber(g.numIncomingArgRegs(decl))

proc emitParamMoves(g: var CodeGen; decl: Cursor) =
  ## Settle each register-passed parameter into its allocated home. A param the
  ## allocator left in its incoming arg register becomes the named local `p.i`
  ## (x64 refers to a bound register by name); one the allocator relocated to a
  ## callee-saved register (because it lives across a call) is `mov`'d there as a
  ## *raw* register — never a named local, so the epilogue can `pop` that
  ## callee-saved reg without a "kill it first" binding conflict. Stack-passed
  ## params (7th+) are handled by `emitStackParamLoadsX64`.
  let declarative = isDeclarativeAbi(g.prog, decl)  # full signature ⇒ params bound as `pN.0`
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # no parameters
  # THE plan (see abi.nim): register indices / name ordinals below read it.
  # rdi = hidden result ptr for a >16B return; floats consume xmm0–7, not GPRs.
  let plan = planCall(g.md, paramSlots(g.prog, c), g.retIndirect)
  var pIdx = 0
  c.into:
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
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
      if tn.len > 0 and loc.kind == NamedStack and not pl.onStack:
        # ≤16B by-value aggregate passed in registers: declare its `(s)` home, fill
        # from its GPR word(s). (One that did NOT fit is stack-passed → handled by
        # `emitStackParamLoadsX64`; we skip it here.)
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        g.regsToStruct(nm, tn, g.md.intArgRegs[pl.gpFirst ..< pl.gpFirst + pl.words])
      elif tn.len > 0 and loc.kind == InReg and not pl.onStack:
        # >16B by-reference aggregate passed in a register: a pointer homed like a
        # scalar; field accesses route through it (recorded in varType). A stack-
        # passed pointer (past the regs) is loaded by `emitStackParamLoadsX64`.
        g.varType[nm] = tn
        g.movReg(loc.r, g.md.gprAt(pl))
      elif tn.len > 0:
        # Stack-passed aggregate (by-value that didn't fit, or a by-ref pointer past
        # the arg regs): record its type so the body can navigate it; the bytes /
        # pointer are brought in by `emitStackParamLoadsX64`. Consumes no GPR.
        g.varType[nm] = tn
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming xmm{fpIndex}; if
        # the allocator gave it a (callee-saved-equivalent) home, move it there. SysV
        # has no callee-saved xmm, so a float crossing a call instead spills (next branch).
        g.fmovF(loc.f, g.md.floatArgRegs[pl.fpIndex], loc.typ.size * 8)
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming xmm arg register into it so `addr`/loads/stores work.
        assert not pl.onStack, "arkham x64 v0: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, g.md.floatArgRegs[pl.fpIndex], bits)
      elif not pl.onStack:                      # register-passed scalar parameter
        let argReg = g.md.gprAt(pl)
        if loc.kind == InReg and loc.r == argReg:
          if declarative:
            g.rb.bindParam(argReg, paramName(pl.ord)) # the signature binds it as `pN.0`
          else:
            # no signature binding (empty params) → bind the param's own name to its
            # arg register so the body can refer to it by name.
            g.emRegLocalVar(nm, argReg, typeCur)
          # An ArgResident param (kept in its arg reg though the proc has calls) is dead
          # after the first call clobbers the reg; record it so `flushArgResidentParams`
          # kills the binding then. In a LEAF proc no call fires, so it never flushes and
          # the binding persists for the whole body — the existing leaf behavior.
          g.argResidentParams.add (argReg, g.rb.boundName(argReg))
        elif loc.kind == InReg:
          # Relocated to a callee-saved or caller-save volatile home. In the declarative
          # path the signature binds argReg to `pN.0`, so the relocation move must
          # *read* it by name (a raw `(reg)` use of a bound register is rejected); the
          # binding is then killed so the now-dead arg register is free. The empty-
          # signature path has no binding, so it moves the raw register. A caller-save
          # home is then bound by the param's own name so `emitCall2`'s `(scope …)`
          # save/restore can refer to it (callee-saved homes stay raw for epilogue pops).
          if declarative:
            g.ab.tree MovX64: (g.emReg loc.r; g.ab.sym paramName(pl.ord))
            g.ab.tree KillX64: g.ab.sym paramName(pl.ord)
          else:
            g.movReg(loc.r, argReg)
        elif loc.kind == NamedStack and loc.typ.kind != AFloat:
          # an address-taken / spilled scalar param: declare its `(s)` slot and spill the
          # incoming argument register into it so `addr`/loads/stores work. Type the slot
          # with the param's real type (e.g. a pointer) — a generic `(i 64)` slot would
          # reject the typed store and forbid a later deref. In the declarative path the
          # arg reg is bound to `pN.0`, so reference it by that name (and kill it); the
          # empty-signature path uses the raw register.
          g.emTypedStackVar(nm, typeCur)        # (var :nm (s) <param type>)
          g.ab.tree MovX64:
            g.emStackMem(nm)
            if declarative: g.ab.sym paramName(pl.ord) else: g.ab.reg argReg
          if declarative: g.ab.tree KillX64: g.ab.sym paramName(pl.ord)
        else:
          raiseAssert "arkham x64 v0: spilled / float parameter: " & nm
      # else: stack-passed (7th+) — loaded by emitStackParamLoadsX64.

# ── stack frame: callee-saved save/restore + incoming stack parameters ───────
# x86-64 has no pair store, so each used callee-saved GPR is a single `push`/`pop`.
# Frames are needed when the proc uses a callee-saved register (for a cross-call
# local or a stack-param home). Saved registers stay RAW (`(rbx)`), never named
# locals, so the epilogue can pop them without nifasm's bound-register guard.

proc pickStackArgBaseX64(g: var CodeGen; hasStackParams: bool) =
  ## A proc with stack-passed parameters needs the incoming-args base in a register
  ## that survives the frame `sub`s (rsp moves). Pick a callee-saved reg the body
  ## isn't using. Split out of `computeFrameX64` because the body-buffer emitter
  ## needs the register's IDENTITY before the body (its stack-param loads name it)
  ## while the frame SHAPE is finalized only after.
  g.stackArgBaseReg = NoReg
  if hasStackParams:
    for r in g.md.intCalleeSaved:
      if r notin g.ra.usedCallee:
        g.stackArgBaseReg = r
        break
    # The allocator reserved a non-sealed callee-saved reg when it set `hasStackParams`,
    # so the pick above always finds one. (Belt-and-braces: a genuine miss would be an
    # allocator/emitter classification drift — both must read `g.ra.hasStackParams`.)
    assert g.stackArgBaseReg != NoReg, "arkham x64n: no callee-saved reg for stackArgBaseReg"

proc computeFrameX64(g: var CodeGen; isEntry, hasCall: bool) =
  ## Finalize the frame shape. Runs AFTER the body is emitted (body-buffer model):
  ## only then are `ra.usedCallee` / `hasStackVars` final. `stackArgBaseReg` was
  ## picked up front (`pickStackArgBaseX64`) and is pushed with the frame regs.
  g.frameRegs = @[]
  for r in g.md.intCalleeSaved:
    if r in g.ra.usedCallee: g.frameRegs.add r
  if g.stackArgBaseReg != NoReg:
    g.frameRegs.add g.stackArgBaseReg
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
  # Stack params are addressed relative to `stackArgBaseReg` (the incoming-args base,
  # captured before the frame `sub`s), so this runs AFTER those `sub`s and after the
  # arg registers are freed — `pl.byteOff` is the offset within the stack-arg area.
  # Collect each param's name, aggregate-type-name (if any) and ABI slot, then run
  # THE shared classifier so "which params are stack-passed and at what byte offset"
  # matches the signature, the caller and the allocator exactly.
  var nms: seq[string] = @[]
  var tns: seq[string] = @[]
  var tcurs: seq[Cursor] = @[]
  var slots: seq[AsmSlot] = @[]
  block:
    var pc = c
    pc.into:
      while pc.hasMore:
        var nm = ""
        var tn = ""
        var tcur = pc
        pc.into:                              # (param :name pragmas type)
          nm = symName(pc); inc pc
          skip pc                             # pragmas
          tcur = pc
          if pc.kind == Symbol and slotOf(g.prog, pc).kind == AMem: tn = symName(pc)
          while pc.hasMore: skip pc
        nms.add nm; tns.add tn; tcurs.add tcur; slots.add slotOf(g.prog, tcur)
  for i, pl in planCall(g.md, slots, g.retIndirect).args:
    if not pl.onStack: continue
    let nm = nms[i]
    let off = pl.byteOff.int64
    if pl.isAgg and not pl.byRef:
      # A by-value aggregate passed entirely on the stack: declare its `(s)` home and
      # copy its eightbytes in from the incoming area `[stackArgBaseReg + byteOff + k*8]`
      # (the offset nifasm gave the caller's `(arg pN k)` writes).
      g.varType[nm] = tns[i]
      g.emStackVar(nm, tns[i])
      # Copy the incoming bytes into the home with MINIMAL register pressure: the home
      # address goes into the staging bridge, and ONE reused value register carries each
      # word — rather than `regsToStruct`, which needs a held register per word.
      let homeAddr = g.pickStagingSealed("a stack-param aggregate home", AddrSlot)
      g.emStackAddr(homeAddr, nm)
      let v = g.pickStaging()
      g.bindTemp(v, AddrSlot)
      for k in 0 ..< pl.words:
        g.ab.tree MovX64:                       # v ← incoming word k
          g.emReg v
          g.ab.tree MemX: (g.ab.reg g.stackArgBaseReg; g.ab.intLit (off + (k * 8).int64))
        g.ab.tree MovX64:                       # home word k ← v
          g.emWordThroughPtr(homeAddr, k)
          g.emReg v
      g.giveBack v
      g.giveBack homeAddr
    else:
      # A scalar / pointer (incl. a by-ref aggregate's pointer): one word from the
      # incoming area into its home — a callee-saved register, or (totality, under full
      # register pressure) its own `(s)` slot, bridged through a staging reg.
      let loc = g.ra.locationOfSym(nm)
      case loc.kind
      of InReg:
        g.ab.tree MovX64:
          g.emReg loc.r
          g.ab.tree MemX: (g.ab.reg g.stackArgBaseReg; g.ab.intLit off)
      of NamedStack:                            # spilled stack param: incoming → `(s)` slot
        # Declare the `(s)` home before filling it — otherwise the store below (and
        # every later body reference) names an undeclared slot and nifasm rejects it
        # ("Expected index register or stack variable in mem"). Register-passed
        # spilled scalar params already do this via `emTypedStackVar` (emitParamMoves);
        # the stack-passed scalar path was missing it. (A by-ref aggregate's pointer
        # home is typed/declared elsewhere via `varType`, so only the scalar case
        # needs the slot decl here.)
        if not pl.byRef:
          g.emTypedStackVar(nm, tcurs[i])
        let s = g.pickStagingSealed("a spilled stack-param bridge", loc.typ)
        g.ab.tree MovX64:
          g.emReg s
          g.ab.tree MemX: (g.ab.reg g.stackArgBaseReg; g.ab.intLit off)
        g.emitStoreLoc(loc, s)
        g.giveBack s
      else:
        raiseAssert "arkham x64 v0: stack parameter home " & $loc.kind & ": " & nm

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


# ── value core: shared helpers of the fused emitter ──────────────────────────
# Single-pass: every register decision is made inline at the point of emission
# (dest threading); `g.ra` carries only the decl-only pre-pass (param/local
# homes) plus the emitter-private `locs`/`aux` memo the fused lvalue walk
# writes. Every proc body is emitted through `genProc` → `emitProcBody2`.

proc emImm(g: var CodeGen; loc: Location) =
  ## Emit an immediate VALUE operand: `(nil)` for a null pointer, else the integer.
  if isNilImm(loc): g.ab.nilValue()
  else: g.ab.intLit loc.ival

proc placeImm(g: var CodeGen; dest: Reg; loc: Location) =
  ## `mov dest, <imm>` — emits `(mov dest (nil))` for a nil so the register binds to
  ## the `(nil)` type, else the ordinary `movImm`.
  if isNilImm(loc):
    g.ab.tree MovX64: (g.emReg dest; g.ab.nilValue())
  else: g.movImm(dest, loc.ival)

proc place2(g: var CodeGen; src: Location; dest: Reg) =
  ## Materialize `src` into register `dest` (no-op when it is already there).
  case src.kind
  of InReg: (if src.r != dest: g.movReg(dest, src.r))
  of Imm: g.placeImm(dest, src)
  of NamedStack, Mem, Glob, Tvar: g.emitLoadLoc(src, dest)
  else: raiseAssert "arkham x64n: place2 src " & $src.kind

proc aggrAddrInto(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool)
proc bindLvalGlobalBases(g: var CodeGen; c: Cursor; bound: var seq[Reg])
proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string; regs: openArray[Reg])

proc aggrArgAddr(g: var CodeGen; a: Cursor; recorded: Reg; avoid: openArray[Reg]): (Reg, bool) =
  ## Materialize `&a` (an aggregate-LVALUE call argument) into a bound register, ready to
  ## marshal from. `recorded` is the allocator's reserved callee-saved survivor; `NoReg`
  ## means it spilled (the `reserveHeldScratch` totality backstop), so re-derive the
  ## address into a transient staging register instead — sealing the marshal destinations
  ## `avoid` (the arg registers about to receive the words, not yet sealed here) so the
  ## pick cannot alias a word being written. Returns `(addr reg, wasSpilled)`; the caller
  ## releases with `giveBack` (spilled) or `unbindTemp`.
  let slot = AsmSlot(cls: AUInt, size: 8, align: 8)
  if recorded != NoReg:
    g.aggrAddrInto(a, recorded, slot, doBind = true)
    return (recorded, false)
  for r in avoid: g.ra.seal r
  let s = g.pickStagingSealed("an aggregate-arg address", slot)
  for r in avoid: g.ra.unseal r
  g.aggrAddrInto(a, s, slot, doBind = false)   # already bound by pickStagingSealed
  (s, true)
proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string)
proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location)
proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor)

proc aggrArgSource(g: var CodeGen; a: Cursor; tcur: Cursor; tn: string):
                  (string, Reg, bool) =
  ## Reach the bytes of a NON-LVALUE aggregate call argument `a` of nominal type `tn`,
  ## and describe where they are as `(home, ptrReg, isTvar)`: a named stack slot
  ## (`home`), a pointer already in a register (`ptrReg` — a >16B by-ref param), or a
  ## module-level symbol read through its address (both empty/`NoReg`; `isTvar` picks
  ## FS-relative over RIP-relative). An `(oconstr …)`/`(aconstr …)` is BUILT here into a
  ## synthetic slot and reported as that `home`. Shared by the register-passed and the
  ## stack-passed marshalling in `emitCall2Inner` — only the destination differs.
  var home = ""
  var ptrReg = NoReg
  var isTvar = false
  if a.kind == Symbol:
    let sloc = g.ra.locationOfSym(symName(a))
    if sloc.kind == NamedStack:
      home = symName(a)                           # a local: its slot is already addressable
    elif sloc.kind == InReg:
      ptrReg = sloc.r                             # a >16B by-ref param: its pointer is already in a reg
    elif g.lookupSym(symName(a)).cat == scGlobal:
      discard                                     # a global: read through &global (home == "")
    elif g.lookupSym(symName(a)).cat == scTvar:
      isTvar = true                               # a thread-local: read through &threadvar
    else:
      raiseAssert "arkham x64: aggregate symbol arg neither local nor global: " & symName(a) &
        " (locKind=" & $sloc.kind & ")"
  else:                                           # oconstr/aconstr: build into a temp
    let pos = cursorToPosition(g.buf[], a)
    home = "aggtmp" & $pos & ".0"
    g.emTypedStackVar(home, tcur)
    g.varType[home] = tn
    g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
  (home, ptrReg, isTvar)

proc binFold(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location; opCur: Cursor) =
  ## `dest op= <memory operand>` (a `NamedStack` slot or a `Mem` access chain `opCur`),
  ## EXCEPT a sub-8-byte field: it has no 64-bit ALU memory form (`add r64, m32` doesn't
  ## exist, and a folded 64-bit read would over-read the field). Such a field is loaded
  ## through a staging reg first — the sized `mov` sign/zero-extends it to the full
  ## 64-bit register — then `op dest, reg`.
  if g.exprSlot(opCur).size < 8:
    # `dest` already holds the other operand (the accumulator); the staging reg that
    # receives the sized load must NOT be `dest`, or the load clobbers it and the
    # `op dest, s` degenerates to `op dest, dest` — dropping this operand (the set
    # membership `setbyte and (1 shl bit)` miscompiled to `setbyte and setbyte`).
    # The sub-width operand is sign/zero-extended into a full 64-bit register by the
    # sized load below, so bind the staging reg to the WIDE type of the operand's
    # class (a char/uint → `(u 64)`, a signed int → `(i 64)`).
    let s = g.pickStagingSealed("a sub-width operand",
                                AsmSlot(cls: g.exprSlot(opCur).cls, size: 8, align: 8),
                                avoid = dest)
    if loc.kind == NamedStack:
      g.emitLoadLoc(loc, s)                       # sized load → sign/zero-extended
    else:                                         # Mem: load via the lvalue (premat base)
      g.prematLval2(opCur)
      g.ab.tree MovX64: (g.emReg s; g.ab.tree MemX: g.emLvalAddr2(opCur))
      g.unbindLvalTemps2(opCur)
    g.binReg(op, dest, s)
    g.giveBack s
  elif loc.kind == NamedStack:
    g.binMem(op, dest, loc)
  else:
    g.binMemLval2(op, dest, opCur)

proc normalizeBinWidth(g: var CodeGen; resTypeC: Cursor; rD: Reg; op: X64Inst) =
  ## arkham keeps register values canonically sign/zero-extended to their full
  ## 64-bit form. `add`/`sub`/`mul`/`shl` on a sub-64-bit type can leave nonzero
  ## bits ABOVE the type width (shl overflow past the top bit, add carry, unsigned
  ## sub borrow) — so a following `shr` / unsigned-compare / `div` would read those
  ## stale bits. Re-normalize the result to restore the invariant. `!&`/`!$` in
  ## tinyhashes are the canonical case: `x shl 10'u32` overflowed into bits 32+ and
  ## the next `shr 6'u32` pulled them back down, diverging RTTI hashes from the C
  ## backend. (`and`/`or`/`xor`/`shr` of already-normalized operands stay normalized,
  ## so they need no fixup.)
  if op notin {AddX64, SubX64, ImulX64, ShlX64}: return
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

proc binStoreSuppressPos(g: var CodeGen; rhs: Cursor; storeWidth: int): int =
  ## `rhs`'s token position when it is a sub-64-bit integer `add`/`sub`/`mul`/`shl`
  ## whose `normalizeBinWidth` fixup is made redundant by a truncating store of
  ## `storeWidth` bytes; else -1. SOUND: `normalize` (`shl;sar`) only rewrites bits
  ## AT/ABOVE the type width B, while the store keeps only the low `storeWidth`≤B
  ## bytes — identical stored bytes with or without it. The bin result is the store's
  ## RHS (single use), so no other reader observes the un-normalized register.
  result = -1
  if rhs.kind != TagLit or storeWidth <= 0: return
  let (op, isBin) = binArithOp(rhs)
  if not isBin or op notin {AddX64, SubX64, ImulX64, ShlX64}: return
  var resTy = rhs
  inc resTy                                              # step into `(op …` → result type
  let slot = typeToSlot(resTy)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8 and
     storeWidth <= slot.size:
    result = cursorToPosition(g.buf[], rhs)

proc emitMemIntrin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core `mem*` intrinsic: allocCall placed the 3 args in rdi/rsi/rdx (a
  ## normal int-arg call), so just emit them, bind the loop scratch (rsi/rdx/rcx),
  ## and run the shared inline loop. Result → rax (moved to its home by emitCall2).
  let s = AsmSlot(cls: AInt, size: 8, align: 8)
  for idx in 0 ..< min(3, argCurs.len):
    var aD = regLoc(g.md.intArgRegs[idx], s)
    g.releaseArgDest(aD.r, (if argCurs[idx].kind == Symbol: symName(argCurs[idx]) else: ""))
    g.emitValue2(argCurs[idx], aD)              # → rdi / rsi / rdx
  # rdi (dest ptr) and rax (result/byte) are used RAW by the inline loop; a call-free
  # local the allocator homed in one of them leaves a stale typed name that `emReg`
  # would emit. Kill it so the loop sees raw registers (rsi/rdx/rcx get fresh temps).
  g.releaseStaleName(RDI); g.releaseStaleName(RAX)
  g.bindTemp(RSI, s); g.bindTemp(RDX, s); g.bindTemp(RCX, s)
  g.genMemIntrinBody(builtin)

proc atomicValueIsImm(loc: Location): bool {.inline.} = loc.kind == Imm

proc seedWork(g: var CodeGen; work: Reg; val: Location) =
  ## Load the atomic's VALUE operand into the working register — a register copy, or
  ## `mov work, imm` when the allocator left it a literal (see `allocInstr`).
  if val.kind == Imm: g.placeImm(work, val)
  else: g.movReg(work, val.r)

proc workOp(g: var CodeGen; op: X64Inst; work: Reg; val: Location) =
  ## `work <op>= val`, immediate or register.
  if val.kind == Imm: g.binImm(op, work, val.ival)
  else: g.binReg(op, work, val.r)

proc genAtomicXadd(g: var CodeGen; dst, pReg, work: Reg; val: Location;
                   pointee: Cursor; returnNew, sub: bool) =
  ## `lock xadd [p], work` with `work` seeded from `val` — the exchange leaves the
  ## OLD value in `work`. For `sub` the addend is negated first, so memory is
  ## decremented; `returnNew` then recomputes `old ± delta`, for which `val` is still
  ## available (the sequence writes only `work` and `dst`).
  g.seedWork(work, val)
  if sub:
    g.ab.tree NegX64: g.emReg work            # work ← -delta
  g.ab.tree LockX64:
    g.ab.tree XaddX64:
      g.emMemAt(pReg, pointee)
      g.emReg work                             # work ← old; [p] += work
  if returnNew:
    g.workOp(if sub: SubX64 else: AddX64, work, val)   # new = old ± delta
  g.movReg(dst, work)

proc genAtomicLoopRmw(g: var CodeGen; dst, pReg, work: Reg; val: Location;
                      pointee: Cursor; op: X64Inst) =
  ## `rax = [p]; loop: work = rax op val; lock cmpxchg [p], work; jne loop`. There
  ## is no lock-prefixed fetch form for and/or/xor that yields the old value, so
  ## spin on `cmpxchg` — whose comparand register is architecturally `rax`. The old
  ## value ends up there and moves to `dst` once the loop is left.
  let lDone = g.freshLabel()
  g.ab.tree MovX64: (g.emReg RAX; g.emMemAt(pReg, pointee))   # rax = [p]
  g.emitLoop:
    g.movReg(work, RAX)
    g.workOp(op, work, val)                         # work = rax op val (the new value)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt(pReg, pointee)
        g.emReg work                                # if [p]==rax: [p]=work else rax=[p]
    g.emJcc(JeX64, lDone)                           # cmpxchg succeeded (ZF=1) → exit forward
  g.emLab(lDone)                                    # else fall to the back-edge and retry
  g.movReg(dst, RAX)

proc instrOperandReg(g: CodeGen; cur: Cursor): Reg =
  ## The register an already-emitted `(instr …)` operand landed in. `allocInstr`
  ## asked for `NeedsReg` on every operand a lowering reads, so anything else here
  ## is an allocator bug, not a source-level condition.
  let l = g.ra.locs[cursorToPosition(g.buf[], cur)]
  if l.kind != InReg:
    raiseAssert "arkham x64n: intrinsic operand is not in a register"
  l.r

proc atomicPointee(g: var CodeGen; ptrArg: Cursor): Cursor =
  ## The type an atomic accesses: the pointee of its cell operand. Sizing the
  ## `(mem …)` by it is not a refinement — an untyped operand defaults to a 64-bit
  ## access, so an atomic on a `uint32` lock word would read and WRITE the four
  ## adjacent bytes and corrupt whatever field sits next to it (see `emMemAt`).
  result = g.getType(ptrArg)
  if isPtrType(result): inc result
  else: result = g.prog.intType

proc emitAtomicInstr2(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                      argCurs: seq[Cursor]; res: Location) =
  ## An atomic row's x86-64 sequence, on operands the ALLOCATOR placed (see the
  ## section header above for the register discipline). `res` is the row's result
  ## home, and is `Undef` for the rows that produce no value.
  # A fence has no cell operand at all — and its memory order is not evaluated —
  # so it must be answered before anything reads `argCurs[0]`.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword MfenceX64
    return
  of AtomicSignalFenceOp:
    # A compiler barrier only: it orders nothing in hardware, and what it forbids
    # — hoisting a memory access across it — arkham does not do to begin with.
    return
  else: discard
  # `rax` and `r11` are about to be raw scratch. A dead local can still be sitting
  # in `regLocal` under its typed name, which `emReg` would emit instead of the raw
  # tag — a type mismatch against the pointee-typed `(mem …)` operand.
  for r in [RAX, R11]: g.releaseStaleName(r)
  let pointee = g.atomicPointee(argCurs[0])
  let p = g.instrOperandReg(argCurs[0])
  # The VALUE operand of every row but the compare-exchange (whose operand 1 is the
  # `expected` POINTER). It may be a folded immediate — see `atomicValueMayBeImm`.
  let val = if op in {AtomicLoadOp, AtomicCompareExchangeOp}: default(Location)
            else: g.ra.locs[cursorToPosition(g.buf[], argCurs[1])]
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  # The working register, for the forms that need one — a load reads straight into
  # its destination and a compare-exchange works out of `rax`, so those two take no
  # `r11` and get no binding for it. Bound to the CELL's type, not a generic scalar:
  # nifasm type-checks `xchg`/`cmpxchg` against their memory operand, and the cell may
  # well be a pointer (a lock-free list head is the common case) — an `(i 64)` binding
  # is rejected against a `(ptr (ptr T))` access.
  let needsWork = op notin {AtomicLoadOp, AtomicCompareExchangeOp}
  if needsWork: g.bindTemp(R11, slotOf(g.prog, pointee))
  block:
    case op
    of AtomicLoadOp:
      # An aligned `mov` IS the atomic load here; the strong memory model does the
      # acquire for us.
      g.ab.tree MovX64: (g.emReg res.r; g.emMemAt(p, pointee))
    of AtomicStoreOp:
      # `xchg` with a memory operand carries an implicit LOCK, which is what makes
      # the store sequentially consistent; a plain `mov` would need a trailing
      # `mfence` to match, for the same cost.
      g.seedWork(R11, val)
      g.ab.tree XchgX64: (g.emMemAt(p, pointee); g.emReg R11)
    of AtomicExchangeOp:
      g.seedWork(R11, val)
      g.ab.tree XchgX64: (g.emMemAt(p, pointee); g.emReg R11)   # r11 ↔ [p]; r11 ← old
      g.movReg(res.r, R11)
    of AtomicFetchAddOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = false, sub = false)
    of AtomicFetchSubOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = false, sub = true)
    of AtomicAddFetchOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = true, sub = false)
    of AtomicSubFetchOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = true, sub = true)
    of AtomicFetchAndOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, AndX64)
    of AtomicFetchOrOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, OrX64)
    of AtomicFetchXorOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, XorX64)
    of AtomicCompareExchangeOp:
      let ep = g.instrOperandReg(argCurs[1])          # `expected`, a POINTER
      let des = g.instrOperandReg(argCurs[2])
      g.ab.tree MovX64: (g.emReg RAX; g.emMemAt(ep, pointee))    # rax = *expected
      g.ab.tree LockX64:
        g.ab.tree CmpxchgX64:
          g.emMemAt(p, pointee)
          g.emReg des                    # if [p]==rax: [p]=des,ZF=1 else rax=[p]
      let lFail = g.freshLabel()
      let lDone = g.freshLabel()
      g.emJcc(JneX64, lFail)
      g.movImm(res.r, 1)                                         # success
      g.emJmp(lDone)
      g.emLab(lFail)
      # The failure path MUST publish what was actually there: that is the whole
      # protocol — the caller retries against the value it now holds.
      g.ab.tree MovX64: (g.emMemAt(ep, pointee); g.emReg RAX)
      g.movImm(res.r, 0)
      g.emLab(lDone)
    else:
      # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
      # empty, so this is the message that column promises.
      lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 lowering — " &
                "guard the call with a `when`"
  if needsWork: g.unbindTemp(R11)
  # Release the operand temps' nifasm bindings. Ordinarily a volatile temp's binding
  # dies when the register is rebound for the next value, but an operand that had to
  # be escalated to a CALLEE-SAVED register (`reserveInstrReg`) may see no such rebind
  # before the epilogue's `pop` — which nifasm rejects while the register is still
  # bound to a name.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.ra.locs[cursorToPosition(g.buf[], argCurs[i])]
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

proc emitBitBuiltin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core GCC bit builtin: the single integer argument goes to rdi (a
  ## normal int-arg call), then the inline scan. Result → rax (moved to its
  ## home by emitCall2). The legacy twin is `genBitBuiltin`.
  var aD = regLoc(RDI, AsmSlot(cls: AInt, size: 8, align: 8))
  g.releaseArgDest(aD.r, (if argCurs[0].kind == Symbol: symName(argCurs[0]) else: ""))
  g.emitValue2(argCurs[0], aD)                        # → rdi
  let ar = RDI
  case builtin
  of "__builtin_ctzll", "__builtin_ctz":
    # count trailing zeros == index of the least-significant set bit == BSF.
    # (x == 0 is UB in C and never reached: nimony callers guard the zero case.)
    g.ab.tree BsfX64: (g.emReg RAX; g.emReg ar)
  of "__builtin_bswap64":
    # reverse all 8 bytes: move the arg into rax, BSWAP it in place (64-bit).
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 64)
  of "__builtin_bswap32":
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 32)
  of "__builtin_bswap16":
    # x86 BSWAP r16 is undefined; reverse as a 32-bit bswap then take the high half
    # back down (the two low bytes end up swapped in bits 0..15).
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 32)
    g.ab.tree ShrX64: (g.emReg RAX; g.ab.intLit 16)
  else:
    raiseAssert "arkham x64n: bit builtin not yet implemented: " & builtin

proc inPlaceIntrinsicX64(op: IntrinsicOp): bool {.inline.} =
  ## Which lowerings write their destination IN PLACE is a fact about *this*
  ## target, not about the opcode: a pinned row records it as `tie`, but a
  ## portable row (`Bswap`) has no tie and still lands on x86's in-place BSWAP.
  ## So the backend decides, and the caller seeds the destination with operand 0.
  ## Safe for every form here: they have a single register operand (`rol`/`ror`
  ## take their count as an immediate — the row's `tie` made the allocator keep it
  ## one), so that seeding copy can clobber no other operand.
  op in {BswapOp, BswapPinnedOp, RolOp, RorOp}

proc emitIntrinsicOps(g: var CodeGen; op: IntrinsicOp; argBits: int;
                      dst, src0: Reg; rotCount: int64) =
  ## Emit one intrinsic row's instruction(s) on ALREADY-PLACED operands. Shared by
  ## the allocator-driven path (`emitInstr2`, which reads the placement out of
  ## `ra.locs`) and the `.assembler` path (`genAsmProc`, where the placement is
  ## the user's `.register` annotation) — they differ only in how `dst`/`src0`
  ## were chosen, never in what gets emitted. For an in-place row the caller has
  ## already seeded `dst` from operand 0 and passes `src0 == dst`.
  let bits = if argBits in {8, 16, 32}: 32 else: 64
  case op
  of BsfOp, CtzOp:
    # count-trailing-zeros == index of the least-significant set bit. `src == 0` is
    # undefined (the row says so); nimony's callers guard the zero case.
    g.ab.tree BsfX64: (g.emReg dst; g.emReg src0)
  of BsrOp:
    g.ab.tree BsrX64: (g.emReg dst; g.emReg src0)
  of ClzOp:
    # `__builtin_clz` counts leading zeros; BSR yields the index of the HIGHEST set
    # bit, and `clz == (W-1) - bsr`, which for a power-of-two W is `bsr xor (W-1)`.
    g.ab.tree BsrX64: (g.emReg dst; g.emReg src0)
    g.ab.tree XorX64: (g.emReg dst; g.ab.intLit(bits - 1))
  of PopcntOp, PopcountOp:
    g.ab.tree PopcntX64: (g.emReg dst; g.emReg src0; g.ab.intLit bits)
  of BswapPinnedOp, BswapOp:
    # x86 BSWAP r16 is undefined, so a 16-bit swap is a 32-bit BSWAP whose two low
    # bytes end up in bits 16..31 — shift them back down.
    if argBits == 16:
      g.ab.tree BswapX64: (g.emReg dst; g.ab.intLit 32)
      g.ab.tree ShrX64: (g.emReg dst; g.ab.intLit 16)
    else:
      g.ab.tree BswapX64: (g.emReg dst; g.ab.intLit bits)
  of RolOp:
    g.ab.tree RolX64: (g.emReg dst; g.ab.intLit rotCount)
  of RorOp:
    g.ab.tree RorX64: (g.emReg dst; g.ab.intLit rotCount)
  else:
    raiseAssert "arkham x64n: no lowering for intrinsic `" & IntrinsicNames[op] & "`"

proc x64InoutTag(op: IntrinsicOp): X64Inst =
  ## The nifasm tag a two-address row emits. Name-for-name throughout — the row's
  ## name IS the assembler's mnemonic — so this crosses the two ENUMS and nothing
  ## else; a row that reaches here without a tag is one the table gained and this
  ## did not, which `NopX64` turns into the caller's `lengError`. (It once also
  ## reconciled two vocabularies: `bitand` → `(and)`, because the pragma argument
  ## was an ident and could not be a Nim keyword. It is a string now, and the cover
  ## names are gone.)
  case op
  of AddOp: AddX64
  of SubOp: SubX64
  of AndOp: AndX64
  of OrOp: OrX64
  of XorOp: XorX64
  of ShlOp: ShlX64
  of ShrOp: ShrX64
  of SarOp: SarX64
  of NegOp: NegX64
  of NotOp: NotX64
  of IncOp: IncX64
  of DecOp: DecX64
  else: NopX64

proc emitInoutInstr2(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                     argCurs: seq[Cursor]) =
  ## `add(d, s)` in an ordinary proc: `(add <d's home> <s>)`. The destination is
  ## `(haddr d)`, and d's home is whatever the allocator gave it — a register, or
  ## an `(s)` slot, both of which x86 accepts as a destination directly.
  let row = IntrinsicRows[op]
  let tag = x64InoutTag(op)
  if tag == NopX64:
    lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 two-address form",
              lengInfo(c)
  proc emitDest(g: var CodeGen; d: Cursor) =
    var inner = d
    var sym = d
    if d.kind == TagLit and d.exprKind == HaddrC:
      inner.into:
        sym = inner; skip inner
        while inner.hasMore: skip inner
    if sym.kind != Symbol:
      lengError d, "the destination of `" & IntrinsicNames[op] & "` must be a " &
                "`var` argument naming a local", lengInfo(d)
    let loc = g.ra.locationOfSym(symName(sym))
    case loc.kind
    of InReg: g.emReg loc.r
    of NamedStack: g.emStackMem(loc.name)
    else:
      lengError d, "the destination of `" & IntrinsicNames[op] & "` has no " &
                "register or stack home", lengInfo(d)
  if row.arity == 1:
    g.ab.tree tag: g.emitDest(argCurs[0])
  else:
    # The source was already emitted and memo'd by the fused emitInstr2.
    let src = g.ra.locs[cursorToPosition(g.buf[], argCurs[1])]
    g.ab.tree tag:
      g.emitDest(argCurs[0])
      case src.kind
      of InReg: g.emReg src.r
      of Imm: g.ab.intLit src.ival
      of NamedStack: g.emStackMem(src.name)
      else:
        lengError argCurs[1], "unsupported source operand for `" &
                  IntrinsicNames[op] & "`", lengInfo(c)

proc proctypeOfTarget(g: var CodeGen; targetCur: Cursor): Cursor =
  ## The resolved proctype body of an indirect call target, for ABI queries. The target
  ## is just an EXPRESSION whose type IS the proctype — a proc-typed local/param, a
  ## closure's `(dot clo fld.0)` field, or a vtable `(cast Proctype …)` (`getType` of a
  ## cast yields its target type). One rule: `getType(target)`, peel a `(ptr proctype)`.
  result = resolveType(g.prog, g.getType(targetCur))
  if result.kind == TagLit and result.typeKind != ProctypeT:
    var inner = result; inc inner                        # peel `(ptr proctype)` → proctype
    result = resolveType(g.prog, inner)
  assert result.kind == TagLit and result.typeKind == ProctypeT,
    "arkham x64n: indirect call target is not a proctype"

proc transparentCastInner(g: var CodeGen; c: Cursor; home: Location): tuple[hit: bool, inner: Cursor] =
  ## A conv/cast is a NO-OP when the allocator dest-threaded the SAME stack home onto
  ## both it and its inner operand (they denote one value) and the conversion is a
  ## non-narrowing, non-pointer int relabel. For a register home the emitter already
  ## folds this in place; but when the shared home is a spill SLOT, re-emitting the
  ## cast round-trips the value through the staging bridge (load slot→reg; store
  ## reg→slot), once PER level of a nested `cast(conv(field))` chain — the store/reload
  ## NOP storms in spilled rawAlloc/rawDealloc code. Return the inner cursor so the
  ## caller can emit it straight into the shared home instead. Non-narrowing only: the
  ## inner's sized slot store/reload already preserves its value at the source width
  ## (a 32-bit field load zero/sign-extends), so widen/identity needs no fixup; a
  ## NARROWING cast emits a real `shl;shr` truncation and must NOT be skipped.
  result = (false, default(Cursor))
  if home.kind != NamedStack: return
  if not (c.kind == TagLit and c.exprKind in {ConvC, CastC}): return
  var tgtC, innerC: Cursor
  block:
    var cc = c
    cc.into:
      tgtC = cc; skip cc
      innerC = cc; skip cc
      while cc.hasMore: skip cc
  let innerLoc = g.ra.locs[cursorToPosition(g.buf[], innerC)]
  if innerLoc.kind != NamedStack or innerLoc.name != home.name: return
  let tc = resolveType(g.prog, tgtC)
  if isPtrType(tc) or isPtrType(resolveType(g.prog, g.getType(innerC))): return
  let (srcW, _) = g.srcWidthSigned(innerC)
  if intTypeWidth(tc) >= srcW: result = (true, innerC)

proc produceIntoMem2(g: var CodeGen; c: Cursor; dst: Location) =
  ## Totality bridge of the FUSED core: `dst` is an `(s)` spill slot (`etmpN.0`,
  ## minted when `takeTmp` found the pools dry). Materialize the value into a
  ## transient staging register — the reserved bridge guarantees one is always
  ## free — then store it to the slot. No `locs` override: the fused
  ## `emitValue2` takes the destination as a parameter, so the recursion simply
  ## passes the bound staging register.
  block:
    let ti = g.transparentCastInner(c, dst)
    if ti.hit:
      var d = dst                        # the inner produces into the shared slot
      g.emitValue2(ti.inner, d)
      return
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoMem2 slot=" & dst.name
  # The staging reg is NOT bound/sealed across the recursion: a leaf/combine
  # binds it only when it materializes the value, so a deep right-nested
  # spilled chain reuses the SAME bridge register level-by-level — one
  # always-free bridge keeps produce-into total at ANY depth.
  let s = g.pickStaging()                # total: the reserved bridge is always pickable
  var d = regLoc(s, dst.typ, isTemp = true)
  g.emitValue2(c, d)
  # `s` carries the produced value into the spill store and MUST be a tracked
  # binding. A bin/combine producer already bound it; a LEAF (symbol/load/imm)
  # produced into a register does not — bind it here so `emitStoreLoc`'s
  # `emReg s` emits the checked name. `giveBack` unbinds.
  if not g.rb.isBoundTemp(s): g.bindTemp(s, dst.typ)
  g.emitStoreLoc(dst, s)                 # spill the produced value to its `(s)` slot
  g.giveBack s                           # unbind the staging name

proc emitLeafImm(g: var CodeGen; dest: var Location; natural: Location) =
  ## FUSED literal leaf: resolve the constraint against the immediate; a
  ## register destination gets it materialized (binding a fresh temp first —
  ## an already-bound temp, e.g. the produce staging, is left as is).
  g.resolveDestE(dest, natural)
  if dest.kind == InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.movImm(dest.r, natural.ival)

proc emitValue2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED decide-and-emit (vmgen dest threading): resolve `dest` — a
  ## constraint (dontCare / needsReg / regOrImm) or a fixed location — against
  ## `c`, emit the code that materializes the value there, and return the
  ## resolved location in `dest` for the consumer. An `Imm` / in-home leaf
  ## stays put (the consumer folds or reads it). Callers route float-typed
  ## values to `emitFValue2`.
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest)
    return
  let pos = cursorToPosition(g.buf[], c)          # for the keepovf no-fold guard
  case c.kind
  of IntLit: g.emitLeafImm(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.emitLeafImm(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.emitLeafImm(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    if home.kind != NoLoc:                        # a function-local: its (frozen) home
      g.resolveDestE(dest, home)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return        # takeTmp went dry
      if dest.kind == InReg and not (home.kind == InReg and home.r == dest.r):
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        if dest.isTemp and home.kind == InReg and isSubWidthIntSlot(dest.typ):
          # A REGISTER-homed local into a SUB-WIDTH temp: reinterpret through
          # `(cast …)` (zero machine code) — a plain mov would be a narrowing
          # move nifasm rejects; the real truncation is the consumer's extendTo.
          var tc = dest.typ.typ
          g.ab.tree MovX64:
            g.emReg dest.r
            g.ab.tree CastX:
              g.genTypeBody(tc)
              g.emReg home.r
        else:
          g.place2(home, dest.r)
    else:
      g.forceRegDestE(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      let si = g.lookupSym(symName(c))
      if si.cat == scProc:                        # a proc as a value → its code pointer
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        g.ab.tree LeaX64: (g.emReg dest.r; g.ab.sym si.asmName)
      else:                                       # a module-level global / tvar: load it
        var cc = c
        let loc = g.asLoc(cc)
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, loc.typ)
        g.place2(loc, dest.r)
  of StrLit:
    g.forceRegDestE(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let nm = "msg." & $g.rodata.len & "." & g.prog.thisModuleSuffix
    g.rodata.add (nm, strVal(c))
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.ab.tree LeaX64: (g.emReg dest.r; g.ab.sym nm)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitBin2(c, dest)
    of DivC, ModC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitDivMod2(c, dest)
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
      # Unary in-place: the operand computes into the result register, the op
      # applies in place (the fused port of allocValue's NegC + emitValue2's).
      g.forceRegDestE(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc                                 # result type
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
        if c.exprKind == NegC:
          g.ab.tree NegX64: g.emReg dest.r
        else:
          g.ab.tree NotX64: g.emReg dest.r
        if not (iv.kind == InReg and iv.r == dest.r): g.freeVal(iv)
    of SufC, ParC:                                # wrapper → the inner value
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
      # nil is a 0 of the `(nil)` type (a null pointer): keep the nil slot so
      # the consumer emits/binds `(nil)`, not an `(i 64)` 0.
      g.resolveDestE(dest, immLoc(0, g.exprSlot(c)))
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      if dest.kind == InReg:
        if dest.isTemp:
          if not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        elif g.rb.isBound(dest.r) and not g.rb.isPtrBound(dest.r):
          g.bindTemp(dest.r, g.exprSlot(c))       # displace the stale int-typed name
        g.ab.tree MovX64: (g.emReg dest.r; g.ab.nilValue())
    of OvfC:
      # Wrapping arithmetic: `(ovf)` is always false as a VALUE; materializing
      # it into a register would be a flag-read hazard — reject like before.
      g.resolveDestE(dest, immLoc(0, ScalarSlot))
      if dest.kind == InReg:
        raiseAssert "arkham x64n: (ovf) is only valid as an if/ite condition right after keepovf"
    of SizeofC:
      var t = c; var sz = 0'i64
      t.into:
        sz = typeSizeAlign(g.prog, t)[0].int64
        while t.hasMore: skip t
      g.emitLeafImm(dest, immLoc(sz, ScalarSlot))
    else: raiseAssert "arkham x64n: emitValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitValue2(fused) kind " & $c.kind

proc fbinOps(ek: LengExpr): (X64Inst, X64Inst) =
  ## (32-bit, 64-bit) SSE instruction pair for a float binary-arith node.
  case ek
  of AddC: (AddssX64, AddsdX64)
  of SubC: (SubssX64, SubsdX64)
  of MulC: (MulssX64, MulsdX64)
  of DivC: (DivssX64, DivsdX64)
  else: raiseAssert "arkham x64n: fbinOps " & $ek

proc ensureFAccum(g: var CodeGen; resF: FReg; loc: Location; bits: int) =
  ## Make the destructive-SSE accumulator `resF` hold the value just produced at
  ## `loc`. Normally the allocator fixed the producing operand's dest to the result
  ## register, so `loc` IS `resF` and this is a no-op; but when `resF` is a produce-into
  ## staging register (a spilled bin RESULT) the allocator placed the operand in its own
  ## location — move/load it in (the float analogue of the integer `place2`).
  case loc.kind
  of InFReg:
    if loc.f != resF:
      g.fmovF(resF, loc.f, bits)
      if loc.isTemp: g.unbindFTmp(loc.f)
  of NamedStack: g.emFloatScalarLoad(resF, loc.name, bits)
  else: raiseAssert "arkham x64n: float accumulator source " & $loc.kind

proc emLvalAddr2(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (the operand of a `(mem …)` /
  ## `(lea …)`), reading any embedded value register from its pre-allocated `locs`.
  ## v1 slice: a stack-var base (`(rsp) name`), a `dot` field over such a base or a
  ## `deref`, and a pointer `deref` (`(cast (ptr pointee) ptrReg)`).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm)
    if loc.kind == NoLoc:
      # a module-level global aggregate base: its address is in the pre-assigned base
      # register (materialized by prematLval2) — either the allocator's `locs[pos]` reg
      # or, for a transient load, the emit-time staging reg parked in `lvalGlobBase`.
      # Type it `(cast (ptr globalType) reg)` so the enclosing dot/at can compute the offset.
      let pos = cursorToPosition(g.buf[], c)
      let baseReg = (if g.lvalGlobBase.hasKey(pos): g.lvalGlobBase[pos]
                     else: g.ra.locs[pos].r)
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                             # (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg baseReg
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
          if g.lvalStride.hasKey(atPos):
            g.emReg g.lvalStride[atPos]                 # 3-operand form: non-SIB stride scratch
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
      let patPos = cursorToPosition(g.buf[], c)
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
          if g.lvalStride.hasKey(patPos):
            g.emReg g.lvalStride[patPos]                # 3-operand form: non-SIB stride scratch
          while cc.hasMore: skip cc
    of BaseobjC:
      # `(baseobj BaseType depth lvalue)` — an object→base view. The base sub-object is at
      # offset 0, so the ADDRESS is the inner lvalue's, only the TYPE narrows. A `(deref p)`
      # inner re-emits as `(cast (ptr BaseType) p)` (same pointer, base-typed, so an enclosing
      # `dot` resolves a base field and an `addr` yields `(ptr BaseType)`); any other inner
      # lvalue is emitted transparently (nifasm flattens inherited fields for resolution).
      var cc = c
      cc.into:
        let baseTy = cc; skip cc                          # the base type (a Symbol)
        skip cc                                           # depth
        if cc.kind == TagLit and cc.exprKind == DerefC:
          var dc = cc
          dc.into:
            let pReg = g.ra.locs[cursorToPosition(g.buf[], dc)]
            g.ab.tree CastX:
              g.ab.ptrType: g.ab.sym symName(baseTy)
              g.emReg pReg.r
            while dc.hasMore: skip dc
        else:
          g.emLvalAddr2(cc)                               # transparent (inherited fields flatten)
        while cc.hasMore: skip cc
    of AconstrC, OconstrC:
      # A constructor base materialized into `aggtmp<pos>` by `prematLval2`: address it as
      # an ordinary `(rsp) name` stack-var base.
      let pos = cursorToPosition(g.buf[], c)
      g.ab.reg RSP
      g.ab.sym ("aggtmp" & $pos & ".0")
    else: raiseAssert "arkham x64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emLvalAddr2 kind " & $c.kind

proc reloadMemBase2(g: var CodeGen; pos: int) =
  ## A `deref`/`pat`/`at` pointer base or register index the allocator left in a
  ## `NamedStack`/`Mem` home (a genuinely spilled pointer) must be in a register for
  ## `[reg]` addressing. Load it into a sealed staging reg, point its location at that
  ## reg for the lval emission, and park the original home in `savedHomes` so
  ## `restoreMemBase2` (via `unbindLvalTemps2`) puts it back. (A register-homed base is
  ## the common case and returns immediately — no steal can move it under us anymore.)
  let loc = g.ra.locs[pos]
  if loc.kind notin {NamedStack, Mem}: return
  let s = g.pickStagingSealed("a memory address base/index", loc.typ)
  g.emitLoadLoc(loc, s)
  g.savedHomes[pos] = loc
  g.ra.locs[pos] = regLoc(s, loc.typ)

proc restoreMemBase2(g: var CodeGen; pos: int) =
  ## Undo `reloadMemBase2`: release the staging reg and restore the local's stack home.
  if g.savedHomes.hasKey(pos):
    g.giveBack g.ra.locs[pos].r
    g.ra.locs[pos] = g.savedHomes[pos]
    g.savedHomes.del pos

proc takeLvalStride(g: var CodeGen; c: Cursor; atPos: int; asBase = false) =
  ## Reserve the non-SIB `(at/pat base idx scratch)` stride scratch from the emit-time
  ## STAGING set (the always-free R11 bridge + free caller-saved), NOT a pool register
  ## the allocator handed out — so it cannot starve when register-homed locals fill the
  ## pool (the x64 trepro `out of registers for an index stride scratch` case). Sealed +
  ## bound BEFORE the base/index are materialized, so their (possibly spilled) reloads
  ## via `pickStagingScratch` pick OTHER staging regs and never alias the scratch (the
  ## Bug-J disjointness invariant — nifasm also rejects scratch==base at assemble time).
  ## A nested `(at (at …) …)` nests fine: each level seals its own scratch, so the inner
  ## level's pick avoids the outer's. Released by `dropLvalStride` after the `(mem …)`.
  ##
  ## `asBase`: this `(at)`/`(pat)` is itself the BASE of an enclosing indexed access. x86
  ## allows only ONE index register per memory operand, so even a SIB-valid stride (the
  ## inner dimension of `a[i][j]` whose element size is 1/2/4/8) must materialize the inner
  ## address into a clean base register when its index is a register — else the fold would
  ## carry two index registers (the `(at (at base i) j)` two-register case nifasm rejects).
  if not (g.atNeedsScratch(c) or (asBase and g.atIndexIsReg(c))): return
  let s = g.pickStagingScratch()
  if s == NoReg: raiseAssert "arkham x64: no staging register for an (at) stride scratch"
  g.ra.seal s
  g.bindTemp(s, AsmSlot(cls: AInt, size: 8, align: 8))
  g.lvalStride[atPos] = s

proc dropLvalStride(g: var CodeGen; atPos: int) =
  ## Release a `takeLvalStride` scratch after the consuming `(mem …)`/`(lea …)`.
  if g.lvalStride.hasKey(atPos):
    let s = g.lvalStride[atPos]
    g.unbindTemp(s)
    g.ra.unseal s
    g.lvalStride.del atPos

proc prematAddrVal2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue base/index value `c` into a register for the enclosing
  ## `(mem …)`. A register-homed base materializes in place; a genuinely spilled base
  ## (`NamedStack`/`Mem`) is brought into a staging reg by `reloadMemBase2`. Scoped to
  ## the lvalue tree (NOT general `emitValue2`). The destination was decided by
  ## `emitLvalue2` (`resolveLvalVal`) and parked in the memo; thread it.
  let pos = cursorToPosition(g.buf[], c)
  var d = g.ra.locs[pos]
  g.emitValue2(c, d)
  g.ra.locs[pos] = d
  g.reloadMemBase2(pos)

proc prematLval2(g: var CodeGen; c: Cursor; asBase = false) =
  ## Materialize an lvalue's embedded values (a `deref` pointer, an index, a global
  ## base's address) into their allocated registers BEFORE the consuming `(mem …)` /
  ## `(lea …)` tree opens (an emit-inside-the-tree would corrupt it). For a stack /
  ## register-pointer symbol base this is a no-op.
  if c.kind == Symbol:
    # A module-level global aggregate base: `lea baseReg, &global`. The base register
    # (the access result for a load/addr, or a store scratch) was assigned by the
    # allocator and is already bound by the caller — see emitMemLoad2 / emitAddr2.
    let pos = cursorToPosition(g.buf[], c)
    let loc = g.ra.locs[pos]
    if g.ra.locationOfSym(symName(c)).kind == NoLoc:        # a module-level global / threadvar base
      if loc.kind == InReg:
        g.emSymAddrByName(loc.r, symName(c))                # allocator-assigned base reg (glob or tvar)
      else:
        # transient base (the allocator reserved nothing): lea &sym into an emit-time
        # staging GPR (R11 bridge), parked in `lvalGlobBase` for `emLvalAddr2`, released
        # by `unbindLvalTemps2`. Sealed+bound BEFORE any sibling premat picks staging.
        let s = g.pickStagingScratch()
        if s == NoReg: raiseAssert "arkham x64: no staging register for a global base address"
        g.ra.seal s
        g.bindTemp(s, AsmSlot(cls: AUInt, size: 8, align: 8))
        g.lvalGlobBase[pos] = s
        g.emSymAddrByName(s, symName(c))                    # &global (RIP-rel) / &threadvar (FS+off)
    return
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.prematLval2(cc, asBase)                       # a dot over an indexed base propagates
        while cc.hasMore: skip cc
    of DerefC:
      var cc = c
      cc.into:
        g.prematAddrVal2(cc)                            # the pointer → its register (follow steals)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      g.takeLvalStride(c, atPos, asBase)                # stride / nested-base scratch ← staging
      var cc = c
      cc.into:
        g.prematLval2(cc, asBase = true); skip cc       # base IS indexed by THIS at
        if cc.kind notin {IntLit, UIntLit}:             # register index → its reg
          g.prematAddrVal2(cc)                          # follow steals
        while cc.hasMore: skip cc
    of PatC:
      let patPos = cursorToPosition(g.buf[], c)
      g.takeLvalStride(c, patPos, asBase)               # stride / nested-base scratch ← staging
      var cc = c
      cc.into:
        g.prematAddrVal2(cc)                            # the pointer → its register (follow steals)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:             # register index → its reg
          g.prematAddrVal2(cc)                          # follow steals
        while cc.hasMore: skip cc
    of BaseobjC:                                        # transparent: materialize the inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                               # base type, depth
        g.prematLval2(cc)                              # the inner lvalue
        while cc.hasMore: skip cc
    of AconstrC, OconstrC:
      # A constructor used as an lvalue base (`[a,b][i]`): build it into a synthetic stack
      # temp `aggtmp<pos>` HERE (before the access instruction opens), then address that
      # temp in `emLvalAddr2`. Mirrors the aggregate call-arg materialization.
      let pos = cursorToPosition(g.buf[], c)
      let home = "aggtmp" & $pos & ".0"
      var tcur = c; inc tcur                            # the constructed (array/object) type
      g.emTypedStackVar(home, tcur)
      if tcur.kind == Symbol: g.varType[home] = symName(tcur)
      g.genStore2(c, namedStackLoc(home, g.exprSlot(c)))
    else: discard

proc unbindLvalTemps2(g: var CodeGen; c: Cursor) =
  ## Release any scratch temp an lvalue's embedded value was loaded into (e.g. a
  ## stack-homed pointer reloaded for a `deref`/`pat`), AFTER the consuming
  ## (mem …)/(lea …) instruction. A reg-homed base sits in its own home (not a temp)
  ## ⇒ no-op. The load/store RESULT temp is separate (the consumer unbinds it).
  if c.kind == Symbol:
    let pos = cursorToPosition(g.buf[], c)
    if g.lvalGlobBase.hasKey(pos):                    # transient global-base staging reg
      let s = g.lvalGlobBase[pos]
      g.unbindTemp(s)
      g.ra.unseal s
      g.lvalGlobBase.del pos
    return
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
          let idxPos = cursorToPosition(g.buf[], cc)
          g.restoreMemBase2(idxPos)                      # demoted (stolen) index reload
          let il = g.ra.locs[idxPos]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      g.dropLvalStride(atPos)                            # the non-SIB stride scratch
    of DerefC:
      var cc = c
      cc.into:
        let pPos = cursorToPosition(g.buf[], cc)
        g.restoreMemBase2(pPos)                          # demoted (stolen) pointer reload
        let ploc = g.ra.locs[pPos]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        while cc.hasMore: skip cc
    of PatC:
      let patPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        let pPos = cursorToPosition(g.buf[], cc)
        g.restoreMemBase2(pPos)                          # demoted (stolen) pointer reload
        let ploc = g.ra.locs[pPos]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        skip cc                                          # pointer
        if cc.kind notin {IntLit, UIntLit}:             # register index temp
          let idxPos = cursorToPosition(g.buf[], cc)
          g.restoreMemBase2(idxPos)                      # demoted (stolen) index reload
          let il = g.ra.locs[idxPos]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      g.dropLvalStride(patPos)                            # the non-SIB stride scratch
    of BaseobjC:                                        # transparent: release the inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                               # base type, depth
        g.unbindLvalTemps2(cc)                         # the inner lvalue
        while cc.hasMore: skip cc
    else: discard

proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor) =
  ## `dest op= [<lvalue c>]` — fold a memory-load operand into an ALU op via the
  ## value-core address machinery (prematLval2 / emLvalAddr2 / unbindLvalTemps2).
  ## The mirror of emitMemLoad2 with an ALU op in place of the load `mov`.
  g.prematLval2(c)
  g.ab.tree op:
    g.emReg dest
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)

proc aggrAddrInto(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool) =
  ## THE address-of any lvalue into register `dest`: `&(deref p)`
  ## is `p` itself; a global/threadvar leas its absolute address; a `baseobj` is the inner
  ## lvalue's address (base sub-object at offset 0), retyped; anything else leas the
  ## `emLvalAddr2` subtree. `doBind` names a fresh temp `dest` (ptr-typed via `aslot`,
  ## except a deref carries the pointer's own nominal type). The single source of truth
  ## for "where does this aggregate/lvalue live", shared by `(addr …)`, the aggregate
  ## marshalling, and the aggregate copy.
  if lv.kind == TagLit and lv.exprKind == DerefC:
    # &(deref p) == p — produce the pointer directly into dest. Carry p's own (named,
    # unresolved) pointer type, not `aslot`'s structural spelling, so a peer `ptr Named`
    # in a later compare/store matches.
    var p: Cursor
    block:
      var dd = lv
      dd.into:
        p = dd; skip dd
        while dd.hasMore: skip dd
    var pLoc = g.ra.locs[cursorToPosition(g.buf[], p)]  # the CALLER's walk decided p's spot
    g.emitValue2(p, pLoc)
    g.ra.locs[cursorToPosition(g.buf[], p)] = pLoc
    if doBind:
      g.bindTemp(dest, AsmSlot(cls: AUInt, size: 8, align: 8, typ: g.getType(p)))
    g.place2(pLoc, dest)
    if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
  elif lv.kind == TagLit and lv.exprKind == BaseobjC:
    # `&(baseobj BaseT depth inner)`: base sub-object at offset 0, so the address is
    # `&inner` retyped to `(ptr BaseT)`.
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
      var pLoc = g.ra.locs[cursorToPosition(g.buf[], p)] # the CALLER's walk decided p's spot
      g.emitValue2(p, pLoc)
      g.ra.locs[cursorToPosition(g.buf[], p)] = pLoc
      if doBind: g.bindTemp(dest, aslot)                  # (ptr BaseT)
      g.place2(pLoc, dest)
      if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
    else:
      if doBind: g.bindTemp(dest, aslot)
      g.prematLval2(inner)
      g.ab.tree LeaX64: (g.emReg dest; g.emLvalAddr2(inner))
      g.unbindLvalTemps2(inner)
  elif lv.kind == Symbol and g.lookupSym(symName(lv)).cat in {scGlobal, scTvar}:
    # &global / &threadvar (no stack base / embedded value to materialize).
    if doBind: g.bindTemp(dest, aslot)
    var lc = lv
    let loc = g.asLoc(lc)                                # Glob/Tvar with the global's precise type
    case loc.kind
    of Glob: g.emGlobalAddr(dest, loc.name)             # &global → RIP-relative lea
    of Tvar:                                            # &threadvar = FS base + offset (folded)
      # A foreign tvar (other module) resolves the same way — nifasm whole-program-links
      # and folds its unified-block FS offset into the lea (see `emTvarAddr`).
      g.emGlobalAddr(dest, TlsBlockName)
      g.ab.tree LeaX64: (g.emReg dest; g.emReg dest; g.ab.sym loc.name)
    else: raiseAssert "arkham x64n: &sym resolved to " & $loc.kind
  elif lv.kind == Symbol:                               # a LOCAL aggregate var
    let home = g.ra.locationOfSym(symName(lv))
    if doBind: g.bindTemp(dest, aslot)
    case home.kind
    of NamedStack: g.emStackAddr(dest, home.name)       # &local stack slot
    of InReg: g.movReg(dest, home.r)                    # by-ref aggregate param: reg holds &it
    else: raiseAssert "arkham x64n: aggrAddr of local " & symName(lv) & " home " & $home.kind
  else:
    if doBind: g.bindTemp(dest, aslot)                  # bind first: a global base leas &g into dest
    var bound: seq[Reg] = @[]
    g.bindLvalGlobalBases(lv, bound)                    # bind any UNBOUND global-base reg first
    g.prematLval2(lv)
    g.ab.tree LeaX64:
      g.emReg dest
      g.emLvalAddr2(lv)
    g.unbindLvalTemps2(lv)
    for r in bound: g.unbindTemp(r)

proc fieldSlotByName(g: var CodeGen; typeName, field: string): AsmSlot =
  ## The asm slot of `typeName.field` — so an aggregate-copy scratch can be typed to
  ## match the field (nifasm is strict: a `(ptr T)` field can't move through an
  ## `(i 64)` register). Resolves the object body from the type's decl like aggrLayout.
  var d = lookupType(g.prog, typeName)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = slotOf(g.prog, fieldType(g.prog, d, field))
    while d.hasMore: skip d

proc genAggrCopy2(g: var CodeGen; dstVar, srcVar, typeName: string; tmp: Reg) =
  ## Whole-aggregate copy `dstVar ← srcVar`, one FIELD at a time through the allocator-
  ## provided scratch GPR `tmp` (typed per field, so a pointer field keeps `(ptr T)`).
  ## Both operands address by name via emAggrFieldMem (a stack `(s)` slot's dot form,
  ## or a by-ref param's pointer). A per-field copy (vs. per-8-byte-word) moves every
  ## field at its own type, so a struct with two fields PACKED into one eightbyte
  ## (e.g. `{int32; int32}`) copies BOTH — a word-by-word copy carried only the field
  ## at the eightbyte boundary and dropped the rest. (The register-ABI marshalling
  ## `transferAggrWords` must stay word-granular and handles packing via raw u64
  ## words; a memory→memory copy has no such constraint, so per-field is simplest.)
  for f in aggrLayout(g.prog, typeName):
    g.bindTemp(tmp, g.fieldSlotByName(typeName, f.name))
    g.ab.tree MovX64: (g.emReg tmp; g.emAggrFieldMem(srcVar, f.name))
    g.ab.tree MovX64: (g.emAggrFieldMem(dstVar, f.name); g.emReg tmp)
    g.unbindTemp(tmp)

proc emByteAtImm(g: var CodeGen; p: Reg; off: int) =
  ## `(mem (at (cast (aptr (u 8)) p) off))` — the byte at `[p + off]` (immediate offset).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg p
      g.ab.intLit off.int64

proc emWordAtSlot(g: var CodeGen; name: string; off: int) =
  ## `(cast (u 64) (mem (rsp) name off))` — the eightbyte at byte offset `off` of the
  ## NAMED stack slot `name`, typed as a raw word. The pointer twin `emWordThroughPtr`
  ## needs the slot's ADDRESS in a register first; this needs no register at all,
  ## because nifasm folds `off` into the slot's own rsp displacement (and bounds-checks
  ## it against the slot, which the register form cannot).
  g.ab.tree CastX:
    g.ab.uintType(64)
    g.ab.tree MemX:
      g.ab.reg RSP
      g.ab.sym name
      g.ab.intLit off.int64

proc emByteAtSlot(g: var CodeGen; name: string; off: int) =
  ## The byte-granular `emWordAtSlot`, for a copy's sub-word tail.
  g.ab.tree CastX:
    g.ab.uintType(8)
    g.ab.tree MemX:
      g.ab.reg RSP
      g.ab.sym name
      g.ab.intLit off.int64

type AggrEnd = object
  ## One end (source or destination) of a whole-aggregate copy, in the form the MACHINE
  ## can actually address it:
  ##   * a NAMED rsp-relative `(s)` slot — costs ZERO registers, each word addressed as
  ##     `(mem (rsp) slot off)`;
  ##   * an address already materialized in a register — costs one.
  ## Making the form explicit is what TIERS the copy's register demand: a copy between
  ## two named slots needs only the transfer register, one named end needs two, and only
  ## a copy between two computed addresses needs the three that used to be demanded
  ## unconditionally. That last tier is what exhausted the emit-time staging pool under
  ## `-d:danger` (every volatile hosting a call-free local), and it is now rare rather
  ## than universal.
  slot: string        ## non-empty ⇒ an rsp-relative named slot
  reg: Reg            ## else, the register holding the aggregate's address

proc slotEnd(name: string): AggrEnd {.inline.} = AggrEnd(slot: name, reg: NoReg)
proc regEnd(r: Reg): AggrEnd {.inline.} = AggrEnd(slot: "", reg: r)

proc emWordAt(g: var CodeGen; e: AggrEnd; idx: int) =
  if e.slot.len > 0: g.emWordAtSlot(e.slot, idx * 8)
  else: g.emWordThroughPtr(e.reg, idx)

proc emByteAt(g: var CodeGen; e: AggrEnd; off: int) =
  if e.slot.len > 0: g.emByteAtSlot(e.slot, off)
  else: g.emByteAtImm(e.reg, off)

proc copyAggr(g: var CodeGen; dst, src: AggrEnd; size: int; tmp: Reg) =
  ## Copy `size` bytes from `src` to `dst` through the bound scratch `tmp` — 8-byte words
  ## for the aligned bulk, then a sized byte tail. Layout-agnostic and byte-accurate, so it
  ## is TOTAL for any aggregate regardless of field packing. nifasm's sized mem↔reg move
  ## extends a byte load / truncates a byte store, so `tmp` stays a plain `(u 64)`.
  ## (`tmp` and any register end are bound by the caller.)
  let words = size div 8
  for i in 0 ..< words:
    g.ab.tree MovX64: (g.emReg tmp; g.emWordAt(src, i))
    g.ab.tree MovX64: (g.emWordAt(dst, i); g.emReg tmp)
  for b in 0 ..< (size - words * 8):                     # sub-word tail, byte by byte
    let off = words * 8 + b
    g.ab.tree MovX64: (g.emReg tmp; g.emByteAt(src, off))
    g.ab.tree MovX64: (g.emByteAt(dst, off); g.emReg tmp)

proc copyAggr(g: var CodeGen; dst, src: Reg; size: int; tmp: Reg) {.inline.} =
  ## Both ends are addresses in registers — the historical shape.
  g.copyAggr(regEnd(dst), regEnd(src), size, tmp)

proc aggrSrcEnd(g: var CodeGen; name: string; staged: var Reg): AggrEnd =
  ## The copy-source form of the aggregate `name`, and how many registers it costs:
  ##   * an rsp-relative `(s)` slot — an allocator-homed `NamedStack` local OR an emitter-
  ##     synthesized temp (`stackSlots`) — costs NOTHING;
  ##   * a by-ref aggregate param, whose pointer is ALREADY in a register, costs nothing
  ##     either (the old code copied that register into a fresh staging one);
  ##   * only a module-level global/const/threadvar genuinely needs an address, because its
  ##     `lea` is RIP-relative and there is no rsp-relative form of it.
  ## `staged` receives the register to `giveBack`, or `NoReg`.
  staged = NoReg
  let home = g.ra.locationOfSym(name)
  case home.kind
  of NamedStack: return slotEnd(name)
  of InReg: return regEnd(home.r)
  else:
    if name in g.stackSlots: return slotEnd(name)
    staged = g.pickStagingSealed("an aggregate-copy source address", AddrSlot)
    g.emSymAddrByName(staged, name)
    return regEnd(staged)

proc emAggrSrcAddr(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &name` for an aggregate SOURCE that may be a local stack slot, a by-ref
  ## aggregate param (its pointer is already in a register), OR a module-level
  ## global / `const` / threadvar. `locationOfSym` yields NamedStack/InReg for a local
  ## and `NoLoc` for a module-level symbol (disambiguated by category in
  ## `emSymAddrByName`). Crucially, the rsp-base `emStackAddr` must NOT be used for a
  ## global/const — its address is RIP-relative, not stack-relative (e.g. copying a
  ## global `const` aggregate like `NoNifLineInfo` out via a `return`).
  let home = g.ra.locationOfSym(name)
  case home.kind
  of NamedStack: g.emStackAddr(dest, name)
  of InReg: g.movReg(dest, home.r)
  else: g.emSymAddrByName(dest, name)

proc copyStructThroughPtr2(g: var CodeGen; srcVar, typeName: string; ptrReg: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at (the >16B aggregate hidden-result-
  ## pointer return). This runs at the `ret` and crosses NO call, so its scratch comes
  ## from the transient staging pool, never a callee-saved survivor (a survivor would
  ## force the allocator to find a stealable callee-saved local, which can spuriously
  ## fail). Usually that is ONE register — the word-transfer temp — because the source
  ## is a stack slot or an already-held pointer (`aggrSrcEnd`); only a global source
  ## stages a second.
  var sp = NoReg
  let src = g.aggrSrcEnd(srcVar, sp)
  let tmp = g.pickStagingSealed("a struct-through-ptr word", AddrSlot, avoid = sp)
  g.copyAggr(regEnd(ptrReg), src, aggrByteSize(g.prog, typeName), tmp)
  g.giveBack tmp
  g.giveBack sp

proc emWordThroughPtr(g: var CodeGen; p: Reg; idx: int) =
  ## `(mem (at (cast (aptr (u 64)) p) idx))` — the `idx`-th 8-byte word at `[p]`, typed
  ## `(u 64)`. nifasm scales `idx` by 8, so this is raw `[p + idx*8]` access that
  ## ignores the aggregate's field layout entirely.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(64)
        g.emReg p
      g.ab.intLit idx.int64

proc emPtrElemMem(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## `(mem (at (cast (aptr ElemTy) p) idx))` — element `idx` of an array whose first
  ## element is at `[p]`; nifasm scales `idx` by the element size (from ElemTy) and
  ## sizes the access from ElemTy. Used to build an `aconstr` straight into the array
  ## addressed by a pointer (e.g. a global's address) — the array twin of
  ## `emPtrFieldMem`.
  var et = elemTy
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.genTypeBody(et)
        g.emReg p
      g.ab.intLit idx.int64

proc regsToStructThroughPtr(g: var CodeGen; ptrReg: Reg; typeName: string;
                            regs: openArray[Reg]) =
  ## `[ptrReg] ← regs` — marshal a ≤16B aggregate held in `regs` (the by-value ABI
  ## return registers rax:rdx) into the memory `ptrReg` points at. A FULL eightbyte is
  ## a raw `(u 64)` word (handles packed fields); a trailing PARTIAL eightbyte (a
  ## single sub-word field) uses the field-typed access. The through-pointer twin of
  ## `regsToStruct` (which addresses a named stack slot) — used to store an aggregate
  ## call result into a global.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emWordThroughPtr(ptrReg, i); g.emReg regs[i])
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovX64: (g.emPtrFieldMem(ptrReg, typeName, fn); g.emReg regs[i])

proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string;
                         regs: openArray[Reg]) =
  ## `regs ← [addrReg]` — load a ≤16B aggregate at `[addrReg]` into the by-value ABI
  ## argument registers (a FULL eightbyte as a raw `(u 64)` word, a trailing PARTIAL via
  ## the field-typed access). The reverse of `regsToStructThroughPtr`; lets an aggregate
  ## CALL ARGUMENT marshal straight from its address (`aggrAddrInto`) with no copy temp.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(addrReg, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(addrReg, typeName, fn))

proc flatCopyToPtr(g: var CodeGen; srcVar: string; sizeBytes: int; dstPtr, tmp: Reg) =
  ## Copy the `sizeBytes`-byte aggregate stack slot `srcVar` into `[dstPtr]`, through
  ## scratch `tmp`, by the one `copyAggr` (word bulk + byte tail — any size,
  ## layout-agnostic). `srcVar` is a synthetic `(s)` slot at every call site, so the
  ## source is addressed straight off rsp and the copy holds TWO registers, not three.
  ## Three was the count that exhausted the staging pool in `toDecimal64` under
  ## `-d:danger`, and it was never a machine requirement — only a consequence of forcing
  ## every source into a register first.
  g.bindTemp(tmp, AsmSlot(cls: AUInt, size: 8, align: 8))
  var sp = NoReg
  let src = g.aggrSrcEnd(srcVar, sp)
  g.copyAggr(regEnd(dstPtr), src, sizeBytes, tmp)
  g.giveBack sp
  g.unbindTemp(tmp)

proc buildNestedAggrTemp(g: var CodeGen; valC, fty: Cursor): (string, int) =
  ## Build an aggregate field/element value `valC` (an inline `(oconstr/aconstr …)`, an
  ## aggregate symbol, or a memory lvalue) — of declared nominal type `fty` — into a
  ## synthetic stack temp through the general `genStore2` (which recurses for deeper
  ## nesting), and return the temp's name + byte size.
  ##
  ## The caller derives the DESTINATION pointer only AFTER this returns (then calls
  ## `copyNestedAggrTemp`): a pointer held across the build costs one staging register
  ## per nesting level, and a depth-4 nest exhausted the pool. Computing it afterwards
  ## keeps only two staging registers live at once — the destination pointer and the
  ## word-transfer scratch — so nesting is no longer depth-bounded by the pool size.
  ## (a64's `genNestedAggrField` already orders it this way; this is the x64 twin.)
  if fty.kind != Symbol:
    raiseAssert "arkham x64n: nested aggregate field of non-nominal type"
  let ntn = symName(fty)
  let pos = cursorToPosition(g.buf[], valC)
  let tmpName = "nctmp" & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, g.exprSlot(valC)))   # build (no staging held)
  (tmpName, aggrByteSize(g.prog, ntn))

proc copyNestedAggrTemp(g: var CodeGen; tmpName: string; sizeBytes: int; dstPtr: Reg) =
  ## Copy a `buildNestedAggrTemp` temp into the sub-aggregate at `[dstPtr]`.
  let scratch = g.pickStagingSealed("a nested-aggregate-field copy word", AddrSlot)
  g.flatCopyToPtr(tmpName, sizeBytes, dstPtr, scratch)
  g.giveBack scratch

proc emLvalFieldMem(g: var CodeGen; lhs: Cursor; field: string) =
  ## `(mem (dot <lvalue address> field))` — a field within the aggregate addressed by
  ## the lvalue `lhs` (a `dot`/`at`/`deref` chain). The lvalue's embedded value
  ## registers must already be materialized (`prematLval2`).
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.emLvalAddr2(lhs)
      g.ab.sym field

proc bindLvalGlobalBases(g: var CodeGen; c: Cursor; bound: var seq[Reg]) =
  ## Bind the pre-assigned address register of every global base in lvalue `c`, so
  ## `prematLval2` leas `&global` into a BOUND register before the `(mem …)` tree
  ## opens (emReg rejects an unbound scratch-pool reg). The scalar load reuses its
  ## result temp for this (see emitMemLoad2's "bind first"); an aggregate copy has
  ## no result reg, so it binds the base regs explicitly. Recurses only into the
  ## BASE (first child) of a dot/at/deref — not the index/field.
  if c.kind == Symbol:
    let loc = g.ra.locs[cursorToPosition(g.buf[], c)]
    if loc.kind == InReg and loc.isTemp and not g.rb.isBoundTemp(loc.r) and
       g.ra.locationOfSym(symName(c)).kind == NoLoc:
      # only an UNBOUND base reg (else the caller already bound it — e.g. `emitAddr2`
      # reuses its bound result reg for the global base; rebinding would clobber it).
      g.bindTemp(loc.r, ScalarSlot)
      bound.add loc.r
  elif c.kind == TagLit and c.exprKind in {AtC, DotC, DerefC, PatC}:
    var cc = c
    cc.into:
      g.bindLvalGlobalBases(cc, bound); skip cc          # the base only
      while cc.hasMore: skip cc

proc emFieldOperand(g: var CodeGen; dst: Location) =
  ## The `(mem (dot <base> field))` operand for a `Field` destination, dispatching on
  ## how its base aggregate is addressed (a pointer register / a named stack slot / an
  ## lvalue subtree). nifasm sizes the access from the field's declared type. A
  ## `FbGlob`/`FbTvar` (survivor-spill) base must be pre-materialized into an `FbReg`
  ## by the caller BEFORE the enclosing store instruction opens — `emGlobalAddr` is a
  ## separate `lea`, so re-deriving it inside this operand would corrupt the open tree.
  case dst.base.kind
  of FbReg:  g.emPtrFieldMem(dst.base.reg, dst.aggrType, dst.field)
  of FbSlot: g.emAggrFieldMem(dst.base.sym, dst.field)
  of FbLval: g.emLvalFieldMem(dst.base.lval, dst.field)
  of FbGlob, FbTvar:
    raiseAssert "arkham x64n: FbGlob/FbTvar field base must be pre-materialized " &
                "(materializeGlobBase) before the operand opens"

proc emFieldAddr(g: var CodeGen; dst: Location; into: Reg) =
  ## `&(base.field)` → `into`: just `lea` over the field's own memory operand, so the
  ## base forms need no special handling. The recursion base for a nested aggregate
  ## field.
  g.ab.tree LeaX64: (g.emReg into; g.emFieldOperand(dst))

proc fieldTypeByName(g: var CodeGen; typeName, field: string): Cursor =
  ## The declared (nominal) type cursor of `typeName.field` — resolves the object body
  ## from the type's decl like `fieldSlotByName`.
  var d = lookupType(g.prog, typeName)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = fieldType(g.prog, d, field)
    while d.hasMore: skip d

proc materializeGlobBase(g: var CodeGen; dst: Location; avoid: Reg): (Location, Reg) =
  ## If `dst` is a survivor-spill `baseGlob` field (the `reserveHeldScratch` totality
  ## backstop: `&g` could not be held in a callee-saved register), re-`lea` `&g` into a
  ## fresh transient and return an equivalent `baseReg` field over it (plus the transient
  ## to `giveBack`). Otherwise pass `dst` through unchanged (`NoReg` cleanup).
  ##
  ## For a SCALAR field this must be called AFTER the value is evaluated, so the transient
  ## need not survive the value's possible call (a global address is re-derivable, so we
  ## simply recompute it here instead of holding it across the call).
  if dst.base.kind notin {FbGlob, FbTvar}: return (dst, NoReg)
  let t = g.pickStagingSealed("a re-derived global field base", AddrSlot, avoid = avoid)
  g.emSymAddr(t, (if dst.base.kind == FbTvar: tvarLoc(dst.base.sym, dst.typ)
                  else: globLoc(dst.base.sym, dst.typ)))
  (fieldLocReg(dst.aggrType, dst.field, t, dst.typ), t)

proc genFieldStore2(g: var CodeGen; dst: Location; valC: Cursor) =
  ## Store value `valC` into the aggregate-field destination `dst` — the `Field` case
  ## of `genStore2`, and the ONE per-field store behind `genConstr2`. A scalar/float/
  ## pointer field emits its value and moves it into the field operand (a POINTER field
  ## reinterprets a scalar register via `(cast (ptr …) reg)` for nifasm's strict
  ## typing); a nested aggregate field recurses (`genNestedAggrField` builds/copies the
  ## value into the field's address). No per-field special-casing at the call site.
  if dst.typ.kind == AMem:                              # nested aggregate field
    # Build the value into its own stack temp FIRST, holding nothing (see
    # `buildNestedAggrTemp`), and only then derive the field address for the copy.
    # A `baseGlob` (spilled-survivor) base is likewise re-derived AFTER the build, so
    # its transient crosses no call rather than being held across the whole recursion.
    let ftyCur = g.fieldTypeByName(dst.aggrType, dst.field)
    let (tmpName, sizeBytes) = g.buildNestedAggrTemp(valC, ftyCur)
    let (d, gbTmp) = g.materializeGlobBase(dst, NoReg)
    let fptr = g.pickStagingSealed("a nested-aggregate-field pointer", AddrSlot)
    g.emFieldAddr(d, fptr)
    g.copyNestedAggrTemp(tmpName, sizeBytes, fptr)
    g.giveBack fptr
    if gbTmp != NoReg: g.giveBack gbTmp
  else:                                                 # scalar / float / pointer field
    var v: Location
    if g.isFloatExpr(valC):
      v = dontCare
      g.emitFValue2(valC, v)
    else:
      v = needsReg(ScalarSlot)                          # single-use (allocSingleUse's shape)
      g.emitValue2(valC, v)
    # Re-derive a spilled-survivor `&g` AFTER the value eval (so it survives no call).
    let (d, gbTmp) = g.materializeGlobBase(dst, if v.kind == InReg: v.r else: NoReg)
    if v.kind == InFReg:                                # float field
      let bits = if v.typ.size == 4: 32 else: 64
      g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
        g.emFieldOperand(d)
        g.emFReg v.f
      if v.isTemp: g.unbindFTmp(v.f)
    elif v.kind == NamedStack:
      # A foldable stack-homed scalar/pointer rhs — e.g. a demoted local/param read
      # straight from its `(s)` slot. x86 has no mem→mem `mov`, so bridge the value
      # through a staging register before storing it into the field operand.
      var fty = resolveType(g.prog, g.fieldTypeByName(d.aggrType, d.field))
      let s = g.pickStagingSealed("a constr field stack rhs", v.typ)
      g.emitLoadLoc(v, s)
      g.ab.tree MovX64:
        g.emFieldOperand(d)
        if isPtrType(fty):
          g.ab.tree CastX:
            g.genTypeBody(fty)
            g.emReg s
        else:
          g.emReg s
      g.giveBack s
    else:
      var fty = resolveType(g.prog, g.fieldTypeByName(d.aggrType, d.field))
      g.ab.tree MovX64:
        g.emFieldOperand(d)
        case v.kind
        of Imm: g.emImm(v)
        of InReg:
          if isPtrType(fty):
            g.ab.tree CastX:
              g.genTypeBody(fty)
              g.emReg v.r
          else:
            g.emReg v.r
        else: raiseAssert "arkham x64n: constr field rhs " & $v.kind
      if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
    if gbTmp != NoReg: g.giveBack gbTmp

proc constrFieldStores(g: var CodeGen; c: Cursor; base: Location) =
  ## The ONE field-store loop behind `genConstr2`/`genConstrIntoLval2`/nested fields:
  ## walk `(oconstr T child*)` and store each value into its field via the uniform
  ## `genFieldStore2`. `base` names the destination aggregate — a stack slot
  ## (`NamedStack`), a pointer in a register (`InReg`), or an lvalue subtree (`Mem`,
  ## pre-materialized by the caller).
  ##
  ## A child is one of: a `(kv field value)` (store at that field); a nested
  ## `(oconstr BaseT …)` (an INHERITED base sub-object — recurse, storing the base's
  ## fields BY NAME into the same destination: nifasm flattens inherited fields, so
  ## each resolves to its offset-0-relative slot in the derived aggregate); or a
  ## leading BARE value (the inherited base's positional initializer, in practice the
  ## RTTI/vtable header pointer at offset 0 — `aggrLayout` lists base fields first, so
  ## it fills the next positional field). This mirrors the leng C backend's oconstr.
  var tc = c; inc tc                                    # the constructed type symbol
  let typeName = symName(tc)
  var cc = c
  cc.into:
    skip cc                                             # the constructed type
    var posIdx = 0                                      # positional (inherited-base) value index
    template storeField(field: string; valC: Cursor) =
      let fSlot = g.fieldSlotByName(typeName, field)
      let fdst =
        case base.kind
        of NamedStack: fieldLoc(typeName, field, base.name, fSlot)
        of InReg:      fieldLocReg(typeName, field, base.r, fSlot)
        of Mem:        fieldLocLval(typeName, field, base.cur, fSlot)
        of Glob, Tvar: fieldLocGlob(typeName, field, base.name, fSlot,  # addr re-derived per store
                                    isTvar = base.kind == Tvar)
        else: raiseAssert "arkham x64n: bad oconstr base " & $base.kind
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
        storeField(aggrLayout(g.prog, typeName)[posIdx].name, cc)
        inc posIdx
      skip cc

proc genConstrIntoLval2(g: var CodeGen; c: Cursor; lhs: Cursor) =
  ## Emit `(oconstr T (kv field value)*)` straight into the memory aggregate addressed
  ## by lvalue `lhs` (e.g. `n->chunks[0] = (p, size)`). The address-targeted twin of
  ## `genConstr2`: materialize the lvalue's embedded regs once, then store each field
  ## value at `(dot <lhs> field)`.
  g.prematLval2(lhs)                                     # the lvalue's base/index regs, once
  g.constrFieldStores(c, memLoc(lhs, ScalarSlot))        # base = the lvalue subtree
  g.unbindLvalTemps2(lhs)                                # release the lvalue's base/index temps

proc emLvalElemMem(g: var CodeGen; lhs: Cursor; idx: int) =
  ## `(mem (at <lvalue address> idx))` — element `idx` of the array addressed by `lhs`.
  ## The lvalue's embedded value registers must already be materialized (`prematLval2`).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.emLvalAddr2(lhs)
      g.ab.intLit idx

template aconstrElemStores(g: var CodeGen; c: Cursor; destOp: untyped) =
  ## The ONE element-store loop behind `genAconstr2`/`genAconstrIntoLval2`: walk
  ## `(aconstr ArrayT e0 e1 …)`, emit each (bare) element value and store it at the
  ## destination operand `destOp(i)` emits. nifasm sizes each store from the array's
  ## element type; a pointer element is reinterpreted via `(cast (ptr …) reg)` for
  ## nifasm's strict typing. The array twin of `constrFieldStores`.
  block:
    var tc = c; inc tc                                  # the array type
    let elemTyRaw = innerType(g.prog, resolveType(g.prog, tc))  # nominal element type
    let elemSlot = slotOf(g.prog, elemTyRaw)
    let et = resolveType(g.prog, elemTyRaw)
    let etIsPtr = isPtrType(et)
    var cc = c
    cc.into:
      skip cc                                           # the array type
      var i = 0
      while cc.hasMore:
        let valC = cc
        if elemSlot.kind == AMem:                       # nested aggregate element
          # Build first, lea `&element[i]` after — the field twin's depth-independence
          # (see `buildNestedAggrTemp`) applies to array elements just the same.
          let (tmpName, sizeBytes) = g.buildNestedAggrTemp(valC, elemTyRaw)
          let eptr = g.pickStagingSealed("an aconstr aggregate-element pointer", AddrSlot)
          g.ab.tree LeaX64: (g.emReg eptr; destOp(i))   # &element[i]
          g.copyNestedAggrTemp(tmpName, sizeBytes, eptr)
          g.giveBack eptr
          inc i
          skip cc
          continue
        var v: Location
        if g.isFloatExpr(valC):
          v = dontCare
          g.emitFValue2(valC, v)
        else:
          v = needsReg(ScalarSlot)
          g.emitValue2(valC, v)
        if v.kind == InFReg:                            # float element
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            destOp(i)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          # scalar/ptr element. The element must be in a GPR to store (no mem→mem
          # mov); load a spilled (NamedStack) value into a staging register first.
          var vReg: Reg
          var ownV = false
          if v.kind == InReg:
            vReg = v.r
          else:
            vReg = g.pickStagingSealed("aconstr scalar element", v.typ)
            g.emitLoadLoc(v, vReg)
            ownV = true
          var etc = et
          g.ab.tree MovX64:
            destOp(i)
            if etIsPtr:
              g.ab.tree CastX: (g.genTypeBody(etc); g.emReg vReg)
            else:
              g.emReg vReg
          if ownV: g.giveBack(vReg)
          elif v.isTemp: g.unbindTemp(v.r)
        inc i
        skip cc

proc genAconstrIntoLval2(g: var CodeGen; c: Cursor; lhs: Cursor) =
  ## Emit `(aconstr ArrayT e0 e1 …)` straight into the array addressed by lvalue `lhs`.
  ## The address-targeted twin of `genAconstr2` (cf. `genConstrIntoLval2` for objects).
  g.prematLval2(lhs)                                     # the lvalue's base/index regs, once
  template dest(i) = g.emLvalElemMem(lhs, i)
  g.aconstrElemStores(c, dest)
  g.unbindLvalTemps2(lhs)                                # release the lvalue's base/index temps

proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string) =
  ## Emit `(oconstr T (kv field value)*)` into the stack aggregate `dstVar`: each
  ## value was placed in a register temp by the allocator (a SIMD temp for a float
  ## field); store it at the field's offset.
  g.constrFieldStores(c, namedStackLoc(dstVar, ScalarSlot))   # base = the stack slot

proc genAconstr2(g: var CodeGen; c: Cursor; dstVar: string) =
  ## Emit `(aconstr ArrayT e0 e1 …)` into the stack array `dstVar`: store each (bare)
  ## element value at `(mem (at (rsp) dstVar i))`. The array twin of `genConstr2`.
  template dest(i) = g.emAggrElemMem(dstVar, i)
  g.aconstrElemStores(c, dest)

proc genBaseobj2(g: var CodeGen; c: Cursor; dst: Location) =
  ## `(baseobj BaseType depth value)` — an object→base up-conversion (slicing). Inheritance
  ## lays the base sub-object FIRST (offset 0), so the base view is the value's prefix:
  ## build the (derived) `value` into a synthetic temp, then copy only the BaseType fields
  ## into the aggregate destination `dst`. `depth` is informational (BaseType is the target).
  assert dst.kind == NamedStack, "arkham x64n: baseobj into " & $dst.kind
  var cc = c
  cc.into:
    let baseTy = cc; skip cc                              # the base type (a Symbol)
    skip cc                                               # depth (intlit) — ignored
    let valC = cc
    let pos = cursorToPosition(g.buf[], valC)
    let derivedTy = g.getType(valC)
    let derivedTn = symName(derivedTy)
    let dtmp = "botmp" & $pos & ".0"
    g.emTypedStackVar(dtmp, derivedTy)
    g.varType[dtmp] = derivedTn
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)))  # build derived (no held temp)
    let scratch = g.pickStagingSealed("a baseobj prefix copy", AddrSlot)
    g.genAggrCopy2(dst.name, dtmp, symName(baseTy), scratch)        # copy the base prefix
    g.giveBack scratch
    while cc.hasMore: skip cc

proc storeScalar2(g: var CodeGen; dst, v: Location) =
  ## Move a just-computed scalar `v` into a scalar home `dst` (InReg / InFReg /
  ## NamedStack), releasing `v` if it is a temp. When BOTH `dst` and `v` are memory
  ## — a stolen-victim local stored into a stack-homed var/lhs, which x86 cannot do
  ## directly — the value is bridged through a transient staging register.
  case dst.kind
  of InReg: g.place2(v, dst.r)                          # dest-passed ⇒ usually a no-op
  of InFReg:
    let bits = dst.typ.size * 8
    if v.kind in {NamedStack, Mem}: g.floatMemMov(v, dst.f, bits, load = true)
    elif v.kind == InFReg and v.f != dst.f: g.fmovF(dst.f, v.f, bits)
  of NamedStack:
    let bits = dst.typ.size * 8
    if dst.typ.isFloat:
      case v.kind
      of InFReg:
        g.emitStoreFLoc(dst, v.f, bits)
        if v.isTemp: g.unbindFTmp(v.f)
      of NamedStack, Mem:
        let fs = g.pickFStagingSealed("a scalar store")
        g.floatMemMov(v, fs, bits, load = true)
        g.emitStoreFLoc(dst, fs, bits)
        g.rb.unsealF fs
      else: raiseAssert "arkham x64n: float scalar store rhs " & $v.kind
    else:
      case v.kind
      of InReg:
        g.emitStoreLoc(dst, v.r)
        if v.isTemp: g.unbindTemp(v.r)
      of NamedStack, Mem:
        let s = g.pickStagingSealed("a scalar store", v.typ)
        g.emitLoadLoc(v, s)
        g.emitStoreLoc(dst, s)
        g.giveBack s
      else: raiseAssert "arkham x64n: scalar store rhs " & $v.kind
  else: raiseAssert "arkham x64n: scalar store dst " & $dst.kind

proc aggrAddrLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## Address of an aggregate DESTINATION location into the (bound) `dest` — the dst twin
  ## of `aggrAddrInto`: a named stack slot / global leas its address; a complex lvalue
  ## (`Mem`) routes through `aggrAddrInto` on its captured subtree.
  case loc.kind
  of NamedStack: g.emStackAddr(dest, loc.name)
  of Glob, Tvar: g.emSymAddr(dest, loc)   # &global (RIP-rel) / &threadvar (FS base + offset)
  of Mem: g.aggrAddrInto(loc.cur, dest, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
  else: raiseAssert "arkham x64n: aggrAddrLoc of " & $loc.kind

proc aggrDstEnd(g: var CodeGen; loc: Location; staged: var Reg): AggrEnd =
  ## The copy-destination twin of `aggrSrcEnd`: a `NamedStack` slot is written straight
  ## through `(mem (rsp) name off)` and costs no register; a global/threadvar/computed
  ## lvalue must have its address materialized. `staged` receives the register to
  ## `giveBack`, or `NoReg`.
  staged = NoReg
  if loc.kind == NamedStack: return slotEnd(loc.name)
  staged = g.pickStagingSealed("an aggregate-copy dst address", ScalarSlot)
  g.aggrAddrLoc(loc, staged)
  regEnd(staged)

proc isAggrCopySrc(c: Cursor): bool =
  ## An aggregate-valued source that is COPIED (not produced): a symbol or a memory lvalue.
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo(g: var CodeGen; dst: Location): (bool, int) =
  ## (is `dst` an aggregate location?, its byte size). A global / thread-local aggregate
  ## both reduce to an address (`aggrAddrLoc` → `emSymAddr`) for the whole-aggregate copy.
  case dst.kind
  of NamedStack, Glob, Tvar: (dst.typ.kind == AMem, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc genAggrCopyStore(g: var CodeGen; rhs: Cursor; dst: Location; size: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce each side to the form the machine can
  ## address it in (`aggrDstEnd`/`aggrSrcEnd`), then `copyAggr`. ONE path for every
  ## (destination form × source form). The working registers come from the emit-time
  ## STAGING set (the R11 bridge + free caller-saved), NOT the allocator pool, so the copy
  ## never starves when register-homed locals fill the pool; each is sealed before the next
  ## is picked (and before address computation, which may itself stage), so they stay
  ## disjoint.
  ##
  ## The count is TIERED by operand form rather than fixed at three: a named `(s)` slot on
  ## either side is addressed straight off rsp and needs no register at all, so two named
  ## ends cost one register (the transfer), one named end costs two, and only a copy
  ## between two COMPUTED addresses costs three. Three-for-everything was self-inflicted —
  ## the price of "reduce both sides to an address" — and it is what ran the staging pool
  ## dry once `-d:danger` filled every volatile with a call-free local.
  if dst.kind == Mem:
    g.emitLvalue2(dst.cur)                 # pick the dst lvalue's embedded values
  var dstAddr = NoReg
  let dstE = g.aggrDstEnd(dst, dstAddr)                                  # &dst (or its slot)
  if dst.kind == Mem: g.freeLvalTemps2(dst.cur)
  var srcAddr = NoReg
  let srcE =
    if rhs.kind == Symbol: g.aggrSrcEnd(symName(rhs), srcAddr)
    else:
      g.emitLvalue2(rhs)                   # pick the src lvalue's embedded values
      srcAddr = g.pickStagingSealed("an aggregate-copy src address", ScalarSlot)
      g.aggrAddrInto(rhs, srcAddr, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
      g.freeLvalTemps2(rhs)
      regEnd(srcAddr)
  # In the top tier both addresses have already consumed the R11 bridge, so the per-word
  # transfer register is a third staging pick and can genuinely fail under pressure. Fall
  # back to the pool register `allocAggrCopy` reserved for exactly this (it can demote a
  # local; the emitter cannot). Staging succeeds in the common case, and then the
  # reserved register simply goes unused.
  var tmp = g.pickStagingScratch()
  if tmp == NoReg:
    tmp = g.pickHeldReg()        # non-demoting callee-saved grab (freed right after)
  if tmp == NoReg:
    tmp = g.pickStagingSealed("an aggregate-copy transfer register", AddrSlot)
  else:
    g.releaseStaleName(tmp)      # drop a dead binding so `(rebind)` is legal
    g.ra.seal tmp
    g.bindTemp(tmp, AddrSlot)
  g.copyAggr(dstE, srcE, size, tmp)
  g.giveBack tmp                                                 # unbinds + unseals the bridge
  g.giveBack srcAddr; g.giveBack dstAddr                         # unbind + unseal (NoReg ⇒ no-op)

proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location) =
  ## The general destination-passing store of the value core. An aggregate COPY (symbol /
  ## lvalue source) goes through the ONE `genAggrCopyStore` regardless of destination form;
  ## constructors/calls/baseobj PRODUCE into the destination per-form; a scalar/float
  ## destination goes through `storeScalar2`.
  let (dstAggr, aggrSize) = g.dstAggrInfo(dst)
  if dstAggr and isAggrCopySrc(rhs):                     # the ONE whole-aggregate copy path
    g.genAggrCopyStore(rhs, dst, aggrSize)
    return
  if rhs.kind == TagLit and rhs.exprKind in {ConvC, CastC} and
     g.exprSlot(rhs).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (`Path(s)` for
    # `Path = distinct string`) is byte-transparent — store its underlying operand into
    # the same destination (allocator twin in `allocStore`).
    var inner = rhs
    inner.into:
      skip inner                                         # the target type
      g.genStore2(inner, dst)                    # the operand → same dest
      while inner.hasMore: skip inner
    return
  if dst.kind == NamedStack and dst.typ.kind == AMem:    # aggregate destination (a slot var)
    let dstVar = dst.name
    let tn = g.varType[dstVar]
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.genConstr2(rhs, dstVar)                          # build object field-by-field
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.genAconstr2(rhs, dstVar)                          # build array element-by-element
    elif rhs.kind == TagLit and rhs.exprKind == CallC:   # call-returned aggregate
      if g.aggrByRef(tn):                                # >16B: pass &dst as the hidden result ptr
        g.emStackAddr(RDI, dstVar)
        var d = dontCare
        g.emitCall2(rhs, d, hiddenPtr = true)            # the callee writes through rdi
      else:
        var d = dontCare
        g.emitCall2(rhs, d)                              # ≤16B result in rax:rdx
        g.regsToStruct(dstVar, tn, x64RetRegs)
    elif rhs.kind == TagLit and rhs.exprKind == BaseobjC:
      g.genBaseobj2(rhs, dst)                   # object→base slice
    else: raiseAssert "arkham x64n: aggregate store rhs " & $rhs.exprKind
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AFloat:  # float global / threadvar
    var fv = dontCare
    g.emitFValue2(rhs, fv)                               # rhs → an xmm
    assert fv.kind == InFReg, "arkham x64n: float global store rhs " & $fv.kind
    let gbits = if dst.typ.size == 4: 32 else: 64
    let op = if gbits == 32: MovssX64 else: MovsdX64
    # &dst is re-derived into a transient here (no call since the rhs), so the allocator
    # reserves nothing — matching the scalar global store. Type the address `(ptr (f N))`
    # so the `(mem p)` deref carries the precise float type (nifasm is strict). `emSymAddr`
    # handles a global (RIP-rel lea) or a thread-local (FS base + offset) uniformly.
    var pSlot = ScalarSlot
    if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
    let addrT = g.pickStagingSealed("a float global store address", pSlot)
    g.emSymAddr(addrT, dst)
    g.ab.tree op:
      g.ab.tree MemX: g.emReg addrT
      g.emFReg fv.f
    g.giveBack addrT
    if fv.isTemp: g.unbindFTmp(fv.f)
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AMem:
    # Aggregate store into a module-level symbol — a global OR a thread-local. Compute
    # `&dst` into a pointer (via `emSymAddr`, the ONE address-of for either kind) and
    # build/copy the aggregate THROUGH that pointer — an `oconstr` field-by-field, an
    # array by element, a call by its ABI (>16B → &dst as the hidden result pointer in
    # rdi; ≤16B → the result regs stored through &dst). The build dispatches only on the
    # RHS kind; global-vs-threadvar lives entirely in `emSymAddr`. The address temp
    # is a callee-saved survivor picked at emission (`takeHeld`).
    if rhs.kind == TagLit and rhs.exprKind == CallC and
       dst.typ.size > g.md.aggrByRefThreshold:
      g.emSymAddr(RDI, dst)                              # >16B: &dst is the hidden result ptr
      var d = dontCare
      g.emitCall2(rhs, d, hiddenPtr = true)              # callee writes through rdi
    else:
      # `spilled`: the address survivor could not get a callee-saved register
      # (totality backstop), so no register holds `&dst` across the build —
      # re-derive it per use instead (the address is re-derivable for either kind).
      var survivor = NoReg                               # the callee-saved &dst holder
      let heldLoc = g.takeHeld("an aggregate global &g", canSpill = true)
      let spilled = heldLoc.kind == NamedStack
      if not spilled: survivor = heldLoc.r
      if rhs.kind == TagLit and rhs.exprKind == OconstrC:
        if spilled:
          g.constrFieldStores(rhs, dst)                  # Glob/Tvar base: &dst re-derived per field
        else:
          g.bindTemp(survivor, ScalarSlot)
          g.emSymAddr(survivor, dst)
          g.constrFieldStores(rhs, regLoc(survivor, dst.typ))  # build field-by-field through &dst
          g.unbindTemp(survivor)
      elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
        # &dst held for the element loop: a transient when spilled (correct unless an
        # element value itself calls under genuine exhaustion — astronomically rare; a
        # literal-element array has none), else the reserved survivor.
        let addrT = if spilled: g.pickStagingSealed("a spilled aconstr sym base", AddrSlot)
                    else: (g.bindTemp(survivor, ScalarSlot); survivor)
        g.emSymAddr(addrT, dst)
        var atc = rhs; inc atc                            # the array type
        let elemTy = innerType(g.prog, resolveType(g.prog, atc))
        template dest(i) = g.emPtrElemMem(addrT, elemTy, i)  # element i through &dst
        g.aconstrElemStores(rhs, dest)
        if spilled: g.giveBack addrT else: g.unbindTemp(addrT)
      elif rhs.kind == TagLit and rhs.exprKind == CallC:  # ≤16B result in rax:rdx
        var d = dontCare
        g.emitCall2(rhs, d)
        # lea AFTER the call (rax:rdx hold the result): a transient when spilled, sealing
        # the result regs so the pick avoids them; else the reserved survivor.
        var addrT: Reg
        if spilled:
          g.ra.seal {RAX, RDX}
          addrT = g.pickStagingSealed("a spilled call-result sym base", AddrSlot)
          g.ra.unseal {RAX, RDX}
        else:
          addrT = survivor; g.bindTemp(addrT, ScalarSlot)
        g.emSymAddr(addrT, dst)
        g.regsToStructThroughPtr(addrT, symName(g.getType(rhs)), x64RetRegs)
        if spilled: g.giveBack addrT else: g.unbindTemp(addrT)
      else: raiseAssert "arkham x64n: aggregate sym store rhs " & $rhs.exprKind
      g.freeVal(heldLoc)
  elif dst.kind in {Glob, Tvar}:                         # scalar/pointer global / threadvar
    var v = needsReg(ScalarSlot)                         # single-use rhs (allocSingleUse's shape)
    g.emitValue2(rhs, v)
    var glbStaging = NoReg
    if v.kind in {NamedStack, Mem}:                      # demoted (stolen) local rhs → reg
      glbStaging = g.pickStagingSealed("a global store rhs", v.typ)
      g.emitLoadLoc(v, glbStaging)
      v = regLoc(glbStaging, v.typ)
    assert v.kind == InReg, "arkham x64n: global store rhs " & $v.kind
    case dst.kind
    of Tvar:                                             # nifasm resolves FS:[off]
      g.ab.tree MovX64:
        g.ab.sym dst.name
        g.emReg v.r
    of Glob:                                             # &g into a transient, then store
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries the
      # global's PRECISE type — a typed-pointer value into a pointer global would
      # otherwise mismatch a generic mem (nifasm is strict; see `scalarMemMov`).
      var pSlot = ScalarSlot
      if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
      # The address is re-derived here (no call since the rhs), so a transient staging
      # register suffices — no allocator-reserved survivor.
      let addrT = g.pickStagingSealed("a global store address", pSlot,
                    avoid = (if v.kind == InReg: v.r else: NoReg))
      g.emGlobalAddr(addrT, dst.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg addrT
        g.emReg v.r
      g.giveBack addrT
    else: discard
    if glbStaging != NoReg: g.giveBack glbStaging
    elif v.isTemp: g.unbindTemp(v.r)
  elif dst.kind == Mem:                                  # store through a complex lvalue (dot/deref/at)
    # (A whole-aggregate copy through an `Mem` lvalue went through `genAggrCopyStore` at
    # the top; here the rhs PRODUCES into the address — a constructor or a scalar/float.)
    let lhs = dst.cur
    # A global aggregate base needs an address scratch, held across the rhs; bind it so
    # prematLval2's `lea scratch, &g` emits a checked name.
    # Only a CONSTRUCTOR build needs `&g` held across the rhs; a scalar store
    # emits the rhs FIRST (fused order), so its global base is a transient
    # premat staging pick (the dontCare marker) — no survivor, no exhaustion.
    var globScratch = NoReg
    var globHeld = dontCare
    if (rhs.kind == TagLit and rhs.exprKind in {OconstrC, AconstrC}) and
       g.lvalueGlobalBaseE(lhs):
      globHeld = g.takeHeld("a global address")
      globScratch = globHeld.r
    if globScratch != NoReg: g.bindTemp(globScratch, AsmSlot(cls: AInt, size: 8, align: 8))
    let globBaseLoc = (if globScratch != NoReg: regLoc(globScratch, ScalarSlot)
                       else: dontCare)
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genConstrIntoLval2(rhs, lhs)                      # build field-by-field into the address
      g.freeLvalTemps2(lhs)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genAconstrIntoLval2(rhs, lhs)                     # build array element-by-element
      g.freeLvalTemps2(lhs)
    else:
      # Evaluate the rhs BEFORE materializing the lhs base. A stack-homed `deref`/`at`
      # base pointer is reloaded into a fresh STAGING register at emit time (see
      # `reloadMemBase2`), which the register allocator does not track — so if the base
      # were materialized first, evaluating the rhs (whose value-core temps the
      # allocator DID place) could land on that staging register and clobber the base.
      # This is exactly the self-referencing field store `x.f = g(x.f)` (e.g. the
      # allocator's `next.prevSize = size or (next.prevSize and 1)`): the rhs re-reads
      # `next.prevSize` through its own base, overwriting the not-yet-consumed store
      # base. Emitting the base AFTER the rhs makes `pickStagingScratch` avoid the live
      # rhs value (it is a `boundTemp`) and reuse a now-dead rhs intermediate's register.
      # Safe to reorder: hexer un-nests, so every lvalue-embedded value is an idempotent
      # symbol/immediate load. `prematLval2(lhs)` therefore moves down to just before
      # each store's `emLvalAddr2(lhs)`.
      # If the rhs is a sub-width int bin-arith stored into this (same-or-narrower)
      # integer field, the store truncates → its `shl;sar` re-normalize is dead.
      let savedSuppress = g.binNormSuppressPos
      block:
        let dstTyR = resolveType(g.prog, g.getType(lhs))
        let w = if isPtrType(dstTyR): 8 else: typeToSlot(dstTyR).size
        g.binNormSuppressPos = g.binStoreSuppressPos(rhs, w)
      var v: Location
      if g.isFloatExpr(rhs):
        v = dontCare
        g.emitFValue2(rhs, v)                             # rhs value FIRST
      else:
        v = needsReg(ScalarSlot)
        g.emitValue2(rhs, v)
      # lvalue picks AFTER the rhs: the live rhs value is a bound temp, so the
      # picks (and later premat staging) cannot land on it. `isStore=false`:
      # a global base stages transiently — nothing to survive, the rhs is done.
      g.emitLvalue2(lhs, globBaseLoc, isStore = false)
      g.binNormSuppressPos = savedSuppress
      let floatRhs = v.kind == InFReg or
                     (v.kind in {NamedStack, Mem} and v.typ.isFloat)
      if floatRhs:                                        # float store
        let bits = if v.typ.size == 4: 32 else: 64
        if v.kind != InFReg:                              # demoted (stolen) float local → staging xmm
          let fs = g.pickFStagingSealed("a memory store rhs")
          g.floatMemMov(v, fs, bits, load = true)
          g.prematLval2(lhs)                              # base regs AFTER the rhs is secured
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.ab.tree MemX: g.emLvalAddr2(lhs)
            g.emFReg fs
          g.rb.unsealF fs
        else:
          g.prematLval2(lhs)
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.ab.tree MemX: g.emLvalAddr2(lhs)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
      else:                                               # integer/immediate store
        # A POINTER destination field reinterprets the source register via
        # `(cast <fieldType> reg)`: nifasm is strict, so an `(i 64)` reg (e.g. a
        # materialized `nil`, or pointer arithmetic) cannot move into a `(ptr T)`
        # field without it (mirrors genConstr2's pointer-field store).
        var dstTy = resolveType(g.prog, g.getType(lhs))
        let dstPtr = isPtrType(dstTy)
        var rhsStaging = NoReg
        if v.kind in {NamedStack, Mem}:                   # demoted (stolen) local → staging reg
          rhsStaging = g.pickStagingSealed("a memory store rhs", v.typ)
          g.emitLoadLoc(v, rhsStaging)
          v = regLoc(rhsStaging, v.typ)
        g.prematLval2(lhs)                                 # base regs AFTER the rhs is secured
        g.ab.tree MovX64:
          g.ab.tree MemX: g.emLvalAddr2(lhs)
          case v.kind
          of Imm: g.emImm(v)
          of InReg:
            if dstPtr:
              g.ab.tree CastX:
                g.genTypeBody(dstTy)
                g.emReg v.r
            else:
              g.emReg v.r
          else: raiseAssert "arkham x64n: store rhs " & $v.kind
        if rhsStaging != NoReg: g.giveBack rhsStaging
        elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
      g.unbindLvalTemps2(lhs)                             # release embedded base/index temps
      g.freeLvalTemps2(lhs)
    if globScratch != NoReg: g.unbindTemp(globScratch)
    g.freeVal(globHeld)
  elif dst.kind == Field:                                # a field within an aggregate
    g.genFieldStore2(dst, rhs)
  else:                                                  # scalar / float home (reg or `(s)` slot)
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
      var v = g.takeFTmp(dst.typ)            # carry the precise (f N) width
      g.emitFValue2(rhs, v)
      g.storeScalar2(dst, v)
    else:
      var v = needsReg(dst.typ)
      g.emitValue2(rhs, v)
      g.storeScalar2(dst, v)

proc genVarDecl2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = cursorToPosition(g.buf[], cc)         # SymbolDef pos (aux key, matches allocVarDecl)
    let nm = symName(cc); inc cc
    skip cc                                              # pragmas
    let declaredCur = cc; skip cc                        # type (`.` when shoggoth omitted it)
    let typeCur = g.declType(declaredCur, cc)            # infer from the initializer
    g.symType[nm] = typeCur                              # record the type for getType (conds)
    if nm in g.ra.aliasedCasts:
      # Identity-cast value alias (see `allocVarDecl`): `nm` has NO home of its own — its
      # `symPos` points at the source `c1`, so every use resolves to `c1`'s live register
      # and field/deref uses auto-emit `(cast T nm→c1)`. Emit NEITHER a decl NOR a store
      # (a decl would rebind the register away from the still-live `c1`). Keep only the
      # type record above so `getType`/cond helpers see `nm`'s (cast) type.
      while cc.hasMore: skip cc
    else:
      let loc = g.ra.locationOfSym(nm)
      let hasVal = cc.hasMore and cc.kind != DotToken
      case loc.kind
      of InReg: g.emRegLocalVar(nm, loc.r, typeCur)
      of InFReg: g.emFRegLocalVar(nm, loc.f, loc.typ.size * 8)   # float local in an xmm
      of NamedStack:
        g.emTypedStackVar(nm, typeCur)
        if typeCur.kind == Symbol: g.varType[nm] = symName(typeCur)  # aggregate field layout
      else: raiseAssert "arkham x64n: var home " & $loc.kind
      if hasVal:
        # Same-width cast/copy inheritance (see `allocVarDecl`): when the value is just
        # another local homed on THIS var's register, `emRegLocalVar` above already renamed
        # the register from the source to `nm` via a zero-machine-code `(rebind)` — the
        # value is in place, so the store is a no-op reg→reg move to skip entirely.
        var skipInit = false
        if loc.kind == InReg:
          let srcSym = copyCastSrcSym(cc)
          if srcSym.kind == Symbol:
            let sh = g.ra.locationOfSym(symName(srcSym))
            if sh.kind == InReg and sh.r == loc.r: skipInit = true
        if not skipInit: g.genStore2(cc, loc)  # the one general store path
      while cc.hasMore: skip cc

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

# ── conditional-move (branchless select) ─────────────────────────────────────

proc cmovTagFor(jccTag: X64Inst): X64Inst =
  ## The `cmov<cc>` whose condition matches `jccTag` (taken when the relation holds):
  ## `cmov<cc> D, S` performs `D = cc ? S : D`.
  case jccTag
  of JeX64:  CmoveX64
  of JneX64: CmovneX64
  of JlX64:  CmovlX64
  of JleX64: CmovleX64
  of JgX64:  CmovgX64
  of JgeX64: CmovgeX64
  of JbX64:  CmovbX64
  of JbeX64: CmovbeX64
  of JaX64:  CmovaX64
  of JaeX64: CmovaeX64
  else: raiseAssert "arkham x64: no cmov for " & $jccTag

proc tryEmitCmov(g: var CodeGen; c: Cursor): bool =
  ## Lower a select diamond (see `matchSelectDiamond`) branchlessly to
  ## `cmp; cmov<cc> DST, A` — no forward jumps, no label. Returns false for anything
  ## that does not fit; the caller then falls back to branch lowering.
  var sd: SelectDiamond
  if not g.matchSelectDiamond(c, sd): return false
  # ── emit: cmp (sets flags) → THEN→scratch → ELSE→DST → cmov DST, scratch ──
  # The cmp reads the condition operands at their ORIGINAL values (DST not yet
  # written). THEN is captured into a scratch register before ELSE overwrites DST, so
  # `if c: x = x …` self-reads stay correct. Both stores of a simple value are pure
  # `mov` (movImm never `xor`s; a 64-bit-normalised scalar move needs no flag-setting
  # `shl`/`sar` extend), so the flags survive to the cmov.
  let ct = cmovTagFor(g.emitScalarCmpE(sd.a, sd.b, sd.ek, whenTrue = true))
  let rT = g.pickStagingSealed("a cmov then-value", g.selectStagingSlot(sd), avoid = sd.dst.r)
  g.genStore2(sd.thenRhs, regLoc(rT, sd.dst.typ))
  g.genStore2(sd.elseRhs, sd.dst)
  g.ab.tree ct: (g.emReg sd.dst.r; g.emReg rT)
  g.giveBack rT
  return true

proc genStmt2(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return                 # an empty statement (e.g. `(stmts .)`)
  # Capture our own tail-position, then default children to non-tail: only the
  # LAST child of a straight-line `stmts`/`scope` inherits it (control leaves any
  # other child sideways, and a nested compound gets its own reset below).
  let myTail = g.tailStmt
  g.tailStmt = false
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore
        g.genStmt2(cc); skip cc
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore   # kills trail the last stmt but emit no bytes,
        g.genStmt2(cc); skip cc                  # so tail fall-through into the epilogue survives
    g.exitScope()
  of VarS, ConstS: g.genVarDecl2(c)    # a local const = an immutable var with a literal init
  of CallS:
    var d = dontCare                   # a statement call: result unused
    g.emitCall2(c, d)
    g.freeVal(d)
  of InstrS:
    var d = dontCare
    g.emitInstr2(c, d)
    g.freeVal(d)
  of BreakS:
    assert g.loopEnds.len > 0, "arkham x64n: `break` outside a loop"
    g.emJmp(g.loopEnds[^1])
  of AsgnS:
    var cc = c
    cc.into:
      let asgnPos = cursorToPosition(g.buf[], c)
      if cc.kind == Symbol:
        let lhsCur = cc                                     # for asLoc (global/tvar)
        var dst = g.ra.locationOfSym(symName(cc)); skip cc  # local lvalue; a global → Undef
        if dst.kind == NoLoc:                               # module-level global / threadvar
          var lc = lhsCur
          dst = g.asLoc(lc)                                 # Glob/Tvar with precise type
        g.genStore2(cc, dst)                       # the one general store path
      else:
        # A memory store through a complex lvalue (dot/deref/at).
        let lhsCur = cc
        var rhsCur = cc; skip rhsCur                        # past the lhs → the rhs value
        g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot))   # the one general store path
      while cc.hasMore: skip cc
  of WhileS:
    let lEnd = g.freshLabel()
    g.loopEnds.add lEnd
    g.emitLoop:
      var cc = c
      cc.into:
        let condC = cc; skip cc
        g.emitCondE(condC, lEnd, whenTrue = false)     # forward exit when cond is false
        while cc.hasMore: (g.genStmt2(cc); skip cc)     # body
    g.emLab(lEnd)
    discard g.loopEnds.pop()
  of IfS:
    if not g.tryEmitCmov(c):        # branchless select diamond, else fall through
      let lEnd = g.freshLabel()
      var cc = c
      cc.into:
        while cc.hasMore:
          case cc.substructureKind
          of ElifU:
            let lNext = g.freshLabel()
            var peek = cc; skip peek
            let isLastBranch = not peek.hasMore   # no `elif`/`else` follows this branch
            var bc = cc
            bc.into:
              let condC = bc; skip bc
              g.emitCondE(condC, lNext, whenTrue = false)
              while bc.hasMore: (g.genStmt2(bc); skip bc)
              # The skip-to-merge jump exists only to hop over later branches; the last
              # branch has none, so it falls through `lNext` (empty) into `lEnd`.
              if not isLastBranch: g.emJmp(lEnd)
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
          var v = needsReg(ScalarSlot)
          g.emitValue2(cc, v)
          g.place2(v, RDI)
          g.freeVal(v)
        else: g.movImm(RDI, 0)
        g.movImm(RAX, LinuxX64ExitNr); g.emSyscall()
      else:
        if g.retAggrName.len > 0:                          # aggregate return
          var srcName: string
          if cc.kind == Symbol:
            srcName = symName(cc)                          # a named local aggregate
          else:
            # An inline aggregate VALUE returned by value (`$`'s `(ret (oconstr
            # string …))`, or a memory lvalue): materialize it into a synthetic temp
            # via the general store path (mirrors the aggregate call-argument
            # marshalling), then marshal that temp out by the ABI below.
            let pos = cursorToPosition(g.buf[], cc)
            srcName = "rettmp" & $pos & ".0"
            var tcur = cc
            if cc.exprKind in {OconstrC, AconstrC}: inc tcur   # the constructed type
            else: tcur = g.getType(cc)
            g.emTypedStackVar(srcName, tcur)
            g.varType[srcName] = g.retAggrName
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)))
          if g.retIndirect:                                # >16B: copy through the hidden ptr
            g.copyStructThroughPtr2(srcName, g.retAggrName, g.indirectReg)
            g.movReg(RAX, g.indirectReg)                   # SysV: return the buffer pointer in rax
          else:
            g.structToRegs(srcName, g.retAggrName, x64RetRegs)  # ≤16B → rax:rdx
        elif hasVal:                                       # scalar / float result → ret reg
          let retPos = cursorToPosition(g.buf[], cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(FloatRet, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)))
          else:
            g.genStore2(cc, regLoc(g.md.intRetReg, ScalarSlot))
        # The epilogue (framePop + ret) is emitted ONCE at the proc tail by
        # emitProcBody2; a `ret` that is NOT the tail must jump there rather than fall
        # through into the following statements (e.g. a mid-proc `if cond: return x`).
        # A tail `ret` falls straight through the (zero-byte) scope kills into the
        # epilogue, so it needs no jump and does not force the shared label.
        if not myTail:
          g.emJmp(g.retLabel2); g.retLabelUsed2 = true
      while cc.hasMore: skip cc
  of CaseS:
    # `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`. Mirrors the
    # legacy genCase: selector → a register live across ALL range tests; a non-match
    # falls through to else (or the end); bodies are emitted AFTER the test chain, so
    # each ends in a jmp to lEnd. (Leng `case` has no fall-through.)
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      var selLoc = needsReg(ScalarSlot)                  # held across ALL range tests
      g.emitValue2(cc, selLoc); skip cc
      # The selector must live in a GPR across the whole test chain. `emitValue2`
      # may leave it spilled (NamedStack) or homed in a tvar/global; in that case
      # load it into a sealed staging register for the duration of the tests.
      var selReg: Reg
      var ownSelReg = false
      if selLoc.kind == InReg:
        selReg = selLoc.r
      else:
        selReg = g.pickStagingSealed("case selector", selLoc.typ)
        g.emitLoadLoc(selLoc, selReg)
        ownSelReg = true
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
      if ownSelReg: g.giveBack(selReg)                    # release the staging reg we loaded into
      else: g.freeVal(selLoc)                             # selector dead after the tests
      if hasElse:
        var e = elseBody
        e.into:
          while e.hasMore: (g.genStmt2(e); skip e)
      g.emJmp(lEnd)
      for idx in 0 ..< bodies.len:
        g.emLab(bodies[idx][0])
        g.genStmt2(bodies[idx][1])                        # body (a stmts node)
        if idx < bodies.len - 1: g.emJmp(lEnd)            # last body falls through to lEnd
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
  of KeepovfS:
    # `(keepovf (op type a b) dest)` — an overflow-checked arithmetic store: emit the
    # plain `dest = a op b` (like AsgnS, value FIRST), which leaves the hardware
    # overflow/carry flag set; the `(ovf)` test that MUST immediately follow reads it
    # (see emitCond2). The result store is a flag-preserving `mov`, so the flag is
    # still live at the test. Record the op's signedness so that test picks `jo` (OF,
    # signed) vs `jb` (CF, unsigned).
    var cc = c
    cc.into:
      let kPos = cursorToPosition(g.buf[], c)
      var opCur = cc                                        # the (op …) value
      # The `(ovf)` that follows reads the flag THIS op sets: emit it even when
      # constant-foldable (the allocator suppressed the fold at this position too).
      g.noFoldPos = cursorToPosition(g.buf[], opCur)
      block:
        var opTy = opCur; inc opTy                          # past the op tag → its result type
        g.ovfSigned = isSignedType(opTy)
        # The hardware OF/CF reflects overflow at the OP's width, but arkham keeps int
        # locals in 64-bit registers, so a sub-64-bit `keepovf` would need a narrow op
        # (or a sign-extend/compare) for its `(ovf)` to be correct. Native-width (`int`
        # = `(i -1)`, and `(i 64)`/`(u 64)`) is exact; reject narrower widths loudly
        # rather than silently miss overflow.
        if intTypeWidth(opTy) < 64:
          raiseAssert "arkham x64n: keepovf for sub-64-bit type not yet supported " &
                      "(width " & $intTypeWidth(opTy) & ")"
      skip cc                                               # advance to dest
      if cc.kind == Symbol:
        let lhsCur = cc
        var dst = g.ra.locationOfSym(symName(cc)); skip cc
        if dst.kind == NoLoc:
          var lc = lhsCur
          dst = g.asLoc(lc)
        g.genStore2(opCur, dst)
      else:
        let lhsCur = cc; skip cc
        g.genStore2(opCur, memLoc(lhsCur, ScalarSlot))
      g.noFoldPos = -1
      while cc.hasMore: skip cc
  else: raiseAssert "arkham x64n: genStmt2 " & $c.stmtKind

# ── fused value core: unconverted-proc stubs (die as each case lands) ────────
proc emitBin2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED binary-arith: allocBin's placement policy (Sethi–Ullman swap,
  ## destination passthrough, rhs-temp recycling, aliasRhs hazard) decided
  ## right here, then emitted — one ladder, no replay hints.
  let pos = cursorToPosition(g.buf[], c)
  let (op, isBin) = binArithOp(c)
  assert isBin, "arkham x64n: emitBin2 on a non-bin node"
  let ek = c.exprKind
  let suppressNorm = pos >= 0 and pos == g.binNormSuppressPos
  var lhsC, rhsC, resTypeC: Cursor
  block:
    var cc = c
    cc.into:
      resTypeC = cc; skip cc                             # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  # ── Sethi–Ullman swap: foldable/memory lhs + computed rhs → rhs first, into
  # the accumulator; the leaf lhs folds after (sub completes with a neg).
  let lhsMem = isMemLeaf(lhsC)
  let swap = ek notin {ShlC, ShrC} and (commutativeExpr(ek) or ek == SubC) and
             (g.isFoldableLeafE(lhsC) or lhsMem) and
             not (g.isFoldableLeafE(rhsC) or isMemLeaf(rhsC)) and
             not (dest.kind == InReg and g.symInRegE(lhsC, dest.r))
  if swap:
    var acc = dest
    if acc.kind != InReg: acc = g.takeTmp(ScalarSlot)
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoMem2(c, acc)                          # pools dry: whole node via staging
      dest = acc
      return
    let rD = acc.r
    var rdst = acc
    g.emitValue2(rhsC, rdst)                             # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundTemp(rD): g.bindTemp(rD, acc.typ)
    var lLoc = dontCare                                  # the leaf lhs: its natural place
    if lhsMem:
      g.emitLvalue2(lhsC)                                # pick embedded base/index regs
      lLoc = memLoc(lhsC, ScalarSlot)
    else:
      g.resolveLvalVal(lhsC, lLoc)                       # imm / register / stack home
    let foldOp = if op == SubX64: AddX64 else: op        # sub folds as add (after neg)
    let rdSeal = not g.ra.isSealed(rD) and not g.rb.isBoundTemp(rD)
    if rdSeal: g.ra.seal {rD}
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # rD := -rhs
    case lLoc.kind                                       # rD := rD <foldOp> lhs
    of Imm:
      if lLoc.ival < low(int32).int64 or lLoc.ival > high(int32).int64:
        let s = g.pickStagingSealed("a bin imm64", acc.typ)
        g.movImm(s, lLoc.ival)
        g.binReg(foldOp, rD, s)
        g.giveBack s
      else: g.binImm(foldOp, rD, lLoc.ival)
    of InReg: g.binReg(foldOp, rD, lLoc.r)
    of NamedStack, Mem: g.binFold(foldOp, rD, lLoc, lhsC) # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin(swapped) lhs " & $lLoc.kind
    if lhsMem: g.freeLvalTemps2(lhsC)                    # embedded picks die with the fold
    if not suppressNorm: g.normalizeBinWidth(resTypeC, rD, op)
    if rdSeal: g.ra.unseal {rD}
    dest = acc
    return
  # ── canonical order: lhs into a register (or straight into a pinned dest
  # when safe), rhs folds in place.
  var lDest = needsReg(ScalarSlot)
  if dest.kind == InReg and ek notin {ShlC, ShrC} and
     not g.isFoldableLeafE(lhsC) and
     (g.isFoldableLeafE(rhsC) or isMemLeaf(rhsC)) and
     not g.exprReadsRegE(lhsC, dest.r) and not g.exprReadsRegE(rhsC, dest.r):
    lDest = dest                                         # compute lhs straight into dest
  g.emitValue2(lhsC, lDest)
  var rDest = dontCare
  if ek in {ShlC, ShrC} and g.md.shiftCountReg != NoReg and
     not isConstShiftCount(rhsC):
    # x86 variable shift: the count must be in cl. A live bound TEMP there is a
    # real hazard; a (`ShiftRegOk`) HOME is interval-proved dead at every
    # variable shift, and a committed call argument in rcx was PARKED off it
    # by the marshaller — so only a temp is asserted.
    if g.rb.isBoundTemp(g.md.shiftCountReg):
      raiseAssert "arkham: variable shift while the count register holds a live value"
    rDest = regLoc(g.md.shiftCountReg, ScalarSlot)
  g.emitValue2(rhsC, rDest)                              # rhs → wherever (may stay imm/home)
  # ── result placement: keep a fixed dest; else in-place RMW on a dead lhs
  # temp; else recycle the dead rhs temp (aliasRhs); else a fresh temp.
  var res = dest
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: res = lDest
    elif rDest.kind == InReg and rDest.isTemp and lDest.kind == InReg and
         ek notin {ShlC, ShrC}:
      res = rDest
    else: res = g.takeTmp(ScalarSlot)
  else: discard
  let aliasRhs = res.kind == InReg and rDest.kind == InReg and res.r == rDest.r and
                 not (lDest.kind == InReg and res.kind == InReg and lDest.r == res.r)
  if aliasRhs and ek in {ShlC, ShrC}:
    raiseAssert "arkham: variable shift whose destination aliases the count register"
  # ── emission (the old emitBin2 body over the freshly decided locations).
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:                      # incl. a takeTmp-dry etmp slot
    resStaging = g.pickStagingSealed("a memory bin result", res.typ)
    rD = resStaging
  else:
    assert res.kind == InReg, "arkham x64n: bin result " & $res.kind
    rD = res.r
  let reusedLhs = lDest.kind == InReg and lDest.r == rD  # in-place RMW on the left temp
  let reusedRhs = rDest.kind == InReg and rDest.r == rD  # dest recycled the RHS temp
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(rD):
    g.bindTemp(rD, res.typ)
  if not isPtrType(resolveType(g.prog, resTypeC)):
    let nm = g.rb.boundName(rD)
    if g.rb.isBoundTemp(rD):
      if reusedLhs or reusedRhs:                         # inherited an operand's binding
        var rtc = resTypeC
        g.bindTemp(rD, slotOf(g.prog, rtc))
    elif nm.len > 0:
      g.rebindLocalAs(nm, rD, resTypeC)
  let rdSeal = not g.ra.isSealed(rD) and not g.rb.isBoundTemp(rD)
  if rdSeal: g.ra.seal {rD}
  if aliasRhs:
    assert lDest.kind == InReg, "arkham x64n: aliasRhs lhs " & $lDest.kind
    g.binReg(op, rD, lDest.r)                            # dest := rhs op lhs
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # dest := lhs - rhs
  else:
    g.place2(lDest, rD)                                  # dest := lhs
    case rDest.kind                                      # dest op= rhs
    of Imm:
      if rDest.ival < low(int32).int64 or rDest.ival > high(int32).int64:
        let s = g.pickStagingSealed("a bin imm64", res.typ)
        g.movImm(s, rDest.ival)
        g.binReg(op, rD, s)
        g.giveBack s
      else: g.binImm(op, rD, rDest.ival)
    of InReg: g.binReg(op, rD, rDest.r)
    of NamedStack, Mem: g.binFold(op, rD, rDest, rhsC)   # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin rhs " & $rDest.kind
  if not suppressNorm: g.normalizeBinWidth(resTypeC, rD, op)
  if rdSeal: g.ra.unseal {rD}
  if not reusedRhs: g.freeVal(rDest)                     # freeVal frees only temps
  if not reusedLhs: g.freeVal(lDest)
  if resStaging != NoReg:                                # store the result to its memory home
    g.emitStoreLoc(res, resStaging)
    g.giveBack resStaging
  dest = res
proc settleResultReg(g: var CodeGen; dest: var Location; resReg: Reg) =
  ## FUSED result settling: move/store a value produced in the fixed register
  ## `resReg` (rax after a div/mem-intrinsic, rdx for a remainder) into `dest`,
  ## resolving an unconstrained dest to `resReg` itself as a bound temp.
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(resReg, ScalarSlot, isTemp = true)
    if not g.rb.isBoundTemp(resReg): g.bindTemp(resReg, dest.typ)
  of InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    if dest.r != resReg: g.movReg(dest.r, resReg)
  of NamedStack, Mem:                                   # a memory home / spill slot
    let bound = g.rb.isBoundTemp(resReg)
    if not bound: g.bindTemp(resReg, ScalarSlot)
    g.emitStoreLoc(dest, resReg)
    if not bound: g.unbindTemp(resReg)
  else: raiseAssert "arkham x64n: fixed-reg result dest " & $dest.kind

proc emitDivMod2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED x86 `idiv`/`div`: dividend → rax (fixed), divisor → a register
  ## (never rax/rdx — the temp pools exclude both); the result (rax quotient /
  ## rdx remainder) moves/stores to `dest`. A constant power-of-two divisor
  ## strength-reduces to shifts.
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
  # rdx is clobbered. A live bound TEMP there is a real hazard; a (`DivRegOk`)
  # home is interval-proved dead at every div, and a committed call argument in
  # rdx cannot coexist with a later-arg div — the marshaller PARKED it off rdx
  # (`fixedRegsClobberedByE`), so an accum seal on rdx here is the protected case.
  if g.rb.isBoundTemp(g.md.divRemReg):
    raiseAssert "arkham: div/mod while the remainder register holds a live value"
  let acc = g.md.intRetReg                              # rax: dividend, then result

  # Constant power-of-two divisor → shifts (~20-40 cycles saved). Signed mod
  # keeps `idiv` (bias is fiddly); a huge unsigned-mod mask falls through.
  let (dvsIsConst, dval) = g.tryConstFold(dvsC)
  let isPow2 = dvsIsConst and dval >= 2 and (dval and (dval - 1)) == 0
  if isPow2 and not (signed and wantRem) and
     (not wantRem or dval - 1 <= high(int32).int64):
    var k = 0'i64
    var t = dval
    while t > 1: (t = t shr 1; inc k)                   # k = log2(divisor)
    var aD = regLoc(acc, ScalarSlot)
    g.emitValue2(divC, aD)                              # dividend → rax
    if wantRem:                                         # unsigned mod: acc &= 2^k - 1
      g.binImm(AndX64, acc, dval - 1)
    elif not signed:                                    # unsigned div: acc >>>= k
      g.binImm(ShrX64, acc, k)
    else:                                               # signed div: bias, then sar
      let tmp = g.pickStagingSealed("a pow2-div sign bias", ScalarSlot, avoid = acc)
      g.movReg(tmp, acc)
      g.binImm(SarX64, tmp, 63)                         # tmp = sign mask
      g.binImm(ShrX64, tmp, 64 - k)                     # tmp = bias if negative
      g.binReg(AddX64, acc, tmp)
      g.binImm(SarX64, acc, k)
      g.giveBack tmp
    g.settleResultReg(dest, acc)
    return
  var aD = regLoc(acc, ScalarSlot)
  g.emitValue2(divC, aD)                                # dividend → rax
  var dD = needsReg(ScalarSlot)
  g.emitValue2(dvsC, dD)                                # divisor → a register
  if dD.kind == InReg and (dD.r == g.md.intRetReg or dD.r == g.md.divRemReg):
    raiseAssert "arkham: div/mod divisor aliases rax/rdx"
  var dvsLoc = dD
  var dvsStaging = NoReg
  if dvsLoc.kind != InReg:                              # spilled divisor → staging (not rax/rdx)
    dvsStaging = g.pickStagingSealed("an idiv divisor", dvsLoc.typ)
    g.emitLoadLoc(dvsLoc, dvsStaging)
    dvsLoc = regLoc(dvsStaging, dvsLoc.typ)
  let op = if signed: IdivX64 else: DivX64
  g.ab.tree op:
    g.ab.reg g.md.divRemReg                             # (rdx): high half / remainder
    g.ab.reg g.md.intRetReg                             # (rax): low half / quotient
    g.emReg dvsLoc.r                                    # divisor, by its bound name
  if dvsStaging != NoReg: g.giveBack dvsStaging
  else: g.freeVal(dD)
  g.settleResultReg(dest, if wantRem: g.md.divRemReg else: g.md.intRetReg)
proc emitScalarCmpE(g: var CodeGen; aC, bC: Cursor; ek: LengExpr;
                    whenTrue: bool): X64Inst =
  ## FUSED integer `cmp` for the relation `ek`: operand placement (allocCond's
  ## memory-fold rules) decided inline, flags set, staging released; returns
  ## the `jcc` tag taken when the relation holds as `whenTrue`.
  let unsigned = g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC)
  result = cmpJccTag(ek, whenTrue, signed = not unsigned)
  if isMemLeaf(aC) and not isMemLeaf(bC):
    # left is a memory load, right is not → fold the LEFT: `cmp [mem], reg/imm`
    # (x86 allows a memory destination; only one memory operand).
    g.emitLvalue2(aC)                                  # pick embedded base/index
    var rD = dontCare
    g.emitValue2(bC, rD)                               # right → reg / imm / its home
    var bLoc = rD
    var bigImmStaging = NoReg
    if bLoc.kind == Imm and
       (bLoc.ival < low(int32).int64 or bLoc.ival > high(int32).int64):
      bigImmStaging = g.pickStagingSealed("a cmp imm64", bLoc.typ)
      g.movImm(bigImmStaging, bLoc.ival)
      bLoc = regLoc(bigImmStaging, bLoc.typ)
    var aBound: seq[Reg] = @[]
    g.bindLvalGlobalBases(aC, aBound)                  # bind a global base before the lea
    g.prematLval2(aC)                                  # materialize the lhs base first
    var rhsStaging = NoReg
    if bLoc.kind == NamedStack:                        # no `cmp [mem], [mem]`
      rhsStaging = g.pickStagingSealed("a cmp(memlhs) rhs", bLoc.typ)
      g.emitLoadLoc(bLoc, rhsStaging)
    g.ab.tree CmpX64:
      g.ab.tree MemX: g.emLvalAddr2(aC)
      case bLoc.kind
      of Imm: g.emImm(bLoc)
      of InReg: g.emReg bLoc.r
      of NamedStack: g.emReg rhsStaging
      else: raiseAssert "arkham x64n: cmp(memlhs) rhs " & $bLoc.kind
    if rhsStaging != NoReg: g.giveBack rhsStaging
    g.unbindLvalTemps2(aC)
    for r in aBound: g.unbindTemp(r)
    if bigImmStaging != NoReg: g.giveBack bigImmStaging
    g.freeVal(rD)
    g.freeLvalTemps2(aC)
    return
  # A pointer-typed lhs carries its precise slot so a pool-dry etmp spill and
  # its staged reload stay ptr-typed — `cmp (i 64) (nil)` is a nifasm error
  # (the a64 twin's cmpBridgeSlot rule).
  var lD = needsReg(
    if isPtrType(resolveType(g.prog, g.getType(aC))): g.exprSlot(aC)
    else: ScalarSlot)
  g.emitValue2(aC, lD)                                 # left → a register
  var rD = dontCare
  let rhsMemFold = isMemLeaf(bC)
  if rhsMemFold:
    g.emitLvalue2(bC)                                  # fold the right: cmp reg, [mem]
  else:
    g.emitValue2(bC, rD)                               # right → reg / imm / home slot
  var aLoc = lD
  var bLoc = rD
  var bigImmStaging = NoReg
  if bLoc.kind == Imm and
     (bLoc.ival < low(int32).int64 or bLoc.ival > high(int32).int64):
    bigImmStaging = g.pickStagingSealed("a cmp imm64", bLoc.typ)
    g.movImm(bigImmStaging, bLoc.ival)
    bLoc = regLoc(bigImmStaging, bLoc.typ)
  var cmpStaging = NoReg
  if aLoc.kind == NamedStack:                          # pool-dry etmp lhs: load it
    cmpStaging = g.pickStagingSealed("a cmp lhs", aLoc.typ)
    g.emitLoadLoc(aLoc, cmpStaging)
    aLoc = regLoc(cmpStaging, aLoc.typ)
  assert aLoc.kind == InReg, "arkham x64n: cmp lhs " & $aLoc.kind
  if rhsMemFold:
    var bBound: seq[Reg] = @[]
    g.bindLvalGlobalBases(bC, bBound)
    g.prematLval2(bC)
    g.ab.tree CmpX64:
      g.emReg aLoc.r
      g.ab.tree MemX: g.emLvalAddr2(bC)
    g.unbindLvalTemps2(bC)
    for r in bBound: g.unbindTemp(r)
    g.freeLvalTemps2(bC)
  else:
    case bLoc.kind
    of Imm:
      g.ab.tree CmpX64: (g.emReg aLoc.r; g.emImm(bLoc))
    of InReg:
      g.ab.tree CmpX64: (g.emReg aLoc.r; g.emReg bLoc.r)
    of NamedStack:                                     # spilled scalar: cmp reg, [rsp+slot]
      g.ab.tree CmpX64:
        g.emReg aLoc.r
        g.emStackMem(bLoc.name)
    else: raiseAssert "arkham x64n: cmp rhs " & $bLoc.kind
  if bigImmStaging != NoReg: g.giveBack bigImmStaging
  g.freeVal(rD)
  if cmpStaging != NoReg: g.giveBack cmpStaging
  g.freeVal(lD)

proc emitCondE(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## FUSED branch test: jump to `toLabel` when the condition holds
  ## (`whenTrue`) — short-circuit and/or/not, `cmp`/`jcc` relations, `(ovf)`,
  ## or `cmp v, 0` for a plain boolean value. Operand placement inline.
  if c.kind == TagLit and c.exprKind == OvfC:
    let tag =
      if g.ovfSigned: (if whenTrue: JoX64 else: JnoX64)
      else:           (if whenTrue: JbX64 else: JaeX64)
    g.emJcc(tag, toLabel)
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
    of NotC:
      g.emitCondE(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCondE(aC, lSkip, false)
        g.emitCondE(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCondE(aC, toLabel, false)
        g.emitCondE(bC, toLabel, false)
    else:                                              # OrC
      if whenTrue:
        g.emitCondE(aC, toLabel, true)
        g.emitCondE(bC, toLabel, true)
      else:
        let lSkip = g.freshLabel()
        g.emitCondE(aC, lSkip, true)
        g.emitCondE(bC, toLabel, false)
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
      # FLOAT comparison: comisd/comiss; both operands in xmm registers.
      let fbits = g.floatBits(aC)
      let tag = cmpJccTag(ek, whenTrue, signed = false)
      var fa = dontCare
      g.emitFValue2(aC, fa)
      var fb = dontCare
      g.emitFValue2(bC, fb)
      assert fa.kind == InFReg and fb.kind == InFReg, "arkham x64n: float cmp operands"
      g.ab.tree (if fbits == 32: ComissX64 else: ComisdX64):
        g.emFReg fa.f; g.emFReg fb.f
      g.emJcc(tag, toLabel)
      g.freeVal(fb)
      g.freeVal(fa)
      return
    let tag = g.emitScalarCmpE(aC, bC, ek, whenTrue)
    g.emJcc(tag, toLabel)
  else:
    var v = needsReg(ScalarSlot)
    g.emitValue2(c, v)
    if v.kind == InReg:
      g.ab.tree CmpX64: (g.emReg v.r; g.ab.intLit 0)
      g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
      g.freeVal(v)
    else:
      # a pool-dry etmp bool value: load it staged, compare against zero.
      let s = g.pickStagingSealed("a bool cond operand", v.typ)
      g.emitLoadLoc(v, s)
      g.ab.tree CmpX64: (g.emReg s; g.ab.intLit 0)
      g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
      g.giveBack s

proc emitCondValue2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED comparison / and/or/not as a 0/1 VALUE: assume 1, clear to 0 unless
  ## the condition holds. The result temp is reserved (and bound) BEFORE the
  ## condition emits, so operand picks cannot land on it.
  case dest.kind
  of Undef, NeedsReg, RegOrImm: dest = g.takeTmp(ScalarSlot)
  else: discard
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  assert res.kind == InReg, "arkham x64n: cond-value result " & $res.kind
  if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
  let lEnd = g.freshLabel()
  g.movImm(res.r, 1)
  g.emitCondE(c, lEnd, whenTrue = true)
  g.movImm(res.r, 0)
  g.emLab(lEnd)
  dest = res
proc emitMemLoad2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED addressing expr in VALUE position → load `[addr]` into a register.
  ## Decisions inline (allocValue's Deref/Dot/At/Pat case): force a register
  ## result, seal a fixed dest across the embedded-value picks (an index temp
  ## landing on it would mistype the load), pick the embedded values
  ## (`emitLvalue2`; a global base reuses the result register), then the old
  ## emission body.
  g.forceRegDestE(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.ra.isSealed(res.r)
  if sealedHere: g.ra.seal {res.r}
  g.emitLvalue2(c, globBase = res)
  if sealedHere: g.ra.unseal {res.r}
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    # An array / flexible-array-member lvalue DECAYS to its address: `lea`.
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, ScalarSlot)
    g.prematLval2(c)
    g.ab.tree LeaX64:
      g.emReg res.r
      g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)
  else:
    var bindSlot = res.typ
    if isPtrType(cty): bindSlot = g.exprSlot(c)
    if res.isTemp and not g.rb.isBoundTemp(res.r):
      g.bindTemp(res.r, bindSlot)                       # bind first: a global base leas &g
    g.prematLval2(c)                                    #   into res before the (mem …) tree
    g.ab.tree MovX64:
      g.emReg res.r
      g.ab.tree MemX: g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)                               # release staging/stride
  g.freeLvalTemps2(c)                                   # release the picked embedded temps
  dest = res

proc emitAddr2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(addr lvalue)` → a pointer in a register. Identity `&(deref p)`
  ## with a register-homed `p` and a transient dest is `p`'s register itself —
  ## no temp, no copy (kept non-temp so a consuming binop won't clobber it).
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
        let home = g.ra.locationOfSym(symName(p))
        if home.kind == InReg:
          dest = home                                   # the address IS p's register
          return
  g.forceRegDestE(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  g.emitLvalue2(lv, globBase = res)                     # a global base reuses the lea dest
  g.aggrAddrInto(lv, res.r, g.exprSlot(c), doBind = res.isTemp)
  g.freeLvalTemps2(lv)
  dest = res
proc produceIntoFMem2(g: var CodeGen; c: Cursor; dst: Location) =
  ## FUSED SIMD produce-into: `dst` is an `(s)(f N)` `eftmp` slot. Materialize
  ## into a staging xmm (the reserved bridge first) and store. The staging xmm
  ## IS sealed across the recursion (destructive SSE writes the accumulator
  ## before the rhs — see the legacy twin's staging-depth note).
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoFMem2 slot=" & dst.name
  let bits = dst.typ.size * 8
  let fs = g.pickFStagingSealed("a spilled float result (deep float nest > staging pool)")
  var d = fregLoc(fs, dst.typ, isTemp = true)
  g.emitFValue2(c, d)
  g.emitStoreFLoc(dst, fs, bits)
  g.unbindFTmp(fs)                       # release the staging name (the recursion bound it)
  g.rb.unsealF fs

proc foldableFloatLeafE(g: var CodeGen; c: Cursor): bool =
  c.kind == Symbol and g.ra.locationOfSym(symName(c)).kind in {InFReg, NamedStack}

proc emitFBinE(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED float binary-arith (allocFBin's policy inline): destructive SSE —
  ## `a` computes straight into the result xmm, `b` folds in place (a float
  ## local in a register) or draws a SIMD temp; a commutative op with a
  ## foldable float leaf lhs and a computed rhs swaps (rhs first).
  let (op32, op64) = fbinOps(c.exprKind)
  let ek = c.exprKind
  var lhsC, rhsC: Cursor
  var fslot = AsmSlot(cls: AFloat, size: 8, align: 8)
  block:
    var cc = c
    cc.into:
      fslot = slotOf(g.prog, cc); skip cc                # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let lHome = (if lhsC.kind == Symbol: g.ra.locationOfSym(symName(lhsC)) else: noLoc)
  let swap = ek in {AddC, MulC} and g.foldableFloatLeafE(lhsC) and
             not g.foldableFloatLeafE(rhsC) and
             not (dest.kind == InFReg and lHome.kind == InFReg and lHome.f == dest.f)
  if swap:
    var acc = dest
    if acc.kind != InFReg: acc = g.takeFTmp(fslot)
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoFMem2(c, acc); dest = acc; return
    let bits = if acc.typ.size == 4: 32 else: 64
    var rdst = acc
    g.emitFValue2(rhsC, rdst)                            # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundFTmp(acc.f): g.bindFTmp(acc.f)
    if lHome.kind == InFReg:
      g.fbin(op32, op64, acc.f, lHome.f, bits)
    else:                                                # spilled float local: staged load
      let lt = g.pickFStagingSealed("a spilled float operand", avoid = acc.f)
      g.bindFTmp(lt)
      g.emFloatScalarLoad(lt, lHome.name, bits)
      g.fbin(op32, op64, acc.f, lt, bits)
      g.unbindFTmp(lt)
      g.rb.unsealF lt
    dest = acc
    return
  if dest.kind != InFReg: dest = g.takeFTmp(fslot)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let res = dest
  let bits = if res.typ.size == 4: 32 else: 64
  var lD = res
  g.emitFValue2(lhsC, lD)                                # a → the result xmm
  if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
  if rhsC.kind == Symbol and g.ra.locationOfSym(symName(rhsC)).kind == InFReg:
    let rHome = g.ra.locationOfSym(symName(rhsC))
    if rHome.f == res.f and
       not (lhsC.kind == Symbol and symName(lhsC) == symName(rhsC)):
      raiseAssert "arkham: float operand fold aliases the destination register"
    g.fbin(op32, op64, res.f, rHome.f, bits)             # in-place local fold
  else:
    var rD = g.takeFTmp(fslot)
    g.emitFValue2(rhsC, rD)
    if rD.kind == InFReg:
      g.fbin(op32, op64, res.f, rD.f, bits)
      g.freeVal(rD)
    else:                                                # eftmp-spilled rhs: staged fold
      let fs2 = g.pickFStagingSealed("a spilled float operand", avoid = res.f)
      g.emFloatScalarLoad(fs2, rD.name, bits)
      g.fbin(op32, op64, res.f, fs2, bits)
      g.rb.unsealF fs2
  dest = res

proc emitCast2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(conv|cast Type inner)`. Decisions inline (allocValue CastC/ConvC):
  ## float targets/sources force the SIMD/GPR shapes; a NARROWING cast whose
  ## inner is a symbol with a frozen home forces a fresh temp (narrow-in-place
  ## would corrupt the live variable); otherwise the inner dest-threads (the
  ## identity) and the result is re-represented in place.
  let isCast = c.exprKind == CastC
  var tc, targetCur, inner: Cursor
  block:
    var cc = c
    cc.into:
      targetCur = cc                                     # target type AS WRITTEN (nominal)
      tc = resolveType(g.prog, cc); skip cc              # target type (resolved)
      inner = cc; skip cc
      while cc.hasMore: skip cc
  if g.isFloatExpr(c):
    # conversion TO float: the result is an xmm (int source → cvtsi2sd; float
    # source → precision convert).
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ
                        else: AsmSlot(cls: AFloat, size: 8, align: 8))
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoFMem2(c, dest); return
    let res = dest
    let dstBits = if res.typ.size == 4: 32 else: 64
    if g.isFloatExpr(inner):
      var fv = res                                       # dest-pass into the operand
      g.emitFValue2(inner, fv)
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
      g.emFcvt(res.f, res.f, dstBits, g.floatBits(inner))
    else:
      var iv = needsReg(ScalarSlot)
      g.emitValue2(inner, iv)
      var ivReg: Reg
      var ownIv = false
      if iv.kind == InReg:
        ivReg = iv.r
      else:                                              # spilled operand → staging
        ivReg = g.pickStagingSealed("int→float operand", iv.typ)
        g.emitLoadLoc(iv, ivReg)
        ownIv = true
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
      let (srcW, srcSigned) = g.srcWidthSigned(inner)
      g.extendTo(ivReg, srcW, srcSigned)                 # normalize to the full int value
      g.fcvtI2F(res.f, ivReg, dstBits)
      if ownIv: g.giveBack(ivReg)
      else: g.freeVal(iv)
    dest = res
    return
  if g.isFloatExpr(inner):
    # FLOAT source → int/ptr target: cvttsd2si, then a narrow target extends.
    if isCast:                                           # `(cast int float)` = bit reinterpret
      raiseAssert "arkham: float bit-reinterpret cast not supported yet"
    g.forceRegDestE(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let res = dest
    var fv = dontCare
    g.emitFValue2(inner, fv)
    assert fv.kind == InFReg, "arkham x64n: float→int operand " & $fv.kind
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
    g.fcvtF2I(res.r, fv.f, (if fv.typ.size == 4: 32 else: 64))
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
      let sh = g.ra.locationOfSym(symName(inner))
      var tgc = targetCur
      if sh.kind in {InReg, NamedStack} and slotOf(g.prog, tgc).size < sh.typ.size:
        g.forceRegDestE(dest)
  # A memory-home destination: compute into a temp, re-represent, store.
  if dest.kind in {NamedStack, Mem} and not (dest.kind == NamedStack and dest.spillTemp):
    var tmp = needsReg(dest.typ)
    g.emitCast2(c, tmp)
    let s = (if tmp.kind == InReg: tmp.r
             else: g.pickStagingSealed("a cast result", tmp.typ))
    if tmp.kind != InReg: g.emitLoadLoc(tmp, s)
    g.emitStoreLoc(dest, s)
    if tmp.kind != InReg: g.giveBack s
    else: g.freeVal(tmp)
    return
  # Pre-retype a register-homed named dest to the INNER's type while the inner
  # emits (int arithmetic under an int→ptr reinterpret runs int-typed).
  if dest.kind == InReg and not dest.isTemp and
     (isPtrType(tc) or isPtrType(resolveType(g.prog, g.getType(inner)))):
    let nm = g.rb.boundName(dest.r)
    if nm.len > 0:
      var st = g.getType(inner)
      g.rebindLocalAs(nm, dest.r, st)
  var iv = dest                                          # identity: thread dest down
  if iv.kind == Undef:
    # An unconstrained dest could resolve to the inner's memory home — but the
    # cast re-represents (rebind/extend) in a REGISTER. Demand reg-or-imm: a
    # foldable literal stays an Imm (returned above), a memory home loads.
    iv = regOrImm(dest.typ)
  g.emitValue2(inner, iv)
  dest = iv
  if dest.kind == Imm: return                            # a folded constant reinterprets freely
  if dest.kind == NamedStack and dest.spillTemp: return  # produced into its slot already
  assert dest.kind == InReg, "arkham x64n: cast result " & $dest.kind
  let res2 = dest
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  let kindChange = ptrTarget or srcPtr
  if kindChange:
    if res2.isTemp:
      g.bindTemp(res2.r, (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot))
    else:
      let nm = g.rb.boundName(res2.r)                    # the register's named local
      if nm.len > 0: g.rebindLocalAs(nm, res2.r, targetCur)
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if kindChange:
    if ptrTarget and not srcPtr and srcW < 64: g.extendTo(res2.r, srcW, signed = false)
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW:
      g.extendTo(res2.r, srcW, signed = (not isCast) and srcSigned)   # widen
    else:
      g.extendTo(res2.r, targetW, signed = isSignedType(tc))          # narrow / equal
proc emitCall2(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false) =
  ## FUSED call. allocCall's placement decisions run inline: each scalar arg
  ## dest-threads straight into its ABI register (or a parked callee-saved
  ## survivor when a later argument's shift/div would clobber it — decided by
  ## `fixedRegsClobberedByE` right here); aggregate args reserve their held
  ## scratches at the point of use; the result settles from rax/xmm0 into
  ## `dest`. `hiddenPtr` documents a >16B-result call whose rdi the caller
  ## pre-loaded; the plan derives the same fact from the callee's return type.
  discard hiddenPtr
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
  var stagedFnptr = NoReg
  var fnptrLoc = dontCare                            # the held fn-ptr value (freed post-call)
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
    g.emitValue2(targetCur, fnptrLoc)              # fn-ptr target → a held register
    if fnptrLoc.kind == InReg:
      fnptrReg = fnptrLoc.r
    else:                                          # pool-dry etmp: staged reload
      assert fnptrLoc.kind == NamedStack, "arkham x64n: indirect call target loc " & $fnptrLoc.kind
      stagedFnptr = g.pickStagingSealed("an indirect call target", AddrSlot)
      g.emitLoadLoc(fnptrLoc, stagedFnptr)
      fnptrReg = stagedFnptr
    if targetCur.kind == Symbol and g.rb.boundName(fnptrReg) == symName(targetCur):
      tgt = CallTarget(declarative: declarative, asmName: symName(targetCur), retType: retType)
    else:
      let nm = g.rb.freshTmpName("fntmp")
      g.ab.tree RebindX64:
        g.ab.symDef nm
        var pc = proctype
        g.genTypeBody(pc)
        g.ab.reg fnptrReg
      g.rb.bindScratch(fnptrReg, nm, isPtr = false)
      fnTargetName = nm
      tgt = CallTarget(declarative: declarative, asmName: nm, retType: retType)
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
    if tgt.memIntrin.len > 0:                      # C mem* intrinsic → inline loop
      g.emitMemIntrin2(argCurs, tgt.memIntrin)     # (fused arg emission inside)
      g.settleResultReg(dest, RAX)
      return
    if tgt.bitBuiltin.len > 0:                     # GCC bit builtin → inline bsf/…
      g.emitBitBuiltin2(argCurs, tgt.bitBuiltin)
      g.settleResultReg(dest, RAX)
      return
  let isSyscall = tgt.syscall
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: AsmSlot(cls: AInt, size: 8, align: 8)
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let resultByRef = hasResult and resSlot.kind == AMem and resSlot.size > g.md.aggrByRefThreshold
  var callArgSlots: seq[AsmSlot] = @[]
  for a in argCurs: callArgSlots.add g.exprSlot(a)
  let plan = planCall(g.md, callArgSlots, resultByRef)
  # Which ABI argument registers does a LATER argument overwrite by ISA fiat?
  var laterClob: seq[set[Reg]] = @[]
  block:
    var per: seq[set[Reg]] = @[]
    for a in argCurs: per.add g.fixedRegsClobberedByE(a)
    laterClob = newSeq[set[Reg]](per.len + 1)
    for i in countdown(per.len - 1, 0): laterClob[i] = laterClob[i+1] + per[i]
  var heldArgs: seq[Location] = @[]                # parked survivors, freed post-call

  proc settleCallResult(g: var CodeGen; dest: var Location) =
    ## Move the call result (rax / xmm0) into `dest`.
    if not hasResult: return
    if resultIsFloat:
      if dest.kind != InFReg:
        dest = g.takeFTmp(resSlot)                 # the float pool excludes xmm0
      if dest.kind == InFReg:
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
        if dest.f != FloatRet:
          g.fmovF(dest.f, FloatRet, (if dest.typ.size == 4: 32 else: 64))
      else:                                        # eftmp slot: store xmm0 straight
        g.emitStoreFLoc(dest, FloatRet, dest.typ.size * 8)
    elif resSlot.kind == AMem:
      discard                                      # aggregate result: consumed by the caller
    else:
      case dest.kind
      of Undef, NeedsReg, RegOrImm:
        dest = regLoc(RAX, resSlot, isTemp = true)
        if not g.rb.isBoundTemp(RAX): g.bindTemp(RAX, resSlot)
      of InReg:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, resSlot)
        if dest.r != RAX: g.movReg(dest.r, RAX)
      of NamedStack, Mem:
        let bound = g.rb.isBoundTemp(RAX)
        if not bound: g.bindTemp(RAX, resSlot)
        g.emitStoreLoc(dest, RAX)
        if not bound: g.unbindTemp(RAX)
      else: raiseAssert "arkham x64n: call result dest " & $dest.kind

  if not tgt.declarative:
    # ── Manual-marshalling path (empty signature: float params/results, ≤16B
    # by-value aggregate results). Args go straight into raw ABI registers.
    var sealedArgs: set[Reg] = {}
    var pendingRestores: seq[tuple[dst, src: Reg]] = @[]
    if resultByRef: (g.rb.sealAccum g.md.intArgRegs[0]; sealedArgs.incl g.md.intArgRegs[0])
    for j in 0 ..< argCurs.len:
      let a = argCurs[j]
      let pl = plan.args[j]
      if pl.isAgg:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham x64: aggregate call-arg of non-nominal type"
        let tn = symName(tcur)
        var exposed = false
        if not pl.onStack:
          for k in 0 ..< pl.words:
            if g.md.gprAt(pl, k) in laterClob[j+1]: exposed = true
        var parked: seq[Reg] = @[]
        if exposed:
          for k in 0 ..< pl.words:
            let h = g.takeHeld("a clobber-exposed aggregate call argument")
            heldArgs.add h
            parked.add h.r
        var marshalRegs = @(g.md.intArgRegs[pl.gpFirst ..< pl.gpFirst + pl.words])
        if parked.len > 0:
          marshalRegs = parked
          for k in 0 ..< pl.words:
            g.releaseStaleName(parked[k])
            pendingRestores.add (dst: g.md.gprAt(pl, k), src: parked[k])
            g.rb.sealAccum parked[k]; sealedArgs.incl parked[k]
        if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
          let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
          heldArgs.add addrHeld
          let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
          g.emitLvalue2(a)                         # pick embedded base/index regs
          let (srcAddr, spillAddr) = g.aggrArgAddr(a, recorded, marshalRegs)
          if not pl.byRef:
            g.marshalAggrFromAddr(srcAddr, tn, marshalRegs)
          else:
            g.movReg(marshalRegs[0], srcAddr)
          if spillAddr: g.giveBack srcAddr else: g.unbindTemp srcAddr
          g.freeLvalTemps2(a)
        else:
          var home = ""
          var ptrReg = NoReg
          if a.kind == Symbol:
            let sloc = g.ra.locationOfSym(symName(a))
            if sloc.kind == NamedStack: home = symName(a)
            elif sloc.kind == InReg: ptrReg = sloc.r
            elif g.lookupSym(symName(a)).cat == scGlobal: discard
            else:
              raiseAssert "arkham x64: aggregate symbol arg neither local nor global: " & symName(a)
          else:
            let pos = cursorToPosition(g.buf[], a)
            home = "aggtmp" & $pos & ".0"
            g.emTypedStackVar(home, tcur)
            g.varType[home] = tn
            g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
          if not pl.byRef:
            if ptrReg != NoReg: g.marshalAggrFromAddr(ptrReg, tn, marshalRegs)
            elif home.len > 0: g.structToRegs(home, tn, marshalRegs)
            else: g.globalToRegs(symName(a), tn, marshalRegs)
          else:
            if ptrReg != NoReg: g.movReg(marshalRegs[0], ptrReg)
            elif home.len > 0: g.emStackAddr(marshalRegs[0], home)
            else: g.emGlobalAddr(marshalRegs[0], symName(a))
      elif g.isFloatExpr(a):
        var fD = fregLoc(g.md.floatArgRegs[pl.fpIndex],
                         AsmSlot(cls: AFloat, size: 8, align: 8))
        g.emitFValue2(a, fD)                       # → its xmm arg register
      else:
        let abiReg = g.md.gprAt(pl)
        g.releaseArgDest(abiReg, (if a.kind == Symbol: symName(a) else: ""))
        var aD = regLoc(abiReg, ScalarSlot)
        g.emitValue2(a, aD)                        # → its GPR arg register
      if not pl.isFloat and not pl.onStack:
        for k in 0 ..< pl.words:
          g.rb.sealAccum g.md.gprAt(pl, k); sealedArgs.incl g.md.gprAt(pl, k)
    for pr in pendingRestores:                     # parked words → their raw ABI registers
      g.releaseStaleName(pr.dst)
      g.movReg(pr.dst, pr.src)
    g.ab.tree PrepareX64:
      g.ab.sym tgt.asmName
      if isSyscall: g.emSyscall()
      else: g.ab.keyword CallX64
    g.flushArgResidentParams()
    g.rb.unsealAccums(sealedArgs)
    if fnTargetName.len > 0:
      g.ab.tree KillX64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    if stagedFnptr != NoReg: g.giveBack stagedFnptr
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    g.settleCallResult(dest)
    return
  # ── the unified declarative path: every argument binds via `(arg pN [k])`.
  var sealedArgs: set[Reg] = {}
  var pendingArgBinds: seq[tuple[nameIdx: int, src: Reg, wordIdx: int]] = @[]
  var pendingSpillArgs: seq[tuple[nameIdx: int, slot: Location]] = @[]
  g.ab.tree PrepareX64:
    g.ab.sym tgt.asmName
    if resultByRef:
      g.ab.tree MovX64:
        g.ab.tree ArgX: g.ab.sym paramName(0)
        g.emReg g.md.intArgRegs[0]
      g.rb.sealAccum g.md.intArgRegs[0]; sealedArgs.incl g.md.intArgRegs[0]
    for j in 0 ..< argCurs.len:
      let a = argCurs[j]
      let pl = plan.args[j]
      let nameIdx = pl.ord
      if pl.isAgg:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham x64: aggregate call-arg of non-nominal type"
        let tn = symName(tcur)
        let byRef = pl.byRef
        let gprWords = pl.words
        let fits = not pl.onStack
        let isLval = a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}
        var exposed = false
        if fits:
          for k in 0 ..< gprWords:
            if g.md.gprAt(pl, k) in laterClob[j+1]: exposed = true
        var parked: seq[Reg] = @[]
        if exposed:
          for k in 0 ..< gprWords:
            let h = g.takeHeld("a clobber-exposed aggregate call argument")
            heldArgs.add h
            parked.add h.r
        var dst: seq[Reg] = @[]
        if fits:
          if parked.len > 0:
            for r in parked:
              g.releaseStaleName(r)
              dst.add r
          else:
            let aSym = if a.kind == Symbol: symName(a) else: ""
            for k in 0 ..< gprWords:
              let r = g.md.gprAt(pl, k)
              g.releaseArgDest(r, aSym)
              dst.add r
        if not fits:
          g.ra.hasStackVars = true           # outgoing stack-arg area ⇒ frame sub
          var srcAddr = NoReg
          var srcSpilled = false
          var srcOwned = true
          if isLval:
            let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
            heldArgs.add addrHeld
            let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
            g.emitLvalue2(a)
            (srcAddr, srcSpilled) = g.aggrArgAddr(a, recorded, [])
          else:
            let (home, ptrReg, isTvar) = g.aggrArgSource(a, tcur, tn)
            if ptrReg != NoReg:
              srcAddr = ptrReg; srcOwned = false
            else:
              srcAddr = g.pickStagingSealed("a stack aggregate-arg address", AddrSlot)
              srcSpilled = true
              if home.len > 0: g.emStackAddr(srcAddr, home)
              elif isTvar: g.emTvarAddr(srcAddr, symName(a))
              else: g.emGlobalAddr(srcAddr, symName(a))
          template outgoingSlot(k: int; indexed: bool) =
            g.ab.tree MemX:
              g.ab.reg RSP
              g.ab.tree ArgX:
                g.ab.sym paramName(nameIdx)
                if indexed: g.ab.intLit k.int64
          if byRef:
            g.ab.tree MovX64: (outgoingSlot(0, false); g.emReg srcAddr)
          else:
            for k in 0 ..< gprWords:
              let w = g.pickStagingSealed("a stack aggregate-arg word", AddrSlot)
              g.ab.tree MovX64: (g.emReg w; g.emWordThroughPtr(srcAddr, k))
              g.ab.tree MovX64: (outgoingSlot(k, true); g.emReg w)
              g.giveBack w
          if srcOwned:
            if srcSpilled: g.giveBack srcAddr else: g.unbindTemp srcAddr
          if isLval: g.freeLvalTemps2(a)
        elif isLval:
          let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
          heldArgs.add addrHeld
          let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
          g.emitLvalue2(a)
          let (srcAddr, spillAddr) = g.aggrArgAddr(a, recorded, dst)
          if byRef: g.movReg(dst[0], srcAddr)
          else: g.marshalAggrFromAddr(srcAddr, tn, dst)
          if spillAddr: g.giveBack srcAddr else: g.unbindTemp srcAddr
          g.freeLvalTemps2(a)
        else:
          let (home, ptrReg, isTvar) = g.aggrArgSource(a, tcur, tn)
          if byRef:
            if ptrReg != NoReg: g.movReg(dst[0], ptrReg)
            elif home.len > 0: g.emStackAddr(dst[0], home)
            elif isTvar: g.emTvarAddr(dst[0], symName(a))
            else: g.emGlobalAddr(dst[0], symName(a))
          else:
            if ptrReg != NoReg: g.marshalAggrFromAddr(ptrReg, tn, dst)
            elif home.len > 0: g.structToRegs(home, tn, dst)
            elif isTvar: g.tvarToRegs(symName(a), tn, dst)
            else: g.globalToRegs(symName(a), tn, dst)
        if fits:
          if parked.len > 0:
            for k in 0 ..< gprWords:
              pendingArgBinds.add (nameIdx: nameIdx, src: dst[k],
                                   wordIdx: (if byRef: -1 else: k))
              g.rb.sealAccum dst[k]; sealedArgs.incl dst[k]
          else:
            for k in 0 ..< gprWords:
              g.ab.tree MovX64:
                g.ab.tree ArgX:
                  g.ab.sym paramName(nameIdx)
                  if not byRef: g.ab.intLit k.int64
                g.emReg dst[k]
      elif g.isFloatExpr(a):
        var fD = fregLoc(g.md.floatArgRegs[pl.fpIndex],
                         AsmSlot(cls: AFloat, size: 8, align: 8))
        g.emitFValue2(a, fD)
        g.ab.tree MovX64:
          g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
          g.emFReg fD.f
      else:
        # Scalar arg. Clobber-exposed → compute into a parked survivor and bind
        # at the end; else straight into the ABI register.
        var aD: Location
        var parkSpilled = false
        if not pl.onStack and g.md.gprAt(pl) in laterClob[j+1]:
          let hr = g.pickHeldReg()
          if hr != NoReg:
            g.pickedRegs.incl hr
            aD = regLoc(hr, ScalarSlot, isTemp = true)
          else:
            # No survivor free. A bound POOL temp parks just as safely: the
            # later-arg clobbers are the FIXED cl/rdx only, and every later
            # pick avoids bound temps. Both pools dry → produce into a minted
            # slot and reload at the bind-flush point (memory survives all).
            aD = g.takeTmp(ScalarSlot)
          heldArgs.add aD
          g.emitValue2(a, aD)
          if aD.kind != InReg:
            pendingSpillArgs.add (nameIdx: nameIdx, slot: aD)
            parkSpilled = true
        elif not pl.onStack:
          let abiReg = g.md.gprAt(pl)
          g.releaseArgDest(abiReg, (if a.kind == Symbol: symName(a) else: ""))
          aD = regLoc(abiReg, ScalarSlot)
          g.emitValue2(a, aD)
        else:
          aD = needsReg(ScalarSlot)
          g.emitValue2(a, aD)                      # 7th+ arg: any register
        if not parkSpilled:
          var srcReg = NoReg
          var ownSrc = false
          if aD.kind == InReg:
            srcReg = aD.r
          else:                                    # pool-dry etmp: staged reload
            srcReg = g.pickStaging()
            g.bindTemp(srcReg, ScalarSlot)
            g.emitLoadLoc(aD, srcReg)
            ownSrc = true
          if not pl.onStack:
            if not ownSrc and srcReg != g.md.gprAt(pl):
              pendingArgBinds.add (nameIdx: nameIdx, src: srcReg, wordIdx: -1)
              g.rb.sealAccum srcReg; sealedArgs.incl srcReg
            else:
              g.ab.tree MovX64:
                g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
                g.emReg srcReg
          else:
            g.ra.hasStackVars = true         # outgoing stack-arg area ⇒ frame sub
            g.ab.tree MovX64:
              g.ab.tree MemX:
                g.ab.reg RSP
                g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
              g.emReg srcReg
            if not ownSrc: g.freeVal(aD)           # the stack-arg temp dies with its store
          if ownSrc: g.giveBack srcReg
      if not pl.isFloat and not pl.onStack:
        for k in 0 ..< pl.words:
          g.rb.sealAccum g.md.gprAt(pl, k); sealedArgs.incl g.md.gprAt(pl, k)
    for ps in pendingSpillArgs:
      # A clobber-exposed arg that had to park in a minted slot: reload through
      # staging and bind now, after every clobbering computation ran.
      let s = g.pickStaging()
      g.bindTemp(s, ScalarSlot)
      g.emitLoadLoc(ps.slot, s)
      g.ab.tree MovX64:
        g.ab.tree ArgX: g.ab.sym paramName(ps.nameIdx)
        g.emReg s
      g.giveBack s
    for pb in pendingArgBinds:
      g.ab.tree MovX64:
        g.ab.tree ArgX:
          g.ab.sym paramName(pb.nameIdx)
          if pb.wordIdx >= 0: g.ab.intLit pb.wordIdx.int64
        g.emReg pb.src
    if isSyscall: g.emSyscall()
    else: g.ab.keyword CallX64
    g.flushArgResidentParams()
    if hasResult and not resultByRef and not resultIsFloat and resSlot.kind != AMem:
      g.ab.tree MovX64:
        g.emReg RAX
        g.ab.tree ResX: g.ab.sym "ret.0"
  g.rb.unsealAccums(sealedArgs)
  if fnTargetName.len > 0:
    g.ab.tree KillX64: g.ab.sym fnTargetName
    discard g.rb.takeBinding(fnptrReg)
  if stagedFnptr != NoReg: g.giveBack stagedFnptr
  g.freeVal(fnptrLoc)
  for h in heldArgs: g.freeVal(h)
  g.settleCallResult(dest)
proc takeInstrReg(g: var CodeGen; slot: AsmSlot): Location =
  ## A register an `(instr …)` operand or result MUST have (no memory form).
  ## Pools first; exhausted, draw from the emit-time STAGING set — an intrinsic
  ## crosses no call, so a transient serves (sealed so a nested pick can't
  ## reuse it; the consumer's `giveBack` unseals). This is strictly better than
  ## the old allocator's answer, which had to DEMOTE a local to memory here.
  let r = g.pickTempReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, slot, isTemp = true)
  # NOT the R11 bridge: the atomic sequences use it as their own work register
  # (`seedWork`/xadd), and the old allocator's pools could never produce it —
  # the lowering bodies rely on that.
  let s = g.pickStagingScratch(avoid = R11)
  if s == NoReg:
    raiseAssert "arkham x64n: out of registers for an intrinsic operand in proc " &
                g.curProcName
  g.ra.seal {s}
  result = regLoc(s, slot, isTemp = true)

proc atomicValueMayBeImmE(op: IntrinsicOp; i: int): bool {.inline.} =
  ## May an atomic's operand `i` stay a literal on x86-64? (Port of the
  ## allocator's `atomicValueMayBeImm`, x64 half.)
  i == 1 and op in {AtomicStoreOp, AtomicExchangeOp, AtomicFetchAddOp,
                    AtomicFetchSubOp, AtomicAddFetchOp, AtomicSubFetchOp,
                    AtomicFetchAndOp, AtomicFetchOrOp, AtomicFetchXorOp}

proc emitInstr2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(instr SYM X*)`: allocInstr's operand/result placement decided
  ## inline; each evaluated operand's resolved Location is written to the
  ## `ra.locs` memo so the shared transliteration bodies (`emitAtomicInstr2`,
  ## `emitInoutInstr2`, `instrOperandReg`) read them unchanged.
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  block:
    var fc = c
    fc.into:
      fsym = symName(fc); skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if tgX64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no x86-64 lowering — " &
              "guard the call with a `when`"
  if row.isFlagRead or row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` is a flag instruction; flags " &
              "are only legal inside an `{.assembler.}` proc, where no " &
              "instruction may be inserted between one and its use",
              lengInfo(c)
  if row.inoutOperand >= 0:
    # Two-address row: the destination operand IS its home; sources are
    # immediates (per the row) or registers.
    var ops: seq[Location] = @[]
    var i = 0
    for a in argCurs:
      if i != row.inoutOperand:
        var d = regOrImm(ScalarSlot)
        g.emitValue2(a, d)
        g.ra.locs[cursorToPosition(g.buf[], a)] = d
        ops.add d
      inc i
    g.emitInoutInstr2(c, tgt.op, argCurs)
    for d in ops:
      if d.kind == InReg: g.giveBack d.r
    dest = Location(kind: Undef)                # no value: nothing consumes this node
    return
  # Resolve the result FIRST and seal it, so an operand pick cannot land on it.
  var res = Location(kind: Undef)
  if not row.isVoidResult:
    case dest.kind
    of NeedsReg, RegOrImm: dest = g.takeInstrReg(dest.typ)
    of Undef: dest = g.takeInstrReg(ScalarSlot)
    else: discard
    res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.ra.isSealed(res.r)
  if sealedHere: g.ra.seal {res.r}
  var ops: seq[Location] = @[]
  block:
    var i = 0
    for a in argCurs:
      if i >= row.evaluatedOperands: break      # trailing memory-order knobs: never evaluated
      var d =
        if (row.tie >= 0 and i != row.tie) or atomicValueMayBeImmE(tgt.op, i):
          regOrImm(g.exprSlot(a))
        else:
          g.takeInstrReg(g.exprSlot(a))
      g.emitValue2(a, d)
      g.ra.locs[cursorToPosition(g.buf[], a)] = d
      ops.add d
      inc i
  if sealedHere: g.ra.unseal {res.r}
  if tgt.op.isAtomic:
    g.emitAtomicInstr2(c, tgt.op, argCurs, res)
    for d in ops:
      if d.kind == InReg and not (res.kind == InReg and d.r == res.r):
        g.giveBack d.r
    return
  if res.kind != InReg:
    raiseAssert "arkham x64n: intrinsic result is not in a register"
  # The transliteration (the old emitInstr2 tail, over the fresh decisions).
  let a0 = if argCurs.len > 0: g.ra.locs[cursorToPosition(g.buf[], argCurs[0])]
           else: default(Location)
  let aliasesA0 = a0.kind == InReg and a0.r == res.r
  if res.isTemp and not aliasesA0 and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  let inPlace = inPlaceIntrinsicX64(tgt.op)
  if inPlace and not aliasesA0:
    if a0.kind == InReg: g.movReg(res.r, a0.r)
    else: g.place2(a0, res.r)
  let src0 = if inPlace: res.r else: g.instrOperandReg(argCurs[0])
  var rotCount = 0'i64
  if tgt.op in {RolOp, RorOp}:
    let cnt = g.ra.locs[cursorToPosition(g.buf[], argCurs[1])]
    if cnt.kind != Imm:
      raiseAssert "arkham x64n: `" & IntrinsicNames[tgt.op] &
                  "` needs a compile-time rotate count"
    rotCount = cnt.ival
  g.emitIntrinsicOps(tgt.op, tgt.argBits, res.r, src0, rotCount)
  for d in ops:
    if d.kind == InReg and d.r != res.r: g.giveBack d.r
  dest = res
proc emitFValue2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED SIMD value: resolve `dest` (an xmm constraint / fixed register /
  ## `eftmp` slot) against `c` and materialize the float value there.
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let f64 = AsmSlot(cls: AFloat, size: 8, align: 8)
  case c.kind
  of FloatLit:
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
      if dest.kind == NamedStack:
        g.produceIntoFMem2(c, dest); return
    let bits = if dest.typ.size == 4: 32 else: 64
    if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
    let gpr = g.pickStagingSealed("a float literal bit pattern",
                                  AsmSlot(cls: AInt, size: 8, align: 8))
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest.f, gpr, bits)
    g.giveBack gpr
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    case home.kind
    of InFReg:
      if dest.kind != InFReg:
        dest = home                                      # use the home in place
      elif home.f != dest.f:
        let bits = if dest.typ.size == 4: 32 else: 64
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
        g.fmovF(dest.f, home.f, bits)
    of NamedStack:                                       # spilled float local
      if dest.kind != InFReg:
        dest = g.takeFTmp(home.typ)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      g.emFloatScalarLoad(dest.f, home.name, bits)
    else:                                                # a float global / tvar read
      if dest.kind != InFReg:
        dest = g.takeFTmp(g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      var cc = c
      let loc = g.asLoc(cc)
      g.floatMemMov(loc, dest.f, bits, load = true)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC: g.emitFBinE(c, dest)
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
          skip cc                                        # result float type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      var iv = dest
      g.emitFValue2(inner, iv)                           # operand → dest
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      let z = g.pickFStagingSealed("a float neg temp")
      g.bindFTmp(z)
      g.fmovF(z, dest.f, bits)                           # z = operand
      let gpr = g.pickStagingSealed("a float neg zero",
                                    AsmSlot(cls: AInt, size: 8, align: 8))
      g.movImm(gpr, 0)
      g.fmovFromGpr(dest.f, gpr, bits)                   # dest = 0.0
      g.giveBack gpr
      g.fbin(SubssX64, SubsdX64, dest.f, z, bits)        # dest = 0.0 - operand
      g.unbindFTmp(z); g.rb.unsealF z
    of InfC, NeginfC, NanC:
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      let gpr = g.pickStagingSealed("a float special-value bit pattern",
                                    AsmSlot(cls: AInt, size: 8, align: 8))
      let pat =
        if bits == 32:
          case c.exprKind
          of InfC: 0x7F80_0000'i64
          of NeginfC: 0xFF80_0000'i64
          else: 0x7FC0_0000'i64                          # NanC (quiet NaN)
        else:
          case c.exprKind
          of InfC: 0x7FF0_0000_0000_0000'i64
          of NeginfC: cast[int64](0xFFF0_0000_0000_0000'u64)
          else: 0x7FF8_0000_0000_0000'i64                # NanC (quiet NaN)
      g.movImm(gpr, pat)
      g.fmovFromGpr(dest.f, gpr, bits)
      g.giveBack gpr
    of ConvC, CastC: g.emitCast2(c, dest)                # conversion TO float
    of CallC: g.emitCall2(c, dest)                       # float-result call → xmm0
    of DerefC, DotC, AtC, PatC:
      # float lvalue load → movss/movsd res, [addr]
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      g.emitLvalue2(c)                                   # pick embedded base/index
      g.prematLval2(c)
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
        g.emFReg dest.f
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
    else: raiseAssert "arkham x64n: emitFValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitFValue2(fused) kind " & $c.kind
proc resolveLvalVal(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED: decide (only) where an lvalue-embedded VALUE — a deref'd pointer, a
  ## computed index — will live; `prematLval2` materializes it into the decided
  ## location right before the consuming `(mem …)` opens. A symbol resolves to
  ## its home, a literal to an immediate, a computed subtree to a reserved temp
  ## (its own computation emits at premat time, dest-threaded).
  case c.kind
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    if home.kind == NoLoc: g.forceRegDestE(dest)     # a global/tvar value read
    else: g.resolveDestE(dest, home)
  of IntLit: g.resolveDestE(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.resolveDestE(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.resolveDestE(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  else: g.forceRegDestE(dest)                        # computed: reserve the result

proc emitLvalWalk(g: var CodeGen; n: var Cursor; globBase: Location; isStore: bool;
                  heldBase = false) =
  ## FUSED port of the allocator's `allocLvalue2`: walk an lvalue subtree,
  ## deciding its embedded values' locations into the `ra.locs` memo — the
  ## registers `prematLval2` materializes into and `emLvalAddr2` reads. Pure
  ## pick-and-record: NO emission here. Advances `n` past the whole lvalue.
  ##
  ## `heldBase` says an enclosing `(at …)`/`(pat …)` has an INDEX that CALLS (a
  ## bounds check, typically): the base is materialized before that call and
  ## read back after it, so its scratch must be a callee-saved survivor rather
  ## than a volatile the call would clobber (075b051's fix, fused twin).
  case n.kind
  of Symbol:
    let nm = symName(n)
    if g.ra.locationOfSym(nm).kind == NoLoc:         # a module-level global aggregate base
      let pos = cursorToPosition(g.buf[], n)
      if globBase.kind == InReg:
        g.ra.locs[pos] = globBase
      elif not isStore and not heldBase:
        # transient global base for a LOAD: `prematLval2` sources the address
        # from emit-time staging (the R11 bridge) — leave the position
        # unresolved as the marker.
        g.ra.locs[pos] = dontCare
      else:
        g.ra.locs[pos] = g.takeHeld("a global base address")
    inc n                                            # stack-var / pointer / global base name
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        g.emitLvalWalk(n, globBase, isStore, heldBase) # base (a stack var, deref, or global)
        while n.hasMore: skip n                      # field name (+ any extras)
    of DerefC:
      n.into:
        let pPos = cursorToPosition(g.buf[], n)
        var d = if heldBase: g.takeHeld("a deref base held across an index call")
                else: needsReg(ScalarSlot)
        g.resolveLvalVal(n, d)                       # the pointer → a register
        g.ra.locs[pPos] = d
        skip n
        while n.hasMore: skip n
    of AtC:
      n.into:
        # Peek at the index BEFORE deciding the base: a calling index (a bounds
        # check) clobbers the volatiles between the base's materialization and
        # its use, so the base subtree must take survivors.
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCallE(idxPeek)
        g.emitLvalWalk(n, globBase, isStore, held)   # base (stack array, deref, or global)
        if n.kind in {IntLit, UIntLit}: skip n       # immediate index — folds, no scratch
        else:
          let iPos = cursorToPosition(g.buf[], n)
          var idx = needsReg(ScalarSlot)
          g.resolveLvalVal(n, idx)                   # register index (folds via scale)
          g.ra.locs[iPos] = idx
          skip n
        while n.hasMore: skip n
    of PatC:
      n.into:
        var idxPeek = n; skip idxPeek                # same base-vs-calling-index hazard
        let held = heldBase or subtreeHasCallE(idxPeek)
        let pPos = cursorToPosition(g.buf[], n)
        var d = if held: g.takeHeld("a pat base held across an index call")
                else: needsReg(ScalarSlot)
        g.resolveLvalVal(n, d)                       # the pointer → a register
        g.ra.locs[pPos] = d
        skip n
        if n.kind in {IntLit, UIntLit}: skip n       # immediate index
        else:
          let iPos = cursorToPosition(g.buf[], n)
          var idx = needsReg(ScalarSlot)
          g.resolveLvalVal(n, idx)
          g.ra.locs[iPos] = idx
          skip n
        while n.hasMore: skip n
    of BaseobjC:                                     # `(baseobj BaseT depth lvalue)` — transparent
      n.into:
        skip n                                       # base type
        skip n                                       # depth
        g.emitLvalWalk(n, globBase, isStore, heldBase) # the inner lvalue
        while n.hasMore: skip n
    of AconstrC, OconstrC:
      # A constructor used as an lvalue base (`[a,b][i]`): nothing to decide
      # here — `prematLval2` builds it into its `aggtmp<pos>` slot via the
      # (fused) `genStore2`, whose single-use temps are decided there.
      skip n
    else:
      raiseAssert "arkham x64n: computed lvalue base not supported: " & $n.exprKind
  else:
    inc n

proc emitLvalue2(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false) =
  var n = c
  g.emitLvalWalk(n, globBase, isStore)

proc freeLvalTemps2(g: var CodeGen; c: Cursor) =
  ## FUSED port of `releaseLvalTemps`: release the reserved scratch of an
  ## lvalue's address computation — a computed index (`at`/`pat`), a computed
  ## pointer (`deref`/`pat`) — dead once the consuming access used the address.
  ## `freeVal` is a no-op on a symbol's home (non-temp). The stride scratch /
  ## global-base staging are released by `unbindLvalTemps2` (staging-managed).
  if c.kind != TagLit: return
  case c.exprKind
  of DotC:
    var cc = c
    cc.into:
      g.freeLvalTemps2(cc)                           # base
      while cc.hasMore: skip cc
  of DerefC:
    var cc = c
    cc.into:
      g.freeVal(g.ra.locs[cursorToPosition(g.buf[], cc)])   # the pointer value
      while cc.hasMore: skip cc
  of AtC:
    var cc = c
    cc.into:
      g.freeLvalTemps2(cc)                           # base (by-value: does not advance)
      skip cc                                        # → the index operand
      if cc.kind notin {IntLit, UIntLit}:
        g.freeVal(g.ra.locs[cursorToPosition(g.buf[], cc)]) # the computed index
      while cc.hasMore: skip cc
  of PatC:
    var cc = c
    cc.into:
      g.freeVal(g.ra.locs[cursorToPosition(g.buf[], cc)])   # the pointer value
      skip cc
      if cc.kind notin {IntLit, UIntLit}:
        g.freeVal(g.ra.locs[cursorToPosition(g.buf[], cc)]) # the computed index
      while cc.hasMore: skip cc
  of BaseobjC:                                       # transparent: free the inner lvalue's temps
    var cc = c
    cc.into:
      skip cc; skip cc                               # base type, depth
      g.freeLvalTemps2(cc)                           # the inner lvalue
      while cc.hasMore: skip cc
  else: discard

proc emitProcBody2(g: var CodeGen; info: ProcInfo; frameHasCall: bool) =
  ## The pure-emitter twin of `emitProcBody`, run ONCE (no plan pass). Reuses the
  ## shared signature / frame / param-settling / scope machinery; only the value
  ## core (`genStmt2`/`emitValue2`) differs.
  ##
  ## Body-buffer model (chibicc's trick): the BODY is emitted into a side buffer
  ## first; the prologue — whose shape (callee-saved pushes, alignment pad, the
  ## `(s)` region `sub`) is only final once the body is known — is written after
  ## it, into the main buffer, and the body appended. This is what lets the
  ## merged value core mint spill slots and draw callee-saved temps INLINE
  ## during emission. Only `stackArgBaseReg`'s identity is fixed up front (the
  ## body's stack-param loads name it).
  g.pickStackArgBaseX64(g.ra.hasStackParams)
  # Seal the base so inline callee-saved temp draws during the body cannot take
  # it (its pushes/loads are written into the prologue after the body).
  if g.stackArgBaseReg != NoReg: g.ra.seal {g.stackArgBaseReg}
  var side = g.ab.sideBuf()
  swap(g.ab, side)                        # emit into the side buffer; `side` holds main
  g.enterScope()
  if g.retIndirect:
    # The hidden result pointer arrives in rdi. Save it into the callee-saved
    # `indirectReg` for the duration of the body. In the DECLARATIVE path the
    # signature binds rdi to `paramName(0)`, so it must be read by name (a raw
    # `(reg rdi)` use of a bound register is rejected) and the binding killed. But a
    # NON-declarative proc (float/≤16B-aggregate-result param forces an empty
    # signature) never emits that binding, so there `p0.0` is undefined — read the
    # raw arg register instead, mirroring how non-declarative params are moved.
    if isDeclarativeAbi(g.prog, info.decl):
      g.ab.tree MovX64: (g.emReg g.indirectReg; g.ab.sym paramName(0))
      g.ab.tree KillX64: g.ab.sym paramName(0)
    else:
      g.movReg(g.indirectReg, g.md.intArgRegs[0])
  g.emitParamMoves(info.decl)
  g.emitStackParamLoadsX64(info.decl)               # via stackArgBaseReg, regs now free
  if info.isEntry and g.hasGlobalInits:              # run runtime global inits at startup
    g.ab.tree PrepareX64:
      g.ab.sym g.globalInitSym
      g.ab.keyword CallX64
  g.retLabel2 = g.freshLabel()                       # shared epilogue for mid-proc `ret`
  g.retLabelUsed2 = false
  g.binNormSuppressPos = -1                          # no store-fused normalize elision pending
  var c = info.decl
  c.into:
    inc c; skip c; skip c; skip c                    # name, params, ret, pragmas
    # The whole body is in tail position: after it, control reaches the epilogue.
    # The entry proc ends in an exit syscall (no epilogue jump), so leave it false.
    g.tailStmt = not info.isEntry
    if c.stmtKind == StmtsS: g.genStmt2(c)
    while c.hasMore: skip c
  g.exitScope()
  if g.retLabelUsed2: g.emLab(g.retLabel2)           # a non-tail `ret` lands here
  if info.isEntry:
    g.movImm(RAX, 60); g.movImm(RDI, 0); g.emSyscall()
  swap(g.ab, side)                        # back to the main buffer; `side` holds the body
  # The body is emitted — `ra.usedCallee` / `hasStackVars` are final. Finalize the
  # frame and write the prologue, then splice the body after it.
  g.computeFrameX64(info.isEntry, frameHasCall)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl)
    g.ab.tree StmtsX64:
      g.framePush()
      # Capture the incoming stack-args base (rsp after the pushes) BEFORE the frame
      # `sub`s move rsp — stack params are then loaded relative to it, after the `(s)`
      # region exists and `emitParamMoves` has freed the arg registers. RAW register
      # operands: this text is written AFTER the body was emitted (body-buffer model),
      # so `emReg`/`binImm` would render whatever binding the reg carries post-body —
      # a name that, in program order, is not bound yet at this point.
      if g.stackArgBaseReg != NoReg:
        g.ab.tree MovX64: (g.ab.reg g.stackArgBaseReg; g.ab.reg RSP)
        g.ab.tree AddX64:
          g.ab.reg g.stackArgBaseReg
          g.ab.intLit g.framePushBytesX64().int64
      if g.framePad > 0: g.binImm(SubX64, RSP, g.framePad.int64)
      if g.ra.hasStackVars:
        g.ab.tree SubX64: (g.ab.reg RSP; g.ab.keyword SsizeX)
      # Declare the totality spill slots (`etmp`/`eftmp`/`held`) — minted INLINE
      # during body emission (`takeTmp` exhaustion), which is why this loop runs
      # here, in the prologue that is written AFTER the body. A pointer slot
      # keeps its precise `(ptr T)` type so a later deref/cmp type-checks; an
      # integer slot is the generic `(s)(i 64)`.
      for st in g.ra.spillTemps:
        if st.isFloat:
          g.emFloatStackVar(st.name, st.typ.size * 8)
        elif isNilSlot(st.typ) or
             (not cursorIsNil(st.typ.typ) and isPtrType(resolveType(g.prog, st.typ.typ))):
          g.emTypedStackVar(st.name, st.typ.typ)   # `(nil)` / `(ptr T)` slot keeps its type
        else:
          g.emScalarStackVar(st.name)
      g.ab.append side                                 # the body
      if not info.isEntry:
        g.framePop()
        g.ab.keyword RetX64

proc recordVarType(g: var CodeGen; c: Cursor) =
  ## `(param :nm . type)` / `(var :nm pragmas type …)` → record `symType[nm] = type`.
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc                                    # pragmas
      let typeCur = cc; skip cc                  # type
      g.symType[nm] = g.declType(typeCur, cc)    # `.` ⇒ inferred from the initializer
    while cc.hasMore: skip cc

proc recordSymTypes(g: var CodeGen; c: Cursor) =
  ## Pre-pass: populate `symType` for every local var decl so `getType` works during
  ## allocation, before emission fills them in incrementally. Recurses statement
  ## containers; nested proc/type decls are allocated separately.
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

# ── `.assembler` procs: transliteration, not compilation ────────────────────
# doc/intrinsics.md §8. Everything below deliberately bypasses `allocateProc` and
# the whole value core: in an `.assembler` body every location is DECLARED, so
# there is nothing to allocate, and every construct must map one-to-one to an
# instruction, so there is nothing to lower. What is left is a checker plus a
# literal transcription — and arkham is the only checker there is (nimony's sem
# just forwards the pragmas), so each rejection below is a user-facing error with
# the offending node's own file/line/col, not a `raiseAssert`.

proc x64RegByName(name: string): Reg =
  ## `"rdi"` → `RDI`. The inverse of `x64RegName`, over the 16 GPRs; `NoReg` for
  ## anything else (including `rsp`/`rbp`, which the frame owns — see `asmPinReg`).
  result = NoReg
  for r in [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15]:
    if x64RegName(r) == name: return r

proc asmPinReg(g: var CodeGen; at: Cursor; name: string): Reg =
  ## Resolve a `.register: "…"` spelling to a register, rejecting the ones the
  ## proc's own frame owns: `rsp`/`rbp` move under the prologue's pushes, so a
  ## value pinned there would be silently destroyed.
  result = x64RegByName(name)
  if result == NoReg:
    lengError at, "`" & name & "` is not an x86-64 general-purpose register", g.asmInfo
  if result in {RSP, RBP}:
    lengError at, "`" & name & "` is reserved for the stack frame and cannot hold a value",
              g.asmInfo

type
  AsmDeclKind = enum
    aslNone,       ## no location pragma at all
    aslReg,        ## `{.register: "rax".}`
    aslStack       ## `{.stack.}`
  AsmDeclLoc = object
    ## Where a `.assembler` param/local was DECLARED to live.
    kind: AsmDeclKind
    r: Reg

proc asmDeclLoc(g: var CodeGen; prag: Cursor): AsmDeclLoc =
  ## Read `(pragmas (register "rax"))` / `(pragmas (stack))` off a param or local.
  result = AsmDeclLoc(kind: aslNone, r: NoReg)
  if prag.substructureKind != PragmasU: return
  var p = prag
  p.into:
    while p.hasMore:
      case p.pragmaKind
      of RegisterP:
        let at = p
        var nm = ""
        p.into:
          if p.hasMore and p.kind == StrLit: (nm = strVal(p); inc p)
          while p.hasMore: skip p
        result = AsmDeclLoc(kind: aslReg, r: g.asmPinReg(at, nm))
      of StackP:
        result = AsmDeclLoc(kind: aslStack, r: NoReg)
        skip p
      else: skip p

proc isResultName(nm: string): bool {.inline.} =
  ## Nimony names a routine's implicit result `result.<n>[.<module>]`. It is the one
  ## local a user cannot annotate — `result` is not a declaration they write — so
  ## `.assembler` pins it to the ABI return register instead of demanding a pragma.
  nm.startsWith("result.")

proc x64FlagOf(op: IntrinsicOp): X64Flag =
  ## The nifasm condition tag a flag-read row denotes. `(ite (zf) …)` already
  ## exists in the assembler with all ten x86 conditions, so a flag intrinsic is
  ## no new mechanism — the row says which bit and which polarity, and this maps
  ## the one enum to the other. Name-for-name, `of`/`no` included (they were once
  ## `ovf`/`novf`, for want of a keyword in ident position).
  case op
  of ZfOp: ZfO
  of NotZfOp: NzO
  of CfOp: CfO
  of NotCfOp: NcO
  of SfOp: SfO
  of NotSfOp: NsO
  of OfOp: OfO
  of NotOfOp: NoO
  of PfOp: PfO
  of NotPfOp: NpO
  else: NoFlag

proc instrOpAt(g: var CodeGen; c: Cursor): IntrinsicOp =
  ## The row an `(instr SYM …)` node names, or `NoIntrinsicOp` if `c` is not one.
  result = NoIntrinsicOp
  if c.kind != TagLit or c.exprKind != InstrC: return
  var fc = c
  var sym = ""
  fc.into:
    sym = symName(fc); skip fc
    while fc.hasMore: skip fc
  result = instrTargetOf(g.prog, sym).op

proc asmNoteInfo(g: var CodeGen; c: Cursor) {.inline.} =
  ## Remember the innermost node that carried line info, so a rejection deeper in
  ## (NIF line info is sparse) still points at the right statement.
  let li = lengInfo(c)
  if li.len > 0: g.asmInfo = li

proc asmRegOf(g: var CodeGen; c: Cursor): Reg =
  ## The register an operand names. `.assembler` operands must be ATOMS, so this is
  ## a table lookup and nothing else — no evaluation, no materialization.
  if c.kind != Symbol:
    lengError c, "an `.assembler` operand must be a variable or a literal, not " &
              "a computed expression", g.asmInfo
  let nm = symName(c)
  if nm in g.asmStack:
    lengError c, "`" & userName(nm) & "` lives on the stack; this operand needs a register",
              g.asmInfo
  if not g.asmReg.hasKey(nm):
    lengError c, "`" & userName(nm) & "` has no declared location — every local in an " &
              "`.assembler` proc needs `{.register: \"…\".}` or `{.stack.}`", g.asmInfo
  result = g.asmReg[nm]

proc asmScanLocs(g: var CodeGen; c: Cursor; used: var set[Reg]; anyStack: var bool) =
  ## Pre-pass over the body: which registers the locals pin (so the prologue knows
  ## which callee-saved ones to push) and whether any `(s)` slot exists (so the
  ## prologue reserves the `(ssize)` region the epilogue releases). Both facts are
  ## needed BEFORE the first statement is emitted, and both are pure declaration
  ## reading — no evaluation is involved.
  if c.kind != TagLit: return
  if c.stmtKind == VarS:
    var cc = c
    cc.into:
      inc cc                                     # name
      let loc = g.asmDeclLoc(cc)
      case loc.kind
      of aslReg: used.incl loc.r
      of aslStack: anyStack = true
      of aslNone: discard
      while cc.hasMore: skip cc
    return
  if c.stmtKind in {ProcS, TypeS}: return
  var cc = c
  cc.into:
    while cc.hasMore: (g.asmScanLocs(cc, used, anyStack); skip cc)

proc asmStmt(g: var CodeGen; c: Cursor)
proc asmInstr(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor)

proc isAsmStackSym(g: CodeGen; c: Cursor): bool {.inline.} =
  c.kind == Symbol and symName(c) in g.asmStack

proc asmAtom(c: Cursor): Cursor =
  ## Peel the type-only wrappers the front end puts around a literal: `result = 100`
  ## in a `uint64` context arrives as `(conv (u 64) 100)`. A conversion of a
  ## CONSTANT is a fact about the constant — the assembler encodes the immediate
  ## at the operand's width and no instruction exists to emit — so folding it is
  ## what "one-to-one" means here. A `conv` of a *value* is a real sign/zero
  ## extension and is left alone, so it still reaches the rejection below.
  result = c
  while result.kind == TagLit and result.exprKind in {ConvC, CastC}:
    var inner = result
    var got = result
    var count = 0
    inner.into:
      skip inner                                 # the target type
      while inner.hasMore:
        if count == 0: got = inner
        inc count
        skip inner
    if count != 1 or got.kind notin {IntLit, UIntLit, CharLit}: return
    result = got

proc asmOperand(g: var CodeGen; cur: Cursor) =
  ## One source operand of a flag-defining instruction: a register local, a stack
  ## slot, or a literal. Unlike `asmRegOf` this permits memory and immediates,
  ## because `cmp`/`test` take them directly — no materialisation involved.
  let c = asmAtom(cur)
  case c.kind
  of Symbol:
    if g.isAsmStackSym(c): g.emStackMem(symName(c))
    else: g.emReg g.asmRegOf(c)
  of IntLit: g.ab.intLit intVal(c)
  of UIntLit: g.ab.intLit cast[int64](uintVal(c))
  else:
    lengError c, "an `.assembler` operand must be a variable or a literal", g.asmInfo

proc asmInoutDest(g: var CodeGen; c: Cursor) =
  ## Emit the destination of a two-address row. The operand arrives as
  ## `(haddr d)` — the compiler binding d's LOCATION for a `var` parameter, not
  ## the user taking a pointer (see nimony/doc/tags.md). So it resolves to d's
  ## DECLARED home and nothing is materialised: that tag is the whole reason this
  ## needs no "an `addr` here means something else" rule.
  if c.kind != TagLit or c.exprKind != HaddrC:
    lengError c, "the destination of a two-address instruction must be a `var` " &
              "argument naming a local", g.asmInfo
  var inner = c
  var sym = c
  inner.into:
    sym = inner; skip inner
    while inner.hasMore: skip inner
  if sym.kind != Symbol:
    lengError sym, "the destination of a two-address instruction must be a local " &
              "with a declared location", g.asmInfo
  let nm = symName(sym)
  if nm in g.asmStack: g.emStackMem(nm)
  else: g.emReg g.asmRegOf(sym)

proc asmInoutInstr(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `add(d, s)` / `neg(d)` — a row that writes THROUGH operand 0 and returns
  ## nothing. Statement-only, since there is no value to bind.
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let row = IntrinsicRows[op]
  if argCurs.len != row.arity:
    lengError c, "`" & IntrinsicNames[op] & "` takes " & $row.arity & " operand(s)",
              g.asmInfo
  let tag = x64InoutTag(op)
  if tag == NopX64:
    lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 two-address form",
              g.asmInfo
  if row.arity == 1:
    g.ab.tree tag: g.asmInoutDest(argCurs[0])
  else:
    if g.isAsmStackSym(argCurs[1]) and
       argCurs[0].kind == TagLit and argCurs[0].exprKind == HaddrC:
      # `(add [mem], [mem])` does not exist. Only flagged when BOTH are memory;
      # a memory destination with a register or immediate source is fine.
      var d = argCurs[0]; inc d
      if d.kind == Symbol and symName(d) in g.asmStack:
        lengError c, "`" & IntrinsicNames[op] & "` cannot take two memory operands",
                  g.asmInfo
    g.ab.tree tag: (g.asmInoutDest(argCurs[0]); g.asmOperand(argCurs[1]))

proc asmFlagInstr(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `cmp(a, b)` / `test(a, b)` — an instruction whose entire output is flags.
  ## It is a statement, never a value: there is nothing to bind.
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  if argCurs.len != 2:
    lengError c, "`" & IntrinsicNames[op] & "` takes two operands", g.asmInfo
  if g.isAsmStackSym(argCurs[0]) and g.isAsmStackSym(argCurs[1]):
    lengError c, "`" & IntrinsicNames[op] & "` cannot take two memory operands",
              g.asmInfo
  let tag = if op == CmpOp: CmpX64 else: TestX64
  g.ab.tree tag: (g.asmOperand(argCurs[0]); g.asmOperand(argCurs[1]))

proc asmAsgn(g: var CodeGen; c: Cursor) =
  ## `(asgn dest src)` — the only shape that produces a value. `dest` is an atom
  ## with a declared home; `src` is an atom, a literal, or ONE `(instr …)`.
  var cc = c
  cc.into:
    let destC = cc
    skip cc
    let srcC = asmAtom(cc)
    # A `{.stack.}` local is a memory operand, so a move touching one is `mov
    # [slot], reg` / `mov reg, [slot]`. Memory on BOTH sides would take a scratch
    # register no one declared — the one thing `.assembler` will not invent.
    if g.isAsmStackSym(destC):
      if g.isAsmStackSym(srcC):
        lengError srcC, "a memory-to-memory move needs a scratch register; " &
                  "assign through a `{.register: \"…\".}` local", g.asmInfo
      let nm = symName(destC)
      case srcC.kind
      of Symbol:
        g.ab.tree MovX64: (g.emStackMem(nm); g.emReg g.asmRegOf(srcC))
      of IntLit:
        g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit intVal(srcC))
      of UIntLit:
        g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit cast[int64](uintVal(srcC)))
      else:
        lengError srcC, "a `{.stack.}` local can only be assigned a variable or a literal",
                  g.asmInfo
      skip cc
      while cc.hasMore: skip cc
      return
    let dst = g.asmRegOf(destC)
    case srcC.kind
    of Symbol:
      if g.isAsmStackSym(srcC):
        g.ab.tree MovX64: (g.emReg dst; g.emStackMem(symName(srcC)))
      else:
        g.movReg(dst, g.asmRegOf(srcC))
    of IntLit:
      g.movImm(dst, intVal(srcC))
    of UIntLit:
      g.movImm(dst, cast[int64](uintVal(srcC)))
    of TagLit:
      if srcC.exprKind != InstrC:
        lengError srcC, "an `.assembler` statement must be one instruction; `" &
                  $srcC.exprKind & "` would need temporaries", g.asmInfo
      g.asmInstr(destC, dst, srcC)
    else:
      lengError srcC, "unsupported `.assembler` operand", g.asmInfo
    skip cc
    while cc.hasMore: skip cc

proc asmInstr(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor) =
  ## `(instr SYM X*)` in an `.assembler` body: the operands are already where the
  ## user put them, so this is the row's opcode over `dst` and the operand
  ## registers — the same `emitIntrinsicOps` the allocated path ends in.
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    fsym = symName(fc); skip fc
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if tgX64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no x86-64 lowering; an " &
              "`.assembler` proc has no fallback path", g.asmInfo
  if row.isFlagRead:
    # The rule of §6, at its one enforcement point: a flag has no register behind
    # it, and `setcc` — the instruction that would give it one — reads the same
    # bit that everything emitted in between may already have destroyed.
    lengError c, "`" & IntrinsicNames[tgt.op] & "()` is a flag, not a value; " &
              "it can only be an `if` condition", g.asmInfo
  if row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` produces no value, only flags; " &
              "use it as a statement", g.asmInfo
  if row.inoutOperand >= 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` writes through its first " &
              "operand and returns nothing; use it as a statement", g.asmInfo
  if argCurs.len == 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` takes no operands here", g.asmInfo
  var rotCount = 0'i64
  if tgt.op in {RolOp, RorOp}:
    if argCurs.len < 2 or argCurs[1].kind notin {IntLit, UIntLit}:
      lengError c, "`" & IntrinsicNames[tgt.op] & "` needs a literal rotate count",
                g.asmInfo
    rotCount = (if argCurs[1].kind == IntLit: intVal(argCurs[1])
                else: cast[int64](uintVal(argCurs[1])))
  # An in-place form reads and writes one register, so the destination must be
  # seeded with operand 0 first. Outside `.assembler` the allocator arranges the
  # tie; here the user did, and if they did not the seeding `mov` is the honest
  # transliteration of what they wrote.
  let src0 = if inPlaceIntrinsicX64(tgt.op): dst else: g.asmRegOf(argCurs[0])
  if inPlaceIntrinsicX64(tgt.op):
    g.movReg(dst, g.asmRegOf(argCurs[0]))
  g.emitIntrinsicOps(tgt.op, tgt.argBits, dst, src0, rotCount)

proc asmVarDecl(g: var CodeGen; c: Cursor) =
  ## `(var :nm (pragmas (register "rax")) T init?)` — a DECLARATION of a location,
  ## not an allocation request. Several locals may name the same register (the user
  ## pinned them together); only the first declares a nifasm binding.
  var cc = c
  cc.into:
    let nameC = cc
    let nm = symName(cc); inc cc
    let loc = g.asmDeclLoc(cc)
    skip cc                                      # pragmas
    let typeCur = cc
    skip cc                                      # type
    let hasInit = cc.hasMore and cc.kind != DotToken
    let initC = asmAtom(cc)
    case loc.kind
    of aslReg:
      g.asmReg[nm] = loc.r
      # The signature already bound the ABI registers (`p0.0`, `ret.0`); pinning a
      # local onto one of those is legal — it is the same machine register under a
      # second source name — but must not redeclare the binding.
      if not g.rb.isBound(loc.r):
        g.emRegLocalVar(nm, loc.r, typeCur)
    of aslStack:
      g.asmStack.incl nm
      g.emTypedStackVar(nm, typeCur)
    of aslNone:
      if isResultName(nm):
        # The result is pinned to the ABI return register, derived rather than
        # annotated: Nimony has no syntax for annotating `result`, and the ABI
        # leaves no choice anyway.
        g.asmReg[nm] = g.md.intRetReg
      else:
        lengError nameC, "`" & userName(nm) & "` needs `{.register: \"…\".}` or `{.stack.}` — an " &
                  "`.assembler` proc declares every location", g.asmInfo
    if hasInit:
      # `var r {.register: "rax".} = x` is an assignment like any other.
      if loc.kind == aslStack:
        case initC.kind
        of Symbol:
          if g.isAsmStackSym(initC):
            lengError initC, "a memory-to-memory move needs a scratch register; " &
                      "assign through a `{.register: \"…\".}` local", g.asmInfo
          g.ab.tree MovX64: (g.emStackMem(nm); g.emReg g.asmRegOf(initC))
        of IntLit:
          g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit intVal(initC))
        of UIntLit:
          g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit cast[int64](uintVal(initC)))
        else:
          lengError initC, "a `{.stack.}` local can only be initialized with a " &
                    "variable or a literal", g.asmInfo
      else:
        case initC.kind
        of Symbol:
          if g.isAsmStackSym(initC):
            g.ab.tree MovX64: (g.emReg g.asmReg[nm]; g.emStackMem(symName(initC)))
          else:
            g.movReg(g.asmReg[nm], g.asmRegOf(initC))
        of IntLit: g.movImm(g.asmReg[nm], intVal(initC))
        of UIntLit: g.movImm(g.asmReg[nm], cast[int64](uintVal(initC)))
        of TagLit:
          if initC.exprKind != InstrC:
            lengError initC, "an `.assembler` initializer must be one instruction or an atom",
                      g.asmInfo
          g.asmInstr(nameC, g.asmReg[nm], initC)
        else:
          lengError initC, "unsupported `.assembler` initializer", g.asmInfo
      skip cc
    while cc.hasMore: skip cc

proc asmStmt(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return
  g.asmNoteInfo(c)
  # Tail position, tracked exactly as `genStmt2` does: only the LAST statement of
  # a straight-line `stmts`/`scope` inherits it. A `ret` there falls through to the
  # epilogue instead of jumping to it — in a mode whose premise is one-to-one, a
  # `jmp` to the very next label is an instruction the user did not write.
  let myTail = g.tailStmt
  g.tailStmt = false
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore
        g.asmStmt(cc); skip cc
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore
        g.asmStmt(cc); skip cc
    g.exitScope()
  of VarS: g.asmVarDecl(c)
  of AsgnS: g.asmAsgn(c)
  of InstrS:
    # An instruction in statement position produces no value, so the rows that
    # belong here are the two that have no result: one that writes through an
    # `inout` operand, and one whose whole output is the flags.
    let op = g.instrOpAt(c)
    if op != NoIntrinsicOp and IntrinsicRows[op].inoutOperand >= 0:
      g.asmInoutInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isFlagWrite:
      g.asmFlagInstr(c, op)
    else:
      lengError c, "an instruction used as a statement must have a destination",
                g.asmInfo
  of WhileS:
    # `while true` only. A conditional loop would need the condition evaluated into
    # flags, which is §6's flag intrinsics — not yet available, so it is rejected
    # rather than silently compiled through the ordinary (allocating) path.
    var cc = c
    cc.into:
      let condC = cc
      if not (condC.kind == TagLit and condC.exprKind == TrueC):
        lengError condC, "an `.assembler` loop must be `while true`; use `break` to leave it",
                  g.asmInfo
      skip cc
      let lEnd = g.freshLabel()
      g.loopEnds.add lEnd
      g.emitLoop:
        while cc.hasMore: (g.asmStmt(cc); skip cc)
      g.emLab(lEnd)
      discard g.loopEnds.pop()
  of IfS:
    # `if <flag>(): … else: …` → nifasm's `(ite (zf) then else)`, which already
    # exists with all ten x86 conditions. A flag is the ONLY condition allowed:
    # anything else would have to be computed into a register first, and the
    # instruction that computed it would clobber the very bit an enclosing flag
    # test might be reading. `elif` is a nested `if` on the machine, and writing
    # it that way keeps every `(ite …)` one flag test.
    var cc = c
    var branches = 0
    cc.into:
      while cc.hasMore:
        case cc.substructureKind
        of ElifU:
          inc branches
          if branches > 1:
            lengError cc, "an `.assembler` `if` takes one condition; write a " &
                      "nested `if` for the next flag test", g.asmInfo
          var bc = cc
          bc.into:
            let condC = bc
            let op = g.instrOpAt(condC)
            if op == NoIntrinsicOp or not IntrinsicRows[op].isFlagRead:
              lengError condC, "an `.assembler` condition must be a flag " &
                        "intrinsic such as `zf()`; any other condition would " &
                        "need an instruction that clobbers the flags", g.asmInfo
            let flag = x64FlagOf(op)
            if flag == NoFlag:
              lengError condC, "`" & IntrinsicNames[op] &
                        "` has no x86-64 condition code", g.asmInfo
            skip bc
            # `(ite cond then else)`: nifasm reads exactly two statements, so an
            # `if` with no `else` gets an empty one.
            var peek = cc; skip peek
            let hasElse = peek.hasMore and peek.substructureKind == ElseU
            g.ab.tree IteX64:
              g.ab.keyword flag
              g.ab.tree StmtsX64:
                g.enterScope()
                while bc.hasMore: (g.asmStmt(bc); skip bc)
                g.exitScope()
              g.ab.tree StmtsX64:
                if hasElse:
                  var ec = peek
                  ec.into:
                    g.enterScope()
                    while ec.hasMore: (g.asmStmt(ec); skip ec)
                    g.exitScope()
        of ElseU:
          discard                                # emitted inside the `elif` above
        else:
          lengError cc, "unsupported `if` shape in an `.assembler` proc", g.asmInfo
        skip cc
  of BreakS:
    if g.loopEnds.len == 0:
      lengError c, "`break` outside a loop", g.asmInfo
    g.emJmp(g.loopEnds[^1])
  of LabS:
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emJmp(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of RetS:
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isAsmStackSym(cc):
          g.ab.tree MovX64: (g.emReg g.md.intRetReg; g.emStackMem(symName(cc)))
        else:
          g.movReg(g.md.intRetReg, g.asmRegOf(cc))  # a no-op when already pinned there
        skip cc
      while cc.hasMore: skip cc
    if not myTail:
      g.retLabelUsed2 = true
      g.emJmp(g.retLabel2)
  else:
    lengError c, "`" & $c.stmtKind & "` is not allowed in an `.assembler` proc", g.asmInfo

proc genAsmProc(g: var CodeGen; info: ProcInfo) =
  ## Emit an `.assembler` proc: no allocator, no analyser, no value core. The
  ## signature is the ordinary declarative one (that is what lets ordinary Nimony
  ## call it), and the `.register` annotations on the parameters are checked
  ## AGAINST it — in an `.assembler` proc a location constraint is an assertion,
  ## not a request.
  g.varType.clear(); g.symType.clear(); g.stackSlots.clear()
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.asmReg.clear(); g.asmStack.clear()
  g.asmInfo = lengInfo(info.decl)
  g.loopEnds = @[]
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.ra = RegAlloc()
  if info.isEntry:
    lengError info.decl, "the program entry point cannot be an `.assembler` proc", g.asmInfo
  if not isDeclarativeAbi(g.prog, info.decl):
    lengError info.decl, "an `.assembler` proc's parameters and result must be " &
              "integers or pointers (float and small-aggregate boundaries are not " &
              "modelled in the typed signature yet)", g.asmInfo
  # Parameters: bind each ABI register to the signature's `pN.0` (as the allocated
  # path does) and map the param's own Leng name onto the same register, so the
  # body may spell it either way and `emReg` renders the one nifasm knows.
  var used: set[Reg] = {}
  block:
    var pc = info.decl
    inc pc; inc pc                               # head → name → params
    var ord = 0
    if pc.kind == TagLit:
      pc.into:
        while pc.hasMore:
          var nameC = pc
          pc.into:                               # (param :nm pragmas type)
            nameC = pc
            let nm = symName(pc); inc pc
            let loc = g.asmDeclLoc(pc)
            skip pc                              # pragmas
            g.symType[nm] = pc
            if ord >= g.md.intArgRegs.len:
              lengError nameC, "an `.assembler` proc takes at most " &
                        $g.md.intArgRegs.len & " parameters (the 7th and beyond " &
                        "arrive on the stack)", g.asmInfo
            let abiReg = g.md.intArgRegs[ord]
            case loc.kind
            of aslNone:
              lengError nameC, "parameter `" & userName(nm) & "` needs `{.register: \"" &
                        x64RegName(abiReg) & "\".}` — an `.assembler` proc's " &
                        "annotations ARE its ABI", g.asmInfo
            of aslStack:
              lengError nameC, "parameter `" & userName(nm) & "` arrives in " &
                        x64RegName(abiReg) & ", so it cannot be `{.stack.}`", g.asmInfo
            of aslReg:
              if loc.r != abiReg:
                lengError nameC, "parameter `" & userName(nm) & "` is passed in " &
                          x64RegName(abiReg) & " by the C ABI, but is pinned to " &
                          x64RegName(loc.r), g.asmInfo
            g.asmReg[nm] = abiReg
            g.rb.bindParam(abiReg, paramName(ord))
            used.incl abiReg
            while pc.hasMore: skip pc
          inc ord
  # The result register. The signature's `(result :ret.0 (rax) …)` is the CALLER's
  # view; inside the proc rax stays an ordinary register the body may pin a local
  # onto — exactly what the allocated path does when it writes the result.
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                      # → return type
    if not (rc.kind == DotToken or (rc.kind == TagLit and rc.typeKind == VoidT)):
      used.incl g.md.intRetReg
  var anyStack = false
  block:                                         # scan the BODY (`asmScanLocs` stops at a `proc`)
    var bc = info.decl
    bc.into:
      inc bc; skip bc; skip bc; skip bc          # name, params, ret, pragmas
      if bc.stmtKind == StmtsS: g.asmScanLocs(bc, used, anyStack)
      while bc.hasMore: skip bc
  g.ra.usedCallee = used * g.md.intCalleeSavedSet
  g.ra.hasStackVars = anyStack
  g.pickStackArgBaseX64(hasStackParams = false)
  g.computeFrameX64(isEntry = false, hasCall = false)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl)
    g.ab.tree StmtsX64:
      g.enterScope()
      g.framePush()
      if g.framePad > 0: g.binImm(SubX64, RSP, g.framePad.int64)
      if g.ra.hasStackVars:
        g.ab.tree SubX64: (g.ab.reg RSP; g.ab.keyword SsizeX)
      g.retLabel2 = g.freshLabel()
      g.retLabelUsed2 = false
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c            # name, params, ret, pragmas
        g.tailStmt = true                        # the whole body is in tail position
        if c.stmtKind == StmtsS: g.asmStmt(c)
        while c.hasMore: skip c
      # The label FIRST, then the scope kills: every `ret` jumps here, so the kills
      # belong on the path that actually reaches the epilogue (emitting them before
      # the label would leave them stranded after the body's final `jmp`).
      if g.retLabelUsed2: g.emLab(g.retLabel2)
      g.exitScope()
      g.framePop()
      g.ab.keyword RetX64

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. Every per-proc
# table (regLocal/boundTemps + the ra.locs snapshot) must be reset here or
# RegisterBindingsMatchLoc breaks.
proc genProc(g: var CodeGen; info: ProcInfo) =
  if info.isAsm:
    g.genAsmProc(info)
    return
  # Unlike A64 (where a thread-local goes through a TLV-descriptor thunk call), x64
  # reads/writes a tvar directly as an FS-segment operand — no call — so tvar
  # accesses must NOT mark the proc non-leaf. Hence the empty tvar set here.
  if not g.cleanSigComputed:                   # compute the clean-signature set once
    g.cleanSigProcs = cleanSigProcNames(g.prog)
    g.cleanSigComputed = true
  let an = analyseProc(g.buf[], info.decl,
                       cleanCallees = g.cleanSigProcs,
                       procIsClean = isCleanSigProc(g.prog, info.decl),
                       entryLeadingClobber = info.isEntry and g.hasGlobalInits)
  g.varType.clear()                           # reuse the backing storage across procs
  g.symType.clear()
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.rb.resetProc()                            # per-proc register-binding state
  g.aliasToDecl.clear()                       # per-proc param ABI alias → decl name
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
  # The pre-pass allocates HOMES only (decl walk); every expression decision is
  # made inline by the fused emitters at the point of emission. The x64 stride
  # scratch comes from emit-time staging (takeLvalStride).
  g.pickedRegs = {}
  g.pickedFRegs = {}
  g.emitTmpSpills = 0
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, x64Machine, g.typeCtx, preseal)
  when defined(arkhamTracePath):
    stderr.writeLine "[arkham] " & info.asmName & ": NEW"
  when defined(arkhamDumpLocs):
    block:
      stderr.writeLine "=== allocValue locs ==="
      for pos in g.ra.locs.base ..< g.ra.locs.base + g.ra.locs.data.len:
        let l = g.ra.locs[pos]
        if l.kind == Undef: continue
        var s = "  pos " & $pos & " : " & $l.kind
        case l.kind
        of InReg: s.add " r=" & $l.r
        of Imm: s.add " imm=" & $l.ival
        of NamedStack, Glob, Tvar: s.add " " & l.name
        else: discard
        stderr.writeLine s
  if g.retIndirect:
    g.indirectReg = RBX
    g.ra.usedCallee.incl RBX                   # saved/restored like any callee reg
  # Pure-emit path: the allocator already assigned every value position; emit once.
  # (The frame is finalized INSIDE emitProcBody2, after the body — body-buffer model.
  # The entry injects a `call` to the synthetic global-init proc, so it makes a call
  # even when its own body does not — keep rsp 16-aligned for that call.)
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.argResidentParams.setLen 0; g.argResidentFlushed = false
  g.savedHomes.clear()
  g.lvalStride.clear()
  g.noFoldPos = -1
  g.curProcName = info.asmName
  when defined(arkhamDbgProc):
    block:
      var pc = info.decl; inc pc
      stderr.writeLine "DBG emit proc " & symName(pc)
  g.emitProcBody2(info, an.hasCall or (info.isEntry and g.hasGlobalInits))

proc genGlobal(g: var CodeGen; nifName: string; decl: Cursor) =
  ## `(gvar :name <type>)` — a zero-initialized `.bss` global (also `const`); any
  ## initializer is run at program entry by `emitGlobalInits`.
  # An importc-WITHOUT-exportc gvar names an external (its slot is an `exportc`
  # definition in another bundled module): emit NO slot — references resolve to
  # the bare C name via `emGlobalAddr`. An exportc gvar IS the definition, emitted
  # under its bare C name so importc references in other modules link to it.
  if nifName in g.prog.importcOnlyGvars: return
  let name = g.prog.gvarAsmName(nifName)
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
      var relocs: seq[(int, string)] = @[]
      constToBytes(g.prog, typeCur, c, bytes, relocs)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
        for (off, sym) in relocs:               # symbol-address fields (vtable/RTTI)
          g.ab.tree RelocX:
            g.ab.intLit off
            g.ab.sym sym
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
      elif hasValue:
        # A static-ADDRESS initializer (function-pointer hook etc.): emit the
        # symbol as the gvar's value so nifasm bakes its resolved address into the
        # slot — also correct for a foreign module's gvar in a bundle.
        let addrSym = constAddrSym(c)
        if addrSym.len > 0:
          g.ab.sym addrSym
      g.ab.close()
    while c.hasMore: skip c                      # value (also handled at entry, if runtime)

proc buildGlobalInitProc(g: var CodeGen; initBuf: var TokenBuf) =
  ## Lower each global's RUNTIME initializer into a synthetic `(proc … (stmts (asgn
  ## g e) …))` so it routes through the ordinary value-core pipeline (allocateProc +
  ## emitProcBody2) — no special-case emitter. The entry calls this proc at startup
  ## (see `emitProcBody2`). Const-scalar initializers are laid out as static data by
  ## `genGlobal` and are skipped here, so a module with none gets no init proc.
  ##
  ## `initBuf` shares the input buffer's pool + tag pool, so each `(asgn …)`'s symbol
  ## use re-interns to the SAME `SymId` and the copied initializer subtree is a bulk
  ## `copyMem`. Built into a separate buffer (not the input) so `cursorToPosition`
  ## keys the allocator/emitter location map by position WITHIN `initBuf`.
  var inits: seq[(string, Cursor)] = @[]
  for name, decl in g.globals:
    var c = decl
    if c.stmtKind == ConstS: continue           # emitted as a rodata data blob
    c.into:
      inc c; skip c                             # name, pragmas
      skip c                                    # type
      # A constant-scalar or static-address initializer was laid out as static
      # data (see genGlobal), so there is no entry-time store to emit for it here.
      if c.hasMore and c.kind != DotToken and not isConstScalarInit(c) and
         constAddrSym(c).len == 0:
        inits.add (name, c)
      while c.hasMore: skip c
  if inits.len == 0: return
  g.hasGlobalInits = true
  g.globalInitSym = "arkhamGlobalInit.0"
  template tag(e): TagId = TagId(uint32(ord(e)))
  initBuf.openTag tag(ProcS)
  initBuf.addSymDef g.globalInitSym
  initBuf.openTag tag(ParamsT); initBuf.closeTag()       # (params)
  initBuf.addDotToken()                                  # void return
  initBuf.openTag tag(PragmasU); initBuf.closeTag()      # (pragmas)
  initBuf.openTag tag(StmtsS)
  for (name, initCur) in inits:
    initBuf.openTag tag(AsgnS)
    initBuf.addSymUse name                               # the global lvalue
    initBuf.addSubtree initCur                           # its initializer expression
    initBuf.closeTag()
  initBuf.closeTag()                                     # stmts
  initBuf.closeTag()                                     # proc

proc generateX64*(buf: var TokenBuf; inputPath: string; tags: TagPool): string =
  ## Compile a parsed Leng module to x86-64 / Linux asm-NIF text.
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: x64Machine)
  g.ab.renderReg = x64RegName                 # render register slots as x86 names
  g.prog = collect(buf, inputPath, tags)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
  # Build the synthetic global-init proc (if any runtime initializers exist) BEFORE
  # the proc loop, so the entry proc's frame/body account for the startup `call`.
  # `initBuf` must outlive `genProc` below; it shares `buf`'s pool + tag pool.
  var initBuf = createTokenBuf(64, buf.pool, buf.tags)
  g.buildGlobalInitProc(initBuf)
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
    if g.hasGlobalInits:                         # emit the synthetic init proc itself
      let savedBuf = g.buf
      g.buf = addr initBuf
      var ic = initBuf.beginRead()
      genProc(g, ProcInfo(asmName: g.globalInitSym, decl: ic, isEntry: false))
      g.buf = savedBuf
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
