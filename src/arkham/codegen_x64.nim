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
    # staging — is now `bindTemp`'d to a checked name (see `pickStaging`/the spill
    # paths), so a *raw* pool register reaching here means an unbound scratch
    # slipped past the binder: the silent-clobber hole this work closes. Every OTHER
    # register has an irreducible structural raw use and is allowed: rax/rdi/rsi/rdx/
    # r8/r9 are the syscall + call-argument / return ABI registers; rcx is the 4th call
    # arg; rsp/rbp are the frame/segment bases; rbx/r12–r15 are callee-saved param
    # homes. (The fixed rcx/rdx/rsi/r8 scratch *inside* the self-contained atomics /
    # mem* / byte-copy loops is nonetheless bound there, for extra checker coverage.)
    assert r notin g.md.intTempRegs,
      "arkham x64: unbound scratch-pool register reached emReg: " & x64RegName(r)
    g.ab.reg r

proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg

proc giveBack(g: var CodeGen; r: Reg) {.inline.} =
  ## Release a transient register obtained during premat / value evaluation. Its
  ## scratch binding (`bindTemp`) is `(kill)`'d first; then a staging register
  ## (caller-saved, sealed while it held an address/index so a sibling pick couldn't
  ## reuse it) is unsealed. Unbinding/unsealing a reg that carries neither is a
  ## harmless no-op.
  if r == NoReg: return
  g.unbindTemp(r)
  g.ra.unseal {r}

proc pickStagingSealed(g: var CodeGen; what: string): Reg =
  ## A transient caller-saved staging register, sealed so a nested pick cannot
  ## reuse it until `giveBack` releases it; fails loudly when none is free (the
  ## reserved R11 bridge makes that near-impossible).
  result = g.pickStagingScratch()
  if result == NoReg: raiseAssert "arkham x64n: no staging register for " & what
  g.ra.seal result

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
  ## a raw `(xmmN)`. The SIMD twin of `bindTemp`.
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
  result = "L" & $g.labelCount & ".0"
  inc g.labelCount

# ── expressions ──────────────────────────────────────────────────────────────

proc genTypeBody(g: var CodeGen; c: var Cursor)
proc framePop(g: var CodeGen)
proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg
# value-core emitters (defined far below) used by the shared memory-move helpers
# (`scalarMemMov`/`floatMemMov`) to emit a folded access chain:
proc emitValue2(g: var CodeGen; c: Cursor)
proc prematLval2(g: var CodeGen; c: Cursor)
proc emLvalAddr2(g: var CodeGen; c: Cursor)
proc unbindLvalTemps2(g: var CodeGen; c: Cursor)

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
  ## `(var :name (s) T)` with `T` the value's actual Leng type. Use this (not the
  ## generic `(i 64)` slot) for a homed/spilled scalar whose type matters to
  ## nifasm — e.g. a pointer param that the body later derefs, where an `(i 64)`
  ## slot would both reject the typed store and forbid the deref (nifasm is strict).
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
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
  if cursorIsNil(typ.typ):
    g.ab.intType(64)
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(reg)` the binding
  ## checker can't see. `boundTemps` records that `r`'s `regLocal` entry is a temp, not
  ## a named local. Released by `unbindTemp`.
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

proc collectAtScratch(g: var CodeGen; n: Cursor; res: var HashSet[int]; asBase = false) =
  ## Pre-pass (value core): record every `(at …)` position needing a scratch GPR for
  ## nifasm's 3-operand `(at base idx scratch)` form, so the allocator reserves it.
  ## Two reasons: (1) the element stride is not a SIB scale (a multi-dimensional array's
  ## OUTER dimension); (2) the access is itself the BASE of an enclosing `at`/`pat` and
  ## has a register index — x86 allows only ONE index register per operand, so a nested
  ## `a[i][j]` must materialize the inner `a[i]` into a clean base register before the
  ## outer index folds (`asBase` flags this; an immediate inner index already folds to a
  ## clean displacement, so it never forces one). Runs after `recordSymTypes`, so
  ## `getType` resolves any base. Walks `n`'s whole subtree.
  var c = n
  if c.kind == TagLit:
    if c.exprKind in {AtC, PatC} and
       (g.atNeedsScratch(c) or (asBase and g.atIndexIsReg(c))):
      res.incl cursorToPosition(g.buf[], c)
    var cc = c
    var firstChild = true
    cc.into:
      while cc.hasMore:
        # The FIRST child is the address base of an `at` (the indexed aggregate) or a
        # `dot` (the offset base); a `pat`'s first child is a pointer VALUE in its own
        # register (always a clean base) so it does not propagate. The base is itself
        # indexed-by-an-enclosing-access iff THIS node indexes it (at) or passes a
        # propagated `asBase` through (dot).
        let childAsBase =
          if not firstChild: false
          elif c.exprKind == AtC: true
          elif c.exprKind == DotC: asBase
          else: false
        g.collectAtScratch(cc, res, childAsBase)
        firstChild = false
        skip cc

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
      let p = g.pickStagingSealed("a global load address")
      g.bindTemp(p, pSlot)
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
      let p = g.pickStagingSealed("a global store address")
      g.bindTemp(p, pSlot)
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
  ## a global is always accessed by first materializing its address.
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym name)

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
  if r != NoReg and g.regLocal.hasKey(r):
    g.ab.tree KillX64: g.ab.sym g.regLocal[r]
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
  ## free (the genuinely-out-of-registers case).
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
  ## float local/param home, and not `avoid`. Clobbering it transiently is then safe.
  ## `FloatStagingBridge` (xmm15) is tried FIRST and is the RESERVED float bridge:
  ## it is kept out of the allocator's float temp pool (`floatTempRegs`), so it is
  ## never a live float local/temp home — always pickable. That guarantees
  ## `pickFStaging` never fails, making `produceIntoFMem2` total (every spilled float
  ## value position has a staging xmm). The arg registers follow for nested staging.
  if FloatStagingBridge != avoid and FloatStagingBridge notin g.sealedF:
    return FloatStagingBridge
  for f in g.md.floatArgRegs:
    if f != avoid and f notin g.sealedF and not g.regHoldsLiveFLoc(f):
      return f
  return NoFReg

proc pickFStagingSealed(g: var CodeGen; what: string; avoid: FReg = NoFReg): FReg =
  ## A transient staging xmm, sealed (`sealedF`) so a nested pick cannot reuse it;
  ## the caller releases it with `g.sealedF.excl`. Fails loudly when none is free.
  ## The float twin of `pickStagingSealed`.
  result = g.pickFStaging(avoid)
  if result == NoFReg: raiseAssert "arkham x64n: no staging xmm for " & what
  g.sealedF.incl result

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

# ── atomic builtins (GCC `__atomic_*` → x86 lock-prefixed instructions) ──────
# x86-64 has a strong memory model: a plain aligned `mov` is already an atomic
# load/store, `xchg` with memory is implicitly locked, and an RMW that returns the
# old value uses `lock xadd` / a `lock cmpxchg` retry loop. The `memorder` arg is
# ignored (all sequences are at least acquire/release), matching the A64 backend.
# Inside a sequence there are no calls, so RAX/RCX/RDX (not in the allocator pool)
# are free scratch; the result lands in RAX (the integer return register).

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
  ## A FULL eightbyte is moved as a RAW `(u 64)` word — the slot's address goes into
  ## the R11 staging bridge (a by-ref aggregate already has its pointer in a reg) and
  ## `emWordThroughPtr` reads/writes the whole 8 bytes. This is what makes fields
  ## PACKED into one eightbyte (e.g. `{int32; int32}`) all transfer: a field-TYPED
  ## per-field move would carry only the field at the eightbyte boundary (a 4-byte
  ## mov) and silently drop the rest. A raw word also subsumes the old pointer-field
  ## `(cast (ptr T) reg)` dance (the bytes move regardless of type).
  ##
  ## A TRAILING PARTIAL eightbyte (the aggregate's size is not a multiple of 8 — for a
  ## ≤16-byte aggregate this is always a single sub-word field, e.g. the `int32` of a
  ## `{int64; int32}`) keeps the field-TYPED access, which moves exactly its bytes (no
  ## over-read/over-write past the slot).
  let byteSize = aggrByteSize(g.prog, typeName)
  let loc = g.ra.locationOfSym(varName)
  var baseReg = NoReg
  var addrTmp = NoReg
  if byteSize >= 8:                                    # at least one full eightbyte
    if loc.kind == InReg:
      baseReg = loc.r                                  # a by-ref aggregate's pointer
    else:
      addrTmp = g.pickStaging()                        # R11 bridge ← &slot
      g.emStackAddr(addrTmp, varName)
      baseReg = addrTmp
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:                          # a full eightbyte → raw u64 word
      g.ab.tree MovX64:
        if toRegs: (g.emReg regs[i]; g.emWordThroughPtr(baseReg, i))
        else: (g.emWordThroughPtr(baseReg, i); g.emReg regs[i])
    else:                                              # trailing partial eightbyte → field
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      if fn.len == 0: raiseAssert "arkham x64: sub-word-packed aggregate ABI unsupported"
      g.ab.tree MovX64:
        if toRegs: (g.emReg regs[i]; g.emAggrFieldMem(varName, fn))
        else: (g.emAggrFieldMem(varName, fn); g.emReg regs[i])
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
  let p = g.pickStagingSealed("a global aggregate call-arg address")
  g.emGlobalAddr(p, name)
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
  ## Lower a Leng `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
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


# ── value-core: the PURE emitter (consumes precomputed locs/aux) ──────────────
# Single-pass: the register allocator (allocExprs=true) has already assigned every
# value position a Location in `g.ra.locs` (+ `aux`); this code only emits bytes,
# making NO register decisions — so there is no plan/replay seam. See
# `codegen2_design.md`. Every proc body is emitted through this path (`genProc` →
# `emitProcBody2`); the old reactive emitter and the `procModeled2` gate it fed
# have been deleted entirely.

proc place2(g: var CodeGen; src: Location; dest: Reg) =
  ## Materialize `src` into register `dest` (no-op when it is already there).
  case src.kind
  of InReg: (if src.r != dest: g.movReg(dest, src.r))
  of Imm: g.movImm(dest, src.ival)
  of NamedStack, Mem, Glob, Tvar: g.emitLoadLoc(src, dest)
  else: raiseAssert "arkham x64n: place2 src " & $src.kind

proc emitFValue2(g: var CodeGen; c: Cursor)
proc emitFMemLoad2(g: var CodeGen; c: Cursor)
proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitCondValue2(g: var CodeGen; c: Cursor)
proc emitMemLoad2(g: var CodeGen; c: Cursor)
proc emitAddr2(g: var CodeGen; c: Cursor)
proc aggrAddrInto(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool)
proc bindLvalGlobalBases(g: var CodeGen; c: Cursor; bound: var seq[Reg])
proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string; regs: openArray[Reg])
proc emitCast2(g: var CodeGen; c: Cursor)
proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string)
proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location; auxPos: int)
proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor)

proc binFold(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location; opCur: Cursor) =
  ## `dest op= <memory operand>` (a `NamedStack` slot or a `Mem` access chain `opCur`),
  ## EXCEPT a sub-8-byte field: it has no 64-bit ALU memory form (`add r64, m32` doesn't
  ## exist, and a folded 64-bit read would over-read the field). Such a field is loaded
  ## through a staging reg first — the sized `mov` sign/zero-extends it to the full
  ## 64-bit register — then `op dest, reg`.
  if g.exprSlot(opCur).size < 8:
    let s = g.pickStagingSealed("a sub-width operand")
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

proc emitBin2(g: var CodeGen; c: Cursor) =
  ## Emit a binary-arith node into its precomputed result register, replaying the
  ## allocator's operand placement (`aux.foldB` ⇒ the rhs stays a memory operand).
  let pos = cursorToPosition(g.buf[], c)
  let res = g.ra.locs[pos]
  let (op, isBin) = binArithOp(c)
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
    of NamedStack, Mem: g.binFold(foldOp, rD, lhsLoc, lhsC)  # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin(swapped) lhs " & $lhsLoc.kind
    return
  g.emitValue2(lhsC)                                     # materialize sub-results first
  g.emitValue2(rhsC)
  let lhsLoc = g.ra.locs[cursorToPosition(g.buf[], lhsC)]
  let rhsLoc = g.ra.locs[cursorToPosition(g.buf[], rhsC)]
  # A result whose home is a stolen-victim local (demoted to its stack slot) is
  # computed into a transient staging reg and stored back afterwards.
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:
    resStaging = g.pickStagingSealed("a memory bin result")
    rD = resStaging
  else:
    assert res.kind == InReg, "arkham x64n: bin result " & $res.kind
    rD = res.r
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
    of NamedStack, Mem: g.binFold(op, rD, rhsLoc, rhsC)  # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin rhs " & $rhsLoc.kind
  if rhsLoc.kind == InReg and rhsLoc.isTemp: g.unbindTemp(rhsLoc.r)
  if lhsLoc.kind == InReg and lhsLoc.isTemp and not reusedLhs: g.unbindTemp(lhsLoc.r)
  if resStaging != NoReg:                                # store the result to its stack home
    g.emitStoreLoc(res, resStaging)
    g.giveBack resStaging

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

proc emitBitBuiltin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core GCC bit builtin: allocCall placed the single integer argument in rdi
  ## (a normal int-arg call), so emit it, then the inline scan. Result → rax (moved to
  ## its home by emitCall2). The legacy twin is `genBitBuiltin`.
  g.emitValue2(argCurs[0])                            # → rdi
  let aloc = g.ra.locs[cursorToPosition(g.buf[], argCurs[0])]
  let ar = if aloc.kind == InReg: aloc.r else: RDI
  case builtin
  of "__builtin_ctzll", "__builtin_ctz":
    # count trailing zeros == index of the least-significant set bit == BSF.
    # (x == 0 is UB in C and never reached: nimony callers guard the zero case.)
    g.ab.tree BsfX64: (g.emReg RAX; g.emReg ar)
  else:
    raiseAssert "arkham x64n: bit builtin not yet implemented: " & builtin

proc proctypeOfTarget(g: var CodeGen; targetCur: Cursor): Cursor =
  ## The resolved proctype body of an indirect call target (a `(cast Proctype fnptr)`
  ## function-pointer expression), for ABI queries.
  var ptType = targetCur
  if targetCur.kind == TagLit and targetCur.exprKind in {CastC, ConvC}:
    ptType = targetCur; inc ptType                       # the cast's target type
  result = resolveType(g.prog, ptType)
  assert result.kind == TagLit and result.typeKind == ProctypeT,
    "arkham x64n: indirect call target is not a proctype"

proc emitCall2(g: var CodeGen; c: Cursor) =
  ## Emit a call. The allocator placed each argument in its ABI register (integer →
  ## rdi…r9, float → xmm0–7) and the result in rax / xmm0 (or a dest-passed home).
  ## Two ABIs: the DECLARATIVE one (all-scalar-int params) binds each arg via
  ## `(arg pN)` inside the prepare and reads `(res ret.0)`; the NON-DECLARATIVE one
  ## (float param/return — and later aggregates) evaluates args into raw ABI registers
  ## and emits a bare `(prepare f (call))`, reading the result from rax / xmm0 raw.
  ##
  ## A STATIC call (target is a symbol) and an INDIRECT call (target is a fn-ptr
  ## expression, e.g. a vtable load) share this one path: both use the SysV ABI, so
  ## both run the same marshalling loop below. They differ only in how the `(prepare …)`
  ## symbol and the ABI signature are obtained — a cached `CallTarget` for a symbol, or
  ## one synthesized from the proctype with the fn-ptr evaluated into a (held,
  ## proctype-bound) register whose `regLocal` name nifasm accepts as the target.
  let pos = cursorToPosition(g.buf[], c)
  let resLoc = g.ra.locs[pos]
  var argCurs: seq[Cursor] = @[]
  var fsym = ""
  var targetCur: Cursor
  var indirect = false
  block:
    var fc = c
    fc.into:
      targetCur = fc
      indirect = fc.kind != Symbol
      if not indirect: fsym = symName(fc)
      skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)

  # Resolve the ABI description (`tgt`) and the `(prepare …)` symbol uniformly.
  var tgt: CallTarget
  var fnptrReg = NoReg                               # indirect: the fn-ptr's held register
  var fnptrTemp = false
  if indirect:                                       # target is a fn-ptr expression
    let proctype = g.proctypeOfTarget(targetCur)
    if not isDeclarativeAbi(g.prog, proctype):
      raiseAssert "arkham x64n: non-declarative indirect call not yet supported"
    var retType = proctype                           # the proctype's return type (3rd child)
    block:
      var q = proctype
      q.into:
        skip q; skip q                               # the Empty (name) slot, the params
        retType = q
        while q.hasMore: skip q
    # Evaluate the fn-ptr into its allocator-assigned (held) register. A `(cast Proctype
    # …)` binds that register as a PROCTYPE-typed temp (isPtrType ⊇ ProctypeT), so its
    # `regLocal` name is already a ProcT symbol nifasm accepts as a `(prepare …)` target
    # — no separate var decl needed. It stays bound across arg evaluation below.
    g.emitValue2(targetCur)
    let tloc = g.ra.locs[cursorToPosition(g.buf[], targetCur)]
    assert tloc.kind == InReg, "arkham x64n: indirect call target loc " & $tloc.kind
    fnptrReg = tloc.r
    fnptrTemp = tloc.isTemp
    assert g.regLocal.hasKey(fnptrReg), "arkham x64n: indirect call target not bound to a name"
    tgt = CallTarget(declarative: true, asmName: g.regLocal[fnptrReg], retType: retType)
  else:
    if not g.callTarget.hasKey(fsym):               # resolve + cache (post-flip: no gate prepass)
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        g.callTarget[fsym] = CallTarget(declarative: true, indirect: true,
          asmName: fsym, retType: g.indirectRetType(si.decl))
      else:
        g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    tgt = g.callTarget[fsym]
    if tgt.memIntrin.len > 0:                        # C mem* intrinsic → inline loop
      g.emitMemIntrin2(argCurs, tgt.memIntrin)
      if resLoc.kind == InReg and resLoc.r != RAX: g.movReg(resLoc.r, RAX)
      return
    if tgt.atomic.len > 0:                           # __atomic_* builtin → inline sequence
      g.emitAtomic2(argCurs, tgt.atomic)
      if resLoc.kind == InReg and resLoc.r != RAX: g.movReg(resLoc.r, RAX)
      return
    if tgt.bitBuiltin.len > 0:                        # GCC bit builtin (ctz/…) → inline bsf/…
      g.emitBitBuiltin2(argCurs, tgt.bitBuiltin)
      if resLoc.kind == InReg and resLoc.isTemp: g.bindTemp(resLoc.r, AsmSlot(cls: AInt, size: 8, align: 8))
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
    # release the fn-ptr register (indirect only): its proctype temp is dead post-call.
    if indirect and fnptrTemp: g.unbindTemp(fnptrReg)
    if hasResult and resLoc.kind == InReg:
      # rebind a reused dead-local reg to the NAVIGATED return type (a scalar result only —
      # an aggregate-by-value return spans rax:rdx and is consumed word-by-word, not as a reg).
      if resLoc.isTemp and resSlot.kind != AMem: g.bindTemp(resLoc.r, resSlot)
      if resLoc.r != RAX: g.movReg(resLoc.r, RAX)
  else:
    # Non-declarative: each arg is evaluated straight into its raw ABI register (float →
    # xmm{n}, integer → the GPR); an aggregate arg is marshalled into consecutive GPRs
    # (by-value ≤16B) or passed as a pointer (by-ref). The intIdx/fIdx counting mirrors
    # allocCall so an aggregate's register range matches.
    #
    # A committed argument register must survive while LATER args are evaluated. Hexer
    # un-nests CALL args (so no arg is itself a call), but it does NOT un-nest an
    # `(oconstr …)`/`(aconstr …)` argument — that aggregate is BUILT inline here, and the
    # build copies sub-aggregate fields through a staging register (`pickStaging…` /
    # `copyStructThroughPtr2`). Without protection that pick can grab an arg register
    # already holding an earlier argument (e.g. rdi = `&seq` for `s.add Thing(...)`),
    # clobbering it before the call. Sealing each committed arg reg into `liveAccums`
    # (the documented "arg/return reg holding an in-flight value" set the staging picker
    # avoids) makes the later build route around it.
    var intIdx = if resultByRef: 1 else: 0               # rdi = hidden result ptr (set by the caller)
    var sealedArgs: set[Reg] = {}
    if resultByRef: (g.liveAccums.incl g.md.intArgRegs[0]; sealedArgs.incl g.md.intArgRegs[0])
    for idx in 0 ..< argCurs.len:
      let a = argCurs[idx]
      let intIdx0 = intIdx                               # arg's committed GPRs = [intIdx0, intIdx)
      if g.exprSlot(a).kind == AMem:
        # ── The ONE aggregate-argument path (mirrors allocCall's single AMem branch). ──
        # ONCE (a named stack home, or a global read in place), and the ABI marshalling
        # below is form-blind — driven purely by the TYPE's size. A local, a global, an
        # `(oconstr/aconstr …)`, and an aggregate lvalue (`(at/dot/deref …)`) differ only
        # in how the bytes are reached; once reached they marshal identically. New source
        # forms extend `aggrArgHome`, not the marshaller — no special case per call kind.
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham x64: aggregate call-arg of non-nominal type"
        let tn = symName(tcur)
        let sz = aggrByteSize(g.prog, tn)
        let words = (sz + 7) div 8
        if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
          # An aggregate LVALUE argument: take its ADDRESS (`aggrAddrInto` = `gen_addr`)
          # and marshal STRAIGHT from there — no copy into a temp (the seam that coupled
          # the old call path to `genStore2`). The allocator reserved one address scratch.
          let srcAddr = g.ra.aux[cursorToPosition(g.buf[], a)].scratch[^1]
          g.aggrAddrInto(a, srcAddr, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = true)
          if sz <= g.md.aggrByRefThreshold:
            g.marshalAggrFromAddr(srcAddr, tn, g.md.intArgRegs[intIdx ..< intIdx + words])
            intIdx += words
          else:
            g.movReg(g.md.intArgRegs[intIdx], srcAddr); inc intIdx
          g.unbindTemp(srcAddr)
        else:
          var home = ""                                   # a named stack slot, or "" ⇒ read &global
          var ptrReg = NoReg                              # a by-ref param: pointer to the aggregate in a reg
          if a.kind == Symbol:
            let sloc = g.ra.locationOfSym(symName(a))
            if sloc.kind == NamedStack:
              home = symName(a)                           # a local: its slot is already addressable
            elif sloc.kind == InReg:
              ptrReg = sloc.r                             # a >16B by-ref param: its pointer is already in a reg
            elif g.lookupSym(symName(a)).cat == scGlobal:
              discard                                     # a global: read through &global (home == "")
            else:
              raiseAssert "arkham x64: aggregate symbol arg neither local nor global: " & symName(a)
          else:                                           # oconstr/aconstr: build into a temp
            let pos = cursorToPosition(g.buf[], a)
            home = "aggtmp" & $pos & ".0"
            g.emTypedStackVar(home, tcur)
            g.varType[home] = tn
            g.genStore2(a, namedStackLoc(home, g.exprSlot(a)), pos)
          if sz <= g.md.aggrByRefThreshold:               # by-value: words → GPRs
            let regs = g.md.intArgRegs[intIdx ..< intIdx + words]
            if ptrReg != NoReg: g.marshalAggrFromAddr(ptrReg, tn, regs)
            elif home.len > 0: g.structToRegs(home, tn, regs)
            else: g.globalToRegs(symName(a), tn, regs)
            intIdx += words
          else:                                           # by-reference: &arg → one GPR
            if ptrReg != NoReg: g.movReg(g.md.intArgRegs[intIdx], ptrReg)
            elif home.len > 0: g.emStackAddr(g.md.intArgRegs[intIdx], home)
            else: g.emGlobalAddr(g.md.intArgRegs[intIdx], symName(a))
            inc intIdx
      elif g.isFloatExpr(a):
        g.emitValue2(a)                                   # → its xmm arg register
      else:
        g.emitValue2(a)                                   # → its GPR arg register
        inc intIdx
      for k in intIdx0 ..< intIdx:                        # protect this arg's regs from a later arg's build
        g.liveAccums.incl g.md.intArgRegs[k]; sealedArgs.incl g.md.intArgRegs[k]
    g.ab.tree PrepareX64:
      g.ab.sym tgt.asmName
      if isSyscall: g.emSyscall()
      else: g.ab.keyword CallX64
    g.liveAccums = g.liveAccums - sealedArgs              # the call consumed them; unseal
    if hasResult:
      if resultIsFloat:
        if resLoc.kind == InFReg:
          if resLoc.isTemp: g.bindFTmp(resLoc.f)
          if resLoc.f != FloatRet:
            g.fmovF(resLoc.f, FloatRet, (if resLoc.typ.size == 4: 32 else: 64))
      elif resLoc.kind == InReg:
        # scalar result only — an aggregate-by-value return spans rax:rdx (consumed word-by-word).
        if resLoc.isTemp and resSlot.kind != AMem: g.bindTemp(resLoc.r, resSlot)
        if resLoc.r != RAX: g.movReg(resLoc.r, RAX)

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
  if res.kind == InReg:
    if res.isTemp: g.bindTemp(res.r, res.typ)  # rebind a reused dead-local reg to the result type
    if res.r != resReg: g.movReg(res.r, resReg)

proc produceIntoMem2(g: var CodeGen; c: Cursor; pos: int; dst: Location) =
  ## Totality bridge (the value-core analogue of legacy `spillComputed`): the allocator
  ## spilled this value position to an `(s)` slot (`etmpN.0`) because the register pool
  ## was exhausted. Materialize the value into a transient staging register — the
  ## reserved staging bridge guarantees one is always free — then store it to the slot.
  ## The trick that makes EVERY node kind produce-into-memory through ONE path: override
  ## `locs[pos]` to the staging register and recurse through `emitValue2`, so a leaf,
  ## bin, call, load, cast … each emits into the register exactly as for a normal
  ## register result. `locs[pos]` is restored to the slot before returning so any
  ## consumer (a binop folding a spilled operand, `storeScalar2`) reads the memory form.
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoMem2 slot=" & dst.name
  # The staging reg is NOT sealed across the recursion: `emitBin2` evaluates BOTH
  # operands first and only writes the result reg at the (post-order, sequential)
  # combine, where the recursion binds it (`boundTemps` then protects it). So a deep
  # right-nested spilled chain reuses the SAME bridge register level-by-level — one
  # always-free bridge makes produce-into total at ANY depth. (Sealing it here would
  # reserve one reg per nesting level and exhaust the staging pool on deep chains.)
  let s = g.pickStaging()                # total: the reserved bridge is always pickable
  g.ra.locs[pos] = regLoc(s, dst.typ, isTemp = true)
  g.emitValue2(c)                        # the node now sees an InReg dst → produces into s
  g.ra.locs[pos] = dst                   # restore the slot location for the consumer
  g.emitStoreLoc(dst, s)                 # spill the produced value to its `(s)` slot
  g.giveBack s                           # unbind the staging name

proc followHome(g: var CodeGen; pos: int): Location =
  ## Resolve a Symbol use-site snapshot (`locs[pos]`) to the local's CURRENT home.
  ## A snapshot tagged `homeSym` (see `Location.homeSym`) named the local's register
  ## home when the use was allocated; a later `stealForTmp` may have demoted the local
  ## to its stack slot (e.g. to free the register for an `(at)` stride scratch), moving
  ## the symbol's *def* home but leaving this use-site copy stale. Follow it: if the home
  ## left the snapshot register, return — and re-sync `locs[pos]` to — the current home
  ## (its stack slot, which `reloadMemBase2` then loads into a fresh staging reg ≠ the
  ## scratch). A no-op when the local kept its register, so non-stolen snapshots and plain
  ## temps are unaffected. Replaces the allocator's old `resyncAddrLocs` tree-walk —
  ## a steal is now the single source of truth, resolved lazily at use.
  result = g.ra.locs[pos]
  if result.kind == InReg and result.homeSym.len > 0:
    let cur = g.ra.locationOfSym(result.homeSym)
    if cur.kind != Undef and not (cur.kind == InReg and cur.r == result.r):
      result = cur
      g.ra.locs[pos] = cur

proc emitValue2(g: var CodeGen; c: Cursor) =
  ## Ensure `c`'s value is materialized at its precomputed `locs[pos]`. A leaf whose
  ## location is a register is moved there (the allocator placed it via destination-
  ## passing / a `NeedsReg` reservation); a leaf left as `Imm` / in its own home stays
  ## put (the consumer folds or reads it). A computed node runs its op into its result.
  let pos = cursorToPosition(g.buf[], c)
  let dst = g.ra.locs[pos]
  if dst.kind == InFReg:                                 # a float value → the SIMD path
    g.emitFValue2(c); return
  if dst.kind == NamedStack and dst.isTemp:              # spilled (etmp) result → produce-into
    g.produceIntoMem2(c, pos, dst); return
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
    of OvfC:
      # `(ovf)` reads the hardware overflow flag of the immediately preceding `keepovf`
      # and is valid ONLY as an if/ite condition (handled in `emitCond2`, lowered to
      # `jo`/`jb`). It has no value-position lowering — materializing it into a register
      # here would need a `seto` and, more importantly, would mean a flag-clobbering
      # instruction ran between the keepovf and its read. Reject it loudly.
      raiseAssert "arkham x64n: (ovf) is only valid as an if/ite condition right after keepovf"
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
    g.ensureFAccum(res.f, g.ra.locs[cursorToPosition(g.buf[], rhsC)], bits)
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
  g.ensureFAccum(res.f, g.ra.locs[cursorToPosition(g.buf[], lhsC)], bits)
  let rhsLoc = g.ra.locs[cursorToPosition(g.buf[], rhsC)]
  if rhsLoc.kind == InFReg and not rhsLoc.isTemp:        # in-place float local: fold directly
    g.fbin(op32, op64, res.f, rhsLoc.f, bits)
  elif rhsLoc.kind == NamedStack:                        # spilled rhs (ftmp): produce, then fold
    g.emitFValue2(rhsC)                                  # b → its `(s)(f N)` slot
    let fs = g.pickFStagingSealed("a spilled float operand", avoid = res.f)
    g.emFloatScalarLoad(fs, rhsLoc.name, bits)
    g.fbin(op32, op64, res.f, fs, bits)
    g.sealedF.excl fs
  else:
    g.emitFValue2(rhsC)                                  # b → its SIMD temp
    g.fbin(op32, op64, res.f, rhsLoc.f, bits)
    if rhsLoc.isTemp: g.unbindFTmp(rhsLoc.f)

proc produceIntoFMem2(g: var CodeGen; c: Cursor; pos: int; dst: Location) =
  ## The SIMD twin of `produceIntoMem2`: the allocator spilled this FLOAT value
  ## position to an `(s)(f N)` slot (`eftmpN.0`). Materialize it into a staging xmm
  ## (the reserved float bridge), store it to the slot, and restore `locs[pos]` so a
  ## consumer reads the memory form.
  ## NB unlike the integer twin, the staging xmm IS sealed across the recursion: SSE is
  ## destructive 2-operand, so `emitFBin2` writes the result reg (`res`) with the lhs
  ## BEFORE evaluating the rhs — `res` is live across the rhs subtree and must be held.
  ## So a deep right-nested *non-foldable* float chain reserves one xmm per level and is
  ## bounded by the staging pool (the bridge xmm15 + the 8 arg regs ⇒ depth ≤ 9). That
  ## covers every realistic float expression (real code hits zero float spills; a
  ## balanced tree nests only O(log n)); a pathological deeper chain asserts LOUDLY in
  ## `pickFStaging` (never a silent miscompile). The integer path is unbounded because
  ## `emitBin2` evaluates both operands first and writes the result reg last.
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoFMem2 slot=" & dst.name
  let bits = dst.typ.size * 8
  # the reserved float bridge (xmm15) is tried first
  let fs = g.pickFStagingSealed("a spilled float result (deep float nest > staging pool)")
  g.ra.locs[pos] = fregLoc(fs, dst.typ, isTemp = true)
  g.emitFValue2(c)                       # produces into the staging xmm
  g.ra.locs[pos] = dst
  g.emitStoreFLoc(dst, fs, bits)
  g.unbindFTmp(fs)                       # release the staging name (the recursion bound it)
  g.sealedF.excl fs

proc emitFValue2(g: var CodeGen; c: Cursor) =
  ## Ensure `c`'s FLOAT value is materialized at its precomputed `locs[pos]` (an
  ## xmm register). The SIMD twin of `emitValue2`; mirrors `genIntoF`.
  let pos = cursorToPosition(g.buf[], c)
  let dst = g.ra.locs[pos]
  if dst.kind == NamedStack and dst.isTemp:              # spilled (ftmp) result → produce-into
    g.produceIntoFMem2(c, pos, dst); return
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
          if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
            g.emReg g.ra.aux[patPos].scratch[0]         # 3-operand form: non-SIB stride scratch
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
    else: raiseAssert "arkham x64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emLvalAddr2 kind " & $c.kind

proc reloadMemBase2(g: var CodeGen; pos: int) =
  ## A `deref`/`pat`/`at` pointer base or register index whose local was demoted to
  ## its stack home by a `stealForTmp` arrives here as a `NamedStack`/`Mem` location,
  ## but `[reg]` addressing needs it in a register. Load it into a sealed staging reg,
  ## point its location at that reg for the lval emission, and park the original home
  ## in `savedHomes` so `restoreMemBase2` (via `unbindLvalTemps2`) puts it back — the
  ## local keeps its stack home for its other uses.
  let loc = g.followHome(pos)              # a stolen register-home → its current (stack) home
  if loc.kind notin {NamedStack, Mem}: return
  let s = g.pickStagingSealed("a memory address base/index")
  g.emitLoadLoc(loc, s)
  g.savedHomes[pos] = loc
  g.ra.locs[pos] = regLoc(s, loc.typ)

proc restoreMemBase2(g: var CodeGen; pos: int) =
  ## Undo `reloadMemBase2`: release the staging reg and restore the local's stack home.
  if g.savedHomes.hasKey(pos):
    g.giveBack g.ra.locs[pos].r
    g.ra.locs[pos] = g.savedHomes[pos]
    g.savedHomes.del pos

proc prematAddrVal2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue base/index value `c` into a register for the enclosing
  ## `(mem …)`. `followHome` FIRST re-points a stolen register-home snapshot at its
  ## current (stack) home — so the `emitValue2` below does NOT load the value back into
  ## the snapshot register (which a `stealForTmp` may have handed to the `(at)` stride
  ## scratch); `reloadMemBase2` then brings that stack home into a fresh staging reg ≠
  ## the scratch. Scoped to the lvalue tree (NOT general `emitValue2`), exactly like the
  ## old `resyncAddrLocs`: a plain operand snapshot keeps its reg-promise.
  let pos = cursorToPosition(g.buf[], c)
  discard g.followHome(pos)
  g.emitValue2(c)
  g.reloadMemBase2(pos)

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
        g.prematAddrVal2(cc)                            # the pointer → its register (follow steals)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        # Bind the non-SIB stride scratch FIRST (names a checked temp for `(at … scratch)`).
        # It MUST precede the base/index materialization: a demoted (stolen) base/index is
        # reloaded by `reloadMemBase2` into a staging reg via `pickStagingScratch`, which
        # avoids `boundTemps` — binding the scratch now keeps that reload off the scratch's
        # register (else base/idx staging could land on the scratch and alias it).
        g.bindTemp(g.ra.aux[atPos].scratch[0], AsmSlot(cls: AInt, size: 8, align: 8))
      var cc = c
      cc.into:
        g.prematLval2(cc); skip cc                      # base
        if cc.kind notin {IntLit, UIntLit}:             # register index → its reg
          g.prematAddrVal2(cc)                          # follow steals
        while cc.hasMore: skip cc
    of PatC:
      let patPos = cursorToPosition(g.buf[], c)
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
        # Bind the stride scratch FIRST (same reload-collision guard as AtC).
        g.bindTemp(g.ra.aux[patPos].scratch[0], AsmSlot(cls: AInt, size: 8, align: 8))
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
          let idxPos = cursorToPosition(g.buf[], cc)
          g.restoreMemBase2(idxPos)                      # demoted (stolen) index reload
          let il = g.ra.locs[idxPos]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.unbindTemp(g.ra.aux[atPos].scratch[0])        # the non-SIB stride scratch
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
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
        g.unbindTemp(g.ra.aux[patPos].scratch[0])        # the non-SIB stride scratch
    of BaseobjC:                                        # transparent: release the inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                               # base type, depth
        g.unbindLvalTemps2(cc)                         # the inner lvalue
        while cc.hasMore: skip cc
    else: discard

proc emitMemLoad2(g: var CodeGen; c: Cursor) =
  ## Load the scalar at lvalue `c` into its pre-allocated result register:
  ## `mov res, (mem <addr>)`. A POINTER-typed lvalue binds the result temp to its
  ## precise `(ptr T)` type (the value-core's generic i64 slot would mismatch the
  ## typed field memory, and downstream pointer uses — cmp / store — need it typed).
  let res = g.ra.locs[cursorToPosition(g.buf[], c)]
  assert res.kind == InReg, "arkham x64n: mem-load result " & $res.kind
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    # An array / flexible-array-member lvalue (e.g. a chunk's `data[]`) DECAYS to its
    # address: `lea res, <addr>`, not a value load. `lea` is type-lenient, so a generic
    # slot suffices; a consuming `(pat …)`/`(at …)` casts the base to the element pointer.
    if res.isTemp: g.bindTemp(res.r, ScalarSlot)
    g.prematLval2(c)
    g.ab.tree LeaX64:
      g.emReg res.r
      g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)
    return
  var bindSlot = res.typ
  if isPtrType(cty): bindSlot = g.exprSlot(c)
  if res.isTemp: g.bindTemp(res.r, bindSlot)            # bind first: a global base leas &g
  g.prematLval2(c)                                       #   into res before the (mem …) tree
  g.ab.tree MovX64:
    g.emReg res.r
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)                                  # release embedded base/index temps

proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor) =
  ## `dest op= [<lvalue c>]` — fold a memory-load operand into an ALU op via the
  ## value-core address machinery (prematLval2 / emLvalAddr2 / unbindLvalTemps2).
  ## The mirror of emitMemLoad2 with an ALU op in place of the load `mov`.
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
    g.emitValue2(p)
    let pLoc = g.ra.locs[cursorToPosition(g.buf[], p)]
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
      g.emitValue2(p)
      let pLoc = g.ra.locs[cursorToPosition(g.buf[], p)]
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
    of Tvar:
      if loc.name notin g.tvarNames:
        raiseAssert "arkham x64: address-of a foreign thread-local (module-system TODO): " & loc.name
      g.emGlobalAddr(dest, TlsBlockName)                # &threadvar = FS base + offset (folded)
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

proc emitAddr2(g: var CodeGen; c: Cursor) =
  ## `(addr lvalue)` → a pointer in the result register, via the shared `aggrAddrInto`.
  var res = g.ra.locs[cursorToPosition(g.buf[], c)]
  # A result whose home is a stolen-victim local (demoted to its stack slot) is
  # computed into a transient staging reg and stored back afterwards.
  var addrStaging = NoReg
  let memRes = res
  if res.kind in {NamedStack, Mem}:
    addrStaging = g.pickStagingSealed("an addr result")
    res = regLoc(addrStaging, res.typ)
  else:
    assert res.kind == InReg, "arkham x64n: addr result " & $res.kind
  let aslot = g.exprSlot(c)         # the precise `(ptr T)` result type
  var lv: Cursor
  block:
    var cc = c
    cc.into:
      lv = cc; skip cc
      while cc.hasMore: skip cc
  g.aggrAddrInto(lv, res.r, aslot, doBind = res.isTemp)
  if addrStaging != NoReg:                               # store the pointer to its stack home
    g.emitStoreLoc(memRes, addrStaging)
    g.giveBack addrStaging

proc emitCast2(g: var CodeGen; c: Cursor) =
  ## `(conv|cast Type inner)` over integer/pointer (no float source/target — gated out):
  ## the inner computes into the result register (dest-passing); then re-represent it in
  ## the target's 64-bit register form. A pointer target is a reinterpret (only a narrow
  ## int source gets zero-extended); an integer target widens (sign per conv/source, zero
  ## per cast) or narrows/truncates to the target width.
  let isCast = c.exprKind == CastC
  var tc, targetCur, inner: Cursor
  block:
    var cc = c
    cc.into:
      targetCur = cc                                     # target type AS WRITTEN (nominal)
      tc = resolveType(g.prog, cc); skip cc              # target type (resolved)
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
  # A pointer-involving cast (int↔ptr arithmetic, or a ptr→ptr reinterpret) whose
  # result register is a register-homed var that the inner DEST-PASSES into: the
  # register must carry the INNER's type WHILE the inner is emitted — e.g. the integer
  # arithmetic under an int→ptr reinterpret runs in an int-typed accumulator — then the
  # cast's target type after. Pre-retype the named local to the inner's type here; the
  # materialization below flips it to the target. (A temp result is handled there.)
  if res.kind == InReg and not res.isTemp and
     (isPtrType(tc) or isPtrType(resolveType(g.prog, g.getType(inner)))):
    let nm = g.regLocal.getOrDefault(res.r, "")
    if nm.len > 0:
      var st = g.getType(inner)
      g.rebindLocalAs(nm, res.r, st)
  g.emitValue2(inner)
  let iv = g.ra.locs[cursorToPosition(g.buf[], inner)]
  # A result home that is a stolen-victim local (demoted to its stack slot) is
  # computed into a transient staging reg and stored back afterwards.
  var res2 = res
  var castStaging = NoReg
  if res2.kind in {NamedStack, Mem}:
    castStaging = g.pickStagingSealed("a cast result")
    res2 = regLoc(castStaging, res2.typ)
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  # A cast that involves a POINTER on EITHER side (int↔ptr pointer arithmetic, or a
  # ptr→ptr reinterpret between nominal pointees) is a pure 8-byte reinterpret whose
  # ONLY effect is the register's nifasm type. The result register is retyped to the
  # cast's precise target — a temp via `bindTemp`, a register-homed var via
  # `rebindLocalAs` (found by its current `regLocal` name) — and a reg→reg move of a
  # differently-typed source is reinterpreted with `(cast tc src)`. This keeps nifasm's
  # strict ptr/aptr/nominal-pointee check passing through pointer arithmetic WITHOUT
  # loosening the checker (mirrors the legacy `coerceThroughCast`).
  let kindChange = ptrTarget or srcPtr
  template retypeCastRes() =
    if res2.isTemp:
      g.bindTemp(res2.r, (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot))
    else:
      let nm = g.regLocal.getOrDefault(res2.r, "")       # the register's named local
      if nm.len > 0: g.rebindLocalAs(nm, res2.r, targetCur)
  if iv.kind in {NamedStack, Mem}:                        # demoted (stolen) operand → result reg
    if kindChange: retypeCastRes()
    elif res2.isTemp: g.bindTemp(res2.r, res2.typ)
    g.emitLoadLoc(iv, res2.r)
  else:
    if iv.kind == InReg and iv.r != res2.r:
      if kindChange:
        retypeCastRes()
        var tcur = targetCur
        g.ab.tree MovX64:
          g.emReg res2.r
          g.ab.tree CastX:
            g.genTypeBody(tcur)
            g.emReg iv.r
      else:
        if res2.isTemp: g.bindTemp(res2.r, res2.typ)
        g.movReg(res2.r, iv.r)
    elif iv.kind == InReg:                                # iv.r == res2.r: in-place identity
      if kindChange: retypeCastRes()
    elif iv.kind == Imm:
      if kindChange: retypeCastRes()
      elif res2.isTemp: g.bindTemp(res2.r, res2.typ)
      g.movImm(res2.r, iv.ival)
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if kindChange:
    # int↔ptr / ptr↔ptr is a pure reinterpret; a narrow int source going into a pointer
    # was already zero-extended into the register by its own emission. No extend.
    if ptrTarget and not srcPtr and srcW < 64: g.extendTo(res2.r, srcW, signed = false)
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW:
      g.extendTo(res2.r, srcW, signed = (not isCast) and srcSigned)   # widen
    else:
      g.extendTo(res2.r, targetW, signed = isSignedType(tc))          # narrow / equal
  if castStaging != NoReg:                                # store the result to its stack home
    g.emitStoreLoc(res, castStaging)
    g.giveBack castStaging

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

proc copyAggr(g: var CodeGen; dst, src: Reg; size: int; tmp: Reg) =
  ## copy `size` bytes from `[src]` to `[dst]` through the bound scratch `tmp` — 8-byte
  ## words for the aligned bulk, then a sized byte tail. Layout-agnostic and byte-accurate,
  ## so it is TOTAL for any aggregate regardless of field packing; both ends are just an address
  ## in a register. nifasm's sized mem↔reg move extends a byte load / truncates a byte
  ## store, so `tmp` stays a plain `(u 64)`. (`dst`, `src`, `tmp` are bound by the caller.)
  let words = size div 8
  for i in 0 ..< words:
    g.ab.tree MovX64: (g.emReg tmp; g.emWordThroughPtr(src, i))
    g.ab.tree MovX64: (g.emWordThroughPtr(dst, i); g.emReg tmp)
  for b in 0 ..< (size - words * 8):                     # sub-word tail, byte by byte
    let off = words * 8 + b
    g.ab.tree MovX64: (g.emReg tmp; g.emByteAtImm(src, off))
    g.ab.tree MovX64: (g.emByteAtImm(dst, off); g.emReg tmp)

proc copyStructThroughPtr2(g: var CodeGen; srcVar, typeName: string; ptrReg, tmp: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at, through scratch `tmp` (the >16B
  ## aggregate hidden-result-pointer return). Leas the source's address into one staging
  ## register and funnels through the one `copyAggr`.
  let sp = g.pickStagingSealed("a struct-through-ptr source pointer")
  g.emStackAddr(sp, srcVar)
  g.bindTemp(tmp, AsmSlot(cls: AUInt, size: 8, align: 8))
  g.copyAggr(ptrReg, sp, aggrByteSize(g.prog, typeName), tmp)
  g.unbindTemp(tmp)
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
  ## scratch `tmp`. Leas the source's address into one staging register and funnels
  ## through the one `copyAggr` (word bulk + byte tail — any size, layout-agnostic).
  let srcPtr = g.pickStagingSealed("a flat-copy source pointer")
  g.emStackAddr(srcPtr, srcVar)
  g.bindTemp(tmp, AsmSlot(cls: AUInt, size: 8, align: 8))
  g.copyAggr(dstPtr, srcPtr, sizeBytes, tmp)
  g.unbindTemp(tmp)
  g.giveBack srcPtr

proc genNestedAggrField(g: var CodeGen; valC, fty: Cursor; fieldPtr: Reg) =
  ## Materialize an aggregate field value `valC` (an inline `(oconstr/aconstr …)`, an
  ## aggregate symbol, or a memory lvalue) — of declared field type `fty` — into the
  ## sub-aggregate at `[fieldPtr]`: build/copy it into a synthetic temp through the
  ## general `genStore2` (which recurses for deeper nesting), then copy that temp
  ## through the field pointer.
  if fty.kind != Symbol:
    raiseAssert "arkham x64n: nested aggregate field of non-nominal type"
  let ntn = symName(fty)
  let pos = cursorToPosition(g.buf[], valC)
  let tmpName = "nctmp" & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, g.exprSlot(valC)), pos)
  let scratch = g.pickStagingSealed("a nested-aggregate-field copy word")
  g.flatCopyToPtr(tmpName, aggrByteSize(g.prog, ntn), fieldPtr, scratch)
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
    if loc.kind == InReg and loc.isTemp and loc.r notin g.boundTemps and
       g.ra.locationOfSym(symName(c)).kind == Undef:
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
  ## lvalue subtree). nifasm sizes the access from the field's declared type.
  if dst.baseReg != NoReg:      g.emPtrFieldMem(dst.baseReg, dst.aggrType, dst.field)
  elif dst.baseName.len > 0:    g.emAggrFieldMem(dst.baseName, dst.field)
  else:                         g.emLvalFieldMem(dst.baseLval, dst.field)

proc emFieldAddr(g: var CodeGen; dst: Location; into: Reg) =
  ## `&(base.field)` → `into`: just `lea` over the field's own memory operand, so the
  ## three base forms need no special handling. The recursion base for a nested
  ## aggregate field.
  g.ab.tree LeaX64: (g.emReg into; g.emFieldOperand(dst))

proc fieldTypeByName(g: var CodeGen; typeName, field: string): Cursor =
  ## The declared (nominal) type cursor of `typeName.field` — resolves the object body
  ## from the type's decl like `fieldSlotByName`.
  var d = lookupType(g.prog, typeName)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = fieldType(g.prog, d, field)
    while d.hasMore: skip d

proc genFieldStore2(g: var CodeGen; dst: Location; valC: Cursor) =
  ## Store value `valC` into the aggregate-field destination `dst` — the `Field` case
  ## of `genStore2`, and the ONE per-field store behind `genConstr2`. A scalar/float/
  ## pointer field emits its value and moves it into the field operand (a POINTER field
  ## reinterprets a scalar register via `(cast (ptr …) reg)` for nifasm's strict
  ## typing); a nested aggregate field recurses (`genNestedAggrField` builds/copies the
  ## value into the field's address). No per-field special-casing at the call site.
  if dst.typ.kind == AMem:                              # nested aggregate field
    let ftyCur = g.fieldTypeByName(dst.aggrType, dst.field)
    let fptr = g.pickStagingSealed("a nested-aggregate-field pointer")
    g.emFieldAddr(dst, fptr)
    g.genNestedAggrField(valC, ftyCur, fptr)
    g.giveBack fptr
  else:                                                 # scalar / float / pointer field
    g.emitValue2(valC)
    let v = g.ra.locs[cursorToPosition(g.buf[], valC)]
    if v.kind == InFReg:                                # float field
      let bits = if v.typ.size == 4: 32 else: 64
      g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
        g.emFieldOperand(dst)
        g.emFReg v.f
      if v.isTemp: g.unbindFTmp(v.f)
    else:
      var fty = resolveType(g.prog, g.fieldTypeByName(dst.aggrType, dst.field))
      g.ab.tree MovX64:
        g.emFieldOperand(dst)
        case v.kind
        of Imm: g.ab.intLit v.ival
        of InReg:
          if isPtrType(fty):
            g.ab.tree CastX:
              g.genTypeBody(fty)
              g.emReg v.r
          else:
            g.emReg v.r
        else: raiseAssert "arkham x64n: constr field rhs " & $v.kind
      if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)

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
        else: raiseAssert "arkham x64n: bad oconstr base " & $base.kind
      g.genStore2(valC, fdst, cursorToPosition(g.buf[], valC))
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
          let eptr = g.pickStagingSealed("an aconstr aggregate-element pointer")
          g.ab.tree LeaX64: (g.emReg eptr; destOp(i))   # &element[i]
          g.genNestedAggrField(valC, elemTyRaw, eptr)
          g.giveBack eptr
          inc i
          skip cc
          continue
        g.emitValue2(valC)
        let v = g.ra.locs[cursorToPosition(g.buf[], valC)]
        if v.kind == InFReg:                            # float element
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            destOp(i)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          var etc = et
          g.ab.tree MovX64:
            destOp(i)
            if etIsPtr:
              g.ab.tree CastX: (g.genTypeBody(etc); g.emReg v.r)
            else:
              g.emReg v.r
          if v.isTemp: g.unbindTemp(v.r)
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
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)), pos)  # build derived (no held temp)
    let scratch = g.pickStagingSealed("a baseobj prefix copy")
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
        g.sealedF.excl fs
      else: raiseAssert "arkham x64n: float scalar store rhs " & $v.kind
    else:
      case v.kind
      of InReg:
        g.emitStoreLoc(dst, v.r)
        if v.isTemp: g.unbindTemp(v.r)
      of NamedStack, Mem:
        let s = g.pickStagingSealed("a scalar store")
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
  of Glob: g.emGlobalAddr(dest, loc.name)
  of Mem: g.aggrAddrInto(loc.cur, dest, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
  else: raiseAssert "arkham x64n: aggrAddrLoc of " & $loc.kind

proc isAggrCopySrc(c: Cursor): bool =
  ## An aggregate-valued source that is COPIED (not produced): a symbol or a memory lvalue.
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo(g: var CodeGen; dst: Location): (bool, int) =
  ## (is `dst` an aggregate location?, its byte size). Tvar aggregates are unsupported.
  case dst.kind
  of NamedStack, Glob: (dst.typ.kind == AMem, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc genAggrCopyStore(g: var CodeGen; rhs: Cursor; dst: Location; size, auxPos: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce BOTH sides to
  ## an address in a register (`aggrAddrLoc`/`aggrAddrInto` — the one `gen_addr`), then
  ## `copyAggr`. ONE path for every (destination form × source form); the allocator
  ## reserved `[dstAddr, srcAddr]`. The per-field transfer register is the staging bridge
  ## (R11), picked here — both addresses are already in `a[0]`/`a[1]`, so the bridge is
  ## free — sparing a pool GPR so the copy fits under high register pressure.
  let a = g.ra.aux[auxPos].scratch
  g.bindTemp(a[0], ScalarSlot); g.aggrAddrLoc(dst, a[0])         # &dst
  g.bindTemp(a[1], ScalarSlot)
  g.aggrAddrInto(rhs, a[1], AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)  # &rhs
  let tmp = g.pickStagingSealed("an aggregate-copy transfer register")
  g.bindTemp(tmp, AsmSlot(cls: AUInt, size: 8, align: 8))
  g.copyAggr(a[0], a[1], size, tmp)
  g.giveBack tmp                                                 # unbinds + unseals the bridge
  g.unbindTemp(a[1]); g.unbindTemp(a[0])

proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location; auxPos: int) =
  ## The general destination-passing store of the value core. An aggregate COPY (symbol /
  ## lvalue source) goes through the ONE `genAggrCopyStore` regardless of destination form;
  ## constructors/calls/baseobj PRODUCE into the destination per-form; a scalar/float
  ## destination goes through `storeScalar2`.
  let (dstAggr, aggrSize) = g.dstAggrInfo(dst)
  if dstAggr and isAggrCopySrc(rhs):                     # the ONE whole-aggregate copy path
    g.genAggrCopyStore(rhs, dst, aggrSize, auxPos)
    return
  if rhs.kind == TagLit and rhs.exprKind in {ConvC, CastC} and
     g.exprSlot(rhs).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (`Path(s)` for
    # `Path = distinct string`) is byte-transparent — store its underlying operand into
    # the same destination (allocator twin in `allocStore`).
    var inner = rhs
    inner.into:
      skip inner                                         # the target type
      g.genStore2(inner, dst, auxPos)                    # the operand → same dest
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
        g.emitCall2(rhs)                                 # the callee writes through rdi
      else:
        g.emitCall2(rhs)                                 # ≤16B result in rax:rdx
        g.regsToStruct(dstVar, tn, x64RetRegs)
    elif rhs.kind == TagLit and rhs.exprKind == BaseobjC:
      g.genBaseobj2(rhs, dst)                   # object→base slice
    else: raiseAssert "arkham x64n: aggregate store rhs " & $rhs.exprKind
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AFloat:  # float global / threadvar
    g.emitValue2(rhs)                                    # rhs → an xmm
    let fv = g.ra.locs[cursorToPosition(g.buf[], rhs)]
    assert fv.kind == InFReg, "arkham x64n: float global store rhs " & $fv.kind
    let gbits = if dst.typ.size == 4: 32 else: 64
    let op = if gbits == 32: MovssX64 else: MovsdX64
    case dst.kind
    of Glob:                                             # &g into the address temp, then movss/movsd
      let addrT = g.ra.aux[auxPos].scratch[0]
      var pSlot = ScalarSlot                             # type it `(ptr (f N))` (nifasm is strict)
      if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
      g.bindTemp(addrT, pSlot)
      g.emGlobalAddr(addrT, dst.name)
      g.ab.tree op:
        g.ab.tree MemX: g.emReg addrT
        g.emFReg fv.f
      g.unbindTemp(addrT)
    else: raiseAssert "arkham x64n: float threadvar store not supported"
    if fv.isTemp: g.unbindFTmp(fv.f)
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AMem:
    # Aggregate store into a GLOBAL: address it into a pointer scratch and build/copy
    # the aggregate THROUGH that pointer — an `oconstr` field-by-field (InReg base), a
    # symbol by whole-aggregate copy, a call by its ABI (>16B → &g as the hidden result
    # pointer in rdi; ≤16B → the result regs stored through &g). The allocator reserves
    # the &g address temp at `aux[auxPos].scratch[0]` (+ a copy temp at `[1]`).
    assert dst.kind == Glob, "arkham x64n: aggregate threadvar store not supported"
    if rhs.kind == TagLit and rhs.exprKind == CallC and
       dst.typ.size > g.md.aggrByRefThreshold:
      g.emGlobalAddr(RDI, dst.name)                      # >16B: &g is the hidden result ptr
      g.emitCall2(rhs)                                   # callee writes through rdi
    else:
      let addrT = g.ra.aux[auxPos].scratch[0]
      g.bindTemp(addrT, ScalarSlot)
      if rhs.kind == TagLit and rhs.exprKind == OconstrC:
        g.emGlobalAddr(addrT, dst.name)
        g.constrFieldStores(rhs, regLoc(addrT, dst.typ))  # build field-by-field through &g
      elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
        g.emGlobalAddr(addrT, dst.name)
        var atc = rhs; inc atc                            # the array type
        let elemTy = innerType(g.prog, resolveType(g.prog, atc))
        template dest(i) = g.emPtrElemMem(addrT, elemTy, i)  # element i through &g
        g.aconstrElemStores(rhs, dest)
      elif rhs.kind == TagLit and rhs.exprKind == CallC:  # ≤16B result in rax:rdx
        g.emitCall2(rhs)
        g.emGlobalAddr(addrT, dst.name)                   # lea AFTER the call (rax:rdx kept)
        g.regsToStructThroughPtr(addrT, symName(g.getType(rhs)), x64RetRegs)
      else: raiseAssert "arkham x64n: aggregate global store rhs " & $rhs.exprKind
      g.unbindTemp(addrT)
  elif dst.kind in {Glob, Tvar}:                         # scalar/pointer global / threadvar
    g.emitValue2(rhs)
    var v = g.ra.locs[cursorToPosition(g.buf[], rhs)]
    var glbStaging = NoReg
    if v.kind in {NamedStack, Mem}:                      # demoted (stolen) local rhs → reg
      glbStaging = g.pickStagingSealed("a global store rhs")
      g.emitLoadLoc(v, glbStaging)
      v = regLoc(glbStaging, v.typ)
    assert v.kind == InReg, "arkham x64n: global store rhs " & $v.kind
    case dst.kind
    of Tvar:                                             # nifasm resolves FS:[off]
      g.ab.tree MovX64:
        g.ab.sym dst.name
        g.emReg v.r
    of Glob:                                             # &g into the address temp, then store
      let addrT = g.ra.aux[auxPos].scratch[0]
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries the
      # global's PRECISE type — a typed-pointer value into a pointer global would
      # otherwise mismatch a generic mem (nifasm is strict; see `scalarMemMov`).
      var pSlot = ScalarSlot
      if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
      g.bindTemp(addrT, pSlot)
      g.emGlobalAddr(addrT, dst.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg addrT
        g.emReg v.r
      g.unbindTemp(addrT)
    else: discard
    if glbStaging != NoReg: g.giveBack glbStaging
    elif v.isTemp: g.unbindTemp(v.r)
  elif dst.kind == Mem:                                  # store through a complex lvalue (dot/deref/at)
    # (A whole-aggregate copy through an `Mem` lvalue went through `genAggrCopyStore` at
    # the top; here the rhs PRODUCES into the address — a constructor or a scalar/float.)
    let lhs = dst.cur
    # A global aggregate base reserved an address scratch (aux); bind it so prematLval2's
    # `lea scratch, &g` emits a checked name. The allocator held it across the rhs.
    let globScratch = if g.ra.aux.hasKey(auxPos): g.ra.aux[auxPos].scratch[0] else: NoReg
    if globScratch != NoReg: g.bindTemp(globScratch, AsmSlot(cls: AInt, size: 8, align: 8))
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.genConstrIntoLval2(rhs, lhs)                      # build field-by-field into the address
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.genAconstrIntoLval2(rhs, lhs)                     # build array element-by-element
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
      g.emitValue2(rhs)                                   # rhs value FIRST
      var v = g.ra.locs[cursorToPosition(g.buf[], rhs)]
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
          g.sealedF.excl fs
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
          rhsStaging = g.pickStagingSealed("a memory store rhs")
          g.emitLoadLoc(v, rhsStaging)
          v = regLoc(rhsStaging, v.typ)
        g.prematLval2(lhs)                                 # base regs AFTER the rhs is secured
        g.ab.tree MovX64:
          g.ab.tree MemX: g.emLvalAddr2(lhs)
          case v.kind
          of Imm: g.ab.intLit v.ival
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
    if globScratch != NoReg: g.unbindTemp(globScratch)
  elif dst.kind == Field:                                # a field within an aggregate
    g.genFieldStore2(dst, rhs)
  else:                                                  # scalar / float home (reg or `(s)` slot)
    # A COMPUTED rhs whose result the allocator destination-passed into a register that is
    # NOT this store's own home (e.g. the var was register-allocated but then EVICTED to the
    # stack, so its initializer's value still lands in the old register as a transient). That
    # register may carry a stale binding from an earlier, now-dead register-local: the emitter
    # only kills such a binding when ANOTHER register-homed local reuses the register (via
    # `emRegLocalVar`), never when a value temp does. Kill it here so the transient emits as a
    # clean raw register, not under the dead local's (wrongly-typed) name. A Symbol rhs reading
    # the live bound local itself is excluded.
    let vPre = g.ra.locs[cursorToPosition(g.buf[], rhs)]
    if vPre.kind == InReg and not vPre.isTemp and
       not (dst.kind == InReg and dst.r == vPre.r) and
       g.regLocal.hasKey(vPre.r) and
       not (rhs.kind == Symbol and symName(rhs) == g.regLocal[vPre.r]):
      g.ab.tree KillX64: g.ab.sym g.regLocal[vPre.r]
      g.regLocal.del vPre.r
      g.boundTemps.excl vPre.r
    g.emitValue2(rhs)
    let v = g.ra.locs[cursorToPosition(g.buf[], rhs)]
    g.storeScalar2(dst, v)

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
    if hasVal: g.genStore2(cc, loc, declPos)            # the one general store path
    while cc.hasMore: skip cc

proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## Emit a branch test, jumping to `toLabel` when the condition holds (`whenTrue`):
  ## a short-circuit `and`/`or`/`not` tree, a `cmp`/`jcc` for a comparison `(op a b)`,
  ## or `cmp v, 0` for a plain boolean value. Operand locations were pre-assigned by
  ## `allocCond`; the short-circuit forms mirror the legacy `emitCondJump`.
  if c.kind == TagLit and c.exprKind == OvfC:
    # The overflow flag of the immediately preceding `keepovf` (read straight from the
    # hardware flag — no operand, no register). A signed op overflows iff OF is set
    # (`jo`); an unsigned op overflows iff CF is set (`jb`). `g.ovfSigned` was recorded
    # by the keepovf. Nothing flag-clobbering may sit between (the spec guarantees it).
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
      # compare (Leng assumes non-NaN), so the jcc tag is the unsigned one. Both
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
    var aLoc = g.ra.locs[cursorToPosition(g.buf[], aC)]
    var bLoc = g.ra.locs[cursorToPosition(g.buf[], bC)]
    # x86 `cmp r/m64, imm` only takes a *sign-extended imm32*; a wider immediate (e.g.
    # the overflow-saturation `int64.max`/`low`) must be materialized into a register
    # first (movabs), since nifasm has no scratch pool of its own.
    var bigImmStaging = NoReg
    if bLoc.kind == Imm and (bLoc.ival < low(int32).int64 or bLoc.ival > high(int32).int64):
      bigImmStaging = g.pickStagingSealed("a cmp imm64")
      g.movImm(bigImmStaging, bLoc.ival)
      bLoc = regLoc(bigImmStaging, bLoc.typ)
    var cmpStaging = NoReg
    if aLoc.kind == NamedStack:
      # demoted (stolen) local as cmp lhs: load it into a staging reg so the rhs may
      # itself be memory (`cmp [a],[b]` is illegal); the InReg-lhs path then applies.
      cmpStaging = g.pickStagingSealed("a cmp lhs")
      g.emitLoadLoc(aLoc, cmpStaging)
      aLoc = regLoc(cmpStaging, aLoc.typ)
    if aLoc.kind == Mem:                                 # left folded: cmp [addr], rreg/imm
      var aBound: seq[Reg] = @[]
      g.bindLvalGlobalBases(aC, aBound)                  # bind a global base reg before the lea
      g.prematLval2(aC)                                   # materialize the lhs base first
      var rhsStaging = NoReg
      if bLoc.kind == NamedStack:
        # x86 forbids `cmp [mem], [mem]`: a spilled (demoted) rhs local must be loaded
        # into a register. Pick AFTER prematLval2 so the staging reg avoids the now-bound
        # lhs base pointer.
        rhsStaging = g.pickStagingSealed("a cmp(memlhs) rhs")
        g.emitLoadLoc(bLoc, rhsStaging)
      g.ab.tree CmpX64:
        g.ab.tree MemX: g.emLvalAddr2(aC)
        case bLoc.kind
        of Imm: g.ab.intLit bLoc.ival
        of InReg: g.emReg bLoc.r
        of NamedStack: g.emReg rhsStaging
        else: raiseAssert "arkham x64n: cmp(memlhs) rhs " & $bLoc.kind
      if rhsStaging != NoReg: g.giveBack rhsStaging
      g.unbindLvalTemps2(aC)
      for r in aBound: g.unbindTemp(r)
    else:
      assert aLoc.kind == InReg, "arkham x64n: cmp lhs " & $aLoc.kind
      case bLoc.kind
      of Imm:
        g.ab.tree CmpX64: (g.emReg aLoc.r; g.ab.intLit bLoc.ival)
      of InReg:
        g.ab.tree CmpX64: (g.emReg aLoc.r; g.emReg bLoc.r)
      of NamedStack:                                     # spilled scalar slot: cmp reg, [rsp+slot]
        g.ab.tree CmpX64:
          g.emReg aLoc.r
          g.emStackMem(bLoc.name)
      of Mem:                                            # folded memory load: cmp reg, [addr]
        var bBound: seq[Reg] = @[]
        g.bindLvalGlobalBases(bC, bBound)                # bind a global base reg before the lea
        g.prematLval2(bC)
        g.ab.tree CmpX64:
          g.emReg aLoc.r
          g.ab.tree MemX: g.emLvalAddr2(bC)
        g.unbindLvalTemps2(bC)
        for r in bBound: g.unbindTemp(r)
      else: raiseAssert "arkham x64n: cmp rhs " & $bLoc.kind
    g.emJcc(tag, toLabel)
    if bigImmStaging != NoReg: g.giveBack bigImmStaging
    elif bLoc.kind == InReg and bLoc.isTemp: g.unbindTemp(bLoc.r)
    if cmpStaging != NoReg: g.giveBack cmpStaging
    elif aLoc.kind == InReg and aLoc.isTemp: g.unbindTemp(aLoc.r)
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
  of VarS, ConstS: g.genVarDecl2(c)    # a local const = an immutable var with a literal init
  of CallS: g.emitCall2(c)
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
        if dst.kind == Undef:                               # module-level global / threadvar
          var lc = lhsCur
          dst = g.asLoc(lc)                                 # Glob/Tvar with precise type
        g.genStore2(cc, dst, asgnPos)                       # the one general store path
      else:
        # A memory store through a complex lvalue (dot/deref/at).
        let lhsCur = cc
        var rhsCur = cc; skip rhsCur                        # past the lhs → the rhs value
        g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot), asgnPos)   # the one general store path
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
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)), pos)
          if g.retIndirect:                                # >16B: copy through the hidden ptr
            let tmp = g.ra.aux[cursorToPosition(g.buf[], cc)].scratch[0]
            g.copyStructThroughPtr2(srcName, g.retAggrName, g.indirectReg, tmp)
            g.movReg(RAX, g.indirectReg)                   # SysV: return the buffer pointer in rax
          else:
            g.structToRegs(srcName, g.retAggrName, x64RetRegs)  # ≤16B → rax:rdx
        elif hasVal:                                       # scalar / float result → ret reg
          let retPos = cursorToPosition(g.buf[], cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(FloatRet, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)), retPos)
          else:
            g.genStore2(cc, regLoc(g.md.intRetReg, ScalarSlot), retPos)
        # The epilogue (framePop + ret) is emitted ONCE at the proc tail by
        # emitProcBody2; a `ret` that is NOT the tail must jump there rather than fall
        # through into the following statements (e.g. a mid-proc `if cond: return x`).
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
        if dst.kind == Undef:
          var lc = lhsCur
          dst = g.asLoc(lc)
        g.genStore2(opCur, dst, kPos)
      else:
        let lhsCur = cc; skip cc
        g.genStore2(opCur, memLoc(lhsCur, ScalarSlot), kPos)
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
      if info.isEntry and g.hasGlobalInits:              # run runtime global inits at startup
        g.ab.tree PrepareX64:
          g.ab.sym g.globalInitSym
          g.ab.keyword CallX64
      # Declare the totality spill slots the allocator synthesized (`etmp`/`ftmp`):
      # a value position the register pool couldn't hold is produced into its slot
      # via a staging register (`produceIntoMem2`/`produceIntoFMem2`). A pointer slot
      # keeps its precise `(ptr T)` type so a later deref/cmp through it type-checks;
      # an integer slot is the generic `(s)(i 64)` (sized mem↔reg moves truncate/extend).
      for st in g.ra.spillTemps:
        if st.isFloat:
          g.emFloatStackVar(st.name, st.typ.size * 8)
        elif not cursorIsNil(st.typ.typ) and isPtrType(resolveType(g.prog, st.typ.typ)):
          g.emTypedStackVar(st.name, st.typ.typ)
        else:
          g.emScalarStackVar(st.name)
      g.retLabel2 = g.freshLabel()                       # shared epilogue for mid-proc `ret`
      g.retLabelUsed2 = false
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c                    # name, params, ret, pragmas
        if c.stmtKind == StmtsS: g.genStmt2(c)
        while c.hasMore: skip c
      g.exitScope()
      if g.retLabelUsed2: g.emLab(g.retLabel2)           # a non-tail `ret` lands here
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

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. Every per-proc
# table (regLocal/boundTemps + the ra.locs snapshot) must be reset here or
# RegisterBindingsMatchLoc breaks.
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
  # The pure-emit path is the ONLY path: every proc is allocated with
  # `allocExprs=true` and emitted by `emitProcBody2`. The legacy reactive emitter
  # has been deleted entirely.
  var atScratch = initHashSet[int]()
  g.collectAtScratch(info.decl, atScratch)   # global-rooted non-SIB `(at)` strides
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, x64Machine, g.typeCtx, preseal,
                      allocExprs = true, atScratch = atScratch)
  when defined(arkhamTracePath):
    stderr.writeLine "[arkham] " & info.asmName & ": NEW"
  when defined(arkhamDumpLocs):
    block:
      stderr.writeLine "=== allocValue locs ==="
      for pos in 0 ..< g.ra.locs.len:
        let l = g.ra.locs[pos]
        if l.kind == Undef: continue
        var s = "  pos " & $pos & " : " & $l.kind
        case l.kind
        of InReg: s.add " r=" & $l.r
        of Imm: s.add " imm=" & $l.ival
        of NamedStack, Glob, Tvar: s.add " " & l.name
        else: discard
        if g.ra.aux.hasKey(pos): s.add "   [foldB=" & $g.ra.aux[pos].foldB & "]"
        stderr.writeLine s
  if g.retIndirect:
    g.indirectReg = RBX
    g.ra.usedCallee.incl RBX                   # saved/restored like any callee reg
  # The entry injects a `call` to the synthetic global-init proc, so it makes a call
  # even when its own body does not — keep rsp 16-aligned for that call.
  g.computeFrameX64(info.isEntry, an.hasCall or (info.isEntry and g.hasGlobalInits))
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  # Pure-emit path: the allocator already assigned every value position; emit once.
  g.ab.planning = false
  g.regLocal.clear(); g.aliasToDecl.clear(); g.boundTemps = {}; g.scopeLocals = @[]
  g.fregLocal.clear(); g.boundFTmps = {}; g.scopeFLocals = @[]; g.savedHomes.clear()
  g.tmpBindCount = 0; g.ftmpBindCount = 0
  when defined(arkhamDbgProc):
    block:
      var pc = info.decl; inc pc
      stderr.writeLine "DBG emit proc " & symName(pc)
  g.emitProcBody2(info, declarative)

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
