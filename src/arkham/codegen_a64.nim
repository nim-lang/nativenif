#
#           Arkham — native AArch64 code generator for NIFC
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3: code generation. Walks a NIFC module, runs the analyser + register
## allocator per proc, and emits typed AArch64 / Darwin asm-NIF that `nifasm`
## type-checks, assembles and links.
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

import std / [assertions, tables, sets, strformat]
import nifcore, nifcdecl
import slots, machine, analyser, register_allocator, programs
import asmbuf
import codegen_common

const DarwinLibSystem = "/usr/lib/libSystem.B.dylib"

# When the backend targets Linux (`g.a64Linux`), an `importc`'d libc function
# recognised as a syscall (see `programs.collect` / `LinuxSyscalls`) is emitted as
# a `(syproc …)` and invoked inline via a `(svc 0)` marker (number in x8, args
# x0–x5, result x0) instead of a Darwin dynamic `extcall`, so nifasm's static ELF
# backend serves it without a dynamic linker. `LinuxA64ExitNr` and the table live
# in `programs`; AArch64 uses the asm-generic unistd numbers (write=64 not 1).

# The `CodeGen` state object and the NIFC type/lvalue analysis live in
# `codegen_common`; this module is the AArch64 instruction-selection backend.

# ── low-level emit helpers ──────────────────────────────────────────────────

let ScalarSlot = AsmSlot(kind: AInt, size: 8, align: 8)
  ## Placeholder slot for a register/immediate dont-care result: no consumer of an
  ## `InReg`/`Imm` value reads `.typ` (the old `Val` carried no type). As a scratch
  ## binding type it carries no cursor, so `bindTemp` falls back to `(i 64)`. A `let`
  ## (not `const`) because `AsmSlot` now holds a `Cursor`, not a compile-time value.

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot)
proc unbindTemp(g: var CodeGen; r: Reg)
proc stealReg(g: var CodeGen; logIdx: int): Reg
proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg

# Order in which a codegen-time steal looks for a victim register-local: prefer
# the volatile temp pool (x9–x15 — call-free locals the allocator put there once
# the callee-saved pool was full, the common case), then callee-saved (x19–x28).
# Fixed order ⇒ the plan and emit passes pick the same victim deterministically.
const StealOrder = [R9, R10, R11, R12, R13, R14, R15,
                    R19, R20, R21, R22, R23, R24, R25, R26, R27, R28]

proc emReg(g: var CodeGen; r: Reg) {.inline.} =
  ## A value GPR operand: a register currently hosting a named local / param /
  ## `rebind`-bound scratch → its checked name (which nifasm type-checks and resolves
  ## back to the register); otherwise the raw `(xN)` tag.
  if g.regLocal.hasKey(r): g.ab.sym g.regLocal[r]
  else:
    # The volatile scratch pool (x9–x15) is the only register class the allocator
    # hands out for arbitrary computed values, and every such hand-out is `bindTemp`'d
    # to a checked name (see `tryBorrowTmp`), so a *raw* pool register reaching here
    # means an unbound scratch slipped past the binder — the silent-clobber hole this
    # work closes. Every OTHER register has an irreducible structural raw use and is
    # allowed: x0–x7 are arg/return + syscall registers, x8 the indirect result, x16/
    # x17 assembler veneers, x19–x28 callee-saved param/local homes (saved raw by
    # stp/ldp), fp/lr/sp the frame.
    assert r notin g.md.intTempRegs,
      "arkham a64: unbound scratch-pool register reached emReg: " & regName(r)
    g.ab.reg r

proc emOp(g: CodeGen; r: Reg): string =
  ## The asm-NIF operand spelling of register `r` for a `splice`d text fragment — the
  ## text-path counterpart of `emReg` (`emReg` can't be used because `splice` consumes
  ## a string): a bound register by its checked name (no parens), an unbound register
  ## as the raw `(xN)` tag. Used by the inline-asm lowerings (extend, atomics) whose
  ## operands may be `rebind`-bound scratch or register-locals.
  if g.regLocal.hasKey(r): g.regLocal[r]
  else: "(" & regName(r) & ")"

proc movImm(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovA64: g.emReg d; g.ab.intLit v

proc movReg(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovA64: g.emReg d; g.emReg s

proc binReg(g: var CodeGen; op: A64Inst; d, s: Reg) =
  g.ab.tree op: g.emReg d; g.emReg s

proc binImm(g: var CodeGen; op: A64Inst; d: Reg; v: int64) =
  g.ab.tree op: g.emReg d; g.ab.intLit v

proc emAdr(g: var CodeGen; d: Reg; sym: string) =
  g.ab.tree AdrA64: g.emReg d; g.ab.sym sym

proc emLdaxr(g: var CodeGen; rt, rn: Reg) =        # rt ← exclusive-acquire [rn]
  g.ab.tree LdaxrA64: g.emReg rt; g.emReg rn
proc emStlxr(g: var CodeGen; rs, rt, rn: Reg) =    # store-release-exclusive rt→[rn]; rs←status
  g.ab.tree StlxrA64: g.emReg rs; g.emReg rt; g.emReg rn
proc emLdar(g: var CodeGen; rt, rn: Reg) =         # rt ← acquire [rn]
  g.ab.tree LdarA64: g.emReg rt; g.emReg rn
proc emStlr(g: var CodeGen; rt, rn: Reg) =         # release store rt→[rn]
  g.ab.tree StlrA64: g.emReg rt; g.emReg rn
proc emLdrb(g: var CodeGen; rt, base, idx: Reg) =  # rt ← zero-extended byte [base+idx]
  g.ab.tree LdrbA64: g.emReg rt; g.emReg base; g.emReg idx
proc emStrb(g: var CodeGen; rt, base, idx: Reg) =  # store low byte of rt → [base+idx]
  g.ab.tree StrbA64: g.emReg rt; g.emReg base; g.emReg idx

proc genTlvAddr(g: var CodeGen; name: string; dest: Reg) =
  ## `dest ← &threadlocal(name)`. nifasm lowers `(adr dest tvar)` into the macOS
  ## TLV descriptor thunk call, which clobbers x0 and lr. Procs that touch a
  ## thread-local are therefore analysed as having a call: they get a stack frame
  ## (lr saved) and keep their params out of the volatile argument registers.
  g.ab.tree AdrA64:
    g.emReg dest
    g.ab.sym name

proc emPair(g: var CodeGen; op: A64Inst; r1, r2: Reg; off: int) =
  # stp/ldp save/restore *physical* callee-saved registers (which may also be
  # named-local homes), so emit raw register nodes, not the local names.
  g.ab.tree op: g.ab.reg r1; g.ab.reg r2; g.ab.reg SP; g.ab.intLit off

proc emFPair(g: var CodeGen; op: A64Inst; f1, f2: FReg; off: int) =
  g.ab.tree op: g.ab.dreg f1; g.ab.dreg f2; g.emReg SP; g.ab.intLit off

proc framePush(g: var CodeGen) =
  ## Push fp/lr, then the used callee-saved GPRs, then the callee-saved SIMD
  ## registers — a LIFO stack of pairs.
  g.emPair(StpA64, FP, LR, -16)
  var i = 0
  while i < g.frameRegs.len:
    g.emPair(StpA64, g.frameRegs[i], g.frameRegs[i+1], -16)
    i += 2
  i = 0
  while i < g.frameFRegs.len:
    g.emFPair(FstpA64, g.frameFRegs[i], g.frameFRegs[i+1], -16)
    i += 2

proc framePop(g: var CodeGen) =
  ## Restore in reverse (post-index): SIMD, then callee-saved GPRs, then fp/lr.
  var i = g.frameFRegs.len - 2
  while i >= 0:
    g.emFPair(FldpA64, g.frameFRegs[i], g.frameFRegs[i+1], 16)
    i -= 2
  i = g.frameRegs.len - 2
  while i >= 0:
    g.emPair(LdpA64, g.frameRegs[i], g.frameRegs[i+1], 16)
    i -= 2
  g.emPair(LdpA64, FP, LR, 16)

proc killFrameRegLocals(g: var CodeGen) =
  ## Before an explicit-`ret` `framePop`, release any register-local bound to a
  ## callee-saved register the epilogue restores raw — nifasm forbids a raw use of
  ## a still-bound register, and at a return every local is dead. The binding is
  ## dropped so the trailing `exitScope` does not double-kill it. (A second `ret`
  ## on another path needing the same callee register bound is the pre-existing
  ## multi-`ret` limitation — out of scope here.)
  for r in g.frameRegs:
    if g.regLocal.hasKey(r):
      g.ab.tree KillA64: g.ab.sym g.regLocal[r]
      g.regLocal.del r

proc framePushBytes(g: CodeGen): int =
  ## Bytes `framePush` lowers SP by: the fp/lr pair plus each saved callee-saved
  ## GPR / SIMD pair (16 bytes apiece). Used to address incoming stack arguments
  ## relative to SP right after the prologue's pushes (before locals are carved).
  if not g.hasFrame: 0
  else: 16 * (1 + g.frameRegs.len div 2 + g.frameFRegs.len div 2)

# ── scratch register pool (volatile temps not held by a local) ──────────────

proc tryBorrowTmp(g: var CodeGen; typ: AsmSlot): Reg =
  ## Like `borrowTmp` but returns `NoReg` when the scratch pool is exhausted
  ## (instead of failing). The caller then spills the value to a stack slot, so
  ## register allocation never fails. The reg-or-`NoReg` outcome is recorded by the
  ## planning pass and replayed verbatim by the emit pass (see `genProc`), keeping
  ## the two walks byte-identical. A real register is `bindTemp`'d to a typed name
  ## (`typ`) so every later `emReg` of it emits a checked symbol rather than a raw
  ## `(xN)`; the caller releases it (and the binding) via `giveBack`.
  result = NoReg
  if not g.ab.planning:                          # emit pass: replay the planned decision
    result = g.borrowLog[g.borrowIdx]; inc g.borrowIdx
  else:
    for r in g.md.intTempRegs:                    # plan pass: real pool allocation
      if r in g.freeTmp and not g.ra.isSealed(r):
        excl g.freeTmp, r
        result = r
        break
    g.borrowLog.add result                        # the chosen reg, or NoReg (exhausted)
  if result != NoReg: g.bindTemp(result, typ)     # typed name ⇒ emReg emits a symbol

proc borrowTmp(g: var CodeGen; typ: AsmSlot): Reg =
  result = g.tryBorrowTmp(typ)                    # binds on a pool hit
  if result == NoReg:
    # Pool empty. Mirror x64's `borrowTmp`: evict a register-bound local to a stack
    # slot and reuse its register (`stealReg`), so a scratch-needing site (a global
    # address load, an atomic, a function-pointer call) never refuses to compile
    # just because the pool is full of locals. The steal decision is logged at the
    # same `borrowLog` position the plan pass recorded `NoReg` and replayed (with the
    # spill store) by the emit pass, keeping the two walks byte-consistent.
    let idx = if g.ab.planning: g.borrowLog.len - 1 else: g.borrowIdx - 1
    result = g.stealReg(idx)
    if result == NoReg:
      # Pool empty AND no register-bound local to evict (e.g. the locals live in
      # callee-saved homes the steal order can still reach, but all are sealed/live —
      # or an early scratch need precedes every local decl). Fall back to a transient
      # caller-saved staging register, exactly as a spill's `pickStaging` does: a
      # clobberable scratch, sealed for the temp's lifetime so a nested borrow can't
      # reuse it (`giveBack` unseals). The pick is a deterministic function of the
      # per-pass-identical state, so plan and emit agree without a borrow-log entry.
      result = g.pickStagingScratch()
      if result == NoReg:
        raiseAssert "arkham a64: out of registers (no local to steal for scratch)"
      g.ra.seal result
    g.bindTemp(result, typ)                        # steal / staging-fallback reg → typed name

proc giveBack(g: var CodeGen; r: Reg) =
  ## Release a scratch register: drop its `bindTemp` binding (a `(kill)`, no machine
  ## code), unseal a staging-fallback register held across the borrow, and return a
  ## pool register to the pool. A no-op for a plain staging/arg register (not a pool
  ## member, never bound here).
  if r == NoReg: return
  g.unbindTemp(r)
  g.ra.unseal {r}
  if r in g.md.intTempRegs: g.freeTmp.incl r

# ── SIMD/FP scratch pool + emit helpers (double precision) ──────────────────

proc bindFTmp(g: var CodeGen; f: FReg; bits: int) =
  ## Give scratch v-register `f` a typed nifasm name `ftmpN.0` via `(rebind …)`, so
  ## every later `emFReg f` emits a checked symbol the binding checker sees rather than
  ## a raw `(dN)`/`(sN)`. The SIMD twin of `bindTemp`; the name counter bumps in BOTH
  ## passes (names replay identically) and the `(rebind …)` tree auto-no-ops in the plan
  ## pass. The binding type `(f bits)` carries the precision so a *named* use recovers
  ## s/d (unlike x64, the arm64 operand encodes precision).
  let name = "ftmp" & $g.ftmpBindCount & ".0"; inc g.ftmpBindCount
  g.ab.tree RebindA64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.freg(f, bits)
  g.fregLocal[f] = name
  g.boundFTmps.incl f

proc unbindFTmp(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## `fregLocal`/`boundFTmps` entries. A no-op when `f` carries no temp binding.
  if f in g.boundFTmps:
    g.ab.tree KillA64: g.ab.sym g.fregLocal[f]
    g.fregLocal.del f
    g.boundFTmps.excl f

proc tryBorrowFTmp(g: var CodeGen; bits: int): FReg =
  ## Like `borrowFTmp` but returns `NoFReg` when the SIMD scratch pool is exhausted
  ## (instead of failing), so the caller can spill to a float stack slot — the float
  ## analogue of `tryBorrowTmp`. The reg-or-`NoFReg` outcome is recorded/replayed
  ## through `borrowLogF` like any borrow decision. A real register is `bindFTmp`'d to
  ## a typed name so `emFReg` emits a checked symbol; the caller releases it via
  ## `giveBackF`.
  result = NoFReg
  if not g.ab.planning:                            # emit pass: replay the planned decision
    result = g.borrowLogF[g.borrowIdxF]; inc g.borrowIdxF
  else:
    for f in g.md.floatTempRegs:                    # plan pass: real pool allocation
      if f in g.freeFTmp:
        excl g.freeFTmp, f
        result = f
        break
    g.borrowLogF.add result                         # the chosen reg, or NoFReg (exhausted)
  if result != NoFReg: g.bindFTmp(result, bits)     # typed name ⇒ emFReg emits a symbol

proc borrowFTmp(g: var CodeGen; bits: int): FReg =
  ## A SIMD scratch register from the pool, `bindFTmp`'d to a typed `ftmpN.0` name so
  ## `emFReg` emits a checked symbol. Asserts on exhaustion: callers that use this
  ## (rather than `tryBorrowFTmp` + a spill path) only ever need one or two transient
  ## temps whose deep sub-expressions recurse through the now-total `genFBin`, so the
  ## pool cannot be empty at the borrow point in practice.
  result = g.tryBorrowFTmp(bits)
  if result == NoFReg:
    raiseAssert "arkham a64 v0: out of SIMD scratch registers"

proc giveBackF(g: var CodeGen; f: FReg) =
  g.unbindFTmp(f)                                  # release the scratch binding (if any)
  if f in g.md.floatTempRegs: g.freeFTmp.incl f

# `bits` (32 or 64) selects the s/d register view; nifasm reads the operand tag
# to pick single- vs double-precision encodings.
proc emFReg(g: var CodeGen; f: FReg; bits: int) {.inline.} =
  ## A float value operand: a v-register hosting a named float local / scratch temp →
  ## its checked name (nifasm recovers the precision from the binding's type);
  ## otherwise the raw `(dN)`/`(sN)` tag. The SIMD twin of `emReg`: the v16–v31 scratch
  ## pool is the only register class the allocator hands out for arbitrary computed
  ## floats, and every such hand-out is bound (`bindFTmp` / `emFRegLocalVar`), so a raw
  ## pool register reaching here is an unbound scratch slipping past the binder. The
  ## v0–v7 arg/return registers and v8–v15 callee-saved homes (saved raw by fstp/fldp)
  ## keep their structural raw uses.
  if g.fregLocal.hasKey(f): g.ab.sym g.fregLocal[f]
  else:
    assert f notin g.md.floatTempRegs,
      "arkham a64: unbound float scratch-pool register reached emFReg: " & regName(f)
    g.ab.freg(f, bits)

proc fmovF(g: var CodeGen; d, s: FReg; bits: int) =
  if d == s: return
  g.ab.tree FmovA64: g.emFReg(d, bits); g.emFReg(s, bits)

proc fmovFromGpr(g: var CodeGen; d: FReg; s: Reg; bits: int) =   # fmov dD/sD, xS/wS (bits)
  g.ab.tree FmovA64: g.emFReg(d, bits); g.ab.reg s

proc fmovToGpr(g: var CodeGen; d: Reg; s: FReg; bits: int) =     # fmov xD/wD, dS/sS (bits)
  g.ab.tree FmovA64: g.ab.reg d; g.emFReg(s, bits)

proc fbin(g: var CodeGen; op: A64Inst; d, s: FReg; bits: int) =  # d = d op s
  g.ab.tree op: g.emFReg(d, bits); g.emFReg(s, bits)

proc fcvtI2F(g: var CodeGen; op: A64Inst; d: FReg; s: Reg; bits: int) =  # scvtf/ucvtf dD, xS
  g.ab.tree op: g.emFReg(d, bits); g.ab.reg s

proc fcvtF2I(g: var CodeGen; op: A64Inst; d: Reg; s: FReg; bits: int) =  # fcvtzs/fcvtzu xD, dS
  g.ab.tree op: g.ab.reg d; g.emFReg(s, bits)

proc emFcvt(g: var CodeGen; d, s: FReg; dstBits, srcBits: int) =  # fcvt: precision convert
  g.ab.tree FcvtA64: g.emFReg(d, dstBits); g.emFReg(s, srcBits)

proc emFLoad(g: var CodeGen; d: FReg; addrReg: Reg; bits: int) =  # fldr dD/sD, [addrReg]
  g.ab.tree FldrA64:
    g.emFReg(d, bits)
    g.ab.tree MemX: g.emReg addrReg          # name when the pointer is a bound temp

proc emFStore(g: var CodeGen; d: FReg; addrReg: Reg; bits: int) = # fstr dD/sD, [addrReg]
  g.ab.tree FstrA64:
    g.ab.tree MemX: g.emReg addrReg          # name when the pointer is a bound temp
    g.emFReg(d, bits)

# ── expressions: target-into-register ───────────────────────────────────────

proc genInto(g: var CodeGen; c: var Cursor; dest: Reg)
proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int)
proc genCall(g: var CodeGen; c: var Cursor)
proc genAtomic(g: var CodeGen; c: var Cursor; builtin: string)
proc genMemIntrin(g: var CodeGen; c: var Cursor; builtin: string)
proc genAddr(g: var CodeGen; c: var Cursor; dest: Reg)
proc materializeCond(g: var CodeGen; c: var Cursor; dest: Reg)
proc genReg(g: var CodeGen; c: var Cursor): Location
proc genFReg(g: var CodeGen; c: var Cursor; bits: int): Location
proc structToRegs(g: var CodeGen; varName, typeName: string; firstArg: int)
proc regsToStruct(g: var CodeGen; varName, typeName: string; firstArg: int)
proc aggrAddr(g: var CodeGen; c: var Cursor): tuple[r: Reg, temp: bool]
proc emitLoad(g: var CodeGen; loc: Location; dest: Reg)
proc gen(g: var CodeGen; c: var Cursor; dest: var Location)
proc byteCopyConst(g: var CodeGen; dst, src: Reg; size: int)
proc genTypeBody(g: var CodeGen; c: var Cursor)
proc genPointee(g: var CodeGen; c: var Cursor)
proc genProctypeSig(g: var CodeGen; c: var Cursor)
proc indirectRetType(g: var CodeGen; gvarDecl: Cursor): Cursor
proc emitPatAddr(g: var CodeGen; c: var Cursor; dest: Reg)

proc emFieldMem(g: var CodeGen; base, field: string) =
  ## `(mem (dot base field))` — nifasm resolves the field offset from the
  ## aggregate's type. `base` is a `(s)` stack var.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field

proc emPtrFieldMem(g: var CodeGen; ptrReg: Reg; typeName, field: string) =
  ## `(mem (dot (cast (ptr T) (xN)) field))` — field access through a register
  ## holding a pointer to the aggregate (for >16B by-ref / x8-indirect). The
  ## `cast` types the bare register so nifasm's `dot` can compute the offset.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym typeName
        g.emReg ptrReg
      g.ab.sym field

proc emAggrFieldMem(g: var CodeGen; base, field: string) =
  ## Field memory operand for the aggregate named `base`, dispatching on how it
  ## is held: a `(s)` stack struct → direct `(dot …)`; a pointer in a register
  ## (a by-reference param) → through the pointer.
  let loc = g.ra.locationOfSym(base)
  case loc.kind
  of NamedStack: g.emFieldMem(base, field)
  of InReg:      g.emPtrFieldMem(loc.r, g.varType[base], field)
  else: raiseAssert "arkham: aggregate base neither stack nor pointer: " & base

proc emAggrDot(g: var CodeGen; base, field: string) =
  ## The `(dot …)` operand alone (no `mem` wrapper), location-aware — for `lea`
  ## (address-of a field). Stack struct → `(dot var field)`; pointer → cast.
  let loc = g.ra.locationOfSym(base)
  case loc.kind
  of NamedStack:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field
  of InReg:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym g.varType[base]
        g.emReg loc.r
      g.ab.sym field
  else: raiseAssert "arkham: aggregate base neither stack nor pointer: " & base

proc emStackVar(g: var CodeGen; name, typeName: string) =
  ## Declare a nifasm-managed stack slot `(var :name (s) typeName)`.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.sym typeName
  g.ab.close()

proc emScalarStackVar(g: var CodeGen; name: string) =
  ## Declare a spilled integer/pointer scalar's stack slot `(var :name (s) (i 64))`.
  ## Always 8-byte wide / 8-aligned (arkham keeps scalars 64-bit in registers and
  ## nifasm's `ldr`/`str` need an 8-aligned slot), regardless of the logical width.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc emTypedStackVar(g: var CodeGen; name: string; t: Cursor) =
  ## `(var :name (s) T)` with `T` the value's actual NIFC type. Use this (not the
  ## generic `(i 64)` slot) for an evicted scalar whose type matters to nifasm — e.g.
  ## a pointer local that the body later derefs, where an `(i 64)` slot would both
  ## reject the typed store and forbid the deref (nifasm is strict). Mirrors x64.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  var tc = t
  if tc.kind == Symbol: g.ab.sym symName(tc)
  else: g.genTypeBody(tc)
  g.ab.close()

proc emScalarLoad(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← [slot]` — load a spilled scalar (nifasm resolves the `(s)` var to
  ## `[sp,#off]`).
  g.ab.tree MovA64: (g.emReg dest; g.ab.sym name)

proc emScalarStore(g: var CodeGen; name: string; src: Reg) =
  ## `[slot] ← src` — store to a spilled scalar's `(s)` var.
  g.ab.tree MovA64: (g.ab.sym name; g.emReg src)

proc emBindType(g: var CodeGen; typ: AsmSlot) =
  ## Emit the NIFC type for a scratch binding: the slot's own type when known, else
  ## the generic `(i 64)` (a register/immediate dont-care placeholder carries no
  ## cursor). Mirrors `emScalarStackVar`'s type emission.
  if cursorIsNil(typ.typ):
    g.ab.intType(64)
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(xN)` the binding
  ## checker can't see. The name counter bumps in BOTH passes (so names replay
  ## identically); the `(rebind …)` tree auto-no-ops in the plan pass (zero machine
  ## code — pure nifasm bookkeeping). `boundTemps` records that `r`'s `regLocal` entry
  ## is a transient temp; released by `unbindTemp`.
  let name = "tmp" & $g.tmpBindCount & ".0"; inc g.tmpBindCount
  g.ab.tree RebindA64:
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
    g.ab.tree KillA64: g.ab.sym g.regLocal[r]
    g.regLocal.del r
    g.boundTemps.excl r

proc emFloatStackVar(g: var CodeGen; name: string; bits: int) =
  ## Declare a spilled float scalar's stack slot `(var :name (s) (f N))`. nifasm
  ## sizes/aligns the slot and resolves the bare symbol to `[sp,#off]`.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.floatType(bits)
  g.ab.close()

proc emFloatScalarLoad(g: var CodeGen; dest: FReg; name: string; bits: int) =
  ## `dest ← [slot]` — load a spilled float (nifasm resolves the `(s)` var operand).
  g.ab.tree FldrA64: (g.emFReg(dest, bits); g.ab.sym name)

proc emFloatScalarStore(g: var CodeGen; name: string; src: FReg; bits: int) =
  ## `[slot] ← src` — store to a spilled float's `(s)` var.
  g.ab.tree FstrA64: (g.ab.sym name; g.emFReg(src, bits))

# MODEL: the `pickStaging` action in proofs/arkham_bindings.tla — only ever returns a
# register with no live owner (the `Free` guard); staging on an occupied reg breaks
# NoSharedRegister. Change this ⇒ re-check that action.
proc pickStagingScratch(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## The first caller-saved arg register (x0–x7) that is not `avoid`, not sealed, not
  ## a named local's home, not a bound scratch temp, and not a live expression
  ## accumulator. arkham never register-allocates a *local* to an arg register (locals
  ## go to x9–x15 / x19–x28); a leaf-proc *param* there is in `regLocal`, and a genInto
  ## target (the return value x0, or a call argument) is in `liveAccums` — so an x0–x7
  ## outside all three holds nothing live and is safe to clobber transiently. Returns
  ## `NoReg` when none is free (the genuinely-out-of-registers case). The scan order is
  ## fixed, so the plan and emit passes return the same register from the same state.
  ## (The scratch pool x9–x15 is exhausted by the time this runs.)
  for r in IntArgRegs:
    if r != avoid and not g.ra.isSealed(r) and not g.regLocal.hasKey(r) and
       r notin g.liveAccums and r notin g.boundTemps:
      return r
  return NoReg

proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## A transient compute register for a spill (see `pickStagingScratch`).
  result = g.pickStagingScratch(avoid)
  if result == NoReg:
    raiseAssert "arkham a64: no staging register available for a spill"

const FloatStagingCandidates = {F0, F1, F2, F3, F4, F5, F6, F7}
  ## The SIMD registers `pickFStaging` may hand out as a float spill's transient
  ## staging reg (v0–v7 — disjoint from the v16–v31 scratch pool). A `genIntoF`
  ## accumulator that lands in one of these (a float-arg-register target) is an
  ## in-flight value with no named-local binding, so it is added to `sealedF` for
  ## its lifetime — the SIMD analogue of `liveAccums` guarding a GPR accumulator.

proc regHoldsLiveFLoc(g: var CodeGen; f: FReg): bool =
  ## True if a float local/param currently lives in SIMD register `f` (per the
  ## allocator's view). A leaf-proc float param sits in its incoming arg register
  ## (v0–v7), so the float staging pick must not clobber it.
  for name, pos in g.ra.symPos:
    let loc = g.ra.locs[pos]
    if loc.kind == InFReg and loc.f == f: return true

proc pickFStaging(g: var CodeGen; avoid: FReg = NoFReg): FReg =
  ## The float analogue of `pickStagingScratch`: the first SIMD arg register (v0–v7)
  ## that is not the scratch pool (v16–v31, exhausted by the time we get here), not an
  ## in-flight float arg / held staging reg (`sealedF`), not a live float local/param
  ## home, and not `avoid`. Clobbering it transiently is then safe. The scan order is
  ## fixed, so the plan and emit passes return the same register from the same state.
  ## `NoFReg` only when every v0–v7 is occupied — the genuinely-out-of-float-regs case.
  for f in g.md.floatArgRegs:
    if f != avoid and f notin g.sealedF and not g.regHoldsLiveFLoc(f):
      return f
  return NoFReg

# ── codegen-time register steal (evict a live local to a stack slot) ─────────
# The exact mirror of x64's steal machinery: when the scratch pool is exhausted
# at a `borrowTmp`, evict a register-bound local to a nifasm `(s)` slot and hand
# its register over as scratch — recorded in the plan pass, replayed (with the
# spill store) in the emit pass, keyed by the borrow-log index so both passes
# stay byte-consistent. `recordEviction` emits no machine code (it only mutates
# the allocator's view, which `genProc` snapshot/restores); `replayEviction` does.

proc localNameInReg(g: var CodeGen; r: Reg): string =
  ## The allocator's name (the `symPos` key) of the local currently homed in reg
  ## `r`, or "". The *allocator* identity — distinct from `regLocal[r]`, the nifasm
  ## *binding* name, which for a declarative param is the signature alias `pN.0`.
  for name, pos in g.ra.symPos:
    if g.ra.locs[pos].kind == InReg and g.ra.locs[pos].r == r: return name
  result = ""

proc recordEviction(g: var CodeGen; r: Reg): StealEvent =
  ## Plan-pass: evict the register-local currently in `r` to a fresh stack slot,
  ## mutating the allocator's view so every later `locationOfSym(victim)` reads the
  ## slot (`g.ra.locs` is snapshot/restored across the two passes). Returns the event
  ## for the caller to record. Caller guarantees `regLocal.hasKey(r)`.
  let bindName = g.regLocal[r]                    # nifasm binding (maybe a pN.0 alias)
  var victim = g.localNameInReg(r)                # allocator name (symPos key)
  if victim.len == 0: victim = bindName           # they coincide for a non-param local
  let typ = g.ra.locationOfSym(victim).typ
  let slot = "evict" & $g.spillCount & ".0"; inc g.spillCount
  # Live IFF the victim is already materialized (a declared local / settled param —
  # `symType` covers both); a future local whose reused home reg is stolen before its
  # own decl has nothing of its own to save (see the x64 twin for the full rationale).
  let live = g.symType.hasKey(victim)
  g.ra.locs[g.ra.symPos[victim]] = namedStackLoc(slot, typ)
  g.ra.hasStackVars = true
  g.regLocal.del r
  result = StealEvent(victim: victim, bindName: bindName, slot: slot, reg: r, typ: typ, live: live)

proc replayEviction(g: var CodeGen; ev: StealEvent) =
  ## Emit-pass: re-apply a recorded eviction — declare the slot, store the victim's
  ## live value, kill its register binding, repoint its location to the slot. A
  ## pointer keeps its `(ptr T)` slot type (else nifasm's strict store/reload rejects
  ## the typed value and a later deref is illegal); other scalars stay `(i 64)`.
  # Type from the PLAN-recorded `ev.typ` (not a re-query of mutable `symType`, which is
  # unset for a victim evicted before its decl → would wrongly pick `(i 64)` for a ptr).
  if not cursorIsNil(ev.typ.typ) and isPtrType(resolveType(g.prog, ev.typ.typ)):
    var tc = ev.typ.typ
    g.emTypedStackVar(ev.slot, tc)               # (var :evictN.0 (s) (ptr …))
  else:
    g.emScalarStackVar(ev.slot)                  # (var :evictN.0 (s) (i 64))
  if ev.live:                                    # only a materialized victim has a value
    g.emScalarStore(ev.slot, ev.reg)             # store the victim's live (bound) value
  if g.regLocal.getOrDefault(ev.reg, "") == ev.bindName:
    g.ab.tree KillA64: g.ab.sym ev.bindName      # release the register binding
  g.ra.locs[g.ra.symPos[ev.victim]] = namedStackLoc(ev.slot, ev.typ)
  g.regLocal.del ev.reg

# MODEL: the `steal` action in proofs/arkham_bindings.tla — the evicted victim must move
# to a stack slot (loc→Stack, binding cleared) or LiveLocalsHaveHomes / RegisterBindingsMatchLoc
# break. Change this ⇒ re-check that action.
proc stealReg(g: var CodeGen; logIdx: int): Reg =
  ## `freeTmp` is exhausted. Evict a register-bound local that is *not* in flight
  ## (not sealed, not a live accumulator, not a bound scratch temp) and hand its
  ## register over as scratch. Recorded in the plan pass, replayed in the emit pass,
  ## keyed by `logIdx` so both passes stay byte-consistent. Returns `NoReg` when
  ## nothing is safe to steal.
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

# MODEL: a staging register handed out for a *held* value must be tracked, not raw (see
# proofs/arkham_bindings.tla NoSharedRegister) — hence the total `borrowTmp` below, not a
# bare `pickStaging`; two raw staging values would otherwise collide on one register.
proc forceReg(g: var CodeGen; dest: var Location) =
  ## Ensure `dest` is in a register, mutating it IN PLACE. An immediate / spilled
  ## memory operand is materialized into a fresh scratch temp — or, when the pool is
  ## exhausted, a transient staging register (so this never fails). The temp is
  ## marked `isTemp` so a later `freeTemp` releases it (a no-op for a staging reg or
  ## any persistent location); a value already in a register is left untouched.
  case dest.kind
  of InReg: discard
  of Imm:
    let t = g.borrowTmp(ScalarSlot)                       # total: pool / steal / sealed staging
    g.movImm(t, dest.ival); dest = regLoc(t, dest.typ, isTemp = true)
  of NamedStack, Mem, Glob, Tvar:
    let t = g.borrowTmp(ScalarSlot)
    g.emitLoad(dest, t); dest = regLoc(t, dest.typ, isTemp = true)
  else: raiseAssert "arkham: cannot force a value of kind " & $dest.kind & " into a register"

proc freeTemp(g: var CodeGen; loc: Location) {.inline.} =
  ## Release `loc`'s register iff it is a borrowed temp; a no-op on every persistent
  ## location (register-resident local, stack slot, immediate, …) — like vmgen's
  ## `freeTemp`. The single release point replacing the old `if owns: giveBack`.
  ## Handles both GPR (`InReg`) and SIMD (`InFReg`) temps.
  if loc.isTemp:
    case loc.kind
    of InReg: g.giveBack loc.r
    of InFReg: g.giveBackF loc.f
    else: discard

proc place(g: var CodeGen; v: Location; dest: Reg) =
  ## Materialize `v` into `dest`, releasing any owned scratch it occupied. Placing
  ## into a known register never needs a scratch temp (so it is always total).
  case v.kind
  of Imm: g.movImm(dest, v.ival)
  of InReg:
    g.movReg(dest, v.r)
    if v.isTemp and v.r != dest: g.giveBack v.r
  of NamedStack, Mem, Glob, Tvar:
    g.emitLoad(v, dest)
  else: raiseAssert "arkham: cannot place a value of kind " & $v.kind

proc spillComputed(g: var CodeGen; c: var Cursor): Location =
  ## The scratch pool is exhausted: materialize `c`'s value into a fresh `(s)` slot
  ## via a transient staging register, and hand it back as a `NamedStack` operand
  ## (which every consumer — `forceReg`/`place`/genBin's combine — already loads).
  ## This is what makes register allocation total: a deep expression spills instead
  ## of failing. The staging reg is sealed across the recursive eval so the inner
  ## walk (itself total — genBin's exhausted path reuses `dest` rather than pinning
  ## a register per level) can't clobber the value being built, so spill nesting
  ## does not cascade.
  let slotName = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let stage = g.pickStaging()
  g.ra.seal stage
  g.emScalarStackVar(slotName)                  # (var :spill.N (s) (i 64))
  g.genInto(c, stage)                           # compute the value into the staging reg
  g.emScalarStore(slotName, stage)              # store it to the slot
  g.ra.unseal {stage}
  result = namedStackLoc(slotName, AsmSlot(kind: AInt, size: 8, align: 8))

proc genVal(g: var CodeGen; c: var Cursor): Location =
  ## The dont-care evaluator: produce `c`'s value where it naturally lives — a
  ## literal as an `Imm`, a register-resident local in place (`InReg`, not owned),
  ## a memory lvalue as a foldable `NamedStack`/`Mem` (loaded on demand) —
  ## materializing any *computed* value into a scratch register (`InReg`, owned),
  ## or (when the pool is exhausted) a spill slot. The counterpart of `gen(…, dest)`.
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
      g.emAdr(t, si.asmName)
      inc c
      return regLoc(t, ScalarSlot, isTemp = true)
    let loc = g.asLoc(c)
    case loc.kind
    of InReg: result = regLoc(loc.r, loc.typ, isTemp = false)
    of NamedStack: result = loc                 # foldable spilled scalar in place
    of Glob, Tvar:                              # load through its address into a scratch
      let t = g.borrowTmp(ScalarSlot); g.emitLoad(loc, t)
      result = regLoc(t, loc.typ, isTemp = true)
    else: raiseAssert "arkham v1: operand of kind " & $loc.kind
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC:                       # a memory lvalue used as a value
      result = g.asLoc(c)                        # a foldable `Mem` operand
    of PatC:                                     # pointer indexing → eager element load
      let t = g.borrowTmp(ScalarSlot); g.genInto(c, t)
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

proc genReg(g: var CodeGen; c: var Cursor): Location =
  ## Evaluate `c` into *some* register via the `NeedsReg` constraint — `gen` writes
  ## back the concrete `InReg`: a register-resident symbol in place, else a borrowed
  ## scratch (`isTemp`) the caller releases with `freeTemp`. `.r` is the register.
  result = needsReg(ScalarSlot)
  g.gen(c, result)

proc commutativeOp(op: A64Inst): bool {.inline.} =
  ## Integer ops for which `a op b == b op a`, so Sethi–Ullman may evaluate the
  ## heavier operand first and fold the lighter one. (sub/shifts/div are
  ## position-sensitive and stay in source order.)
  op in {AddA64, MulA64, AndA64, OrrA64, EorA64}

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

proc isComputedOperand(c: Cursor): bool =
  ## Mirrors `genVal`: the operand kinds it materializes into a fresh register
  ## (and would spill on pool exhaustion), as opposed to those it reads in place
  ## (literal, register/stack local, memory lvalue). genBin intercepts these so a
  ## deep right operand spills without pinning `dest`.
  case c.kind
  of IntLit, Symbol: false
  of TagLit: c.exprKind notin {DotC, AtC, DerefC}
  else: true

proc spillOperandAround(g: var CodeGen; c: var Cursor; dest: Reg; op: A64Inst) =
  ## Pool-exhausted evaluation of genBin's right operand that keeps register
  ## allocation TOTAL. The left operand is already in `dest`; spill it to a fresh
  ## slot so `dest` is free, evaluate the (possibly deep) right operand into `dest`
  ## — the recursion reuses `dest`, never pinning a register per nesting level —
  ## then reassemble `dest = a op b` with a single transient staging reg taken only
  ## here, after the recursion has fully unwound (so it never nests → one reg covers
  ## any depth). Evaluation order a-before-b is preserved. `c` is consumed past the
  ## right operand.
  let slotA = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let slotLoc = namedStackLoc(slotA, AsmSlot(kind: AInt, size: 8, align: 8))
  g.emScalarStackVar(slotA)
  g.emScalarStore(slotA, dest)                # store a → slotA (free dest)
  g.genInto(c, dest)                          # b → dest (recursion reuses dest)
  let s = g.pickStaging(avoid = dest)         # transient; recursion done → never nests
  g.movReg(s, dest)                           # s = b
  g.emitLoad(slotLoc, dest)                   # dest = a (reload)
  g.binReg(op, dest, s)                       # dest = a op b

proc genBin(g: var CodeGen; c: var Cursor; dest: Reg;
            signedOp: A64Inst; unsignedOp = NoA64Inst) =
  ## `(op Type a b)` → `dest = a op b`. Normally `a` is computed into `dest`, then
  ## the right operand `b` is folded as an immediate / loaded register. For a
  ## commutative op whose RIGHT operand needs strictly more registers than the left
  ## (Sethi–Ullman), the operands are swapped: the heavier one is evaluated into
  ## `dest` first and the lighter folded after — so a right-nested chain like
  ## `1+(2+(4+…))` collapses into `dest` with no scratch temp (and never spills).
  ## The swap is taken only when both operands are pure (no call) and the light
  ## operand does not read `dest`. If `b` lives in `dest`, it is saved before `a`
  ## overwrites it. When `b` is a computed operand that must occupy a register and
  ## the scratch pool is exhausted, `spillOperandAround` spills `a`, evaluates `b`
  ## into the freed `dest`, and reassembles — so even a deep NON-commutative
  ## right-nest allocates with O(1) live registers and O(depth) slots. Register
  ## allocation is total.
  c.into:
    let op = if unsignedOp != NoA64Inst and not isSignedType(c): unsignedOp
             else: signedOp
    skip c                                  # result type; c at a
    var aPeek = c
    var bPeek = c; skip bPeek                # bPeek at b
    var other: Location                     # the operand folded into dest last
    var combined = false                    # the spill path emits its own combine
    if commutativeOp(op) and suWeight(bPeek) > suWeight(aPeek) and
       not hasCall(aPeek) and not hasCall(bPeek) and not g.refsReg(aPeek, dest):
      g.genInto(bPeek, dest)                # heavier operand (b) → dest first
      other = g.genVal(c)                   # lighter operand (a) folded after (c at a)
      skip c                                # consume b in the real cursor
    elif g.operandInReg(bPeek, dest):
      let saved = g.borrowTmp(ScalarSlot)
      g.movReg(saved, dest)                 # preserve b before `a` clobbers dest
      g.genInto(c, dest)                    # a → dest
      skip c                                # consume b
      other = regLoc(saved, ScalarSlot, isTemp = true)
    else:
      g.genInto(c, dest)                    # a → dest; c now at b
      if isComputedOperand(c):              # b must be materialized into a register
        let t = g.tryBorrowTmp(ScalarSlot)
        if t == NoReg:                       # pool exhausted → total spill path
          g.spillOperandAround(c, dest, op)
          combined = true
        else:
          g.genInto(c, t)                    # b → scratch temp
          other = regLoc(t, ScalarSlot, isTemp = true)
      else:
        other = g.genVal(c)                  # b is a leaf / memory / in-place value
    if not combined:
      if op in {AddA64, SubA64} and other.kind == Imm and
         other.ival >= 0 and other.ival <= 0xFFFF:
        g.binImm(op, dest, other.ival)       # dest op= small immediate
      else:
        g.forceReg(other)
        g.binReg(op, dest, other.r)          # dest op= b
        g.freeTemp(other)

proc genMod(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `(mod Type a b)` → `dest = a - (a div b)*b` (nifasm has no `msub`).
  c.into:
    let signed = isSignedType(c); skip c
    # Save `b` first if it lives in `dest` (else `genInto(a, dest)` clobbers it).
    var bPeek = c
    skip bPeek
    var bSaved = NoReg
    if g.operandInReg(bPeek, dest):
      bSaved = g.borrowTmp(ScalarSlot)
      g.movReg(bSaved, dest)
    g.genInto(c, dest)                      # dest = a
    var br: Reg
    var bt = false
    if bSaved != NoReg: (br = bSaved; skip c)   # br = b (saved); consume b
    else: (let t = g.genReg(c); br = t.r; bt = t.isTemp)  # br = b
    let q = g.borrowTmp(ScalarSlot)
    g.movReg(q, dest)                       # q = a
    g.binReg(if signed: SdivA64 else: UdivA64, q, br)  # q = a div b
    g.binReg(MulA64, q, br)                 # q = (a div b)*b
    g.binReg(SubA64, dest, q)               # dest = a - q
    g.giveBack q
    if bSaved != NoReg: g.giveBack bSaved
    elif bt: g.giveBack br

proc genNeg(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `(neg Type a)` → `dest = -a`.
  c.into:
    skip c                                  # type
    g.genInto(c, dest)
    g.ab.tree NegA64: g.emReg dest

proc genBitnot(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `(bitnot Type a)` → `~a = -a - 1` (nifasm has no `mvn`).
  c.into:
    skip c                                  # type
    g.genInto(c, dest)
    g.ab.tree NegA64: g.emReg dest          # dest = -a
    g.binImm(SubA64, dest, 1)               # dest = -a - 1

proc genNot(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## boolean `(not a)` → `dest = 1 - a` (a ∈ {0,1}); no result-type child.
  c.into:
    let b = g.genReg(c)
    g.movImm(dest, 1)
    g.binReg(SubA64, dest, b.r)
    g.freeTemp(b)

proc extendTo(g: var CodeGen; dest: Reg; width: int; signed: bool) =
  ## Normalize the low `width` bits of `dest` to its full 64-bit register form
  ## (sign- or zero-extended). No-op for 64-bit. nifasm has no sxtb/uxtb, so we
  ## use the `lsl #(64-w); asr|lsr #(64-w)` shift pair (immediate shifts), written
  ## here as an inline asm-NIF fragment.
  if width <= 0 or width >= 64: return
  let d = g.emOp(dest)                       # bound name or raw `(xN)` (parens included)
  let sh = 64 - width
  let down = if signed: "asr" else: "lsr"
  g.ab.splice &"(lsl {d} {sh}) ({down} {d} {sh})"

proc derefPtrCur(g: var CodeGen; nn: Cursor): tuple[r: Reg, temp: bool] =
  ## Recompute the pointer of a `(deref p)` cursor into a register.
  var p = nn
  var pr = NoReg
  var pt = false
  p.into:
    let rl = g.genReg(p); pr = rl.r; pt = rl.isTemp
    while p.hasMore: skip p                  # (cppref)?
  result = (pr, pt)

proc dotBaseField(cur: Cursor): (string, string) =
  ## Base symbol + field name of a `(dot base field …)` cursor — the a64 address
  ## helpers key the aggregate base by name (single-level). Reads a copy of `cur`.
  var c = cur
  var base = ""
  var field = ""
  c.into:
    if c.kind == Symbol: base = symName(c)
    skip c                                   # base subtree
    field = symName(c); inc c
    while c.hasMore: skip c                   # depth selector
  (base, field)

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

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &global` — adrp+add (nifasm resolves the gvar to its `.bss`/`.data`
  ## address). AArch64 has no typed PC-relative memory operand, so a global is
  ## always accessed by first materializing its address.
  g.emAdr(dest, name)

proc loadOperandReg(g: var CodeGen; v: Location; tmps: var seq[Reg]): Reg =
  ## Materialize `v` into a register for a single memory-operand instruction. The
  ## register is transient — it lives only for the one access this operand feeds,
  ## with no calls in between — so a caller-saved staging register is safe when the
  ## scratch pool is exhausted, keeping indexed/global access total under pressure.
  if v.kind == InReg:
    if v.isTemp: tmps.add v.r
    return v.r
  result = g.tryBorrowTmp(ScalarSlot)
  if result != NoReg: tmps.add result
  else:
    result = g.pickStaging()
    g.ra.seal result          # hold it so a sibling base/index pick can't reuse it
    tmps.add result           # `giveBack` is a no-op for staging; `unseal` below
  g.place(v, result)

proc atNeedsScratch(g: var CodeGen; atNode: Cursor): bool =
  ## Does this `(at base idx)` level need an explicit scratch register? AArch64 (like
  ## x86) folds `base + idx*scale` into one LDR/STR operand only for a scale of
  ## 1/2/4/8 and a single index; a register index whose element stride is anything
  ## else (a multi-dimensional array's outer dimension, stride = the inner array's
  ## size) cannot fold, so arkham hands nifasm a scratch and nifasm computes
  ## `base + idx*stride` into it (the `(at base idx scratch)` 3-operand form). An
  ## immediate index always folds to a displacement → never needs one.
  let stride = typeSizeAlign(g.prog, resolveType(g.prog, g.getType(atNode)))[0]
  if stride in [1, 2, 4, 8]: return false
  var n = atNode
  var idxIsReg = false
  n.into:
    skip n                                      # the array base
    idxIsReg = n.kind != IntLit                 # a non-literal index lives in a register
    while n.hasMore: skip n
  result = idxIsReg

proc prematAccess(g: var CodeGen; n: var Cursor; tmps: var seq[Reg]; regs: var seq[Reg]) =
  ## PASS 1 of address emission. Walk the NIFC lvalue subtree `n` and materialize
  ## every embedded VALUE — a deref'd pointer, a computed array index, a global's
  ## address, a non-scale stride's scratch — into a register NOW, emitting the load
  ## as an ordinary preceding statement (this runs at statement level, before the
  ## consuming instruction tree opens). Registers are appended to `regs` in traversal
  ## order; `emAccessAddr` (pass 2) consumes them in that exact order. Borrowed
  ## scratch is pushed to `tmps` for the caller to free after pass 2. `n` is fully
  ## advanced (over its own copy at the call site).
  case n.kind
  of Symbol:
    let nm = symName(n); inc n
    let loc = g.ra.locationOfSym(nm)
    if loc.kind notin {NamedStack, InReg}:
      # A global aggregate base: materialize its address into a register. (It lives
      # only for the one access this operand feeds, so a transient caller-saved
      # staging register is safe when the pool is empty.)
      let si = g.lookupSym(nm)
      if si.cat != scGlobal:
        raiseAssert "arkham a64 v0: unsupported lvalue base: " & nm
      var r = g.tryBorrowTmp(ScalarSlot)
      if r != NoReg: tmps.add r
      else:
        r = g.pickStaging()
        g.ra.seal r             # hold the base addr so the index pick can't reuse it
        tmps.add r
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
            tmps.add s
          regs.add s
        while n.hasMore: skip n
    of DerefC:
      n.into:
        regs.add g.loadOperandReg(g.genVal(n), tmps)  # the pointer → a register
        while n.hasMore: skip n                  # (cppref)?
    else: raiseAssert "arkham a64 v0: not an lvalue: " & $n.exprKind
  else: raiseAssert "arkham a64 v0: not an lvalue: " & $n.kind

proc emAccessAddr(g: var CodeGen; n: var Cursor; regs: openArray[Reg]; ri: var int) =
  ## PASS 2: re-emit the lvalue subtree `n` as an asm-NIF address expression so
  ## nifasm collapses the chain to `base+offset` (+ index*scale) from the declared
  ## types. Emits ONLY register / stack-symbol / immediate leaves — every embedded
  ## value was already loaded into a register by `prematAccess`, consumed here from
  ## `regs` (same traversal order) — so this pass emits no instruction of its own.
  ## A stack var contributes its bare name; a register-resident pointer its register.
  case n.kind
  of Symbol:
    let nm = symName(n); inc n
    let loc = g.ra.locationOfSym(nm)
    case loc.kind
    of NamedStack: g.ab.sym nm                   # a stack var: nifasm resolves to sp+off
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
          g.ab.sym field
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
      # The deref'd pointer is in a register (pre-loaded). Type it as `(ptr Pointee)`
      # so an enclosing `(dot …)`/`(at …)` can compute the field/element offset.
      var pointee = g.getType(n)                  # deref result = the pointee type
      n.into:
        g.ab.tree CastX:
          g.ab.ptrType:
            if pointee.kind == Symbol: g.ab.sym symName(pointee)
            else: g.genTypeBody(pointee)
          g.emReg regs[ri]; inc ri                # the pointer (pre-loaded)
        skip n                                    # skip the pointer value subtree
        while n.hasMore: skip n                   # (cppref)?
    else: raiseAssert "arkham a64 v0: not an lvalue: " & $n.exprKind
  else: raiseAssert "arkham a64 v0: not an lvalue: " & $n.kind

proc prematAt(g: var CodeGen; nn: Cursor; tmps: var seq[Reg]): seq[Reg] =
  ## Pre-materialize the values embedded in an `(at …)` access chain (pass 1), as
  ## statements emitted BEFORE the consuming instruction tree. Returns the registers
  ## for `emAccessAddr`; free `tmps` (and `unseal` any sealed staging) afterwards.
  result = @[]
  var c = nn
  g.prematAccess(c, tmps, result)

proc freeAtTmps(g: var CodeGen; tmps: seq[Reg]) =
  ## Release scratch borrowed by `prematAt` after pass 2 — unseal a staging reg
  ## held across the operand, and return real pool temps.
  for t in tmps:
    g.ra.unseal {t}
    g.giveBack t

proc emitLoad(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← <scalar Location>` (integer/pointer). One switch over every kind.
  case loc.kind
  of InReg: g.movReg(dest, loc.r)
  of NamedStack: g.emScalarLoad(dest, loc.name)
  of Glob:
    let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree MemX: g.emReg tmp
    g.giveBack tmp
  of Tvar:
    if g.a64Linux:
      # Static-ELF Linux is single-threaded (per-thread == per-process), so a
      # thread-local lives at a fixed `.bss` address like a global — `adr`+load,
      # no TLV thunk (which is Darwin-only). nifasm declares the tvar as a gvar
      # (see `genTvar`), so the symbol resolves via adrp+add.
      let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
      g.ab.tree MovA64:
        g.emReg dest
        g.ab.tree MemX: g.emReg tmp
      g.giveBack tmp
    else:
      g.genTlvAddr(loc.name, dest)             # dest ← &var
      g.ab.tree MovA64:
        g.emReg dest
        g.ab.tree MemX: g.emReg dest            # dest ← [dest]
  of Mem:
    var nn = loc.cur
    case nn.exprKind
    of DotC:
      let (base, field) = dotBaseField(nn)
      g.ab.tree MovA64:
        g.emReg dest
        g.emAggrFieldMem(base, field)
    of AtC:
      var tmps: seq[Reg]
      let regs = g.prematAt(nn, tmps)            # materialize embedded values FIRST
      var ri = 0
      g.ab.tree MovA64:
        g.emReg dest
        g.ab.tree MemX: g.emAccessAddr(nn, regs, ri)
      g.freeAtTmps(tmps)
    of DerefC:
      let (pr, pt) = g.derefPtrCur(nn)
      g.ab.tree MovA64:
        g.emReg dest
        g.ab.tree MemX: g.emReg pr
      if pt: g.giveBack pr
    else: raiseAssert "arkham: emitLoad on Mem expr " & $nn.exprKind
  else: raiseAssert "arkham: integer load from location kind " & $loc.kind

proc emitLoadF(g: var CodeGen; loc: Location; dest: FReg; bits: int) =
  ## `dest ← <float Location>`. `bits` is the contextual precision (s/d view).
  case loc.kind
  of InFReg: g.fmovF(dest, loc.f, bits)
  of NamedStack: g.emFloatScalarLoad(dest, loc.name, bits)
  of Glob:
    let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
    g.emFLoad(dest, tmp, bits)
    g.giveBack tmp
  of Mem:
    var nn = loc.cur
    case nn.exprKind
    of DotC:
      let (base, field) = dotBaseField(nn)
      g.ab.tree FldrA64:
        g.emFReg(dest, bits)
        g.emAggrFieldMem(base, field)
    of AtC:
      var tmps: seq[Reg]
      let regs = g.prematAt(nn, tmps)            # materialize embedded values FIRST
      var ri = 0
      g.ab.tree FldrA64:
        g.emFReg(dest, bits)
        g.ab.tree MemX: g.emAccessAddr(nn, regs, ri)
      g.freeAtTmps(tmps)
    of DerefC:
      let (pr, pt) = g.derefPtrCur(nn)
      g.emFLoad(dest, pr, bits)
      if pt: g.giveBack pr
    else: raiseAssert "arkham: float load on Mem expr " & $nn.exprKind
  else: raiseAssert "arkham: float load from location kind " & $loc.kind

proc emitStore(g: var CodeGen; loc: Location; src: Reg) =
  ## `<scalar Location> ← src` (integer/pointer). `src` already holds the value, so
  ## for a deref/tvar destination the address can be (re)computed safely afterwards.
  case loc.kind
  of InReg: g.movReg(loc.r, src)
  of NamedStack: g.emScalarStore(loc.name, src)
  of Glob:
    let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emReg tmp
      g.emReg src
    g.giveBack tmp
  of Tvar:
    if g.a64Linux:
      # Single-threaded static ELF: store through the tvar's fixed `.bss` address.
      let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
      g.ab.tree MovA64:
        g.ab.tree MemX: g.emReg tmp
        g.emReg src
      g.giveBack tmp
    else:
      g.genTlvAddr(loc.name, IntRet)           # x0 ← &var (clobbers x0/lr, not src)
      g.ab.tree MovA64:
        g.ab.tree MemX: g.emReg IntRet
        g.emReg src
  of Mem:
    var nn = loc.cur
    case nn.exprKind
    of DotC:
      let (base, field) = dotBaseField(nn)
      g.ab.tree MovA64:
        g.emAggrFieldMem(base, field)
        g.emReg src
    of AtC:
      var tmps: seq[Reg]
      let regs = g.prematAt(nn, tmps)            # materialize embedded values FIRST
      var ri = 0
      g.ab.tree MovA64:
        g.ab.tree MemX: g.emAccessAddr(nn, regs, ri)
        g.emReg src
      g.freeAtTmps(tmps)
    of DerefC:
      let (pr, pt) = g.derefPtrCur(nn)
      g.ab.tree MovA64:
        g.ab.tree MemX: g.emReg pr
        g.emReg src
      if pt: g.giveBack pr
    else: raiseAssert "arkham: emitStore on Mem expr " & $nn.exprKind
  else: raiseAssert "arkham: integer store to location kind " & $loc.kind

proc emitStoreF(g: var CodeGen; loc: Location; src: FReg; bits: int) =
  ## `<float Location> ← src`.
  case loc.kind
  of InFReg: g.fmovF(loc.f, src, bits)
  of NamedStack: g.emFloatScalarStore(loc.name, src, bits)
  of Glob:
    let tmp = g.borrowTmp(ScalarSlot); g.emAdr(tmp, loc.name)
    g.emFStore(src, tmp, bits)
    g.giveBack tmp
  of Mem:
    var nn = loc.cur
    case nn.exprKind
    of DotC:
      let (base, field) = dotBaseField(nn)
      g.ab.tree FstrA64:
        g.emAggrFieldMem(base, field)
        g.emFReg(src, bits)
    of AtC:
      var tmps: seq[Reg]
      let regs = g.prematAt(nn, tmps)            # materialize embedded values FIRST
      var ri = 0
      g.ab.tree FstrA64:
        g.ab.tree MemX: g.emAccessAddr(nn, regs, ri)
        g.emFReg(src, bits)
      g.freeAtTmps(tmps)
    of DerefC:
      let (pr, pt) = g.derefPtrCur(nn)
      g.emFStore(src, pr, bits)
      if pt: g.giveBack pr
    else: raiseAssert "arkham: float store on Mem expr " & $nn.exprKind
  else: raiseAssert "arkham: float store to location kind " & $loc.kind

proc emitAddr(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← &<Location>`. The address counterpart to the load/store family.
  ## (Register-resident scalars are spilled when address-taken, and by-reference
  ## aggregates are intercepted by `aggrAddr`, so those never reach here.)
  case loc.kind
  of Tvar:
    # Linux: a tvar's address is its fixed `.bss` address (adrp+add, like a global);
    # Darwin: obtained at run time via the TLV descriptor thunk.
    if g.a64Linux: g.emAdr(dest, loc.name)
    else: g.genTlvAddr(loc.name, dest)
  of Glob: g.emAdr(dest, loc.name)
  of NamedStack:
    g.ab.tree LeaA64:
      g.emReg dest
      g.ab.sym loc.name
  of Mem:
    var nn = loc.cur
    case nn.exprKind
    of DotC:
      let (base, field) = dotBaseField(nn)
      g.ab.tree LeaA64:
        g.emReg dest
        g.emAggrDot(base, field)
    of AtC:
      var tmps: seq[Reg]
      let regs = g.prematAt(nn, tmps)            # materialize embedded values FIRST
      var ri = 0
      g.ab.tree LeaA64:
        g.emReg dest
        g.emAccessAddr(nn, regs, ri)
      g.freeAtTmps(tmps)
    of DerefC:                                # &(deref p) == p
      nn.into:
        g.genInto(nn, dest)
        while nn.hasMore: skip nn
    else: raiseAssert "arkham: address-of Mem expr " & $nn.exprKind
  else: raiseAssert "arkham: cannot take the address of location kind " & $loc.kind

proc rebindLocalAs(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Re-establish register `r`'s binding to the named local `name`, retyped to
  ## `typeCur`, via a zero-machine-code `(rebind …)`. `rebind` auto-kills the transient
  ## tenant `r` currently carries, so no manual `kill` is needed. The scope already
  ## tracks `name` (declared by `emRegLocalVar`), so `scopeLocals` is NOT touched. Type
  ## emission mirrors `emRegLocalVar`: a pointer keeps its precise `(ptr …)`, every
  ## other scalar is the generic `(i 64)` register form.
  g.ab.tree RebindA64:
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
  ## int becomes a pointer). nifasm `rebind` IS that reinterpret — a checked, named,
  ## zero-machine-code retype — so the value is computed straight into `dest` and its
  ## binding flipped across the cast, with NO runtime `mov`:
  ##   rebind dest → source type  (free) · genInto source → dest · rebind dest → tc (free)
  ## Consumes the source at `c`. The x64 twin in codegen_x64.nim — keep them in sync.
  ##
  ## In-place is unsafe only when the SOURCE reads `dest` (a pointer self-update
  ## `p = cast[ptr T](add … p …)`), because rebinding `dest` to the source type kills
  ## the binding the source needs; `refsReg` is the same self-clobber check genBin's
  ## operand-swap uses. That (and a raw, unbound register, which has no binding to flip)
  ## falls back to a scratch register + a single `(cast tc s)` store. A named-local
  ## `dest` is sealed by the enclosing `genInto`, so the source can't evict it.
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
    let s = g.borrowTmp(srcSlot)
    g.genInto(c, s)
    if isPtrType(tc) and srcSlot.kind in {AInt, AUInt} and srcSlot.size < 8:
      g.extendTo(s, srcSlot.size * 8, signed = false)
    var tcc = tc
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree CastX:                             # the NIFC cast, preserved
        g.genTypeBody(tcc)
        g.emReg s
    g.giveBack s

proc genCoerce(g: var CodeGen; c: var Cursor; dest: Reg; isCast: bool) =
  ## Shared lowering for `(conv Type Expr)` / `(cast Type Expr)`. Both evaluate
  ## `Expr` and re-represent it in `Type`'s 64-bit register form. The choice of
  ## sign- vs zero-extension depends on the direction:
  ##  * widening  — extend from the *source* width: a `conv` follows the source
  ##                signedness (value-preserving); a `cast` zero-extends the bits.
  ##  * narrowing/equal — truncate to the target width, extend per the *target*.
  ##  * pointer target — zero-extend a narrower int (int→ptr); else keep the bits.
  ## Integer/char/bool/pointer only (floats `raiseAssert` upstream).
  c.into:
    let tc = resolveType(g.prog, c)           # resolve named types/enums
    let targetSigned = isSignedType(tc)
    let targetW = intTypeWidth(tc)
    let targetPtr = isPtrType(tc)
    skip c                                    # target type
    let srcSlot2 = g.exprSlot(c)
    let srcIsPtr = not cursorIsNil(srcSlot2.typ) and isPtrType(resolveType(g.prog, srcSlot2.typ))
    if g.isFloatExpr(c):
      # float source → integer/pointer target (`dest` is a GPR).
      let fbits = g.floatBits(c)
      let f = g.borrowFTmp(fbits)
      g.genIntoF(c, f, fbits)
      if isCast:
        g.fmovToGpr(dest, f, fbits)           # reinterpret the float's bits
      else:
        g.fcvtF2I(if targetSigned: FcvtzsA64 else: FcvtzuA64, dest, f, fbits)  # truncate
        if targetW < 64 and not targetPtr:
          g.extendTo(dest, targetW, signed = targetSigned)
      g.giveBackF f
    elif targetPtr or srcIsPtr:
      # Any coercion that crosses representations — int→ptr (NIFC encodes pointer
      # arithmetic as `(cast ptr (add (u 64) …))`), ptr→int, or ptr→ptr — reinterprets
      # through the preserved NIFC cast. `coerceThroughCast` is the (rebind-based)
      # mechanism; mirrors the x64 backend.
      g.coerceThroughCast(tc, c, srcSlot2, dest)
      if not targetPtr and targetW < 64:           # ptr→narrow int: extend the result
        g.extendTo(dest, targetW, signed = targetSigned)
    else:
      let (srcW, srcSigned) = g.srcWidthSigned(c)
      g.genInto(c, dest)                      # value → dest
      if srcW < targetW:                      # widening int→int
        g.extendTo(dest, srcW, signed = (not isCast) and srcSigned)
      else:                                   # narrowing or equal width
        g.extendTo(dest, targetW, signed = targetSigned)
    while c.hasMore: skip c

proc genConv(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `(conv Type Expr)` — value-preserving numeric conversion.
  g.genCoerce(c, dest, isCast = false)

proc genCast(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `(cast Type Expr)` — reinterpret the bits in the target type.
  g.genCoerce(c, dest, isCast = true)

# ── floating-point expressions (single + double precision) ──────────────────
# `bits` (32/64) is the value's precision, threaded top-down: it selects s/d
# register views and single/double instructions. A bare literal has no inherent
# width, so it adopts the contextual `bits`.

proc spillFOperandAround(g: var CodeGen; c: var Cursor; dest: FReg;
                         op: A64Inst; bits: int) =
  ## Pool-exhausted evaluation of genFBin's right operand, keeping float register
  ## allocation TOTAL — the SIMD mirror of `spillOperandAround`. `a` is already in
  ## `dest`; spill it to a fresh `(s) (f N)` slot so `dest` is free, evaluate the
  ## (possibly deep) right operand into `dest` — the recursion reuses `dest`, never
  ## pinning a SIMD temp per nesting level — then reassemble `dest = a op b` with a
  ## single transient staging v-register (v0–v7) taken only here, after the recursion
  ## has fully unwound (so it never nests → one reg covers any depth). Operand order
  ## a-before-b is preserved and `a op b` is computed (not `b op a`), so this is
  ## correct for the non-commutative `fsub`/`fdiv` too. `c` is consumed past `b`.
  let slotA = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  g.emFloatStackVar(slotA, bits)               # (var :spill.N (s) (f N))
  g.emFloatScalarStore(slotA, dest, bits)      # [slotA] = a  (free dest)
  g.genIntoF(c, dest, bits)                     # b → dest (recursion reuses dest)
  let s = g.pickFStaging(avoid = dest)          # transient; recursion done → never nests
  if s == NoFReg:
    raiseAssert "arkham a64: no SIMD staging register available for a float spill"
  g.emFloatScalarLoad(s, slotA, bits)           # s = a (reload)
  g.fbin(op, s, dest, bits)                      # s = a op b   (correct operand order)
  g.fmovF(dest, s, bits)                         # dest = a op b

proc genFBin(g: var CodeGen; c: var Cursor; dest: FReg; op: A64Inst; bits: int) =
  ## `(op (f N) a b)` → `dest = a op b` (fadd/fsub/fmul/fdiv). `a` goes into `dest`;
  ## `b` is folded in place (a float local), evaluated into a borrowed SIMD temp, or —
  ## when the scratch pool is exhausted — spilled via `spillFOperandAround`, which
  ## keeps allocation total for arbitrarily deep right-nested float expressions.
  c.into:
    skip c                                    # result float type
    g.genIntoF(c, dest, bits)                  # a → dest
    var inPlace = NoFReg                        # b an in-place float local? fold directly
    if c.kind == Symbol:
      let loc = g.ra.locationOfSym(symName(c))
      if loc.kind == InFReg: inPlace = loc.f
    if inPlace != NoFReg:
      g.fbin(op, dest, inPlace, bits)
      inc c                                    # consume b
    else:
      let fr = g.tryBorrowFTmp(bits)            # b → a SIMD scratch temp …
      if fr == NoFReg:
        g.spillFOperandAround(c, dest, op, bits)   # … or spill (total)
      else:
        g.genIntoF(c, fr, bits)
        g.fbin(op, dest, fr, bits)
        g.giveBackF fr

proc genConvToF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## `(conv (f N) Expr)` — produce a `bits`-wide float in `dest`: int→float
  ## (`scvtf`/`ucvtf`) or float→float (`fcvt` if the precision changes).
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
      g.fcvtI2F(if srcSigned: ScvtfA64 else: UcvtfA64, dest, tmp, bits)
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

proc genFReg(g: var CodeGen; c: var Cursor; bits: int): Location =
  ## Evaluate the float expression `c` into *some* SIMD register, returned as an
  ## `InFReg` `Location`: a symbol's home register in place (`isTemp = false`), or a
  ## borrowed scratch (`isTemp = true`) the caller releases with `freeTemp`. `.f` is
  ## the register.
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InFReg:
      result = fregLoc(loc.f, loc.typ); inc c; return
  let f = g.borrowFTmp(bits)
  g.genIntoF(c, f, bits)
  result = fregLoc(f, AsmSlot(kind: AFloat, size: bits div 8, align: bits div 8), isTemp = true)

proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## Evaluate a `bits`-wide float expression into the SIMD register `dest`.
  # While `dest` holds the value being built, a deep sub-operand may exhaust the SIMD
  # scratch pool and spill — its transient `pickFStaging` register must not clobber
  # `dest`. The v16–v31 pool is never a staging candidate, but a v0–v7 accumulator
  # (a float-arg-register target) IS and is no named local, so record it in `sealedF`
  # for the duration. Save/restore via `protect` so a nested `genIntoF` into the same
  # reg keeps it protected exactly once.
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
    let l = g.asLoc(c)
    g.emitLoadF(l, dest, bits)
  of TagLit:
    case c.exprKind
    of AddC: g.genFBin(c, dest, FaddA64, bits)
    of SubC: g.genFBin(c, dest, FsubA64, bits)
    of MulC: g.genFBin(c, dest, FmulA64, bits)
    of DivC: g.genFBin(c, dest, FdivA64, bits)
    of NegC:
      c.into:
        skip c                                # result type
        g.genIntoF(c, dest, bits)
        g.ab.tree FnegA64: g.emFReg(dest, bits)
    of ConvC: g.genConvToF(c, dest, bits)
    of CastC: g.genCastToF(c, dest, bits)
    of CallC:
      g.genCall(c)                            # float result lands in v0 …
      g.fmovF(dest, FloatRet, bits)           # … move it to the destination
    of DotC:                                  # float struct field: dest ← [base+off]
      let l = g.asLoc(c); g.emitLoadF(l, dest, bits)
    of AtC:                                   # float array element: dest ← arr[idx]
      let l = g.asLoc(c); g.emitLoadF(l, dest, bits)
    of DerefC:                                # `(deref p)` → dest ← [p]
      let l = g.asLoc(c); g.emitLoadF(l, dest, bits)
    else: raiseAssert "arkham v1: float expression not supported: " & $c.exprKind
  else:
    raiseAssert "arkham v1: float operand not supported: " & $c.kind

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
    # array/flexarray decays to its address via genAddr (lenient), so a generic slot is
    # fine there. Mirrors x64's emitPatAddr.
    let baseReg = g.borrowTmp(if isArr: ScalarSlot else: slotOf(g.prog, baseTyC))
    if isArr:
      g.genAddr(c, baseReg)                     # decay: baseReg ← &field
    else:
      g.genInto(c, baseReg)                     # baseReg ← the pointer value
    var idxImm = false
    var idxV = 0'i64
    var idxReg = NoReg
    if c.kind == IntLit: (idxImm = true; idxV = intVal(c); inc c)
    elif c.kind == UIntLit: (idxImm = true; idxV = cast[int64](uintVal(c)); inc c)
    else: (idxReg = g.borrowTmp(ScalarSlot); g.genInto(c, idxReg))
    g.ab.tree LeaA64:
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
  # `dest`. Pool temps (x9–x15) are never staging candidates, but an arg/return
  # register IS, and is not in `regLocal` (it is no named local) — so record it as
  # a live accumulator for the duration. Save/restore (not unconditional excl) so a
  # nested `genInto` into the same reg (SU swap / operandInReg) keeps it protected.
  let protect = dest in {R0..R7} and dest notin g.liveAccums
  if protect: g.liveAccums.incl dest
  # Protect a register-local *home* (x9–x28) from a codegen-time *steal* during the
  # build of its own value: the result lands in `dest`, so an initializer/rvalue
  # whose scratch demand (e.g. an arm64 atomic LL/SC loop) would otherwise evict
  # `dest` must not — else the final write would target a stale, evicted register.
  # `liveAccums` only guards arg/return regs; a steal can still evict a callee-saved
  # home, so seal it here. Save/restore (not unconditional unseal) so a nested
  # `genInto` into the same reg keeps it sealed.
  let sealHome = g.regLocal.hasKey(dest) and not g.ra.isSealed(dest)
  if sealHome: g.ra.seal dest
  case c.kind
  of IntLit:
    g.movImm(dest, intVal(c)); inc c
  of UIntLit:
    g.movImm(dest, cast[int64](uintVal(c))); inc c
  of CharLit:
    g.movImm(dest, int64(ord(charLit(c)))); inc c
  of StrLit:
    let nm = "msg." & $g.rodata.len
    if not g.ab.planning: g.rodata.add (nm, strVal(c))   # plan pass emits no rodata
    g.emAdr(dest, nm); inc c
  of Symbol:
    let l = g.asLoc(c)
    g.emitLoad(l, dest)
  of TagLit:
    case c.exprKind
    of AddC: g.genBin(c, dest, AddA64)
    of SubC: g.genBin(c, dest, SubA64)
    of MulC: g.genBin(c, dest, MulA64)
    of DivC: g.genBin(c, dest, SdivA64, UdivA64)
    of ModC: g.genMod(c, dest)
    of ShlC: g.genBin(c, dest, LslA64)
    of ShrC: g.genBin(c, dest, AsrA64, LsrA64)
    of BitandC: g.genBin(c, dest, AndA64)
    of BitorC: g.genBin(c, dest, OrrA64)
    of BitxorC: g.genBin(c, dest, EorA64)
    of BitnotC: g.genBitnot(c, dest)
    of NegC: g.genNeg(c, dest)
    of NotC: g.genNot(c, dest)
    of EqC, NeqC, LtC, LeC, AndC, OrC:      # comparison/logic as a value → 0/1
      g.materializeCond(c, dest)
    of ConvC: g.genConv(c, dest)
    of CastC: g.genCast(c, dest)
    of CallC:
      g.genCall(c)                          # result lands in x0 …
      g.movReg(dest, IntRet)                # … move it to the destination
    of DotC:                                # field load: dest ← [base+offset]
      let l = g.asLoc(c); g.emitLoad(l, dest)
    of DerefC:                              # `(deref p)` → dest ← [p]
      let l = g.asLoc(c); g.emitLoad(l, dest)
    of AddrC:                               # `(addr lvalue)` → dest ← &lvalue
      c.into:
        g.genAddr(c, dest)
        while c.hasMore: skip c             # (cppref)?
    of AtC:                                 # `(at arr idx)` → dest ← arr[idx]
      let l = g.asLoc(c); g.emitLoad(l, dest)
    of PatC:                                 # pointer index: &elem into dest, then load
      g.emitPatAddr(c, dest)
      g.ab.tree MovA64: (g.emReg dest; g.ab.tree MemX: g.emReg dest)
    of SufC, ParC:                            # `(suf v "type")` / `(par v)` wrap one value
      c.into:
        g.genInto(c, dest)
        while c.hasMore: skip c               # the type suffix / trailing tokens
    of TrueC: g.movImm(dest, 1); skip c       # boolean / nil literals → immediate
    of FalseC: g.movImm(dest, 0); skip c
    of NilC: g.movImm(dest, 0); skip c
    else: raiseAssert "arkham v1: expression not supported: " & $c.exprKind
  else:
    raiseAssert "arkham v1: operand not supported: " & $c.kind
  if sealHome: g.ra.unseal {dest}
  if protect: g.liveAccums.excl dest

proc genAddr(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `dest ← &lvalue`, with `c` positioned at the lvalue. Parse the addressing
  ## mode once, then let `emitAddr` form the address. `pat` (pointer indexing)
  ## can't fold into a single memory operand — its base pointer needs a register —
  ## so it is formed eagerly by `emitPatAddr`.
  if c.kind == TagLit and c.exprKind == PatC:
    g.emitPatAddr(c, dest)
  else:
    let l = g.asLoc(c)
    g.emitAddr(l, dest)

# ── calls ────────────────────────────────────────────────────────────────────

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
           "arkham a64: indirect call through a non-proctype value"
    var q = pt                                  # consume a copy; `result` keeps a cursor
    q.into:
      skip q                                    # Empty (the proc-name slot)
      skip q                                    # Params
      result = q                                # RetType (`.` / `(void)` / a real type)
      while q.hasMore: skip q                   # drain RetType + Pragmas
    while d.hasMore: skip d

proc genProctypeSig(g: var CodeGen; c: var Cursor) =
  ## Lower a NIFC `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
  ## signature `(proctype (params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (x0)
  ## T))? (clobber …))` — the AAPCS64 assignment, identical in shape to a
  ## declarative proc's signature (`emitSignature`), so nifasm can resolve an
  ## *indirect* `(prepare …)` call through a function pointer against it. A function
  ## pointer is still 8 bytes (nifasm sizes `ProcT` as a pointer); the signature is
  ## metadata for call sites.
  g.ab.proctypeType:
    c.into:
      skip c                                    # the Empty slot (a proc has its name here)
      g.ab.tree ParamsD:
        if c.kind == TagLit:                    # (params (param …) …)
          var idx = 0
          c.into:
            while c.hasMore:
              c.into:                           # (param :name pragmas type)
                inc c                           # name → positional pN.0
                skip c                          # pragmas
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  if idx < IntArgRegs.len: g.ab.reg IntArgRegs[idx]  # raw reg *location*
                  else: g.ab.keyword SO         # 9th+ → stack-passed
                  g.genPointee(c)              # param type BY REFERENCE (named → sym);
                                               # a self-referential closure sig can't recurse
                while c.hasMore: skip c
              inc idx
        else:
          skip c
      g.ab.tree ResultD:
        # The RetType is always the node after Params (a `.`/`(void)` for void).
        if retIsVoid(c):
          skip c                                # consume the void `.`/`(void)` node
        else:
          g.ab.symDef "ret.0"
          g.ab.reg IntRet                       # raw reg *location* of the result
          g.genPointee(c)                       # return type BY REFERENCE (named → sym)
      while c.hasMore: skip c                    # pragmas
    g.ab.tree ClobberD:
      for r in ConvClobbersGpr: g.ab.reg r   # a clobber *declaration*: raw reg locations

proc emitSyprocA64(g: var CodeGen; sp: SyscallProc) =
  ## Emit a `(syproc :name (params …) (result …)? NR)` decl for a Linux syscall:
  ## params in the syscall ABI registers (x0–x5, identical to AAPCS64's arg regs),
  ## result in x0, and the AArch64 syscall number. A `svc` preserves every register
  ## but x0, so no `(clobber …)` is emitted (the `(svc)` marker marks x0 itself).
  ## Invoked inline at call sites via the `(svc 0)` marker; emits no code.
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
                if idx >= IntArgRegs.len:
                  raiseAssert "arkham a64: syscall with too many arguments"
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  g.ab.reg IntArgRegs[idx]
                  g.genTypeBody(pc)
                while pc.hasMore: skip pc
              inc idx
      g.ab.tree ResultD:                         # c at the return type
        if not retIsVoid(c):
          g.ab.symDef "ret.0"
          g.ab.reg IntRet
          g.genTypeBody(c)
      g.ab.intLit sp.sysNrA64.int64
    while c.hasMore: skip c                       # drain the importc decl's pragmas + body

proc genCall(g: var CodeGen; c: var Cursor) =
  ## `(call f arg…)` — internal `(call)` or external `(extcall)`. Integer/
  ## pointer args go straight into x0,x1,… left-to-right (no nested calls — the
  ## optimizer flattens them), each committed arg register sealed so scratch use
  ## during marshalling can't clobber it. The result lands in x0.
  c.into:
    let fsym = symName(c); inc c
    if not g.callTarget.hasKey(fsym):
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        # The callee is a *variable* holding a function pointer. Its proctype is a
        # full signature, so it has the same typing as a direct call and goes
        # through the SAME declarative `(prepare …)` path — only the call
        # instruction differs (nifasm emits an indirect call when the prepare
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
      g.genAtomic(c, tgt.atomic)               # consumes the args; result in x0
    elif tgt.memIntrin.len > 0:                # C mem* intrinsic → inline byte loop
      g.genMemIntrin(c, tgt.memIntrin)         # consumes the args; result in x0
    elif tgt.bitBuiltin.len > 0:               # GCC bit builtin: needs rbit/clz (unwired)
      raiseAssert "arkham arm64 v0: bit builtin not yet implemented: " & tgt.bitBuiltin
    elif tgt.declarative:
      # Declarative call: bind each scalar argument to its positional param `p{i}`
      # and the result to `ret.0`, so nifasm cross-checks the ABI. The `(mov (arg
      # p{i}) x{i})` / `(mov (x0) (res ret.0))` bindings target the value's own
      # register, so they assemble to nothing (self-move elision) yet still mark
      # the argument/result as satisfied.
      var sealedHere: set[Reg] = {}
      var stackTmps: seq[Reg] = @[]            # held values for stack args
      var stackArgIdx: seq[int] = @[]          # their positional param index
      g.ab.tree PrepareA64:
        g.ab.sym tgt.asmName
        var idx = 0
        # Phase 1 — evaluate every argument into a register. The first 8 bind to
        # x0–x7 (self-move-elided); the rest land in sealed temps held until the
        # outgoing stack area is reserved. All evaluation happens before any SP
        # adjustment, so reads of the caller's own locals stay correctly offset.
        while c.hasMore:
          if idx < IntArgRegs.len:
            g.genInto(c, IntArgRegs[idx])      # value → x{idx}
            g.ab.tree MovA64:
              g.ab.tree ArgX: g.ab.sym paramName(idx)
              g.emReg IntArgRegs[idx]
            g.ra.seal IntArgRegs[idx]; sealedHere.incl IntArgRegs[idx]
          else:
            let t = g.borrowTmp(ScalarSlot)
            g.genInto(c, t)
            g.ra.seal t; sealedHere.incl t
            stackTmps.add t; stackArgIdx.add idx
          inc idx
        # Phase 2 — reserve the outgoing stack area and store the held args into
        # it. nifasm resolves `(arg p.k)` to each stack slot's byte offset.
        if stackTmps.len > 0:
          g.ab.tree SubA64: g.emReg SP; g.ab.keyword CsizeX
          for k in 0 ..< stackTmps.len:
            g.ab.tree MovA64:
              g.ab.tree MemX:
                g.emReg SP
                g.ab.tree ArgX: g.ab.sym paramName(stackArgIdx[k])
              g.emReg stackTmps[k]
        if tgt.syscall:
          g.ab.tree SvcA64: g.ab.intLit 0       # `(svc)`: kernel trap, no `bl`
        else:
          g.ab.keyword CallA64
        if stackTmps.len > 0:
          g.ab.tree AddA64: g.emReg SP; g.ab.keyword CsizeX
        if not retIsVoid(tgt.retType):
          g.ab.tree MovA64:
            g.emReg IntRet
            g.ab.tree ResX: g.ab.sym "ret.0"
      for t in stackTmps: g.giveBack t
      g.ra.unseal sealedHere
    else:
      var idx = 0
      var fidx = 0
      var sealedHere: set[Reg] = {}
      var sealedFHere: set[FReg] = {}
      while c.hasMore:
        if g.isFloatExpr(c):
          # A float argument goes in v{fidx}. v0–v7 are disjoint from the GPR scratch
          # pool (v16–v31), but a *later* float argument that spills (genFBin's
          # `spillFOperandAround`) takes its transient reload register from v0–v7 via
          # `pickFStaging` — so seal each marshalled float arg in `sealedF` to keep
          # that pick from clobbering it (the SIMD analogue of sealing GPR args).
          assert fidx < FloatArgRegs.len, "arkham v1: >8 float args (stack passing TODO)"
          let fr = FloatArgRegs[fidx]
          g.genIntoF(c, fr, g.floatBits(c))
          g.sealedF.incl fr; sealedFHere.incl fr
          inc fidx
        elif c.kind == Symbol and g.varType.hasKey(symName(c)):
          let vn = symName(c)
          let tn = g.varType[vn]
          if aggrByteSize(g.prog, tn) > 16:
            # >16B → by reference: pass a pointer to it in x{idx}.
            # v1 passes &original; AAPCS64's caller-made copy is a TODO.
            assert idx < IntArgRegs.len, "arkham v1: >8 args (stack passing TODO)"
            let loc = g.ra.locationOfSym(vn)
            case loc.kind
            of NamedStack:
              g.ab.tree LeaA64:
                g.emReg IntArgRegs[idx]
                g.ab.sym vn
            of InReg: g.movReg(IntArgRegs[idx], loc.r)   # already a pointer
            else: raiseAssert "arkham v1: by-ref arg neither stack nor pointer: " & vn
            g.ra.seal IntArgRegs[idx]; sealedHere.incl IntArgRegs[idx]
            inc idx
          else:
            # ≤16B → by value: marshal its words into x{idx..}
            let nw = aggrWordCount(g.prog, tn)
            assert idx + nw <= IntArgRegs.len, "arkham v1: aggregate arg exceeds GPRs"
            g.structToRegs(vn, tn, idx)
            for k in 0 ..< nw:
              g.ra.seal IntArgRegs[idx + k]; sealedHere.incl IntArgRegs[idx + k]
            idx += nw
          inc c
        else:
          assert idx < IntArgRegs.len, "arkham v1: >8 integer args (stack passing TODO)"
          let ar = IntArgRegs[idx]
          g.genInto(c, ar)
          g.ra.seal ar; sealedHere.incl ar
          inc idx
      g.ab.tree PrepareA64:
        g.ab.sym tgt.asmName
        g.ab.keyword (if tgt.extern: ExtcallA64 else: CallA64)
      g.ra.unseal sealedHere
      g.sealedF = g.sealedF - sealedFHere

# ── statements ──────────────────────────────────────────────────────────────

proc genOconstr(g: var CodeGen; c: var Cursor; destVar: string) =
  ## `(oconstr Type (kv Field Value)*)` → store each field value into the
  ## aggregate stack var `destVar` (field-wise; no temporary copy).
  c.into:
    skip c                                  # the constructed type
    while c.hasMore:
      assert c.substructureKind == KvU, "arkham v1: oconstr expects (kv …) pairs"
      c.into:                               # (kv Field Value [InheritDepth])
        let field = symName(c); inc c
        let rr = g.genReg(c)                # value → register
        g.ab.tree MovA64:
          g.emAggrFieldMem(destVar, field)
          g.emReg rr.r
        g.freeTemp(rr)
        while c.hasMore: skip c             # optional inherited-object INTLIT

proc genPointee(g: var CodeGen; c: var Cursor) =
  ## Emit a pointer's pointee / element type. A *named* type is referenced by
  ## symbol rather than inlined: this breaks the infinite recursion of
  ## self-referential types (a `(ptr T)` field inside `T`, e.g. the TLSF
  ## `SmallChunk`/`AvlNode`) and lets nifasm resolve — and auto-import across
  ## modules — the type declaration by name. Mirrors the x64 backend.
  if c.kind == Symbol:
    g.ab.sym symName(c); inc c
  else:
    g.genTypeBody(c)

proc genTypeBody(g: var CodeGen; c: var Cursor) =
  ## Translate a NIFC type at `c` into asm-NIF, advancing `c` past it. Named
  ## types are inlined (resolved against `typeDecls`); object field pragmas are
  ## dropped. v1: int/uint/bool/ptr scalars and objects.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, symName(c))  # resolves across modules
    d.into:                                 # (type SymbolDef TypePragmas body)
      inc d                                 # name
      skip d                                # TypePragmas (one slot: `.` or (pragmas …))
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
        c.into: g.genPointee(c)             # pointee (named → by-reference)
    of AptrT:                               # pointer to (array of) — a scalar ptr
      g.ab.aptrType:
        c.into: g.genPointee(c)             # element type (named → by-reference)
    of FlexarrayT:                          # variable-length array tail (last fld)
      g.ab.flexarrayType:
        c.into: g.genTypeBody(c)            # element type
    of ProctypeT:
      # A function pointer (8 bytes). Emit its full ABI signature — not an opaque
      # `(ptr (void))` — so nifasm can type-check and resolve an indirect call
      # `(prepare <fnptr> … (call))` against it.
      g.genProctypeSig(c)
    of ArrayT:
      c.into:                               # NIFC `(array Type Expr)`
        g.ab.arrayType:
          g.genTypeBody(c)                  # element type
          if c.kind == IntLit:
            g.ab.intLit intVal(c); inc c
          else:
            raiseAssert "arkham v1: array length must be a literal"
    of EnumT:
      c.into:                               # NIFC `(enum BaseType efld*)`
        g.genTypeBody(c)                    # collapse to the base integer type
        while c.hasMore: skip c             # efld members
    of ObjectT:
      c.into:
        # Inheritance: a Symbol base is emitted by reference (nifasm resolves it
        # and lays the base out first); a `.` means no base. Preserving it lets
        # nifasm compute inherited-field offsets for the `(cast (ptr Derived)
        # x).baseField` idiom.
        var baseName = ""
        if c.kind == Symbol: baseName = symName(c)
        skip c                              # inheritance slot (`.` or base sym)
        g.ab.objectType:
          if baseName.len > 0: g.ab.sym baseName
          while c.hasMore:
            c.into:                         # (fld :name pragmas type)
              let fn = symName(c); inc c
              skip c                        # field pragmas (dropped)
              g.ab.fldDef(fn):
                g.genTypeBody(c)            # field type
    else:
      raiseAssert "arkham v1: type not supported: " & $c.typeKind
  else:
    raiseAssert "arkham v1: malformed type"

# ── AAPCS64 small-aggregate (≤16B) marshalling ──────────────────────────────
# A ≤16-byte aggregate travels in 1–2 consecutive GPRs; word i ↔ the field at
# byte offset 8·i (word-aligned fields only for now — sub-word packing and the
# >16-byte by-reference / x8-indirect paths `raiseAssert`). Layout/size live in
# slots.nim so the register allocator shares them.

proc structToRegs(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## Aggregate → x{firstArg+i} (one GPR per 8-byte word).
  let lay = aggrLayout(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham v1: sub-word-packed aggregate ABI unsupported"
    g.ab.tree MovA64:
      g.emReg IntArgRegs[firstArg + i]
      g.emAggrFieldMem(varName, fn)

proc regsToStruct(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## x{firstArg+i} → aggregate (one GPR per 8-byte word).
  let lay = aggrLayout(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham v1: sub-word-packed aggregate ABI unsupported"
    g.ab.tree MovA64:
      g.emAggrFieldMem(varName, fn)
      g.emReg IntArgRegs[firstArg + i]

proc copyStructThroughPtr(g: var CodeGen; srcVar, typeName: string; ptrReg: Reg) =
  ## Field-wise copy of the aggregate `srcVar` to the memory `ptrReg` points at
  ## (any layout — sub-word fields are fine, it copies per field).
  for f in aggrLayout(g.prog, typeName):
    let tmp = g.borrowTmp(ScalarSlot)
    g.ab.tree MovA64: (g.emReg tmp; g.emAggrFieldMem(srcVar, f.name))
    g.ab.tree MovA64: (g.emPtrFieldMem(ptrReg, typeName, f.name); g.emReg tmp)
    g.giveBack tmp

# ── named register locals (typed nifasm vars; transient scratch stays `(xN)`) ─

proc emRegLocalVar(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## `(var :name (reg) type)` + bind `r` to `name` for its scope. arkham keeps
  ## scalars 64-bit in registers (width/signedness via explicit extends), so an
  ## int/uint/bool/char local is declared `(i 64)`; a pointer keeps `(ptr T)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register.
  if g.regLocal.hasKey(r):
    g.ab.tree KillA64: g.ab.sym g.regLocal[r]
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.reg r
  let rt = resolveType(g.prog, typeCur)
  if isPtrType(rt):
    var tc = typeCur
    g.genTypeBody(tc)
  else: g.ab.intType(64)
  g.ab.close()
  g.regLocal[r] = name
  g.scopeLocals[^1].add (name: name, reg: r)

proc emFRegLocalVar(g: var CodeGen; name: string; f: FReg; bits: int) =
  ## Declare a float register local: bind v-register `f` to `name` via `(rebind …)` for
  ## the rest of its scope, so subsequent uses emit the typed name instead of a raw
  ## `(dN)`/`(sN)`. The SIMD twin of `emRegLocalVar`. `rebind` kills `f`'s prior tenant
  ## itself, so no manual prior-kill is needed.
  g.ab.tree RebindA64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.freg(f, bits)
  g.fregLocal[f] = name
  g.freeFTmp.excl f                             # a local's home is no longer scratch
  g.scopeFLocals[^1].add (name: name, f: f)

proc enterScope(g: var CodeGen) =
  g.scopeLocals.add @[]
  g.scopeFLocals.add @[]

proc exitScope(g: var CodeGen) =
  ## Skip any local whose register was already rebound to a later one (already
  ## killed at that rebind via emRegLocalVar).
  for it in g.scopeLocals.pop():
    if g.regLocal.getOrDefault(it.reg, "") == it.name:
      g.ab.tree KillA64: g.ab.sym it.name
      g.regLocal.del it.reg
  for it in g.scopeFLocals.pop():
    if g.fregLocal.getOrDefault(it.f, "") == it.name:
      g.ab.tree KillA64: g.ab.sym it.name
      g.fregLocal.del it.f

proc genVarDecl(g: var CodeGen; c: var Cursor) =
  ## `(var :name pragmas type value)`. Scalars land in their allocated register;
  ## aggregates become a nifasm-managed `(var :name (s) type)` stack var, with
  ## field stores doing the initialization (v1: no `oconstr` initializer).
  c.into:
    let name = symName(c); inc c            # name
    skip c                                  # pragmas
    let typeCur = c                         # capture the type before skipping
    g.symType[name] = typeCur               # record for getType
    skip c                                  # type
    let loc = g.ra.locationOfSym(name)
    case loc.kind
    of NamedStack:
      if loc.typ.kind == AFloat:
        # spilled float scalar: a nifasm `(s) (f N)` slot + a store of its
        # initializer (computed into a scratch SIMD register first).
        let bits = loc.typ.size * 8
        g.emFloatStackVar(name, bits)
        if c.kind == DotToken: inc c          # no initializer
        else:
          let f = g.borrowFTmp(bits)
          g.genIntoF(c, f, bits)
          g.emFloatScalarStore(name, f, bits)
          g.giveBackF f
      elif loc.typ.kind != AMem:
        # spilled integer/pointer scalar: a nifasm `(s)` slot + a store of its
        # initializer (computed into a scratch register first). A pointer's slot must
        # carry its PRECISE type — nifasm is strict, so a generic `(i 64)` slot would
        # reject the now precisely-typed store (`coerceThroughCast` types the value) and
        # forbid a later deref. Integers keep the 8-byte `(i 64)` slot. Mirrors x64.
        let isPtr = isPtrType(resolveType(g.prog, typeCur))
        if isPtr: g.emTypedStackVar(name, typeCur)
        else: g.emScalarStackVar(name)
        if c.kind == DotToken: inc c          # no initializer
        else:
          let tmp = g.borrowTmp(if isPtr: slotOf(g.prog, typeCur) else: ScalarSlot)
          g.genInto(c, tmp)
          g.emScalarStore(name, tmp)
          g.giveBack tmp
      else:
        g.ab.open NifasmDecl.VarD
        g.ab.symDef name
        g.ab.keyword SO                       # `(s)` — nifasm-managed stack slot
        var tc = typeCur                       # nifasm wants a *named* type ref
        if tc.kind == Symbol: g.ab.sym symName(tc)
        else: g.genTypeBody(tc)               # inline only for scalar aggregates
        g.ab.close()
        let typeName = if tc.kind == Symbol: symName(tc) else: ""
        if typeName.len > 0: g.varType[name] = typeName
        if c.kind == DotToken: inc c          # no initializer
        elif c.exprKind == OconstrC: g.genOconstr(c, name)
        elif c.exprKind == CallC:             # receive an aggregate return
          assert typeName.len > 0, "arkham v1: call-returned aggregate needs a named type"
          if aggrByteSize(g.prog, typeName) > 16:
            # >16B: hand the callee a pointer to this var via x8; it writes there.
            g.ab.tree LeaA64: g.emReg IndirectResultReg; g.ab.sym name
            g.genCall(c)
          else:
            g.genCall(c)
            g.regsToStruct(name, typeName, 0)
        else:                                 # copy-init from another aggregate: `var b = a`
          assert typeName.len > 0, "arkham v1: aggregate copy-init needs a named type: " & name
          let dstA = g.borrowTmp(ScalarSlot)
          g.ab.tree LeaA64: (g.emReg dstA; g.ab.sym name)
          let (srcA, srcT) = g.aggrAddr(c)
          g.byteCopyConst(dstA, srcA, aggrByteSize(g.prog, typeName))
          if srcT: g.giveBack srcA
          g.giveBack dstA
    of InReg:
      g.emRegLocalVar(name, loc.r, typeCur)   # (var :name (reg) type) — typed for nifasm
      if c.kind == DotToken: inc c          # no initializer
      else: g.genInto(c, loc.r)
    of InFReg:
      g.emFRegLocalVar(name, loc.f, loc.typ.size * 8)  # (rebind :name (f bits) (dN))
      if c.kind == DotToken: inc c          # no initializer
      else: g.genIntoF(c, loc.f, loc.typ.size * 8)   # float local
    else: raiseAssert "arkham v1: stack-resident local: " & name

proc genStmt(g: var CodeGen; c: var Cursor)

proc genActionStmts(g: var CodeGen; c: var Cursor) =
  ## Emit the statements of an `(elif … action)` / `(else action)` body,
  ## flattening a `(stmts …)` arg.
  if c.stmtKind == StmtsS:
    c.into:
      while c.hasMore: genStmt(g, c)
  else:
    genStmt(g, c)

# ── control flow: labels + goto ─────────────────────────────────────────────

proc freshLabel(g: var CodeGen): string =
  # Name must be a NIF *symbol* (needs a '.'), but `extractBasename` strips a
  # trailing `.<digits>`, so put the counter *before* the suffix ("L0.0", …)
  # to keep basenames ("L0", "L1") distinct.
  result = "L" & $g.labelCount & ".0"
  if not g.ab.planning: inc g.labelCount   # plan pass emits no labels → don't burn names

proc emLab(g: var CodeGen; name: string) =
  g.ab.tree LabA64: g.ab.symDef name        # (lab :L)

proc emBr(g: var CodeGen; tag: A64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name              # (b L) / (beq L) / …

# ── atomics: GCC __atomic_* builtins → AArch64 load/store-exclusive loops ─────
# arkham lowers the call-shaped atomic builtins (see programs.collect) the way
# the LLVM backend does, but to a portable LL/SC retry loop. Memory ordering is
# always the strong acquire/release form (matching the backend's seq_cst); the
# `memorder` argument is ignored. Every variant leaves its result in x0.

proc genAtomicRmw(g: var CodeGen; pReg, val: Reg; isXchg: bool;
                  op: A64Inst; returnNew: bool) =
  ## `loop: ldaxr old,[p]; new = old op val (or val for xchg); stlxr st,new,
  ## [p]; cbnz st,loop`. Result (old or new) → x0. `pReg`/`val` stay live.
  let xOld = g.borrowTmp(ScalarSlot)
  let xNew = g.borrowTmp(ScalarSlot)
  let xStatus = g.borrowTmp(ScalarSlot)
  let loop = g.freshLabel()
  let (p, v, old, neu, st) = (g.emOp pReg, g.emOp val,
                              g.emOp xOld, g.emOp xNew, g.emOp xStatus)
  let update =                              # new ← val (xchg) | old op val (rmw)
    if isXchg: &"(mov {neu} {v})"
    else:      &"(mov {neu} {old}) ({op} {neu} {v})"
  g.ab.splice &"(lab :{loop}) " &
              &"(ldaxr {old} {p}) " &
              update & " " &
              &"(stlxr {st} {neu} {p}) " &
              &"(cmp {st} 0) (bne {loop})"   # retry on store-exclusive failure
  g.movReg(IntRet, if returnNew: xNew else: xOld)
  g.giveBack xStatus; g.giveBack xNew; g.giveBack xOld

proc genAtomicCmpXchg(g: var CodeGen; c: var Cursor) =
  ## `__atomic_compare_exchange_n(ptr, expected_ptr, desired, weak, succ, fail)`.
  ## Returns 1 on success, 0 on failure; on failure *expected is updated.
  let pReg = g.genReg(c)
  let expPtr = g.genReg(c)
  let des = g.genReg(c)
  skip c; skip c; skip c                    # weak, success order, failure order
  let xExp = g.borrowTmp(ScalarSlot)
  let xOld = g.borrowTmp(ScalarSlot)
  let xStatus = g.borrowTmp(ScalarSlot)
  let loop = g.freshLabel()
  let lFail = g.freshLabel()
  let lDone = g.freshLabel()
  let (p, ep, d) = (g.emOp pReg.r, g.emOp expPtr.r, g.emOp des.r)
  let (exp, old, st, ret) = (g.emOp xExp, g.emOp xOld,
                             g.emOp xStatus, g.emOp IntRet)
  g.ab.splice(
    &"(ldar {exp} {ep}) " &                  # expected = *expected_ptr
    &"(lab :{loop}) (ldaxr {old} {p}) " &
    &"(cmp {old} {exp}) (bne {lFail}) " &          # mismatch → fail
    &"(stlxr {st} {d} {p}) " &
    &"(cmp {st} 0) (bne {loop}) " &                # store-exclusive lost → retry
    &"(mov {ret} 1) (b {lDone}) " &
    &"(lab :{lFail}) (clrex) " &                   # drop the exclusive reservation
    &"(stlr {old} {ep}) " &                        # *expected = actual old value
    &"(mov {ret} 0) (lab :{lDone})")
  g.giveBack xStatus; g.giveBack xOld; g.giveBack xExp
  g.freeTemp(des)
  g.freeTemp(expPtr)
  g.freeTemp(pReg)

proc genAtomic(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower one `__atomic_*` builtin call. `c` is positioned at the first
  ## argument; this consumes all of them. Result (if any) lands in x0.
  case builtin
  of "__atomic_load_n":                      # (ptr, memorder) → *ptr
    let pReg = g.genReg(c); skip c
    g.emLdar(IntRet, pReg.r)
    g.freeTemp(pReg)
  of "__atomic_store_n":                     # (ptr, val, memorder) → void
    let pReg = g.genReg(c)
    let val = g.genReg(c); skip c
    g.emStlr(val.r, pReg.r)
    g.freeTemp(val)
    g.freeTemp(pReg)
  of "__atomic_clear":                       # (ptr, memorder) → void; *ptr = 0
    let pReg = g.genReg(c); skip c
    let z = g.borrowTmp(ScalarSlot); g.movImm(z, 0)
    g.emStlr(z, pReg.r)
    g.giveBack z
    g.freeTemp(pReg)
  of "__atomic_thread_fence":                # (memorder) → void
    skip c
    g.ab.keyword DmbA64
  of "__atomic_signal_fence":                # (memorder) → void; compiler barrier
    skip c                                   # no hardware fence needed
  of "__atomic_exchange_n",
     "__atomic_fetch_add", "__atomic_fetch_sub",
     "__atomic_fetch_and", "__atomic_fetch_or", "__atomic_fetch_xor",
     "__atomic_add_fetch", "__atomic_sub_fetch":
    let pReg = g.genReg(c)
    let val = g.genReg(c); skip c            # ptr, val, memorder
    case builtin
    of "__atomic_exchange_n":  g.genAtomicRmw(pReg.r, val.r, true, NoA64Inst, false)
    of "__atomic_fetch_add":   g.genAtomicRmw(pReg.r, val.r, false, AddA64, false)
    of "__atomic_fetch_sub":   g.genAtomicRmw(pReg.r, val.r, false, SubA64, false)
    of "__atomic_fetch_and":   g.genAtomicRmw(pReg.r, val.r, false, AndA64, false)
    of "__atomic_fetch_or":    g.genAtomicRmw(pReg.r, val.r, false, OrrA64, false)
    of "__atomic_fetch_xor":   g.genAtomicRmw(pReg.r, val.r, false, EorA64, false)
    of "__atomic_add_fetch":   g.genAtomicRmw(pReg.r, val.r, false, AddA64, true)
    of "__atomic_sub_fetch":   g.genAtomicRmw(pReg.r, val.r, false, SubA64, true)
    else: discard
    g.freeTemp(val)
    g.freeTemp(pReg)
  of "__atomic_test_and_set":                # (ptr, memorder) → bool (old != 0)
    let pReg = g.genReg(c); skip c
    let one = g.borrowTmp(ScalarSlot); g.movImm(one, 1)
    g.genAtomicRmw(pReg.r, one, true, NoA64Inst, false)  # x0 = old
    let xOld = g.borrowTmp(ScalarSlot); g.movReg(xOld, IntRet)
    let lSkip = g.freshLabel()
    let (old, ret) = (g.emOp xOld, g.emOp IntRet)
    g.ab.splice &"(mov {ret} 0) (cmp {old} 0) (beq {lSkip}) (mov {ret} 1) (lab :{lSkip})"
    g.giveBack xOld; g.giveBack one
    g.freeTemp(pReg)
  of "__atomic_compare_exchange_n":
    g.genAtomicCmpXchg(c)
  else:
    raiseAssert "arkham: unsupported atomic builtin: " & builtin

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers to a short inline AArch64 byte loop
# (register-offset ldrb/strb). Sizes are runtime values; result lands in x0
# (memcpy/memmove/memset return dest, memcmp returns the first byte difference).

proc genMemIntrin(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower one `mem*` intrinsic call. `c` is at the first argument; this consumes
  ## all of them.
  case builtin
  of "memcpy":                                 # (dst, src, n) → dst
    let dstL = g.genReg(c)
    let srcL = g.genReg(c)
    let nL = g.genReg(c)
    let (dst, src, n) = (dstL.r, srcL.r, nL.r)
    let i = g.borrowTmp(ScalarSlot)
    let b = g.borrowTmp(ScalarSlot)
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: g.emReg i; g.emReg n
    g.emBr(BhsA64, done)                        # i >= n (unsigned) → done
    g.emLdrb(b, src, i)
    g.emStrb(b, dst, i)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(done)
    g.movReg(IntRet, dst)                       # memcpy returns dest
    g.giveBack b; g.giveBack i
    g.freeTemp(nL); g.freeTemp(srcL); g.freeTemp(dstL)
  of "memmove":                                # (dst, src, n) → dst; overlap-safe
    let dstL = g.genReg(c)
    let srcL = g.genReg(c)
    let nL = g.genReg(c)
    let (dst, src, n) = (dstL.r, srcL.r, nL.r)
    let i = g.borrowTmp(ScalarSlot)
    let b = g.borrowTmp(ScalarSlot)
    let fwd = g.freshLabel()
    let bwd = g.freshLabel()
    let fwdLoop = g.freshLabel()
    let done = g.freshLabel()
    g.ab.tree CmpA64: g.emReg dst; g.emReg src
    g.emBr(BlsA64, fwd)                         # dst <= src → forward copy is safe
    # backward: i = n; while i != 0: i -= 1; dst[i] = src[i]
    g.movReg(i, n)
    g.emLab(bwd)
    g.ab.tree CmpA64: g.emReg i; g.ab.intLit 0
    g.emBr(BeqA64, done)
    g.binImm(SubA64, i, 1)
    g.emLdrb(b, src, i)
    g.emStrb(b, dst, i)
    g.emBr(BA64, bwd)
    # forward: i = 0; while i < n: dst[i] = src[i]; i += 1
    g.emLab(fwd)
    g.movImm(i, 0)
    g.emLab(fwdLoop)
    g.ab.tree CmpA64: g.emReg i; g.emReg n
    g.emBr(BhsA64, done)
    g.emLdrb(b, src, i)
    g.emStrb(b, dst, i)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, fwdLoop)
    g.emLab(done)
    g.movReg(IntRet, dst)
    g.giveBack b; g.giveBack i
    g.freeTemp(nL); g.freeTemp(srcL); g.freeTemp(dstL)
  of "memset":                                 # (dst, val, n) → dst
    let dstL = g.genReg(c)
    let valL = g.genReg(c)
    let nL = g.genReg(c)
    let (dst, val, n) = (dstL.r, valL.r, nL.r)
    let i = g.borrowTmp(ScalarSlot)
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: g.emReg i; g.emReg n
    g.emBr(BhsA64, done)
    g.emStrb(val, dst, i)                       # store the low byte of `val`
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(done)
    g.movReg(IntRet, dst)
    g.giveBack i
    g.freeTemp(nL); g.freeTemp(valL); g.freeTemp(dstL)
  of "memcmp":                                 # (a, b, n) → first byte difference
    let paL = g.genReg(c)
    let pbL = g.genReg(c)
    let nL = g.genReg(c)
    let (pa, pb, n) = (paL.r, pbL.r, nL.r)
    let i = g.borrowTmp(ScalarSlot)
    let ba = g.borrowTmp(ScalarSlot)
    let bb = g.borrowTmp(ScalarSlot)
    let loop = g.freshLabel()
    let diff = g.freshLabel()
    let equal = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: g.emReg i; g.emReg n
    g.emBr(BhsA64, equal)                       # ran off the end with no diff → 0
    g.emLdrb(ba, pa, i)
    g.emLdrb(bb, pb, i)
    g.ab.tree CmpA64: g.emReg ba; g.emReg bb
    g.emBr(BneA64, diff)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(diff)                               # bytes are 0..255 → signed sub gives sign
    g.movReg(IntRet, ba)
    g.binReg(SubA64, IntRet, bb)
    g.emBr(BA64, done)
    g.emLab(equal)
    g.movImm(IntRet, 0)
    g.emLab(done)
    g.giveBack bb; g.giveBack ba; g.giveBack i
    g.freeTemp(nL); g.freeTemp(pbL); g.freeTemp(paL)
  else:
    raiseAssert "arkham: unsupported mem intrinsic: " & builtin

proc cmpOperandUnsigned(g: var CodeGen; c: Cursor): bool =
  ## Does comparison/`case` operand `c` carry an unsigned (or char) type? Drives the
  ## unsigned-vs-signed condition code. A bare signed literal is ambiguous (→ false,
  ## let the other operand decide); `UIntLit`/`CharLit` are unsigned; every other
  ## operand is typed through `getType` — so unsigned fields, array elements, derefs,
  ## casts, computed expressions, and an unsigned symbol in *either* operand position
  ## are detected, not just a bare unsigned symbol in the first position.
  case c.kind
  of UIntLit, CharLit: result = true
  of IntLit: result = false
  else: result = not isSignedType(resolveType(g.prog, g.getType(c)))

proc emitCmpBranch(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## `c` is a comparison `(op a b)` (NO type child). Emit `cmp a, b` and branch
  ## to `toLabel` when the condition is true/false. Ordering signedness comes
  ## from the first operand's slot (unsigned var → unsigned branch).
  let ek = c.exprKind
  var tag: A64Inst
  c.into:
    if g.isFloatExpr(c):
      # Floating compare: `fcmp a, b` sets the flags so the *unsigned* branch
      # conditions match the ordered comparison (lo = a<b, ls = a<=b); NaN makes
      # them false, as required. Only `==`/`!=`/`<`/`<=` appear (NIFC normalizes).
      tag =
        case ek
        of EqC:  (if whenTrue: BeqA64 else: BneA64)
        of NeqC: (if whenTrue: BneA64 else: BeqA64)
        of LtC:  (if whenTrue: BloA64 else: BhsA64)
        of LeC:  (if whenTrue: BlsA64 else: BhiA64)
        else: raiseAssert "arkham v1: float condition not supported: " & $ek
      let fbits = g.floatBits(c)
      let fa = g.genFReg(c, fbits)
      let fb = g.genFReg(c, fbits)
      g.ab.tree FcmpA64: g.emFReg(fa.f, fbits); g.emFReg(fb.f, fbits)
      g.freeTemp(fb)
      g.freeTemp(fa)
    else:
      var bPeek = c; skip bPeek                   # unsigned if EITHER operand is
      let signed = not (g.cmpOperandUnsigned(c) or g.cmpOperandUnsigned(bPeek))
      tag =
        case ek
        of EqC:  (if whenTrue: BeqA64 else: BneA64)
        of NeqC: (if whenTrue: BneA64 else: BeqA64)
        of LtC:  (if whenTrue: (if signed: BltA64 else: BloA64)
                  else:        (if signed: BgeA64 else: BhsA64))
        of LeC:  (if whenTrue: (if signed: BleA64 else: BlsA64)
                  else:        (if signed: BgtA64 else: BhiA64))
        else: raiseAssert "arkham v1: condition not supported: " & $ek
      let a = g.genReg(c)
      var bImm = false
      var bImmV = 0'i64
      var b = regLoc(NoReg, ScalarSlot)         # filled below unless `b` is a small imm
      if c.kind == IntLit and intVal(c) >= 0 and intVal(c) <= 0xFFFF:
        bImm = true; bImmV = intVal(c); inc c
      else:
        b = g.genReg(c)
      g.ab.tree CmpA64:
        g.emReg a.r
        if bImm: g.ab.intLit bImmV else: g.emReg b.r
      if not bImm: g.freeTemp(b)
      g.freeTemp(a)
  g.emBr(tag, toLabel)

proc emitCondJump(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## Short-circuit conditional jump: emit code that branches to `toLabel` when
  ## the condition `c` evaluates to `whenTrue`. Handles and/or/not, comparisons,
  ## and a plain boolean value (`cmp v, #0`).
  if c.kind == TagLit:
    case c.exprKind
    of AndC:
      c.into:
        if whenTrue:                          # a&&b true: a false skips, b decides
          let lSkip = g.freshLabel()
          g.emitCondJump(c, lSkip, false)
          g.emitCondJump(c, toLabel, true)
          g.emLab(lSkip)
        else:                                 # a&&b false: either false → jump
          g.emitCondJump(c, toLabel, false)
          g.emitCondJump(c, toLabel, false)
      return
    of OrC:
      c.into:
        if whenTrue:                          # a||b true: either true → jump
          g.emitCondJump(c, toLabel, true)
          g.emitCondJump(c, toLabel, true)
        else:                                 # a||b false: a true skips, b decides
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
  # a plain boolean value: branch on `v != 0` / `v == 0`
  let v = g.genReg(c)
  g.ab.tree CmpA64: (g.emReg v.r; g.ab.intLit 0)
  g.emBr(if whenTrue: BneA64 else: BeqA64, toLabel)
  g.freeTemp(v)

proc materializeCond(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## Spill a pending condition into `dest` as a `0`/`1` boolean.
  ## The compare itself (and short-circuit `and`/`or`) is
  ## shared with the branch path via `emitCondJump`: assume true, jump over the
  ## reset when the condition holds, otherwise fall through to `dest ← 0`.
  let lEnd = g.freshLabel()
  g.movImm(dest, 1)
  g.emitCondJump(c, lEnd, whenTrue = true)
  g.movImm(dest, 0)
  g.emLab(lEnd)

proc emitChain(g: var CodeGen; c: var Cursor; lEnd: string) =
  if not c.hasMore: return
  case c.substructureKind
  of ElifU:
    var branch = c
    skip c                                  # `c` → the rest of the chain
    let lNext = g.freshLabel()
    branch.into:
      g.emitCondJump(branch, lNext, whenTrue = false)
      g.genActionStmts(branch)
      g.emBr(BA64, lEnd)
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

proc genWhile(g: var CodeGen; c: var Cursor) =
  ## Lstart: cmp; b<false> Lend; body; b Lstart; Lend:
  let lStart = g.freshLabel()
  let lEnd = g.freshLabel()
  g.loopEnds.add lEnd                       # so an inner `(break)` targets Lend
  c.into:
    let condStart = c
    skip c                                  # `c` → first body statement
    g.emLab(lStart)
    var cond = condStart
    g.emitCondJump(cond, lEnd, whenTrue = false)
    while c.hasMore: genStmt(g, c)
    g.emBr(BA64, lStart)
  g.emLab(lEnd)
  discard g.loopEnds.pop()

proc genBreak(g: var CodeGen; c: var Cursor) =
  ## `(break)` → unconditional jump to the enclosing loop's end label.
  assert g.loopEnds.len > 0, "arkham v1: `break` outside a loop"
  g.emBr(BA64, g.loopEnds[^1])
  skip c

# ── case statement ──────────────────────────────────────────────────────────

proc cmpImm(g: var CodeGen; selReg: Reg; v: int64) =
  ## `cmp selReg, #v` — immediate when it fits, otherwise via a scratch register.
  if v >= 0 and v <= 0xFFFF:
    g.ab.tree CmpA64: g.emReg selReg; g.ab.intLit v
  else:
    let tmp = g.borrowTmp(ScalarSlot)
    g.movImm(tmp, v)
    g.ab.tree CmpA64: g.emReg selReg; g.emReg tmp
    g.giveBack tmp

proc emitRangeTest(g: var CodeGen; selReg: Reg; c: var Cursor;
                   lBody: string; signed: bool) =
  ## Emit a test for one `BranchRange` against `selReg`, branching to `lBody`
  ## when it matches. `c` is advanced past the range.
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()            # in-range: lo <= sel <= hi
      g.cmpImm(selReg, lo)
      g.emBr(if signed: BltA64 else: BloA64, lSkip)
      g.cmpImm(selReg, hi)
      g.emBr(if signed: BgtA64 else: BhiA64, lSkip)
      g.emBr(BA64, lBody)
      g.emLab(lSkip)
  else:
    g.cmpImm(selReg, branchImm(c))
    g.emBr(BeqA64, lBody)

proc genCase(g: var CodeGen; c: var Cursor) =
  ## `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`.
  ## Selector → a register; per-branch comparison tests jump to the branch body;
  ## a non-match falls through to the `else` body (or the end). NIFC `case` has
  ## no fall-through, so each body ends with a jump to the end label.
  let lEnd = g.freshLabel()
  c.into:
    # Selector signedness drives ordered range comparisons.
    let signed = not g.cmpOperandUnsigned(c)
    let sel = g.genReg(c)                    # selector value, live across all tests
    let selReg = sel.r
    # Pass 1: emit the comparison tests; remember each body's StmtList cursor.
    var bodies: seq[(string, Cursor)] = @[]
    var elseBody = c                        # placeholder; overwritten if an `else` exists
    var hasElse = false
    while c.hasMore:
      case c.substructureKind
      of OfU:
        let lBody = g.freshLabel()
        var branch = c
        skip c
        branch.into:                        # branch → (ranges …) then StmtList
          assert branch.substructureKind == RangesU, "arkham: case `of` needs `ranges`"
          branch.into:
            while branch.hasMore:
              g.emitRangeTest(selReg, branch, lBody, signed)
          bodies.add (lBody, branch)        # branch now at the StmtList (copy saved)
          skip branch                       # consume it so the outer `into` balances
      of ElseU:
        elseBody = c
        hasElse = true
        skip c
      else: skip c
    g.freeTemp(sel)
    # No match falls through here: run the else body (if any), then skip bodies.
    if hasElse:
      elseBody.into:
        g.genActionStmts(elseBody)
    g.emBr(BA64, lEnd)
    # Pass 2: emit each branch body.
    for (lBody, bc) in bodies:
      g.emLab(lBody)
      var body = bc
      g.genActionStmts(body)
      g.emBr(BA64, lEnd)
  g.emLab(lEnd)

proc aggrAddr(g: var CodeGen; c: var Cursor): tuple[r: Reg, temp: bool] =
  ## Address of an aggregate lvalue → a register, consuming the lvalue cursor. A
  ## by-reference param (InReg aggregate) already *is* the address; otherwise
  ## borrow a temp and `genAddr` (stack var → lea, global → adr, dot/at → lea).
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InReg:
      result = (loc.r, false); inc c; return
  let r = g.borrowTmp(ScalarSlot)
  g.genAddr(c, r)
  result = (r, true)

proc byteCopyConst(g: var CodeGen; dst, src: Reg; size: int) =
  ## `dst[0..<size] ← src[0..<size]` — the same inline byte loop as `memcpy`
  ## (register-offset ldrb/strb), with `size` a compile-time constant. Used for
  ## whole-aggregate assignment / copy-init; `dst`/`src` stay live.
  let i = g.borrowTmp(ScalarSlot)
  let b = g.borrowTmp(ScalarSlot)
  let loop = g.freshLabel()
  let done = g.freshLabel()
  g.movImm(i, 0)
  g.emLab(loop)
  g.cmpImm(i, size)
  g.emBr(BhsA64, done)                          # i >= size (unsigned) → done
  g.emLdrb(b, src, i)
  g.emStrb(b, dst, i)
  g.binImm(AddA64, i, 1)
  g.emBr(BA64, loop)
  g.emLab(done)
  g.giveBack b; g.giveBack i

proc gen(g: var CodeGen; c: var Cursor; dest: var Location) =
  ## The single value/destination entry point. `dest` says where `c`'s value must
  ## go: a concrete `InReg`/`InFReg` register, a memory location to store at, or
  ## `Undef` — the dont-care target, filled in (via `var`) with where it landed.
  case dest.kind
  of InReg: g.genInto(c, dest.r)
  of InFReg: g.genIntoF(c, dest.f, dest.typ.size * 8)
  of Undef: dest = g.genVal(c)
  of NeedsReg:
    # "must be a register, my choice": evaluate where the value naturally lives,
    # then ensure it occupies a register (a register-resident local stays in place;
    # anything else is materialized into scratch). The concrete `InReg`, carrying its
    # `isTemp` flag, is written back so the caller knows whether to `freeTemp`.
    dest = g.genVal(c)
    g.forceReg(dest)
  of RegOrImm:
    # "a GPR or an immediate, not memory" — a memory operand is loaded into a temp.
    # (Not yet used by the a64 backend; handled for enum-totality / future use.)
    dest = g.genVal(c)
    if dest.kind notin {Imm, InReg}: g.forceReg(dest)
  of NamedStack, Mem, Glob, Tvar:
    let bits = dest.typ.size * 8
    if dest.typ.isFloat:
      let fr = g.genFReg(c, bits)
      g.emitStoreF(dest, fr.f, bits)
      g.freeTemp(fr)
    else:
      let rr = g.genReg(c)
      g.emitStore(dest, rr.r)
      g.freeTemp(rr)
  else: raiseAssert "arkham a64: gen() cannot target dest kind " & $dest.kind

proc genAsgn(g: var CodeGen; c: var Cursor) =
  ## `(asgn lvalue rvalue)`. The lvalue's type decides float vs integer; its shape
  ## decides the address operand. An aggregate is a whole-buffer copy; every scalar
  ## and float store goes through the unified `gen`, selecting register vs memory
  ## vs the float path purely from the destination `Location`.
  c.into:
    let slot = g.exprSlot(c)                # the lvalue's type → float / int / aggregate
    if slot.kind == AMem:                   # whole-aggregate copy (any size)
      let (dstA, dstT) = g.aggrAddr(c)      # &lvalue (consumes the lvalue)
      let (srcA, srcT) = g.aggrAddr(c)      # &rvalue (an aggregate lvalue)
      g.byteCopyConst(dstA, srcA, slot.size)
      if srcT: g.giveBack srcA
      if dstT: g.giveBack dstA
    else:
      var dst = g.asLoc(c)                  # classify + consume lvalue; c → rvalue
      g.gen(c, dst)                          # rhs → destination (scalar / float)

proc genStmt(g: var CodeGen; c: var Cursor) =
  if c.kind == DotToken:                       # an empty statement (e.g. `(stmts .)`)
    inc c; return
  case c.stmtKind
  of StmtsS:
    c.into:
      while c.hasMore: genStmt(g, c)
  of VarS, GvarS, TvarS, ConstS:
    genVarDecl(g, c)
  of CallS:
    genCall(g, c)                           # statement call: result discarded
  of AsgnS:
    genAsgn(g, c)
  of IfS:
    genIf(g, c)
  of WhileS:
    genWhile(g, c)
  of CaseS:
    genCase(g, c)
  of BreakS:
    genBreak(g, c)
  of ScopeS:                                # only `scope` is a fresh scope
    g.enterScope()
    c.into:
      while c.hasMore: genStmt(g, c)
    g.exitScope()
  of RetS:
    if g.isEntryProc and g.a64Linux:
      # The Linux ELF entry must terminate the process: place the exit code in x0
      # and invoke the `exit` syscall (there is no C runtime to return to).
      c.into:
        if c.hasMore and c.kind != DotToken: g.genInto(c, IntRet)
        else: g.movImm(IntRet, 0)
        while c.hasMore: skip c                     # void `(ret .)` → drop the `.`
      g.movImm(R8, LinuxA64ExitNr.int64)           # x8 = exit
      g.ab.tree SvcA64: g.ab.intLit 0
      return
    # (ret e?): place the value in x0 (or x0:x1 for a ≤16B aggregate), restore
    # the frame, then return.
    c.into:
      if c.hasMore and c.kind != DotToken:
        if g.retIndirect:
          # >16B: copy the result into the caller's buffer (x19) and return its
          # address in x0 (AAPCS64: x8 = result address, also returned in x0).
          assert c.kind == Symbol, "arkham v1: aggregate ret value must be a local"
          g.copyStructThroughPtr(symName(c), g.retAggrName, g.indirectReg)
          g.movReg(IntRet, g.indirectReg)
          inc c
        elif g.retAggrName.len > 0:
          assert c.kind == Symbol, "arkham v1: aggregate ret value must be a local"
          g.structToRegs(symName(c), g.retAggrName, 0)
          inc c
        elif g.retIsFloat:
          g.genIntoF(c, FloatRet, g.retFloatBits)   # float result in v0
        else:
          g.genInto(c, IntRet)
      while c.hasMore: skip c                   # void `(ret .)` → drop the `.`
    g.killFrameRegLocals()                    # release locals bound to restored regs
    if g.ra.hasStackVars:                     # release nifasm-managed slots
      g.ab.tree AddA64: g.emReg SP; g.ab.keyword SsizeX
    if g.hasFrame: framePop(g)
    g.ab.keyword RetA64
  else:
    raiseAssert "arkham v1: statement not supported: " & $c.stmtKind

# ── proc emission ────────────────────────────────────────────────────────────

proc initFreeTmp(g: var CodeGen) =
  g.freeTmp = {}
  for r in g.md.intTempRegs: g.freeTmp.incl r
  g.freeFTmp = {}
  for f in g.md.floatTempRegs: g.freeFTmp.incl f
  for name, pos in g.ra.symPos:               # locals occupying a volatile reg
    let loc = g.ra.locs[pos]
    if loc.kind == InReg: g.freeTmp.excl loc.r
    elif loc.kind == InFReg: g.freeFTmp.excl loc.f   # held by a float local/param

proc computeFrame(g: var CodeGen; hasCall: bool) =
  g.frameRegs = @[]
  for r in IntCalleeSaved:
    if r in g.ra.usedCallee: g.frameRegs.add r
  if g.frameRegs.len mod 2 == 1:              # save in pairs → pad to even
    for r in IntCalleeSaved:
      if r notin g.ra.usedCallee: (g.frameRegs.add r; break)
  g.frameFRegs = @[]
  for f in FloatCalleeSaved:
    if f in g.ra.usedCalleeF: g.frameFRegs.add f
  if g.frameFRegs.len mod 2 == 1:             # pad SIMD saves to an even count too
    for f in FloatCalleeSaved:
      if f notin g.ra.usedCalleeF: (g.frameFRegs.add f; break)
  g.hasFrame = hasCall or g.frameRegs.len > 0 or g.frameFRegs.len > 0

proc emitStackParamLoads(g: var CodeGen; decl: Cursor) =
  ## Load the incoming stack-passed parameters (the 9th integer/pointer arg
  ## onward) from the caller's outgoing argument area into their register homes.
  ## Emitted right after `framePush` and *before* SP is lowered for locals, so
  ## each arg sits at the statically-known offset `framePushBytes + k*8` from the
  ## current SP (the caller left SP pointing at the first stack arg on entry).
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # (params) is `.` → no parameters
  let base = g.framePushBytes()
  var idx = 0
  var fidx = 0
  var stackOrd = 0
  c.into:
    while c.hasMore:
      var nm = ""
      var isFloat = false
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        if c.kind == TagLit and c.typeKind == FT: isFloat = true
        while c.hasMore: skip c               # type (+ anything else)
      if isFloat:
        inc fidx                              # floats use v0–v7; never stack here
      else:
        if idx >= IntArgRegs.len:
          let loc = g.ra.locationOfSym(nm)
          assert loc.kind == InReg,
            "arkham v1: stack parameter without a register home: " & nm
          g.ab.tree MovA64:                   # home ← [sp + base + stackOrd*8]
            g.emReg loc.r
            g.ab.tree MemX:
              g.emReg SP
              g.ab.intLit (base + stackOrd * 8)
          inc stackOrd
        inc idx

proc emitParamMoves(g: var CodeGen; decl: Cursor) =
  ## Move each parameter from its incoming ABI register to the home the
  ## allocator chose (a callee-saved register for cross-call params; arg regs
  ## stay put for leaf procs). Emitted after the prologue saved the homes.
  ## Stack-passed params (9th integer arg onward) are loaded separately by
  ## `emitStackParamLoads` and skipped here.
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # (params) is `.` → no parameters
  var idx = 0
  var fidx = 0
  c.into:                                     # into (params …)
    while c.hasMore:
      var nm = ""
      var tn = ""
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        g.symType[nm] = c                     # record the param's type for getType
        # Only true aggregates get a `varType` entry; a named *enum* (or scalar
        # typedef), local or cross-module, resolves to a scalar and stays in the
        # register path. `slotOf` loads a foreign module if the type lives there.
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = symName(c)
        while c.hasMore: skip c               # type (+ anything else)
      let loc = g.ra.locationOfSym(nm)
      if tn.len > 0 and loc.kind == NamedStack:
        # ≤16B by-value aggregate: declare its stack home, fill from its GPR(s)
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        g.regsToStruct(nm, tn, idx)
        idx += aggrWordCount(g.prog, tn)
      elif tn.len > 0 and loc.kind == InReg:
        # >16B by-reference aggregate: a pointer, homed like a scalar; field
        # accesses route through it (recorded in varType).
        g.varType[nm] = tn
        g.movReg(loc.r, IntArgRegs[idx])
        inc idx
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming v{fidx}; if
        # the allocator gave it a callee-saved home, move it there.
        g.fmovF(loc.f, FloatArgRegs[fidx], loc.typ.size * 8)
        inc fidx
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming SIMD arg register into it so `addr`/loads/stores work.
        assert fidx < FloatArgRegs.len, "arkham v1: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, FloatArgRegs[fidx], bits)
        inc fidx
      elif loc.kind == NamedStack:
        # An address-taken scalar param: declare its `(s)` slot and spill the
        # incoming argument register into it so `addr`/loads/stores work.
        assert idx < IntArgRegs.len, "arkham v1: >8 integer params (stack TODO)"
        g.emScalarStackVar(nm)
        g.emScalarStore(nm, IntArgRegs[idx])
        inc idx
      else:
        case loc.kind
        of InReg:
          if idx < IntArgRegs.len:
            g.movReg(loc.r, IntArgRegs[idx])
          # else: a stack-passed param — already loaded into loc.r by
          # emitStackParamLoads before SP was lowered. Nothing to move.
        else: raiseAssert "arkham v1: stack-resident parameter: " & nm
        inc idx

proc emitSignature(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## Emit the proc's `(params)/(result)/(clobber)`. When `declarative`, the ABI
  ## is stated explicitly — positional `p{i}` register params and an `x0` result
  ## — so nifasm cross-checks every call site; otherwise both stay empty and
  ## arkham marshals by hand (floats/aggregates/by-ref/>8/named types). The
  ## clobber set is always the convention's, derived here (never per-proc
  ## precomputed), which is reliable across modules.
  if declarative:
    var c = decl
    c.into:
      inc c                                   # name → params slot
      g.ab.tree ParamsD:
        if c.kind == TagLit:                  # (params (param …) …)
          var idx = 0
          c.into:
            while c.hasMore:
              c.into:                         # (param :name pragmas type)
                inc c                         # name → use positional p{idx}
                skip c                        # pragmas
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  if idx < IntArgRegs.len:
                    g.ab.reg IntArgRegs[idx]  # x0–x7: raw reg *location*
                  else:
                    g.ab.keyword SO           # 9th+ → stack-passed `(s)`
                  g.genTypeBody(c)            # the param type (consumes it)
                while c.hasMore: skip c
              inc idx
        else:
          skip c                              # no params slot → consume it
      g.ab.tree ResultD:                      # c now at the return type
        if retIsVoid(c):
          skip c                              # void → empty (result)
        else:
          g.ab.symDef "ret.0"
          g.ab.reg IntRet                     # raw reg *location* of the result
          g.genTypeBody(c)                    # the result type (consumes it)
      while c.hasMore: skip c                 # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  g.ab.tree ClobberD:
    for r in ConvClobbersGpr: g.ab.reg r     # a clobber *declaration*: raw reg locations

proc emitGlobalInits(g: var CodeGen)

proc emitProcBody(g: var CodeGen; info: ProcInfo) =
  ## Emit one proc's `(proc …)` (signature + body). Run twice by `genProc`: once
  ## in planning mode (emission suppressed, scratch decisions recorded), once for
  ## real (decisions replayed). Reads the per-proc `ret*`/frame state set up by
  ## `genProc`; touches only state `genProc` resets between the two passes.
  g.ab.tree ProcD:
    g.ab.symDef info.asmName                  # "main.0" for the entry
    g.emitSignature(info.decl, isDeclarativeAbi(g.prog, info.decl))
    g.ab.tree StmtsA64:
      if g.hasFrame: framePush(g)
      # Read incoming stack args while SP still points at the caller's argument
      # area (after the pushes, before locals lower SP).
      g.emitStackParamLoads(info.decl)
      if g.ra.hasStackVars:                   # reserve nifasm-managed slots
        g.ab.tree SubA64: g.emReg SP; g.ab.keyword SsizeX
      if g.retIndirect:                       # park the x8 result pointer
        g.movReg(g.indirectReg, IndirectResultReg)
      g.emitParamMoves(info.decl)
      if info.isEntry: g.emitGlobalInits()    # run module-level var initializers
      g.enterScope()                          # the proc body's scope (register locals)
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c         # name, params, return type, pragmas
        if c.stmtKind == StmtsS:
          c.into:
            while c.hasMore: genStmt(g, c)
      g.exitScope()                           # `kill` the proc's register locals
      # Fallthrough epilogue: a void proc whose body has no explicit `(ret)`
      # must still restore the frame and return (unreachable dead code after an
      # explicit `ret`, harmless). The Linux entry exits the process instead, since
      # there is no C runtime to return to.
      if info.isEntry and g.a64Linux:
        g.movImm(IntRet, 0)
        g.movImm(R8, LinuxA64ExitNr.int64)
        g.ab.tree SvcA64: g.ab.intLit 0
      else:
        if g.ra.hasStackVars:
          g.ab.tree AddA64: g.emReg SP; g.ab.keyword SsizeX
        if g.hasFrame: framePop(g)
        g.ab.keyword RetA64

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. The two-pass seam
# below must reset every per-proc table (regLocal/boundTemps/freeTmp + the ra.locs snapshot)
# or RegisterBindingsMatchLoc and replay completeness break.
proc genProc(g: var CodeGen; info: ProcInfo) =
  let an = analyseProc(g.buf[], info.decl, g.tvarNames)
  g.varType = initTable[string, string]()     # per-proc (symbol names recycle)
  g.symType = initTable[string, Cursor]()
  g.regLocal = initTable[Reg, string]()        # per-proc named-local bindings
  g.scopeLocals = @[]
  g.fregLocal.clear()                          # per-proc float named-local bindings
  g.boundFTmps = {}
  g.boundTemps = {}                            # per-proc scratch-temp bindings
  g.scopeFLocals = @[]
  g.ftmpBindCount = 0
  g.spillCount = 0
  # Determine the aggregate return convention BEFORE allocation: a named object
  # ≤16B → x0[:x1]; >16B → x8 indirect result (callee writes through the caller-
  # supplied pointer, which we park in x19 for the proc's lifetime).
  g.retAggrName = ""
  g.retIndirect = false
  g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                   # head → name → params, skip → return type
    # A named *aggregate* return uses the x0[:x1] / x8 ABI; a named enum/scalar
    # return resolves to a scalar and stays in x0 (handled by the default path).
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrName = symName(rc)
      g.retIndirect = aggrByteSize(g.prog, g.retAggrName) > 16
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true                     # float return → v0
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  let preseal = if g.retIndirect: {R19} else: {}
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, aarch64Machine, preseal)
  if g.retIndirect:
    g.indirectReg = R19
    g.ra.usedCallee.incl R19                  # saved/restored like any callee reg
  g.initFreeTmp()
  g.computeFrame(an.hasCall)
  # Single walk, two modes (see x64's `genProc`). The plan pass runs `emitProcBody`
  # with emission suppressed (`ab.planning`), recording every scratch borrow (and
  # spill-on-exhaustion) decision in `borrowLog`/`borrowLogF` with the real pool +
  # ABI seals while no bytes are produced; the emit pass replays those decisions
  # verbatim. Identical walk + identical register decisions ⇒ the emit pass is
  # byte-identical to a single inline-borrow pass — which is what makes the
  # spill-on-exhaustion path (a deep expression spills instead of asserting) sound.
  # The plan pass no longer touches `labelCount`/`rodata` (see `freshLabel` / the
  # StrLit case), so no snapshot/restore of those is needed — the emit pass numbers
  # labels exactly as a single pass would.
  let sealedSnapshot = g.ra.sealed
  # A codegen-time steal evicts a local by mutating `g.ra.locs` mid-walk; snapshot it
  # so the emit pass starts from the same allocation the plan pass saw and re-applies
  # the (identically replayed) evictions itself.
  let locsSnapshot = g.ra.locs
  g.stealEvents.clear()
  g.borrowLog.setLen 0; g.borrowLogF.setLen 0
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.ab.planning = true
  g.emitProcBody(info)
  g.ab.planning = false
  g.ra.locs = locsSnapshot                     # undo plan-pass evictions for the emit pass
  # Reset the per-proc emission state the plan pass dirtied, so the emit pass
  # reproduces a single-pass result. (The `ret*`/frame fields were fixed above and
  # stay constant across the two passes.)
  g.ra.sealed = sealedSnapshot
  g.varType.clear()
  g.symType.clear()
  g.regLocal.clear()
  g.scopeLocals = @[]
  g.fregLocal.clear()
  g.boundFTmps = {}
  g.boundTemps = {}
  g.scopeFLocals = @[]
  g.ftmpBindCount = 0
  g.loopEnds = @[]
  g.initFreeTmp()
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.spillCount = 0
  g.emitProcBody(info)                         # emit for real, replaying the plan

# ── driver ──────────────────────────────────────────────────────────────────

proc genType(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(type :name <translated body>)` — a top-level type definition that
  ## nifasm's stack-slot allocator consults for aggregate field offsets.
  var c = decl
  c.into:                                     # (type SymbolDef TypePragmas body)
    inc c                                     # name
    skip c                                    # TypePragmas (one slot: `.` or (pragmas …))
    g.ab.tree TypeD:
      g.ab.symDef name
      g.genTypeBody(c)

proc genGlobal(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit a top-level `const`/`gvar`. A true `const` with a value becomes a
  ## read-only `.text` data blob; a `gvar` with a compile-time-constant SCALAR
  ## initializer is laid out as static `.bss`-image data (so it is correct even for
  ## a FOREIGN module's gvar in a bundle, whose entry-time `emitGlobalInits` never
  ## runs — and for a `var` later mutated). Any other (runtime) initializer is a
  ## zeroed slot filled at entry by `emitGlobalInits`.
  var c = decl
  let isConst = c.stmtKind == ConstS
  c.into:                                     # (gvar SymbolDef VarPragmas Type Value?)
    inc c                                     # name
    skip c                                    # pragmas
    let typeCur = c
    skip c                                    # type
    let hasValue = c.hasMore and c.kind != DotToken
    if isConst and hasValue:
      var bytes = ""
      constToBytes(g.prog, typeCur, c, bytes)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
    else:
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                       # type
      if hasValue and isConstScalarInit(c):
        g.ab.intLit cast[int64](constLitBits(c))
      g.ab.close()
    while c.hasMore: skip c                   # value (runtime inits done at entry)

proc genTvar(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(tvar :name <type> <intlit>?)` — a macOS thread-local variable. A
  ## literal initializer is baked into the per-thread template dyld copies on
  ## first access; non-literal initializers are unsupported (a thread-local is
  ## per-thread, so the entry-time `emitGlobalInits` path cannot serve them).
  var c = decl
  c.into:                                     # (tvar SymbolDef VarPragmas Type Value?)
    inc c                                     # name
    skip c                                    # pragmas
    if g.a64Linux:
      # Static-ELF Linux is single-threaded (per-thread == per-process): emit the
      # thread-local as a plain `.bss` global (no Darwin TLV template). Its access
      # routes through the global adrp+add path; a compile-time-constant scalar
      # initializer is baked as static `.bss`-image data (correct cross-module),
      # any other initializer is stored at entry by `emitGlobalInits`.
      let typeCur = c
      skip c                                  # type
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                       # type
      if c.hasMore and c.kind != DotToken and isConstScalarInit(c):
        g.ab.intLit cast[int64](constLitBits(c))
      g.ab.close()
      while c.hasMore: skip c                 # value (runtime inits done at entry)
      return
    g.ab.open NifasmDecl.TvarD
    g.ab.symDef name
    g.genTypeBody(c)                          # type
    if c.kind == IntLit:
      g.ab.intLit intVal(c)                   # literal initializer → TLV template
    elif c.kind != DotToken:
      raiseAssert "arkham: thread-local initializer must be an integer literal: " & name
    g.ab.close()
    while c.hasMore: skip c

proc emitGlobalInits(g: var CodeGen) =
  ## At program entry, store each global's initializer (if any) into its slot.
  ## On Linux the thread-locals are `.bss` globals too (see `genTvar`), so their
  ## literal initializers are stored here as well — the block is otherwise zeroed.
  template storeInit(name: string; decl: Cursor) =
    var c = decl
    c.into:
      inc c; skip c                           # name, pragmas
      let gslot = slotOf(g.prog, c)           # the global's declared type
      let gbits = if gslot.size == 4: 32 else: 64
      skip c                                   # type
      # A constant-scalar initializer was laid out as static data (see genGlobal /
      # genTvar), so there is no entry-time store to emit for it.
      if c.hasMore and c.kind != DotToken and not isConstScalarInit(c):
        if gslot.kind == AFloat:               # float global: store via fstr
          let fv = g.borrowFTmp(gbits)
          g.genIntoF(c, fv, gbits)
          let p = g.borrowTmp(ScalarSlot)
          g.emAdr(p, name)
          g.emFStore(fv, p, gbits)
          g.giveBack p
          g.giveBackF fv
        else:
          let v = g.borrowTmp(ScalarSlot)
          g.genInto(c, v)                       # evaluate initializer
          let p = g.borrowTmp(ScalarSlot)
          g.emAdr(p, name)
          g.ab.tree MovA64:
            g.ab.tree MemX: g.emReg p
            g.emReg v
          g.giveBack p
          g.giveBack v
      while c.hasMore: skip c
  for name, decl in g.globals:
    if decl.stmtKind == ConstS: continue        # emitted as a rodata data blob
    storeInit(name, decl)
  if g.a64Linux:
    for name, decl in g.tvars: storeInit(name, decl)

proc generateA64*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                  linux = false): string =
  ## Compile a parsed NIFC module to AArch64 asm-NIF text — Darwin/Mach-O by
  ## default, or Linux/ELF when `linux` (svc-based syscalls, static, no dyld/TLV),
  ## which `nifasm`'s `linux_arm64` target assembles to a qemu-runnable ELF.
  ## `inputPath` and `tags` let the program model load *other* modules on demand
  ## to resolve cross-module symbols (`Foo.0.othermod`).
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: aarch64Machine,
                  a64Linux: linux)
  g.prog = collect(buf, inputPath, tags)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
  g.ab.tree StmtsA64:
    g.ab.tree ArchD: g.ab.ident (if linux: "linux_arm64" else: "arm64")
    if not linux:
      # Darwin: thread-local vars resolve their TLV descriptor thunk against
      # libSystem (`__tlv_bootstrap`), so the dylib must be loaded even without
      # extern calls. Each extern is a dynamic import. (On Linux all externs lower
      # to `svc` syscalls — the static ELF needs no imports.)
      if g.prog.needsLibSystem or g.tvars.len > 0:
        g.ab.tree ImpD: g.ab.str DarwinLibSystem
      for ex in g.prog.externOrder:
        g.ab.tree ExtprocD:
          g.ab.symDef ex.asmName
          g.ab.str ex.extName
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)
    for sp in g.prog.syscalls:                  # one `(syproc …)` per used syscall
      g.emitSyprocA64(sp)
    for info in g.prog.procs:
      genProc(g, info)
    # NOTE: foreign types are NOT emitted here. arkham loads other modules only to
    # resolve their layout for *its own* codegen (sizing, field offsets, ABI). The
    # actual cross-module linking is nifasm's job: a module-suffixed symbol like
    # `Foo.0.othermod` makes nifasm auto-import `othermod.s.nif` (which arkham
    # produced when it compiled that module). Emitting the decl inline is ignored.
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
