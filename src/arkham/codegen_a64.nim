#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3: code generation. Walks a Leng module, runs the analyser + register
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

# The `CodeGen` state object and the Leng type/lvalue analysis live in
# `codegen_common`; this module is the AArch64 instruction-selection backend.

# ── low-level emit helpers ──────────────────────────────────────────────────

let ScalarSlot = AsmSlot(cls: AInt, size: 8, align: 8)
  ## Placeholder slot for a register/immediate dont-care result: no consumer of an
  ## `InReg`/`Imm` value reads `.typ` (the old `Val` carried no type). As a scratch
  ## binding type it carries no cursor, so `bindTemp` falls back to `(i 64)`. A `let`
  ## (not `const`) because `AsmSlot` now holds a `Cursor`, not a compile-time value.

proc bindTemp(g: var CodeGen; r: Reg; typ: AsmSlot)
proc unbindTemp(g: var CodeGen; r: Reg)
# Order in which a codegen-time steal looks for a victim register-local: prefer
# the volatile temp pool (x9–x15 — call-free locals the allocator put there once
# the callee-saved pool was full, the common case), then callee-saved (x19–x28).
# Fixed order ⇒ the plan and emit passes pick the same victim deterministically.
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
proc emLdar(g: var CodeGen; rt, rn: Reg; bits = 64) =   # rt ← acquire [rn] (sized)
  g.ab.tree LdarA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits
proc emStlr(g: var CodeGen; rt, rn: Reg; bits = 64) =   # release store rt→[rn] (sized)
  g.ab.tree StlrA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits
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

proc structToRegs(g: var CodeGen; varName, typeName: string; firstArg: int)
proc regsToStruct(g: var CodeGen; varName, typeName: string; firstArg: int)
proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string; firstArg: int)
proc takeBridge(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg   # defined below
proc dropBridge(g: var CodeGen; r: Reg)                                 # defined below
proc emWordThroughPtr(g: var CodeGen; p: Reg; idx: int)                 # defined below
proc genTypeBody(g: var CodeGen; c: var Cursor)
proc genPointee(g: var CodeGen; c: var Cursor)
proc genProctypeSig(g: var CodeGen; c: var Cursor)
proc indirectRetType(g: var CodeGen; gvarDecl: Cursor): Cursor
proc emFieldMem(g: var CodeGen; base, field: string) =
  ## `(mem (dot base field))` — nifasm resolves the field offset from the
  ## aggregate's type. `base` is a `(s)` stack var.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field

proc emAggrElemMem(g: var CodeGen; base: string; idx: int) =
  ## `(mem (at base idx))` — element `idx` of the array stack var `base`; nifasm folds
  ## the constant `idx*elemSize` into the load/store offset and sizes it from the
  ## array's element type (an immediate index needs no stride scratch).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.sym base
      g.ab.intLit idx

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
  else:
    # a synthetic nifasm `(s)` slot (e.g. an inline-constructor arg temp) is addressed
    # by name like a `NamedStack` var — the allocator just doesn't track it.
    if g.varType.hasKey(base): g.emFieldMem(base, field)
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
  else:
    # a synthetic nifasm `(s)` slot (e.g. an inline-constructor arg temp) is addressed
    # by name like a `NamedStack` var — the allocator just doesn't track it. Mirrors
    # `emAggrFieldMem`'s fallback (this is its no-`mem`-wrapper address-of-field twin).
    if g.varType.hasKey(base):
      g.ab.tree DotX:
        g.ab.sym base
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
  ## The ONE local-variable stack-slot emitter — `(var :name (s) <slot type>)`,
  ## dispatching on the value class so callers need no per-form ladder (genVarDecl2
  ## mirrors x64's single call). The slot type is NOT always the real type: a64 spills
  ## every integer/bool/char scalar to a forced `(i 64)` (arkham keeps scalars 64-bit
  ## in registers and the `ldr/str` accessors are 64-bit, so a narrow slot would
  ## mis-size the access). A POINTER keeps its real `(ptr T)` type (the body may deref
  ## it); a FLOAT its `(f N)`; an aggregate its real type plus the `(s (align N))`
  ## stack-slot alignment. This backend-specific scalar rule lives here, not in the
  ## caller — that is the whole point of routing through one proc.
  let slot = slotOf(g.prog, t)
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  let sa = stackSlotAlign(g.prog, t)
  if sa > 8:                                  # over-aligned slot → `(s (align N))`
    g.ab.tree X64Flag.SO:
      g.ab.tree AlignX: g.ab.intLit sa.int64
  else:
    g.ab.keyword SO                           # ordinary 8-granular slot → `(s)`
  case slot.kind
  of AFloat:
    g.ab.floatType(slot.size * 8)             # `(f N)` — typed fp slot
  of AMem:
    var tc = t                                # aggregate: its real type (align applied above)
    if tc.kind == Symbol: g.ab.sym symName(tc) else: g.genTypeBody(tc)
  else:                                       # int / uint / bool / char / pointer
    if isPtrType(resolveType(g.prog, t)):
      var tc = t                              # pointer: real `(ptr T)` so the body can deref
      if tc.kind == Symbol: g.ab.sym symName(tc) else: g.genTypeBody(tc)
    else:
      g.ab.intType(64)                        # scalar: forced 8-byte slot (64-bit access)
  g.ab.close()

proc emScalarLoad(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← [slot]` — load a spilled scalar (nifasm resolves the `(s)` var to
  ## `[sp,#off]`).
  g.ab.tree MovA64: (g.emReg dest; g.ab.sym name)

proc emScalarStore(g: var CodeGen; name: string; src: Reg) =
  ## `[slot] ← src` — store to a spilled scalar's `(s)` var.
  g.ab.tree MovA64: (g.ab.sym name; g.emReg src)

proc emBindType(g: var CodeGen; typ: AsmSlot) =
  ## Emit the Leng type for a scratch binding: the slot's own type when known, else
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
# ── codegen-time register steal (evict a live local to a stack slot) ─────────
# The exact mirror of x64's steal machinery: when the scratch pool is exhausted
# at a `borrowTmp`, evict a register-bound local to a nifasm `(s)` slot and hand
# its register over as scratch — recorded in the plan pass, replayed (with the
# spill store) in the emit pass, keyed by the borrow-log index so both passes
# stay byte-consistent. `recordEviction` emits no machine code (it only mutates
# the allocator's view, which `genProc` snapshot/restores); `replayEviction` does.

# MODEL: the `steal` action in proofs/arkham_bindings.tla — the evicted victim must move
# to a stack slot (loc→Stack, binding cleared) or LiveLocalsHaveHomes / RegisterBindingsMatchLoc
# break. Change this ⇒ re-check that action.
# MODEL: a staging register handed out for a *held* value must be tracked, not raw (see
# proofs/arkham_bindings.tla NoSharedRegister) — hence the total `borrowTmp` below, not a
# bare `pickStaging`; two raw staging values would otherwise collide on one register.
const SuCallWeight = 1000          # a call dominates demand → sorts first

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

# ── floating-point expressions (single + double precision) ──────────────────
# `bits` (32/64) is the value's precision, threaded top-down: it selects s/d
# register views and single/double instructions. A bare literal has no inherent
# width, so it adopts the contextual `bits`.

# MODEL: the init-home seal in proofs/arkham_bindings.tla (`beginInit` seals the home;
# ValueConsistency). The `sealHome` below protects a register-local home while its own
# value is built — without it a steal evicts the home and the write lands in a stale reg.
# ── calls ────────────────────────────────────────────────────────────────────

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
           "arkham a64: indirect call through a non-proctype value"
    var q = pt                                  # consume a copy; `result` keeps a cursor
    q.into:
      skip q                                    # Empty (the proc-name slot)
      skip q                                    # Params
      result = q                                # RetType (`.` / `(void)` / a real type)
      while q.hasMore: skip q                   # drain RetType + Pragmas
    while d.hasMore: skip d

proc genProctypeSig(g: var CodeGen; c: var Cursor) =
  ## Lower a Leng `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
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

# ── statements ──────────────────────────────────────────────────────────────

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
  ## Translate a Leng type at `c` into asm-NIF, advancing `c` past it. Named
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
      c.into:                               # Leng `(array Type Expr)`
        g.ab.arrayType:
          g.genTypeBody(c)                  # element type
          if c.kind == IntLit:
            g.ab.intLit intVal(c); inc c
          else:
            raiseAssert "arkham v1: array length must be a literal"
    of EnumT:
      c.into:                               # Leng `(enum BaseType efld*)`
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
            if c.kind == TagLit and c.typeKind == UnionT:
              # An object VARIANT's union part: `(union (object …branch)+)`. Branches
              # overlap (nifasm lays the union out as max branch size); emit through.
              g.ab.unionType:
                c.into:
                  while c.hasMore: g.genTypeBody(c)
            else:
              c.into:                       # (fld :name pragmas type)
                let fn = symName(c); inc c
                skip c                      # field pragmas (dropped)
                g.ab.fldDef(fn):
                  g.genTypeBody(c)          # field type
    else:
      raiseAssert "arkham v1: type not supported: " & $c.typeKind
  else:
    raiseAssert "arkham v1: malformed type"

# ── AAPCS64 small-aggregate (≤16B) marshalling ──────────────────────────────
# A ≤16-byte aggregate travels in 1–2 consecutive GPRs; word i ↔ the field at
# byte offset 8·i (word-aligned fields only for now — sub-word packing and the
# >16-byte by-reference / x8-indirect paths `raiseAssert`). Layout/size live in
# slots.nim so the register allocator shares them.

proc emWordThroughPtr(g: var CodeGen; p: Reg; idx: int) =
  ## `(mem (at (cast (aptr (u 64)) p) idx))` — the `idx`-th raw 8-byte word at `[p]`,
  ## typed `(u 64)` (ignores the aggregate's field layout). nifasm strides by 8.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(64)
        g.emReg p
      g.ab.intLit idx

proc aggrWordsToFromRegs(g: var CodeGen; varName, typeName: string;
                         firstArg: int; toRegs: bool) =
  ## Move a ≤16-byte aggregate between its memory home and x{firstArg+i} (the by-value
  ## aggregate ABI). A FULL eightbyte moves as a RAW `(u 64)` word — the slot's address
  ## goes into a staging bridge (a by-ref aggregate already has its pointer in a reg)
  ## and `emWordThroughPtr` carries the whole 8 bytes, so fields PACKED into one word
  ## (`{int32; int32}`) all transfer (a field-typed move would drop all but the field
  ## at the boundary). A trailing PARTIAL eightbyte (a single sub-word field for a
  ## ≤16-byte aggregate) keeps the field-typed access (exact bytes, no over-read).
  let byteSize = aggrByteSize(g.prog, typeName)
  let loc = g.ra.locationOfSym(varName)
  var baseReg = NoReg
  var bridge = NoReg
  if byteSize >= 8:                                    # at least one full eightbyte
    if loc.kind == InReg:
      baseReg = loc.r                                  # a by-ref aggregate's pointer
    else:
      bridge = g.takeBridge()
      g.ab.tree LeaA64: (g.emReg bridge; g.ab.sym varName)   # bridge ← &slot
      baseReg = bridge
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:                          # a full eightbyte → raw u64 word
      g.ab.tree MovA64:
        if toRegs: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(baseReg, i))
        else: (g.emWordThroughPtr(baseReg, i); g.emReg IntArgRegs[firstArg + i])
    else:                                              # trailing partial eightbyte → field
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      if fn.len == 0: raiseAssert "arkham a64: sub-word-packed aggregate ABI unsupported"
      g.ab.tree MovA64:
        if toRegs: (g.emReg IntArgRegs[firstArg + i]; g.emAggrFieldMem(varName, fn))
        else: (g.emAggrFieldMem(varName, fn); g.emReg IntArgRegs[firstArg + i])
  if bridge != NoReg: g.dropBridge bridge

proc structToRegs(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## Aggregate → x{firstArg+i} (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeName, firstArg, toRegs = true)

proc regsToStruct(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## x{firstArg+i} → aggregate (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeName, firstArg, toRegs = false)

proc globalToRegs(g: var CodeGen; name, typeName: string; firstArg: int) =
  ## Read a GLOBAL aggregate's words into x{firstArg+i}. The global is a `.bss` label
  ## (no stack slot), so its address goes into a staging bridge and each word is read
  ## through that pointer — a FULL eightbyte as a raw `(u 64)` word (handles packed
  ## fields), a trailing PARTIAL eightbyte field-typed. For a global passed by value as
  ## a call argument (`equalStrings(s, "")` where `s` is a global `string`).
  let bridge = g.takeBridge()
  g.emGlobalAddr(bridge, name)
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(bridge, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emPtrFieldMem(bridge, typeName, fn))
  g.dropBridge bridge

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

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers to a short inline AArch64 byte loop
# (register-offset ldrb/strb). Sizes are runtime values; result lands in x0
# (memcpy/memmove/memset return dest, memcmp returns the first byte difference).

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

# ── case statement ──────────────────────────────────────────────────────────

# ── proc emission ────────────────────────────────────────────────────────────

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

# ════════════════════════════════════════════════════════════════════════════
#  Pure-emit value core (`*2`) — the AArch64 twin of codegen_x64.nim's emit*2
#  family. The allocator (allocExprs=true, machine `aarch64MachineN`) precomputes
#  a Location for EVERY value position into `ra.locs` plus per-op selection hints
#  in `ra.aux`; these procs are pure consumers that read `locs[pos]`/`aux[pos]`
#  and emit bytes — no emit-time borrow/steal/spill, no plan/replay. Transient
#  scratch the emitter still needs (a folded memory operand a64 must load, a
#  global address temp, a produce-into-memory spill) comes from the reserved
#  staging bridges x14/x15/v31 (`IntBridgeRegs`/`FloatBridgeReg`), withheld from
#  the allocator pool so one is always free.
# ════════════════════════════════════════════════════════════════════════════

proc emitValue2(g: var CodeGen; c: Cursor)
proc emitFValue2(g: var CodeGen; c: Cursor)
proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location; auxPos: int)
proc emitCall2(g: var CodeGen; c: Cursor)
proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc genStmt2(g: var CodeGen; c: Cursor)
proc emLvalAddr2(g: var CodeGen; c: Cursor)
proc prematLval2(g: var CodeGen; c: Cursor)
proc unbindLvalTemps2(g: var CodeGen; c: Cursor)
proc emitMemLoad2(g: var CodeGen; c: Cursor)
proc emitFMemLoad2(g: var CodeGen; c: Cursor)
proc emitAddr2(g: var CodeGen; c: Cursor)
proc emitBin2(g: var CodeGen; c: Cursor)
proc emitMod2(g: var CodeGen; c: Cursor)
proc emitFBin2(g: var CodeGen; c: Cursor)
proc emitCast2(g: var CodeGen; c: Cursor)
proc emitCondValue2(g: var CodeGen; c: Cursor)
proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string)
proc genAconstr2(g: var CodeGen; c: Cursor; dstVar: string)
proc storeReg2(g: var CodeGen; dst: Location; src: Reg)

template posOf(g: CodeGen; cur: Cursor): int = cursorToPosition(g.buf[], cur)

# ── staging bridges (always free; reserved out of the allocator pool) ────────

proc takeBridge(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg =
  ## A staging-bridge GPR (x14/x15). Bound to a typed name so `emReg` emits a
  ## checked symbol and a typed memory base type-checks. Released by `dropBridge`.
  ## Two bridges nest (e.g. a `cmp` of two spilled operands); a third asserts.
  for r in IntBridgeRegs:
    if r != avoid and r notin g.boundTemps:
      g.bindTemp(r, typ); return r
  raiseAssert "arkham a64n: both staging bridges in use"

proc dropBridge(g: var CodeGen; r: Reg) =
  if r != NoReg: g.unbindTemp(r)

proc takeFBridge(g: var CodeGen; bits: int): FReg =
  g.bindFTmp(FloatBridgeReg, bits); FloatBridgeReg

proc dropFBridge(g: var CodeGen) =
  g.unbindFTmp(FloatBridgeReg)

# ── scalar Location → register / register → Location ─────────────────────────

proc place2(g: var CodeGen; src: Location; dest: Reg) =
  ## `dest ← <scalar Location src>`. The pure-emit analogue of `emitLoad`: a
  ## global/threadvar address is formed straight into `dest` (no borrowed temp),
  ## a complex lvalue routes through the `*2` address machinery.
  case src.kind
  of InReg: g.movReg(dest, src.r)
  of Imm: g.movImm(dest, src.ival)
  of NamedStack: g.emScalarLoad(dest, src.name)
  of Glob:
    # `dest = &g` then `dest = [dest]`. The deref must be typed `(ptr <globalType>)` so
    # it yields the global's PRECISE type: `dest` is bound to the *value* type, so a bare
    # `(mem dest)` drops a pointer level — harmless for a scalar global, but a POINTER
    # global would then load `object` where `(ptr object)` is wanted (nifasm is strict).
    # Cast the address in the deref rather than spend a scarce bridge (mirrors the x64
    # `scalarMemMov` Glob-load fix).
    g.emAdr(dest, src.name)
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree MemX:
        if not cursorIsNil(src.typ.typ):
          var pt = g.prog.ptrTypeOf(src.typ.typ)
          g.ab.tree CastX: (g.genTypeBody(pt); g.emReg dest)
        else:
          g.emReg dest
  of Tvar:
    if g.a64Linux: g.emAdr(dest, src.name)
    else: g.genTlvAddr(src.name, dest)
    g.ab.tree MovA64: (g.emReg dest; g.ab.tree MemX: g.emReg dest)
  of Mem:
    g.prematLval2(src.cur)
    g.ab.tree MovA64: (g.emReg dest; g.ab.tree MemX: g.emLvalAddr2(src.cur))
    g.unbindLvalTemps2(src.cur)
  else: raiseAssert "arkham a64n: place2 src " & $src.kind

proc placeF2(g: var CodeGen; src: Location; dest: FReg; bits: int) =
  ## `dest ← <float Location src>`.
  case src.kind
  of InFReg: g.fmovF(dest, src.f, bits)
  of NamedStack: g.emFloatScalarLoad(dest, src.name, bits)
  of Glob:
    let b = g.takeBridge(); g.emAdr(b, src.name); g.emFLoad(dest, b, bits); g.dropBridge b
  of Mem:
    g.prematLval2(src.cur)
    g.ab.tree FldrA64: (g.emFReg(dest, bits); g.ab.tree MemX: g.emLvalAddr2(src.cur))
    g.unbindLvalTemps2(src.cur)
  else: raiseAssert "arkham a64n: placeF2 src " & $src.kind

proc storeReg2(g: var CodeGen; dst: Location; src: Reg) =
  ## `<scalar Location dst> ← src` (integer/pointer).
  case dst.kind
  of InReg: g.movReg(dst.r, src)
  of NamedStack: g.emScalarStore(dst.name, src)
  of Glob:
    let b = g.takeBridge(); g.emAdr(b, dst.name)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emReg b
      g.emReg src
    g.dropBridge b
  of Tvar:
    let b = g.takeBridge()
    if g.a64Linux: g.emAdr(b, dst.name) else: g.genTlvAddr(dst.name, b)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emReg b
      g.emReg src
    g.dropBridge b
  of Mem:
    g.prematLval2(dst.cur)
    g.ab.tree MovA64:
      g.ab.tree MemX: g.emLvalAddr2(dst.cur)
      g.emReg src
    g.unbindLvalTemps2(dst.cur)
  else: raiseAssert "arkham a64n: storeReg2 dst " & $dst.kind

proc storeFReg2(g: var CodeGen; dst: Location; src: FReg; bits: int) =
  case dst.kind
  of InFReg: g.fmovF(dst.f, src, bits)
  of NamedStack: g.emFloatScalarStore(dst.name, src, bits)
  of Glob:
    let b = g.takeBridge(); g.emAdr(b, dst.name); g.emFStore(src, b, bits); g.dropBridge b
  of Mem:
    g.prematLval2(dst.cur)
    g.ab.tree FstrA64:
      g.ab.tree MemX: g.emLvalAddr2(dst.cur)
      g.emFReg(src, bits)
    g.unbindLvalTemps2(dst.cur)
  else: raiseAssert "arkham a64n: storeFReg2 dst " & $dst.kind

# ── lvalue addressing (mirrors x64 emLvalAddr2/prematLval2/unbindLvalTemps2) ──

proc reloadMemBase2(g: var CodeGen; pos: int) =
  ## A deref/at/pat base or register index the allocator spilled (NamedStack/Mem)
  ## must be in a register for `[reg]` addressing: load it into a bridge, repoint
  ## its location, and park the home so `restoreMemBase2` puts it back. (A register-
  ## homed base returns immediately — no steal can move it under us anymore.)
  let loc = g.ra.locs[pos]
  if loc.kind notin {NamedStack, Mem}: return
  let s = g.takeBridge(loc.typ)
  g.place2(loc, s)
  g.savedHomes[pos] = loc
  g.ra.locs[pos] = regLoc(s, loc.typ)

proc restoreMemBase2(g: var CodeGen; pos: int) =
  if g.savedHomes.hasKey(pos):
    g.dropBridge g.ra.locs[pos].r
    g.ra.locs[pos] = g.savedHomes[pos]
    g.savedHomes.del pos

proc prematAddrVal2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue base/index value `c` into a register for the enclosing
  ## `(mem …)`. A register-homed base materializes in place; a genuinely spilled base
  ## (`NamedStack`/`Mem`) is brought into a bridge by `reloadMemBase2`. Scoped to the
  ## lvalue tree (NOT general `emitValue2`).
  let pos = g.posOf(c)
  g.emitValue2(c)
  g.reloadMemBase2(pos)

proc emLvalAddr2(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (operand of a `(mem …)`/`(lea
  ## …)`), reading any embedded value register from its pre-allocated `locs`.
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm)
    if loc.kind == Undef:                                 # module-level global base
      let baseReg = g.ra.locs[g.posOf(c)]
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                               # (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg baseReg.r
    elif loc.kind == InReg and g.varType.hasKey(nm):      # by-ref aggregate param (pointer)
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym g.varType[nm]
        g.emReg loc.r
    else:                                                 # a `(s)` stack-var base
      g.ab.sym nm
  of TagLit:
    case c.exprKind
    of DotC:
      g.ab.tree DotX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                      # base
          g.ab.sym symName(cc); skip cc                   # field name
          while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      g.ab.tree AtX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                      # base
          case cc.kind                                    # index (nifasm scales it)
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else: g.emReg g.ra.locs[g.posOf(cc)].r          # register index
          skip cc
          if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
            g.emReg g.ra.aux[atPos].scratch[0]            # non-scale stride scratch
          while cc.hasMore: skip cc
    of DerefC:
      var pointee = g.getType(c)
      var cc = c
      cc.into:
        let pReg = g.ra.locs[g.posOf(cc)]
        g.ab.tree CastX:
          g.ab.ptrType:
            if pointee.kind == Symbol: g.ab.sym symName(pointee)
            else: g.genTypeBody(pointee)
          g.emReg pReg.r
        while cc.hasMore: skip cc
    of PatC:
      let patPos = g.posOf(c)
      var elem = g.getType(c)
      g.ab.tree AtX:
        var cc = c
        cc.into:
          let pReg = g.ra.locs[g.posOf(cc)]
          g.ab.tree CastX:
            g.ab.aptrType:
              if elem.kind == Symbol: g.ab.sym symName(elem)
              else: g.genTypeBody(elem)
            g.emReg pReg.r
          skip cc                                         # past pointer
          case cc.kind                                    # index
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else: g.emReg g.ra.locs[g.posOf(cc)].r
          skip cc
          if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
            g.emReg g.ra.aux[patPos].scratch[0]           # non-scale stride scratch
          while cc.hasMore: skip cc
    of BaseobjC:
      # `(baseobj BaseType depth lvalue)` — object→base view. Base sub-object at offset 0,
      # so the ADDRESS is the inner lvalue's, only the TYPE narrows. A `(deref p)` inner
      # re-emits as `(cast (ptr BaseType) p)`; any other inner is transparent (nifasm
      # flattens inherited fields).
      var cc = c
      cc.into:
        let baseTy = cc; skip cc                          # base type (a Symbol)
        skip cc                                           # depth
        if cc.kind == TagLit and cc.exprKind == DerefC:
          var dc = cc
          dc.into:
            let pReg = g.ra.locs[g.posOf(dc)]
            g.ab.tree CastX:
              g.ab.ptrType: g.ab.sym symName(baseTy)
              g.emReg pReg.r
            while dc.hasMore: skip dc
        else:
          g.emLvalAddr2(cc)                               # transparent
        while cc.hasMore: skip cc
    else: raiseAssert "arkham a64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emLvalAddr2 kind " & $c.kind

proc prematLval2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue's embedded values (a deref pointer, an index, a global
  ## base address) into their allocated registers BEFORE the consuming `(mem …)`/
  ## `(lea …)` tree opens.
  if c.kind == Symbol:
    let loc = g.ra.locs[g.posOf(c)]
    if loc.kind == InReg and g.ra.locationOfSym(symName(c)).kind == Undef:
      # a module-level global aggregate base: `lea reg, &g` into the address register
      # the allocator assigned (already bound by the caller — the access result reg for
      # a load/addr, or the aux store scratch for a store).
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
        g.prematAddrVal2(cc)                              # the pointer → its reg (follow steals)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      cc.into:
        g.prematLval2(cc); skip cc                        # base
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.bindTemp(g.ra.aux[atPos].scratch[0], ScalarSlot)
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      cc.into:
        g.prematAddrVal2(cc)                              # the pointer → its reg (follow steals)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
        g.bindTemp(g.ra.aux[patPos].scratch[0], ScalarSlot)
    of BaseobjC:                                          # transparent: materialize inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                                 # base type, depth
        g.prematLval2(cc)
        while cc.hasMore: skip cc
    else: discard

proc unbindLvalTemps2(g: var CodeGen; c: Cursor) =
  ## Release scratch an lvalue's embedded value used (a reloaded base/index), AFTER
  ## the consuming `(mem …)`/`(lea …)` instruction.
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc); skip cc
        if cc.kind notin {IntLit, UIntLit}:
          let idxPos = g.posOf(cc)
          g.restoreMemBase2(idxPos)
          let il = g.ra.locs[idxPos]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.unbindTemp(g.ra.aux[atPos].scratch[0])
    of DerefC:
      var cc = c
      cc.into:
        let pPos = g.posOf(cc)
        g.restoreMemBase2(pPos)
        let ploc = g.ra.locs[pPos]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        while cc.hasMore: skip cc
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      cc.into:
        let pPos = g.posOf(cc)
        g.restoreMemBase2(pPos)
        let ploc = g.ra.locs[pPos]
        if ploc.kind == InReg and ploc.isTemp: g.unbindTemp(ploc.r)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          let idxPos = g.posOf(cc)
          g.restoreMemBase2(idxPos)
          let il = g.ra.locs[idxPos]
          if il.kind == InReg and il.isTemp: g.unbindTemp(il.r)
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
        g.unbindTemp(g.ra.aux[patPos].scratch[0])
    of BaseobjC:                                          # transparent: release inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                                 # base type, depth
        g.unbindLvalTemps2(cc)
        while cc.hasMore: skip cc
    else: discard

# ── memory loads / address-of ────────────────────────────────────────────────

proc emitMemLoad2(g: var CodeGen; c: Cursor) =
  ## Load the scalar at lvalue `c` into its pre-allocated result register.
  let res = g.ra.locs[g.posOf(c)]
  assert res.kind == InReg, "arkham a64n: mem-load result " & $res.kind
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    if res.isTemp: g.bindTemp(res.r, ScalarSlot)          # array lvalue DECAYS to its address
    g.prematLval2(c)
    g.ab.tree LeaA64: (g.emReg res.r; g.emLvalAddr2(c))
    g.unbindLvalTemps2(c)
    return
  var bindSlot = res.typ
  if isPtrType(cty): bindSlot = g.exprSlot(c)
  if res.isTemp: g.bindTemp(res.r, bindSlot)
  g.prematLval2(c)
  g.ab.tree MovA64:
    g.emReg res.r
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)

proc emitFMemLoad2(g: var CodeGen; c: Cursor) =
  let res = g.ra.locs[g.posOf(c)]
  assert res.kind == InFReg, "arkham a64n: float mem-load result " & $res.kind
  let bits = if res.typ.size == 4: 32 else: 64
  if res.isTemp: g.bindFTmp(res.f, bits)
  g.prematLval2(c)
  g.ab.tree FldrA64:
    g.emFReg(res.f, bits)
    g.ab.tree MemX: g.emLvalAddr2(c)
  g.unbindLvalTemps2(c)

proc bindLvalGlobalBases(g: var CodeGen; c: Cursor; bound: var seq[Reg]) =
  ## Bind every UNBOUND global-base address register in lvalue `c` so `prematLval2` leas
  ## `&global` into a bound register (`emReg` rejects an unbound scratch). Skips an
  ## already-bound base reg (a caller — e.g. `emitAddr2` — may reuse its bound result reg).
  if c.kind == Symbol:
    let loc = g.ra.locs[g.posOf(c)]
    if loc.kind == InReg and loc.isTemp and loc.r notin g.boundTemps and
       g.ra.locationOfSym(symName(c)).kind == Undef:
      g.bindTemp(loc.r, ScalarSlot)
      bound.add loc.r
  elif c.kind == TagLit and c.exprKind in {AtC, DotC, DerefC, PatC}:
    var cc = c
    cc.into:
      g.bindLvalGlobalBases(cc, bound); skip cc          # the base only
      while cc.hasMore: skip cc

proc aggrAddrInto(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool) =
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
    g.emitValue2(p)
    let pLoc = g.ra.locs[g.posOf(p)]
    if doBind:
      g.bindTemp(dest, AsmSlot(cls: AUInt, size: 8, align: 8, typ: g.getType(p)))
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
      g.emitValue2(p)
      let pLoc = g.ra.locs[g.posOf(p)]
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
    let home = g.ra.locationOfSym(symName(lv))
    if doBind: g.bindTemp(dest, aslot)
    case home.kind
    of NamedStack:                                      # &local stack slot
      g.ab.tree LeaA64:
        g.emReg dest
        g.ab.sym home.name
    of InReg: g.movReg(dest, home.r)                    # by-ref aggregate param: reg holds &it
    else: raiseAssert "arkham a64n: aggrAddr of local " & symName(lv) & " home " & $home.kind
  else:
    if doBind: g.bindTemp(dest, aslot)
    var bound: seq[Reg] = @[]
    g.bindLvalGlobalBases(lv, bound)                    # bind any UNBOUND global-base reg first
    g.prematLval2(lv)
    g.ab.tree LeaA64: (g.emReg dest; g.emLvalAddr2(lv))
    g.unbindLvalTemps2(lv)
    for r in bound: g.unbindTemp(r)

proc emitAddr2(g: var CodeGen; c: Cursor) =
  ## `(addr lvalue)` → pointer in the result register, via the shared `aggrAddrInto`.
  var res = g.ra.locs[g.posOf(c)]
  let memRes = res
  var addrStaging = NoReg
  if res.kind in {NamedStack, Mem}:
    addrStaging = g.takeBridge(res.typ)
    res = regLoc(addrStaging, res.typ)
  else:
    assert res.kind == InReg, "arkham a64n: addr result " & $res.kind
  let aslot = g.exprSlot(c)
  var lv: Cursor
  block:
    var cc = c
    cc.into:
      lv = cc; skip cc
      while cc.hasMore: skip cc
  g.aggrAddrInto(lv, res.r, aslot, doBind = res.isTemp)
  if addrStaging != NoReg:
    g.storeReg2(memRes, addrStaging)
    g.dropBridge addrStaging

# ── integer arithmetic ───────────────────────────────────────────────────────

proc binA64Op(g: var CodeGen; c: Cursor): A64Inst =
  ## The a64 opcode for a binary-arith node; div/shift signedness from the result type.
  var rt: Cursor
  block:
    var cc = c
    cc.into:
      rt = cc
      while cc.hasMore: skip cc
  let signed = isSignedType(rt)
  case c.exprKind
  of AddC: AddA64
  of SubC: SubA64
  of MulC: MulA64
  of DivC: (if signed: SdivA64 else: UdivA64)
  of ShlC: LslA64
  of ShrC: (if signed: AsrA64 else: LsrA64)
  of BitandC: AndA64
  of BitorC: OrrA64
  of BitxorC: EorA64
  else: raiseAssert "arkham a64n: binA64Op " & $c.exprKind

proc foldRhs2(g: var CodeGen; op: A64Inst; dest: Reg; rhsLoc: Location; rhsC: Cursor) =
  ## `dest = dest op rhs`, materializing the rhs as a64 needs (no memory operand; a
  ## large/non-add immediate goes through a bridge). `dest` already holds the lhs.
  case rhsLoc.kind
  of Imm:
    if op in {AddA64, SubA64} and rhsLoc.ival >= 0 and rhsLoc.ival <= 0xFFFF:
      g.binImm(op, dest, rhsLoc.ival)
    else:
      let b = g.takeBridge(avoid = dest)
      g.movImm(b, rhsLoc.ival)
      g.binReg(op, dest, b)
      g.dropBridge b
  of InReg:
    g.binReg(op, dest, rhsLoc.r)
  of NamedStack, Mem, Glob, Tvar:
    let b = g.takeBridge(avoid = dest)
    g.place2(rhsLoc, b)
    g.binReg(op, dest, b)
    g.dropBridge b
  else: raiseAssert "arkham a64n: foldRhs2 " & $rhsLoc.kind

proc emitBin2(g: var CodeGen; c: Cursor) =
  ## `(op T a b)` → `dest = a op b` into the precomputed result register, replaying
  ## the allocator's operand placement (swapped / foldB / aliasRhs).
  let pos = g.posOf(c)
  let res = g.ra.locs[pos]
  let op = g.binA64Op(c)
  var lhsC, rhsC: Cursor
  block:
    var cc = c
    cc.into:
      skip cc                                             # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let aux = g.ra.aux.getOrDefault(pos)
  if aux.swapped:
    assert res.kind == InReg, "arkham a64n: bin(swapped) result " & $res.kind
    let rD = res.r
    g.emitValue2(rhsC)                                    # rhs → rD first
    let lhsLoc = g.ra.locs[g.posOf(lhsC)]
    let foldOp = if op == SubA64: AddA64 else: op
    if op == SubA64:
      g.ab.tree NegA64: g.emReg rD                        # rD := -rhs
    g.foldRhs2(foldOp, rD, lhsLoc, lhsC)                  # rD := rD <foldOp> lhs
    return
  g.emitValue2(lhsC)
  g.emitValue2(rhsC)
  let lhsLoc = g.ra.locs[g.posOf(lhsC)]
  let rhsLoc = g.ra.locs[g.posOf(rhsC)]
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:
    resStaging = g.takeBridge(res.typ)
    rD = resStaging
  else:
    assert res.kind == InReg, "arkham a64n: bin result " & $res.kind
    rD = res.r
  let reusedLhs = lhsLoc.kind == InReg and lhsLoc.r == rD
  if res.isTemp and not reusedLhs: g.bindTemp(rD, res.typ)
  if aux.aliasRhs:
    assert lhsLoc.kind == InReg, "arkham a64n: aliasRhs lhs " & $lhsLoc.kind
    g.binReg(op, rD, lhsLoc.r)                            # dest := rhs op lhs
    if op == SubA64:
      g.ab.tree NegA64: g.emReg rD                        # dest := lhs - rhs
  else:
    g.place2(lhsLoc, rD)                                  # dest := lhs
    g.foldRhs2(op, rD, rhsLoc, rhsC)                      # dest op= rhs
  if rhsLoc.kind == InReg and rhsLoc.isTemp: g.unbindTemp(rhsLoc.r)
  if lhsLoc.kind == InReg and lhsLoc.isTemp and not reusedLhs: g.unbindTemp(lhsLoc.r)
  if resStaging != NoReg:
    g.storeReg2(res, resStaging)
    g.dropBridge resStaging

proc emitMod2(g: var CodeGen; c: Cursor) =
  ## `(mod T a b)` → `dest = a - (a div b)*b` (a64 has no `msub` in nifasm). The
  ## dividend is in `dest`, the divisor in a register (allocDivModRisc forced it).
  let pos = g.posOf(c)
  let res = g.ra.locs[pos]
  var rt, divC, dvsC: Cursor
  block:
    var cc = c
    cc.into:
      rt = cc; skip cc
      divC = cc; skip cc
      dvsC = cc; skip cc
      while cc.hasMore: skip cc
  let signed = isSignedType(rt)
  g.emitValue2(divC)
  g.emitValue2(dvsC)
  let divLoc = g.ra.locs[g.posOf(divC)]
  let dvsLoc = g.ra.locs[g.posOf(dvsC)]
  assert dvsLoc.kind == InReg, "arkham a64n: mod divisor " & $dvsLoc.kind
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:
    resStaging = g.takeBridge(res.typ); rD = resStaging
  else:
    assert res.kind == InReg, "arkham a64n: mod result " & $res.kind
    rD = res.r
  let reusedDiv = divLoc.kind == InReg and divLoc.r == rD
  if res.isTemp and not reusedDiv: g.bindTemp(rD, res.typ)
  g.place2(divLoc, rD)                                    # dest := a
  let q = g.takeBridge(avoid = rD)
  g.movReg(q, rD)                                         # q := a
  g.binReg(if signed: SdivA64 else: UdivA64, q, dvsLoc.r) # q := a div b
  g.binReg(MulA64, q, dvsLoc.r)                           # q := (a div b)*b
  g.binReg(SubA64, rD, q)                                 # dest := a - q
  g.dropBridge q
  if dvsLoc.kind == InReg and dvsLoc.isTemp: g.unbindTemp(dvsLoc.r)
  if divLoc.kind == InReg and divLoc.isTemp and not reusedDiv: g.unbindTemp(divLoc.r)
  if resStaging != NoReg:
    g.storeReg2(res, resStaging)
    g.dropBridge resStaging

# ── float arithmetic ─────────────────────────────────────────────────────────

proc fbinA64Op(ek: LengExpr): A64Inst =
  case ek
  of AddC: FaddA64
  of SubC: FsubA64
  of MulC: FmulA64
  of DivC: FdivA64
  else: raiseAssert "arkham a64n: fbinA64Op " & $ek

proc ensureFAccum2(g: var CodeGen; resF: FReg; loc: Location; bits: int) =
  ## Make `resF` hold the value just produced at `loc` (usually a no-op — the
  ## allocator dest-passed the operand into resF; otherwise move/load it in).
  case loc.kind
  of InFReg:
    if loc.f != resF:
      g.fmovF(resF, loc.f, bits)
      if loc.isTemp: g.unbindFTmp(loc.f)
  of NamedStack: g.emFloatScalarLoad(resF, loc.name, bits)
  else: raiseAssert "arkham a64n: float accumulator source " & $loc.kind

proc emitFBin2(g: var CodeGen; c: Cursor) =
  ## `(op (f N) a b)` → `dest = a op b` (the SIMD twin of emitBin2).
  let pos = g.posOf(c)
  let res = g.ra.locs[pos]
  assert res.kind == InFReg, "arkham a64n: float bin result " & $res.kind
  let op = fbinA64Op(c.exprKind)
  let bits = if res.typ.size == 4: 32 else: 64
  var lhsC, rhsC: Cursor
  block:
    var cc = c
    cc.into:
      skip cc                                             # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let aux = g.ra.aux.getOrDefault(pos)
  if aux.swapped:
    g.emitFValue2(rhsC)
    g.ensureFAccum2(res.f, g.ra.locs[g.posOf(rhsC)], bits)
    let lhome = g.ra.locationOfSym(symName(lhsC))
    if lhome.kind == InFReg:
      g.fbin(op, res.f, lhome.f, bits)
    else:
      let lt = g.takeFBridge(bits)
      g.emFloatScalarLoad(lt, lhome.name, bits)
      g.fbin(op, res.f, lt, bits)
      g.dropFBridge()
    return
  g.emitFValue2(lhsC)
  g.ensureFAccum2(res.f, g.ra.locs[g.posOf(lhsC)], bits)
  let rhsLoc = g.ra.locs[g.posOf(rhsC)]
  if rhsLoc.kind == InFReg and not rhsLoc.isTemp:
    g.fbin(op, res.f, rhsLoc.f, bits)
  elif rhsLoc.kind == NamedStack:
    g.emitFValue2(rhsC)
    let fs = g.takeFBridge(bits)
    g.emFloatScalarLoad(fs, rhsLoc.name, bits)
    g.fbin(op, res.f, fs, bits)
    g.dropFBridge()
  else:
    g.emitFValue2(rhsC)
    g.fbin(op, res.f, rhsLoc.f, bits)
    if rhsLoc.isTemp: g.unbindFTmp(rhsLoc.f)

# ── casts / conversions ──────────────────────────────────────────────────────

proc emitCast2(g: var CodeGen; c: Cursor) =
  ## `(conv|cast Type inner)`. Int/ptr and to/from float.
  let isCast = c.exprKind == CastC
  var targetCur, tc, inner: Cursor
  block:
    var cc = c
    cc.into:
      targetCur = cc
      tc = resolveType(g.prog, cc); skip cc
      inner = cc; skip cc
      while cc.hasMore: skip cc
  let res = g.ra.locs[g.posOf(c)]
  if res.kind == Imm: return                              # identity over a folded immediate
  if res.kind == InFReg:                                  # → float
    let dstBits = if res.typ.size == 4: 32 else: 64
    if g.isFloatExpr(inner):
      g.emitFValue2(inner)
      let fv = g.ra.locs[g.posOf(inner)]
      if res.isTemp: g.bindFTmp(res.f, dstBits)
      let srcBits = g.floatBits(inner)
      if srcBits == dstBits: g.ensureFAccum2(res.f, fv, dstBits)
      else:
        if fv.kind == InFReg: g.emFcvt(res.f, fv.f, dstBits, srcBits)
        else: (let b = g.takeFBridge(srcBits); g.placeF2(fv, b, srcBits); g.emFcvt(res.f, b, dstBits, srcBits); g.dropFBridge())
        if fv.kind == InFReg and fv.isTemp: g.unbindFTmp(fv.f)
    else:
      g.emitValue2(inner)
      let iv = g.ra.locs[g.posOf(inner)]
      assert iv.kind == InReg, "arkham a64n: int→float operand " & $iv.kind
      if res.isTemp: g.bindFTmp(res.f, dstBits)
      let (srcW, srcSigned) = g.srcWidthSigned(inner)
      if isCast:
        g.fmovFromGpr(res.f, iv.r, dstBits)
      else:
        g.extendTo(iv.r, srcW, srcSigned)
        g.fcvtI2F(if srcSigned: ScvtfA64 else: UcvtfA64, res.f, iv.r, dstBits)
      if iv.isTemp: g.unbindTemp(iv.r)
    return
  if g.isFloatExpr(inner):                                # float → int/ptr
    g.emitFValue2(inner)
    let fv = g.ra.locs[g.posOf(inner)]
    assert fv.kind == InFReg, "arkham a64n: float→int operand " & $fv.kind
    let fbits = if fv.typ.size == 4: 32 else: 64
    if res.isTemp: g.bindTemp(res.r, res.typ)
    if isCast:
      g.fmovToGpr(res.r, fv.f, fbits)
    else:
      g.fcvtF2I(if isSignedType(tc): FcvtzsA64 else: FcvtzuA64, res.r, fv.f, fbits)
      if not isPtrType(tc):
        let targetW = intTypeWidth(tc)
        if targetW < 64: g.extendTo(res.r, targetW, signed = isSignedType(tc))
    if fv.isTemp: g.unbindFTmp(fv.f)
    return
  # integer / pointer target
  g.emitValue2(inner)
  let iv = g.ra.locs[g.posOf(inner)]
  var res2 = res
  var castStaging = NoReg
  if res2.kind in {NamedStack, Mem}:
    castStaging = g.takeBridge(res2.typ)
    res2 = regLoc(castStaging, res2.typ)
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  let kindChange = ptrTarget or srcPtr
  template retypeCastRes() =
    if res2.isTemp:
      g.bindTemp(res2.r, (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot))
    else:
      let nm = g.regLocal.getOrDefault(res2.r, "")
      if nm.len > 0: g.rebindLocalAs(nm, res2.r, targetCur)
  if iv.kind in {NamedStack, Mem}:
    if kindChange: retypeCastRes()
    elif res2.isTemp: g.bindTemp(res2.r, res2.typ)
    g.place2(iv, res2.r)
  else:
    if iv.kind == InReg and iv.r != res2.r:
      if kindChange:
        retypeCastRes()
        var tcur = targetCur
        g.ab.tree MovA64:
          g.emReg res2.r
          g.ab.tree CastX: (g.genTypeBody(tcur); g.emReg iv.r)
      else:
        if res2.isTemp: g.bindTemp(res2.r, res2.typ)
        g.movReg(res2.r, iv.r)
    elif iv.kind == InReg:
      if kindChange: retypeCastRes()
    elif iv.kind == Imm:
      if kindChange: retypeCastRes()
      elif res2.isTemp: g.bindTemp(res2.r, res2.typ)
      g.movImm(res2.r, iv.ival)
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if kindChange:
    if ptrTarget and not srcPtr and srcW < 64: g.extendTo(res2.r, srcW, signed = false)
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW: g.extendTo(res2.r, srcW, signed = (not isCast) and srcSigned)
    else: g.extendTo(res2.r, targetW, signed = isSignedType(tc))
  if iv.kind == InReg and iv.isTemp and iv.r != res2.r: g.unbindTemp(iv.r)
  if castStaging != NoReg:
    g.storeReg2(res, castStaging)
    g.dropBridge castStaging

# ── calls ────────────────────────────────────────────────────────────────────

proc emitMemIntrin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Inline `mem*` byte loop. The allocator placed the 3 args in x0/x1/x2 (a normal
  ## int-arg call); during this leaf intrinsic the free arg registers x3/x4/x5 are the
  ## loop scratch (raw, caller-saved). Result → x0 (moved to its home by emitCall2).
  for idx in 0 ..< min(3, argCurs.len):
    g.emitValue2(argCurs[idx])
    let a = g.ra.locs[g.posOf(argCurs[idx])]
    if a.kind == InReg and a.isTemp: g.unbindTemp(a.r)   # x0/x1/x2 used raw below
  let (dst, src, n) = (R0, R1, R2)                       # for memset: src holds `val`
  let (i, b, b2) = (R3, R4, R5)
  case builtin
  of "memcpy", "memmove":
    let loop = g.freshLabel(); let done = g.freshLabel()
    if builtin == "memmove":
      let fwd = g.freshLabel(); let bwd = g.freshLabel()
      g.ab.tree CmpA64: (g.ab.reg dst; g.ab.reg src)
      g.emBr(BlsA64, fwd)
      g.movReg(i, n)
      g.emLab(bwd)
      g.ab.tree CmpA64: (g.ab.reg i; g.ab.intLit 0)
      g.emBr(BeqA64, done)
      g.binImm(SubA64, i, 1)
      g.emLdrb(b, src, i); g.emStrb(b, dst, i)
      g.emBr(BA64, bwd)
      g.emLab(fwd)
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
    g.emBr(BhsA64, done)
    g.emLdrb(b, src, i); g.emStrb(b, dst, i)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(done)
    g.movReg(IntRet, dst)
  of "memset":
    let loop = g.freshLabel(); let done = g.freshLabel()
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
    g.emBr(BhsA64, done)
    g.emStrb(src, dst, i)                                # store low byte of `val` (in x1)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(done)
    g.movReg(IntRet, dst)
  of "memcmp":
    let loop = g.freshLabel(); let diff = g.freshLabel()
    let equal = g.freshLabel(); let done = g.freshLabel()
    g.movImm(i, 0)
    g.emLab(loop)
    g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
    g.emBr(BhsA64, equal)
    g.emLdrb(b, dst, i); g.emLdrb(b2, src, i)            # dst=pa, src=pb
    g.ab.tree CmpA64: (g.ab.reg b; g.ab.reg b2)
    g.emBr(BneA64, diff)
    g.binImm(AddA64, i, 1)
    g.emBr(BA64, loop)
    g.emLab(diff)
    g.movReg(IntRet, b); g.binReg(SubA64, IntRet, b2)
    g.emBr(BA64, done)
    g.emLab(equal)
    g.movImm(IntRet, 0)
    g.emLab(done)
  else: raiseAssert "arkham a64n: unsupported mem intrinsic: " & builtin

proc atomicBits(g: var CodeGen; ptrArg: Cursor): int =
  ## Access width (bits) of an atomic = the size of the pointee of `ptrArg` (a `ptr T`).
  ## The LL/SC exclusive ops MUST be sized to this (see sizeFieldA64 in nifasm): a
  ## 64-bit `ldaxr`/`stlxr` on a sub-64-bit lock word reads/writes the adjacent bytes,
  ## so its compare sees the neighbour's bits and its store corrupts them.
  var t = g.getType(ptrArg)
  if isPtrType(t):
    inc t
    result = typeSizeAlign(g.prog, resolveType(g.prog, t))[0] * 8
  else:
    result = 64
  if result notin {8, 16, 32, 64}: result = 64

proc wsfx(bits: int): string =
  ## Trailing access-width operand for the LL/SC asm-NIF text (omitted for 64-bit, the
  ## nifasm parse default — keeps the common case's output unchanged).
  if bits != 64: &" {bits}" else: ""

proc emitRmw2(g: var CodeGen; opStr: string; isXchg, returnNew: bool; bits: int) =
  ## `loop: ldaxr old,[x0]; new = old op x1 (or x1 for xchg); stlxr st,new,[x0];
  ## cmp st,0; bne loop`. Scratch x3/x4/x5 (raw). Result → x0. Sized to `bits`.
  let loop = g.freshLabel()
  let p = g.emOp R0
  let v = g.emOp R1
  let old = g.emOp R3
  let neu = g.emOp R4
  let st = g.emOp R5
  let w = wsfx(bits)
  let update = if isXchg: &"(mov {neu} {v})" else: &"(mov {neu} {old}) ({opStr} {neu} {v})"
  g.ab.splice &"(lab :{loop}) (ldaxr {old} {p}{w}) " & update & " " &
              &"(stlxr {st} {neu} {p}{w}) (cmp {st} 0) (bne {loop})"
  g.movReg(IntRet, if returnNew: R4 else: R3)

proc emitAtomic2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Inline `__atomic_*` LL/SC sequence. Args in x0(ptr)/x1(val|expPtr)/x2(des);
  ## loop scratch x3/x4/x5 (raw, free during this leaf op). Result → x0.
  for idx in 0 ..< argCurs.len:
    g.emitValue2(argCurs[idx])
    let a = g.ra.locs[g.posOf(argCurs[idx])]
    if a.kind == InReg and a.isTemp: g.unbindTemp(a.r)
  let bits = g.atomicBits(argCurs[0])
  case builtin
  of "__atomic_load_n": g.emLdar(IntRet, R0, bits)
  of "__atomic_store_n": g.emStlr(R1, R0, bits)
  of "__atomic_clear":
    g.movImm(R3, 0); g.emStlr(R3, R0, bits)
  of "__atomic_thread_fence": g.ab.keyword DmbA64
  of "__atomic_signal_fence": discard
  of "__atomic_exchange_n": g.emitRmw2("", true, false, bits)
  of "__atomic_fetch_add": g.emitRmw2("add", false, false, bits)
  of "__atomic_fetch_sub": g.emitRmw2("sub", false, false, bits)
  of "__atomic_fetch_and": g.emitRmw2("and", false, false, bits)
  of "__atomic_fetch_or": g.emitRmw2("orr", false, false, bits)
  of "__atomic_fetch_xor": g.emitRmw2("eor", false, false, bits)
  of "__atomic_add_fetch": g.emitRmw2("add", false, true, bits)
  of "__atomic_sub_fetch": g.emitRmw2("sub", false, true, bits)
  of "__atomic_compare_exchange_n":
    let loop = g.freshLabel(); let lFail = g.freshLabel(); let lDone = g.freshLabel()
    let (pp, ep, d) = (g.emOp R0, g.emOp R1, g.emOp R2)
    let (exp, old, st, ret) = (g.emOp R3, g.emOp R4, g.emOp R5, g.emOp IntRet)
    let w = wsfx(bits)
    g.ab.splice(
      &"(ldar {exp} {ep}{w}) (lab :{loop}) (ldaxr {old} {pp}{w}) " &
      &"(cmp {old} {exp}) (bne {lFail}) (stlxr {st} {d} {pp}{w}) " &
      &"(cmp {st} 0) (bne {loop}) (mov {ret} 1) (b {lDone}) " &
      &"(lab :{lFail}) (clrex) (stlr {old} {ep}{w}) (mov {ret} 0) (lab :{lDone})")
  else: raiseAssert "arkham a64n: unsupported atomic builtin: " & builtin

proc proctypeOfTarget(g: var CodeGen; targetCur: Cursor): Cursor =
  ## The resolved proctype body of an indirect call target, for ABI queries. Two target
  ## shapes: a `(cast Proctype fnptr)` (vtable load) carries the proctype as its cast
  ## TARGET TYPE; any other fn-ptr EXPRESSION (e.g. a closure's `(dot clo fld.0)` proc
  ## field) carries it as the expression's TYPE — so resolve `getType(expr)`, not the
  ## expression itself. A `(ptr proctype)` field type is peeled to the proctype body.
  var ptType: Cursor
  if targetCur.kind == TagLit and targetCur.exprKind in {CastC, ConvC}:
    ptType = targetCur; inc ptType                       # the cast's target type
  else:
    ptType = g.getType(targetCur)                        # the fn-ptr expression's type
  result = resolveType(g.prog, ptType)
  if result.kind == TagLit and result.typeKind != ProctypeT:
    var inner = result; inc inner                        # peel `(ptr proctype)` → proctype
    result = resolveType(g.prog, inner)
  assert result.kind == TagLit and result.typeKind == ProctypeT,
    "arkham a64n: indirect call target is not a proctype"

proc emitCall2(g: var CodeGen; c: Cursor) =
  ## Emit a call. The allocator placed each argument in its ABI register and the
  ## result in x0 / v0 (or a dest-passed home).
  ##
  ## A STATIC call (target is a symbol) and an INDIRECT call (target is a fn-ptr
  ## expression, e.g. a vtable load) share this one path: both use the AAPCS64 ABI, so
  ## both run the same marshalling loop below. They differ only in how the `(prepare …)`
  ## symbol and the ABI signature are obtained — a cached `CallTarget` for a symbol, or
  ## one synthesized from the proctype with the fn-ptr evaluated into a (held,
  ## proctype-bound) register whose `regLocal` name nifasm accepts as the target.
  let pos = g.posOf(c)
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
      raiseAssert "arkham a64n: non-declarative indirect call not yet supported"
    var retType = proctype                           # the proctype's return type (3rd child)
    block:
      var q = proctype
      q.into:
        skip q; skip q                               # the Empty (name) slot, the params
        retType = q
        while q.hasMore: skip q
    # A `(cast Proctype …)` binds its register as a PROCTYPE-typed temp, whose `regLocal`
    # name is a ProcT symbol nifasm accepts as a `(prepare …)` target. It stays bound
    # across arg evaluation below.
    g.emitValue2(targetCur)                          # fn-ptr → its (held) register, proctype-bound
    let tloc = g.ra.locs[g.posOf(targetCur)]
    assert tloc.kind == InReg, "arkham a64n: indirect call target loc " & $tloc.kind
    fnptrReg = tloc.r
    fnptrTemp = tloc.isTemp
    assert g.regLocal.hasKey(fnptrReg), "arkham a64n: indirect call target not bound to a name"
    tgt = CallTarget(declarative: true, asmName: g.regLocal[fnptrReg], retType: retType)
  else:
    if not g.callTarget.hasKey(fsym):
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        g.callTarget[fsym] = CallTarget(declarative: true, indirect: true,
          asmName: fsym, retType: g.indirectRetType(si.decl))
      else:
        g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    tgt = g.callTarget[fsym]
    if tgt.memIntrin.len > 0:
      g.emitMemIntrin2(argCurs, tgt.memIntrin)
      if resLoc.kind == InReg and resLoc.r != IntRet: g.movReg(resLoc.r, IntRet)
      return
    if tgt.atomic.len > 0:
      g.emitAtomic2(argCurs, tgt.atomic)
      if resLoc.kind == InReg and resLoc.r != IntRet:
        if resLoc.isTemp: g.bindTemp(resLoc.r, AsmSlot(cls: AInt, size: 8, align: 8))
        g.movReg(resLoc.r, IntRet)
      return
    if tgt.bitBuiltin.len > 0:
      raiseAssert "arkham a64n: bit builtin not yet implemented: " & tgt.bitBuiltin
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: ScalarSlot
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let nStack = max(0, argCurs.len - IntArgRegs.len)
  if tgt.declarative:
    g.ab.tree PrepareA64:
      g.ab.sym tgt.asmName
      # Register args (x0–x7) first, while SP still points at the caller frame.
      for idx in 0 ..< min(argCurs.len, IntArgRegs.len):
        g.emitValue2(argCurs[idx])
        let aloc = g.ra.locs[g.posOf(argCurs[idx])]
        # Reference the arg register RAW: a checked-name temp binding carries a generic
        # `(i 64)` that nifasm's strict reg→reg `mov` rejects into a sub-width param.
        if aloc.kind == InReg and aloc.isTemp: g.unbindTemp(aloc.r)
        g.ab.tree MovA64:
          g.ab.tree ArgX: g.ab.sym paramName(idx)
          g.ab.reg aloc.r
      if nStack > 0:
        # Reserve the outgoing area, then compute + store each stack arg IMMEDIATELY:
        # the allocator reuses ONE scratch register for all stack args (each is dead
        # after its store), so they must not be deferred (else they clobber each other).
        g.ab.tree SubA64: g.emReg SP; g.ab.keyword CsizeX
        for idx in IntArgRegs.len ..< argCurs.len:
          g.emitValue2(argCurs[idx])
          let aloc = g.ra.locs[g.posOf(argCurs[idx])]
          g.ab.tree MovA64:
            g.ab.tree MemX:
              g.emReg SP
              g.ab.tree ArgX: g.ab.sym paramName(idx)
            g.emReg aloc.r
          if aloc.kind == InReg and aloc.isTemp: g.unbindTemp(aloc.r)
      if tgt.syscall:
        g.ab.tree SvcA64: g.ab.intLit 0
      else: g.ab.keyword CallA64
      if nStack > 0:
        g.ab.tree AddA64: g.emReg SP; g.ab.keyword CsizeX
      if hasResult:
        g.ab.tree MovA64:
          g.emReg IntRet
          g.ab.tree ResX: g.ab.sym "ret.0"
    # release the fn-ptr register (indirect only): its proctype temp is dead post-call.
    if indirect and fnptrTemp: g.unbindTemp(fnptrReg)
    if hasResult and resLoc.kind == InReg and resLoc.r != IntRet:
      # x0 itself is raw-usable (arg/return reg) and needs no binding; only a result
      # moved to a non-x0 home (a pool reg) is bound so its checked name resolves.
      if resLoc.isTemp and resSlot.kind != AMem: g.bindTemp(resLoc.r, resSlot)
      g.movReg(resLoc.r, IntRet)
  else:
    var intIdx = 0
    var fIdx = 0
    for idx in 0 ..< argCurs.len:
      let a = argCurs[idx]
      if g.isFloatExpr(a):
        g.emitFValue2(a)
        inc fIdx
      elif g.exprSlot(a).kind == AMem:
        # The "where do the bytes come from" dispatch lives here ONCE: a local/by-ref
        # symbol home, a global read in place, or any computed aggregate (oconstr/
        # aconstr/lvalue) built into a temp via the ONE general `genStore2`. The ABI
        # marshalling below is form-blind — driven only by the type's size.
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham a64: aggregate call-arg of non-nominal type"
        let tn = symName(tcur)
        let sz = aggrByteSize(g.prog, tn)
        if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
          # An aggregate LVALUE argument: take its ADDRESS (`aggrAddrInto`) and marshal
          # STRAIGHT from there — no copy temp (the seam that coupled the call path to
          # `genStore2`). The allocator reserved one address scratch.
          let srcAddr = g.ra.aux[g.posOf(a)].scratch[^1]
          g.aggrAddrInto(a, srcAddr, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = true)
          if sz > 16:
            g.movReg(IntArgRegs[intIdx], srcAddr); inc intIdx
          else:
            g.marshalAggrFromAddr(srcAddr, tn, intIdx)
            intIdx += aggrWordCount(g.prog, tn)
          g.unbindTemp(srcAddr)
        else:
          var home = ""                                   # a named home (stack / by-ref param / temp)
          var isGlobal = false                            # else "" + isGlobal ⇒ read &global in place
          if a.kind == Symbol:
            case g.lookupSym(symName(a)).cat
            of scGlobal: isGlobal = true
            of scTvar: raiseAssert "arkham a64: aggregate threadvar passed by value not supported"
            else: home = symName(a)                       # local stack slot OR by-ref param (InReg)
          else:                                           # oconstr/aconstr: build into a temp
            let pos = g.posOf(a)
            home = "aggtmp" & $pos & ".0"
            g.emTypedStackVar(home, tcur)
            g.varType[home] = tn
            g.genStore2(a, namedStackLoc(home, g.exprSlot(a)), pos)
          if sz > 16:                                     # by-reference: address → one GPR
            if isGlobal: g.emGlobalAddr(IntArgRegs[intIdx], symName(a))
            elif g.ra.locationOfSym(home).kind == InReg:  # by-ref param: pointer already in a reg
              g.movReg(IntArgRegs[intIdx], g.ra.locationOfSym(home).r)
            else: g.ab.tree LeaA64: (g.emReg IntArgRegs[intIdx]; g.ab.sym home)
            inc intIdx
          else:                                           # by-value: words → x{n}
            let nw = aggrWordCount(g.prog, tn)
            if isGlobal: g.globalToRegs(symName(a), tn, intIdx)
            else: g.structToRegs(home, tn, intIdx)
            intIdx += nw
      else:
        g.emitValue2(a)
        inc intIdx
    g.ab.tree PrepareA64:
      g.ab.sym tgt.asmName
      g.ab.keyword (if tgt.extern: ExtcallA64 else: CallA64)
    if hasResult:
      if resultIsFloat:
        if resLoc.kind == InFReg:
          let rbits = if resSlot.size == 4: 32 else: 64
          if resLoc.isTemp: g.bindFTmp(resLoc.f, rbits)
          if resLoc.f != FloatRet: g.fmovF(resLoc.f, FloatRet, rbits)
      elif resLoc.kind == InReg and resLoc.r != IntRet:
        if resLoc.isTemp and resSlot.kind != AMem: g.bindTemp(resLoc.r, resSlot)
        g.movReg(resLoc.r, IntRet)

# ── conditions ───────────────────────────────────────────────────────────────

proc emitCond2(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## Branch to `toLabel` when condition `c` holds (`whenTrue`).
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
    of NotC: g.emitCond2(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCond2(aC, lSkip, false)
        g.emitCond2(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCond2(aC, toLabel, false)
        g.emitCond2(bC, toLabel, false)
    else:
      if whenTrue:
        g.emitCond2(aC, toLabel, true)
        g.emitCond2(bC, toLabel, true)
      else:
        let lSkip = g.freshLabel()
        g.emitCond2(aC, lSkip, true)
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
      let fbits = g.floatBits(aC)
      let tag =
        case ek
        of EqC:  (if whenTrue: BeqA64 else: BneA64)
        of NeqC: (if whenTrue: BneA64 else: BeqA64)
        of LtC:  (if whenTrue: BloA64 else: BhsA64)
        of LeC:  (if whenTrue: BlsA64 else: BhiA64)
        else: raiseAssert "arkham a64n: float cond " & $ek
      g.emitFValue2(aC)
      g.emitFValue2(bC)
      let aLoc = g.ra.locs[g.posOf(aC)]
      let bLoc = g.ra.locs[g.posOf(bC)]
      g.ab.tree FcmpA64: g.emFReg(aLoc.f, fbits); g.emFReg(bLoc.f, fbits)
      g.emBr(tag, toLabel)
      if bLoc.isTemp: g.unbindFTmp(bLoc.f)
      if aLoc.isTemp: g.unbindFTmp(aLoc.f)
      return
    let signed = not (g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC))
    let tag =
      case ek
      of EqC:  (if whenTrue: BeqA64 else: BneA64)
      of NeqC: (if whenTrue: BneA64 else: BeqA64)
      of LtC:  (if whenTrue: (if signed: BltA64 else: BloA64) else: (if signed: BgeA64 else: BhsA64))
      of LeC:  (if whenTrue: (if signed: BleA64 else: BlsA64) else: (if signed: BgtA64 else: BhiA64))
      else: raiseAssert "arkham a64n: cond " & $ek
    g.emitValue2(aC)
    let aLoc0 = g.ra.locs[g.posOf(aC)]
    var aReg = NoReg
    var aBridge = NoReg
    if aLoc0.kind == InReg: aReg = aLoc0.r
    else: (aBridge = g.takeBridge(aLoc0.typ); g.place2(aLoc0, aBridge); aReg = aBridge)
    let bLoc = g.ra.locs[g.posOf(bC)]
    if bLoc.kind == Imm and bLoc.ival >= 0 and bLoc.ival <= 0xFFFF:
      g.ab.tree CmpA64: (g.emReg aReg; g.ab.intLit bLoc.ival)
    else:
      g.emitValue2(bC)
      let bL = g.ra.locs[g.posOf(bC)]
      var bReg = NoReg
      var bBridge = NoReg
      if bL.kind == InReg: bReg = bL.r
      else: (bBridge = g.takeBridge(bL.typ, avoid = aReg); g.place2(bL, bBridge); bReg = bBridge)
      g.ab.tree CmpA64: (g.emReg aReg; g.emReg bReg)
      if bL.kind == InReg and bL.isTemp: g.unbindTemp(bL.r)
      if bBridge != NoReg: g.dropBridge bBridge
    g.emBr(tag, toLabel)
    if aBridge != NoReg: g.dropBridge aBridge
    elif aLoc0.kind == InReg and aLoc0.isTemp: g.unbindTemp(aLoc0.r)
    return
  g.emitValue2(c)
  let v = g.ra.locs[g.posOf(c)]
  assert v.kind == InReg, "arkham a64n: bool cond " & $v.kind
  g.ab.tree CmpA64: (g.emReg v.r; g.ab.intLit 0)
  g.emBr(if whenTrue: BneA64 else: BeqA64, toLabel)
  if v.isTemp: g.unbindTemp(v.r)

proc emitCondValue2(g: var CodeGen; c: Cursor) =
  ## A comparison / and/or/not as a 0/1 value: assume 1, clear to 0 unless it holds.
  let res = g.ra.locs[g.posOf(c)]
  assert res.kind == InReg, "arkham a64n: cond-value result " & $res.kind
  if res.isTemp: g.bindTemp(res.r, res.typ)
  let lEnd = g.freshLabel()
  g.movImm(res.r, 1)
  g.emitCond2(c, lEnd, whenTrue = true)
  g.movImm(res.r, 0)
  g.emLab(lEnd)

# ── value dispatch ───────────────────────────────────────────────────────────

proc produceIntoMem2(g: var CodeGen; c: Cursor; pos: int; dst: Location) =
  ## Totality bridge: the allocator spilled this value position to a stack slot.
  ## Produce it into the reserved produce bridge (x16, isolated from the x14/x15 fold
  ## bridges so it never collides during the recursion) — NOT held across the
  ## recursion, so a deep right-nested spilled chain reuses the same bridge level-by-
  ## level — then store it to the slot.
  let s = R16                                             # the produce bridge (IP0; free here)
  g.ra.locs[pos] = regLoc(s, dst.typ, isTemp = true)
  g.emitValue2(c)                                         # produces into s (binds it at its combine)
  g.ra.locs[pos] = dst
  g.storeReg2(dst, s)
  g.unbindTemp(s)

proc emitValue2(g: var CodeGen; c: Cursor) =
  ## Materialize `c`'s value at its precomputed `locs[pos]`.
  let pos = g.posOf(c)
  let dst = g.ra.locs[pos]
  if dst.kind == InFReg:
    g.emitFValue2(c); return
  if dst.kind in {NamedStack, Mem} and dst.isTemp:
    # A value position the allocator spilled to a fresh `(s)` slot (`etmpN.0`) because
    # the register pool was exhausted — produce it into the bridge and store it. This
    # covers EVERY node kind uniformly (a leaf symbol/literal *as well as* a computed
    # node), mirroring x64: a spilled leaf operand must still be evaluated and stored,
    # otherwise the slot is read uninitialized by the consumer.
    g.produceIntoMem2(c, pos, dst)
    return
  if dst.kind in {NamedStack, Mem, Glob, Tvar, Imm}:
    # A leaf the allocator left in place (folded immediate / a resident local /
    # global / foldable lvalue): nothing to materialize — the consumer reads it.
    if c.kind == TagLit and c.exprKind in {AddC, SubC, MulC, DivC, ModC, ShlC, ShrC,
        BitandC, BitorC, BitxorC, NegC, BitnotC, NotC, EqC, NeqC, LtC, LeC, AndC, OrC,
        DerefC, DotC, AtC, PatC, AddrC, CastC, ConvC, CallC}:
      # A computed node whose result was spilled to a non-temp NamedStack/Mem slot
      # (dest-passed into a real local's home). (The isTemp spill case is handled by
      # the `dst.isTemp` produce-into block above, for every node kind.)
      if dst.kind in {NamedStack, Mem}:
        g.produceIntoMem2(c, pos, dst)
        return
    return
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
      if home.kind != Undef:
        if dst.isTemp: g.bindTemp(dst.r, dst.typ)
        g.place2(home, dst.r)
      else:
        let si = g.lookupSym(symName(c))
        if si.cat == scProc:
          if dst.isTemp: g.bindTemp(dst.r, dst.typ)
          g.emAdr(dst.r, si.asmName)
        else:
          var cc = c
          let loc = g.asLoc(cc)
          if dst.isTemp: g.bindTemp(dst.r, loc.typ)
          g.place2(loc, dst.r)
  of StrLit:
    if dst.kind == InReg:
      let nm = "msg." & $g.rodata.len
      g.rodata.add (nm, strVal(c))
      if dst.isTemp: g.bindTemp(dst.r, dst.typ)
      g.emAdr(dst.r, nm)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, BitandC, BitorC, BitxorC, ShlC, ShrC: g.emitBin2(c)
    of ModC: g.emitMod2(c)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC: g.emitCondValue2(c)
    of DerefC, DotC, AtC, PatC: g.emitMemLoad2(c)
    of AddrC: g.emitAddr2(c)
    of CastC, ConvC: g.emitCast2(c)
    of CallC:
      g.emitCall2(c)
    of NegC, BitnotC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc                                         # result type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitValue2(inner)
      let res = g.ra.locs[g.posOf(c)]
      let iv = g.ra.locs[g.posOf(inner)]
      if res.kind == InReg:
        if res.isTemp and (iv.kind != InReg or iv.r != res.r): g.bindTemp(res.r, res.typ)
        if iv.kind == InReg and iv.r != res.r: g.movReg(res.r, iv.r)
        elif iv.kind != InReg: g.place2(iv, res.r)
        g.ab.tree NegA64: g.emReg res.r
        if c.exprKind == BitnotC: g.binImm(SubA64, res.r, 1)  # ~a = -a - 1
        if iv.kind == InReg and iv.isTemp and iv.r != res.r: g.unbindTemp(iv.r)
    of SufC, ParC:
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
    else: raiseAssert "arkham a64n: emitValue2 expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emitValue2 kind " & $c.kind

proc emitFValue2(g: var CodeGen; c: Cursor) =
  ## Materialize `c`'s FLOAT value at its precomputed `locs[pos]` (a v-register).
  let pos = g.posOf(c)
  let dst = g.ra.locs[pos]
  if dst.kind == NamedStack:
    # spilled float result: produce into the float bridge (v31), not held across the
    # recursion, then store back.
    let bits = dst.typ.size * 8
    let fs = FloatBridgeReg
    g.ra.locs[pos] = fregLoc(fs, dst.typ, isTemp = true)
    g.emitFValue2(c)
    g.ra.locs[pos] = dst
    g.emFloatScalarStore(dst.name, fs, bits)
    g.unbindFTmp(fs)
    return
  assert dst.kind == InFReg, "arkham a64n: emitFValue2 dst " & $dst.kind
  let bits = if dst.typ.size == 4: 32 else: 64
  case c.kind
  of FloatLit:
    if dst.isTemp: g.bindFTmp(dst.f, bits)
    let gpr = g.takeBridge()
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dst.f, gpr, bits)
    g.dropBridge gpr
  of Symbol:
    var home = g.ra.locationOfSym(symName(c))
    if home.kind == Undef:                               # a module-level float global / tvar
      var cc = c
      home = g.asLoc(cc)                                 # Glob/Tvar with the float slot
    if dst.isTemp: g.bindFTmp(dst.f, bits)
    g.placeF2(home, dst.f, bits)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC: g.emitFBin2(c)
    of NegC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitFValue2(inner)
      let iv = g.ra.locs[g.posOf(inner)]
      if dst.isTemp and (iv.kind != InFReg or iv.f != dst.f): g.bindFTmp(dst.f, bits)
      g.ensureFAccum2(dst.f, iv, bits)
      g.ab.tree FnegA64: g.emFReg(dst.f, bits)
    of ConvC, CastC: g.emitCast2(c)
    of CallC: g.emitCall2(c)
    of DotC, AtC, DerefC, PatC: g.emitFMemLoad2(c)
    of SufC, ParC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitFValue2(inner)
    else: raiseAssert "arkham a64n: emitFValue2 expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emitFValue2 kind " & $c.kind

# ── stores ───────────────────────────────────────────────────────────────────

proc storeScalar2(g: var CodeGen; dst, v: Location) =
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
    if dst.typ.isFloat:
      case v.kind
      of InFReg:
        g.emFloatScalarStore(dst.name, v.f, bits)
        if v.isTemp: g.unbindFTmp(v.f)
      of NamedStack, Mem, Glob:
        let fs = g.takeFBridge(bits)
        g.placeF2(v, fs, bits)
        g.emFloatScalarStore(dst.name, fs, bits)
        g.dropFBridge()
      else: raiseAssert "arkham a64n: float scalar store rhs " & $v.kind
    else:
      case v.kind
      of InReg:
        g.emScalarStore(dst.name, v.r)
        if v.isTemp: g.unbindTemp(v.r)
      of Imm:
        let b = g.takeBridge(dst.typ); g.movImm(b, v.ival); g.emScalarStore(dst.name, b); g.dropBridge b
      of NamedStack, Mem, Glob, Tvar:
        let b = g.takeBridge(dst.typ); g.place2(v, b); g.emScalarStore(dst.name, b); g.dropBridge b
      else: raiseAssert "arkham a64n: scalar store rhs " & $v.kind
  else: raiseAssert "arkham a64n: scalar store dst " & $dst.kind

# ── aggregates ───────────────────────────────────────────────────────────────

proc emByteAtImm(g: var CodeGen; p: Reg; off: int) =
  ## `(mem (at (cast (aptr (u 8)) p) off))` — the byte at `[p + off]` (immediate offset).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg p
      g.ab.intLit off

proc copyAggr(g: var CodeGen; dst, src: Reg; size: int; tmp: Reg) =
  ## THE one aggregate memcpy (a struct/array `store`): copy `size` bytes from `[src]` to
  ## `[dst]` through the bound scratch `tmp` — 8-byte words for the aligned bulk, then a
  ## sized byte tail. Layout-agnostic and byte-accurate (mirrors the x64 `copyAggr`).
  let words = size div 8
  for i in 0 ..< words:
    g.ab.tree MovA64: (g.emReg tmp; g.emWordThroughPtr(src, i))
    g.ab.tree MovA64: (g.emWordThroughPtr(dst, i); g.emReg tmp)
  for b in 0 ..< (size - words * 8):                     # sub-word tail, byte by byte
    let off = words * 8 + b
    g.ab.tree MovA64: (g.emReg tmp; g.emByteAtImm(src, off))
    g.ab.tree MovA64: (g.emByteAtImm(dst, off); g.emReg tmp)

proc copyStructThroughPtr2(g: var CodeGen; srcVar, typeName: string; ptrReg, tmp: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at, through scratch `tmp`. Leas the
  ## source's address into one staging bridge and funnels through the one `copyAggr`.
  let sp = g.takeBridge()
  g.ab.tree LeaA64: (g.emReg sp; g.ab.sym srcVar)        # sp = &srcVar
  g.bindTemp(tmp, ScalarSlot)
  g.copyAggr(ptrReg, sp, aggrByteSize(g.prog, typeName), tmp)
  g.unbindTemp(tmp)
  g.dropBridge sp

proc regsToStructThroughPtr(g: var CodeGen; ptrReg: Reg; typeName: string; firstArg: int) =
  ## `[ptrReg] ← x{firstArg+i}` — marshal a ≤16B aggregate held in the return registers
  ## into the memory `ptrReg` points at: a FULL eightbyte as a raw `(u 64)` word
  ## (handles packed fields), a trailing PARTIAL eightbyte by field. The through-pointer
  ## twin of `regsToStruct` — stores an aggregate call result into a global.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emWordThroughPtr(ptrReg, i); g.emReg IntArgRegs[firstArg + i])
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovA64: (g.emPtrFieldMem(ptrReg, typeName, fn); g.emReg IntArgRegs[firstArg + i])

proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string; firstArg: int) =
  ## `x{firstArg+i} ← [addrReg]` — load a ≤16B aggregate at `[addrReg]` into the by-value
  ## ABI argument registers (reverse of `regsToStructThroughPtr`); lets an aggregate CALL
  ## ARGUMENT marshal straight from its address (`aggrAddrInto`) with no copy temp.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(addrReg, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeName), i * 8)
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emPtrFieldMem(addrReg, typeName, fn))

proc emLvalFieldMem(g: var CodeGen; lhs: Cursor; field: string) =
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.emLvalAddr2(lhs)
      g.ab.sym field

proc emLvalElemMem(g: var CodeGen; lhs: Cursor; idx: int) =
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.emLvalAddr2(lhs)
      g.ab.intLit idx

proc emAggrElemAt(g: var CodeGen; base: string; idx: int) =
  ## Bare `(at base idx)` ADDRESS tree (no `(mem …)` wrapper) — what a64's `lea` takes
  ## to compute `&base[idx]`. The element twin of `emAggrDot`.
  g.ab.tree AtX:
    g.ab.sym base
    g.ab.intLit idx

proc emLvalElemAt(g: var CodeGen; lhs: Cursor; idx: int) =
  ## Bare `(at <lvalue address> idx)` address tree — for `lea` of an lvalue element.
  g.ab.tree AtX:
    g.emLvalAddr2(lhs)
    g.ab.intLit idx

proc emPtrElemMem(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## `(mem (at (cast (aptr ElemTy) p) idx))` — element `idx` of an array at `[p]`;
  ## nifasm scales by the element size. The array twin of `emPtrFieldMem`.
  var et = elemTy
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.genTypeBody(et)
        g.emReg p
      g.ab.intLit idx.int64

proc emPtrElemAt(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## Bare `(at (cast (aptr ElemTy) p) idx)` address tree — for `lea` of an element
  ## through a pointer base (e.g. a global's address).
  var et = elemTy
  g.ab.tree AtX:
    g.ab.tree CastX:
      g.ab.aptrType: g.genTypeBody(et)
      g.emReg p
    g.ab.intLit idx.int64

proc fieldSlotByName(g: var CodeGen; typeName, field: string): AsmSlot =
  ## The asm slot of `typeName.field` (so a `Field` destination carries the field's
  ## slot — a nested aggregate field has an `AMem` slot). Resolves the object body
  ## from the type's decl.
  var d = lookupType(g.prog, typeName)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = slotOf(g.prog, fieldType(g.prog, d, field))
    while d.hasMore: skip d

proc fieldTypeByName(g: var CodeGen; typeName, field: string): Cursor =
  ## The declared (nominal) type cursor of `typeName.field`.
  var d = lookupType(g.prog, typeName)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = fieldType(g.prog, d, field)
    while d.hasMore: skip d

proc emFieldOperand(g: var CodeGen; dst: Location) =
  ## The `(mem (dot <base> field))` operand for a `Field` destination, dispatching on
  ## how its base aggregate is addressed (a pointer reg / a named stack slot / an
  ## lvalue subtree). nifasm sizes the access from the field's declared type.
  if dst.baseReg != NoReg:    g.emPtrFieldMem(dst.baseReg, dst.aggrType, dst.field)
  elif dst.baseName.len > 0:  g.emAggrFieldMem(dst.baseName, dst.field)
  else:                       g.emLvalFieldMem(dst.baseLval, dst.field)

proc emFieldDot(g: var CodeGen; dst: Location) =
  ## The bare `(dot <base> field)` ADDRESS tree (no `(mem …)` wrapper) — what a64's
  ## `lea` takes (unlike x86, which leas a memory operand).
  if dst.baseReg != NoReg:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym dst.aggrType
        g.emReg dst.baseReg
      g.ab.sym dst.field
  elif dst.baseName.len > 0:
    g.emAggrDot(dst.baseName, dst.field)
  else:
    g.ab.tree DotX:
      g.emLvalAddr2(dst.baseLval)
      g.ab.sym dst.field

proc emFieldAddr(g: var CodeGen; dst: Location; into: Reg) =
  ## `&(base.field)` → `into`: `lea` over the field's address tree.
  g.ab.tree LeaA64: (g.emReg into; g.emFieldDot(dst))

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
  let ntn = symName(fty)
  let pos = g.posOf(valC)
  let tmpName = "nctmp" & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, slotOf(g.prog, fty)), pos)   # build (no bridge held)
  let fptr = g.takeBridge()
  g.emFieldAddr(dst, fptr)
  let tmp = g.takeBridge(avoid = fptr)
  for f in aggrLayout(g.prog, ntn):
    g.ab.tree MovA64: (g.emReg tmp; g.emAggrFieldMem(tmpName, f.name))
    g.ab.tree MovA64: (g.emPtrFieldMem(fptr, ntn, f.name); g.emReg tmp)
  g.dropBridge tmp
  g.dropBridge fptr

proc genFieldStore2(g: var CodeGen; dst: Location; valC: Cursor) =
  ## Store value `valC` into the aggregate-field destination `dst` — the `Field` case of
  ## `genStore2`, and the ONE per-field store behind `genConstr2`. A scalar/float/pointer
  ## field emits its value into the field operand (a POINTER field reinterprets a scalar
  ## via `(cast (ptr …) reg)` for nifasm's strict typing); a nested aggregate field
  ## recurses through `genNestedAggrField`. No per-field special-casing at the call site.
  if dst.typ.kind == AMem:                              # nested aggregate field
    let ftyCur = g.fieldTypeByName(dst.aggrType, dst.field)
    g.genNestedAggrField(dst, valC, ftyCur)
  else:                                                 # scalar / float / pointer field
    g.emitValue2(valC)
    let v = g.ra.locs[g.posOf(valC)]
    if v.kind == InFReg:                                # float field
      let bits = if v.typ.size == 4: 32 else: 64
      g.ab.tree FstrA64: (g.emFieldOperand(dst); g.emFReg(v.f, bits))
      if v.isTemp: g.unbindFTmp(v.f)
    else:
      var fty = resolveType(g.prog, g.fieldTypeByName(dst.aggrType, dst.field))
      g.ab.tree MovA64:
        g.emFieldOperand(dst)
        if isPtrType(fty):
          g.ab.tree CastX:
            g.genTypeBody(fty)
            g.emReg v.r
        else: g.emReg v.r
      if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)

proc constrFieldStores(g: var CodeGen; c: Cursor; base: Location) =
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
        else: raiseAssert "arkham a64n: bad oconstr base " & $base.kind
      g.genStore2(valC, fdst, g.posOf(valC))
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

template aconstrElemStores(g: var CodeGen; c: Cursor; destOp, addrOp: untyped) =
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
          let ntn = symName(elemTyRaw)
          let pos = g.posOf(valC)
          let tmpName = "nctmp" & $pos & ".0"
          g.emTypedStackVar(tmpName, elemTyRaw)
          g.varType[tmpName] = ntn
          g.genStore2(valC, namedStackLoc(tmpName, elemSlot), pos)  # build (no bridge held)
          let eptr = g.takeBridge()
          g.ab.tree LeaA64: (g.emReg eptr; addrOp(i))   # &element[i]
          let tmp = g.takeBridge(avoid = eptr)
          for f in aggrLayout(g.prog, ntn):             # copy field-by-field (objects)
            g.ab.tree MovA64: (g.emReg tmp; g.emAggrFieldMem(tmpName, f.name))
            g.ab.tree MovA64: (g.emPtrFieldMem(eptr, ntn, f.name); g.emReg tmp)
          g.dropBridge tmp
          g.dropBridge eptr
          inc i
          skip cc
          continue
        g.emitValue2(valC)
        let v = g.ra.locs[g.posOf(valC)]
        if v.kind == InFReg:
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree FstrA64: (destOp(i); g.emFReg(v.f, bits))
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          var etc = et
          g.ab.tree MovA64:
            destOp(i)
            if etIsPtr:
              g.ab.tree CastX:
                g.genTypeBody(etc)
                g.emReg v.r
            else: g.emReg v.r
          if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
        inc i
        skip cc

proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string) =
  g.constrFieldStores(c, namedStackLoc(dstVar, ScalarSlot))   # base = the stack slot

proc genAconstr2(g: var CodeGen; c: Cursor; dstVar: string) =
  template dest(i) = g.emAggrElemMem(dstVar, i)
  template elemAddr(i) = g.emAggrElemAt(dstVar, i)
  g.aconstrElemStores(c, dest, elemAddr)

proc genConstrIntoLval2(g: var CodeGen; c: Cursor; lhs: Cursor) =
  g.prematLval2(lhs)
  g.constrFieldStores(c, memLoc(lhs, ScalarSlot))            # base = the lvalue subtree
  g.unbindLvalTemps2(lhs)

proc genAconstrIntoLval2(g: var CodeGen; c: Cursor; lhs: Cursor) =
  g.prematLval2(lhs)
  template dest(i) = g.emLvalElemMem(lhs, i)
  template elemAddr(i) = g.emLvalElemAt(lhs, i)
  g.aconstrElemStores(c, dest, elemAddr)
  g.unbindLvalTemps2(lhs)

proc genBaseobj2(g: var CodeGen; c: Cursor; dst: Location) =
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
    let dtmp = "botmp" & $pos & ".0"
    g.emTypedStackVar(dtmp, derivedTy)
    g.varType[dtmp] = symName(derivedTy)
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)), pos)  # build derived
    let s = g.takeBridge()
    for f in aggrLayout(g.prog, symName(baseTy)):         # copy the base prefix
      g.ab.tree MovA64: (g.emReg s; g.emAggrFieldMem(dtmp, f.name))
      g.ab.tree MovA64: (g.emAggrFieldMem(dst.name, f.name); g.emReg s)
    g.dropBridge s
    while cc.hasMore: skip cc

proc aggrAddrLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## Address of an aggregate DESTINATION location into the (bound) `dest` — the dst twin
  ## of `aggrAddrInto`.
  case loc.kind
  of NamedStack:
    g.ab.tree LeaA64:
      g.emReg dest
      g.ab.sym loc.name
  of Glob: g.emGlobalAddr(dest, loc.name)
  of Mem: g.aggrAddrInto(loc.cur, dest, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
  else: raiseAssert "arkham a64n: aggrAddrLoc of " & $loc.kind

proc isAggrCopySrc(c: Cursor): bool =
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo(g: var CodeGen; dst: Location): (bool, int) =
  case dst.kind
  of NamedStack, Glob: (dst.typ.kind == AMem, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc genAggrCopyStore(g: var CodeGen; rhs: Cursor; dst: Location; size, auxPos: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce BOTH sides to an address in a register
  ## (`aggrAddrLoc`/`aggrAddrInto`), then `copyAggr`. The allocator reserved
  ## `[dstAddr, srcAddr]`; the per-field transfer register is a staging bridge (x14/x15),
  ## taken here — both addresses are already in `a[0]`/`a[1]`, so a bridge is free — sparing
  ## a pool GPR so the copy fits under high register pressure.
  let a = g.ra.aux[auxPos].scratch
  g.bindTemp(a[0], ScalarSlot); g.aggrAddrLoc(dst, a[0])         # &dst
  g.bindTemp(a[1], ScalarSlot)
  g.aggrAddrInto(rhs, a[1], AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)  # &rhs
  let tmp = g.takeBridge(AsmSlot(cls: AUInt, size: 8, align: 8))
  g.copyAggr(a[0], a[1], size, tmp)
  g.dropBridge tmp
  g.unbindTemp(a[1]); g.unbindTemp(a[0])

proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location; auxPos: int) =
  ## The general destination-passing store: emit `rhs` so its value lands at `dst`. An
  ## aggregate COPY goes through the ONE `genAggrCopyStore`; constructors/calls/baseobj
  ## PRODUCE per-form; a scalar/float destination through `storeScalar2`.
  let (dstAggr, aggrSize) = g.dstAggrInfo(dst)
  if dstAggr and isAggrCopySrc(rhs):                         # the ONE whole-aggregate copy path
    g.genAggrCopyStore(rhs, dst, aggrSize, auxPos)
    return
  if rhs.kind == TagLit and rhs.exprKind in {ConvC, CastC} and
     g.exprSlot(rhs).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (`Path(s)` for
    # `Path = distinct string`) is byte-transparent — store its underlying operand into
    # the same destination (allocator twin in `allocStore`).
    var inner = rhs
    inner.into:
      skip inner                                             # the target type
      g.genStore2(inner, dst, auxPos)                        # the operand → same dest
      while inner.hasMore: skip inner
    return
  if dst.kind == NamedStack and dst.typ.kind == AMem:        # aggregate destination
    let dstVar = dst.name
    let tn = g.varType[dstVar]
    if rhs.kind == TagLit and rhs.exprKind == OconstrC: g.genConstr2(rhs, dstVar)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC: g.genAconstr2(rhs, dstVar)
    elif rhs.kind == TagLit and rhs.exprKind == CallC:
      if aggrByteSize(g.prog, tn) > 16:
        g.ab.tree LeaA64: (g.emReg IndirectResultReg; g.ab.sym dstVar)
        g.emitCall2(rhs)
      else:
        g.emitCall2(rhs)
        g.regsToStruct(dstVar, tn, 0)
    elif rhs.kind == TagLit and rhs.exprKind == BaseobjC:
      g.genBaseobj2(rhs, dst)                              # object→base slice
    else: raiseAssert "arkham a64n: aggregate store rhs " & $rhs.exprKind
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AMem:
    # Aggregate store into a GLOBAL: address it into a pointer scratch and build/copy
    # the aggregate THROUGH that pointer — `oconstr` field-by-field (InReg base), a
    # symbol by whole-aggregate copy, a call by its ABI (>16B → &g as the hidden result
    # ptr x8; ≤16B → the result regs x0:x1 stored through &g). The allocator reserves
    # the &g address temp at `aux[auxPos].scratch[0]` (+ a copy temp at `[1]`).
    assert dst.kind == Glob, "arkham a64n: aggregate threadvar store not supported"
    if rhs.kind == TagLit and rhs.exprKind == CallC and
       dst.typ.size > g.md.aggrByRefThreshold:
      g.emAdr(IndirectResultReg, dst.name)              # >16B: &g is the hidden result ptr
      g.emitCall2(rhs)
    else:
      let addrT = g.ra.aux[auxPos].scratch[0]
      g.bindTemp(addrT, ScalarSlot)
      if rhs.kind == TagLit and rhs.exprKind == OconstrC:
        g.emAdr(addrT, dst.name)
        g.constrFieldStores(rhs, regLoc(addrT, dst.typ))
      elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
        g.emAdr(addrT, dst.name)
        var atc = rhs; inc atc                            # the array type
        let elemTy = innerType(g.prog, resolveType(g.prog, atc))
        template dest(i) = g.emPtrElemMem(addrT, elemTy, i)  # element i through &g
        template elemAddr(i) = g.emPtrElemAt(addrT, elemTy, i)
        g.aconstrElemStores(rhs, dest, elemAddr)
      elif rhs.kind == TagLit and rhs.exprKind == CallC:  # ≤16B result in x0:x1
        g.emitCall2(rhs)
        g.emAdr(addrT, dst.name)
        g.regsToStructThroughPtr(addrT, symName(g.getType(rhs)), 0)
      else: raiseAssert "arkham a64n: aggregate global store rhs " & $rhs.exprKind
      g.unbindTemp(addrT)
  elif dst.kind in {Glob, Tvar}:                             # scalar/float/pointer global/tvar
    if dst.typ.kind == AFloat:
      g.emitValue2(rhs)
      let fv = g.ra.locs[g.posOf(rhs)]
      let bits = if dst.typ.size == 4: 32 else: 64
      let b = g.takeBridge()
      if dst.kind == Glob or g.a64Linux: g.emAdr(b, dst.name) else: g.genTlvAddr(dst.name, b)
      g.emFStore(fv.f, b, bits)
      g.dropBridge b
      if fv.kind == InFReg and fv.isTemp: g.unbindFTmp(fv.f)
    else:
      g.emitValue2(rhs)
      var v = g.ra.locs[g.posOf(rhs)]
      g.storeReg2(dst, (if v.kind == InReg: v.r else: (let b = g.takeBridge(); g.place2(v, b); b)))
      if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
      elif v.kind notin {InReg, Imm}: discard            # bridge auto-dropped? handle below
  elif dst.kind == Mem:                                      # store through complex lvalue
    let lhs = dst.cur
    # A global aggregate base in the lvalue reserved an address scratch (aux); bind it
    # so prematLval2's `lea scratch, &g` emits a checked name. The allocator held it
    # across the rhs evaluation.
    let globScratch = if g.ra.aux.hasKey(auxPos): g.ra.aux[auxPos].scratch[0] else: NoReg
    if globScratch != NoReg: g.bindTemp(globScratch, ScalarSlot)
    if rhs.kind == TagLit and rhs.exprKind == OconstrC: g.genConstrIntoLval2(rhs, lhs)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC: g.genAconstrIntoLval2(rhs, lhs)
    else:
      g.emitValue2(rhs)
      var v = g.ra.locs[g.posOf(rhs)]
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
          if v.kind == Imm: g.ab.intLit v.ival
          elif dstPtr:
            g.ab.tree CastX:
              g.genTypeBody(dstTy)
              g.emReg vr
          else: g.emReg vr
        if vBridge != NoReg: g.dropBridge vBridge
        elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
      g.unbindLvalTemps2(lhs)
    if globScratch != NoReg: g.unbindTemp(globScratch)
  elif dst.kind == Field:                                    # a field within an aggregate
    g.genFieldStore2(dst, rhs)
  else:                                                      # scalar / float register or `(s)` slot
    g.emitValue2(rhs)
    let v = g.ra.locs[g.posOf(rhs)]
    g.storeScalar2(dst, v)

# ── var declarations ─────────────────────────────────────────────────────────

proc genVarDecl2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = g.posOf(cc)
    let nm = symName(cc); inc cc
    skip cc                                                  # pragmas
    let typeCur = cc; skip cc                                # type
    g.symType[nm] = typeCur
    let loc = g.ra.locationOfSym(nm)
    let hasVal = cc.hasMore and cc.kind != DotToken
    case loc.kind
    of InReg: g.emRegLocalVar(nm, loc.r, typeCur)
    of InFReg: g.emFRegLocalVar(nm, loc.f, loc.typ.size * 8)
    of NamedStack:
      g.emTypedStackVar(nm, typeCur)                         # one route; dispatches on slot class
      if loc.typ.kind == AMem and typeCur.kind == Symbol:
        g.varType[nm] = symName(typeCur)                     # aggregate field layout
    else: raiseAssert "arkham a64n: var home " & $loc.kind
    if hasVal: g.genStore2(cc, loc, declPos)
    while cc.hasMore: skip cc

# ── case test ────────────────────────────────────────────────────────────────

proc cmpImm2(g: var CodeGen; selReg: Reg; v: int64) =
  if v >= 0 and v <= 0xFFFF:
    g.ab.tree CmpA64: (g.emReg selReg; g.ab.intLit v)
  else:
    let b = g.takeBridge(); g.movImm(b, v)
    g.ab.tree CmpA64: (g.emReg selReg; g.emReg b)
    g.dropBridge b

proc emitCaseTest2(g: var CodeGen; selReg: Reg; c: var Cursor; lBody: string; signed: bool) =
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()
      g.cmpImm2(selReg, lo); g.emBr(if signed: BltA64 else: BloA64, lSkip)
      g.cmpImm2(selReg, hi); g.emBr(if signed: BgtA64 else: BhiA64, lSkip)
      g.emBr(BA64, lBody)
      g.emLab(lSkip)
  else:
    g.cmpImm2(selReg, branchImm(c)); g.emBr(BeqA64, lBody)

# ── statement dispatch ───────────────────────────────────────────────────────

proc genStmt2(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return
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
  of VarS, GvarS, TvarS, ConstS: g.genVarDecl2(c)
  of CallS: g.emitCall2(c)
  of BreakS:
    assert g.loopEnds.len > 0, "arkham a64n: `break` outside a loop"
    g.emBr(BA64, g.loopEnds[^1])
  of AsgnS:
    var cc = c
    cc.into:
      let asgnPos = g.posOf(c)
      if cc.kind == Symbol:
        let lhsCur = cc
        var dst = g.ra.locationOfSym(symName(cc)); skip cc
        if dst.kind == Undef:
          var lc = lhsCur
          dst = g.asLoc(lc)
        g.genStore2(cc, dst, asgnPos)
      else:
        let lhsCur = cc
        var rhsCur = cc; skip rhsCur
        g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot), asgnPos)
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
      g.emBr(BA64, lStart)
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
            g.emBr(BA64, lEnd)
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
      if g.isEntryProc and g.a64Linux:
        if hasVal:
          g.emitValue2(cc)
          g.place2(g.ra.locs[g.posOf(cc)], IntRet)
        else: g.movImm(IntRet, 0)
        g.movImm(R8, LinuxA64ExitNr.int64)
        g.ab.tree SvcA64: g.ab.intLit 0
      else:
        if g.retAggrName.len > 0:
          var srcName: string
          if cc.kind == Symbol:
            srcName = symName(cc)                          # a named local aggregate
          else:
            # An inline aggregate VALUE returned by value (`(ret (oconstr …))` /
            # memory lvalue): materialize into a synthetic temp via the general store
            # path (mirrors the aggregate call-argument marshalling), then marshal out.
            let pos = g.posOf(cc)
            srcName = "rettmp" & $pos & ".0"
            var tcur = cc
            if cc.exprKind in {OconstrC, AconstrC}: inc tcur   # the constructed type
            else: tcur = g.getType(cc)
            g.emTypedStackVar(srcName, tcur)
            g.varType[srcName] = g.retAggrName
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)), pos)
          if g.retIndirect:
            let tmp = g.ra.aux[g.posOf(cc)].scratch[0]
            g.copyStructThroughPtr2(srcName, g.retAggrName, g.indirectReg, tmp)
            g.movReg(IntRet, g.indirectReg)
          else:
            g.structToRegs(srcName, g.retAggrName, 0)
        elif hasVal:
          let retPos = g.posOf(cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(FloatRet, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)), retPos)
          else:
            g.genStore2(cc, regLoc(IntRet, ScalarSlot), retPos)
        g.emBr(BA64, g.retLabel2); g.retLabelUsed2 = true
      while cc.hasMore: skip cc
  of CaseS:
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      g.emitValue2(cc); skip cc
      let selLoc = g.ra.locs[g.posOf(selC)]
      assert selLoc.kind == InReg, "arkham a64n: case selector " & $selLoc.kind
      let selReg = selLoc.r
      var bodies: seq[(string, Cursor)] = @[]
      var elseBody = cc
      var hasElse = false
      while cc.hasMore:
        case cc.substructureKind
        of OfU:
          let lBody = g.freshLabel()
          var branch = cc
          skip cc
          branch.into:
            branch.into:
              while branch.hasMore: g.emitCaseTest2(selReg, branch, lBody, signed)
            bodies.add (lBody, branch)
            skip branch
        of ElseU:
          elseBody = cc; hasElse = true; skip cc
        else: skip cc
      if selLoc.isTemp: g.unbindTemp(selReg)
      if hasElse:
        var e = elseBody
        e.into:
          while e.hasMore: (g.genStmt2(e); skip e)
      g.emBr(BA64, lEnd)
      for (lBody, bc) in bodies:
        g.emLab(lBody)
        g.genStmt2(bc)
        g.emBr(BA64, lEnd)
    g.emLab(lEnd)
  of LabS:
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emBr(BA64, symName(cc)); skip cc
      while cc.hasMore: skip cc
  else: raiseAssert "arkham a64n: genStmt2 " & $c.stmtKind

# ── proc emission / driver (pure-emit path) ──────────────────────────────────

proc recordVarType2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc
      g.symType[nm] = cc
    while cc.hasMore: skip cc

proc recordSymTypes2(g: var CodeGen; c: Cursor) =
  if c.kind != TagLit: return
  case c.stmtKind
  of VarS, GvarS, TvarS, ConstS: g.recordVarType2(c)
  of ProcS, TypeS: discard
  else:
    var cc = c
    cc.into:
      while cc.hasMore:
        g.recordSymTypes2(cc)
        skip cc

proc atNeedsScratch(g: var CodeGen; atNode: Cursor): bool =
  ## Does this `(at base idx)` level need an explicit scratch register? AArch64 folds
  ## `base + idx*scale` into one LDR/STR operand only for a scale of 1/2/4/8 and a
  ## single register index; a stride that is anything else (a multi-dimensional array's
  ## outer dimension) cannot fold, so nifasm gets a scratch and computes
  ## `base + idx*stride` into it (`(at base idx scratch)` 3-operand form). An immediate
  ## index always folds to a displacement → never needs one.
  let stride = typeSizeAlign(g.prog, resolveType(g.prog, g.getType(atNode)))[0]
  if stride in [1, 2, 4, 8]: return false
  var n = atNode
  var idxIsReg = false
  n.into:
    skip n                                      # the array base
    idxIsReg = n.kind != IntLit
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

proc collectAtScratch2(g: var CodeGen; n: Cursor; res: var HashSet[int]; asBase = false) =
  ## Mirror of x64's collectAtScratch: record every `(at …)` position needing a scratch
  ## GPR for the `(at base idx scratch)` 3-operand form. Two reasons: a non-fold-scale
  ## element stride, OR (like x86) an access that is the BASE of an enclosing `at`/`pat`
  ## with a register index — AArch64 LDR/STR also takes only ONE index register, so a
  ## nested `a[i][j]` must materialize the inner `a[i]` into a clean base first
  ## (`asBase`; an immediate inner index already folds to a clean displacement). Walks
  ## the whole subtree.
  var c = n
  if c.kind == TagLit:
    if c.exprKind in {AtC, PatC} and
       (g.atNeedsScratch(c) or (asBase and g.atIndexIsReg(c))):  # `pat` strides like `at`
      res.incl g.posOf(c)
    var cc = c
    var firstChild = true
    cc.into:
      while cc.hasMore:
        let childAsBase =
          if not firstChild: false
          elif c.exprKind == AtC: true            # the indexed aggregate base
          elif c.exprKind == DotC: asBase         # passthrough offset base
          else: false                             # a `pat` pointer is a clean value-reg base
        g.collectAtScratch2(cc, res, childAsBase)
        firstChild = false
        skip cc

proc emitProcBody2(g: var CodeGen; info: ProcInfo; declarative: bool) =
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsA64:
      if g.hasFrame: framePush(g)
      g.emitStackParamLoads(info.decl)
      if g.ra.hasStackVars:
        g.ab.tree SubA64: g.emReg SP; g.ab.keyword SsizeX
      if g.retIndirect: g.movReg(g.indirectReg, IndirectResultReg)
      g.emitParamMoves(info.decl)
      if info.isEntry and g.hasGlobalInits:           # run runtime global inits at startup
        g.ab.tree PrepareA64:
          g.ab.sym g.globalInitSym
          g.ab.keyword CallA64
      for st in g.ra.spillTemps:
        if st.isFloat: g.emFloatStackVar(st.name, st.typ.size * 8)
        elif not cursorIsNil(st.typ.typ) and isPtrType(resolveType(g.prog, st.typ.typ)):
          g.emTypedStackVar(st.name, st.typ.typ)
        else: g.emScalarStackVar(st.name)
      g.retLabel2 = g.freshLabel()
      g.retLabelUsed2 = false
      g.enterScope()
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c
        if c.stmtKind == StmtsS:
          c.into:
            while c.hasMore: (g.genStmt2(c); skip c)
      g.exitScope()
      if g.retLabelUsed2: g.emLab(g.retLabel2)
      if info.isEntry and g.a64Linux:
        g.movImm(IntRet, 0)
        g.movImm(R8, LinuxA64ExitNr.int64)
        g.ab.tree SvcA64: g.ab.intLit 0
      else:
        if g.ra.hasStackVars:
          g.ab.tree AddA64: g.emReg SP; g.ab.keyword SsizeX
        if g.hasFrame: framePop(g)
        g.ab.keyword RetA64

proc genProc2(g: var CodeGen; info: ProcInfo) =
  let an = analyseProc(g.buf[], info.decl, g.tvarNames)
  g.varType.clear()
  g.symType.clear()
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.regLocal.clear(); g.aliasToDecl.clear(); g.boundTemps = {}; g.scopeLocals = @[]
  g.fregLocal.clear(); g.boundFTmps = {}; g.scopeFLocals = @[]
  g.tmpBindCount = 0; g.ftmpBindCount = 0; g.loopEnds = @[]; g.spillCount = 0
  g.savedHomes.clear()
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrName = symName(rc)
      g.retIndirect = aggrByteSize(g.prog, g.retAggrName) > 16
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  let preseal = if g.retIndirect: {R19} else: {}
  block:                                            # pre-fill symType for allocation-time getType
    var pc = info.decl
    pc.into:
      inc pc
      if pc.kind == TagLit:
        var p = pc
        p.into:
          while p.hasMore: (g.recordVarType2(p); skip p)
      skip pc; skip pc; skip pc
      if pc.stmtKind == StmtsS: g.recordSymTypes2(pc)
      while pc.hasMore: skip pc
  var atScratch = initHashSet[int]()
  g.collectAtScratch2(info.decl, atScratch)
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, aarch64MachineN, g.typeCtx, preseal,
                      allocExprs = true, atScratch = atScratch)
  if g.retIndirect:
    g.indirectReg = R19
    g.ra.usedCallee.incl R19
  # The entry injects a `call` to the synthetic global-init proc, so it makes a call
  # even when its own body does not — give it a frame (lr saved) for that call.
  g.computeFrame(an.hasCall or (info.isEntry and g.hasGlobalInits))
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  g.ab.planning = false
  g.regLocal.clear(); g.aliasToDecl.clear(); g.boundTemps = {}; g.scopeLocals = @[]
  g.fregLocal.clear(); g.boundFTmps = {}; g.scopeFLocals = @[]; g.savedHomes.clear()
  g.tmpBindCount = 0; g.ftmpBindCount = 0
  g.emitProcBody2(info, declarative)

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. The two-pass seam
# below must reset every per-proc table (regLocal/boundTemps/freeTmp + the ra.locs snapshot)
# or RegisterBindingsMatchLoc and replay completeness break.
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
      g.genTypeBody(tc2)                       # type
      if hasValue and isConstScalarInit(c):
        g.ab.intLit cast[int64](constLitBits(c))
      elif hasValue:
        # Static-ADDRESS initializer (function-pointer hook etc.) — emit the
        # symbol so nifasm bakes its resolved address into the slot.
        let addrSym = constAddrSym(c)
        if addrSym.len > 0:
          g.ab.sym addrSym
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

proc buildGlobalInitProc(g: var CodeGen; initBuf: var TokenBuf) =
  ## Lower each global's RUNTIME initializer into a synthetic `(proc … (stmts (asgn
  ## g e) …))` so it routes through the ordinary value-core pipeline (allocateProc +
  ## emitProcBody2) — no special-case emitter. The entry calls this proc at startup
  ## (see `emitProcBody2`). Const-scalar initializers are laid out as static data by
  ## `genGlobal` and are skipped here, so a module with none gets no init proc.
  var inits: seq[(string, Cursor)] = @[]
  for name, decl in g.globals:
    var c = decl
    if c.stmtKind == ConstS: continue           # emitted as a rodata data blob
    c.into:
      inc c; skip c                             # name, pragmas
      skip c                                    # type
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

proc generateA64*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                  linux = false): string =
  ## Compile a parsed Leng module to AArch64 asm-NIF text — Darwin/Mach-O by
  ## default, or Linux/ELF when `linux` (svc-based syscalls, static, no dyld/TLV),
  ## which `nifasm`'s `linux_arm64` target assembles to a qemu-runnable ELF.
  ## `inputPath` and `tags` let the program model load *other* modules on demand
  ## to resolve cross-module symbols (`Foo.0.othermod`).
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: aarch64MachineN,
                  a64Linux: linux)
  g.prog = collect(buf, inputPath, tags, darwin = not linux)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
  # Build the synthetic global-init proc (if any runtime initializers) BEFORE the proc
  # loop so the entry proc's frame/body account for the startup call. `initBuf` shares
  # `buf`'s pool + tag pool and must outlive the `genProc2` below.
  var initBuf = createTokenBuf(64, buf.pool, buf.tags)
  g.buildGlobalInitProc(initBuf)
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
      genProc2(g, info)
    if g.hasGlobalInits:                         # emit the synthetic init proc itself
      let savedBuf = g.buf
      g.buf = addr initBuf
      var ic = initBuf.beginRead()
      genProc2(g, ProcInfo(asmName: g.globalInitSym, decl: ic, isEntry: false))
      g.buf = savedBuf
    # NOTE: foreign types are NOT emitted here. arkham loads other modules only to
    # resolve their layout for *its own* codegen (sizing, field offsets, ABI). The
    # actual cross-module linking is nifasm's job: a module-suffixed symbol like
    # `Foo.0.othermod` makes nifasm auto-import `othermod.asm.nif` (which arkham
    # produced when it compiled that module). Emitting the decl inline is ignored.
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
