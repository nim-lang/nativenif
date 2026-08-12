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
import stress

let aarch64MachineA = stressed(aarch64MachineN)
  ## The machine arkham allocates against: `aarch64MachineN` itself, unless the
  ## `-d:arkhamStress` shrink is armed (see `stress.nim`). A module-level `let`
  ## so the environment is read and the pools rebuilt once, not per proc.

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
  let nm = g.rb.boundName(r)
  if nm.len > 0: g.ab.sym nm
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
  let nm = g.rb.boundName(r)
  if nm.len > 0: nm
  else: "(" & regName(r) & ")"

proc movImm(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovA64: g.emReg d; g.ab.intLit v

proc movReg(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovA64: g.emReg d; g.emReg s

# `w32` selects the 32-bit W-form tag (`add`→`addw`, `add3`→`addw3`, …) for an
# UNSIGNED 32-bit result: the W-form auto zero-extends into bits 32..63, so the
# `normalizeBinWidth` shift-pair that would otherwise re-clear the top half is
# elided (see emitBin2). Only add/sub/mul have W-forms; other ops pass w32 = false.
proc wForm(op: A64Inst): A64Inst =
  case op
  of AddA64: AddwA64
  of SubA64: SubwA64
  of MulA64: MulwA64
  else: op

proc binReg(g: var CodeGen; op: A64Inst; d, s: Reg; w32 = false) =
  g.ab.tree (if w32: wForm(op) else: op): g.emReg d; g.emReg s

proc binImm(g: var CodeGen; op: A64Inst; d: Reg; v: int64; w32 = false) =
  g.ab.tree (if w32: wForm(op) else: op): g.emReg d; g.ab.intLit v

# 3-operand forms `(op3 D A B)` → `D = A op B` (arm64 native, non-destructive). Used
# when the left source `A` is a still-live local in a register distinct from the
# result `D`, so the value is computed without a preceding `mov D, A`. The 2-operand
# op tag is mapped to its distinct 3-operand tag (`add`→`add3`, …); nifasm dispatches
# on the tag's fixed arity (see parse3OperandsA64).
proc threeOpTag(op: A64Inst; w32 = false): A64Inst =
  if w32:
    case op
    of AddA64: return Addw3A64
    of SubA64: return Subw3A64
    of MulA64: return Mulw3A64
    else: discard
  case op
  of AddA64: Add3A64
  of SubA64: Sub3A64
  of MulA64: Mul3A64
  of AndA64: And3A64
  of OrrA64: Orr3A64
  of EorA64: Eor3A64
  of LslA64: Lsl3A64
  of LsrA64: Lsr3A64
  of AsrA64: Asr3A64
  else: op

proc binReg3(g: var CodeGen; op: A64Inst; d, a, b: Reg; w32 = false) =
  g.ab.tree threeOpTag(op, w32): g.emReg d; g.emReg a; g.emReg b

proc binImm3(g: var CodeGen; op: A64Inst; d, a: Reg; v: int64; w32 = false) =
  g.ab.tree threeOpTag(op, w32): g.emReg d; g.emReg a; g.ab.intLit v

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
    let dead = g.rb.takeBinding(r)
    if dead.len > 0:
      g.ab.tree KillA64: g.ab.sym dead

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
  let name = g.rb.freshFTmpName()
  g.ab.tree RebindA64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.freg(f, bits)
  g.rb.bindFScratch(f, name)

proc unbindFTmp(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## binding. A no-op when `f` carries no temp binding. Also clears the fused
  ## core's reserve flag (see `unbindTemp`).
  g.pickedFRegs.excl f
  let dead = g.rb.takeFScratch(f)
  if dead.len > 0:
    g.ab.tree KillA64: g.ab.sym dead

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
  let nm = g.rb.boundFName(f)
  if nm.len > 0: g.ab.sym nm
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
proc marshalStackAggrArg(g: var CodeGen; a: Cursor; paramNm: string)    # defined below
proc takeBridge(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg   # defined below
proc dropBridge(g: var CodeGen; r: Reg)                                 # defined below
proc releaseStaleName(g: var CodeGen; r: Reg)                           # defined below
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
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.sym typeName
  g.ab.close()

proc emScalarStackVar(g: var CodeGen; name: string) =
  ## Declare a spilled integer/pointer scalar's stack slot `(var :name (s) (i 64))`.
  ## Always 8-byte wide / 8-aligned (arkham keeps scalars 64-bit in registers and
  ## nifasm's `ldr`/`str` need an 8-aligned slot), regardless of the logical width.
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc emTypedStackVar(g: var CodeGen; name: string; t: Cursor) =
  ## The ONE local-variable stack-slot emitter — `(var :name (s) <the value's real
  ## Leng type>)`, dispatching on the value class so callers need no per-form ladder.
  ## Identical in effect to x64's: the slot says what it holds. A scalar's slot still
  ## OCCUPIES 8 bytes and stays 8-aligned (`allocSlotUp` rounds every footprint up to
  ## the slot granularity), so a narrow type costs nothing in layout — it only tells
  ## nifasm the ACCESS width, which is what keeps a `bool`/`int8` home honest: the
  ## store writes one byte and the load `ldrsb`/`ldrb`-extends it back to arkham's
  ## canonical 64-bit form. Declaring `(i 64)` here instead made every such slot
  ## untyped to the checker AND made the load a raw 64-bit read of whatever a callee
  ## holding `ptr int8` had left in the upper seven bytes.
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  if isNilValue(t):                          # a spilled nil → `(s) (nil)` (8-byte, align 8)
    g.ab.keyword SO
    g.ab.nilValue()
    g.ab.close()
    return
  let slot = slotOf(g.prog, t)
  let sa = stackSlotAlign(g.prog, t)
  if sa > 8:                                  # over-aligned slot → `(s (align N))`
    g.ab.tree X64Flag.SO:
      g.ab.tree AlignX: g.ab.intLit sa.int64
  else:
    g.ab.keyword SO                           # ordinary 8-granular slot → `(s)`
  if slot.kind == AFloat:
    g.ab.floatType(slot.size * 8)             # `(f N)` — typed fp slot
  else:
    var tc = t                                # everything else: its own type
    if tc.kind == Symbol: g.ab.sym symName(tc) else: g.genTypeBody(tc)
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
  ## later `emReg r` emits a checked symbol rather than a raw `(xN)` the binding
  ## checker can't see. The binding is recorded as a transient temp; released by
  ## `unbindTemp`.
  let name = g.rb.freshTmpName()
  g.ab.tree RebindA64:
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
    g.ab.tree KillA64: g.ab.sym dead

proc emFloatStackVar(g: var CodeGen; name: string; bits: int) =
  ## Declare a spilled float scalar's stack slot `(var :name (s) (f N))`. nifasm
  ## sizes/aligns the slot and resolves the bare symbol to `[sp,#off]`.
  g.ra.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
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
  ## always accessed by first materializing its address. An importc/exportc gvar is
  ## referenced by its bare C name (cross-module linkage), like on x86-64.
  g.emAdr(dest, g.prog.gvarRefName(name))

proc rebindLocalAs(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Re-establish register `r`'s binding to the named local `name`, retyped to
  ## `typeCur`, via a zero-machine-code `(rebind …)`. `rebind` auto-kills the transient
  ## tenant `r` currently carries, so no manual `kill` is needed. The scope already
  ## tracks `name` (declared by `emRegLocalVar`), so `scopeLocals` is NOT touched. Type
  ## emission mirrors `emRegLocalVar`: the type given is the type declared, pointer or
  ## not (it used to flatten every non-pointer to `(i 64)`).
  let isPtr = isPtrType(resolveType(g.prog, typeCur))
  g.ab.tree RebindA64:
    g.ab.symDef name
    var t = typeCur
    g.genTypeBody(t)
    g.ab.reg r
  g.rb.rebindLocal(r, name, isPtr)

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
  ##
  ## The signature mirrors `emitSignature`'s declarative split. A DECLARATIVE proctype
  ## (all single-GPR scalar params + scalar/void result) states the positional
  ## `pN.0`/`ret.0` ABI so an indirect `(prepare …)` is cross-checked via `(arg pN)`/
  ## `(res ret.0)`. A NON-declarative one (a float/aggregate param or an aggregate
  ## return — e.g. a CPS continuation `proc(c): Continuation`) emits EMPTY `(params)`/
  ## `(result)`, exactly as a non-declarative concrete proc does, so nifasm requires no
  ## per-param bindings and the call site marshals args into raw ABI registers itself.
  let declarative = isDeclarativeAbi(g.prog, c)
  g.ab.proctypeType:
    if declarative:
      c.into:
        skip c                                  # the Empty slot (a proc has its name here)
        # A >16B by-ref aggregate result travels via x8 (handled raw at the call site),
        # not a signature param — the result slot is empty.
        var retC = c
        skip retC                               # params slot → return type
        var retByRef = false
        if not retIsVoid(retC):
          let rs = slotOf(g.prog, retC)
          retByRef = rs.kind == AMem and rs.size > 16
        g.ab.tree ParamsD:
          if c.kind == TagLit:                  # (params (param …) …)
            # THE plan (see abi.nim). AArch64's hidden result pointer travels in x8
            # (off the argument file), so the plan is never shifted (retByRef=false).
            let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
            var pIdx = 0
            c.into:
              while c.hasMore:
                let pl = plan.args[pIdx]
                inc pIdx
                c.into:                         # (param :name pragmas type)
                  inc c                         # name → positional pN.0
                  skip c                        # pragmas
                  if pl.isAgg:
                    # Aggregate param: >16B by-ref pointer in one x-reg, ≤16B by-value
                    # over `pl.words` consecutive x-regs (`(arg pN k)` selects word k).
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.tree RegsD:
                        for k in 0 ..< pl.words: g.ab.reg g.md.gprAt(pl, k)
                      if pl.byRef:
                        g.ab.ptrType: g.genPointee(c)
                      else:
                        g.genPointee(c)
                  else:
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      if not pl.onStack: g.ab.reg g.md.gprAt(pl)  # raw reg *location*
                      else: g.ab.keyword SO       # 9th+ → stack-passed
                      g.genPointee(c)            # param type BY REFERENCE (named → sym);
                                                 # a self-referential closure sig can't recurse
                  while c.hasMore: skip c
          else:
            skip c
        g.ab.tree ResultD:
          # The RetType is always the node after Params (a `.`/`(void)` for void).
          if retIsVoid(c) or retByRef:
            skip c                              # void, or returned via the x8 indirect pointer
          elif slotOf(g.prog, c).kind == AMem:
            # ≤16B by-value aggregate result → x0:x1 raw, EMPTY result slot (see
            # emitSignature): the caller reads the return registers directly.
            skip c
          else:
            g.ab.symDef synth("ret.0")
            g.ab.reg IntRet                     # raw reg *location* of the result
            g.genPointee(c)                     # return type BY REFERENCE (named → sym)
        while c.hasMore: skip c                  # pragmas
    else:
      g.ab.keyword ParamsD
      g.ab.keyword ResultD
      skip c                                     # advance past the whole proctype node
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
          g.ab.symDef synth("ret.0")
          g.ab.reg IntRet
          g.genTypeBody(c)
      if sp.sysNrA64 < 0:
        # A row whose AArch64 column is `-1` (a legacy call the asm-generic ABI
        # dropped: `open`, `stat`, `fork`, …). Emitting it anyway would trap with
        # x8 = -1, i.e. a silent ENOSYS that surfaces as `fileExists` always false
        # rather than as a build error. std/posix routes each of these through the
        # `*at`/`*2` form under `linuxA64Raw`; reaching here means one was missed.
        raiseAssert "arkham a64: no AArch64 syscall for " & sp.asmName
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
    of VarargsT:
      # A C `{.varargs.}` importc marker materialises as a synthetic trailing
      # param `(param :vanon . . (varargs))` — e.g. posix `open`/`fcntl`. It owns
      # no storage of its own; the variadic slot is just one ABI/syscall register
      # wide. Emit it as a 64-bit uint so the param maps to exactly one register.
      # `skip` drains the whole `(varargs …)` node, with or without a recorded
      # element type.
      g.ab.uintType(64); skip c
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
              # An object VARIANT's union part: branches are `(of RANGES BODY)` /
              # `(else BODY)` and overlap (nifasm lays the union out as max branch
              # size). The asm-NIF union is UNTAGGED, so emit only the bodies — the
              # discriminant is the `fld` preceding the union. A body-less branch
              # (`of x: nil`) contributes no member.
              g.ab.unionType:
                c.into:
                  while c.hasMore:
                    var bodyc = unionBranchBody(c)
                    if bodyc.kind != DotToken: g.genTypeBody(bodyc)
                    skip c
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
# A ≤16-byte aggregate travels in 1–2 consecutive GPRs. The transfer is purely
# POSITIONAL — eightbyte i is the 8 bytes at offset 8·i — and never consults the
# field layout, so an object, a tuple, an array and a field packing that straddles
# the eightbyte boundary all marshal alike. A trailing PARTIAL eightbyte (an
# aggregate whose size is not a multiple of 8) goes through `loadAggrTail` /
# `storeAggrTail`, which touch exactly the aggregate's own bytes. The >16-byte
# by-reference / x8-indirect paths still `raiseAssert`. Layout/size live in
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

proc emScalarAtOff(g: var CodeGen; p: Reg; off, size: int) =
  ## `(mem (cast (aptr (u size·8)) p) off)` — the `size`-byte unsigned scalar at the
  ## RAW byte offset `off` from `[p]`. `(at …)` strides by the element size and so
  ## can only reach multiples of the width; nifasm's `(mem base offset)` form takes a
  ## free byte displacement, which is what an aggregate's unaligned tail needs.
  g.ab.tree MemX:
    g.ab.tree CastX:
      g.ab.aptrType: g.ab.uintType(size * 8)
      g.emReg p
    g.ab.intLit off

proc loadAggrTail(g: var CodeGen; dst, base: Reg; aggrSize, byteOff: int) =
  ## `dst ←` the aggregate's trailing `aggrSize - byteOff` bytes at `[base + byteOff]`,
  ## right-justified in `dst` (the by-value ABI leaves the eightbyte's padding bits
  ## unspecified, so the high bytes are free).
  ##
  ## Reads NOTHING outside the aggregate. The eightbyte a ≤16-byte value ends in may
  ## be the last mapped bytes of a page — a heap `seq` payload, the tail of a `.bss`
  ## section — and a lazy 8-byte over-read there is a segfault that only shows up on
  ## the allocation that happens to land at the boundary.
  let n = aggrSize - byteOff
  if byteOff >= 8:
    # A whole eightbyte precedes this one, so the aggregate's LAST 8 bytes are all in
    # bounds: read them as one word and shift the tail down into place.
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, aggrSize - 8, 8))
    g.binImm(LsrA64, dst, int64((8 - n) * 8))
  elif n in {1, 2, 4}:
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, byteOff, n))
  else:
    # A 3/5/6/7-byte aggregate: no single load covers it and there is no full word to
    # borrow from, so assemble it from the top byte down.
    let tmp = g.takeBridge(avoid = base)
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, byteOff + n - 1, 1))
    for b in countdown(n - 2, 0):
      g.binImm(LslA64, dst, 8)
      g.ab.tree MovA64: (g.emReg tmp; g.emScalarAtOff(base, byteOff + b, 1))
      g.binReg(OrrA64, dst, tmp)
    g.dropBridge tmp

proc storeAggrTail(g: var CodeGen; base, src: Reg; aggrSize, byteOff: int) =
  ## `[base + byteOff] ←` the low `aggrSize - byteOff` bytes of `src`. The write-side
  ## twin of `loadAggrTail`, and the reason it cannot simply store a full word: the
  ## bytes past the aggregate belong to whatever sits next to it.
  let n = aggrSize - byteOff
  if n in {1, 2, 4}:
    g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff, n); g.emReg src)
  else:
    let tmp = g.takeBridge(avoid = base)
    g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff, 1); g.emReg src)
    for b in 1 ..< n:
      g.binImm3(LsrA64, tmp, src, int64(8 * b))
      g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff + b, 1); g.emReg tmp)
    g.dropBridge tmp

proc aggrWordsToFromRegs(g: var CodeGen; varName, typeName: string;
                         firstArg: int; toRegs: bool) =
  ## Move a ≤16-byte aggregate between its memory home and x{firstArg+i} (the by-value
  ## aggregate ABI). The whole transfer is positional: the slot's address goes into a
  ## staging bridge (a by-ref aggregate already has its pointer in a reg) and each
  ## eightbyte moves as a RAW `(u 64)` word, so fields PACKED into one word
  ## (`{int32; int32}`) all transfer and a non-object aggregate — a tuple, an array —
  ## needs no layout at all. A trailing PARTIAL eightbyte goes through
  ## `loadAggrTail` / `storeAggrTail`: exact bytes, no over-read, no over-write.
  let byteSize = aggrByteSize(g.prog, typeName)
  let loc = g.ra.locationOfSym(varName)
  var baseReg = NoReg
  var bridge = NoReg
  if loc.kind == InReg:
    baseReg = loc.r                                    # a by-ref aggregate's pointer
  else:
    bridge = g.takeBridge()
    case (if loc.kind == NoLoc: g.lookupSym(varName).cat else: scNone)
    of scGlobal: g.emGlobalAddr(bridge, varName)       # `(ret NoNifLineInfo)`: a global
    of scTvar: g.genTlvAddr(varName, bridge)           # source, addressed with `adr`
    else: g.ab.tree LeaA64: (g.emReg bridge; g.ab.sym varName)  # bridge ← &slot
    baseReg = bridge
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:                          # a full eightbyte → raw u64 word
      g.ab.tree MovA64:
        if toRegs: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(baseReg, i))
        else: (g.emWordThroughPtr(baseReg, i); g.emReg IntArgRegs[firstArg + i])
    elif toRegs:
      g.loadAggrTail(IntArgRegs[firstArg + i], baseReg, byteSize, i * 8)
    else:
      g.storeAggrTail(baseReg, IntArgRegs[firstArg + i], byteSize, i * 8)
  if bridge != NoReg: g.dropBridge bridge

proc structToRegs(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## Aggregate → x{firstArg+i} (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeName, firstArg, toRegs = true)

proc regsToStruct(g: var CodeGen; varName, typeName: string; firstArg: int) =
  ## x{firstArg+i} → aggregate (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeName, firstArg, toRegs = false)

proc globalToRegs(g: var CodeGen; name, typeName: string; firstArg: int; isTvar = false) =
  ## Read a GLOBAL (or THREADVAR) aggregate's words into x{firstArg+i}. It is a label,
  ## not a stack slot, so its address goes into a staging bridge and each word is read
  ## through that pointer — a FULL eightbyte as a raw `(u 64)` word (handles packed
  ## fields), a trailing PARTIAL eightbyte through `loadAggrTail`. For a global passed
  ## by value as a call argument (`equalStrings(s, "")` where `s` is a global `string`).
  let bridge = g.takeBridge()
  if isTvar: g.genTlvAddr(name, bridge) else: g.emGlobalAddr(bridge, name)
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(bridge, i))
    else:
      g.loadAggrTail(IntArgRegs[firstArg + i], bridge, byteSize, i * 8)
  g.dropBridge bridge

# ── named register locals (typed nifasm vars; transient scratch stays `(xN)`) ─

proc emRegLocalVar(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## `(var :name (reg) type)` + bind `r` to `name` for its scope. arkham keeps
  ## scalars 64-bit in registers (width/signedness via explicit extends), so an
  ## int/uint/bool/char local is declared `(i 64)`; a pointer keeps `(ptr T)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillA64: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.reg r
  let rt = resolveType(g.prog, typeCur)
  let isPtr = isPtrType(rt)
  # The local's OWN type — `(u 8)` stays `(u 8)`. arkham still keeps every scalar
  # 64-bit-wide in the register and normalizes with explicit extends; the declared
  # type is what the VARIABLE is, and a register operand's type never reaches the
  # encoder (nifasm's `movTypeOk`), so it costs nothing and makes a wide value
  # landing in a narrow local without its extend an error rather than an invisible
  # truncation. This used to flatten every non-pointer to `(i 64)`.
  var tc = typeCur
  g.genTypeBody(tc)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr)

proc emFRegLocalVar(g: var CodeGen; name: string; f: FReg; bits: int) =
  ## Declare a float register local: bind v-register `f` to `name` via `(rebind …)` for
  ## the rest of its scope, so subsequent uses emit the typed name instead of a raw
  ## `(dN)`/`(sN)`. The SIMD twin of `emRegLocalVar`. `rebind` kills `f`'s prior tenant
  ## itself, so no manual prior-kill is needed.
  g.ab.tree RebindA64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.freg(f, bits)
  g.rb.bindFLocal(f, name)
  g.freeFTmp.excl f                             # a local's home is no longer scratch

proc enterScope(g: var CodeGen) =
  g.rb.enterScope()

proc exitScope(g: var CodeGen) =
  ## Skip any local whose register was already rebound to a later one (already
  ## killed at that rebind via emRegLocalVar).
  let dead = g.rb.exitScope()
  for name in dead.gprs:
    g.ab.tree KillA64: g.ab.sym name
  for name in dead.fprs:
    g.ab.tree KillA64: g.ab.sym name

# ── control flow: labels + goto ─────────────────────────────────────────────

proc freshLabel(g: var CodeGen): string =
  # Name must be a NIF *symbol* (needs a '.'), but `extractBasename` strips a
  # trailing `.<digits>`, so put the counter *before* the suffix ("L0.0", …)
  # to keep basenames ("L0", "L1") distinct. `SynthMark` keeps them out of the
  # Leng namespace, where a `block L0:` would produce the very same name.
  result = synth("L") & $g.labelCount & ".0"
  inc g.labelCount

proc emLab(g: var CodeGen; name: string) =
  g.ab.tree LabA64: g.ab.symDef name        # (lab :L)

proc emBr(g: var CodeGen; tag: A64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name              # (b L) / (beq L) / …

template emitLoop(g: var CodeGen; body: untyped) =
  ## Structured infinite loop `(loop (stmts …))`: nifasm emits the back-edge INTERNALLY,
  ## so no backward branch reaches the asm-NIF (keeps "every branch forward, back-edges
  ## are loops" true). `body` must branch FORWARD to a break/exit label defined AFTER the
  ## loop. (a64 has no reg-mirror cache — nothing else to manage, unlike x64's `emitLoop`.)
  g.ab.tree LoopA64:
    g.ab.tree StmtsA64:
      body

# ── the atomic rows (`{.intrinsic: "AtomicX".}` → AArch64 LL/SC loops) ─────────
# AArch64 has no lock prefix: every read-modify-write is a load-exclusive /
# store-exclusive retry loop, and the acquire/release forms (`ldaxr`/`stlxr`)
# carry the ordering. Memory ordering is always that strong form, so the
# memory-order operands are not evaluated (see `evaluatedOperands`).
#
# An atomic arrives as `(instr …)`, so its operands are wherever the ALLOCATOR put
# them and the sequence assumes no ABI; the three registers it takes for itself are
# `AtomicScratchRegs`, which the allocator never hands out. See `emitAtomicInstr2`.

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
  # THE plan (see abi.nim): which params are stack-passed and at what byte offset
  # within the incoming-arg area — the same answer the signature and the caller got.
  let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
  var pIdx = 0
  c.into:
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
      var nm = ""
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        while c.hasMore: skip c               # type (+ anything else)
      if not pl.isFloat and pl.onStack:
        # Stack-passed. Its incoming bytes sit at `[sp + base + byteOff]` (valid here,
        # before SP is lowered). A scalar / >16B-by-ref pointer is LOADED into its home;
        # a ≤16B by-value aggregate's home is a POINTER to those bytes (address-of), so
        # the body reads its fields through it (varType set in emitParamMoves) with no
        # copy. The pointer is absolute, surviving any later frame `sub sp`.
        let loc = g.ra.locationOfSym(nm)
        assert loc.kind == InReg,
          "arkham v1: stack parameter without a register home: " & nm
        # RAW register operands: this text is written into the PROLOGUE, which
        # the body-buffer model emits AFTER the body — `emReg` would render
        # whatever binding the home register carries post-body, a name that is
        # not bound yet at this point in program order. (Pre-body the bindings
        # were empty, so raw is also byte-identical to the old output.)
        if pl.isAgg and not pl.byRef:
          g.ab.tree LeaA64:                   # home ← &[sp + base + byteOff] = sp + imm
            g.ab.reg loc.r
            g.ab.tree MemX:
              g.ab.reg SP
              g.ab.intLit (base + pl.byteOff)
        else:
          g.ab.tree MovA64:                   # home ← [sp + base + byteOff]
            g.ab.reg loc.r
            g.ab.tree MemX:
              g.ab.reg SP
              g.ab.intLit (base + pl.byteOff)

proc emitParamMoves(g: var CodeGen; decl: Cursor) =
  ## Move each parameter from its incoming ABI register to the home the
  ## allocator chose (callee-saved for cross-call params; arg regs stay put for
  ## leaf procs). Emitted after the prologue saved the homes. Stack-passed params
  ## (9th integer arg onward) are loaded separately by `emitStackParamLoads` and
  ## skipped here.
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # (params) is `.` → no parameters
  # THE plan (see abi.nim): register indices below read it — no local counting.
  let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
  var pIdx = 0
  c.into:                                     # into (params …)
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
      var nm = ""
      var tn = ""
      var typeCur: Cursor
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        typeCur = c
        g.symType[nm] = typeCur               # record the param's type for getType
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
        g.regsToStruct(nm, tn, pl.gpFirst)
      elif tn.len > 0 and loc.kind == InReg:
        # A pointer-homed aggregate: a >16B by-reference one, OR a stack-passed ≤16B
        # by-value one (whose home is a pointer to its incoming bytes). Field accesses
        # route through the pointer (recorded in varType). Register-passed → move the
        # pointer from its incoming arg register; STACK-passed → `emitStackParamLoads`
        # already loaded/computed the pointer into the home, and the param consumed
        # NO register (the plan's skip rule), so there is nothing to move.
        g.varType[nm] = tn
        if not pl.onStack:
          g.movReg(loc.r, g.md.gprAt(pl))
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming v{fpIndex}; if
        # the allocator gave it a callee-saved home, move it there.
        g.fmovF(loc.f, FloatArgRegs[pl.fpIndex], loc.typ.size * 8)
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming SIMD arg register into it so `addr`/loads/stores work.
        assert not pl.onStack, "arkham v1: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, FloatArgRegs[pl.fpIndex], bits)
      elif loc.kind == NamedStack:
        # An address-taken scalar param: declare its `(s)` slot and spill the
        # incoming argument register into it so `addr`/loads/stores work. The slot
        # carries the PARAMETER's type (as on x64), so a narrow one is stored and
        # reloaded at its own width instead of as a raw 64-bit cell.
        assert not pl.onStack, "arkham v1: >8 integer params (stack TODO)"
        g.emTypedStackVar(nm, typeCur)
        g.emScalarStore(nm, g.md.gprAt(pl))
      else:
        case loc.kind
        of InReg:
          if not pl.onStack:
            g.movReg(loc.r, g.md.gprAt(pl))
          # else: a stack-passed param — already loaded into loc.r by
          # emitStackParamLoads before SP was lowered. Nothing to move.
        else: raiseAssert "arkham v1: stack-resident parameter: " & nm

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
      # A >16B by-reference aggregate RESULT travels through the AAPCS64 indirect-result
      # register x8 (set by the caller, moved to a callee-saved home in the prologue) —
      # NOT through a signature param, unlike x86-64's hidden-pointer-in-rdi. So the
      # result slot is just empty; x8 is handled raw on both sides.
      var retC = c
      skip retC                               # params slot → return type
      var retByRef = false
      if not retIsVoid(retC):
        let rs = slotOf(g.prog, retC)
        retByRef = rs.kind == AMem and rs.size > 16
      g.ab.tree ParamsD:
        if c.kind == TagLit:                  # (params (param …) …)
          # THE plan (see abi.nim); AArch64's hidden result pointer is x8, off the
          # argument file, so the plan is never shifted (retByRef=false).
          let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
          var pIdx = 0
          c.into:
            while c.hasMore:
              let pl = plan.args[pIdx]
              inc pIdx
              c.into:                         # (param :name pragmas type)
                inc c                         # name → use positional p{ord}
                skip c                        # pragmas
                if pl.isFloat:
                  raiseAssert "arkham a64: float param in signature not yet supported"
                if pl.isAgg:
                  # An aggregate param: a >16B aggregate is a by-ref pointer in one x-reg;
                  # a ≤16B by-value aggregate spans `pl.words` consecutive x-regs (one per
                  # eightbyte). Emitted with `(regs …)` (ABI-only); `(arg pN k)` at a call
                  # selects word k. The body reads the registers raw into its own home.
                  if pl.onStack:
                    # Doesn't fit the remaining arg registers → stack-passed `(s)`. A >16B
                    # aggregate travels as ONE pointer (`(s) (ptr T)`, 8 bytes); a ≤16B
                    # by-value one occupies its eightbytes (`(s) T`). The plan's skip rule:
                    # a later smaller param can still take a free register.
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.keyword SO
                      if pl.byRef:
                        g.ab.ptrType: g.genTypeBody(c)
                      else:
                        g.genTypeBody(c)
                  else:
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.tree RegsD:
                        for k in 0 ..< pl.words: g.ab.reg g.md.gprAt(pl, k)
                      if pl.byRef:
                        g.ab.ptrType: g.genTypeBody(c)
                      else:
                        g.genTypeBody(c)
                else:
                  g.ab.tree ParamD:
                    g.ab.symDef paramName(pl.ord)
                    if not pl.onStack:
                      g.ab.reg g.md.gprAt(pl)   # x0–x7: raw reg *location*
                    else:
                      g.ab.keyword SO           # 9th+ → stack-passed `(s)`
                    g.genTypeBody(c)            # the param type (consumes it)
                while c.hasMore: skip c
        else:
          skip c                              # no params slot → consume it
      g.ab.tree ResultD:                      # c now at the return type
        if retIsVoid(c) or retByRef:
          skip c                              # void, or returned via the x8 indirect pointer
        else:
          let rs = slotOf(g.prog, c)
          if rs.kind == AFloat:
            raiseAssert "arkham a64: float result in signature not yet supported"
          if rs.kind == AMem:
            # A ≤16B by-value aggregate result travels in x0:x1 with an EMPTY result slot
            # (like a >16B by-ref result via x8): the callee marshals it into x0:x1 (the
            # body's `structToRegs`) and the caller reads those raw after the call — no
            # `(res ret.0)` binding to declare here (mirrors the x64 rax:rdx result).
            skip c
          else:
            g.ab.symDef synth("ret.0")
            g.ab.reg IntRet                   # raw reg *location* of the result
            g.genTypeBody(c)                  # the result type (consumes it)
      while c.hasMore: skip c                 # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  g.ab.tree ClobberD:
    # A diverging callee returns to nobody, so no caller can observe what it
    # destroyed — declaring clobbers only forces every proc with a cold guard onto
    # callee-saved homes. See the x64 twin in `emitSignature`.
    if not declIsNoReturn(decl):
      for r in ConvClobbersGpr: g.ab.reg r   # a clobber *declaration*: raw reg locations

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

proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location)
proc genStmt2(g: var CodeGen; c: Cursor)
proc emLvalAddr2(g: var CodeGen; c: Cursor)
proc prematLval2(g: var CodeGen; c: Cursor)
proc unbindLvalTemps2(g: var CodeGen; c: Cursor)
proc genConstr2(g: var CodeGen; c: Cursor; dstVar: string)
proc genAconstr2(g: var CodeGen; c: Cursor; dstVar: string)

# ── fused value core (step 3): decide-and-emit overloads ─────────────────────
# The destination is a threaded parameter (constraint in, resolved location
# out) instead of the allocator's per-position plan — the a64 twin of the x64
# fused core. Old locs-reading procs stay live until genProc2 flips.
proc emitValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitBin2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitMod2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFBinE(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondValue2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondE(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitScalarCmpE(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool): A64Inst
proc emitMemLoad2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitAddr2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCast2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCall2(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false)
proc emitInstr2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitLvalue2(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false)
proc freeLvalTemps2(g: var CodeGen; c: Cursor)
proc resolveLvalVal(g: var CodeGen; c: Cursor; dest: var Location)
proc produceIntoMem2(g: var CodeGen; c: Cursor; dst: Location)
proc produceIntoFMem2(g: var CodeGen; c: Cursor; dst: Location)
proc atNeedsScratch(g: var CodeGen; atNode: Cursor): bool
proc atIndexIsReg(g: var CodeGen; atNode: Cursor): bool
proc storeReg2(g: var CodeGen; dst: Location; src: Reg)

template posOf(g: CodeGen; cur: Cursor): int = cursorToPosition(g.buf[], cur)

# ── staging bridges (always free; reserved out of the allocator pool) ────────

proc tryTakeBridge(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg =
  ## `takeBridge` for a caller that HAS another answer when both bridges are
  ## already staging: reports exhaustion as `NoReg` instead of asserting.
  for r in IntBridgeRegs:
    if r != avoid and not g.rb.isBoundTemp(r):
      g.bindTemp(r, typ); return r
  NoReg

proc takeBridge(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg =
  ## A staging-bridge GPR (x14/x15). Bound to a typed name so `emReg` emits a
  ## checked symbol and a typed memory base type-checks. Released by `dropBridge`.
  ## Two bridges nest (e.g. a `cmp` of two spilled operands); a third asserts.
  result = g.tryTakeBridge(typ, avoid)
  if result == NoReg:
    raiseAssert "arkham a64n: both staging bridges in use in proc " & g.curProcName

proc dropBridge(g: var CodeGen; r: Reg) =
  if r != NoReg: g.unbindTemp(r)

proc takeFBridge(g: var CodeGen; bits: int): FReg =
  g.bindFTmp(FloatBridgeReg, bits); FloatBridgeReg

proc dropFBridge(g: var CodeGen) =
  g.unbindFTmp(FloatBridgeReg)

# ── fused value core: emit-time destination protocol (step 3, a64 twin) ──────
# Lazy-bind lifecycle identical to x64's: `takeTmp` RESERVES (pickedRegs flag
# guards the reserve→bind gap; the consumer binds on materialization);
# `freeVal` releases. Pool dry → mint an `etmp` slot (declared by the
# post-body prologue). The a64-only rule: intrinsic/atomic operands must
# NEVER fall back to the bridges — the atomics own x14/x15/x16.

proc takeTmp(g: var CodeGen; slot: AsmSlot): Location =
  ## Reserve an expression-temp GPR (lazy-bound by its consumer); an `etmp`
  ## spill-slot Location when the pools are dry.
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
  ## A SURVIVOR scratch (outlives a call / stays off the bridges): callee-saved
  ## only. Demoting a local mid-emission is impossible in the merged core, so
  ## exhaustion spills the (re-derivable) survivor to a `heldN.0` slot
  ## (`canSpill`) or fails loudly.
  let r = g.pickHeldReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, ScalarSlot, isTemp = true)
  # Second chance, callee-saved only (the value must survive a call): judged by
  # LIVE bindings instead of the `regHoldsHome` union — see `pickStagingA64` for
  # why the union is what runs out under `-d:release`.
  for cs in g.md.intCalleeSaved:
    if cs notin g.pickedRegs and not g.ra.isSealed(cs) and not g.rb.isAccum(cs) and
       not g.rb.isBound(cs):
      g.ra.usedCallee.incl cs                    # the (post-body) prologue saves it
      g.releaseStaleName(cs)
      g.pickedRegs.incl cs
      return regLoc(cs, ScalarSlot, isTemp = true)
  if canSpill:
    let nm = g.mintSpillName("held")
    g.ra.spillTemps.add (name: nm, typ: AsmSlot(cls: AInt, size: 8, align: 8),
                         isFloat: false)
    return namedStackLoc(nm, ScalarSlot, spillTemp = true)
  raiseAssert "arkham a64n: out of registers for " & what &
              " in proc " & g.curProcName & " (nothing to spill), picked: " &
              $g.pickedRegs

proc pickStagingA64(g: var CodeGen): Reg =
  ## Last-resort transient GPR for an operand that MUST be in a register and cannot
  ## use a bridge (an atomic's operands: its LL/SC sequence owns x14/x15/x16).
  ##
  ## Same candidates `pickTempReg`/`pickHeldReg` walk, but judged by what is LIVE
  ## rather than by `regHoldsHome` — the immutable per-proc UNION of every register
  ## any local is EVER homed in. The union is the right conservative answer for an
  ## ordinary temp, but as a last resort it throws away the allocator's whole point:
  ## one register homes many locals across DISJOINT scopes, so the union refuses all
  ## of them for the entire body. `-d:release` is where that bites — shoggoth's
  ## inlining multiplies the number of distinct locals while their scopes keep peak
  ## pressure flat, so the union grows and the free set shrinks even though nothing
  ## is more live than before. `rb` is the authority instead: the emitter binds a
  ## register local at its `(var :name (reg) T)` and releases it at scope exit, and
  ## nifasm's binding checker validates the result. This is the x86-64
  ## `pickStagingScratch`'s reasoning, ported.
  ##
  ## A register carrying ANY binding — a live local or an anonymous in-flight temp —
  ## is still refused, so nothing owned can be clobbered.
  for r in g.md.intTempRegs:
    if r notin g.pickedRegs and not g.ra.isSealed(r) and not g.rb.isAccum(r) and
       not g.rb.isBound(r):
      g.releaseStaleName(r); return r
  for r in g.md.intCalleeSaved:
    if r notin g.pickedRegs and not g.ra.isSealed(r) and not g.rb.isAccum(r) and
       not g.rb.isBound(r):
      g.ra.usedCallee.incl r                     # the (post-body) prologue saves it
      g.releaseStaleName(r); return r
  NoReg

proc takeInstrReg(g: var CodeGen; slot: AsmSlot; atomic: bool): Location =
  ## A register an `(instr …)` operand or result MUST have (never a spill slot).
  ## Pools, then a callee-saved survivor, then — for a NON-atomic intrinsic — a
  ## staging bridge.
  ##
  ## The bridges are off-limits to the ATOMIC lowerings, which is where the blanket
  ## "never a bridge" rule came from: their `ldaxr`/`stlxr` retry loops use
  ## x14/x15/x16 themselves, so an operand parked there would be destroyed between
  ## the exclusive load and the store. `clz`/`rbit`/`rev`/`bswap` are ONE
  ## instruction with nothing in between, and at most a result plus one operand —
  ## exactly what two bridges cover. Under `-d:release` (shoggoth's denser
  ## expressions leave the pools empty) a bridge is sometimes the only register
  ## left, and the alternative was a hard failure.
  let r = g.pickTempReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, slot, isTemp = true)
  if atomic:
    let s = g.pickStagingA64()
    if s == NoReg:
      result = g.takeHeld("an atomic intrinsic operand")  # fails loudly
      result.typ = slot                        # keep the precise type for the binding
      return
    g.pickedRegs.incl s
    return regLoc(s, slot, isTemp = true)
  let h = g.pickHeldReg()
  if h != NoReg:
    g.pickedRegs.incl h
    return regLoc(h, slot, isTemp = true)
  let b = g.takeBridge(slot)                   # binds it; `freeVal` releases it
  g.pickedRegs.incl b
  result = regLoc(b, slot, isTemp = true)

proc freeVal(g: var CodeGen; loc: Location) {.inline.} =
  ## Release a reserved/resolved temp — the emit-time `releaseTmp`: clear the
  ## pick flag and, if a consumer bound it, `(kill)` the binding. A no-op for
  ## every other location kind.
  if loc.kind == InReg and loc.isTemp:
    g.pickedRegs.excl loc.r
    g.unbindTemp(loc.r)
  elif loc.kind == InFReg and loc.isTemp:
    g.pickedFRegs.excl loc.f
    g.unbindFTmp(loc.f)

proc resolveDestE(g: var CodeGen; dest: var Location; natural: Location) =
  ## Resolve a LEAF destination constraint against the value's natural location
  ## — the emit-time twin of the allocator's `resolveDest` (lazy-bound temps).
  case dest.kind
  of Undef: dest = natural
  of NeedsReg:
    dest = (if natural.kind == InReg: natural else: g.takeTmp(natural.typ))
  of RegOrImm:
    dest = (if natural.kind in {InReg, Imm}: natural else: g.takeTmp(natural.typ))
  else: discard                              # fixed InReg/InFReg/NamedStack/…: keep

proc forceRegDestE(g: var CodeGen; dest: var Location) =
  ## Ensure a value's `dest` is a register (or, pool-dry, an etmp slot the
  ## produce-into path serves).
  case dest.kind
  of NeedsReg, RegOrImm: dest = g.takeTmp(dest.typ)
  of Undef: dest = g.takeTmp(ScalarSlot)
  else: discard

# ── scalar Location → register / register → Location ─────────────────────────

proc emImm(g: var CodeGen; loc: Location) =
  ## Emit an immediate VALUE operand: `(nil)` for a null pointer, else the integer.
  if isNilImm(loc): g.ab.nilValue()
  else: g.ab.intLit loc.ival

proc placeImm(g: var CodeGen; dest: Reg; loc: Location) =
  ## `mov dest, <imm>` — emits `(mov dest (nil))` for a nil so the register binds to
  ## the `(nil)` type, else the ordinary `movImm`.
  if isNilImm(loc):
    g.ab.tree MovA64: (g.emReg dest; g.ab.nilValue())
  else: g.movImm(dest, loc.ival)

proc placeImmTyped(g: var CodeGen; dest: Reg; loc: Location; typeCur: Cursor) =
  ## `placeImm` for a `dest` bound with `typeCur`'s slot. When that slot is a POINTER
  ## and the literal is a non-zero integer, the bare `(mov dest <imm>)` is exactly the
  ## shape nifasm's `checkPtrStore` rejects — it cannot tell it from a code generator's
  ## stale register binding. Spell the intent out with an explicit `(cast …)`, which
  ## opts out of that rule: `cast[pointer](-1)`, mmap's MAP_FAILED, is a deliberate
  ## non-zero pointer literal.
  if not isNilImm(loc) and loc.ival != 0 and not cursorIsNil(typeCur) and
      isPtrType(resolveType(g.prog, typeCur)):
    var tc = typeCur
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree CastX: (g.genTypeBody(tc); g.ab.intLit loc.ival)
  else:
    g.placeImm(dest, loc)

proc globalIsGvarSlot(g: var CodeGen; name: string): bool =
  ## True when `name` is a real `.bss`/`.data` gvar (nifasm `GvarD`, carrying a
  ## page-offset patch site) — the `gload`/`gstore` fold target — rather than a
  ## read-only `const` blob (`RodataD`), which is a label with no gvar site. Mirrors
  ## `genGlobal`'s split exactly: rodata iff the decl is a `const` WITH a value.
  let si = g.lookupSym(name)
  if si.cat != scGlobal: return false
  var d = si.decl
  if d.stmtKind != ConstS: return true                  # a `var`/gvar → GvarD
  inc d; skip d; skip d                                  # const: name, pragmas, type
  result = not (d.hasMore and d.kind != DotToken)        # value-less const → gvar slot

proc place2(g: var CodeGen; src: Location; dest: Reg) =
  ## `dest ← <scalar Location src>`. The pure-emit analogue of `emitLoad`: a
  ## global/threadvar address is formed straight into `dest` (no borrowed temp),
  ## a complex lvalue routes through the `*2` address machinery.
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
      # The deref is typed `(ptr <globalType>)` so it yields the PRECISE type — `dest` is
      # bound to the *value* type, so a bare `(mem dest)` would drop a pointer level
      # (harmless for a scalar, but a POINTER const would load `object` where `(ptr
      # object)` is wanted; nifasm is strict). Cast in the deref rather than spend a bridge.
      g.emAdr(dest, g.prog.gvarRefName(src.name))
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
    let b = g.takeBridge(); g.emAdr(b, g.prog.gvarRefName(src.name))
    g.emFLoad(dest, b, bits); g.dropBridge b
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
    if g.globalIsGvarSlot(dst.name):
      # Fold: `adrp x17, g@PAGE ; str src, [x17, g@PAGEOFF]` — no bridge, no address `add`.
      g.ab.tree GstoreA64: (g.emReg src; g.ab.sym g.prog.gvarRefName(dst.name))
    else:
      let b = g.takeBridge(); g.emAdr(b, g.prog.gvarRefName(dst.name))
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
    let b = g.takeBridge(); g.emAdr(b, g.prog.gvarRefName(dst.name))
    g.emFStore(src, b, bits); g.dropBridge b
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
  var s = g.tryTakeBridge(loc.typ)
  if s == NoReg:
    # Both bridges are already staging inside this one address chain (a `(mem …)`
    # with a spilled base AND a spilled index, under an aggregate copy that put its
    # two end addresses there first). Any register with no live binding serves — the
    # reload dies with the operand — and `pickStagingA64` finds those the whole-proc
    # home union hides.
    s = g.pickStagingA64()
    if s == NoReg:
      raiseAssert "arkham a64n: no register to reload a spilled memory base in proc " &
                  g.curProcName
    g.pickedRegs.incl s
    g.bindTemp(s, loc.typ)
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
  ## lvalue tree (NOT general `emitValue2`). The destination was decided by
  ## `emitLvalue2` (`resolveLvalVal`) and parked in the memo; thread it.
  let pos = g.posOf(c)
  var d = g.ra.locs[pos]
  g.emitValue2(c, d)
  g.ra.locs[pos] = d
  g.reloadMemBase2(pos)

proc inlineAggrHome(g: var CodeGen; c: Cursor): string =
  ## The stack slot standing in for an aggregate CONSTRUCTOR used as an lvalue base —
  ## `[a, b][i]`, which hexer hands over as `(at (aconstr …) i)`. A constructor is a
  ## value, not a location, so there is nothing to address until one exists; this
  ## names the slot that `prematLval2` builds it into and `emLvalAddr2` then reads.
  ## Keyed on the node's position, so both passes name the same slot without a side
  ## table.
  synth("lvaltmp") & $g.posOf(c) & ".0"

proc emLvalAddr2(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (operand of a `(mem …)`/`(lea
  ## …)`), reading any embedded value register from its pre-allocated `locs`.
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm)
    if loc.kind == NoLoc:                                 # module-level global base
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
    of AconstrC, OconstrC:
      g.ab.sym g.inlineAggrHome(c)                        # built by `prematLval2`
    else: raiseAssert "arkham a64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham a64n: emLvalAddr2 kind " & $c.kind

proc lvalMaterializedRegs(g: CodeGen; c: Cursor; acc: var set[Reg]) =
  ## Every register the lvalue/value subtree `c` has materialized something into (a
  ## deref pointer, an index, a global base address). `locs` is position-indexed
  ## over the proc's whole token span, so the subtree is a plain range scan — no
  ## structural re-walk that could miss a nesting level. An untouched entry is
  ## `Undef` (the zero value), never a bogus `InReg`.
  let first = g.posOf(c)
  var e = c; skip e
  for p in first ..< g.posOf(e):
    let l = g.ra.locs[p]
    if l.kind == InReg: acc.incl l.r

proc strideRecycle(g: CodeGen; idxCur, baseCur: Cursor): Reg =
  ## The index's register when it may double as the stride scratch, else `NoReg`.
  ##
  ## Two conditions. It must be a TRANSIENT — a staging bridge or a pool temp this
  ## operand reserved for the index — so that no later read can see the multiply's
  ## result; an index left in its allocator-assigned home is a named local whose
  ## value outlives the access. And it must not be the BASE's register: nifasm
  ## allows `scratch == index` (it stages the stride constant in its own reserved
  ## x16, so `scratch = idx*stride` reads the index in the very instruction that
  ## overwrites it) but rejects `scratch == base`, which the following
  ## `add scratch, base, scratch` would destroy before reading.
  if idxCur.kind in {IntLit, UIntLit}: return NoReg
  let l = g.ra.locs[g.posOf(idxCur)]
  if l.kind != InReg or not l.isTemp or not g.rb.isBoundTemp(l.r): return NoReg
  var baseRegs: set[Reg] = {}
  g.lvalMaterializedRegs(baseCur, baseRegs)
  if l.r in baseRegs: NoReg else: l.r

proc bindStrideScratch(g: var CodeGen; atPos: int; recycle: Reg) =
  ## Bind the stride scratch `reserveStrideScratch` reserved for the access at
  ## `atPos`, taking the staging bridge now if that is what it settled for.
  ##
  ## `recycle` is the index's own register when `strideRecycle` proved it reusable —
  ## the last resort when BOTH bridges already carry this same operand's reloaded
  ## base and index. Three spilled operands in one `(mem …)` is what a `-d:release`
  ## build reaches (shoggoth's inlining and CSE make expressions dense enough that
  ## nothing is left in the pools), and there is no third bridge.
  if atPos in g.lvalStrideOnBridge:
    var r = g.tryTakeBridge()
    if r == NoReg:
      # No bridge left (both already carry this operand's reloaded base and index).
      # Any register with NO live binding still serves — the scratch is a plain
      # transient — and `pickStagingA64` judges that by what is bound right now
      # instead of by the whole-proc home union `reserveStrideScratch` consulted.
      r = g.pickStagingA64()
      if r != NoReg:
        g.pickedRegs.incl r
        g.bindTemp(r, ScalarSlot)
      else:
        if recycle == NoReg:
          raiseAssert "arkham a64n: no stride scratch for the indexed access in proc " &
                      g.curProcName
        # nifasm ALLOWS `scratch == index`: it stages the stride constant in its own
        # reserved x16, so `scratch = idx*stride` reads the index in the very
        # instruction that overwrites it. Only `scratch == base` is rejected there
        # (that one would destroy the base before `add scratch, base, scratch`).
        r = recycle
      g.lvalStrideOnBridge.excl atPos   # no bridge of its own to release
    g.ra.aux[atPos] = ExprAux(scratch: @[r])
  else:
    g.bindTemp(g.ra.aux[atPos].scratch[0], ScalarSlot)

proc releaseStrideScratch(g: var CodeGen; atPos: int) =
  ## Release it after the consuming `(mem …)`/`(lea …)`. `dropBridge` and the pool
  ## release are the same two operations, so the only difference a bridge makes is
  ## that the position stops being marked.
  let r = g.ra.aux[atPos].scratch[0]
  g.lvalStrideOnBridge.excl atPos
  g.pickedRegs.excl r
  g.unbindTemp(r)

proc prematLval2(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue's embedded values (a deref pointer, an index, a global
  ## base address) into their allocated registers BEFORE the consuming `(mem …)`/
  ## `(lea …)` tree opens.
  if c.kind == Symbol:
    let loc = g.ra.locs[g.posOf(c)]
    if loc.kind == InReg and g.ra.locationOfSym(symName(c)).kind == NoLoc:
      # a module-level global aggregate base: `lea reg, &g` into the address register
      # the walk reserved (fused: a lazy-bound pick — bind it here, at
      # materialization; pre-fuse it was bound by the caller).
      if loc.isTemp and not g.rb.isBoundTemp(loc.r): g.bindTemp(loc.r, ScalarSlot)
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
      var recycle = NoReg
      cc.into:
        let baseCur = cc
        g.prematLval2(cc); skip cc                        # base
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
          recycle = g.strideRecycle(cc, baseCur)          # last-resort stride scratch
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.bindStrideScratch(atPos, recycle)
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      var recycle = NoReg
      cc.into:
        let baseCur = cc
        g.prematAddrVal2(cc)                              # the pointer → its reg (follow steals)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.prematAddrVal2(cc)                            # follow steals
          recycle = g.strideRecycle(cc, baseCur)          # last-resort stride scratch
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
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
        if t.kind == Symbol: g.varType[home] = symName(t)
        g.genStore2(c, namedStackLoc(home, g.exprSlot(c)))
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

proc bindLvalGlobalBases(g: var CodeGen; c: Cursor; bound: var seq[Reg]) =
  ## Bind every UNBOUND global-base address register in lvalue `c` so `prematLval2` leas
  ## `&global` into a bound register (`emReg` rejects an unbound scratch). Skips an
  ## already-bound base reg (a caller — e.g. `emitAddr2` — may reuse its bound result reg).
  if c.kind == Symbol:
    let loc = g.ra.locs[g.posOf(c)]
    if loc.kind == InReg and loc.isTemp and not g.rb.isBoundTemp(loc.r) and
       g.ra.locationOfSym(symName(c)).kind == NoLoc:
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
    var pLoc = g.ra.locs[g.posOf(p)]    # the CALLER's walk decided p's spot
    g.emitValue2(p, pLoc)
    g.ra.locs[g.posOf(p)] = pLoc
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
      var pLoc = g.ra.locs[g.posOf(p)]  # the CALLER's walk decided p's spot
      g.emitValue2(p, pLoc)
      g.ra.locs[g.posOf(p)] = pLoc
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

proc foldRhs2(g: var CodeGen; op: A64Inst; dest: Reg; rhsLoc: Location; rhsC: Cursor;
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

const ThreeOpA64 = {AddA64, SubA64, MulA64, AndA64, OrrA64, EorA64,
                    LslA64, LsrA64, AsrA64}
  ## Ops with a native 3-operand `(op D A B)` nifasm encoding (see parseArith3A64).

proc foldRhs3(g: var CodeGen; op: A64Inst; dest, rn: Reg; rhsLoc: Location; rhsC: Cursor;
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

proc normalizeUnaryWidth(g: var CodeGen; resTypeC: Cursor; rD: Reg) =
  ## The `neg`/`bitnot` twin of `normalizeBinWidth`. Both are computed 64-bit wide,
  ## so on a sub-64-bit type they leave bits ABOVE the type width: `~15'u8` is
  ## `0xFFFF_FFFF_FFFF_FFF0`, not `0xF0`, and a following unsigned compare (or
  ## `lsr`, or `udiv`) reads the stale bits. Signed types need it too, but only at
  ## the boundary — `neg` of `-128'i8` is `+128`, whose i8 value is `-128` again.
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

proc isUnsigned32(resTypeC: Cursor): bool =
  ## True for a `(u 32)` result — the case where an add/sub/mul W-form gives the
  ## fully-normalized (zero-extended) value for free, letting emitBin2 both emit the
  ## `addw`/`subw`/`mulw` tag and skip the `normalizeBinWidth` shift-pair.
  let slot = typeToSlot(resTypeC)
  slot.kind == AUInt and slot.size == 4

proc normalizeBinWidth(g: var CodeGen; resTypeC: Cursor; rD: Reg; op: A64Inst) =
  ## arkham keeps register values canonically sign/zero-extended to their full
  ## 64-bit form. `add`/`sub`/`mul`/`lsl` on a sub-64-bit type can leave nonzero
  ## bits ABOVE the type width (lsl overflow, add carry, unsigned sub borrow) — a
  ## following `lsr` / unsigned compare / `udiv` would then read those stale bits.
  ## Re-normalize the result to restore the invariant. tinyhashes' `!&`/`!$` are the
  ## canonical case: `x shl 10'u32` overflowed past bit 31 and the next `shr 6'u32`
  ## pulled the leaked bits back down. (`and`/`orr`/`eor`/`lsr` of already-normalized
  ## operands stay normalized, so they need no fixup.)
  if op notin {AddA64, SubA64, MulA64, LslA64}: return
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

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

# ── calls ────────────────────────────────────────────────────────────────────

proc emitMemIntrin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Inline `mem*` byte loop. The allocator placed the 3 args in x0/x1/x2 (a normal
  ## int-arg call); during this leaf intrinsic the free arg registers x3/x4/x5 are the
  ## loop scratch (raw, caller-saved). Result → x0 (moved to its home by emitCall2).
  for idx in 0 ..< min(3, argCurs.len):
    var aD = regLoc(IntArgRegs[idx], ScalarSlot)
    g.emitValue2(argCurs[idx], aD)                       # → x0 / x1 / x2 directly
    g.unbindTemp(aD.r)                                   # used raw below
  let (dst, src, n) = (R0, R1, R2)                       # for memset: src holds `val`
  let (i, b, b2) = (R3, R4, R5)
  case builtin
  of "memcpy", "memmove":
    let done = g.freshLabel()
    if builtin == "memmove":
      let fwd = g.freshLabel()
      g.ab.tree CmpA64: (g.ab.reg dst; g.ab.reg src)
      g.emBr(BlsA64, fwd)
      g.movReg(i, n)
      g.emitLoop:
        g.ab.tree CmpA64: (g.ab.reg i; g.ab.intLit 0)
        g.emBr(BeqA64, done)
        g.binImm(SubA64, i, 1)
        g.emLdrb(b, src, i); g.emStrb(b, dst, i)
      g.emLab(fwd)
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
      g.emBr(BhsA64, done)
      g.emLdrb(b, src, i); g.emStrb(b, dst, i)
      g.binImm(AddA64, i, 1)
    g.emLab(done)
    g.movReg(IntRet, dst)
  of "memset":
    let done = g.freshLabel()
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
      g.emBr(BhsA64, done)
      g.emStrb(src, dst, i)                              # store low byte of `val` (in x1)
      g.binImm(AddA64, i, 1)
    g.emLab(done)
    g.movReg(IntRet, dst)
  of "memcmp":
    let diff = g.freshLabel()
    let equal = g.freshLabel(); let done = g.freshLabel()
    g.movImm(i, 0)
    g.emitLoop:
      g.ab.tree CmpA64: (g.ab.reg i; g.ab.reg n)
      g.emBr(BhsA64, equal)
      g.emLdrb(b, dst, i); g.emLdrb(b2, src, i)          # dst=pa, src=pb
      g.ab.tree CmpA64: (g.ab.reg b; g.ab.reg b2)
      g.emBr(BneA64, diff)
      g.binImm(AddA64, i, 1)
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

proc instrOperandReg(g: CodeGen; cur: Cursor): Reg =
  ## The register an already-emitted `(instr …)` operand landed in. `allocInstr`
  ## asked for `NeedsReg` on every operand a lowering reads, so anything else here
  ## is an allocator bug, not a source-level condition.
  let l = g.ra.locs[cursorToPosition(g.buf[], cur)]
  if l.kind != InReg:
    raiseAssert "arkham a64n: intrinsic operand is not in a register"
  l.r

proc releaseStaleName(g: var CodeGen; r: Reg) =
  ## A register about to be used as RAW scratch must carry no stale named-local
  ## binding: `emOp`/`emReg` would emit that typed name instead of the `(xN)` tag,
  ## and its type would not match the pointee-typed exclusive access. `(kill)` the
  ## binding so the raw tag is what comes out. The x86-64 twin does the same.
  if r != NoReg:
    let dead = g.rb.takeBinding(r)
    if dead.len > 0:
      g.ab.tree KillA64: g.ab.sym dead

proc emitAtomicRmw2(g: var CodeGen; dst, p, v: Reg; opStr: string;
                    isXchg, returnNew: bool; bits: int) =
  ## `loop: ldaxr old,[p]; new = old op v (or v, for an exchange); stlxr st,new,[p];
  ## cmp st,0; beq done` — a non-zero status means another agent won the line, so
  ## the loop falls through to nifasm's internal back-edge and re-reads.
  ##
  ## `old`/`new`/`st` are the dedicated scratch (`AtomicScratchRegs`); `p` and `v`
  ## are only ever read, which is what lets `dst` alias either of them.
  let lDone = g.freshLabel()
  let (pS, vS) = (g.emOp p, g.emOp v)
  let old = g.emOp AtomicScratchRegs[0]
  let neu = g.emOp AtomicScratchRegs[1]
  let st = g.emOp AtomicScratchRegs[2]
  let w = wsfx(bits)
  let update = if isXchg: &"(mov {neu} {vS})" else: &"(mov {neu} {old}) ({opStr} {neu} {vS})"
  # Structured `(loop …)`: nifasm emits the back-edge internally. The exclusive
  # store SUCCEEDS when `st == 0` → the forward `(beq lDone)` leaves the loop.
  g.ab.splice &"(loop (stmts (ldaxr {old} {pS}{w}) " & update & " " &
              &"(stlxr {st} {neu} {pS}{w}) (cmp {st} 0) (beq {lDone}))) (lab :{lDone})"
  g.movReg(dst, AtomicScratchRegs[if returnNew: 1 else: 0])

proc emitAtomicInstr2(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                      argCurs: seq[Cursor]; res: Location) =
  ## An atomic row's AArch64 sequence, on operands the ALLOCATOR placed. Every
  ## variant is the strong acquire/release form, so the memory-order operands are
  ## not evaluated at all (see `evaluatedOperands`) — whatever order was asked for,
  ## this satisfies it.
  # A fence has no cell operand, and its memory order is not evaluated, so it must
  # be answered before anything reads `argCurs[0]`.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword DmbA64
    return
  of AtomicSignalFenceOp:
    # A compiler barrier only: it orders nothing in hardware, and what it forbids —
    # hoisting a memory access across it — arkham does not do to begin with.
    return
  else: discard
  for r in AtomicScratchRegs: g.releaseStaleName(r)
  let bits = g.atomicBits(argCurs[0])
  let p = g.instrOperandReg(argCurs[0])
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  case op
  of AtomicLoadOp: g.emLdar(res.r, p, bits)
  of AtomicStoreOp: g.emStlr(g.instrOperandReg(argCurs[1]), p, bits)
  of AtomicExchangeOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "", true, false, bits)
  of AtomicFetchAddOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, false, bits)
  of AtomicFetchSubOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, false, bits)
  of AtomicFetchAndOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "and", false, false, bits)
  of AtomicFetchOrOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "orr", false, false, bits)
  of AtomicFetchXorOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "eor", false, false, bits)
  of AtomicAddFetchOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, true, bits)
  of AtomicSubFetchOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, true, bits)
  of AtomicCompareExchangeOp:
    let lSucc = g.freshLabel()
    let lFail = g.freshLabel()
    let lDone = g.freshLabel()
    let pp = g.emOp p
    let ep = g.emOp g.instrOperandReg(argCurs[1])   # `expected`, a POINTER
    let d = g.emOp g.instrOperandReg(argCurs[2])
    let exp = g.emOp AtomicScratchRegs[0]
    let old = g.emOp AtomicScratchRegs[1]
    let st = g.emOp AtomicScratchRegs[2]
    let ret = g.emOp res.r
    let w = wsfx(bits)
    # Two FORWARD exits from the loop body: `(bne lFail)` when the cell no longer
    # holds `expected`, `(beq lSucc)` when the exclusive store succeeded. A non-zero
    # `st` (another agent won the line) falls through to the internal back-edge and
    # re-reads. The failure path MUST publish what was actually there — that is the
    # whole protocol: the caller retries against the value it now holds.
    g.ab.splice(
      &"(ldar {exp} {ep}{w}) (loop (stmts (ldaxr {old} {pp}{w}) " &
      &"(cmp {old} {exp}) (bne {lFail}) (stlxr {st} {d} {pp}{w}) " &
      &"(cmp {st} 0) (beq {lSucc}))) " &
      &"(lab :{lSucc}) (mov {ret} 1) (b {lDone}) " &
      &"(lab :{lFail}) (clrex) (stlr {old} {ep}{w}) (mov {ret} 0) (lab :{lDone})")
  else:
    # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
    # empty, so this is the message that column promises.
    lengError c, "`" & IntrinsicNames[op] & "` has no AArch64 lowering — " &
              "guard the call with a `when`"
  # Release the operand temps' nifasm bindings. Ordinarily a volatile temp's binding
  # dies when the register is rebound for the next value, but an operand that had to
  # be escalated to a CALLEE-SAVED register (`reserveInstrReg`) may see no such rebind
  # before the epilogue's `ldp` — which nifasm rejects while the register is still
  # bound to a name.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.ra.locs[g.posOf(argCurs[i])]
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

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
    "arkham a64n: indirect call target is not a proctype"

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
        let b = g.takeBridge(dst.typ); g.placeImm(b, v); g.emScalarStore(dst.name, b); g.dropBridge b
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

proc flatCopyToPtr2(g: var CodeGen; srcVar: string; sizeBytes: int; dstPtr, tmp: Reg) =
  ## Copy the `sizeBytes`-byte aggregate stack slot `srcVar` into `[dstPtr]` through the
  ## (already bound) word scratch `tmp` — the a64 twin of x64's `flatCopyToPtr`. The
  ## source address goes into the reserved produce bridge x16: it is never allocator-
  ## assigned, and the copy's own instructions synthesize only through X17 (large
  ## load/store offsets), so it cannot be clobbered mid-copy. A flat word copy is
  ## byte-accurate whatever the field layout — a PER-FIELD copy would mis-load a field
  ## that is itself an aggregate (e.g. a 16-byte `seq`) as one scalar.
  let srcPtr = R16
  g.bindTemp(srcPtr, AsmSlot(cls: AUInt, size: 8, align: 8))
  g.ab.tree LeaA64: (g.emReg srcPtr; g.ab.sym srcVar)
  g.copyAggr(dstPtr, srcPtr, sizeBytes, tmp)
  g.unbindTemp(srcPtr)

proc copyStructThroughPtr2(g: var CodeGen; srcVar, typeName: string; ptrReg: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at (the >16B aggregate hidden-result-
  ## pointer return). This runs at the `ret` and crosses NO call, so both scratch
  ## registers it needs — the source address and the word-transfer temp — come from the
  ## two staging bridges, never an allocator-reserved callee-saved survivor (mirrors the
  ## x64 `pickStagingSealed` pair). Leas the source's address into one bridge and funnels
  ## through the one `copyAggr` with the other bridge as the word temp.
  let sp = g.takeBridge()
  g.ab.tree LeaA64: (g.emReg sp; g.ab.sym srcVar)        # sp = &srcVar
  let tmp = g.takeBridge(avoid = sp)
  g.copyAggr(ptrReg, sp, aggrByteSize(g.prog, typeName), tmp)
  g.dropBridge tmp
  g.dropBridge sp

proc regsToStructThroughPtr(g: var CodeGen; ptrReg: Reg; typeName: string; firstArg: int) =
  ## `[ptrReg] ← x{firstArg+i}` — marshal a ≤16B aggregate held in the return registers
  ## into the memory `ptrReg` points at: a FULL eightbyte as a raw `(u 64)` word
  ## (handles packed fields), a trailing PARTIAL eightbyte through `storeAggrTail`. The
  ## through-pointer twin of `regsToStruct` — stores an aggregate call result into a
  ## global.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emWordThroughPtr(ptrReg, i); g.emReg IntArgRegs[firstArg + i])
    else:
      g.storeAggrTail(ptrReg, IntArgRegs[firstArg + i], byteSize, i * 8)

proc marshalAggrFromAddr(g: var CodeGen; addrReg: Reg; typeName: string; firstArg: int) =
  ## `x{firstArg+i} ← [addrReg]` — load a ≤16B aggregate at `[addrReg]` into the by-value
  ## ABI argument registers (reverse of `regsToStructThroughPtr`); lets an aggregate CALL
  ## ARGUMENT marshal straight from its address (`aggrAddrInto`) with no copy temp.
  let byteSize = aggrByteSize(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovA64: (g.emReg IntArgRegs[firstArg + i]; g.emWordThroughPtr(addrReg, i))
    else:
      g.loadAggrTail(IntArgRegs[firstArg + i], addrReg, byteSize, i * 8)

proc aggrArgAddr(g: var CodeGen; a: Cursor; dst: Reg) =
  ## Put the ADDRESS of an aggregate call-argument SOURCE into `dst` (a usable scratch
  ## register). Mirrors the register-marshalling source dispatch — a symbol local/global,
  ## a by-ref param pointer already in a register, an lvalue, or an `oconstr`/`aconstr`
  ## built into a temp — but yields an address, which the stack-passed path reads through.
  if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
    g.aggrAddrInto(a, dst, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
  elif a.kind == Symbol:
    case g.lookupSym(symName(a)).cat
    of scGlobal: g.emGlobalAddr(dst, symName(a))
    of scTvar: g.genTlvAddr(symName(a), dst)
    else:
      let home = symName(a)
      let hl = g.ra.locationOfSym(home)
      if hl.kind == InReg: g.movReg(dst, hl.r)          # by-ref param: pointer already in a reg
      else: g.ab.tree LeaA64: (g.emReg dst; g.ab.sym home)
  else:                                                 # oconstr/aconstr → build into a temp, then &temp
    let pos = g.posOf(a)
    let home = synth("aggtmp") & $pos & ".0"
    g.emTypedStackVar(home, g.getType(a))
    g.varType[home] = symName(g.getType(a))
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
  let tcur = g.getType(a)
  if tcur.kind != Symbol:
    raiseAssert "arkham a64: aggregate stack-arg of non-nominal type"
  let tn = symName(tcur)
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
    for i in 0 ..< aggrWordCount(g.prog, tn):
      if sz - i * 8 >= 8:
        g.ab.tree MovA64: (g.emReg w; g.emWordThroughPtr(src, i))
      else:
        if i == 0 and sz notin {1, 2, 4}:
          raiseAssert "arkham a64: " & $sz & "-byte aggregate stack-arg ABI unsupported"
        g.loadAggrTail(w, src, sz, i * 8)
      g.ab.tree MovA64:
        g.ab.tree MemX:
          g.emReg SP
          g.ab.tree ArgX: (g.ab.sym paramNm; g.ab.intLit i.int64)
        g.emReg w
    g.dropBridge w
  g.dropBridge src

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
  case dst.base.kind
  of FbReg:  g.emPtrFieldMem(dst.base.reg, dst.aggrType, dst.field)
  of FbSlot: g.emAggrFieldMem(dst.base.sym, dst.field)
  of FbLval: g.emLvalFieldMem(dst.base.lval, dst.field)
  of FbGlob, FbTvar:
    raiseAssert "arkham a64n: FbGlob/FbTvar field base must be pre-materialized"

proc emFieldDot(g: var CodeGen; dst: Location) =
  ## The bare `(dot <base> field)` ADDRESS tree (no `(mem …)` wrapper) — what a64's
  ## `lea` takes (unlike x86, which leas a memory operand).
  case dst.base.kind
  of FbReg:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym dst.aggrType
        g.emReg dst.base.reg
      g.ab.sym dst.field
  of FbSlot:
    g.emAggrDot(dst.base.sym, dst.field)
  of FbLval:
    g.ab.tree DotX:
      g.emLvalAddr2(dst.base.lval)
      g.ab.sym dst.field
  of FbGlob, FbTvar:
    raiseAssert "arkham a64n: FbGlob/FbTvar field base must be pre-materialized"

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
  let tmpName = synth("nctmp") & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, slotOf(g.prog, fty)))   # build (no bridge held)
  let fptr = g.takeBridge()
  g.emFieldAddr(dst, fptr)
  let tmp = g.takeBridge(avoid = fptr)
  g.flatCopyToPtr2(tmpName, aggrByteSize(g.prog, ntn), fptr, tmp)
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
    var v: Location
    if g.isFloatExpr(valC):
      v = dontCare
      g.emitFValue2(valC, v)
    else:
      v = needsReg(ScalarSlot)                          # single-use (allocSingleUse's shape)
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
          let tmpName = synth("nctmp") & $pos & ".0"
          g.emTypedStackVar(tmpName, elemTyRaw)
          g.varType[tmpName] = ntn
          g.genStore2(valC, namedStackLoc(tmpName, elemSlot))  # build (no bridge held)
          let eptr = g.takeBridge()
          g.ab.tree LeaA64: (g.emReg eptr; addrOp(i))   # &element[i]
          let tmp = g.takeBridge(avoid = eptr)
          g.flatCopyToPtr2(tmpName, aggrByteSize(g.prog, ntn), eptr, tmp)
          g.dropBridge tmp
          g.dropBridge eptr
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
    let dtmp = synth("botmp") & $pos & ".0"
    g.emTypedStackVar(dtmp, derivedTy)
    g.varType[dtmp] = symName(derivedTy)
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)))  # build derived
    # The base view is the derived value's PREFIX (base fields first, offset 0), so a
    # flat copy of `sizeof(BaseType)` bytes is exact — and unlike a per-field copy it
    # stays correct when a base field is itself an aggregate.
    let dptr = g.takeBridge()
    g.ab.tree LeaA64: (g.emReg dptr; g.ab.sym dst.name)
    let tmp = g.takeBridge(avoid = dptr)
    g.flatCopyToPtr2(dtmp, aggrByteSize(g.prog, symName(baseTy)), dptr, tmp)
    g.dropBridge tmp
    g.dropBridge dptr
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
  of Tvar: g.genTlvAddr(loc.name, dest)
  of Mem: g.aggrAddrInto(loc.cur, dest, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)
  else: raiseAssert "arkham a64n: aggrAddrLoc of " & $loc.kind

proc isAggrCopySrc(c: Cursor): bool =
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo(g: var CodeGen; dst: Location): (bool, int) =
  case dst.kind
  of NamedStack, Glob, Tvar: (dst.typ.kind == AMem, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc genAggrCopyStore(g: var CodeGen; rhs: Cursor; dst: Location; size: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce BOTH sides to an address in a register
  ## (`aggrAddrLoc`/`aggrAddrInto`), then `copyAggr`. The allocator reserved
  ## `[dstAddr, srcAddr]`; the per-field transfer register is a staging bridge (x14/x15),
  ## taken here — both addresses are already in `a[0]`/`a[1]`, so a bridge is free — sparing
  ## a pool GPR so the copy fits under high register pressure.
  # Emit-time picks: pool temp, else callee-saved survivor, else a staging
  # bridge — the copy crosses no call, so even a bridge-backed address is safe
  # and the acquisition is total. (When both bridges serve as addresses, the
  # transfer register falls back to the produce bridge x16 below.)
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
  g.aggrAddrInto(rhs, a1, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = false)  # &rhs
  if rhs.kind == TagLit: g.freeLvalTemps2(rhs)
  var tmp: Reg
  if b0 != NoReg and b1 != NoReg:
    tmp = R16                        # total exhaustion: the produce bridge serves
    g.bindTemp(tmp, AsmSlot(cls: AUInt, size: 8, align: 8))
  else:
    tmp = g.takeBridge(AsmSlot(cls: AUInt, size: 8, align: 8))
  g.copyAggr(a0, a1, size, tmp)
  g.dropBridge tmp                   # unbind (uniform for a bridge or x16)
  g.unbindTemp(a1); g.unbindTemp(a0)
  g.freeVal(h1); g.freeVal(h0)

proc genStore2(g: var CodeGen; rhs: Cursor; dst: Location) =
  ## The general destination-passing store: emit `rhs` so its value lands at `dst`. An
  ## aggregate COPY goes through the ONE `genAggrCopyStore`; constructors/calls/baseobj
  ## PRODUCE per-form; a scalar/float destination through `storeScalar2`.
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
  if dst.kind == NamedStack and dst.typ.kind == AMem:        # aggregate destination
    let dstVar = dst.name
    let tn = g.varType[dstVar]
    if rhs.kind == TagLit and rhs.exprKind == OconstrC: g.genConstr2(rhs, dstVar)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC: g.genAconstr2(rhs, dstVar)
    elif rhs.kind == TagLit and rhs.exprKind == CallC:
      if aggrByteSize(g.prog, tn) > 16:
        g.ab.tree LeaA64: (g.emReg IndirectResultReg; g.ab.sym dstVar)
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
      g.emAdr(IndirectResultReg, dst.name)              # >16B: &g is the hidden result ptr
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
        g.regsToStructThroughPtr(addrT, symName(g.getType(rhs)), 0)
      else: raiseAssert "arkham a64n: aggregate global store rhs " & $rhs.exprKind
      g.unbindTemp(addrT)
      g.freeVal(heldLoc)
  elif dst.kind in {Glob, Tvar}:                             # scalar/float/pointer global/tvar
    if dst.typ.kind == AFloat:
      var fv = dontCare
      g.emitFValue2(rhs, fv)
      let bits = if dst.typ.size == 4: 32 else: 64
      var fr = NoFReg
      var fb = false
      if fv.kind == InFReg: fr = fv.f
      else:                                              # eftmp spill (pool-dry) → bridge
        fr = g.takeFBridge(bits); g.placeF2(fv, fr, bits); fb = true
      let b = g.takeBridge()
      if dst.kind == Glob or g.a64Linux: g.emAdr(b, dst.name) else: g.genTlvAddr(dst.name, b)
      g.emFStore(fr, b, bits)
      g.dropBridge b
      if fb: g.dropFBridge()
      elif fv.kind == InFReg and fv.isTemp: g.unbindFTmp(fv.f)
    else:
      var v = needsReg(ScalarSlot)                       # single-use rhs (allocSingleUse's shape)
      g.emitValue2(rhs, v)
      var vb = NoReg
      var vr: Reg
      if v.kind == InReg: vr = v.r
      else: (vb = g.takeBridge(); g.place2(v, vb); vr = vb)
      g.storeReg2(dst, vr)
      if vb != NoReg: g.dropBridge vb
      elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
  elif dst.kind == Mem:                                      # store through complex lvalue
    let lhs = dst.cur
    # A global aggregate base in the lvalue needs an address scratch, held across the
    # rhs; bind it so prematLval2's `lea scratch, &g` emits a checked name. Only
    # a CONSTRUCTOR build holds `&g` across the rhs (a scalar store emits the rhs
    # FIRST, so its global base is a plain walk pick — no survivor needed).
    var globScratch = NoReg
    var globHeld = dontCare
    if (rhs.kind == TagLit and rhs.exprKind in {OconstrC, AconstrC}) and
       g.lvalueGlobalBaseE(lhs):
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
        v = dontCare
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
      g.freeLvalTemps2(lhs)
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

proc emitLeafImm(g: var CodeGen; dest: var Location; natural: Location) =
  ## FUSED literal leaf: resolve the constraint against the immediate; a
  ## register destination gets it materialized (binding a fresh temp first).
  g.resolveDestE(dest, natural)
  if dest.kind == InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.placeImm(dest.r, natural)
  elif dest.kind == NamedStack and dest.spillTemp:
    # `needsReg` under a dry pool minted an etmp slot: the literal MUST be
    # stored into it (silently skipping it hands the consumer's reload
    # garbage) — through the produce bridge, like produceIntoMem2.
    let s = R16
    g.bindTemp(s, dest.typ)
    g.placeImm(s, natural)
    g.storeReg2(dest, s)
    g.unbindTemp(s)

proc produceIntoMem2(g: var CodeGen; c: Cursor; dst: Location) =
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
  ## not put it here in the first place — see `emitBin2`'s swap suppression. It
  ## cannot be repaired from this side: handing the nested level a real bridge
  ## instead just moves the shortage (`takeBridge` then asserts with both x14/x15
  ## already serving the address the recursion is materializing).
  let s = R16                                             # the produce bridge (IP0)
  var d = regLoc(s, dst.typ, isTemp = true)
  g.emitValue2(c, d)
  if not g.rb.isBoundTemp(s): g.bindTemp(s, dst.typ)      # a leaf produced raw: bind for the store
  g.storeReg2(dst, s)
  g.unbindTemp(s)

proc produceIntoFMem2(g: var CodeGen; c: Cursor; dst: Location) =
  ## The SIMD twin: produce into the float bridge (v31), then store.
  let bits = dst.typ.size * 8
  let fs = FloatBridgeReg
  var d = fregLoc(fs, dst.typ, isTemp = true)
  g.emitFValue2(c, d)
  if not g.rb.isBoundFTmp(fs): g.bindFTmp(fs, bits)
  g.emFloatScalarStore(dst.name, fs, bits)
  g.unbindFTmp(fs)

proc resolveLvalVal(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED: decide (only) where an lvalue-embedded VALUE — a deref'd pointer, a
  ## computed index — will live; `prematLval2` materializes it later. A symbol
  ## resolves to its home, a literal to an immediate, a computed subtree to a
  ## reserved temp (its computation emits at premat time, dest-threaded).
  case c.kind
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    if home.kind == NoLoc: g.forceRegDestE(dest)     # a global/tvar value read
    else: g.resolveDestE(dest, home)
  of IntLit: g.resolveDestE(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.resolveDestE(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.resolveDestE(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  else: g.forceRegDestE(dest)                        # computed: reserve the result

proc reserveStrideScratch(g: var CodeGen; atPos: int) =
  ## Reserve the `(at/pat base idx scratch)` stride scratch for the access at `atPos`.
  ##
  ## The pools first, as always. But this scratch lives for exactly one `(mem …)` and
  ## competes with every register-homed local for the pool, so a proc with enough live
  ## locals used to run out and there was nowhere to go: the consumer needs a REGISTER,
  ## so the `heldN.0` spill fallback `takeHeld` offers cannot serve it. Fall back to a
  ## staging bridge instead — never allocator-assigned, so it neither starves nor can
  ## alias the base/index nifasm requires it to differ from. The bridge is not free at
  ## walk time (nothing is emitted yet), so record the intent and let `prematLval2`
  ## take it at emission, where a bridge's lifetime belongs.
  var t = g.takeTmp(ScalarSlot)
  if t.kind != InReg:
    let r = g.pickHeldReg()
    if r == NoReg:
      g.lvalStrideOnBridge.incl atPos
      g.ra.aux[atPos] = ExprAux(scratch: @[NoReg])   # filled in by `prematLval2`
      return
    g.pickedRegs.incl r
    t = regLoc(r, ScalarSlot, isTemp = true)
  g.ra.aux[atPos] = ExprAux(scratch: @[t.r])

proc emitLvalWalk(g: var CodeGen; n: var Cursor; globBase: Location; isStore: bool;
                  heldBase = false; asBase = false) =
  ## FUSED port of the allocator's `allocLvalue2` (a64 flavour): decide the
  ## lvalue's embedded values' locations into the `ra.locs` memo, reserving the
  ## a64 stride scratch (the `(at base idx scratch)` 3-operand form) into
  ## `ra.aux` where `atNeedsScratch`/nested-base rules demand one. Pure
  ## pick-and-record. `heldBase`: an enclosing at/pat index CALLS — base
  ## scratches must be callee-saved survivors (075b051). `asBase`: this node is
  ## the BASE of an enclosing indexed access (one index register per operand).
  case n.kind
  of Symbol:
    let nm = symName(n)
    if g.ra.locationOfSym(nm).kind == NoLoc:         # a module-level global aggregate base
      let pos = g.posOf(n)
      if globBase.kind == InReg:
        # The caller donated its result register; it owns (and frees) that pick —
        # record it non-temp so freeLvalTemps2 won't unbind the live result.
        g.ra.locs[pos] = regLoc(globBase.r, globBase.typ)
      else:
        # a64 always materializes &global into an allocator-visible register
        # (no x64-style staging marker): a survivor under a calling index or
        # for a store held across the rhs, else an ordinary temp.
        if isStore or heldBase:
          g.ra.locs[pos] = g.takeHeld("a global base address")
        else:
          var d = g.takeTmp(ScalarSlot)
          if d.kind != InReg:
            d = g.takeHeld("a global base address")  # pool dry: survivor beats a bridge
          g.ra.locs[pos] = d
    inc n
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        g.emitLvalWalk(n, globBase, isStore, heldBase, asBase)  # offset-transparent base
        while n.hasMore: skip n
    of DerefC:
      n.into:
        let pPos = g.posOf(n)
        var d = if heldBase: g.takeHeld("a deref base held across an index call")
                else: needsReg(ScalarSlot)
        g.resolveLvalVal(n, d)
        g.ra.locs[pPos] = d
        skip n
        while n.hasMore: skip n
    of AtC:
      let atPos = g.posOf(n)
      let needsScratch = g.atNeedsScratch(n) or (asBase and g.atIndexIsReg(n))
      n.into:
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCallE(idxPeek)
        g.emitLvalWalk(n, globBase, isStore, held, asBase = true)  # the indexed base
        if n.kind in {IntLit, UIntLit}: skip n
        else:
          let iPos = g.posOf(n)
          var idx = needsReg(ScalarSlot)
          g.resolveLvalVal(n, idx)
          g.ra.locs[iPos] = idx
          skip n
        while n.hasMore: skip n
      if needsScratch:
        g.reserveStrideScratch(atPos)
    of PatC:
      let patPos = g.posOf(n)
      let needsScratch = g.atNeedsScratch(n) or (asBase and g.atIndexIsReg(n))
      n.into:
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCallE(idxPeek)
        let pPos = g.posOf(n)
        var d = if held: g.takeHeld("a pat base held across an index call")
                else: needsReg(ScalarSlot)
        g.resolveLvalVal(n, d)                       # the pointer (a clean value base)
        g.ra.locs[pPos] = d
        skip n
        if n.kind in {IntLit, UIntLit}: skip n
        else:
          let iPos = g.posOf(n)
          var idx = needsReg(ScalarSlot)
          g.resolveLvalVal(n, idx)
          g.ra.locs[iPos] = idx
          skip n
        while n.hasMore: skip n
      if needsScratch:
        g.reserveStrideScratch(patPos)
    of BaseobjC:
      n.into:
        skip n                                       # base type
        skip n                                       # depth
        g.emitLvalWalk(n, globBase, isStore, heldBase, asBase)
        while n.hasMore: skip n
    of AconstrC, OconstrC:
      # A constructor base: `prematLval2`'s consumer builds it into its aggtmp
      # via the (fused) genStore2 — nothing to decide here.
      skip n
    else:
      raiseAssert "arkham a64n: computed lvalue base not supported: " & $n.exprKind
  else:
    inc n

proc emitLvalue2(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false) =
  var n = c
  g.emitLvalWalk(n, globBase, isStore)

proc freeLvalTemps2(g: var CodeGen; c: Cursor) =
  ## FUSED port of `releaseLvalTemps`: release the reserved picks of an
  ## lvalue's address computation — computed index/pointer temps, the a64
  ## stride scratch, and a global-base temp. (`unbindLvalTemps2` already
  ## unbinds; this clears the pick flags and frees the pool.)
  case c.kind
  of Symbol:
    if g.ra.locationOfSym(symName(c)).kind == NoLoc:
      g.freeVal(g.ra.locs[g.posOf(c)])               # the global base temp/survivor
  of TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.freeLvalTemps2(cc)
        while cc.hasMore: skip cc
    of DerefC:
      var cc = c
      cc.into:
        g.freeVal(g.ra.locs[g.posOf(cc)])
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      cc.into:
        g.freeLvalTemps2(cc)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.freeVal(g.ra.locs[g.posOf(cc)])
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(atPos) and g.ra.aux[atPos].scratch.len > 0:
        g.releaseStrideScratch(atPos)
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      cc.into:
        g.freeVal(g.ra.locs[g.posOf(cc)])
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.freeVal(g.ra.locs[g.posOf(cc)])
        while cc.hasMore: skip cc
      if g.ra.aux.hasKey(patPos) and g.ra.aux[patPos].scratch.len > 0:
        g.releaseStrideScratch(patPos)
    of BaseobjC:
      var cc = c
      cc.into:
        skip cc; skip cc
        g.freeLvalTemps2(cc)
        while cc.hasMore: skip cc
    else: discard
  else: discard

proc emitValue2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED decide-and-emit (a64): resolve `dest` against `c`, emit, return the
  ## resolved location. Callers route float-typed values to `emitFValue2`.
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest)
    return
  let pos = g.posOf(c)                            # for the keepovf no-fold guard
  case c.kind
  of IntLit: g.emitLeafImm(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.emitLeafImm(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.emitLeafImm(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  of Symbol:
    let home = g.ra.locationOfSym(symName(c))
    if home.kind != NoLoc:
      g.resolveDestE(dest, home)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      if dest.kind == InReg and not (home.kind == InReg and home.r == dest.r):
        if dest.isTemp and not g.rb.isBoundTemp(dest.r):
          g.bindTemp(dest.r, dest.typ)
        g.place2(home, dest.r)
    else:
      g.forceRegDestE(dest)
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
    g.forceRegDestE(dest)
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
      g.forceRegDestE(dest)
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
        g.ab.tree NegA64: g.emReg dest.r
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
      g.resolveDestE(dest, immLoc(0, g.exprSlot(c)))
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
proc retypeBinDest(g: var CodeGen; rD: Reg; resTypeC: Cursor;
                   inheritedOperand: bool) =
  ## Give `rD`'s nifasm binding the type of the arithmetic result about to land in
  ## it. The register is a named local's home (or a bound temp) whose declared type
  ## may be a pointer while the value being computed into it is an integer — the
  ## `(var :c.0 (ptr T) (cast (ptr T) (bitand (i 64) …)))` shape, where an enclosing
  ## cast puts the pointer type back on. The `rebind` is zero machine code: the
  ## register never moves, only its declared type does.
  ##
  ## A POINTER result type is not handled here — `checkArithResultType` has already
  ## rejected the node. Retyping the binding to `(i 64)` and back around the
  ## instruction would make an ill-typed `(add (ptr T) …)` assemble by hiding it from
  ## nifasm's `checkIntegerArithmetic`, under a raw-byte reading of `+` that the C
  ## backend does not share.
  if not isPtrType(resolveType(g.prog, resTypeC)):
    let nm = g.rb.boundName(rD)
    if g.rb.isBoundTemp(rD):
      if inheritedOperand:                               # inherited an operand's binding
        var rtc = resTypeC
        g.bindTemp(rD, slotOf(g.prog, rtc))
    elif nm.len > 0:
      g.rebindLocalAs(nm, rD, resTypeC)

proc emitBin2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 binary-arith: the shared allocBin policy decided inline
  ## (Sethi–Ullman swap, dest passthrough, rhs recycling, aliasRhs), emitted
  ## with the a64 non-destructive 3-op / W-form machinery.
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
  let lhsMem = isMemLeaf(lhsC)
  let swap = ek notin {ShlC, ShrC} and (commutativeExpr(ek) or ek == SubC) and
             (g.isFoldableLeafE(lhsC) or lhsMem) and
             not (g.isFoldableLeafE(rhsC) or isMemLeaf(rhsC)) and
             not (dest.kind == InReg and g.symInRegE(lhsC, dest.r))
  if swap:
    var acc = dest
    if acc.kind != InReg: acc = g.takeTmp(ScalarSlot)
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
      g.ab.tree NegA64: g.emReg rD                       # rD := -rhs
    g.foldRhs2(foldOp, rD, lLoc, lhsC)                   # bridges serve Imm/slot/Mem lhs
    if lhsMem: g.freeLvalTemps2(lhsC)
    g.normalizeBinWidth(resTypeC, rD, op)
    dest = acc
    return
  var lDest = needsReg(ScalarSlot)
  if dest.kind == InReg and ek notin {ShlC, ShrC} and
     not g.isFoldableLeafE(lhsC) and
     (g.isFoldableLeafE(rhsC) or isMemLeaf(rhsC)) and
     not g.exprReadsRegE(lhsC, dest.r) and not g.exprReadsRegE(rhsC, dest.r):
    lDest = dest                                         # compute lhs straight into dest
  g.emitValue2(lhsC, lDest)
  # The lhs partial is LIVE in `lDest` across the rhs evaluation, which recurses
  # into arbitrary emission — see the x86-64 twin for the failure this prevents.
  # A bound temp is already excluded from every pick; a fixed destination carries
  # no binding, so say what it is holding.
  let lSeal = lDest.kind == InReg and not g.ra.isSealed(lDest.r) and
              not g.rb.isBoundTemp(lDest.r)
  if lSeal: g.ra.seal {lDest.r}
  var rDest = dontCare
  if ek == DivC: rDest = needsReg(ScalarSlot)            # sdiv/udiv need a register rhs
  g.emitValue2(rhsC, rDest)
  if lSeal: g.ra.unseal {lDest.r}                        # the partial is consumed below
  var res = dest
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: res = lDest # in-place on the dead lhs temp
    elif rDest.kind == InReg and rDest.isTemp and lDest.kind == InReg and
         ek notin {ShlC, ShrC, DivC}:
      res = rDest                                        # recycle the dead rhs temp
    else: res = g.takeTmp(ScalarSlot)
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
        g.ab.tree NegA64: g.emReg rD                     # dest := lhs - rhs
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
  var rt, divC, dvsC: Cursor
  block:
    var cc = c
    cc.into:
      rt = cc; skip cc
      divC = cc; skip cc
      dvsC = cc; skip cc
      while cc.hasMore: skip cc
  let signed = isSignedType(rt)
  var lD = needsReg(ScalarSlot)
  g.emitValue2(divC, lD)
  var rD0 = needsReg(ScalarSlot)
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
    else: res = g.takeTmp(ScalarSlot)
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
proc foldableFloatLeafE(g: var CodeGen; c: Cursor): bool =
  c.kind == Symbol and g.ra.locationOfSym(symName(c)).kind in {InFReg, NamedStack}

proc emitFBinE(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 float binary-arith (allocFBin's policy inline).
  let op = fbinA64Op(c.exprKind)
  let ek = c.exprKind
  var lhsC, rhsC: Cursor
  var fslot = AsmSlot(cls: AFloat, size: 8, align: 8)
  block:
    var cc = c
    cc.into:
      fslot = slotOf(g.prog, cc); skip cc              # result float type
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
  let bits = if res.typ.size == 4: 32 else: 64
  var lD = res
  g.emitFValue2(lhsC, lD)                              # a → the result register
  if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f, bits)
  if rhsC.kind == Symbol and g.ra.locationOfSym(symName(rhsC)).kind == InFReg:
    let rHome = g.ra.locationOfSym(symName(rhsC))
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

proc emitFValue2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 SIMD value: resolve `dest` (a v-register / eftmp slot) and
  ## materialize the float value there.
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
    if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
    let gpr = g.takeBridge()
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest.f, gpr, bits)
    g.dropBridge gpr
  of Symbol:
    var home = g.ra.locationOfSym(symName(c))
    if home.kind == NoLoc:                             # a module-level float global / tvar
      var cc = c
      home = g.asLoc(cc)
    case home.kind
    of InFReg:
      if dest.kind != InFReg:
        dest = home                                    # use the home in place
      elif home.f != dest.f:
        let bits = if dest.typ.size == 4: 32 else: 64
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, bits)
        g.fmovF(dest.f, home.f, bits)
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
proc mirrorBranch(t: A64Inst): A64Inst =
  ## The condition that holds for `cmp b, a` given `t` holds for `cmp a, b`.
  ## Equality is symmetric; the orderings change side.
  case t
  of BeqA64: BeqA64
  of BneA64: BneA64
  of BltA64: BgtA64
  of BleA64: BgeA64
  of BgtA64: BltA64
  of BgeA64: BleA64
  of BloA64: BhiA64
  of BlsA64: BhsA64
  of BhiA64: BloA64
  of BhsA64: BlsA64
  else: raiseAssert "arkham a64n: no mirror for " & $t

proc isCmpImmLeaf(c: Cursor): bool =
  ## A bare integer literal, `(suf …)`/`(par …)` wrappers included: what `cmp`
  ## takes as an immediate — and, on the left, what costs a materialising `mov`.
  var cur = c
  if cur.kind == TagLit and cur.exprKind in {SufC, ParC}: inc cur
  result = cur.kind in {IntLit, UIntLit, CharLit}

proc emitScalarCmpE(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool): A64Inst =
  ## FUSED integer `cmp`: operands resolve dontCare (a home / immediate stays
  ## put; a computed subtree takes a temp) and the bridges serve everything
  ## else — 075b051's stackHomeSlot / placeImmTyped bridge typing preserved.
  var aC = aC0
  var bC = bC0
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
  if isMemLeaf(aC):
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
  if isMemLeaf(bC):
    g.emitLvalue2(bC)
    bD = memLoc(bC, ScalarSlot)
    bMem = true
  else:
    g.emitValue2(bC, bD)
  if bD.kind == Imm and bD.ival >= 0 and bD.ival <= 0xFFFF:
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

proc emitCondE(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## FUSED branch test — the a64 twin of x64's emitCondE.
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
    of NotC: g.emitCondE(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCondE(aC, lSkip, false)
        g.emitCondE(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCondE(aC, toLabel, false)
        g.emitCondE(bC, toLabel, false)
    else:
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
      let fbits = g.floatBits(aC)
      let tag =
        case ek
        of EqC:  (if whenTrue: BeqA64 else: BneA64)
        of NeqC: (if whenTrue: BneA64 else: BeqA64)
        of LtC:  (if whenTrue: BloA64 else: BhsA64)
        of LeC:  (if whenTrue: BlsA64 else: BhiA64)
        else: raiseAssert "arkham a64n: float cond " & $ek
      var fa = dontCare
      g.emitFValue2(aC, fa)
      var fb = dontCare
      g.emitFValue2(bC, fb)
      assert fa.kind == InFReg and fb.kind == InFReg, "arkham a64n: float cmp operands"
      g.ab.tree FcmpA64: g.emFReg(fa.f, fbits); g.emFReg(fb.f, fbits)
      g.emBr(tag, toLabel)
      g.freeVal(fb)
      g.freeVal(fa)
      return
    let tag = g.emitScalarCmpE(aC, bC, ek, whenTrue)
    g.emBr(tag, toLabel)
    return
  var v = needsReg(ScalarSlot)
  g.emitValue2(c, v)
  if v.kind == InReg:
    g.ab.tree CmpA64: (g.emReg v.r; g.ab.intLit 0)
    g.emBr(if whenTrue: BneA64 else: BeqA64, toLabel)
    g.freeVal(v)
  else:                                            # pool-dry etmp bool: bridge reload
    let b = g.takeBridge(v.typ)
    g.place2(v, b)
    g.ab.tree CmpA64: (g.emReg b; g.ab.intLit 0)
    g.emBr(if whenTrue: BneA64 else: BeqA64, toLabel)
    g.dropBridge b

proc emitCondValue2(g: var CodeGen; c: Cursor; dest: var Location) =
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
  g.emitCondE(c, lEnd, whenTrue = true)
  g.movImm(res.r, 0)
  g.emLab(lEnd)
  dest = res
proc emitMemLoad2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED addressing expr in VALUE position → load `[addr]` into a register.
  g.forceRegDestE(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.ra.isSealed(res.r)
  if sealedHere: g.ra.seal {res.r}
  g.emitLvalue2(c, globBase = res)              # picks; a global base reuses the result reg
  if sealedHere: g.ra.unseal {res.r}
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    # an array / flexarray lvalue DECAYS to its address
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, ScalarSlot)
    g.prematLval2(c)
    g.ab.tree LeaA64: (g.emReg res.r; g.emLvalAddr2(c))
    g.unbindLvalTemps2(c)
  else:
    var bindSlot = res.typ
    if isPtrType(cty): bindSlot = g.exprSlot(c)
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, bindSlot)
    g.prematLval2(c)
    g.ab.tree MovA64:
      g.emReg res.r
      g.ab.tree MemX: g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)
  g.freeLvalTemps2(c)
  dest = res

proc emitAddr2(g: var CodeGen; c: Cursor; dest: var Location) =
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
        let home = g.ra.locationOfSym(symName(p))
        if home.kind == InReg:
          dest = home                           # the address IS p's register
          return
  g.forceRegDestE(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  g.emitLvalue2(lv, globBase = res)             # a global base reuses the lea dest
  g.aggrAddrInto(lv, res.r, g.exprSlot(c), doBind = res.isTemp)
  g.freeLvalTemps2(lv)
  dest = res

proc emitCast2(g: var CodeGen; c: Cursor; dest: var Location) =
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
  if g.isFloatExpr(c):                          # → float result
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ
                        else: AsmSlot(cls: AFloat, size: 8, align: 8))
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
    g.forceRegDestE(dest)
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
      let sh = g.ra.locationOfSym(symName(inner))
      var tgc = targetCur
      if sh.kind in {InReg, NamedStack} and slotOf(g.prog, tgc).size < sh.typ.size:
        g.forceRegDestE(dest)
      elif sh.kind == InReg and dest.kind in {Undef, NeedsReg, RegOrImm} and
           (isPtrType(tc) or (not cursorIsNil(sh.typ.typ) and
                              isPtrType(resolveType(g.prog, sh.typ.typ)))):
        # A pointer-ness change over a register-homed local, with no destination
        # of our own: without a temp the value would be threaded up in the
        # SYMBOL's home and the re-representation below would `rebindLocalAs`
        # that home — retyping the local itself for the rest of its scope. A
        # later use at its declared type then fails the binding checker. The
        # x64 twin carries the measured repro.
        g.forceRegDestE(dest)
  if dest.kind in {NamedStack, Mem} and not (dest.kind == NamedStack and dest.spillTemp):
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
  if dest.kind == Imm: return                   # a folded constant reinterprets freely
  if dest.kind == NamedStack and dest.spillTemp: return
  assert dest.kind == InReg, "arkham a64n: cast result " & $dest.kind
  let res2 = dest
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  let kindChange = ptrTarget or srcPtr
  if kindChange:
    if res2.isTemp:
      g.bindTemp(res2.r, (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot))
    else:
      let nm = g.rb.boundName(res2.r)
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
  # The register now holds the TARGET's value, so put the target type back on the
  # name the pre-retype above widened. `kindChange` already did it.
  if preRetyped.len > 0 and not kindChange:
    g.rebindLocalAs(preRetyped, res2.r, targetCur)
proc emitCall2(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false) =
  ## FUSED a64 call: allocCall's placements decided inline. No parking on
  ## AArch64 (no ISA-pinned clobber registers); scalar args dest-thread
  ## straight into their ABI registers, aggregate sources reach their words
  ## via `aggrAddrInto`/`structToRegs`, the result settles from x0/v0.
  discard hiddenPtr                            # the x8 hidden pointer is set by the caller
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
    assert fnptrLoc.kind == InReg, "arkham a64n: indirect call target loc " & $fnptrLoc.kind
    fnptrReg = fnptrLoc.r
    if targetCur.kind == Symbol and g.rb.boundName(fnptrReg) == symName(targetCur):
      tgt = CallTarget(declarative: declarative, asmName: symName(targetCur), retType: retType)
    else:
      let nm = g.rb.freshTmpName("fntmp")
      g.ab.tree RebindA64:
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
    if tgt.memIntrin.len > 0:
      g.emitMemIntrin2(argCurs, tgt.memIntrin)   # (fused arg emission inside)
      if not (dest.kind == InReg and not dest.isTemp):
        dest = regLoc(IntRet, ScalarSlot, isTemp = true)
      elif dest.r != IntRet:
        g.movReg(dest.r, IntRet)
      return
    if tgt.bitBuiltin.len > 0:
      raiseAssert "arkham a64n: bit builtin not yet implemented: " & tgt.bitBuiltin
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: ScalarSlot
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let resultByRef = hasResult and resSlot.kind == AMem and resSlot.size > 16
  var heldArgs: seq[Location] = @[]

  proc settleCallResult(g: var CodeGen; dest: var Location) =
    if not hasResult or resultByRef: return
    if resultIsFloat:
      let rbits = if resSlot.size == 4: 32 else: 64
      if dest.kind != InFReg:
        dest = g.takeFTmp(resSlot)             # the float pool excludes v0
      if dest.kind == InFReg:
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f, rbits)
        if dest.f != FloatRet: g.fmovF(dest.f, FloatRet, rbits)
      else:
        g.emFloatScalarStore(dest.name, FloatRet, rbits)
    elif resSlot.kind == AMem:
      discard                                  # ≤16B aggregate result: caller reads x0:x1
    else:
      case dest.kind
      of Undef, NeedsReg, RegOrImm:
        dest = regLoc(IntRet, resSlot, isTemp = true)   # x0 itself is raw-usable
      of InReg:
        if dest.r != IntRet:
          if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, resSlot)
          g.movReg(dest.r, IntRet)
      of NamedStack, Mem:
        g.storeReg2(dest, IntRet)
      else: raiseAssert "arkham a64n: call result dest " & $dest.kind

  if tgt.declarative:
    var callArgSlots: seq[AsmSlot] = @[]
    for a in argCurs: callArgSlots.add g.exprSlot(a)
    let plan = planCall(g.md, callArgSlots, retByRef = false)
    g.ab.tree PrepareA64:
      g.ab.sym tgt.asmName
      var stackArgs: seq[int] = @[]
      for j in 0 ..< argCurs.len:
        let a = argCurs[j]
        let pl = plan.args[j]
        var tn = ""
        if pl.isAgg:
          let tcur = g.getType(a)
          if tcur.kind != Symbol:
            raiseAssert "arkham a64: aggregate call-arg of non-nominal type"
          tn = symName(tcur)
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
            g.aggrAddrInto(a, srcAddr, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = true)
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
            if pl.byRef:
              if isTvar: g.genTlvAddr(symName(a), g.md.gprAt(pl))
              elif isGlobal: g.emGlobalAddr(g.md.gprAt(pl), symName(a))
              elif g.ra.locationOfSym(home).kind == InReg:
                g.movReg(g.md.gprAt(pl), g.ra.locationOfSym(home).r)
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
        else:
          var aD = regLoc(g.md.gprAt(pl), ScalarSlot)
          g.emitValue2(a, aD)                  # → its ABI register directly
          # Release the temp binding so the arg register is referenced RAW where it
          # can be. Where it CANNOT — the allocator also homes plain locals in the
          # volatile arg registers, and nifasm insists a bound register be named —
          # the name carries arkham's generic `(i 64)`, which nifasm accepts into a
          # sub-width param as the ABI truncation it is (memfiles' `close`, where
          # `canRaise` lives in x0 and is dead across the `raiseOSError(cint)` it
          # stages).
          g.unbindTemp(aD.r)
          g.ab.tree MovA64:
            g.ab.tree ArgX: g.ab.sym paramName(j)
            g.emReg aD.r
      for j in stackArgs:
        let a = argCurs[j]
        if g.exprSlot(a).kind == AMem:
          g.marshalStackAggrArg(a, paramName(j))
        else:
          var aD = needsReg(ScalarSlot)
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
      if tgt.syscall:
        g.ab.tree SvcA64: g.ab.intLit 0
      else: g.ab.keyword CallA64
      if hasResult and not resultByRef and not resultIsFloat and resSlot.kind != AMem:
        g.ab.tree MovA64:
          g.emReg IntRet
          g.ab.tree ResX: g.ab.sym synth("ret.0")
    if fnTargetName.len > 0:
      g.ab.tree KillA64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    g.settleCallResult(dest)
  else:
    var intIdx = 0
    var fIdx = 0
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
          var fD = fregLoc(FloatArgRegs[fIdx], AsmSlot(cls: AFloat, size: 8, align: 8))
          g.emitFValue2(a, fD)                 # promoted to double by the front end
          varTail.add (NoReg, FloatArgRegs[fIdx], off)
          inc fIdx
        else:
          var aD = regLoc(IntArgRegs[intIdx], ScalarSlot)
          g.emitValue2(a, aD)
          varTail.add (IntArgRegs[intIdx], NoFReg, off)
          inc intIdx
      elif g.isFloatExpr(a):
        var fD = fregLoc(FloatArgRegs[fIdx], AsmSlot(cls: AFloat, size: 8, align: 8))
        g.emitFValue2(a, fD)
        inc fIdx
      elif g.exprSlot(a).kind == AMem:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham a64: aggregate call-arg of non-nominal type"
        let tn = symName(tcur)
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
          g.aggrAddrInto(a, srcAddr, AsmSlot(cls: AUInt, size: 8, align: 8), doBind = true)
          if sz > 16:
            g.movReg(IntArgRegs[intIdx], srcAddr); inc intIdx
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
          if sz > 16:
            if isTvar: g.genTlvAddr(symName(a), IntArgRegs[intIdx])
            elif isGlobal: g.emGlobalAddr(IntArgRegs[intIdx], symName(a))
            elif g.ra.locationOfSym(home).kind == InReg:
              g.movReg(IntArgRegs[intIdx], g.ra.locationOfSym(home).r)
            else: g.ab.tree LeaA64: (g.emReg IntArgRegs[intIdx]; g.ab.sym home)
            inc intIdx
          else:
            let nw = aggrWordCount(g.prog, tn)
            if isGlobal: g.globalToRegs(symName(a), tn, intIdx, isTvar)
            else: g.structToRegs(home, tn, intIdx)
            intIdx += nw
      else:
        var aD = regLoc(IntArgRegs[intIdx], ScalarSlot)
        g.emitValue2(a, aD)                    # → its ABI register directly
        inc intIdx
    # Drop the variadic tail into a freshly reserved outgoing area at [sp+0…]. The
    # frame nifasm sizes has no room for it (that reservation is driven by a callee's
    # DECLARED signature, and a Darwin extern declares none), so carve it here and
    # give it back straight after the call — 16-aligned, as the ABI requires SP to be.
    var varArea = 0
    if varTail.len > 0:
      varArea = (varTail.len * 8 + 15) and not 15
      g.ab.tree SubA64: (g.ab.reg SP; g.ab.intLit varArea)
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
      g.ab.keyword (if tgt.extern: ExtcallA64 else: CallA64)
    if varArea > 0:
      g.ab.tree AddA64: (g.ab.reg SP; g.ab.intLit varArea)
    if fnTargetName.len > 0:
      g.ab.tree KillA64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    g.settleCallResult(dest)

proc emitInstr2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED a64 `(instr SYM X*)`: operand placement inline (pool → survivor,
  ## never a bridge — the atomics own x14/x15/x16); resolved operand Locations
  ## go to the `ra.locs` memo so `emitAtomicInstr2` reads them unchanged.
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
              "are only legal inside an `{.assembler.}` proc, which the AArch64 " &
              "backend does not support yet", lengInfo(c)
  if tgA64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no AArch64 lowering — " &
              "guard the call with a `when`"
  # Resolve the result FIRST and seal it, so an operand pick cannot land on it.
  var res = Location(kind: Undef)
  if not row.isVoidResult:
    case dest.kind
    of NeedsReg, RegOrImm: dest = g.takeInstrReg(dest.typ, tgt.op.isAtomic)
    of Undef: dest = g.takeInstrReg(ScalarSlot, tgt.op.isAtomic)
    else: discard
    res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.ra.isSealed(res.r)
  if sealedHere: g.ra.seal {res.r}
  var ops: seq[Location] = @[]
  block:
    var i = 0
    for a in argCurs:
      if i >= row.evaluatedOperands: break     # trailing memory-order knobs
      # No immediate atomics on a64 (the LL/SC loops have no spare scratch to
      # materialize one — the allocator's atomicValueMayBeImm was x86-only).
      var d = g.takeInstrReg(g.exprSlot(a), tgt.op.isAtomic)
      g.emitValue2(a, d)
      g.ra.locs[cursorToPosition(g.buf[], a)] = d
      ops.add d
      inc i
  if sealedHere: g.ra.unseal {res.r}
  if tgt.op.isAtomic:
    g.emitAtomicInstr2(c, tgt.op, argCurs, res)
    for d in ops:
      if not (res.kind == InReg and d.kind == InReg and d.r == res.r): g.freeVal(d)
    return
  if res.kind != InReg:
    raiseAssert "arkham a64n: intrinsic result is not in a register"
  let a0 = g.ra.locs[cursorToPosition(g.buf[], argCurs[0])]
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
  else:
    raiseAssert "arkham a64n: no lowering for intrinsic `" & IntrinsicNames[tgt.op] & "`"
  for d in ops:
    if d.kind == InReg and d.r != res.r: g.freeVal(d)
  dest = res

# ── var declarations ─────────────────────────────────────────────────────────

proc genVarDecl2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    let declPos = g.posOf(cc)
    let nm = symName(cc); inc cc
    skip cc                                                  # pragmas
    let declaredCur = cc; skip cc                            # type (`.` when shoggoth omitted it)
    let typeCur = g.declType(declaredCur, cc)                # infer from the initializer
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
    if hasVal: g.genStore2(cc, loc)
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

# ── conditional-move (branchless select) ─────────────────────────────────────

proc cselTagFor(branchTag: A64Inst): A64Inst =
  ## The `csel<cc>` whose condition matches branch tag `branchTag` (which fires
  ## when the relation holds): `csel<cc> D, S1, S2` yields `D = cc ? S1 : S2`.
  case branchTag
  of BeqA64: CseleqA64
  of BneA64: CselneA64
  of BltA64: CselltA64
  of BleA64: CselleA64
  of BgtA64: CselgtA64
  of BgeA64: CselgeA64
  of BloA64: CselloA64
  of BlsA64: CsellsA64
  of BhiA64: CselhiA64
  of BhsA64: CselhsA64
  else: raiseAssert "arkham a64n: no csel for " & $branchTag

proc tryEmitCsel(g: var CodeGen; c: Cursor): bool =
  ## Lower a select diamond (see `matchSelectDiamond`) branchlessly to
  ## `cmp; csel<cc> DST, A, B` — no forward jumps, no label. Returns false for
  ## anything that does not fit; the caller then falls back to branch lowering.
  var sd: SelectDiamond
  if not g.matchSelectDiamond(c, sd): return false
  # ── emit: cmp (sets NZCV) → THEN→bridge → ELSE→DST → csel DST, bridge, DST ──
  # The cmp reads the condition operands at their ORIGINAL values (DST not yet
  # written). THEN is captured into a fresh bridge before ELSE overwrites DST, so
  # `if c: x = x …` style self-reads stay correct; both stores are mov/ldr-only, so
  # the flags survive to the csel.
  let ct = cselTagFor(g.emitScalarCmpE(sd.a, sd.b, sd.ek, whenTrue = true))
  let rT = g.takeBridge(g.selectStagingSlot(sd))
  g.genStore2(sd.thenRhs, regLoc(rT, sd.dst.typ))
  g.genStore2(sd.elseRhs, sd.dst)
  g.ab.tree ct: (g.emReg sd.dst.r; g.emReg rT; g.emReg sd.dst.r)
  g.dropBridge rT
  return true

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
  of CallS:
    var d = dontCare                   # a statement call: result unused
    g.emitCall2(c, d)
    g.freeVal(d)
  of InstrS:
    var d = dontCare
    g.emitInstr2(c, d)
    g.freeVal(d)
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
        if dst.kind == NoLoc:
          var lc = lhsCur
          dst = g.asLoc(lc)
        g.genStore2(cc, dst)
      else:
        let lhsCur = cc
        var rhsCur = cc; skip rhsCur
        g.genStore2(rhsCur, memLoc(lhsCur, ScalarSlot))
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
    if not g.tryEmitCsel(c):        # branchless select diamond, else fall through
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
              g.emitCondE(condC, lNext, whenTrue = false)
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
          var d = needsReg(ScalarSlot)
          g.emitValue2(cc, d)
          g.place2(d, IntRet)                            # exit code → x0
          g.freeVal(d)
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
            srcName = synth("rettmp") & $pos & ".0"
            var tcur = cc
            if cc.exprKind in {OconstrC, AconstrC}: inc tcur   # the constructed type
            else: tcur = g.getType(cc)
            g.emTypedStackVar(srcName, tcur)
            g.varType[srcName] = g.retAggrName
            g.genStore2(cc, namedStackLoc(srcName, slotOf(g.prog, tcur)))
          if g.retIndirect:
            g.copyStructThroughPtr2(srcName, g.retAggrName, g.indirectReg)
            g.movReg(IntRet, g.indirectReg)
          else:
            g.structToRegs(srcName, g.retAggrName, 0)
        elif hasVal:
          let retPos = g.posOf(cc)
          if g.retIsFloat:
            let fb = g.retFloatBits
            g.genStore2(cc, fregLoc(FloatRet, AsmSlot(cls: AFloat, size: fb div 8, align: fb div 8)))
          else:
            g.genStore2(cc, regLoc(IntRet, ScalarSlot))
        g.emBr(BA64, g.retLabel2); g.retLabelUsed2 = true
      while cc.hasMore: skip cc
  of CaseS:
    let lEnd = g.freshLabel()
    var cc = c
    cc.into:
      let selC = cc
      let signed = not g.cmpOperandUnsigned(selC)
      var selLoc = needsReg(ScalarSlot)                  # held across ALL range tests
      g.emitValue2(cc, selLoc); skip cc
      # Pool-dry etmp slot → a bridge for the (call-free) test chain; x15 stays
      # free for cmpImm2's large-literal materialization.
      var selReg: Reg
      var selBridge = NoReg
      if selLoc.kind == InReg: selReg = selLoc.r
      else:
        selBridge = g.takeBridge(selLoc.typ); g.place2(selLoc, selBridge); selReg = selBridge
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
      if selBridge != NoReg: g.dropBridge selBridge
      elif selLoc.isTemp: g.unbindTemp(selReg)
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
  of KeepovfS:
    # `(keepovf (op type a b) dest)` — overflow-checked arithmetic store. The nifasm
    # a64 vocabulary has no flag-setting arithmetic (`adds`/`subs`) and no V/C-flag
    # branches, so the overflow PREDICATE is computed into a staging bridge right
    # after the op, from snapshots of the operand values:
    #   signed add:   ovf ⟺ ((d ^ a) and (d ^ b)) < 0
    #   signed sub:   ovf ⟺ ((a ^ b) and (d ^ a)) < 0
    #   unsigned add: ovf ⟺ d <u a   (carry out)
    #   unsigned sub: ovf ⟺ a <u b   (borrow)
    # The bridge(s) stay bound across the `(ovf)` test that follows (only trivial
    # register moves may sit between — the Leng spec guarantees no call/bridge user),
    # and that test consumes and releases them (see emitCond2's OvfC).
    var cc = c
    cc.into:
      var opCur = cc                                        # the (op …) value
      let ek = opCur.exprKind
      block:
        var opTy = opCur; inc opTy                          # past the op tag → its result type
        g.ovfSigned = isSignedType(opTy)
        # Register values are kept canonically 64-bit; a sub-64-bit keepovf would
        # need a narrow op for its predicate to be exact. Reject loudly (as x64 does).
        if intTypeWidth(opTy) < 64:
          raiseAssert "arkham a64n: keepovf for sub-64-bit type not yet supported " &
                      "(width " & $intTypeWidth(opTy) & ")"
      if ek notin {AddC, SubC, MulC}:
        raiseAssert "arkham a64n: keepovf op not yet supported: " & $ek
      var aC, bC: Cursor
      block:
        var oc = opCur
        oc.into:
          skip oc                                           # result type
          aC = oc; skip oc
          bC = oc; skip oc
          while oc.hasMore: skip oc
      skip cc                                               # advance to dest
      if cc.kind != Symbol:
        raiseAssert "arkham a64n: keepovf into a complex lvalue not yet supported"
      var dst = g.ra.locationOfSym(symName(cc))
      if dst.kind == NoLoc:
        var lc = cc
        dst = g.asLoc(lc)
      skip cc
      # The sequence below READS `d` back to derive the overflow predicate, so the
      # destination has to be a register. When the allocator gave it a stack home
      # (peak pressure under `-d:release`), compute into a transient and store the
      # result once the predicate has been built from it.
      var rD: Reg
      var spillDst = dontCare
      if dst.kind == InReg:
        rD = dst.r
      else:
        rD = g.pickStagingA64()
        if rD == NoReg:
          raiseAssert "arkham a64n: no register for the keepovf destination in proc " &
                      g.curProcName
        g.pickedRegs.incl rD
        g.bindTemp(rD, ScalarSlot)
        spillDst = dst
      # Operand values at their pre-allocated locations, then snapshots into the two
      # staging bridges — the op below may overwrite either operand's register (the
      # allocator dest-passes into `rD`, which can alias an operand home or temp).
      var aLoc = dontCare
      g.emitValue2(aC, aLoc)
      var bLoc = dontCare
      g.emitValue2(bC, bLoc)
      let rA = g.takeBridge()
      g.place2(aLoc, rA)
      let rB = g.takeBridge()
      g.place2(bLoc, rB)
      if aLoc.kind == InReg and aLoc.isTemp: g.unbindTemp(aLoc.r)
      if bLoc.kind == InReg and bLoc.isTemp: g.unbindTemp(bLoc.r)
      if ek == MulC:
        # `d = a * b`; overflow is read straight off the 128-bit product's HIGH half
        # (`smulh`/`umulh` — the register-role equivalent of x86 `imul`→rdx), so there
        # is no division, no `INT64_MIN·-1` special case, and only the two bridges +
        # dest are ever live (no stack snapshot of `a`):
        #   unsigned: ovf ⟺ umulh(a,b) != 0
        #   signed:   ovf ⟺ smulh(a,b) != (d asr 63)   (the low result's sign extension)
        g.movReg(rD, rA)                                    # d := a
        g.binReg(MulA64, rD, rB)                            # d := a * b (low 64)
        if g.ovfSigned:
          g.binReg(SmulhA64, rA, rB)                        # rA := high(a*b); `a` now dead
          g.movReg(rB, rD)                                  # rB := d
          g.ab.splice &"(asr {g.emOp(rB)} 63)"             # rB := d asr 63 (expected high)
          g.binReg(EorA64, rA, rB)                          # rA := high ^ expected (0 ⟺ no ovf)
        else:
          g.binReg(UmulhA64, rA, rB)                        # rA := high(a*b) (0 ⟺ no ovf)
        g.dropBridge rB
        g.ovfMode = OvfNeqZero
        g.ovfReg = rA
        g.ovfBridges = @[rA]
      else:
        g.movReg(rD, rA)                                    # d := a
        g.binReg(if ek == AddC: AddA64 else: SubA64, rD, rB) # d := a op b
        if g.ovfSigned:
          if ek == AddC:
            g.binReg(EorA64, rA, rD)                        # rA = a ^ d
            g.binReg(EorA64, rB, rD)                        # rB = b ^ d
          else:
            g.binReg(EorA64, rB, rA)                        # rB = a ^ b (before rA is reused)
            g.binReg(EorA64, rA, rD)                        # rA = a ^ d
          g.binReg(AndA64, rA, rB)                          # rA sign bit = overflow
          g.dropBridge rB
          g.ovfMode = OvfSign
          g.ovfReg = rA
          g.ovfBridges = @[rA]
        elif ek == AddC:
          g.dropBridge rB
          g.ovfMode = OvfCmpLo                              # carry: d <u a
          g.ovfReg = rD
          g.ovfReg2 = rA
          g.ovfBridges = @[rA]
        else:
          g.ovfMode = OvfCmpLo                              # borrow: a <u b
          g.ovfReg = rA
          g.ovfReg2 = rB
          g.ovfBridges = @[rA, rB]
      if spillDst.kind != Undef:
        # After the predicate — which reads `rD` — and before the `(ovf)` test,
        # which may read it too (`OvfCmpLo`'s carry form compares `d <u a`). The
        # store does not touch `rD`, and the test's `ovfBridges` release frees it.
        g.storeReg2(spillDst, rD)
        g.ovfBridges.add rD
      while cc.hasMore: skip cc
  else: raiseAssert "arkham a64n: genStmt2 " & $c.stmtKind

# ── proc emission / driver (pure-emit path) ──────────────────────────────────

proc recordVarType2(g: var CodeGen; c: Cursor) =
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc
      let typeCur = cc; skip cc                  # type
      g.symType[nm] = g.declType(typeCur, cc)    # `.` ⇒ inferred from the initializer
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

proc emitProcBody2(g: var CodeGen; info: ProcInfo; declarative: bool;
                   frameHasCall: bool) =
  ## Body-buffer model (the x64 stage-2 twin): the BODY is emitted into a side
  ## buffer first; the prologue — whose shape (callee-saved pairs, the `(s)`
  ## region `sub`) is only final once the body is known — is written after it,
  ## into the main buffer, and the body appended. This is what lets the merged
  ## value core mint spill slots and draw callee-saved temps INLINE during
  ## emission. The prologue text is written with POST-body RegBind state, so it
  ## uses only RAW register operands (see `emitStackParamLoads`).
  var side = g.ab.sideBuf()
  swap(g.ab, side)                        # emit into the side buffer; `side` holds main
  # One scope covers caller-save param bindings (`emRegLocalVar` in
  # emitParamMoves) and the body locals — `scopeLocals` must be non-empty
  # before those param binds, and param kills must outlive the body.
  g.enterScope()
  if g.retIndirect: g.movReg(g.indirectReg, IndirectResultReg)
  g.emitParamMoves(info.decl)
  g.retLabel2 = g.freshLabel()
  g.retLabelUsed2 = false
  var c = info.decl
  c.into:
    inc c; skip c; skip c; skip c
    if c.stmtKind == StmtsS:
      c.into:
        while c.hasMore: (g.genStmt2(c); skip c)
  g.exitScope()
  if g.retLabelUsed2: g.emLab(g.retLabel2)
  if info.isEntry and g.a64Linux:                 # the entry exits by syscall (no epilogue)
    g.movImm(IntRet, 0)
    g.movImm(R8, LinuxA64ExitNr.int64)
    g.ab.tree SvcA64: g.ab.intLit 0
  swap(g.ab, side)                        # back to the main buffer; `side` holds the body
  # The body is emitted — `ra.usedCallee`/`usedCalleeF`/`hasStackVars` are final.
  # Finalize the frame and write the prologue, then splice the body after it.
  g.computeFrame(frameHasCall)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsA64:
      if g.hasFrame: framePush(g)
      g.emitStackParamLoads(info.decl)
      if g.ra.hasStackVars:
        g.ab.tree SubA64: g.ab.reg SP; g.ab.keyword SsizeX
      # etmp/eftmp/held slots minted DURING body emission: their decls must
      # precede the body's loads/stores, and the set is only known post-body —
      # so they are declared here, in the prologue, not in the side buffer.
      for st in g.ra.spillTemps:
        if st.isFloat: g.emFloatStackVar(st.name, st.typ.size * 8)
        elif isNilSlot(st.typ) or
             (not cursorIsNil(st.typ.typ) and isPtrType(resolveType(g.prog, st.typ.typ))):
          g.emTypedStackVar(st.name, st.typ.typ)   # `(nil)` / `(ptr T)` slot keeps its type
        else: g.emScalarStackVar(st.name)
      g.ab.append side                            # the body
      if not (info.isEntry and g.a64Linux):
        if g.ra.hasStackVars:
          g.ab.tree AddA64: g.ab.reg SP; g.ab.keyword SsizeX
        if g.hasFrame: framePop(g)
        g.ab.keyword RetA64

proc genProc2(g: var CodeGen; info: ProcInfo) =
  when defined(arkhamTraceProcs):
    stderr.writeLine "arkham genProc2: " & info.asmName
  if info.isAsm:
    # `.assembler` is a transliteration whose register names are x86-64's; there is
    # no target-neutral reading of `{.register: "rax".}`. Rejecting is the whole
    # point of the mode ("no fallbacks", doc/intrinsics.md §8) — an AArch64 body is
    # a different `when` branch the user must write.
    lengError info.decl, "an `.assembler` proc is not supported by the AArch64 " &
              "backend yet; its register pins name x86-64 registers", lengInfo(info.decl)
  if not g.cleanSigComputed:                   # compute the clean-signature set once
    g.cleanSigProcs = cleanSigProcNames(g.prog)
    g.noReturnProcs = noReturnProcs(g.prog)
    g.cleanSigComputed = true
  let an = analyseProc(g.buf[], info.decl, g.tvarNames,
                       cleanCallees = g.cleanSigProcs,
                       procIsClean = isCleanSigProc(g.prog, info.decl),
                       noReturnCallees = g.noReturnProcs)
  g.varType.clear()
  g.symType.clear()
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.loopEnds = @[]
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
  # The pre-pass allocates HOMES only (decl walk); every expression decision is
  # made inline by the fused emitters at the point of emission. The `(at base
  # idx scratch)` stride scratch is a pick-time reservation inside the fused
  # lvalue walk (emitLvalWalk → ra.aux memo).
  g.pickedRegs = {}
  g.pickedFRegs = {}
  g.emitTmpSpills = 0
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, aarch64MachineA, g.typeCtx, preseal)
  if g.retIndirect:
    g.indirectReg = R19
    g.ra.usedCallee.incl R19
  # fp/lr only when a `bl` exists. An atomic is an
  # instruction now, not a call, so a CAS loop no longer drags a frame onto an
  # otherwise-leaf hot path (rawDealloc and friends) — that is what `hasCall` says.
  # (The frame itself is finalized INSIDE emitProcBody2, after the body —
  # body-buffer model.)
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  g.rb.resetProc(); g.aliasToDecl.clear(); g.savedHomes.clear()
  g.noFoldPos = -1
  g.curProcName = info.asmName            # names the proc in this backend's diagnostics
  g.emitProcBody2(info, declarative, frameHasCall = an.hasCall)

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

proc genGlobal(g: var CodeGen; nifName: string; decl: Cursor) =
  ## Emit a top-level `const`/`gvar`. A true `const` with a value becomes a
  ## read-only `.text` data blob; a `gvar` with a compile-time-constant SCALAR
  ## initializer is laid out as static `.bss`-image data (so it is correct even for
  ## a FOREIGN module's gvar in a bundle, whose entry-time `emitGlobalInits` never
  ## runs — and for a `var` later mutated). Any other (runtime) initializer is a
  ## zeroed slot filled at entry by `emitGlobalInits`.
  # An importc-WITHOUT-exportc gvar names an external (its slot is an `exportc`
  # definition in another bundled module): emit NO slot — references resolve to the
  # bare C name via `emGlobalAddr`. An exportc gvar IS the definition, emitted under
  # that bare C name so importc references in other modules link to it.
  if nifName in g.prog.importcOnlyGvars: return
  let name = g.prog.gvarAsmName(nifName)
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
      g.genGlobalInitValue(name, typeCur, c, hasValue)
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

proc generateA64*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                  linux = false): string =
  ## Compile a parsed Leng module to AArch64 asm-NIF text — Darwin/Mach-O by
  ## default, or Linux/ELF when `linux` (svc-based syscalls, static, no dyld/TLV),
  ## which `nifasm`'s `linux_arm64` target assembles to a qemu-runnable ELF.
  ## `inputPath` and `tags` let the program model load *other* modules on demand
  ## to resolve cross-module symbols (`Foo.0.othermod`).
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: aarch64MachineA,
                  a64Linux: linux)
  g.prog = collect(buf, inputPath, tags, darwin = not linux)
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
      genProc2(g, info)
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
