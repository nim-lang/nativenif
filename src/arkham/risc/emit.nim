#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## The Arm emitter's primitives — the layer everything above is written in.
##
## The staging BRIDGES are the idea to understand here. AArch64 keeps two
## registers permanently out of the allocator's pools, so the emitter always has
## somewhere to put a value it is moving; `takeBridge`/`dropBridge` hand them
## out. That is what makes the destination protocol (`takeTmp` / `takeHeld` /
## `resolveDestE`) total — it can always answer, even with every pool dry.
##
## Also here: the immediate encoders. `add`/`sub` take a 12-bit immediate,
## `and`/`orr`/`eor` take a bitmask immediate that is not a range at all, and
## Thumb-2 takes a third shape again — so "can this constant be folded into the
## instruction" is a real question with three answers, and both `isLogicalImm`
## (from nifasm's own encoder) and `thumbimm` are consulted rather than guessed.

import std / [assertions, tables, sets, strformat, strutils]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    stress, context, typeutil, 
                    mirrors, temps, typenav, regbind, abi]
import machine_a64 as machine
from machine_m as machine_m import nil
from "../../nifasm/arm64/encoder" as arm64 import isLogicalImm
from thumbimm import nil

type
  RiscInst* = A64Inst
    ## An instruction tag, as the SHARED load/store emitter sees one.
    ##
    ## The alias is not decoration. `RiscInst` is the right name in
    ## `nifasm/arm64`, where the enum genuinely is AArch64's — but this emitter
    ## serves three targets going on four, and 75 of the tags it writes are the
    ## SAME tag id on every one of them (`(add3 …)` is `Add3A64`, `Add3M` and
    ## `Add3Rv` at one ordinal; the suffix is which enum you reached it through,
    ## not which machine it means). A signature reading `op: RiscInst` says the
    ## emitter is AArch64's, which is the fact this whole directory exists to
    ## deny.
    ##
    ## The MEMBER names stay `AddA64` and so on, because they are generated from
    ## `doc/instructions.md` and renaming them would churn nifasm's a64 selector
    ## for no behavioural gain. Read the suffix as "the shared row", and read a
    ## tag that is genuinely one target's — `(csel…)`, `(stp)`, `(vfadd)` — as
    ## guarded by a `TargetFeature`, because every one of them now is.

  WideRefKind* = enum
    wrSlot        ## a nifasm `(s)` stack slot, addressed by name
    wrBase        ## `[base + off]`, the address already in a register

  WideRef* = object
    ## WHERE a 64-bit value's eight bytes are. Deliberately not a `Location`:
    ## a `Location` describes where a value may go, and every one of these is
    ## already resolved to an address the two halves can be read off.
    off*: int
    case kind*: WideRefKind
    of wrSlot: name*: string
    of wrBase: base*: Reg

template WideSlot*(): AsmSlot = AsmSlot(cls: AInt, size: 8, align: 8)
  ## The `AsmSlot` of a 64-bit integer temp — the one slot on this target whose
  ## size EXCEEDS the word, which is what `isWideSlot` recognizes. `align: 8` is
  ## the type's natural alignment; nifasm rounds the slot to the target granule.

let aarch64MachineA* = stressed(aarch64MachineN)
  ## The machine arkham allocates against: `aarch64MachineN` itself, unless the
  ## `-d:arkhamStress` shrink is armed (see `stress.nim`). A module-level `let`
  ## so the environment is read and the pools rebuilt once, not per proc.

const EntryExitShim* = "`mexit.0"
  ## The semihosting `exit` shim every Cortex-M image carries, whatever the
  ## program imports. A bare-metal entry proc cannot RETURN: `lr` at reset holds
  ## no valid address, so falling off the end of `main` branches into nothing —
  ## which is why 17 corpus fixtures hung rather than failing. The entry
  ## therefore tail-calls this instead of executing an epilogue.

const DarwinLibSystem* = "/usr/lib/libSystem.B.dylib"

const SuCallWeight* = 1000          # a call dominates demand → sorts first

const StackArgFpBias* = 16
  ## Distance from the frame pointer to the caller's first stack argument. `framePush`
  ## sets `fp` right after `stp fp, lr, [sp, #-16]!`, so it sits exactly one pair below
  ## the SP the caller entered with — which is where the outgoing argument area starts.

template posOf*(g: CodeGen; cur: Cursor): int = cursorToPosition(g.buf[], cur)

const ThreeOpA64* = {AddA64, SubA64, MulA64, AndA64, OrrA64, EorA64,
                    LslA64, LsrA64, AsrA64}
  ## Ops with a native 3-operand `(op D A B)` nifasm encoding (see parseArith3A64).

# Order in which a codegen-time steal looks for a victim register-local: prefer
# the volatile temp pool (x9–x15 — call-free locals the allocator put there once
# the callee-saved pool was full, the common case), then callee-saved (x19–x28).
# Fixed order ⇒ the plan and emit passes pick the same victim deterministically.
# `w32` selects the 32-bit W-form tag (`add`→`addw`, `add3`→`addw3`, …) for an
# UNSIGNED 32-bit result: the W-form auto zero-extends into bits 32..63, so the
# `normalizeBinWidth` shift-pair that would otherwise re-clear the top half is
# elided (see emitBin2). Only add/sub/mul have W-forms; other ops pass w32 = false.
# 3-operand forms `(op3 D A B)` → `D = A op B` (arm64 native, non-destructive). Used
# when the left source `A` is a still-live local in a register distinct from the
# result `D`, so the value is computed without a preceding `mov D, A`. The 2-operand
# op tag is mapped to its distinct 3-operand tag (`add`→`add3`, …); nifasm dispatches
# on the tag's fixed arity (see parse3OperandsA64).
const
  CpacrAddr* = 0xE000ED88'i64
    ## The Coprocessor Access Control Register.
  CpacrFullAccessCp10Cp11* = 0x00F00000'i64
    ## Full access for CP10 and CP11 — the two coprocessor slots the FPU lives in.

const
  UDivMod64Base* = "`udivmod64.0"
    ## `(N: r0:r1, D: r2:r3)` → quotient in r0:r1, remainder in r2:r3.
  SDivMod64Base* = "`sdivmod64.0"
    ## The signed wrapper: |N| div |D| through the unsigned routine, then the
    ## signs put back. Truncating toward zero, and the remainder takes the
    ## DIVIDEND's sign — C's rule, and Leng's.

# The names of the two software-division helpers. Only the NAMES: the bodies
# are `risc/runtime`'s, but a call site is far below it, so the two would
# otherwise be a cycle.
proc uDivMod64Proc*(g: CodeGen): string {.inline.} =
  ## The divider routines, MODULE-QUALIFIED — the same rule the semihosting
  ## globals follow, and for the same reason: a one-dot symbol is module-LOCAL,
  ## so the render compresses it out of the embedded index and nothing outside
  ## the module can resolve it. These are emitted once per module that divides,
  ## and any OTHER module that imports such a proc has to be able to name the
  ## routine it calls.
  UDivMod64Base & "." & thisModuleSuffix(g.prog)

proc sDivMod64Proc*(g: CodeGen): string {.inline.} =
  SDivMod64Base & "." & thisModuleSuffix(g.prog)

proc releaseStaleName*(g: var CodeGen; r: Reg)

proc isWideSlot*(g: CodeGen; s: AsmSlot): bool {.inline.}

proc genPointee*(g: var CodeGen; c: var Cursor)

proc genTypeBody*(g: var CodeGen; c: var Cursor)

proc emReg*(g: var CodeGen; r: Reg) {.inline.} =
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
    # …with one qualification the AArch64 file did not need: this holds only for a
    # register that is EXCLUSIVELY scratch. On AArch64 the pool (x9–x15) and the
    # argument registers (x0–x7) are disjoint, so "in the pool" implies "must be
    # bound". Cortex-M has four argument registers and no spare volatile at all,
    # so r1–r3 are BOTH — and their raw use as arguments is exactly the
    # "irreducible structural" case the list above exempts.
    assert r notin g.md.intTempRegs or r in g.md.intArgRegs,
      "arkham: unbound scratch-pool register reached emReg: " & g.ab.renderReg(r)
    g.ab.rawReg r

proc emOp*(g: CodeGen; r: Reg): string =
  ## The asm-NIF operand spelling of register `r` for a `splice`d text fragment — the
  ## text-path counterpart of `emReg` (`emReg` can't be used because `splice` consumes
  ## a string): a bound register by its checked name (no parens), an unbound
  ## register as its raw tag. Used by the inline-asm lowerings (extend, atomics)
  ## whose operands may be `rebind`-bound scratch or register-locals.
  ##
  ## The raw spelling comes from `ab.renderReg`, the SAME shim `emReg` renders
  ## through, and not from `machine.regName`. That hard-coded AArch64 name was
  ## invisible for as long as every register reaching a splice on Cortex-M
  ## happened to be bound: the first unbound one — `extendTo` narrowing a raw
  ## argument register during a call's marshalling — emitted `(uxtb (x0) (x0))`
  ## into a Cortex-M module, where nifasm rightly does not know what `(x0)` is.
  let nm = g.rb.boundName(r)
  if nm.len > 0: nm
  else: "(" & g.ab.renderReg(r) & ")"

proc movImm*(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovA64: g.emReg d; g.ab.intLit v

proc movReg*(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovA64: g.emReg d; g.emReg s

proc wForm(op: RiscInst): RiscInst =
  case op
  of AddA64: AddwA64
  of SubA64: SubwA64
  of MulA64: MulwA64
  else: op

proc hereTarget*(g: CodeGen): IntrinsicTarget {.inline.} =
  ## The tag the SHARED intrinsic row table uses for the target being emitted.
  ## `codegen_arm` serves both Arm profiles, and reading `tgA64` for both was a
  ## proxy that held only while no row distinguished them; the volatile rows do.
  case g.md.arch
  of X86: tgX64
  of Arm64: tgA64
  of ThumbM: tgThumbM
  of Rv32:
    # Never reached: every membership test goes through `hasHereLowering`, which
    # answers for RV32 before asking this. Spelled as a failure rather than a
    # plausible substitute, because a substitute would silently claim some other
    # target's lowerings.
    quit "arkham: hereTarget has no RV32 value (use hasHereLowering)"

proc hasHereLowering*(g: CodeGen; targets: set[IntrinsicTarget]): bool {.inline.} =
  ## Whether the intrinsic table claims a lowering for the target being emitted.
  ##
  ## Always false on RV32, and not because the lowerings are missing: nimony's
  ## `IntrinsicTarget` has no `tgRv32` member for a row to NAME, so no row can
  ## claim it. That enum lives in the shared library and adding a member is
  ## nimony's change to make. Until it does, `{.instruction.}` and `{.intrinsic.}`
  ## are refused on this target by name — which is the correct answer, and the one
  ## the call sites already phrase, since each reports `md.targetName`.
  g.md.arch != Rv32 and g.hereTarget in targets

proc destructive3(g: CodeGen; op: RiscInst): bool {.inline.} =
  ## Ops with no destructive `D op= S` spelling on this target: Thumb-2's
  ## `sdiv`/`udiv` are three-operand instructions and nifasm parses them as such,
  ## so the same tag has to arrive with `D` repeated.
  TwoAddrForms notin g.md.caps and op in {SdivA64, UdivA64}

proc binReg*(g: var CodeGen; op: RiscInst; d, s: Reg; w32 = false) =
  if g.destructive3(op):
    g.ab.tree op: (g.emReg d; g.emReg d; g.emReg s)
  else:
    g.ab.tree (if w32: wForm(op) else: op): g.emReg d; g.emReg s

proc binImm*(g: var CodeGen; op: RiscInst; d: Reg; v: int64; w32 = false) =
  if g.destructive3(op):
    g.ab.tree op: (g.emReg d; g.emReg d; g.ab.intLit v)
  else:
    g.ab.tree (if w32: wForm(op) else: op): g.emReg d; g.ab.intLit v

proc emNeg*(g: var CodeGen; d: Reg) =
  ## `d = -d`. A target with a destructive form spells it with one operand;
  ## Thumb-2's `neg`/`rsb` names its source, so the register is repeated there.
  if TwoAddrForms in g.md.caps:
    g.ab.tree NegA64: g.emReg d
  else:
    g.ab.tree NegA64: (g.emReg d; g.emReg d)

proc threeOpTag(op: RiscInst; w32 = false): RiscInst =
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

proc binReg3*(g: var CodeGen; op: RiscInst; d, a, b: Reg; w32 = false) =
  g.ab.tree threeOpTag(op, w32): g.emReg d; g.emReg a; g.emReg b

proc binImm3*(g: var CodeGen; op: RiscInst; d, a: Reg; v: int64; w32 = false) =
  g.ab.tree threeOpTag(op, w32): g.emReg d; g.emReg a; g.ab.intLit v

proc emAdr*(g: var CodeGen; d: Reg; sym: string) =
  g.ab.tree AdrA64: g.emReg d; g.ab.sym sym

proc emLdaxr(g: var CodeGen; rt, rn: Reg) =        # rt ← exclusive-acquire [rn]
  g.ab.tree LdaxrA64: g.emReg rt; g.emReg rn

proc emStlxr(g: var CodeGen; rs, rt, rn: Reg) =    # store-release-exclusive rt→[rn]; rs←status
  g.ab.tree StlxrA64: g.emReg rs; g.emReg rt; g.emReg rn

proc emLdar*(g: var CodeGen; rt, rn: Reg; bits = 64) =   # rt ← acquire [rn] (sized)
  g.ab.tree LdarA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits

proc emStlr*(g: var CodeGen; rt, rn: Reg; bits = 64) =   # release store rt→[rn] (sized)
  g.ab.tree StlrA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits

proc emByteAt*(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 8)) base) idx))` — the byte at `base[idx]`.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg base
      g.emReg idx

proc emLdrb*(g: var CodeGen; rt, base, idx: Reg) =  # rt ← zero-extended byte [base+idx]
  # A target with `RegOffsetMem` spells the byte access as three registers; one
  # without it takes a memory OPERAND (and puts the destination first either
  # way), so the index folds into an `(at …)` instead. Same instruction,
  # different operand shape — see `genInstM`'s `loadStore`.
  if RegOffsetMem in g.md.caps:
    g.ab.tree LdrbA64: g.emReg rt; g.emReg base; g.emReg idx
  else:
    g.ab.tree LdrbA64: (g.emReg rt; g.emByteAt(base, idx))

proc emStrb*(g: var CodeGen; rt, base, idx: Reg) =  # store low byte of rt → [base+idx]
  if RegOffsetMem in g.md.caps:
    g.ab.tree StrbA64: g.emReg rt; g.emReg base; g.emReg idx
  else:
    g.ab.tree StrbA64: (g.emByteAt(base, idx); g.emReg rt)

proc emQwordAt*(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 64)) base) idx))` — the quadword at `base[idx]`.
  ## nifasm scales `idx` by 8 (`lsl #3`). `base` and `idx` must be distinct.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(wordBits())
        g.emReg base
      g.emReg idx

proc emLoadQwordAt*(g: var CodeGen; dest, base, idx: Reg) =
  g.ab.tree MovA64: (g.emReg dest; g.emQwordAt(base, idx))

proc emStoreQwordAt*(g: var CodeGen; base, idx, src: Reg) =
  g.ab.tree MovA64: (g.emQwordAt(base, idx); g.emReg src)

proc genTlvAddr*(g: var CodeGen; name: string; dest: Reg) =
  ## `dest ← &threadlocal(name)`, which is the SAME `(adr dest sym)` a global's
  ## address is. What differs is what nifasm makes of it, and that follows from
  ## the DECLARATION `genTvar` emitted, not from the reference: a `(tvar …)` on
  ## Darwin lowers to the TLV descriptor thunk call (which clobbers x0 and lr —
  ## so a proc touching a thread-local is analysed as having a call, gets a stack
  ## frame, and keeps its params out of the volatile argument registers), while a
  ## `(gvar …)` is an ordinary address materialization.
  ##
  ## The sites that used to write `if g.a64Linux: g.emAdr(…) else: g.genTlvAddr(…)`
  ## were choosing between two spellings of one tree; the choice they meant to
  ## express is `oneThread`, and it is made once, where the variable is declared.
  g.ab.tree AdrA64:
    g.emReg dest
    g.ab.sym name

proc produceBridge*(g: CodeGen): Reg {.inline.} =
  ## The third always-free scratch, beyond the two staging bridges. AArch64
  ## borrows the assembler's x16 (IP0); Cortex-M cannot borrow nifasm's r12,
  ## because nifasm folds operands through it at sites this emitter never sees,
  ## so it dedicates r8 instead (see `machine_m.ProduceBridge`).
  ##
  ## Read from the machine description rather than chosen here: slot R16 is not
  ## even MAPPED on Cortex-M, so the `if thumbM` this used to be could — and once
  ## did — put a register name no assembler accepts into the output.
  g.md.produceBridge

proc indirectResultReg*(g: CodeGen): Reg {.inline.} =
  ## Where the caller leaves `&result` for an aggregate return too wide for
  ## registers. AArch64 has a dedicated x8 off the argument file; Cortex-M has no
  ## such register and dedicates r9 (see `machine_m.IndirectResultReg`), which
  ## keeps this emitter's one code shape working on both.
  g.md.indirectResultReg

proc emConvClobbers*(g: var CodeGen) =
  ## The caller-saved set this target's calling convention destroys, emitted as a
  ## `(clobber …)` DECLARATION — raw register locations, never variable names.
  ## AAPCS32 has four (r0–r3) where AAPCS64 has sixteen, which is the whole reason
  ## the list comes from the target rather than from a constant.
  for r in g.md.convClobbersGpr: g.ab.rawReg r

proc bindFTmp*(g: var CodeGen; f: FReg; bits: int) =
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

proc unbindFTmp*(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## binding. A no-op when `f` carries no temp binding. Also clears the fused
  ## core's reserve flag (see `unbindTemp`).
  g.pickedFRegs.excl f
  let dead = g.rb.takeFScratch(f)
  if dead.len > 0:
    g.ab.tree KillA64: g.ab.sym dead

proc checkFloatWidth*(g: CodeGen; bits: int) =
  ## Cortex-M4F's FPv4-SP is SINGLE PRECISION. There is no `.f64` instruction to
  ## lower a double to, so this is missing HARDWARE rather than a missing
  ## feature — refused by name, at the point the width first becomes visible,
  ## instead of dragging in a softfloat library nobody asked for.
  if Float64 notin g.md.caps and bits != 32:
    quit "arkham cortex-m: a " & $bits & "-bit float has no hardware on this core " &
         "(FPv4-SP is single precision); use `float32` — see M5 in doc/cortex_m.md"

proc emFReg*(g: var CodeGen; f: FReg; bits: int) {.inline.} =
  ## A float value operand: a v-register hosting a named float local / scratch temp →
  ## its checked name (nifasm recovers the precision from the binding's type);
  ## otherwise the raw `(dN)`/`(sN)` tag. The SIMD twin of `emReg`: the v16–v31 scratch
  ## pool is the only register class the allocator hands out for arbitrary computed
  ## floats, and every such hand-out is bound (`bindFTmp` / `emFRegLocalVar`), so a raw
  ## pool register reaching here is an unbound scratch slipping past the binder. The
  ## v0–v7 arg/return registers and v8–v15 callee-saved homes (saved raw by fstp/fldp)
  ## keep their structural raw uses.
  g.checkFloatWidth(bits)
  let nm = g.rb.boundFName(f)
  if nm.len > 0: g.ab.sym nm
  else:
    assert f notin g.md.floatTempRegs,
      "arkham a64: unbound float scratch-pool register reached emFReg: " & regName(f)
    g.ab.freg(f, bits)

proc fmovF*(g: var CodeGen; d, s: FReg; bits: int) =
  if d == s: return
  g.ab.tree FmovA64: g.emFReg(d, bits); g.emFReg(s, bits)

proc fmovFromGpr*(g: var CodeGen; d: FReg; s: Reg; bits: int) =   # fmov dD/sD, xS/wS (bits)
  g.ab.tree FmovA64:
    g.emFReg(d, bits)
    g.emReg s

proc fmovToGpr*(g: var CodeGen; d: Reg; s: FReg; bits: int) =     # fmov xD/wD, dS/sS (bits)
  g.ab.tree FmovA64:
    g.emReg d
    g.emFReg(s, bits)

proc fbin*(g: var CodeGen; op: RiscInst; d, s: FReg; bits: int) =  # d = d op s
  g.ab.tree op: g.emFReg(d, bits); g.emFReg(s, bits)

proc fcvtI2F*(g: var CodeGen; op: RiscInst; d: FReg; s: Reg; bits: int) =  # scvtf/ucvtf dD, xS
  g.ab.tree op:
    g.emFReg(d, bits)
    g.emReg s                                      # see fmovFromGpr

proc fcvtF2I*(g: var CodeGen; op: RiscInst; d: Reg; s: FReg; bits: int) =  # fcvtzs/fcvtzu xD, dS
  g.ab.tree op:
    g.emReg d
    g.emFReg(s, bits)

proc emFcvt*(g: var CodeGen; d, s: FReg; dstBits, srcBits: int) =  # fcvt: precision convert
  ## Only reachable where there are two precisions to convert between, so a target
  ## without `Float64` never arrives — but having both is not the same fact as
  ## spelling the convert `(fcvt …)`, and a target that spells it otherwise must
  ## say so rather than inherit AArch64's row.
  if FloatConvert notin g.md.caps:
    quit "arkham " & g.md.targetName & ": no `(fcvt …)` row for a " & $srcBits &
         "-to-" & $dstBits & "-bit float conversion on this target"
  g.ab.tree FcvtA64: g.emFReg(d, dstBits); g.emFReg(s, srcBits)

proc emFLoad*(g: var CodeGen; d: FReg; addrReg: Reg; bits: int) =  # fldr dD/sD, [addrReg]
  g.ab.tree FldrA64:
    g.emFReg(d, bits)
    g.ab.tree MemX: g.emReg addrReg          # name when the pointer is a bound temp

proc emFStore*(g: var CodeGen; d: FReg; addrReg: Reg; bits: int) = # fstr dD/sD, [addrReg]
  g.ab.tree FstrA64:
    g.ab.tree MemX: g.emReg addrReg          # name when the pointer is a bound temp
    g.emFReg(d, bits)

proc emFieldMem*(g: var CodeGen; base, field: string) =
  ## `(mem (dot base field))` — nifasm resolves the field offset from the
  ## aggregate's type. `base` is a `(s)` stack var.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field

proc emAggrElemMem*(g: var CodeGen; base: string; idx: int) =
  ## `(mem (at base idx))` — element `idx` of the array stack var `base`; nifasm folds
  ## the constant `idx*elemSize` into the load/store offset and sizes it from the
  ## array's element type (an immediate index needs no stride scratch).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.sym base
      g.ab.intLit idx

proc emPtrFieldMem*(g: var CodeGen; ptrReg: Reg; typeSym: SymId; field: string) =
  ## `(mem (dot (cast (ptr T) (xN)) field))` — field access through a register
  ## holding a pointer to the aggregate (for >16B by-ref / x8-indirect). The
  ## `cast` types the bare register so nifasm's `dot` can compute the offset.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(typeSym)
        g.emReg ptrReg
      g.ab.sym field

proc emAggrFieldMem*(g: var CodeGen; base, field: string) =
  ## Field memory operand for the aggregate named `base`, dispatching on how it
  ## is held: a `(s)` stack struct → direct `(dot …)`; a pointer in a register
  ## (a by-reference param) → through the pointer.
  let loc = g.plan.homeOfSym(base)
  case loc.kind
  of NamedStack: g.emFieldMem(base, field)
  of StackPtr:
    raiseAssert "arkham a64: spilled by-ref field must go through a loaded pointer: " & base
  of InReg:      g.emPtrFieldMem(loc.r, g.varType[base], field)
  of InRegPair:
    raiseAssert "arkham a64: InRegPair field must go through pairFieldReg: " & base
  else:
    # a synthetic nifasm `(s)` slot (e.g. an inline-constructor arg temp) is addressed
    # by name like a `NamedStack` var — the allocator just doesn't track it.
    if g.varType.hasKey(base): g.emFieldMem(base, field)
    else: raiseAssert "arkham: aggregate base neither stack nor pointer: " & base

proc emAggrDot*(g: var CodeGen; base, field: string) =
  ## The `(dot …)` operand alone (no `mem` wrapper), location-aware — for `lea`
  ## (address-of a field). Stack struct → `(dot var field)`; pointer → cast.
  let loc = g.plan.homeOfSym(base)
  case loc.kind
  of NamedStack:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field
  of StackPtr:
    raiseAssert "arkham a64: spilled by-ref field must go through a loaded pointer: " & base
  of InReg:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(g.varType[base])
        g.emReg loc.r
      g.ab.sym field
  of InRegPair:
    raiseAssert "arkham a64: InRegPair field must go through pairFieldReg: " & base
  else:
    # a synthetic nifasm `(s)` slot (e.g. an inline-constructor arg temp) is addressed
    # by name like a `NamedStack` var — the allocator just doesn't track it. Mirrors
    # `emAggrFieldMem`'s fallback (this is its no-`mem`-wrapper address-of-field twin).
    if g.varType.hasKey(base):
      g.ab.tree DotX:
        g.ab.sym base
        g.ab.sym field
    else: raiseAssert "arkham: aggregate base neither stack nor pointer: " & base

proc emStackVar*(g: var CodeGen; name: string; typeSym: SymId) =
  ## Declare a nifasm-managed stack slot `(var :name (s) typeSym)`.
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.emTypeSym(typeSym)
  g.ab.close()

proc emTypedStackVar*(g: var CodeGen; name: string; t: Cursor) =
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
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
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

proc emScalarLoad*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← [slot]` — load a spilled scalar (nifasm resolves the `(s)` var to
  ## `[sp,#off]`).
  g.ab.tree MovA64: (g.emReg dest; g.ab.sym name)

proc emScalarStore*(g: var CodeGen; name: string; src: Reg) =
  ## `[slot] ← src` — store to a spilled scalar's `(s)` var.
  ##
  ## THE invalidation point for a store: whatever mirrored this slot's old value
  ## is stale from here on. It sits at the lowest level on purpose — every scalar
  ## store to a slot funnels through here, so no store path can forget it.
  g.killMirrorsOf name
  g.ab.tree MovA64: (g.ab.sym name; g.emReg src)

proc emBindType*(g: var CodeGen; typ: AsmSlot) =
  ## Emit the Leng type for a scratch binding: the slot's own type when known, else
  ## the generic `(i 64)` (a register/immediate dont-care placeholder carries no
  ## cursor). Mirrors `emScalarStackVar`'s type emission.
  if isNilSlot(typ):
    g.ab.nilValue()                  # `(nil)` — a null pointer, not an `(i 64)` 0
  elif cursorIsNil(typ.typ):
    g.ab.intType(wordBits())
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

when defined(arkhamBridgeDbg):
  ## `-d:arkhamBridgeDbg`: the evidence apparatus behind `EmitterBridgeDemand`.
  ## Reports, per proc, the peak number of reserved bridges live at once and the
  ## peak number still held when a RECURSIVE emit call is entered. The second is
  ## the one that decides whether a fixed reservation composes; see design.md.
  var dbgPeakBridges*: int = 0
  var dbgPeakHeldAtRecursion*: int = 0
proc unbindTemp*(g: var CodeGen; r: Reg) =
  ## Release a scratch binding made by `bindTemp`: `(kill)` the name and drop the
  ## binding. A no-op when `r` carries no temp binding (so it is safe on every
  ## `giveBack`, whether or not the reg was a bound temp). Also clears the fused
  ## core's reserve flag, so every legacy release site frees a `takeTmp` pick.
  g.pickedRegs.excl r
  g.lastResortBridges.excl r
  let dead = g.rb.takeScratch(r)
  if dead.len > 0:
    g.ab.tree KillA64: g.ab.sym dead

proc emFloatScalarLoad*(g: var CodeGen; dest: FReg; name: string; bits: int) =
  ## `dest ← [slot]` — load a spilled float (nifasm resolves the `(s)` var operand).
  g.ab.tree FldrA64: (g.emFReg(dest, bits); g.ab.sym name)

proc emFloatScalarStore*(g: var CodeGen; name: string; src: FReg; bits: int) =
  ## `[slot] ← src` — store to a spilled float's `(s)` var.
  g.killMirrorsOf name                                  # see `emScalarStore`
  g.ab.tree FstrA64: (g.ab.sym name; g.emFReg(src, bits))

proc extendTo*(g: var CodeGen; dest: Reg; width: int; signed: bool) =
  ## Normalize the low `width` bits of `dest` to its full REGISTER form (sign- or
  ## zero-extended). A no-op at the register width itself — which is why this has
  ## to ask the target: 32 bits is a narrowing cast needing two shifts on AArch64
  ## and nothing at all on Cortex-M, where the register IS 32 bits.
  ##
  ## Without `SubwordExtend` it is the `lsl #(W-w); asr|lsr #(W-w)` pair (nifasm
  ## has no sxtb/uxtb tag on a64); with it, a real `uxtb`/`sxtb`/`uxth`/`sxth`,
  ## which is one instruction and reads far better than a shift pair.
  let regWidth = wordBits()
  if width <= 0 or width >= regWidth: return
  let d = g.emOp(dest)                       # bound name or raw reg (parens included)
  if SubwordExtend in g.md.caps and width in [8, 16]:
    let op = (if width == 8: (if signed: "sxtb" else: "uxtb")
              else: (if signed: "sxth" else: "uxth"))
    g.ab.splice &"({op} {d} {d})"
  else:
    let sh = regWidth - width
    let down = if signed: "asr" else: "lsr"
    g.ab.splice &"(lsl {d} {sh}) ({down} {d} {sh})"

proc emGlobalAddr*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &global` — adrp+add (nifasm resolves the gvar to its `.bss`/`.data`
  ## address). AArch64 has no typed PC-relative memory operand, so a global is
  ## always accessed by first materializing its address. An importc/exportc gvar is
  ## referenced by its bare C name (cross-module linkage), like on x86-64.
  ##
  ## THE read side of the ADDRESS mirrors: when a register in this straight-line
  ## region still holds `&name`, the two-instruction materialization collapses to
  ## one `mov`. This is the whole reason address mirrors exist on AArch64 and not
  ## on x86-64, where the address is a single RIP-relative `lea` and copying one
  ## register to another would save nothing.
  let asmName = g.prog.gvarRefName(name)
  g.killMirror(dest)                            # `dest` is written either way
  let m = g.rb.addrMirror(asmName)
  if m != NoReg and m != dest: g.movReg(dest, m)
  else: g.emAdr(dest, asmName)

proc rebindLocalAs*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
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
    g.ab.rawReg r
  g.rb.rebindLocal(r, name, isPtr)

proc rebindTempAs*(g: var CodeGen; r: Reg; typeCur: Cursor) =
  ## Retype an already-bound scratch on `r` to `typeCur`, keeping it a temp
  ## (unlike `rebindLocalAs`, which would drop the `boundTemps` bit). Used after
  ## a narrowing cast: the temp was bound at 64-bit so the source could land,
  ## `extendTo` has now truncated, and a later `(mov u32dst tmp)` needs the
  ## target width on the name.
  let name = g.rb.boundName(r)
  if name.len == 0: return
  let slot = slotOf(g.prog, typeCur)
  let isPtr = isPtrType(resolveType(g.prog, typeCur))
  g.ab.tree RebindA64:
    g.ab.symDef name
    var t = typeCur
    g.genTypeBody(t)
    g.ab.rawReg r
  g.rb.bindScratch(r, name, isPtr)
  g.tmpBindTyp[r] = slot

proc indirectRetType*(g: var CodeGen; gvarDecl: Cursor): Cursor =
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

proc genProctypeSig*(g: var CodeGen; c: var Cursor) =
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
          retByRef = rs.kind == AMem and rs.size > 2 * wordSize()
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
                  if pl.isAgg or pl.isWideScalar:
                    # Aggregate param: >16B by-ref pointer in one x-reg, ≤16B by-value
                    # over `pl.words` consecutive x-regs (`(arg pN k)` selects word k).
                    # A scalar too wide for one register (`(i 64)` on Cortex-M) takes
                    # the same `(regs …)` form and for the same reason.
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.tree RegsD:
                        for k in 0 ..< pl.words: g.ab.rawReg g.md.gprAt(pl, k)
                      if pl.byRef:
                        g.ab.ptrType: g.genPointee(c)
                      else:
                        g.genPointee(c)
                  else:
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      if not pl.onStack: g.ab.rawReg g.md.gprAt(pl)  # raw reg *location*
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
          elif g.isWideSlot(slotOf(g.prog, c)):
            skip c                              # 64-bit result: r0:r1 raw (see emitSignature)
          elif slotOf(g.prog, c).kind == AMem:
            # ≤16B by-value aggregate result → x0:x1 raw, EMPTY result slot (see
            # emitSignature): the caller reads the return registers directly.
            skip c
          else:
            g.ab.symDef synth("ret.0")
            g.ab.rawReg g.md.intRetReg                     # raw reg *location* of the result
            g.genPointee(c)                     # return type BY REFERENCE (named → sym)
        while c.hasMore: skip c                  # pragmas
    else:
      g.ab.keyword ParamsD
      g.ab.keyword ResultD
      skip c                                     # advance past the whole proctype node
    g.ab.tree ClobberD:
      g.emConvClobbers()

proc genPointee*(g: var CodeGen; c: var Cursor) =
  ## Emit a pointer's pointee / element type. A *named* type is referenced by
  ## symbol rather than inlined: this breaks the infinite recursion of
  ## self-referential types (a `(ptr T)` field inside `T`, e.g. the TLSF
  ## `SmallChunk`/`AvlNode`) and lets nifasm resolve — and auto-import across
  ## modules — the type declaration by name. Mirrors the x64 backend.
  if c.kind == Symbol:
    g.ab.sym symName(c); inc c
  else:
    g.genTypeBody(c)

proc genTypeBody*(g: var CodeGen; c: var Cursor) =
  ## Translate a Leng type at `c` into asm-NIF, advancing `c` past it. Named
  ## types are inlined (resolved against `typeDecls`); object field pragmas are
  ## dropped. v1: int/uint/bool/ptr scalars and objects.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, c.symId)  # resolves across modules
    d.into:                                 # (type SymbolDef TypePragmas body)
      inc d                                 # name
      skip d                                # TypePragmas (one slot: `.` or (pragmas …))
      g.genTypeBody(d)
    inc c
  of TagLit:
    case c.typeKind
    of IT:
      var t = c; inc t
      g.ab.intType(if t.kind == IntLit: int(intVal(t)) else: wordBits()); skip c
    of UT:
      var t = c; inc t
      g.ab.uintType(if t.kind == IntLit: int(intVal(t)) else: wordBits()); skip c
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
      g.ab.uintType(wordBits()); skip c
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

proc emWordThroughPtr*(g: var CodeGen; p: Reg; idx: int) =
  ## `(mem (at (cast (aptr (u W)) p) idx))` — the `idx`-th raw WORD at `[p]`, typed
  ## `(u W)` (ignores the aggregate's field layout). nifasm strides by the element
  ## width, so the same node means 8-byte words on AArch64 and 4-byte on Cortex-M.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(wordBits())
        g.emReg p
      g.ab.intLit idx

proc emScalarAtOff*(g: var CodeGen; p: Reg; off, size: int) =
  ## `(mem (cast (aptr (u size·8)) p) off)` — the `size`-byte unsigned scalar at the
  ## RAW byte offset `off` from `[p]`. `(at …)` strides by the element size and so
  ## can only reach multiples of the width; nifasm's `(mem base offset)` form takes a
  ## free byte displacement, which is what an aggregate's unaligned tail needs.
  g.ab.tree MemX:
    g.ab.tree CastX:
      g.ab.aptrType: g.ab.uintType(size * 8)
      g.emReg p
    g.ab.intLit off

proc freshLabel*(g: var CodeGen): string =
  # Name must be a NIF *symbol* (needs a '.'), but `extractBasename` strips a
  # trailing `.<digits>`, so put the counter *before* the suffix ("L0.0", …)
  # to keep basenames ("L0", "L1") distinct. `SynthMark` keeps them out of the
  # Leng namespace, where a `block L0:` would produce the very same name.
  result = synth("L") & $g.labelCount & ".0"
  inc g.labelCount

proc emLab*(g: var CodeGen; name: string) =
  ## THE control-flow invalidation point for the store-forwarding mirrors: what a
  ## register holds at a label does not follow from the instructions above it —
  ## some other path branched here. Hooking it at the label DEFINITION rather
  ## than at each of `if`/`case`/`and`/`or` is what makes this one line instead
  ## of a survey: arkham emits no merge point that is not a label. (The one
  ## exception is `(loop …)`, whose back edge nifasm emits internally.)
  g.killAllMirrors()
  g.ab.tree LabA64: g.ab.symDef name        # (lab :L)

proc emBr*(g: var CodeGen; tag: RiscInst; name: string) =
  g.ab.tree tag: g.ab.sym name              # (b L) / (beq L) / …

template emitLoop*(g: var CodeGen; body: untyped) =
  ## Structured infinite loop `(loop (stmts …))`: nifasm emits the back-edge INTERNALLY,
  ## so no backward branch reaches the asm-NIF (keeps "every branch forward, back-edges
  ## are loops" true). `body` must branch FORWARD to a break/exit label defined AFTER the
  ## loop.
  ##
  ## The implicit back edge is why the store-forwarding mirrors are cleared here: the
  ## top of the body is a merge point with no label of its own, so nothing a register
  ## held before the loop may be assumed inside it.
  g.killAllMirrors()
  g.ab.tree LoopA64:
    g.ab.tree StmtsA64:
      body

proc cmpOperandUnsigned*(g: var CodeGen; c: Cursor): bool =
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

proc freeLvalTemps2*(g: var CodeGen; c: Cursor; addrIntact = false)

type AggrEnd* = object
  ## One end (source or destination) of a whole-aggregate copy, in the form the
  ## MACHINE can actually address it:
  ##   * a NAMED stack `(s)` slot — costs ZERO registers, each word addressed as
  ##     `(mem name off)` with the offset folded into the slot's own frame
  ##     displacement;
  ##   * an address already materialized in a register — costs one.
  ##
  ## Making the form explicit is what TIERS the copy's register demand: two named
  ## ends need only the transfer register, one named end needs two, and only a copy
  ## between two computed addresses needs three. Reducing every source to an address
  ## in a register first — "one path for all forms" — made three the price of EVERY
  ## copy, and three is one more bridge than any other step in this emitter wants.
  ## Ported from x86-64, where the same change is what stopped the emit-time staging
  ## pool running dry under `-d:danger`.
  slot*: string        ## non-empty ⇒ a named stack slot
  reg*: Reg            ## else, the register holding the aggregate's address

proc slotEnd*(name: string): AggrEnd {.inline.} = AggrEnd(slot: name, reg: NoReg)
proc regEnd*(r: Reg): AggrEnd {.inline.} = AggrEnd(slot: "", reg: r)

proc bridgeRegs*(g: CodeGen): seq[Reg] {.inline.} =
  ## THE emitter's scratch: every register this back end may take transiently and
  ## the allocator may never assign. NOT a constant — the AArch64 registers are
  ## x14/x15/x16, and slot R14 is `lr` on Cortex-M, where taking it as scratch
  ## destroys the return address and shows up as a hang at `bx lr` with nothing at
  ## the crash site to suggest why.
  ##
  ## THREE, while `EmitterBridgeDemand` is two — one register of SLACK, and that
  ## slack is what makes every step reachable with its full declaration free
  ## (`tightCompositions == 0`, checked on every emission under `-d:arkhamStress`).
  ## It was not always slack: until `AggrEnd` tiering landed, an aggregate copy
  ## between two computed ends really did hold three at once.
  ##
  ## The third is the produce bridge (x16 / r8), last in the order deliberately: its
  ## own call sites (`produceIntoMem2` and friends, via `takeProduceBridge`) still
  ## get it first, and the staging draw reaches it only where it would otherwise
  ## have had nothing.
  g.md.bridgeRegs

proc liveBridges*(g: CodeGen): int =
  ## How many DISTINCT reserved bridges are live right now. BOUND or merely
  ## RESERVED: `produceIntoMem2` threads its bridge into `emitValue2` UNBOUND on
  ## purpose (a leaf may produce raw into it, and only then is it bound for the
  ## store), holding it with `pickedRegs` alone — so a bound-only count would miss
  ## precisely the site whose invariant this is. Counting bound-only reports a
  ## peak-across-recursion of 1 where the truth is 2.
  var seen: set[Reg] = {}
  for r in g.md.bridgeRegs:
    if r notin seen and (g.rb.isBoundTemp(r) or r in g.pickedRegs):
      seen.incl r; inc result

proc distinctBridges*(g: CodeGen): int =
  var seen: set[Reg] = {}
  for r in g.md.bridgeRegs:
    if r notin seen: seen.incl r; inc result

proc heldBridgeNames*(g: CodeGen): string =
  var seen: set[Reg] = {}
  for r in g.md.bridgeRegs:
    if r notin seen and (g.rb.isBoundTemp(r) or r in g.pickedRegs):
      seen.incl r
      if result.len > 0: result.add ", "
      result.add $r

const BridgeCheck* = defined(arkhamStress) or defined(arkhamBridgeCheck) or
                     not defined(release)
  ## Whether the I1 budget assertions are compiled in. ON in a debug build and in
  ## every `-d:arkhamStress` binary — the pool-dry pass is exactly where the margin
  ## is thin — and OFF in a shipped release build, where they would cost a walk of
  ## three registers per recursive emit call for a property the stress pass has
  ## already established over the whole corpus.

proc bridgeBudgetFailed(g: CodeGen; what: string; need: int) {.noinline.} =
  ## Two different failures wear this assertion, and they want different fixes.
  let head = "arkham " & g.md.targetName & ": I1 bridge budget — " & what &
             " needs " & $need & " of " & $g.distinctBridges() &
             " reserved bridges"
  if need > g.distinctBridges():
    # Not a composition at all: the step does not fit this machine even alone.
    raiseAssert head & ", which is more than this target reserves at all, in " &
      "proc " & g.curProcName & ". Either the machine model is short a bridge " &
      "(RV32 shipped `[R29, R30, R30]` and had two where it claimed three — see " &
      "`machinedesc.checkMachine`) or the step must be written to a smaller " &
      "budget: see design.md, \"Making the reservation a bound instead of a " &
      "measurement\", I3."
  raiseAssert head & ", but " & $g.liveBridges() & " (" & g.heldBridgeNames() &
    ") are already held by an ENCLOSING step, in proc " & g.curProcName &
    ". A COMPOSITION failure, not pressure: the allocator never owns these " &
    "registers, so no amount of spilling elsewhere frees one, and the step that " &
    "fails is not the step that is wrong. The fix belongs to the HOLDER — it " &
    "must release across the recursion, the way `genNestedAggrField` builds its " &
    "value into a frame slot BEFORE taking its bridges. See design.md, " &
    "\"Making the reservation a bound instead of a measurement\", I1."

var tightCompositions*: int = 0
  ## How many times a step was entered with less than its DECLARED worst case
  ## free. See `bridgeScopePush`.

var lastResortTakes*: int = 0
  ## How many times a step took a bridge past its declaration BECAUSE every
  ## alternative was gone. Counted, never asserted — see `tryTakeBridge`'s
  ## `lastResort`.

proc bridgeScopePush*(g: var CodeGen; demand: BridgeDemand; what: string) =
  ## Open a declared bridge scope.
  ##
  ## Two conditions, and keeping them apart is the whole content of this proc.
  ##
  ##  * **Progress (I1), an ERROR.** A step entered with every bridge already held
  ##    cannot emit anything at all, whatever it turns out to be. One free is the
  ##    weakest requirement that rules that out, and it is the one that holds.
  ##  * **Worst case (I2), a COUNT.** A declaration is static; demand is not. A
  ##    step that declares two is not obliged to take two on this path, so being
  ##    entered with only one free is not yet wrong — it is only *unproven*. Made
  ##    an error, it would reject compositions that provably never bite; ignored,
  ##    it would hide the ones that eventually will.
  ##
  ## The gap between the two is therefore counted, not asserted, and that count is
  ## the work queue for I3: each one is a place where a fixed reservation stops
  ## being demonstrably sufficient and starts being merely lucky. Measured on the
  ## corpus it is reached only under `ARKHAM_STRESS`, and only by `emitLvalue2`
  ## entered from inside another two-bridge step.
  if g.liveBridges() + 1 > g.distinctBridges():
    if g.lastResortBridges == {}:
      bridgeBudgetFailed(g, what, 1)
    else:
      # A step already went past its declaration because it had nothing else. The
      # emitter is knowingly outside its budget until that bridge comes back, so
      # this shortfall is the escape working rather than an unaccounted
      # composition — counted, like a tight one, and not asserted.
      inc tightCompositions
  if g.liveBridges() + ord(demand) > g.distinctBridges():
    inc tightCompositions
  when defined(arkhamBridgeDbg):
    if g.liveBridges() > dbgPeakHeldAtRecursion:
      dbgPeakHeldAtRecursion = g.liveBridges()
  g.bridgeScopes.add (base: g.liveBridges(), cap: ord(demand), what: what)

proc bridgeScopePop*(g: var CodeGen) =
  ## Close it, checking the step gave back exactly what it took. A LEAK is not a
  ## crash here and never would be — the register simply stays bound, and the next
  ## step silently runs with one fewer, until something far away asserts. This is
  ## the only place that difference is visible.
  let sc = g.bridgeScopes.pop()
  if getCurrentException() != nil:
    # Unwinding already. A step abandoned mid-way has of course not released its
    # bridges, so the leak below is a CONSEQUENCE of the failure in flight, and
    # raising it here would replace the real diagnostic with a derived one — which
    # is exactly what it did on first use: an under-declared `genAconstr2` reported
    # itself as a leak in `genStore2` three frames out.
    return
  let live = g.liveBridges()
  if live > sc.base:
    raiseAssert "arkham " & g.md.targetName & ": I2 bridge leak — " & sc.what &
      " left " & $(live - sc.base) & " of its " & $sc.cap &
      " declared bridge(s) still held (" & g.heldBridgeNames() &
      ") in proc " & g.curProcName &
      ". Every `takeBridge` needs its `dropBridge` on every path out."

proc bridgeOverDeclared*(g: CodeGen) {.noinline.} =
  let sc = g.bridgeScopes[^1]
  raiseAssert "arkham " & g.md.targetName & ": I2 bridge budget — " & sc.what &
    " declared " & $sc.cap & " bridge(s) and is taking " &
    $(g.liveBridges() - sc.base + 1) & ", in proc " & g.curProcName &
    ". Raise the declaration to the matching `BridgeDemand` member if the step " &
    "really holds that many at once — which forces every machine model to " &
    "reserve one more (`machinedesc.checkMachine`) and is meant to be a decision, " &
    "not a default. Otherwise the step is holding a bridge it could have " &
    "released: see design.md, \"Making the reservation a bound instead of a " &
    "measurement\", I2."

proc bridgeRaise*(g: var CodeGen; demand: BridgeDemand; what: string) =
  ## Widen the innermost declaration for the rest of the current step.
  ##
  ## For a demand a step only discovers as it runs. `prematLval2` is the case:
  ## whether an lvalue's address chain needs a second bridge depends on whether
  ## its base or index turned out to be SPILLED, which the walk that planned the
  ## lvalue could not say. Raising is not a new scope — the registers are taken by
  ## `prematLval2` and released by the consumer's `freeLvalTemps2`, a lifetime that
  ## deliberately spans several procs and belongs to the enclosing step — so it is
  ## that step's declaration that has to grow, and it reverts when the step's own
  ## scope pops.
  when BridgeCheck:
    if g.bridgeScopes.len > 0 and ord(demand) > g.bridgeScopes[^1].cap:
      g.bridgeScopes[^1].cap = ord(demand)
      g.bridgeScopes[^1].what = what
      if g.bridgeScopes[^1].base + ord(demand) > g.distinctBridges():
        inc tightCompositions

proc bridgeTakeAllowed*(g: CodeGen): bool {.inline.} =
  ## Whether one more take fits the innermost declaration.
  g.bridgeScopes.len == 0 or
    g.liveBridges() - g.bridgeScopes[^1].base < g.bridgeScopes[^1].cap

template withBridges*(g: var CodeGen; demand: BridgeDemand; what: string;
                      body: untyped) =
  ## I2: declare this step's bridge demand around the takes that realise it.
  ##
  ## `bdTransient` is the DEFAULT — every recursive emit entry opens one — so only
  ## a step that holds two or three at once needs to say so. Placing the
  ## declaration above the first take is the point: the assertion then names the
  ## step and its budget, instead of blaming whichever take happened to be the one
  ## that found nothing left.
  when BridgeCheck:
    g.bridgeScopePush(demand, what)
    try:
      body
    finally:
      g.bridgeScopePop()
  else:
    body

template bridgeStep*(g: var CodeGen; what: string; demand = bdTransient) =
  ## The implicit scope every RECURSIVE emit entry opens (`emitValue2`,
  ## `genStore2`, `emitLvalue2`). Scoped to the rest of the enclosing proc via
  ## `defer`, because those procs return from many places.
  when BridgeCheck:
    g.bridgeScopePush(demand, what)
    defer: g.bridgeScopePop()


when defined(arkhamBridgeDbg):
  proc dbgNoteBridges*(g: CodeGen; r: Reg) =
    let n = g.liveBridges()
    if n > dbgPeakBridges: dbgPeakBridges = n
    if n >= 2:
      var frames: seq[string] = @[]
      for ln in getStackTrace().splitLines():
        if "arkham/risc" in ln or "arkham/core" in ln:
          let i = ln.rfind(") ")
          if i >= 0: frames.add ln[i+2 .. ^1]
      # innermost first, skipping the take machinery itself
      var chain: seq[string] = @[]
      for k in countdown(frames.high, 0):
        let f = frames[k]
        if f in ["dbgNoteBridges", "tryTakeBridge", "takeBridge",
                 "takeProduceBridge"]: continue
        chain.add f
        if chain.len >= 3: break
      stderr.writeLine "CONC " & $n & " " & chain.join(" <- ")

proc dropBridge*(g: var CodeGen; r: Reg) =
  if r != NoReg: g.unbindTemp(r)

proc takeFBridge*(g: var CodeGen; bits: int): FReg =
  g.bindFTmp(g.md.floatBridgeReg, bits); g.md.floatBridgeReg

proc dropFBridge*(g: var CodeGen) =
  g.unbindFTmp(g.md.floatBridgeReg)

proc takeTmp*(g: var CodeGen; slot: AsmSlot): Location =
  ## Reserve an expression-temp GPR (lazy-bound by its consumer); an `etmp`
  ## spill-slot Location when the pools are dry.
  let r = g.pickTempReg()
  if r == NoReg:
    let nm = g.mintSpillName("etmp")
    g.plan.addSpillTemp(nm, slot)
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedRegs.incl r
  result = regLoc(r, slot, isTemp = true)

proc takeFTmp*(g: var CodeGen; slot: AsmSlot): Location =
  ## The SIMD twin of `takeTmp` (an `eftmp` slot when the float pools are dry).
  let f = g.pickFTempReg()
  if f == NoFReg:
    let nm = g.mintSpillName("eftmp")
    g.plan.addSpillTemp(nm, slot, isFloat = true)
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedFRegs.incl f
  result = fregLoc(f, slot, isTemp = true)

proc takeHeld*(g: var CodeGen; what: string; canSpill = false): Location =
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
    if cs notin g.pickedRegs and cs notin g.rawHomeRegs and not g.plan.isSealed(cs) and
       not g.rb.isAccum(cs) and not g.rb.isBound(cs):
      g.plan.usedCallee.incl cs                    # the (post-body) prologue saves it
      g.releaseStaleName(cs)
      g.pickedRegs.incl cs
      return regLoc(cs, ScalarSlot, isTemp = true)
  if canSpill:
    let nm = g.mintSpillName("held")
    g.plan.addSpillTemp(nm, ScalarSlot)
    return namedStackLoc(nm, ScalarSlot, spillTemp = true)
  raiseAssert "arkham a64n: out of registers for " & what &
              " in proc " & g.curProcName & " (nothing to spill), picked: " &
              $g.pickedRegs

proc tryTakeHeld*(g: var CodeGen): Location =
  ## `takeHeld` for a caller that HAS another answer when no survivor is free:
  ## reports exhaustion as an `Undef` Location instead of asserting. Reserves the
  ## register exactly as `takeHeld` does — the `pickedRegs` flag is what closes the
  ## reserve→bind gap, and dropping it lets the very next pick hand the same register
  ## out from under the value this one is holding.
  let r = g.pickHeldReg()
  if r == NoReg: return dontCare
  g.pickedRegs.incl r
  result = regLoc(r, ScalarSlot, isTemp = true)

proc pickStagingA64*(g: var CodeGen): Reg =
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
  ## is still refused, so nothing owned can be clobbered. A MIRROR is not owned
  ## (`RegMapping` rule 1): its value is still in memory, and `releaseStaleName`
  ## below retires it as the register is handed over.
  for r in g.md.intTempRegs:
    if r notin g.pickedRegs and r notin g.rawHomeRegs and not g.plan.isSealed(r) and
       not g.rb.isAccum(r) and (not g.rb.isBound(r) or g.rb.isMirror(r)):
      g.releaseStaleName(r); return r
  for r in g.md.intCalleeSaved:
    if r notin g.pickedRegs and r notin g.rawHomeRegs and not g.plan.isSealed(r) and
       not g.rb.isAccum(r) and not g.rb.isBound(r):
      g.plan.usedCallee.incl r                     # the (post-body) prologue saves it
      g.releaseStaleName(r); return r
  if g.md.intTempRegs.len == 0:
    # Only where there is no volatile pool at all, and last: the ARGUMENT
    # registers. Cortex-M's pool is EMPTY by design — its only caller-saved
    # registers ARE r0–r3, so
    # letting the ALLOCATOR home a value there means handing out r1 as a temp while
    # r1 holds staged argument word 1 (see `machine_m.IntTempRegs`, where that bug
    # is written up). The pool stays empty for exactly that reason.
    #
    # What this adds is narrower than a pool: a TRANSIENT the emitter takes and
    # gives back before anything else can want the register. The one thing that
    # could want it is the marshalling, and `stagedArgs` is the emitter saying so —
    # it holds a call's arguments from its `(prepare …)` to its `(call)`, and the
    # incoming parameters for as long as the prologue runs. Outside those windows
    # nothing on this target has a claim on r0–r3.
    #
    # Only a transient: a value that must survive a CALL asks `takeHeld`, which is
    # callee-saved-only and untouched by this.
    for r in g.md.intArgRegs:
      if r notin g.stagedArgs and r notin g.pickedRegs and r notin g.rawHomeRegs and
         not g.plan.isSealed(r) and not g.rb.isAccum(r) and
         (not g.rb.isBound(r) or g.rb.isMirror(r)):
        g.releaseStaleName(r); return r
  NoReg

proc freeVal*(g: var CodeGen; loc: Location) {.inline.} =
  ## Release a reserved/resolved temp — the emit-time `releaseTmp`: clear the
  ## pick flag and, if a consumer bound it, `(kill)` the binding. A no-op for
  ## every other location kind.
  ##
  ## A register that has become a MIRROR was already released — by the store that
  ## made it one — and its binding is now the map's, not this value's. Killing it
  ## here would undo the forwarding at the very moment it becomes useful (the
  ## caller of `storeScalar2` frees the value it just stored).
  if loc.kind == InReg and loc.isTemp:
    g.pickedRegs.excl loc.r
    if not g.rb.isMirror(loc.r): g.unbindTemp(loc.r)
  elif loc.kind == InFReg and loc.isTemp:
    g.pickedFRegs.excl loc.f
    if not g.rb.isFMirror(loc.f): g.unbindFTmp(loc.f)

proc resolveDestE*(g: var CodeGen; dest: var Location; natural: Location) =
  ## Resolve a LEAF destination constraint against the value's natural location
  ## — the emit-time twin of the allocator's `resolveDest` (lazy-bound temps).
  case dest.kind
  of Undef: dest = natural
  of NeedsReg:
    dest = (if natural.kind == InReg: natural else: g.takeTmp(natural.typ))
  of RegOrImm:
    dest = (if natural.kind in {InReg, Imm}: natural else: g.takeTmp(natural.typ))
  else: discard                              # fixed InReg/InFReg/NamedStack/…: keep

proc forceRegDestE*(g: var CodeGen; dest: var Location) =
  ## Ensure a value's `dest` is a register (or, pool-dry, an etmp slot the
  ## produce-into path serves).
  case dest.kind
  of NeedsReg, RegOrImm: dest = g.takeTmp(dest.typ)
  of Undef: dest = g.takeTmp(ScalarSlot)
  else: discard

proc emImm*(g: var CodeGen; loc: Location) =
  ## Emit an immediate VALUE operand: `(nil)` for a null pointer, else the integer.
  if isNilImm(loc): g.ab.nilValue()
  else: g.ab.intLit loc.ival

proc placeImm*(g: var CodeGen; dest: Reg; loc: Location) =
  ## `mov dest, <imm>` — emits `(mov dest (nil))` for a nil so the register binds to
  ## the `(nil)` type, else the ordinary `movImm`.
  if isNilImm(loc):
    g.ab.tree MovA64: (g.emReg dest; g.ab.nilValue())
  else: g.movImm(dest, loc.ival)

proc globalIsGvarSlot*(g: var CodeGen; name: string): bool =
  ## True when `name` is a real `.bss`/`.data` gvar (nifasm `GvarD`, carrying a
  ## page-offset patch site) — the `gload`/`gstore` fold target — rather than a
  ## read-only `const` blob (`RodataD`), which is a label with no gvar site. Mirrors
  ## `genGlobal`'s split exactly: rodata iff the decl is a `const` WITH a value.
  # The fold is an `adrp`+folded-access pair. A target without it materializes a
  # global's address absolutely (Cortex-M: movw/movt, patched once the .bss
  # layout is known), so the address and the access stay separate there.
  if PcRelGlobalFold notin g.md.caps: return false
  let si = g.lookupSym(name)
  if si.cat != scGlobal: return false
  var d = si.decl
  if d.stmtKind != ConstS: return true                  # a `var`/gvar → GvarD
  inc d; skip d; skip d                                  # const: name, pragmas, type
  result = not (d.hasMore and d.kind != DotToken)        # value-less const → gvar slot

proc globalAddrSlot*(g: var CodeGen; name: string): AsmSlot =
  ## The slot for an address temp about to hold `&global` / `&threadvar`:
  ## `(ptr <its declared type>)`. The `(mem p)` deref built on that temp then carries
  ## the PRECISE pointee type instead of nifasm's generic `(i 64)` reading — without
  ## which storing a pointer-typed value, or a `(nil)`-typed one (`exc = nil` into a
  ## `ptr Exception` threadvar), into a pointer global/threadvar is a type error
  ## (nifasm is strict). x64's `scalarMemMov` types its store-address temp the same
  ## way. The type comes from the DECLARATION, so there is no case with no answer.
  typeToSlot(g.prog.ptrTypeOf(g.globalDeclType(name)))

proc restoreMemBase2*(g: var CodeGen; pos: int) =
  if g.savedHomes.hasKey(pos):
    g.dropBridge g.plan.planned(pos).r
    g.plan.planAtEmitTime(pos, g.savedHomes[pos])
    g.savedHomes.del pos

proc inlineAggrHome*(g: var CodeGen; c: Cursor): string =
  ## The stack slot standing in for an aggregate CONSTRUCTOR used as an lvalue base —
  ## `[a, b][i]`, which hexer hands over as `(at (aconstr …) i)`. A constructor is a
  ## value, not a location, so there is nothing to address until one exists; this
  ## names the slot that `prematLval2` builds it into and `emLvalAddr2` then reads.
  ## Keyed on the node's position, so both passes name the same slot without a side
  ## table.
  synth("lvaltmp") & $g.posOf(c) & ".0"

proc emLvalAddr2*(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (operand of a `(mem …)`/`(lea
  ## …)`), reading any embedded value register from its pre-allocated `locs`.
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.plan.locationOfSym(nm, cursorToPosition(g.buf[], c))
    if loc.kind == NoLoc:                                 # module-level global base
      let planned = g.plan.planned(g.posOf(c))
      # An allocated register, or — when the walk had none to give — the bridge
      # `prematLval2` derived `&g` into late (see `lateGlobalBase`).
      let baseReg = if planned.kind == InReg: planned.r
                    else: g.lvalGlobBase[g.posOf(c)]
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                               # (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg baseReg
    elif loc.kind == InReg and g.varType.hasKey(nm):      # by-ref aggregate param (pointer)
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(g.varType[nm])
        g.emReg loc.r
    elif loc.kind == StackPtr:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(loc.pointeeType)
        g.emReg g.lvalGlobBase[g.posOf(c)]
    elif loc.kind == InRegPair:
      raiseAssert "arkham a64n: address of InRegPair local " & nm
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
          else: g.emReg g.plan.planned(g.posOf(cc)).r          # register index
          skip cc
          if g.plan.aux.hasKey(atPos) and g.plan.aux[atPos].scratch.len > 0:
            g.emReg g.plan.aux[atPos].scratch[0]            # non-scale stride scratch
          while cc.hasMore: skip cc
    of DerefC:
      var pointee = g.getType(c)
      var cc = c
      cc.into:
        let pReg = g.plan.planned(g.posOf(cc))
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
          let pReg = g.plan.planned(g.posOf(cc))
          g.ab.tree CastX:
            g.ab.aptrType:
              if elem.kind == Symbol: g.ab.sym symName(elem)
              else: g.genTypeBody(elem)
            g.emReg pReg.r
          skip cc                                         # past pointer
          case cc.kind                                    # index
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else: g.emReg g.plan.planned(g.posOf(cc)).r
          skip cc
          if g.plan.aux.hasKey(patPos) and g.plan.aux[patPos].scratch.len > 0:
            g.emReg g.plan.aux[patPos].scratch[0]           # non-scale stride scratch
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
            let pReg = g.plan.planned(g.posOf(dc))
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
    let l = g.plan.planned(p)
    if l.kind == InReg: acc.incl l.r

proc strideRecycle*(g: CodeGen; idxCur, baseCur: Cursor): Reg =
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
  let l = g.plan.planned(g.posOf(idxCur))
  if l.kind != InReg or not l.isTemp or not g.rb.isBoundTemp(l.r): return NoReg
  var baseRegs: set[Reg] = {}
  g.lvalMaterializedRegs(baseCur, baseRegs)
  if l.r in baseRegs: NoReg else: l.r

proc releaseStrideScratch(g: var CodeGen; atPos: int) =
  ## Release it after the consuming `(mem …)`/`(lea …)`. `dropBridge` and the pool
  ## release are the same two operations, so the only difference a bridge makes is
  ## that the position stops being marked.
  let r = g.plan.aux[atPos].scratch[0]
  g.lvalStrideOnBridge.excl atPos
  g.pickedRegs.excl r
  g.unbindTemp(r)

proc lateGlobalBase*(g: var CodeGen; c: Cursor): bool =
  ## Is `c` a module-level global lvalue base that the walk could NOT give an
  ## allocated register? Then its address is materialized LATE — after the index it
  ## would otherwise have to survive — into a staging bridge.
  ##
  ## A global's address is RE-DERIVABLE: `adrp`+`add` of a link-time label, no inputs.
  ## So the step never actually needed a register that outlives a call; it only needed
  ## one because `prematLval2` materializes the base BEFORE the index. Deriving it
  ## after instead costs nothing at run time and removes the demand entirely — the
  ## same reasoning `fieldLocGlob` states on x64, and what design.md means by fixing
  ## it "in the demand of the step that asked" rather than in a bigger pool.
  c.kind == Symbol and
    g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc and
    g.plan.planned(g.posOf(c)).kind != InReg

proc lateSpilledBase*(g: var CodeGen; c: Cursor): bool =
  ## The same argument as `lateGlobalBase`, for a base that is not a global: a base
  ## the allocator SPILLED is re-derivable too. Its value sits at a fixed frame
  ## offset and reloading it is one `ldr` with no inputs, so materializing it before
  ## the index it must then survive buys nothing and costs a bridge held across the
  ## whole index evaluation.
  ##
  ## That holding is the composition I3 exists to remove. Measured, it is the ONLY
  ## one left: an outer `p[i]` whose pointer spilled holds a bridge, a
  ## `produceIntoMem2` inside the index holds the produce bridge, and the inner
  ## address chain then declares two with one free. Deriving the base late drops the
  ## outer holder and with it the composition — at no run-time cost, because the
  ## `ldr` happens either way and only its POSITION changes.
  ##
  ## Restricted to a spill TEMP (`etmp`/`held`, minted per value position) rather
  ## than any stack home. Moving a load later is only sound if nothing in between
  ## can write the slot, and a minted temp is unnameable — no source-level store and
  ## no callee can reach it. A named local's home would need `Plan.aliasable`
  ## consulted, and address-taken locals are exactly what arkham has no points-to
  ## analysis to bound; the temps are where the demand actually is.
  let loc = g.plan.planned(g.posOf(c))
  loc.kind == NamedStack and loc.spillTemp

proc binA64Op*(g: var CodeGen; c: Cursor): RiscInst =
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

proc isLogicalImmA64(v: int64): bool =
  ## Is `v` an AArch64 "bitmask immediate" — the form `and`/`orr`/`eor` take
  ## directly? Every bitfield mask is one (0xff, 0xf, 0x1ff, 0x3fff, …), so this
  ## is the difference between `and x, y, #0xff` and materializing the constant
  ## into a register first. nifasm owns the encoding; this only has to agree with
  ## it on WHICH values are representable, and it answers with the same routine.
  arm64.isLogicalImm(cast[uint64](v))

proc logicalImmOk*(g: CodeGen; v: int64): bool {.inline.} =
  ## Whether `v` may ride along as an immediate operand of `and`/`orr`/`eor`.
  ## The targets encode constants completely differently, so this asks the
  ## description which set the one being emitted for uses.
  case g.md.immStyle
  of ThumbExpandImm: thumbimm.isModifiedImm(v)
  of A64Bitmask: isLogicalImmA64(v)
  of X86Imm32: v >= low(int32) and v <= high(int32)
  of RvImm12: v >= -2048 and v <= 2047

proc normalizeUnaryWidth*(g: var CodeGen; resTypeC: Cursor; rD: Reg) =
  ## The `neg`/`bitnot` twin of `normalizeBinWidth`. Both are computed 64-bit wide,
  ## so on a sub-64-bit type they leave bits ABOVE the type width: `~15'u8` is
  ## `0xFFFF_FFFF_FFFF_FFF0`, not `0xF0`, and a following unsigned compare (or
  ## `lsr`, or `udiv`) reads the stale bits. Signed types need it too, but only at
  ## the boundary — `neg` of `-128'i8` is `+128`, whose i8 value is `-128` again.
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

proc isUnsigned32*(resTypeC: Cursor): bool =
  ## True for a `(u 32)` result — the case where an add/sub/mul W-form gives the
  ## fully-normalized (zero-extended) value for free, letting emitBin2 both emit the
  ## `addw`/`subw`/`mulw` tag and skip the `normalizeBinWidth` shift-pair.
  let slot = typeToSlot(resTypeC)
  slot.kind == AUInt and slot.size == 4

proc normalizeBinWidth*(g: var CodeGen; resTypeC: Cursor; rD: Reg; op: RiscInst) =
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

proc fbinA64Op*(ek: LengExpr): RiscInst =
  case ek
  of AddC: FaddA64
  of SubC: FsubA64
  of MulC: FmulA64
  of DivC: FdivA64
  else: raiseAssert "arkham a64n: fbinA64Op " & $ek

proc atomicBits*(g: var CodeGen; ptrArg: Cursor): int =
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

proc wsfx*(bits: int): string =
  ## Trailing access-width operand for the LL/SC asm-NIF text (omitted for 64-bit, the
  ## nifasm parse default — keeps the common case's output unchanged).
  if bits != 64: &" {bits}" else: ""

proc instrOperandReg*(g: CodeGen; cur: Cursor): Reg =
  ## The register an already-emitted `(instr …)` operand landed in. `allocInstr`
  ## asked for `NeedsReg` on every operand a lowering reads, so anything else here
  ## is an allocator bug, not a source-level condition.
  let l = g.plan.planned(cursorToPosition(g.buf[], cur))
  if l.kind != InReg:
    raiseAssert "arkham a64n: intrinsic operand is not in a register"
  l.r

proc releaseStaleName*(g: var CodeGen; r: Reg) =
  ## A register about to be used as RAW scratch must carry no stale named-local
  ## binding: `emOp`/`emReg` would emit that typed name instead of the `(xN)` tag,
  ## and its type would not match the pointee-typed exclusive access. `(kill)` the
  ## binding so the raw tag is what comes out. The x86-64 twin does the same.
  if r != NoReg:
    let dead = g.rb.takeBinding(r)
    if dead.len > 0:
      g.ab.tree KillA64: g.ab.sym dead

proc emitAtomicRmw2*(g: var CodeGen; dst, p, v: Reg; opStr: string;
                    isXchg, returnNew: bool; bits: int) =
  ## `loop: ldaxr old,[p]; new = old op v (or v, for an exchange); stlxr st,new,[p];
  ## cmp st,0; beq done` — a non-zero status means another agent won the line, so
  ## the loop falls through to nifasm's internal back-edge and re-reads.
  ##
  ## `old`/`new`/`st` are the dedicated scratch (`AtomicScratchRegs`); `p` and `v`
  ## are only ever read, which is what lets `dst` alias either of them.
  let lDone = g.freshLabel()
  let (pS, vS) = (g.emOp p, g.emOp v)
  let old = g.emOp g.md.atomicScratch[0]
  let neu = g.emOp g.md.atomicScratch[1]
  let st = g.emOp g.md.atomicScratch[2]
  let w = wsfx(bits)
  let update = if isXchg: &"(mov {neu} {vS})" else: &"(mov {neu} {old}) ({opStr} {neu} {vS})"
  # Structured `(loop …)`: nifasm emits the back-edge internally. The exclusive
  # store SUCCEEDS when `st == 0` → the forward `(beq lDone)` leaves the loop.
  g.ab.splice &"(loop (stmts (ldaxr {old} {pS}{w}) " & update & " " &
              &"(stlxr {st} {neu} {pS}{w}) (cmp {st} 0) (beq {lDone}))) (lab :{lDone})"
  g.movReg(dst, g.md.atomicScratch[if returnNew: 1 else: 0])

proc emAtomicLoadM*(g: var CodeGen; dst, p: Reg; bits: int) =
  ## `dst ← the bits-wide cell at [p]`, zero-extended. Not an exclusive load:
  ## nothing is claimed, because nothing is going to be stored back.
  # Each arm emits its own tree: `ldrb`/`ldrh` are `MInst` members and `ldr` is an
  # `RiscInst` one (the shared spelling lives in the A64 enum), so there is no
  # common variable to select into — the tag IDS are what nifasm reads, and those
  # agree.
  case bits
  of 8:
    g.ab.tree LdrbM:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
  of 16:
    g.ab.tree LdrhM:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
  else:
    g.ab.tree LdrA64:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)

proc emAtomicStoreM*(g: var CodeGen; p, src: Reg; bits: int) =
  case bits
  of 8:
    g.ab.tree StrbM:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src
  of 16:
    g.ab.tree StrhM:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src
  else:
    g.ab.tree StrA64:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src

proc emitAtomicRmwM*(g: var CodeGen; dst, p, v: Reg; opTag: RiscInst;
                    isXchg, returnNew: bool; bits: int) =
  ## `loop: ldrex old,[p]; new = old op v (or v); strex st,new,[p]; cmp st,0;
  ## beq done` — a non-zero status means another agent won the line, so the loop
  ## falls through to nifasm's internal back-edge and re-reads.
  ##
  ## `old`/`new`/`st` are the three reserved bridges; `p` and `v` are only ever
  ## read, which is what lets `dst` alias either of them.
  let old = g.md.atomicScratch[0]
  let neu = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lDone = g.freshLabel()
  g.emitLoop:
    g.ab.tree LdrexM: (g.emReg old; g.emReg p; g.ab.intLit bits)
    if isXchg:
      g.ab.tree MovA64: (g.emReg neu; g.emReg v)
    else:
      g.ab.tree MovA64: (g.emReg neu; g.emReg old)
      g.ab.tree opTag: (g.emReg neu; g.emReg v)
    g.ab.tree StrexM: (g.emReg st; g.emReg neu; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lDone)
  g.emLab(lDone)
  # A sub-word RMW computed on a zero-extended `old`, so the result needs no
  # narrowing: `strex{b,h}` stores the low bits and the returned value is what
  # the cell holds.
  g.movReg(dst, if returnNew: neu else: old)

proc emitAtomicCasM*(g: var CodeGen; ret, p, ep, d: Reg; bits: int) =
  ## Compare-and-swap. The FAILURE path is the whole protocol: it publishes what
  ## the cell actually held through `ep`, so the caller retries against the value
  ## it now holds — and it must `clrex` first, because it leaves the pair without
  ## the store and the monitor would otherwise stay armed on this address.
  let exp = g.md.atomicScratch[0]
  let old = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lSucc = g.freshLabel()
  let lFail = g.freshLabel()
  let lDone = g.freshLabel()
  g.emAtomicLoadM(exp, ep, bits)
  g.emitLoop:
    g.ab.tree LdrexM: (g.emReg old; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg old; g.emReg exp)
    g.emBr(BneA64, lFail)
    g.ab.tree StrexM: (g.emReg st; g.emReg d; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lSucc)
  g.emLab(lSucc)
  g.movImm(ret, 1)
  g.emBr(BA64, lDone)
  g.emLab(lFail)
  g.ab.keyword ClrexM
  g.emAtomicStoreM(ep, old, bits)
  g.movImm(ret, 0)
  g.emLab(lDone)

proc proctypeOfTarget*(g: var CodeGen; targetCur: Cursor): Cursor =
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

proc emByteAtImm*(g: var CodeGen; p: Reg; off: int) =
  ## `(mem (at (cast (aptr (u 8)) p) off))` — the byte at `[p + off]` (immediate offset).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg p
      g.ab.intLit off

proc emWordAtSlot*(g: var CodeGen; name: string; off: int) =
  ## `(cast (u W) (mem name off))` — the word at byte offset `off` of the NAMED stack
  ## slot `name`. The pointer twin `emWordThroughPtr` needs the slot's ADDRESS in a
  ## register first; this needs no register at all, because nifasm folds `off` into
  ## the slot's own frame displacement — and bounds-checks it against the slot, which
  ## the register form cannot. (x64's `emWordAtSlot`, at the target's word width.)
  g.ab.tree CastX:
    g.ab.uintType(wordBits())
    g.ab.tree MemX:
      g.ab.sym name
      g.ab.intLit off.int64

proc emByteAtSlot*(g: var CodeGen; name: string; off: int) =
  ## The byte-granular `emWordAtSlot`, for a copy's sub-word tail.
  g.ab.tree CastX:
    g.ab.uintType(8)
    g.ab.tree MemX:
      g.ab.sym name
      g.ab.intLit off.int64

proc emWordAt(g: var CodeGen; e: AggrEnd; idx: int) =
  if e.slot.len > 0: g.emWordAtSlot(e.slot, idx * wordSize())
  else: g.emWordThroughPtr(e.reg, idx)

proc emByteAt(g: var CodeGen; e: AggrEnd; off: int) =
  if e.slot.len > 0: g.emByteAtSlot(e.slot, off)
  else: g.emByteAtImm(e.reg, off)

proc copyAggr*(g: var CodeGen; dst, src: AggrEnd; size: int; tmp: Reg) =
  ## THE one aggregate memcpy (a struct/array `store`): copy `size` bytes from `src` to
  ## `dst` through the bound scratch `tmp` — whole WORDS for the aligned bulk, then a
  ## sized byte tail. Layout-agnostic and byte-accurate (mirrors the x64 `copyAggr`).
  ##
  ## The word here must be the TARGET's, and must agree with `emWordThroughPtr`'s
  ## stride: that node emits `(aptr (u W))` and nifasm strides by the element
  ## width, so counting 8-byte words while it strides 4 copies exactly half the
  ## aggregate and reports no error at all.
  let w = wordSize()
  let words = size div w
  for i in 0 ..< words:
    g.ab.tree MovA64: (g.emReg tmp; g.emWordAt(src, i))
    g.ab.tree MovA64: (g.emWordAt(dst, i); g.emReg tmp)
  for b in 0 ..< (size - words * w):                     # sub-word tail, byte by byte
    let off = words * w + b
    g.ab.tree MovA64: (g.emReg tmp; g.emByteAt(src, off))
    g.ab.tree MovA64: (g.emByteAt(dst, off); g.emReg tmp)

proc copyAggr*(g: var CodeGen; dst, src: Reg; size: int; tmp: Reg) =
  ## Both ends are addresses in registers — the historical shape.
  g.copyAggr(regEnd(dst), regEnd(src), size, tmp)

proc emAggrElemAt*(g: var CodeGen; base: string; idx: int) =
  ## Bare `(at base idx)` ADDRESS tree (no `(mem …)` wrapper) — what a64's `lea` takes
  ## to compute `&base[idx]`. The element twin of `emAggrDot`.
  g.ab.tree AtX:
    g.ab.sym base
    g.ab.intLit idx

proc emPtrElemMem*(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## `(mem (at (cast (aptr ElemTy) p) idx))` — element `idx` of an array at `[p]`;
  ## nifasm scales by the element size. The array twin of `emPtrFieldMem`.
  var et = elemTy
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.genTypeBody(et)
        g.emReg p
      g.ab.intLit idx.int64

proc emPtrElemAt*(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## Bare `(at (cast (aptr ElemTy) p) idx)` address tree — for `lea` of an element
  ## through a pointer base (e.g. a global's address).
  var et = elemTy
  g.ab.tree AtX:
    g.ab.tree CastX:
      g.ab.aptrType: g.genTypeBody(et)
      g.emReg p
    g.ab.intLit idx.int64

proc fieldSlotByName*(g: var CodeGen; typeSym: SymId; field: string): AsmSlot =
  ## The asm slot of `typeSym.field` (so a `Field` destination carries the field's
  ## slot — a nested aggregate field has an `AMem` slot). Resolves the object body
  ## from the type's decl.
  var d = lookupType(g.prog, typeSym)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = slotOf(g.prog, fieldType(g.prog, d, field))
    while d.hasMore: skip d

proc fieldTypeByName*(g: var CodeGen; typeSym: SymId; field: string): Cursor =
  ## The declared (nominal) type cursor of `typeSym.field`.
  var d = lookupType(g.prog, typeSym)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = fieldType(g.prog, d, field)
    while d.hasMore: skip d

proc isAggrCopySrc*(c: Cursor): bool =
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo*(g: var CodeGen; dst: Location): (bool, int) =
  case dst.kind
  of NamedStack: (dst.typ.kind == AMem, dst.typ.size)
  of StackPtr: (true, dst.typ.size)      # `typ` is the pointee: always an aggregate
  of Glob, Tvar: (dst.typ.kind == AMem, dst.typ.size)
  of InRegPair: (true, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc resolveLvalVal*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED: decide (only) where an lvalue-embedded VALUE — a deref'd pointer, a
  ## computed index — will live; `prematLval2` materializes it later. A symbol
  ## resolves to its home, a literal to an immediate, a computed subtree to a
  ## reserved temp (its computation emits at premat time, dest-threaded).
  case c.kind
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == NoLoc: g.forceRegDestE(dest)     # a global/tvar value read
    else: g.resolveDestE(dest, home)
  of IntLit: g.resolveDestE(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.resolveDestE(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.resolveDestE(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  else: g.forceRegDestE(dest)                        # computed: reserve the result

proc reserveStrideScratch*(g: var CodeGen; atPos: int) =
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
      g.plan.aux[atPos] = ExprAux(scratch: @[NoReg])   # filled in by `prematLval2`
      return
    g.pickedRegs.incl r
    t = regLoc(r, ScalarSlot, isTemp = true)
  g.plan.aux[atPos] = ExprAux(scratch: @[t.r])

proc freeLvalTemps2*(g: var CodeGen; c: Cursor; addrIntact = false) =
  ## FUSED port of `releaseLvalTemps`: release the reserved picks of an
  ## lvalue's address computation — computed index/pointer temps, the a64
  ## stride scratch, and a global-base temp. (`unbindLvalTemps2` already
  ## unbinds; this clears the pick flags and frees the pool.)
  ##
  ## `addrIntact` says the consuming instruction only READ this address — a
  ## STORE through it, where the `(mem …)` is the destination operand. Then the
  ## global-base register still holds `&g` and is kept as an address mirror
  ## instead of being killed, so the next access to the same global is a `mov`
  ## rather than another `adrp`+`add`. A LOAD must never pass it: `mov base,
  ## [base]` reuses the base register as its destination.
  case c.kind
  of Symbol:
    if g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:
      let base = g.plan.planned(g.posOf(c))               # the global base temp/survivor
      if addrIntact and base.kind == InReg and base.isTemp and
         g.lookupSym(symName(c)).cat == scGlobal and
         g.mirrorAddrStored(base.r, g.prog.gvarRefName(symName(c))):
        discard                                          # kept as an address mirror
      else:
        g.freeVal(base)
  of TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.freeLvalTemps2(cc, addrIntact)
        while cc.hasMore: skip cc
    of DerefC:
      var cc = c
      cc.into:
        g.freeVal(g.plan.planned(g.posOf(cc)))
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      cc.into:
        g.freeLvalTemps2(cc, addrIntact)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.freeVal(g.plan.planned(g.posOf(cc)))
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(atPos) and g.plan.aux[atPos].scratch.len > 0:
        g.releaseStrideScratch(atPos)
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      cc.into:
        g.freeVal(g.plan.planned(g.posOf(cc)))
        skip cc
        if cc.kind notin {IntLit, UIntLit}:
          g.freeVal(g.plan.planned(g.posOf(cc)))
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(patPos) and g.plan.aux[patPos].scratch.len > 0:
        g.releaseStrideScratch(patPos)
    of BaseobjC:
      var cc = c
      cc.into:
        skip cc; skip cc
        g.freeLvalTemps2(cc, addrIntact)
        while cc.hasMore: skip cc
    else: discard
  else: discard

proc pow2Log*(g: var CodeGen; c: Cursor): int =
  ## `k` when the expression at `c` is the compile-time constant 2^k for k in 1..62,
  ## else -1. Goes through `tryConstFold` rather than pattern-matching a literal: the
  ## divisor that matters is spelled `sizeof(NifToken).uint`, not `4`, and the shared
  ## folder is the one place that already knows how to evaluate that (and `(suf …)`,
  ## `(conv …)`, and constant arithmetic besides). Folding here loses nothing — a
  ## compile-time constant has no side effect to drop by not emitting it.
  ##
  ## STRICTLY POSITIVE, so `k` stops at 62: 2^63 folds to a negative `int64` and
  ## `x div -9223372036854775808` is not `x lsr 63`. Excluding it costs an unsigned
  ## divide by 2^63 that no real code performs.
  let (ok, v) = g.tryConstFold(c)
  if not ok or v <= 0: return -1
  var u = uint64(v)
  if (u and (u - 1)) != 0'u64: return -1                 # not a power of two
  result = 0
  while u > 1'u64:
    u = u shr 1
    inc result
  if result < 1 or result > 62: result = -1

proc foldableFloatLeafE*(g: var CodeGen; c: Cursor): bool =
  c.kind == Symbol and g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind in {InFReg, NamedStack}

proc mirrorBranch*(t: RiscInst): RiscInst =
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

proc isCmpImmLeaf*(c: Cursor): bool =
  ## A bare integer literal, `(suf …)`/`(par …)` wrappers included: what `cmp`
  ## takes as an immediate — and, on the left, what costs a materialising `mov`.
  var cur = c
  if cur.kind == TagLit and cur.exprKind in {SufC, ParC}: inc cur
  result = cur.kind in {IntLit, UIntLit, CharLit}

proc armInoutTag*(op: IntrinsicOp): RiscInst =
  ## The two-address Arm form of a row that writes through operand 0. `(add D S)`
  ## is one tag for both Arm targets — nifasm dispatches on the arch — so only
  ## `not` differs: Thumb-2 spells it `mvn` and the AArch64 vocabulary has no
  ## row for it yet.
  case op
  of AddOp: AddA64
  of SubOp: SubA64
  of AndOp: AndA64
  of OrOp: OrrA64
  of XorOp: EorA64
  of ShlOp: LslA64
  of ShrOp: LsrA64
  of SarOp: AsrA64
  of NegOp: NegA64
  of NotOp:
    # Thumb-2 has `mvn`, but it is a two-OPERAND form (`(mvn D S)`) in a tag enum
    # of its own, and no row claims an Arm target for `not` yet. Refused by name
    # rather than approximated with an `eor #-1` this file invented.
    NopA64
  of IncOp, DecOp:
    # x86 has one-operand `inc`/`dec`; Arm's `add`/`sub` take the 1 as an
    # immediate, and inventing that operand here would be this file deciding what
    # `inc(d)` means. The row is refused by name.
    NopA64
  else: NopA64

proc atNeedsScratch*(g: var CodeGen; atNode: Cursor): bool =
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

proc atIndexIsReg*(g: var CodeGen; atNode: Cursor): bool =
  ## Whether the index of an `(at base idx)` / `(pat ptr idx)` lives in a register (any
  ## non-literal) rather than an immediate that folds to a displacement.
  var n = atNode
  result = false
  n.into:
    skip n                                       # the array base (at) / pointer (pat)
    if n.hasMore: result = n.kind notin {IntLit, UIntLit}
    while n.hasMore: skip n

proc slotWide*(name: string; off = 0): WideRef =
  WideRef(kind: wrSlot, name: name, off: off)

proc baseWide*(r: Reg; off = 0): WideRef =
  WideRef(kind: wrBase, base: r, off: off)

proc isWideSlot*(g: CodeGen; s: AsmSlot): bool {.inline.} =
  ## A scalar too wide for ONE REGISTER ON THIS TARGET — the whole trigger for
  ## everything in this file.
  ##
  ## Not a Cortex-M question, though it arrived as one. The test is
  ## `size > wordSize()`, which is false by construction wherever the word is
  ## eight bytes and true on any 32-bit target — so this file's `int64`
  ## arithmetic is inherited by the next 32-bit back end rather than rewritten
  ## for it. Every call site used to write `g.thumbM and g.isWideExpr(…)`, which
  ## said the same thing twice and said it in terms of the wrong fact.
  s.kind in {AInt, AUInt, ABool} and s.size > wordSize()

proc isWideExpr*(g: var CodeGen; c: Cursor): bool {.inline.} =
  g.isWideSlot(g.exprSlot(c))

proc dropWideRegs*(g: var CodeGen; rs: seq[Reg]) =
  for i in countdown(rs.high, 0): g.unbindTemp(rs[i])

proc emWideWord*(g: var CodeGen; w: WideRef; i: int) =
  ## Word `i` (0 = low, 1 = high; little-endian) of the 64-bit value at `w`, as a
  ## nifasm memory operand explicitly typed `(u 32)`.
  g.ab.tree CastX:
    g.ab.uintType(32)
    g.ab.tree MemX:
      case w.kind
      of wrSlot: g.ab.sym w.name
      of wrBase: g.emReg w.base
      g.ab.intLit int64(w.off + 4 * i)

proc wideLoad*(g: var CodeGen; d: Reg; w: WideRef; i: int) =
  g.ab.tree MovA64: (g.emReg d; g.emWideWord(w, i))

proc wideStore*(g: var CodeGen; w: WideRef; i: int; s: Reg) =
  g.ab.tree MovA64: (g.emWideWord(w, i); g.emReg s)

proc mintWideSlot*(g: var CodeGen): string =
  ## A fresh 8-byte `etmp` slot. Declared by the prologue's `spillTemps` loop,
  ## which sizes it from the slot's own `size` — see `emScalarStackVar`.
  result = g.mintSpillName("etmp")
  g.plan.addSpillTemp(result, WideSlot)

proc stripParens*(c: Cursor): Cursor =
  ## Look through `(par …)` / `(suf <value> "sfx")` to the value they wrap. A
  ## plain `inc` rather than `into`: `into` insists its body consume every child,
  ## and only the first one is wanted here.
  result = c
  while result.kind == TagLit and result.exprKind in {SufC, ParC}:
    inc result
