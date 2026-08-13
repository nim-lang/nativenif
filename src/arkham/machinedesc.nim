#
#           Arkham — shared machine model for the native code generators
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Architecture-neutral register slots and the `MachineDesc` the register
## allocator is parameterized over.
##
## `Reg` / `FReg` are an abstract, arch-neutral enumeration of physical
## registers — numbered slots, not hardware names (every modern ISA numbers its
## registers, conflates pointers with integers, and keeps the floating-point
## file separate; that is exactly the GPR `Reg` vs FP `FReg` split here). The
## enum is sized for the widest target (AArch64: 31 GPRs, 32 FP regs). A backend
## reuses a *subset* of the slots — x86-64, with 16 GPRs / 16 XMM, simply never
## allocates `R16..R30` / `F16..F31` — and renders each slot to its own spelling
## through its own `regName` shim (`R0` → `"x0"` on AArch64, `"rax"` on x86-64).
##
## The allocator only ever sees the slots and the `MachineDesc`; it has no
## knowledge of any concrete ABI. A backend describes its register file and
## calling convention by populating a `MachineDesc`.

import slots
import nifcore   # `Cursor`: a `Mem` location captures the lvalue subtree to re-emit

const SynthMark* = "`"
  ## Prefix of every asm-NIF symbol arkham MINTS itself: the positional
  ## parameters, the result binding, scratch/spill bindings, labels and the
  ## aggregate homes. Leng symbols are copied into the asm verbatim and nifasm
  ## scopes them by their full name, so a synthetic name that is spellable as a
  ## Nim identifier is *shadowed* the moment the body declares a local of that
  ## name — and every later reference silently resolves to the local instead.
  ## `formatfloat`'s `mulShift(x: uint64; y: uint64x2)` hit exactly that: its
  ## locals `p0`/`p1` reach Leng as `p0.0`/`p1.0`, which are also the positional
  ## names of its own two parameters.
  ##
  ## The leading backtick is nimony's marker for "compiler-generated, unspellable
  ## in Nim source" (hexer mints `` `x.N ``, `` `tc.N ``, `` `cse.N `` …), so it
  ## rules out any collision with user code. Inside that namespace arkham owns
  ## the tags `p` `ret` `tmp` `ftmp` `fntmp` `L` `etmp` `eftmp` `held` `aggtmp`
  ## `nctmp` `botmp` `rettmp`, none of which hexer mints — and all but `ret` and
  ## `L` carry a counter *in the name*, so even a same-tag hexer symbol (`` `tmp.N ``
  ## from the duplifier) stays a different string from `` `tmpN.0 ``.

template synth*(tag: string): string = SynthMark & tag
  ## Spelling of an arkham-minted asm symbol whose name is exactly `tag`.

type
  Reg* = enum   ## abstract GPR slot; a backend maps it to a hardware register
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
    R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30,
    SP, NoReg

  FReg* = enum  ## abstract FP/SIMD slot
    F0, F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14, F15,
    F16, F17, F18, F19, F20, F21, F22, F23, F24, F25, F26, F27, F28, F29, F30, F31,
    NoFReg

  TargetArch* = enum
    ## Which ISA the `MachineDesc` describes. The register allocator is otherwise
    ## arch-neutral, but a few instruction-selection quirks (x86's destructive
    ## 2-operand RMW, `div` clobbering RDX, variable shift via RCX) are handled by
    ## `if md.arch == X86` branches in the expression walk rather than a callback.
    X86, Arm64

  MachineDesc* = object
    ## A target's register file + calling convention, as the allocator needs it.
    ## All registers are slots from a *subset* of `Reg`/`FReg` (a narrower ISA
    ## like x86-64 leaves the high slots unused).
    arch*: TargetArch                ## the ISA, for the few arch-specific walk branches
    intRetReg*: Reg                  ## integer/pointer return register (rax / x0 = R0)
    divRemReg*: Reg                  ## x86 idiv's clobbered high-half / remainder reg
                                     ## (rdx = R2); `NoReg` on ISAs without the constraint
                                     ## (arm64 sdiv/msub use ordinary scratch)
    shiftCountReg*: Reg              ## x86 variable-shift count register (cl ⊂ rcx = R1);
                                     ## `NoReg` on ISAs where any reg works (arm64)
    intArgRegs*: seq[Reg]            ## integer/pointer argument registers, ABI order
    floatArgRegs*: seq[FReg]         ## float argument registers, ABI order
    intTempRegs*: seq[Reg]           ## caller-saved scratch (call-free locals)
    stagingBridgeReg*: Reg           ## the volatile kept out of every general pool so a
                                     ## staging pick can never fail (x86-64: R11).
                                     ## `callerSaveRescue` is the ONE allocator client
                                     ## allowed to take it.
    intLocalTempRegs*: seq[Reg]      ## subset of `intTempRegs` a call-free local may be
                                     ## *homed* in; the rest of `intTempRegs` stays
                                     ## reserved as emitter scratch. Empty on x86-64 (its
                                     ## only temp reg, R10, is the staging scratch — a
                                     ## local there starves the emitter); the full temp
                                     ## pool on AArch64 (7 volatile regs, scratch to spare)
    intCalleeSaved*: seq[Reg]        ## callee-saved (locals live across a call)
    floatTempRegs*: seq[FReg]        ## caller-saved FP scratch
    floatCalleeSaved*: seq[FReg]     ## callee-saved FP regs
    intCalleeSavedSet*: set[Reg]     ## membership form of `intCalleeSaved`
    floatCalleeSavedSet*: set[FReg]  ## membership form of `floatCalleeSaved`
    aggrByRefThreshold*: int         ## aggregates larger than this go by reference

type
  LocKind* = enum
    Undef          ## the dontCare target (fill me in), and the "produces no value"
                   ## marker for statement positions. NEVER the answer to a symbol
                   ## lookup — that is `NoLoc`, so a zero-initialized `locs[]` entry
                   ## or a genuine dont-care can no longer be confused with "this
                   ## name is not a proc-local" (historically that conflation made
                   ## module-level globals, thread-locals and emitter-synthesized
                   ## slots indistinguishable from an absent location).
    NoLoc          ## a symbol-lookup MISS (`locationOfSym`/`symLoc`): the name is
                   ## not an allocator-known local/param — a module-level symbol
                   ## (global / tvar / proc, disambiguated via `lookupSym`) or an
                   ## emitter-synthesized stack slot (`stackSlots`)
    NeedsReg       ## a destination *constraint*: the value must end up in a GPR,
                   ## but the callee chooses which one (allocating lazily, or
                   ## reusing the register a value already occupies). Like `Undef`,
                   ## it is filled in (via `var`) with the concrete `InReg` it
                   ## resolved to. Never produced as a value — only passed as a
                   ## `gen(…, dest)` target, so value-`case`s need not handle it.
    RegOrImm       ## a destination *constraint*: the value must end up in a GPR OR
                   ## a (small) immediate — but NOT a memory operand. This is the
                   ## operand-B constraint of an ALU op whose destination is memory:
                   ## x86 allows at most one memory operand, so `b` of `op [mem], b`
                   ## must be reg/imm (a memory `b` is loaded first). Filled in (via
                   ## `var`) with the concrete `InReg`/`Imm`. Destination-only.
    InReg          ## value in a GPR
    InFReg         ## value in an FP/SIMD register
    NamedStack     ## a stack var/slot managed by nifasm, addressed by `name`
                   ## (aggregate, spilled scalar, or synthetic spill — no cursor)
    Mem            ## a foldable memory operand: the lvalue subtree `cur`
                   ## (`(dot …)`/`(at …)`/`(deref …)`) re-emitted on demand so
                   ## nifasm collapses the access chain to `base+offset`
    Field          ## a field `field` (of aggregate type `aggrType`) WITHIN an
                   ## aggregate destination, addressed via `base` (a `FieldBase`
                   ## variant — register pointer, stack slot, global/tvar or
                   ## lvalue subtree; each an explicit kind, not a priority
                   ## ladder of sentinel fields). `typ` is the field's slot, so
                   ## a store into it dispatches scalar/float/aggregate like any
                   ## other destination — and a nested aggregate field recurses
                   ## (a `(dot base field)` re-resolved to a `Field` whose base
                   ## is the field's address). This is what lets the one
                   ## `genStore2`/`allocStore` path build an `oconstr`
                   ## field-by-field with no per-field special-casing.
    Glob           ## a module-level global addressed by `name` (RIP-relative)
    Tvar           ## a thread-local addressed by `name` (FS/TLV)
    Imm            ## a known immediate (constant / target hint)

  FieldBaseKind* = enum
    FbReg          ## a pointer to the aggregate held in a register
    FbSlot         ## the aggregate IS the stack slot named `sym`
    FbGlob         ## a module-level global: its address is RE-DERIVED into a
                   ## fresh transient at each use (the survivor-spill totality
                   ## path — a link-time constant needs no register held across
                   ## the field value's evaluation)
    FbTvar         ## a thread-local: address re-derived per use, like `FbGlob`
    FbLval         ## an lvalue subtree whose address is the aggregate (its
                   ## embedded temps must be pre-materialized)

  FieldBase* = object
    ## HOW a `Field` location reaches its aggregate — one explicit kind per
    ## addressing form. (Formerly a priority ladder of four sentinel fields:
    ## `baseReg != NoReg`, else `baseGlob.len > 0`, else `baseName.len > 0`,
    ## else `baseLval` — a missing case fell through to the WRONG arm instead
    ## of failing.)
    case kind*: FieldBaseKind
    of FbReg: reg*: Reg
    of FbSlot, FbGlob, FbTvar: sym*: string
    of FbLval: lval*: Cursor

  Location* = object
    ## The one descriptor for "where a value lives, or should go" — long-lived
    ## storage (the allocator's output) and just-computed values (the codegen's
    ## dont-care result) share it.
    typ*: AsmSlot
    isTemp*: bool     ## REGISTERS ONLY (`InReg`/`InFReg`): the codegen borrowed this
                      ## register as scratch and must hand it back, vs. a
                      ## register-resident local (which it must not). Meaningless —
                      ## and never set — for every other kind; `spillTemp` is the
                      ## produce-into marker for `NamedStack`.
    spillTemp*: bool  ## `NamedStack` ONLY: a synthesized `etmp`/`eftmp`/`held` spill
                      ## slot the emitter must PRODUCE the value into through a
                      ## staging register (`produceIntoMem2`), as opposed to a
                      ## symbol's stack home left in place for operand folding.
                      ## (Formerly overloaded onto `isTemp`, which silently meant
                      ## two unrelated things depending on the kind.)
    case kind*: LocKind
    of Undef, NoLoc, NeedsReg, RegOrImm: discard
    of InReg:
      r*: Reg
    of InFReg: f*: FReg
    of NamedStack, Glob, Tvar: name*: string
    of Mem: cur*: Cursor
    of Field:
      field*: string         ## the member name
      aggrType*: string      ## the enclosing aggregate's nominal type name
      base*: FieldBase       ## how the aggregate is reached (explicit kind)
    of Imm: ival*: int64

template noLoc*: Location =
  ## The symbol-lookup miss: "this name has no allocator location".
  Location(kind: NoLoc)

template dontCare*: Location =
  ## The "fill me in" target for the dont-care evaluator. A template (not a
  ## `const`) because `Location` now embeds a `Cursor`, which has no static
  ## representation — but `Undef` carries none, so this is a cheap literal.
  Location(kind: Undef)

proc needsReg*(typ: AsmSlot): Location {.inline.} =
  ## A "must be a GPR, your choice" destination: the callee resolves it to a
  ## concrete `InReg` (reusing a register-resident value in place, or allocating
  ## scratch) and writes that back through `dest`. Lets binary/unary operations
  ## thread a flexible register constraint instead of pre-committing one via an
  ## eager `borrowTmp`.
  Location(kind: NeedsReg, typ: typ)

proc regOrImm*(typ: AsmSlot): Location {.inline.} =
  ## A "must be a GPR or an immediate, not memory" destination — the operand-B
  ## constraint for an ALU op with a memory destination (one memory operand max).
  ## Resolved to a concrete `InReg`/`Imm` and written back through `dest`.
  Location(kind: RegOrImm, typ: typ)

proc regLoc*(r: Reg; typ: AsmSlot; isTemp = false): Location {.inline.} =
  Location(kind: InReg, r: r, typ: typ, isTemp: isTemp)
proc fregLoc*(f: FReg; typ: AsmSlot; isTemp = false): Location {.inline.} =
  Location(kind: InFReg, f: f, typ: typ, isTemp: isTemp)
proc namedStackLoc*(name: string; typ: AsmSlot; spillTemp = false): Location {.inline.} =
  ## `spillTemp` marks a *spill-temp* slot (an `etmp`/`eftmp` synthesized when the
  ## register pool was exhausted) — a value position the emitter must PRODUCE into
  ## (via a staging register), as opposed to a symbol's stack home left in place for
  ## folding. The emitter (`produceIntoMem2`) keys on it.
  Location(kind: NamedStack, name: name, typ: typ, spillTemp: spillTemp)
proc globLoc*(name: string; typ: AsmSlot): Location {.inline.} =
  Location(kind: Glob, name: name, typ: typ)
proc tvarLoc*(name: string; typ: AsmSlot): Location {.inline.} =
  Location(kind: Tvar, name: name, typ: typ)
proc memLoc*(cur: Cursor; typ: AsmSlot): Location {.inline.} =
  Location(kind: Mem, cur: cur, typ: typ)
proc fieldLoc*(aggrType, field, baseName: string; typ: AsmSlot): Location {.inline.} =
  ## Field `field` of a stack-slot aggregate named `baseName` (the genConstr2 base).
  Location(kind: Field, aggrType: aggrType, field: field,
           base: FieldBase(kind: FbSlot, sym: baseName), typ: typ)
proc fieldLocReg*(aggrType, field: string; baseReg: Reg; typ: AsmSlot): Location {.inline.} =
  ## Field `field` of an aggregate whose address is held in `baseReg` (a by-ref
  ## param / hidden-result buffer / a nested field's computed address).
  Location(kind: Field, aggrType: aggrType, field: field,
           base: FieldBase(kind: FbReg, reg: baseReg), typ: typ)
proc fieldLocGlob*(aggrType, field, globName: string; typ: AsmSlot;
                   isTvar = false): Location {.inline.} =
  ## Field `field` of a module-level aggregate `globName` (a global, or a thread-local
  ## if `isTvar`), whose address is RE-DERIVED into a fresh transient at each field store
  ## (`emFieldOperand`/`emFieldAddr`). Used when the allocator's address survivor spilled
  ## to a slot (`reserveHeldScratch` totality backstop): the address is re-derivable
  ## (a link-time global, or FS-base+offset tvar), so recomputing it per use needs no
  ## register held across the (possibly call-containing) field value evaluation.
  let base = if isTvar: FieldBase(kind: FbTvar, sym: globName)
             else: FieldBase(kind: FbGlob, sym: globName)
  Location(kind: Field, aggrType: aggrType, field: field, base: base, typ: typ)
proc fieldLocLval*(aggrType, field: string; baseLval: Cursor; typ: AsmSlot): Location {.inline.} =
  ## Field `field` of an aggregate addressed by the lvalue subtree `baseLval` (the
  ## genConstrIntoLval2 base — its embedded temps must be pre-materialized).
  Location(kind: Field, aggrType: aggrType, field: field,
           base: FieldBase(kind: FbLval, lval: baseLval), typ: typ)
proc immLoc*(ival: int64; typ: AsmSlot): Location {.inline.} =
  Location(kind: Imm, ival: ival, typ: typ)

proc sameReg*(a, b: Location): bool {.inline.} =
  ## True if both name the same physical register (for move coalescing).
  (a.kind == InReg and b.kind == InReg and a.r == b.r) or
  (a.kind == InFReg and b.kind == InFReg and a.f == b.f)

# ── emitter scratch demand ──────────────────────────────────────────────────
# A step of emission sometimes needs a transient register that belongs to no
# value in the program — an x86 store whose source is also in memory has to pass
# through one, because the ISA has no memory-to-memory move.
#
# Today the emitter DECIDES that at emission time and takes the register from a
# reserved pool (`StagingCandidates`, headed by the one register kept out of the
# allocator's hands so a pick can never fail). That reservation is why the
# allocator cannot give a cross-call value a volatile even when six of them are
# idle: the emitter's claim on the register file is real but not written down,
# so nobody can prove a volatile is free.
#
# The fix is to write the claim down — as a VALUE the allocator can read without
# emitting anything. These functions are that value. The emitter calls them at
# the site it used to decide implicitly, so the two can never disagree: there is
# one function and, for now, one caller.

type
  ScratchDemand* = object
    ## What one emission step needs in transient registers.
    gprs*: int          ## general-purpose scratch registers
    fregs*: int         ## SIMD scratch registers
    slot*: AsmSlot      ## the type a GPR scratch must be bound at (nifasm checks it)

proc memToMemBridgeDemand*(md: MachineDesc; dst, v: Location): ScratchDemand =
  ## Storing `v` into the stack home `dst` when `v` is ITSELF in memory: neither
  ## ISA has a memory-to-memory move, so the value passes through one register.
  ##
  ## The source sets differ by ISA and that is the point of asking the machine
  ## rather than hardcoding a `case`: AArch64 also has no store-immediate and no
  ## RIP-relative operand, so an `Imm`, a global and a thread-local each need the
  ## bridge there and none of them does on x86-64.
  if dst.kind != NamedStack: return ScratchDemand()
  if dst.typ.isFloat:
    let fromMem = (case md.arch
                   of X86: v.kind in {NamedStack, Mem}
                   of Arm64: v.kind in {NamedStack, Mem, Glob})
    if fromMem: ScratchDemand(fregs: 1) else: ScratchDemand()
  else:
    let needsBridge = (case md.arch
                       of X86: v.kind in {NamedStack, Mem}
                       of Arm64: v.kind in {NamedStack, Mem, Glob, Tvar, Imm})
    if needsBridge:
      ScratchDemand(gprs: 1, slot: (if md.arch == X86: v.typ else: dst.typ))
    else:
      ScratchDemand()
