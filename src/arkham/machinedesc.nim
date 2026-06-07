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
    intArgRegs*: seq[Reg]            ## integer/pointer argument registers, ABI order
    floatArgRegs*: seq[FReg]         ## float argument registers, ABI order
    intTempRegs*: seq[Reg]           ## caller-saved scratch (call-free locals)
    intCalleeSaved*: seq[Reg]        ## callee-saved (locals live across a call)
    floatTempRegs*: seq[FReg]        ## caller-saved FP scratch
    floatCalleeSaved*: seq[FReg]     ## callee-saved FP regs
    intCalleeSavedSet*: set[Reg]     ## membership form of `intCalleeSaved`
    floatCalleeSavedSet*: set[FReg]  ## membership form of `floatCalleeSaved`
    aggrByRefThreshold*: int         ## aggregates larger than this go by reference

type
  LocKind* = enum
    Undef          ## the dontCare target (fill me in)
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
    OnStack        ## value in a frame slot at `offset` (from the frame base)
    NamedStack     ## a stack var/slot managed by nifasm, addressed by `name`
                   ## (aggregate, spilled scalar, or synthetic spill — no cursor)
    Mem            ## a foldable memory operand: the lvalue subtree `cur`
                   ## (`(dot …)`/`(at …)`/`(deref …)`) re-emitted on demand so
                   ## nifasm collapses the access chain to `base+offset`
    Glob           ## a module-level global addressed by `name` (RIP-relative)
    Tvar           ## a thread-local addressed by `name` (FS/TLV)
    Imm            ## a known immediate (constant / target hint)

  Location* = object
    ## The one descriptor for "where a value lives, or should go" — long-lived
    ## storage (the allocator's output) and just-computed values (the codegen's
    ## dont-care result) share it. `isTemp` marks a register the codegen borrowed
    ## as scratch and must hand back (vs. a register-resident local, which it must
    ## not); `freeTemp` releases it and no-ops on every persistent location. It is
    ## meaningless for the non-register kinds.
    typ*: AsmSlot
    isTemp*: bool
    case kind*: LocKind
    of Undef, NeedsReg, RegOrImm: discard
    of InReg: r*: Reg
    of InFReg: f*: FReg
    of OnStack: offset*: int
    of NamedStack, Glob, Tvar: name*: string
    of Mem: cur*: Cursor
    of Imm: ival*: int64

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
proc stackLoc*(offset: int; typ: AsmSlot): Location {.inline.} =
  Location(kind: OnStack, offset: offset, typ: typ)
proc namedStackLoc*(name: string; typ: AsmSlot): Location {.inline.} =
  Location(kind: NamedStack, name: name, typ: typ)
proc globLoc*(name: string; typ: AsmSlot): Location {.inline.} =
  Location(kind: Glob, name: name, typ: typ)
proc tvarLoc*(name: string; typ: AsmSlot): Location {.inline.} =
  Location(kind: Tvar, name: name, typ: typ)
proc memLoc*(cur: Cursor; typ: AsmSlot): Location {.inline.} =
  Location(kind: Mem, cur: cur, typ: typ)
proc immLoc*(ival: int64; typ: AsmSlot): Location {.inline.} =
  Location(kind: Imm, ival: ival, typ: typ)

proc sameReg*(a, b: Location): bool {.inline.} =
  ## True if both name the same physical register (for move coalescing).
  (a.kind == InReg and b.kind == InReg and a.r == b.r) or
  (a.kind == InFReg and b.kind == InFReg and a.f == b.f)
