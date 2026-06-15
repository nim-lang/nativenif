#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Machine-agnostic type/size classification: maps a Leng type cursor to an
## `AsmSlot` (kind + size + align). Drives register-class and width decisions
## in the register allocator and code generator.

import std / [assertions]
import nifcore
import nifcdecl

type
  AsmTypeKind* = enum
    ABool          # also models CPU flag results
    AInt, AUInt, AFloat
    AMem           # aggregate / by-reference (object, array, union, void)

  AsmSlot* = object
    cls*: AsmTypeKind             # the value class — read via the `kind` accessor below,
                                  # never directly. `typ` is meant to be the source of
                                  # truth; `cls` is the cached projection of it until every
                                  # slot reliably carries a `typ` (see `kind`).
    size*, align*, offset*: int   # offset only meaningful for fields/slots
    typ*: Cursor                  # the Leng type this slot was classified from, when
                                  # known (a `typeToSlot` result carries it). Lets a
                                  # scratch register be `(rebind …)`'d to its concrete
                                  # type — incl. a pointer's pointee — rather than a
                                  # lenient raw `(reg)`. `cursorIsNil` for a manually
                                  # built dont-care slot (an int/register placeholder),
                                  # where the binder falls back to `(i 64)`.

  VarProp* = enum
    AddrTaken   # address taken (or an array): cannot live in a register
    IsDisjoint  # only `obj.f` used, never `obj` itself
    AllRegs     # used only in a call-free region: any (volatile) register is fine
  VarProps* = set[VarProp]

proc kind*(s: AsmSlot): AsmTypeKind {.inline.} =
  ## The value class of this slot. An accessor (not a field) on purpose: the goal
  ## is that every slot carries a `typ` and this becomes `typeToSlot(s.typ).kind`,
  ## at which point `cls` disappears. Until then it returns the cached `cls` so the
  ## switch is a one-line change here rather than at the ~50 read sites.
  s.cls

proc align*(address, alignment: int): int {.inline.} =
  (address + (alignment - 1)) and not (alignment - 1)

proc isFloat*(s: AsmSlot): bool {.inline.} = s.kind == AFloat
proc inRegClass*(s: AsmSlot): bool {.inline.} =
  ## True if a value of this slot can live in a (single) register at all.
  s.kind != AMem and s.size > 0 and s.size <= 8

# ── AAPCS64 argument / result classification ────────────────────────────────
# Per the Arm 64-bit Procedure Call Standard: integer/pointer scalars go in one
# GPR (x0–x7); 16-byte scalars / small aggregates pack into a GPR pair; floats
# and HFAs go in SIMD regs (v0–v7); aggregates larger than 16 bytes are passed
# by reference (a pointer to a caller-made copy); aggregate results larger than
# 16 bytes use the x8 indirect-result register. arkham's scalar (GPR) path is
# implemented; the others are classified correctly but their value codegen
# (SIMD, GPR-pair packing, by-ref copies, x8) is still pending.

type
  ArgClass* = enum
    AcGpr        ## one general-purpose register (x0–x7)
    AcGprPair    ## two consecutive GPRs (9..16-byte scalar / small aggregate)
    AcSimd       ## SIMD/FP register(s): float scalar or HFA
    AcByRef      ## by reference (pointer to a copy): aggregate > 16 bytes
  ResultClass* = enum
    RcGpr        ## x0 (x0/x1 for 16-byte)
    RcSimd       ## v0… : float / HFA
    RcIndirect   ## caller passes x8 = address; callee writes there (> 16 bytes)

proc classifyArg*(s: AsmSlot): ArgClass =
  case s.kind
  of AFloat: AcSimd
  of AMem:
    if s.size > 16: AcByRef
    elif s.size > 8: AcGprPair
    else: AcGpr
  else:
    if s.size > 8: AcGprPair else: AcGpr

proc classifyResult*(s: AsmSlot): ResultClass =
  case s.kind
  of AFloat: RcSimd
  of AMem: (if s.size > 16: RcIndirect else: RcGpr)
  else: RcGpr

proc typeBits*(c: Cursor): int =
  ## First child of a `(i N)` / `(u N)` / `(f N)` / `(c N)` type is the bit count.
  var t = c
  inc t   # past the type head → first child
  if t.kind == IntLit: int(intVal(t)) else: 0

proc scalarSlot(kind: AsmTypeKind; bits: int): AsmSlot =
  # `(i -1)` etc. (platform int) → assume 64-bit for now.
  let sz = if bits > 0: (bits + 7) div 8 else: 8
  result = AsmSlot(cls: kind, size: sz, align: min(sz, 8))

proc typeToSlot*(c: Cursor): AsmSlot =
  ## Classify a Leng type at `c`. Aggregates and unknowns become `AMem`
  ## (passed/kept by reference) for now. The classified slot retains `c` in `.typ`
  ## so a scratch register holding a value of this type can be `(rebind …)`'d to its
  ## concrete Leng type (see `bindTemp`).
  case c.typeKind
  of IT:   result = scalarSlot(AInt,  typeBits(c))
  of UT:   result = scalarSlot(AUInt, typeBits(c))
  of CT:   result = scalarSlot(AUInt, max(8, typeBits(c)))   # char: at least 1 byte
  of FT:   result = scalarSlot(AFloat, typeBits(c))
  of BoolT: result = AsmSlot(cls: ABool, size: 1, align: 1)
  of PtrT, AptrT, ProctypeT:
    result = AsmSlot(cls: AUInt, size: 8, align: 8)           # an address
  else:
    result = AsmSlot(cls: AMem, size: 0, align: 1)            # object/array/union/void/…
  result.typ = c

# ── aggregate layout descriptors ────────────────────────────────────────────
# The name-resolving size/layout queries (`typeSizeAlign`, `aggrLayout`, …) live
# in `programs.nim` since they must follow named types across modules; slots
# keeps only the pure, structural pieces.

type
  FieldInfo* = tuple[name: string, off, size: int]

proc fieldAtOffset*(lay: seq[FieldInfo]; byteOff: int): string =
  for f in lay:
    if f.off == byteOff: return f.name
  result = ""
