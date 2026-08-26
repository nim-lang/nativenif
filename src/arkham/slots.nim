#
#           Arkham — native code generator for Leng
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
    DivRegOk    # AllRegs AND no div/mod in the live interval → the div/rem register
                # (rdx on x86-64) is a legal extra home (its fixed role never overlaps)
    ShiftRegOk  # AllRegs AND no *variable* shift in the live interval → the shift-count
                # register (rcx/cl on x86-64) is a legal extra home
    ArgResident # a PARAM whose live range crosses no call: the earliest call in
                # the proc is exactly at its LAST use (the consuming call, which clobbers
                # the arg reg anyway). It may STAY in its incoming arg register instead of
                # taking a callee-saved home — no prologue save, and same-position passing
                # makes the call-site marshal a self-move (elided). See allocParams.
  VarProps* = set[VarProp]

# ── target word ─────────────────────────────────────────────────────────────
# Everything below used to hardcode a 64-bit word: a pointer was 8 bytes, Leng's
# platform `int` resolved to 8, and "fits in a register" meant "<= 8". That is
# true of both existing targets and of neither 32-bit one, so the width is now a
# value.
#
# It is PROCESS-GLOBAL rather than threaded through `typeToSlot`. arkham compiles
# exactly one module for exactly one target per run (`arkham -a:x64 file.nif`),
# and the classification is called from 19 sites across four modules that would
# otherwise each have to carry a descriptor they do not otherwise need. The
# single writer is the backend entry point (`generateX64` / `generateA64` / …),
# which sets it before parsing anything — see `setTargetWord`.

type
  TargetWord* = object
    ## The width facts a type classification needs, in BYTES.
    ptrSize*: int     ## a pointer / proc pointer, and Leng's platform `int`
    ptrAlign*: int    ## a pointer's natural alignment
    maxScalar*: int   ## widest scalar one GPR holds (the `inRegClass` bound)
    maxFloat*: int    ## widest float the FPU HAS — the width to assume when an
                      ## expression's own type does not say (a bare literal).
                      ## 8 where doubles exist; 4 on Cortex-M4F, whose FPv4-SP is
                      ## single precision and has no `.f64` instruction at all

const
  Word64* = TargetWord(ptrSize: 8, ptrAlign: 8, maxScalar: 8, maxFloat: 8)
    ## x86-64 and AArch64.
  Word32* = TargetWord(ptrSize: 4, ptrAlign: 4, maxScalar: 4, maxFloat: 4)
    ## ARMv7-M (Cortex-M) and any other 32-bit target.

var targetWord = Word64
  ## Defaults to 64-bit so a backend that never calls `setTargetWord` behaves
  ## exactly as before this was configurable.

proc setTargetWord*(t: TargetWord) =
  ## Set the target's word facts. Call ONCE, from the backend entry point, before
  ## any type is classified — a slot computed under the wrong width is not
  ## detectably wrong later, it is just a field at the wrong offset.
  targetWord = t

proc wordSize*(): int {.inline.} = targetWord.ptrSize
proc wordAlign*(): int {.inline.} = targetWord.ptrAlign
proc maxScalarSize*(): int {.inline.} = targetWord.maxScalar
proc maxFloatSize*(): int {.inline.} = targetWord.maxFloat
proc defaultFloatSlot*(): AsmSlot {.inline.} =
  ## The dont-care FLOAT placeholder: the widest float this target has. A bare
  ## literal carries no width of its own, and picking one that the target cannot
  ## encode turns "no width stated" into a refusal.
  AsmSlot(cls: AFloat, size: maxFloatSize(), align: maxFloatSize())
proc wordBits*(): int {.inline.} = targetWord.ptrSize * 8
  ## The native register width in BITS — what a temp or a raw register operand is
  ## declared at in the emitted asm-NIF. 64 on x86-64 and AArch64, 32 on Cortex-M.

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
  s.kind != AMem and s.size > 0 and s.size <= maxScalarSize()

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
  # The AAPCS64 thresholds stated in words: an aggregate wider than TWO words
  # goes by reference, one wider than a single word packs into a GPR pair. On a
  # 64-bit target these are the familiar 16 and 8.
  let w = wordSize()
  case s.kind
  of AFloat: AcSimd
  of AMem:
    if s.size > 2*w: AcByRef
    elif s.size > w: AcGprPair
    else: AcGpr
  else:
    if s.size > w: AcGprPair else: AcGpr

proc classifyResult*(s: AsmSlot): ResultClass =
  case s.kind
  of AFloat: RcSimd
  of AMem: (if s.size > 2*wordSize(): RcIndirect else: RcGpr)
  else: RcGpr

proc typeBits*(c: Cursor): int =
  ## First child of a `(i N)` / `(u N)` / `(f N)` / `(c N)` type is the bit count.
  var t = c
  inc t   # past the type head → first child
  if t.kind == IntLit: int(intVal(t)) else: 0

proc scalarSlot(kind: AsmTypeKind; bits: int): AsmSlot =
  # `(i -1)` etc. is Leng's platform-width scalar: it resolves to the target
  # WORD, not to a fixed 64 bits. nifasm's `normScalarBits` must agree exactly —
  # a disagreement does not fail loudly, it silently sizes a field to 0 and
  # collapses every later field's offset.
  let sz = if bits > 0: (bits + 7) div 8 else: wordSize()
  result = AsmSlot(cls: kind, size: sz, align: min(sz, wordAlign()))

proc typeToSlot*(c: Cursor; ptrSize = 8): AsmSlot =
  ## Classify a Leng type at `c`. Aggregates and unknowns become `AMem`
  ## (passed/kept by reference) for now. The classified slot retains `c` in `.typ`
  ## so a scratch register holding a value of this type can be `(rebind …)`'d to its
  ## concrete Leng type (see `bindTemp`). `ptrSize` is the target's pointer/word
  ## size in bytes (8 for the native targets, 4 for wasm32).
  case c.typeKind
  of IT:   result = scalarSlot(AInt,  typeBits(c), ptrSize)
  of UT:   result = scalarSlot(AUInt, typeBits(c), ptrSize)
  of CT:   result = scalarSlot(AUInt, max(8, typeBits(c)), ptrSize)   # char: at least 1 byte
  of FT:   result = scalarSlot(AFloat, typeBits(c), ptrSize)
  of BoolT: result = AsmSlot(cls: ABool, size: 1, align: 1)
  of PtrT, AptrT, ProctypeT:
    result = AsmSlot(cls: AUInt, size: wordSize(), align: wordAlign())  # an address
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

proc addrSlot*(): AsmSlot {.inline.} =
  ## A slot holding an ADDRESS, at the target's pointer width. Sites that build
  ## one inline used to spell `AsmSlot(cls: AUInt, size: 8, align: 8)`, which is
  ## a silent 8-byte slot on a 32-bit target — twice the space, and any
  ## neighbouring slot's offset shifted with it.
  AsmSlot(cls: AUInt, size: wordSize(), align: wordAlign())
