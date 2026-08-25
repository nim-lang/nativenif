#
#           nativenif — the Thumb-2 modified immediate
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## "ThumbExpandImm" — the 12-bit immediate (i:imm3:imm8) the 32-bit Thumb-2
## data-processing forms take. It represents either a small value replicated
## across byte lanes, or an 8-bit value with its top bit set rotated to any
## position; the direct analogue of AArch64's bitmask immediate, and the reason a
## great many constants need no literal pool.
##
## This lives in `src/common` because BOTH ends of the pipeline need it and they
## must agree exactly: `nifasm/thumb2` needs the ENCODING to emit the instruction,
## and arkham needs the PREDICATE to decide whether a constant may ride along as
## an operand at all (`logicalImmOk`, via `ImmStyle.ThumbExpandImm`). Arkham cannot
## simply import `thumb2`, which pulls in `buffers`/`relocs` and would make the code
## generator depend on the assembler's byte-emission machinery for one predicate —
## so the rule used to be written out twice, in two files, with nothing tying the
## copies together. Keeping it here is dependency-free for both: this module
## imports nothing.
##
## The AArch64 twin needs no such module: `arm64.isLogicalImm` is already reachable
## from arkham, and `isLogicalImmA64` just calls it.

proc encodeModifiedImm*(value: uint32; encoding: var uint32): bool =
  ## Returns false when `value` is not representable, in which case the caller
  ## must fall back to MOVW/MOVT.
  # Form 1: 0000_00XY where the 12-bit field is 0000 xxxxxxxx (value < 256)
  if value < 256:
    encoding = value
    return true
  # Form 2..4: byte-replicated patterns.
  let b0 = value and 0xFF
  let b1 = (value shr 8) and 0xFF
  let b2 = (value shr 16) and 0xFF
  let b3 = (value shr 24) and 0xFF
  if b0 == b2 and b1 == 0 and b3 == 0 and b0 != 0:
    encoding = (0x1'u32 shl 8) or b0        # 0x00XY00XY
    return true
  if b1 == b3 and b0 == 0 and b2 == 0 and b1 != 0:
    encoding = (0x2'u32 shl 8) or b1        # 0xXY00XY00
    return true
  if b0 == b1 and b1 == b2 and b2 == b3 and b0 != 0:
    encoding = (0x3'u32 shl 8) or b0        # 0xXYXYXYXY
    return true
  # Form 5: an 8-bit value with bit 7 SET, rotated right by 8..31.
  for rot in 8 .. 31:
    let rotated = (value shl rot) or (value shr (32 - rot))
    if rotated < 0x100 and (rotated and 0x80) != 0:
      # `rotated` is the unrotated 8-bit constant; the field stores the amount
      # needed to rotate it back into place.
      encoding = (uint32(rot) shl 7) or (rotated and 0x7F)
      return true
  return false

proc isModifiedImm*(value: uint32): bool {.inline.} =
  ## Is `value` representable at all? The question a code generator asks.
  var enc: uint32
  encodeModifiedImm(value, enc)

proc isModifiedImm*(v: int64): bool {.inline.} =
  ## The signed overload arkham reaches for: a NIF integer literal is an `int64`,
  ## and anything outside the unsigned 32-bit range is out of the question before
  ## the bit patterns are even considered.
  if v < 0 or v > 0xFFFFFFFF'i64: false
  else: isModifiedImm(uint32(v))
