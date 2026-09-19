#
#           nativenif — the AArch64 logical (bitmask) immediate
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The `N:immr:imms` bitmask immediate of AArch64's `and`/`orr`/`eor`/`tst`.
## The twin of `thumbimm`, here for the same reason: `nifasm/arm64` needs the
## ENCODING, arkham needs the PREDICATE (`ImmStyle.A64Bitmask`), and arkham must
## not import the encoder, which pulls in `buffers`/`relocs`. This module
## imports nothing.

# AArch64's `and`/`orr`/`eor` take an immediate directly, but not an arbitrary
# one: the field is `N:immr:imms`, which denotes a pattern of `n` ones rotated
# right by `immr` inside an element of 2/4/8/16/32/64 bits, repeated to fill the
# register. Every mask a bitfield extraction produces — 0xff, 0xf, 0x7, 0x1ff,
# 0x3fff — is one, which is why the form exists and why materializing the
# constant into a register first (`mov b,#0xff; and x,b`) is pure waste.

proc trailingZeros(x: uint64): int =
  result = 0
  var t = x
  while (t and 1'u64) == 0'u64: (t = t shr 1; inc result)

proc trailingOnes(x: uint64): int =
  result = 0
  var t = x
  while (t and 1'u64) == 1'u64: (t = t shr 1; inc result)

proc leadingOnes(x: uint64): int =
  result = 0
  var t = x
  while result < 64 and (t and (1'u64 shl 63)) != 0'u64: (t = t shl 1; inc result)

proc isShiftedMask(x: uint64): bool =
  ## `x` is a single contiguous run of ones (and non-zero).
  x != 0'u64 and ((x + (x and (not x + 1))) and x) == 0'u64

proc encodeLogicalImm*(value: uint64; encoding: var uint32): bool =
  ## Compute the `N:immr:imms` field (13 bits, N in bit 12) for the 64-bit
  ## logical-immediate forms, or return false when `value` is not representable.
  ## All-zeros and all-ones are the two excluded patterns — they need no mask.
  ##
  ## The classic derivation: the pattern repeats, so first find the smallest
  ## element size whose halves differ; within that element the value must be a
  ## contiguous run of ones (possibly wrapping), and `immr` is the rotation that
  ## brings it back to the low bits.
  if value == 0'u64 or value == not 0'u64: return false

  var size = 64
  while size > 2:
    size = size div 2
    let mask = (1'u64 shl size) - 1
    if (value and mask) != ((value shr size) and mask):
      size = size * 2
      break

  let mask = (not 0'u64) shr (64 - size)
  var v = value and mask

  var rot, runLen: int
  if isShiftedMask(v):
    rot = trailingZeros(v)
    runLen = trailingOnes(v shr rot)
  else:
    v = v or not mask                        # the run wraps: work on its complement
    if not isShiftedMask(not v): return false
    let clo = leadingOnes(v)
    rot = 64 - clo
    runLen = clo + trailingOnes(v) - (64 - size)

  let immr = uint32((size - rot) and (size - 1))
  var nimms = uint32(not (size - 1)) shl 1
  nimms = nimms or uint32(runLen - 1)
  let n = ((nimms shr 6) and 1) xor 1
  encoding = (n shl 12) or (immr shl 6) or (nimms and 0x3F'u32)
  result = true

proc isLogicalImm*(value: uint64): bool {.inline.} =
  var enc = 0'u32
  encodeLogicalImm(value, enc)
