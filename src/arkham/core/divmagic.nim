#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Division by a constant as a multiplication by its reciprocal (Granlund &
## Montgomery, "Division by Invariant Integers using Multiplication"; the
## generator below follows libdivide's `u64_gen`/`s64_gen`). `div r64` costs
## tens of cycles and does not pipeline; the replacement is one `mul` and a few
## shifts. Only the target-neutral half lives here: the magic constant and the
## shift. Each emitter spells the sequence in its own instructions.
##
## The quotient for an unsigned `n`:
##
##   q = mulhi(n, magic)
##   if add: q = ((n - q) shr 1 + q) shr shift  else: q = q shr shift
##
## and for a signed `n`, where `mulhi` is the SIGNED high half:
##
##   q = mulhi(n, magic)
##   if add: q += (if divisor < 0: -n else: n)
##   q = q sar shift; q += q shr 63           # round toward zero
##
## A remainder is `n - q * divisor` in both cases.

import std / assertions

type
  DivMagic* = object
    magic*: uint64   ## the multiplier; for a signed divisor read it as `int64`
    shift*: int
    add*: bool       ## the magic needed 65 bits: the "add" fixup is required

proc div128by64(hi, lo, d: uint64; rem: var uint64): uint64 =
  ## `(hi:lo) div d` for `hi < d`, so the quotient fits 64 bits. Restoring
  ## long division one bit at a time: this runs once per constant divisor at
  ## compile time, so clarity beats speed.
  var r = hi
  result = 0'u64
  for i in countdown(63, 0):
    let carry = r shr 63
    r = (r shl 1) or ((lo shr i) and 1'u64)
    result = result shl 1
    if carry != 0'u64 or r >= d:
      r = r - d                  # wraps back into range when `carry` was set
      result = result or 1'u64
  rem = r

proc floorLog2(x: uint64): int =
  result = -1
  var t = x
  while t != 0'u64:
    t = t shr 1
    inc result

proc isPow2(x: uint64): bool {.inline.} = x != 0'u64 and (x and (x - 1'u64)) == 0'u64

proc unsignedDivMagic*(d: uint64): DivMagic =
  ## The magic for an unsigned 64-bit divisor that is NOT a power of two (the
  ## emitters turn those into shifts).
  assert not isPow2(d) and d > 1'u64
  let fl = floorLog2(d)
  var rem = 0'u64
  var m = div128by64(1'u64 shl fl, 0'u64, d, rem)    # 2^(64+fl) div d
  if d - rem < (1'u64 shl fl):
    result = DivMagic(magic: m + 1'u64, shift: fl, add: false)
  else:
    m = m + m
    let twice = rem + rem
    if twice >= d or twice < rem: m = m + 1'u64
    result = DivMagic(magic: m + 1'u64, shift: fl, add: true)

proc signedDivMagic*(d: int64): DivMagic =
  ## The magic for a signed 64-bit divisor whose magnitude is at least 3 and NOT
  ## a power of two. The sign of the divisor is folded into `magic`; the
  ## emitter needs it again only for the `add` fixup.
  let absD = if d < 0: 0'u64 - cast[uint64](d) else: cast[uint64](d)
  assert not isPow2(absD) and absD > 2'u64
  let fl = floorLog2(absD)
  var rem = 0'u64
  var m = div128by64(1'u64 shl (fl - 1), 0'u64, absD, rem)  # 2^(63+fl) div |d|
  var shift = fl - 1
  var add = false
  if absD - rem >= (1'u64 shl fl):
    m = m + m
    let twice = rem + rem
    if twice >= absD or twice < rem: m = m + 1'u64
    shift = fl
    add = true
  m = m + 1'u64
  if d < 0: m = 0'u64 - m
  result = DivMagic(magic: m, shift: shift, add: add)

when isMainModule:
  import std / syncio
  # Brute-force check against the hardware division, including the operands
  # around every boundary the fixups exist for.
  proc mulhiU(a, b: uint64): uint64 =
    let a0 = a and 0xFFFF_FFFF'u64
    let a1 = a shr 32
    let b0 = b and 0xFFFF_FFFF'u64
    let b1 = b shr 32
    let p00 = a0 * b0
    let p01 = a0 * b1
    let p10 = a1 * b0
    let p11 = a1 * b1
    let mid = (p00 shr 32) + (p01 and 0xFFFF_FFFF'u64) + (p10 and 0xFFFF_FFFF'u64)
    result = p11 + (p01 shr 32) + (p10 shr 32) + (mid shr 32)

  proc mulhiS(a, b: int64): int64 =
    var h = mulhiU(cast[uint64](a), cast[uint64](b))
    if a < 0: h = h - cast[uint64](b)
    if b < 0: h = h - cast[uint64](a)
    cast[int64](h)

  proc udiv(n: uint64; m: DivMagic): uint64 =
    let q = mulhiU(n, m.magic)
    if m.add: ((n - q) shr 1 + q) shr m.shift
    else: q shr m.shift

  proc sdiv(n, d: int64; m: DivMagic): int64 =
    var q = mulhiS(n, cast[int64](m.magic))
    if m.add:
      q = cast[int64](cast[uint64](q) + (if d < 0: 0'u64 - cast[uint64](n) else: cast[uint64](n)))
    q = q shr m.shift                       # `shr` on int64 is arithmetic
    q + cast[int64](cast[uint64](q) shr 63)

  var x = 0x9E37_79B9_7F4A_7C15'u64
  proc next(): uint64 =
    x = x xor (x shl 13); x = x xor (x shr 7); x = x xor (x shl 17)
    x

  var divisors: seq[uint64] = @[]
  for d in 3'u64 .. 2000'u64: divisors.add d
  for k in 2 .. 63:
    for delta in [1'u64, 3'u64]:
      divisors.add (1'u64 shl k) + delta
      divisors.add (1'u64 shl k) - delta
  for i in 0 ..< 2000: divisors.add next()
  divisors.add high(uint64)
  divisors.add high(uint64) - 1

  var numers: seq[uint64] = @[0'u64, 1, 2, high(uint64), high(uint64) - 1,
                               uint64 high(int64), (uint64 high(int64)) + 1'u64]
  for i in 0 ..< 300: numers.add next()
  var checks = 0
  for d in divisors:
    if isPow2(d) or d < 2'u64: continue
    let um = unsignedDivMagic(d)
    for n in numers:
      doAssert udiv(n, um) == n div d, $n & " div " & $d
      inc checks
    for sd in [cast[int64](d), cast[int64](0'u64 - d)]:
      let a = if sd < 0: 0'u64 - cast[uint64](sd) else: cast[uint64](sd)
      if a <= 2'u64 or isPow2(a) or sd == low(int64): continue
      let sm = signedDivMagic(sd)
      for n in numers:
        let sn = cast[int64](n)
        if sn == low(int64) and sd == -1: continue
        doAssert sdiv(sn, sd, sm) == sn div sd, $sn & " div " & $sd
        inc checks
  echo "divmagic: ", checks, " checks passed"
