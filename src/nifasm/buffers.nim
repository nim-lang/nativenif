# Nifasm - Common Bytes Type

import std / [strutils]

type
  Bytes* = object
    data: seq[byte]

proc initBytes*(): Bytes =
  result = Bytes(data: @[])

proc add*(buf: var Bytes; b: byte) =
  buf.data.add(b)

proc addUint16*(buf: var Bytes; val: uint16) =
  buf.add(byte(val and 0xFF))
  buf.add(byte((val shr 8) and 0xFF))

proc addUint32*(buf: var Bytes; val: uint32) =
  buf.add(byte(val and 0xFF))
  buf.add(byte((val shr 8) and 0xFF))
  buf.add(byte((val shr 16) and 0xFF))
  buf.add(byte((val shr 24) and 0xFF))

proc addt32*(buf: var Bytes; val: int32) =
  buf.addUint32(uint32(val))

proc addt64*(buf: var Bytes; val: int64) =
  buf.add(byte(val and 0xFF))
  buf.add(byte((val shr 8) and 0xFF))
  buf.add(byte((val shr 16) and 0xFF))
  buf.add(byte((val shr 24) and 0xFF))
  buf.add(byte((val shr 32) and 0xFF))
  buf.add(byte((val shr 40) and 0xFF))
  buf.add(byte((val shr 48) and 0xFF))
  buf.add(byte((val shr 56) and 0xFF))

proc len*(buf: Bytes): int =
  ## Get the length of the buffer
  buf.data.len

proc insertRepeated*(buf: var Bytes; at: int; b: byte; count: int) =
  ## Insert `count` copies of `b` at byte position `at`, shifting later bytes.
  ## Used by the `casejmp` slot padding (NOP fill to the uniform slot size).
  if count <= 0: return
  let oldLen = buf.data.len
  buf.data.setLen(oldLen + count)
  for i in countdown(oldLen - 1, at):
    buf.data[i + count] = buf.data[i]
  for i in 0 ..< count:
    buf.data[at + i] = b

proc removeRange*(buf: var Bytes; at, count: int) =
  ## Delete `count` bytes at position `at`, shifting later bytes down. The inverse
  ## of `insertRepeated`; the caller must rebase every recorded byte position after
  ## `at` itself (see `shiftCodePositions`).
  if count <= 0: return
  let oldLen = buf.data.len
  for i in at + count ..< oldLen:
    buf.data[i - count] = buf.data[i]
  buf.data.setLen(oldLen - count)

proc `[]=`*(buf: var Bytes; i: int; b: byte) {.inline.} =
  buf.data[i] = b

proc `[]`*(buf: Bytes; i: int): byte {.inline.} =
  buf.data[i]

proc rawData*(buf: Bytes): pointer {.inline.} =
  addr buf.data[0]

proc `$`*(buf: Bytes): string =
  result = ""
  for i, b in buf.data:
    if i > 0: result.add(" ")
    result.add(b.toHex(2).toUpper())


proc patchThumbMovwMovtPair*(buf: var Bytes; at: int; value: uint32) =
  ## Rewrite the 16-bit immediates of a MOVW/MOVT pair at byte offset `at` so the
  ## pair materializes `value`. Both instructions are 32-bit Thumb encodings —
  ## two little-endian HALFWORDS each, high halfword first — and the immediate is
  ## scattered as imm4:i:imm3:imm8 across them.
  ##
  ## Lives here rather than in `thumb2` because `relocs` needs it too (for the
  ## absolute MOVW+MOVT relocation) and `thumb2` imports `relocs`, so the
  ## dependency can only run this way. One copy: the scatter is easy to get
  ## subtly wrong and a second copy would drift.
  ##
  ## Only the immediate fields are touched; `rd` and the MOVW/MOVT opcode bits
  ## are preserved from whatever is already there.
  for half in 0 ..< 2:
    let v = uint16((value shr (16 * half)) and 0xFFFF)
    let imm4 = uint16((v shr 12) and 0xF)
    let i    = uint16((v shr 11) and 0x1)
    let imm3 = uint16((v shr 8) and 0x7)
    let imm8 = uint16(v and 0xFF)
    let o = at + 4 * half
    let oldHi = uint16(buf[o]) or (uint16(buf[o + 1]) shl 8)
    let oldLo = uint16(buf[o + 2]) or (uint16(buf[o + 3]) shl 8)
    let hi = (oldHi and 0xFBF0'u16) or (i shl 10) or imm4
    let lo = (oldLo and 0x8F00'u16) or (imm3 shl 12) or imm8
    buf[o] = byte(hi and 0xFF)
    buf[o + 1] = byte((hi shr 8) and 0xFF)
    buf[o + 2] = byte(lo and 0xFF)
    buf[o + 3] = byte((lo shr 8) and 0xFF)
