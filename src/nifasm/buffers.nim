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

