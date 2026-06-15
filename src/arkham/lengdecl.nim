#
#           Arkham — native AArch64 code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
#

## Leng tag decoding for `nifcore` cursors.
##
## Reuses the canonical, NIF-API-independent enums from `models/leng_tags`
## (`LengStmt`, `LengExpr`, `LengType`, `LengPragma`, `LengOther`, …) whose
## ordinals are the master tag ordinals. To make a parsed `nifcore` buffer's
## `cursorTagId` line up with those ordinals, seed the buffer's `TagPool`
## from the same master `TagData` (just like `nifstreams` seeds its global
## pool). Then `cast[LengStmt](tagId)` works exactly as in `nifc_model` — but
## over `nifcore` cursors, keeping the enums clear of any NIF-API coupling.

import std / assertions
import nifcore
import "../../../nimony/src/models" / [leng_tags, tags]
export leng_tags

proc createLengTagPool*(): TagPool =
  ## A `nifcore` tag pool seeded so each Leng tag's `TagId` equals its master
  ## `TagEnum` ordinal. Pass to `parseFromFile`/`parseFromBuffer` as
  ## `sharedTags` so `tagEnumOf`/`stmtKind`/… can decode by ordinal.
  result = newTagPool()
  for e in TagEnum:
    if e == InvalidTagId: continue
    let id = result.registerTag(TagData[e][0])
    assert uint32(id) == uint32(TagData[e][1]),
      "leng tag pool misalignment for " & TagData[e][0]

template tagEnumOf*(c: Cursor): TagEnum =
  (if c.kind == TagLit: cast[TagEnum](uint32(c.cursorTagId)) else: InvalidTagId)

proc stmtKind*(c: Cursor): LengStmt {.inline.} =
  let e = tagEnumOf(c)
  if rawTagIsLengStmt(e): cast[LengStmt](e) else: NoStmt

proc exprKind*(c: Cursor): LengExpr {.inline.} =
  let e = tagEnumOf(c)
  if rawTagIsLengExpr(e): cast[LengExpr](e) else: NoExpr

proc pragmaKind*(c: Cursor): LengPragma {.inline.} =
  let e = tagEnumOf(c)
  if rawTagIsLengPragma(e): cast[LengPragma](e) else: NoPragma

proc substructureKind*(c: Cursor): LengOther {.inline.} =
  let e = tagEnumOf(c)
  if rawTagIsLengOther(e): cast[LengOther](e) else: NoSub

proc typeKind*(c: Cursor): LengType {.inline.} =
  if c.kind == DotToken: return VoidT       # an empty type slot reads as void
  let e = tagEnumOf(c)
  if rawTagIsLengType(e): cast[LengType](e) else: NoType
