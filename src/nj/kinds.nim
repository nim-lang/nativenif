

import "../../../nimony/src/lib" / [nifcursors, bitabs, lineinfos, nifstreams]
import tags, model

# Model accessors

proc exprKind*(t: TagEnum): NjExpr {.inline.} =
  if rawTagIsNjExpr(t):
    cast[NjExpr](t)
  else:
    NoExpr

proc stmtKind*(t: TagEnum): NjStmt {.inline.} =
  if rawTagIsNjStmt(t):
    cast[NjStmt](t)
  else:
    NoStmt

proc typeKind*(t: TagEnum): NjType {.inline.} =
  if rawTagIsNjType(t):
    cast[NjType](t)
  else:
    NoType

proc te*(n: Cursor): TagEnum = cast[TagEnum](n.tagId)

proc exprKind*(n: Cursor): NjExpr {.inline.} = n.te.exprKind
proc stmtKind*(n: Cursor): NjStmt {.inline.} = n.te.stmtKind
proc typeKind*(n: Cursor): NjType {.inline.} = n.te.typeKind

# Other helpers

proc infoStr(n: Cursor): string =
  if n.info.isValid:
    let raw = unpack(pool.man, n.info)
    result = pool.files[raw.file] & "(" & $raw.line & ", " & $raw.col & ")"
  else:
    result = "???"

proc error*(msg: string; n: Cursor) =
  #writeStackTrace()
  let tagStr = if n.kind != ParRi: toString(n, false) else: "-"
  quit "[Error] " & msg & " at " & infoStr(n) &
    " (kind=" & $n.kind & ", tag=" & tagStr & ")"

proc bug*(msg: string) =
  writeStackTrace()
  quit "BUG: " & msg

proc skipParRi*(n: var Cursor) {.inline.} =
  if n.kind != ParRi: error("Expected )", n)
  inc n

proc skipParRi*(n: var Cursor; context: string) {.inline.} =
  if n.kind != ParRi: error("Expected ) for " & context, n)
  inc n
