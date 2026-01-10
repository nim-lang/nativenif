

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

proc otherKind*(t: TagEnum): NjOther {.inline.} =
  if rawTagIsNjOther(t):
    cast[NjOther](t)
  else:
    NoOther

proc te*(n: Cursor): TagEnum = cast[TagEnum](n.tagId)

proc exprKind*(n: Cursor): NjExpr {.inline.} = n.te.exprKind
proc stmtKind*(n: Cursor): NjStmt {.inline.} = n.te.stmtKind
proc typeKind*(n: Cursor): NjType {.inline.} = n.te.typeKind
proc otherKind*(n: Cursor): NjOther {.inline.} = n.te.otherKind

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

type
  TypeDecl* = object
    name*, pragmas*, body*: Cursor

proc asTypeDeclImpl(n: var Cursor): TypeDecl =
  assert n.stmtKind == TypeS
  inc n
  result = TypeDecl(name: n)
  skip n
  result.pragmas = n
  skip n
  result.body = n

proc asTypeDecl*(n: Cursor): TypeDecl =
  var n = n
  asTypeDeclImpl(n)

proc takeTypeDecl*(n: var Cursor): TypeDecl =
  result = asTypeDeclImpl(n)
  skip n # skip body
  skipParRi n

type
  FieldDecl* = object
    name*, pragmas*, typ*: Cursor

proc takeFieldDecl*(n: var Cursor): FieldDecl =
  assert n.otherKind == FldU
  inc n
  result = FieldDecl(name: n)
  skip n
  result.pragmas = n
  skip n
  result.typ = n
  skip n
  skipParRi n

type
  ParamDecl* = object
    name*, pragmas*, typ*: Cursor

proc takeParamDecl*(n: var Cursor): ParamDecl =
  assert n.otherKind == ParamU
  inc n
  result = ParamDecl(name: n)
  skip n
  result.pragmas = n
  skip n
  result.typ = n
  skip n
  skipParRi n


type
  ProcType* = object
    params*, returnType*, pragmas*: Cursor

proc takeProcType*(n: var Cursor; skipProcBody: bool): ProcType =
  var isProc = false
  if n.stmtKind == ProcS:
    isProc = true
    inc n
    skip n # skip the name
  elif n.typeKind == ProctypeT:
    inc n # into the proctype
  else:
    raiseAssert "proctype or proc expected"  
  result = ProcType(params: n)
  skip n
  result.returnType = n
  skip n
  result.pragmas = n
  skip n
  if isProc:
    if skipProcBody:
      skip n
      skipParRi n
  else:
    skipParRi n

type
  ProcDecl* = object
    name*, params*, returnType*, pragmas*, body*: Cursor

proc takeProcDecl*(n: var Cursor): ProcDecl =
  assert n.stmtKind == ProcS
  inc n
  result = ProcDecl(name: n)
  skip n
  result.params = n
  skip n
  result.returnType = n
  skip n
  result.pragmas = n
  skip n
  result.body = n
  skip n
  skipParRi n

type
  VarDecl* = object
    name*, pragmas*, typ*, value*: Cursor

proc takeVarDecl*(n: var Cursor): VarDecl =
  assert n.stmtKind in {GvarS, TvarS, VarS, ConstS}
  inc n
  result = VarDecl(name: n)
  skip n
  result.pragmas = n
  skip n
  result.typ = n
  skip n
  result.value = n
  skip n
  skipParRi n
