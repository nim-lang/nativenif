## NativeNif (c) 2026 Andreas Rumpf

import std / [assertions, syncio, tables, sets, intsets, strutils]
from std / os import changeFileExt, splitFile, extractFilename

import bitabs, lineinfos, nifstreams, nifcursors
import slots, analyser
import machine
import .. / nj / [model, kinds, blueprint]

type
  Context = object
    dest: TokenBuf
    intmSize, inConst, labels: int
    generatedTypes: HashSet[SymId]
    requestedSyms: HashSet[string]
    fields: Table[SymId, AsmSlot]
    types: Table[SymId, AsmSlot]
    locals: Table[SymId, Location]
    strings: Table[string, int]
    floats: Table[FloatId, int]
    vars: seq[SymId]
    returnLoc: Location
    exitProcLabel: int
    globals: Table[SymId, Location]
    rega: RegAllocator

proc initContext(intmSize: int): Context =
  result = Context(intmSize: intmSize, rega: initRegAllocator())

proc error(msg: string; n: Cursor) {.noreturn.} =
  write stdout, "[Error] "
  write stdout, msg
  writeLine stdout, toString(n, false)
  when defined(debug):
    writeStackTrace()
  quit 1

proc mergeBranch(arg: var AsmSlot; value: AsmSlot) =
  arg.offset = max(arg.offset, value.offset)
  arg.align = max(arg.align, value.align)

proc integralBits(c: var Context; t: Cursor): int =
  var n = t
  inc n
  if n.kind == IntLit:
    result = pool.integers[n.intId].int
    inc n
  else:
    error "expected `IntLit` but got: ", n
  skipParRi n

template inBytes(x: int): int = x div 8
proc fillTypeSlot(c: var Context; t: Cursor; dest: var AsmSlot)

proc fieldName(c: var Context; n: Cursor): SymId =
  if n.kind in {SymbolDef}:
    result = n.symId
  else:
    error "field name must be a SymDef, but got: ", n
    result = SymId(0)

proc genFieldPragmas(c: var Context; n: Cursor;
                     field: var AsmSlot) =
  # CommonPragma ::= (align Number) | (was Identifier) | Attribute
  # FieldPragma ::= CommonPragma | (bits Number)
  var n = n
  if n.kind == DotToken:
    discard
  elif n.otherKind == PragmasU:
    inc n
    while n.kind != ParRi:
      case n.pragmaKind
      of AlignP:
        inc n
        field.align = pool.integers[n.intId]
        inc n
        skipParRi n
      of WasP, AttrP:
        skip n
      of BitsP:
        error c.m, "bit sizes fields are not supported: ", n
        skip n
      else:
        error c.m, "invalid proc type pragma: ", n
        skip n
    inc n
  else:
    error c.m, "expected field pragmas but got: ", n
    skip n

proc genObjectBody(c: var Context; n: Cursor;
                   obj: var AsmSlot; k: NjType) =
  obj.kind = AMem
  var n = n.firstSon
  if n.kind == Symbol:
    # inheritance
    fillTypeSlot c, n, obj
    inc n
  elif n.kind == DotToken:
    inc n
  while n.otherKind == FldU:
    let decl = takeFieldDecl(n)
    let fn = fieldName(c, decl.name)
    var f = AsmSlot()
    genFieldPragmas c, decl.pragmas, f
    fillTypeSlot c, decl.typ, f
    setField c, fn, obj, f
    if k == ObjectT:
      inc obj.size, f.size
    else:
      # union:
      obj.size = max(obj.size, f.size)
    obj.align = max(obj.align, f.align)
  # padding at object end:
  obj.size = obj.size + (obj.size mod obj.align)

proc fillTypeSlot(c: var Context; t: Cursor; dest: var AsmSlot) =
  let k = t.typeKind
  case k
  of IT:
    let bytes = integralBits(c, t).inBytes
    dest = AsmSlot(kind: AInt, size: bytes, align: bytes)
  of UT, CT:
    let bytes = integralBits(c, t).inBytes
    dest = AsmSlot(kind: AUInt, size: bytes, align: bytes)
  of FT:
    let bytes = integralBits(c, t).inBytes
    dest = AsmSlot(kind: AFloat, size: bytes, align: bytes)
  of BoolT:
    dest = AsmSlot(kind: ABool, size: 1, align: 1)
  of PtrT, APtrT, ProctypeT:
    dest = AsmSlot(kind: AUInt, size: c.intmSize, align: c.intmSize)
  of FlexarrayT:
    # Call `elementType` to get the alignment right:
    fillTypeSlot c, t.firstSon, dest
    dest.kind = AMem
    dest.size = 0
  of ArrayT:
    var n = t.firstSon
    fillTypeSlot c, n, dest
    skip n
    if n.kind == IntLit:
      dest.size *= pool.integers[n.intId]
    else:
      error "expected `IntLit` but got: ", n
    dest.kind = AMem
  of ObjectT, UnionT:
    genObjectBody c, t, dest, k
  else:
    if t.kind == Symbol:
      let id = t.symId
      let def = c.m.defs.getOrDefault(id)
      if def.pos == 0:
        error c.m, "undeclared symbol: ", t
      else:
        if c.types.hasKey(id):
          dest = c.types[id]
        else:
          let n = readonlyCursorAt(c.m.src, def.pos)
          let decl = asTypeDecl(n)
          fillTypeSlot c, decl.body, dest
          c.types[id] = dest
    else:
      error c.m, "node is not a type: ", t

proc generateTypes(c: var Context; o: TypeOrder) =
  for d in o.ordered.s:
    var n = d
    var decl = takeTypeDecl(n)
    if not c.generatedTypes.containsOrIncl(decl.name.symId):
      var dest = AsmSlot()
      fillTypeSlot c, decl.body, dest
      c.types[decl.name.symId] = dest

proc getAsmSlot(c: var Context; n: Cursor): AsmSlot =
  let t = getType(c.m, n)
  if t.tagId == ErrT:
    error c.m, "cannot compute type of expression: ", n
  else:
    result = AsmSlot()
    fillTypeSlot c, t, result

proc typeToSlot(c: var Context; t: Cursor): AsmSlot =
  result = AsmSlot()
  fillTypeSlot c, t, result

include register_allocator

proc generateNifasm*(m: sink Module; intmSize: int): TokenBuf =
  var c = initGenContext(m, intmSize)
  c.dest.buildTree StmtsT, NoLineInfo:
    var n = beginRead(m.stream)
    while n.kind != EofToken:
      trStmt c, c.dest, n
  result = move c.dest

# Helper to write to file
proc writeNifasm*(buf: TokenBuf; filename: string) =
  var s = nifstreams.createStream()
  for t in buf:
    s.add t
  s.add eofToken()
  writeFile filename, s.r