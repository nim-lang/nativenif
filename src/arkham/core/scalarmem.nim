#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The block-memory rows `zeroMemIns` / `copyMemIns` / `cmpMemIns`.
##
## Their operands are LOCATIONS, never pointers: every one arrives as `(haddr L)`
## — the tag that says "bind L's location" — and the byte count is optional,
## defaulting to the size of the first operand's type:
##
##   (instr zeroMemIns (haddr D) [N])
##   (instr copyMemIns (haddr D) (haddr S) [N])
##   (instr cmpMemIns  (haddr A) (haddr B) [N])        ; a value: memcmp's sign
##
## Two lowerings, chosen ONCE, by the analyser:
##
## * **register form** (`matchScalarMemInstr`): every location is a bare scalar
##   local or parameter, all of the same scalar type, and the count is absent or
##   equal to that type's width. Then the op is `D = 0`, `D = S`, or a compare of
##   the operands' bytes in memory order — no address exists and nothing forces
##   the locals out of their registers. The analyser records the instruction in
##   `ProcAnalysis.scalarMemOps` (keyed by its token position), treats `D` as a
##   definition and the sources as uses, and does NOT count a call point. The
##   emitters look the position up and never re-derive the decision: a location
##   the analyser left register-eligible must not reach the memory form.
## * **memory form**: anything else. The locations' addresses go to the first
##   argument registers and the inline loop runs, so it IS a call point, and the
##   `haddr` makes each location's root address-taken (`memRowArgs` supplies the
##   operands the loop expects).
##
## The register form needs a one-register operand (`maxBytes`), and `cmpMemIns`
## additionally a byte-reverse instruction (`allowCmp`).

import std / [tables]
import nifcore, nifcdecl
import "../../../../nimony/src/lib" / intrinsics

type
  ScalarMemKind* = enum
    smNone
    smZero          ## `D = 0`
    smCopy          ## `D = S`
    smCmp           ## an unsigned compare of the operands' bytes in MEMORY order
                    ## (byte-reversed, as the targets are little-endian): -1/0/1
  ScalarMemOp* = object
    kind*: ScalarMemKind
    dst*: Cursor    ## the `D` (smCmp: `A`) symbol token inside its `(haddr …)`
    src*: Cursor    ## smCopy: `S`, smCmp: `B` — the symbol inside its `(haddr …)`
    bytes*: int     ## the operand width

proc scalarTypeBytes*(t: Cursor): int =
  ## The byte width of a scalar `(i N)`/`(u N)`/`(f N)`/`(c N)` type, or 0 for
  ## anything else (named types, pointers, `bool`, aggregates, `(i -1)`).
  result = 0
  if t.kind != TagLit or t.typeKind notin {IT, UT, FT, CT}: return
  var b = t
  inc b
  if b.kind == IntLit:
    let bits = int(intVal(b))
    if bits in [8, 16, 32, 64]: result = bits div 8

proc sameScalarType(a, b: Cursor): bool =
  ## `(u 64)` and `(u 64 (importc "size_t"))` are the same machine type.
  a.typeKind == b.typeKind and scalarTypeBytes(a) == scalarTypeBytes(b)

proc constSize(n: Cursor): int =
  ## A compile-time byte count — an integer literal through conversions — or -1.
  var p = n
  while p.kind == TagLit and p.exprKind in {ConvC, CastC, SufC, ParC}:
    if p.exprKind in {ConvC, CastC}:
      inc p; skip p                     # past the target type
    else:
      inc p
  result = if p.kind in {IntLit, UIntLit} and intVal(p) >= 0: int(intVal(p)) else: -1

proc rowOperands(instr: Cursor): seq[Cursor] =
  result = @[]
  var n = instr
  n.into:
    skip n                              # the callee
    while n.hasMore:
      result.add n
      skip n

proc matchScalarMemInstr*(instr: Cursor; op: IntrinsicOp;
                          localTypes: Table[SymId, Cursor];
                          maxBytes: int; allowCmp: bool): ScalarMemOp =
  ## The register form of the block-memory row `op` applied by `instr`, or
  ## `smNone`. `localTypes` maps every scalar local and parameter to its type.
  result = ScalarMemOp(kind: smNone)
  if not op.isMemOp: return
  if op == CmpMemOp and not allowCmp: return
  let args = rowOperands(instr)
  let nLoc = memLocOperands(op)
  if args.len < nLoc: return
  var syms: seq[Cursor] = @[]
  var typ = default(Cursor)
  for i in 0 ..< nLoc:
    let a = args[i]
    if a.kind != TagLit or a.exprKind != HaddrC: return
    var s = a
    inc s
    if s.kind != Symbol or not localTypes.hasKey(s.symId): return
    let t = localTypes.getOrDefault(s.symId)
    if i == 0: typ = t
    elif not sameScalarType(typ, t): return
    syms.add s
  let w = scalarTypeBytes(typ)
  if w <= 0 or w > maxBytes: return
  if args.len > nLoc and constSize(args[nLoc]) != w: return
  case op
  of ZeroMemOp: result = ScalarMemOp(kind: smZero, dst: syms[0], bytes: w)
  of CopyMemOp: result = ScalarMemOp(kind: smCopy, dst: syms[0], src: syms[1], bytes: w)
  else: result = ScalarMemOp(kind: smCmp, dst: syms[0], src: syms[1], bytes: w)

proc memRowArgs*(instr: Cursor; op: IntrinsicOp; firstSize: int;
                 lits: var TokenBuf): seq[Cursor] =
  ## The memory form's three operands in the order the inline loop takes them —
  ## `(dest, 0, n)` for a fill, `(dest, src, n)` / `(a, b, n)` otherwise. The
  ## locations are the `(haddr L)` operands themselves (an address, as a value);
  ## the fill byte and an absent count (`firstSize`: the size of the first
  ## location's type) are literals in `lits`, which the caller keeps alive while
  ## the cursors are in use. A literal needs no position lookup, so a cursor into
  ## another buffer is fine there.
  let args = rowOperands(instr)
  let nLoc = memLocOperands(op)
  lits.addIntLit 0
  lits.addIntLit firstSize
  result = @[args[0]]
  result.add(if op == ZeroMemOp: cursorAt(lits, 0) else: args[1])
  result.add(if args.len > nLoc: args[nLoc] else: cursorAt(lits, 1))
