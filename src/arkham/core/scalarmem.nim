#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## `memcpy`/`memset` on the ADDRESS OF A SCALAR LOCAL, lowered as a plain move.
##
## `copyMem(addr result, addr x, 8)` (the C way to reinterpret a float's bits) and
## `zeroMem(addr x, sizeof x)` reach arkham, once the inliner has spliced
## `copyMem`/`zeroMem`, as
##
##   (call memcpy (conv (ptr (void)) (addr D)) (conv (ptr (void)) (addr S)) (conv size_t 8))
##   (call memset (conv (ptr (void)) (addr D)) (conv int 0) (conv size_t (sizeof (i 64))))
##
## Taken literally, the `(addr D)` makes `D` address-taken and pins it to a stack
## slot, and the call is a call point that clobbers the volatiles. But when the size
## is a compile-time constant equal to the width of `D` (and of `S`), the operation
## is exactly `D = bitcast(S)` / `D = 0`: the address never needs to EXIST. So the
## analyser ignores the `addr` for such an operand (it is a def of `D` and a use of
## `S`, nothing more), does not count the call as a call point, and the emitters
## lower it to a register move (`emitScalarMemOp`).
##
## The shape is decided ONCE, here, by the analyser, which records every match in
## `ProcAnalysis.scalarMemOps` keyed by the call's token position. The emitters look
## the call up there and never re-derive the decision: an operand the analyser left
## register-eligible MUST NOT reach the generic lowering, which needs its address.
##
## Only statement-position calls qualify (the call's value — `memcpy`'s returned
## destination pointer — is then dead), and only these operand types: `(i N)`,
## `(u N)`, `(f N)`, `(c N)` of 1, 2, 4 or 8 bytes. A pointer local is excluded
## because its width is the target's, which the analyser does not know; `bool` is
## excluded because a copy into it may produce a value other than 0/1.
## `memcmp` (`smCmp`) is the exception to the statement rule: it is a VALUE, so it
## qualifies wherever the call stands, and the emitters take it at `emitCall`. Its
## operands may be any two scalars of the compared width; their bits are compared,
## not their values. Only a target with a byte-reverse instruction lowers it
## (`allowCmp`).

import std / [tables]
import nifcore, nifcdecl

type
  ScalarMemKind* = enum
    smNone
    smCopy          ## `memcpy(addr D, addr S, sizeof D)`: `D = bitcast[typeof D](S)`
    smZero          ## `memset(addr D, 0, sizeof D)`: `D = 0`
    smCmp           ## `memcmp(addr A, addr B, N)`: an unsigned compare of the two
                    ## operands' bytes in MEMORY order (byte-reversed, as the targets
                    ## are little-endian), giving -1/0/1 — memcmp's sign
  ScalarMemOp* = object
    kind*: ScalarMemKind
    dst*: Cursor    ## the `D` symbol token inside its `(addr …)` (smCmp: `A`)
    src*: Cursor    ## smCopy: the `S` symbol token inside its `(addr …)` (smCmp: `B`)
    bytes*: int     ## the operand width (== the constant size)

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

proc peelConv(n: Cursor): Cursor =
  ## Skip `(conv T x)`, `(cast T x)`, `(suf x "T")`, `(par x)`.
  result = n
  while result.kind == TagLit:
    case result.exprKind
    of ConvC, CastC:
      var t = result
      inc t; skip t                     # past the target type
      result = t
    of SufC, ParC:
      var t = result
      inc t
      result = t
    else: break

proc constSize(n: Cursor): int =
  ## A compile-time byte count: an integer literal (through conversions) or the
  ## `(sizeof T)` of a scalar type. -1 when it is not one.
  let p = peelConv(n)
  case p.kind
  of IntLit, UIntLit:
    let v = intVal(p)
    result = if v >= 0 and v <= 8: int(v) else: -1
  of TagLit:
    if p.exprKind == SizeofC:
      var t = p
      inc t
      let b = scalarTypeBytes(t)
      result = if b > 0: b else: -1
    else:
      result = -1
  else:
    result = -1

proc isZeroLit(n: Cursor): bool =
  let p = peelConv(n)
  p.kind in {IntLit, UIntLit} and intVal(p) == 0

proc addrOfSym(n: Cursor): Cursor =
  ## The symbol token `S` of an `(addr S)`/`(haddr S)` argument (through pointer
  ## conversions), else a cursor whose `kind` is not `Symbol`.
  let p = peelConv(n)
  if p.kind == TagLit and p.exprKind in {AddrC, HaddrC}:
    var s = p
    inc s
    result = s
  else:
    result = n                          # never a Symbol: the caller checks `kind`

proc sameScalarType(a, b: Cursor): bool =
  ## `(u 64)` and `(u 64 (importc "size_t"))` are the same machine type.
  a.typeKind == b.typeKind and scalarTypeBytes(a) == scalarTypeBytes(b)

proc matchScalarMemCall*(call: Cursor; memName: string;
                         localTypes: Table[SymId, Cursor];
                         maxBytes: int; crossClass: bool;
                         allowCmp: bool): ScalarMemOp =
  ## `call` is a `(call F a0 a1 a2)` whose callee `F` lowers as the C function
  ## `memName`. `localTypes` maps every scalar LOCAL (`scalarTypeBytes` > 0) to its
  ## declared type. A copy qualifies between two locals of the same scalar type, or
  ## between a float and an integer of the same width (a bit reinterpretation —
  ## `movq`/`fmov`, exactly what a `cast` between the two emits). `maxBytes` is the
  ## widest operand one register of the target holds; `crossClass` says whether the
  ## target has the float↔GPR move (a soft-float or 32-bit target says no).
  result = ScalarMemOp(kind: smNone)
  if memName notin ["memcpy", "memset", "memcmp"]: return
  if memName == "memcmp" and not allowCmp: return
  var args: seq[Cursor] = @[]
  var n = call
  n.into:
    skip n                              # the callee
    while n.hasMore:
      args.add n
      skip n
  if args.len != 3: return
  let size = constSize(args[2])
  if size <= 0 or size > maxBytes: return
  let d = addrOfSym(args[0])
  if d.kind != Symbol or not localTypes.hasKey(d.symId): return
  let dt = localTypes.getOrDefault(d.symId)
  if scalarTypeBytes(dt) != size: return
  if memName == "memcmp":
    let b = addrOfSym(args[1])
    if b.kind != Symbol or not localTypes.hasKey(b.symId): return
    if scalarTypeBytes(localTypes.getOrDefault(b.symId)) != size: return
    return ScalarMemOp(kind: smCmp, dst: d, src: b, bytes: size)
  if memName == "memcpy":
    let s = addrOfSym(args[1])
    if s.kind != Symbol or not localTypes.hasKey(s.symId): return
    let st = localTypes.getOrDefault(s.symId)
    if scalarTypeBytes(st) != size: return
    let isCross = (dt.typeKind == FT) != (st.typeKind == FT)
    if isCross:
      if not crossClass: return
    elif not sameScalarType(dt, st): return
    result = ScalarMemOp(kind: smCopy, dst: d, src: s, bytes: size)
  else:
    if not isZeroLit(args[1]): return
    result = ScalarMemOp(kind: smZero, dst: d, bytes: size)

proc directCalleeTokens*(decl: Cursor): seq[Cursor] =
  ## The callee token of every `(call SYM …)` in `decl` whose callee is a bare
  ## symbol — the candidates the driver resolves into `memCallNames`.
  result = @[]
  var stack = @[decl]
  while stack.len > 0:
    let n = stack.pop()
    if n.kind != TagLit: continue
    var it = n
    it.into:
      if (n.stmtKind == CallS or n.exprKind == CallC) and it.kind == Symbol:
        result.add it
      while it.hasMore:
        if it.kind == TagLit: stack.add it
        skip it
