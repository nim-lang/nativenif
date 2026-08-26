#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Constants that become DATA rather than instructions.
##
## A `const` blob, a global’s initializer, a float literal’s exact bits. The
## interesting cases are the ones that cannot be bytes yet: a pointer field
## inside a blob names a symbol whose address is a layout fact, so it is emitted
## as a relocation for nifasm to bake in.

import std / [tables, sets, assertions, algorithm, strutils, os]
import symparser
import nifcore, nifcdecl
import asmslots, machinedesc, analyser, planer, programs, abi
import "../arm/machine_m"
import layout, asmbuf, typenav, regbind, context
import diag, asmcommon, typeutil


# ── static constant data layout (shared) ───────────────────────────────────
# Lower a Leng compile-time constant (`scalar` / `(oconstr …)` / `(aconstr …)` /
# string) to the raw little-endian bytes of its in-memory representation, so a
# backend can emit it as one read-only `(rodata …)` blob instead of zeroing
# `.bss` and running an initialiser at entry. Arch-neutral: the layout follows
# the same `typeSizeAlign` the ABI uses.

proc specialFloatBits*(ek: LengExpr; bits: int): int64 =
  ## IEEE-754 bit pattern of `(inf)` / `(-inf)` / `(nan)` at `bits` width. Both
  ## backends materialize these through a GPR: the exponent-all-ones patterns are
  ## outside what either ISA's float immediate encoding reaches (a64's `fmov`
  ## 8-bit immediate covers normal values only; x64 has no float immediate at
  ## all). `nan` is the quiet NaN — the sign bit is clear and the payload is the
  ## leading quiet bit, matching what every other backend emits for it.
  if bits == 32:
    case ek
    of InfC: 0x7F80_0000'i64
    of NeginfC: 0xFF80_0000'i64
    else: 0x7FC0_0000'i64
  else:
    case ek
    of InfC: 0x7FF0_0000_0000_0000'i64
    of NeginfC: cast[int64](0xFFF0_0000_0000_0000'u64)
    else: 0x7FF8_0000_0000_0000'i64

proc constLitBits*(c: Cursor): uint64 =
  ## Raw bits of a scalar literal, unwrapping `(suf value "type")` / `(par …)` and
  ## reinterprets `(cast Type value)` (e.g. `cast[ptr CFile](1)` collapses to the bits
  ## of `1`). A `(conv Type value)` is value-preserving for a same-class conversion, but
  ## a class-CHANGING conversion — int↔float — is a NUMERIC conversion (`(conv (f 64) 123)`
  ## ⇒ the bits of `123.0`, NOT of the integer `123`), so the outermost conv's target
  ## class is tracked and applied to the base literal.
  var v = c
  var convTargetFloat = -1                             # -1 unknown / 0 int-class / 1 float-class
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind == ConvC:
      var t = v; inc t                                 # → target type
      if convTargetFloat < 0:                          # remember the OUTERMOST conv's target class
        convTargetFloat = (if t.kind == TagLit and t.typeKind == FT: 1 else: 0)
      skip t; v = t                                    # → the wrapped value
    elif v.exprKind == CastC: (inc v; skip v)          # bit-reinterpret: past tag + target type
    else: inc v                                        # suf/par: descend to the wrapped value
  var rawFloat = false
  case v.kind
  of IntLit:   result = cast[uint64](intVal(v))
  of UIntLit:  result = uintVal(v)
  of CharLit:  result = uint64(ord(charLit(v)))
  of FloatLit: (result = cast[uint64](floatVal(v)); rawFloat = true)
  of TagLit:
    case v.exprKind
    of TrueC:  result = 1'u64
    of FalseC: result = 0'u64
    of NilC:   result = 0'u64
    of NegC:   (inc v; result = cast[uint64](-cast[int64](constLitBits(v))))
    of InfC, NeginfC, NanC:
      # Always the f64 pattern; the FT case of `constToBytes` narrows it when the
      # constant's type is `(f 32)`, exactly as it does for a plain float literal.
      result = cast[uint64](specialFloatBits(v.exprKind, 64)); rawFloat = true
    else: raiseAssert "arkham const: unsupported scalar " & $v.exprKind
  else: raiseAssert "arkham const: unsupported literal kind " & $v.kind
  # Apply a class-changing int↔float conversion against the base literal's class.
  if convTargetFloat == 1 and not rawFloat:
    result = cast[uint64](float64(cast[int64](result)))   # int → float (123 ⇒ 123.0)
  elif convTargetFloat == 0 and rawFloat:
    result = cast[uint64](int64(cast[float64](result)))   # float → int (truncating)

proc branchImm*(c: var Cursor): int64 =
  ## A Leng `BranchValue` for a `case`: a Number / CharLiteral / `(true)` / `(false)`
  ## or a typed/wrapped constant `(suf 3 +Enum)` / `(cast …)` / `(neg …)`. Advance
  ## past it. (Symbol branch values — enum consts — are not yet supported.) Shared
  ## by both backends; wrapped forms unwrap through `constLitBits`.
  case c.kind
  of IntLit:  result = intVal(c); inc c
  of UIntLit: result = cast[int64](uintVal(c)); inc c
  of CharLit: result = int64(ord(charLit(c))); inc c
  of TagLit:
    case c.exprKind
    of TrueC:  result = 1; skip c
    of FalseC: result = 0; skip c
    of SufC, ParC, CastC, ConvC, NegC:                  # typed/wrapped enum-or-int
      result = cast[int64](constLitBits(c)); skip c     # `(suf 3 +Enum)` → 3
    else: raiseAssert "arkham: unsupported case branch value: " & $c.exprKind
  else: raiseAssert "arkham: unsupported case branch value kind: " & $c.kind

proc isConstScalarInit*(c: Cursor): bool =
  ## Whether an initializer is a compile-time-constant SCALAR — a literal, a
  ## bool/nil literal, or a (negate / cast / conv / suf / par) wrapping one. Such a
  ## gvar initializer can be laid out as static data (see the backend `genGlobal`),
  ## so it is correct even for a FOREIGN module's gvar in a bundle, where the
  ## module's entry-time initializer code never runs. (Aggregate constructors and
  ## address-of initializers — which need a relocation — are NOT covered here.)
  var v = c
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC, NegC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)   # past the tag + target type
    else: inc v                                        # descend to the wrapped value
  case v.kind
  of IntLit, UIntLit, CharLit, FloatLit: true
  of TagLit: v.exprKind in {TrueC, FalseC, NilC}
  else: false

proc constAddrSym*(c: Cursor): string =
  ## If `c` is a static-ADDRESS initializer — a bare symbol naming a proc or
  ## global (a link-time constant address), possibly wrapped in the same
  ## conv/cast/par peels as `isConstScalarInit` — return that symbol's name; else
  ## "". A function-pointer hook (`var gExitFlush = nimNoopFlush`) is the canonical
  ## case. The backend `genGlobal` emits it as the gvar's value and nifasm bakes
  ## the resolved address into the `.bss` slot (see nifasm `bssSymInits`), so it is
  ## correct even for a FOREIGN module's gvar in a bundle whose entry-time
  ## initializer code never runs — unlike the runtime `(asgn)` path.
  result = ""
  var v = c
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)
    else: inc v
  # An explicit address-of a global/const/proc symbol — `(addr strlit.0)` is the
  # canonical case (a string literal's `more` field points at the data const). The
  # symbol's address is a link-time constant, so it bakes as a reloc exactly like a
  # bare symbol. Peel the `(addr …)` then any further conv/cast/par wrappers.
  if v.kind == TagLit and v.exprKind in AddrKinds:
    inc v                                              # past the (addr tag
    while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
      if v.exprKind in {CastC, ConvC}: (inc v; skip v)
      else: inc v
  if v.kind == Symbol: result = symName(v)

proc isStaticConstInit*(c: Cursor): bool =
  ## Whether an initializer is a compile-time constant that `constToBytes` can lay
  ## out as raw bytes: a scalar literal, a static address, a string, or an
  ## `(aconstr …)`/`(oconstr …)` built recursively out of those.
  ##
  ## This is the IR CONTRACT for a `gvar`'s value. Anything else is code, and code
  ## is not arkham's to schedule: hexer lowers a runtime initializer to an `(asgn …)`
  ## in the module's init proc (`lengcgen`'s `trToplevel`), which reaches arkham as
  ## an ordinary statement. `genGlobal` rejects a violation rather than guessing.
  if c.kind == StrLit: return true
  if isConstScalarInit(c): return true
  if constAddrSym(c).len > 0: return true
  if c.kind == TagLit and c.exprKind in {AconstrC, OconstrC}:
    result = true
    var vc = c
    vc.into:
      skip vc                                  # the constructed type
      while vc.hasMore:
        if vc.kind == TagLit and vc.substructureKind == KvU:
          var kv = vc
          kv.into:
            inc kv                             # field name
            if kv.hasMore and not isStaticConstInit(kv): result = false
            while kv.hasMore: skip kv
        elif not isStaticConstInit(vc):
          result = false
        skip vc
  else:
    result = false

proc appendLE(buf: var string; bits: uint64; size: int) =
  for i in 0 ..< size: buf.add char((bits shr (8 * i)) and 0xFF'u64)

proc constScalarBits*(p: var Program; typ, val: Cursor): uint64 =
  ## `constLitBits`, narrowed to the width of the DECLARED type. `constLitBits`
  ## speaks f64 throughout, so an `(f 32)` constant needs its value ROUNDED to
  ## single precision: truncating the double bits to four bytes yields 0 for
  ## every literal whose mantissa fits in a double's low word — i.e. all of them.
  result = constLitBits(val)
  let rt = resolveType(p, typ)
  if rt.kind == TagLit and rt.typeKind == FT and typeSizeAlign(p, rt)[0] == 4:
    result = uint64(cast[uint32](float32(cast[float64](result))))

proc constToBytes*(p: var Program; typ, val: Cursor; buf: var string;
                   relocs: var seq[(int, string)]) =
  ## Append the in-memory bytes of constant `val` (of Leng type `typ`) to `buf`.
  ## A pointer/proc field whose value is a *symbol address* (e.g. a vtable/RTTI
  ## const pointing at another const or a proc — `(cast (ptr …) Foo.0.vt)`) cannot
  ## be baked at compile time; record `(blob-offset, symbol-name)` in `relocs` and
  ## reserve one WORD of placeholder bytes. The backend emits these as `(reloc off sym)`
  ## children of the `(rodata …)` blob and nifasm bakes the resolved address into
  ## `.text` in `writeElf`. `relocs` offsets are relative to the blob start, so the
  ## top-level caller must pass a `buf` that begins empty (the blob).
  let rt = resolveType(p, typ)
  if rt.kind != TagLit: raiseAssert "arkham const: unresolved type"
  case rt.typeKind
  of IT, UT, CT, BoolT, FT, EnumT:
    let (sz, _) = typeSizeAlign(p, rt)
    appendLE(buf, constScalarBits(p, rt, val), sz)
  of PtrT, AptrT, ProctypeT:
    let addrSym = constAddrSym(val)
    if addrSym.len > 0:
      relocs.add (buf.len, addrSym)          # link-time address (baked by nifasm)
      for i in 0 ..< wordSize(): buf.add '\0'  # placeholder for the address
    else:
      appendLE(buf, constLitBits(val), wordSize())  # nil / integer-encoded address
  of FlexarrayT:
    var et = rt; inc et                      # element type
    if val.kind == StrLit:
      buf.add strVal(val)
    else:
      var vc = val                           # (aconstr T elem*)
      vc.into:
        skip vc                              # the constructed type
        while vc.hasMore: (constToBytes(p, et, vc, buf, relocs); skip vc)
  of ArrayT:
    var et = rt; inc et                      # element type
    let elemType = et
    skip et                                  # past element type → length
    let n = if et.kind == IntLit: int(intVal(et)) else: 0
    let (esz, _) = typeSizeAlign(p, elemType)
    var count = 0
    var vc = val                             # (aconstr T elem*)
    vc.into:
      skip vc                                # the constructed type
      while vc.hasMore: (constToBytes(p, elemType, vc, buf, relocs); skip vc; inc count)
    for k in count ..< n:                    # zero-fill trailing elements
      for i in 0 ..< esz: buf.add '\0'
  of ObjectT:
    # Match each `(oconstr … (kv field value) …)` value to a type field
    # *positionally* (hexer emits constructor fields in declaration order). This
    # avoids decoding field-name symbols, which sidesteps the foreign-module
    # string-pool of a cross-module type (the value literals live in *our* pool;
    # the type only supplies sizes/offsets via `typeSizeAlign`). A trailing
    # `flexarray` field (size 0) appends its bytes past the fixed part.
    let startLen = buf.len
    var vals: seq[Cursor] = @[]
    var vc = val
    vc.into:
      skip vc                                # the constructed type
      while vc.hasMore:
        vc.into:                             # (kv field value)
          inc vc                             # skip field name (atom → no pool)
          vals.add vc
          while vc.hasMore: skip vc
    var oc = rt
    var off = 0
    var maxAl = 1
    var fi = 0
    oc.into:
      # An object *constant* of an inherited type would need the base's fields
      # laid out first (positionally matched against the leading oconstr values),
      # like objSizeAlign/aggrLayout do for runtime layout. Not yet implemented —
      # fail loudly rather than emit silently-misaligned bytes.
      if oc.kind == Symbol:
        raiseAssert "arkham: object constant of an inherited type not yet supported"
      skip oc                                # base / inheritance
      while oc.hasMore:
        oc.into:                             # (fld :name pragmas type)
          inc oc                             # skip field name (atom → no pool)
          skip oc                            # field pragmas
          let ftype = oc
          let (fsz, fal) = typeSizeAlign(p, oc)
          skip oc
          off = align(off, fal)
          if fal > maxAl: maxAl = fal
          while buf.len < startLen + off: buf.add '\0'   # pad to field offset
          if fi < vals.len:
            constToBytes(p, ftype, vals[fi], buf, relocs)
          else:
            for i in 0 ..< fsz: buf.add '\0'
          inc fi
          off += fsz
    while (buf.len - startLen) < align(off, maxAl): buf.add '\0'  # tail padding
  else:
    raiseAssert "arkham const: unsupported const type " & $rt.typeKind

proc genGlobalInitValue*(g: var CodeGen; name: string; typ, val: Cursor; hasValue: bool) =
  ## Emit a gvar's initial VALUE into the open `(gvar :name <type> …)` as STATIC
  ## data: nifasm prefills the (writable) slot from the on-disk image, so the value
  ## is there before any code runs — correct for a foreign module's gvar in a bundle
  ## just as much as for the main module's.
  ##
  ## Three shapes, cheapest first: a scalar's raw bits; a symbol whose address only
  ## the final layout knows, which nifasm bakes into the slot; and an object / array
  ## / string constant, laid out by `constToBytes` as bytes plus one `(reloc off
  ## sym)` per address-valued field.
  ##
  ## A value that is NOT a compile-time constant is a contract violation, not a case
  ## to fall back on: hexer lowers a runtime initializer to an `(asgn …)` in the
  ## module's init proc (`lengcgen`'s `trToplevel`), so it reaches arkham as an
  ## ordinary statement and never as a gvar value. Say so rather than guess.
  if not hasValue: return
  if isConstScalarInit(val):
    g.ab.intLit cast[int64](constScalarBits(g.prog, typ, val))
  else:
    let addrSym = constAddrSym(val)
    if addrSym.len > 0:
      g.ab.sym addrSym
    elif isStaticConstInit(val):
      var bytes = ""
      var relocs: seq[(int, string)] = @[]
      constToBytes(g.prog, typ, val, bytes, relocs)
      g.ab.str bytes
      for (off, sym) in relocs:
        g.ab.tree RelocX:
          g.ab.intLit off
          g.ab.sym sym
    else:
      lengError val, "the initializer of the global `" & name & "` is not a compile-time " &
        "constant. Runtime initialization belongs in the module\'s init proc as an " &
        "assignment, which is where hexer lowers it"