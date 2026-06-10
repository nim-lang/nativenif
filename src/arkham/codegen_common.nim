#
#           Arkham — shared front-end for the native code generators
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Architecture-neutral front-end shared by the per-target backends
## (`codegen_a64`, `codegen_x64`). Holds the `CodeGen` state object, the NIFC
## type/lvalue analysis (`getType` / `exprSlot` / `asLoc` and friends) and
## the type predicates. None of this emits instructions — instruction selection
## and the machine frame live in the backends. The `md` field carries the
## target `MachineDesc` so the backends drive the (shared) register allocator
## and scratch pools from it.

import std / [tables, sets, assertions]
import nifcore, nifcdecl
import slots, machinedesc, analyser, register_allocator, programs
import asmbuf
import typenav
export typenav   # SymCat / SymInfo / getType / exprSlot moved here; re-export so
                 # the backends' `g.lookupSym(...).cat` etc. keep resolving

type
  CodeGen* = object
    ab*: AsmBuf
    ra*: RegAlloc
    buf*: ptr TokenBuf
    md*: MachineDesc                         ## target register file + ABI
    prog*: Program                           ## the whole program (cross-module type env)
    callTarget*: Table[string, CallTarget]
    globals*: Table[string, Cursor]          ## global var name → its decl cursor
    tvars*: Table[string, Cursor]            ## thread-local var name → its decl cursor (macOS TLV)
    tvarNames*: HashSet[string]              ## tvar names, for the per-proc analyser
    freeTmp*: set[Reg]                       ## volatile temps free for scratch
    freeFTmp*: set[FReg]                     ## volatile SIMD/FP temps free for scratch
    spillCount*: int                         ## fresh-spill-slot counter (per proc): when
                                             ## the scratch pool is exhausted, a computed
                                             ## value is materialized into an `(s)` slot
                                             ## `spill.N` instead of a register — so register
                                             ## allocation never fails
    retIsFloat*: bool                        ## current proc returns a float (in v0)
    retFloatBits*: int                       ## width (32/64) of the float return type
    rodata*: seq[(string, string)]           ## module-level string literals
    hasFrame*: bool                          ## current proc needs a stack frame
    frameRegs*: seq[Reg]                     ## callee-saved GPRs to save (even count)
    frameFRegs*: seq[FReg]                   ## callee-saved SIMD regs to save (even count)
    framePad*: int                           ## x64: extra prologue `sub rsp` for 16-byte call alignment
    labelCount*: int                         ## fresh-label counter
    loopEnds*: seq[string]                   ## stack of enclosing-loop end labels (for `break`)
    retLabel2*: string                       ## value-core: shared epilogue label a mid-proc `ret` jumps to
    retLabelUsed2*: bool                     ## value-core: a `ret` jumped to retLabel2 ⇒ emit the label
    retAggrName*: string                     ## current proc's aggregate return type (or "")
    retIndirect*: bool                       ## return type is >16B (x8 indirect result)
    isEntryProc*: bool                       ## the proc currently emitted is the entry
    a64Linux*: bool                          ## a64 backend: target Linux/ELF (svc-based
                                             ## syscalls, no Darwin TLV/dyld) instead of
                                             ## the default Darwin/Mach-O — lets the arm64
                                             ## output run under qemu-aarch64 on Linux
    sealedF*: set[FReg]                       ## SIMD arg registers (xmm0–7) pinned to an
                                              ## in-flight value: a float arg being marshalled
                                              ## into xmmN, or a transient float staging reg
                                              ## (`pickFStaging`) held across a sibling
                                              ## evaluation. A later float spill's staging
                                              ## pick must avoid these — the float analogue of
                                              ## `sealed`/`liveAccums` on the GPR side.
    liveAccums*: set[Reg]                     ## arg/return registers currently holding an
                                             ## in-flight expression accumulator (a genInto
                                             ## target that is *not* a named local, so absent
                                             ## from `regLocal`). A spill's transient staging
                                             ## register must avoid these — else it clobbers
                                             ## the value being built (e.g. x0 = the return
                                             ## value while a deep right-operand spills).
    indirectReg*: Reg                        ## callee-saved reg holding the x8 dest pointer
    varType*: Table[string, string]          ## aggregate var/param name → its type name
    symType*: Table[string, Cursor]          ## local/param name → its NIFC type cursor (for getType)
    regLocal*: Table[Reg, string]            ## reg → the named local currently bound to it
                                             ## (x64 named-locals: emit the name, not `(reg)`)
    aliasToDecl*: Table[string, string]      ## param ABI alias `pN.0` → the param's own decl
                                             ## name (its `symPos` key). A register-passed
                                             ## param binds its arg reg to the signature alias
                                             ## `pN.0`, which is NOT a `symPos` key; this lets
                                             ## `recordEviction` recover the decl name from the
                                             ## point-in-time `regLocal[r]` with no `ra.locs`
                                             ## reverse scan. Populated at the param prologue.
    boundTemps*: set[Reg]                    ## x64: registers whose `regLocal` entry is a
                                             ## transient scratch temp `(rebind …)`'d by
                                             ## `bindTemp`, NOT a steal-able local. `stealReg`
                                             ## / `evictFixedReg` skip these (a temp is not a
                                             ## local to spill); released by `unbindTemp`.
    tmpBindCount*: int                       ## x64: per-proc fresh-name counter for scratch
                                             ## register bindings (`tmpN.0`). Bumped in BOTH
                                             ## passes so the names replay identically, like
                                             ## `spillCount`.
    scopeLocals*: seq[seq[tuple[name: string, reg: Reg]]]  ## per-scope register locals to `kill`
    fregLocal*: Table[FReg, string]          ## the SIMD twin of `regLocal`: xmm reg → the
                                             ## named float local/scratch currently bound to it
                                             ## (`emFReg` emits the name, not `(xmmN)`). Covers
                                             ## both float register locals (InFReg, declared via
                                             ## `emFRegLocalVar`) and scratch temps (`bindFTmp`).
                                             ## Only the xmm8–15 scratch pool is tracked; the
                                             ## xmm0–7 arg/return/staging regs stay raw.
    boundFTmps*: set[FReg]                    ## SIMD twin of `boundTemps`: xmm regs whose
                                             ## `fregLocal` entry is a transient scratch temp,
                                             ## released by `unbindFTmp`.
    ftmpBindCount*: int                       ## per-proc fresh-name counter for float scratch
                                             ## bindings (`ftmpN.0`); bumped in BOTH passes.
    scopeFLocals*: seq[seq[tuple[name: string, f: FReg]]]  ## per-scope float register locals to `kill`
    savedHomes*: Table[int, Location]        ## value-core pure path: a deref/at/pat base or
                                             ## index whose local was demoted to its stack home
                                             ## by a `stealForTmp` is loaded into a transient
                                             ## staging reg for the lval emission; its original
                                             ## `NamedStack`/`Mem` home is parked here (keyed by
                                             ## value position) and restored by `unbindLvalTemps2`.
    hasGlobalInits*: bool                     ## the module has runtime (non-static) global
                                             ## initializers, emitted as a synthetic init
                                             ## proc the entry calls (see `buildGlobalInitProc`)
    globalInitSym*: string                    ## the synthetic init proc's asm-NIF symbol

# ── type predicates ─────────────────────────────────────────────────────────

proc isSignedType*(c: Cursor): bool =
  ## NIFC arithmetic carries its result type as the first child; treat it as
  ## signed unless it is an unsigned/char integer. (A `case` disambiguates the
  ## NifcType enum members, which share spellings with nifasm's NifasmType.)
  if c.kind != TagLit: return true
  case c.typeKind
  of UT, CT: false
  else: true

proc intTypeWidth*(c: Cursor): int =
  ## Bit width of an integer/char type; 64 for pointer/bool/other (register width).
  if c.kind != TagLit: return 64
  case c.typeKind
  of IT, UT, CT:
    var t = c; inc t
    if t.kind == IntLit and intVal(t) > 0: int(intVal(t)) else: 64
  else: 64

proc slotWidthSigned*(s: AsmSlot): tuple[width: int, signed: bool] =
  ## A scalar slot's significant bit width and signedness (for extension).
  case s.kind
  of AInt:  (s.size * 8, true)
  of AUInt: (s.size * 8, false)
  of ABool: (8, false)
  else:     (64, true)                      # float/aggregate: no widening extend

proc isPtrType*(c: Cursor): bool =
  ## A `case` (not an `in {…}` set) so the discriminant type picks nifcdecl's
  ## `NifcType.PtrT`, not nifasm's same-spelled `NifasmType` member.
  if c.kind != TagLit: return false
  case c.typeKind
  of PtrT, AptrT, ProctypeT: true
  else: false

proc aggrByRef*(g: var CodeGen; typeName: string): bool {.inline.} =
  ## SysV/AAPCS: an aggregate larger than the by-value threshold is passed AND
  ## returned by reference (a hidden pointer) instead of in registers — the single
  ## predicate behind every "by-ref vs by-value" branch (call marshalling, a
  ## call-returned-aggregate var, param moves, incoming-arg-reg counting).
  aggrByteSize(g.prog, typeName) > g.md.aggrByRefThreshold

# ── structural type / slot analysis ─────────────────────────────────────────

proc typeCtx*(g: var CodeGen): TypeCtx {.inline.} =
  ## A `TypeCtx` view over this `CodeGen`'s symbol tables, so `getType` / `exprSlot`
  ## (which now live in `typenav`, below both the allocator and the emitter) read
  ## the same storage. The fields are stable for the lifetime of the call.
  TypeCtx(prog: addr g.prog, callTarget: addr g.callTarget,
          globals: addr g.globals, tvars: addr g.tvars, symType: addr g.symType)

proc lookupSym*(g: var CodeGen; nm: string): SymInfo {.inline.} =
  g.typeCtx.lookupSym(nm)

proc getType*(g: var CodeGen; c: Cursor): Cursor {.inline.} =
  g.typeCtx.getType(c)

proc exprSlot*(g: var CodeGen; c: Cursor): AsmSlot {.inline.} =
  g.typeCtx.exprSlot(c)

proc tryConstFold*(g: var CodeGen; c: Cursor): (bool, int64) =
  ## Evaluate a compile-time-constant INTEGER expression to its value WITHOUT
  ## advancing the cursor or emitting anything: a literal, `sizeof`/`alignof`, or
  ## any `+ - * and or xor shl` over such (recursively). The caller materializes
  ## the result as a single lazy `Imm` Location — one immediate, foldable into the
  ## consuming `cmp`/`add`/… — instead of the runtime mov/sub sequence a tree-walk
  ## would emit (e.g. `SmallChunkSize - sizeof(SmallChunk)` → `0xFC0`, not a
  ## load-load-subtract). Returns (false, 0) for anything not a pure int constant.
  case c.kind
  of IntLit:  return (true, intVal(c))
  of UIntLit: return (true, cast[int64](uintVal(c)))
  of CharLit: return (true, int64(ord(charLit(c))))
  of TagLit:
    case c.exprKind
    of TrueC:        return (true, 1)
    of FalseC, NilC: return (true, 0)
    of SufC, ParC:                               # `(suf v "type")` / `(par v)`
      var t = c; inc t
      return g.tryConstFold(t)
    of SizeofC:
      var t = c; inc t
      return (true, typeSizeAlign(g.prog, t)[0].int64)
    of AlignofC:
      var t = c; inc t
      return (true, typeSizeAlign(g.prog, t)[1].int64)
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC:
      var t = c; inc t; skip t                   # past the result type → operand a
      let (okA, va) = g.tryConstFold(t); skip t  # → operand b
      let (okB, vb) = g.tryConstFold(t)
      if not (okA and okB): return (false, 0)
      case c.exprKind
      of AddC:    return (true, va + vb)
      of SubC:    return (true, va - vb)
      of MulC:    return (true, va * vb)
      of BitandC: return (true, va and vb)
      of BitorC:  return (true, va or vb)
      of BitxorC: return (true, va xor vb)
      of ShlC:    return (true, (if vb >= 0 and vb < 64: va shl vb else: 0))
      else:       return (false, 0)
    else: return (false, 0)
  else: return (false, 0)

proc isFloatExpr*(g: var CodeGen; c: Cursor): bool =
  ## Whether `c` has floating-point type (so it flows through the SIMD path).
  g.exprSlot(c).kind == AFloat

proc floatBits*(g: var CodeGen; c: Cursor): int =
  ## Bit width (32 or 64) of a float expression; 64 when undeterminable (e.g. a
  ## bare literal — the caller's context width should be used instead).
  if g.exprSlot(c).size == 4: 32 else: 64

proc srcWidthSigned*(g: var CodeGen; c: Cursor): tuple[width: int, signed: bool] =
  ## Best-effort source scalar (bit width, signedness) of the expression at `c`,
  ## *without* consuming it — used to pick sign- vs zero-extension when a
  ## conversion *widens*. Unknown → (64, true): treated as full register width,
  ## i.e. no widening extension is applied (the pre-source-aware behaviour).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm)
    if loc.kind != Undef:
      return slotWidthSigned(loc.typ)        # a local/param: the allocator knows it
    let si = g.lookupSym(nm)                   # a global / thread-local: read its decl type
    case si.cat
    of scProc: return (64, true)               # a code pointer
    of scGlobal, scTvar:
      var d = si.decl
      d.into:
        inc d; skip d                          # name, pragmas
        return slotWidthSigned(slotOf(g.prog, d))
    of scNone: return (64, true)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC,
       BitandC, BitorC, BitxorC, BitnotC, NegC, ConvC, CastC:
      var t = c                               # these carry their result type first
      t.into:
        return slotWidthSigned(slotOf(g.prog, t))
    else: return (64, true)
  else: return (64, true)

# ── unified location model (addressing modes + computed values) ─────────────
# `Location` (machinedesc) is THE descriptor for "where a value lives, or should
# go" — a register, a stack slot, a global/thread-local, a foldable memory operand
# (`Mem`, carrying the lvalue subtree to re-emit), an immediate, or `Undef` (the
# dont-care target). It is shared by the register
# allocator (long-lived storage) and the backends (just-computed values + lvalue
# destinations). `asLoc` parses a NIFC lvalue cursor into one; `genVal` produces a
# computed value as one; the `gen`/load-store family consume it. This replaces the
# former separate `Lvalue` + `Val` descriptors that flowed through codegen.

proc asLoc*(g: var CodeGen; c: var Cursor): Location =
  ## Classify and consume an lvalue (Symbol / dot / at / deref) into a `Location`.
  ## `typ` records float-ness/width for the caller. A `Mem` captures the lvalue
  ## subtree (`cur`) so a backend re-emits it as a `(dot …)`/`(at …)`/`(deref …)`
  ## operand; a `NamedStack` is addressed by the *location's* name, not the
  ## variable's (a codegen-time steal renames an evicted register-local's slot to
  ## `evictN.0`; for an un-evicted local the two coincide).
  let slot = g.exprSlot(c)
  let nCur = c                                 # capture the subtree before consuming
  case c.kind
  of Symbol:
    let nm = symName(c); inc c
    let si = g.lookupSym(nm)
    case si.cat
    of scTvar: result = tvarLoc(nm, slot)
    of scGlobal: result = globLoc(nm, slot)
    of scProc:
      # A proc as a value is its address, not an lvalue; `genVal` emits the `lea`.
      raiseAssert "arkham: proc used as an lvalue: " & nm
    of scNone:
      let loc = g.ra.locationOfSym(nm)
      case loc.kind
      of InReg: result = regLoc(loc.r, slot)
      of InFReg: result = fregLoc(loc.f, slot)
      of NamedStack: result = namedStackLoc(loc.name, slot)  # aggregate or scalar; `typ` tells apart
      else: raiseAssert "arkham: symbol is not an lvalue: " & nm
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC, PatC: (result = memLoc(nCur, slot); skip c)
    else: raiseAssert "arkham: not an lvalue: " & $c.exprKind
  else: raiseAssert "arkham: not an lvalue: " & $c.kind

proc retIsVoid*(t: Cursor): bool {.inline.} =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

# ── static constant data layout (shared) ───────────────────────────────────
# Lower a NIFC compile-time constant (`scalar` / `(oconstr …)` / `(aconstr …)` /
# string) to the raw little-endian bytes of its in-memory representation, so a
# backend can emit it as one read-only `(rodata …)` blob instead of zeroing
# `.bss` and running an initialiser at entry. Arch-neutral: the layout follows
# the same `typeSizeAlign` the ABI uses.

proc constLitBits*(c: Cursor): uint64 =
  ## Raw bits of a scalar literal, unwrapping `(suf value "type")` / `(par …)` and
  ## value-preserving reinterprets `(cast Type value)` / `(conv Type value)` — e.g.
  ## `cast[ptr CFile](1)` (a fd encoded as a pointer) collapses to the bits of `1`.
  var v = c
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)   # past the tag + target type
    else: inc v                                        # descend to the wrapped value
  case v.kind
  of IntLit:   result = cast[uint64](intVal(v))
  of UIntLit:  result = uintVal(v)
  of CharLit:  result = uint64(ord(charLit(v)))
  of FloatLit: result = cast[uint64](floatVal(v))
  of TagLit:
    case v.exprKind
    of TrueC:  result = 1'u64
    of FalseC: result = 0'u64
    of NilC:   result = 0'u64
    of NegC:   (inc v; result = cast[uint64](-cast[int64](constLitBits(v))))
    else: raiseAssert "arkham const: unsupported scalar " & $v.exprKind
  else: raiseAssert "arkham const: unsupported literal kind " & $v.kind

proc branchImm*(c: var Cursor): int64 =
  ## A NIFC `BranchValue` for a `case`: a Number / CharLiteral / `(true)` / `(false)`
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

proc appendLE(buf: var string; bits: uint64; size: int) =
  for i in 0 ..< size: buf.add char((bits shr (8 * i)) and 0xFF'u64)

proc constToBytes*(p: var Program; typ, val: Cursor; buf: var string) =
  ## Append the in-memory bytes of constant `val` (of NIFC type `typ`) to `buf`.
  let rt = resolveType(p, typ)
  if rt.kind != TagLit: raiseAssert "arkham const: unresolved type"
  case rt.typeKind
  of IT, UT, CT, BoolT, FT, EnumT:
    let (sz, _) = typeSizeAlign(p, rt)
    appendLE(buf, constLitBits(val), sz)
  of PtrT, AptrT, ProctypeT:
    appendLE(buf, constLitBits(val), 8)      # nil only (address relocs: TODO)
  of FlexarrayT:
    var et = rt; inc et                      # element type
    if val.kind == StrLit:
      buf.add strVal(val)
    else:
      var vc = val                           # (aconstr T elem*)
      vc.into:
        skip vc                              # the constructed type
        while vc.hasMore: (constToBytes(p, et, vc, buf); skip vc)
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
      while vc.hasMore: (constToBytes(p, elemType, vc, buf); skip vc; inc count)
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
            constToBytes(p, ftype, vals[fi], buf)
          else:
            for i in 0 ..< fsz: buf.add '\0'
          inc fi
          off += fsz
    while (buf.len - startLen) < align(off, maxAl): buf.add '\0'  # tail padding
  else:
    raiseAssert "arkham const: unsupported const type " & $rt.typeKind

proc paramName*(idx: int): string {.inline.} =
  ## The asm-NIF symbol for positional call parameter `idx`. nifasm's scope keys
  ## symbols by NIF *basename* (the part before the `.<counter>` suffix), so the
  ## counter cannot disambiguate — `p.0` and `p.1` would both reduce to basename
  ## `p` and collide. Each param therefore gets a distinct basename `pN`.
  result = "p" & $idx & ".0"

proc spillName*(n: int): string {.inline.} =
  ## The asm-NIF symbol for spill slot `n`. Like `paramName`, this must give each
  ## slot a distinct *basename* (`spill0`, `spill1`, …): nifasm's scope keys stack
  ## symbols by NIF basename (the part before the `.<counter>` suffix), so the
  ## counter cannot disambiguate — `spill.0` and `spill.1` would both reduce to
  ## basename `spill` and ALIAS the same stack slot (a value stored to one is read
  ## back from the other). Hence `spillN.0`, not `spill.N`.
  result = "spill" & $n & ".0"

proc operandInReg*(g: var CodeGen; operand: Cursor; dest: Reg): bool =
  ## Does the (peeked, not consumed) `operand` resolve to a register-resident
  ## local whose home register is `dest`? The accumulator codegen evaluates a
  ## binary op's left operand into `dest`; if the *right* operand lives in `dest`
  ## that would clobber it before use, so the caller must save it first. Only
  ## a bare register symbol can alias — a literal has no register, and a nested
  ## expression is materialized into a fresh scratch (never a live local's home).
  result = false
  if operand.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(operand))
    result = loc.kind == InReg and loc.r == dest
