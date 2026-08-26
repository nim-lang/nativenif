#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## "What is this value, and how wide?" — the type questions the emitters ask.
##
## Signedness and width, pointer-ness, the `AsmSlot` a Leng type classifies to,
## and the `Location` an lvalue reduces to. Two things worth naming: an
## arithmetic result whose type arkham cannot pin is refused rather than
## guessed (`checkArithResultType`), and `arrivesNormalized` is what decides
## whether a sub-word value still needs its extend — the difference between
## correct narrow arithmetic and a silent 32-bit answer.

import std / [assertions, strutils]

import nifcore, nifcdecl
import asmslots, machinedesc, planer, programs
import "../arm/machine_m"
import asmbuf, typenav, context
import diag


# ── type predicates ─────────────────────────────────────────────────────────

proc isSignedType*(c: Cursor): bool =
  ## Leng arithmetic carries its result type as the first child; treat it as
  ## signed unless it is an unsigned/char integer. (A `case` disambiguates the
  ## LengType enum members, which share spellings with nifasm's NifasmType.)
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
  ## `LengType.PtrT`, not nifasm's same-spelled `NifasmType` member.
  if c.kind != TagLit: return false
  case c.typeKind
  of PtrT, AptrT, ProctypeT: true
  else: false

proc binResultSlot*(g: var CodeGen; resTypeC: Cursor): AsmSlot =
  ## The slot for the register a binary-arith result lands in: the node's OWN
  ## result type, so the temp is bound `(c 8)`/`(u 16)`/… rather than a dont-care
  ## `(i 64)`. The register is 64 bits wide either way — that is where the value
  ## lives, not what it is, and binding it as `(i 64)` discards the range and the
  ## signedness the rest of the pipeline is entitled to check.
  var t = resTypeC
  result = slotOf(g.prog, t)

proc bindTypeDiffers*(prog: var Program; a, b: Cursor): bool =
  ## Would nifasm see two different BINDING types for `a` and `b`? Compares exactly
  ## what a register binding declares — pointer-ness, width, signedness — so a
  ## caller can skip a retype that would emit the same type it already has.
  ## Two pointers always count as differing: the pointee drives field/element
  ## typing, and a retype between them is free (zero machine code).
  let ra = resolveType(prog, a)
  let rb = resolveType(prog, b)
  let pa = isPtrType(ra)
  let pb = isPtrType(rb)
  if pa or pb: return true
  result = intTypeWidth(ra) != intTypeWidth(rb) or isSignedType(ra) != isSignedType(rb)
  if not result:
    # `intTypeWidth` answers 64 for anything that is not a literal `(i|u|c N)`, so
    # every ENUM looks the same width as every other. nifasm types an enum binding
    # by its BASE, and `(u 16)` vs `(u 8)` is exactly the mismatch that reached it:
    # `(cast NimonyType e)` out of a `TagEnum` skipped the pre-retype in `emitCast2`
    # and emitted a bare narrowing move. The SLOT does carry the base width.
    var ac = a
    var bc = b
    result = slotOf(prog, ac).size != slotOf(prog, bc).size

proc slotTypeDiffers*(prog: var Program; s: AsmSlot; t: Cursor): bool =
  ## `bindTypeDiffers` for a slot that may carry no cursor at all. A dont-care slot
  ## binds as `(i 64)`, so it differs from anything that is not that.
  if cursorIsNil(s.typ):
    let rt = resolveType(prog, t)
    return isPtrType(rt) or intTypeWidth(rt) != 64 or not isSignedType(rt)
  var a = s.typ
  result = bindTypeDiffers(prog, a, t)

proc checkArithResultType*(prog: var Program; resTypeC: Cursor; fallback = "") =
  ## An arithmetic node states its result type as its first child, and that type is
  ## an integer or a float. NO pointer is legal — not `(ptr T)`, not `(aptr T)`, not
  ## a proc type. Arithmetic on a pointer is not a Leng form.
  ##
  ## The reason is that an `add` does not say whether the offset counts BYTES or
  ## ELEMENTS, and the backends answered differently: nifasm emitted a plain machine
  ## `add` (bytes) while lengc compiles the same node as `((T)(a + b))` — C pointer
  ## arithmetic, SCALED by the pointee. Nothing in the program says which the
  ## producer meant, so there is no reinterpretation that is safe to pick.
  ##
  ## Both well-typed spellings already exist. Offsetting an array pointer is
  ## `(at base index)` / `(pat p i)`, which carry the element type and so have ONE
  ## meaning; raw byte work casts to an integer, computes, and casts back — the
  ## shape `cast_ptr_local_retype` exercises in the corpus.
  ##
  ## (`(aptr T)` was admitted here at first, on the theory that the array pointer's
  ## element stride made its arithmetic well-defined. It does not: the stride tells
  ## you what one element is, not whether `+ 8` meant eight of them.)
  let rt = resolveType(prog, resTypeC)
  if isPtrType(rt):
    lengError(resTypeC, "arithmetic result type is a pointer (" & $rt.typeKind &
              "); Leng has no arithmetic on pointers. Offset an array pointer with " &
              "`(at …)`/`(pat …)`, or cast to an integer, compute, and cast back.",
              fallback)

proc isNilValue*(c: Cursor): bool {.inline.} =
  ## True if `c` is the synthesized Leng `(nil)` node (a null-pointer value/type).
  not cursorIsNil(c) and c.kind == TagLit and c.exprKind == NilC

proc isNilSlot*(s: AsmSlot): bool {.inline.} =
  ## True if `s` carries the synthesized Leng `(nil)` type (a null pointer) — its
  ## register binds to the asm `(nil)` type and its immediate emits `(nil)`, not `0`.
  isNilValue(s.typ)

proc isSubWidthIntSlot*(s: AsmSlot): bool {.inline.} =
  ## A sized integer slot NARROWER than a register — `(i 32)`, `(u 8)`, … — that also
  ## carries its Leng type (so it can be re-emitted in a `(cast …)`). arkham keeps every
  ## register-homed local a full `(i 64)` binding and expresses width through explicit
  ## extends, so a temp bound to one of these is a deliberate narrow BRIDGE: a value
  ## arriving from a full-width register must be reinterpreted into it, never `mov`ed
  ## (nifasm allows only widening moves).
  s.kind in {AInt, AUInt} and s.size > 0 and s.size < 8 and not cursorIsNil(s.typ)

proc isNilImm*(loc: Location): bool {.inline.} =
  ## A `nil` value resolved to an immediate (`p = nil`, `p == nil`): emit `(nil)`.
  loc.kind == Imm and isNilSlot(loc.typ)

proc aggrByRef*(g: var CodeGen; typeSym: SymId): bool {.inline.} =
  ## SysV/AAPCS: an aggregate larger than the by-value threshold is passed AND
  ## returned by reference (a hidden pointer) instead of in registers — the single
  ## predicate behind every "by-ref vs by-value" branch (call marshalling, a
  ## call-returned-aggregate var, param moves, incoming-arg-reg counting).
  aggrByteSize(g.prog, typeSym) > g.md.aggrByRefThreshold

proc emTypeSym*(g: var CodeGen; id: SymId) {.inline.} =
  ## Emit the nominal type `id` as an asm-NIF symbol — THE boundary where a pool id
  ## becomes text, and now the only one. The asm buffer gets its own pool
  ## (`initAsmBuf` calls `createTokenBuf` with no `sharedPool`), so an INPUT-pool id
  ## is meaningless there and the name has to cross as characters; `addSymUse`
  ## re-interns it on the far side.
  ##
  ## Everything upstream of this call is keyed by the id: `lookupType` and the
  ## layout API over it, `varType`, `Location.StackPtr.pointeeType` /
  ## `Location.Field.aggrType`, `retAggrSym`. `pool.syms[]` yields `lent string`, so
  ## the operand costs no copy.
  g.ab.sym g.prog.pool.syms[id]

proc truncateImm*(v: int64; bits: int; signed: bool): int64 {.inline.} =
  ## Keep the low `bits` of `v`, sign-extending when `signed`. A Leng
  ## `cast[byte](4000)` is this truncation, not a nifasm-illegal
  ## `(mov (u 8) 4000)`.
  if bits <= 0 or bits >= 64: return v
  let mask = (1'i64 shl bits) - 1
  result = v and mask
  if signed and (result and (1'i64 shl (bits - 1))) != 0:
    result = result or (not mask)

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

template ScalarSlot*(): AsmSlot =
  ## The dont-care scalar placeholder: an integer of REGISTER width. A
  ## template rather than a `let` because a module-level `let` is evaluated
  ## before the backend entry point calls `setTargetWord`, so it would snapshot
  ## the 64-bit default and describe every Cortex-M scratch as eight bytes —
  ## which is exactly how a 32-bit dont-care becomes indistinguishable from a
  ## genuine 64-bit value (`isWideSlot`).
  ##
  ## THE dont-care scalar slot: one full integer register, carrying no Leng type
  ## cursor. Not a missing type — it is arkham's canonical register form for an
  ## integer, whose width lives in explicit extends rather than in the register.
  ## See `valueSlot` for when a value may take it and when it may not. No consumer
  ## of an `InReg`/`Imm` value reads `.typ`, so it is also the register/immediate
  ## dont-care result. (Both backends used to define this separately.)
  AsmSlot(cls: AInt, size: wordSize(), align: wordAlign())

proc slotIsPointer*(g: var CodeGen; s: AsmSlot): bool =
  ## Does `s` describe a POINTER-KIND value — a real `(ptr T)`/`(aptr T)`/`(proctype …)`,
  ## or the `(nil)` literal? The one place that answers this, so the emitters stop
  ## spelling `not cursorIsNil(s.typ) and isPtrType(resolveType(…))` out by hand.
  ##
  ## A dont-care `ScalarSlot` carries no cursor and is NOT one: that is the deliberate
  ## "canonical 64-bit integer register" marker, not a missing type — see `valueSlot`.
  if isNilSlot(s): return true
  if cursorIsNil(s.typ): return false
  isPtrType(resolveType(g.prog, s.typ))

proc valueSlot*(g: var CodeGen; c: Cursor): AsmSlot =
  ## THE slot to bind a register temp that is about to hold the VALUE of `c`.
  ##
  ## Two different things get called "the type" of a register here, and only one of
  ## them may be dropped:
  ##
  ## * An integer's WIDTH is not carried by its register. arkham keeps every integer
  ##   full-register-width and expresses narrowness with explicit extends, so an
  ##   integer value temp is canonically `ScalarSlot`. Binding it at the value's own
  ##   narrow width makes the very move that brings a 64-bit value in a NARROWING
  ##   move, which nifasm rejects — see `emitCast2`'s canonical-width rule, which
  ##   exists for exactly that reason.
  ## * A pointer's POINTER-NESS is not a width, and it must survive. Losing it is what
  ##   turns `cmp tmp, (nil)` and `mov (mem &ptrGlobal), tmp` into type errors, and it
  ##   is what nifasm's strictness is there to catch.
  ##
  ## So: pointer/`nil` values keep their real type, integers keep the canonical
  ## register width. `c` having no type node at all is not a failure — a Leng literal
  ## is typed by where it GOES, and `ScalarSlot` is the right answer for it.
  let s = g.exprSlot(c)
  if g.slotIsPointer(s): s else: ScalarSlot

proc globalDeclType*(g: var CodeGen; name: string): Cursor =
  ## The DECLARED type of a module-level `gvar` / `tvar` / `const` — the third child
  ## of its `SymInfo.decl`, which every global has.
  ##
  ## This is where a global's type LIVES, so a `Glob`/`Tvar` `Location` never has to
  ## fall back on a guess when its own `AsmSlot` was built from a dont-care
  ## `ScalarSlot` and carries no cursor. The emitters used to branch on
  ## `cursorIsNil(loc.typ.typ)` and emit an untyped `(mem reg)` on the nil side —
  ## which nifasm reads as a bare `(i 64)` access, exactly the imprecision that made
  ## `exc = nil` (a `ptr Exception` threadvar) a type error.
  let si = g.lookupSym(name)
  assert si.cat in {scGlobal, scTvar},
         "arkham: globalDeclType of a non-global symbol: " & name
  var d = si.decl
  result = si.decl                              # overwritten below (always present)
  d.into:
    inc d; skip d                               # name, pragmas → the declared type
    result = d
    while d.hasMore: skip d

proc declType*(g: var CodeGen; typeCur, valueCur: Cursor): Cursor =
  ## The type a local should be DECLARED with. Shoggoth's SROA / cse /
  ## induction-variable passes synthesize `(var :t . . <value>)` with the type
  ## slot LEFT EMPTY and the type implied by the initializer — a form lengc
  ## already infers (`codegen.genVarDecl`'s `getNominalType` fallback), so
  ## arkham must too. An empty slot otherwise sizes as `AMem 0` (which asserts
  ## in `typeSizeAlign`) and, worse, an `(addr x)` initializer silently loses
  ## its `(ptr T)`-ness so every later deref/field access mistypes.
  ## `allocVarDecl` already infers the SLOT this way (`typeIsOmitted`); this
  ## gives the emitter and `symType` the matching type CURSOR, so the two
  ## passes agree.
  if typeCur.kind != DotToken: return typeCur
  if not valueCur.hasMore or valueCur.kind == DotToken: return typeCur
  result = g.getType(valueCur)

proc tryConstFold*(g: var CodeGen; c: Cursor): (bool, int64) =
  ## Evaluate a compile-time-constant INTEGER expression to its value WITHOUT
  ## advancing the cursor or emitting anything. Delegates to `constFold`
  ## (programs.nim) — the ONE width-masked evaluator the allocator and both
  ## emitters consult, so a fold decision is a pure function of the subtree and
  ## the passes cannot disagree about it. The caller materializes the result as
  ## a single `Imm` Location — one immediate, foldable into the consuming
  ## `cmp`/`add`/… — instead of the runtime mov/sub sequence a tree-walk would
  ## emit (e.g. `SmallChunkSize - sizeof(SmallChunk)` → `0xFC0`, not a
  ## load-load-subtract).
  constFold(g.prog, c)

proc isFloatExpr*(g: var CodeGen; c: Cursor): bool =
  ## Whether `c` has floating-point type (so it flows through the SIMD path).
  g.exprSlot(c).kind == AFloat

proc floatBits*(g: var CodeGen; c: Cursor): int =
  ## Bit width (32 or 64) of a float expression; 64 when undeterminable (e.g. a
  ## bare literal — the caller's context width should be used instead).
  if g.exprSlot(c).size == 4 or maxFloatSize() == 4: 32 else: 64

proc srcWidthSigned*(g: var CodeGen; c: Cursor): tuple[width: int, signed: bool] =
  ## Best-effort source scalar (bit width, signedness) of the expression at `c`,
  ## *without* consuming it — used to pick sign- vs zero-extension when a
  ## conversion *widens*. Unknown → (64, true): treated as full register width,
  ## i.e. no widening extension is applied (the pre-source-aware behaviour).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.plan.locationOfSym(nm, cursorToPosition(g.buf[], c))
    if loc.kind != NoLoc:
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
  of UIntLit, CharLit:
    # An UNSIGNED literal. The width is the full register (nothing to extend), but
    # the signedness decides `scvtf` vs `ucvtf`: `float(0xFFFF_FFFF_FFFF_FFFF'u64)`
    # is 1.8446744073709552e19, not -1.0.
    return (64, false)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC,
       BitandC, BitorC, BitxorC, BitnotC, NegC, ConvC, CastC:
      var t = c                               # these carry their result type first
      t.into:
        return slotWidthSigned(slotOf(g.prog, t))
    of SufC, ParC:                            # wrappers: the inner value decides
      var t = c
      t.into:
        return g.srcWidthSigned(t)
    of TrueC, FalseC: return (64, false)
    else: return (64, true)
  else: return (64, true)

proc literalArrivesNormalized(lit: Cursor; width: int; signed: bool): bool =
  ## Is the integer literal at `lit` already in the canonical 64-bit register form
  ## for (`width`, `signed`)? A literal reaches a register through `movImm`, which
  ## writes its exact 64-bit two's-complement value — so the answer is simply
  ## whether the value is in that type's range. `-1` IS canonical for a signed
  ## 32-bit target (all ones is int32(-1) sign-extended) and is NOT for an unsigned
  ## one. `width` is 1..63 here (the caller excluded 0 and 64), so both shifts fit.
  let hi = 1'i64 shl (width - 1)
  case lit.kind
  of IntLit:
    let v = intVal(lit)
    if signed: v >= -hi and v < hi
    else: v >= 0 and v < (1'i64 shl width)
  of UIntLit:
    let u = uintVal(lit)
    if signed:
      let v = cast[int64](u)
      v >= -hi and v < hi
    else: u < (1'u64 shl width)
  else: false

proc arrivesNormalized*(g: var CodeGen; src: Cursor; width: int; signed: bool): bool =
  ## True when emitting `src` into a register ALREADY leaves the canonical 64-bit
  ## form for (`width`, `signed`) — so the `extendTo` a conversion would append is
  ## dead code. `extendTo` costs a shift PAIR on both targets, and `nifcore.kind`
  ## carried two of them (4 of its 14 instructions) around a body that is a load
  ## and a mask; `nifcore.Cursor`'s whole token-dispatch path carried twelve.
  ##
  ## Deliberately syntactic and deliberately narrow: it claims a fact only where
  ## the fact is established by the very next instruction nifasm emits, never from
  ## a whole-function invariant. Shared by both backends because every fact it
  ## reads is a Leng-level or nifasm-level one, not an encoding-level one.
  if width <= 0 or width >= 64: return false
  # 1. The source's own scalar type ALREADY is (width, signed). arkham keeps every
  #    sub-64-bit scalar normalized to its type's width in a register — that is the
  #    invariant `normalizeBinWidth` restores after `add`/`sub`/`mul`/`shl` and that
  #    it relies on when it skips the fixup for `and`/`or`/`xor`/`shr`. Re-extending
  #    to a width the value already has is a pure no-op. `srcWidthSigned` answers
  #    (64, true) for anything it cannot classify — a call result included, whose
  #    upper half neither ABI promises — and 64 never equals `width` here, so an
  #    unknown source is excluded rather than assumed.
  let (sw, ss) = g.srcWidthSigned(src)
  if sw == width and ss == signed: return true
  var c = src
  while c.kind == TagLit and c.exprKind in {SufC, ParC}:
    c = sub(c)                                  # `(suf 255 "u32")`, `(par x)`
  # 2. A LITERAL. `movImm` materializes it as its exact 64-bit two's-complement
  #    value, so it is already canonical for (width, signed) exactly when it lies
  #    in that type's range — and re-extending it is the purest dead code there is.
  if literalArrivesNormalized(c, width, signed): return true
  case c.exprKind
  of DerefC:
    # A typed pointer deref becomes `(mem …)` whose type is the POINTEE, and
    # nifasm sizes the load from it: a sub-word integer is loaded sign-/zero-
    # extending, a 4-byte one zeroing the upper half (x64 `intMemAccess` →
    # `emitLoadExt`; a64 `memWidthOpc` → `ldrsb`/`ldrsh`/`ldrsw` vs
    # `ldrb`/`ldrh`/`ldr w`). So the value arrives already extended.
    #
    # ONLY a genuine deref: a stack SLOT operand carries `StackOffT`, which x64's
    # `intMemAccess` reads as a full 64-bit access — nothing is extended there.
    # (a64's `memWidthOpc` does unwrap `StackOffT` and size by the slot's content
    # type, but this stays the conservative intersection of the two.)
    let sl = typeToSlot(resolveType(g.prog, g.getType(c)))
    result = sl.kind in {AInt, AUInt, ABool} and sl.size * 8 == width and
             (sl.kind == AInt) == signed
  of BitandC:
    # `x and M` for a non-negative literal mask M is bounded by M, hence already
    # zero-extended when M < 2^width. A SIGNED target needs the stronger bound
    # M < 2^(width-1): only below the sign bit do zero- and sign-extension agree.
    # `char(x and 0x7f)` — the varint writers' shape — is exactly that, and Leng's
    # `(c 8)` is a signed 8-bit type.
    let bound = 1'i64 shl (width - ord(signed))
    var t = c
    t.into:
      skip t                                    # the result type
      while t.hasMore:
        var lit = t                             # a literal arrives `(suf 15u "u32")`
        if lit.exprKind == SufC:
          lit = sub(lit)
        if lit.kind == IntLit or lit.kind == UIntLit:
          let m = (if lit.kind == IntLit: intVal(lit) else: cast[int64](uintVal(lit)))
          if m >= 0 and m < bound: result = true
        skip t
  else: result = false

# ── unified location model (addressing modes + computed values) ─────────────
# `Location` (machinedesc) is THE descriptor for "where a value lives, or should
# go" — a register, a stack slot, a global/thread-local, a foldable memory operand
# (`Mem`, carrying the lvalue subtree to re-emit), an immediate, or `Undef` (the
# dont-care target). It is shared by the register
# allocator (long-lived storage) and the backends (just-computed values + lvalue
# destinations). `asLoc` parses a Leng lvalue cursor into one; `genVal` produces a
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
      let loc = g.plan.homeOfSym(nm)
      case loc.kind
      of InReg: result = regLoc(loc.r, slot)
      of InRegPair: result = loc
      of InFReg: result = fregLoc(loc.f, slot)
      of NamedStack: result = namedStackLoc(loc.name, slot)  # aggregate or scalar; `typ` tells apart
      of StackPtr: result = stackPtrLoc(loc.ptrName, loc.pointeeType, slot)
      else: raiseAssert "arkham: symbol is not an lvalue: " & nm
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC, PatC: (result = memLoc(nCur, slot); skip c)
    else: raiseAssert "arkham: not an lvalue: " & $c.exprKind
  else: raiseAssert "arkham: not an lvalue: " & $c.kind

proc retIsVoid*(t: Cursor): bool {.inline.} =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)