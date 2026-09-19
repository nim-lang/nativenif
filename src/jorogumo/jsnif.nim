#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## The JS tag enum and tree builder — #2445 §3: jorogumo produces JavaScript
## as a NIF tree over a dedicated tag pool, never as strings. `jsenc` is the
## tiny text emitter that renders this tree; a peephole pass can sit between
## codegen and the emitter without either side knowing.
##
## Tag alignment is the construction rule, not a hope: `createTags[JsTag]`
## registers every value of `JsTag` in ordinal order so the resulting `TagId`
## is `ord(tag) + 1` (0 is the pool's invalid id), asserted at pool creation.
## Reading and writing therefore translate with the `tagOf`/`jsTagOf` shims
## alone — no side table, no per-node array lookup.
##
## The tree is deliberately width-explicit: every arithmetic, comparison and
## heap-access node carries a `WidthCode` child. JavaScript's numeric stack is
## two disjoint worlds (`Number` for ≤ 32-bit ints and `f64`, `BigInt` for
## 64-bit ints), and the renderer must pick forms (`|0`, `>>>0`, BigInt
## operators) from the declared width, never from a guess about the operands.

import nifcore

type
  JsTag* = enum
    ## The private wire format of jorogumo. Names here are the tag spellings
    ## in the pool; they are internal and never user-visible.
    NoJs          # placeholder so `jsTagOf` has a sentinel for non-tag cursors
    # ── top level
    Top           ## (top STMT*) — module-level statement list
    # ── declarations
    Func          ## (func NAME PARAMS BODY+) — `function NAME(p) { … }`
    Let           ## (let NAME INIT?) — `let NAME = INIT;` / `let NAME;`
    Params        ## (params NAME*) — parameter list; `()` when empty
    # ── statements
    Block         ## (block STMT+) — plain `{ … }`
    Label         ## (label NAME STMT+) — `NAME: { … }`, the target of a Break (§4)
    Break         ## (break NAME) — `break NAME;` — forward-only, scoped (§4)
    If            ## (if COND THEN+ ELSE?) — ELSE is an `Else` child or `.`
    Else          ## (else STMT+)
    While         ## (while COND BODY+)
    Try           ## (try BODY+ EXCEPT* FINALLY?)
    Except        ## (except NAME? BODY+) — binding name or `.`
    Finally       ## (finally BODY+)
    Throw         ## (throw EXPR)
    Return        ## (return EXPR?)
    ExprStmt      ## (expr EXPR)
    # ── literals
    # `Number` ints, floats and strings are PLAIN NIF tokens (IntLit, FloatLit,
    # StrLit) — every other NIF dialect spells them that way, and the emitter
    # dispatches on the token kind. Only literals that no token can carry are
    # tags: BigInt needs its tag because a u64 does not fit an IntLit, and the
    # keyword literals have no token of their own.
    BigIntLit     ## (bigint STRLIT) — `BigInt` literal; digits as text (u64 range)
    TrueLit       ## `true`
    FalseLit      ## `false`
    NullLit       ## `null`
    UndefLit      ## `undefined`
    NanLit        ## `NaN`
    InfLit        ## `Infinity`
    # ── names and composites
    # A raw JS name is nifcore's `Ident` TOKEN (addIdent): an identifier that
    # is not a Nim symbol — exactly what a host global or an `importjs` name
    # is. Symbols stay Symbol/SymbolDef, so the two never blur.
    Call          ## (call FN ARG*)
    Prop          ## (prop OBJ NAME-STRLIT) — `OBJ.NAME`
    Index         ## (index ARR IDX) — `ARR[IDX]`
    Assign        ## (assign TARGET VALUE)
    Cond          ## (cond C A B) — `C ? A : B`
    Seq           ## (seq EXPR+) — `(a, b, c)`: run the parts, yield the last.
                  ## The comma operator is how a multi-store fill (a constructor
                  ## written field by field) becomes one expression, which is
                  ## what an aggregate VALUE must be to sit in an argument slot.
    New           ## (new CTOR ARG*)
    Arrow         ## (arrow PARAMS BODY) — `(p) => { BODY }`
    # ── linear memory (§1: one ArrayBuffer, pointers are offsets)
    HLoad         ## (hload W ADDR) — typed read through the view for W
    HStore        ## (hstore W ADDR VALUE)
    # ── extern value bridge (§6: real JS values live outside the buffer)
    EWrap         ## (ewrap VALUE) — JS value → int32 handle
    EUnwrap       ## (eunwrap HANDLE) — int32 handle → JS value
    EStrLit       ## (estr STRLIT) — jsstring literal (a handle interned at startup)
    Raw           ## (raw NAME TPL ARG*) — importjs splice (semantics pinned
                  ## against Nim 2.2.4's jsgen empirically): `#` consumes the
                  ## next argument, `$1`/`$#` name the proc, `@` spreads the
                  ## args not yet consumed, `$$` is a literal `$`.
    # ── operations; first child is the WidthCode
    Add Sub Mul Div Mod Shl Shr And Or Xor
    LAnd LOr      ## C's `&&`/`||` — SHORT-CIRCUIT, so they cannot be `And`/`Or`:
                  ## Leng spells bitwise `bitand`/`bitor` and logical `and`/`or`,
                  ## and rendering the latter as `&`/`|` would run a right-hand
                  ## side that must not run (`p != nil and p.x > 0`).
    Not Neg BNot
    Eq Neq Lt Le Gt Ge
    # ── the numeric width bridge
    Cvt           ## (cvt FROM TO VALUE) — a move between the two numeric worlds
    Reint         ## (reint FROM TO VALUE) — MOVE THE BITS, not the value: Leng's
                  ## `cast` between a float and an integer of the same size is
                  ## the double's own bit pattern, which no arithmetic
                  ## conversion produces.
                  ## of §1: `Number` (≤32-bit ints, f32/f64) and `BigInt`
                  ## (64-bit ints). Codegen knows both widths; the renderer
                  ## picks `Number(…)`, `BigInt(…)`, `Math.trunc`, `Math.fround`
                  ## and the narrow-wrap from the pair. There is no JS operator
                  ## that does this, so it must be a node of its own.

  WidthCode* = enum
    ## Width+signedness carried by every arithmetic/comparison/heap node,
    ## stored as its ordinal in an IntLit child. `f32`/`f64` are legal for
    ## HLoad/HStore only; the emitter rejects them on arithmetic (float
    ## operations render untyped and need no wrap).
    wI8 = 0
    wU8 = 1
    wI16 = 2
    wU16 = 3
    wI32 = 4
    wU32 = 5
    wI64 = 6
    wU64 = 7
    wF32 = 8
    wF64 = 9

proc createJsTagPool*(): TagPool =
  ## The pool every jorogumo buffer shares. `createTags` asserts the
  ## `TagId == ord(JsTag) + 1` alignment while registering, so a hole or a
  ## reordered member is a crash here, not a misrendered program later.
  createTags[JsTag]()

template tagOf*(t: JsTag): TagId =
  ## The `+1` shim of `createTags`, spelled once.
  TagId(ord(t) + 1)

template jsTagOf*(c: Cursor): JsTag =
  ## The inverse shim. A non-tag cursor reads as `NoJs`, and a tag id outside
  ## the enum (a foreign pool leaked into this buffer) is a hard error rather
  ## than a silent cast onto an unrelated member.
  if c.kind != TagLit:
    NoJs
  else:
    let id = uint32(c.cursorTagId)
    # The pool maps `tagOf(t) = ord(t)+1`, so the valid id range is
    # 1 ..= ord(high)+1 — the bound is high PLUS the shim, and writing it
    # without the `+1` rejects the enum's last member (which is how Cvt was
    # rejected the moment it became the final tag).
    doAssert id >= 1'u32 and id <= uint32(JsTag.high) + 1'u32,
      "jsTagOf: foreign tag id " & $id
    cast[JsTag](id - 1'u32)

# ── builder sugar ───────────────────────────────────────────────────────────
# Flat, single-purpose procs over the raw nifcore writer; codegen composes
# these, never `openTag`/`addIntLit` directly, so the grammar lives in one
# file. Line infos ride along from `info` where the caller has them.

proc openTree*(b: var TokenBuf; t: JsTag) {.inline.} =
  doAssert t != NoJs, "openTree: NoJs is a sentinel, not a tag"
  b.openTag tagOf(t)

template tree*(b: var TokenBuf; t: JsTag; body: untyped) =
  ## `openTree`/`closeTag` as one unit — the grammar reads as the tree it
  ## builds: `b.tree Add: b.width(wI32); b.tree lhs; b.tree rhs`.
  b.openTree t
  body
  b.closeTag

proc width*(b: var TokenBuf; w: WidthCode) {.inline.} =
  ## The explicit width child every operation node demands.
  b.addIntLit int64(w)

proc symDef*(b: var TokenBuf; name: string) {.inline.} = b.addSymDef name
proc symUse*(b: var TokenBuf; name: string) {.inline.} = b.addSymUse name
proc strLit*(b: var TokenBuf; s: string) {.inline.} = b.addStrLit s
proc numLit*(b: var TokenBuf; i: int64) {.inline.} = b.addIntLit i
proc floatLit*(b: var TokenBuf; f: float) {.inline.} = b.addFloatLit f
proc bigIntLit*(b: var TokenBuf; digits: string) {.inline.} =
  ## Digits as text: the u64 range does not fit an `int64` literal token.
  b.tree BigIntLit: b.strLit digits
proc ident*(b: var TokenBuf; name: string) {.inline.} = b.addIdent name
proc lit*(b: var TokenBuf; t: JsTag) {.inline.} =
  ## Nullary literal tags: `true`, `null`, `NaN`, …
  doAssert t in {TrueLit, FalseLit, NullLit, UndefLit, NanLit, InfLit},
    "lit: not a nullary literal tag"
  b.openTree t
  b.closeTag
template cvtNode*(b: var TokenBuf; fromW, toW: WidthCode; body: untyped) =
  ## A width move: both widths ride along, then the operand.
  b.openTree Cvt
  b.width fromW
  b.width toW
  body
  b.closeTag

template reintNode*(b: var TokenBuf; fromW, toW: WidthCode; body: untyped) =
  ## A bit-level reinterpretation; the widths say which pair of views to read
  ## the scratch through.
  b.openTree Reint
  b.width fromW
  b.width toW
  body
  b.closeTag

proc params*(b: var TokenBuf) =
  ## Empty parameter list; fill it with `symDef` between open/close otherwise.
  b.openTree Params
  b.closeTag
