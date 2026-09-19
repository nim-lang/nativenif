#
#           The web back end — Leng → JavaScript / wasm32
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## The web IR: ONE tree that `codegen` produces for both web targets, and that
## two renderers print — `jsrender` as JavaScript text, `wasmrender` as a wasm32
## binary. Nothing target-specific is decided while lowering Leng; the tree says
## WHAT happens (a load of this width, a call through this signature, a frame
## of this size) and each renderer says how its host spells it.
##
## Tag alignment is the construction rule, not a hope: `createTags[WebTag]`
## registers every value of `WebTag` in ordinal order so the resulting `TagId`
## is `ord(tag) + 1` (0 is the pool's invalid id), asserted at pool creation.
## Reading and writing therefore translate with the `tagOf`/`webTagOf` shims
## alone.
##
## The tree is TYPED. Every arithmetic, comparison, conversion and memory node
## carries a `WidthCode`, every parameter and local declares one, every function
## declares its result, and an indirect call carries its signature. JavaScript
## needs the widths to pick between its two numeric worlds (`Number`, `BigInt`)
## and to canonicalise results; wasm needs them for its value types. A renderer
## never guesses what an operand "probably" is.
##
## Literal tokens (IntLit, FloatLit) are typed by the position they sit in —
## an operand of a `(add wF64 …)` is an f64, an argument is its parameter's
## width — which is also how Leng types a bare literal. A 64-bit integer
## literal is always a `BigIntLit`, because JavaScript must spell it `123n`.
##
## A few nodes exist only for the JavaScript host (`raw`, `ewrap`, `eunwrap`,
## `estr`, `arrow`, `index`, and raw `Ident` names): the `importjs` bridge. The
## wasm renderer refuses them by name; the code generator does not produce them
## for a wasm build.

import nifcore

type
  WebTag* = enum
    ## The private wire format of the web back end. Names here are the tag
    ## spellings in the pool; they are internal and never user-visible.
    NoTag         # placeholder so `webTagOf` has a sentinel for non-tag cursors
    # ── top level
    Top           ## (top FUNC*) — the program's functions
    Func          ## (func NAME PARAMS RET LOCALS STMT*) — RET is a width or `.`
    Params        ## (params PARAM*)
    Param         ## (param NAME W) — a parameter or (inside `locals`) a local
    Locals        ## (locals PARAM*) — every local of the function, hoisted: a
                  ## local lives for the whole call and starts at zero
    Sig           ## (sig RET W*) — an indirect call's signature
    # ── statements
    Block         ## (block STMT*) — plain `{ … }`
    Label         ## (label NAME STMT*) — the target of a `break NAME`
    Break         ## (break NAME?) — forward exit of a label, or of the
                  ## innermost `while` when unnamed
    If            ## (if COND THEN* ELSE?) — ELSE is an `Else` child
    Else          ## (else STMT*)
    While         ## (while COND BODY*)
    Return        ## (return EXPR?)
    ExprStmt      ## (expr EXPR) — evaluate for effect, drop any value
    Leave         ## (leave) — pop this function's shadow-stack frame
    # ── literals that no token can carry
    BigIntLit     ## (bigint STRLIT) — a 64-bit integer; digits as text (u64 range)
    TrueLit       ## 1 as a boolean
    FalseLit      ## 0 as a boolean
    NanLit        ## NaN
    InfLit        ## +Infinity
    # ── composites
    Call          ## (call FN ARG*) — FN names a `func` or a host import
    ICall         ## (icall SIG TARGET ARG*) — through a function-table slot
    Assign        ## (assign NAME VALUE) — a local or a global; also a value
    Cond          ## (cond C A B)
    Seq           ## (seq EXPR+) — run the parts, yield the last
    # ── linear memory
    HLoad         ## (hload W ADDR)
    HStore        ## (hstore W ADDR VALUE)
    MemCopy       ## (memcopy DST SRC N) — overlap-safe
    MemFill       ## (memfill DST BYTE N)
    MemSize       ## (memsize) — in 64 KiB pages
    MemGrow       ## (memgrow PAGES) — the old size in pages, or -1
    Frame         ## (frame N) — push an N-byte shadow-stack frame, yield its base
    # ── the rest of the machine
    Ctz Clz Popcnt ## (ctz W X) — the count, an i32
    Unreachable   ## (unreachable) — a trap
    # ── operations; first child is the WidthCode
    Add Sub Mul Div Mod Shl Shr And Or Xor
    LAnd LOr      ## C's `&&`/`||` — SHORT-CIRCUIT, so they cannot be `And`/`Or`
    Not Neg BNot
    Eq Neq Lt Le Gt Ge
    # ── the numeric width bridge
    Cvt           ## (cvt FROM TO VALUE) — a value conversion
    Reint         ## (reint FROM TO VALUE) — MOVE THE BITS between a float and
                  ## an integer of the same size
    # ── the JavaScript host only (the `importjs` bridge, §6)
    Index         ## (index ARR IDX) — `ARR[IDX]`
    Arrow         ## (arrow PARAMS STMT*) — `(p) => { … }`
    EWrap         ## (ewrap VALUE) — JS value → int32 handle
    EUnwrap       ## (eunwrap HANDLE) — int32 handle → JS value
    EStrLit       ## (estr STRLIT) — jsstring literal (a handle interned at startup)
    Raw           ## (raw NAME TPL ARG*) — importjs splice: `#` consumes the
                  ## next argument, `$1`/`$#` name the proc, `@` spreads the
                  ## args not yet consumed, `$$` is a literal `$`.

  WidthCode* = enum
    ## Width+signedness carried by every typed node, stored as its ordinal in
    ## an IntLit child.
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

const
  JsOnlyTags* = {Index, Arrow, EWrap, EUnwrap, EStrLit, Raw}
    ## What only the JavaScript host can render.

proc createWebTagPool*(): TagPool =
  ## The pool every web-IR buffer shares. `createTags` asserts the
  ## `TagId == ord(WebTag) + 1` alignment while registering.
  createTags[WebTag]()

template tagOf*(t: WebTag): TagId =
  ## The `+1` shim of `createTags`, spelled once.
  TagId(ord(t) + 1)

template webTagOf*(c: Cursor): WebTag =
  ## The inverse shim. A non-tag cursor reads as `NoTag`, and a tag id outside
  ## the enum (a foreign pool leaked into this buffer) is a hard error rather
  ## than a silent cast onto an unrelated member.
  if c.kind != TagLit:
    NoTag
  else:
    let id = uint32(c.cursorTagId)
    doAssert id >= 1'u32 and id <= uint32(WebTag.high) + 1'u32,
      "webTagOf: foreign tag id " & $id
    cast[WebTag](id - 1'u32)

proc widthBits*(w: WidthCode): int =
  case w
  of wI8, wU8: 8
  of wI16, wU16: 16
  of wI32, wU32, wF32: 32
  of wI64, wU64, wF64: 64

proc isBig*(w: WidthCode): bool {.inline.} = w in {wI64, wU64}
proc isFloat*(w: WidthCode): bool {.inline.} = w in {wF32, wF64}
proc isSigned*(w: WidthCode): bool {.inline.} = w in {wI8, wI16, wI32, wI64}

# ── builder sugar ───────────────────────────────────────────────────────────
# Flat, single-purpose procs over the raw nifcore writer; codegen composes
# these, never `openTag`/`addIntLit` directly, so the grammar lives in one file.

proc openTree*(b: var TokenBuf; t: WebTag) {.inline.} =
  doAssert t != NoTag, "openTree: NoTag is a sentinel, not a tag"
  b.openTag tagOf(t)

template tree*(b: var TokenBuf; t: WebTag; body: untyped) =
  ## `openTree`/`closeTag` as one unit — the grammar reads as the tree it
  ## builds: `b.tree Add: b.width(wI32); …`.
  b.openTree t
  body
  b.closeTag

proc width*(b: var TokenBuf; w: WidthCode) {.inline.} =
  ## The explicit width child every typed node demands.
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
proc lit*(b: var TokenBuf; t: WebTag) {.inline.} =
  ## Nullary literal tags.
  doAssert t in {TrueLit, FalseLit, NanLit, InfLit, MemSize, Unreachable, Leave},
    "lit: not a nullary tag"
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
  ## A bit-level reinterpretation.
  b.openTree Reint
  b.width fromW
  b.width toW
  body
  b.closeTag

proc param*(b: var TokenBuf; name: string; w: WidthCode) =
  ## `(param NAME W)` — a parameter, or a local inside `(locals …)`.
  b.openTree Param
  b.symDef name
  b.width w
  b.closeTag

proc params*(b: var TokenBuf) =
  ## Empty parameter list.
  b.openTree Params
  b.closeTag

# ── module facts that are not code ──────────────────────────────────────────

type
  WebImport* = object
    ## A function the host provides. `name` is both the tree's callee symbol
    ## and the wasm `env` import name.
    name*: string
    params*: seq[WidthCode]
    hasRet*: bool
    ret*: WidthCode

  WebModule* = object
    ## Everything a renderer needs besides the `(top …)` tree.
    imports*: seq[WebImport]      ## the host floor first (`nim_write`, `nim_exit`)
    globals*: seq[(string, WidthCode)] ## scalar globals no address reaches (errv, ovf)
    dataSegs*: seq[(uint32, string)]   ## the static image: (address, bytes)
    memTop*: uint32               ## end of the static image
    table*: seq[string]           ## function-table slot → func (or import) name;
                                  ## slot 0 is the null function pointer, and an
                                  ## empty name is an unbound slot
    entry*: string                ## the entry func (`main`)
    entryParams*: seq[WidthCode]
    entryHasRet*: bool
    entryRet*: WidthCode
    exports*: seq[(string, string)] ## (C name, func name): a host-driven library
                                   ## when non-empty
    callbacks*: seq[string]       ## JS text: `importjs` callback bridges
