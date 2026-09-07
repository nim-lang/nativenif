#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##
## The tiny jsnif → JavaScript text emitter. No codegen logic lives here: it
## walks a jsnif `TokenBuf` (§3) and prints it. Correctness rests on two
## habits — every operation node carries its own explicit `WidthCode`, and
## composite expression forms are parenthesised at emission — so the renderer
## needs neither a precedence table nor guesses about what an operand
## "probably" is. Peephole optimization, if it comes, belongs upstream on the
## tree, not here.
##
## Width semantics of the emitted forms:
## - ≤ 32-bit arithmetic lives in `Number`; every result is canonicalised to
##   its width (`|0`, `>>>0`, the shift trick for 8/16) so values never drift
##   wider than the type that produced them.
## - 64-bit arithmetic lives in `BigInt`, where `+ - * / % & | ^ << >>`
##   already have the integer semantics Leng asks for (`/` truncates; `%`
##   follows the dividend, like Nim's `mod`). `HLoad` from `BI64`/`BU64` is
##   already a BigInt, so the worlds meet only where codegen puts them.
## - Shift-COUNT masking (JS shifts are mod-32; BigInt shifts are exact) and
##   division-by-zero checks are the GENERATOR's job, not the renderer's:
##   codegen emits `b & 63` / the `divByZero` check, the renderer renders.
##
## `indent` counts nesting levels (two spaces each) and is threaded through
## expressions as well as statements: an `arrow` body is a statement list
## inside an expression and must line up with the statement that holds it.

import std / [strutils]
import nifcore
import jsnif

const
  viewNames*: array[WidthCode, string] = [
    "I8", "U8", "I16", "U16", "I32", "U32", "BI64", "BU64", "F32", "F64"
  ]
    ## Typed-array view names over the one `ArrayBuffer` (§1).

proc jsPreamble*(memBytes, stackBytes, dataEnd: int): string =
  ## The host contract, emitted once per file: the linear-memory buffer, the
  ## views above it, the extern-value table of the bridge (§6). The buffer
  ## GROWS (`growMem` is wasm `memory.grow`'s twin: reallocate, copy, rebind
  ## the views; old pages survive, and so does every pointer, because pointers
  ## ARE offsets). The M0 refusal — `memoryGrow(_) { return -1; }` — was the
  ## placeholder for this.
  ##
  ## The buffer is split: static data and the bump heap from 0 upwards, the
  ## SHADOW STACK (§2) in the last `stackBytes`, growing down from the top.
  ## Frames are C-style (`frame`/`leave` strictly nested), and because locals
  ## live at byte offsets in the same space as the heap, `addr` of a local and
  ## `deref` of a pointer need no second address space. `osalloc` refuses to
  ## grow past `SP_MIN`, so the two cannot collide; appended pages land ABOVE
  ## the stack, exactly as they do in wasm, where the same crowding exists at
  ## exhaustion.
  "let JMEM = new ArrayBuffer(" & $memBytes & ");\n" &
  "let I8 = new Int8Array(JMEM), U8 = new Uint8Array(JMEM),\n" &
  "    I16 = new Int16Array(JMEM), U16 = new Uint16Array(JMEM),\n" &
  "    I32 = new Int32Array(JMEM), U32 = new Uint32Array(JMEM),\n" &
  "    F32 = new Float32Array(JMEM), F64 = new Float64Array(JMEM),\n" &
  "    BI64 = new BigInt64Array(JMEM), BU64 = new BigUint64Array(JMEM);\n" &
  "const EXT = [];  // extern value table: handle -> real JS value (§6)\n" &
  "const FTAB = []; // function table: slot -> JS function; 0 is the null pointer\n" &
  "let errv = 0, ovf = 0; // the flags register, as two globals (ithaqua's model)\n" &
  "let JSP = [null];  // the same table, grown by ewrap\n" &
  "function ewrap(v) {\n" &
  "  if (typeof v === \"number\" || typeof v === \"bigint\") return v;\n" &
  "  if (typeof v === \"boolean\") return v ? 1 : 0;\n" &
  "  if (v === null || v === undefined) return 0;\n" &
  "  const h = JSP.length; JSP.push(v); return h | 0;\n" &
  "}\n" &
  "function eunwrap(h) {\n" &
  "  if (typeof h === \"bigint\") return Number(h);\n" &
  "  return h < 1 ? null : JSP[h];\n" &
  "}\n" &
  # The osalloc contract is wasm's: size in 64 KiB pages, grow returns the old
  # page count or -1. Not bytes — osalloc multiplies by 65536 itself.
  "function memorySize() { return JMEM.byteLength >> 16; }\n" &
  # wasm `memory.grow`'s twin: append `pages` 64 KiB pages, contents intact,
  # return the OLD page count or -1. Pointers are offsets, so the copy keeps
  # every one valid; the views are rebound to the new buffer, and every reader
  # goes through the live binding.
  "function memoryGrow(pages) {\n" &
  "  const old = JMEM.byteLength >> 16;\n" &
  "  let nb;\n" &
  "  try {\n" &
  "    nb = new ArrayBuffer(JMEM.byteLength + pages * 65536);\n" &
  "    new Uint8Array(nb).set(new Uint8Array(JMEM));\n" &
  "  } catch (e) { return -1; }\n" &
  "  JMEM = nb;\n" &
  "  I8 = new Int8Array(JMEM); U8 = new Uint8Array(JMEM);\n" &
  "  I16 = new Int16Array(JMEM); U16 = new Uint16Array(JMEM);\n" &
  "  I32 = new Int32Array(JMEM); U32 = new Uint32Array(JMEM);\n" &
  "  F32 = new Float32Array(JMEM); F64 = new Float64Array(JMEM);\n" &
  "  BI64 = new BigInt64Array(JMEM); BU64 = new BigUint64Array(JMEM);\n" &
  "  return old;\n" &
  "}\n" &
  # The static image: the wasm data section's twin. Base64 because the image
  # is arbitrary bytes and a JS string literal is not.
  "function D(b64, at) {\n" &
  "  const bin = atob(b64);\n" &
  "  for (let i = 0; i < bin.length; ++i) U8[at + i] = bin.charCodeAt(i);\n" &
  "}\n" &
  # The host face, the same two entry points ithaqua imports from `env`.
  # node-only by nature: a browser has no fd 1 to write to (M8 gives DOM
  # programs a console-backed one).
  "function nim_write(fd, buf, len) {\n" &
  "  const m = Buffer.from(JMEM, buf, len);\n" &
  "  (fd === 2 ? process.stderr : process.stdout).write(m);\n" &
  "  return len;\n" &
  "}\n" &
  "function nim_exit(code) { process.exit(code); }\n" &
  # ithaqua's ruling for a syscall the target cannot serve: `unreachable`, a
  # loud trap, not a silent no-op. The throw is the JS twin of that trap.
  "function nim_unreachable() { throw new Error('unreachable: unsupported syscall'); }\n" &
  # The shadow stack (§2): the top `stackBytes` of the buffer, growing DOWN.
  # frame(n) returns the new base and leave(f) restores it; a frame's locals
  # live at byte offsets from the base in the SAME address space as the heap,
  # which is what lets `addr` of a local and `deref` of a pointer share one
  # representation. The base is 16-aligned so a slot aligned by its own type —
  # a 16-byte array is align 16 in C — lands correctly whatever the frame size.
  "let SP_MIN = " & $(memBytes - stackBytes) & ";\n" &
  "let SP = " & $memBytes & ";\n" &
  "function frame(n) {\n" &
  "  const f = (SP - n) & ~15;\n" &
  "  if (f < SP_MIN) throw new Error(\"stack overflow\");\n" &
  "  SP = f; return f;\n" &
  "}\n" &
  # leave takes the frame BASE, not its size: `frame` aligns the base down, so
  # adding the size back would not restore the caller's SP.
  "function leave(f) { SP = f; }\n" &
  # Bit-level reinterpretation (`cast` between a float and an integer of the
  # same size). One scratch cell, read back through the other view; the program
  # is single-threaded and each helper completes before it returns.
  "const _CB = new ArrayBuffer(8);\n" &
  "const _CF = new Float64Array(_CB), _CI = new BigInt64Array(_CB),\n" &
  "      _FF = new Float32Array(_CB), _FI = new Int32Array(_CB);\n" &
  "function f64bits(x) { _CF[0] = x; return _CI[0]; }\n" &
  "function bitsf64(b) { _CI[0] = b; return _CF[0]; }\n" &
  "function f32bits(x) { _FF[0] = x; return _FI[0]; }\n" &
  "function bitsf32(i) { _FI[0] = i | 0; return _FF[0]; }\n" &
  # memcpy over the one buffer: the aggregate-assignment and sret primitives.
  "function copyMem(d, s, n) { U8.copyWithin(d, s, s + n); }\n" &
  # The shadow stack is reused memory, so an uninitialized local would read the
  # previous frame's bytes; the back end zeroes what Leng leaves undefined.
  "function zeroMem(d, n) { U8.fill(0, d, d + n); }\n" &
  # The mem intrinsics Leng emits: ithaqua lowers them to `memory.fill` and a
  # synthetic byte loop; these are the same three, over the `U8` view.
  # `memcmp` follows C: the difference of the first differing UNSIGNED byte
  # pair, 0 when the first n bytes match.
  "function fillMem(d, v, n) { U8.fill(v, d, d + n); }\n" &
  "function memcmp(a, b, n) {\n" &
  "  for (let i = 0; i < n; i++) {\n" &
  "    const x = U8[a + i], y = U8[b + i];\n" &
  "    if (x !== y) return x - y;\n" &
  "  }\n" &
  "  return 0;\n" &
  "}\n" &
  # The allocator is the osalloc CONTRACT (§5): the same shape as wasm's, and
  # bounded by SP_MIN so the heap can never walk into the shadow stack.
  "let heapTop = " & $dataEnd & ";\n" &
  "function osalloc(_, n) {\n" &
  "  const b = (heapTop + 15) & ~15; const r = b + ((n + 15) & ~15);\n" &
  "  if (r > SP_MIN) throw new Error(\"out of memory\");\n" &
  "  heapTop = r; return b >>> 0;\n" &
  "}\n"

proc utf8Len(b: char): int =
  ## The length of the UTF-8 sequence starting at `b`, 0 when `b` cannot
  ## start one. Not a validator — the caller checks the continuation bytes.
  let u = uint8(b)
  if u < 0x80: 1
  elif u >= 0xC2 and u <= 0xDF: 2
  elif u >= 0xE0 and u <= 0xEF: 3
  elif u >= 0xF0 and u <= 0xF4: 4
  else: 0

proc validUtf8At(s: string; i: int): int =
  ## The length of the valid UTF-8 sequence at `i`, or 0 if the bytes there
  ## are not a well-formed sequence (no overlongs, no surrogates).
  let n = utf8Len(s[i])
  if n == 0 or i + n > s.len: return 0
  let b0 = uint8(s[i])
  for k in 1 ..< n:
    if (uint8(s[i + k]) and 0xC0'u8) != 0x80'u8: return 0
  case n
  of 3:
    # E0 must not be overlong; ED must not encode a surrogate.
    if b0 == 0xE0 and uint8(s[i + 1]) < 0xA0: return 0
    if b0 == 0xED and uint8(s[i + 1]) >= 0xA0: return 0
  of 4:
    if b0 == 0xF0 and uint8(s[i + 1]) < 0x90: return 0
    if b0 == 0xF4 and uint8(s[i + 1]) >= 0x90: return 0
  else: discard
  n

proc escapeJsString*(s: string): string =
  ## A JS double-quoted literal for `s`. Nim strings are UTF-8, and a JS
  ## source file is UTF-8, so well-formed sequences pass through unchanged —
  ## text stays text. A byte that does not start a valid sequence (a lone
  ## continuation byte, an overlong form, a surrogate) could not survive a
  ## JS file at all, so it goes out as `\xNN`. The `\u2028`/`\u2029`
  ## sequences (line terminators inside string literals; legal since ES2019)
  ## are escaped so a generated file survives any transport that re-wraps
  ## lines.
  result = newStringOfCap(s.len + 2)
  result.add '"'
  var i = 0
  while i < s.len:
    let c = s[i]
    case c
    of '"':
      result.add "\\\""
      inc i
    of '\\':
      result.add "\\\\"
      inc i
    of '\n':
      result.add "\\n"
      inc i
    of '\r':
      result.add "\\r"
      inc i
    of '\t':
      result.add "\\t"
      inc i
    else:
      if uint8(c) < 0x20:
        # a raw control byte in a JS literal is a syntax error or a trap
        result.add "\\x" & toHex(uint32(uint8(c)), 2)
        inc i
        continue
      let n = validUtf8At(s, i)
      if n == 0:
        result.add "\\x" & toHex(uint32(uint8(c)), 2)
        inc i
      elif c == '\xE2' and n == 3 and s[i + 2] in ['\xA8', '\xA9']:
        result.add "\\u202" & (if s[i + 2] == '\xA8': '8' else: '9')
        inc i, 3
      else:
        for k in 0 ..< n: result.add s[i + k]
        inc i, n
  result.add '"'

# ── small cursor helpers ────────────────────────────────────────────────────

proc firstChild(c: Cursor): Cursor {.inline.} = c.sub()

proc pad(n: int): string = spaces(n * 2)

proc scaleOf(w: WidthCode): int =
  case w
  of wI8, wU8: 1
  of wI16, wU16: 2
  of wI32, wU32, wF32: 4
  of wI64, wU64, wF64: 8

proc wrapNarrow(text: string; w: WidthCode): string =
  ## Canonicalise a result to its declared width. JS bitwise operators already
  ## land on int32, so `|0`/`>>>0` covers 32-bit; 8/16 use the shift-trick.
  ## Floats need nothing. Both 64-bit widths DO: BigInt is exact and unbounded,
  ## so `0u64 - 1` would stay -1 where Leng says 2^64-1, and `maxI64 + 1` would
  ## stay 2^63 where the hardware wraps to minI64. wasm wraps i64 ops in the
  ## ALU; the `asIntN` call is that wrap.
  case w
  of wI8: "(" & text & " << 24 >> 24)"
  of wU8: "(" & text & " << 24 >>> 24)"
  of wI16: "(" & text & " << 16 >> 16)"
  of wU16: "(" & text & " << 16 >>> 16)"
  of wI32: "(" & text & " | 0)"
  of wU32: "(" & text & " >>> 0)"
  of wI64: "BigInt.asIntN(64, " & text & ")"
  of wU64: "(" & text & " & 0xFFFF_FFFF_FFFF_FFFFn)"
  else: text

# ── expressions: pure text, built bottom-up ─────────────────────────────────
# An operation's full form (wrapping included) is assembled as a string in
# its case — the operand texts are in hand there, so a wrap never has to
# hunt down what was already emitted.

proc exprText(c: Cursor; indent: int): string
proc stmtText*(c: Cursor; indent: int): string
  ## Forward decls — `arrow` bodies are statements, and statements embed
  ## expressions, so the two walks are mutually recursive.

proc nameOf(c: Cursor): string =
  ## The bare text of a name-ish token: a symbol, a raw `ident`, or a `str`.
  case c.kind
  of Symbol, SymbolDef: symName(c)
  of Ident, StrLit: strVal(c)
  else: raiseAssert "jsenc: name expected, got " & $c.kind

proc spliceTemplate(name, tpl: string; args: openArray[string]): string =
  ## The `importjs` template language, pinned EMPIRICALLY against Nim
  ## 2.2.4's jsgen (`#.$1(#, #)` → `self.insertAdjacentText(position, data)`;
  ## `$$(#)` → `$("sel")`): `#` consumes the next argument, `$1` and `$#`
  ## name the proc (that is how `dom.nim` reaches the method name), `@`
  ## spreads the arguments not yet consumed, `$$` is a literal `$`. A bare
  ## `$` before anything else is a template error in Nim too — reject it the
  ## same way rather than passing it through.
  result = ""
  var consumed = 0
  var i = 0
  while i < tpl.len:
    let ch = tpl[i]
    if ch == '$' and i + 1 < tpl.len:
      let nx = tpl[i + 1]
      if nx == '$':
        result.add '$'
        inc i, 2
        continue
      elif nx == '1' or nx == '#':
        result.add name
        inc i, 2
        continue
    if ch == '$':
      raiseAssert "importjs: invalid extern name (unescaped '$'): " & tpl
    if ch == '@':
      var firstHere = true
      while consumed < args.len:
        if not firstHere: result.add ", "
        result.add args[consumed]
        firstHere = false
        inc consumed
      inc i
      continue
    if ch == '#':
      doAssert consumed < args.len, "importjs: more # than arguments"
      result.add args[consumed]
      inc consumed
      inc i
      continue
    result.add ch
    inc i

proc opWidth(c: Cursor): WidthCode =
  ## The WidthCode every operation node carries as its first child. A node
  ## without one is a generator bug; naming the node is what makes it findable,
  ## where nifcore's own assert would only say "IntLit expected".
  let it = c.firstChild
  if it.kind != IntLit:
    raiseAssert "jsenc: `" & $jsTagOf(c) & "` carries no width child"
  WidthCode(it.intVal)

proc pairWidths(c: Cursor): (WidthCode, WidthCode) =
  ## The FROM/TO pair of `cvt`/`reint`, with the same naming guard.
  var it = c.firstChild
  if it.kind != IntLit:
    raiseAssert "jsenc: `" & $jsTagOf(c) & "` carries no width children"
  result[0] = WidthCode(it.intVal)
  skip it
  if it.kind != IntLit:
    raiseAssert "jsenc: `" & $jsTagOf(c) & "` has no destination width"
  result[1] = WidthCode(it.intVal)

proc operandTexts(c: Cursor; indent: int; w: out WidthCode): seq[string] =
  var it = c.firstChild
  w = opWidth(c)
  skip it
  while it.hasMore:
    result.add exprText(it, indent)
    skip it

proc exprText(c: Cursor; indent: int): string =
  # Literals and symbols are PLAIN TOKENS, so the dispatch starts on the token
  # kind; only composite and special-cased nodes are tags.
  case c.kind
  of Symbol, SymbolDef, Ident: return nameOf(c)
  of IntLit: return $intVal(c)
  of FloatLit:
    # Nim's `$float` is shortest-roundtrip, so it re-parses to the same double.
    let v = floatVal(c)
    # NaN/±Inf have no JS literal spelling; `($float)` would write "inf".
    return if v != v: "NaN"
           elif v == Inf: "Infinity"
           elif v == -Inf: "(-Infinity)"
           else: $v
  of StrLit: return escapeJsString(strVal(c))
  else: discard
  case jsTagOf(c)
  of NoJs:
    raiseAssert "jsenc: not a jsnif node: " & $c.kind
  of Top, Block, Let, Func, Params, Label, Break, If, Else, While, Try,
       Except, Finally, Throw, Return, ExprStmt:
    raiseAssert "jsenc: statement where an expression was expected: " & $jsTagOf(c)
  # ── literals that need a tag
  of BigIntLit: result = strVal(c.firstChild) & "n"
  of TrueLit: result = "true"
  of FalseLit: result = "false"
  of NullLit: result = "null"
  of UndefLit: result = "undefined"
  of NanLit: result = "NaN"
  of InfLit: result = "Infinity"
  # ── composites
  of Call:
    var it = c.firstChild
    var fn = exprText(it, indent)
    if jsTagOf(it) == Arrow:
      fn = "(" & fn & ")"                        # an immediately-invoked arrow
                                                 # needs grouping: `(() => {…})(…)`
    skip it
    var args: seq[string]
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    result = fn & "(" & args.join(", ") & ")"
  of Prop:
    var it = c.firstChild
    let obj = exprText(it, indent)
    skip it
    result = obj & "." & nameOf(it)
  of Index:
    var it = c.firstChild
    let arr = exprText(it, indent)
    skip it
    result = arr & "[" & exprText(it, indent) & "]"
  of Assign:
    var it = c.firstChild
    let lhs = exprText(it, indent)
    skip it
    result = "(" & lhs & " = " & exprText(it, indent) & ")"
  of Cond:
    var it = c.firstChild
    let a = exprText(it, indent)
    skip it
    let b = exprText(it, indent)
    skip it
    result = "(" & a & " ? " & b & " : " & exprText(it, indent) & ")"
  of Seq:
    # The comma operator: every part runs, the last one is the value. An
    # aggregate is a LOCATION, so a constructor compiles to a run of stores
    # whose value is the address they were written through.
    var parts: seq[string]
    var it = c.firstChild
    while it.hasMore:
      parts.add exprText(it, indent)
      skip it
    doAssert parts.len > 0, "jsenc: empty seq"
    result = "(" & parts.join(", ") & ")"
  of New:
    # the constructor is the first child but NOT an argument: `new Error(..)`
    var it = c.firstChild
    let ctor = exprText(it, indent)
    skip it
    var args: seq[string]
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    result = "(new " & ctor & "(" & args.join(", ") & "))"
  of Arrow:
    var it = c.firstChild
    var ps: seq[string]
    if jsTagOf(it) == Params:
      var pit = it.firstChild
      while pit.hasMore:
        ps.add nameOf(pit)
        skip pit
      skip it
    result = "(" & ps.join(", ") & ") => {\n"
    while it.hasMore:
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
  # ── linear memory
  of HLoad:
    var it = c.firstChild
    let w = opWidth(c)
    skip it
    let at = exprText(it, indent)
    let s = scaleOf(w)
    result = viewNames[w] & "[" & (if s > 1: "(" & at & ") / " & $s else: at) & "]"
  of HStore:
    var it = c.firstChild
    let w = opWidth(c)
    skip it
    let at = exprText(it, indent)
    skip it
    let s = scaleOf(w)
    result = "(" & viewNames[w] & "[" & (if s > 1: "(" & at & ") / " & $s else: at) &
      "] = " & exprText(it, indent) & ")"
  # ── extern bridge
  of EWrap: result = "ewrap(" & exprText(c.firstChild, indent) & ")"
  of EUnwrap: result = "eunwrap(" & exprText(c.firstChild, indent) & ")"
  of EStrLit: result = "ewrap(" & escapeJsString(strVal(c.firstChild)) & ")"
  of Cvt:
    # (cvt FROM TO VALUE) — the two numeric worlds of §1. The pair decides:
    # BigInt in, Number out loses the 64-bit range exactly as a C truncation
    # does; Number in, BigInt out must truncate toward zero first, because
    # `BigInt(2.5)` is a TypeError in JS but `(int64)2.5` is 2 in Leng.
    let (fromW, toW) = pairWidths(c)
    var it = c.firstChild
    skip it
    skip it
    let v = exprText(it, indent)
    let fromBig = fromW in {wI64, wU64}
    let toBig = toW in {wI64, wU64}
    let fromFl = fromW in {wF32, wF64}
    let toFl = toW in {wF32, wF64}
    var s = v
    if fromBig and not toBig:
      if toW in {wI8, wU8, wI16, wU16, wI32, wU32}:
        # Narrow INSIDE BigInt first: `Number(big)` rounds to the nearest
        # double, and the low bits the narrow must keep are exactly what
        # rounding past 2^53 throws away.
        let bits = if toW in {wI8, wU8}: 8 elif toW in {wI16, wU16}: 16 else: 32
        s = (if toW in {wI8, wI16, wI32}: "BigInt.asIntN(" & $bits & ", "
             else: "BigInt.asUintN(" & $bits & ", ") & s & ")"
      s = "Number(" & s & ")"
    elif toBig and not fromBig:
      s = (if fromFl: "BigInt(Math.trunc(" & s & "))"
           elif fromW == wU8: "BigInt((" & s & ") & 0xFF)"
           elif fromW == wU16: "BigInt((" & s & ") & 0xFFFF)"
           else: "BigInt(" & s & ")")
    elif fromFl and not toFl: s = "Math.trunc(" & s & ")"
    result = if toW == wF32: "(Math.fround(" & s & "))"
             elif toW == wU64: "(" & s & " & 0xFFFF_FFFF_FFFF_FFFFn)"
             elif toBig or toFl: "(" & s & ")"
             else: wrapNarrow(s, toW)
  of Reint:
    # (reint FROM TO VALUE) — the same scratch cell, the other view. codegen
    # has already rejected the pairs that have no bit-for-bit reading.
    let (fromW, toW) = pairWidths(c)
    var it = c.firstChild
    skip it
    skip it
    let v = exprText(it, indent)
    result = case fromW
      of wF64: (if toW == wU64: "(f64bits(" & v & ") & 0xFFFF_FFFF_FFFF_FFFFn)"
                else: "f64bits(" & v & ")")
      of wF32: (if toW == wU32: "(f32bits(" & v & ") >>> 0)"
                else: "f32bits(" & v & ")")
      of wI64, wU64: "bitsf64(" & v & ")"
      of wI32, wU32: "bitsf32(" & v & ")"
      else: raiseAssert "jsenc: cannot reinterpret " & $fromW & " as " & $toW
  of Raw:
    # (raw NAME TPL ARG*) — NAME is also the `EXT` entry it lowers to, so
    # splicing here yields exactly what codegen would have emitted inline.
    var it = c.firstChild
    let name = nameOf(it)
    skip it
    let tpl = strVal(it)
    skip it
    var args: seq[string]
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    result = spliceTemplate(name, tpl, args)
  # ── operations: first child is the WidthCode, operands follow it
  of Add, Sub, Mul, Div, Mod, Shl, Shr, And, Or, Xor, LAnd, LOr,
     Not, Neg, BNot, Eq, Neq, Lt, Le, Gt, Ge:
    var w: WidthCode
    let ops = operandTexts(c, indent, w)
    let is64 = w in {wI64, wU64}
    # arity is verified once here so every branch below stays a single
    # expression — the width-wrap template must compose, not statement.
    if jsTagOf(c) in {Not, Neg, BNot}:
      doAssert ops.len == 1, "jsenc: unary op with " & $ops.len & " operands"
    else:
      doAssert ops.len == 2, "jsenc: binary op with " & $ops.len & " operands"
    template wrap(s: string): string = wrapNarrow(s, w)
    template bin(op: string): string = wrap("(" & ops[0] & op & ops[1] & ")")
    template cmp(op: string): string =
      "(" & ops[0] & op & ops[1] & ")"  # operands are already canonical
    template uni(op: string): string =
      # The OPERAND gets its own parens: `-` before a negative literal splices
      # `--1` even inside outer parens, and that parses as a decrement of a
      # literal — a SyntaxError, not a number.
      wrap("(" & op & "(" & ops[0] & "))")
    result = case jsTagOf(c)
      of Add: bin " + "
      of Sub: bin " - "
      of Mul:
        if w in {wI8, wU8, wI16, wU16, wI32, wU32}:
          # `a * b | 0` rounds the product to a double first, so a product
          # above 2^53 has lost its low bits before the wrap. `Math.imul`
          # keeps them: it IS the hardware multiply.
          wrap "Math.imul(" & ops[0] & ", " & ops[1] & ")"
        else: bin " * "                         # BigInt is exact; fp wants no imul
      of Div:
        if is64: "(" & ops[0] & " / " & ops[1] & ")"  # BigInt division truncates
        elif w in {wF32, wF64}:
          wrap "(" & ops[0] & " / " & ops[1] & ")"  # fp division: truncating the
                                                   # quotient would be an integer
        else: wrap "Math.trunc(" & ops[0] & " / " & ops[1] & ")"
      of Mod: bin " % "  # JS and BigInt `%` both follow the dividend, like Nim
      of Shl:
        if is64: "(" & ops[0] & " << BigInt(" & ops[1] & "))"
        else: wrap "(" & ops[0] & " << " & ops[1] & ")"
      of Shr:
        # `>>>` over uint32; BU64 values are non-negative so BigInt `>>` is
        # already logical.
        if is64: wrap "(" & ops[0] & " >> BigInt(" & ops[1] & "))"
        elif w in {wU8, wU16, wU32}: wrap "(" & ops[0] & " >>> " & ops[1] & ")"
        else: wrap "(" & ops[0] & " >> " & ops[1] & ")"
      of And: bin " & "
      of Or: bin " | "
      # Short-circuit, and no narrow-wrap: with canonical 0/1 booleans (which
      # is what TrueC/FalseC and every comparison produce) `a && b` is already
      # 0 or 1, and wrapping it would defeat the point of the operator.
      of LAnd: cmp " && "
      of LOr: cmp " || "
      of Xor: bin " ^ "
      of Not: "(!" & ops[0] & ")"  # logical negation; the width child is vacuous
      of Neg: uni "-"
      of BNot: uni "~"
      of Eq: cmp " == "   # loose by intent: operands are primitives; `==`
      of Neq: cmp " != "  # alone bridges Number and BigInt
      of Lt: cmp " < "
      of Le: cmp " <= "
      of Gt: cmp " > "
      of Ge: cmp " >= "
      else: raiseAssert "jsenc: unreachable operation case"

# ── statements ──────────────────────────────────────────────────────────────
# `stmtText` renders one statement, possibly multi-line, WITHOUT a trailing
# newline; `indent` is the nesting level of the block it sits in.

proc blockText(c: Cursor; indent: int): string =
  ## The statement children of `c` rendered inside `{ … }` at `indent+1`.
  result = "{\n"
  var it = c.sub()
  while it.hasMore:
    result.add stmtText(it, indent + 1) & '\n'
    skip it
  result.add pad(indent) & "}"

proc blockTextSkip1(c: Cursor; indent: int): string =
  ## `blockText` for an `except` tree, whose first child is the binding name
  ## (or `.`), not a statement.
  result = "{\n"
  var it = c.sub()
  skip it
  while it.hasMore:
    result.add stmtText(it, indent + 1) & '\n'
    skip it
  result.add pad(indent) & "}"

proc paramsText(c: Cursor): string =
  result = "("
  var first = true
  var it = c.sub()
  while it.hasMore:
    if not first: result.add ", "
    result.add nameOf(it)
    first = false
    skip it
  result.add ")"

proc stmtText*(c: Cursor; indent: int): string =
  let p = pad(indent)
  case jsTagOf(c)
  of NoJs:
    raiseAssert "jsenc: not a jsnif statement: " & $c.kind
  of Top:
    raiseAssert "jsenc: `top` must be emitted via genJs"
  of Func:
    var it = c.firstChild
    let name = nameOf(it)
    skip it
    let ps = paramsText(it)
    skip it
    result = p & "function " & name & ps & " {\n"
    while it.hasMore:
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
  of Let:
    var it = c.firstChild
    let name = nameOf(it)
    skip it
    if it.kind == DotToken:
      result = p & "let " & name & ";"
    else:
      result = p & "let " & name & " = " & exprText(it, indent) & ";"
  of Params:
    raiseAssert "jsenc: `params` outside a func/arrow"
  of Block:
    result = p & blockText(c, indent)
  of Label:
    var it = c.firstChild
    let name = nameOf(it)
    # the label's body is every remaining child, wrapped in a plain block so
    # `break NAME` has a real labeled-statement target (§4)
    var bodyIt = it
    skip bodyIt
    result = p & name & ": {\n"
    while bodyIt.hasMore:
      result.add stmtText(bodyIt, indent + 1) & '\n'
      skip bodyIt
    result.add pad(indent) & "}"
  of Break:
    let lab = c.firstChild
    result = if lab.hasMore: p & "break " & nameOf(lab) & ";"
             else: p & "break;"
  of If:
    var it = c.firstChild
    let cond = exprText(it, indent)
    skip it
    # then-branch: children until an `Else` tree or a trailing dot
    var thenBuf = ""
    while it.hasMore and jsTagOf(it) != Else:
      if it.kind == DotToken: break
      thenBuf.add stmtText(it, indent + 1) & '\n'
      skip it
    result = p & "if (" & cond & ") {\n" & thenBuf & pad(indent) & "}"
    if it.hasMore and jsTagOf(it) == Else:
      # the `else` tree's children ARE its statements
      result.add " else " & blockText(it, indent)
  of Else:
    raiseAssert "jsenc: `else` outside `if`"
  of While:
    var it = c.firstChild
    let cond = exprText(it, indent)
    skip it
    result = p & "while (" & cond & ") {\n"
    while it.hasMore:
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
  of Try:
    result = p & "try {\n"
    var it = c.firstChild
    while it.hasMore and jsTagOf(it) notin {Except, Finally}:
      if it.kind == DotToken: break
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
    while it.hasMore:
      case jsTagOf(it)
      of Except:
        var e = it.firstChild
        if e.kind == DotToken:
          result.add " catch " & blockTextSkip1(it, indent)
        else:
          result.add " catch (" & nameOf(e) & ") " & blockTextSkip1(it, indent)
      of Finally:
        result.add " finally " & blockText(it, indent)
      else:
        raiseAssert "jsenc: unexpected child in `try`: " & $jsTagOf(it)
      skip it
  of Except, Finally:
    raiseAssert "jsenc: `" & $jsTagOf(c) & "` outside `try`"
  of Throw:
    result = p & "throw " & exprText(c.firstChild, indent) & ";"
  of Return:
    let v = c.firstChild
    result = if not v.hasMore: p & "return;"
             else: p & "return " & exprText(v, indent) & ";"
  of ExprStmt:
    result = p & exprText(c.firstChild, indent) & ";"
  else:
    raiseAssert "jsenc: expression where a statement was expected: " & $jsTagOf(c)

proc genJs*(buf: var TokenBuf): string =
  ## Render a whole program: the buffer's root must be a `top` tree. The
  ## preamble is NOT included — the CLI prepends it once per file.
  var c = beginRead(buf)
  doAssert jsTagOf(c) == Top, "jsenc: genJs expects a `top` root, got " & $jsTagOf(c)
  var it = c.sub()
  while it.hasMore:
    result.add stmtText(it, 0) & '\n'
    skip it
