#
#           The web back end — Leng → JavaScript / wasm32
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##
## The web IR → JavaScript renderer. No codegen logic lives here: it walks the
## `(top …)` tree `codegen` produced and prints it, with the host contract
## (the preamble) in front and the program's start at the end. Correctness rests on two
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

import std / [strutils, base64]
import nifcore
import webnif

const
  viewNames*: array[WidthCode, string] = [
    "I8", "U8", "I16", "U16", "I32", "U32", "BI64", "BU64", "F32", "F64"
  ]
    ## Typed-array view names over the one `ArrayBuffer` (§1).
  dvGet: array[WidthCode, string] = [
    "getInt8", "getUint8", "getInt16", "getUint16", "getInt32", "getUint32",
    "getBigInt64", "getBigUint64", "getFloat32", "getFloat64"
  ]
  dvSet: array[WidthCode, string] = [
    "setInt8", "setUint8", "setInt16", "setUint16", "setInt32", "setUint32",
    "setBigInt64", "setBigUint64", "setFloat32", "setFloat64"
  ]
    ## The alignment-free accessors; the byte widths keep their direct view.

proc jsPreamble*(memBytes, stackBytes, dataEnd: int; browser = false): string =
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
  # The target face: node writes to fds through `fs`; a browser has neither
  # `fs` nor a synchronous fd, so stdout/stderr land on `console.log`/
  # `console.error` one line at a time (devtools shows engine output live,
  # no host drain loop), `nim_exit` throws instead of killing the tab, and
  # `__takeOutput()` still returns whatever has no line ending yet.
  (if browser:
    ("const __outBuf = [];  // writes to fds the console cannot serve\n" &
     "const __dec = [new TextDecoder(\"utf-8\"), new TextDecoder(\"utf-8\")];\n" &
     "  // one streaming decoder per console fd: a UTF-8 sequence split across\n" &
     "  // two flushes must not decode into a replacement char\n" &
     "let __pend = [\"\", \"\"];  // the unterminated tail of each console fd\n" &
     "function __takeOutput() {\n" &
     "  const s = __outBuf.join(\"\") + __pend[0] + __pend[1];\n" &
     "  __outBuf.length = 0; __pend = [\"\", \"\"];\n" &
     "  return s;\n" &
     "}\n")
   else:
    "const fs = require(\"fs\");  // for the synchronous nim_write below\n") &
  "let JMEM = new ArrayBuffer(" & $memBytes & ");\n" &
  "let I8 = new Int8Array(JMEM), U8 = new Uint8Array(JMEM),\n" &
  "    I16 = new Int16Array(JMEM), U16 = new Uint16Array(JMEM),\n" &
  "    I32 = new Int32Array(JMEM), U32 = new Uint32Array(JMEM),\n" &
  "    F32 = new Float32Array(JMEM), F64 = new Float64Array(JMEM),\n" &
  "    BI64 = new BigInt64Array(JMEM), BU64 = new BigUint64Array(JMEM),\n" &
  "    DV = new DataView(JMEM);  // width-2+ heap access: no alignment trap, no vanishing store\n" &
  "const EXT = [];  // extern value table: handle -> real JS value (§6)\n" &
  "const FTAB = []; // function table: slot -> JS function; 0 is the null pointer\n" &
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
  "const __internExt = ewrap; // splice-facing alias: intern a host value as a handle\n" &
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
  "  DV = new DataView(JMEM);\n" &
  "  return old;\n" &
  "}\n" &
  # The static image: the wasm data section's twin. Base64 because the image
  # is arbitrary bytes and a JS string literal is not.
  "function D(b64, at) {\n" &
  "  const bin = atob(b64);\n" &
  "  for (let i = 0; i < bin.length; ++i) U8[at + i] = bin.charCodeAt(i);\n" &
  "}\n" &
  # The host face, the same two entry points the wasm renderer imports from
  # `env`. The
  # body branches on the target: node writes the fd synchronously; a browser
  # buffers UTF-8 into __outBuf (drained via __takeOutput) and has no process
  # to exit, so nim_exit throws and the host's frame call unwinds.
  (if browser:
    ("function nim_write(fd, buf, len) {\n" &
     "  if (fd === 1 || fd === 2) {\n" &
     "    // the console is line-oriented: log every complete line as it forms,\n" &
     "    // keep the partial tail for the next write (or __takeOutput)\n" &
     "    const i = fd - 1;\n" &
     "    __pend[i] += __dec[i].decode(U8.subarray(buf, buf + len), {stream: true});\n" &
     "    let nl;\n" &
     "    while ((nl = __pend[i].indexOf(\"\\n\")) >= 0) {\n" &
     "      (fd === 2 ? console.error : console.log)(__pend[i].slice(0, nl));\n" &
     "      __pend[i] = __pend[i].slice(nl + 1);\n" &
     "    }\n" &
     "  } else {\n" &
     "    __outBuf.push(new TextDecoder(\"utf-8\").decode(U8.subarray(buf, buf + len)));\n" &
     "  }\n" &
     "  return len;\n" &
     "}\n" &
     "function nim_exit(code) { throw new Error(\"nim_exit(\" + code + \")\"); }\n")
   else:
    ("function nim_write(fd, buf, len) {\n" &
     "  // fs.writeSync, not process.stdout.write: the latter is asynchronous on\n" &
     "  // pipes (macOS/Windows), and the process.exit a `nim_exit` performs would\n" &
     "  // cut a pending write. The sync call lands before the exit, everywhere.\n" &
     "  fs.writeSync(fd === 2 ? 2 : 1, Buffer.from(JMEM, buf, len));\n" &
     "  return len;\n" &
     "}\n" &
     "function nim_exit(code) { process.exit(code); }\n")) &
  # The ruling for a syscall the target cannot serve: `unreachable`, a
  # loud trap, not a silent no-op. The throw is the JS twin of that trap.
  "function nim_unreachable() { throw new Error('unreachable: unsupported syscall'); }\n" &
  # The shadow stack (§2): the top `stackBytes` of the buffer, growing DOWN.
  # frame(n) returns the new base; a frame's locals live at byte offsets from
  # the base in the SAME address space as the heap, which is what lets `addr`
  # of a local and `deref` of a pointer share one representation. The base is
  # 16-aligned so a slot aligned by its own type — a 16-byte array is align 16
  # in C — lands correctly whatever the frame size.
  #
  # leave restores the CALLER's SP, not this frame's base. Restoring the base
  # would leave SP short by one frame after every call, so a proc called in a
  # loop (a seq `[]=` — one frame per write) would creep down and trip
  # SP_MIN. The wasm renderer parks the entry SP in a local of its own; JS has
  # no such local, so it goes on a parallel stack. Frames are strictly nested (one frame()/leave() pair per routine,
  # callees between them), so LIFO push/pop restores the exact entry SP.
  "let SP_MIN = " & $(memBytes - stackBytes) & ";\n" &
  "let SP = " & $memBytes & ";\n" &
  "const _SPF = [];  // entry SP of each open frame; strictly nested, so LIFO\n" &
  # Modulo, not `& ~15`: a bitwise AND goes through ToInt32 and wraps at 2 GiB.
  "function frame(n) {\n" &
  "  const r = SP - n; const f = r - (r % 16);\n" &
  "  if (f < SP_MIN) throw new Error(\"stack overflow\");\n" &
  "  _SPF.push(SP); SP = f; return f;\n" &
  "}\n" &
  "function leave() { SP = _SPF.pop(); }\n" &
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
  # memcpy over the one buffer (overlap-safe, like wasm's `memory.copy`).
  "function copyMem(d, s, n) { U8.copyWithin(d, s, s + n); }\n" &
  # The string bridge (M7 §6): a Nim `string` crossing an `importjs` splice.
  # The representation is the SSO string of lib/std/system/stringimpl.nim for
  # the 4-byte target: byte0 = slen (or the sentinel 254=static / 255=heap);
  # slen <= PAYLOAD(6) keeps the chars inline at value+1; otherwise `more`
  # (value+4) points to a LongString { fullLen@0, rc@4, capImpl@8, data@12 }.
  # These mirror `len`/`rawData` exactly, so short, medium, long and static all
  # decode correctly. TextEncoder/Decoder exist in both node and the browser.
  "const __STR_PAYLOAD = 6, __STR_DATAOFF = 12, __STR_STATIC = 254;\n" &
  "function nimStrToJs(s) {\n" &
  "  const sl = U8[s];\n" &
  "  if (sl <= __STR_PAYLOAD)\n" &
  "    return new TextDecoder(\"utf-8\").decode(U8.subarray(s + 1, s + 1 + sl));\n" &
  "  const more = DV.getUint32(s + 4, true);\n" &
  "  const n = DV.getInt32(more, true);\n" &
  "  return new TextDecoder(\"utf-8\").decode(U8.subarray(more + __STR_DATAOFF, more + __STR_DATAOFF + n));\n" &
  "}\n" &
  "function cstrToJs(p) {\n" &
  "  let e = p; while (U8[e] !== 0) ++e;\n" &
  "  return new TextDecoder(\"utf-8\").decode(U8.subarray(p, e));\n" &
  "}\n" &
  # A JS string back to Nim as a STATIC string (byte0=254, capImpl=0): the GC's
  # `=destroy` frees only a HeapSlen string, so a bridge result is never freed
  # and never refcounted — it leaks rather than risk a bad refcount (plan §6
  # first-cut liveness, matching the never-released handle table). The inline
  # cache (first 3 chars at value+1) is synced so `==`/`hash` agree with a
  # compiler literal of the same text.
  "function jsToNimStr(v) {\n" &
  "  const enc = new TextEncoder().encode(typeof v === \"string\" ? v : String(v));\n" &
  "  const n = enc.length;\n" &
  "  const p = osalloc(0, __STR_DATAOFF + n + 1);\n" &
  "  DV.setInt32(p + 0, n, true); DV.setInt32(p + 4, 0, true); DV.setInt32(p + 8, 0, true);\n" &
  "  U8.set(enc, p + __STR_DATAOFF); U8[p + __STR_DATAOFF + n] = 0;\n" &
  "  const val = osalloc(0, 8);\n" &
  "  U8[val] = __STR_STATIC;\n" &
  "  for (let i = 0; i < 3 && i < n; ++i) U8[val + 1 + i] = enc[i];\n" &
  "  DV.setUint32(val + 4, p, true);\n" &
  "  return val;\n" &
  "}\n" &
  "function jsToCstr(v) {\n" &
  "  const enc = new TextEncoder().encode(typeof v === \"string\" ? v : String(v));\n" &
  "  const n = enc.length;\n" &
  "  const p = osalloc(0, n + 1);\n" &
  "  U8.set(enc, p); U8[p + n] = 0;\n" &
  "  return p;\n" &
  "}\n" &
  # Length-based bridges, for the C shapes that are neither a Nim string nor
  # a NUL-terminated cstring: a (data, length) view. `strViewToJs` decodes a
  # WGPUStringView (WebGPU's string shape — NOT NUL-terminated); `memView`
  # hands the host a live subarray of linear memory (queue.writeBuffer data),
  # re-reading U8 at call time so a grown memory is never stale.
  "function strViewToJs(p, n) {\n" &
  "  if (n === 0 || p === 0) return \"\";\n" &
  "  if (n < 0) {\n" &
  "    // WGPUStringView's WGPU_STRLEN sentinel (high(csize_t) crosses as -1):\n" &
  "    // the string is NUL-terminated, so find the end before decoding.\n" &
  "    let z = U8.indexOf(0, p);\n" &
  "    n = z < 0 ? U8.length - p : z - p;\n" &
  "  }\n" &
  "  return new TextDecoder(\"utf-8\").decode(U8.subarray(p, p + n));\n" &
  "}\n" &
  "function memView(p, n) { return U8.subarray(p, p + n); }\n" &
  # wasm's `memory.fill`.
  "function fillMem(d, v, n) { U8.fill(v, d, d + n); }\n" &
  # The portable bit rows. wasm has i32.ctz/clz/popcount; JS has Math.clz32
  # and nothing else, so the rest are loops spelled the obvious way. The
  # count is a Number (0..64) in both worlds; the zero case answers with the
  # width, like the wasm opcodes do (C calls it UB; nimony guards, but the
  # wasm target records 32/64 and so does this).
  "function ctz32(x) { x |= 0; if (x === 0) return 32; let n = 0; while ((x & 1) === 0) { x >>>= 1; ++n; } return n; }\n" &
  "function clz32(x) { return Math.clz32(x | 0); }\n" &
  "function popcnt32(x) { x >>>= 0; let n = 0; while (x !== 0) { x &= x - 1; ++n; } return n; }\n" &
  "function ctz64(x) { let u = BigInt.asUintN(64, x); if (u === 0n) return 64; let n = 0; while ((u & 1n) === 0n) { u >>= 1n; ++n; } return n; }\n" &
  "function clz64(x) { let u = BigInt.asUintN(64, x); if (u === 0n) return 64; let n = 0; while ((u & 0x8000000000000000n) === 0n) { u <<= 1n; ++n; } return n; }\n" &
  "function popcnt64(x) { let u = BigInt.asUintN(64, x); let n = 0; while (u !== 0n) { u &= u - 1n; ++n; } return n; }\n" &
  # Division by zero traps natively (SIGFPE) and on wasm; JS would hand back
  # Infinity->0 or a RangeError with a foreign message. One story for both
  # widths: a named throw — and the helper form means each operand is
  # evaluated exactly once, which a `b === 0 ? ...` ternary would not give.
  # A float → integer conversion traps when the truncated value does not fit,
  # and on NaN, exactly as wasm's `trunc` does; `lo`/`hi` are the range of the
  # 32- or 64-bit conversion the target width goes through.
  "function ftoi(x, lo, hi) { const t = Math.trunc(x); if (!(t >= lo && t < hi)) throw new Error(\"float conversion out of range\"); return t; }\n" &
  "function idiv(a, b) { if (b === 0) throw new Error(\"division by zero\"); return Math.trunc(a / b); }\n" &
  "function imod(a, b) { if (b === 0) throw new Error(\"division by zero\"); return a % b; }\n" &
  "function idiv64(a, b) { if (b === 0n) throw new Error(\"division by zero\"); return a / b; }\n" &
  "function imod64(a, b) { if (b === 0n) throw new Error(\"division by zero\"); return a % b; }\n" &
  # The allocator is the osalloc CONTRACT (§5): the same shape as wasm's, and
  # bounded by SP_MIN so the heap can never walk into the shadow stack.
  "let heapTop = " & $dataEnd & ";\n" &
  # Modulo, not `& ~15`: a bitwise AND goes through ToInt32 and wraps at 2 GiB.
  "function osalloc(_, n) {\n" &
  "  const a = heapTop + 15; const b = a - (a % 16);\n" &
  "  const m = n + 15; const r = b + (m - (m % 16));\n" &
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
  ## f64 needs nothing. f32 DOES: JS computes every operation in double, where
  ## the hardware f32 op rounds its result — `Math.fround` is that rounding,
  ## and without it an f32 intermediate diverges from wasm and native. On the
  ## exact cases (a negation, an already-rounded operand) the fround is a
  ## no-op, so applying it uniformly through `wrap` costs nothing in meaning.
  ## Both 64-bit int widths DO: BigInt is exact and unbounded,
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
  of wF32: "(Math.fround(" & text & "))"
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
  else: raiseAssert "jsrender: name expected, got " & $c.kind

const
  ExternIdentStart = {'a'..'z', 'A'..'Z', '_', '$'}
  ExternIdentChars = ExternIdentStart + {'0'..'9'}

proc externName(sym: string): string =
  ## What `$1`/`$#` substitute for. Nim's `setExternName` (`pragmas.nim` in
  ## 2.2.4) resolves the pattern with `extname % s.name.s` at DECLARATION time,
  ## so the text reaching the call site carries the proc's PLAIN Nim name,
  ## unmangled — which is exactly why `dom.nim`'s `#.$1(#, #)` reaches
  ## `insertAdjacentText` and not a unique symbol. jorogumo carries the mangled
  ## `NAME.DISAMBIG.MODULESUFFIX` into the splice, and a Nim identifier cannot
  ## contain a dot, so the source name is whatever precedes the first one.
  ##
  ## A base that is not a JS identifier — an operator, a quoted name — is
  ## REFUSED. Nim pastes such a name in verbatim and emits text that cannot
  ## parse; a back end here does not generate syntax it knows to be broken, and
  ## `#`-only templates or an explicit extern name bind those shapes anyway.
  let cut = find(sym, '.')
  result = if cut > 0: substr(sym, 0, cut - 1) else: sym
  var legal = result.len > 0 and result[0] in ExternIdentStart
  if legal:
    for ch in result:
      if ch notin ExternIdentChars:
        legal = false
        break
  if not legal:
    raiseAssert "importjs: `$1` needs a JS-legal proc name, but `" & sym &
      "` does not have one"

proc spliceTemplate(name, tpl: string; args: openArray[string]): string =
  ## The `importjs` template language, pinned EMPIRICALLY against Nim
  ## 2.2.4's jsgen (`#.$1(#, #)` → `self.insertAdjacentText(position, data)`;
  ## `$$(#)` → `$("sel")`): `#` consumes the next argument, `$1` and `$#`
  ## name the proc (that is how `dom.nim` reaches the method name — `name`
  ## here is `externName`, NOT the mangled symbol), `@` spreads the
  ## arguments not yet consumed, `$$` is a literal `$`. A bare
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
    raiseAssert "jsrender: `" & $webTagOf(c) & "` carries no width child"
  WidthCode(it.intVal)

proc pairWidths(c: Cursor): (WidthCode, WidthCode) =
  ## The FROM/TO pair of `cvt`/`reint`, with the same naming guard.
  var it = c.firstChild
  if it.kind != IntLit:
    raiseAssert "jsrender: `" & $webTagOf(c) & "` carries no width children"
  result[0] = WidthCode(it.intVal)
  skip it
  if it.kind != IntLit:
    raiseAssert "jsrender: `" & $webTagOf(c) & "` has no destination width"
  result[1] = WidthCode(it.intVal)

proc operandTexts(c: Cursor; indent: int; w: out WidthCode): seq[string] =
  var it = c.firstChild
  w = opWidth(c)
  skip it
  while it.hasMore:
    result.add exprText(it, indent)
    skip it

proc exprText(c: Cursor; indent: int): string =
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
  case webTagOf(c)
  of NoTag:
    raiseAssert "jsrender: not a web IR node: " & $c.kind
  of Top, Block, Func, Params, Param, Locals, Sig, Label, Break, If, Else,
     While, Return, ExprStmt, Leave:
    raiseAssert "jsrender: statement where an expression was expected: " & $webTagOf(c)
  # ── literals that need a tag
  of BigIntLit: result = strVal(c.firstChild) & "n"
  of TrueLit: result = "true"
  of FalseLit: result = "false"
  of NanLit: result = "NaN"
  of InfLit: result = "Infinity"
  # ── composites
  of Call:
    var it = c.firstChild
    var fn = exprText(it, indent)
    if webTagOf(it) == Arrow:
      fn = "(" & fn & ")"                        # an immediately-invoked arrow
                                                 # needs grouping: `(() => {…})(…)`
    skip it
    var args: seq[string]
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    result = fn & "(" & args.join(", ") & ")"
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
    doAssert parts.len > 0, "jsrender: empty seq"
    result = "(" & parts.join(", ") & ")"
  of ICall:
    # (icall SIG TARGET ARG*) — the function-table slot; JS does not check
    # the signature, wasm's `call_indirect` does.
    var it = c.firstChild
    skip it                                      # the signature
    let fn = exprText(it, indent)
    skip it
    var args: seq[string]
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    result = "FTAB[" & fn & "](" & args.join(", ") & ")"
  of MemCopy, MemFill, MemGrow, Frame:
    var args: seq[string]
    var it = c.firstChild
    while it.hasMore:
      args.add exprText(it, indent)
      skip it
    let fn = case webTagOf(c)
             of MemCopy: "copyMem"
             of MemFill: "fillMem"
             of MemGrow: "memoryGrow"
             else: "frame"
    result = fn & "(" & args.join(", ") & ")"
  of MemSize: result = "memorySize()"
  of Unreachable: result = "nim_unreachable()"
  of Ctz, Clz, Popcnt:
    let w = opWidth(c)
    var it = c.firstChild
    skip it
    let base = case webTagOf(c)
               of Ctz: "ctz"
               of Clz: "clz"
               else: "popcnt"
    result = base & (if w.isBig: "64(" else: "32(") & exprText(it, indent) & ")"
  of Arrow:
    var it = c.firstChild
    var ps: seq[string]
    if webTagOf(it) == Params:
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
    # Width 2+ goes through the DataView: a typed array at a fractional index
    # reads `undefined` and the store below vanishes — silent wrong code, the
    # one outcome worse than wasm's trap. The DataView needs no alignment and
    # costs nothing extra on aligned access; the byte views stay direct.
    if s == 1: result = viewNames[w] & "[" & at & "]"
    else: result = "DV." & dvGet[w] & "(" & at & ", true)"
  of HStore:
    var it = c.firstChild
    let w = opWidth(c)
    skip it
    let at = exprText(it, indent)
    skip it
    let s = scaleOf(w)
    let val = exprText(it, indent)
    if s == 1: result = "(" & viewNames[w] & "[" & at & "] = " & val & ")"
    else: result = "(DV." & dvSet[w] & "(" & at & ", " & val & ", true))"
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
      s = (if fromFl: s                        # see below: the trapping form
           elif fromW == wU8: "BigInt((" & s & ") & 0xFF)"
           elif fromW == wU16: "BigInt((" & s & ") & 0xFFFF)"
           else: "BigInt(" & s & ")")
    elif fromFl and not toFl:
      s = case toW
          of wI8, wI16, wI32: "ftoi(" & s & ", -2147483648, 2147483648)"
          of wU8, wU16, wU32: "ftoi(" & s & ", 0, 4294967296)"
          else: s
    if fromFl and toBig:
      s = (if toW == wI64: "BigInt(ftoi(" & v & ", -9223372036854775808, 9223372036854775808))"
           else: "BigInt(ftoi(" & v & ", 0, 18446744073709551616))")
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
      else: raiseAssert "jsrender: cannot reinterpret " & $fromW & " as " & $toW
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
    # `$1`/`$#` want the Nim source name, not the symbol `NAME` carries — see
    # `externName`. `#`-only templates never look at it, which is why this gap
    # stayed invisible until a `dom.nim`-shaped binding was tried for real.
    result = spliceTemplate(externName(name), tpl, args)
  # ── operations: first child is the WidthCode, operands follow it
  of Add, Sub, Mul, Div, Mod, Shl, Shr, And, Or, Xor, LAnd, LOr,
     Not, Neg, BNot, Eq, Neq, Lt, Le, Gt, Ge:
    var w: WidthCode
    let ops = operandTexts(c, indent, w)
    let is64 = w in {wI64, wU64}
    # arity is verified once here so every branch below stays a single
    # expression — the width-wrap template must compose, not statement.
    if webTagOf(c) in {Not, Neg, BNot}:
      doAssert ops.len == 1, "jsrender: unary op with " & $ops.len & " operands"
    else:
      doAssert ops.len == 2, "jsrender: binary op with " & $ops.len & " operands"
    template wrap(s: string): string = wrapNarrow(s, w)
    template bin(op: string): string = wrap("(" & ops[0] & op & ops[1] & ")")
    template cmp(op: string): string =
      "(" & ops[0] & op & ops[1] & ")"  # operands are already canonical
    template uni(op: string): string =
      # The OPERAND gets its own parens: `-` before a negative literal splices
      # `--1` even inside outer parens, and that parses as a decrement of a
      # literal — a SyntaxError, not a number.
      wrap("(" & op & "(" & ops[0] & "))")
    result = case webTagOf(c)
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
        # Integer division by zero TRAPS natively; the preamble helper throws
        # the same named error at both widths instead of Infinity->0 (Number)
        # or a foreign RangeError (BigInt).
        if is64: "(idiv64(" & ops[0] & ", " & ops[1] & "))"  # BigInt division truncates
        elif w in {wF32, wF64}:
          wrap "(" & ops[0] & " / " & ops[1] & ")"  # fp division: truncating the
                                                   # quotient would be an integer
        else: wrap "idiv(" & ops[0] & ", " & ops[1] & ")"
      of Mod:
        # fp `%` is fmod and answers NaN for `x % 0`, like the hardware; only
        # the integer worlds get the trap helper.
        if is64: wrap "imod64(" & ops[0] & ", " & ops[1] & ")"
        elif w in {wF32, wF64}: bin " % "
        else: wrap "imod(" & ops[0] & ", " & ops[1] & ")"
      of Shl:
        # A 64-bit shift count is taken mod 64, as wasm's `i64.shl` and the
        # hardware take it; a BigInt shift is exact and would not wrap.
        if is64: wrap "(" & ops[0] & " << (BigInt(" & ops[1] & ") & 63n))"
        else: wrap "(" & ops[0] & " << " & ops[1] & ")"
      of Shr:
        # `>>>` over uint32; BU64 values are non-negative so BigInt `>>` is
        # already logical.
        if is64: wrap "(" & ops[0] & " >> (BigInt(" & ops[1] & ") & 63n))"
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
      else: raiseAssert "jsrender: unreachable operation case"

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

proc paramName(c: Cursor): string =
  ## The name of a `(param NAME W)` — or of a bare name, as an arrow's
  ## parameter list spells it.
  if webTagOf(c) == Param: nameOf(c.firstChild) else: nameOf(c)

proc paramWidth(c: Cursor): WidthCode =
  var it = c.firstChild
  skip it
  WidthCode(it.intVal)

proc paramsText(c: Cursor): string =
  result = "("
  var first = true
  var it = c.sub()
  while it.hasMore:
    if not first: result.add ", "
    result.add paramName(it)
    first = false
    skip it
  result.add ")"

proc zeroOf(w: WidthCode): string =
  ## A fresh local's value: zero in its own numeric world.
  if w.isBig: "0n" else: "0"

proc stmtText*(c: Cursor; indent: int): string =
  let p = pad(indent)
  case webTagOf(c)
  of NoTag:
    raiseAssert "jsrender: not a jsnif statement: " & $c.kind
  of Top:
    raiseAssert "jsrender: `top` must be emitted via genJs"
  of Func:
    # (func NAME PARAMS RET LOCALS STMT*): the widths matter to wasm only; a
    # JS local needs just its zero, which must be a BigInt for a 64-bit one.
    var it = c.firstChild
    let name = nameOf(it)
    skip it
    let ps = paramsText(it)
    skip it
    skip it                                      # the result width
    result = p & "function " & name & ps & " {\n"
    var lets: seq[string] = @[]
    var li = it.firstChild
    while li.hasMore:
      lets.add paramName(li) & " = " & zeroOf(paramWidth(li))
      skip li
    skip it
    if lets.len > 0:
      result.add pad(indent + 1) & "let " & lets.join(", ") & ";\n"
    while it.hasMore:
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
  of Params, Param, Locals, Sig:
    raiseAssert "jsrender: `" & $webTagOf(c) & "` outside a func"
  of Leave:
    result = p & "leave();"
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
    while it.hasMore and webTagOf(it) != Else:
      if it.kind == DotToken: break
      thenBuf.add stmtText(it, indent + 1) & '\n'
      skip it
    result = p & "if (" & cond & ") {\n" & thenBuf & pad(indent) & "}"
    if it.hasMore and webTagOf(it) == Else:
      # the `else` tree's children ARE its statements
      result.add " else " & blockText(it, indent)
  of Else:
    raiseAssert "jsrender: `else` outside `if`"
  of While:
    var it = c.firstChild
    let cond = exprText(it, indent)
    skip it
    result = p & "while (" & cond & ") {\n"
    while it.hasMore:
      result.add stmtText(it, indent + 1) & '\n'
      skip it
    result.add pad(indent) & "}"
  of Return:
    let v = c.firstChild
    result = if not v.hasMore: p & "return;"
             else: p & "return " & exprText(v, indent) & ";"
  of ExprStmt:
    result = p & exprText(c.firstChild, indent) & ";"
  else:
    raiseAssert "jsrender: expression where a statement was expected: " & $webTagOf(c)

proc genJs*(buf: var TokenBuf): string =
  ## Render a whole program: the buffer's root must be a `top` tree. The
  ## preamble is NOT included — the CLI prepends it once per file.
  var c = beginRead(buf)
  doAssert webTagOf(c) == Top, "jsrender: genJs expects a `top` root, got " & $webTagOf(c)
  var it = c.sub()
  while it.hasMore:
    result.add stmtText(it, 0) & '\n'
    skip it

proc dataInitJs*(m: WebModule): string =
  ## The static image as JS: one `D(base64, address)` call per segment (the
  ## data section's twin). Base64 because the image is arbitrary bytes and a
  ## JS string literal is not.
  result = ""
  for (at, s) in m.dataSegs:
    result.add "D(\"" & encode(s) & "\", " & $at & ");\n"

proc renderJs*(tree: var TokenBuf; m: WebModule; memBytes, stackBytes: int;
               browser = false): string =
  ## The whole program as one self-contained `.js` file: the host contract,
  ## the module's globals and static image, the functions, the function table,
  ## and finally the start — `main`, whose result is the exit code, or, for a
  ## host-driven library, the module init plus the export surface.
  result = jsPreamble(memBytes, stackBytes, int m.memTop, browser)
  if m.globals.len > 0:
    var gs: seq[string] = @[]
    for (n, w) in m.globals: gs.add n & " = " & zeroOf(w)
    result.add "let " & gs.join(", ") & ";\n"
  result.add dataInitJs(m)
  result.add genJs(tree)
  # JS wrappers bridging Nim procs used as `importjs` callbacks; all-scalar
  # procs need none and pass through as FTAB entries, so this is often empty.
  for cb in m.callbacks:
    result.add cb
  result.add "FTAB[0] = () => { throw new Error(\"nil function pointer\"); };\n"
  for slot in 1 ..< m.table.len:
    let f = m.table[slot]
    if f.len > 0:
      result.add "FTAB[" & $slot & "] = " & f & ";\n"
    else:
      # A slot taken for a proc that was never lowered — a bodyless `importc`
      # used as a value — binds HERE, rather than turning the whole file into
      # a ReferenceError at load or a TypeError at a call that may never happen.
      result.add "FTAB[" & $slot & "] = () => { throw new Error(\"unbound function-table slot " &
        $slot & "\"); };\n"
  var zeros: seq[string] = @[]
  for w in m.entryParams: zeros.add zeroOf(w)
  let entryCall = m.entry & "(" & zeros.join(", ") & ")"
  if m.exports.len > 0:
    # A host-driven library (exportc procs, no meaningful main): run the module
    # init (main drives the ini chain + top level) so globals are live before
    # the host calls in, expose the exportc procs under their C names, and DO
    # NOT exit — the host owns the lifecycle.
    result.add entryCall & ";\n"
    # node hands the surface to `require`; a browser has no module system in a
    # classic <script>, so it lands on globalThis.NIF.
    var ex = (if browser: "globalThis.NIF = {" else: "module.exports = {")
    for (cName, f) in m.exports:
      ex &= "\n  " & cName & ": " & f & ","
    # The host reads results straight out of linear memory. `memory.buffer`
    # mirrors the wasm export, so the JS engine is a drop-in for the wasm one;
    # it is a getter because memoryGrow REPLACES JMEM.
    ex &= "\n  memory: { get buffer(){ return JMEM; } },"
    # The host-bridge for handles: `__internExt` pushes a real JS object into
    # the host value table and returns the int32 handle the exported procs take.
    ex &= "\n  __internExt: ewrap,"
    if browser:
      # no fd to write to: buffered stdout/stderr is drained here after a call.
      ex &= "\n  __takeOutput,"
    ex &= "\n};\n"
    result.add ex
  elif not m.entryHasRet:
    result.add entryCall & ";\n"
  else:
    result.add "nim_exit(Number(" & entryCall & ") | 0);\n"
