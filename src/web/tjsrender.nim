#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## Self-contained tests for `webnif` + `jsrender`: the tag-pool alignment, the
## width-driven operation forms, every statement shape, the `importjs`
## template splice, and two checks that make a JS ENGINE the judge — a
## generated program that prints `hello jorogumo` through the bridge and one
## that computes 42 through the linear memory. Run: `nim c -r tjsrender.nim`.
## Without `node` on PATH the engine blocks are skipped and the skip is
## reported, so a run on a machine with no node is not silently thinner than
## it looks.

import std / [os, osproc, strutils]
import nifcore
import webnif, jsrender

let tags = createWebTagPool()  # asserts TagId == ord(WebTag)+1 while registering

proc createTop(): TokenBuf =
  ## Opens the root `top`; `render` is its counterpart and closes it.
  result = createTokenBuf(sharedTags = tags)
  result.openTree Top

proc render(buf: var TokenBuf): string =
  buf.closeTag
  # `genJs` terminates every top-level statement; the goldens speak in
  # statements, so the trailing newline is not part of what they compare.
  strip(genJs(buf))

proc expect(label, got, want: string) =
  if got != want:
    echo "FAIL ", label, "\n  got:  ", got.replace("\n", "\n        ")
    echo "  want: ", want.replace("\n", "\n        ")
    quit 1
  echo "ok ", label

# ── 1. expressions: width-driven forms ──────────────────────────────────────

block narrow_add:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Add:
        b.width wI32
        b.numLit 2
        b.numLit 3
  expect "i32 add wraps", render(b), "(x = ((2 + 3) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Add:
        b2.width wU8
        b2.numLit 2
        b2.numLit 3
  expect "u8 add wraps", render(b2), "(x = ((2 + 3) << 24 >>> 24));"

block big_add:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Add:
        b.width wI64
        b.bigIntLit "1"
        b.bigIntLit "2"
  expect "i64 add is BigInt and wraps", render(b),
         "(x = BigInt.asIntN(64, (1n + 2n)));"

block div_forms:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Div:
        b.width wI32
        b.numLit 7
        b.numLit 2
  expect "i32 div goes through the trap helper", render(b), "(x = (idiv(7, 2) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Div:
        b2.width wI64
        b2.bigIntLit "10"
        b2.bigIntLit "3"
  expect "i64 div goes through the trap helper", render(b2), "(x = (idiv64(10n, 3n)));"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Assign:
      b3.symUse "x"
      b3.tree Div:
        b3.width wF64
        b3.symUse "a"
        b3.symUse "b"
  expect "f64 div must not truncate the quotient", render(b3),
         "(x = (a / b));"

block f32_rounding:
  # JS computes every operation in double where the hardware f32 op rounds its
  # result; Math.fround IS that rounding. Without it an f32 intermediate
  # diverges from wasm and native — e.g. the product compared at f32.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Add:
        b.width wF32
        b.symUse "a"
        b.symUse "b"
  expect "f32 add rounds to f32", render(b), "(x = (Math.fround((a + b))));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Mul:
        b2.width wF32
        b2.symUse "a"
        b2.symUse "b"
  expect "f32 mul rounds to f32", render(b2), "(x = (Math.fround((a * b))));"

block mod_trap:
  # Integer division and remainder by zero TRAP natively (SIGFPE, wasm trap);
  # the preamble helpers throw one named error at both widths. fp `%` is fmod
  # and answers NaN for `x % 0`, like the hardware, so it stays inline.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Mod:
        b.width wI32
        b.numLit 7
        b.numLit 2
  expect "i32 mod goes through the trap helper", render(b), "(x = (imod(7, 2) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Mod:
        b2.width wI64
        b2.bigIntLit "7"
        b2.bigIntLit "2"
  expect "i64 mod goes through the trap helper", render(b2),
         "(x = BigInt.asIntN(64, imod64(7n, 2n)));"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Assign:
      b3.symUse "x"
      b3.tree Mod:
        b3.width wF64
        b3.symUse "a"
        b3.symUse "b"
  expect "f64 mod stays inline", render(b3), "(x = (a % b));"

block mul_forms:
  # `a * b | 0` rounds the product to a double before the wrap, so a product
  # above 2^53 has already lost its low bits. `Math.imul` is the hardware
  # multiply and keeps them.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Mul:
        b.width wI32
        b.symUse "a"
        b.symUse "b"
  expect "i32 mul uses Math.imul", render(b), "(x = (Math.imul(a, b) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Mul:
        b2.width wU32
        b2.symUse "a"
        b2.symUse "b"
  expect "u32 mul uses Math.imul too", render(b2),
         "(x = (Math.imul(a, b) >>> 0));"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Assign:
      b3.symUse "x"
      b3.tree Mul:
        b3.width wF64
        b3.symUse "a"
        b3.symUse "b"
  expect "f64 mul is the plain product", render(b3), "(x = (a * b));"

block cvt_narrow_forms:
  # `Number(big)` rounds to the nearest double: the low bits the narrow must
  # keep are exactly what rounding past 2^53 discards. The narrow happens
  # inside BigInt, and only then becomes a Number.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.cvtNode(wI64, wI32):
        b.bigIntLit "9007199254740997"
  expect "big to i32 narrows inside BigInt", render(b),
         "(x = (Number(BigInt.asIntN(32, 9007199254740997n)) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.cvtNode(wI64, wU16):
        b2.bigIntLit "65541"
  expect "big to u16 narrows unsigned", render(b2),
         "(x = (Number(BigInt.asUintN(16, 65541n)) << 16 >>> 16));"

block neg_forms:
  # `-` spliced before a negative literal reads as a decrement of it, even
  # inside outer parens; the operand carries its own.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Neg:
        b.width wI32
        b.numLit -5
  expect "neg of a negative literal", render(b), "(x = ((-(-5)) | 0));"

block shift_forms:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Shl:
        b.width wI32
        b.numLit 1
        b.numLit 3
  expect "i32 shl", render(b), "(x = ((1 << 3) | 0));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Assign:
      b2.symUse "x"
      b2.tree Shr:
        b2.width wU32
        b2.symUse "v"
        b2.numLit 4
  expect "u32 shr is logical", render(b2), "(x = ((v >>> 4) >>> 0));"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Assign:
      b3.symUse "x"
      b3.tree Shr:
        b3.width wI64
        b3.symUse "v"
        b3.numLit 4
  expect "i64 shr widens the count", render(b3),
         "(x = BigInt.asIntN(64, (v >> (BigInt(4) & 63n))));"

block comparisons:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree Eq:
        b.width wI64
        b.symUse "a"
        b.symUse "b"
  expect "eq is loose by intent", render(b), "(x = (a == b));"

block heap_access:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "x"
      b.tree HLoad:
        b.width wI32
        b.numLit 16
  # Width 2+ goes through the DataView: a typed array at a fractional index
  # reads `undefined` and the store vanishes — silent wrong code, worse than
  # wasm's trap. The byte widths have no fractional index and stay direct.
  expect "i32 load uses the DataView", render(b), "(x = DV.getInt32(16, true));"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree HStore:
      b2.width wF64
      b2.numLit 24
      b2.floatLit 1.5
  expect "f64 store uses the DataView", render(b2), "(DV.setFloat64(24, 1.5, true));"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Assign:
      b3.symUse "x"
      b3.tree HLoad:
        b3.width wU8
        b3.symUse "p"
  expect "u8 load unscaled", render(b3), "(x = U8[p]);"

  var b4 = createTop()
  b4.tree ExprStmt:
    b4.tree Assign:
      b4.symUse "x"
      b4.tree HLoad:
        b4.width wI64
        b4.symUse "p"
  expect "i64 load uses the BigInt DataView", render(b4), "(x = DV.getBigInt64(p, true));"

# ── 2. composites and the bridge ────────────────────────────────────────────

block composites:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Call:
      b.symUse "f"
      b.tree Index:
        b.symUse "arr"
        b.numLit 2
      b.tree Cond:
        b.tree Not:
          b.width wI32
          b.symUse "c"
        b.tree Assign:
          b.symUse "a"
          b.tree Seq:
            b.symUse "p"
            b.numLit 1
        b.lit FalseLit
  expect "composites", render(b),
    "f(arr[2], ((!c) ? (a = (p, 1)) : false));"

block bridge:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "h"
      b.tree EWrap:
        b.ident "window"
  b.tree ExprStmt:
    b.tree Assign:
      b.symUse "s"
      b.tree EStrLit:
        b.strLit "hi"
  b.tree ExprStmt:
    b.tree EUnwrap:
      b.symUse "h"
  expect "bridge", render(b),
    "(h = ewrap(window));\n(s = ewrap(\"hi\"));\neunwrap(h);"

block machine_nodes:
  # The nodes wasm has an instruction for, and JS a preamble helper.
  var b = createTop()
  b.tree ExprStmt:
    b.tree MemCopy:
      b.symUse "d"
      b.symUse "s"
      b.numLit 8
  b.tree ExprStmt:
    b.tree MemFill:
      b.symUse "d"
      b.numLit 0
      b.numLit 8
  b.tree ExprStmt:
    b.tree ICall:
      b.tree Sig:
        b.width wI32
        b.width wI32
      b.symUse "slot"
      b.numLit 7
  b.tree ExprStmt:
    b.tree Ctz:
      b.width wU64
      b.symUse "v"
  b.tree ExprStmt:
    b.tree Cvt:
      b.width wF64
      b.width wI32
      b.symUse "f"
  b.lit Leave
  expect "machine nodes", render(b), """copyMem(d, s, 8);
fillMem(d, 0, 8);
FTAB[slot](7);
ctz64(v);
(ftoi(f, -2147483648, 2147483648) | 0);
leave();"""

block string_escapes:
  expect "escapes", escapeJsString("a\"b\\c\nd\tx\0e\u2028f héllo"),
    "\"a\\\"b\\\\c\\nd\\tx\\x00e\\u2028f héllo\""

block raw_splice:
  # The dom.nim shapes, pinned against Nim 2.2.4's jsgen. The symbols carry the
  # PIPELINE's mangling (`NAME.DISAMBIG.MODULESUFFIX`), not bare words: `$1`/`$#`
  # have to un-mangle to the Nim source name, and goldens written with bare
  # names would pass whether or not that un-mangling happens.
  var b = createTop()
  b.tree ExprStmt:
    b.tree Raw:
      b.symUse "insertAdjacentText.0.dom"
      b.strLit "#.$1(#, #)"
      b.symUse "self"
      b.strLit "afterend"
      b.symUse "el"
  expect "dom splice", render(b),
    "self.insertAdjacentText(\"afterend\", el);"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Raw:
      b2.symUse "jq.0.mod"
      b2.strLit "$$(#)"
      b2.strLit "sel"
  expect "escaped dollar", render(b2), "$(\"sel\");"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Raw:
      b3.symUse "after.0.mod"
      b3.strLit "#.$1(@)"
      b3.symUse "self"
      b3.symUse "a"
      b3.symUse "b"
  expect "varargs spread", render(b3), "self.after(a, b);"

  var b4 = createTop()
  b4.tree ExprStmt:
    b4.tree Raw:
      b4.symUse "focus.0.dom"
      b4.strLit "#.$#()"
      b4.symUse "el"
  expect "dollar-hash names the proc too", render(b4), "el.focus();"

  # Two refusals: a proc whose name cannot be a JS identifier, and a `$` form
  # Nim's `%` would not have resolved. Splicing either one emits text node
  # rejects at parse time with nothing pointing back at the pragma, which is
  # worse than a compiler error naming the template.
  var refused = 0
  for (sym, tpl) in [("+.0.mod", "#.$1(#)"), ("ok.0.mod", "($1 + $2)")]:
    try:
      var b5 = createTop()
      b5.tree ExprStmt:
        b5.tree Raw:
          b5.symUse sym
          b5.strLit tpl
          b5.symUse "a"
      discard render(b5)
    except AssertionDefect:
      inc refused
  if refused != 2:
    echo "FAIL bad extern templates are refused (", refused, " of 2 refused)"
    quit 1
  echo "ok bad extern templates refused"

# ── 3. statements ───────────────────────────────────────────────────────────

block statements:
  var b = createTop()
  b.tree Func:
    b.symDef "run"
    b.tree Params:
      b.param "a", wI32
      b.param "b", wI32
    b.width wI32
    b.tree Locals:
      b.param "t", wI32
      b.param "w", wI64
    b.tree If:
      b.tree Lt:
        b.width wI32
        b.symUse "a"
        b.symUse "b"
      b.tree Label:
        b.ident "done"
        b.tree Break:
          b.ident "done"
      b.tree Else:
        b.tree While:
          b.symUse "c"
          b.tree Return:
            b.symUse "a"
    b.tree Return:
      b.symUse "b"
  b.tree Block:
    b.tree ExprStmt:
      b.tree Assign:
        b.symUse "cb"
        b.tree Arrow:
            b.openTree Params
            b.symDef "ev"
            b.closeTag
            b.tree ExprStmt:
              b.tree Call:
                b.symUse "handle"
                b.symUse "ev"
  expect "statements", render(b), """function run(a, b) {
  let t = 0, w = 0n;
  if ((a < b)) {
    done: {
      break done;
    }
  } else {
    while (c) {
      return a;
    }
  }
  return b;
}
{
  (cb = (ev) => {
    handle(ev);
  });
}"""

# ── 4. engine-judged checks (skip when node is absent) ──────────────────────

let nodeExe = findExe("node")

proc runNode(js: string): tuple[output: string; exitCode: int] =
  ## `execCmdEx`'s line reader re-adds a trailing newline the child did not
  ## write, so callers compare stripped output: what matters is what the
  ## engine printed, not how the pipe was drained.
  let path = getTempDir() / "jorogumo_check_" & $getCurrentProcessId() & ".js"
  writeFile(path, js)
  defer: removeFile(path)
  execCmdEx(nodeExe & " " & quoteShell(path))

if nodeExe.len == 0:
  echo "skip engine checks: node not on PATH"
else:
  block engine_hello:
    var b = createTop()
    b.tree Func:
      b.symDef "main"
      b.params()
      b.addDotToken
      b.openTree Locals
      b.closeTag
      b.tree ExprStmt:
        b.tree Raw:
          b.symUse "write"
          b.strLit "process.stdout.write(eunwrap(#))"
          b.tree EStrLit:
            b.strLit "hello jorogumo\n"
    b.tree ExprStmt:
      b.tree Call:
        b.symUse "main"
    let r = runNode(jsPreamble(64 * 1024, 64 * 1024, 4096) & render(b))
    expect "engine hello", strip(r.output), "hello jorogumo"

  block engine_memory:
    # I32[0] = 21 * 2 (wrapped i32), print it — the heap, an operation and
    # the bridge in one program.
    var b = createTop()
    b.tree ExprStmt:
      b.tree HStore:
        b.width wI32
        b.numLit 0
        b.tree Mul:
          b.width wI32
          b.numLit 21
          b.numLit 2
    b.tree ExprStmt:
      b.tree Raw:
        b.symUse "write"
        b.strLit "process.stdout.write(String(I32[0]))"
    let r = runNode(jsPreamble(64 * 1024, 64 * 1024, 4096) & render(b))
    expect "engine memory", strip(r.output), "42"

echo "tjsrender: all checks passed"
