#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## Self-contained tests for `jsnif` + `jsenc`: the tag-pool alignment, the
## width-driven operation forms, every statement shape, the `importjs`
## template splice, and two checks that make a JS ENGINE the judge — a
## generated program that prints `hello jorogumo` through the bridge and one
## that computes 42 through the linear memory. Run: `nim c -r tjsenc.nim`.
## Without `node` on PATH the engine blocks are skipped and the skip is
## reported, so a run on a machine with no node is not silently thinner than
## it looks.

import std / [os, osproc, strutils]
import nifcore
import jsnif, jsenc

let tags = createJsTagPool()  # asserts TagId == ord(JsTag)+1 while registering

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
  b.tree Let:
    b.symDef "x"
    b.tree Add:
      b.width wI32
      b.numLit 2
      b.numLit 3
  expect "i32 add wraps", render(b), "let x = ((2 + 3) | 0);"

  var b2 = createTop()
  b2.tree Let:
    b2.symDef "x"
    b2.tree Add:
      b2.width wU8
      b2.numLit 2
      b2.numLit 3
  expect "u8 add wraps", render(b2), "let x = ((2 + 3) << 24 >>> 24);"

block big_add:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree Add:
      b.width wI64
      b.bigIntLit "1"
      b.bigIntLit "2"
  expect "i64 add is BigInt and wraps", render(b),
         "let x = BigInt.asIntN(64, (1n + 2n));"

block div_forms:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree Div:
      b.width wI32
      b.numLit 7
      b.numLit 2
  expect "i32 div truncates", render(b), "let x = (Math.trunc(7 / 2) | 0);"

  var b2 = createTop()
  b2.tree Let:
    b2.symDef "x"
    b2.tree Div:
      b2.width wI64
      b2.bigIntLit "10"
      b2.bigIntLit "3"
  expect "i64 div truncates natively", render(b2), "let x = (10n / 3n);"

block shift_forms:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree Shl:
      b.width wI32
      b.numLit 1
      b.numLit 3
  expect "i32 shl", render(b), "let x = ((1 << 3) | 0);"

  var b2 = createTop()
  b2.tree Let:
    b2.symDef "x"
    b2.tree Shr:
      b2.width wU32
      b2.symUse "v"
      b2.numLit 4
  expect "u32 shr is logical", render(b2), "let x = ((v >>> 4) >>> 0);"

  var b3 = createTop()
  b3.tree Let:
    b3.symDef "x"
    b3.tree Shr:
      b3.width wI64
      b3.symUse "v"
      b3.numLit 4
  expect "i64 shr widens the count", render(b3),
         "let x = BigInt.asIntN(64, (v >> BigInt(4)));"

block comparisons:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree Eq:
      b.width wI64
      b.symUse "a"
      b.symUse "b"
  expect "eq is loose by intent", render(b), "let x = (a == b);"

block heap_access:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree HLoad:
      b.width wI32
      b.numLit 16
  expect "i32 load scales", render(b), "let x = I32[(16) / 4];"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree HStore:
      b2.width wF64
      b2.numLit 24
      b2.floatLit 1.5
  expect "f64 store scales", render(b2), "(F64[(24) / 8] = 1.5);"

  var b3 = createTop()
  b3.tree Let:
    b3.symDef "x"
    b3.tree HLoad:
      b3.width wU8
      b3.symUse "p"
  expect "u8 load unscaled", render(b3), "let x = U8[p];"

# ── 2. composites and the bridge ────────────────────────────────────────────

block composites:
  var b = createTop()
  b.tree Let:
    b.symDef "x"
    b.tree Call:
      b.symUse "f"
      b.tree Prop:
        b.symUse "o"
        b.strLit "m"
      b.tree Index:
        b.symUse "arr"
        b.numLit 2
      b.tree Cond:
        b.tree Not:
          b.width wI32
          b.symUse "c"
        b.tree Assign:
          b.symUse "a"
          b.tree New:
            b.ident "Error"
            b.strLit "boom"
        b.lit NullLit
  expect "composites", render(b),
    "let x = f(o.m, arr[2], ((!c) ? (a = (new Error(\"boom\"))) : null));"

block bridge:
  var b = createTop()
  b.tree Let:
    b.symDef "h"
    b.tree EWrap:
      b.ident "window"
  b.tree Let:
    b.symDef "s"
    b.tree EStrLit:
      b.strLit "hi"
  b.tree ExprStmt:
    b.tree EUnwrap:
      b.symUse "h"
  expect "bridge", render(b),
    "let h = ewrap(window);\nlet s = ewrap(\"hi\");\neunwrap(h);"

block string_escapes:
  expect "escapes", escapeJsString("a\"b\\c\nd\tx\0e\u2028f héllo"),
    "\"a\\\"b\\\\c\\nd\\tx\\x00e\\u2028f héllo\""

block raw_splice:
  # the dom.nim shapes, pinned against Nim 2.2.4's jsgen:
  var b = createTop()
  b.tree ExprStmt:
    b.tree Raw:
      b.symUse "insertAdjacentText"
      b.strLit "#.$1(#, #)"
      b.symUse "self"
      b.strLit "afterend"
      b.symUse "el"
  expect "dom splice", render(b),
    "self.insertAdjacentText(\"afterend\", el);"

  var b2 = createTop()
  b2.tree ExprStmt:
    b2.tree Raw:
      b2.symUse "jq"
      b2.strLit "$$(#)"
      b2.strLit "sel"
  expect "escaped dollar", render(b2), "$(\"sel\");"

  var b3 = createTop()
  b3.tree ExprStmt:
    b3.tree Raw:
      b3.symUse "after"
      b3.strLit "#.$1(@)"
      b3.symUse "self"
      b3.symUse "a"
      b3.symUse "b"
  expect "varargs spread", render(b3), "self.after(a, b);"

# ── 3. statements ───────────────────────────────────────────────────────────

block statements:
  var b = createTop()
  b.tree Func:
    b.symDef "run"
    b.openTree Params
    b.symDef "a"
    b.symDef "b"
    b.closeTag
    b.tree If:
      b.tree Lt:
        b.width wI32
        b.symUse "a"
        b.symUse "b"
      b.tree Label:
        b.symDef "done"
        b.tree Break:
          b.symUse "done"
      b.tree Else:
        b.tree While:
          b.symUse "c"
          b.tree Return:
            b.symUse "a"
    b.tree Try:
      b.tree Throw:
        b.tree New:
          b.ident "Error"
          b.strLit "x"
      b.tree Except:
        b.symDef "e"
        b.tree ExprStmt:
          b.tree Call:
            b.ident "console.log"
            b.symUse "e"
      b.tree Finally:
        b.tree ExprStmt:
          b.symUse "cleanup"
    b.tree Return:
      b.symUse "b"
  b.tree Block:
    b.tree Let:
      b.symDef "cb"
      b.tree Arrow:
          b.openTree Params
          b.symDef "ev"
          b.closeTag
          b.tree ExprStmt:
            b.tree Call:
              b.symUse "handle"
              b.symUse "ev"
  b.tree Let:
    b.symDef "nothing"
    b.addDotToken
  expect "statements", render(b), """function run(a, b) {
  if ((a < b)) {
    done: {
      break done;
    }
  } else {
    while (c) {
      return a;
    }
  }
  try {
    throw (new Error("x"));
  } catch (e) {
    console.log(e);
  } finally {
    cleanup;
  }
  return b;
}
{
  let cb = (ev) => {
    handle(ev);
  };
}
let nothing;"""

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

echo "tjsenc: all checks passed"
