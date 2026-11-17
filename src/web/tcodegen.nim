#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## Tests for the static layout and the data image (`codegen`): every global
## gets an address, a constant's fields land where the layout rules say, an
## address-valued field is a fixup resolved at layout time, and the whole image
## really is in linear memory — checked by a JS ENGINE reading it back through
## the pointer, not by inspecting the emitted text.
##
## Run: `nim c -r tcodegen.nim`. Without `node` the engine check is skipped and
## the skip is reported.

import std / [os, osproc, strutils, tables]
import nifcore, nifcoreparse
import "../arkham/core" / lengdecl
import webnif, codegen, jsrender

proc check(label: string; cond: bool; detail = "") =
  if not cond:
    echo "FAIL ", label
    if detail.len > 0: echo "  ", detail
    quit 1
  echo "ok ", label

proc must(label: string; cond: bool; detail = "") =
  ## An invariant of the test's own helpers: silent unless it breaks, so the
  ## report lists what is being asserted about the layout, not bookkeeping.
  if not cond:
    echo "FAIL (helper) ", label
    if detail.len > 0: echo "  ", detail
    quit 1

proc expect(label: string; got, want: string) =
  check label, got == want, "got: " & got & "  want: " & want

proc findAddr(g: WebGen; part: string): uint32 =
  ## The address of the one global whose name contains `part` — the names in
  ## the fixture carry a trailing `.` that the NIF API completes to the module
  ## suffix, so matching on the whole name would be guessing at that.
  result = 0
  for sym, a in g.globalAddr:
    let name = poolSym(g.lengPool, sym)   # the layout is keyed by POOL ID; the
    if name.contains(part):               # spelling is what a test matches on
      must "unique " & part, result == 0, "both " & name & " and the previous match"
      result = a

proc segAt(g: WebGen; a: uint32): string =
  ## The image bytes that land at `address` `a`.
  result = ""
  for (at, s) in g.dataSegs:
    if at == a:
      must "one segment per address", result.len == 0
      result = s

proc u32at(s: string; off: int): uint32 =
  must "u32 in range", off + 4 <= s.len, "segment of " & $s.len & " bytes, offset " & $off
  uint32(uint8(s[off])) or (uint32(uint8(s[off + 1])) shl 8) or
    (uint32(uint8(s[off + 2])) shl 16) or (uint32(uint8(s[off + 3])) shl 24)

proc fixturePath: string =
  for dir in ["", getCurrentDir() / "fixtures", getAppDir() / "fixtures",
              getAppDir() / "../fixtures", getAppDir() / "../src/web/fixtures"]:
    let p = dir / "tdata1.c.nif"
    if fileExists(p): return p
  quit "tcodegen: fixtures/tdata1.c.nif not found"

let tags = createLengTagPool()   # NOT the web IR pool: a buffer is Leng-tagged or JS-tagged, never both
let path = fixturePath()
var buf = parseFromFile(path, sharedTags = tags)
var g = createWebGen(buf, path, tags)
layoutProgram(g)

check "layout starts above the null guard", g.memTop > NullGuard, $g.memTop
let
  strA = findAddr(g, "HELLO")
  wordsA = findAddr(g, "words")
  ptrsA = findAddr(g, "ptrs")
  guardA = findAddr(g, "guard")
  wideA = findAddr(g, "wide")
  msgA = findAddr(g, "msg")
check "globals are distinct",
  strA != wordsA and strA != ptrsA and guardA != wideA and msgA != strA

# the object constant: fields at their layout offsets, the flexarray tail
# carrying the payload inline (a tail is not a pointer).
let strSeg = segAt(g, strA)
check "const image is fixed part + payload", strSeg.len == 8 + 15, $strSeg.len
expect "fullLen at offset 0", $u32at(strSeg, 0), "14"
check "rc is zero (not initialized)", u32at(strSeg, 4) == 0
expect "flexarray tail at offset 8", strSeg[8 .. 22], "hello jorogumo\0"

# an array constant: elements at the element stride.
let wordsSeg = segAt(g, wordsA)
check "3 i32 elements", wordsSeg.len == 12, $wordsSeg.len
expect "array elements", $u32at(wordsSeg, 0) & "," & $u32at(wordsSeg, 4) & "," &
  $u32at(wordsSeg, 8), "7,8,9"

# fixups: a proc symbol becomes its function-table slot, a nil slot stays 0.
let ptrsSeg = segAt(g, ptrsA)
check "2 pointer slots", ptrsSeg.len == 8, $ptrsSeg.len
check "proc symbol → function-table slot", u32at(ptrsSeg, 0) >= 1, $u32at(ptrsSeg, 0)
check "nil slot is zero", u32at(ptrsSeg, 4) == 0

# a `(addr g)` initializer resolves to the global's own address — the fixup
# this module exists to resolve.
let msgSeg = segAt(g, msgA)
check "addr fixup is one word", msgSeg.len == 4, $msgSeg.len
expect "addr fixup points at the const", $u32at(msgSeg, 0), $strA

# zero-initialized globals reserve space only: no bytes to store.
check "zero-init gvar has no segment", segAt(g, guardA).len == 0
check "but it does have an address", guardA >= NullGuard

# a 64-bit initializer is not truncated by the little-endian writer.
let wideSeg = segAt(g, wideA)
check "i64 image is 8 bytes", wideSeg.len == 8, $wideSeg.len
var wide = 0'u64
for i in 0 ..< 8: wide = wide or (uint64(uint8(wideSeg[i])) shl (8 * i))
expect "i64 initializer", $wide, "4294967296"

# the emitted image is self-describing: one loader call per segment.
let image = dataInitJs(WebModule(dataSegs: g.dataSegs, memTop: g.memTop))
check "one loader call per segment",
  image.count('\n') == g.dataSegs.len, $g.dataSegs.len

# ── the engine is the judge: read the image back through the pointer ────────

let nodeExe = findExe("node")
if nodeExe.len == 0:
  echo "skip engine check: node not on PATH"
else:
  let probe = """
function rd(at) { let s = ""; for (;;) { const c = U8[at]; if (c === 0) break; s += String.fromCharCode(c); ++at; } return s; }
console.log(U32[$1 / 4]);
console.log(rd($1 + 8));
console.log(String(U32[$2 / 4] === $1));
console.log(String(BU64[$3 / 8]));
console.log([U32[$4 / 4], U32[$4 / 4 + 1], U32[$4 / 4 + 2]].join(","));
console.log([U32[$5 / 4], U32[$5 / 4 + 1]].join(","));
console.log(U8[$6]);
""".replace("$1", $strA).replace("$2", $msgA).replace("$3", $wideA)
   .replace("$4", $wordsA).replace("$5", $ptrsA).replace("$6", $guardA)
  let jsPath = getTempDir() / "jorogumo_layout_" & $getCurrentProcessId() & ".js"
  writeFile(jsPath, jsPreamble(64 * 1024, 64 * 1024, 4096) & image & probe)
  defer: removeFile(jsPath)
  let r = execCmdEx(nodeExe & " " & quoteShell(jsPath))
  expect "engine reads the image back", strip(r.output),
    "14\nhello jorogumo\ntrue\n4294967296\n7,8,9\n1,0\n0"

# Each fixture is a program run under node, so the engine is the judge:
# generate, render, run, compare. An older fixture exits with the sum of the
# checks it passes; a newer one prints one counter or value per line (an
# `importjs` `console.log` splice) and exits 0, so no two failures can add up
# to the expected code. What each fixture checks:
#
# * tsplice: the frame plan and the lowering walk the same tree. An `importjs`
#   splice reserves no sret temporary; a reservation nobody took shifted every
#   later temporary (a 12-byte constructor met an 8-byte slot). It splices a
#   string, builds a pair of strings, calls a splice through `onerr` (which
#   reaches it like a `call`, string argument and all) and passes a constructor
#   to a call: 3 + 3 + (5 + 7 + 11). The fixture stubs the runtime's string
#   bridge entry points, which a string splice calls.
# * tgrowstore: a store whose value is a call that grows linear memory must land
#   in the NEW buffer, not the one JS read `DV` from before the call (5), and a
#   load through a pointer such a call returns must read the new buffer (7),
#   and so must a store through such a pointer (20). A lost store leaves the
#   global 0; a stale load reads the 0 the old buffer still holds.
#
# The string fixtures below stub the runtime's entry points
# (`nimStrBeginStore`, `nimStrEndStore`, `nimStrBridgeDestroy`,
# `nimStrBridgeCstr`, `nimStrBridgeData`, `nimStrBridgeLen`) over a string
# layout of their own, `(len, data)`, which is not the runtime's: the bridge
# must build and read a string through them alone. `begin` heads each buffer
# with a magic word and the address of the string it was built for, and
# `destroy` counts as good only a string `begin` built at that very address and
# not yet destroyed; anything else is a bad destroy.
#
# * tstrbridge: a string an `importjs` proc returns is an ordinary owned Nim
#   string, built in a frame temporary of the caller and read back through
#   `data`/`len` when it is a splice argument: 10 chars, 3, empty, and three
#   two-byte UTF-8 chars (6 bytes); two live results of one expression do not
#   share a slot (10 * 100 + 13); every begin has its end (6 and 6).
# * toomstr: the runtime's `nimStrBeginStore` returns nil when the allocation
#   failed and leaves the string as its OOM marker (here `len` -1). The bridge
#   must then write no bytes (word 0 stays as it was) and not call `end`.
# * tcbargs: a callback taking a `string` and a `cstring`, fired three times.
#   It reads both right (1 + 2 each call, 9). The wrapper builds both as Nim
#   strings in its frame (6 begins, 6 ends), passes the cstring through
#   `nimStrBridgeCstr` (3) and destroys each string at its own address after
#   the call (6 good destroys, 0 bad).
# * tcbstring: a callback that returns a `string`, an aggregate, so the Nim
#   proc takes its result slot as a hidden first parameter; fired with a
#   parameter and with none, each as a named proc and as a stored proc value.
#   The host sees "alphabet" twice and "zero" twice. Each result is built by
#   the callee and moved into the wrapper's result slot, so this fixture's
#   `destroy` checks the buffer, not the address it was built at, and empties
#   the string: a result destroyed before its conversion would print empty.
#   6 begins and ends (2 arguments, 4 results), 6 good destroys, 0 bad.
# * tnull: JS `null` and `undefined` are the empty string (a string splice
#   returning either: length 0 twice) and the nil cstring (a cstring splice
#   returning either: nil twice), not the text "null". A callback fired with
#   (null, undefined) gets the nil cstring and the empty string; the wrapper
#   still destroys both slots (2 good destroys, 0 bad).
# * tcallback: fires a named proc and a stored fn-ptr with `null`, `undefined`,
#   an object, a function and a number: the first two must arrive as nil (+1
#   each), the object and the function as handles (+2 each), the number
#   untouched (+16). A JS function handed to a callback that returns it comes
#   back as the same function (+32).
type FixtureRun = object
  file, label: string
  exitCode: int
  output: string    ## the expected output, when the fixture prints its checks

const fixtureRuns = [
  FixtureRun(file: "tsplice", exitCode: 29,
             label: "splice then constructors: the plan matches the lowering"),
  FixtureRun(file: "tgrowstore", exitCode: 32,
             label: "a load or store whose operand grows memory uses the live buffer"),
  FixtureRun(file: "tstrbridge", exitCode: 0,
             output: "0123456789\nabc\n0\nαβγ\n6\n1013\n6\n6",
             label: "bridged strings are built and read through the runtime's entry points"),
  FixtureRun(file: "toomstr", exitCode: 0, output: "-1\n0\n0",
             label: "a failed string allocation: no write through nil, no end"),
  FixtureRun(file: "tcbargs", exitCode: 0, output: "9\n6\n6\n3\n6\n0",
             label: "callback string and cstring arguments: owned by the wrapper, freed"),
  FixtureRun(file: "tcbstring", exitCode: 0,
             output: "alphabet\nalphabet\nzero\nzero\n6\n6\n6\n0",
             label: "string-result callbacks: the result slot first, destroyed after conversion"),
  FixtureRun(file: "tnull", exitCode: 0, output: "0\n0\n1\n1\n1\n0\n2\n0",
             label: "JS null into Nim: the empty string, the nil cstring"),
  FixtureRun(file: "tcallback", exitCode: 54,
             label: "handle callback arguments: null, undefined, object, function, number")]

proc runFixture(dir, name, nodeExe: string): (string, int) =
  ## Generate `name`.c.nif in `dir`, render it as JS and run it under node.
  let fixture = dir / name & ".c.nif"
  var fbuf = parseFromFile(fixture, sharedTags = tags)
  var fmod = default(WebModule)
  var ftree = generate(fbuf, fixture, tags, wtJs, fmod)
  let js = getTempDir() / "jorogumo_" & name & "_" & $getCurrentProcessId() & ".js"
  writeFile(js, renderJs(ftree, fmod, 64 * 1024 * 1024, 64 * 1024))
  defer: removeFile(js)
  execCmdEx(nodeExe & " " & quoteShell(js))

if nodeExe.len > 0:
  for r in fixtureRuns:
    let (output, code) = runFixture(path.parentDir, r.file, nodeExe)
    # The exit codes above are the POSIX status, the low 8 bits of what the
    # program passed to `exit`; node on Windows reports all 32 bits, so compare
    # the part every host reports.
    check r.label, (code and 0xFF) == r.exitCode and
      (r.output.len == 0 or strip(output) == r.output),
      "exit " & $code & "\n" & output

echo "tcodegen: all checks passed"
