#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## Tests for the static layout and the data image (`codegen_js`): every global
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
import codegen_js, jsenc

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

proc findAddr(g: JsGen; part: string): uint32 =
  ## The address of the one global whose name contains `part` — the names in
  ## the fixture carry a trailing `.` that the NIF API completes to the module
  ## suffix, so matching on the whole name would be guessing at that.
  result = 0
  for name, a in g.globalAddr:
    if name.contains(part):
      must "unique " & part, result == 0, "both " & name & " and the previous match"
      result = a

proc segAt(g: JsGen; a: uint32): string =
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
              getAppDir() / "../fixtures", getAppDir() / "../src/jorogumo/fixtures"]:
    let p = dir / "tdata1.c.nif"
    if fileExists(p): return p
  quit "tcodegen: fixtures/tdata1.c.nif not found"

let tags = createLengTagPool()   # NOT the jsnif pool: a buffer is Leng-tagged or JS-tagged, never both
let path = fixturePath()
var buf = parseFromFile(path, sharedTags = tags)
var g = createJsGen(buf, path, tags)
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
let image = dataInitJs(g)
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

echo "tcodegen: all checks passed"
