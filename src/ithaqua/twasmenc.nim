#
#           Ithaqua — WebAssembly code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Self-contained tests for `wasmenc`: LEB128 edge cases, a byte-exact golden
## module, node validation + instantiation of a richer module, and type dedup.
## Run: `nim c -r twasmenc.nim`.
##
## The encoding checks need nothing but this file. The two checks that make a
## wasm ENGINE the judge — does the module validate, and does running it produce
## 42 — need `node` on PATH; without it they are skipped and the skip is
## reported, so a run on a machine with no node is not silently thinner than it
## looks. CI installs node, and the tester turns its absence into a failure
## there (see `ithaquaTests`).

import std / [os, osproc, strutils, sequtils]
import wasmenc

proc uleb(x: uint32): seq[byte] =
  var b: ByteBuf
  b.addU32 x
  b.data

proc sleb(x: int64): seq[byte] =
  var b: ByteBuf
  b.addI64 x
  b.data

proc decodeSleb(bytes: openArray[byte]): int64 =
  ## Reference sleb128 decoder, used only to prove the encoder round-trips.
  var shift = 0
  var i = 0
  var cur: byte
  while true:
    cur = bytes[i]; inc i
    result = result or (int64(cur and 0x7F'u8) shl shift)
    shift += 7
    if (cur and 0x80'u8) == 0'u8: break
  if shift < 64 and (cur and 0x40'u8) != 0'u8:
    result = result or (not 0'i64 shl shift)

let nodeExe = findExe("node")
  ## "" when node is absent: the two engine-judged blocks then skip.
var skipped = 0

proc runNode(scriptSrc, wasmPath: string): tuple[output: string; exitCode: int] =
  ## Writes `scriptSrc` to a temp .js and runs `node script wasmPath`.
  let scriptPath = getTempDir() / "ithaqua_check_" & $getCurrentProcessId() & ".js"
  writeFile(scriptPath, scriptSrc)
  defer: removeFile(scriptPath)
  let cmd = "node " & quoteShell(scriptPath) & " " & quoteShell(wasmPath)
  execCmdEx(cmd)

# ── 1. LEB128 edge cases ────────────────────────────────────────────────────

block leb128:
  assert uleb(0'u32) == @[0x00'u8]
  assert uleb(127'u32) == @[0x7F'u8]
  assert uleb(128'u32) == @[0x80'u8, 0x01'u8]
  assert uleb(624485'u32) == @[0xE5'u8, 0x8E'u8, 0x26'u8]

  assert sleb(-1'i64) == @[0x7F'u8]
  assert sleb(63'i64) == @[0x3F'u8]
  assert sleb(64'i64) == @[0xC0'u8, 0x00'u8]
  assert sleb(-64'i64) == @[0x40'u8]
  assert sleb(-123456'i64) == @[0xC0'u8, 0xBB'u8, 0x78'u8]

  let lowBytes = sleb(low(int64))
  assert lowBytes.len == 10, "int64.low sleb should be 10 bytes, got " & $lowBytes.len
  assert decodeSleb(lowBytes) == low(int64)

# ── 2. golden module: (i32,i32)->i32, export "add2", body add ────────────────

block golden:
  var m: WasmModule
  let t = m.addFuncType([ValI32, ValI32], [ValI32])
  let f = m.addFunction(t)
  m.addExportFunc("add2", f)
  var body: ByteBuf
  body.add OpLocalGet
  body.addU32 0'u32
  body.add OpLocalGet
  body.addU32 1'u32
  body.add OpI32Add
  var noLocals: seq[(uint32, byte)] = @[]
  m.addCode(noLocals, body.data)

  let expected = @[
    0x00'u8, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x61, 0x64, 0x64, 0x32, 0x00, 0x00,
    0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B]
  let got = m.encode()
  if got != expected:
    echo "golden mismatch"
    echo "  expected: ", expected.mapIt(it.toHex(2)).join(" ")
    echo "  got:      ", got.mapIt(it.toHex(2)).join(" ")
    assert false

  # instantiate under node and check add2(20,22) == 42
  if nodeExe.len == 0:
    inc skipped
    break golden
  let wasmPath = getTempDir() / "ithaqua_add2_" & $getCurrentProcessId() & ".wasm"
  writeFile(wasmPath, got)
  defer: removeFile(wasmPath)
  const src = """
const fs = require("fs");
const b = fs.readFileSync(process.argv[2]);
if (!WebAssembly.validate(b)) { console.error("INVALID"); process.exit(1); }
const inst = new WebAssembly.Instance(new WebAssembly.Module(b));
const r = inst.exports.add2(20, 22);
if (r !== 42) { console.error("BAD result " + r); process.exit(1); }
console.log("OK " + r);
"""
  let (outp, exitCode) = runNode(src, wasmPath)
  assert exitCode == 0, "node add2 check failed (" & $exitCode & "): " & outp
  assert "OK 42" in outp, "unexpected node output: " & outp

# ── 3. richer module: memory + data + global + start + table + call_indirect ─

block richer:
  var m: WasmModule
  let vt = m.addFuncType([], [])                # () -> ()
  let funcA = m.addFunction(vt)                 # index 0 — call_indirect target
  let startFn = m.addFunction(vt)               # index 1 — the start function

  m.addMemory(1'u32)
  m.addData(8'i32, @[byte('h'), byte('i')])

  var ginit: ByteBuf
  ginit.add OpI32Const
  ginit.addI32 1024'i32
  discard m.addGlobal(ValI32, true, ginit.data)

  discard m.addTable(1'u32)
  m.addElem(0'i32, @[funcA])
  m.setStart(startFn)

  var noLocals: seq[(uint32, byte)] = @[]
  m.addCode(noLocals, @[])                      # funcA: empty body

  var startBody: ByteBuf                        # startFn: i32.const 0; call_indirect vt table0
  startBody.add OpI32Const
  startBody.addI32 0'i32
  startBody.add OpCallIndirect
  startBody.addU32 vt
  startBody.add 0x00'u8                         # table index 0
  m.addCode(noLocals, startBody.data)

  let bytes = m.encode()
  if nodeExe.len == 0:
    inc skipped
    break richer
  let wasmPath = getTempDir() / "ithaqua_rich_" & $getCurrentProcessId() & ".wasm"
  writeFile(wasmPath, bytes)
  defer: removeFile(wasmPath)
  const src = """
const fs = require("fs");
const b = fs.readFileSync(process.argv[2]);
if (!WebAssembly.validate(b)) { console.error("INVALID"); process.exit(1); }
new WebAssembly.Instance(new WebAssembly.Module(b));
console.log("VALID");
"""
  let (outp, exitCode) = runNode(src, wasmPath)
  assert exitCode == 0, "node richer check failed (" & $exitCode & "): " & outp
  assert "VALID" in outp, "unexpected node output: " & outp

# ── 4. type dedup ───────────────────────────────────────────────────────────

block dedup:
  var m: WasmModule
  let a = m.addFuncType([ValI32, ValI32], [ValI32])
  let b = m.addFuncType([ValI32, ValI32], [ValI32])   # identical → same index
  let c = m.addFuncType([ValI64], [ValI32])           # different → new index
  assert a == b, "identical signatures should dedup to the same index"
  assert c != a, "distinct signature must get a fresh index"
  assert a == 0'u32 and c == 1'u32

if skipped > 0:
  echo "twasmenc: all tests passed (", skipped,
       " engine-judged blocks SKIPPED - `node` is not on PATH)"
else:
  echo "twasmenc: all tests passed"
