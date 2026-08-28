#
#           Ithaqua — WebAssembly code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Binary module encoder for wasm 1.0 (MVP) plus the sign-extension ops.
##
## This is the byte-emitting foundation ithaqua's codegen layer drives to
## assemble a whole-program `wasm32` module from Leng IR. It owns three layers:
## a `ByteBuf` with LEB128/IEEE primitives, the value-type and opcode constants
## from the wasm spec, and a `WasmModule` section assembler whose `encode`
## serializes sections in spec order (empty sections skipped).

import std / [tables]

# ── low-level byte buffer ───────────────────────────────────────────────────

type
  ByteBuf* = object
    data*: seq[byte]

proc add*(b: var ByteBuf; x: byte) =
  b.data.add x

proc add*(b: var ByteBuf; bytes: openArray[byte]) =
  for x in bytes: b.data.add x

proc addU32*(b: var ByteBuf; x: uint32) =
  ## Unsigned LEB128.
  var v = x
  while true:
    let lo = byte(v and 0x7F'u32)
    v = v shr 7
    if v == 0'u32:
      b.add lo
      break
    else:
      b.add (lo or 0x80'u8)

proc addI64*(b: var ByteBuf; value: int64) =
  ## Signed LEB128 (sleb128); terminates on the sign-bit rule so it is width
  ## independent — `addI32` funnels through here.
  var v = value
  while true:
    let lo = byte(v and 0x7F'i64)
    v = ashr(v, 7)
    let signSet = (lo and 0x40'u8) != 0'u8
    if (v == 0'i64 and not signSet) or (v == -1'i64 and signSet):
      b.add lo
      break
    else:
      b.add (lo or 0x80'u8)

proc addI32*(b: var ByteBuf; value: int32) =
  b.addI64 int64(value)

proc addF32*(b: var ByteBuf; x: float32) =
  ## Little-endian IEEE-754 single.
  let bits = cast[uint32](x)
  b.add byte(bits and 0xFF'u32)
  b.add byte((bits shr 8) and 0xFF'u32)
  b.add byte((bits shr 16) and 0xFF'u32)
  b.add byte((bits shr 24) and 0xFF'u32)

proc addF64*(b: var ByteBuf; x: float64) =
  ## Little-endian IEEE-754 double.
  let bits = cast[uint64](x)
  b.add byte(bits and 0xFF'u64)
  b.add byte((bits shr 8) and 0xFF'u64)
  b.add byte((bits shr 16) and 0xFF'u64)
  b.add byte((bits shr 24) and 0xFF'u64)
  b.add byte((bits shr 32) and 0xFF'u64)
  b.add byte((bits shr 40) and 0xFF'u64)
  b.add byte((bits shr 48) and 0xFF'u64)
  b.add byte((bits shr 56) and 0xFF'u64)

proc addName*(b: var ByteBuf; s: string) =
  ## A wasm `name`: LEB length prefix followed by the raw UTF-8 bytes.
  b.addU32 uint32(s.len)
  for ch in s: b.add byte(ch)

proc addBytesWithLen*(b: var ByteBuf; bytes: openArray[byte]) =
  ## LEB length prefix followed by the raw bytes (a `vec(byte)`).
  b.addU32 uint32(bytes.len)
  b.add bytes

# ── value types ─────────────────────────────────────────────────────────────

const
  ValI32* = 0x7F'u8
  ValI64* = 0x7E'u8
  ValF32* = 0x7D'u8
  ValF64* = 0x7C'u8
  ValFuncref* = 0x70'u8
  BlockVoid* = 0x40'u8

# ── opcodes ─────────────────────────────────────────────────────────────────

const
  # control
  OpUnreachable* = 0x00'u8
  OpNop* = 0x01'u8
  OpBlock* = 0x02'u8
  OpLoop* = 0x03'u8
  OpIf* = 0x04'u8
  OpElse* = 0x05'u8
  OpEnd* = 0x0B'u8
  OpBr* = 0x0C'u8
  OpBrIf* = 0x0D'u8
  OpBrTable* = 0x0E'u8
  OpReturn* = 0x0F'u8
  OpCall* = 0x10'u8
  OpCallIndirect* = 0x11'u8

  # parametric
  OpDrop* = 0x1A'u8
  OpSelect* = 0x1B'u8

  # variable
  OpLocalGet* = 0x20'u8
  OpLocalSet* = 0x21'u8
  OpLocalTee* = 0x22'u8
  OpGlobalGet* = 0x23'u8
  OpGlobalSet* = 0x24'u8

  # memory loads/stores
  OpI32Load* = 0x28'u8
  OpI64Load* = 0x29'u8
  OpF32Load* = 0x2A'u8
  OpF64Load* = 0x2B'u8
  OpI32Load8S* = 0x2C'u8
  OpI32Load8U* = 0x2D'u8
  OpI32Load16S* = 0x2E'u8
  OpI32Load16U* = 0x2F'u8
  OpI64Load8S* = 0x30'u8
  OpI64Load8U* = 0x31'u8
  OpI64Load16S* = 0x32'u8
  OpI64Load16U* = 0x33'u8
  OpI64Load32S* = 0x34'u8
  OpI64Load32U* = 0x35'u8
  OpI32Store* = 0x36'u8
  OpI64Store* = 0x37'u8
  OpF32Store* = 0x38'u8
  OpF64Store* = 0x39'u8
  OpI32Store8* = 0x3A'u8
  OpI32Store16* = 0x3B'u8
  OpI64Store8* = 0x3C'u8
  OpI64Store16* = 0x3D'u8
  OpI64Store32* = 0x3E'u8
  OpMemorySize* = 0x3F'u8
  OpMemoryGrow* = 0x40'u8

  # consts
  OpI32Const* = 0x41'u8
  OpI64Const* = 0x42'u8
  OpF32Const* = 0x43'u8
  OpF64Const* = 0x44'u8

  # i32 comparisons
  OpI32Eqz* = 0x45'u8
  OpI32Eq* = 0x46'u8
  OpI32Ne* = 0x47'u8
  OpI32LtS* = 0x48'u8
  OpI32LtU* = 0x49'u8
  OpI32GtS* = 0x4A'u8
  OpI32GtU* = 0x4B'u8
  OpI32LeS* = 0x4C'u8
  OpI32LeU* = 0x4D'u8
  OpI32GeS* = 0x4E'u8
  OpI32GeU* = 0x4F'u8

  # i64 comparisons
  OpI64Eqz* = 0x50'u8
  OpI64Eq* = 0x51'u8
  OpI64Ne* = 0x52'u8
  OpI64LtS* = 0x53'u8
  OpI64LtU* = 0x54'u8
  OpI64GtS* = 0x55'u8
  OpI64GtU* = 0x56'u8
  OpI64LeS* = 0x57'u8
  OpI64LeU* = 0x58'u8
  OpI64GeS* = 0x59'u8
  OpI64GeU* = 0x5A'u8

  # f32 comparisons
  OpF32Eq* = 0x5B'u8
  OpF32Ne* = 0x5C'u8
  OpF32Lt* = 0x5D'u8
  OpF32Gt* = 0x5E'u8
  OpF32Le* = 0x5F'u8
  OpF32Ge* = 0x60'u8

  # f64 comparisons
  OpF64Eq* = 0x61'u8
  OpF64Ne* = 0x62'u8
  OpF64Lt* = 0x63'u8
  OpF64Gt* = 0x64'u8
  OpF64Le* = 0x65'u8
  OpF64Ge* = 0x66'u8

  # i32 arithmetic
  OpI32Clz* = 0x67'u8
  OpI32Ctz* = 0x68'u8
  OpI32Popcnt* = 0x69'u8
  OpI32Add* = 0x6A'u8
  OpI32Sub* = 0x6B'u8
  OpI32Mul* = 0x6C'u8
  OpI32DivS* = 0x6D'u8
  OpI32DivU* = 0x6E'u8
  OpI32RemS* = 0x6F'u8
  OpI32RemU* = 0x70'u8
  OpI32And* = 0x71'u8
  OpI32Or* = 0x72'u8
  OpI32Xor* = 0x73'u8
  OpI32Shl* = 0x74'u8
  OpI32ShrS* = 0x75'u8
  OpI32ShrU* = 0x76'u8
  OpI32Rotl* = 0x77'u8
  OpI32Rotr* = 0x78'u8

  # i64 arithmetic
  OpI64Clz* = 0x79'u8
  OpI64Ctz* = 0x7A'u8
  OpI64Popcnt* = 0x7B'u8
  OpI64Add* = 0x7C'u8
  OpI64Sub* = 0x7D'u8
  OpI64Mul* = 0x7E'u8
  OpI64DivS* = 0x7F'u8
  OpI64DivU* = 0x80'u8
  OpI64RemS* = 0x81'u8
  OpI64RemU* = 0x82'u8
  OpI64And* = 0x83'u8
  OpI64Or* = 0x84'u8
  OpI64Xor* = 0x85'u8
  OpI64Shl* = 0x86'u8
  OpI64ShrS* = 0x87'u8
  OpI64ShrU* = 0x88'u8
  OpI64Rotl* = 0x89'u8
  OpI64Rotr* = 0x8A'u8

  # f32 ops
  OpF32Abs* = 0x8B'u8
  OpF32Neg* = 0x8C'u8
  OpF32Ceil* = 0x8D'u8
  OpF32Floor* = 0x8E'u8
  OpF32Trunc* = 0x8F'u8
  OpF32Nearest* = 0x90'u8
  OpF32Sqrt* = 0x91'u8
  OpF32Add* = 0x92'u8
  OpF32Sub* = 0x93'u8
  OpF32Mul* = 0x94'u8
  OpF32Div* = 0x95'u8
  OpF32Min* = 0x96'u8
  OpF32Max* = 0x97'u8
  OpF32Copysign* = 0x98'u8

  # f64 ops
  OpF64Abs* = 0x99'u8
  OpF64Neg* = 0x9A'u8
  OpF64Ceil* = 0x9B'u8
  OpF64Floor* = 0x9C'u8
  OpF64Trunc* = 0x9D'u8
  OpF64Nearest* = 0x9E'u8
  OpF64Sqrt* = 0x9F'u8
  OpF64Add* = 0xA0'u8
  OpF64Sub* = 0xA1'u8
  OpF64Mul* = 0xA2'u8
  OpF64Div* = 0xA3'u8
  OpF64Min* = 0xA4'u8
  OpF64Max* = 0xA5'u8
  OpF64Copysign* = 0xA6'u8

  # conversions
  OpI32WrapI64* = 0xA7'u8
  OpI32TruncF32S* = 0xA8'u8
  OpI32TruncF32U* = 0xA9'u8
  OpI32TruncF64S* = 0xAA'u8
  OpI32TruncF64U* = 0xAB'u8
  OpI64ExtendI32S* = 0xAC'u8
  OpI64ExtendI32U* = 0xAD'u8
  OpI64TruncF32S* = 0xAE'u8
  OpI64TruncF32U* = 0xAF'u8
  OpI64TruncF64S* = 0xB0'u8
  OpI64TruncF64U* = 0xB1'u8
  OpF32ConvertI32S* = 0xB2'u8
  OpF32ConvertI32U* = 0xB3'u8
  OpF32ConvertI64S* = 0xB4'u8
  OpF32ConvertI64U* = 0xB5'u8
  OpF32DemoteF64* = 0xB6'u8
  OpF64ConvertI32S* = 0xB7'u8
  OpF64ConvertI32U* = 0xB8'u8
  OpF64ConvertI64S* = 0xB9'u8
  OpF64ConvertI64U* = 0xBA'u8
  OpF64PromoteF32* = 0xBB'u8
  OpI32ReinterpretF32* = 0xBC'u8
  OpI64ReinterpretF64* = 0xBD'u8
  OpF32ReinterpretI32* = 0xBE'u8
  OpF64ReinterpretI64* = 0xBF'u8

  # sign extension
  OpI32Extend8S* = 0xC0'u8
  OpI32Extend16S* = 0xC1'u8
  OpI64Extend8S* = 0xC2'u8
  OpI64Extend16S* = 0xC3'u8
  OpI64Extend32S* = 0xC4'u8

# ── export/import kind tags ─────────────────────────────────────────────────

const
  KindFunc = 0x00'u8
  KindTable = 0x01'u8
  KindMemory = 0x02'u8
  KindGlobal = 0x03'u8

# ── module assembler ────────────────────────────────────────────────────────

type
  WasmModule* = object
    typeSec: ByteBuf
    typeCount: uint32
    typeDedup: Table[string, uint32]
    importSec: ByteBuf
    importCount: uint32
    funcSec: ByteBuf          ## the "function" section: type index per defined func
    funcSecCount: uint32
    tableSec: ByteBuf
    tableCount: uint32
    memSec: ByteBuf
    memCount: uint32
    globalSec: ByteBuf
    globalCount: uint32
    exportSec: ByteBuf
    exportCount: uint32
    elemSec: ByteBuf
    elemCount: uint32
    codeSec: ByteBuf
    codeCount: uint32
    dataSec: ByteBuf
    dataCount: uint32
    numImportFuncs: uint32    ## function index space: imports occupy [0, numImportFuncs)
    numLocalFuncs: uint32
    hasStart: bool
    startFunc: uint32

proc sigKey(params, results: openArray[byte]): string =
  ## A dedup key for a functype; `@params`/`@results` stringify unambiguously.
  result = $(@params) & "->" & $(@results)

proc addFuncType*(m: var WasmModule; params, results: openArray[byte]): uint32 =
  ## Interns a `(params) -> (results)` signature, returning its type index.
  ## Identical signatures are deduplicated.
  let key = sigKey(params, results)
  let existing = m.typeDedup.getOrDefault(key, high(uint32))
  if existing != high(uint32):
    return existing
  m.typeSec.add 0x60'u8
  m.typeSec.addU32 uint32(params.len)
  m.typeSec.add params
  m.typeSec.addU32 uint32(results.len)
  m.typeSec.add results
  result = m.typeCount
  m.typeDedup[key] = result
  inc m.typeCount

proc addImportFunc*(m: var WasmModule; module, name: string; typeIdx: uint32): uint32 =
  ## Imports a function; returns its function index. Function imports occupy the
  ## low end of the function index space, ahead of any defined function.
  m.importSec.addName module
  m.importSec.addName name
  m.importSec.add KindFunc
  m.importSec.addU32 typeIdx
  inc m.importCount
  result = m.numImportFuncs
  inc m.numImportFuncs

proc addFunction*(m: var WasmModule; typeIdx: uint32): uint32 =
  ## Declares a defined function of the given type; returns its function index
  ## (imports counted first). Pair each with an `addCode` in the same order.
  m.funcSec.addU32 typeIdx
  inc m.funcSecCount
  result = m.numImportFuncs + m.numLocalFuncs
  inc m.numLocalFuncs

proc addMemory*(m: var WasmModule; minPages: uint32; maxPages = 0'u32; hasMax = false) =
  ## Adds a linear memory. Only memory 0 exists in the MVP.
  if hasMax:
    m.memSec.add 0x01'u8
    m.memSec.addU32 minPages
    m.memSec.addU32 maxPages
  else:
    m.memSec.add 0x00'u8
    m.memSec.addU32 minPages
  inc m.memCount

proc addGlobal*(m: var WasmModule; valType: byte; mutable: bool; initExpr: openArray[byte]): uint32 =
  ## Adds a global. `initExpr` is the const init expression WITHOUT its trailing
  ## `end` (appended here). Returns the global index.
  m.globalSec.add valType
  m.globalSec.add (if mutable: 0x01'u8 else: 0x00'u8)
  m.globalSec.add initExpr
  m.globalSec.add OpEnd
  result = m.globalCount
  inc m.globalCount

proc addTable*(m: var WasmModule; minEntries: uint32): uint32 =
  ## Adds a funcref table with no maximum; returns the table index.
  m.tableSec.add ValFuncref
  m.tableSec.add 0x00'u8
  m.tableSec.addU32 minEntries
  result = m.tableCount
  inc m.tableCount

proc addExportFunc*(m: var WasmModule; name: string; funcIdx: uint32) =
  m.exportSec.addName name
  m.exportSec.add KindFunc
  m.exportSec.addU32 funcIdx
  inc m.exportCount

proc addExportMemory*(m: var WasmModule; name: string; memIdx: uint32) =
  m.exportSec.addName name
  m.exportSec.add KindMemory
  m.exportSec.addU32 memIdx
  inc m.exportCount

proc addExportGlobal*(m: var WasmModule; name: string; globalIdx: uint32) =
  m.exportSec.addName name
  m.exportSec.add KindGlobal
  m.exportSec.addU32 globalIdx
  inc m.exportCount

proc addExportTable*(m: var WasmModule; name: string; tableIdx: uint32) =
  m.exportSec.addName name
  m.exportSec.add KindTable
  m.exportSec.addU32 tableIdx
  inc m.exportCount

proc setStart*(m: var WasmModule; funcIdx: uint32) =
  m.hasStart = true
  m.startFunc = funcIdx

proc addCode*(m: var WasmModule; localDecls: openArray[(uint32, byte)]; body: openArray[byte]) =
  ## Adds one function body. `localDecls` are run-length `(count, valtype)`
  ## pairs. `body` is the instruction stream WITHOUT its trailing `end`, which
  ## is appended here. Add these in the same order as the matching `addFunction`.
  var fn: ByteBuf
  fn.addU32 uint32(localDecls.len)
  for (count, valType) in localDecls:
    fn.addU32 count
    fn.add valType
  fn.add body
  fn.add OpEnd
  m.codeSec.addU32 uint32(fn.data.len)
  m.codeSec.add fn.data
  inc m.codeCount

proc addData*(m: var WasmModule; offset: int32; bytes: openArray[byte]) =
  ## Adds an active data segment for memory 0 at an `i32.const offset`.
  m.dataSec.add 0x00'u8              # active, memory 0
  m.dataSec.add OpI32Const
  m.dataSec.addI32 offset
  m.dataSec.add OpEnd
  m.dataSec.addBytesWithLen bytes
  inc m.dataCount

proc addElem*(m: var WasmModule; tableOffset: int32; funcIdxs: openArray[uint32]) =
  ## Adds an active element segment for table 0 at an `i32.const offset`.
  m.elemSec.add 0x00'u8             # active, table 0, funcref
  m.elemSec.add OpI32Const
  m.elemSec.addI32 tableOffset
  m.elemSec.add OpEnd
  m.elemSec.addU32 uint32(funcIdxs.len)
  for fi in funcIdxs: m.elemSec.addU32 fi
  inc m.elemCount

proc emitSection(dst: var seq[byte]; id: byte; count: uint32; entries: ByteBuf) =
  ## Emits one count-prefixed vector section, skipping it when empty.
  if count == 0'u32: return
  var content: ByteBuf
  content.addU32 count
  content.add entries.data
  var sz: ByteBuf
  sz.addU32 uint32(content.data.len)
  dst.add id
  for x in sz.data: dst.add x
  for x in content.data: dst.add x

proc encode*(m: WasmModule): seq[byte] =
  ## Serializes the module: magic, version, then sections in spec order with
  ## empty sections skipped.
  result = @[0x00'u8, 0x61'u8, 0x73'u8, 0x6D'u8,   # \0asm
             0x01'u8, 0x00'u8, 0x00'u8, 0x00'u8]   # version 1
  emitSection result, 1'u8, m.typeCount, m.typeSec
  emitSection result, 2'u8, m.importCount, m.importSec
  emitSection result, 3'u8, m.funcSecCount, m.funcSec
  emitSection result, 4'u8, m.tableCount, m.tableSec
  emitSection result, 5'u8, m.memCount, m.memSec
  emitSection result, 6'u8, m.globalCount, m.globalSec
  emitSection result, 7'u8, m.exportCount, m.exportSec
  if m.hasStart:
    var content: ByteBuf
    content.addU32 m.startFunc
    var sz: ByteBuf
    sz.addU32 uint32(content.data.len)
    result.add 0x08'u8
    for x in sz.data: result.add x
    for x in content.data: result.add x
  emitSection result, 9'u8, m.elemCount, m.elemSec
  emitSection result, 10'u8, m.codeCount, m.codeSec
  emitSection result, 11'u8, m.dataCount, m.dataSec
