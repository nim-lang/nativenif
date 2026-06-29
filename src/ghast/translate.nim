#       ghast — Leng IR -> SPIR-V translation
# (c) Copyright 2026 Andreas Rumpf
#
# See the file "license.txt", included in this distribution.

## Lowers Leng IR (a `.c.nif` module, the same IR `lengc` consumes for C) into
## SPIR-V, structured like `lengc`'s codegen: a top-level walk dispatches on
## `stmtKind`; each `proc` becomes a SPIR-V function; statements and expressions
## recurse by `stmtKind`/`exprKind`. The Leng IR is decoded by *enum* via the
## nifcore Leng model (`nifcdecl`) — never by tag-name strings.
##
## SPIR-V is SSA with logical addressing, so this is a real (if small) backend:
## scalar `int`/`uint`/`bool` types map to `OpTypeInt`/`OpTypeBool`; locals are
## `OpVariable` in `Function` storage with `OpLoad`/`OpStore`; parameters are SSA
## values (`OpFunctionParameter`); `+`/`-`/`*` map to `OpIAdd`/`OpISub`/`OpIMul`.
## A module-global type/constant section is emitted before all functions (SPIR-V
## requires it); ids are deduplicated within a function.
##
## The supported subset is deliberately narrow. Any construct outside it (calls,
## control flow, aggregates, …) raises `TranslateError`, which `translateModule`
## catches *per proc* — that proc is skipped (its partial output discarded) and
## translation continues. So `ghast` runs on a whole real module and emits SPIR-V
## for the procs it can, rather than only a hand-built fixed module.

import std / [assertions, tables, sets, algorithm, sequtils, strutils]
import "." / spirv
import nifcore, nifcdecl

type
  TranslateError* = object of CatchableError

  SymClass = enum
    scParamValue   ## an SSA value (OpFunctionParameter / loaded builtin)
    scLocalPtr     ## an OpVariable pointer — needs OpLoad / OpStore
    scBuffer       ## a StorageBuffer variable — indexed via OpAccessChain

  SymInfo = object
    id: string         ## the SPIR-V id (dotted, e.g. `i.0`)
    cls: SymClass
    typeId: string     ## value (pointee/element) type id
    ptrId: string      ## for scBuffer: the StorageBuffer pointer-to-element type

  Module = object
    ## Global, committed output, assembled in SPIR-V's mandated section order:
    ## capabilities, memory model, entry points, execution modes, decorations
    ## (annotations), the type/constant/global section, then the functions.
    ## `pool`/`tags` are shared by every buffer (the per-proc ones too) so a
    ## commit splice is a fast same-pool copy and the SPIR-V tag ids resolve.
    entryPoints, execModes, decorations, types, funcs: TokenBuf
    pool: Pool
    tags: TagPool
    caps: HashSet[string]
    counter: int       ## SSA ids are module-global; this keeps temps unique

  ProcGen = object
    ## Per-proc working state. On success its buffers are appended to the
    ## `Module`; on `TranslateError` they are dropped, so a half-translated proc
    ## leaves no trace.
    entryPoints, execModes, decorations, types, funcs: TokenBuf
    typeIds, constIds: Table[string, string]   ## dedup key -> id
    syms: Table[string, SymInfo]
    caps: HashSet[string]

proc err(msg: string) {.noreturn.} =
  raise newException(TranslateError, msg)

proc base(id: string): string =
  ## An id without its NIF module suffix — `int64.0` -> `int64` — for building
  ## derived id names (which `resultId`/`idRef` then take verbatim).
  result = id
  for i in 0 ..< id.len:
    if id[i] == '.':
      result = id[0 ..< i]
      break

proc freshId(m: var Module; prefix: string): string =
  inc m.counter
  result = prefix & $m.counter & idSuffix

# ── types & constants (emitted into the per-proc `types` buffer) ────────────

proc scalarWidth(t: Cursor): int =
  ## The bit width of an `(i N)` / `(u N)` / `(f N)` scalar type.
  var c = t
  c.into:
    if c.kind == IntLit: result = int(intVal(c))
    else: err("scalar type without a width")
    inc c
    while c.hasMore: skip c   # any trailing attributes (importc/header/…)

proc intType(pg: var ProcGen; width: int; signed: bool): string =
  let key = (if signed: "i" else: "u") & $width
  if key in pg.typeIds: return pg.typeIds[key]
  let id = (if signed: "int" else: "uint") & $width & idSuffix
  pg.typeIds[key] = id
  case width
  of 8: pg.caps.incl "Int8"
  of 16: pg.caps.incl "Int16"
  of 64: pg.caps.incl "Int64"
  else: discard
  pg.types.instr OpTypeInt:
    pg.types.resultId id
    pg.types.litOp width
    pg.types.litOp (if signed: 1 else: 0)
  result = id

proc boolType(pg: var ProcGen): string =
  if "bool" in pg.typeIds: return pg.typeIds["bool"]
  let id = "bool" & idSuffix
  pg.typeIds["bool"] = id
  pg.types.instr OpTypeBool:
    pg.types.resultId id
  result = id

proc voidType(pg: var ProcGen): string =
  if "void" in pg.typeIds: return pg.typeIds["void"]
  let id = "void" & idSuffix
  pg.typeIds["void"] = id
  pg.types.instr OpTypeVoid:
    pg.types.resultId id
  result = id

proc valueType(pg: var ProcGen; t: Cursor): string =
  ## SPIR-V type id for a Leng value type. Unsupported types abort the proc.
  case t.typeKind
  of IT: result = intType(pg, scalarWidth(t), signed = true)
  of UT: result = intType(pg, scalarWidth(t), signed = false)
  of BoolT: result = boolType(pg)
  else: err("unsupported type")

proc ptrType(pg: var ProcGen; sc: StorageClass; elem: string): string =
  let key = "ptr:" & $sc & ":" & elem
  if key in pg.typeIds: return pg.typeIds[key]
  let id = "ptr_" & $sc & "_" & base(elem) & idSuffix
  pg.typeIds[key] = id
  pg.types.instr OpTypePointer:
    pg.types.resultId id
    pg.types.enumOp sc
    pg.types.idRef elem
  result = id

proc vecType(pg: var ProcGen; elem: string; n: int): string =
  let key = "vec:" & elem & ":" & $n
  if key in pg.typeIds: return pg.typeIds[key]
  let id = "v" & $n & base(elem) & idSuffix
  pg.typeIds[key] = id
  pg.types.instr OpTypeVector:
    pg.types.resultId id
    pg.types.idRef elem
    pg.types.litOp n
  result = id

proc funcType(pg: var ProcGen; m: var Module; ret: string; params: seq[string]): string =
  let key = "fn:" & ret & ":" & params.join(",")
  if key in pg.typeIds: return pg.typeIds[key]
  let id = "fnty" & $m.counter & idSuffix
  inc m.counter
  pg.typeIds[key] = id
  pg.types.instr OpTypeFunction:
    pg.types.resultId id
    pg.types.idRef ret
    for p in params: pg.types.idRef p
  result = id

proc constInt(pg: var ProcGen; typeId: string; v: int64): string =
  let key = "c:" & typeId & ":" & $v
  if key in pg.constIds: return pg.constIds[key]
  let id = base(typeId) & "_" & (if v < 0: "n" & $(-v) else: $v) & idSuffix
  pg.constIds[key] = id
  pg.types.instr OpConstant:
    pg.types.resultId id
    pg.types.idRef typeId
    pg.types.litOp v
  result = id

# ── expressions ─────────────────────────────────────────────────────────────

proc genExpr(m: var Module; pg: var ProcGen; n: Cursor; expected: string): string

proc bufElemAddr(m: var Module; pg: var ProcGen; buf: SymInfo; idxId: string): string =
  ## `OpAccessChain` to `buf[idx]`: into the StorageBuffer's `(struct (rtarray))`
  ## at member 0 (the runtime array), then element `idx`.
  let u32 = intType(pg, 32, false)
  let zero = constInt(pg, u32, 0)
  result = freshId(m, "ac")
  pg.funcs.instr OpAccessChain:
    pg.funcs.resultId result
    pg.funcs.idRef buf.ptrId
    pg.funcs.idRef buf.id
    pg.funcs.idRef zero
    pg.funcs.idRef idxId

proc genBinop(m: var Module; pg: var ProcGen; n: Cursor; op: SpirvOp): string =
  ## `(add/sub/mul <type> a b)` -> an `OpIAdd`/`OpISub`/`OpIMul` value.
  var c = n
  var resType = ""
  var a = ""
  var b = ""
  c.into:
    resType = valueType(pg, c); skip c
    a = genExpr(m, pg, c, resType); skip c
    b = genExpr(m, pg, c, resType); skip c
    if c.hasMore: err("n-ary arithmetic not supported")
  let id = freshId(m, "t")
  pg.funcs.instr op:
    pg.funcs.resultId id
    pg.funcs.idRef resType
    pg.funcs.idRef a
    pg.funcs.idRef b
  result = id

proc genExpr(m: var Module; pg: var ProcGen; n: Cursor; expected: string): string =
  ## Translate an expression to the id of its SSA result value.
  if n.kind == Symbol:
    let name = symName(n)
    if name notin pg.syms: err("unknown symbol: " & name)
    let s = pg.syms[name]
    case s.cls
    of scParamValue:
      result = s.id
    of scLocalPtr:
      let id = freshId(m, "t")
      pg.funcs.instr OpLoad:
        pg.funcs.resultId id
        pg.funcs.idRef s.typeId
        pg.funcs.idRef s.id
      result = id
    of scBuffer:
      err("buffer '" & name & "' used as a scalar value")
  elif n.kind == IntLit:
    if expected.len == 0: err("integer literal without a type context")
    result = constInt(pg, expected, intVal(n))
  elif n.kind == TagLit:
    case n.exprKind
    of AddC: result = genBinop(m, pg, n, OpIAdd)
    of SubC: result = genBinop(m, pg, n, OpISub)
    of MulC: result = genBinop(m, pg, n, OpIMul)
    of ConvC:
      # `(conv <targetType> <expr>)`. v1 treats a conversion as identity (the
      # only conversions in a kernel are same-width index/int casts); a real
      # width change (OpSConvert/OpUConvert) is a later refinement.
      var c = n
      var val = ""
      c.into:
        skip c                                   # target type
        val = genExpr(m, pg, c, expected); skip c
      result = val
    of SufC:
      # `(suf <intlit> "i32")` — a literal carrying a type suffix.
      var c = n
      var v = 0'i64
      c.into:
        if c.kind == IntLit: v = intVal(c)
        skip c
        while c.hasMore: skip c                  # the suffix string
      if expected.len == 0: err("suffixed literal without a type context")
      result = constInt(pg, expected, v)
    of PatC, AtC:
      # `buf[idx]` read -> OpAccessChain + OpLoad.
      var c = n
      var bufName = ""
      var idxId = ""
      c.into:
        bufName = symName(c); skip c
        idxId = genExpr(m, pg, c, ""); skip c
        while c.hasMore: skip c                  # bound / extra (array `at`) operands
      if bufName notin pg.syms or pg.syms[bufName].cls != scBuffer:
        err("indexing a non-buffer")
      let buf = pg.syms[bufName]
      let address = bufElemAddr(m, pg, buf, idxId)
      let id = freshId(m, "t")
      pg.funcs.instr OpLoad:
        pg.funcs.resultId id
        pg.funcs.idRef buf.typeId
        pg.funcs.idRef address
      result = id
    else: err("unsupported expression")
  else:
    err("unsupported operand")

# ── statements ──────────────────────────────────────────────────────────────

proc genStmt(m: var Module; pg: var ProcGen; n: Cursor) =
  case n.stmtKind
  of StmtsS:
    var c = n
    loopInto c:
      genStmt(m, pg, c)
      skip c
  of VarS:
    # The OpVariable was already declared (pre-scan); handle an initialiser.
    var c = n
    let v = takeVarDecl(c)
    if v.value.kind != DotToken:
      let name = symName(v.name)
      if name notin pg.syms: err("local not pre-declared (nested var?)")
      let s = pg.syms[name]
      let val = genExpr(m, pg, v.value, s.typeId)
      pg.funcs.instr OpStore:
        pg.funcs.idRef s.id
        pg.funcs.idRef val
  of AsgnS:
    var c = n
    c.into:
      if c.kind == TagLit and (c.exprKind == PatC or c.exprKind == AtC):
        # `buf[idx] = rhs` -> OpAccessChain + OpStore.
        var lhs = c
        var bufName = ""
        var idxId = ""
        lhs.into:
          bufName = symName(lhs); skip lhs
          idxId = genExpr(m, pg, lhs, ""); skip lhs
          while lhs.hasMore: skip lhs
        skip c
        if bufName notin pg.syms or pg.syms[bufName].cls != scBuffer:
          err("assigning to a non-buffer index")
        let buf = pg.syms[bufName]
        let val = genExpr(m, pg, c, buf.typeId)
        skip c
        let address = bufElemAddr(m, pg, buf, idxId)
        pg.funcs.instr OpStore:
          pg.funcs.idRef address
          pg.funcs.idRef val
      elif c.kind == Symbol:
        let name = symName(c)
        if name notin pg.syms: err("assignment to unknown symbol")
        let s = pg.syms[name]
        if s.cls != scLocalPtr: err("assignment to a non-variable")
        skip c
        let val = genExpr(m, pg, c, s.typeId)
        skip c
        pg.funcs.instr OpStore:
          pg.funcs.idRef s.id
          pg.funcs.idRef val
      else:
        err("assignment to an unsupported target")
  of RetS:
    var c = n
    c.into:
      if c.kind == DotToken:
        pg.funcs.instr OpReturn: discard
      else:
        let val = genExpr(m, pg, c, "")
        pg.funcs.instr OpReturnValue:
          pg.funcs.idRef val
      skip c
  else:
    err("unsupported statement")

# ── procs ───────────────────────────────────────────────────────────────────

proc declareLocals(m: var Module; pg: var ProcGen; body: Cursor) =
  ## Pre-scan the (flat) body for `var` decls and emit their `OpVariable`s into
  ## the entry block (SPIR-V requires function-local variables there). Nested
  ## decls would come from control flow, which is unsupported and raises first.
  if body.stmtKind != StmtsS: return
  var c = body
  loopInto c:
    if c.stmtKind == VarS:
      var vc = c
      let v = takeVarDecl(vc)
      let typeId = valueType(pg, v.typ)
      let ptrId = ptrType(pg, scFunction, typeId)
      let name = symName(v.name)
      pg.syms[name] = SymInfo(id: name, cls: scLocalPtr, typeId: typeId)
      pg.funcs.instr OpVariable:
        pg.funcs.resultId name
        pg.funcs.idRef ptrId
        pg.funcs.enumOp scFunction
    skip c

proc newProcGen(pool: Pool; tags: TagPool): ProcGen =
  ProcGen(entryPoints: createTokenBuf(8, pool, tags),
          execModes: createTokenBuf(8, pool, tags),
          decorations: createTokenBuf(16, pool, tags),
          types: createTokenBuf(32, pool, tags),
          funcs: createTokenBuf(32, pool, tags),
          typeIds: initTable[string, string](),
          constIds: initTable[string, string](),
          syms: initTable[string, SymInfo](),
          caps: initHashSet[string]())

proc appendAll(dest: var TokenBuf; src: var TokenBuf) =
  var c = src.beginRead()
  while c.hasMore:
    addSubtree(dest, c); skip c

proc commit(m: var Module; pg: var ProcGen) =
  ## Splice a completed proc's sections into the module (per SPIR-V order).
  appendAll(m.entryPoints, pg.entryPoints)
  appendAll(m.execModes, pg.execModes)
  appendAll(m.decorations, pg.decorations)
  appendAll(m.types, pg.types)
  appendAll(m.funcs, pg.funcs)
  for cap in pg.caps: m.caps.incl cap

proc translateProc(m: var Module; procCursor: Cursor) =
  ## Translate one `(proc …)` into a SPIR-V function, committing to `m` only on
  ## success. Pre-builds all output in a `ProcGen` so a `TranslateError` mid-way
  ## leaves the module untouched.
  var pg = newProcGen(m.pool, m.tags)
  var n = procCursor
  let p = takeProcDecl(n)

  let fnName = symName(p.name)
  let retId =
    if p.returnType.kind == DotToken or p.returnType.typeKind == VoidT:
      voidType(pg)
    else:
      valueType(pg, p.returnType)

  var paramTypes: seq[string] = @[]
  var paramOrder: seq[tuple[id, typeId: string]] = @[]
  if p.params.typeKind == ParamsT:
    var pc = p.params
    loopInto pc:
      let pd = takeParamDecl(pc)
      let typeId = valueType(pg, pd.typ)
      let name = symName(pd.name)
      pg.syms[name] = SymInfo(id: name, cls: scParamValue, typeId: typeId)
      paramTypes.add typeId
      paramOrder.add (name, typeId)
  elif p.params.kind != DotToken:
    err("unsupported parameter list")

  let fnTypeId = funcType(pg, m, retId, paramTypes)

  pg.funcs.instr OpFunction:
    pg.funcs.resultId fnName
    pg.funcs.idRef retId
    pg.funcs.enumOp fcNone
    pg.funcs.idRef fnTypeId
  for prm in paramOrder:
    pg.funcs.instr OpFunctionParameter:
      pg.funcs.resultId prm.id
      pg.funcs.idRef prm.typeId
  let entry = freshId(m, "entry")
  pg.funcs.instr OpLabel:
    pg.funcs.resultId entry

  declareLocals(m, pg, p.body)
  genStmt(m, pg, p.body)

  pg.funcs.instr OpFunctionEnd:
    discard

  commit(m, pg)

# ── compute kernels ─────────────────────────────────────────────────────────

proc isKernel(procCursor: Cursor): bool =
  ## A compute kernel = a void-returning proc with at least one pointer param
  ## (a buffer). Such a proc becomes an `OpEntryPoint GLCompute`; everything
  ## else becomes an ordinary SPIR-V function.
  var n = procCursor
  let p = takeProcDecl(n)
  if not (p.returnType.kind == DotToken or p.returnType.typeKind == VoidT):
    return false
  result = false
  if p.params.typeKind == ParamsT:
    var pc = p.params
    loopInto pc:
      let pd = takeParamDecl(pc)
      if pd.typ.typeKind == PtrT: result = true

proc translateKernel(m: var Module; procCursor: Cursor) =
  ## Lower a `for i in a||b` device kernel `proc k(i; buf…)` to an
  ## `OpEntryPoint GLCompute`: the index param is bound to `gl_GlobalInvocationId.x`
  ## and each pointer param to a `StorageBuffer` (descriptor set 0, binding N),
  ## then the body is emitted inline into `main`.
  var pg = newProcGen(m.pool, m.tags)
  var n = procCursor
  let p = takeProcDecl(n)
  let mainId = symName(p.name)

  let u32 = intType(pg, 32, false)
  let voidId = voidType(pg)
  let fnty = funcType(pg, m, voidId, @[])
  let vec3u = vecType(pg, u32, 3)
  let ptrInVec3 = ptrType(pg, scInput, vec3u)
  let ptrInU32 = ptrType(pg, scInput, u32)
  let zero = constInt(pg, u32, 0)

  # The GlobalInvocationId builtin input variable.
  let gid = "gid" & idSuffix
  pg.types.instr OpVariable:
    pg.types.resultId gid
    pg.types.idRef ptrInVec3
    pg.types.enumOp scInput
  pg.decorations.instr OpDecorate:
    pg.decorations.idRef gid
    pg.decorations.enumOp decBuiltIn
    pg.decorations.enumOp biGlobalInvocationId

  # Classify params: the first scalar is the grid index, each pointer a buffer.
  var indexParam = ""
  var indexType = ""
  var binding = 0
  if p.params.typeKind == ParamsT:
    var pc = p.params
    loopInto pc:
      let pd = takeParamDecl(pc)
      let pname = symName(pd.name)
      if pd.typ.typeKind == PtrT:
        let elem = valueType(pg, elementType(pd.typ))
        let rta = freshId(m, "rta")
        pg.types.instr OpTypeRuntimeArray:
          pg.types.resultId rta
          pg.types.idRef elem
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef rta
          pg.decorations.enumOp decArrayStride
          pg.decorations.litOp 4
        let st = freshId(m, "buf")
        pg.types.instr OpTypeStruct:
          pg.types.resultId st
          pg.types.idRef rta
        pg.decorations.instr OpMemberDecorate:
          pg.decorations.idRef st
          pg.decorations.litOp 0
          pg.decorations.enumOp decOffset
          pg.decorations.litOp 0
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef st
          pg.decorations.enumOp decBlock
        let sbPtr = ptrType(pg, scStorageBuffer, st)
        let varId = base(pname) & idSuffix
        pg.types.instr OpVariable:
          pg.types.resultId varId
          pg.types.idRef sbPtr
          pg.types.enumOp scStorageBuffer
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef varId
          pg.decorations.enumOp decDescriptorSet
          pg.decorations.litOp 0
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef varId
          pg.decorations.enumOp decBinding
          pg.decorations.litOp binding
        inc binding
        let elemPtr = ptrType(pg, scStorageBuffer, elem)
        pg.syms[pname] = SymInfo(id: varId, cls: scBuffer, typeId: elem, ptrId: elemPtr)
      else:
        if indexParam.len > 0: err("kernel: more than one scalar parameter")
        indexParam = pname
        indexType = intType(pg, 32, true)   # index used as a 32-bit int

  if indexParam.len == 0: err("kernel: no grid-index parameter")

  pg.entryPoints.instr OpEntryPoint:
    pg.entryPoints.enumOp exeGLCompute
    pg.entryPoints.idRef mainId
    pg.entryPoints.strOp "main"
    pg.entryPoints.idRef gid                 # SPIR-V 1.3 interface = Input/Output vars
  pg.execModes.instr OpExecutionMode:
    pg.execModes.idRef mainId
    pg.execModes.enumOp modeLocalSize
    pg.execModes.litOp 1
    pg.execModes.litOp 1
    pg.execModes.litOp 1

  pg.funcs.instr OpFunction:
    pg.funcs.resultId mainId
    pg.funcs.idRef voidId
    pg.funcs.enumOp fcNone
    pg.funcs.idRef fnty
  let entry = freshId(m, "entry")
  pg.funcs.instr OpLabel:
    pg.funcs.resultId entry

  # i = int32(gl_GlobalInvocationID.x)
  let gidPtr = freshId(m, "gidp")
  pg.funcs.instr OpAccessChain:
    pg.funcs.resultId gidPtr
    pg.funcs.idRef ptrInU32
    pg.funcs.idRef gid
    pg.funcs.idRef zero
  let gidx = freshId(m, "gidx")
  pg.funcs.instr OpLoad:
    pg.funcs.resultId gidx
    pg.funcs.idRef u32
    pg.funcs.idRef gidPtr
  let idx = freshId(m, "idx")
  pg.funcs.instr OpBitcast:                  # uint32 -> int32 (same width)
    pg.funcs.resultId idx
    pg.funcs.idRef indexType
    pg.funcs.idRef gidx
  pg.syms[indexParam] = SymInfo(id: idx, cls: scParamValue, typeId: indexType)

  genStmt(m, pg, p.body)

  pg.funcs.instr OpReturn:
    discard
  pg.funcs.instr OpFunctionEnd:
    discard

  commit(m, pg)

# ── module ──────────────────────────────────────────────────────────────────

proc translateModule*(input: var TokenBuf): TokenBuf =
  ## Walk a Leng module's top-level statements, translate each `proc`, and
  ## assemble the final SPIR-V module (capabilities, memory model, the shared
  ## type/constant section, then the functions).
  let tags = createTags[SpirvOp]()
  let pool = newPool()
  var m = Module(entryPoints: createTokenBuf(8, pool, tags),
                 execModes: createTokenBuf(8, pool, tags),
                 decorations: createTokenBuf(16, pool, tags),
                 types: createTokenBuf(64, pool, tags),
                 funcs: createTokenBuf(64, pool, tags),
                 pool: pool, tags: tags,
                 caps: initHashSet[string](), counter: 0)
  var c = input.beginRead()
  if c.stmtKind == StmtsS:
    loopInto c:
      if c.stmtKind == ProcS:
        try:
          if isKernel(c): translateKernel(m, c)
          else: translateProc(m, c)
        except TranslateError:
          discard   # unsupported proc — skip, keep going
      skip c

  result = createTokenBuf(64, pool, tags)
  beginModule result
  result.instr OpCapability:
    result.enumOp capShader
  for cap in sorted(toSeq(m.caps)):
    result.instr OpCapability:
      result.identOp cap
  result.instr OpMemoryModel:
    result.enumOp addrLogical
    result.enumOp memGLSL450
  appendAll(result, m.entryPoints)
  appendAll(result, m.execModes)
  appendAll(result, m.decorations)
  appendAll(result, m.types)
  appendAll(result, m.funcs)
  endModule result
