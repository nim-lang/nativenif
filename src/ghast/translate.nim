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
## control flow, aggregates, …) is a hard failure: `err` `quit`s on the first
## unsupported construct, so ghast never silently emits a quietly-incomplete
## module — an unsupported construct aborts the whole run, not just its proc.
##
## SPIR-V ids are `nifcore` `SymId`s (interned once in the shared pool), never
## passed around as strings — the type/constant helpers return the `SymId` they
## mint, and `genExpr` yields its result through a `Location` (see arkham).

import std / [assertions, tables, sets, algorithm, sequtils, strutils]
import "." / spirv
import nifcore, nifcdecl

type
  SymClass = enum
    scParamValue   ## an SSA value (OpFunctionParameter / loaded builtin)
    scLocalPtr     ## an OpVariable pointer — needs OpLoad / OpStore
    scBuffer       ## a StorageBuffer variable — indexed via OpAccessChain

  SymInfo = object
    id: SymId          ## the SPIR-V id (dotted, e.g. `i.0`)
    cls: SymClass
    typeId: SymId      ## value (pointee/element) type id
    ptrId: SymId       ## for scBuffer: the StorageBuffer pointer-to-element type

  Location = object
    ## Where an expression's result lives — for now just the SPIR-V id of the
    ## SSA value `genExpr` produced. Mirrors arkham's `Location`; kept as an
    ## object so it can grow (constant-folded immediates, storage classes, …).
    s: SymId

  Module = object
    ## Global, committed output, assembled in SPIR-V's mandated section order:
    ## capabilities, memory model, entry points, execution modes, decorations
    ## (annotations), the type/constant/global section, then the functions.
    ## `pool`/`tags` are shared by every buffer (the per-proc ones too) so a
    ## commit splice is a fast same-pool copy and the SPIR-V tag ids resolve.
    entryPoints, execModes, decorations, types, funcs: TokenBuf
    pool: Pool
    tags: TagPool
    caps: HashSet[SpirvOp]
    counter: int       ## SSA ids are module-global; this keeps temps unique

  ProcGen = object
    ## Per-proc working state, assembled in its own buffers and appended to the
    ## `Module` on success (SPIR-V's section order is applied at that point).
    ## `pool` is the module's shared literals pool — the one every id is interned
    ## into, so a `SymId` minted here is valid in every buffer.
    entryPoints, execModes, decorations, types, funcs: TokenBuf
    typeIds, constIds: Table[string, SymId]   ## dedup key -> id
    syms: Table[string, SymInfo]
    caps: HashSet[SpirvOp]
    pool: Pool

proc err(msg: string) {.noreturn.} =
  quit "ghast: " & msg

proc base(id: string): string =
  ## An id name without its NIF module suffix — `int64.0` -> `int64` — for
  ## building derived, human-readable id names.
  result = id
  for i in 0 ..< id.len:
    if id[i] == '.':
      result = id[0 ..< i]
      break

proc mint(pg: var ProcGen; name: string): SymId =
  ## Intern an id name into the shared pool, yielding its `SymId`.
  pg.pool.syms.getOrIncl(name)

proc stem(pg: ProcGen; id: SymId): string =
  ## The readable stem of an already-minted id — its pooled name minus the NIF
  ## module suffix (`int64.0` -> `int64`), used to name ids derived from it.
  base(poolSym(pg.pool, id))

proc freshId(m: var Module; prefix: string): SymId =
  inc m.counter
  result = m.pool.syms.getOrIncl(prefix & $m.counter & idSuffix)

# ── types & constants (emitted into the per-proc `types` buffer) ────────────

proc scalarWidth(t: Cursor): int =
  ## The bit width of an `(i N)` / `(u N)` / `(f N)` scalar type.
  var c = t
  c.into:
    if c.kind == IntLit: result = int(intVal(c))
    else: err("scalar type without a width")
    inc c
    while c.hasMore: skip c   # any trailing attributes (importc/header/…)

proc intType(pg: var ProcGen; width: int; signed: bool): SymId =
  let key = (if signed: "i" else: "u") & $width
  if key in pg.typeIds: return pg.typeIds[key]
  let id = mint(pg, (if signed: "int" else: "uint") & $width & idSuffix)
  pg.typeIds[key] = id
  case width
  of 8: pg.caps.incl Int8
  of 16: pg.caps.incl Int16
  of 64: pg.caps.incl Int64
  else: discard
  pg.types.def id, OpTypeInt:
    pg.types.litOp width
    pg.types.litOp (if signed: 1 else: 0)
  result = id

proc boolType(pg: var ProcGen): SymId =
  if "bool" in pg.typeIds: return pg.typeIds["bool"]
  let id = mint(pg, "bool" & idSuffix)
  pg.typeIds["bool"] = id
  pg.types.def id, OpTypeBool:
    discard
  result = id

proc voidType(pg: var ProcGen): SymId =
  if "void" in pg.typeIds: return pg.typeIds["void"]
  let id = mint(pg, "void" & idSuffix)
  pg.typeIds["void"] = id
  pg.types.def id, OpTypeVoid:
    discard
  result = id

proc valueType(pg: var ProcGen; t: Cursor): SymId =
  ## SPIR-V type id for a Leng value type. Unsupported types abort the run.
  case t.typeKind
  of IT: result = intType(pg, scalarWidth(t), signed = true)
  of UT: result = intType(pg, scalarWidth(t), signed = false)
  of BoolT: result = boolType(pg)
  else: err("unsupported type")

proc ptrType(pg: var ProcGen; sc: SpirvOp; elem: SymId): SymId =
  let key = "ptr:" & $sc & ":" & $elem
  if key in pg.typeIds: return pg.typeIds[key]
  let id = mint(pg, "ptr_" & $sc & "_" & stem(pg, elem) & idSuffix)
  pg.typeIds[key] = id
  pg.types.def id, OpTypePointer:
    pg.types.enumOp sc
    pg.types.idRef elem
  result = id

proc vecType(pg: var ProcGen; elem: SymId; n: int): SymId =
  let key = "vec:" & $elem & ":" & $n
  if key in pg.typeIds: return pg.typeIds[key]
  let id = mint(pg, "v" & $n & stem(pg, elem) & idSuffix)
  pg.typeIds[key] = id
  pg.types.def id, OpTypeVector:
    pg.types.idRef elem
    pg.types.litOp n
  result = id

proc funcType(pg: var ProcGen; m: var Module; ret: SymId; params: seq[SymId]): SymId =
  let key = "fn:" & $ret & ":" & params.mapIt($it).join(",")
  if key in pg.typeIds: return pg.typeIds[key]
  let id = mint(pg, "fnty" & $m.counter & idSuffix)
  inc m.counter
  pg.typeIds[key] = id
  pg.types.def id, OpTypeFunction:
    pg.types.idRef ret
    for p in params: pg.types.idRef p
  result = id

proc constInt(pg: var ProcGen; typeId: SymId; v: int64): SymId =
  let key = "c:" & $typeId & ":" & $v
  if key in pg.constIds: return pg.constIds[key]
  let id = mint(pg, stem(pg, typeId) & "_" & (if v < 0: "n" & $(-v) else: $v) & idSuffix)
  pg.constIds[key] = id
  pg.types.def id, OpConstant:
    pg.types.idRef typeId
    pg.types.litOp v
  result = id

# ── expressions ─────────────────────────────────────────────────────────────

proc genExpr(m: var Module; pg: var ProcGen; n: Cursor; expected: SymId; dest: var Location)

proc bufElemAddr(m: var Module; pg: var ProcGen; buf: SymInfo; idxId: SymId): SymId =
  ## `OpAccessChain` to `buf[idx]`: into the StorageBuffer's `(struct (rtarray))`
  ## at member 0 (the runtime array), then element `idx`.
  let u32 = intType(pg, 32, false)
  let zero = constInt(pg, u32, 0)
  result = freshId(m, "ac")
  pg.funcs.def result, OpAccessChain:
    pg.funcs.idRef buf.ptrId
    pg.funcs.idRef buf.id
    pg.funcs.idRef zero
    pg.funcs.idRef idxId

proc genBinop(m: var Module; pg: var ProcGen; n: Cursor; op: SpirvOp; dest: var Location) =
  ## `(add/sub/mul <type> a b)` -> an `OpIAdd`/`OpISub`/`OpIMul` value.
  var c = n
  var resType = SymId(0)
  var a, b: Location
  c.into:
    resType = valueType(pg, c); skip c
    genExpr(m, pg, c, resType, a); skip c
    genExpr(m, pg, c, resType, b); skip c
    if c.hasMore: err("n-ary arithmetic not supported")
  let id = freshId(m, "t")
  pg.funcs.def id, op:
    pg.funcs.idRef resType
    pg.funcs.idRef a.s
    pg.funcs.idRef b.s
  dest.s = id

proc genExpr(m: var Module; pg: var ProcGen; n: Cursor; expected: SymId; dest: var Location) =
  ## Translate an expression, binding `dest` to the id of its SSA result value.
  if n.kind == Symbol:
    let name = symName(n)
    if name notin pg.syms: err("unknown symbol: " & name)
    let s = pg.syms[name]
    case s.cls
    of scParamValue:
      dest.s = s.id
    of scLocalPtr:
      let id = freshId(m, "t")
      pg.funcs.def id, OpLoad:
        pg.funcs.idRef s.typeId
        pg.funcs.idRef s.id
      dest.s = id
    of scBuffer:
      err("buffer '" & name & "' used as a scalar value")
  elif n.kind == IntLit:
    if expected == SymId(0): err("integer literal without a type context")
    dest.s = constInt(pg, expected, intVal(n))
  elif n.kind == TagLit:
    case n.exprKind
    of AddC: genBinop(m, pg, n, OpIAdd, dest)
    of SubC: genBinop(m, pg, n, OpISub, dest)
    of MulC: genBinop(m, pg, n, OpIMul, dest)
    of ConvC:
      # `(conv <targetType> <expr>)`. v1 treats a conversion as identity (the
      # only conversions in a kernel are same-width index/int casts); a real
      # width change (OpSConvert/OpUConvert) is a later refinement.
      var c = n
      c.into:
        skip c                                   # target type
        genExpr(m, pg, c, expected, dest); skip c
    of SufC:
      # `(suf <intlit> "i32")` — a literal carrying a type suffix.
      var c = n
      var v = 0'i64
      c.into:
        if c.kind == IntLit: v = intVal(c)
        skip c
        while c.hasMore: skip c                  # the suffix string
      if expected == SymId(0): err("suffixed literal without a type context")
      dest.s = constInt(pg, expected, v)
    of PatC, AtC:
      # `buf[idx]` read -> OpAccessChain + OpLoad.
      var c = n
      var bufName = ""
      var idx: Location
      c.into:
        bufName = symName(c); skip c
        genExpr(m, pg, c, SymId(0), idx); skip c
        while c.hasMore: skip c                  # bound / extra (array `at`) operands
      if bufName notin pg.syms or pg.syms[bufName].cls != scBuffer:
        err("indexing a non-buffer")
      let buf = pg.syms[bufName]
      let address = bufElemAddr(m, pg, buf, idx.s)
      let id = freshId(m, "t")
      pg.funcs.def id, OpLoad:
        pg.funcs.idRef buf.typeId
        pg.funcs.idRef address
      dest.s = id
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
      var val: Location
      genExpr(m, pg, v.value, s.typeId, val)
      pg.funcs.instr OpStore:
        pg.funcs.idRef s.id
        pg.funcs.idRef val.s
  of AsgnS:
    var c = n
    c.into:
      if c.kind == TagLit and (c.exprKind == PatC or c.exprKind == AtC):
        # `buf[idx] = rhs` -> OpAccessChain + OpStore.
        var lhs = c
        var bufName = ""
        var idx: Location
        lhs.into:
          bufName = symName(lhs); skip lhs
          genExpr(m, pg, lhs, SymId(0), idx); skip lhs
          while lhs.hasMore: skip lhs
        skip c
        if bufName notin pg.syms or pg.syms[bufName].cls != scBuffer:
          err("assigning to a non-buffer index")
        let buf = pg.syms[bufName]
        var val: Location
        genExpr(m, pg, c, buf.typeId, val)
        skip c
        let address = bufElemAddr(m, pg, buf, idx.s)
        pg.funcs.instr OpStore:
          pg.funcs.idRef address
          pg.funcs.idRef val.s
      elif c.kind == Symbol:
        let name = symName(c)
        if name notin pg.syms: err("assignment to unknown symbol")
        let s = pg.syms[name]
        if s.cls != scLocalPtr: err("assignment to a non-variable")
        skip c
        var val: Location
        genExpr(m, pg, c, s.typeId, val)
        skip c
        pg.funcs.instr OpStore:
          pg.funcs.idRef s.id
          pg.funcs.idRef val.s
      else:
        err("assignment to an unsupported target")
  of RetS:
    var c = n
    c.into:
      if c.kind == DotToken:
        pg.funcs.instr OpReturn: discard
      else:
        var val: Location
        genExpr(m, pg, c, SymId(0), val)
        pg.funcs.instr OpReturnValue:
          pg.funcs.idRef val.s
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
      let ptrId = ptrType(pg, Function, typeId)
      let name = symName(v.name)
      let idSym = mint(pg, name)
      pg.syms[name] = SymInfo(id: idSym, cls: scLocalPtr, typeId: typeId)
      pg.funcs.def idSym, OpVariable:
        pg.funcs.idRef ptrId
        pg.funcs.enumOp Function
    skip c

proc newProcGen(pool: Pool; tags: TagPool): ProcGen =
  ProcGen(entryPoints: createTokenBuf(8, pool, tags),
          execModes: createTokenBuf(8, pool, tags),
          decorations: createTokenBuf(16, pool, tags),
          types: createTokenBuf(32, pool, tags),
          funcs: createTokenBuf(32, pool, tags),
          typeIds: initTable[string, SymId](),
          constIds: initTable[string, SymId](),
          syms: initTable[string, SymInfo](),
          caps: initHashSet[SpirvOp](),
          pool: pool)

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
  ## success. Pre-builds all output in a `ProcGen` so its sections can be spliced
  ## into the module in SPIR-V's mandated order.
  var pg = newProcGen(m.pool, m.tags)
  var n = procCursor
  let p = takeProcDecl(n)

  let fnName = mint(pg, symName(p.name))
  let retId =
    if p.returnType.kind == DotToken or p.returnType.typeKind == VoidT:
      voidType(pg)
    else:
      valueType(pg, p.returnType)

  var paramTypes: seq[SymId] = @[]
  var paramOrder: seq[tuple[id, typeId: SymId]] = @[]
  if p.params.typeKind == ParamsT:
    var pc = p.params
    loopInto pc:
      let pd = takeParamDecl(pc)
      let typeId = valueType(pg, pd.typ)
      let name = symName(pd.name)
      let idSym = mint(pg, name)
      pg.syms[name] = SymInfo(id: idSym, cls: scParamValue, typeId: typeId)
      paramTypes.add typeId
      paramOrder.add (idSym, typeId)
  elif p.params.kind != DotToken:
    err("unsupported parameter list")

  let fnTypeId = funcType(pg, m, retId, paramTypes)

  pg.funcs.def fnName, OpFunction:
    pg.funcs.idRef retId
    pg.funcs.enumOp None
    pg.funcs.idRef fnTypeId
  for prm in paramOrder:
    pg.funcs.def prm.id, OpFunctionParameter:
      pg.funcs.idRef prm.typeId
  let entry = freshId(m, "entry")
  pg.funcs.def entry, OpLabel:
    discard

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
  let mainId = mint(pg, symName(p.name))

  let u32 = intType(pg, 32, false)
  let voidId = voidType(pg)
  let fnty = funcType(pg, m, voidId, @[])
  let vec3u = vecType(pg, u32, 3)
  let ptrInVec3 = ptrType(pg, Input, vec3u)
  let ptrInU32 = ptrType(pg, Input, u32)
  let zero = constInt(pg, u32, 0)

  # The GlobalInvocationId builtin input variable.
  let gid = mint(pg, "gid" & idSuffix)
  pg.types.def gid, OpVariable:
    pg.types.idRef ptrInVec3
    pg.types.enumOp Input
  pg.decorations.instr OpDecorate:
    pg.decorations.idRef gid
    pg.decorations.enumOp BuiltIn
    pg.decorations.enumOp GlobalInvocationId

  # Classify params: the first scalar is the grid index, each pointer a buffer.
  var indexParam = ""
  var indexType = SymId(0)
  var binding = 0
  if p.params.typeKind == ParamsT:
    var pc = p.params
    loopInto pc:
      let pd = takeParamDecl(pc)
      let pname = symName(pd.name)
      if pd.typ.typeKind == PtrT:
        let elem = valueType(pg, elementType(pd.typ))
        let rta = freshId(m, "rta")
        pg.types.def rta, OpTypeRuntimeArray:
          pg.types.idRef elem
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef rta
          pg.decorations.enumOp ArrayStride
          pg.decorations.litOp 4
        let st = freshId(m, "buf")
        pg.types.def st, OpTypeStruct:
          pg.types.idRef rta
        pg.decorations.instr OpMemberDecorate:
          pg.decorations.idRef st
          pg.decorations.litOp 0
          pg.decorations.enumOp Offset
          pg.decorations.litOp 0
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef st
          pg.decorations.enumOp Block
        let sbPtr = ptrType(pg, StorageBuffer, st)
        let varId = mint(pg, base(pname) & idSuffix)
        pg.types.def varId, OpVariable:
          pg.types.idRef sbPtr
          pg.types.enumOp StorageBuffer
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef varId
          pg.decorations.enumOp DescriptorSet
          pg.decorations.litOp 0
        pg.decorations.instr OpDecorate:
          pg.decorations.idRef varId
          pg.decorations.enumOp Binding
          pg.decorations.litOp binding
        inc binding
        let elemPtr = ptrType(pg, StorageBuffer, elem)
        pg.syms[pname] = SymInfo(id: varId, cls: scBuffer, typeId: elem, ptrId: elemPtr)
      else:
        if indexParam.len > 0: err("kernel: more than one scalar parameter")
        indexParam = pname
        indexType = intType(pg, 32, true)   # index used as a 32-bit int

  if indexParam.len == 0: err("kernel: no grid-index parameter")

  pg.entryPoints.instr OpEntryPoint:
    pg.entryPoints.enumOp GLCompute
    pg.entryPoints.idRef mainId
    pg.entryPoints.strOp "main"
    pg.entryPoints.idRef gid                 # SPIR-V 1.3 interface = Input/Output vars
  pg.execModes.instr OpExecutionMode:
    pg.execModes.idRef mainId
    pg.execModes.enumOp LocalSize
    pg.execModes.litOp 1
    pg.execModes.litOp 1
    pg.execModes.litOp 1

  pg.funcs.def mainId, OpFunction:
    pg.funcs.idRef voidId
    pg.funcs.enumOp None
    pg.funcs.idRef fnty
  let entry = freshId(m, "entry")
  pg.funcs.def entry, OpLabel:
    discard

  # i = int32(gl_GlobalInvocationID.x)
  let gidPtr = freshId(m, "gidp")
  pg.funcs.def gidPtr, OpAccessChain:
    pg.funcs.idRef ptrInU32
    pg.funcs.idRef gid
    pg.funcs.idRef zero
  let gidx = freshId(m, "gidx")
  pg.funcs.def gidx, OpLoad:
    pg.funcs.idRef u32
    pg.funcs.idRef gidPtr
  let idx = freshId(m, "idx")
  pg.funcs.def idx, OpBitcast:               # uint32 -> int32 (same width)
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
                 caps: initHashSet[SpirvOp](), counter: 0)
  var c = input.beginRead()
  if c.stmtKind == StmtsS:
    loopInto c:
      if c.stmtKind == ProcS:
        # Any unsupported construct `quit`s (see `err`): ghast fails on the whole
        # module rather than silently emitting a quietly-incomplete one.
        if isKernel(c): translateKernel(m, c)
        else: translateProc(m, c)
      skip c

  result = createTokenBuf(64, pool, tags)
  beginModule result
  result.instr OpCapability:
    result.enumOp Shader
  for cap in sorted(toSeq(m.caps)):
    result.instr OpCapability:
      result.enumOp cap
  result.instr OpMemoryModel:
    result.enumOp Logical
    result.enumOp GLSL450
  appendAll(result, m.entryPoints)
  appendAll(result, m.execModes)
  appendAll(result, m.decorations)
  appendAll(result, m.types)
  appendAll(result, m.funcs)
  endModule result
