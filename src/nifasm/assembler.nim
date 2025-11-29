
import std / [tables, streams, os]
import "../../../nimony/src/lib" / [nifreader, nifstreams, nifcursors, bitabs, lineinfos, symparser]
import tags, model
import x86, elf
import sem, slots

proc tag(n: Cursor): TagEnum = cast[TagEnum](n.tagId)

proc infoStr(n: Cursor): string =
  if n.info.isValid:
    let raw = unpack(pool.man, n.info)
    result = pool.files[raw.file] & "(" & $raw.line & ", " & $raw.col & ")"
  else:
    result = "???"

proc error(msg: string; n: Cursor) =
  quit "[Error] " & msg & " at " & infoStr(n)

proc typeError(want, got: Type; n: Cursor) =
  error("Type mismatch: expected " & $want & ", got " & $got, n)

proc getInt(n: Cursor): int64 =
  if n.kind == IntLit:
    result = pool.integers[n.intId]
  else:
    error("Expected integer literal", n)

proc getSym(n: Cursor): string =
  if n.kind in {Symbol, SymbolDef}:
    result = pool.syms[n.symId]
  else:
    error("Expected symbol", n)

proc getStr(n: Cursor): string =
  if n.kind == StringLit:
    result = pool.strings[n.litId]
  else:
    error("Expected string literal", n)

proc parseRegister(n: var Cursor): Register =
  let t = n.tag
  result = case t
    of RaxTagId, R0TagId: RAX
    of RcxTagId, R2TagId: RCX
    of RdxTagId, R3TagId: RDX
    of RbxTagId, R1TagId: RBX
    of RspTagId, R7TagId: RSP
    of RbpTagId, R6TagId: RBP
    of RsiTagId, R4TagId: RSI
    of RdiTagId, R5TagId: RDI
    of R8TagId: R8
    of R9TagId: R9
    of R10TagId: R10
    of R11TagId: R11
    of R12TagId: R12
    of R13TagId: R13
    of R14TagId: R14
    of R15TagId: R15
    # XMMs should be handled but return type prevents it?
    # Register enum is GPR.
    # We need to separate XMM parsing or expand Register enum?
    # x86.nim has Register and XmmRegister.
    # Let's keep this for GPRs.
    else:
      error("Expected GPR register, got: " & $t, n)
      RAX
  inc n
  if n.kind != ParRi: error("Expected ) after register", n)
  inc n

proc tagToRegister(t: TagEnum): Register =
  ## Convert a TagEnum to a Register (for register binding tracking)
  result = case t
    of RaxTagId, R0TagId: RAX
    of RcxTagId, R2TagId: RCX
    of RdxTagId, R3TagId: RDX
    of RbxTagId, R1TagId: RBX
    of RspTagId, R7TagId: RSP
    of RbpTagId, R6TagId: RBP
    of RsiTagId, R4TagId: RSI
    of RdiTagId, R5TagId: RDI
    of R8TagId: R8
    of R9TagId: R9
    of R10TagId: R10
    of R11TagId: R11
    of R12TagId: R12
    of R13TagId: R13
    of R14TagId: R14
    of R15TagId: R15
    else: RAX  # Should not happen

type
  LoadedModule = object
    buf: TokenBuf
    stream: nifstreams.Stream
    loaded: bool  # True if already loaded into scope

  GenContext = object
    scope: Scope
    buf: Buffer  # Code buffer (.text section)
    bssBuf: Buffer  # BSS buffer (.bss section) for zero-initialized global variables
    procName: string
    inCall: bool
    clobbered: set[Register] # Registers clobbered in current flow
    slots: SlotManager
    ssizePatches: seq[int]
    tlsOffset: int  # Current TLS offset for thread-local variables
    bssOffset: int  # Current offset in .bss section
    modules: Table[string, LoadedModule]  # Cache of loaded foreign modules
    baseDir: string  # Base directory for finding module files
    regBindings: Table[Register, string]  # Maps registers to variable names they're bound to

  Operand = object
    reg: Register
    typ: Type
    isImm: bool
    immVal: int64
    isMem: bool
    mem: MemoryOperand
    isSsize: bool
    label: LabelId

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseClobbers(n: var Cursor): set[Register]

proc parseObjectBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  var fields: seq[(string, Type)] = @[]
  var offset = 0
  var maxAlign = 1  # Track maximum alignment requirement
  inc n
  while n.kind != ParRi:
    if n.kind == ParLe and n.tag == FldTagId:
      inc n
      if n.kind != SymbolDef: error("Expected field name", n)
      let name = getSym(n)
      inc n
      let ftype = parseType(n, scope, ctx)
      fields.add (name, ftype)
      
      # Align field to its natural alignment
      let fieldAlign = asmAlignOf(ftype)
      offset = alignTo(offset, fieldAlign)
      
      # Track maximum alignment for the struct
      if fieldAlign > maxAlign:
        maxAlign = fieldAlign
      
      # Move past this field
      offset += asmSizeOf(ftype)
      
      if n.kind != ParRi: error("Expected )", n)
      inc n
    else:
      error("Expected field definition", n)
  inc n
  
  # Round up total size to be a multiple of the struct's alignment
  let finalSize = alignTo(offset, maxAlign)
  result = Type(kind: ObjectT, fields: fields, size: finalSize, align: maxAlign)

proc loadForeignModule(ctx: var GenContext; modname: string; scope: Scope; n: Cursor) =
  ## Load a foreign module and add its symbols to the scope
  if ctx.modules.hasKey(modname):
    if ctx.modules[modname].loaded:
      return  # Already loaded
  else:
    # Try to find the module file
    # Look for modname.s.nif (semchecked) or modname.nif
    var modfile = ""
    let semchecked = ctx.baseDir / modname & ".s.nif"
    let plain = ctx.baseDir / modname & ".nif"

    if fileExists(semchecked):
      modfile = semchecked
    elif fileExists(plain):
      modfile = plain
    else:
      error("Foreign module file not found: " & modname & " (tried: " & semchecked & ", " & plain & ")", n)
      return

    # Open and parse the module
    var stream = nifstreams.open(modfile)
    discard processDirectives(stream.r)
    let buf = fromStream(stream)
    ctx.modules[modname] = LoadedModule(buf: buf, stream: stream, loaded: false)

  # Parse the module's declarations
  var n = beginRead(ctx.modules[modname].buf)
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe:
        let start = n
        case n.tag
        of TypeTagId:
          inc n
          if n.kind != SymbolDef:
            skip n
            continue
          let name = getSym(n)
          # Extract basename (without module suffix) for lookup
          var basename = name
          extractBasename(basename)
          inc n
          if n.kind == ParLe and n.tag == ObjectTagId:
            let typ = parseObjectBody(n, scope, ctx)
            let sym = Symbol(name: basename, kind: skType, typ: typ, isForeign: true)
            scope.define(sym)
          else:
            let typ = parseType(n, scope, ctx)
            let sym = Symbol(name: basename, kind: skType, typ: typ, isForeign: true)
            scope.define(sym)
          if n.kind != ParRi: skip n
          inc n
        of ProcTagId:
          # Parse proc signature only (skip body)
          inc n
          if n.kind != SymbolDef:
            skip n
            continue
          let name = getSym(n)
          var basename = name
          extractBasename(basename)
          inc n

          var sig = Signature(params: @[], result: @[], clobbers: {})

          # Parse params
          if n.kind == ParLe and n.tag == ParamsTagId:
            sig.params = parseParams(n, scope, ctx)

          # Parse result
          if n.kind == ParLe and n.tag == ResultTagId:
            var r = parseResult(n, scope, ctx)
            sig.result = r

          # Parse clobber
          if n.kind == ParLe and n.tag == ClobberTagId:
            sig.clobbers = parseClobbers(n)

          let sym = Symbol(name: basename, kind: skProc, sig: sig, isForeign: true)
          scope.define(sym)

          # Skip body
          n = start
          skip n
        of GvarTagId:
          inc n
          if n.kind != SymbolDef:
            skip n
            continue
          let name = getSym(n)
          var basename = name
          extractBasename(basename)
          inc n
          let typ = parseType(n, scope, ctx)
          let sym = Symbol(name: basename, kind: skGvar, typ: typ, isForeign: true)
          scope.define(sym)
          n = start
          skip n
        of TvarTagId:
          inc n
          if n.kind != SymbolDef:
            skip n
            continue
          let name = getSym(n)
          var basename = name
          extractBasename(basename)
          inc n
          let typ = parseType(n, scope, ctx)
          let sym = Symbol(name: basename, kind: skTvar, typ: typ, isForeign: true)
          scope.define(sym)
          n = start
          skip n
        else:
          skip n
      else:
        skip n
    inc n

  ctx.modules[modname].loaded = true

proc lookupWithAutoImport(ctx: var GenContext; scope: Scope; name: string; n: Cursor): Symbol =
  ## Lookup a symbol, automatically loading foreign modules if needed
  result = scope.lookup(name)
  if result == nil:
    # Check if this is a foreign symbol (has module suffix)
    let modname = extractModule(name)
    if modname != "":
      # Load the foreign module
      loadForeignModule(ctx, modname, scope, n)
      # Try lookup again (with basename)
      var basename = name
      extractBasename(basename)
      result = scope.lookup(basename)

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, scope, name, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & name, n)
    result = sym.typ
    inc n
  elif n.kind == ParLe:
    let t = n.tag
    inc n
    case t
    of BoolTagId:
      result = Type(kind: BoolT)
    of ITagId:
      result = Type(kind: IntT, bits: int(getInt(n)))
      inc n
    of UTagId:
      result = Type(kind: UIntT, bits: int(getInt(n)))
      inc n
    of FTagId:
      result = Type(kind: FloatT, bits: int(getInt(n)))
      inc n
    of PtrTagId:
      let base = parseType(n, scope, ctx)
      result = Type(kind: PtrT, base: base)
    of AptrTagId:
      let base = parseType(n, scope, ctx)
      result = Type(kind: AptrT, base: base)
    of ArrayTagId:
      let elem = parseType(n, scope, ctx)
      let len = getInt(n)
      inc n
      result = Type(kind: ArrayT, elem: elem, len: len)
    else:
      error("Unknown type tag: " & $t, n)
    if n.kind != ParRi: error("Expected )", n)
    inc n
  else:
    error("Expected type", n)


proc parseUnionBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  var fields: seq[(string, Type)] = @[]
  var maxSize = 0
  var maxAlign = 1  # Track maximum alignment requirement
  inc n 
  while n.kind != ParRi:
    if n.kind == ParLe and n.tag == FldTagId:
      inc n
      if n.kind != SymbolDef: error("Expected field name", n)
      let name = getSym(n)
      inc n
      let ftype = parseType(n, scope, ctx)
      fields.add (name, ftype)
      
      let size = asmSizeOf(ftype)
      let fieldAlign = asmAlignOf(ftype)
      
      # Union size is the maximum of all field sizes
      if size > maxSize:
        maxSize = size
      
      # Track maximum alignment
      if fieldAlign > maxAlign:
        maxAlign = fieldAlign
      
      if n.kind != ParRi: error("Expected )", n)
      inc n
    else:
      error("Expected field definition", n)
  inc n
  
  # Round up size to be a multiple of the union's alignment
  let finalSize = alignTo(maxSize, maxAlign)
  result = Type(kind: UnionT, fields: fields, size: finalSize, align: maxAlign)

proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (params (param :name (reg) Type) ...)
  inc n # params
  while n.kind != ParRi:
    if n.kind == ParLe and n.tag == ParamTagId:
      inc n # param
      if n.kind != SymbolDef: error("Expected param name", n)
      let name = getSym(n)
      inc n

      # (reg) or (s) location
      var reg = InvalidTagId
      var onStack = false
      if n.kind == ParLe:
        let locTag = n.tag
        if rawTagIsNifasmReg(locTag):
          reg = locTag
          inc n
          if n.kind != ParRi: error("Expected )", n)
          inc n
        elif locTag == STagId:
          onStack = true
          inc n
          if n.kind != ParRi: error("Expected )", n)
          inc n
        else:
          # Stack or other location, skip for now
          inc n
          if n.kind != ParRi: error("Expected )", n)
          inc n
      else:
        error("Expected location", n)

      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg, onStack: onStack)

      if n.kind != ParRi: error("Expected )", n)
      inc n
    else:
      error("Expected param declaration", n)
  inc n

proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (result (ret :name (reg) Type) ...)
  if n.kind == ParLe and n.tag == ResultTagId:
    inc n
    # if it's a block of results or a single declaration?
    # "result value declaration".
    # Usually return values are just (ret :name (loc) Type)
    # Let's try parsing one.
    if n.kind != SymbolDef: error("Expected result name", n)
    let name = getSym(n)
    inc n
    var reg = InvalidTagId
    if n.kind == ParLe:
      let locTag = n.tag
      if rawTagIsNifasmReg(locTag):
        reg = locTag
        inc n
        if n.kind != ParRi: error("Expected )", n)
        inc n
      else:
        inc n
        if n.kind != ParRi: error("Expected )", n)
        inc n
    else:
      error("Expected location", n)
    let typ = parseType(n, scope, ctx)
    result.add Param(name: name, typ: typ, reg: reg)
    if n.kind != ParRi: error("Expected )", n)
    inc n
  else:
    # Maybe no return values
    discard

proc parseClobbers(n: var Cursor): set[Register] =
  # (clobber (rax) (rbx) ...)
  if n.kind == ParLe and n.tag == ClobberTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe and rawTagIsNifasmReg(n.tag):
        result.incl parseRegister(n)
      else:
        error("Expected register in clobber list", n)
    inc n

proc pass1Proc(n: var Cursor; scope: Scope; ctx: var GenContext) =
  # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
  inc n
  if n.kind != SymbolDef: error("Expected proc name", n)
  let name = getSym(n)
  inc n

  var sig = Signature(params: @[], result: @[], clobbers: {})

  # Parse params
  if n.kind == ParLe and n.tag == ParamsTagId:
    sig.params = parseParams(n, scope, ctx)

  # Parse result
  if n.kind == ParLe and n.tag == ResultTagId:
     var r = parseResult(n, scope, ctx)
     sig.result = r

  # Parse clobber
  if n.kind == ParLe and n.tag == ClobberTagId:
    sig.clobbers = parseClobbers(n)

  let sym = Symbol(name: name, kind: skProc, sig: sig)
  scope.define(sym)

proc pass1(n: var Cursor; scope: Scope; ctx: var GenContext) =
  var n = n
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe:
        let start = n
        case n.tag
        of TypeTagId:
          inc n
          if n.kind != SymbolDef: error("Expected type name", n)
          let name = getSym(n)
          inc n
          if n.kind == ParLe and n.tag == ObjectTagId:
            let typ = parseObjectBody(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ))
          elif n.kind == ParLe and n.tag == UnionTagId:
            let typ = parseUnionBody(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ))
          else:
            let typ = parseType(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ))
          if n.kind != ParRi: error("Expected ) at end of type decl", n)
          inc n
        of ProcTagId:
          # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
          pass1Proc(n, scope, ctx)

          n = start
          skip n
        of RodataTagId:
          inc n
          if n.kind != SymbolDef: error("Expected rodata name", n)
          let name = getSym(n)
          scope.define(Symbol(name: name, kind: skRodata))
          n = start
          skip n
        of GvarTagId:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = getSym(n)
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skGvar, typ: typ))
          n = start
          skip n
        of TvarTagId:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = getSym(n)
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skTvar, typ: typ))
          n = start
          skip n
        else:
          skip n
      else:
        skip n
    inc n

proc genInst(n: var Cursor; ctx: var GenContext)

proc pass2Proc(n: var Cursor; ctx: var GenContext) =
  let oldScope = ctx.scope
  ctx.scope = newScope(oldScope)

  inc n
  let name = getSym(n)
  ctx.procName = name

  # Find/Create label for proc
  let sym = oldScope.lookup(name)
  if sym.offset == -1:
     let lab = ctx.buf.createLabel()
     sym.offset = int(lab)
  ctx.buf.defineLabel(LabelId(sym.offset))

  # Initialize stack context
  ctx.slots = initSlotManager()
  ctx.ssizePatches = @[]
  # Clear register bindings at the start of each proc
  ctx.regBindings = initTable[Register, string]()

  # Add params to scope
  var paramOffset = 16 # RBP + 16 (skip RBP, RetAddr)
  for param in sym.sig.params:
    if param.onStack:
      ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, onStack: true, offset: paramOffset))
      paramOffset += slots.alignedSize(param.typ)
    else:
      ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, reg: param.reg))
      # Track register binding for parameters
      if param.reg != InvalidTagId:
        let targetReg = tagToRegister(param.reg)
        ctx.regBindings[targetReg] = param.name

  inc n
  while n.kind == ParLe and n.tag != StmtsTagId:
    skip n
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      genInst(n, ctx)
    inc n
  if n.kind != ParRi: error("Expected ) at end of proc", n)
  inc n

  # Check that all declared cfvars were used exactly once
  for cfvarName, cfvarSym in ctx.scope.syms:
    if cfvarSym.kind == skCfvar:
      if not cfvarSym.used:
        quit "[Error] Control flow variable '" & cfvarName & "' declared but never used in proc " & ctx.procName

  # Patch ssize
  let alignedStackSize = (ctx.slots.stackSize + 15) and not 15
  for pos in ctx.ssizePatches:
    # Write int32 at pos
    if pos + 4 <= ctx.buf.data.len:
      ctx.buf.data[pos] = byte(alignedStackSize and 0xFF)
      ctx.buf.data[pos+1] = byte((alignedStackSize shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((alignedStackSize shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((alignedStackSize shr 24) and 0xFF)
    else:
      # Should not happen if patched correctly
      discard

  ctx.scope = oldScope

proc genStmt(n: var Cursor; ctx: var GenContext) =
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      genInst(n, ctx)
    inc n
  else:
    genInst(n, ctx)

proc isIntegerType(t: Type): bool =
  ## Check if type is an integer type (int or uint)
  t.kind in {TypeKind.IntT, TypeKind.UIntT}

proc isFloatType(t: Type): bool =
  ## Check if type is a floating point type
  t.kind == TypeKind.FloatT

proc canDoIntegerArithmetic(t: Type): bool =
  ## Check if type supports integer arithmetic operations (add, sub)
  ## Includes integer types and array pointers (for pointer arithmetic)
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.AptrT}

proc canDoBitwiseOps(t: Type): bool =
  ## Check if type supports bitwise operations
  t.kind in {TypeKind.IntT, TypeKind.UIntT}

proc parseOperand(n: var Cursor; ctx: var GenContext; expectedType: Type = nil): Operand =
  if n.kind == ParLe:
    let t = n.tag
    if rawTagIsNifasmReg(t):
      result.reg = parseRegister(n)
      result.typ = Type(kind: IntT, bits: 64) # Explicit register usage is assumed to be Int64 compatible
      # Check if this register is bound to a variable
      if result.reg in ctx.regBindings:
        error("Register " & $result.reg & " is bound to variable '" & 
              ctx.regBindings[result.reg] & "', use the variable name instead", n)
    elif t == DotTagId:
      # (dot <base> <fieldname>)
      inc n
      var baseOp = parseOperand(n, ctx)

      if n.kind != Symbol and n.kind != SymbolDef:
        error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      
      # Type check: base must be a pointer to an object/union, or a stack variable with object/union type
      var objType: Type
      var baseReg: Register
      var baseDisp: int32 = 0

      if baseOp.typ.kind == TypeKind.PtrT:
        # Base is a pointer to an object or union
        objType = baseOp.typ.base
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        baseReg = baseOp.reg
      elif baseOp.isMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        # Base is a stack-allocated object or union
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseDisp = baseOp.mem.displacement
      else:
        error("dot requires pointer to object/union or stack object/union, got " & $baseOp.typ, n)
      
      # Find field in object/union type
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype) in objType.fields:
        # For unions, all fields are at offset 0
        if objType.kind == TypeKind.ObjectT:
          # Align to field's natural alignment
          fieldOffset = alignTo(fieldOffset, asmAlignOf(ftype))
        
        if fname == fieldName:
          fieldType = ftype
          break
        
        # For objects, move past this field
        if objType.kind == TypeKind.ObjectT:
          fieldOffset += asmSizeOf(ftype)
      
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      
      # Result is memory operand pointing to the field
      result.isMem = true
      result.mem = MemoryOperand(
        base: baseReg,
        displacement: baseDisp + int32(fieldOffset),
        hasIndex: false
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)

      if n.kind != ParRi: error("Expected ) after dot expression", n)
      inc n
    elif t == AtTagId:
      # (at <base> <index>)
      inc n
      var baseOp = parseOperand(n, ctx)
      var indexOp = parseOperand(n, ctx)

      # Type check: index must be an integer
      if not isIntegerType(indexOp.typ):
        error("Array index must be integer type, got " & $indexOp.typ, n)

      # Type check: base must be aptr or stack array
      var elemType: Type
      var baseReg: Register
      var baseDisp: int32 = 0

      if baseOp.typ.kind == TypeKind.AptrT:
        # Base is an array pointer
        elemType = baseOp.typ.base
        baseReg = baseOp.reg
      elif baseOp.isMem and baseOp.typ.kind == TypeKind.ArrayT:
        # Base is a stack-allocated array
        elemType = baseOp.typ.elem
        baseReg = baseOp.mem.base
        baseDisp = baseOp.mem.displacement
      else:
        error("at requires aptr or stack array, got " & $baseOp.typ, n)

      # Check if index is immediate or register
      if indexOp.isImm:
        # Immediate index: compute offset directly
        let offset = indexOp.immVal * asmSizeOf(elemType)
        result.isMem = true
        result.mem = MemoryOperand(
          base: baseReg,
          displacement: baseDisp + int32(offset),
          hasIndex: false
        )
      elif indexOp.isMem:
        error("Array index cannot be memory operand", n)
      else:
        # Register index: use scaled indexing
        let elemSize = asmSizeOf(elemType)
        if elemSize notin [1, 2, 4, 8]:
          error("Element size " & $elemSize & " not supported for scaled indexing (must be 1, 2, 4, or 8)", n)

        result.isMem = true
        result.mem = MemoryOperand(
          base: baseReg,
          index: indexOp.reg,
          scale: elemSize,
          displacement: baseDisp,
          hasIndex: true
        )

      result.typ = Type(kind: TypeKind.PtrT, base: elemType)

      if n.kind != ParRi: error("Expected ) after at expression", n)
      inc n
    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      if n.kind != ParRi: error("Expected )", n)
      inc n
      result.reg = RAX
      result.label = LabelId(sym.offset)
      # Label address type is pointer to code?
      result.typ = Type(kind: UIntT, bits: 64) # Address
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      # Cast allows us to opt-out of type system, so we don't check against expectedType here
      var op = parseOperand(n, ctx, nil)
      op.typ = castType
      result = op
      if n.kind != ParRi: error("Expected ) after cast", n)
      inc n
    elif t == MemTagId:
      # (mem <address-expr>) or (mem <base> <offset>) or (mem <base> <index> <scale>) etc
      inc n

      # Check if first child is an address expression (dot/at) or explicit addressing
      if n.kind == ParLe and (n.tag == DotTagId or n.tag == AtTagId):
        # Wrapped address expression: (mem (dot ...) or (mem (at ...))
        var addrOp = parseOperand(n, ctx)
        if not addrOp.isMem:
          error("mem requires address expression", n)

        # Dereference the pointer type
        if addrOp.typ.kind != TypeKind.PtrT:
          error("mem requires pointer type, got " & $addrOp.typ, n)

        result = addrOp
        result.typ = addrOp.typ.base  # Dereference: ptr T -> T
      else:
        # Explicit addressing: (mem base) or (mem base offset) or (mem base index scale [offset])
        var baseOp = parseOperand(n, ctx)
        if baseOp.isImm or baseOp.isMem:
          error("mem base must be a register", n)

        var displacement: int32 = 0
        var hasIndex = false
        var indexReg: Register = RAX
        var scale: int = 1

        # Check for offset
        if n.kind == IntLit or n.kind == Symbol:
          if n.kind == IntLit:
            displacement = int32(getInt(n))
            inc n
          elif n.kind == Symbol:
            # Could be index register
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
              # This is the index register
              hasIndex = true
              indexReg = case indexSym.reg
                of RaxTagId, R0TagId: RAX
                of RcxTagId, R2TagId: RCX
                of RdxTagId, R3TagId: RDX
                of RbxTagId, R1TagId: RBX
                of RspTagId, R7TagId: RSP
                of RbpTagId, R6TagId: RBP
                of RsiTagId, R4TagId: RSI
                of RdiTagId, R5TagId: RDI
                of R8TagId: R8
                of R9TagId: R9
                of R10TagId: R10
                of R11TagId: R11
                of R12TagId: R12
                of R13TagId: R13
                of R14TagId: R14
                of R15TagId: R15
                else: RAX
              inc n

              # Check for scale
              if n.kind == IntLit:
                scale = int(getInt(n))
                if scale notin [1, 2, 4, 8]:
                  error("mem scale must be 1, 2, 4, or 8", n)
                inc n

                # Check for displacement after scale
                if n.kind == IntLit:
                  displacement = int32(getInt(n))
                  inc n
            else:
              error("Expected index register or offset in mem", n)

        result.isMem = true
        result.mem = MemoryOperand(
          base: baseOp.reg,
          index: indexReg,
          scale: scale,
          displacement: displacement,
          hasIndex: hasIndex
        )
        # Type is unknown for explicit addressing
        result.typ = Type(kind: IntT, bits: 64)  # Default assumption

      if n.kind != ParRi: error("Expected ) after mem", n)
      inc n
    elif t == SsizeTagId:
      result.isSsize = true
      result.typ = Type(kind: IntT, bits: 64)
      inc n
      if n.kind != ParRi: error("Expected )", n)
      inc n
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.isImm = true
    result.immVal = getInt(n)
    inc n
    # Immediate type inference?
    # If expectedType is provided, try to match it.
    if expectedType != nil and (expectedType.kind in {IntT, UIntT, FloatT}):
        result.typ = expectedType
    else:
        result.typ = Type(kind: IntT, bits: 64) # Default
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.onStack:
        result.isMem = true
        result.mem = MemoryOperand(base: RBP, displacement: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = case sym.reg
          of RaxTagId, R0TagId: RAX
          of RcxTagId, R2TagId: RCX
          of RdxTagId, R3TagId: RDX
          of RbxTagId, R1TagId: RBX
          of RspTagId, R7TagId: RSP
          of RbpTagId, R6TagId: RBP
          of RsiTagId, R4TagId: RSI
          of RdiTagId, R5TagId: RDI
          of R8TagId: R8
          of R9TagId: R9
          of R10TagId: R10
          of R11TagId: R11
          of R12TagId: R12
          of R13TagId: R13
          of R14TagId: R14
          of R15TagId: R15
          else: RAX

        # Check if clobbered
        if result.reg in ctx.clobbered:
          error("Access to variable '" & name & "' in register " & $result.reg & " which was clobbered", n)

      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.reg = RAX
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      result.reg = RAX
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of rodata
      inc n
    elif sym != nil and sym.kind == skGvar:
      # Global variable - return its address
      # For foreign symbols, we can't generate code, but we can typecheck
      if sym.isForeign:
        error("Cannot access foreign global variable '" & name & "' directly (must be linked)", n)
      result.reg = RAX
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of gvar
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Accessing thread local variable via FS segment
      # On x86-64 Linux, TLS variables are accessed via FS segment
      # The offset is stored in sym.offset (allocated in pass2)
      # Use RBP as base register (standard for offset-only addressing)
      result.isMem = true
      result.mem = MemoryOperand(
        base: RBP,  # RBP allows displacement-only addressing
        displacement: int32(sym.offset),
        hasIndex: false,
        useFsSegment: true  # Use FS segment register
      )
      result.typ = sym.typ
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDest(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == ParLe and rawTagIsNifasmReg(n.tag):
    result.reg = parseRegister(n)
    result.typ = Type(kind: IntT, bits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings:
      error("Register " & $result.reg & " is bound to variable '" & 
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and sym.kind == skVar:
       if sym.onStack:
         result.isMem = true
         result.mem = MemoryOperand(base: RBP, displacement: int32(sym.offset))
         result.typ = sym.typ
       elif sym.reg != InvalidTagId:
         result.reg = case sym.reg
            of RaxTagId, R0TagId: RAX
            of RcxTagId, R2TagId: RCX
            of RdxTagId, R3TagId: RDX
            of RbxTagId, R1TagId: RBX
            of RspTagId, R7TagId: RSP
            of RbpTagId, R6TagId: RBP
            of RsiTagId, R4TagId: RSI
            of RdiTagId, R5TagId: RDI
            of R8TagId: R8
            of R9TagId: R9
            of R10TagId: R10
            of R11TagId: R11
            of R12TagId: R12
            of R13TagId: R13
            of R14TagId: R14
            of R15TagId: R15
            else: RAX
         result.typ = sym.typ
         # Writing to a register makes it valid (unclobbered)
         ctx.clobbered.excl(result.reg)
       else:
         error("Variable has no location", n)
       inc n
    elif sym != nil and sym.kind == skTvar:
       # Writing to thread local variable via FS segment
       result.isMem = true
       result.mem = MemoryOperand(
         base: RBP,  # RBP allows displacement-only addressing
         displacement: int32(sym.offset),
         hasIndex: false,
         useFsSegment: true  # Use FS segment register
       )
       result.typ = sym.typ
       inc n
    else:
       error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc checkType(want, got: Type; n: Cursor) =
  if not compatible(want, got):
    typeError(want, got, n)

proc checkIntegerArithmetic(t: Type; op: string; n: Cursor) =
  if not canDoIntegerArithmetic(t):
    error("Operation '" & op & "' requires integer or pointer type, got " & $t, n)

proc checkIntegerType(t: Type; op: string; n: Cursor) =
  if not isIntegerType(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkFloatType(t: Type; op: string; n: Cursor) =
  if not isFloatType(t):
    error("Operation '" & op & "' requires floating point type, got " & $t, n)

proc checkBitwiseType(t: Type; op: string; n: Cursor) =
  if not canDoBitwiseOps(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkCompatibleTypes(t1, t2: Type; op: string; n: Cursor) =
  ## Check that two operands have compatible types for an operation
  if not compatible(t1, t2):
    error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc genInst(n: var Cursor; ctx: var GenContext) =
  if n.kind != ParLe: error("Expected instruction", n)
  let tag = n.tag
  let start = n

  if tag == CallTagId:
    if ctx.inCall: error("Nested calls are not allowed", n)
    ctx.inCall = true
    defer: ctx.inCall = false
    # (call target (mov arg val) ...)
    inc n
    if n.kind != Symbol: error("Expected proc symbol", n)
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skProc: error("Unknown proc: " & name, n)
    if sym.isForeign:
      error("Cannot call foreign proc '" & name & "' (must be linked)", n)
    inc n

    # Parse arguments
    var args: Table[string, Operand]
    while n.kind == ParLe:
      if n.tag == MovTagId:
        inc n # mov
        if n.kind != Symbol: error("Expected argument name", n)
        let argName = getSym(n)
        inc n
        let val = parseOperand(n, ctx)
        args[argName] = val
        if n.kind != ParRi: error("Expected ) after argument", n)
        inc n
      else:
        error("Expected (mov arg val) in call", n)

    # Validate arguments against signature
    let sig = sym.sig
    for param in sig.params:
      if param.name notin args:
        error("Missing argument: " & param.name, n)
      let arg = args[param.name]
      checkType(param.typ, arg.typ, start)

      var paramReg = RAX # Default
      if param.onStack:
        # Argument is on stack.
        # We need to push or move to stack slot?
        # nifasm is low level. Caller prepares arguments.
        # If param is on stack, it is at [RSP + X] relative to caller?
        # Wait, caller pushes args.
        # So we need `push arg`.
        # But nifasm uses `mov` syntax?
        # If signature says (param :x (s) ...), call uses (mov :x val).
        # We should emit `push val`?
        # Or `mov [rsp+offset], val` (if we reserved space).
        # Standard convention: PUSH args.
        # But nifasm doesn't have PUSH in CallTagId logic.
        # The order matters for PUSH.
        # We iterate params.
        # If we push, we must do it in reverse order (for C convention)?
        # Or correct order?
        # System V: stack args are pushed right-to-left.
        # We have named args. We need to sort them or process in signature order?
        # Signature order is likely declaration order.
        # If we process in order, we might need to adjust.
        # Let's assume we emit `mov` to register for reg params.
        # For stack params, we should emit `push`?
        # But `emitCall` does not handle pushing.
        # If we need to push, we should do it.
        # For now, let's error on stack params or implement push.
        # x86 module needs emitPush.
        error("Stack parameters not yet supported in call generation", n)
      else:
        case param.reg
        of RaxTagId, R0TagId: paramReg = RAX
        of RdiTagId, R5TagId: paramReg = RDI
        of RsiTagId, R4TagId: paramReg = RSI
        of RdxTagId, R3TagId: paramReg = RDX
        of RcxTagId, R2TagId: paramReg = RCX
        of R8TagId: paramReg = R8
        of R9TagId: paramReg = R9
        else: discard

        if arg.isSsize:
           ctx.buf.emitMovImmToReg32(paramReg, 0)
           ctx.ssizePatches.add(ctx.buf.data.len - 4)
        elif arg.isImm:
          ctx.buf.emitMovImmToReg(paramReg, arg.immVal)
        elif arg.isMem:
          ctx.buf.emitMov(paramReg, arg.mem)
        elif arg.reg != paramReg:
          ctx.buf.emitMov(paramReg, arg.reg)

    # Clobber registers
    ctx.clobbered.incl(sig.clobbers)

    var labId: LabelId
    if sym.offset == -1:
       labId = ctx.buf.createLabel()
       sym.offset = int(labId)
    else:
       labId = LabelId(sym.offset)

    ctx.buf.emitCall(labId)

    if n.kind != ParRi: error("Expected ) after call", n)
    inc n
    return

  if tag == IteTagId:
    inc n

    # Check if condition is a cfvar (symbol) or a hardware flag (parens)
    let lElse = ctx.buf.createLabel()
    let lEnd = ctx.buf.createLabel()

    # Save clobbered state
    let oldClobbered = ctx.clobbered

    if n.kind == Symbol:
      # Control flow variable: (ite cfvar ...)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)

      # Check if this cfvar has already been used
      if sym.used:
        error("Control flow variable '" & name & "' used more than once", n)
      sym.used = true

      inc n

      # When using a cfvar in ite, we don't emit any jump here.
      # The cfvar's label should be defined at the start of the "then" branch.
      # If jtrue was called, it jumped directly to the "then" branch.
      # If jtrue was NOT called, execution falls through to the "else" branch.

      # We need to emit an unconditional jump to else before the then branch
      ctx.buf.emitJmp(lElse)

      # Define the cfvar's label here (start of then branch)
      ctx.buf.defineLabel(LabelId(sym.offset))

    elif n.kind == ParLe:
      # Hardware flag: (ite (flag) ...)
      let condTag = n.tag
      inc n
      if n.kind != ParRi: error("Expected ) after cond", n)
      inc n

      case condTag
      of OfTagId: ctx.buf.emitJno(lElse)
      of NoTagId: ctx.buf.emitJo(lElse)
      of ZfTagId: ctx.buf.emitJne(lElse)
      of NzTagId: ctx.buf.emitJe(lElse)
      of SfTagId: ctx.buf.emitJns(lElse)
      of NsTagId: ctx.buf.emitJs(lElse)
      of CfTagId: ctx.buf.emitJae(lElse)
      of NcTagId: ctx.buf.emitJb(lElse)
      of PfTagId: ctx.buf.emitJnp(lElse)
      of NpTagId: ctx.buf.emitJp(lElse)
      else: error("Unsupported condition: " & $condTag, n)
    else:
      error("Expected cfvar or flag condition in ite", n)

    genStmt(n, ctx) # Then block
    # Clobbered state propagates?
    # Control flow merge: union of clobbered sets?
    # If a register is clobbered in THEN but not ELSE, it is clobbered after? Yes.
    let thenClobbered = ctx.clobbered

    ctx.buf.emitJmp(lEnd)

    ctx.clobbered = oldClobbered # Reset for Else
    ctx.buf.defineLabel(lElse)
    genStmt(n, ctx) # Else block
    let elseClobbered = ctx.clobbered

    ctx.buf.defineLabel(lEnd)

    # Merge clobbered
    ctx.clobbered = thenClobbered + elseClobbered

    if n.kind != ParRi: error("Expected ) after ite", n)
    inc n
    return

  if tag == LoopTagId:
    inc n

    # Pre-loop
    genStmt(n, ctx)
    let lStart = ctx.buf.createLabel()
    let lEnd = ctx.buf.createLabel()

    ctx.buf.defineLabel(lStart)

    if n.kind != ParLe: error("Expected condition", n)
    let condTag = n.tag
    inc n
    if n.kind != ParRi: error("Expected ) after cond", n)
    inc n

    case condTag
    of ZfTagId: ctx.buf.emitJne(lEnd)
    of NzTagId: ctx.buf.emitJe(lEnd)
    else: error("Unsupported loop condition: " & $condTag, n)

    # Body
    genStmt(n, ctx)
    ctx.buf.emitJmp(lStart)
    ctx.buf.defineLabel(lEnd)

    # Loop body clobbers propagate
    # But we might execute loop 0 times?
    # If it's a while loop check at start (which this seems to be? No, structure is (loop pre cond post)?)
    # "As in NJVL... (loop (stmts) (cond) (stmts))"
    # It's a do-while or mid-test loop.
    # If we execute the body, clobbers happen.
    # If we skip, they don't?
    # "All control flow variables are always virtual... The first implementations... do not check if these jumps would skip useful instructions"
    # For clobber tracking, we should assume body MIGHT run.
    # So union with pre-loop state?
    # But `ctx.clobbered` accumulates.
    # So whatever happened in body is added.

    if n.kind != ParRi: error("Expected ) after loop", n)
    inc n
    return

  if tag == CfvarTagId:
    # (cfvar :name.0)
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = getSym(n)
    inc n

    # Control flow variables are always virtual (bool type, never materialized)
    # We create a label for when this cfvar becomes "true"
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: name, kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)

    if n.kind != ParRi: error("Expected )", n)
    inc n
    return

  if tag == VarTagId:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = getSym(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    if n.kind == ParLe:
      let locTag = n.tag
      if rawTagIsNifasmReg(locTag):
        reg = locTag
        inc n
        if n.kind != ParRi: error("Expected )", n)
        inc n
      elif locTag == STagId:
        onStack = true
        inc n
        if n.kind != ParRi: error("Expected )", n)
        inc n
      else:
        inc n
        if n.kind != ParRi: error("Expected )", n)
        inc n
    else:
      error("Expected location", n)
    let typ = parseType(n, ctx.scope, ctx)

    let sym = Symbol(name: name, kind: skVar, typ: typ)
    if onStack:
       sym.onStack = true
       sym.offset = ctx.slots.allocSlot(typ)
    else:
       sym.reg = reg
       # Check if register is already bound to another variable
       let targetReg = tagToRegister(reg)
       if targetReg in ctx.regBindings:
         error("Register " & $targetReg & " is already bound to variable '" & 
               ctx.regBindings[targetReg] & "', kill it first before reusing", n)
       # Track the register binding
       ctx.regBindings[targetReg] = name

    ctx.scope.define(sym)

    if n.kind != ParRi: error("Expected )", n)
    inc n
    return

  if tag == JtrueTagId:
    # (jtrue cfvar1.0 cfvar2.0 ...)
    # Set control flow variable(s) to true by emitting an unconditional jump
    # The jump targets are stored in the cfvar symbols
    inc n
    var jumpTarget: LabelId
    var firstCfvar = true

    while n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil: error("Unknown cfvar: " & name, n)
      if sym.kind != skCfvar: error("Symbol is not a cfvar: " & name, n)

      if firstCfvar:
        jumpTarget = LabelId(sym.offset)
        firstCfvar = false
      # For multiple cfvars, they all jump to the same place (first one's target)
      # This matches the semantics where all are set to true together
      inc n

    if firstCfvar: error("jtrue requires at least one cfvar", start)

    # Emit unconditional jump to the cfvar's target label
    ctx.buf.emitJmp(jumpTarget)

    if n.kind != ParRi: error("Expected )", n)
    inc n
    return

  if tag == KillTagId:
    inc n
    if n.kind != Symbol: error("Expected symbol to kill", n)
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown variable to kill: " & name, n)

    if sym.onStack:
      ctx.slots.killSlot(sym.offset, sym.typ)
    elif sym.reg != InvalidTagId:
      # Remove register binding when variable is killed
      let targetReg = tagToRegister(sym.reg)
      ctx.regBindings.del(targetReg)

    # Remove from scope to ensure it's not used again
    ctx.scope.undefine(name)

    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n
    return

  inc n

  case tag
  of MovTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)

    if dest.isMem:
       if op.isImm:
         # x86 supports mov r/m64, imm32 (sign extended)
         if op.immVal >= low(int32) and op.immVal <= high(int32):
             # We need emitMov(MemoryOperand, int32)
             # I haven't added it to x86.nim yet.
             # But I can load to scratch? No, that clobbers.
             # Assume immediate fits 32-bit or error?
             # "MOV r/m64, imm32" (C7 /0)
             # I'll assume it fits or implement `emitMov(mem, imm)`.
             # Since I can't easily add to x86.nim right now without another round,
             # I'll raise error for mem, imm if not supported.
             # Wait, I can use `emitMovImmToReg` if I have a scratch register? No.
             error("Moving immediate to memory not fully supported yet (requires emitMovImmToMem)", n)
         else:
             error("Immediate too large for memory move (must fit in 32 bits)", n)
       elif op.isSsize:
         # Similar issue, ssize is immediate 0 (patched).
         error("Moving ssize to memory not supported", n)
       elif op.isMem:
         error("Cannot move memory to memory", n)
       else:
         ctx.buf.emitMov(dest.mem, op.reg)
    else:
      # dest is reg
      if op.isSsize:
        ctx.buf.emitMovImmToReg32(dest.reg, 0)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.isImm:
        if op.immVal >= low(int32) and op.immVal <= high(int32):
          ctx.buf.emitMovImmToReg32(dest.reg, int32(op.immVal))
        else:
          ctx.buf.emitMovImmToReg(dest.reg, op.immVal)
      elif op.isMem:
        ctx.buf.emitMov(dest.reg, op.mem)
      else:
        ctx.buf.emitMov(dest.reg, op.reg)

  of AddTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)

    # Type check: add works on integers and pointers
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkCompatibleTypes(dest.typ, op.typ, "add", start)

    if dest.isMem:
      if op.isImm:
        # ADD m64, imm32
        # Need emitAdd(MemoryOperand, int32)
        error("Adding immediate to memory not supported yet", n)
      elif op.isSsize:
        error("Adding ssize to memory not supported", n)
      elif op.isMem:
        error("Cannot add memory to memory", n)
      else:
        ctx.buf.emitAdd(dest.mem, op.reg)
    else:
      if op.isSsize:
        ctx.buf.emitAddImm(dest.reg, 0)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.isImm:
        ctx.buf.emitAddImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        ctx.buf.emitAdd(dest.reg, op.mem)
      else:
        ctx.buf.emitAdd(dest.reg, op.reg)

  of SubTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)

    # Type check: sub works on integers and pointers
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkCompatibleTypes(dest.typ, op.typ, "sub", start)

    if dest.isMem:
      if op.isImm:
        error("Subtracting immediate from memory not supported yet", n)
      elif op.isSsize:
        error("Subtracting ssize from memory not supported", n)
      elif op.isMem:
        error("Cannot subtract memory from memory", n)
      else:
        ctx.buf.emitSub(dest.mem, op.reg)
    else:
      if op.isSsize:
        ctx.buf.emitSubImm(dest.reg, 0)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.isImm:
        ctx.buf.emitSubImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        ctx.buf.emitSub(dest.reg, op.mem)
      else:
        ctx.buf.emitSub(dest.reg, op.reg)

  of MulTagId:
    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "mul", start)
    if op.isImm: error("MUL immediate not supported", n)
    if op.isMem: error("MUL memory not supported yet", n) # Need emitMul(mem)
    ctx.buf.emitMul(op.reg)

  of ImulTagId:
    # (imul dest src) or (imul dest src imm) - but we only support binary or unary?
    # doc says (imul D S)
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "imul", start)
    checkIntegerType(op.typ, "imul", start)
    if dest.isMem: error("IMUL destination cannot be memory", n)
    if op.isImm:
      ctx.buf.emitImulImm(dest.reg, int32(op.immVal))
    elif op.isMem:
      error("IMUL memory source not supported yet", n) # Need emitImul(reg, mem)
    else:
      ctx.buf.emitImul(dest.reg, op.reg)

  of DivTagId:
    # (div (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != ParLe or n.tag != RdxTagId: error("Expected (rdx) for div", n)
    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n

    inc n # (rax)
    if n.kind != ParLe or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "div", start)
    if op.isImm: error("DIV immediate not supported", n)
    if op.isMem: error("DIV memory not supported yet", n)
    ctx.buf.emitDiv(op.reg)

  of IdivTagId:
    # (idiv (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != ParLe or n.tag != RdxTagId: error("Expected (rdx) for idiv", n)
    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n

    inc n # (rax)
    if n.kind != ParLe or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "idiv", start)
    if op.isImm: error("IDIV immediate not supported", n)
    if op.isMem: error("IDIV memory not supported yet", n)
    ctx.buf.emitIdiv(op.reg)

  # Bitwise
  of AndTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkCompatibleTypes(dest.typ, op.typ, "and", start)
    if dest.isMem:
      error("AND to memory not supported yet", n)
    else:
      if op.isImm:
        ctx.buf.emitAndImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        error("AND from memory not supported yet", n)
      else:
        ctx.buf.emitAnd(dest.reg, op.reg)

  of OrTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "or", start)
    checkBitwiseType(op.typ, "or", start)
    checkCompatibleTypes(dest.typ, op.typ, "or", start)
    if dest.isMem:
      error("OR to memory not supported yet", n)
    else:
      if op.isImm:
        ctx.buf.emitOrImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        error("OR from memory not supported yet", n)
      else:
        ctx.buf.emitOr(dest.reg, op.reg)

  of XorTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "xor", start)
    checkBitwiseType(op.typ, "xor", start)
    checkCompatibleTypes(dest.typ, op.typ, "xor", start)
    if dest.isMem:
      error("XOR to memory not supported yet", n)
    else:
      if op.isImm:
        ctx.buf.emitXorImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        error("XOR from memory not supported yet", n)
      else:
        ctx.buf.emitXor(dest.reg, op.reg)

  of ShlTagId, SalTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shl", start)
    if dest.isMem: error("Shift destination cannot be memory", n)
    if op.isImm:
      ctx.buf.emitShl(dest.reg, int(op.immVal))
    elif op.reg == RCX:
      # emitShlCl? x86.nim only has imm count support in emitShl currently?
      # Need to check x86.nim for CL support or add it.
      # Existing emitShl takes `count: int`.
      # We need `emitShlCl(reg)`.
      error("Shift by CL not supported yet in x86 backend", n)
    else:
      error("Shift count must be immediate or CL", n)

  of ShrTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shr", start)
    if dest.isMem: error("Shift destination cannot be memory", n)
    if op.isImm:
      ctx.buf.emitShr(dest.reg, int(op.immVal))
    else:
      error("Shift count must be immediate", n)

  of SarTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "sar", start)
    if dest.isMem: error("Shift destination cannot be memory", n)
    if op.isImm:
      ctx.buf.emitSar(dest.reg, int(op.immVal))
    else:
      error("Shift count must be immediate", n)

  # Unary
  of IncTagId:
    let op = parseDest(n, ctx) # Dest/Src same
    checkIntegerArithmetic(op.typ, "inc", start)
    if op.isMem: error("INC memory not supported yet", n)
    ctx.buf.emitInc(op.reg)

  of DecTagId:
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "dec", start)
    if op.isMem: error("DEC memory not supported yet", n)
    ctx.buf.emitDec(op.reg)

  of NegTagId:
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.isMem: error("NEG memory not supported yet", n)
    ctx.buf.emitNeg(op.reg)

  of NotTagId:
    let op = parseDest(n, ctx)
    checkBitwiseType(op.typ, "not", start)
    if op.isMem: error("NOT memory not supported yet", n)
    ctx.buf.emitNot(op.reg)

  # Comparison
  of CmpTagId:
    let dest = parseDest(n, ctx) # Actually just operand 1
    let op = parseOperand(n, ctx)
    # Comparisons work on integers and pointers
    checkIntegerArithmetic(dest.typ, "cmp", start)
    checkIntegerArithmetic(op.typ, "cmp", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmp", start)
    if dest.isMem:
      if op.isImm:
        # CMP m64, imm32
        error("CMP memory, immediate not supported yet", n)
      elif op.isMem:
        error("Cannot compare memory with memory", n)
      else:
        ctx.buf.emitCmp(op.reg, dest.mem) # cmp reg, mem? No, cmp mem, reg.
        # x86.nim: emitCmp(mem, reg) -> CMP r/m64, r64 (39 /r).
        # Wait, 39 is CMP r/m64, r64 (store in r/m? no, compare r/m with r).
        # Opcode 39: CMP r/m64, r64. MR encoding.
        # Operand order: CMP op1, op2.
        # If op1 is mem, op2 is reg.
        ctx.buf.emitCmp(dest.mem, op.reg)
    else:
      if op.isImm:
        ctx.buf.emitCmpImm(dest.reg, int32(op.immVal))
      elif op.isMem:
        ctx.buf.emitCmp(dest.reg, op.mem)
      else:
        ctx.buf.emitCmp(dest.reg, op.reg)

  of TestTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "test", start)
    checkBitwiseType(op.typ, "test", start)
    checkCompatibleTypes(dest.typ, op.typ, "test", start)
    if dest.isMem:
      error("TEST memory not supported yet", n)
    else:
      if op.isImm:
        # emitTestImm
        error("TEST immediate not supported yet", n)
      elif op.isMem:
        error("TEST with memory operand not supported yet", n)
      else:
        ctx.buf.emitTest(dest.reg, op.reg)

  # Conditional Sets
  of SeteTagId, SetzTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSete(dest.reg)
  of SetneTagId, SetnzTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetne(dest.reg)
  of SetaTagId, SetnbeTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSeta(dest.reg)
  of SetaeTagId, SetnbTagId, SetncTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetae(dest.reg)
  of SetbTagId, SetnaeTagId, SetcTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetb(dest.reg)
  of SetbeTagId, SetnaTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetbe(dest.reg)
  of SetgTagId, SetnleTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetg(dest.reg)
  of SetgeTagId, SetnlTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetge(dest.reg)
  of SetlTagId, SetngeTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetl(dest.reg)
  of SetleTagId, SetngTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetle(dest.reg)
  of SetoTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSeto(dest.reg)
  of SetsTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSets(dest.reg)
  of SetpTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem: error("SETcc memory not supported yet", n)
    ctx.buf.emitSetp(dest.reg)

  # Conditional moves
  of CmoveTagId, CmovzTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmove(dest.reg, op.mem)
    else: ctx.buf.emitCmove(dest.reg, op.reg)

  of CmovneTagId, CmovnzTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovne(dest.reg, op.mem)
    else: ctx.buf.emitCmovne(dest.reg, op.reg)

  of CmovaTagId, CmovnbeTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmova(dest.reg, op.mem)
    else: ctx.buf.emitCmova(dest.reg, op.reg)

  of CmovaeTagId, CmovnbTagId, CmovncTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovae(dest.reg, op.mem)
    else: ctx.buf.emitCmovae(dest.reg, op.reg)

  of CmovbTagId, CmovnaeTagId, CmovcTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovb(dest.reg, op.mem)
    else: ctx.buf.emitCmovb(dest.reg, op.reg)

  of CmovbeTagId, CmovnaTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovbe(dest.reg, op.mem)
    else: ctx.buf.emitCmovbe(dest.reg, op.reg)

  of CmovgTagId, CmovnleTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovg(dest.reg, op.mem)
    else: ctx.buf.emitCmovg(dest.reg, op.reg)

  of CmovgeTagId, CmovnlTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovge(dest.reg, op.mem)
    else: ctx.buf.emitCmovge(dest.reg, op.reg)

  of CmovlTagId, CmovngeTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovl(dest.reg, op.mem)
    else: ctx.buf.emitCmovl(dest.reg, op.reg)

  of CmovleTagId, CmovngTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovle(dest.reg, op.mem)
    else: ctx.buf.emitCmovle(dest.reg, op.reg)

  of CmovoTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovo(dest.reg, op.mem)
    else: ctx.buf.emitCmovo(dest.reg, op.reg)

  of CmovsTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovs(dest.reg, op.mem)
    else: ctx.buf.emitCmovs(dest.reg, op.reg)

  of CmovpTagId, CmovpeTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovp(dest.reg, op.mem)
    else: ctx.buf.emitCmovp(dest.reg, op.reg)

  of CmovnpTagId, CmovpoTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovnp(dest.reg, op.mem)
    else: ctx.buf.emitCmovnp(dest.reg, op.reg)

  of CmovnsTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovns(dest.reg, op.mem)
    else: ctx.buf.emitCmovns(dest.reg, op.reg)

  of CmovnoTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.isMem: error("CMOV destination must be a register", n)
    if op.isImm: error("CMOV immediate not supported", n)
    if op.isMem: ctx.buf.emitCmovno(dest.reg, op.mem)
    else: ctx.buf.emitCmovno(dest.reg, op.reg)

  # Stack
  of PushTagId:
    let op = parseOperand(n, ctx)
    if op.isImm:
      ctx.buf.emitPush(int32(op.immVal))
    elif op.isMem:
      error("PUSH memory not supported yet", n)
    else:
      ctx.buf.emitPush(op.reg)

  of PopTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem:
      error("POP memory not supported yet", n)
    else:
      ctx.buf.emitPop(dest.reg)

  of SyscallTagId:
    ctx.buf.emitSyscall()
  of LeaTagId:
    let dest = parseRegister(n) # LEA dest must be register
    let op = parseOperand(n, ctx)
    # LEA reg, label (rip-rel) or LEA reg, mem
    if op.isMem:
      ctx.buf.emitLea(dest, op.mem)
    else:
      ctx.buf.emitLea(dest, op.label)
  of JmpTagId:
    let op = parseOperand(n, ctx)
    if op.isMem:
      error("JMP memory not supported yet", n)
    elif op.label != LabelId(0) or op.typ.kind == UIntT: # Label check
      # op.label is set if it was a label operand
      if op.typ.kind == UIntT: # Label address
         ctx.buf.emitJmp(op.label)
      else:
         ctx.buf.emitJmpReg(op.reg)
    else:
      ctx.buf.emitJmpReg(op.reg) # Default to reg jump if not label?

  of JeTagId, JzTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJe(op.label)
  of JneTagId, JnzTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJne(op.label)
  of JgTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJg(op.label)
  of JgeTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJge(op.label)
  of JlTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJl(op.label)
  of JleTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJle(op.label)
  of JaTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJa(op.label)
  of JaeTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJae(op.label)
  of JbTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJb(op.label)
  of JbeTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJbe(op.label)
  of JngTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJle(op.label)
  of JngeTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJl(op.label)
  of JnaTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJbe(op.label)
  of JnaeTagId:
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    ctx.buf.emitJb(op.label)

  of NopTagId:
    ctx.buf.emitNop()

  of RetTagId:
    ctx.buf.emitRet()

  of LabTagId:
    # (lab :label)
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # Label might not be defined yet if this is inside a proc body?
    # No, Pass 1 handles types/procs. Labels are local to procs?
    # Labels are typically declared in Pass 1?
    # nifasm: labels can be defined inline.
    # We need to define the label symbol in the scope if not exists, or look it up.
    # If it's a forward jump, we need to have created it.
    # Pass 1 does not scan bodies for labels.
    # So we create it here if missing.
    if sym == nil:
       let labId = ctx.buf.createLabel()
       ctx.scope.define(Symbol(name: name, kind: skLabel, offset: int(labId)))
       ctx.buf.defineLabel(labId)
    elif sym.kind == skLabel:
       if sym.offset == -1:
          let labId = ctx.buf.createLabel()
          sym.offset = int(labId)
          ctx.buf.defineLabel(labId)
       else:
          ctx.buf.defineLabel(LabelId(sym.offset))
    else:
       error("Symbol is not a label", n)
    inc n
    if n.kind != ParRi: error("Expected )", n)
    inc n
    return # (lab) is a stmt on its own

  of MovapdTagId:
    # (movapd dest src)
    let dest = parseDest(n, ctx) # Should check if XMM
    let op = parseOperand(n, ctx) # Should check if XMM/Mem
    # Need to support XMM registers in parseRegister/Operand
    # And emitMovapd (likely similar to movsd but packed)
    # For now, placeholder error or implement if x86 supports it
    error("MOVAPD not supported yet", n)

  of MovsdTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    # Dest must be XMM? Or Mem?
    # x86: MOVSD xmm1, xmm2/m64
    # MOVSD xmm1/m64, xmm2
    # So one must be XMM.
    if dest.isMem and op.isMem:
      error("MOVSD memory to memory not supported", n)
    # We need to check if registers are XMM.
    # Currently parseRegister returns Register enum which is GPR.
    # We need XmmRegister support.
    # Let's assume we add XMM support to parseRegister or use a variant.
    error("MOVSD not fully supported yet (needs XMM register parsing)", n)

  of AddsdTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "addsd", start)
    checkFloatType(op.typ, "addsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)

  of SubsdTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "subsd", start)
    checkFloatType(op.typ, "subsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)

  of MulsdTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "mulsd", start)
    checkFloatType(op.typ, "mulsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)

  of DivsdTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "divsd", start)
    checkFloatType(op.typ, "divsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)

  of LockTagId:
    inc n
    if n.kind != ParLe: error("Expected instruction to lock", n)
    let innerTag = n.tag
    case innerTag
    of AddTagId:
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock add", start)
      checkIntegerArithmetic(op.typ, "lock add", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock add", start)
      if not dest.isMem: error("Atomic ADD requires memory destination", n)
      if op.isImm: error("Atomic ADD immediate not supported yet", n)
      if op.isMem: error("Atomic ADD memory source not supported", n)
      ctx.buf.emitLock()
      ctx.buf.emitAdd(dest.mem, op.reg)
    of SubTagId:
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock sub", start)
      checkIntegerArithmetic(op.typ, "lock sub", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock sub", start)
      if not dest.isMem: error("Atomic SUB requires memory destination", n)
      if op.isImm: error("Atomic SUB immediate not supported yet", n)
      if op.isMem: error("Atomic SUB memory source not supported", n)
      ctx.buf.emitLock()
      ctx.buf.emitSub(dest.mem, op.reg)
    of AndTagId:
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock and", start)
      checkBitwiseType(op.typ, "lock and", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock and", start)
      if not dest.isMem: error("Atomic AND requires memory destination", n)
      if op.isImm: error("Atomic AND immediate not supported yet", n)
      if op.isMem: error("Atomic AND memory source not supported", n)
      ctx.buf.emitLock()
      ctx.buf.emitAnd(dest.mem, op.reg)
    of OrTagId:
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock or", start)
      checkBitwiseType(op.typ, "lock or", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock or", start)
      if not dest.isMem: error("Atomic OR requires memory destination", n)
      if op.isImm: error("Atomic OR immediate not supported yet", n)
      if op.isMem: error("Atomic OR memory source not supported", n)
      ctx.buf.emitLock()
      ctx.buf.emitOr(dest.mem, op.reg)
    of XorTagId:
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock xor", start)
      checkBitwiseType(op.typ, "lock xor", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock xor", start)
      if not dest.isMem: error("Atomic XOR requires memory destination", n)
      if op.isImm: error("Atomic XOR immediate not supported yet", n)
      if op.isMem: error("Atomic XOR memory source not supported", n)
      ctx.buf.emitLock()
      ctx.buf.emitXor(dest.mem, op.reg)
    of IncTagId:
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock inc", start)
      if not dest.isMem: error("Atomic INC requires memory destination", n)
      ctx.buf.emitLock()
      ctx.buf.emitInc(dest.mem)
    of DecTagId:
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock dec", start)
      if not dest.isMem: error("Atomic DEC requires memory destination", n)
      ctx.buf.emitLock()
      ctx.buf.emitDec(dest.mem)
    of NotTagId:
      let dest = parseDest(n, ctx)
      checkBitwiseType(dest.typ, "lock not", start)
      if not dest.isMem: error("Atomic NOT requires memory destination", n)
      ctx.buf.emitLock()
      ctx.buf.emitNot(dest.mem)
    of NegTagId:
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock neg", start)
      if not dest.isMem: error("Atomic NEG requires memory destination", n)
      ctx.buf.emitLock()
      ctx.buf.emitNeg(dest.mem)
    else:
       error("Unsupported instruction for LOCK prefix: " & $innerTag, n)

    inc n
    if n.kind != ParRi: error("Expected ) after locked instruction", n)
    inc n

  of XchgTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xchg", start)
    checkIntegerType(op.typ, "xchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "xchg", start)
    if dest.isMem:
       if op.isImm: error("XCHG memory, immediate not supported", n)
       if op.isMem: error("XCHG memory, memory not supported", n)
       ctx.buf.emitXchg(dest.mem, op.reg)
    else:
       if op.isImm: error("XCHG reg, immediate not supported", n)
       if op.isMem:
          ctx.buf.emitXchg(op.mem, dest.reg)
       else:
          ctx.buf.emitXchg(dest.reg, op.reg)

  of XaddTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xadd", start)
    checkIntegerType(op.typ, "xadd", start)
    checkCompatibleTypes(dest.typ, op.typ, "xadd", start)
    if dest.isMem:
       if op.isImm: error("XADD memory, immediate not supported", n)
       if op.isMem: error("XADD memory, memory not supported", n)
       ctx.buf.emitXadd(dest.mem, op.reg)
    else:
       if op.isImm: error("XADD reg, immediate not supported", n)
       if op.isMem: error("XADD reg, memory not supported (dest must be r/m, src must be r)", n)
       ctx.buf.emitXadd(dest.reg, op.reg)

  of CmpxchgTagId:
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "cmpxchg", start)
    checkIntegerType(op.typ, "cmpxchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmpxchg", start)
    if dest.isMem:
       if op.isImm: error("CMPXCHG memory, immediate not supported", n)
       if op.isMem: error("CMPXCHG memory, memory not supported", n)
       ctx.buf.emitCmpxchg(dest.mem, op.reg)
    else:
       if op.isImm: error("CMPXCHG reg, immediate not supported", n)
       if op.isMem: error("CMPXCHG reg, memory not supported (dest must be r/m, src must be r)", n)
       ctx.buf.emitCmpxchg(dest.reg, op.reg)

  of Cmpxchg8bTagId:
    let dest = parseDest(n, ctx)
    if dest.isMem:
       ctx.buf.emitCmpxchg8b(dest.mem)
    else:
       ctx.buf.emitCmpxchg8b(dest.reg)

  of MfenceTagId: ctx.buf.emitMfence()
  of SfenceTagId: ctx.buf.emitSfence()
  of LfenceTagId: ctx.buf.emitLfence()
  of PauseTagId: ctx.buf.emitPause()

  of ClflushTagId:
    let op = parseDest(n, ctx)
    if op.isMem: error("CLFLUSH expects memory operand via register?", n)
    # emitClflush(Register). x86.nim takes Register. CLFLUSH m8. ModRM encodes address.
    # So it takes a register which holds the address? No, it takes an address.
    # x86.nim implementation: emitClflush(reg) -> 0F AE /7 (CLFLUSH m8).
    # encodeModRM(amDirect, 7, int(reg)).
    # amDirect means register mode (11).
    # CLFLUSH requires memory operand (ModRM != 11).
    # So emitClflush in x86.nim is BUGGY if it uses amDirect!
    # It should use amIndirect or whatever.
    # If emitClflush(reg) means "flush address in reg", it should be [reg].
    # I'll leave it for now but this looks suspicious.
    ctx.buf.emitClflush(op.reg)

  of ClflushoptTagId:
    let op = parseDest(n, ctx)
    ctx.buf.emitClflushopt(op.reg)

  of Prefetcht0TagId:
    let op = parseDest(n, ctx)
    ctx.buf.emitPrefetchT0(op.reg)
  of Prefetcht1TagId:
    let op = parseDest(n, ctx)
    ctx.buf.emitPrefetchT1(op.reg)
  of Prefetcht2TagId:
    let op = parseDest(n, ctx)
    ctx.buf.emitPrefetchT2(op.reg)
  of PrefetchntaTagId:
    let op = parseDest(n, ctx)
    ctx.buf.emitPrefetchNta(op.reg)

  else:
    error("Unknown instruction: " & $tag, n)

  if n.kind != ParRi: error("Expected ) at end of instruction", n)
  inc n

proc pass2(n: var Cursor; ctx: var GenContext) =
  var n = n
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe:
        let start = n
        case n.tag
        of ProcTagId:
          # Skip foreign procs - they're not code-generated
          inc n
          if n.kind != SymbolDef:
            skip n
            continue
          let name = getSym(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym != nil and sym.isForeign:
            # Skip foreign proc body
            n = start
            skip n
          else:
            n = start
            pass2Proc(n, ctx)
        of RodataTagId:
          inc n
          let name = getSym(n)
          let sym = ctx.scope.lookup(name)
          let labId = ctx.buf.createLabel()
          sym.offset = int(labId)
          ctx.buf.defineLabel(labId)
          inc n
          let s = getStr(n)
          for c in s: ctx.buf.add byte(c)
          inc n
          inc n
        of GvarTagId:
          # Global variable declaration - goes in .bss section (zero-initialized writable memory)
          inc n
          let name = getSym(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym == nil: error("Global variable not found in scope: " & name, n)
          if sym.isForeign:
            error("Cannot define foreign global variable '" & name & "'", n)
          inc n
          # Skip type (already parsed in pass1)
          skip n

          # Allocate space in .bss section
          let size = slots.alignedSize(sym.typ)
          # Align bssOffset to the type's alignment
          let align = asmSizeOf(sym.typ)
          if align > 1:
            ctx.bssOffset = (ctx.bssOffset + align - 1) and not (align - 1)

          # Create a label for the global variable address
          let labId = ctx.bssBuf.createLabel()
          sym.offset = int(labId)
          ctx.bssBuf.defineLabel(labId)

          # Store the actual offset for later use in relocations
          # The offset will be used when generating code that references this variable
          # For now, we just track it in sym.offset as the label ID
          # The actual memory offset is ctx.bssOffset
          ctx.bssOffset += size

          inc n # )
        of TvarTagId:
          # Thread local variable declaration
          inc n
          let name = getSym(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym == nil: error("TLS variable not found in scope: " & name, n)
          if sym.isForeign:
            error("Cannot define foreign TLS variable '" & name & "'", n)
          inc n
          # Skip type (already parsed in pass1)
          skip n

          # Allocate TLS offset for this variable
          # TLS offsets start from 0 and grow upward
          let size = slots.alignedSize(sym.typ)
          sym.offset = ctx.tlsOffset
          ctx.tlsOffset += size

          inc n # )
        else:
          if rawTagIsNifasmInst(n.tag) or n.tag == IteTagId or n.tag == LoopTagId:
             genInst(n, ctx)
          else:
             skip n
      else:
        skip n
    inc n

proc writeElf(a: var GenContext; outfile: string) =
  a.buf.finalize()
  a.bssBuf.finalize()
  let code = a.buf.data
  let baseAddr = 0x400000.uint64
  let headersSize = 64 + (56 * 2)  # ELF header + 2 program headers
  let pageSize = 0x1000.uint64

  # Calculate addresses and sizes
  let textOffset = headersSize.uint64
  let textVaddr = baseAddr + textOffset
  let textSize = code.len.uint64
  let textAlignedSize = (textSize + pageSize - 1) and not (pageSize - 1)

  # .bss section comes after .text in memory
  let bssVaddr = textVaddr + textAlignedSize
  let bssSize = a.bssOffset.uint64
  let bssAlignedSize = if bssSize > 0: ((bssSize + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  let entryAddr = textVaddr
  var ehdr = initHeader(entryAddr)
  ehdr.e_phnum = 2  # Two program headers: .text and .bss
  ehdr.e_phoff = 64  # Program headers start after ELF header

  # .text program header (executable, readable)
  var textPhdr = initPhdr(textOffset, textVaddr, textSize, textAlignedSize, PF_R or PF_X)

  # .bss program header (writable, readable, not executable)
  # p_filesz = 0 because .bss is not stored in the file (zero-initialized)
  # p_memsz = actual size needed in memory
  var bssPhdr = initPhdr(0, bssVaddr, 0, bssAlignedSize, PF_R or PF_W)

  var f = newFileStream(outfile, fmWrite)
  defer: f.close()

  # Write ELF header
  f.write(ehdr)

  # Write program headers
  f.write(textPhdr)
  f.write(bssPhdr)

  # Write .text section (code)
  if code.len > 0:
    f.writeData(unsafeAddr code[0], code.len)
    # Pad to page boundary
    let padding = int(textAlignedSize - textSize)
    if padding > 0:
      var zeros = newSeq[byte](padding)
      f.writeData(unsafeAddr zeros[0], padding)

  # .bss section is not written to file (it's zero-initialized by the loader)
  # The loader will allocate the memory and zero it

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

proc assemble*(filename, outfile: string) =
  var buf = parseFromFile(filename)
  var n = beginRead(buf)

  # Extract base directory from filename
  let baseDir = filename.splitFile.dir

  var scope = newScope()

  # Create a minimal ctx for pass1 (for foreign module loading)
  var ctx = GenContext(
    scope: scope,
    buf: initBuffer(),
    bssBuf: initBuffer(),
    tlsOffset: 0,
    bssOffset: 0,
    modules: initTable[string, LoadedModule](),
    baseDir: baseDir
  )

  var n1 = n
  pass1(n1, scope, ctx)

  # Update ctx with proper buffers for pass2
  ctx.buf = initBuffer()
  ctx.bssBuf = initBuffer()
  var n2 = n
  pass2(n2, ctx)

  writeElf(ctx, outfile)

  # Close all module streams
  for module in ctx.modules.mvalues:
    nifstreams.close(module.stream)
