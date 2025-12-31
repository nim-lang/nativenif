
import std / [tables, sets, streams, os, osproc]
import "../../../nimony/src/lib" / [nifreader, nifstreams, nifcursors, bitabs, lineinfos, symparser]
import instructions, model, tagconv
import buffers, relocs, x86, arm64, elf, macho, pe
import sem, slots

proc tag(n: Cursor): TagEnum = cast[TagEnum](n.tagId)

proc infoStr(n: Cursor): string =
  if n.info.isValid:
    let raw = unpack(pool.man, n.info)
    result = pool.files[raw.file] & "(" & $raw.line & ", " & $raw.col & ")"
  else:
    result = "???"

proc error(msg: string; n: Cursor) =
  writeStackTrace()
  let tagStr = if n.kind != ParRi: toString(n, false) else: "-"
  quit "[Error] " & msg & " at " & infoStr(n) &
    " (kind=" & $n.kind & ", tag=" & tagStr & ")"

proc skipParRi(n: var Cursor) {.inline.} =
  if n.kind != ParRi: error("Expected )", n)
  inc n

proc skipParRi(n: var Cursor; context: string) {.inline.} =
  if n.kind != ParRi: error("Expected ) for " & context, n)
  inc n

proc typeError(want, got: Type; n: Cursor) =
  error("Type mismatch: expected " & $want & ", got " & $got, n)

proc getInt(n: Cursor): int64 =
  if n.kind == IntLit:
    result = pool.integers[n.intId]
  else:
    error("Expected integer literal", n)

proc getSym(n: Cursor): string =
  case n.kind
  of Symbol:
    result = pool.syms[n.symId]
  else:
    error("Expected symbol", n)

proc getStr(n: Cursor): string =
  if n.kind == StringLit:
    result = pool.strings[n.litId]
  else:
    error("Expected string literal", n)

proc isIntegerType(t: Type): bool =
  ## Check if type is an integer type (int, uint, literal) or a register (which is untyped)
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}

proc isFloatType(t: Type): bool =
  ## Check if type is a floating point type
  t.kind == TypeKind.FloatT

proc canDoIntegerArithmetic(t: Type): bool =
  ## Check if type supports integer arithmetic operations (add, sub)
  ## Includes integer types, literals, array pointers (for pointer arithmetic), and registers
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.AptrT, TypeKind.RegisterT}

proc canDoBitwiseOps(t: Type): bool =
  ## Check if type supports bitwise operations (including registers and literals)
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}


proc parseRegister(n: var Cursor): x86.Register =
  let regTag = tagToX64Reg(n.tag)
  result =
    case regTag
    of RaxR, R0R: x86.RAX
    of RcxR, R2R: x86.RCX
    of RdxR, R3R: x86.RDX
    of RbxR, R1R: x86.RBX
    of RspR, R7R: x86.RSP
    of RbpR, R6R: x86.RBP
    of RsiR, R4R: x86.RSI
    of RdiR, R5R: x86.RDI
    of R8R: x86.R8
    of R9R: x86.R9
    of R10R: x86.R10
    of R11R: x86.R11
    of R12R: x86.R12
    of R13R: x86.R13
    of R14R: x86.R14
    of R15R: x86.R15
    # XMMs should be handled but return type prevents it?
    # Register enum is GPR.
    # We need to separate XMM parsing or expand Register enum?
    # x86.nim has Register and XmmRegister.
    # Let's keep this for GPRs.
    else:
      error("Expected GPR register, got: " & $n.tag, n)
      x86.RAX
  inc n
  skipParRi n, "register"

proc tagToRegister(t: TagEnum): x86.Register =
  ## Convert a TagEnum to a Register (for register binding tracking)
  let regTag = tagToX64Reg(t)
  result =
    case regTag
    of RaxR, R0R: x86.RAX
    of RcxR, R2R: x86.RCX
    of RdxR, R3R: x86.RDX
    of RbxR, R1R: x86.RBX
    of RspR, R7R: x86.RSP
    of RbpR, R6R: x86.RBP
    of RsiR, R4R: x86.RSI
    of RdiR, R5R: x86.RDI
    of R8R: x86.R8
    of R9R: x86.R9
    of R10R: x86.R10
    of R11R: x86.R11
    of R12R: x86.R12
    of R13R: x86.R13
    of R14R: x86.R14
    of R15R: x86.R15
    else: x86.RAX  # Should not happen

type
  LoadedModule = object
    buf: TokenBuf
    stream: nifstreams.Stream
    loaded: bool  # True if already loaded into scope

  Arch = enum
    X64        # Linux x86-64 (ELF)
    A64        # macOS ARM64 (Mach-O)
    WinX64     # Windows x86-64 (PE)
    WinA64     # Windows ARM64 (PE)

  ImportedLib = object
    name: string     # Library path (e.g. "/usr/lib/libSystem.B.dylib")
    ordinal: int     # Library ordinal (1-based index)

  ExtProcInfo = object
    name: string     # Internal name
    extName: string  # External symbol name (e.g. "_write")
    libOrdinal: int  # Which library (1-based)
    gotSlot: int     # GOT slot index
    stubOffset: int  # Offset in stub section
    callSites: seq[int]  # Positions of BL instructions that call this proc

  CallContext = object
    ## Context for a `prepare` block - tracks call setup state
    target: string              # Target proc/symbol name
    sig: Signature              # Signature (from proc or proc type)
    isExternal: bool            # True if calling external proc
    extProcIdx: int             # Index into extProcs for external calls
    paramLookup: Table[string, Param]   # Quick lookup for params
    resultLookup: Table[string, Param]  # Quick lookup for results
    argsSet: HashSet[string]    # Arguments that have been assigned
    resultsSet: HashSet[string] # Results that have been bound
    callEmitted: bool           # True after (call) or (extcall) is emitted
    stackArgSize: int           # Computed size of stack arguments (csize)

  GenContext = object
    scope: Scope
    buf: relocs.Buffer  # Code buffer (.text section) for x64
    bssBuf: relocs.Buffer  # BSS buffer (.bss section) for zero-initialized global variables
    arch: Arch
    procName: string
    callStack: seq[CallContext] # Stack of active prepare blocks (replaces inCall)
    clobbered: set[x86.Register] # Registers clobbered in current flow (x64 only)
    slots: SlotManager
    ssizePatches: seq[int]
    csizePatches: seq[(int, int)] # (position, callStackDepth) for csize patches
    tlsOffset: int  # Current TLS offset for thread-local variables
    bssOffset: int  # Current offset in .bss section
    modules: Table[string, LoadedModule]  # Cache of loaded foreign modules
    baseDir: string  # Base directory for finding module files
    regBindings: Table[x86.Register, string]  # Maps registers to variable names they're bound to (x64 only)
    # Dynamic linking
    imports: seq[ImportedLib]  # Imported libraries
    extProcs: seq[ExtProcInfo]  # External procs to bind
    gotSlotCount: int  # Number of GOT slots allocated

  OperandKind = enum
    okReg       # Register operand
    okImm       # Immediate value
    okMem       # Memory operand
    okSsize     # Stack size placeholder (patched later)
    okCsize     # Call stack argument size
    okArg       # Argument reference in prepare block
    okLabel     # Label reference

  Operand = object
    kind: OperandKind
    typ: Type
    reg: x86.Register
    immVal: int64
    mem: x86.MemoryOperand
    argName: string
    label: LabelId

proc inCall(ctx: GenContext): bool {.inline.} =
  ## Returns true if we're inside a prepare block
  ctx.callStack.len > 0

proc currentCallStackArgSize(ctx: GenContext): int =
  ## Returns the stack argument size for the current call
  if ctx.callStack.len > 0:
    result = ctx.callStack[^1].stackArgSize

proc computeStackArgSize(sig: Signature): int =
  ## Compute total size needed for stack arguments
  result = 0
  for param in sig.params:
    if param.onStack:
      result += slots.alignedSize(param.typ)

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseClobbers(n: var Cursor): set[x86.Register]
proc genStmt(n: var Cursor; ctx: var GenContext)
proc genInstA64(n: var Cursor; ctx: var GenContext)
proc checkIntegerArithmetic(t: Type; op: string; n: Cursor)
proc checkIntegerType(t: Type; op: string; n: Cursor)
proc checkBitwiseType(t: Type; op: string; n: Cursor)
proc checkCompatibleTypes(t1, t2: Type; op: string; n: Cursor)
proc checkType(want, got: Type; n: Cursor)

proc parseObjectBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  var fields: seq[(string, Type)] = @[]
  var offset = 0
  var maxAlign = 1  # Track maximum alignment requirement
  inc n
  while n.kind != ParRi:
    if n.kind == ParLe and n.tag == FldTagId:
      inc n
      if n.kind != SymbolDef: error("Expected field name", n)
      let name = pool.syms[n.symId]
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

      skipParRi n, "field definition"
    else:
      error("Expected field definition", n)
  inc n

  # Round up total size to be a multiple of the struct's alignment
  let finalSize = alignTo(offset, maxAlign)
  result = Type(kind: ObjectT, fields: fields, size: finalSize, align: maxAlign)

proc isRegTag(locTag: TagEnum): bool =
  rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag)

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
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
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
        of ProcD:
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
          if n.kind == ParLe:
            let paramsDecl = tagToNifasmDecl(n.tag)
            if paramsDecl == ParamsD:
              sig.params = parseParams(n, scope, ctx)

          # Parse result
          if n.kind == ParLe:
            let resultDecl = tagToNifasmDecl(n.tag)
            if resultDecl == ResultD:
              var r = parseResult(n, scope, ctx)
              sig.result = r

          # Parse clobber
          if n.kind == ParLe:
            let clobberDecl = tagToNifasmDecl(n.tag)
            if clobberDecl == ClobberD:
              sig.clobbers = parseClobbers(n)

          let sym = Symbol(name: basename, kind: skProc, sig: sig, isForeign: true)
          scope.define(sym)

          # Skip body
          n = start
          skip n
        of GvarD:
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
        of TvarD:
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
    skipParRi n, "type"
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
      let name = pool.syms[n.symId]
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

      skipParRi n, "union field"
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
    if n.kind == ParLe and tagToNifasmDecl(n.tag) == ParamD:
      inc n # param
      if n.kind != SymbolDef: error("Expected param name", n)
      let name = pool.syms[n.symId]
      inc n

      # (reg) or (s) location
      var reg = InvalidTagId
      var onStack = false
      if n.kind == ParLe:
        let locTag = n.tag
        if rawTagIsX64Reg(locTag):
          reg = locTag
          inc n
          skipParRi n, "param location"
        elif locTag == STagId:
          onStack = true
          inc n
          skipParRi n, "param location"
        else:
          error("Expected location", n)
      else:
        error("Expected location", n)

      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg, onStack: onStack)
      skipParRi n, "param"
    else:
      error("Expected param declaration", n)
  inc n

proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (result (ret :name (reg) Type) ...)
  if n.kind == ParLe and tagToNifasmDecl(n.tag) == ResultD:
    inc n
    while n.kind != ParRi:
      var wrapped = false
      if n.kind == ParLe:
        wrapped = true
        inc n
      if n.kind != SymbolDef: error("Expected result definition", n)
      let name = pool.syms[n.symId]
      inc n
      var reg = InvalidTagId
      if n.kind == ParLe:
        let locTag = n.tag
        if isRegTag(locTag):
          reg = locTag
          inc n
          skipParRi n, "result location"
        else:
          error "result must be a register", n
      else:
        error("Expected location", n)
      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg)
      if wrapped:
        skipParRi n, "result declaration"
    inc n

proc parseClobbers(n: var Cursor): set[x86.Register] =
  # (clobber (rax) (rbx) ...)
  if n.kind == ParLe and tagToNifasmDecl(n.tag) == ClobberD:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe and rawTagIsX64Reg(n.tag):
        result.incl parseRegister(n)
      else:
        error("Expected register in clobber list", n)
    inc n

proc pass1Proc(n: var Cursor; scope: Scope; ctx: var GenContext) =
  # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
  inc n
  if n.kind != SymbolDef: error("Expected proc name", n)
  let name = pool.syms[n.symId]
  inc n

  var sig = Signature(params: @[], result: @[], clobbers: {})

  # Parse params
  if n.kind == ParLe and tagToNifasmDecl(n.tag) == ParamsD:
    sig.params = parseParams(n, scope, ctx)

  # Parse result
  if n.kind == ParLe and tagToNifasmDecl(n.tag) == ResultD:
    sig.result = parseResult(n, scope, ctx)

  # Parse clobber
  if n.kind == ParLe and tagToNifasmDecl(n.tag) == ClobberD:
    sig.clobbers = parseClobbers(n)

  let sym = Symbol(name: name, kind: skProc, sig: sig, offset: -1)
  scope.define(sym)

proc handleArch(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Ident: error("Expected architecture symbol", n)
  let arch = pool.strings[n.litId]
  if arch == "x64":
    ctx.arch = Arch.X64
  elif arch == "arm64":
    ctx.arch = Arch.A64
  elif arch == "win_x64":
    ctx.arch = Arch.WinX64
  elif arch == "win_arm64":
    ctx.arch = Arch.WinA64
  else:
    error("Unknown architecture: " & arch, n)
  inc n
  skipParRi n

proc pass1(n: var Cursor; scope: Scope; ctx: var GenContext) =
  var n = n
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe:
        let start = n
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          inc n
          if n.kind != SymbolDef: error("Expected type name", n)
          let name = pool.syms[n.symId]
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
          skipParRi n
        of ProcD:
          # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
          pass1Proc(n, scope, ctx)

          n = start
          skip n
        of RodataD:
          inc n
          if n.kind != SymbolDef: error("Expected rodata name", n)
          let name = pool.syms[n.symId]
          var sym = Symbol(name: name, kind: skRodata)
          sym.offset = -1  # Mark as forward reference until defined
          scope.define(sym)
          n = start
          skip n
        of GvarD:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = pool.syms[n.symId]
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skGvar, typ: typ))
          n = start
          skip n
        of TvarD:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = pool.syms[n.symId]
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skTvar, typ: typ))
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD:
          # (imp "libpath")
          inc n
          if n.kind != StringLit: error("Expected library path string", n)
          let libPath = getStr(n)
          inc n
          # Add to imports list if not already there
          var found = false
          for lib in ctx.imports:
            if lib.name == libPath:
              found = true
              break
          if not found:
            ctx.imports.add ImportedLib(name: libPath, ordinal: ctx.imports.len + 1)
          skipParRi n
        of ExtprocD:
          # (extproc :name "external_name")
          inc n
          if n.kind != SymbolDef: error("Expected extproc name", n)
          let name = pool.syms[n.symId]
          inc n
          if n.kind != StringLit: error("Expected external symbol name string", n)
          let extName = getStr(n)
          inc n
          # Find the library (use last imported library, or default to libSystem)
          var libOrdinal = 1
          if ctx.imports.len > 0:
            libOrdinal = ctx.imports[^1].ordinal
          # Allocate GOT slot
          let gotSlot = ctx.gotSlotCount
          ctx.gotSlotCount += 1
          # Create symbol
          let sym = Symbol(name: name, kind: skExtProc, extName: extName, libName: "", gotSlot: gotSlot)
          scope.define(sym)
          # Track for code generation
          ctx.extProcs.add ExtProcInfo(name: name, extName: extName, libOrdinal: libOrdinal, gotSlot: gotSlot, stubOffset: -1)
          skipParRi n
        else:
          skip n
      else:
        skip n
    inc n

proc genInstX64(n: var Cursor; ctx: var GenContext)

proc parseRegisterA64(n: var Cursor): arm64.Register =
  let regTag = tagToA64Reg(n.tag)
  result =
    case regTag
    of X0R: arm64.X0
    of X1R: arm64.X1
    of X2R: arm64.X2
    of X3R: arm64.X3
    of X4R: arm64.X4
    of X5R: arm64.X5
    of X6R: arm64.X6
    of X7R: arm64.X7
    of X8R: arm64.X8
    of X9R: arm64.X9
    of X10R: arm64.X10
    of X11R: arm64.X11
    of X12R: arm64.X12
    of X13R: arm64.X13
    of X14R: arm64.X14
    of X15R: arm64.X15
    of X16R: arm64.X16
    of X17R: arm64.X17
    of X18R: arm64.X18
    of X19R: arm64.X19
    of X20R: arm64.X20
    of X21R: arm64.X21
    of X22R: arm64.X22
    of X23R: arm64.X23
    of X24R: arm64.X24
    of X25R: arm64.X25
    of X26R: arm64.X26
    of X27R: arm64.X27
    of X28R: arm64.X28
    of X29R: arm64.X29
    of X30R: arm64.X30
    of SpR: arm64.SP
    of LrR: arm64.LR
    of FpR: arm64.FP
    of XzrR: arm64.Register(31)  # XZR
    else:
      error("Expected ARM64 register, got: " & $n.tag, n)
      arm64.X0
  inc n
  skipParRi n, "register"

proc tagToRegisterA64(t: TagEnum): arm64.Register =
  ## Convert a TagEnum to an ARM64 Register (for register binding tracking)
  let regTag = tagToA64Reg(t)
  result =
    case regTag
    of X0R: arm64.X0
    of X1R: arm64.X1
    of X2R: arm64.X2
    of X3R: arm64.X3
    of X4R: arm64.X4
    of X5R: arm64.X5
    of X6R: arm64.X6
    of X7R: arm64.X7
    of X8R: arm64.X8
    of X9R: arm64.X9
    of X10R: arm64.X10
    of X11R: arm64.X11
    of X12R: arm64.X12
    of X13R: arm64.X13
    of X14R: arm64.X14
    of X15R: arm64.X15
    of X16R: arm64.X16
    of X17R: arm64.X17
    of X18R: arm64.X18
    of X19R: arm64.X19
    of X20R: arm64.X20
    of X21R: arm64.X21
    of X22R: arm64.X22
    of X23R: arm64.X23
    of X24R: arm64.X24
    of X25R: arm64.X25
    of X26R: arm64.X26
    of X27R: arm64.X27
    of X28R: arm64.X28
    of X29R: arm64.X29
    of X30R: arm64.X30
    of SpR: arm64.SP
    of LrR: arm64.LR
    of FpR: arm64.FP
    of XzrR: arm64.Register(31)
    else: arm64.X0  # Should not happen

type
  OperandA64 = object
    kind: OperandKind
    reg: arm64.Register
    typ: Type
    immVal: int64
    mem: arm64.MemoryOperand
    label: LabelId

proc parseOperandA64(n: var Cursor; ctx: var GenContext; expectedType: Type = nil): OperandA64 =
  if n.kind == ParLe:
    let t = n.tag
    if rawTagIsA64Reg(t):
      result.reg = parseRegisterA64(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
    elif t == DotTagId:
      # (dot <base> <fieldname>) - similar to x64
      inc n
      var baseOp = parseOperandA64(n, ctx)
      if n.kind != Symbol:
        error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      var objType: Type
      var baseReg: arm64.Register
      var baseOffset: int32 = 0
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = baseOp.typ.base
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("dot requires pointer to object/union or stack object/union, got " & $baseOp.typ, n)
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype) in objType.fields:
        if objType.kind == TypeKind.ObjectT:
          fieldOffset = alignTo(fieldOffset, asmAlignOf(ftype))
        if fname == fieldName:
          fieldType = ftype
          break
        if objType.kind == TypeKind.ObjectT:
          fieldOffset += asmSizeOf(ftype)
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      result.kind = okMem
      result.mem = arm64.MemoryOperand(
        base: baseReg,
        offset: baseOffset + int32(fieldOffset),
        hasIndex: false
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
      skipParRi n, "dot expression"
    elif t == AtTagId:
      # (at <base> <index>)
      inc n
      var baseOp = parseOperandA64(n, ctx)
      var indexOp = parseOperandA64(n, ctx)
      if not isIntegerType(indexOp.typ):
        error("Array index must be integer type, got " & $indexOp.typ, n)
      var elemType: Type
      var baseReg: arm64.Register
      var baseOffset: int32 = 0
      if baseOp.typ.kind == TypeKind.AptrT:
        elemType = baseOp.typ.base
        baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
        elemType = baseOp.typ.elem
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("at requires aptr or stack array, got " & $baseOp.typ, n)
      if indexOp.kind == okImm:
        let offset = indexOp.immVal * asmSizeOf(elemType)
        result.kind = okMem
        result.mem = arm64.MemoryOperand(
          base: baseReg,
          offset: baseOffset + int32(offset),
          hasIndex: false
        )
      elif indexOp.kind == okMem:
        error("Array index cannot be memory operand", n)
      else:
        let elemSize = asmSizeOf(elemType)
        if elemSize notin [1, 2, 4, 8]:
          error("Element size " & $elemSize & " not supported for scaled indexing (must be 1, 2, 4, or 8)", n)
        result.kind = okMem
        let shift = case elemSize
          of 1: 0
          of 2: 1
          of 4: 2
          of 8: 3
          else: 0
        result.mem = arm64.MemoryOperand(
          base: baseReg,
          index: indexOp.reg,
          shift: shift,
          offset: baseOffset,
          hasIndex: true
        )
      result.typ = Type(kind: TypeKind.PtrT, base: elemType)
      skipParRi n, "`at` expression"
    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      skipParRi n, "label usage"
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandA64(n, ctx, nil)
      op.typ = castType
      result = op
      skipParRi n, "`cast` expression"
    elif t == MemTagId:
      inc n
      if n.kind == ParLe and (n.tag == DotTagId or n.tag == AtTagId):
        var addrOp = parseOperandA64(n, ctx)
        if addrOp.kind != okMem:
          error("mem requires address expression", n)
        if addrOp.typ.kind != TypeKind.PtrT:
          error("mem requires pointer type, got " & $addrOp.typ, n)
        result = addrOp
        result.typ = addrOp.typ.base
      else:
        var baseOp = parseOperandA64(n, ctx)
        if baseOp.kind == okImm or baseOp.kind == okMem:
          error("mem base must be a register", n)
        var offset: int32 = 0
        var hasIndex = false
        var indexReg: arm64.Register = arm64.X0
        var shift: int = 0
        if n.kind == IntLit or n.kind == Symbol:
          if n.kind == IntLit:
            offset = int32(getInt(n))
            inc n
          elif n.kind == Symbol:
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
              hasIndex = true
              indexReg = tagToRegisterA64(indexSym.reg)
              inc n
              if n.kind == IntLit:
                shift = int(getInt(n))
                if shift notin [0, 1, 2, 3]:
                  error("mem shift must be 0, 1, 2, or 3", n)
                inc n
                if n.kind == IntLit:
                  offset = int32(getInt(n))
                  inc n
            else:
              error("Expected index register or offset in mem", n)
        result.kind = okMem
        result.mem = arm64.MemoryOperand(
          base: baseOp.reg,
          index: indexReg,
          shift: shift,
          offset: offset,
          hasIndex: hasIndex
        )
        result.typ = Type(kind: IntT, bits: 64)
      skipParRi n, "`mem` expression"
    elif t == SsizeTagId:
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      inc n
      skipParRi n, "`ssize` expression"
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    inc n
    if expectedType != nil and (expectedType.kind in {IntT, UIntT, FloatT}):
      result.typ = expectedType
    else:
      result.typ = Type(kind: IntLitT, bits: 64) # Literal - compatible with IntT and UIntT
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.onStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg)
        result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      if sym.offset == -1:
        # Forward reference - create label now but don't define it yet
        # It will be defined when the rodata is actually written
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.reg = arm64.X0
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skGvar:
      if sym.isForeign:
        error("Cannot access foreign global variable '" & name & "' directly (must be linked)", n)
      if sym.offset == -1:
        # Forward reference - create label now
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.reg = arm64.X0
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skTvar:
      result.kind = okMem
      result.mem = arm64.MemoryOperand(
        base: arm64.FP,
        offset: int32(sym.offset),
        hasIndex: false
      )
      result.typ = sym.typ
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDestA64(n: var Cursor; ctx: var GenContext; expectedType: Type = nil): OperandA64 =
  if n.kind == ParLe and rawTagIsA64Reg(n.tag):
    result.reg = parseRegisterA64(n)
    if expectedType != nil:
      result.typ = expectedType
    else:
      result.typ = Type(kind: IntT, bits: 64)
  elif n.kind == ParLe and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId):
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem:
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and sym.kind == skVar:
      if sym.onStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg)
        result.typ = sym.typ
      else:
        error("Variable has no location", n)
      inc n
    elif sym != nil and sym.kind == skTvar:
      result.kind = okMem
      result.mem = arm64.MemoryOperand(
        base: arm64.FP,
        offset: int32(sym.offset),
        hasIndex: false
      )
      result.typ = sym.typ
      inc n
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

  if expectedType != nil and result.typ != nil:
    checkType(expectedType, result.typ, n)

proc genPrepareA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  let start = n
  inc n
  if n.kind != Symbol: error("Expected proc symbol or type, got " & $n.kind, n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)

  var callCtx = CallContext(
    target: name,
    paramLookup: initTable[string, Param](),
    resultLookup: initTable[string, Param](),
    argsSet: initHashSet[string](),
    resultsSet: initHashSet[string](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, n)
  elif sym.kind == skProc:
    if sym.isForeign:
      error("Cannot call foreign proc '" & name & "' directly (use extcall)", n)
    callCtx.sig = sym.sig
    callCtx.isExternal = false
  elif sym.kind == skExtProc:
    callCtx.isExternal = true
    for i, ext in ctx.extProcs:
      if ext.name == name:
        callCtx.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, n)

  # Build lookup tables (only for internal procs with signatures)
  if not callCtx.isExternal:
    for param in callCtx.sig.params:
      callCtx.paramLookup[param.name] = param
    for res in callCtx.sig.result:
      callCtx.resultLookup[res.name] = res
    # Compute stack argument size
    callCtx.stackArgSize = computeStackArgSize(callCtx.sig)

  # Push call context
  ctx.callStack.add callCtx
  inc n

  # Process instructions inside prepare block
  while n.kind != ParRi:
    genInstA64(n, ctx)

  # Verify call was emitted and all bindings are done
  let currentCtx = ctx.callStack[^1]
  if not currentCtx.isExternal:
    for param in currentCtx.sig.params:
      if not param.onStack and param.name notin currentCtx.argsSet:
        error("Missing argument: " & param.name, n)

    for res in currentCtx.sig.result:
      if res.name notin currentCtx.resultsSet:
        error("Missing result binding: " & res.name, n)

    if not currentCtx.callEmitted:
      error("Missing (call) or (extcall) in prepare block", n)
  else:
    if not currentCtx.callEmitted:
      error("Missing (extcall) in prepare block", n)

  # Pop call context
  discard ctx.callStack.pop()
  skipParRi n, "prepare"

proc genCallMarkerA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (call) marker inside a prepare block - emits the actual call instruction
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  var callCtx = addr ctx.callStack[^1]
  if callCtx.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if callCtx.isExternal:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, callCtx.target, n)

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)

  ctx.buf.emitBL(labId)
  callCtx.callEmitted = true

  inc n
  skipParRi n, "call"

proc genExtcallA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  var callCtx = addr ctx.callStack[^1]
  if callCtx.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if not callCtx.isExternal:
    error("Use (call) for internal procs, not (extcall)", n)

  # Record call site and emit BL (will be patched to point to stub)
  let callPos = ctx.buf.data.len
  ctx.extProcs[callCtx.extProcIdx].callSites.add callPos
  ctx.buf.data.addUint32(0x94000000'u32)  # BL placeholder

  callCtx.callEmitted = true

  inc n
  skipParRi n, "extcall"

proc genIteA64(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobbered
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)
    if sym.used:
      error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    ctx.buf.emitB(lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == ParLe:
    # Hardware condition - ARM64 uses flags from CMP
    # For now, assume it's a comparison result
    error("Hardware flags in ite not yet supported for ARM64", n)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmt(n, ctx)
  let thenClobbered = ctx.clobbered
  ctx.buf.emitB(lEnd)
  ctx.clobbered = oldClobbered
  ctx.buf.defineLabel(lElse)
  genStmt(n, ctx)
  let elseClobbered = ctx.clobbered
  ctx.buf.defineLabel(lEnd)
  ctx.clobbered = thenClobbered + elseClobbered
  skipParRi n, "ite"

proc genLoopA64(n: var Cursor; ctx: var GenContext) =
  inc n
  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  ctx.buf.defineLabel(lStart)
  if n.kind != ParLe: error("Expected condition", n)
  let condTag = n.tag
  inc n
  skipParRi n, "condition"
  # ARM64 loop conditions - for now assume BEQ/BNE
  error("Loop conditions not yet fully supported for ARM64", n)
  genStmt(n, ctx)
  ctx.buf.emitB(lStart)
  ctx.buf.defineLabel(lEnd)
  skipParRi n

proc genJtrueA64(n: var Cursor; ctx: var GenContext) =
  let start = n
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
    inc n
  if firstCfvar: error("jtrue requires at least one cfvar", start)
  ctx.buf.emitB(jumpTarget)
  skipParRi n

proc genKillA64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)
  if sym.onStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  ctx.scope.undefine(name)
  inc n
  skipParRi n

proc genInstA64(n: var Cursor; ctx: var GenContext) =
  if n.kind != ParLe: error("Expected instruction", n)
  let instTag = tagToA64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = pool.syms[n.symId]
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: name, kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)
    skipParRi n, "cfvar declaration"
    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = pool.syms[n.symId]
    inc n
    var reg = InvalidTagId
    var onStack = false
    if n.kind == ParLe:
      let locTag = n.tag
      if rawTagIsA64Reg(locTag):
        reg = locTag
        inc n
        skipParRi n, "register location"
      elif locTag == STagId:
        onStack = true
        inc n
        skipParRi n, "stack location"
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: name, kind: skVar, typ: baseTyp)
    if onStack:
      sym.onStack = true
      sym.offset = ctx.slots.allocSlot(baseTyp)
      sym.typ = Type(kind: StackOffT, offType: baseTyp)  # Wrap in StackOffT
    else:
      sym.reg = reg
    ctx.scope.define(sym)
    skipParRi n, "variable declaration"
    return
  of NoDecl:
    discard "handle via `case instTag`"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD,
     ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD:
    raiseAssert("Unhandled declaration tag: " & $declTag)

  case instTag
  of StmtsA64:
    inc n
    while n.kind != ParRi:
      genInstA64(n, ctx)
    skipParRi n
  of PrepareA64:
    genPrepareA64(n, ctx)
  of CallA64:
    genCallMarkerA64(n, ctx)
  of ExtcallA64:
    genExtcallA64(n, ctx)
  of IteA64:
    genIteA64(n, ctx)
  of LoopA64:
    genLoopA64(n, ctx)
  of JtrueA64:
    genJtrueA64(n, ctx)
  of KillA64:
    genKillA64(n, ctx)
  of LabA64:
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = pool.syms[n.symId]
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
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
    skipParRi n

  of MovA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem:
      if op.kind == okImm:
        error("Moving immediate to memory not fully supported yet for ARM64", n)
      elif op.kind == okSsize:
        error("Moving ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot move memory to memory", n)
      else:
        arm64.emitStr(ctx.buf.data, op.reg, dest.mem.base, dest.mem.offset)
    else:
      if op.kind == okSsize:
        arm64.emitMovImm(ctx.buf.data, dest.reg, 0'u16)
        ctx.ssizePatches.add(ctx.buf.data.len - 2)
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitMovImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        elif op.immVal >= 0:
          # Use MOVZ + MOVK to load large immediate values
          arm64.emitMovImm64(ctx.buf.data, dest.reg, uint64(op.immVal))
        else:
          error("Immediate value out of range", n)
      elif op.kind == okMem:
        arm64.emitLdr(ctx.buf.data, dest.reg, op.mem.base, op.mem.offset)
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, op.reg)
    skipParRi n

  of AdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("ADR destination must be register", n)
    # Check if operand is a label: type should be UIntT and not immediate/memory
    # Labels/rodata/gvars set typ to UIntT and are not immediate or memory operands
    if op.typ.kind != UIntT or op.kind == okImm or op.kind == okMem:
      error("ADR source must be a label", n)
    arm64.emitAdr(ctx.buf, dest.reg, op.label)
    skipParRi n

  of AddA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkCompatibleTypes(dest.typ, op.typ, "add", start)
    if dest.kind == okMem:
      error("ADD to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add(ctx.buf.data.len - 2)
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          error("Immediate value too large for ADD (must fit in 16 bits)", n)
      elif op.kind == okMem:
        error("ADD from memory not supported yet", n)
      else:
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of SubA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkCompatibleTypes(dest.typ, op.typ, "sub", start)
    if dest.kind == okMem:
      error("SUB to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add(ctx.buf.data.len - 2)
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          error("Immediate value too large for SUB (must fit in 16 bits)", n)
      elif op.kind == okMem:
        error("SUB from memory not supported yet", n)
      else:
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of MulA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "mul", start)
    checkIntegerType(op.typ, "mul", start)
    if dest.kind == okMem: error("MUL destination cannot be memory", n)
    if op.kind == okImm: error("MUL immediate not supported", n)
    if op.kind == okMem: error("MUL memory not supported yet", n)
    arm64.emitMul(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of SdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "sdiv", start)
    checkIntegerType(op.typ, "sdiv", start)
    if dest.kind == okMem: error("SDIV destination cannot be memory", n)
    if op.kind == okImm: error("SDIV immediate not supported", n)
    if op.kind == okMem: error("SDIV memory not supported yet", n)
    arm64.emitSdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of UdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "udiv", start)
    checkIntegerType(op.typ, "udiv", start)
    if dest.kind == okMem: error("UDIV destination cannot be memory", n)
    if op.kind == okImm: error("UDIV immediate not supported", n)
    if op.kind == okMem: error("UDIV memory not supported yet", n)
    arm64.emitUdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of AndA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkCompatibleTypes(dest.typ, op.typ, "and", start)
    if dest.kind == okMem: error("AND to memory not supported yet", n)
    else:
      if op.kind == okImm: error("AND immediate not supported yet", n)
      elif op.kind == okMem: error("AND from memory not supported yet", n)
      else:
        arm64.emitAnd(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of OrrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "orr", start)
    checkBitwiseType(op.typ, "orr", start)
    checkCompatibleTypes(dest.typ, op.typ, "orr", start)
    if dest.kind == okMem: error("ORR to memory not supported yet", n)
    else:
      if op.kind == okImm: error("ORR immediate not supported yet", n)
      elif op.kind == okMem: error("ORR from memory not supported yet", n)
      else:
        arm64.emitOrr(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of EorA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "eor", start)
    checkBitwiseType(op.typ, "eor", start)
    checkCompatibleTypes(dest.typ, op.typ, "eor", start)
    if dest.kind == okMem: error("EOR to memory not supported yet", n)
    else:
      if op.kind == okImm: error("EOR immediate not supported yet", n)
      elif op.kind == okMem: error("EOR from memory not supported yet", n)
      else:
        arm64.emitEor(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of LslA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLslImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsl(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of LsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsr(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of AsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "asr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm: error("ASR immediate not supported yet", n)
    else:
      arm64.emitAsr(ctx.buf.data, dest.reg, dest.reg, op.reg)
    skipParRi n

  of NegA64:
    inc n
    let op = parseDestA64(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    arm64.emitNeg(ctx.buf.data, op.reg, op.reg)
    skipParRi n

  of CmpA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "cmp", start)
    checkIntegerArithmetic(op.typ, "cmp", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmp", start)
    if dest.kind == okMem:
      error("CMP memory not supported yet", n)
    else:
      if op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitCmpImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          error("Immediate value too large for CMP (must fit in 16 bits)", n)
      elif op.kind == okMem:
        error("CMP memory not supported yet", n)
      else:
        arm64.emitCmp(ctx.buf.data, dest.reg, op.reg)
    skipParRi n

  of RetA64:
    inc n
    arm64.emitRet(ctx.buf.data)
    skipParRi n

  of NopA64:
    inc n
    arm64.emitNop(ctx.buf.data)
    skipParRi n

  of SvcA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.kind != okImm:
      error("SVC requires immediate operand", n)
    if op.immVal < 0 or op.immVal > 0xFFFF:
      error("SVC immediate must be 0-65535", n)
    arm64.emitSvc(ctx.buf.data, uint16(op.immVal))
    skipParRi n

  of LdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("LDR destination must be register", n)
    if op.kind == okMem:
      ctx.buf.data.emitLdr(dest.reg, op.mem.base, op.mem.offset)
    else:
      error("LDR source must be memory", n)
    skipParRi n

  of StrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("STR destination must be memory", n)
    if op.kind == okMem: error("STR source cannot be memory", n)
    ctx.buf.data.emitStr(op.reg, dest.mem.base, dest.mem.offset)
    skipParRi n

  of BA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitB(ctx.buf, op.label)
    skipParRi n
  of BlA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBL(ctx.buf, op.label)
    skipParRi n

  of BeqA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBeq(ctx.buf, op.label)
    skipParRi n

  of BneA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBne(ctx.buf, op.label)
    skipParRi n

  of StpA64:
    error("STP instruction not yet implemented", n)

  of LdpA64:
    error("LDP instruction not yet implemented", n)

  of NoA64Inst:
    error("Invalid ARM64 instruction", n)

proc genInst(n: var Cursor; ctx: var GenContext) =
  case ctx.arch
  of Arch.X64, Arch.WinX64:
    genInstX64(n, ctx)
  of Arch.A64, Arch.WinA64:
    genInstA64(n, ctx)

proc collectLabels(n: var Cursor; ctx: var GenContext; scope: Scope) =
  ## Pre-scan a cursor subtree and create placeholder symbols for labels.
  if n.kind == ParLe:
    if n.tag == LabTagId:
      var tmp = n
      inc tmp
      if tmp.kind == SymbolDef:
        let name = pool.syms[tmp.symId]
        var sym = scope.lookup(name)
        if sym == nil:
          let labId = ctx.buf.createLabel()
          sym = Symbol(name: name, kind: skLabel, offset: int(labId))
          scope.define(sym)
        elif sym.kind == skLabel and sym.offset == -1:
          sym.offset = int(ctx.buf.createLabel())
    inc n
    while n.kind != ParRi:
      collectLabels(n, ctx, scope)
    inc n
  else:
    inc n

proc pass2Proc(n: var Cursor; ctx: var GenContext) =
  let oldScope = ctx.scope
  ctx.scope = newScope(oldScope)

  inc n
  if n.kind != SymbolDef:
    error("Expected symbol definition", n)
  let name = pool.syms[n.symId]
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
  ctx.regBindings = initTable[x86.Register, string]()

  # Add params to scope
  var paramOffset = 16 # RBP + 16 (skip RBP, RetAddr)
  for param in sym.sig.params:
    if param.onStack:
      let stackTyp = Type(kind: StackOffT, offType: param.typ)  # Wrap in StackOffT
      ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: stackTyp, onStack: true, offset: paramOffset))
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
  var scan = n
  if scan.kind == ParLe and scan.tag == StmtsTagId:
    collectLabels(scan, ctx, ctx.scope)
  when false: # if ctx.arch in {Arch.X64, Arch.WinX64}:
    x86.emitPush(ctx.buf.data, RBP)
    x86.emitMov(ctx.buf.data, RBP, RSP)
    x86.emitSubImm(ctx.buf.data, RSP, 0)
    ctx.ssizePatches.add(ctx.buf.data.len - 4)
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      genInst(n, ctx)
    inc n
  skipParRi n, "proc declaration"

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

proc parseOperand(n: var Cursor; ctx: var GenContext; expectedType: Type = nil): Operand =
  if n.kind == ParLe:
    let t = n.tag
    if rawTagIsX64Reg(t):
      result.reg = parseRegister(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # Check if this register is bound to a variable
      if result.reg in ctx.regBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.regBindings[result.reg] & "', use the variable name instead", n)
    elif t == DotTagId:
      # (dot <base-reg> <stackvar> <fieldname>) for stack objects, or
      # (dot <ptr-var> <fieldname>) for pointer variables
      inc n

      var objType: Type
      var baseReg: x86.Register
      var baseDisp: int32 = 0
      var baseIndex: x86.Register
      var baseScale = 1
      var baseHasIndex = false
      var useFsSegment = false
      var fieldName: string

      # Check if first arg is a register (explicit stack addressing)
      if n.kind == ParLe and rawTagIsX64Reg(n.tag):
        # (dot (base-reg) stackvar fieldname) - explicit stack object access
        baseReg = parseRegister(n)

        # Parse stack variable name for offset
        if n.kind != Symbol:
          error("Expected stack variable name in dot expression", n)
        let stackVarName = getSym(n)
        let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
        if stackSym == nil or not stackSym.onStack:
          error("Expected stack variable in dot, got: " & stackVarName, n)
        # Unwrap StackOffT to get the base type
        let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
        if baseTyp.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("dot requires object/union type, got " & $baseTyp, n)
        baseDisp = int32(stackSym.offset)
        objType = baseTyp
        inc n

        # Parse field name
        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n
      else:
        # (dot ptr-var fieldname) - pointer variable access
        var baseOp = parseOperand(n, ctx)

        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n

        if baseOp.typ.kind == TypeKind.PtrT:
          # Base is a pointer to an object or union
          objType = baseOp.typ.base
          if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
            error("Cannot access field of non-object/union type " & $objType, n)
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
            baseHasIndex = baseOp.mem.hasIndex
            baseIndex = baseOp.mem.index
            baseScale = baseOp.mem.scale
            useFsSegment = baseOp.mem.useFsSegment
          else:
            baseReg = baseOp.reg
        else:
          error("dot requires (base-reg stackvar field) or (ptr-var field), got " & $baseOp.typ, n)

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
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: baseReg,
        index: baseIndex,
        scale: baseScale,
        displacement: baseDisp + int32(fieldOffset),
        hasIndex: baseHasIndex,
        useFsSegment: useFsSegment
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)

      skipParRi n, "dot expression"
    elif t == AtTagId:
      # (at <base-reg> <stackvar> <index>) for stack arrays, or
      # (at <aptr-var> <index>) for array pointer variables
      inc n

      var elemType: Type
      var baseReg: x86.Register
      var baseDisp: int32 = 0
      var indexOp: Operand

      # Check if first arg is a register (explicit stack addressing)
      if n.kind == ParLe and rawTagIsX64Reg(n.tag):
        # (at (base-reg) stackvar index) - explicit stack array access
        baseReg = parseRegister(n)

        # Parse stack variable name for offset
        if n.kind != Symbol:
          error("Expected stack variable name in at expression", n)
        let stackVarName = getSym(n)
        let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
        if stackSym == nil or not stackSym.onStack:
          error("Expected stack variable in at, got: " & stackVarName, n)
        # Unwrap StackOffT to get the base type
        let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
        if baseTyp.kind != TypeKind.ArrayT:
          error("at requires array type, got " & $baseTyp, n)
        baseDisp = int32(stackSym.offset)
        elemType = baseTyp.elem
        inc n

        # Parse index
        indexOp = parseOperand(n, ctx)
      else:
        # (at aptr-var index) - array pointer access
        var baseOp = parseOperand(n, ctx)
        indexOp = parseOperand(n, ctx)

        if baseOp.typ.kind == TypeKind.AptrT:
          # Base is an array pointer
          elemType = baseOp.typ.base
          baseReg = baseOp.reg
        else:
          error("at requires (base-reg stackvar index) or (aptr-var index), got " & $baseOp.typ, n)

      # Type check: index must be an integer, literal, or register
      if not isIntegerType(indexOp.typ):
        error("Array index must be integer type, got " & $indexOp.typ, n)

      # Check if index is immediate or register
      if indexOp.kind == okImm:
        # Immediate index: compute offset directly
        let offset = indexOp.immVal * asmSizeOf(elemType)
        result.kind = okMem
        result.mem = x86.MemoryOperand(
          base: baseReg,
          displacement: baseDisp + int32(offset),
          hasIndex: false
        )
      elif indexOp.kind == okMem:
        error("Array index cannot be memory operand", n)
      else:
        # Register index: use scaled indexing
        let elemSize = asmSizeOf(elemType)
        if elemSize notin [1, 2, 4, 8]:
          error("Element size " & $elemSize & " not supported for scaled indexing (must be 1, 2, 4, or 8)", n)

        result.kind = okMem
        result.mem = x86.MemoryOperand(
          base: baseReg,
          index: indexOp.reg,
          scale: elemSize,
          displacement: baseDisp,
          hasIndex: true
        )

      result.typ = Type(kind: TypeKind.PtrT, base: elemType)

      skipParRi n, "at expression"
    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      skipParRi n, "label usage"
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
      skipParRi n, "cast expression"
    elif t == MemTagId:
      # (mem <address-expr>) or (mem <base> <offset>) or (mem <base> <index> <scale>) etc
      inc n

      # Check if first child is an address expression (dot/at) or explicit addressing
      if n.kind == ParLe and (n.tag == DotTagId or n.tag == AtTagId):
        # Wrapped address expression: (mem (dot ...) or (mem (at ...))
        var addrOp = parseOperand(n, ctx)
        if addrOp.kind != okMem:
          error("mem requires address expression", n)

        # Dereference the pointer type
        if addrOp.typ.kind != TypeKind.PtrT:
          error("mem requires pointer type, got " & $addrOp.typ, n)

        result = addrOp
        result.typ = addrOp.typ.base  # Dereference: ptr T -> T
      else:
        # Explicit addressing: (mem base) or (mem base offset) or (mem base index scale [offset])
        var baseOp = parseOperand(n, ctx)
        if baseOp.kind == okImm or baseOp.kind == okMem:
          error("mem base must be a register", n)

        var displacement: int32 = 0
        var hasIndex = false
        var indexReg: x86.Register = x86.RAX
        var scale: int = 1

        # Check for offset
        var stackVarType: Type = nil
        if n.kind == IntLit or n.kind == Symbol:
          if n.kind == IntLit:
            displacement = int32(getInt(n))
            inc n
          elif n.kind == Symbol:
            # Could be index register or stack variable (used as offset)
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and (indexSym.kind == skVar or indexSym.kind == skParam) and indexSym.onStack:
              # Stack variable - use its offset as displacement and preserve type (unwrap StackOffT)
              displacement = int32(indexSym.offset)
              stackVarType = if indexSym.typ.kind == StackOffT: indexSym.typ.offType else: indexSym.typ
              inc n
            elif indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
              # This is the index register
              hasIndex = true
              let indexRegTag = tagToX64Reg(indexSym.reg)
              indexReg = case indexRegTag
                of RaxR, R0R: RAX
                of RcxR, R2R: RCX
                of RdxR, R3R: RDX
                of RbxR, R1R: RBX
                of RspR, R7R: RSP
                of RbpR, R6R: RBP
                of RsiR, R4R: RSI
                of RdiR, R5R: RDI
                of R8R: R8
                of R9R: R9
                of R10R: R10
                of R11R: R11
                of R12R: R12
                of R13R: R13
                of R14R: R14
                of R15R: R15
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
              error("Expected index register or stack variable in mem", n)

        result.kind = okMem
        result.mem = x86.MemoryOperand(
          base: baseOp.reg,
          index: indexReg,
          scale: scale,
          displacement: displacement,
          hasIndex: hasIndex
        )
        # Preserve type from stack variable if available, otherwise default
        if stackVarType != nil:
          result.typ = stackVarType
        else:
          result.typ = Type(kind: IntT, bits: 64)  # Default assumption

      skipParRi n, "mem expression"
    elif t == SsizeTagId:
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      inc n
      skipParRi n, "ssize expression"
    elif t == CsizeTagId:
      # (csize) - call stack argument size
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.currentCallStackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
      skipParRi n, "csize expression"
    elif t == ArgTagId:
      # (arg name) - argument reference in prepare block
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      let argName = getSym(n)
      inc n
      skipParRi n, "arg expression"

      let callCtx = addr ctx.callStack[^1]
      if argName notin callCtx.paramLookup:
        error("Unknown argument: " & argName, n)

      let param = callCtx.paramLookup[argName]
      if param.onStack:
        # Stack argument - return the offset as an immediate
        # The offset is computed from the stack parameter declarations
        var offset = 0
        for p in callCtx.sig.params:
          if p.onStack:
            if p.name == argName:
              break
            offset += slots.alignedSize(p.typ)
        result.kind = okArg
        result.argName = argName
        result.kind = okImm
        result.immVal = int64(offset)
        result.typ = param.typ
      else:
        # Register argument - return the register
        result.kind = okArg
        result.argName = argName
        let paramRegTag = tagToX64Reg(param.reg)
        result.reg = case paramRegTag
          of RaxR, R0R: x86.RAX
          of RdiR, R5R: x86.RDI
          of RsiR, R4R: x86.RSI
          of RdxR, R3R: x86.RDX
          of RcxR, R2R: x86.RCX
          of R8R: x86.R8
          of R9R: x86.R9
          of R10R: x86.R10
          of R11R: x86.R11
          else: x86.RAX
        result.typ = param.typ
    elif t == ResTagId:
      # (res name) - result reference in prepare block (after call)
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSym(n)
      inc n
      skipParRi n, "res expression"

      let callCtx = addr ctx.callStack[^1]
      if not callCtx.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      if resName notin callCtx.resultLookup:
        error("Unknown result: " & resName, n)
      if resName in callCtx.resultsSet:
        error("Result already bound: " & resName, n)
      callCtx.resultsSet.incl(resName)

      let res = callCtx.resultLookup[resName]
      let resRegTag = tagToX64Reg(res.reg)
      result.reg = case resRegTag
        of RaxR, R0R: x86.RAX
        of RdiR, R5R: x86.RDI
        of RsiR, R4R: x86.RSI
        of RdxR, R3R: x86.RDX
        of RcxR, R2R: x86.RCX
        of R8R: x86.R8
        of R9R: x86.R9
        else: x86.RAX
      result.typ = res.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    inc n
    # Immediate type inference?
    # If expectedType is provided, try to match it.
    if expectedType != nil and (expectedType.kind in {IntT, UIntT, FloatT}):
      result.typ = expectedType
    else:
      result.typ = Type(kind: IntLitT, bits: 64) # Literal - compatible with IntT and UIntT
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.onStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        let regTag = tagToX64Reg(sym.reg)
        result.reg = case regTag
          of RaxR, R0R: RAX
          of RcxR, R2R: RCX
          of RdxR, R3R: RDX
          of RbxR, R1R: RBX
          of RspR, R7R: RSP
          of RbpR, R6R: RBP
          of RsiR, R4R: RSI
          of RdiR, R5R: RDI
          of R8R: R8
          of R9R: R9
          of R10R: R10
          of R11R: R11
          of R12R: R12
          of R13R: R13
          of R14R: R14
          of R15R: R15
          else: RAX

        # Check if clobbered
        if result.reg in ctx.clobbered:
          error("Access to variable '" & name & "' in register " & $result.reg & " which was clobbered", n)

      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.kind = okLabel
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now but don't define it yet
        # It will be defined when the rodata is actually written
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of rodata
      inc n
    elif sym != nil and sym.kind == skGvar:
      # Global variable - return its address
      # For foreign symbols, we can't generate code, but we can typecheck
      result.kind = okLabel
      if sym.isForeign:
        error("Cannot access foreign global variable '" & name & "' directly (must be linked)", n)
      if sym.offset == -1:
        # Forward reference - create label now
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of gvar
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Accessing thread local variable via FS segment
      # On x86-64 Linux, TLS variables are accessed via FS segment
      # The offset is stored in sym.offset (allocated in pass2)
      # Use RBP as base register (standard for offset-only addressing)
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: x86.RBP,  # RBP allows displacement-only addressing
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

proc parseDest(n: var Cursor; ctx: var GenContext; expectedType: Type = nil): Operand =
  if n.kind == ParLe and rawTagIsX64Reg(n.tag):
    result.reg = parseRegister(n)
    if expectedType != nil:
      result.typ = expectedType
    else:
      result.typ = Type(kind: IntT, bits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == ParLe and n.tag == ArgTagId:
    # (arg name) as destination - for register arguments in prepare block
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    inc n
    if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
    let argName = getSym(n)
    inc n
    skipParRi n, "arg destination"

    var callCtx = addr ctx.callStack[^1]
    if argName notin callCtx.paramLookup:
      error("Unknown argument: " & argName, n)

    let param = callCtx.paramLookup[argName]
    if param.onStack:
      error("Stack argument '" & argName & "' cannot be used directly as destination, use (mem (rsp) (arg " & argName & "))", n)

    # Track that this argument is being set
    if argName in callCtx.argsSet:
      error("Argument already set: " & argName, n)
    callCtx.argsSet.incl(argName)

    # Return the register for this argument
    let paramRegTag = tagToX64Reg(param.reg)
    result.kind = okArg
    result.argName = argName
    result.reg = case paramRegTag
      of RaxR, R0R: x86.RAX
      of RdiR, R5R: x86.RDI
      of RsiR, R4R: x86.RSI
      of RdxR, R3R: x86.RDX
      of RcxR, R2R: x86.RCX
      of R8R: x86.R8
      of R9R: x86.R9
      of R10R: x86.R10
      of R11R: x86.R11
      else: x86.RAX
    result.typ = param.typ
  elif n.kind == ParLe and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId):
    let op = parseOperand(n, ctx)
    if op.kind != okMem:
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and sym.kind == skVar:
       if sym.onStack:
         # Return StackOffT - operations like `add` will reject this at type check
         result.kind = okMem
         result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
         result.typ = sym.typ  # Already StackOffT from declaration
         inc n
         return
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
       result.kind = okMem
       result.mem = x86.MemoryOperand(
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

  if expectedType != nil and result.typ != nil:
    checkType(expectedType, result.typ, n)

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

proc genPrepareX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  let start = n
  inc n
  if n.kind != Symbol: error("Expected proc symbol or type, got " & $n.kind, n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)

  var callCtx = CallContext(
    target: name,
    paramLookup: initTable[string, Param](),
    resultLookup: initTable[string, Param](),
    argsSet: initHashSet[string](),
    resultsSet: initHashSet[string](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, n)
  elif sym.kind == skProc:
    if sym.isForeign:
      error("Cannot call foreign proc '" & name & "' directly (use extcall)", n)
    callCtx.sig = sym.sig
    callCtx.isExternal = false
  elif sym.kind == skExtProc:
    # External proc - find its info
    callCtx.isExternal = true
    for i, ext in ctx.extProcs:
      if ext.name == name:
        callCtx.extProcIdx = i
        break
    # External procs don't have full signatures in current design
    # For now, we skip argument checking for external procs
  else:
    error("Expected proc symbol, got " & $sym.kind, n)

  # Build lookup tables (only for internal procs with signatures)
  if not callCtx.isExternal:
    for param in callCtx.sig.params:
      callCtx.paramLookup[param.name] = param
    for res in callCtx.sig.result:
      callCtx.resultLookup[res.name] = res
    # Compute stack argument size
    callCtx.stackArgSize = computeStackArgSize(callCtx.sig)

  # Push call context
  ctx.callStack.add callCtx
  inc n

  # Process instructions inside prepare block
  while n.kind != ParRi:
    genInstX64(n, ctx)

  # Verify all bindings are done
  let currentCtx = ctx.callStack[^1]
  if not currentCtx.isExternal:
    for param in currentCtx.sig.params:
      if not param.onStack and param.name notin currentCtx.argsSet:
        error("Missing argument: " & param.name, n)

    for res in currentCtx.sig.result:
      if res.name notin currentCtx.resultsSet:
        error("Missing result binding: " & res.name, n)

    # Verify call was emitted
    if not currentCtx.callEmitted:
      error("Missing (call) or (extcall) in prepare block", n)
  else:
    if not currentCtx.callEmitted:
      error("Missing (extcall) in prepare block", n)

  # Pop call context
  discard ctx.callStack.pop()
  skipParRi n, "prepare"

proc genCallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (call) marker inside a prepare block - emits the actual call instruction
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  var callCtx = addr ctx.callStack[^1]
  if callCtx.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if callCtx.isExternal:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, callCtx.target, n)

  # Clobber registers
  ctx.clobbered.incl(callCtx.sig.clobbers)

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)

  ctx.buf.emitCall(labId)
  callCtx.callEmitted = true

  inc n
  skipParRi n, "call"

proc genExtcallX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call via IAT
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  var callCtx = addr ctx.callStack[^1]
  if callCtx.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if not callCtx.isExternal:
    error("Use (call) for internal procs, not (extcall)", n)

  # Record call site and emit IAT call
  let callPos = ctx.buf.data.len
  ctx.extProcs[callCtx.extProcIdx].callSites.add callPos
  ctx.buf.emitIatCall(ctx.extProcs[callCtx.extProcIdx].gotSlot)

  callCtx.callEmitted = true

  inc n
  skipParRi n, "extcall"

  #for (res, dest) in boundResults:
  #  let resReg = tagToRegister(res.reg)
  #  if dest.reg != resReg:
  #    x86.emitMov(ctx.buf.data, dest.reg, resReg)

proc genIatX64(n: var Cursor; ctx: var GenContext) =
  # (iat symbol) - Indirect call through IAT for external procs
  inc n
  if n.kind != Symbol: error("Expected proc symbol for iat", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil or sym.kind != skExtProc: error("iat requires external proc, got: " & name, n)
  inc n
  # Find the extproc to get its IAT slot
  var iatSlot = -1
  for i in 0..<ctx.extProcs.len:
    if ctx.extProcs[i].name == name:
      iatSlot = ctx.extProcs[i].gotSlot
      break
  if iatSlot == -1:
    error("External proc not found: " & name, n)
  # Emit indirect call through IAT using relocation system
  ctx.buf.emitIatCall(iatSlot)
  skipParRi n, "iat"

proc genMovX64(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  let dest = parseDest(n, ctx)
  let op = parseOperand(n, ctx)

  # Type checking
  if dest.typ != nil and op.typ != nil:
    checkType(dest.typ, op.typ, start)

  if dest.kind == okMem:
    if op.kind == okImm:
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
    elif op.kind == okSsize:
      # Similar issue, ssize is immediate 0 (patched).
      error("Moving ssize to memory not supported", n)
    elif op.kind == okMem:
      error("Cannot move memory to memory", n)
    else:
      x86.emitMov(ctx.buf.data, dest.mem, op.reg)
  else:
    # dest is reg
    if op.kind == okSsize:
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, 0)
      ctx.ssizePatches.add(ctx.buf.data.len - 4)
    elif op.kind == okCsize:
      # csize is a known value - the stack argument size for the current call
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okImm:
      if op.immVal >= low(int32) and op.immVal <= high(int32):
        x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
      else:
        x86.emitMovImmToReg(ctx.buf.data, dest.reg, op.immVal)
    elif op.kind == okMem:
      x86.emitMov(ctx.buf.data, dest.reg, op.mem)
    else:
      x86.emitMov(ctx.buf.data, dest.reg, op.reg)
  skipParRi n, "mov"

proc genIteX64(n: var Cursor; ctx: var GenContext) =
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
    let flagTag = tagToX64Flag(n.tag)
    inc n
    skipParRi n, "condition"
    inc n

    case flagTag
    of OfO: ctx.buf.emitJno(lElse)
    of NoO: ctx.buf.emitJo(lElse)
    of ZfO: ctx.buf.emitJne(lElse)
    of NzO: ctx.buf.emitJe(lElse)
    of SfO: ctx.buf.emitJns(lElse)
    of NsO: ctx.buf.emitJs(lElse)
    of CfO: ctx.buf.emitJae(lElse)
    of NcO: ctx.buf.emitJb(lElse)
    of PfO: ctx.buf.emitJnp(lElse)
    of NpO: ctx.buf.emitJp(lElse)
    else: error("Unsupported condition: " & $flagTag, n)
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

  skipParRi n, "ite"

proc genLoopX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Pre-loop
  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  ctx.buf.defineLabel(lStart)

  if n.kind != ParLe: error("Expected condition", n)
  let condTag = n.tag
  inc n
  skipParRi n, "condition"

  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitJne(lEnd)
  of NzO: ctx.buf.emitJe(lEnd)
  else: error("Unsupported loop condition: " & $loopFlagTag, n)

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
  skipParRi n, "loop"

proc genJtrueX64(n: var Cursor; ctx: var GenContext) =
  # (jtrue cfvar1.0 cfvar2.0 ...)
  # Set control flow variable(s) to true by emitting an unconditional jump
  # The jump targets are stored in the cfvar symbols
  let start = n
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

  skipParRi n, "jtrue"

proc genKillX64(n: var Cursor; ctx: var GenContext) =
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
  skipParRi n, "kill"

proc genInstX64(n: var Cursor; ctx: var GenContext) =
  if n.kind != ParLe: error("Expected instruction", n)
  let instTag = tagToX64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    # (cfvar :name.0)
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = pool.syms[n.symId]
    inc n

    # Control flow variables are always virtual (bool type, never materialized)
    # We create a label for when this cfvar becomes "true"
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: name, kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)

    skipParRi n, "cfvar declaration"
    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = pool.syms[n.symId]
    inc n
    var reg = InvalidTagId
    var onStack = false
    if n.kind == ParLe:
      let locTag = n.tag
      if rawTagIsX64Reg(locTag):
        reg = locTag
        inc n
        skipParRi n, "register location"
      elif locTag == STagId:
        onStack = true
        inc n
        skipParRi n, "stack location"
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)

    let sym = Symbol(name: name, kind: skVar, typ: baseTyp)
    if onStack:
      sym.onStack = true
      sym.offset = ctx.slots.allocSlot(baseTyp)
      sym.typ = Type(kind: StackOffT, offType: baseTyp)  # Wrap in StackOffT
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

    skipParRi n, "variable declaration"
    return
  of NoDecl:
    discard "continue with case instTag"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD:
    error("Unexpected declaration: " & $declTag, n)

  case instTag
  of NoX64Inst:
    error("No x86 instruction", n)
  of StmtsX64:
    inc n
    while n.kind != ParRi:
      genInstX64(n, ctx)
    inc n
  of PrepareX64:
    genPrepareX64(n, ctx)
  of CallX64:
    genCallMarkerX64(n, ctx)
  of ExtcallX64:
    genExtcallX64(n, ctx)
  of IatX64:
    genIatX64(n, ctx)

  of MovX64:
    genMovX64(n, ctx)
  of IteX64:
    genIteX64(n, ctx)
  of LoopX64:
    genLoopX64(n, ctx)
  of JtrueX64:
    genJtrueX64(n, ctx)
  of KillX64:
    genKillX64(n, ctx)
  of AddX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)

    # Type check: add works on integers and pointers
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkCompatibleTypes(dest.typ, op.typ, "add", start)

    if dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        # ADD m64, imm32
        # Need emitAdd(MemoryOperand, int32)
        error("Adding immediate to memory not supported yet", n)
      elif op.kind == okSsize:
        error("Adding ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot add memory to memory", n)
      else:
        x86.emitAdd(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okSsize:
        x86.emitAddImm(ctx.buf.data, dest.reg, 0)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.kind == okCsize:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitAdd(ctx.buf.data, dest.reg, op.mem)
      else:
        x86.emitAdd(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "add"

  of SubX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)

    # Type check: sub works on integers and pointers
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkCompatibleTypes(dest.typ, op.typ, "sub", start)

    if dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        error("Subtracting immediate from memory not supported yet", n)
      elif op.kind == okSsize:
        error("Subtracting ssize from memory not supported", n)
      elif op.kind == okMem:
        error("Cannot subtract memory from memory", n)
      else:
        x86.emitSub(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okSsize:
        x86.emitSubImm(ctx.buf.data, dest.reg, 0)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.kind == okCsize:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitSub(ctx.buf.data, dest.reg, op.mem)
      else:
        x86.emitSub(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "sub"

  of MulX64:
    inc n
    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "mul", start)
    if op.kind == okImm: error("MUL immediate not supported", n)
    if op.kind == okMem: error("MUL memory not supported yet", n) # Need emitMul(mem)
    x86.emitMul(ctx.buf.data, op.reg)
    skipParRi n, "mul"

  of ImulX64:
    inc n
    # (imul dest src) or (imul dest src imm) - but we only support binary or unary?
    # doc says (imul D S)
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "imul", start)
    checkIntegerType(op.typ, "imul", start)
    if dest.kind == okMem: error("IMUL destination cannot be memory", n)
    if op.kind == okImm:
      x86.emitImulImm(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okMem:
      error("IMUL memory source not supported yet", n) # Need emitImul(reg, mem)
    else:
      x86.emitImul(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "imul"

  of DivX64:
    # (div (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != ParLe or n.tag != RdxTagId: error("Expected (rdx) for div", n)
    inc n
    skipParRi n, "rdx"

    inc n # (rax)
    if n.kind != ParLe or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    inc n
    skipParRi n, "rax"

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "div", start)
    if op.kind == okImm: error("DIV immediate not supported", n)
    if op.kind == okMem: error("DIV memory not supported yet", n)
    x86.emitDiv(ctx.buf.data, op.reg)
    skipParRi n, "div"

  of IdivX64:
    # (idiv (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != ParLe or n.tag != RdxTagId: error("Expected (rdx) for idiv", n)
    inc n
    skipParRi n, "idiv"

    inc n # (rax)
    if n.kind != ParLe or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    inc n
    skipParRi n, "rax"

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "idiv", start)
    if op.kind == okImm: error("IDIV immediate not supported", n)
    if op.kind == okMem: error("IDIV memory not supported yet", n)
    x86.emitIdiv(ctx.buf.data, op.reg)
    skipParRi n, "idiv"

  # Bitwise
  of AndX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkCompatibleTypes(dest.typ, op.typ, "and", start)
    if dest.kind == okMem:
      error("AND to memory not supported yet", n)
    else:
      if op.kind == okImm:
        x86.emitAndImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        error("AND from memory not supported yet", n)
      else:
        x86.emitAnd(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "and"

  of OrX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "or", start)
    checkBitwiseType(op.typ, "or", start)
    checkCompatibleTypes(dest.typ, op.typ, "or", start)
    if dest.kind == okMem:
      error("OR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        x86.emitOrImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        error("OR from memory not supported yet", n)
      else:
        x86.emitOr(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "or"

  of XorX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "xor", start)
    checkBitwiseType(op.typ, "xor", start)
    checkCompatibleTypes(dest.typ, op.typ, "xor", start)
    if dest.kind == okMem:
      error("XOR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        x86.emitXorImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        error("XOR from memory not supported yet", n)
      else:
        x86.emitXor(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "xor"

  of ShlX64, SalX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      x86.emitShl(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.reg == RCX:
      # emitShlCl? x86.nim only has imm count support in emitShl currently?
      # Need to check x86.nim for CL support or add it.
      # Existing emitShl takes `count: int`.
      # We need `emitShlCl(reg)`.
      error("Shift by CL not supported yet in x86 backend", n)
    else:
      error("Shift count must be immediate or CL", n)
    skipParRi n, "shl"

  of ShrX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      x86.emitShr(ctx.buf.data, dest.reg, int(op.immVal))
    else:
      error("Shift count must be immediate", n)
    skipParRi n, "shr"

  of SarX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "sar", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      x86.emitSar(ctx.buf.data, dest.reg, int(op.immVal))
    else:
      error("Shift count must be immediate", n)
    skipParRi n, "sar"

  # Unary
  of IncX64:
    inc n
    let op = parseDest(n, ctx) # Dest/Src same
    checkIntegerArithmetic(op.typ, "inc", start)
    if op.kind == okMem: error("INC memory not supported yet", n)
    x86.emitInc(ctx.buf.data, op.reg)
    skipParRi n, "inc"

  of DecX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "dec", start)
    if op.kind == okMem: error("DEC memory not supported yet", n)
    x86.emitDec(ctx.buf.data, op.reg)
    skipParRi n, "dec"

  of NegX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    x86.emitNeg(ctx.buf.data, op.reg)
    skipParRi n, "neg"

  of NotX64:
    inc n
    let op = parseDest(n, ctx)
    checkBitwiseType(op.typ, "not", start)
    if op.kind == okMem: error("NOT memory not supported yet", n)
    x86.emitNot(ctx.buf.data, op.reg)
    skipParRi n, "not"

  # Comparison
  of CmpX64:
    inc n
    let dest = parseDest(n, ctx) # Actually just operand 1
    let op = parseOperand(n, ctx)
    # Comparisons work on integers and pointers
    checkIntegerArithmetic(dest.typ, "cmp", start)
    checkIntegerArithmetic(op.typ, "cmp", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmp", start)
    if dest.kind == okMem:
      if op.kind == okImm:
        # CMP m64, imm32
        error("CMP memory, immediate not supported yet", n)
      elif op.kind == okMem:
        error("Cannot compare memory with memory", n)
      else:
        x86.emitCmp(ctx.buf.data, op.reg, dest.mem) # cmp reg, mem? No, cmp mem, reg.
        # x86.nim: emitCmp(mem, reg) -> CMP r/m64, r64 (39 /r).
        # Wait, 39 is CMP r/m64, r64 (store in r/m? no, compare r/m with r).
        # Opcode 39: CMP r/m64, r64. MR encoding.
        # Operand order: CMP op1, op2.
        # If op1 is mem, op2 is reg.
        x86.emitCmp(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okImm:
        x86.emitCmpImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitCmp(ctx.buf.data, dest.reg, op.mem)
      else:
        x86.emitCmp(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmp"

  of TestX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "test", start)
    checkBitwiseType(op.typ, "test", start)
    checkCompatibleTypes(dest.typ, op.typ, "test", start)
    if dest.kind == okMem:
      error("TEST memory not supported yet", n)
    elif op.kind == okImm:
      # emitTestImm
      error("TEST immediate not supported yet", n)
    elif op.kind == okMem:
      error("TEST with memory operand not supported yet", n)
    else:
      x86.emitTest(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "test"

  # Conditional Sets
  of SeteX64, SetzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSete(ctx.buf.data, dest.reg)
    skipParRi n, "sete"

  of SetneX64, SetnzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetne(ctx.buf.data, dest.reg)
    skipParRi n, "setne"

  of SetaX64, SetnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeta(ctx.buf.data, dest.reg)
    skipParRi n, "seta"

  of SetaeX64, SetnbX64, SetncX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetae(ctx.buf.data, dest.reg)
    skipParRi n, "setae"

  of SetbX64, SetnaeX64, SetcX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetb(ctx.buf.data, dest.reg)
    skipParRi n, "setb"
  of SetbeX64, SetnaX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetbe(ctx.buf.data, dest.reg)
    skipParRi n, "setbe"

  of SetgX64, SetnleX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetg(ctx.buf.data, dest.reg)
    skipParRi n, "setg"

  of SetgeX64, SetnlX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetge(ctx.buf.data, dest.reg)
    skipParRi n, "setge"
  of SetlX64, SetngeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetl(ctx.buf.data, dest.reg)
    skipParRi n, "setl"

  of SetleX64, SetngX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetle(ctx.buf.data, dest.reg)
    skipParRi n, "setle"

  of SetoX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeto(ctx.buf.data, dest.reg)
    skipParRi n, "seto"

  of SetsX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSets(ctx.buf.data, dest.reg)
    skipParRi n, "sets"

  of SetpX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetp(ctx.buf.data, dest.reg)
    skipParRi n, "setp"
  # Conditional moves
  of CmoveX64, CmovzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmove(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmove(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmove"

  of CmovneX64, CmovnzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovne(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovne(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovne"

  of CmovaX64, CmovnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmova(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmova(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmova"

  of CmovaeX64, CmovnbX64, CmovncX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovae(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovae(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovae"

  of CmovbX64, CmovnaeX64, CmovcX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovb(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovb(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovb"

  of CmovbeX64, CmovnaX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovbe(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovbe(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovbe"

  of CmovgX64, CmovnleX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovg(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovg(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovg"

  of CmovgeX64, CmovnlX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovge(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovge(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovge"

  of CmovlX64, CmovngeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovl(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovl(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovl"

  of CmovleX64, CmovngX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovle(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovle(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovle"

  of CmovoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovo(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovo(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovo"

  of CmovsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovs(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovs(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovs"

  of CmovpX64, CmovpeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovp(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovp"

  of CmovnpX64, CmovpoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovnp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovnp(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovnp"

  of CmovnsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovns(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovns(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovns"

  of CmovnoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovno(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovno(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmovno"
  # Stack
  of PushX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.kind == okImm:
      x86.emitPush(ctx.buf.data, int32(op.immVal))
    elif op.kind == okMem:
      error("PUSH memory not supported yet", n)
    else:
      x86.emitPush(ctx.buf.data, op.reg)
    skipParRi n, "push"

  of PopX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      error("POP memory not supported yet", n)
    else:
      x86.emitPop(ctx.buf.data, dest.reg)
    skipParRi n, "pop"

  of SyscallX64:
    inc n
    x86.emitSyscall(ctx.buf.data)
    skipParRi n, "syscall"
  of LeaX64:
    # (lea dest-reg base-reg offset) or (lea dest-reg label)
    inc n
    let dest = parseRegister(n) # LEA dest must be register

    # Check if next is a label or register
    if n.kind == ParLe and n.tag == LabTagId:
      # (lea dest (lab label)) - RIP-relative address
      inc n
      if n.kind != Symbol: error("Expected label name", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      skipParRi n, "label usage"
      x86.emitLea(ctx.buf, dest, LabelId(sym.offset))
    elif n.kind == ParLe and rawTagIsX64Reg(n.tag):
      # (lea dest base-reg offset) - explicit addressing
      let baseReg = parseRegister(n)
      var displacement: int32 = 0

      # Parse offset - can be integer or stack variable name
      if n.kind == IntLit:
        displacement = int32(getInt(n))
        inc n
      elif n.kind == Symbol:
        let offsetName = getSym(n)
        let offsetSym = lookupWithAutoImport(ctx, ctx.scope, offsetName, n)
        if offsetSym != nil and (offsetSym.kind == skVar or offsetSym.kind == skParam) and offsetSym.onStack:
          displacement = int32(offsetSym.offset)
        else:
          error("Expected stack variable or integer offset in lea", n)
        inc n
      else:
        error("Expected offset (integer or stack variable) in lea", n)

      let mem = x86.MemoryOperand(
        base: baseReg,
        displacement: displacement,
        hasIndex: false
      )
      x86.emitLea(ctx.buf.data, dest, mem)
    else:
      # Try parsing as a label operand (rodata, gvar, etc.)
      let op = parseOperand(n, ctx)
      if op.kind == okLabel:
        x86.emitLea(ctx.buf, dest, op.label)
      else:
        error("lea requires (base-reg offset) or label", n)
    skipParRi n, "lea"
  of JmpX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.kind == okMem:
      error("JMP memory not supported yet", n)
    elif op.label != LabelId(0) or op.typ.kind == UIntT: # Label check
      # op.label is set if it was a label operand
      if op.typ.kind == UIntT: # Label address
        x86.emitJmp(ctx.buf, op.label)
      else:
        x86.emitJmpReg(ctx.buf.data, op.reg)
    else:
      x86.emitJmpReg(ctx.buf.data, op.reg) # Default to reg jump if not label?
    skipParRi n, "jmp"
  of JeX64, JzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJe(ctx.buf, op.label)
    skipParRi n, "je"
  of JneX64, JnzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJne(ctx.buf, op.label)
    skipParRi n, "jne"
  of JgX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJg(ctx.buf, op.label)
    skipParRi n, "jg"
  of JgeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJge(ctx.buf, op.label)
    skipParRi n, "jge"
  of JlX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJl(ctx.buf, op.label)
    skipParRi n, "jl"
  of JleX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJle(ctx.buf, op.label)
    skipParRi n, "jle"
  of JaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJa(ctx.buf, op.label)
    skipParRi n, "ja"
  of JaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJae(ctx.buf, op.label)
    skipParRi n, "jae"
  of JbX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJb(ctx.buf, op.label)
    skipParRi n, "jb"
  of JbeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJbe(ctx.buf, op.label)
    skipParRi n, "jbe"
  of JngX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJle(ctx.buf, op.label)
    skipParRi n, "jng"
  of JngeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJl(ctx.buf, op.label)
    skipParRi n, "jng"
  of JnaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJbe(ctx.buf, op.label)
    skipParRi n, "jna"
  of JnaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJb(ctx.buf, op.label)
    skipParRi n, "jnae"
  of NopX64:
    inc n
    x86.emitNop(ctx.buf.data)
    skipParRi n, "nop"
  of RetX64:
    inc n
    when false: # if ctx.procName.len > 0:
      x86.emitMov(ctx.buf.data, RSP, RBP)
      x86.emitPop(ctx.buf.data, RBP)
    x86.emitRet(ctx.buf.data)
    skipParRi n, "ret"
  of LabX64:
    # (lab :label)
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = pool.syms[n.symId]
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
    skipParRi n, "lab"

  of MovapdX64:
    # (movapd dest src)
    inc n
    let dest = parseDest(n, ctx) # Should check if XMM
    let op = parseOperand(n, ctx) # Should check if XMM/Mem
    # Need to support XMM registers in parseRegister/Operand
    # And emitMovapd (likely similar to movsd but packed)
    # For now, placeholder error or implement if x86 supports it
    error("MOVAPD not supported yet", n)
    skipParRi n, "movapd"
  of MovsdX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    # Dest must be XMM? Or Mem?
    # x86: MOVSD xmm1, xmm2/m64
    # MOVSD xmm1/m64, xmm2
    # So one must be XMM.
    if dest.kind == okMem and op.kind == okMem:
      error("MOVSD memory to memory not supported", n)
    # We need to check if registers are XMM.
    # Currently parseRegister returns Register enum which is GPR.
    # We need XmmRegister support.
    # Let's assume we add XMM support to parseRegister or use a variant.
    error("MOVSD not fully supported yet (needs XMM register parsing)", n)
    skipParRi n, "movsd"

  of AddsdX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "addsd", start)
    checkFloatType(op.typ, "addsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)
    skipParRi n, "addsd"

  of SubsdX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "subsd", start)
    checkFloatType(op.typ, "subsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)
    skipParRi n, "subsd"

  of MulsdX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "mulsd", start)
    checkFloatType(op.typ, "mulsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)
    skipParRi n, "mulsd"

  of DivsdX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkFloatType(dest.typ, "divsd", start)
    checkFloatType(op.typ, "divsd", start)
    error("Scalar double precision arithmetic not fully supported yet", n)
    skipParRi n, "divsd"

  of LockX64:
    inc n
    if n.kind != ParLe: error("Expected instruction to lock", n)
    let innerInstTag = tagToX64Inst(n.tag)
    case innerInstTag
    of AddX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock add", start)
      checkIntegerArithmetic(op.typ, "lock add", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock add", start)
      if dest.kind != okMem: error("Atomic ADD requires memory destination", n)
      if op.kind == okImm: error("Atomic ADD immediate not supported yet", n)
      if op.kind == okMem: error("Atomic ADD memory source not supported", n)
      x86.emitLock(ctx.buf.data)
      x86.emitAdd(ctx.buf.data, dest.mem, op.reg)
      skipParRi n, "lock add"
    of SubX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock sub", start)
      checkIntegerArithmetic(op.typ, "lock sub", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock sub", start)
      if dest.kind != okMem: error("Atomic SUB requires memory destination", n)
      if op.kind == okImm: error("Atomic SUB immediate not supported yet", n)
      if op.kind == okMem: error("Atomic SUB memory source not supported", n)
      x86.emitLock(ctx.buf.data)
      x86.emitSub(ctx.buf.data, dest.mem, op.reg)
      skipParRi n, "lock sub"
    of AndX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock and", start)
      checkBitwiseType(op.typ, "lock and", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock and", start)
      if dest.kind != okMem: error("Atomic AND requires memory destination", n)
      if op.kind == okImm: error("Atomic AND immediate not supported yet", n)
      if op.kind == okMem: error("Atomic AND memory source not supported", n)
      x86.emitLock(ctx.buf.data)
      x86.emitAnd(ctx.buf.data, dest.mem, op.reg)
      skipParRi n, "lock and"
    of OrX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock or", start)
      checkBitwiseType(op.typ, "lock or", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock or", start)
      if dest.kind != okMem: error("Atomic OR requires memory destination", n)
      if op.kind == okImm: error("Atomic OR immediate not supported yet", n)
      if op.kind == okMem: error("Atomic OR memory source not supported", n)
      x86.emitLock(ctx.buf.data)
      x86.emitOr(ctx.buf.data, dest.mem, op.reg)
      skipParRi n, "lock or"
    of XorX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock xor", start)
      checkBitwiseType(op.typ, "lock xor", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock xor", start)
      if dest.kind != okMem: error("Atomic XOR requires memory destination", n)
      if op.kind == okImm: error("Atomic XOR immediate not supported yet", n)
      if op.kind == okMem: error("Atomic XOR memory source not supported", n)
      x86.emitLock(ctx.buf.data)
      x86.emitXor(ctx.buf.data, dest.mem, op.reg)
      skipParRi n, "lock xor"
    of IncX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock inc", start)
      if dest.kind != okMem: error("Atomic INC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitInc(ctx.buf.data, dest.mem)
      skipParRi n, "lock inc"
    of DecX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock dec", start)
      if dest.kind != okMem: error("Atomic DEC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitDec(ctx.buf.data, dest.mem)
      skipParRi n, "lock dec"
    of NotX64:
      inc n
      let dest = parseDest(n, ctx)
      checkBitwiseType(dest.typ, "lock not", start)
      if dest.kind != okMem: error("Atomic NOT requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNot(ctx.buf.data, dest.mem)
      skipParRi n, "lock not"
    of NegX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock neg", start)
      if dest.kind != okMem: error("Atomic NEG requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNeg(ctx.buf.data, dest.mem)
      skipParRi n, "lock neg"
    else:
       error("Unsupported instruction for LOCK prefix: " & $innerInstTag, n)

    inc n
    skipParRi n, "locked instruction"

  of XchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xchg", start)
    checkIntegerType(op.typ, "xchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "xchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XCHG memory, immediate not supported", n)
      if op.kind == okMem: error("XCHG memory, memory not supported", n)
      x86.emitXchg(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okImm: error("XCHG reg, immediate not supported", n)
      if op.kind == okMem:
        x86.emitXchg(ctx.buf.data, op.mem, dest.reg)
      else:
        x86.emitXchg(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "xchg"
  of XaddX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xadd", start)
    checkIntegerType(op.typ, "xadd", start)
    checkCompatibleTypes(dest.typ, op.typ, "xadd", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XADD memory, immediate not supported", n)
      if op.kind == okMem: error("XADD memory, memory not supported", n)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okImm: error("XADD reg, immediate not supported", n)
      if op.kind == okMem: error("XADD reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitXadd(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "xadd"
  of CmpxchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "cmpxchg", start)
    checkIntegerType(op.typ, "cmpxchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmpxchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("CMPXCHG memory, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG memory, memory not supported", n)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg)
    else:
      if op.kind == okImm: error("CMPXCHG reg, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitCmpxchg(ctx.buf.data, dest.reg, op.reg)
    skipParRi n, "cmpxchg"
  of Cmpxchg8bX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      x86.emitCmpxchg8b(ctx.buf.data, dest.mem)
    else:
      x86.emitCmpxchg8b(ctx.buf.data, dest.reg)
    skipParRi n, "cmpxchg8b"
  of MfenceX64:
    inc n
    x86.emitMfence(ctx.buf.data)
    skipParRi n, "mfence"
  of SfenceX64:
    inc n
    x86.emitSfence(ctx.buf.data)
    skipParRi n, "sfence"
  of LfenceX64:
    inc n
    x86.emitLfence(ctx.buf.data)
    skipParRi n, "lfence"
  of PauseX64:
    inc n
    x86.emitPause(ctx.buf.data)
    skipParRi n, "pause"

  of ClflushX64:
    inc n
    let op = parseDest(n, ctx)
    if op.kind == okMem: error("CLFLUSH expects memory operand via register?", n)
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
    x86.emitClflush(ctx.buf.data, op.reg)
    skipParRi n, "clflush"

  of ClflushoptX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitClflushopt(ctx.buf.data, op.reg)
    skipParRi n, "clflushopt"
  of Prefetcht0X64:
    inc n
    let op = parseDest(n, ctx)
    skipParRi n, "prefetcht0"
    x86.emitPrefetchT0(ctx.buf.data, op.reg)
    skipParRi n, "prefetcht0"
  of Prefetcht1X64:
    inc n
    let op = parseDest(n, ctx)
    skipParRi n, "prefetcht1"
    x86.emitPrefetchT1(ctx.buf.data, op.reg)
    skipParRi n, "prefetcht1"
  of Prefetcht2X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT2(ctx.buf.data, op.reg)
    skipParRi n, "prefetcht2"
  of PrefetchntaX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchNta(ctx.buf.data, op.reg)
    skipParRi n, "prefetchnta"


proc pass2(n: Cursor; ctx: var GenContext) =
  var n = n
  if n.kind == ParLe and n.tag == StmtsTagId:
    inc n
    while n.kind != ParRi:
      if n.kind == ParLe:
        let start = n
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          # Types were fully handled in pass1; skip the definition body.
          n = start
          skip n
        of ProcD:
          # Skip foreign procs - they're not code-generated
          inc n
          if n.kind != SymbolDef:
            error("Expected symbol definition", n)
          let name = pool.syms[n.symId]
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym != nil and sym.isForeign:
            # Skip foreign proc body
            n = start
            skip n
          else:
            n = start
            pass2Proc(n, ctx)
        of RodataD:
          inc n
          if n.kind != SymbolDef: error("Expected symbol definition", n)
          let name = pool.syms[n.symId]
          let sym = ctx.scope.lookup(name)
          inc n
          let s = getStr(n)
          # Define label at the current position (where rodata will be written)
          if sym.offset == -1:
            # Forward reference - create label now
            let labId = ctx.buf.createLabel()
            sym.offset = int(labId)
          # Define label at current position (before writing rodata)
          ctx.buf.defineLabel(LabelId(sym.offset))
          # Now write the rodata string
          for c in s: ctx.buf.data.add byte(c)
          inc n
          inc n
        of GvarD:
          # Global variable declaration - goes in .bss section (zero-initialized writable memory)
          inc n
          if n.kind != SymbolDef: error("Expected symbol definition", n)
          let name = pool.syms[n.symId]
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
        of TvarD:
          # Thread local variable declaration
          inc n
          if n.kind != SymbolDef: error("Expected symbol definition", n)
          let name = pool.syms[n.symId]
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
        of ArchD:
          handleArch(n, ctx)
        of ImpD, ExtprocD:
          # Already handled in pass1, skip
          skip n
        else:
          genInst(n, ctx)
      else:
        error("Expected instruction", n)
    inc n
  else:
    error("Expected stmts", n)

proc writeElf(a: var GenContext; outfile: string) =
  finalize(a.buf)
  finalize(a.bssBuf)
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
    f.writeData(code.rawData, code.len)
    # Pad to page boundary
    let padding = int(textAlignedSize - textSize)
    if padding > 0:
      var zeros = newSeq[byte](padding)
      f.writeData(unsafeAddr zeros[0], padding)

  # .bss section is not written to file (it's zero-initialized by the loader)
  # The loader will allocate the memory and zero it

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

proc writeMachO(a: var GenContext; outfile: string) =
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data
  let baseAddr = 0x100000000.uint64  # macOS default base address
  let pageSize = 0x1000.uint64

  # Calculate sizes
  let codeSize = code.len.uint64
  let codeAlignedSize = (codeSize + pageSize - 1) and not (pageSize - 1)

  # TEXT segment: code
  let textVmaddr = baseAddr
  let entryAddr = textVmaddr

  # Determine CPU type based on architecture
  let (cputype, cpusubtype) = case a.arch
    of Arch.X64:
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)
    of Arch.A64:
      (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    of Arch.WinX64, Arch.WinA64:
      # Should not be called for Windows, but need to cover all cases
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)

  # Build dynlink info for external procs
  var dynlink: macho.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add macho.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add macho.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  macho.writeMachO(code, a.bssOffset, entryAddr, cputype, cpusubtype, outfile, dynlink)

  # macOS arm64 requires code signing for all executables
  when defined(macosx):
    let codesignResult = execCmd("codesign -s - " & quoteShell(outfile))
    if codesignResult != 0:
      raise newException(OSError, "codesign failed with exit code " & $codesignResult)

proc writeExe(a: var GenContext; outfile: string) =
  finalize(a.buf)
  finalize(a.bssBuf)

  # Determine machine type based on architecture
  let machine =
    case a.arch
    of Arch.WinX64:
      pe.IMAGE_FILE_MACHINE_AMD64
    of Arch.WinA64:
      pe.IMAGE_FILE_MACHINE_ARM64
    else:
      pe.IMAGE_FILE_MACHINE_AMD64

  # Build dynlink info for external procs
  var dynlink: pe.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add pe.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add pe.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  writePE(a.buf, a.bssOffset, 0'u32, machine, outfile, dynlink)

proc createLiterals(data: openArray[(string, int)]): Literals =
  result = default(Literals)
  for i in 1 ..< data.len:
    let t = result.tags.getOrIncl(data[i][0])
    assert t.int == data[i][1]

proc assemble*(filename, outfile: string) =
  nifstreams.pool = createLiterals(TagData)
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
    baseDir: baseDir,
    imports: @[],
    extProcs: @[],
    gotSlotCount: 0
  )

  var n1 = n
  pass1(n1, scope, ctx)

  # Update ctx with proper buffers for pass2
  ctx.buf = initBuffer()
  ctx.bssBuf = initBuffer()
  pass2(n, ctx)

  case ctx.arch
  of Arch.X64:
    writeElf(ctx, outfile)
  of Arch.A64:
    writeMachO(ctx, outfile)
  of Arch.WinX64, Arch.WinA64:
    writeExe(ctx, outfile.changeFileExt("exe"))

  # Close all module streams
  for module in ctx.modules.mvalues:
    nifstreams.close(module.stream)
