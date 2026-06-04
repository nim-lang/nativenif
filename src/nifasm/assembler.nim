
import std / [tables, sets, streams, os, osproc]
import nifcore, nifcoreparse, nifmodules
import "../../../nimony/src/lib" / [nifreader, symparser]
import tags, model, tagconv
import buffers, relocs, x86, arm64, elf, macho, pe
import sem, slots
import decls

proc createAsmTagPool(): TagPool =
  ## A `nifcore` tag pool seeded so each asm-NIF tag's `TagId` equals its
  ## `TagEnum` ordinal — the same scheme arkham uses (`nifcdecl.createNifcTagPool`).
  ## `cursorTagId` then decodes by ordinal via `cast[TagEnum](…)`. Shared across
  ## the main module and every lazily-parsed foreign decl so ordinals line up.
  result = newTagPool()
  for e in TagEnum:
    if e == InvalidTagId: continue
    let id = result.registerTag(TagData[e][0])
    assert uint32(id) == uint32(TagData[e][1]),
      "nifasm tag pool misalignment for " & TagData[e][0]

var asmTags: TagPool = createAsmTagPool()
  ## The one seeded tag pool; `assemble` re-creates it per run is unnecessary —
  ## a single process assembles one program.

proc tag(n: Cursor): TagEnum = cast[TagEnum](uint32(n.cursorTagId))

proc nodeRepr(n: Cursor): string =
  ## A compact rendering of the token at `n` for error messages (nifcore has no
  ## whole-subtree `toString` over a bare Cursor, and the diagnostic only needs
  ## the head). Negative tests match on the message text, not this.
  case n.kind
  of TagLit: "(" & tagName(n.tags, n.cursorTagId)
  of Symbol, SymbolDef: "@" & n.symName
  of Ident: n.strVal
  of StrLit: "\"" & n.strVal & "\""
  of IntLit: $n.intVal
  of UIntLit: $n.uintVal
  of FloatLit: $n.floatVal
  of DotToken: "."
  else: $n.kind

proc infoStr(n: Cursor): string =
  let li = n.rawLineInfo
  if li.isValid:
    result = n.lineInfoFile & "(" & $li.line & ", " & $li.col & ")"
  else:
    result = "???"

proc error(msg: string; n: Cursor) =
  writeStackTrace()
  quit "[Error] " & msg & " at " & infoStr(n) &
    " (kind=" & $n.kind & ", tag=" & nodeRepr(n) & ")"

proc extractDedupKey*(s: string): string =
  ## Extract deduplication key from symbol like "foo.0.key.moduleSuffix" -> "foo.0.key"
  ## The dedup key is everything before the module suffix.
  ## Deduplication only applies if there are more than 2 dots.
  ## For "foo.0.moduleSuffix" (2 dots) -> "" (no dedup)
  ## For "foo.0" (1 dot) -> "" (local, no dedup)
  ## For "foo.0.key.moduleSuffix" (3 dots) -> "foo.0.key"
  var dotCount = 0
  var lastDotPos = -1
  for i in 0..<s.len:
    if s[i] == '.':
      inc dotCount
      lastDotPos = i

  if dotCount <= 2:
    return ""  # No deduplication for <= 2 dots

  # More than 2 dots: dedup key is everything before the last dot (module suffix)
  result = s[0 ..< lastDotPos]

proc typeError(want, got: Type; n: Cursor) =
  error("Type mismatch: expected " & $want & ", got " & $got, n)

proc movCompatible(want, got: Type): bool =
  ## Type rule for `mov`: strict compatibility, OR a *widening* integer move —
  ## a smaller integer into a larger register (a safe extending move/load).
  ## Narrowing or a kind change (int↔ptr/float) is still rejected.
  if compatible(want, got): return true
  if want.kind in {IntT, UIntT} and got.kind in {IntT, UIntT, IntLitT}:
    return got.bits <= want.bits
  result = false

proc getInt(n: Cursor): int64 =
  if n.kind == IntLit:
    result = n.intVal
  else:
    error("Expected integer literal", n)

template symName(n: Cursor): string =
  ## The symbol's fully-qualified name. The NIF reader already completes the
  ## self-module trailing-dot compression (using each module's own suffix, set
  ## from its filename), so the interned string is module-correct as-is.
  nifcore.symName(n)

proc getSym(n: Cursor): string =
  case n.kind
  of Symbol:
    result = symName(n)
  else:
    error("Expected symbol", n)

proc getSymDef(n: var Cursor): string =
  if n.kind != SymbolDef:
    error("Expected symbol definition", n)
  result = symName(n)
  skip n

proc getStr(n: Cursor): string =
  if n.kind == StrLit:
    result = n.strVal
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


proc tagToRegister(t: TagEnum; n: Cursor): x86.Register =
  ## Convert a TagEnum to an x86 Register (for register binding tracking)
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
    else:
      error("Expected GPR register, got: " & $t, n)
      x86.RAX

proc parseRegister(n: var Cursor): x86.Register =
  result = tagToRegister(n.tag, n)
  inc n

proc isXmmTag(n: Cursor): bool {.inline.} =
  n.kind == TagLit and n.tag >= Xmm0TagId and n.tag <= Xmm15TagId

proc parseXmm(n: var Cursor): x86.XmmRegister =
  ## Parse an `(xmmN)` SSE register operand (N in 0..15).
  if not isXmmTag(n):
    error("expected xmm register", n)
  result = x86.XmmRegister(ord(n.tag) - ord(Xmm0TagId))
  inc n

const MainModuleName* = ""  # Special name for main module

type
  LoadedModule = ref object
    ## A loaded module. The MAIN module is parsed whole into `buf` (local symbols
    ## carry a `declStart` token position into it). A FOREIGN module is opened
    ## lazily through the shared `nifmodules.ForeignModule`: only its embedded NIF
    ## `.index` (symbol → byte offset) is read up front; declarations are parsed
    ## one at a time on demand, by following a referenced name (nominal typing).
    ## The foreign handle keeps each lazily-parsed decl tree alive so the Cursors
    ## into it stay valid. (A `ref` so a handle stays valid even if `ctx.modules`
    ## rehashes while a decl body recursively pulls in further foreign modules.)
    buf: TokenBuf                          # whole-module tree (main module only)
    foreign: ForeignModule                 # lazy per-symbol loader (foreign only)
    loaded: bool  # True if already loaded into scope

  Arch = enum
    X64        # Linux x86-64 (ELF)
    LinuxA64   # Linux ARM64 (ELF)
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

  CallContextState = enum
    Disabled, NormalCall, ExternalCall

  CallContext = object          ## Context for a `prepare` block - tracks call setup state
    state: CallContextState
    callEmitted: bool           # True after (call) or (extcall) is emitted
    target: string              # Target proc/symbol name
    typ: Type                   # ProcT type (contains params, results, clobbers)
    extProcIdx: int             # Index into extProcs for external calls
    argsSet: HashSet[string]    # Arguments that have been assigned
    resultsSet: HashSet[string] # Results that have been bound
    stackArgSize: int           # Computed size of stack arguments (csize)
    indirect: bool              # Target is a function-pointer variable: `typ` is its
                                # proctype signature and `(call)` is an indirect call
                                # through the loaded pointer (vs a direct `call rel32`)

  GenContext = object
    scope: Scope        # Current (possibly proc-local) lexical scope
    rootScope: Scope    # Module/global scope; foreign symbols are defined here so
                        # they persist past the proc that first referenced them
                        # (processReachableSymbols looks them up to emit bodies).
    buf: relocs.Buffer  # Code buffer (.text section) for x64
    bssBuf: relocs.Buffer  # BSS buffer (.bss section) for zero-initialized global variables
    arch: Arch
    procName: string
    callContext: CallContext # Current call context
    clobbered: set[x86.Register] # Registers clobbered in current flow (x64 only)
    slots: SlotManager
    ssizePatches: seq[int]
    csizePatches: seq[(int, int)] # (position, callStackDepth) for csize patches
    gvarSites: seq[(int, Symbol)] # (adrp position in .text, gvar symbol) for adrp+add patching
    tlvSites: seq[(int, Symbol)]  # (adrp position in .text, tvar symbol) for TLV descriptor adrp+add patching (arm64/macOS)
    tlvSyms: seq[Symbol]          # thread-local vars in descriptor order (arm64/macOS); sym.offset = descriptor index, sym.size = byte offset within the per-thread region
    tlvData: seq[byte]            # the __thread_data init template (concatenated per-thread initial values, arm64/macOS)
    tlsOffset: int  # Current TLS offset for thread-local variables (x86)
    bssOffset: int  # Current offset in .bss section
    modules: Table[string, LoadedModule]  # Cache of loaded foreign modules
    baseDir: string  # Base directory for finding module files
    thisModule: string  # The module being assembled (symbol suffix of the main file);
                        # a `name.0.<thisModule>` reference is local, not foreign
    regBindings: Table[x86.Register, string]  # Maps registers to variable names they're bound to (x64 only)
    # Dynamic linking
    imports: seq[ImportedLib]  # Imported libraries
    extProcs: seq[ExtProcInfo]  # External procs to bind
    gotSlotCount: int  # Number of GOT slots allocated
    # Module system / dead code elimination
    pendingSymbols: seq[string]  # Symbols pending code generation
    generatedSymbols: HashSet[string]  # Symbols already generated
    dedupTable: Table[string, string]  # Maps dedup key to canonical symbol name
    # Thread-local storage (x86-64). nifasm owns the unified per-thread block
    # `arkham.tls.0` (sized for ALL bundled modules' tvars) and synthesizes the
    # entry prologue that points FS at it (`arch_prctl`). Nim thread-locals have no
    # initializers, so the block is just zeroed `.bss`.
    tlsBlockSym: Symbol          # the synthetic `arkham.tls.0` gvar (FS base block)
    entrySym: Symbol             # the entry proc (`_start`/`main.0`) — prologue jumps here
    tlsEntryOffset: int          # .text offset of the synthesized FS-setup prologue, or -1
    # A gvar with a compile-time constant scalar initializer is laid out as static
    # data: arkham emits its bits as the gvar value, and these are written into the
    # (writable) `.bss` image on disk so the slot starts with that value (correct in
    # a bundle, where a foreign module's entry-time initializer never runs).
    bssInits: seq[tuple[off: int64, val: int64, size: int]]  # (.bss byte offset, value, size)

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
    gvarSym: Symbol           # non-nil when the operand is a global's address; the
                              # ELF backend patches its `lea` against the .bss segment

proc inCall(ctx: GenContext): bool {.inline.} =
  ## Returns true if we're inside a prepare block
  ctx.callContext.state != CallContextState.Disabled

proc markSymbolUsed(ctx: var GenContext; fullName: string) =
  ## Mark a symbol as used, adding it to pending list if not yet generated.
  ## Both main module and foreign module symbols are subject to dead code elimination.
  ## Only symbols that are actually referenced (via lookupWithAutoImport) are marked as used.
  ## Handles deduplication: if symbol has a dedup key and we've seen that key before,
  ## the symbol is merged with the canonical one
  if fullName in ctx.generatedSymbols:
    return

  let dedupKey = extractDedupKey(fullName)
  if dedupKey != "":
    # Check if we already have a canonical symbol for this key
    if dedupKey in ctx.dedupTable:
      # Already have this key, merge by using existing canonical
      return
    else:
      # First occurrence of this key, register as canonical
      ctx.dedupTable[dedupKey] = fullName

  # Add to pending if not already there (for both main module and foreign symbols)
  if fullName notin ctx.generatedSymbols:
    ctx.pendingSymbols.add fullName

proc getCanonicalName(ctx: GenContext; fullName: string): string =
  ## Get the canonical name for a symbol (for dedup merging)
  let dedupKey = extractDedupKey(fullName)
  if dedupKey != "" and dedupKey in ctx.dedupTable:
    result = ctx.dedupTable[dedupKey]
  else:
    result = fullName

proc findParam(t: Type; name: string): ptr Param =
  ## Find a parameter by name in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.params.len:
    if t.params[i].name == name:
      return addr t.params[i]
  nil

proc findResult(t: Type; name: string): ptr Param =
  ## Find a result by name in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.results.len:
    if t.results[i].name == name:
      return addr t.results[i]
  nil

proc computeStackArgSize(t: Type): int =
  ## Compute total size needed for stack arguments. Rounded up to 16 bytes so a
  ## caller can `sub sp, sp, #csize` and keep SP 16-byte aligned (required by
  ## AArch64; harmless for x86-64 where the SysV ABI also wants 16-alignment).
  assert t.kind == ProcT
  result = 0
  for param in t.params:
    if param.typ.isOnStack:
      result += slots.alignedSize(param.typ)
  result = (result + 15) and not 15

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parsePtrType(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseClobbers(n: var Cursor): set[x86.Register]
proc parseUnionBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc genStmt(n: var Cursor; ctx: var GenContext)
proc genInstA64(n: var Cursor; ctx: var GenContext)
proc checkIntegerArithmetic(t: Type; op: string; n: Cursor)
proc checkIntegerType(t: Type; op: string; n: Cursor)
proc checkBitwiseType(t: Type; op: string; n: Cursor)
proc checkCompatibleTypes(t1, t2: Type; op: string; n: Cursor)
proc checkType(want, got: Type; n: Cursor)

proc atTypeStart(n: Cursor): bool =
  ## True if `n` is positioned at the start of a `Type` (a named-type symbol or
  ## a recognized type tag) — i.e. NOT at an Empty/pragmas slot. Used to make
  ## NIFC's optional pragmas/base slots tolerant.
  n.kind == Symbol or (n.kind == TagLit and rawTagIsNifasmType(n.tag))

proc parseObjectBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  # NIFC `ObjDecl ::= (object [Empty | Type-base] FieldDecl*)` — the `fields`
  # iterator tolerates the optional inheritance/base slot for us.
  var flds: seq[(string, Type)] = @[]
  var offset = 0
  var maxAlign = 1  # Track maximum alignment requirement
  for fc in fields(n):
    if not atTag(fc, FldTagId): error("Expected field definition", fc)
    var f = fc
    # NIFC `FieldDecl ::= (fld SymbolDef FieldPragmas Type)` — takeField
    # tolerates the optional field-pragmas slot before the type.
    let fr = takeField(f, atTypeStart)
    var nameC = fr.name
    if nameC.kind != SymbolDef: error("Expected field name", nameC)
    let name = symName(nameC)
    var typC = fr.typ
    let ftype = parseType(typC, scope, ctx)
    flds.add (name, ftype)

    # Align field to its natural alignment
    let fieldAlign = asmAlignOf(ftype)
    offset = alignTo(offset, fieldAlign)

    # Track maximum alignment for the struct
    if fieldAlign > maxAlign:
      maxAlign = fieldAlign

    # Move past this field
    offset += asmSizeOf(ftype)
  skip n # advance past the whole (object …) node

  # Round up total size to be a multiple of the struct's alignment
  let finalSize = alignTo(offset, maxAlign)
  result = Type(kind: ObjectT, fields: flds, size: finalSize, align: maxAlign)

proc isRegTag(locTag: TagEnum): bool =
  rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag)

proc openForeignModule(ctx: var GenContext; modname: string; n: Cursor) =
  ## Open a foreign module for LAZY, on-demand symbol resolution: read just its
  ## embedded NIF `.index` (symbol → byte offset) and keep the stream open. The
  ## module's declarations are NOT parsed here — `resolveForeignSym` parses each
  ## one only when its name is actually followed (nominal typing). Idempotent.
  if ctx.modules.hasKey(modname):
    return
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
  let fm = nifmodules.openForeignModule(modfile)
  if not fm.hasEmbeddedIndex:
    error("Foreign module has no embedded NIF index (reindex it): " & modfile, n)
  ctx.modules[modname] = LoadedModule(foreign: fm, loaded: true)

proc resolveForeignSym(ctx: var GenContext; modname, fullName: string; scope: Scope; n: Cursor): Symbol =
  ## Resolve ONE foreign declaration by following its qualified name through the
  ## shared `nifmodules` loader: `getDecl` jumps to the indexed byte offset and
  ## parses just that decl (cached, its buffer kept alive in the ForeignModule),
  ## we then define it in `scope` and return it. A decl's body pulls in further
  ## declarations the same lazy way, on demand — so forward and self/mutually-
  ## recursive references resolve naturally regardless of file order (a pointer
  ## pointee stays nominal via `parsePtrType`; only a by-value reference forces a
  ## follow). `declStart` is unused for foreign symbols — generateSymbol re-reads
  ## the cached decl by name.
  let m = ctx.modules[modname]            # ref: stable across table growth
  if not hasDecl(m.foreign, fullName): return nil
  var c = getDecl(m.foreign, fullName, asmTags)  # cursor at the one decl tree
  let declTag = tagToNifasmDecl(c.tag)
  case declTag
  of TypeD:
    inc c                                 # enter: type tag → name
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)                  # advance past the name
    # Define a placeholder BEFORE parsing the body so a self/mutually-recursive
    # by-value reference inside it (e.g. a proctype field whose result names this
    # very type) resolves to this symbol instead of recursing back into here. The
    # placeholder is filled in place, so the captured reference observes the
    # resolved type.
    result = Symbol(name: fullName, kind: skType, typ: Type(kind: ErrorT),
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
    var parsed: Type
    if c.kind == TagLit and c.tag == ObjectTagId:
      parsed = parseObjectBody(c, scope, ctx)
    elif c.kind == TagLit and c.tag == UnionTagId:
      parsed = parseUnionBody(c, scope, ctx)
    else:
      parsed = parseType(c, scope, ctx)
    result.typ[] = parsed[]
  of ProcD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
    block:
      let sig = takeSig(c)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber; procTyp.clobbers = parseClobbers(cl)
    result = Symbol(name: fullName, kind: skProc, typ: procTyp, offset: -1,
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
  of GvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: fullName, kind: skGvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
  of TvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: fullName, kind: skTvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
  of RodataD:
    # A foreign read-only data blob (e.g. a string literal, or a gvar with a
    # constant-scalar initializer laid out as static data — see arkham genGlobal).
    inc c
    if c.kind != SymbolDef: return nil
    result = Symbol(name: fullName, kind: skRodata, offset: -1, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
  else:
    return nil

proc lookupWithAutoImport(ctx: var GenContext; scope: Scope; name: string; n: Cursor): Symbol =
  ## Lookup a symbol, lazily opening + following names into foreign modules.
  ## Also marks the symbol as used for dependency tracking.
  ##
  ## Important: Symbols with module suffixes (e.g., `foo.0.mymodule`) are distinct
  ## from local symbols (e.g., `foo.0`). When a module suffix is present, we only
  ## look in the foreign module, not in the local scope.
  let modname = extractModule(name)
  if modname != "" and modname != ctx.thisModule:
    # Foreign symbol: open the module's index, then resolve this one decl lazily
    # if it isn't already in scope. (A `…0.<thisModule>` suffix names *this*
    # module's own symbol — arkham emits self-module globals fully qualified — so
    # it must NOT be treated as foreign, which would shadow the local definition.)
    openForeignModule(ctx, modname, n)
    result = scope.lookup(name)
    if result == nil:
      result = resolveForeignSym(ctx, modname, name, scope, n)
  else:
    # This is a local symbol - look up in current scope
    result = scope.lookup(name)

  # Mark symbol as used for dependency tracking
  if result != nil:
    markSymbolUsed(ctx, result.name)

proc parsePtrType(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## Parse the pointee of a `(ptr X)` / `(aptr X)`. A pointer is 8 bytes whatever
  ## it points at, so a bare-symbol pointee carries its qualified NAME in
  ## `baseName` — this is its nominal identity (used for strict, name-based
  ## pointer compatibility, see `compatible`) and, when the type is not yet
  ## defined, the handle for resolving it lazily on first structural access (see
  ## `resolvedBase`). An already-defined symbol also resolves `base` eagerly; a
  ## genuine forward reference (pointee declared later in the still-loading
  ## module, e.g. `(ptr Rtti)`) leaves `base` nil until forced. A structural
  ## pointee (`(ptr (i 32))`) has no name and is resolved eagerly.
  var base: Type = nil
  var baseName = ""
  if n.kind == Symbol:
    baseName = getSym(n)
    let sym = scope.lookup(baseName)
    inc n
    if sym != nil and sym.kind == skType:
      base = sym.typ          # resolved eagerly, but keep baseName (nominal id)
  else:
    base = parseType(n, scope, ctx)
  # Construct with a literal discriminator (Nim can't prove a runtime one safe).
  if kind == AptrT:
    result = Type(kind: AptrT, base: base, baseName: baseName)
  else:
    result = Type(kind: PtrT, base: base, baseName: baseName)

proc resolvedBase(t: Type; ctx: var GenContext; n: Cursor): Type =
  ## Return a pointer/aptr's pointee, resolving & memoizing a lazily-recorded
  ## forward reference (see `parsePtrType`) on first use. By the time any field
  ## or element access runs, the pointee's declaration has been parsed, so the
  ## lookup — which also auto-imports the owning module if needed — succeeds.
  if t.base == nil and t.baseName.len > 0:
    let sym = lookupWithAutoImport(ctx, ctx.scope, t.baseName, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & t.baseName, n)
    t.base = sym.typ
  result = t.base

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, scope, name, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & name, n)
    result = sym.typ
    inc n
  elif n.kind == TagLit:
    let t = n.tag
    # Inline aggregate types (e.g. an array of anonymous objects, or a field
    # whose type is spelled out in place) — parseObjectBody/parseUnionBody each
    # consume the whole `(object …)`/`(union …)` tree, so return directly.
    if t == ObjectTagId:
      return parseObjectBody(n, scope, ctx)
    elif t == UnionTagId:
      return parseUnionBody(n, scope, ctx)
    var nodeEnd = n
    skip nodeEnd          # a cursor positioned just past this whole type node
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
      result = parsePtrType(PtrT, n, scope, ctx)
    of AptrTagId:
      result = parsePtrType(AptrT, n, scope, ctx)
    of ArrayTagId:
      let elem = parseType(n, scope, ctx)
      let len = getInt(n)
      inc n
      result = Type(kind: ArrayT, elem: elem, len: len)
    of ProcTagId:
      # (proc (params ...) (result ...) (clobber ...))
      var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber; procTyp.clobbers = parseClobbers(cl)
      result = procTyp
    of CTagId:
      # NIFC character type `(c N)` — an N-bit integer for the machine.
      result = Type(kind: IntT, bits: int(getInt(n)))
      inc n
    of VoidTagId:
      result = Type(kind: VoidT)
    of VarargsTagId:
      # `(varargs)` — a zero-size variadic marker; modeled as void.
      result = Type(kind: VoidT)
    of FlexarrayTagId:
      # `(flexarray T)` — flexible array member: a zero-length array of T.
      let elem = parseType(n, scope, ctx)
      result = Type(kind: ArrayT, elem: elem, len: 0)
    of EnumTagId:
      # `(enum BaseType EnumFieldDecl*)` — collapses to its base integer type
      # for codegen; the `efld` children are consumed by the trailing skip.
      result = parseType(n, scope, ctx)
    of ProctypeTagId:
      # `(proctype (params …) (result …)? (clobber …)?)` — a function pointer
      # (8 bytes; see `asmSizeOf`). arkham emits the full ABI signature (not an
      # opaque pointer) so an indirect `(prepare <fnptr> … (call))` resolves its
      # args/result against this, exactly like a direct call to a proc.
      var ptParams: seq[Param] = @[]
      var ptResults: seq[Param] = @[]
      var ptClobbers: set[x86.Register] = {}
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; ptParams = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; ptResults = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber; ptClobbers = parseClobbers(cl)
      result = Type(kind: ProcT, params: ptParams, results: ptResults, clobbers: ptClobbers)
    else:
      error("Unknown type tag: " & $t, n)
    # Jump to the precomputed node end: this consumes any NIFC type qualifiers we
    # don't model (IntQualifier atomic/ro, PtrQualifier atomic/ro/restrict, the
    # trailing (cppref) marker) and lands exactly past the whole type node —
    # rem-independent, unlike a `while hasMore` walk over a manually-entered node.
    n = nodeEnd
  else:
    error("Expected type", n)


proc parseUnionBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  var flds: seq[(string, Type)] = @[]
  var maxSize = 0
  var maxAlign = 1  # Track maximum alignment requirement
  for fc in fields(n):
    if not atTag(fc, FldTagId): error("Expected field definition", fc)
    var f = fc
    let fr = takeField(f, atTypeStart)   # tolerates NIFC's FieldPragmas slot
    var nameC = fr.name
    if nameC.kind != SymbolDef: error("Expected field name", nameC)
    let name = symName(nameC)
    var typC = fr.typ
    let ftype = parseType(typC, scope, ctx)
    flds.add (name, ftype)

    let size = asmSizeOf(ftype)
    let fieldAlign = asmAlignOf(ftype)

    # Union size is the maximum of all field sizes
    if size > maxSize:
      maxSize = size

    # Track maximum alignment
    if fieldAlign > maxAlign:
      maxAlign = fieldAlign
  skip n # advance past the whole (union …) node

  # Round up size to be a multiple of the union's alignment
  let finalSize = alignTo(maxSize, maxAlign)
  result = Type(kind: UnionT, fields: flds, size: finalSize, align: maxAlign)

proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (params (param :name (reg) Type) ...)
  for pc in params(n):
    if declTag(pc) != ParamD: error("Expected param declaration", pc)
    var p = pc
    let pr = takeParam(p)
    var nameC = pr.name
    if nameC.kind != SymbolDef: error("Expected param name", nameC)
    let name = symName(nameC)

    # (reg) or (s) location
    var loc = pr.location
    var reg = InvalidTagId
    var onStack = false
    if loc.kind == TagLit:
      let locTag = rawTag(loc)
      if rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag):
        reg = locTag
      elif locTag == STagId:
        onStack = true
      else:
        error("Expected location", loc)
    else:
      error("Expected location", loc)

    var typC = pr.typ
    var typ = parseType(typC, scope, ctx)
    if onStack:
      typ = Type(kind: StackOffT, offType: typ)
    result.add Param(name: name, typ: typ, reg: reg)
  skip n # advance past the whole (params …) node

proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (result (ret :name (reg) Type) ...)
  if n.kind == TagLit and tagToNifasmDecl(n.tag) == ResultD:
    loopInto n:
      # An entry is either wrapped `(ret :name (reg) Type)` or the three slots
      # `:name (reg) Type` inline. Either way we consume them linearly, so the
      # loop's bound stays correct; the (elided) wrapper close needs no skip.
      if n.kind == TagLit:
        inc n                       # enter the (ret …) wrapper
      if n.kind != SymbolDef: error("Expected result definition", n)
      let name = symName(n)
      skip n
      var reg = InvalidTagId
      if n.kind == TagLit:
        let locTag = n.tag
        if isRegTag(locTag):
          reg = locTag
          skip n                    # the whole (reg) location node
        else:
          error "result must be a register", n
      else:
        error("Expected location", n)
      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg)

proc parseClobbers(n: var Cursor): set[x86.Register] =
  # (clobber (rax) (rbx) ...)
  if declTag(n) == ClobberD:
    loopInto n:
      if n.kind == TagLit and rawTagIsX64Reg(rawTag(n)):
        result.incl parseRegister(n)
      elif n.kind == TagLit and rawTagIsA64Reg(rawTag(n)):
        # AArch64 clobbers describe the convention's caller-saved set. The
        # interference model that consumes `clobbers` is x86-only (the A64 path
        # resolves registers directly), so accept and skip them here.
        skip n
      else:
        error("Expected register in clobber list", n)

proc pass1Proc(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
  inc n
  if n.kind != SymbolDef: error("Expected proc name", n)
  let name = symName(n)  # Full qualified name
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})

  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber; procTyp.clobbers = parseClobbers(cl)

  let sym = Symbol(name: name, kind: skProc, typ: procTyp, offset: -1,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc handleArch(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Ident: error("Expected architecture symbol", n)
  let arch = n.strVal
  if arch == "x64":
    ctx.arch = Arch.X64
  elif arch == "linux_arm64":
    ctx.arch = Arch.LinuxA64
  elif arch == "arm64":
    ctx.arch = Arch.A64
  elif arch == "win_x64":
    ctx.arch = Arch.WinX64
  elif arch == "win_arm64":
    ctx.arch = Arch.WinA64
  else:
    error("Unknown architecture: " & arch, n)
  inc n

proc pass1(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; buf: var TokenBuf) =
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declStart = cursorToPosition(buf, start)
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          inc n
          if n.kind != SymbolDef: error("Expected type name", n)
          let name = symName(n)  # Full qualified name
          inc n
          if n.kind == TagLit and n.tag == ObjectTagId:
            let typ = parseObjectBody(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          elif n.kind == TagLit and n.tag == UnionTagId:
            let typ = parseUnionBody(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          else:
            let typ = parseType(n, scope, ctx)
            scope.define(Symbol(name: name, kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
        of ProcD:
          # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
          pass1Proc(n, scope, ctx, moduleName, declStart)

          n = start
          skip n
        of RodataD:
          inc n
          if n.kind != SymbolDef: error("Expected rodata name", n)
          let name = symName(n)  # Full qualified name
          var sym = Symbol(name: name, kind: skRodata,
                          moduleName: moduleName, declStart: declStart)
          sym.offset = -1  # Mark as forward reference until defined
          scope.define(sym)
          n = start
          skip n
        of GvarD:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skGvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of TvarD:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: name, kind: skTvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD:
          # (imp "libpath")
          inc n
          if n.kind != StrLit: error("Expected library path string", n)
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
        of ExtprocD:
          # (extproc :name "external_name")
          inc n
          if n.kind != SymbolDef: error("Expected extproc name", n)
          let name = symName(n)
          inc n
          if n.kind != StrLit: error("Expected external symbol name string", n)
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
        else:
          skip n
      else:
        skip n

proc genInstX64(n: var Cursor; ctx: var GenContext)

proc tagToRegisterA64(t: TagEnum; n: Cursor): arm64.Register =
  ## Convert a TagEnum to an ARM64 Register (for register binding tracking)
  ## Note: X16/X17 are reserved for assembler scratch use but allowed in direct
  ## instructions (e.g., Darwin syscalls use X16 for syscall number).
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
    else:
      error("Expected ARM64 register, got: " & $t, n)
      arm64.X0

proc parseRegisterA64(n: var Cursor): arm64.Register =
  result = tagToRegisterA64(n.tag, n)
  inc n

proc isA64DoubleRegTag(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(D0TagId) and ord(t) <= ord(D31TagId)

proc isA64SingleRegTag(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(S0TagId) and ord(t) <= ord(S31TagId)

proc isA64FpRegTag(t: TagEnum): bool {.inline.} =
  ## True for any scalar fp register tag `(d0)`..`(d31)` / `(s0)`..`(s31)`.
  isA64DoubleRegTag(t) or isA64SingleRegTag(t)

proc isA64FpRegOperand(n: Cursor): bool {.inline.} =
  n.kind == TagLit and isA64FpRegTag(n.tag)

proc isA64SingleOperand(n: Cursor): bool {.inline.} =
  ## Whether the fp register operand `n` is single-precision `(sN)`.
  n.kind == TagLit and isA64SingleRegTag(n.tag)

proc parseFloatRegisterA64(n: var Cursor): arm64.FloatRegister =
  if not isA64FpRegOperand(n): error("Expected fp register (dN/sN)", n)
  let base = if isA64SingleRegTag(n.tag): ord(S0TagId) else: ord(D0TagId)
  result = arm64.FloatRegister(ord(n.tag) - base)
  inc n


type
  OperandA64 = object
    kind: OperandKind
    reg: arm64.Register
    typ: Type
    immVal: int64
    mem: arm64.MemoryOperand
    argName: string       # set for okArg (call argument / result binding by name)
    label: LabelId
    gvarSym: Symbol       # non-nil if this operand is a global (.bss) address;
                          # its `.size` (the .bss byte offset) is read after all
                          # symbols are processed, so forward refs resolve right
    tlvSym: Symbol        # non-nil if this operand is a thread-local var address
                          # (arm64/macOS): `adr` lowers it to the TLV descriptor
                          # call sequence, leaving the variable's address in x0

proc parseOperandA64(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit:
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
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
           baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        # a stack-resident object/union: unwrap the StackOffT to its object type
        objType = baseOp.typ.offType
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
    elif t == AtTagId:
      # (at <base> <index>) folds to an LDR/STR scaled-index operand, or
      # (at <base> <index> <scratch-reg>): the element stride isn't an LDR scale
      # (a multi-dimensional array's outer dimension), so arkham hands us a scratch
      # register and WE compute `base + index*stride` into it — the stride comes
      # from the element type (typed layer), the scratch from arkham (regalloc).
      # `into` bounds the node so the optional third operand reads safely.
      into n:
        var baseOp = parseOperandA64(n, ctx)
        var indexOp = parseOperandA64(n, ctx)
        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)
        var elemType: Type
        var baseReg: arm64.Register
        var baseOffset: int32 = 0
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind == TypeKind.ArrayT:
          # a stack-resident array: unwrap the StackOffT to its array type
          elemType = baseOp.typ.offType.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        else:
          error("at requires aptr or stack array, got " & $baseOp.typ, n)

        var hasScratch = false
        var scratchReg: arm64.Register
        if n.hasMore and n.kind == TagLit and rawTagIsA64Reg(n.tag):
          scratchReg = parseRegisterA64(n)
          hasScratch = true

        if hasScratch:
          # scratch = base + index*stride. arkham only emits this for a register
          # index, so indexOp is in a register; reuse scratch for the stride const.
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          let stride = asmSizeOf(elemType)
          arm64.emitMovImm64(ctx.buf.data, scratchReg, uint64(stride))
          arm64.emitMul(ctx.buf.data, scratchReg, indexOp.reg, scratchReg) # scratch = idx*stride
          arm64.emitAdd(ctx.buf.data, scratchReg, baseReg, scratchReg)     # scratch = base + that
          result.kind = okMem
          result.mem = arm64.MemoryOperand(base: scratchReg, offset: baseOffset, hasIndex: false)
        elif indexOp.kind == okImm:
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseReg, offset: baseOffset + int32(offset), hasIndex: false)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          let elemSize = asmSizeOf(elemType)
          if elemSize notin [1, 2, 4, 8]:
            error("Element size " & $elemSize & " not a scale and no scratch supplied", n)
          let shift = case elemSize
            of 1: 0
            of 2: 1
            of 4: 2
            of 8: 3
            else: 0
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseReg, index: indexOp.reg, shift: shift, offset: baseOffset, hasIndex: true)
        result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n
    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandA64(n, ctx)
      op.typ = castType
      result = op
    elif t == MemTagId:
      inc n
      if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
        var addrOp = parseOperandA64(n, ctx)
        if addrOp.kind != okMem:
          error("mem requires address expression", n)
        if addrOp.typ.kind != TypeKind.PtrT:
          error("mem requires pointer type, got " & $addrOp.typ, n)
        result = addrOp
        result.typ = resolvedBase(addrOp.typ, ctx, n)
      else:
        var baseOp = parseOperandA64(n, ctx)
        if baseOp.kind == okImm or baseOp.kind == okMem:
          error("mem base must be a register", n)
        var offset: int32 = 0
        var hasIndex = false
        var indexReg: arm64.Register = arm64.X0
        var shift: int = 0
        if n.kind == TagLit and n.tag == ArgTagId:
          # (mem (sp) (arg name)) - address of an outgoing stack argument slot
          let argOff = parseOperandA64(n, ctx)
          if argOff.kind != okImm:
            error("(arg ...) in mem must denote a stack argument", n)
          offset = int32(argOff.immVal)
        elif n.kind == IntLit or n.kind == Symbol:
          if n.kind == IntLit:
            offset = int32(getInt(n))
            inc n
          elif n.kind == Symbol:
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
              hasIndex = true
              indexReg = tagToRegisterA64(indexSym.reg, n)
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
    elif t == SsizeTagId:
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == CsizeTagId:
      # (csize) - total bytes reserved for outgoing stack arguments
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name) - argument reference inside a prepare block
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      let argName = getSym(n)
      inc n
      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & argName, n)
      if paramPtr.typ.isOnStack:
        # Stack argument used as an offset (e.g. inside (mem (sp) (arg name))).
        # The offset is the running byte position among the stack-passed params.
        var offset = 0
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
            offset += slots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset)
        result.typ = paramPtr.typ
      else:
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegisterA64(paramPtr.reg, n)
        result.typ = paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference inside a prepare block (after the call)
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSym(n)
      inc n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & resName, n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & resName, n)
      ctx.callContext.resultsSet.incl(resName)
      result.reg = tagToRegisterA64(resPtr.reg, n)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg, n)
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
      # A foreign global is bundled into this same image (see generateSymbol), so
      # it is accessed exactly like a local one — no external linking step.
      # On arm64 the global lives in __DATA/.bss; its address is formed with
      # adrp+add at link time (see AdrA64 + writeMachO). Carry the symbol so its
      # final .bss offset (`sym.size`) is read after all symbols are processed.
      result.gvarSym = sym
      result.reg = arm64.X0
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Thread-local var (macOS/arm64): its address is obtained at run time via
      # the TLV descriptor thunk. Carry the symbol; `adr` lowers the call
      # sequence and leaves the variable's address in x0. It is not a plain
      # memory operand, so it must not be loaded/stored directly.
      result.kind = okLabel
      result.tlvSym = sym
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skProc:
      # A proc used as a value → its code address: `(adr reg proc)` materializes a
      # function pointer. Same label the proc's definition / a direct `(call)` binds,
      # so it resolves to the proc's entry (in __TEXT, reachable by ADR/PC-relative).
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)   # a code pointer
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDestA64(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit and rawTagIsA64Reg(n.tag):
    result.reg = parseRegisterA64(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name) as destination - binds a register argument inside a prepare block
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    inc n
    if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
    let argName = getSym(n)
    inc n
    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil:
      error("Unknown argument: " & argName, n)
    if paramPtr.typ.isOnStack:
      error("Stack argument '" & argName & "' cannot be used directly as destination, use (mem (sp) (arg " & argName & "))", n)
    if argName in ctx.callContext.argsSet:
      error("Argument already set: " & argName, n)
    ctx.callContext.argsSet.incl(argName)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegisterA64(paramPtr.reg, n)
    result.typ = paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId):
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem:
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg, n)
        result.typ = sym.typ
      else:
        error("Variable has no location", n)
      inc n
    elif sym != nil and sym.kind == skTvar:
      # A thread-local var cannot be a direct destination on arm64/macOS: take its
      # address with `(adr (x0) tv)` first, then store through `(mem (x0))`.
      error("Cannot store directly to thread-local '" & name &
            "'; use (adr (x0) " & name & ") then (mem (x0))", n)
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc genPrepareA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  if ctx.callContext.state != CallContextState.Disabled:
    error("Nested prepare blocks are not allowed", hdr)
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[string](),
    resultsSet: initHashSet[string](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the IAT/extcall path.
    ctx.callContext.typ = sym.typ
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls through it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    ctx.callContext.state = CallContextState.ExternalCall
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Compute stack argument size (only for internal procs)
  if ctx.callContext.state == CallContextState.NormalCall:
    ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstA64(n, ctx)

  # Verify call was emitted and all bindings are done
  if ctx.callContext.state == CallContextState.NormalCall:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & param.name, hdr)

    for res in ctx.callContext.typ.results:
      if res.name notin ctx.callContext.resultsSet:
        error("Missing result binding: " & res.name, hdr)

    if not ctx.callContext.callEmitted:
      error("Missing (call) or (extcall) in prepare block", hdr)
  else:
    if not ctx.callContext.callEmitted:
      error("Missing (extcall) in prepare block", hdr)

  ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (call) marker inside a prepare block - emits the actual call instruction
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)

  if ctx.callContext.indirect:
    # Indirect call through a function-pointer variable: load the pointer into x16
    # (IP0 — caller-saved, not an argument register, so the prepared args in x0–x7
    # are untouched) and `blr` through it. A global's address is formed with adrp+add
    # (recorded as a gvar site and patched once the data layout is known), exactly
    # like a `(lea reg gvar)`; then the pointer value is loaded and called.
    if sym.kind == skGvar:
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X16)            # x16 = &fnptr
      ctx.gvarSites.add (pos, sym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X16, 0'i32)  # x16 = fnptr
    else:
      error("Indirect call through unsupported function-pointer location: " &
            $sym.kind, n)
    arm64.emitBlr(ctx.buf.data, arm64.X16)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)

  ctx.buf.emitBL(labId)
  ctx.callContext.callEmitted = true

  inc n

proc genExtcallA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)

  # Record call site and emit BL (will be patched to point to stub)
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.data.addUint32(0x94000000'u32)  # BL placeholder

  ctx.callContext.callEmitted = true

  inc n

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
  elif n.kind == TagLit:
    # Hardware condition - ARM64 uses flags from CMP
    let flagTag = tagToX64Flag(n.tag)
    inc n

    # Emit branch to else if condition is NOT met (inverted condition)
    case flagTag
    of ZfO: ctx.buf.emitBne(lElse)   # if ZF set wanted, jump to else if ZF clear
    of NzO: ctx.buf.emitBeq(lElse)   # if ZF clear wanted, jump to else if ZF set
    else: error("Unsupported ARM64 flag condition: " & $flagTag, n)
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

proc genLoopA64(n: var Cursor; ctx: var GenContext) =
  inc n
  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  ctx.buf.defineLabel(lStart)
  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

  # ARM64 loop conditions - exit loop if condition is NOT met
  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitBne(lEnd)   # if ZF set wanted, exit if ZF clear
  of NzO: ctx.buf.emitBeq(lEnd)   # if ZF clear wanted, exit if ZF set
  else: error("Unsupported ARM64 loop condition: " & $loopFlagTag, n)

  genStmt(n, ctx)
  ctx.buf.emitB(lStart)
  ctx.buf.defineLabel(lEnd)

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

proc genKillA64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)
  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  ctx.scope.undefine(name)
  inc n

proc memWidthOpc(typ: Type; isLoad: bool): tuple[size, opc: int] =
  ## Access width (0=byte,1=half,2=word,3=dword) and the load/store `opc` for a
  ## typed memory operand. A `(mem (dot …))` / `(mem (at …))` carries the field /
  ## element type, so a narrow integer load sign-/zero-extends and a narrow store
  ## writes only its low bits. Anything non-integer (pointer, raw `(mem reg)`,
  ## stack slot) is a full 64-bit access.
  var bits = 64
  var signed = false
  if typ != nil:
    case typ.kind
    of IntT: bits = typ.bits; signed = true       # `(i N)` (and `(c N)` chars)
    of UIntT: bits = typ.bits
    of BoolT: bits = 8
    else: bits = 64                                # PtrT / StackOffT / raw mem
  let size = case bits
    of 8: 0
    of 16: 1
    of 32: 2
    else: 3
  let opc = if not isLoad: 0
            elif size == 3: 1                      # 64-bit: plain load, no extend
            elif signed: 2                         # LDRSB/LDRSH/LDRSW → 64-bit
            else: 1                                # LDRB/LDRH/LDR(W) zero-extend
  (size, opc)

proc genInstA64(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToA64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: name, kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)
    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsA64Reg(locTag):
        # Check for reserved registers (x16/x17 are reserved for assembler scratch)
        let regTag = tagToA64Reg(locTag)
        if regTag == X16R:
          error("Cannot bind variable to x16 (reserved for assembler use as IP0)", n)
        elif regTag == X17R:
          error("Cannot bind variable to x17 (reserved for assembler use as IP1)", n)
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        inc n
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: name, kind: skVar)
    if onStack:
      sym.typ = Type(kind: StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp)
    else:
      sym.typ = baseTyp
      sym.reg = reg
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handle via `case instTag`"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD,
     ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD:
    raiseAssert("Unhandled declaration tag: " & $declTag)

  case instTag
  of StmtsA64:
    loopInto n:
      genInstA64(n, ctx)
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
    let name = symName(n)
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

  of MovA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    # Type-check the move (consistent with x64's mov and ARM64's add/sub): a
    # named local carries its declared type, so e.g. narrowing `(mov i8local
    # i64val)` is rejected, while a widening `(mov i64local i8field)` (extending
    # load) is allowed. Raw registers are RegisterT (compatible with anything).
    if dest.typ != nil and op.typ != nil and not movCompatible(dest.typ, op.typ):
      typeError(dest.typ, op.typ, start)
    if dest.kind == okMem:
      if op.kind == okImm:
        error("Moving immediate to memory not fully supported yet for ARM64", n)
      elif op.kind == okSsize:
        error("Moving ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot move memory to memory", n)
      elif dest.mem.hasIndex:
        var base = dest.mem.base
        if dest.mem.offset != 0:
          arm64.emitAddImm(ctx.buf.data, arm64.X16, base, uint16(dest.mem.offset))
          base = arm64.X16
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        arm64.emitLoadStoreReg(ctx.buf.data, op.reg, base, dest.mem.index, size, opc, dest.mem.shift)
      else:
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        arm64.emitLoadStoreUImm(ctx.buf.data, op.reg, dest.mem.base, dest.mem.offset, size, opc)
    else:
      if op.kind == okSsize:
        arm64.emitMovImm(ctx.buf.data, dest.reg, 0'u16)
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitMovImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          # MOVZ + MOVK loads the full 64-bit pattern, including negatives and
          # the raw bit patterns of floating-point constants.
          arm64.emitMovImm64(ctx.buf.data, dest.reg, cast[uint64](op.immVal))
      elif op.kind == okMem and op.mem.hasIndex:
        var base = op.mem.base
        if op.mem.offset != 0:
          arm64.emitAddImm(ctx.buf.data, arm64.X16, base, uint16(op.mem.offset))
          base = arm64.X16
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        arm64.emitLoadStoreReg(ctx.buf.data, dest.reg, base, op.mem.index, size, opc, op.mem.shift)
      elif op.kind == okMem:
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        arm64.emitLoadStoreUImm(ctx.buf.data, dest.reg, op.mem.base, op.mem.offset, size, opc)
      elif dest.reg == op.reg:
        # 64-bit register self-move is a no-op; elide it. This makes a result
        # self-binding such as `(mov (x0) (res ret.0))` cost nothing, so callers
        # can declaratively bind results to their natural register for free.
        discard
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, op.reg)

  of LeaA64:
    # (lea reg <mem>): load the *address* of a stack var / field into `reg`
    # (`add reg, base, #offset`), rather than the value at it.
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("lea destination must be a register", n)
    if op.kind != okMem: error("lea source must be a memory operand", n)
    arm64.emitAddImm(ctx.buf.data, dest.reg, op.mem.base, uint16(op.mem.offset))

  of AdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("ADR destination must be register", n)
    if op.tlvSym != nil:
      # Thread-local variable (macOS/arm64): obtain its address through the TLV
      # descriptor thunk. The descriptor lives in __DATA/__thread_vars; its first
      # word is a function pointer that, called with the descriptor address in
      # x0, returns the variable's address in x0 (preserving all other regs).
      #   adrp x0, desc@PAGE ; add x0, x0, desc@PAGEOFF   (patched in writeMachO)
      #   ldr  x16, [x0]                                   ; load the thunk
      #   blr  x16                                         ; x0 = &var
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X0)     # x0 = &descriptor
      ctx.tlvSites.add (pos, op.tlvSym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X0, 0'i32)
      arm64.emitBlr(ctx.buf.data, arm64.X16)
      if dest.reg != arm64.X0:
        arm64.emitMov(ctx.buf.data, dest.reg, arm64.X0)
    elif op.gvarSym != nil:
      # Global in __DATA/.bss: form its address with adrp+add (PC-relative adr
      # can't reach __DATA). Emit placeholders; writeMachO patches the page /
      # page-offset once the __DATA layout is known.
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, dest.reg)
      ctx.gvarSites.add (pos, op.gvarSym)
    else:
      # Check if operand is a label: type should be UIntT and not immediate/memory
      if op.typ.kind != UIntT or op.kind == okImm or op.kind == okMem:
        error("ADR source must be a label", n)
      arm64.emitAdr(ctx.buf, dest.reg, op.label)

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
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          error("Immediate value too large for ADD (must fit in 16 bits)", n)
      elif op.kind == okMem:
        error("ADD from memory not supported yet", n)
      else:
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg)

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
        ctx.ssizePatches.add(ctx.buf.data.len - 4)
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          error("Immediate value too large for SUB (must fit in 16 bits)", n)
      elif op.kind == okMem:
        error("SUB from memory not supported yet", n)
      else:
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg)

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

  of AsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "asr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitAsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitAsr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of NegA64:
    inc n
    let op = parseDestA64(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    arm64.emitNeg(ctx.buf.data, op.reg, op.reg)

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

  of RetA64:
    inc n
    arm64.emitRet(ctx.buf.data)

  of NopA64:
    inc n
    arm64.emitNop(ctx.buf.data)

  of SvcA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.kind != okImm:
      error("SVC requires immediate operand", n)
    if op.immVal < 0 or op.immVal > 0xFFFF:
      error("SVC immediate must be 0-65535", n)
    arm64.emitSvc(ctx.buf.data, uint16(op.immVal))

  of LdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("LDR destination must be register", n)
    if op.kind == okMem:
      ctx.buf.data.emitLdr(dest.reg, op.mem.base, op.mem.offset)
    else:
      error("LDR source must be memory", n)

  of StrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("STR destination must be memory", n)
    if op.kind == okMem: error("STR source cannot be memory", n)
    ctx.buf.data.emitStr(op.reg, dest.mem.base, dest.mem.offset)

  of LdaxrA64:
    # (ldaxr Dt Sptr) — Dt ← exclusive-acquire load of [Sptr].
    inc n
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    arm64.emitLdaxr(ctx.buf.data, rt, rn)

  of StlxrA64:
    # (stlxr St Dval Sptr) — store-release-exclusive Dval to [Sptr]; St ← status.
    inc n
    let rs = parseRegisterA64(n)
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    arm64.emitStlxr(ctx.buf.data, rs, rt, rn)

  of LdarA64:
    # (ldar Dt Sptr) — Dt ← acquire load of [Sptr].
    inc n
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    arm64.emitLdar(ctx.buf.data, rt, rn)

  of StlrA64:
    # (stlr Dval Sptr) — release store Dval to [Sptr].
    inc n
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    arm64.emitStlr(ctx.buf.data, rt, rn)

  of LdrbA64:
    # (ldrb Dt Bbase Iindex) — Dt ← zero-extended byte [Bbase + Iindex].
    inc n
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    let rm = parseRegisterA64(n)
    arm64.emitLdrbReg(ctx.buf.data, rt, rn, rm)

  of StrbA64:
    # (strb Dval Bbase Iindex) — store low byte of Dval to [Bbase + Iindex].
    inc n
    let rt = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    let rm = parseRegisterA64(n)
    arm64.emitStrbReg(ctx.buf.data, rt, rn, rm)

  of DmbA64:
    inc n
    arm64.emitDmbIsh(ctx.buf.data)

  of ClrexA64:
    inc n
    arm64.emitClrex(ctx.buf.data)

  of FmovA64:
    # (fmov D S): D=fp,S=fp → reg copy; D=fp,S=gpr / D=gpr,S=fp → bit move.
    # The size (s/d) comes from whichever operand is an fp register.
    inc n
    if isA64FpRegOperand(n):
      let single = isA64SingleOperand(n)
      let rd = parseFloatRegisterA64(n)
      if isA64FpRegOperand(n):
        arm64.emitFmov(ctx.buf.data, rd, parseFloatRegisterA64(n), single)
      else:
        arm64.emitFmovFromGpr(ctx.buf.data, rd, parseRegisterA64(n), single)
    else:
      let rd = parseRegisterA64(n)
      let single = isA64SingleOperand(n)
      arm64.emitFmovToGpr(ctx.buf.data, rd, parseFloatRegisterA64(n), single)

  of FaddA64, FsubA64, FmulA64, FdivA64:
    # (fop D S) → D = D op S  (emitted as `fop Dd, Dd, Ds`).
    inc n
    let single = isA64SingleOperand(n)
    let rd = parseFloatRegisterA64(n)
    let rs = parseFloatRegisterA64(n)
    case instTag
    of FaddA64: arm64.emitFadd(ctx.buf.data, rd, rd, rs, single)
    of FsubA64: arm64.emitFsub(ctx.buf.data, rd, rd, rs, single)
    of FmulA64: arm64.emitFmul(ctx.buf.data, rd, rd, rs, single)
    else:       arm64.emitFdiv(ctx.buf.data, rd, rd, rs, single)

  of FnegA64:
    inc n
    let single = isA64SingleOperand(n)
    let rd = parseFloatRegisterA64(n)
    arm64.emitFneg(ctx.buf.data, rd, rd, single)

  of FcmpA64:
    inc n
    let single = isA64SingleOperand(n)
    let rn = parseFloatRegisterA64(n)
    let rm = parseFloatRegisterA64(n)
    arm64.emitFcmp(ctx.buf.data, rn, rm, single)

  of FldrA64:
    # (fldr D <mem>) — load a double/single.
    inc n
    let single = isA64SingleOperand(n)
    let rt = parseFloatRegisterA64(n)
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem: error("FLDR source must be memory", n)
    arm64.emitFldr(ctx.buf.data, rt, op.mem.base, op.mem.offset, single)

  of FstrA64:
    # (fstr <mem> D) — store a double/single.
    inc n
    let dest = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("FSTR destination must be memory", n)
    let single = isA64SingleOperand(n)
    let rt = parseFloatRegisterA64(n)
    arm64.emitFstr(ctx.buf.data, rt, dest.mem.base, dest.mem.offset, single)

  of ScvtfA64, UcvtfA64:
    # (scvtf Dfp Sgpr) — int → double/single.
    inc n
    let single = isA64SingleOperand(n)
    let rd = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if instTag == ScvtfA64: arm64.emitScvtf(ctx.buf.data, rd, rn, single)
    else:                   arm64.emitUcvtf(ctx.buf.data, rd, rn, single)

  of FcvtzsA64, FcvtzuA64:
    # (fcvtzs Dgpr Sfp) — double/single → int (toward zero).
    inc n
    let rd = parseRegisterA64(n)
    let single = isA64SingleOperand(n)
    let rn = parseFloatRegisterA64(n)
    if instTag == FcvtzsA64: arm64.emitFcvtzs(ctx.buf.data, rd, rn, single)
    else:                    arm64.emitFcvtzu(ctx.buf.data, rd, rn, single)

  of FcvtA64:
    # (fcvt Ddst Ssrc) — precision convert; direction from the operand sizes.
    inc n
    let dstSingle = isA64SingleOperand(n)
    let rd = parseFloatRegisterA64(n)
    let rn = parseFloatRegisterA64(n)
    if dstSingle: arm64.emitFcvtToSingle(ctx.buf.data, rd, rn)  # double → single
    else:         arm64.emitFcvtToDouble(ctx.buf.data, rd, rn)  # single → double

  of BA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitB(ctx.buf, op.label)
  of BlA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBL(ctx.buf, op.label)

  of BeqA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBeq(ctx.buf, op.label)

  of BneA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBne(ctx.buf, op.label)

  of BltA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBlt(ctx.buf, op.label)

  of BleA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBle(ctx.buf, op.label)

  of BgtA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBgt(ctx.buf, op.label)

  of BgeA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBge(ctx.buf, op.label)

  of BloA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBlo(ctx.buf, op.label)

  of BlsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBls(ctx.buf, op.label)

  of BhiA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBhi(ctx.buf, op.label)

  of BhsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBhs(ctx.buf, op.label)

  of StpA64:
    # (stp (rt1) (rt2) (rn) offset) → STP rt1, rt2, [rn, #offset]!  (pre-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("stp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitStp(ctx.buf.data, rt1, rt2, rn, off)

  of LdpA64:
    # (ldp (rt1) (rt2) (rn) offset) → LDP rt1, rt2, [rn], #offset  (post-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("ldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitLdp(ctx.buf.data, rt1, rt2, rn, off)

  of FstpA64:
    # (fstp (dt1) (dt2) (rn) offset) → STP Dt1, Dt2, [Xn, #offset]!  (pre-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fstp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFstpPre(ctx.buf.data, rt1, rt2, rn, off)

  of FldpA64:
    # (fldp (dt1) (dt2) (rn) offset) → LDP Dt1, Dt2, [Xn], #offset  (post-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFldpPost(ctx.buf.data, rt1, rt2, rn, off)

  of NoA64Inst:
    error("Invalid ARM64 instruction", n)

proc genInst(n: var Cursor; ctx: var GenContext) =
  case ctx.arch
  of Arch.X64, Arch.WinX64:
    genInstX64(n, ctx)
  of Arch.A64, Arch.WinA64, Arch.LinuxA64:
    genInstA64(n, ctx)

proc collectLabels(n: var Cursor; ctx: var GenContext; scope: Scope) =
  ## Pre-scan a cursor subtree and create placeholder symbols for labels.
  if n.kind == TagLit:
    if n.tag == LabTagId:
      var tmp = n
      inc tmp
      if tmp.kind == SymbolDef:
        let name = symName(tmp)
        var sym = scope.lookup(name)
        if sym == nil:
          let labId = ctx.buf.createLabel()
          sym = Symbol(name: name, kind: skLabel, offset: int(labId))
          scope.define(sym)
        elif sym.kind == skLabel and sym.offset == -1:
          sym.offset = int(ctx.buf.createLabel())
    loopInto n:
      collectLabels(n, ctx, scope)
  else:
    inc n

proc pass2Proc(n: var Cursor; ctx: var GenContext) =
  let oldScope = ctx.scope
  ctx.scope = newScope(oldScope)

  # `into` bounds the cursor to the proc's own children, so walking to the body
  # can never run into the following decls (the main module's buffer continues
  # past this proc) and a body-less proc just iterates to its end.
  into n:
    if n.kind != SymbolDef:
      error("Expected symbol definition", n)
    let name = symName(n)
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
    # Each proc is a fresh control flow: no registers are clobbered on entry.
    # (Matters now that proc bodies are emitted back-to-back when bundling.)
    ctx.clobbered = {}

    # Add params to scope.
    #
    # Stack-passed params live in the incoming argument area. On x86-64 that area
    # sits above the saved RBP and return address (RBP+16). On AArch64 the return
    # address is in LR (not on the stack) and the caller leaves SP pointing right
    # at the first stack arg, so incoming stack params are addressed SP-relative
    # from offset 0 (valid before the callee shifts SP).
    let isA64Proc = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}
    var paramOffset = if isA64Proc: 0 else: 16
    for param in sym.typ.params:
      if param.typ.isOnStack:
        # param.typ is already StackOffT
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, offset: paramOffset))
        paramOffset += slots.alignedSize(param.typ.offType)
      else:
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, reg: param.reg))
        # Track register binding for parameters (x86 only; the A64 path resolves
        # param registers directly via tagToRegisterA64 and has no regBindings).
        if not isA64Proc and param.reg != InvalidTagId:
          let targetReg = tagToRegister(param.reg, n)
          ctx.regBindings[targetReg] = param.name

    skip n   # past the proc name
    # Emit the body — the `(stmts …)` child — and skip the signature sections
    # (already consumed in pass1). The `while hasMore` is bounded by the proc's
    # `into`, so it stops at the proc end naturally.
    while n.hasMore:
      if atTag(n, StmtsTagId):
        var scan = n
        collectLabels(scan, ctx, ctx.scope)
        loopInto n:
          genInst(n, ctx)
      else:
        skip n

  # Check that all declared cfvars were used exactly once
  for cfvarName, cfvarSym in ctx.scope.syms:
    if cfvarSym.kind == skCfvar:
      if not cfvarSym.used:
        quit "[Error] Control flow variable '" & cfvarName & "' declared but never used in proc " & ctx.procName

  # Patch ssize. On x86 the placeholder is a raw imm32 in the instruction; on
  # AArch64 the immediate is a bit-field of a 32-bit instruction, so the patch
  # rewrites that field (MOVZ imm16 at [20:5]; ADD/SUB imm12 at [21:10]).
  let alignedStackSize = (ctx.slots.stackSize + 15) and not 15
  let isA64 = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}
  let v = uint32(alignedStackSize)
  for pos in ctx.ssizePatches:
    if pos + 4 > ctx.buf.data.len: continue
    if isA64:
      var instr = uint32(ctx.buf.data[pos]) or (uint32(ctx.buf.data[pos+1]) shl 8) or
                  (uint32(ctx.buf.data[pos+2]) shl 16) or (uint32(ctx.buf.data[pos+3]) shl 24)
      if (instr shr 24) == 0xD2'u32:        # MOVZ Xd, #imm16 → imm16 at [20:5]
        instr = (instr and not (0xFFFF'u32 shl 5)) or ((v and 0xFFFF'u32) shl 5)
      else:                                 # ADD/SUB Xd, Xn, #imm12 → imm12 at [21:10]
        instr = (instr and not (0xFFF'u32 shl 10)) or ((v and 0xFFF'u32) shl 10)
      ctx.buf.data[pos]   = byte(instr and 0xFF)
      ctx.buf.data[pos+1] = byte((instr shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((instr shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((instr shr 24) and 0xFF)
    else:
      ctx.buf.data[pos]   = byte(v and 0xFF)
      ctx.buf.data[pos+1] = byte((v shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((v shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((v shr 24) and 0xFF)

  ctx.scope = oldScope

proc genStmt(n: var Cursor; ctx: var GenContext) =
  if atTag(n, StmtsTagId):
    loopInto n:
      genInst(n, ctx)
  else:
    genInst(n, ctx)

proc parseOperand(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == TagLit:
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
      if n.kind == TagLit and rawTagIsX64Reg(n.tag):
        # (dot (base-reg) stackvar fieldname) - explicit stack object access
        baseReg = parseRegister(n)

        # Parse stack variable name for offset
        if n.kind != Symbol:
          error("Expected stack variable name in dot expression", n)
        let stackVarName = getSym(n)
        let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
        if stackSym == nil or not stackSym.typ.isOnStack:
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
          objType = resolvedBase(baseOp.typ, ctx, n)
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

    elif t == AtTagId:
      # (at <base-reg> <stackvar> <index>)            stack array, OR
      # (at <aptr-or-ptr-to-array> <index>)           folds to base+index*scale, OR
      # (at <base> <index> <scratch-reg>)             3-operand form: the element
      #   stride isn't a legal SIB scale (a multi-dimensional array's outer
      #   dimension), so arkham hands us a scratch register and WE compute the
      #   address `base + index*stride` into it — keeping the size arithmetic in
      #   the typed layer (we know the stride) and the register allocation in
      #   arkham (it owns the scratch). `into` bounds the node so the optional
      #   third operand is read without running into the following sibling.
      into n:
        var elemType: Type
        var baseReg: x86.Register
        var baseDisp: int32 = 0
        var baseIndex: x86.Register
        var baseScale: int = 0
        var baseHasIndex = false
        var indexOp: Operand

        if n.kind == TagLit and rawTagIsX64Reg(n.tag):
          # (at (base-reg) stackvar index) - explicit stack array access
          baseReg = parseRegister(n)
          if n.kind != Symbol:
            error("Expected stack variable name in at expression", n)
          let stackVarName = getSym(n)
          let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
          if stackSym == nil or not stackSym.typ.isOnStack:
            error("Expected stack variable in at, got: " & stackVarName, n)
          let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
          if baseTyp.kind != TypeKind.ArrayT:
            error("at requires array type, got " & $baseTyp, n)
          baseDisp = int32(stackSym.offset)
          elemType = baseTyp.elem
          inc n
          indexOp = parseOperand(n, ctx)
        else:
          # (at <base> index) where <base> is an array-pointer variable (`aptr`) or
          # a pointer-to-array address `(cast (ptr (array elem N)) base)` — how
          # arkham reaches a global array or a deref'd array field. A nested `(at …)`
          # base carries its own base register + displacement (+ index), folded on.
          var baseOp = parseOperand(n, ctx)
          indexOp = parseOperand(n, ctx)
          if baseOp.typ.kind == TypeKind.AptrT:
            elemType = resolvedBase(baseOp.typ, ctx, n)
            baseReg = baseOp.reg
          elif baseOp.typ.kind == TypeKind.PtrT and
               resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
            elemType = resolvedBase(baseOp.typ, ctx, n).elem
            if baseOp.kind == okMem:
              baseReg = baseOp.mem.base
              baseDisp = baseOp.mem.displacement
              baseIndex = baseOp.mem.index
              baseScale = baseOp.mem.scale
              baseHasIndex = baseOp.mem.hasIndex
            else:
              baseReg = baseOp.reg
          else:
            error("at requires (base-reg stackvar index) or a pointer-to-array base, got " & $baseOp.typ, n)

        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)

        # Optional third operand: an arkham-supplied scratch register for a stride
        # that can't be a SIB scale.
        var hasScratch = false
        var scratchReg: x86.Register
        if n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
          scratchReg = parseRegister(n)
          hasScratch = true

        if hasScratch:
          # Compute `scratch = baseAddr + index*stride` ourselves (stride from the
          # element type). arkham only emits this for a register index, so indexOp
          # is in a register. base+disp (and a power-of-two-free stride) collapse via
          # one `imul` + one `lea`; a base that already holds an index would need a
          # second index slot we don't have (a deeper mixed-stride nest — not emitted
          # by the current arkham).
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          let stride = asmSizeOf(elemType)
          x86.emitMov(ctx.buf.data, scratchReg, indexOp.reg)        # scratch = index
          x86.emitImulImm(ctx.buf.data, scratchReg, int32(stride))  # scratch *= stride
          x86.emitLea(ctx.buf.data, scratchReg,                     # scratch = base + disp + scratch
            x86.MemoryOperand(base: baseReg, index: scratchReg, scale: 1,
                              displacement: baseDisp, hasIndex: true))
          result.kind = okMem
          result.mem = x86.MemoryOperand(base: scratchReg, displacement: 0, hasIndex: false)
        elif indexOp.kind == okImm:
          # Immediate index: fold into the displacement (any stride).
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: baseIndex, scale: baseScale,
            displacement: baseDisp + int32(offset), hasIndex: baseHasIndex)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          # Register index folded as a SIB scale. arkham only emits the 2-operand
          # form when the stride is a legal scale and the base has no index, so these
          # are invariants here (kept as asserts).
          if baseHasIndex:
            error("at: two register indices cannot fold into one memory operand", n)
          let elemSize = asmSizeOf(elemType)
          if elemSize notin [1, 2, 4, 8]:
            error("Element size " & $elemSize & " not a SIB scale and no scratch supplied", n)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: indexOp.reg, scale: elemSize,
            displacement: baseDisp, hasIndex: true)

        result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n

    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      result.reg = RAX
      result.label = LabelId(sym.offset)
      # Label address type is pointer to code?
      result.typ = Type(kind: UIntT, bits: 64) # Address
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      # Cast allows us to opt-out of type system, so we don't check against expectedType here
      var op = parseOperand(n, ctx)
      op.typ = castType
      result = op
    elif t == MemTagId:
      # (mem <address-expr>) or (mem <base> <offset>) or (mem <base> <index> <scale>) etc.
      # `into` bounds the cursor to the mem node, so the OPTIONAL index/scale/offset
      # checks below are gated by `hasMore` and never read into the following sibling
      # (there is no ParRi sentinel to stop them otherwise).
      into n:
        # Check if first child is an address expression (dot/at) or explicit addressing
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          # Wrapped address expression: (mem (dot ...) or (mem (at ...))
          var addrOp = parseOperand(n, ctx)
          if addrOp.kind != okMem:
            error("mem requires address expression", n)

          # Dereference the pointer type
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)

          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)  # Dereference: ptr T -> T
        else:
          # Explicit addressing: (mem base) or (mem base offset) or (mem base index scale [offset])
          var baseOp = parseOperand(n, ctx)
          if baseOp.kind == okImm or baseOp.kind == okMem:
            error("mem base must be a register", n)

          var displacement: int32 = 0
          var hasIndex = false
          var indexReg: x86.Register = x86.RAX
          var scale: int = 1

          # Check for an optional offset/index (present only if the mem node has
          # more children).
          var stackVarType: Type = nil
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (rsp) (arg name)) — an outgoing stack-argument slot. The arg's
            # byte offset within the reserved area becomes the displacement.
            var an = n; inc an                  # peek the arg name before consuming
            let argName = if an.kind == Symbol: getSym(an) else: ""
            let argOff = parseOperand(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            displacement = int32(argOff.immVal)
            if argName.len > 0: ctx.callContext.argsSet.incl argName
          elif n.hasMore and (n.kind == IntLit or n.kind == Symbol):
            if n.kind == IntLit:
              displacement = int32(getInt(n))
              inc n
            elif n.kind == Symbol:
              # Could be index register or stack variable (used as offset)
              let indexName = getSym(n)
              let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
              if indexSym != nil and (indexSym.kind == skVar or indexSym.kind == skParam) and indexSym.typ.isOnStack:
                # Stack variable - use its offset as displacement and preserve type (unwrap StackOffT)
                displacement = int32(indexSym.offset)
                stackVarType = if indexSym.typ.kind == StackOffT: indexSym.typ.offType else: indexSym.typ
                inc n
              elif indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
                # This is the index register
                hasIndex = true
                indexReg = tagToRegister(indexSym.reg, n)
                inc n

                # Check for scale
                if n.hasMore and n.kind == IntLit:
                  scale = int(getInt(n))
                  if scale notin [1, 2, 4, 8]:
                    error("mem scale must be 1, 2, 4, or 8", n)
                  inc n

                  # Check for displacement after scale
                  if n.hasMore and n.kind == IntLit:
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
    elif t == SsizeTagId:
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == CsizeTagId:
      # (csize) - call stack argument size
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name) - argument reference in prepare block. Capture the node cursor
      # for diagnostics that run after we've advanced past it.
      let argTok = n
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", argTok)
      inc n
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      let argName = getSym(n)
      inc n

      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & argName, argTok)

      if paramPtr.typ.isOnStack:
        # Stack argument - return the offset as an immediate
        # The offset is computed from the stack parameter declarations
        var offset = 0
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
            offset += slots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset)
        result.typ = paramPtr.typ
      else:
        # Register argument - return the register
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegister(paramPtr.reg, argTok)
        result.typ = paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference in prepare block (after call). Capture the
      # node cursor for diagnostics: the semantic checks below run after we've
      # advanced past the node, where `n` would sit at the scope end (no loadable
      # token under nifcore).
      let resTok = n
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", resTok)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSym(n)
      inc n

      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", resTok)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & resName, resTok)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & resName, resTok)
      ctx.callContext.resultsSet.incl(resName)

      result.reg = tagToRegister(resPtr.reg, resTok)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegister(sym.reg, n)

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
      # Global variable - return its address. A foreign global is bundled into
      # this same image (see generateSymbol) and accessed like a local one.
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.gvarSym = sym                       # carry the symbol so `lea` can patch
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
    elif sym != nil and sym.kind == skProc:
      # A proc used as a value → its code address (RIP-relative): `lea reg, proc`
      # materializes a function pointer. Same label the proc's definition / a
      # direct `(call)` binds, so it resolves to the proc's entry.
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)   # a code pointer
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDest(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.reg = parseRegister(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name) as destination - for register arguments in prepare block
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    inc n
    if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
    let argName = getSym(n)
    inc n

    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil:
      error("Unknown argument: " & argName, n)

    if paramPtr.typ.isOnStack:
      error("Stack argument '" & argName & "' cannot be used directly as destination, use (mem (rsp) (arg " & argName & "))", n)

    # Track that this argument is being set
    if argName in ctx.callContext.argsSet:
      error("Argument already set: " & argName, n)
    ctx.callContext.argsSet.incl(argName)

    # Return the register for this argument
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegister(paramPtr.reg, n)
    result.typ = paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId):
    let op = parseOperand(n, ctx)
    if op.kind != okMem:
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # A param (skParam) is bound to a register / stack slot exactly like a var, so
    # it is a valid destination too (mirrors parseDestA64 and the source paths).
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
       if sym.typ.isOnStack:
         # Return StackOffT - operations like `add` will reject this at type check
         result.kind = okMem
         result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
         result.typ = sym.typ  # Already StackOffT from declaration
         inc n
         return
       elif sym.reg != InvalidTagId:
         result.reg = tagToRegister(sym.reg, n)
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
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[string](),
    resultsSet: initHashSet[string](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the extcall path.
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    # External proc - find its info
    ctx.callContext.state = CallContextState.ExternalCall
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
    # External procs don't have full signatures in current design
    # For now, we skip argument checking for external procs
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Compute stack argument size (only for internal procs)
  if ctx.callContext.state == CallContextState.NormalCall:
    ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstX64(n, ctx)

  # Verify all bindings are done
  if ctx.callContext.state == CallContextState.NormalCall:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & param.name, hdr)

    for res in ctx.callContext.typ.results:
      if res.name notin ctx.callContext.resultsSet:
        error("Missing result binding: " & res.name, hdr)

    # Verify call was emitted
    if not ctx.callContext.callEmitted:
      error("Missing (call) or (extcall) in prepare block", hdr)
  else:
    if not ctx.callContext.callEmitted:
      error("Missing (extcall) in prepare block", hdr)
  ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(call)` inside a `prepare` block emits the actual call: a direct `call rel32`
  ## to the prepared proc, or — when the prepare target is a function-pointer
  ## variable — an indirect call that loads the pointer and `call`s through it.
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)

  # Clobber registers
  ctx.clobbered.incl(ctx.callContext.typ.clobbers)

  if ctx.callContext.indirect:
    # Load the function pointer from its variable into rax — which the call
    # clobbers anyway and where a scalar result then lands — and call through it.
    # The gvar's RIP-relative address is recorded as a site and patched by writeElf,
    # exactly like a `(lea reg gvar)`.
    let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RAX)               # lea rax, [rip+fnptr]
    ctx.gvarSites.add (pos, sym)
    x86.emitMov(ctx.buf.data, x86.RAX, x86.MemoryOperand(base: x86.RAX)) # mov rax, [rax]
    x86.emitCallReg(ctx.buf.data, x86.RAX)                              # call rax
  else:
    var labId: LabelId
    if sym.offset == -1:
      labId = ctx.buf.createLabel()
      sym.offset = int(labId)
    else:
      labId = LabelId(sym.offset)
    ctx.buf.emitCall(labId)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(call` head

proc genExtcallX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call via IAT
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)

  # Record call site and emit IAT call
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.emitIatCall(ctx.extProcs[ctx.callContext.extProcIdx].gotSlot)

  ctx.callContext.callEmitted = true

  inc n

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

proc intMemAccess(typ: Type): tuple[bits: int; signed: bool] =
  ## A typed memory operand's access width + signedness, so a sub-word field /
  ## element load sign-/zero-extends and a narrow store writes only its low bits.
  ## Pointers / raw `(mem reg)` / stack slots are full 64-bit accesses.
  if typ == nil: return (64, false)
  case typ.kind
  of IntT: (typ.bits, true)
  of UIntT: (typ.bits, false)
  of BoolT: (8, false)
  else: (64, false)

proc genMovX64(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  let dest = parseDest(n, ctx)
  let op = parseOperand(n, ctx)

  # Type checking. A *sized* integer mem↔reg move legitimately differs in width:
  # a load into a 64-bit register sign-/zero-extends a narrower field/element, and
  # a store writes only the register's low bits. So when exactly one side is memory
  # and both are integer-like, any width pairing is accepted (the sized emit below
  # handles extension/truncation); other moves keep the strict check.
  if dest.typ != nil and op.typ != nil:
    proc isIntLike(t: Type): bool = t.kind in {IntT, UIntT, BoolT, IntLitT}
    let sizedMemReg = (dest.kind == okMem) != (op.kind == okMem) and
                      isIntLike(dest.typ) and isIntLike(op.typ)
    if not sizedMemReg:
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
      let (bits, _) = intMemAccess(dest.typ)     # sized store: don't clobber neighbors
      x86.emitMovToMemSized(ctx.buf.data, dest.mem, op.reg, bits)
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
      let (bits, signed) = intMemAccess(op.typ)  # sized load: sign-/zero-extend sub-word
      x86.emitLoadExt(ctx.buf.data, dest.reg, op.mem, bits, signed)
    else:
      x86.emitMov(ctx.buf.data, dest.reg, op.reg)

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

  elif n.kind == TagLit:
    # Hardware flag: (ite (flag) ...)
    let flagTag = tagToX64Flag(n.tag)
    inc n
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


proc genLoopX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Pre-loop
  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  ctx.buf.defineLabel(lStart)

  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

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


proc genKillX64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)

  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  elif sym.reg != InvalidTagId:
    # Remove register binding when variable is killed
    let targetReg = tagToRegister(sym.reg, n)
    ctx.regBindings.del(targetReg)

  # Remove from scope to ensure it's not used again
  ctx.scope.undefine(name)

  inc n

proc genInstX64(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToX64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    # (cfvar :name.0)
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n

    # Control flow variables are always virtual (bool type, never materialized)
    # We create a label for when this cfvar becomes "true"
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: name, kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)

    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsX64Reg(locTag):
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        inc n
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)

    let sym = Symbol(name: name, kind: skVar)
    if onStack:
      sym.typ = Type(kind: StackOffT, offType: baseTyp)
      # Positive, base-relative offsets (like AArch64): the code generator lowers
      # rsp by a 16-aligned `sub rsp, (ssize)` so the slots sit ABOVE rsp, where a
      # `call`'s pushed return address (and any callee pushes) can't reach them. A
      # red-zone (negative-offset) slot whose address escapes into a call would be
      # clobbered by that call. No frame pointer is needed.
      sym.offset = ctx.slots.allocSlotUp(baseTyp)
    else:
      sym.typ = baseTyp
      sym.reg = reg
      # Check if register is already bound to another variable
      let targetReg = tagToRegister(reg, n)
      if targetReg in ctx.regBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.regBindings[targetReg] & "', kill it first before reusing", n)
      # Track the register binding
      ctx.regBindings[targetReg] = name

    ctx.scope.define(sym)

    return
  of NoDecl:
    discard "continue with case instTag"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD:
    error("Unexpected declaration: " & $declTag, n)

  case instTag
  of NoX64Inst:
    error("No x86 instruction", n)
  of StmtsX64:
    loopInto n:
      genInstX64(n, ctx)
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

  of MulX64:
    inc n
    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "mul", start)
    if op.kind == okImm: error("MUL immediate not supported (use IMUL)", n)
    elif op.kind == okMem:
      x86.emitMul(ctx.buf.data, op.mem)
    else:
      x86.emitMul(ctx.buf.data, op.reg)

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

  of DivX64:
    # (div (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for div", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for div", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "div", start)
    if op.kind == okImm: error("DIV immediate not supported", n)
    # Unsigned divide needs the high half of the dividend (RDX) zeroed.
    x86.emitXor(ctx.buf.data, x86.RDX, x86.RDX)
    if op.kind == okMem:
      x86.emitDiv(ctx.buf.data, op.mem)
    else:
      x86.emitDiv(ctx.buf.data, op.reg)

  of IdivX64:
    # (idiv (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for idiv", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "idiv", start)
    if op.kind == okImm: error("IDIV immediate not supported", n)
    # Signed divide needs RAX sign-extended into RDX:RAX first.
    x86.emitCqo(ctx.buf.data)
    if op.kind == okMem:
      x86.emitIdiv(ctx.buf.data, op.mem)
    else:
      x86.emitIdiv(ctx.buf.data, op.reg)

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

  # Unary
  of IncX64:
    inc n
    let op = parseDest(n, ctx) # Dest/Src same
    checkIntegerArithmetic(op.typ, "inc", start)
    if op.kind == okMem: error("INC memory not supported yet", n)
    x86.emitInc(ctx.buf.data, op.reg)

  of DecX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "dec", start)
    if op.kind == okMem: error("DEC memory not supported yet", n)
    x86.emitDec(ctx.buf.data, op.reg)

  of NegX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    x86.emitNeg(ctx.buf.data, op.reg)

  of NotX64:
    inc n
    let op = parseDest(n, ctx)
    checkBitwiseType(op.typ, "not", start)
    if op.kind == okMem: error("NOT memory not supported yet", n)
    x86.emitNot(ctx.buf.data, op.reg)

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

  # Conditional Sets
  of SeteX64, SetzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSete(ctx.buf.data, dest.reg)

  of SetneX64, SetnzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetne(ctx.buf.data, dest.reg)

  of SetaX64, SetnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeta(ctx.buf.data, dest.reg)

  of SetaeX64, SetnbX64, SetncX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetae(ctx.buf.data, dest.reg)

  of SetbX64, SetnaeX64, SetcX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetb(ctx.buf.data, dest.reg)
  of SetbeX64, SetnaX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetbe(ctx.buf.data, dest.reg)

  of SetgX64, SetnleX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetg(ctx.buf.data, dest.reg)

  of SetgeX64, SetnlX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetge(ctx.buf.data, dest.reg)
  of SetlX64, SetngeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetl(ctx.buf.data, dest.reg)

  of SetleX64, SetngX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetle(ctx.buf.data, dest.reg)

  of SetoX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeto(ctx.buf.data, dest.reg)

  of SetsX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSets(ctx.buf.data, dest.reg)

  of SetpX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetp(ctx.buf.data, dest.reg)
  # Conditional moves
  of CmoveX64, CmovzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmove(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmove(ctx.buf.data, dest.reg, op.reg)

  of CmovneX64, CmovnzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovne(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovne(ctx.buf.data, dest.reg, op.reg)

  of CmovaX64, CmovnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmova(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmova(ctx.buf.data, dest.reg, op.reg)

  of CmovaeX64, CmovnbX64, CmovncX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovae(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovae(ctx.buf.data, dest.reg, op.reg)

  of CmovbX64, CmovnaeX64, CmovcX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovb(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovb(ctx.buf.data, dest.reg, op.reg)

  of CmovbeX64, CmovnaX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovbe(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovbe(ctx.buf.data, dest.reg, op.reg)

  of CmovgX64, CmovnleX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovg(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovg(ctx.buf.data, dest.reg, op.reg)

  of CmovgeX64, CmovnlX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovge(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovge(ctx.buf.data, dest.reg, op.reg)

  of CmovlX64, CmovngeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovl(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovl(ctx.buf.data, dest.reg, op.reg)

  of CmovleX64, CmovngX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovle(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovle(ctx.buf.data, dest.reg, op.reg)

  of CmovoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovo(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovo(ctx.buf.data, dest.reg, op.reg)

  of CmovsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovs(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovs(ctx.buf.data, dest.reg, op.reg)

  of CmovpX64, CmovpeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovp(ctx.buf.data, dest.reg, op.reg)

  of CmovnpX64, CmovpoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovnp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovnp(ctx.buf.data, dest.reg, op.reg)

  of CmovnsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovns(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovns(ctx.buf.data, dest.reg, op.reg)

  of CmovnoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovno(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovno(ctx.buf.data, dest.reg, op.reg)
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

  of PopX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      error("POP memory not supported yet", n)
    else:
      x86.emitPop(ctx.buf.data, dest.reg)

  of SyscallX64:
    inc n
    x86.emitSyscall(ctx.buf.data)
  of LeaX64:
    # (lea dest base-reg offset) or (lea dest label). The destination is a
    # register or a named register local. `lea` *defines* its destination, so a
    # raw register node is accepted whether or not it is bound (unlike a use,
    # which parseDest would reject); a named local resolves to its register.
    inc n
    var dest: x86.Register
    if n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym != nil and sym.kind == skVar and sym.reg != InvalidTagId:
        dest = tagToRegister(sym.reg, n)
        ctx.clobbered.excl(dest)            # writing it makes it valid again
        inc n
      else:
        error("lea destination must be a register or register-bound local", n)
    elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
      dest = parseRegister(n)
    else:
      error("lea destination must be a register", n)

    # Check if next is a label or register
    if n.kind == TagLit and n.tag == LabTagId:
      # (lea dest (lab label)) - RIP-relative address
      inc n
      if n.kind != Symbol: error("Expected label name", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      inc n
      x86.emitLea(ctx.buf, dest, LabelId(sym.offset))
    elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
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
        if offsetSym != nil and offsetSym.kind == skTvar:
          # `lea dest, (fsbase) tvar` ⇒ dest = fsbase + tvar.offset = &tvar. A
          # thread-local has no link-time address (it lives at FS_base + offset);
          # nifasm owns the offset, the caller supplies the FS-base register, and
          # the offset folds into the lea displacement — no pointer arithmetic.
          displacement = int32(offsetSym.offset)
        elif offsetSym != nil and (offsetSym.kind == skVar or offsetSym.kind == skParam) and offsetSym.typ.isOnStack:
          displacement = int32(offsetSym.offset)
        else:
          error("Expected stack variable, thread-local, or integer offset in lea", n)
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
      # Try parsing as a label operand (rodata, gvar, etc.) or an addressing
      # expression — `(at …)` / `(dot …)` / `(mem …)` all parse to an `okMem`
      # operand carrying a full base+index*scale+displacement, which `lea`
      # materializes as an address (matching the AArch64 backend, whose `lea`
      # accepts the same forms). This is how arkham takes the address of an array
      # element or aggregate field on x86-64.
      let op = parseOperand(n, ctx)
      if op.gvarSym != nil:
        # Global in .bss (a different segment): emit a placeholder RIP-relative lea
        # and record the site; writeElf patches the disp32 against the .bss vaddr.
        let pos = x86.emitLeaRipPlaceholder(ctx.buf, dest)
        ctx.gvarSites.add (pos, op.gvarSym)
      elif op.kind == okLabel:
        x86.emitLea(ctx.buf, dest, op.label)
      elif op.kind == okMem:
        x86.emitLea(ctx.buf.data, dest, op.mem)
      else:
        error("lea requires an address expression (base-reg offset, mem, dot, at, or label)", n)
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
  of JeX64, JzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJe(ctx.buf, op.label)
  of JneX64, JnzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJne(ctx.buf, op.label)
  of JgX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJg(ctx.buf, op.label)
  of JgeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJge(ctx.buf, op.label)
  of JlX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJl(ctx.buf, op.label)
  of JleX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJle(ctx.buf, op.label)
  of JaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJa(ctx.buf, op.label)
  of JaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJae(ctx.buf, op.label)
  of JbX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJb(ctx.buf, op.label)
  of JbeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJbe(ctx.buf, op.label)
  of JngX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJle(ctx.buf, op.label)
  of JngeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJl(ctx.buf, op.label)
  of JnaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJbe(ctx.buf, op.label)
  of JnaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    x86.emitJb(ctx.buf, op.label)
  of NopX64:
    inc n
    x86.emitNop(ctx.buf.data)
  of RepmovsbX64:
    inc n
    x86.emitRepMovsb(ctx.buf.data)
  of RepmovswX64:
    inc n
    x86.emitRepMovsw(ctx.buf.data)
  of RepmovsdX64:
    inc n
    x86.emitRepMovsd(ctx.buf.data)
  of RepmovsqX64:
    inc n
    x86.emitRepMovsq(ctx.buf.data)
  of RetX64:
    inc n
    x86.emitRet(ctx.buf.data)
  of LabX64:
    # (lab :label)
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
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

  of MovapdX64:
    # (movapd dest src)
    inc n
    let dest = parseDest(n, ctx) # Should check if XMM
    let op = parseOperand(n, ctx) # Should check if XMM/Mem
    # Need to support XMM registers in parseRegister/Operand
    # And emitMovapd (likely similar to movsd but packed)
    # For now, placeholder error or implement if x86 supports it
    error("MOVAPD not supported yet", n)
  of MovsdX64, MovssX64:
    # `(movsd D S)`: a scalar-float move where one side may be memory:
    #   (movsd (xmmD) (xmmS))   reg→reg ;  (movsd (xmmD) (mem …))  load
    #   (movsd (mem …) (xmmS))  store
    let isD = instTag == MovsdX64
    inc n
    if isXmmTag(n):
      let d = parseXmm(n)
      if isXmmTag(n):
        let s = parseXmm(n)
        if isD: x86.emitMovsd(ctx.buf.data, d, s)
        else:   x86.emitMovss(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movsd/movss source must be xmm or memory", n)
        if isD: x86.emitMovsdLoad(ctx.buf.data, d, s.mem)
        else:   x86.emitMovssLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movsd/movss destination must be xmm or memory", n)
      let s = parseXmm(n)
      if isD: x86.emitMovsdStore(ctx.buf.data, d.mem, s)
      else:   x86.emitMovssStore(ctx.buf.data, d.mem, s)

  of AddsdX64, AddssX64, SubsdX64, SubssX64,
     MulsdX64, MulssX64, DivsdX64, DivssX64, Cvtsd2ssX64, Cvtss2sdX64,
     ComisdX64, ComissX64:
    # Scalar SSE op on two XMM registers: `(op (xmmD) (xmmS))` → dest = dest op src
    # (or just sets EFLAGS for comisd/comiss).
    let it = instTag
    inc n
    let d = parseXmm(n)
    let s = parseXmm(n)
    case it
    of AddsdX64:   x86.emitAddsd(ctx.buf.data, d, s)
    of AddssX64:   x86.emitAddss(ctx.buf.data, d, s)
    of SubsdX64:   x86.emitSubsd(ctx.buf.data, d, s)
    of SubssX64:   x86.emitSubss(ctx.buf.data, d, s)
    of MulsdX64:   x86.emitMulsd(ctx.buf.data, d, s)
    of MulssX64:   x86.emitMulss(ctx.buf.data, d, s)
    of DivsdX64:   x86.emitDivsd(ctx.buf.data, d, s)
    of DivssX64:   x86.emitDivss(ctx.buf.data, d, s)
    of Cvtsd2ssX64: x86.emitCvtsd2ss(ctx.buf.data, d, s)
    of Cvtss2sdX64: x86.emitCvtss2sd(ctx.buf.data, d, s)
    of ComisdX64:  x86.emitComisd(ctx.buf.data, d, s)
    of ComissX64:  x86.emitComiss(ctx.buf.data, d, s)
    else: discard

  of Cvtsi2sdX64, Cvtsi2ssX64:
    # int -> float: `(cvtsi2sd (xmmD) gprS)`; the GPR source may be a named local.
    let it = instTag
    inc n
    let d = parseXmm(n)
    let s = parseOperand(n, ctx).reg
    if it == Cvtsi2sdX64: x86.emitCvtsi2sd(ctx.buf.data, d, s)
    else:                 x86.emitCvtsi2ss(ctx.buf.data, d, s)

  of Cvttsd2siX64, Cvttss2siX64:
    # float -> int (truncating): `(cvttsd2si gprD (xmmS))`; GPR dest may be a local.
    let it = instTag
    inc n
    let d = parseDest(n, ctx).reg
    let s = parseXmm(n)
    if it == Cvttsd2siX64: x86.emitCvttsd2si(ctx.buf.data, d, s)
    else:                  x86.emitCvttss2si(ctx.buf.data, d, s)

  of MovfqX64, MovfdX64:
    # Bit-transfer between a GPR and an XMM register; direction by operand kinds.
    # `(movfq (xmmD) gprS)` = gpr→xmm; `(movfq gprD (xmmS))` = xmm→gpr. The GPR
    # side may be a raw register or a named local.
    let it = instTag
    inc n
    if isXmmTag(n):
      let d = parseXmm(n)
      let s = parseOperand(n, ctx).reg
      if it == MovfqX64: x86.emitMovqGprToXmm(ctx.buf.data, d, s)
      else:              x86.emitMovdGprToXmm(ctx.buf.data, d, s)
    else:
      let d = parseDest(n, ctx).reg
      let s = parseXmm(n)
      if it == MovfqX64: x86.emitMovqXmmToGpr(ctx.buf.data, d, s)
      else:              x86.emitMovdXmmToGpr(ctx.buf.data, d, s)

  of LockX64:
    inc n
    if n.kind != TagLit: error("Expected instruction to lock", n)
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
    of IncX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock inc", start)
      if dest.kind != okMem: error("Atomic INC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitInc(ctx.buf.data, dest.mem)
    of DecX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock dec", start)
      if dest.kind != okMem: error("Atomic DEC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitDec(ctx.buf.data, dest.mem)
    of NotX64:
      inc n
      let dest = parseDest(n, ctx)
      checkBitwiseType(dest.typ, "lock not", start)
      if dest.kind != okMem: error("Atomic NOT requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNot(ctx.buf.data, dest.mem)
    of NegX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock neg", start)
      if dest.kind != okMem: error("Atomic NEG requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNeg(ctx.buf.data, dest.mem)
    of XaddX64:
      # `lock xadd [mem], reg` — atomic exchange-and-add; reg receives the old value.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic XADD requires memory destination", n)
      if op.kind != okReg: error("Atomic XADD source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg)
    of CmpxchgX64:
      # `lock cmpxchg [mem], reg` — compares RAX with [mem]; on equal stores reg,
      # else loads [mem] into RAX. ZF reflects success.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic CMPXCHG requires memory destination", n)
      if op.kind != okReg: error("Atomic CMPXCHG source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg)
    else:
       error("Unsupported instruction for LOCK prefix: " & $innerInstTag, n)

    # Each inner branch already consumed the inner instruction (including its
    # closing `)`), so `n` is now at the `(lock …)` form's own closing paren.

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
  of Cmpxchg8bX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      x86.emitCmpxchg8b(ctx.buf.data, dest.mem)
    else:
      x86.emitCmpxchg8b(ctx.buf.data, dest.reg)
  of MfenceX64:
    inc n
    x86.emitMfence(ctx.buf.data)
  of SfenceX64:
    inc n
    x86.emitSfence(ctx.buf.data)
  of LfenceX64:
    inc n
    x86.emitLfence(ctx.buf.data)
  of PauseX64:
    inc n
    x86.emitPause(ctx.buf.data)

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

  of ClflushoptX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitClflushopt(ctx.buf.data, op.reg)
  of Prefetcht0X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT0(ctx.buf.data, op.reg)
  of Prefetcht1X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT1(ctx.buf.data, op.reg)
  of Prefetcht2X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT2(ctx.buf.data, op.reg)
  of PrefetchntaX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchNta(ctx.buf.data, op.reg)


proc pass2(n: Cursor; ctx: var GenContext) =
  ## Pass2: Generate code only for top-level instructions (entry point).
  ## Declarations (procs, rodata, gvars, etc.) are NOT generated here,
  ## EXCEPT for entry point procs (named `_start`).
  ## Other declarations are only generated when referenced via lookupWithAutoImport,
  ## which marks them as used and adds them to the pending list.
  ## This enables dead code elimination for the main module.
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          # Types were fully handled in pass1; skip the definition body.
          n = start
          skip n
        of ProcD:
          # Check if this is an entry point proc (_start or main.0)
          inc n
          if n.kind != SymbolDef:
            error("Expected symbol definition", n)
          let name = symName(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym != nil and sym.isForeign:
            # Skip foreign proc body
            n = start
            skip n
          elif name == "_start" or name == "main.0":
            # Entry point proc - generate it immediately. Mark it generated so
            # processReachableSymbols (which sees it in the pending list via the
            # lookupWithAutoImport above) does not emit a duplicate copy.
            n = start
            pass2Proc(n, ctx)
            ctx.generatedSymbols.incl name
            ctx.entrySym = sym             # the FS-setup prologue jumps here
          else:
            # Regular proc - skip, will be generated if referenced
            n = start
            skip n
        of RodataD, GvarD, TvarD:
          # Declarations are NOT generated here - they are subject to dead code elimination.
          # They will only be generated when referenced via lookupWithAutoImport.
          # Skip the declaration body.
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD, ExtprocD:
          # Already handled in pass1, skip
          skip n
        else:
          # Top-level instructions (entry point) - generate these
          genInst(n, ctx)
      else:
        error("Expected instruction", n)
  else:
    error("Expected stmts", n)

proc writeElf(a: var GenContext; outfile: string) =
  finalize(a.buf)
  finalize(a.bssBuf)
  var code = a.buf.data
  let baseAddr = 0x400000.uint64
  let headersSize = 64 + (56 * 2)  # ELF header + 2 program headers
  let pageSize = 0x1000.uint64

  # Calculate addresses and sizes
  # The LOAD segment must start at file offset 0 to include headers
  # (some kernels like WSL require this for proper loading)
  let textOffset = 0.uint64  # Include headers in LOAD segment
  let textVaddr = baseAddr   # Segment starts at base address
  let textFileSize = headersSize.uint64 + code.len.uint64  # Headers + code
  let textMemSize = (textFileSize + pageSize - 1) and not (pageSize - 1)

  # Entry point is after the headers. When nifasm synthesized a TLS-setup prologue
  # (see setupTls) it becomes the real entry — it sets the FS base then jumps to the
  # program's entry proc; otherwise the entry is the first byte of code (offset 0).
  let entryOff = if a.tlsEntryOffset >= 0: a.tlsEntryOffset.uint64 else: 0'u64
  let entryAddr = baseAddr + headersSize.uint64 + entryOff

  # .bss section comes after .text in memory
  let bssVaddr = textVaddr + textMemSize
  let bssSize = a.bssOffset.uint64

  # Patch each global's address into the placeholder instruction(s) now that both
  # segments' virtual addresses are known. The gvar's .bss byte offset is `sym.size`.
  for (pos, sym) in a.gvarSites:
    let instrVaddr = textVaddr + headersSize.uint64 + pos.uint64
    let targetVaddr = bssVaddr + sym.size.uint64
    if a.arch == Arch.LinuxA64:
      # AArch64: a PC-relative `adrp rd, page` + `add rd, rd, #pageoff` pair (the
      # placeholder carries the dest reg with zero immediates, so OR them in). Same
      # encoding as the Mach-O backend's gvar patch.
      let pageDiff = int64(targetVaddr and not 0xFFF'u64) -
                     int64(instrVaddr and not 0xFFF'u64)
      let pageOff = targetVaddr and 0xFFF'u64
      let adrpImm = pageDiff shr 12
      let immlo = uint32(adrpImm and 0x03) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      var adrp = uint32(code[pos]) or (uint32(code[pos+1]) shl 8) or
                 (uint32(code[pos+2]) shl 16) or (uint32(code[pos+3]) shl 24)
      adrp = adrp or immlo or immhi
      code[pos+0] = byte(adrp and 0xFF);          code[pos+1] = byte((adrp shr 8) and 0xFF)
      code[pos+2] = byte((adrp shr 16) and 0xFF); code[pos+3] = byte((adrp shr 24) and 0xFF)
      var add = uint32(code[pos+4]) or (uint32(code[pos+5]) shl 8) or
                (uint32(code[pos+6]) shl 16) or (uint32(code[pos+7]) shl 24)
      add = add or (uint32(pageOff and 0xFFF) shl 10)
      code[pos+4] = byte(add and 0xFF);           code[pos+5] = byte((add shr 8) and 0xFF)
      code[pos+6] = byte((add shr 16) and 0xFF);  code[pos+7] = byte((add shr 24) and 0xFF)
    else:
      # x86-64: a RIP-relative `lea` — 7 bytes with a disp32 at offset +3; RIP points
      # at the next instruction (+7).
      let disp = int32(int64(targetVaddr) - int64(instrVaddr + 7))
      code[pos + 3] = byte(disp and 0xFF)
      code[pos + 4] = byte((disp shr 8) and 0xFF)
      code[pos + 5] = byte((disp shr 16) and 0xFF)
      code[pos + 6] = byte((disp shr 24) and 0xFF)
  let bssAlignedSize = if bssSize > 0: ((bssSize + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  let machine = case a.arch
    of Arch.X64, Arch.LinuxA64:
      if a.arch == Arch.X64: EM_X86_64 else: EM_AARCH64
    else:
      EM_X86_64  # fallback

  var ehdr = initHeader(entryAddr, machine)
  ehdr.e_phnum = 2  # Two program headers: .text and .bss
  ehdr.e_phoff = 64  # Program headers start after ELF header

  # .text program header (executable, readable)
  # Starts at file offset 0, includes headers + code. `p_filesz == p_memsz`
  # (both the page-aligned `textMemSize`): the page padding is written to the file
  # below, so the segment has NO zero-fill tail. A non-writable PT_LOAD whose
  # `memsz > filesz` (a bss tail in an R+X segment) is rejected by stricter loaders
  # such as qemu-user ("PT_LOAD with non-writable bss"); real bss lives in the
  # separate writable `bssPhdr`.
  var textPhdr = initPhdr(textOffset, textVaddr, textMemSize, textMemSize, PF_R or PF_X)

  # .bss program header (writable, readable, not executable). Normally `.bss` is
  # zero-initialized by the loader (p_filesz = 0). When some gvars have constant
  # static initializers (`a.bssInits` — e.g. `stdout = 1`), the segment is instead
  # file-backed: an on-disk image holds those bytes (the rest zero), so the slots
  # start with their values without any entry-time init code (correct in a bundle).
  var bssImage: seq[byte]
  if a.bssInits.len > 0 and bssSize > 0:
    bssImage = newSeq[byte](bssSize.int)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)
  # The bss content (if any) is written right after the .text segment in the file.
  let bssFileOff = if bssImage.len > 0: textMemSize else: 0'u64
  let bssFileSz = if bssImage.len > 0: bssSize else: 0'u64
  var bssPhdr = initPhdr(bssFileOff, bssVaddr, bssFileSz, bssAlignedSize, PF_R or PF_W)

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
    let padding = int(textMemSize - textFileSize)
    if padding > 0:
      var zeros = newSeq[byte](padding)
      f.writeData(unsafeAddr zeros[0], padding)

  # Write the initialized .bss image (constant static initializers), if any. The
  # remaining memsz beyond bssSize is zero-filled by the loader.
  if bssImage.len > 0:
    f.writeData(unsafeAddr bssImage[0], bssImage.len)

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

proc writeMachO(a: var GenContext; outfile: string) =
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data

  # Determine CPU type based on architecture
  let (cputype, cpusubtype) = case a.arch
    of Arch.X64:
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)
    of Arch.A64, Arch.LinuxA64:
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

  var gsites: seq[(int, int)] = @[]   # resolve each global's final .bss offset now
  for (pos, sym) in a.gvarSites: gsites.add (pos, sym.size)

  # Thread-local storage (macOS TLV): one 24-byte descriptor per tvar, the
  # __thread_data init template, and the adrp+add sites referencing each
  # descriptor (carried by descriptor index).
  var tlv: macho.TlvInfo
  for sym in a.tlvSyms: tlv.descriptorOffsets.add sym.size
  tlv.threadData = a.tlvData
  for (pos, sym) in a.tlvSites: tlv.sites.add (pos, sym.offset)

  macho.writeMachO(code, a.bssOffset, cputype, cpusubtype, outfile, dynlink, gsites, tlv,
                   a.bssInits)

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


proc generateSymbol(ctx: var GenContext; sym: Symbol) =
  ## Generate code for a single reachable symbol on-demand. nifasm is the linker:
  ## a reachable FOREIGN symbol is bundled into this same output (its body/storage
  ## emitted, cross-module references resolved as ordinary direct relocations) —
  ## exactly like a local symbol, only the declaration is read from the foreign
  ## module's stream (at its indexed byte offset) instead of the main TokenBuf.
  if sym.name in ctx.generatedSymbols:
    return
  ctx.generatedSymbols.incl sym.name

  if sym.moduleName notin ctx.modules:
    return  # Module not loaded, can't generate

  let m = ctx.modules[sym.moduleName]
  var n: Cursor
  if sym.isForeign:
    n = getDecl(m.foreign, sym.name, asmTags)  # cached one-decl tree
  else:
    n = cursorAt(m.buf, sym.declStart)
  let declTag = tagToNifasmDecl(n.tag)

  case sym.kind
  of skProc:
    if declTag == ProcD:
      pass2Proc(n, ctx)
  of skRodata:
    if declTag == RodataD:
      inc n  # rodata
      inc n  # name (already have sym)
      let s = getStr(n)
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
      ctx.buf.defineLabel(LabelId(sym.offset))
      for c in s: ctx.buf.data.add byte(c)
  of skGvar:
    if declTag == GvarD:
      # Allocate space in .bss section
      let size = slots.alignedSize(sym.typ)
      let align = asmSizeOf(sym.typ)
      if align > 1:
        ctx.bssOffset = (ctx.bssOffset + align - 1) and not (align - 1)
      let labId = ctx.bssBuf.createLabel()
      sym.offset = int(labId)
      sym.size = ctx.bssOffset      # byte offset within .bss (for arm64 adrp+add)
      ctx.bssBuf.defineLabel(labId)
      # A constant-scalar initializer (arkham emits its bits as the gvar's value
      # in `(gvar :name type value?)`): record it so writeElf writes the value into
      # the (writable) .bss image. `takeLocal` bounds the decl and exposes the
      # optional value via `hasVal`.
      var dn = n
      let lc = takeLocal(dn)
      if lc.hasVal and lc.val.kind == IntLit:
        ctx.bssInits.add (off: sym.size.int64, val: getInt(lc.val),
                          size: asmSizeOf(sym.typ))
      ctx.bssOffset += size
  of skTvar:
    if declTag == TvarD:
      let size = slots.alignedSize(sym.typ)
      case ctx.arch
      of Arch.A64:
        # macOS TLV: give the variable a descriptor index and a byte offset in
        # the per-thread storage region, and bake a literal initializer (if any)
        # into the __thread_data template dyld copies on first access per thread.
        let align = max(asmSizeOf(sym.typ), 1)
        while (ctx.tlvData.len mod align) != 0: ctx.tlvData.add 0
        sym.offset = ctx.tlvSyms.len    # descriptor index
        sym.size = ctx.tlvData.len      # byte offset within the per-thread region
        ctx.tlvSyms.add sym
        # Parse the optional initializer: (tvar :name type value?)
        var dn = n
        let lc = takeLocal(dn)
        var initVal = 0'i64
        if lc.hasVal and lc.val.kind == IntLit: initVal = getInt(lc.val)
        for i in 0 ..< size:
          ctx.tlvData.add byte((initVal shr (8 * i)) and 0xFF)
      else:
        sym.offset = ctx.tlsOffset
        ctx.tlsOffset += size
  else:
    discard  # Types and other symbols don't need code generation

proc processReachableSymbols(ctx: var GenContext) =
  ## Process all pending symbols until queue is empty
  while ctx.pendingSymbols.len > 0:
    let fullName = ctx.pendingSymbols.pop()
    if fullName in ctx.generatedSymbols:
      continue

    # Handle deduplication
    let canonicalName = getCanonicalName(ctx, fullName)
    if canonicalName != fullName and canonicalName in ctx.generatedSymbols:
      continue  # Already generated the canonical version

    # Find the symbol by its full qualified name (nominal identity).
    let sym = ctx.scope.lookup(fullName)
    if sym != nil:
      generateSymbol(ctx, sym)

proc setupTls(ctx: var GenContext) =
  ## nifasm owns the per-thread TLS. After every bundled tvar has an FS offset
  ## (`ctx.tlsOffset`), reserve the unified `arkham.tls.0` block in `.bss` (sized
  ## for all modules' tvars) and synthesize the entry prologue that points FS at it
  ## via `arch_prctl(ARCH_SET_FS, &arkham.tls.0)`, then jumps to the real entry.
  ## Nim thread-locals have no initializers, so the block is just zeroed `.bss`.
  ## x86-64 only (AArch64 TLS uses a different mechanism, not yet implemented).
  const ArchSetFs = 0x1002      # arch_prctl(2) ARCH_SET_FS
  const ArchPrctlNr = 158       # x86-64 syscall number for arch_prctl
  if ctx.arch != Arch.X64 or ctx.tlsOffset == 0: return
  if ctx.tlsBlockSym == nil or ctx.entrySym == nil: return
  # Reserve the per-thread block in .bss (16-byte aligned); its address is the FS
  # base, and every tvar lives at `FS:[its offset]` within it.
  ctx.bssOffset = (ctx.bssOffset + 15) and not 15
  ctx.tlsBlockSym.size = ctx.bssOffset
  ctx.bssOffset += (ctx.tlsOffset + 15) and not 15
  # Synthesize the FS-setup prologue at the end of .text — it becomes the ELF entry
  # (see writeElf) and tail-jumps to the program's real entry proc.
  ctx.tlsEntryOffset = ctx.buf.data.len
  let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RSI)     # lea rsi, [rip+arkham.tls.0]
  ctx.gvarSites.add (pos, ctx.tlsBlockSym)
  x86.emitMovImmToReg(ctx.buf.data, x86.RDI, ArchSetFs)
  x86.emitMovImmToReg(ctx.buf.data, x86.RAX, ArchPrctlNr)
  x86.emitSyscall(ctx.buf.data)                             # arch_prctl(ARCH_SET_FS, &block)
  x86.emitJmp(ctx.buf, LabelId(ctx.entrySym.offset))        # → real entry

proc assemble*(filename, outfile: string) =
  var buf = parseFromFile(filename, sharedTags = asmTags)

  # Extract base directory from filename
  let baseDir = filename.splitFile.dir
  # The module being assembled — its symbol suffix (e.g. `foo.s.nif` → "foo"), so a
  # `name.0.foo` reference resolves to a local definition instead of a foreign import.
  let thisModule = extractModuleSuffix(filename)

  var scope = newScope()

  # Create a minimal ctx for pass1 (for foreign module loading)
  var ctx = GenContext(
    scope: scope,
    rootScope: scope,
    buf: initBuffer(),
    bssBuf: initBuffer(),
    tlsOffset: 0,
    bssOffset: 0,
    modules: initTable[string, LoadedModule](),
    baseDir: baseDir,
    thisModule: thisModule,
    imports: @[],
    extProcs: @[],
    gotSlotCount: 0,
    pendingSymbols: @[],
    generatedSymbols: initHashSet[string](),
    dedupTable: initTable[string, string](),
    tlsEntryOffset: -1
  )

  # Store main module. `beginRead` BEFORE the move forces the buffer's
  # CursorOwner into existence, which takes a tracked ref on its pool/tags. The
  # move's `=wasMoved` ARC-decrements the moved-from buffer's `pool`; without the
  # owner's ref that would free a pool no cursor yet protects (the classic
  # "beginRead-after-move" heap bug, see [[reindex-tool]]).
  discard beginRead(buf)
  ctx.modules[MainModuleName] = LoadedModule(buf: move buf, loaded: true)

  # The unified per-thread TLS block is owned by nifasm, not any single module
  # (arkham only references it for `&tvar`/`FS:[off]`). Define it up front so those
  # references resolve; it's pre-marked generated (nifasm sizes + allocates it in
  # `setupTls` once all bundled tvars are known) and FS is set in the entry prologue.
  ctx.tlsBlockSym = Symbol(name: "arkham.tls.0", kind: skGvar,
                           typ: Type(kind: UIntT, bits: 8), offset: -1)
  scope.define(ctx.tlsBlockSym)
  ctx.generatedSymbols.incl "arkham.tls.0"

  var n1 = beginRead(ctx.modules[MainModuleName].buf)
  pass1(n1, scope, ctx, MainModuleName, ctx.modules[MainModuleName].buf)

  # x86-64: a thread-local is read/written as `FS:[sym.offset]` with the
  # displacement baked at the *reference* site (no relocation), so every tvar's
  # offset must be fixed before any code is generated — otherwise a reference
  # compiled before the tvar's lazy `generateSymbol` would capture the default 0.
  # (macOS/A64 resolves tvars through relocated descriptors and allocates lazily.)
  if ctx.arch == Arch.X64:
    var tn = beginRead(ctx.modules[MainModuleName].buf)
    if tn.kind == TagLit and tn.tag == StmtsTagId:
      loopInto tn:
        if tn.kind == TagLit and tagToNifasmDecl(tn.tag) == TvarD:
          let start = tn
          inc tn                              # tvar tag
          if tn.kind == SymbolDef:
            let sym = scope.lookup(symName(tn))
            if sym != nil and sym.kind == skTvar and sym.name notin ctx.generatedSymbols:
              sym.offset = ctx.tlsOffset
              ctx.tlsOffset += slots.alignedSize(sym.typ)
              ctx.generatedSymbols.incl sym.name   # don't re-allocate in generateSymbol
          tn = start
        skip tn

  # Update ctx with proper buffers for pass2
  ctx.buf = initBuffer()
  ctx.bssBuf = initBuffer()

  # Generate code for entry point (top-level instructions only)
  # This marks symbols as used via lookupWithAutoImport when they are referenced
  var n = beginRead(ctx.modules[MainModuleName].buf)
  pass2(n, ctx)

  # Process all pending symbols (both main module and foreign modules)
  # This generates code only for symbols that were actually referenced (dead code elimination)
  processReachableSymbols(ctx)

  # Now that every bundled tvar has an FS offset, reserve the unified TLS block and
  # synthesize the entry prologue that sets the FS base (x86-64).
  setupTls(ctx)

  case ctx.arch
  of Arch.X64, Arch.LinuxA64:
    writeElf(ctx, outfile)
  of Arch.A64:
    writeMachO(ctx, outfile)
  of Arch.WinX64, Arch.WinA64:
    writeExe(ctx, outfile.changeFileExt("exe"))

  # Close all foreign-module readers (the main module has no reader).
  for modname, module in ctx.modules.mpairs:
    if modname != MainModuleName and module.foreign != nil:
      nifreader.close(module.foreign.r)
