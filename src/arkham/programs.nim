#
#           Arkham — native AArch64 code generator for NIFC
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## arkham's *program* model over the nifcore API — the nifcore analog of
## nimony's `programs.nim` (and nifc's `nifmodules.nim`). A NIFC name can refer
## to a declaration in **another module**: a mangled symbol like
## `Color.0.othermod` carries its defining module's suffix (`othermod`). This
## module manages that — it scans the main module's top level (`collect`) and
## lazily **loads foreign modules on demand** to resolve cross-module type
## references, keeping their buffers alive so cursors into them stay valid.
##
## All type-name resolution and size/layout queries (`lookupType`, `resolveType`,
## `slotOf`, `typeSizeAlign`, `aggrLayout`, …) route through the `Program`, so a
## named type defined in any module classifies correctly (e.g. a cross-module
## `enum` parameter is a scalar in a register, not a stack aggregate).

import std / [tables, assertions]
import nifcore, nifcdecl, nifcoreparse
import slots, nifmodules
import "../../../nimony/src/lib" / [symparser, nifreader, stringviews]

type
  Extern* = object
    asmName*, extName*: string

  CallTarget* = object
    asmName*: string         ## the asm-NIF symbol to call
    extern*: bool            ## true → (extcall), false → (call)
    syscall*: bool           ## true → a Linux syscall: emitted as a `(syproc …)` and
                             ## invoked inline via `(syscall)`/`(svc)` (no libc, no PLT)
    sysNr*: int              ## x86-64 Linux syscall number (when `syscall`)
    sysNrA64*: int           ## AArch64 Linux syscall number (when `syscall`); `-1` if
                             ## the name has no syscall on that arch
    atomic*: string          ## non-empty → a GCC `__atomic_*` builtin lowered inline
    memIntrin*: string       ## non-empty → a mem* intrinsic (memcpy/…) lowered inline
    bitBuiltin*: string      ## non-empty → a GCC bit builtin (`__builtin_ctzll`, …)
                             ## lowered inline to a native bit instruction (bsf/bsr/…)
    retFloat*: bool          ## true → returns a float (in v0)
    retType*: Cursor         ## the proc's return-type cursor (for `getType`)
    declarative*: bool       ## true → emit/use nifasm's declarative call ABI
                             ## (typed params + `(arg)`/`(res)` cross-checking);
                             ## false → manual marshalling (floats/aggregates/…)
    indirect*: bool          ## true → call *through* a function-pointer variable
                             ## (`asmName` is the gvar/tvar holding the pointer)

  ProcInfo* = object
    asmName*: string         ## the proc's asm-NIF name (entry → "main.0")
    decl*: Cursor            ## the `(proc …)` declaration
    isEntry*: bool

  SyscallProc* = object
    asmName*: string         ## the `(syproc …)` symbol name (e.g. "mmap.0")
    decl*: Cursor            ## the importc proc decl (source of params + return type)
    sysNr*: int              ## x86-64 number
    sysNrA64*: int           ## AArch64 number (`-1` if none on that arch)

  Program* = object
    externOrder*: seq[Extern]               ## extproc decls, in order (main module)
    callTarget*: Table[string, CallTarget]  ## NIFC proc symbol → how to call it
    procs*: seq[ProcInfo]                   ## internal procs to emit (entry first)
    syscalls*: seq[SyscallProc]             ## syscalls used → one `(syproc …)` decl each
    globals*: Table[string, Cursor]         ## global (gvar/const) var name → its decl cursor
    tvars*: Table[string, Cursor]           ## thread-local var name → its decl cursor (macOS TLV)
    typeDecls*: TypeEnv                     ## resolved type env: main + requested foreign
    mainTypeList*: seq[(string, Cursor)]    ## main-module types, in declaration order
    requestedForeign*: seq[(string, Cursor)] ## foreign types referenced (cross-module
                                             ## dependency record; nifasm links them)
    needsLibSystem*: bool
    # ── cross-module machinery ──
    scheme: SplittedModulePath              ## path template (dir/<module>.ext)
    tags: TagPool                           ## shared tag pool for parsing foreign modules
    loaded: Table[string, ForeignModule]    ## module suffix → loaded foreign module
    procPtr*: Cursor                        ## a synthesized `(proctype)` — the code-pointer
                                            ## type of a proc used as a value. A nifcore
                                            ## Cursor keeps its own backing alive (refcounted
                                            ## owner), so no separate buffer must be stored.
    voidPtr*: Cursor                        ## a synthesized `(ptr (void))` — the structural
                                            ## type of a `nil` literal (a generic pointer).
    intType*: Cursor                        ## synthesized `(i 64)` — type of a bare IntLit
    uintType*: Cursor                       ## synthesized `(u 64)` — type of a bare UIntLit
    charType*: Cursor                       ## synthesized `(c 8)`  — type of a bare CharLit
    floatType*: Cursor                      ## synthesized `(f 64)` — type of a bare FloatLit

  TypeEnv* = Table[string, Cursor]          ## a type-symbol table

# ── Linux syscall table (shared) ────────────────────────────────────────────
# nifasm's ELF backend is static (no dynamic linker / PLT), so an `importc`'d libc
# call can't reach a shared object — arkham instead recognises these names and
# lowers them to a raw Linux syscall (emitted as a `(syproc …)` with the syscall
# ABI register assignment + the kernel's clobbers, invoked inline via the
# `(syscall)`/`(svc)` marker). One table, two columns: the x86-64 number and the
# AArch64 (asm-generic unistd) number, which differ (write=1 vs 64, exit=60 vs 93).
# `-1` in a column means "no syscall of this name on that arch" (e.g. x86-64 has
# `open`, AArch64 only `openat`). To teach arkham a new syscall, add one row here.
const LinuxSyscalls* = {
  "read":       (0,   63),
  "write":      (1,   64),
  "open":       (2,   -1),
  "openat":     (-1,  56),
  "close":      (3,   57),
  "mmap":       (9,   222),
  "munmap":     (11,  215),
  "exit":       (60,  93),
  "exit_group": (231, 94),
  # `abort` is a libc function, not a syscall. For now we lower it to the `exit`
  # syscall so a libc-free build links and terminates (it takes no args, so the exit
  # code is whatever is in the syscall's code register — abort is a cold error path).
  "abort":      (60,  93)}

const
  LinuxX64ExitNr* = 60
  LinuxA64ExitNr* = 93

proc lookupSyscall*(name: string): tuple[found: bool, x64, a64: int] =
  ## Resolve libc `name` to its (x86-64, AArch64) syscall numbers, or `found=false`
  ## if arkham does not lower it (the call then goes through the normal extern path).
  for (n, nr) in LinuxSyscalls:
    if n == name: return (true, nr[0], nr[1])
  result = (false, -1, -1)

# ── pass 0: collect the main module's top-level declarations ────────────────

proc parsePragmas(c: var Cursor; importcN, exportcN: var string) =
  if c.substructureKind == PragmasU:
    c.into:
      while c.hasMore:
        case c.pragmaKind
        of ImportcP:
          c.into:
            if c.hasMore: (importcN = strVal(c); inc c)
        of ExportcP:
          c.into:
            if c.hasMore: (exportcN = strVal(c); inc c)
        else: skip c
  else:
    skip c

proc resolveType*(p: var Program; c: Cursor): Cursor

proc abiScalarType(p: var Program; c: Cursor): bool =
  ## A type that travels in a single GPR with no layout resolution needed:
  ## a primitive non-float scalar (`(i N)`/`(u N)`/`(c N)`/`(bool)`), a pointer
  ## (`(ptr …)`/`(aptr …)`/`(proctype …)`), or a named type that resolves to one of
  ## those — notably an `enum`, which collapses to its base integer. Floats and
  ## aggregates (objects/unions/arrays) conservatively answer false so they keep
  ## the manual marshalling path.
  var t = c
  if t.kind == Symbol: t = resolveType(p, t)
  if t.kind != TagLit: return false
  case t.typeKind
  of IT, UT, CT, BoolT, PtrT, AptrT, ProctypeT, EnumT: true
  else: false

proc isDeclarativeAbi*(p: var Program; decl: Cursor): bool =
  ## Whether `decl`'s call boundary maps onto the simple declarative scheme:
  ## every parameter is a single-GPR scalar/pointer and the result is void or a
  ## single-GPR scalar. The first 8 scalar params travel in x0–x7; any beyond
  ## that are passed on the stack (AAPCS64). Everything else (floats, aggregates,
  ## by-ref, indirect result, named types) falls back to manual marshalling.
  var c = decl
  c.into:
    inc c                                     # name → params slot
    if c.kind == TagLit:                      # (params (param :n prag type) …)
      var pc = c
      pc.into:
        while pc.hasMore:
          var ok = false
          pc.into:                            # (param :name pragmas type)
            inc pc                            # name
            skip pc                           # pragmas
            ok = abiScalarType(p, pc)
            while pc.hasMore: skip pc          # type (+ anything else)
          if not ok: return false
    skip c                                    # params
    # return type: void, or a single-GPR scalar
    if not (c.kind == DotToken or (c.kind == TagLit and c.typeKind == VoidT)) and
       not abiScalarType(p, c):
      return false
    while c.hasMore: skip c                   # return type, pragmas, body
  result = true

proc thisModuleSuffix*(p: Program): string =
  ## The main module's NIF symbol suffix (e.g. `sysvq0asl`), used to compress
  ## self-module symbol suffixes when serializing the embedded-index output.
  p.scheme.name

proc ptrTypeOf*(p: Program; elem: Cursor): Cursor =
  ## Synthesize the type of `(addr lvalue)`: a `(ptr <elem>)` whose pointee is a
  ## copy of the element type `elem`. The new buffer SHARES `elem`'s literals and
  ## tag pools, so any symbol / literal ids the copied subtree carries stay valid
  ## (cross-pool copies would corrupt them). The returned cursor keeps its backing
  ## alive via the refcounted owner (the same idiom as `procPtr`). Mirrors
  ## `nifc/typenav.getTypeImpl`'s `AddrC` case — a pointer is not just 8 bytes, it
  ## carries the pointee type so `(deref (addr x))` / `(pat (addr x) i)` navigate.
  var buf = createTokenBuf(8, sharedPool = elem.pool, sharedTags = elem.tags)
  buf.openTag registerTag(elem.tags, "ptr")
  buf.addSubtree elem
  buf.closeTag()
  result = beginRead(buf)

proc collect*(buf: var TokenBuf; inputPath: string; tags: TagPool): Program =
  result = Program(callTarget: initTable[string, CallTarget](),
                   typeDecls: initTable[string, Cursor](),
                   globals: initTable[string, Cursor](),
                   tvars: initTable[string, Cursor](),
                   loaded: initTable[string, ForeignModule](),
                   scheme: splitModulePath(inputPath), tags: tags)
  block:
    # A standalone `(proctype)` parsed against the shared tag pool; its cursor
    # outlives this buffer (the owner refcount keeps the data alive).
    var ptBuf = parseFromBuffer("(proctype)", "", sharedTags = tags)
    result.procPtr = beginRead(ptBuf)
    var npBuf = parseFromBuffer("(ptr (void))", "", sharedTags = tags)
    result.voidPtr = beginRead(npBuf)
    var itBuf = parseFromBuffer("(i 64)", "", sharedTags = tags)
    result.intType = beginRead(itBuf)
    var utBuf = parseFromBuffer("(u 64)", "", sharedTags = tags)
    result.uintType = beginRead(utBuf)
    var ctBuf = parseFromBuffer("(c 8)", "", sharedTags = tags)
    result.charType = beginRead(ctBuf)
    var ftBuf = parseFromBuffer("(f 64)", "", sharedTags = tags)
    result.floatType = beginRead(ftBuf)
  assert buf.beginRead().stmtKind == StmtsS, "NIFC top level must be (stmts …)"
  # Pass 1: register every type declaration. Procs (pass 2) resolve their
  # param/return types via `isDeclarativeAbi`, and a proc may reference a type
  # declared *later* in the module (e.g. a tuple-instance returned by a helper),
  # so all types must be in `typeDecls` before any proc is processed.
  var ct = buf.beginRead()
  ct.into:
    while ct.hasMore:
      if ct.stmtKind == TypeS:
        let typeStart = ct
        var tc = ct
        tc.into:
          let nm = symName(tc)
          result.typeDecls[nm] = typeStart
          result.mainTypeList.add (nm, typeStart)
          while tc.hasMore: skip tc           # drain so `into` stays balanced
      skip ct
  # Pass 2: globals, thread-locals and procs.
  var c = buf.beginRead()
  c.into:
    while c.hasMore:
      if c.stmtKind in {GvarS, TvarS, ConstS}:
        let gStart = c
        var gc = c
        let isTvar = c.stmtKind == TvarS
        gc.into:
          let nm = symName(gc)
          if isTvar: result.tvars[nm] = gStart   # thread-local (macOS TLV)
          else: result.globals[nm] = gStart      # ordinary .bss global / const
          while gc.hasMore: skip gc           # drain so `into` stays balanced
        skip c
      elif c.stmtKind == ProcS:
        let procStart = c
        var pname, importcN, exportcN = ""
        var retFloat = false
        var retType: Cursor
        c.into:
          pname = symName(c); inc c           # name
          skip c                              # params
          retType = c                         # return-type cursor (for getType)
          retFloat = c.kind == TagLit and c.typeKind == FT   # `(f N)` return → v0
          skip c                              # return type
          parsePragmas(c, importcN, exportcN)
          skip c                              # body
        if importcN.len >= 9 and importcN[0 .. 8] == "__atomic_":
          # GCC atomic builtin: not a real external call — arkham lowers it to a
          # lock-free instruction sequence (no extproc/libSystem dependency).
          result.callTarget[pname] = CallTarget(atomic: importcN, retType: retType)
        elif importcN in ["memcpy", "memmove", "memset", "memcmp"]:
          # C mem* intrinsic: lowered inline (no libc dependency) — see genMemIntrin.
          result.callTarget[pname] = CallTarget(memIntrin: importcN, retType: retType)
        elif importcN in ["__builtin_ctzll", "__builtin_ctz",
                          "__builtin_clzll", "__builtin_clz",
                          "__builtin_popcountll", "__builtin_popcount",
                          "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"]:
          # GCC bit builtin (count-trailing/leading-zeros, popcount, byte-swap):
          # lowered inline to a native bit instruction — no libc/extproc. See
          # genBitBuiltin. (nimony's `firstSetBit`/`countTrailingZeroBits` reach
          # `ctz64` ⇒ `__builtin_ctzll` ⇒ a single `bsf`.)
          result.callTarget[pname] = CallTarget(bitBuiltin: importcN, retType: retType)
        elif importcN.len > 0 and lookupSyscall(importcN).found:
          # A Linux syscall: lowered to a raw kernel trap (no libc, no PLT). Emitted
          # as a `(syproc …)` whose proctype puts args in the syscall ABI registers
          # and declares the kernel's clobbers; calls go through the declarative
          # `(prepare …)` path with a `(syscall)`/`(svc)` marker. See genCall.
          let (_, x64Nr, a64Nr) = lookupSyscall(importcN)
          # Name the syproc as a proper SELF-MODULE symbol `<name>.sys.<thisModule>`:
          # nifasm resolves cross-module symbols by full module-qualified name (the render
          # compresses the suffix to a trailing dot and nifasm completes it back), so a
          # basename-only `mmap.sys` would be unresolvable from another bundled module that
          # calls it. Keying on the C `importcN` (not the proc's own `pname`) also collapses
          # aliases — e.g. both `die` and `exit` (`importc "exit"`) → one syproc. The `.sys.`
          # disambiguator is RESERVED: nimony proc disambiguators are always numeric, so a
          # synthesized syproc can never collide with a real proc of the same base name
          # (e.g. the `write` syscall syproc vs syncio's own `write.0` proc).
          let asmN = importcN & ".sys." & thisModuleSuffix(result)
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: false,
                                                syscall: true, sysNr: x64Nr, sysNrA64: a64Nr,
                                                declarative: true, retType: retType)
          # Record one syproc decl per distinct syscall symbol.
          var already = false
          for sp in result.syscalls:
            if sp.asmName == asmN: already = true; break
          if not already:
            result.syscalls.add SyscallProc(asmName: asmN, decl: procStart,
                                            sysNr: x64Nr, sysNrA64: a64Nr)
        elif importcN.len > 0:
          let asmN = importcN & ".0"
          result.externOrder.add Extern(asmName: asmN, extName: "_" & importcN)
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: true,
                                                retFloat: retFloat, retType: retType)
          result.needsLibSystem = true
        else:
          # The program entry is the C `main` (`exportc "main"`). Every OTHER
          # exported proc (`exportc "nimStrDestroy"`, …) is an ordinary proc whose
          # C name is irrelevant to this self-contained image — it must keep its
          # NIF name `pname` so cross-module calls (e.g. `=destroy.2.<mod>`) resolve.
          # (The old `exportcN.len > 0` test wrongly renamed all of them to `main.0`.)
          let entry = exportcN == "main"
          let asmN = if entry: "main.0" else: pname
          result.callTarget[pname] = CallTarget(asmName: asmN, extern: false,
                                                retFloat: retFloat, retType: retType,
                                                declarative: isDeclarativeAbi(result, procStart))
          result.procs.add ProcInfo(asmName: asmN, decl: procStart, isEntry: entry)
      else:
        skip c
  # Emit the entry proc first so it begins the text section.
  for i in 0 ..< result.procs.len:
    if result.procs[i].isEntry and i != 0:
      swap result.procs[0], result.procs[i]
      break

# ── cross-module type lookup (lazy foreign-module loading) ──────────────────

proc loadModule(p: var Program; suffix: string): ForeignModule =
  ## Load (and cache) the foreign module identified by `suffix`. Its file is
  ## `<dir-of-main>/<suffix><ext-of-main>` (the same scheme nifc uses). The file
  ## must carry an embedded `.indexat` index (run `nimony/tools/reindex.nim` on
  ## hand-written fixtures); the shared `nifmodules` loader keeps the reader open
  ## for lazy per-symbol jumps.
  if p.loaded.hasKey(suffix): return p.loaded[suffix]
  var sc = p.scheme
  sc.name = suffix
  let path = $sc
  let m = openForeignModule(path)
  if not m.hasEmbeddedIndex:
    raiseAssert "arkham: module has no embedded index (reindex it): " & path
  p.loaded[suffix] = m
  result = m

proc lookupType*(p: var Program; name: string): Cursor =
  ## The `(type :name …)` declaration for `name`, resolving across modules. A
  ## name with a module suffix (`Foo.0.othermod`) triggers loading that module
  ## (via its `.indexat` index when present); the decl is cached in `typeDecls`
  ## and recorded in `requestedForeign` as a cross-module dependency.
  if p.typeDecls.hasKey(name): return p.typeDecls[name]
  let s = splitSymName(name)
  if s.module.len == 0:
    raiseAssert "arkham: unknown type " & name
  # A reference qualified with our OWN module suffix denotes a local type whose
  # decl `collect` registered under its unqualified (local) name. De-qualify and
  # retry locally rather than (wrongly) trying to load ourselves as a foreign
  # module — generic-instance names like `t.0.I….<self>.<self>` are the case.
  if s.module == p.scheme.name:
    let localName = name[0 ..< name.len - s.module.len]
    if p.typeDecls.hasKey(localName): return p.typeDecls[localName]
    raiseAssert "arkham: unknown local type " & name
  let m = loadModule(p, s.module)
  if not hasDecl(m, name):
    raiseAssert "arkham: type " & name & " not found in module " & s.module
  let d = getDecl(m, name, p.tags)
  p.typeDecls[name] = d
  p.requestedForeign.add (name, d)
  result = d

proc lookupForeignDecl*(p: var Program; name: string; found: var bool): Cursor =
  ## The top-level declaration (`gvar|var|const|tvar|proc|type :name …`) for a
  ## cross-module symbol, loaded from the owning module's embedded index (same
  ## scheme as `lookupType`). Sets `found=false` for an unqualified name, a
  ## reference to our own module, or a symbol absent from the foreign module —
  ## so a single call classifies "local vs foreign" without a separate probe.
  ## A resolved decl is recorded in `requestedForeign` so nifasm links it.
  found = false
  let s = splitSymName(name)
  if s.module.len == 0 or s.module == p.scheme.name: return
  let m = loadModule(p, s.module)
  if not hasDecl(m, name): return
  result = getDecl(m, name, p.tags)
  p.requestedForeign.add (name, result)
  found = true

proc foreignCallTarget*(p: var Program; name: string): CallTarget =
  ## Resolve a cross-module proc reference to a callable target by loading its
  ## declaration from the owning module's embedded index. The asm symbol is the
  ## fully-qualified NIF name; nifasm auto-imports `<module>.s.nif` and links it.
  let s = splitSymName(name)
  assert s.module.len > 0 and s.module != p.scheme.name,
    "arkham: not a foreign proc: " & name
  let m = loadModule(p, s.module)
  assert hasDecl(m, name), "arkham: foreign proc not found: " & name
  let declCur = getDecl(m, name, p.tags)
  var d = declCur
  var retFloat = false
  var retType: Cursor
  var importcN, exportcN = ""
  d.into:
    inc d                                     # name
    skip d                                    # params
    retType = d
    retFloat = d.kind == TagLit and d.typeKind == FT
    skip d                                    # return type
    parsePragmas(d, importcN, exportcN)
    while d.hasMore: skip d                    # body
  result = CallTarget(asmName: name, extern: false, retFloat: retFloat,
                      retType: retType,
                      declarative: isDeclarativeAbi(p, declCur))

# ── named-type resolution ───────────────────────────────────────────────────

proc typeBody*(p: var Program; name: string): Cursor =
  ## The body (3rd child) of a named type decl `(type :name pragmas body)`.
  var d = lookupType(p, name)
  d.into:
    inc d; skip d                             # name, type-pragmas
    result = d                                # the body (a copy)
    skip d                                    # balance the `into`

proc resolveType*(p: var Program; c: Cursor): Cursor =
  ## Follow named-type `Symbol`s (across modules) to the underlying structural
  ## type. A type that is not a named alias is returned unchanged.
  result = c
  var guard = 0
  while result.kind == Symbol:
    result = typeBody(p, symName(result))
    inc guard
    assert guard < 1000, "arkham: cyclic type alias"

# ── size / layout (name-resolving — lives here, not in slots) ────────────────

proc typeSizeAlign*(p: var Program; c: Cursor): (int, int)

proc objSizeAlign(p: var Program; bodyc: Cursor): (int, int) =
  var oc = bodyc
  var off = 0
  var maxAl = 1
  oc.into:
    if oc.kind == Symbol:                      # inherited base: laid out FIRST,
      let (bsz, bal) = typeSizeAlign(p, oc)    # so own fields start at sizeof(base)
      off = bsz
      if bal > maxAl: maxAl = bal
    skip oc                                    # base / inheritance slot
    while oc.hasMore:
      oc.into:                                # (fld :name pragmas type)
        inc oc; skip oc                       # name, field-pragmas
        let (fsz, fal) = typeSizeAlign(p, oc)
        skip oc                               # consume the field type
        off = align(off, fal) + fsz
        if fal > maxAl: maxAl = fal
  result = (align(off, maxAl), maxAl)

proc typeSizeAlign*(p: var Program; c: Cursor): (int, int) =
  ## Size and alignment (bytes) of a NIFC type, mirroring nifasm's layout.
  case c.kind
  of Symbol:
    var d = lookupType(p, symName(c))
    d.into:
      inc d; skip d                           # name, type-pragmas
      let r = typeSizeAlign(p, d); skip d
      result = r
  of TagLit:
    case c.typeKind
    of IT, UT, FT, CT:
      let bits = typeBits(c)
      let bytes = (if bits > 0: bits else: 64) div 8
      result = (bytes, bytes)
    of BoolT: result = (1, 1)
    of VoidT: result = (0, 1)
    of PtrT, AptrT, ProctypeT: result = (8, 8)
    of FlexarrayT:
      # A flexible array member contributes no fixed size; its alignment is that
      # of the element type (so the enclosing struct's tail is aligned for it).
      var t = c
      t.into:
        let (_, eal) = typeSizeAlign(p, t); skip t
        while t.hasMore: skip t               # consume any trailing qualifiers
        result = (0, eal)
    of ObjectT: result = objSizeAlign(p, c)
    of EnumT:                                 # collapses to its base integer type
      var t = c
      t.into:
        result = typeSizeAlign(p, t); skip t
        while t.hasMore: skip t               # efld members
    of ArrayT:
      var t = c
      t.into:
        let (esz, eal) = typeSizeAlign(p, t); skip t
        let n = if t.kind == IntLit: int(intVal(t)) else: 0
        while t.hasMore: skip t               # consume the length (+ any extra)
        result = (esz * n, eal)
    else: raiseAssert "arkham: cannot size type " & $c.typeKind
  else: raiseAssert "arkham: malformed type for sizing"

proc slotOf*(p: var Program; c: Cursor): AsmSlot =
  ## Classify a type cursor into an `AsmSlot`, resolving named types (across
  ## modules) first. A named `enum`/scalar typedef becomes its underlying scalar
  ## slot; a named/inline object, union or array stays `AMem` with its real byte
  ## size and alignment filled in (for AAPCS64 size-based ABI decisions).
  let r = resolveType(p, c)
  if r.kind != TagLit:
    return typeToSlot(r)                       # defensive: shouldn't occur
  case r.typeKind
  of EnumT:
    var base = r
    var t = r
    t.into:
      base = t; skip t                         # base type (a copy)
      while t.hasMore: skip t                  # efld members
    result = slotOf(p, base)                   # base may itself be a named type
  of ObjectT, UnionT, ArrayT:
    let (sz, al) = typeSizeAlign(p, r)
    result = AsmSlot(cls: AMem, size: sz, align: al, typ: r)  # carry the type, like every other path
  else:
    result = typeToSlot(r)                      # scalars, ptr, void, …

# ── aggregate layout (shared by the allocator + the code generator) ─────────

proc aggrByteSize*(p: var Program; typeName: string): int =
  var d = lookupType(p, typeName)
  d.into:
    inc d; skip d                             # name, type-pragmas
    let r = typeSizeAlign(p, d); skip d
    result = r[0]

# ── structural type navigation (the pieces arkham's `getType` walks) ────────

proc fieldType*(p: var Program; objType: Cursor; field: string): Cursor =
  ## The structural type cursor of `field` in a resolved `(object …)` type.
  ## An inherited field (the NIFC `(dot base field depth)` selector counts the
  ## base levels) is resolved by recursing into the object's base type.
  assert objType.kind == TagLit and objType.typeKind == ObjectT,
    "arkham: field access requires an object type"
  var oc = objType
  var baseType: Cursor
  var hasBase = false
  oc.into:
    baseType = oc                             # base / inheritance (a type, or `.`)
    hasBase = oc.kind != DotToken
    skip oc
    while oc.hasMore:
      oc.into:                                # (fld :name pragmas type)
        let fn = symName(oc); inc oc
        skip oc                               # field-pragmas
        result = oc; skip oc                  # field type (a copy)
        if fn == field: return
  if hasBase:                                 # not here → look in the inherited base
    return fieldType(p, resolveType(p, baseType), field)
  raiseAssert "arkham: field '" & field & "' not found"

proc innerType*(p: var Program; t: Cursor): Cursor =
  ## The element/pointee type of a resolved `(ptr T)` / `(aptr T)` / `(array T …)`
  ## / `(flexarray T)` — in each the first child is the element/pointee type.
  assert t.kind == TagLit, "arkham: expected a pointer/array type"
  case t.typeKind
  of PtrT, AptrT, ArrayT, FlexarrayT:
    var tc = t
    tc.into:
      result = tc; skip tc                    # the pointee / element type
      while tc.hasMore: skip tc
  else: raiseAssert "arkham: deref/index of a non-pointer/array type"

proc aggrWordCount*(p: var Program; typeName: string): int =
  ## Number of 8-byte GPRs a ≤16-byte aggregate occupies (1 or 2).
  let sz = aggrByteSize(p, typeName)
  assert sz <= 16, "arkham v1: >16-byte aggregate ABI (by-ref / x8) not yet supported"
  (sz + 7) div 8

proc aggrLayout*(p: var Program; typeName: string): seq[FieldInfo] =
  result = @[]
  var d = lookupType(p, typeName)
  var body: Cursor
  d.into:
    inc d; skip d                             # name, type-pragmas
    body = d; skip d                          # the body
  assert body.kind == TagLit and body.typeKind == ObjectT,
    "arkham: aggregate ABI requires an object type: " & typeName
  var oc = body
  var off = 0
  oc.into:
    if oc.kind == Symbol:                     # inherited base: its fields come
      result = aggrLayout(p, symName(oc))     # first, at their base offsets (the
      off = aggrByteSize(p, symName(oc))      # base sits at offset 0 in derived)
    skip oc                                   # base / inheritance slot
    while oc.hasMore:
      oc.into:                                # (fld :name pragmas type)
        let fn = symName(oc); inc oc
        skip oc                               # field-pragmas
        let (fsz, fal) = typeSizeAlign(p, oc)
        skip oc
        off = align(off, fal)
        result.add (name: fn, off: off, size: fsz)
        off += fsz
