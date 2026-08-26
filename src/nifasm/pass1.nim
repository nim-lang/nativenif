#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Pass 1: read every declaration, define no code.
##
## The whole module is walked for `(proc …)`, `(syproc …)`, `(gvar …)`,
## `(tvar …)`, `(type …)`, `(imp …)`, `(extproc …)` and `(arch …)`, and each
## becomes a `Symbol` in the module scope with its type parsed and its position
## in the buffer recorded. Nothing is emitted: pass 2 needs every signature to
## exist before it can check a call to a proc declared further down, and the
## dead-code walk needs every name before it can decide which ones owe a body.


import nifcore
import core / [context, sem, cursors, diagnostics, typesem, modules,
               tags, model, tagconv, decls]

proc pass1Proc*(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
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
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  let sym = Symbol(name: ctx.symIdOf(name), kind: skProc, typ: procTyp, offset: -1,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc pass1Syproc*(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (syproc :Name (params ...) (result ...) (clobber ...) NR) — a Linux syscall with a
  # full proctype: params bound to the syscall ABI registers (so an `(arg pN)` binding
  # in a `(prepare …)` lands in the right register, e.g. x86-64 arg4 → r10), a result in
  # the kernel's return register, and the registers the syscall instruction clobbers
  # (x86-64: rcx, r11). It has no code/address; the number is kept in `offset` and the
  # `(syscall)`/`(svc)` marker reads it. See genSyscallMarker*.
  inc n
  if n.kind != SymbolDef: error("Expected syproc name", n)
  let name = symName(n)
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  if n.kind != IntLit: error("Expected syscall number in syproc", n)
  let sysNr = int(getInt(n))

  let sym = Symbol(name: ctx.symIdOf(name), kind: skSysProc, typ: procTyp, offset: sysNr,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc handleArch*(n: var Cursor; ctx: var GenContext) =
  ## Also fixes the target WORD SIZE for the whole assembly. asm-NIF always states
  ## `(arch …)` before any declaration, so every type is built under the right
  ## width — and arkham's `slots.setTargetWord` must have picked the same one, or
  ## a `(i -1)` field is sized differently on the two sides of the pipe.
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
  elif arch == "cortex_m":
    ctx.arch = Arch.CortexM
  else:
    error("Unknown architecture: " & arch, n)
  setAsmWordSize(case ctx.arch
                 of Arch.X64, Arch.LinuxA64, Arch.A64, Arch.WinX64, Arch.WinA64: 8
                 of Arch.CortexM: 4)
  inc n

proc pass1*(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; buf: var TokenBuf) =
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
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          elif n.kind == TagLit and n.tag == UnionTagId:
            let typ = parseUnionBody(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          else:
            let typ = parseType(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
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
          var sym = Symbol(name: ctx.symIdOf(name), kind: skRodata,
                          moduleName: moduleName, declStart: declStart)
          sym.offset = -1  # Mark as forward reference until defined
          # A `(rodata :name "bytes" (reloc off sym)*)` whose blob carries
          # symbol-pointer fields cannot live in read-only __TEXT on a PIE image:
          # the absolute target vaddr baked in would be stale under the ASLR slide.
          # Flag it so the Mach-O backend places it in writable __DATA and emits a
          # dyld rebase for each pointer field (see writeMachO). Arch-independent
          # flag; only the macOS path acts on it.
          block:
            var probe = start
            into probe:        # bound the cursor to this rodata's children
              skip probe       # name
              skip probe       # bytes string literal
              if probe.hasMore:  # one or more trailing (reloc ...) children
                sym.dataConst = true
              while probe.hasMore: skip probe   # drain so `into` sees rem == 0
          scope.define(sym)
          n = start
          skip n
        of GvarD:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skGvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of TvarD:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skTvar, typ: typ,
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
          # Load this library; `(imp …)` no longer decides what BINDS to it — each
          # `(extproc …)` names its own, so an import that only needs loading (the
          # Darwin TLV bootstrap, with no externs at all) is expressible too.
          discard ctx.importOrdinal(libPath)
        of ExtprocD:
          # (extproc :name "external_name" "dll"? (params …)? (result …)? (clobber …)?)
          inc n
          if n.kind != SymbolDef: error("Expected extproc name", n)
          let name = symName(n)
          inc n
          if n.kind != StrLit: error("Expected external symbol name string", n)
          let extName = getStr(n)
          inc n
          let libOrdinal = ctx.extprocLib(n)     # the optional dll operand
          let typ = parseExtprocSig(n, scope, ctx)
          # Allocate GOT slot
          let gotSlot = ctx.gotSlotCount
          ctx.gotSlotCount += 1
          # Create symbol
          let sym = Symbol(name: ctx.symIdOf(name), kind: skExtProc, typ: typ, extName: extName, libName: "", gotSlot: gotSlot)
          scope.define(sym)
          # Track for code generation
          ctx.extProcs.add ExtProcInfo(name: name, extName: extName, libOrdinal: libOrdinal, gotSlot: gotSlot, stubOffset: -1)
        of SyprocD:
          # (syproc :name (params ...) (result ...) (clobber ...) NR) — defines a
          # syscall's proctype + number; emits no code (see genSyscallMarker*).
          pass1Syproc(n, scope, ctx, moduleName, declStart)
          n = start
          skip n
        else:
          skip n
      else:
        skip n
