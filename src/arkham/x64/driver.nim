#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `generateX64` — a Leng module in, x86-64 asm-NIF out.
##
## The order is what matters here: the program model is loaded, types and
## globals are declared, then each proc is analysed, planned and emitted. A
## `.assembler` body branches off to `asmproc` instead, because nothing about
## it goes through the allocator.

import std / [tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, analyser, planer, programs, asmbuf,
                    context, diag, typeutil, constdata,
                    regbind]
import machine as machine_x64
import emit, value, frame, stmt, asmproc
import asmproc

proc recordVarType(g: var CodeGen; c: Cursor) =
  ## `(param :nm . type)` / `(var :nm pragmas type …)` → record `symType[nm] = type`.
  var cc = c
  cc.into:
    if cc.kind == SymbolDef:
      let nm = symName(cc); inc cc
      skip cc                                    # pragmas
      let typeCur = cc; skip cc                  # type
      g.symType[nm] = g.declType(typeCur, cc)    # `.` ⇒ inferred from the initializer
    while cc.hasMore: skip cc

proc recordSymTypes(g: var CodeGen; c: Cursor) =
  ## Pre-pass: populate `symType` for every local var decl so `getType` works during
  ## allocation, before emission fills them in incrementally. Recurses statement
  ## containers; nested proc/type decls are allocated separately.
  if c.kind != TagLit: return
  case c.stmtKind
  of VarS, GvarS, TvarS, ConstS: g.recordVarType(c)
  of ProcS, TypeS: discard
  else:
    var cc = c
    cc.into:
      while cc.hasMore:
        g.recordSymTypes(cc)
        skip cc

proc genProc(g: var CodeGen; info: ProcInfo) =
  if info.isAsm:
    g.genAsmProc(info)
    return
  if info.isNaked:
    # An allocated body assumes a frame everywhere: a spill goes to an `(s)` slot,
    # a call needs the outgoing-argument area, a parameter past the sixth is read
    # relative to the frame. Removing the prologue under it does not produce a
    # smaller proc, it produces a wrong one — so `{.naked.}` is only ever legal
    # where every location is declared.
    lengError info.decl, "`{.naked.}` requires `{.assembler.}`: without a frame " &
              "the register allocator has nowhere to spill", lengInfo(info.decl)
  # Unlike A64 (where a thread-local goes through a TLV-descriptor thunk call), x64
  # reads/writes a tvar directly as an FS-segment operand — no call — so tvar
  # accesses must NOT mark the proc non-leaf. Hence the empty tvar set here.
  if not g.cleanSigComputed:                   # compute the clean-signature set once
    g.cleanSigProcs = cleanSigProcNames(g.prog)
    g.noReturnProcs = noReturnProcs(g.prog)
    g.cleanSigComputed = true
  let an = analyseProc(g.buf[], info.decl,
                       cleanCallees = g.cleanSigProcs,
                       procIsClean = isCleanSigProc(g.prog, info.decl),
                       noReturnCallees = g.noReturnProcs)
  g.varType.clear()                           # reuse the backing storage across procs
  g.symType.clear()
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.rb.resetProc()                            # per-proc register-binding state
  g.aliasToDecl.clear()                       # per-proc param ABI alias → decl name
  g.loopEnds = @[]                            # per-proc loop-exit label stack (while/break)
  # Aggregate return convention (before allocation): a named object ≤16B → rax:rdx;
  # >16B → a hidden pointer the caller passes in rdi, parked in a callee-saved reg
  # (rbx) for the proc's lifetime and written through on `ret`.
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                    # head → name → params, skip → ret type
    g.retIsVoid = rc.kind == DotToken            # `(proc :f (params …) . (pragmas …) …)`
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrSym = rc.symId
      g.retIndirect = g.aggrByRef(g.retAggrSym)
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true                       # float return → xmm0
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  let preseal = if g.retIndirect: {RBX} else: {}
  block:                                          # pre-fill symType so getType works in the gate
    var pc = info.decl
    pc.into:
      inc pc                                      # name
      if pc.kind == TagLit:                       # (params …)
        var p = pc
        p.into:
          while p.hasMore: (g.recordVarType(p); skip p)
      skip pc                                      # params
      skip pc                                      # ret type
      skip pc                                      # pragmas
      if pc.stmtKind == StmtsS: g.recordSymTypes(pc)
      while pc.hasMore: skip pc                    # drain (body + any trailing)
  # The pre-pass allocates HOMES only (decl walk); every expression decision is
  # made inline by the fused emitters at the point of emission. The x64 stride
  # scratch comes from emit-time staging (takeLvalStride).
  g.pickedRegs = {}
  g.pickedFRegs = {}
  g.emitTmpSpills = 0
  g.plan = allocateProc(g.buf[], info.decl, an, g.prog, x64MachineA, g.typeCtx, preseal)
  g.curProcName = info.asmName
  # Can an address into THIS frame exist at all? Only a stack-homed symbol has one —
  # a spilled scalar, an aggregate, an address-taken local (`AddrTaken` spills by
  # construction). With every value in a register the frame holds nothing the program
  # can point at, and a tail call's `(popframe)` is then unobservable. This is the
  # SOUND half of the tail-call guard; `tailCallLeaksFrame` is the syntactic half and
  # catches the direct `f(addr x)` shape in procs that do have slots.
  g.frameIsAddressable = false
  for pos in g.plan.symPos.values:
    if g.plan.planned(pos).kind == NamedStack:
      g.frameIsAddressable = true
      break                # names the proc in this backend's diagnostics
  when defined(arkhamCallerSaveDbg):
    # The ALLOCATOR's side of the caller-save audit: for every value it gave a
    # caller-saved home, the live interval it made that decision on, plus every call
    # position inside it. `emitCall2` prints where it actually saved (`CSCALL`);
    # `scratchpad/csdiff.py` joins the two. The emitted asm alone cannot answer this —
    # a value that is live but UNBOUND at a call looks correct to an asm-level audit
    # (nothing to save) and is fatal at run time.
    if g.plan.callerSaveHomes.len > 0:
      var allCalls = ""
      for p in an.callPositions:
        if allCalls.len > 0: allCalls.add ','
        allCalls.add $p
      stderr.write "CSPROC proc=" & info.asmName & " calls=" & allCalls & "\n"
      for name in g.plan.callerSaveHomes.keys:
        let vi = an.vars.getOrDefault(name)
        var crossed = ""
        for p in an.callPositions:
          if p > vi.initEndPos and p <= vi.freeAfter:
            if crossed.len > 0: crossed.add ','
            crossed.add $p
        let home = g.plan.homeOfSym(name)
        stderr.write "CSVAR proc=" & info.asmName & " var=" & name &
          " reg=" & (if home.kind == InReg: $home.r else: "?" & $home.kind) &
          " liveStart=" & $vi.liveStart & " initEnd=" & $vi.initEndPos &
          " freeAfter=" & $vi.freeAfter & " lastUse=" & $vi.lastUsePos &
          " defs=" & $vi.defs & " weight=" & $vi.weight &
          " init=" & $vi.initClass & " crossed=" & crossed & "\n"
  when defined(arkhamTracePath):
    stderr.writeLine "[arkham] " & info.asmName & ": NEW"
  when defined(arkhamDumpLocs):
    block:
      stderr.writeLine "=== allocValue locs ==="
      for pos in g.plan.locs.base ..< g.plan.locs.base + g.plan.locs.data.len:
        let l = g.plan.planned(pos)
        if l.kind == Undef: continue
        var s = "  pos " & $pos & " : " & $l.kind
        case l.kind
        of InReg: s.add " r=" & $l.r
        of InRegPair: s.add " r0=" & $l.r0 & " r1=" & $l.r1
        of Imm: s.add " imm=" & $l.ival
        of NamedStack, Glob, Tvar: s.add " " & l.name
        else: discard
        stderr.writeLine s
  if g.retIndirect:
    g.indirectReg = RBX
    g.plan.usedCallee.incl RBX                   # saved/restored like any callee reg
  # Pure-emit path: the allocator already assigned every value position; emit once.
  # (The frame is finalized INSIDE emitProcBody2, after the body — body-buffer model.
  # The entry injects a `call` to the synthetic global-init proc, so it makes a call
  # even when its own body does not — keep rsp 16-aligned for that call.)
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.argResidentParams.setLen 0; g.argResidentFlushed = false
  g.postDivergeBinds.setLen 0; g.nameBindTyp.clear()
  g.savedHomes.clear()
  g.lvalStride.clear(); g.lvalStrideBorrowed.clear()
  g.noFoldPos = -1
  g.curProcName = info.asmName
  when defined(arkhamDbgProc):
    block:
      var pc = info.decl; inc pc
      stderr.writeLine "DBG emit proc " & symName(pc)
  when defined(arkhamBridgeDbg):
    tightCompositions = 0
    lastResortTakes = 0
  g.emitProcBody2(info, an.hasCall)
  when defined(arkhamBridgeDbg):
    stderr.writeLine "BRIDGE tight=" & $tightCompositions & " lastResort=" &
                     $lastResortTakes & " " & info.asmName
  when defined(arkhamStagingDbg):
    stderr.writeLine "STAGING proc=" & info.asmName & " peak=" & $g.stagingPeak &
      " leaked=" & $g.stagingLive.len & " at=" & g.stagingPeakWhat
    g.stagingPeak = 0
    g.stagingPeakWhat = ""
    g.stagingLive.setLen 0

proc genGlobal*(g: var CodeGen; nifName: string; decl: Cursor) =
  ## `(gvar :name <type>)` — a zero-initialized `.bss` global (also `const`); any
  ## initializer is run at program entry by `emitGlobalInits`.
  # An importc-WITHOUT-exportc gvar names an external (its slot is an `exportc`
  # definition in another bundled module): emit NO slot — references resolve to
  # the bare C name via `emGlobalAddr`. An exportc gvar IS the definition, emitted
  # under its bare C name so importc references in other modules link to it.
  if nifName in g.prog.importcOnlyGvars: return
  let name = g.prog.gvarAsmName(nifName)
  var c = decl
  let isConst = c.stmtKind == ConstS
  c.into:                                       # (gvar SymbolDef VarPragmas Type Value?)
    inc c                                       # name
    skip c                                      # pragmas
    let typeCur = c
    skip c                                      # type
    let hasValue = c.hasMore and c.kind != DotToken
    if isConst and hasValue:
      # A true `const`: a read-only data blob in `.text` (no `.bss`, no entry-time
      # init — emitGlobalInits skips ConstS).
      var bytes = ""
      var relocs: seq[(int, string)] = @[]
      constToBytes(g.prog, typeCur, c, bytes, relocs)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
        for (off, sym) in relocs:               # symbol-address fields (vtable/RTTI)
          g.ab.tree RelocX:
            g.ab.intLit off
            g.ab.sym sym
    else:
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                         # type
      # A compile-time constant SCALAR initializer is laid out as *static data*:
      # emit the constant's bits as the gvar's value, so nifasm initializes the
      # (writable) `.bss` slot from the on-disk image. Correct even for a foreign
      # module's gvar in a bundle (its entry-time `emitGlobalInits` never runs) and
      # for a `var` later mutated (a read-only rodata blob would fault). Other
      # (runtime) initializers are still stored at entry by `emitGlobalInits`.
      g.genGlobalInitValue(name, typeCur, c, hasValue)
      g.ab.close()
    while c.hasMore: skip c                      # value (also handled at entry, if runtime)

proc generateX64*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                  windows = false): string =
  ## Compile a parsed Leng module to x86-64 asm-NIF text — Linux/ELF by default, or
  ## Windows/PE when `windows`, which nifasm's `win_x64` target assembles to a static
  ## `.exe` whose imports bind through the import table (each extern's own
  ## `(dynlib …)`-named library).
  ##
  ## The two targets share ONE code generator: the image is self-contained, so the
  ## convention on both sides of every arkham-generated call is arkham's own (SysV,
  ## `x64Machine`) whichever OS it runs on. Only the edges where the OS is the
  ## other party differ — the calls out to `importc`'d Windows APIs (Win64 ABI, see
  ## `win64Machine`) and the LINUX entry's exit trap (see `emProcessExit`; the
  ## Windows entry returns to ntdll's thunk like an ordinary proc).
  ##
  ## `md` is the ALLOCATED-against machine (`x64MachineA`), so the prologue/epilogue's
  ## view of the callee-saved pool matches `allocateProc`'s under `-d:arkhamStress`.
  ## The foreign edge keeps the unshrunk `win64Machine` — that is an ABI, not an
  ## allocation choice (see `stress.nim`).
  setTargetWord Word64             # x86-64: 8-byte pointers, 8-byte platform int
  var g = newCodeGen(buf, x64MachineA)
  g.ab.renderReg = x64RegName                 # render register slots as x86 names
  g.ab.immAnyDest = true                      # `mov r/m, imm32` exists here
  g.ab.arch = "x64"                           # BodyLib entries this target may splice
  g.prog = collect(buf, inputPath, tags, windows = windows)
  g.adoptProgram()
  g.ab.tree StmtsX64:
    g.ab.tree ArchD: g.ab.ident (if windows: "win_x64" else: "x64")
    if windows:
      # Every `importc` on Windows is a DLL import (there are no raw syscalls to
      # lower to — see `collect`), and every import names its OWN library via
      # the decl's `(dynlib …)` pragma; arkham hardcodes no library name. Externs
      # are emitted grouped per dll behind that dll's `(imp …)` — nifasm binds
      # an `(extproc …)` against the last import library seen.
      var dlls: seq[string] = @[]
      for ex in g.prog.externOrder:
        if ex.dll notin dlls: dlls.add ex.dll
      for dll in dlls:
        g.ab.tree ImpD: g.ab.str dll
        for ex in g.prog.externOrder:
          if ex.dll == dll: g.emitWinExtproc(ex)
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    # `arkham.tls.0` (the per-thread block FS points at) is owned and emitted by
    # nifasm, the linker — one unified block sized for ALL bundled modules' tvars,
    # plus the entry-prologue `arch_prctl` that sets FS. arkham only references it.
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)
    for sp in g.prog.syscalls:                  # one `(syproc …)` per used syscall
      g.emitSyproc(sp)
    for info in g.prog.procs:
      genProc(g, info)
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
