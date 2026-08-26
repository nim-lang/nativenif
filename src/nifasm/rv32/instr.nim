#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 instruction selector: ONE asm-NIF node in, one RV32 instruction out.
##
## The rule holds more easily here than anywhere else in the tree, because the
## machine is regular: three-operand ALU, one addressing mode, fixed-width
## instructions. The two places it would be tempting to break it are both
## refused instead — a constant wider than twelve bits is `lui`+`addi` and a call
## further than a megabyte is `auipc`+`jalr`, and both are the code generator's
## to write.
##
## The exception, as everywhere, is what nifasm ITSELF computes: `(ssize)`, the
## frame size, and a frame slot's offset.
##
## **There are no condition flags**, so `(ite …)`/`(jtrue …)` — which are built
## on the x86 flag vocabulary — mean nothing here and are refused. Control flow
## is `(beqr A B L)` and its five siblings, which compare and branch in one
## instruction, plus `(lab …)`, `(b …)` and `(loop …)`.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, tagconv, decls, stackslots, relocs, buffers,
                    listing]
import encoder as rv
import regs
import operands

proc genStmtRv(n: var Cursor; ctx: var GenContext)
proc genInstRv(n: var Cursor; ctx: var GenContext)

proc genLoopRv(n: var Cursor; ctx: var GenContext) =
  inc n
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtRv(n, ctx)
    rv.emitJ(ctx.buf, lStart)
    return
  error("RV32: only the `(loop (stmts …))` form is supported", n)

proc bindRegRv(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
               reg: rv.Register) =
  if reg in ctx.rv32RegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.rv32RegBindings[reg]))
    ctx.rv32RegBindings.del reg
  ctx.clobberedRv32.excl reg
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.rv32RegBindings[reg] = name
  ctx.scope.define(sym)

proc parseRebindHeaderRv(n: var Cursor; ctx: var GenContext):
                        tuple[name: string; reg: rv.Register] =
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  checkRegWidthRv(typ, "rebind of '" & name & "'", n)
  if n.kind != TagLit or not rawTagIsRv32Gpr(n.tag):
    error("Expected a register for rebind/withreg", n)
  let regTag = n.tag
  let reg = tagToRegisterRv32(regTag, n)
  skip n
  bindRegRv(ctx, name, typ, regTag, reg)
  result = (name, reg)

const RvCallClobbers* = {rv.X1, rv.X5, rv.X6, rv.X7,
                         rv.X10 .. rv.X17, rv.X28 .. rv.X31}
  ## What a call destroys under the ilp32 convention: `ra`, `t0`–`t2`, `a0`–`a7`
  ## and `t3`–`t6`. `s0`–`s11` are callee-saved, which is where a value that must
  ## survive a call belongs — and there are twelve of them, which is why this
  ## target's allocator has room the other two do not.

proc callClobbersRv(ctx: GenContext): set[rv.Register] =
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersRv32
  else: RvCallClobbers

proc genPrepareRv(n: var Cursor; ctx: var GenContext) =
  var hdr = n
  inc hdr
  if hdr.kind != Symbol: error("Expected proc symbol, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)
  if sym == nil: error("Unknown symbol: " & name, hdr)

  let outerCall = ctx.callContext
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false)

  case sym.kind
  of skProc:
    ctx.callContext.typ = sym.typ
  of skGvar, skVar, skParam:
    if sym.typ.kind != ProcT:
      error("Expected proc symbol, got " & $sym.kind, hdr)
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  of skExtProc:
    error("RV32: `extproc` is not implemented yet — this target links nothing " &
          "yet (see R5 in doc/internals/rv32.md)", hdr)
  of skSysProc:
    error("RV32: a syscall is `(ecall)` with the number in a7, not a `syproc` " &
          "declaration", hdr)
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
  if ctx.callContext.stackArgSize > 0:
    error("RV32: '" & name & "' passes arguments on the stack; this target " &
          "passes eight in registers and rejects the rest by name (R5)", hdr)

  into n:
    skip n
    while n.hasMore:
      genInstRv(n, ctx)

  for param in ctx.callContext.typ.params:
    if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
      error("Missing argument: " & ctx.nameOf(param.name), hdr)
  for res in ctx.callContext.typ.results:
    if res.name notin ctx.callContext.resultsSet:
      error("Missing result binding: " & ctx.nameOf(res.name), hdr)
  if not ctx.callContext.callEmitted:
    error("Missing (call) in prepare block", hdr)

  ctx.callContext = outerCall
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerRv(n: var Cursor; ctx: var GenContext) =
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedRv32.incl callClobbersRv(ctx)

  if ctx.callContext.indirect:
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # `jalr ra, rs, 0` — the target is wherever the code generator put it, and
      # any register will do, which is the whole difference from AVR's single Z.
      rv.emitJalr(ctx.buf.data, rv.Ra, tagToRegisterRv32(sym.reg, n), 0)
    else:
      error("RV32: an indirect call needs its target in a register", n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  rv.emitCall(ctx.buf, labId)
  ctx.callContext.callEmitted = true
  inc n

proc genInstRv(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToRv32Inst(n.tag)
  let start = n

  case tagToNifasmDecl(n.tag)
  of CfvarD:
    error("RV32: `(cfvar …)` belongs to the flag-based control flow the other " &
          "targets use; this machine has no flags, so a condition is a branch " &
          "(`(beqr …)`) rather than a value left between two instructions", n)
  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var regTag = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsRv32Gpr(locTag):
        let r = tagToRegisterRv32(locTag, n)
        if r in {rv.Zero, rv.Ra, rv.Sp, rv.Gp, rv.Tp}:
          error("Cannot bind a variable to " & regName(r) &
                ": it is reserved by the ABI", n)
        regTag = locTag
        skip n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: TypeKind.StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      checkRegWidthRv(baseTyp, "variable '" & name & "'", n)
      sym.typ = baseTyp
      sym.reg = regTag
      let r = tagToRegisterRv32(regTag, n)
      if r in ctx.rv32RegBindings:
        error("Register " & regName(r) & " is already bound to variable '" &
              ctx.rv32RegBindings[r] & "', kill it first before reusing", n)
      ctx.rv32RegBindings[r] = name
      ctx.clobberedRv32.excl r
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard
  else:
    raiseAssert("Unhandled declaration tag in RV32 selector")

  if isEscapedTag(n): inc n

  template alu3(emitter: untyped) =
    ## `(op3 D A B)` — three operands, which is what this machine has and what
    ## makes the shared AArch64 spelling fit unchanged.
    inc n
    let d = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let b = parseOperandRv(n, ctx)
    emitter(ctx.buf.data, regOfRv(d, "destination", start),
            regOfRv(a, "first source", start), regOfRv(b, "second source", start))

  template aluI(emitter: untyped) =
    ## `(op D A K)` — the immediate forms, all carrying the SAME 12-bit signed
    ## field, which is why one predicate covers them.
    inc n
    let d = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let k = parseOperandRv(n, ctx)
    emitter(ctx.buf.data, regOfRv(d, "destination", start),
            regOfRv(a, "source", start), immOfRv(k, "immediate", start))

  template shiftI(emitter: untyped) =
    inc n
    let d = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let k = parseOperandRv(n, ctx)
    if k.kind != okImm or k.immVal < 0 or k.immVal > 31:
      error("RV32: a shift amount is 0..31", start)
    emitter(ctx.buf.data, regOfRv(d, "destination", start),
            regOfRv(a, "source", start), int(k.immVal))

  template load(emitter: untyped) =
    inc n
    let d = parseDestRv(n, ctx)
    let s = parseOperandRv(n, ctx)
    if s.kind != okMem: error("RV32: the source of a load must be memory", start)
    emitter(ctx.buf.data, regOfRv(d, "destination", start), s.mem.base,
            int64(s.mem.off))

  template store(emitter: untyped) =
    inc n
    let d = parseDestRv(n, ctx)
    let s = parseOperandRv(n, ctx)
    if d.kind != okMem: error("RV32: the destination of a store must be memory", start)
    emitter(ctx.buf.data, regOfRv(s, "source", start), d.mem.base, int64(d.mem.off))

  template branch(cond: rv.Condition) =
    inc n
    let a = parseOperandRv(n, ctx)
    let b = parseOperandRv(n, ctx)
    let t = parseOperandRv(n, ctx)
    if t.kind != okLabel: error("RV32: a branch needs a label", start)
    rv.emitBranch(ctx.buf, cond, regOfRv(a, "first operand", start),
                  regOfRv(b, "second operand", start), t.label)

  template plain(emitter: untyped) =
    ## `skip n`, NOT `inc n` followed by draining `hasMore`: `inc` steps INTO the
    ## node, and `hasMore` is then relative to the enclosing `(stmts …)` — so the
    ## drain swallowed every statement after this one. It only ever showed up
    ## where such an instruction was not the last in its block.
    emitter(ctx.buf.data)
    skip n

  case instTag
  of StmtsRv:
    loopInto n:
      genInstRv(n, ctx)
  of ScopeRv:
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstRv(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of LabRv:
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil:
      let labId = ctx.buf.createLabel()
      ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skLabel, offset: int(labId)))
      ctx.buf.defineLabel(labId)
      ctx.definedLabels.incl int(labId)
    elif sym.kind == skLabel:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
      ctx.buf.defineLabel(LabelId(sym.offset))
      ctx.definedLabels.incl sym.offset
    else:
      error("Expected label, got " & $sym.kind, n)
    inc n
  of LoopRv: genLoopRv(n, ctx)
  of PrepareRv: genPrepareRv(n, ctx)
  of CallRv:
    if ctx.inCall: genCallMarkerRv(n, ctx)
    else: error("RV32: a call must appear inside a `(prepare …)` block", start)
  of KillRv:
    inc n
    if n.kind != Symbol: error("Expected variable name in kill", n)
    let name = getSym(n)
    let sym = ctx.scope.lookup(ctx.symIdOf(name))
    if sym == nil: error("Unknown symbol in kill: " & name, n)
    if sym.reg != InvalidTagId:
      ctx.rv32RegBindings.del tagToRegisterRv32(sym.reg, n)
    elif sym.typ != nil and sym.typ.isOnStack:
      ctx.slots.killSlot(sym.offset, sym.typ.offType)
    ctx.scope.undefine(ctx.symIdOf(name))
    inc n
  of RebindRv:
    inc n
    discard parseRebindHeaderRv(n, ctx)
  of WithregRv:
    inc n
    let hdr = parseRebindHeaderRv(n, ctx)
    while n.hasMore: genInstRv(n, ctx)
    ctx.rv32RegBindings.del hdr.reg
    ctx.scope.undefine(ctx.symIdOf(hdr.name))

  of MovRv:
    ## `mv rd, rs` IS `addi rd, rs, 0`. There is no move instruction and none is
    ## missing.
    inc n
    let d = parseDestRv(n, ctx)
    let s = parseOperandRv(n, ctx)
    if s.kind == okImm:
      error("RV32: `(mov)` moves a register; a constant is `(addi D (x0) K)` " &
            "when it fits twelve signed bits and `(lui)`+`(addi)` when it does " &
            "not — which is two instructions, so the choice is arkham's", start)
    rv.emitMv(ctx.buf.data, regOfRv(d, "destination", start),
              regOfRv(s, "source", start))

  of Add3Rv: alu3(rv.emitAdd)
  of Sub3Rv: alu3(rv.emitSub)
  of Mul3Rv: alu3(rv.emitMul)
  of And3Rv: alu3(rv.emitAnd)
  of Orr3Rv: alu3(rv.emitOr)
  of Eor3Rv: alu3(rv.emitXor)
  of Lsl3Rv: alu3(rv.emitSll)
  of Lsr3Rv: alu3(rv.emitSrl)
  of Asr3Rv: alu3(rv.emitSra)
  of SltRv: alu3(rv.emitSlt)
  of SltuRv: alu3(rv.emitSltu)
  of DivsRv: alu3(rv.emitDiv)
  of Divu3Rv: alu3(rv.emitDivu)
  of RemsRv: alu3(rv.emitRem)
  of RemuRv: alu3(rv.emitRemu)

  of AddiRv: aluI(rv.emitAddi)
  of SltiRv: aluI(rv.emitSlti)
  of SltiuRv: aluI(rv.emitSltiu)
  of XoriRv: aluI(rv.emitXori)
  of OriRv: aluI(rv.emitOri)
  of AndiRv: aluI(rv.emitAndi)
  of SlliRv: shiftI(rv.emitSlli)
  of SrliRv: shiftI(rv.emitSrli)
  of SraiRv: shiftI(rv.emitSrai)

  of LuiRv:
    inc n
    let d = parseDestRv(n, ctx)
    let k = parseOperandRv(n, ctx)
    if k.kind != okImm: error("RV32: `lui` takes an immediate", start)
    rv.emitLui(ctx.buf.data, regOfRv(d, "destination", start),
               uint32(k.immVal and 0xFFFFF))
  of AuipcRv:
    inc n
    let d = parseDestRv(n, ctx)
    let k = parseOperandRv(n, ctx)
    if k.kind != okImm: error("RV32: `auipc` takes an immediate", start)
    rv.emitAuipc(ctx.buf.data, regOfRv(d, "destination", start),
                 uint32(k.immVal and 0xFFFFF))

  of LwrRv: load(rv.emitLw)
  of LhrRv: load(rv.emitLh)
  of LhurRv: load(rv.emitLhu)
  of LbrRv: load(rv.emitLb)
  of LburRv: load(rv.emitLbu)
  of SwrRv: store(rv.emitSw)
  of Shr32Rv: store(rv.emitSh)
  of SbrRv: store(rv.emitSb)
  of LdrRv: load(rv.emitLw)      ## the shared word-load spelling
  of StrRv: store(rv.emitSw)

  of BeqrRv: branch(rv.CondEq)
  of BnerRv: branch(rv.CondNe)
  of BltrRv: branch(rv.CondLt)
  of BgerRv: branch(rv.CondGe)
  of BlturRv: branch(rv.CondLtu)
  of BgeurRv: branch(rv.CondGeu)

  of BRv:
    inc n
    let t = parseOperandRv(n, ctx)
    if t.kind != okLabel: error("RV32: a jump needs a label", start)
    rv.emitJ(ctx.buf, t.label)
  of BlRv:
    inc n
    let t = parseOperandRv(n, ctx)
    if t.kind != okLabel: error("RV32: a call needs a label", start)
    rv.emitCall(ctx.buf, t.label)
  of JalrRv:
    inc n
    let d = parseDestRv(n, ctx)
    let a = parseOperandRv(n, ctx)
    let k = parseOperandRv(n, ctx)
    rv.emitJalr(ctx.buf.data, regOfRv(d, "destination", start),
                regOfRv(a, "base", start), immOfRv(k, "offset", start))
  of AdrRv:
    ## `lui`+`addi` carrying an absolute address. Two instructions, and legal here
    ## for the reason Cortex-M's MOVW/MOVT pair is: the VALUE is a final-layout
    ## fact only nifasm knows, so it is nifasm encoding its own operand rather
    ## than lowering one the code generator supplied.
    inc n
    let d = parseDestRv(n, ctx)
    let t = parseOperandRv(n, ctx)
    let dr = regOfRv(d, "destination", start)
    if t.gvarSym != nil:
      # A GLOBAL: the data segment's base is not known until the image is laid
      # out, so the site is recorded and patched there, exactly as Cortex-M does.
      ctx.gvarSites.add (ctx.buf.data.len, t.gvarSym)
      rv.emitLui(ctx.buf.data, dr, 0)
      rv.emitAddi(ctx.buf.data, dr, dr, 0)
    elif t.kind == okLabel:
      rv.emitLa(ctx.buf, dr, t.label)
    else:
      error("RV32: `(adr)` needs a label or a global", start)

  of AddRv, SubRv:
    ## The two-operand spelling, and it exists on this three-operand machine for
    ## exactly one job: the frame. `(sub (sp) (ssize))` in the prologue and
    ## `(add (sp) (ssize))` in the epilogue, which is how every other target
    ## spells it too.
    ##
    ## The placeholder carries the SIGN: `addi d, d, 0` for an add and
    ## `addi d, d, -1` for a subtract. The frame size is not known until the body
    ## has been assembled, and the patcher has no other way to tell which of the
    ## two it is looking at — the instruction is the same one.
    inc n
    let d = parseDestRv(n, ctx)
    let s = parseOperandRv(n, ctx)
    let dr = regOfRv(d, "destination", start)
    if s.kind == okSsize:
      ctx.ssizePatches.add (ctx.buf.data.len, int(s.immVal))
      rv.emitAddi(ctx.buf.data, dr, dr, (if instTag == SubRv: -1 else: 0))
    elif s.kind == okImm:
      let v = if instTag == SubRv: -s.immVal else: s.immVal
      if not rv.fitsImm12(v):
        error("RV32: " & $v & " is outside the 12-bit signed immediate; a wider " &
              "adjustment is `lui`+`add`, which is two instructions", start)
      rv.emitAddi(ctx.buf.data, dr, dr, v)
    else:
      let sr = regOfRv(s, "source", start)
      if instTag == SubRv: rv.emitSub(ctx.buf.data, dr, dr, sr)
      else: rv.emitAdd(ctx.buf.data, dr, dr, sr)

  of LeaRv:
    ## The ADDRESS of a frame slot: `addi d, sp, q`. One instruction, and `q` is
    ## nifasm's own number — the slot manager assigned it — so nothing is being
    ## invented on the code generator's behalf.
    inc n
    let d = parseDestRv(n, ctx)
    let sOp = parseOperandRv(n, ctx)
    if sOp.kind != okMem:
      error("RV32: `(lea D S)` takes an address expression", start)
    rv.emitAddi(ctx.buf.data, regOfRv(d, "destination", start), sOp.mem.base,
                int64(sOp.mem.off))

  of RetRv: plain(rv.emitRet)
  of NopRv: plain(rv.emitNop)
  of EcallRv: plain(rv.emitEcall)
  of EbreakRv: plain(rv.emitEbreak)

  of IteRv, JtrueRv:
    error("RV32: `(ite …)`/`(jtrue …)` are built on the x86 FLAG vocabulary, and " &
          "this machine has no flags. A condition here is a branch — " &
          "`(beqr A B L)` and its five siblings — which compares and jumps in " &
          "one instruction", start)
  else:
    error("RV32: instruction '" & $instTag & "' is not implemented yet " &
          "(see doc/internals/rv32.md)", start)

proc genStmtRv(n: var Cursor; ctx: var GenContext) =
  genInstRv(n, ctx)

proc genInstNodeRv*(n: var Cursor; ctx: var GenContext) =
  withListingRow(ctx, n): genInstRv(n, ctx)
