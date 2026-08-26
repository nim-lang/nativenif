#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## RV32 OPERANDS: what an asm-NIF operand node means here.
##
## The whole addressing vocabulary of this machine is **a base register plus a
## 12-bit signed offset**. No index, no scale, no PC-relative form, no
## SP-relative special case — `sp` is an ordinary register and a frame slot is
## `sp + q` like any other access. That single mode is why this file is a third
## the size of the AVR one, and why the target needs only one emitter bridge.
##
## The other shaping fact is what is ABSENT: there are no condition flags, so
## nothing here produces or consumes them. A comparison is `slt` into a register
## or a two-register branch, and both are ordinary instructions with ordinary
## operands.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, tagconv, decls, stackslots, relocs, buffers]
import encoder as rv
import regs

type
  Rv32Mem* = object
    base*: rv.Register
    off*: int

  OperandRv* = object
    kind*: OperandKind
    reg*: rv.Register
    typ*: Type
    immVal*: int64
    mem*: Rv32Mem
    argName*: SymId
    label*: LabelId

proc rvRegType*(): Type {.inline.} = Type(kind: RegisterT, regBits: 32)

proc checkRegWidthRv*(t: Type; what: string; n: Cursor) =
  ## Reject a value too wide for one register BY NAME. A 64-bit scalar is not an
  ## error in the input — it is a backend feature that does not exist yet, and
  ## truncating it silently is the one outcome that must not happen.
  if t == nil: return
  if t.kind == TypeKind.FloatT:
    error("RV32: " & what & " is a float; this target is `ilp32` soft-float and " &
          "has no FPU registers at all (see R5 in doc/internals/rv32.md)", n)
    return
  if t.kind in {TypeKind.IntT, TypeKind.UIntT} and t.bits > 32:
    error("RV32: " & what & " is " & $t.bits & " bits; a 64-bit scalar lives in a " &
          "register PAIR here and that is not implemented yet (see R5 in " &
          "doc/internals/rv32.md)", n)

proc slotMem*(offset: int; n: Cursor): Rv32Mem =
  ## A frame slot, as `sp + q`. Twelve signed bits reach 2047 bytes of frame,
  ## which is enough that a proc exceeding it is a diagnostic rather than a
  ## machinery problem.
  if offset < -2048 or offset > 2047:
    error("RV32: the frame slot at sp+" & $offset & " is past the 12-bit offset " &
          "field; this proc's frame is too large (see R5 in doc/internals/rv32.md)", n)
  Rv32Mem(base: rv.Sp, off: offset)

proc regOfRv*(op: OperandRv; what: string; n: Cursor): rv.Register =
  if op.kind notin {okReg, okArg}:
    error("RV32: " & what & " must be a register", n)
  op.reg

proc immOfRv*(op: OperandRv; what: string; n: Cursor): int64 =
  if op.kind != okImm:
    error("RV32: " & what & " must be an immediate", n)
    return 0
  if not rv.fitsImm12(op.immVal):
    error("RV32: " & what & " is " & $op.immVal & ", outside the 12-bit signed " &
          "immediate every `i`-form here carries — a wider constant is " &
          "`lui`+`addi`, which is two instructions and therefore the code " &
          "generator's to write", n)
    return 0
  op.immVal

proc checkFree(ctx: var GenContext; r: rv.Register; n: Cursor) =
  if r in ctx.rv32RegBindings:
    error("Register " & regName(r) & " is bound to variable '" &
          ctx.rv32RegBindings[r] & "', use the variable name instead", n)

proc parseOperandRv*(n: var Cursor; ctx: var GenContext): OperandRv =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsRv32Gpr(t):
      result.kind = okReg
      result.reg = parseRegisterRv32(n)
      result.typ = rvRegType()
      # `zero` is never a binding and never a clobber: it reads as zero whatever
      # anyone does, which is exactly why the emitter names it so freely.
      if result.reg != rv.Zero: ctx.checkFree(result.reg, n)
    elif t == NilTagId:
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == SsizeTagId:
      # The frame size, patched once the frame is known. The site is the 12-bit
      # immediate of the `addi` that moves SP — fixed width, so patching never
      # resizes an instruction and no position downstream moves.
      result.kind = okSsize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32)
      into n:
        if n.hasMore and n.kind == IntLit:
          result.immVal = getInt(n)
          inc n
    elif t == CsizeTagId:
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okImm
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32, litVal: result.immVal)
      into n:
        while n.hasMore: skip n
    elif t == ArgTagId:
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      var argName: SymId
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        while n.hasMore: skip n
      let p = findParam(ctx.callContext.typ, argName)
      if p == nil: error("Unknown argument: " & ctx.nameOf(argName), n)
      if p.typ.isOnStack:
        error("RV32: '" & ctx.nameOf(argName) & "' is a stack-passed argument; " &
              "this target passes eight in registers and rejects the rest by " &
              "name (see R5 in doc/internals/rv32.md)", n)
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl argName
      result.kind = okArg
      result.argName = argName
      result.reg = tagToRegisterRv32(p.reg, n)
      result.typ = p.typ
    elif t == ResTagId:
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      var resName: SymId
      into n:
        if n.kind != Symbol: error("Expected result name in (res ...)", n)
        resName = getSymId(n)
        inc n
        while n.hasMore: skip n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil: error("Unknown result: " & ctx.nameOf(resName), n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), n)
      ctx.callContext.resultsSet.incl resName
      result.kind = okReg
      result.reg = tagToRegisterRv32(resPtr.reg, n)
      result.typ = resPtr.typ
    elif t == MemTagId:
      # `(mem <base> [offset])`, and the base may itself be a stack slot — in
      # which case the two offsets ADD, in the same instruction's field. That is
      # not a synthesis: the slot's part is nifasm's own number and the rest is
      # the code generator's, and it is still one `lw`.
      var base: OperandRv
      var extra = 0
      into n:
        base = parseOperandRv(n, ctx)
        if n.hasMore and n.kind == IntLit:
          extra = int(getInt(n))
          inc n
        while n.hasMore: skip n
      result.kind = okMem
      if base.kind == okMem:
        result.mem = base.mem
        result.mem.off += extra
        result.typ = base.typ
      elif base.kind in {okReg, okArg}:
        result.mem = Rv32Mem(base: base.reg, off: extra)
        result.typ = rvRegType()
      else:
        error("RV32: (mem ...) needs a base register or a stack slot", n)
      if not rv.fitsImm12(int64(result.mem.off)):
        error("RV32: the offset " & $result.mem.off & " is past the 12-bit field", n)
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandRv(n, ctx)
      op.typ = castType
      result = op
      return
    else:
      error("Unsupported RV32 operand", n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 32, litVal: result.immVal)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown symbol: " & name, n)
    case sym.kind
    of skVar, skParam:
      if sym.typ.isOnStack:
        result.kind = okMem
        result.mem = slotMem(sym.offset, n)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.kind = okReg
        result.reg = tagToRegisterRv32(sym.reg, n)
        result.typ = sym.typ
        if result.reg in ctx.clobberedRv32:
          error("Variable '" & name & "' lives in " & regName(result.reg) &
                ", which a call clobbered; its value is gone", n)
      else:
        error("Variable has no location: " & name, n)
      inc n
    of skLabel:
      result.kind = okLabel
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skRodata, skProc:
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skGvar:
      error("RV32: globals are not implemented yet: '" & name &
            "' (see R5 in doc/internals/rv32.md)", n)
    of skTvar:
      error("RV32 has no thread-local storage yet: '" & name & "'", n)
    else:
      error("Cannot use symbol '" & name & "' as an operand", n)
  else:
    error("Expected operand", n)

proc parseDestRv*(n: var Cursor; ctx: var GenContext): OperandRv =
  if n.kind == TagLit and rawTagIsRv32Gpr(n.tag):
    result.kind = okReg
    result.reg = parseRegisterRv32(n)
    result.typ = rvRegType()
    return
  result = parseOperandRv(n, ctx)

proc condOfRv*(t: TagEnum; n: Cursor): rv.Condition =
  ## The six compare-and-branch tags. There is deliberately no mapping from the
  ## x86 FLAG vocabulary that `(jtrue …)` uses on the other targets: this machine
  ## has no flags, so a condition is not a thing that exists between two
  ## instructions here.
  let inst = tagToRv32Inst(t)
  case inst
  of BeqrRv: rv.CondEq
  of BnerRv: rv.CondNe
  of BltrRv: rv.CondLt
  of BgerRv: rv.CondGe
  of BlturRv: rv.CondLtu
  of BgeurRv: rv.CondGeu
  else:
    error("RV32: not a branch", n)
    rv.CondEq
