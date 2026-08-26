#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## AVR OPERANDS: what an asm-NIF operand node means here.
##
## Two things drive the shape, and both are unusual enough to state up front.
##
## **A register is 8 bits, but a value is 16.** So an operand carries either a
## register or a PAIR, and which one it is depends on the tag rather than on the
## type. `(mov (r24) (r18))` moves a byte; `(movw (rp24) (rp18))` moves a word.
## Nothing here widens one into the other — that would be inventing an
## instruction.
##
## **Memory is addressed only through X, Y and Z**, and only Y and Z have a
## displaced form. There is no SP-relative access at all: SP lives in the I/O
## space and cannot be an address. So Y is a real frame pointer, established in
## the prologue, and every stack slot is `Y+q` with q in 0..63. An address that
## is not already in a pointer pair is an error, not a load through a scratch —
## putting it there is code generation, and this is the assembler.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, tagconv, decls, stackslots, relocs, buffers]
import encoder as avr
import regs

type
  AvrMemKind* = enum
    amPtr       ## `X`, or `Y+q` / `Z+q` — the indirect forms
    amDirect    ## a 16-bit absolute data address: `lds`/`sts`, two words

  AvrMem* = object
    kind*: AvrMemKind
    p*: avr.PtrReg
    disp*: int          ## 0..63; always 0 for X, which has no displaced form
    address*: int       ## `amDirect` only

  OperandAvr* = object
    kind*: OperandKind
    reg*: avr.Register
    pair*: avr.Pair
    isPair*: bool       ## the operand names a PAIR, not one 8-bit register
    typ*: Type
    immVal*: int64
    mem*: AvrMem
    argName*: SymId
    label*: LabelId
    isCode*: bool       ## the label names a proc, so its address is a WORD address

const
  FramePtr* = avr.Y
    ## Y is the frame pointer, and on this target that is not a choice the
    ## prologue could make differently: SP cannot address memory, and of the
    ## three pairs that can, X has no displaced form and Z is the only indirect
    ## call target.
  MaxDisp* = 63
    ## The whole reach of a frame slot. Beyond it the pointer has to be advanced
    ## first, which is more than one instruction.

proc avrRegType*(): Type {.inline.} =
  ## The "fits one 8-bit register" type. 8, not 16: `compatible` bounds a value
  ## by `regBits div 8`, so declaring 16 here would let a word-sized value bind
  ## to a single half unnoticed — which is exactly the mistake this target
  ## invites.
  Type(kind: RegisterT, regBits: 8)

proc avrPairType*(): Type {.inline.} =
  Type(kind: RegisterT, regBits: 16)

proc checkRegWidthAvr*(t: Type; what: string; n: Cursor) =
  ## Reject a value too wide for a pair BY NAME. A 32- or 64-bit scalar is not an
  ## error in the input — it is a backend feature that does not exist yet, and
  ## truncating it silently is the one outcome that must not happen.
  if t == nil: return
  if t.kind == TypeKind.FloatT:
    error("AVR: " & what & " is a float; this target has no FPU and no softfloat " &
          "library (see doc/internals/avr.md)", n)
    return
  if t.kind in {TypeKind.IntT, TypeKind.UIntT} and t.bits > 16:
    error("AVR: " & what & " is " & $t.bits & " bits; a value wider than 16 lives " &
          "in memory here and cannot be bound to a register pair (see M5 in " &
          "doc/internals/avr.md)", n)

proc slotMem*(offset: int; n: Cursor): AvrMem =
  ## A frame slot, as `Y+q`. The slot manager counts UP from the bottom of the
  ## frame and Y points one byte below it — `push` writes at SP and then
  ## decrements, so SP and Y always sit one below the lowest live byte.
  let q = offset + 1
  if q > MaxDisp:
    error("AVR: the frame slot at Y+" & $q & " is past the 63-byte displacement " &
          "range of `ldd`/`std`; this proc's frame is too large (see M5 in " &
          "doc/internals/avr.md)", n)
  AvrMem(kind: amPtr, p: avr.PY, disp: q)

proc regOfAvr*(op: OperandAvr; what: string; n: Cursor): avr.Register =
  ## `okArg` counts: an argument bound to a register IS that register.
  if op.kind notin {okReg, okArg}:
    error("AVR: " & what & " must be a register", n)
  if op.isPair:
    error("AVR: " & what & " must be one 8-bit register, not a pair — an " &
          "instruction here works on a half", n)
  op.reg

proc pairOfAvr*(op: OperandAvr; what: string; n: Cursor): avr.Pair =
  if op.kind notin {okReg, okArg}:
    error("AVR: " & what & " must be a register pair", n)
  if not op.isPair:
    error("AVR: " & what & " must be a register PAIR `(rpN)` — `movw`, `adiw` " &
          "and `sbiw` are the instructions that take one", n)
  op.pair

proc immOfAvr*(op: OperandAvr; what: string; lo, hi: int; n: Cursor): int =
  if op.kind != okImm:
    error("AVR: " & what & " must be an immediate", n)
    return 0
  if op.immVal < lo or op.immVal > hi:
    error("AVR: " & what & " is " & $op.immVal & ", outside " & $lo & ".." & $hi &
          " — the immediate field does not reach it, and widening it is not one " &
          "instruction", n)
    return 0
  int(op.immVal)

proc bindNames*(ctx: var GenContext; name: string; reg: avr.Register; isPair: bool) =
  ## Record a name against the register it lives in — BOTH halves when it is a
  ## pair. That is what makes a raw `(r25)` use of the high half of a pair-typed
  ## local an error: a table keyed by pairs could not see it at all.
  ctx.avrRegBindings[reg] = name
  if isPair: ctx.avrRegBindings[avr.Register(ord(reg) + 1)] = name
  ctx.clobberedAvr.excl reg
  if isPair: ctx.clobberedAvr.excl avr.Register(ord(reg) + 1)

proc unbindNames*(ctx: var GenContext; reg: avr.Register; isPair: bool) =
  ctx.avrRegBindings.del reg
  if isPair: ctx.avrRegBindings.del avr.Register(ord(reg) + 1)

proc checkFree(ctx: var GenContext; r: avr.Register; n: Cursor) =
  if r in ctx.avrRegBindings:
    error("Register " & regName(r) & " is bound to variable '" &
          ctx.avrRegBindings[r] & "', use the variable name instead", n)

proc parseOperandAvr*(n: var Cursor; ctx: var GenContext): OperandAvr =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsAvrPair(t):
      result.kind = okReg
      result.isPair = true
      result.pair = parsePairAvr(n)
      result.reg = lowOf(result.pair)
      result.typ = avrPairType()
      ctx.checkFree(result.reg, n)
      ctx.checkFree(highOf(result.pair), n)
    elif rawTagIsAvrGpr(t):
      result.kind = okReg
      result.reg = parseRegisterAvr(n)
      result.typ = avrRegType()
      ctx.checkFree(result.reg, n)
    elif t == NilTagId:
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == SsizeTagId:
      # The frame size, patched once the frame is known. On this target the site
      # is the 6-bit immediate of an `adiw`/`sbiw`, or the two immediates of a
      # `subi`/`sbci` pair — fixed width either way, so patching never resizes an
      # instruction and no position downstream moves.
      result.kind = okSsize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 16)
      into n:
        if n.hasMore and n.kind == IntLit:
          result.immVal = getInt(n)
          inc n
    elif t == CsizeTagId:
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okImm
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: TypeKind.IntLitT, bits: 16, litVal: result.immVal)
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
        error("AVR: '" & ctx.nameOf(argName) & "' is a stack-passed argument; " &
              "this target passes four pairs in registers and rejects the rest " &
              "by name (see M5 in doc/internals/avr.md)", n)
      # Mark it supplied on ANY mention, and do not complain about a second one.
      # A 16-bit argument here is written in two instructions — `(ldi (lo (arg
      # x)) …)` then `(ldi (hi (arg x)) …)` — so "set exactly once" is not a
      # property a single node can carry on this target. The check that matters,
      # that every register parameter was supplied at all, is unaffected.
      ctx.callContext.argsSet.incl argName
      result.kind = okArg
      result.argName = argName
      let regTag = p.reg
      if rawTagIsAvrPair(regTag):
        result.isPair = true
        result.pair = tagToPairAvr(regTag, n)
        result.reg = lowOf(result.pair)
      else:
        result.reg = tagToRegisterAvr(regTag, n)
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
      if rawTagIsAvrPair(resPtr.reg):
        result.isPair = true
        result.pair = tagToPairAvr(resPtr.reg, n)
        result.reg = lowOf(result.pair)
      else:
        result.reg = tagToRegisterAvr(resPtr.reg, n)
      result.typ = resPtr.typ
    elif t == MemTagId:
      # `(mem <pointer pair> [offset])` — the indirect forms. The base must
      # ALREADY be X, Y or Z: this target has three address registers and the
      # assembler does not spend one behind the code generator's back.
      var base: OperandAvr
      var extra = 0
      into n:
        base = parseOperandAvr(n, ctx)
        if n.hasMore and n.kind == IntLit:
          extra = int(getInt(n))
          inc n
        while n.hasMore: skip n
      if base.kind == okMem:
        # `(mem <stack slot> K)` — the slot's own displacement PLUS K, both in
        # the same instruction's 6-bit field. The slot's part is nifasm's own
        # number; K is the code generator's, and the high half of a 16-bit value
        # is exactly `K = 1`. Nothing is synthesized: it is still one `ldd`.
        result.kind = okMem
        result.mem = base.mem
        result.mem.disp += extra
        if result.mem.kind == amPtr and result.mem.p == avr.PX and result.mem.disp != 0:
          error("AVR: X has no displaced form; only Y and Z take `+q`", n)
        elif result.mem.kind == amPtr and
             (result.mem.disp < 0 or result.mem.disp > MaxDisp):
          error("AVR: the displacement " & $result.mem.disp & " is outside 0..63 — " &
                "this proc's frame is too large (see M5 in doc/internals/avr.md)", n)
        result.typ = base.typ
      elif base.kind in {okReg, okArg} and base.isPair:
        result.kind = okMem
        result.mem = AvrMem(kind: amPtr, p: ptrRegOf(base.pair, n), disp: extra)
        if result.mem.p == avr.PX and extra != 0:
          error("AVR: X has no displaced form; only Y and Z take `+q`", n)
        elif extra < 0 or extra > MaxDisp:
          error("AVR: the displacement " & $extra & " is outside 0..63", n)
        result.typ = avrRegType()
      else:
        error("AVR: (mem ...) needs a pointer PAIR — X (`rp26`), Y (`rp28`) or " &
              "Z (`rp30`) — or a stack slot", n)
    elif t == LoTagId or t == HiTagId:
      # `(lo x)` / `(hi x)` — one half of a value that lives in a pair. This is
      # how a 16-bit add is written: `(add (lo d) (lo s))` then
      # `(adc (hi d) (hi s))`. Spelling the halves as raw registers instead would
      # be rejected by the binding table, and rightly — it could not tell that
      # `(r25)` was the top of some local.
      let wantHigh = t == HiTagId
      var inner: OperandAvr
      into n:
        inner = parseOperandAvr(n, ctx)
        while n.hasMore: skip n
      if inner.kind notin {okReg, okArg} or not inner.isPair:
        error("AVR: `(lo …)`/`(hi …)` needs a value that lives in a register " &
              "pair; this one does not", n)
      result.kind = inner.kind
      result.isPair = false
      result.reg = if wantHigh: highOf(inner.pair) else: lowOf(inner.pair)
      result.typ = avrRegType()
      result.argName = inner.argName
    elif t == DotTagId:
      # `(dot <base> <field>)` — the field's offset folded onto the base address,
      # resolved HERE because nifasm is what knows the layout. arkham names the
      # field and never computes an offset for it.
      var baseOp: OperandAvr
      var fieldName: string
      into n:
        baseOp = parseOperandAvr(n, ctx)
        if n.kind != Symbol: error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n
        while n.hasMore: skip n
      var objType: Type
      var baseMem: AvrMem
      if baseOp.typ != nil and baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType == nil or objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("AVR: `(dot …)` on a pointer to a non-object type", n)
        if baseOp.kind == okMem: baseMem = baseOp.mem
        else:
          baseMem = AvrMem(kind: amPtr, p: ptrRegOf(baseOp.pair, n), disp: 0)
      elif baseOp.kind == okMem and baseOp.typ != nil and
           baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ; baseMem = baseOp.mem
      elif baseOp.kind == okMem and baseOp.typ != nil and
           baseOp.typ.kind == TypeKind.StackOffT and
           baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ.offType; baseMem = baseOp.mem
      else:
        error("AVR: `(dot …)` needs a pointer to an object or a stack object", n)
      var fieldOffset = -1
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype; fieldOffset = foff; break
      if fieldType == nil:
        error("Field '" & fieldName & "' not found", n)
      result.kind = okMem
      result.mem = baseMem
      result.mem.disp += fieldOffset
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
      if result.mem.kind == amPtr and result.mem.p == avr.PX and result.mem.disp != 0:
        error("AVR: X has no displaced form, so a field cannot be reached " &
              "through it; use Z", n)
      elif result.mem.kind == amPtr and
           (result.mem.disp < 0 or result.mem.disp > MaxDisp):
        error("AVR: the field offset " & $result.mem.disp & " is past the 63-byte " &
              "displacement range of `ldd`/`std`", n)
    elif t == AtTagId:
      # A CONSTANT index folds; a computed one does not, because this machine has
      # no scaled address mode — arkham adds that itself and hands over a `(mem …)`.
      var baseOp: OperandAvr
      var idxOp: OperandAvr
      into n:
        baseOp = parseOperandAvr(n, ctx)
        idxOp = parseOperandAvr(n, ctx)
        while n.hasMore: skip n
      if idxOp.kind != okImm:
        error("AVR: `(at …)` folds only a CONSTANT index — there is no scaled " &
              "address mode here, so a computed one is arkham's to add", n)
      var elemType: Type = nil
      var baseMem: AvrMem
      if baseOp.kind == okMem and baseOp.typ != nil and
         baseOp.typ.kind == TypeKind.StackOffT and
         baseOp.typ.offType.kind == TypeKind.ArrayT:
        elemType = baseOp.typ.offType.elem; baseMem = baseOp.mem
      elif baseOp.kind == okMem and baseOp.typ != nil and
           baseOp.typ.kind == TypeKind.ArrayT:
        elemType = baseOp.typ.elem; baseMem = baseOp.mem
      elif baseOp.typ != nil and baseOp.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
        # A NESTED `(at …)`: the inner fold typed itself `ptr <row>`, and
        # indexing that again indexes WITHIN the row — so the stride is the
        # row's element, not the row. Reading it as the row strides by the whole
        # inner array and lands on the wrong element of the wrong one.
        let bt = resolvedBase(baseOp.typ, ctx, n)
        elemType = (if bt != nil and bt.kind == TypeKind.ArrayT: bt.elem else: bt)
        if baseOp.kind == okMem: baseMem = baseOp.mem
        else: baseMem = AvrMem(kind: amPtr, p: ptrRegOf(baseOp.pair, n), disp: 0)
      else:
        error("AVR: `(at …)` needs an array or a pointer", n)
      result.kind = okMem
      result.mem = baseMem
      result.mem.disp += int(idxOp.immVal) * asmSizeOf(elemType)
      result.typ = Type(kind: TypeKind.PtrT, base: elemType)
      if result.mem.kind == amPtr and
         (result.mem.disp < 0 or result.mem.disp > MaxDisp):
        error("AVR: the element offset " & $result.mem.disp & " is past the " &
              "63-byte displacement range", n)
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandAvr(n, ctx)
      op.typ = castType
      result = op
      return
    else:
      error("Unsupported AVR operand", n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 16, litVal: result.immVal)
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
        if rawTagIsAvrPair(sym.reg):
          result.isPair = true
          result.pair = tagToPairAvr(sym.reg, n)
          result.reg = lowOf(result.pair)
        else:
          result.reg = tagToRegisterAvr(sym.reg, n)
        result.typ = sym.typ
        if result.reg in ctx.clobberedAvr:
          error("Variable '" & name & "' lives in " & regName(result.reg) &
                ", which a call clobbered; its value is gone", n)
      else:
        error("Variable has no location: " & name, n)
      inc n
    of skLabel:
      result.kind = okLabel
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: TypeKind.UIntT, bits: 16)
      inc n
    of skRodata, skProc:
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.isCode = sym.kind == skProc
      result.typ = Type(kind: TypeKind.UIntT, bits: 16)
      inc n
    of skGvar:
      error("AVR: globals are not implemented yet: '" & name &
            "' (see M6 in doc/internals/avr.md)", n)
    of skTvar:
      error("AVR has no thread-local storage: '" & name & "'", n)
    else:
      error("Cannot use symbol '" & name & "' as an operand", n)
  else:
    error("Expected operand", n)

proc parseDestAvr*(n: var Cursor; ctx: var GenContext): OperandAvr =
  ## A destination differs from a source in exactly one way: writing a register
  ## that hosts a named local is legal when the write is what `rebind` recorded,
  ## so the bound-register check does not apply. Everything else is shared.
  if n.kind == TagLit and rawTagIsAvrPair(n.tag):
    result.kind = okReg
    result.isPair = true
    result.pair = parsePairAvr(n)
    result.reg = lowOf(result.pair)
    result.typ = avrPairType()
    return
  if n.kind == TagLit and rawTagIsAvrGpr(n.tag):
    result.kind = okReg
    result.reg = parseRegisterAvr(n)
    result.typ = avrRegType()
    return
  result = parseOperandAvr(n, ctx)

proc condOfFlagAvr*(flag: X64Flag; n: Cursor): avr.Condition =
  ## The AVR condition a `(zf)`/`(nz)`/… flag tag selects. asm-NIF spells
  ## conditions with the x86 flag vocabulary on every target, and AVR's status
  ## register happens to hold the same four bits under the same names.
  ##
  ## What it does NOT hold is a combined "less than" — every branch here tests
  ## ONE bit. Signed `<` is the S flag (`brlt`), unsigned `<` is the carry
  ## (`brlo`), and those are different tags, so nothing about this mapping has to
  ## guess which comparison produced the flags.
  case flag
  of ZfO: avr.CondEq
  of NzO: avr.CondNe
  of CfO: avr.CondLo     ## carry set: unsigned <
  of NcO: avr.CondSh     ## carry clear: unsigned >=
  of SfO: avr.CondMi
  of NsO: avr.CondPl
  of OfO: avr.CondVs
  of NoO: avr.CondVc
  else:
    error("AVR: unsupported flag condition " & $flag & " — this machine has no " &
          "parity flag, and every branch tests exactly one status bit", n)
    avr.CondEq
