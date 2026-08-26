#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Cortex-M (ARMv7E-M / Thumb-2) OPERANDS: what an asm-NIF operand node means
## here, and how a value moves between one and a register.
##
##
## The counterpart of `genInstA64`, against `thumb2.nim`'s encoders. Two things
## differ from the AArch64 half and drive most of the shape below:
##
##  * the word is 4 bytes, so a "register" is 32 bits and `RegisterT` is declared
##    at 32 — a `(i 64)` local genuinely does not fit one and is rejected by name
##    rather than silently truncated (see M4 in doc/cortex_m.md);
##  * Cortex-M reuses the `(r0)`..`(r12)`/`(sp)`/`(lr)` spellings that already
##    exist for the other targets, so `rawTagIsMReg` — not the x86 or a64
##    classifier — is what decides whether a tag is a register HERE.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, decls, stackslots, relocs, buffers]
import encoder as thumb2
import regs

type
  OperandM* = object
    kind*: OperandKind
    reg*: thumb2.Register
    freg*: thumb2.FloatRegister   ## the s-register, when `isFloat`
    isFloat*: bool                ## the operand names an FPv4-SP register
    typ*: Type
    immVal*: int64
    mem*: thumb2.MemoryOperand
    argName*: SymId
    label*: LabelId
    isCode*: bool          ## the label names CODE (a proc), not data. Its address
                          ## must carry the Thumb bit — see `rkTMovwMovtFunc`.
    gvarSym*: Symbol       ## non-nil if the operand is a global's (.bss) address
    mimg*: MimgKind        ## for an `okMimg` operand: WHICH layout number it is


proc mRegType(): Type {.inline.} =
  ## The "any type that fits a register" type, at the Cortex-M width. 32, not 64:
  ## `compatible` uses `regBits div 8` as the size bound, so declaring 64 here
  ## would let a `(i 64)` value bind to a 32-bit register unnoticed.
  Type(kind: RegisterT, regBits: 32)

proc checkRegWidthM*(t: Type; what: string; n: Cursor) =
  ## Reject a value too wide for one Thumb register BY NAME. 64-bit scalars are
  ## the expected case here and they are not an error in the input — they are a
  ## backend feature that does not exist yet (M4: register pairs, adds/adcs).
  ## Truncating them silently is the one outcome that must not happen.
  if t == nil: return
  if t.kind == TypeKind.FloatT:
    # A DOUBLE is not a missing feature, it is missing hardware: Cortex-M4F's
    # FPv4-SP is single precision only, and there is no `.f64` instruction to
    # lower to. Refusing beats dragging in a softfloat library nobody asked for.
    if t.bits > 32:
      error("Cortex-M: " & what & " is a " & $t.bits & "-bit float; this core's " &
            "FPv4-SP unit is SINGLE precision only (see M5 in doc/cortex_m.md)", n)
    return
  if t.kind in {TypeKind.IntT, TypeKind.UIntT} and t.bits > 32:
    error("Cortex-M: " & what & " is " & $t.bits & " bits; a 64-bit scalar lives " &
          "in memory here and cannot be bound to a register (see M4 in " &
          "doc/cortex_m.md)", n)

proc argWordTypeM(p: ptr Param): Type =
  ## The type of ONE argument register of `p`. An aggregate spread over several
  ## registers has no per-word Leng type, and neither does a 64-bit scalar split
  ## across a register PAIR — each half is a machine word. Reporting the param's
  ## own `(i 64)` for such a half is what would make `(mov (arg x 0) …)` look
  ## like a 64-bit register move to `checkRegWidthM`.
  if p.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT} or
     p.regs.len > 1:
    mRegType()
  else: p.typ

proc parseOperandM*(n: var Cursor; ctx: var GenContext): OperandM =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsMFloatReg(t):
      result.isFloat = true
      result.freg = parseFloatRegisterM(n)
      result.typ = Type(kind: TypeKind.FloatT, bits: 32)
      if result.freg in ctx.mFRegBindings:
        error("Register " & $result.freg & " is bound to variable '" &
              ctx.mFRegBindings[result.freg] & "', use the variable name instead", n)
    elif rawTagIsMGpr(t):
      result.reg = parseRegisterM(n)
      result.typ = mRegType()
      # A raw use of a register that currently hosts a named local is a code
      # generator bug — it silently clobbers the value. Spell the name instead.
      if result.reg in ctx.mRegBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.mRegBindings[result.reg] & "', use the variable name instead", n)
    elif t == NilTagId:
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == ArgTagId:
      # `(arg name [k])` — an outgoing argument. In a REGISTER it names that
      # register; on the STACK it yields the byte OFFSET within the outgoing
      # argument area, for use inside `(mem (sp) (arg name))`.
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      var argName = SymId(0)
      var wordIdx = 0
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n
      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), n)
      if paramPtr.typ.isOnStack:
        var offset = ctx.callContext.stackArgBase
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName: break
            offset += stackslots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset + wordIdx * asmWordSize())
        result.typ = paramPtr.typ
      else:
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), n)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegisterM(paramPtr.regs[wordIdx], n)
        result.typ = argWordTypeM(paramPtr)
    elif t == ResTagId:
      # `(res name)` — a call's result, readable only after the call.
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil: error("Unknown result: " & ctx.nameOf(resName), n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), n)
      ctx.callContext.resultsSet.incl(resName)
      result.reg = tagToRegisterM(resPtr.reg, n)
      result.typ = resPtr.typ
    elif t == CsizeTagId:
      # `(csize)` — the outgoing stack-argument area of the CURRENT call. The
      # fixed-frame model reserves that area once in the prologue, so nothing
      # adjusts SP per call and this is only ever read as a size.
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okImm
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32, litVal: result.immVal)
      into n:
        while n.hasMore: skip n
    elif t == SsizeTagId:
      # `(ssize)` / `(ssize N)` — the frame size, patched once the frame is known.
      result.kind = okSsize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32)
      into n:
        if n.hasMore and n.kind == IntLit:
          result.immVal = getInt(n)
          inc n
    elif t in {DataloadTagId, DatavmaTagId, DatasizeTagId, BsssizeTagId,
               HeapstartTagId, HeapsizeTagId, NoinitstartTagId, NoinitsizeTagId}:
      # The image-layout numbers: the four the startup code copies and zeroes
      # with, and the regions the layout reserved. Same contract as `(ssize)`: a
      # value only the final layout knows, so what is emitted here is a
      # placeholder of FIXED width and a recorded site.
      result.kind = okMimg
      result.mimg =
        if t == DataloadTagId: mikDataLoad
        elif t == DatavmaTagId: mikDataVma
        elif t == DatasizeTagId: mikDataSize
        elif t == BsssizeTagId: mikBssSize
        elif t == HeapstartTagId: mikHeapStart
        elif t == HeapsizeTagId: mikHeapSize
        elif t == NoinitstartTagId: mikNoinitStart
        else: mikNoinitSize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32)
      inc n
    elif t == CastTagId:
      # `(cast T <operand>)` — a RETYPE, no instruction. Reinterpreting a register
      # as `(aptr T)` is how the code generator reaches an array through a pointer,
      # so this arm is what makes `(at (cast (aptr T) reg) idx)` resolve at all.
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandM(n, ctx)
      op.typ = castType
      result = op
      return
    elif t == DotTagId:
      # `(dot <base> <field>)` — fold the field's offset onto the base address.
      # The result is typed `PtrT(fieldType)`: an embedded sub-object sits AT
      # base+offset rather than behind a loaded pointer, which is what lets
      # `(dot (dot o inner) a)` keep accumulating instead of dereferencing.
      inc n
      let baseOp = parseOperandM(n, ctx)
      if n.kind != Symbol: error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      var objType: Type
      var baseReg = thumb2.R0
      var baseOffset: int32 = 0
      var baseIndex = thumb2.R0
      var baseShift = 0
      var baseHasIndex = false
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        if baseOp.kind == okMem:
          # A NESTED access: fold onto the inner base+offset(+index) rather than
          # treating the inner base register as the pointer, which would lose the
          # inner displacement.
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
          baseIndex = baseOp.mem.index
          baseShift = baseOp.mem.shift
          baseHasIndex = baseOp.mem.hasIndex
        else:
          baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
           baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ.offType
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("dot requires pointer to object/union or stack object/union, got " &
              $baseOp.typ, n)
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      result.kind = okMem
      result.mem = thumb2.MemoryOperand(base: baseReg,
                                        offset: baseOffset + int32(fieldOffset),
                                        hasIndex: baseHasIndex, index: baseIndex,
                                        shift: baseShift)
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
    elif t == AtTagId:
      # `(at <base> <index>)` folds to a scaled-index LDR/STR operand, or
      # `(at <base> <index> <scratch>)` when the element stride is not one of the
      # four LDR scales — then the caller supplies a register and WE compute
      # `base + index*stride` into it.
      into n:
        let baseOp = parseOperandM(n, ctx)
        let indexOp = parseOperandM(n, ctx)
        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)
        var elemType: Type
        var baseReg = thumb2.R0
        var baseOffset: int32 = 0
        var baseHasIndex = false
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.typ.kind == TypeKind.PtrT and
             resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
          elemType = resolvedBase(baseOp.typ, ctx, n).elem
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseOffset = baseOp.mem.offset
            baseHasIndex = baseOp.mem.hasIndex
          else:
            baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.offType.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        else:
          error("at requires aptr, pointer-to-array, or stack array, got " &
                $baseOp.typ, n)
        let stride = asmSizeOf(elemType)

        var scratchReg = thumb2.R0
        var hasScratch = false
        if n.hasMore:
          let scratchOp = parseOperandM(n, ctx)
          if scratchOp.kind notin {okReg, okArg}:
            error("at: 3-operand scratch must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          if indexOp.kind notin {okReg, okArg}:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # `scratch == base` is fatal: the multiply writes scratch (== base)
          # before the add reads the base, so the base is gone and the address is
          # wild. `scratch == index` is fine — the stride goes through IP, so the
          # index survives the multiply.
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          if stride > 0 and (stride and (stride - 1)) == 0:
            # A power-of-two stride is a SHIFT: no constant, no multiply.
            var k = 0
            var t2 = stride
            while t2 > 1: (t2 = t2 shr 1; inc k)
            if k == 0: thumb2.emitMovReg(ctx.buf.data, scratchReg, indexOp.reg)
            else: thumb2.emitLslImm(ctx.buf.data, scratchReg, indexOp.reg, k)
          else:
            # The stride constant goes into IP, never into `scratchReg`: the caller
            # may hand a scratch that ALIASES the index, and materializing the
            # stride there would destroy the index before the multiply.
            thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(stride))
            thumb2.emitMul(ctx.buf.data, scratchReg, indexOp.reg, thumb2.IP)
          thumb2.emitAdd3(ctx.buf.data, scratchReg, baseReg, scratchReg)
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(base: scratchReg, offset: baseOffset)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        elif indexOp.kind == okImm:
          # A constant index folds straight into the displacement.
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(
            base: baseReg,
            offset: baseOffset + int32(indexOp.immVal * stride),
            hasIndex: baseHasIndex, index: thumb2.R0, shift: 0)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        else:
          if baseHasIndex:
            error("at: base already carries an index; use the 3-operand form", n)
          if stride notin [1, 2, 4, 8]:
            error("at: element stride " & $stride & " is not an LDR/STR scale; " &
                  "use the 3-operand form with a scratch register", n)
          var shift = 0
          var t2 = stride
          while t2 > 1: (t2 = t2 shr 1; inc shift)
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(base: baseReg, offset: baseOffset,
                                            hasIndex: true, index: indexOp.reg,
                                            shift: shift)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n
      return
    elif t == MemTagId:
      # `(mem <base> [offset | field-symbol | (arg name)])`, or `(mem <lvalue>)`
      # where the lvalue is a `(dot …)`/`(at …)` that already folded to an address.
      #
      # `into` BOUNDS the cursor to this node's children — without it the
      # optional-offset check reads into the following sibling, and a
      # register-bound name after a `(mem base)` store destination gets eaten as
      # if it were an offset. Same reasoning as the a64 and x64 handlers.
      #
      # Nothing inside the `into` may `return`: it is a template whose scope-exit
      # bookkeeping a `return` jumps straight past, leaving the cursor inside a
      # scope it has left. That surfaces later as nifcore's "advancing past end
      # of scope", nowhere near the cause.
      into n:
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          # The fold already produced the address and typed it `PtrT(elem)`;
          # dereferencing is just unwrapping that pointer to the value's type.
          let addrOp = parseOperandM(n, ctx)
          if addrOp.kind != okMem: error("mem requires an address expression", n)
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)
          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)
        else:
          let baseTok = n                    # peeked for the slot diagnostics
          let base = parseOperandM(n, ctx)
          if base.kind == okMem:
            # A stack variable used as a base: its slot IS the address.
            result.mem = base.mem
          elif base.kind notin {okReg, okArg}:
            error("(mem ...) base must be a register", n)
          else:
            result.mem = thumb2.MemoryOperand(base: base.reg, offset: 0)
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # `(mem (sp) (arg name))` — the slot of an OUTGOING stack argument.
            let argOff = parseOperandM(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            result.mem.offset += int32(argOff.immVal)
          elif n.hasMore and n.kind == IntLit:
            let extra = getInt(n)
            if base.kind == okMem and base.typ != nil and
               base.typ.kind == TypeKind.StackOffT:
              # `(mem name off)` — a raw byte offset WITHIN the named slot. Bounds-
              # checked against it, the one safety a `(cast (aptr T) <reg>)` access
              # can never have. A register base gets no check: there is no object to
              # check against.
              let slotSize = asmSizeOf(base.typ)
              if extra < 0 or extra >= slotSize:
                error("offset " & $extra & " is outside stack slot '" &
                      (if baseTok.kind == Symbol: getSym(baseTok) else: "?") &
                      "' (" & $slotSize & " bytes)", n)
            result.mem.offset += int32(extra)
            inc n
          elif n.hasMore and n.kind == Symbol:
            # A stack PARAMETER's name: its offset in the incoming argument area.
            let fname = getSym(n)
            let fsym = lookupWithAutoImport(ctx, ctx.scope, fname, n)
            if fsym == nil: error("Unknown symbol in (mem ...): " & fname, n)
            result.mem.offset += int32(fsym.offset)
            inc n
          result.kind = okMem
          result.typ =
            if base.kind == okMem and base.typ != nil and
               base.typ.kind == TypeKind.StackOffT:
              base.typ.offType
            elif base.typ != nil and base.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
              resolvedBase(base.typ, ctx, n)
            else: mRegType()
        while n.hasMore: skip n
      return
    else:
      error("Unsupported Cortex-M operand", n)
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
        result.mem = thumb2.MemoryOperand(base: thumb2.SP, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsMFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterM(sym.reg, n)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterM(sym.reg, n)
        result.typ = sym.typ
        if result.reg in ctx.clobberedM:
          error("Variable '" & name & "' lives in " & $result.reg &
                ", which a call clobbered; its value is gone", n)
      else:
        error("Variable has no location: " & name, n)
      inc n
    of skLabel:
      result.reg = thumb2.R0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skRodata, skProc:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.isCode = sym.kind == skProc
      result.reg = thumb2.R0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skGvar:
      result.gvarSym = sym
      result.reg = thumb2.R0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skTvar:
      error("Cortex-M has no thread-local storage: '" & name & "'", n)
    else:
      error("Cannot use symbol '" & name & "' as an operand", n)
  else:
    error("Expected operand", n)

proc parseDestM*(n: var Cursor; ctx: var GenContext): OperandM =
  if n.kind == TagLit and rawTagIsMFloatReg(n.tag):
    result.isFloat = true
    result.freg = parseFloatRegisterM(n)
    result.typ = Type(kind: TypeKind.FloatT, bits: 32)
    if result.freg in ctx.mFRegBindings:
      error("Register " & $result.freg & " is bound to variable '" &
            ctx.mFRegBindings[result.freg] & "', use the variable name instead", n)
  elif n.kind == TagLit and rawTagIsMGpr(n.tag):
    result.reg = parseRegisterM(n)
    result.typ = mRegType()
    if result.reg in ctx.mRegBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.mRegBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # Binding a REGISTER argument inside a prepare block. Unlike an ordinary
    # register destination this deliberately skips the `mRegBindings` check: the
    # argument register is exactly where the value must go, and the call is about
    # to clobber it anyway.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0
    into n:
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      argName = getSymId(n)
      inc n
      if n.hasMore and n.kind == IntLit:
        wordIdx = int(getInt(n))
        inc n
    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil: error("Unknown argument: " & ctx.nameOf(argName), n)
    if paramPtr.typ.isOnStack:
      error("Stack argument '" & ctx.nameOf(argName) &
            "' cannot be a direct destination; use (mem (sp) (arg " &
            ctx.nameOf(argName) & "))", n)
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegisterM(paramPtr.regs[wordIdx], n)
    result.typ = argWordTypeM(paramPtr)
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == CastTagId):
    # `(cast T (mem …))` as a DESTINATION retypes — and thereby sizes — the
    # store, exactly as it does on the read side. This is how a 64-bit value's
    # two halves are addressed: the slot is `(i 64)`, each half is a
    # `(cast (u 32) (mem slot 0|4))`, and the cast is what says so rather than a
    # silent truncation of a 64-bit typed access down to one word.
    let op = parseOperandM(n, ctx)
    if op.kind != okMem: error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown symbol: " & name, n)
    if sym.kind in {skVar, skParam}:
      if sym.typ.isOnStack:
        result.kind = okMem
        result.mem = thumb2.MemoryOperand(base: thumb2.SP, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsMFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterM(sym.reg, n)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterM(sym.reg, n)
        result.typ = sym.typ
        ctx.clobberedM.excl(result.reg)   # writing a fresh value un-clobbers it
      else:
        error("Variable has no location: " & name, n)
      inc n
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc regOfM*(op: OperandM; what: string; n: Cursor): thumb2.Register =
  ## `okArg` counts: an argument bound to a register IS that register, it just
  ## carries the extra bookkeeping that the prepare block checks.
  if op.kind notin {okReg, okArg}: error(what & " must be a register", n)
  op.reg

proc condOfFlagM*(flag: X64Flag; n: Cursor): thumb2.Condition =
  ## The Thumb condition a `(zf)`/`(nz)`/… flag tag selects. asm-NIF spells
  ## conditions with the x86 flag vocabulary on every target (AArch64 does the
  ## same); ARM's flags are N/Z/C/V, and the mapping is exact for the four.
  case flag
  of ZfO: thumb2.CondEQ
  of NzO: thumb2.CondNE
  of CfO: thumb2.CondHS      # C set == unsigned higher-or-same
  of NcO: thumb2.CondLO
  of SfO: thumb2.CondMI      # N set == negative
  of NsO: thumb2.CondPL
  of OfO: thumb2.CondVS
  of NoO: thumb2.CondVC
  else:
    error("Cortex-M: unsupported flag condition " & $flag, n)
    thumb2.CondEQ

proc emitBranchM*(ctx: var GenContext; cond: thumb2.Condition; target: LabelId) =
  if cond == thumb2.CondAL: thumb2.emitB(ctx.buf, target)
  else: thumb2.emitBcond(ctx.buf, cond, target)

proc memWidthM(t: Type): tuple[width: thumb2.MemWidth; signed: bool] =
  ## The ACCESS WIDTH a typed memory operand implies, and whether a load of it
  ## sign-extends. A `(mem …)` carries the pointee / field / slot type, so a
  ## narrow integer must load with `ldrb`/`ldrh` (sign- or zero-extending) and
  ## store only its low bits.
  ##
  ## Without this every access was a full 32-bit `ldr`: reading one byte of a
  ## `(u 8)` array returned that byte AND the three after it, which is not a
  ## crash and not a type error — just a wrong value, and only for programs that
  ## happen to look at sub-word data.
  ##
  ## A stack slot is its content type behind a `(stackoff …)` wrapper; unwrap it
  ## and size by what the slot HOLDS, exactly as `memWidthOpc` does for AArch64.
  var ty = t
  if ty != nil and ty.kind == TypeKind.StackOffT: ty = ty.offType
  if ty == nil: return (thumb2.MemWord, false)
  case ty.kind
  of TypeKind.BoolT: (thumb2.MemByte, false)
  of TypeKind.IntT:
    if ty.bits == 8: (thumb2.MemByte, true)
    elif ty.bits == 16: (thumb2.MemHalf, true)
    else: (thumb2.MemWord, false)
  of TypeKind.UIntT:
    if ty.bits == 8: (thumb2.MemByte, false)
    elif ty.bits == 16: (thumb2.MemHalf, false)
    else: (thumb2.MemWord, false)
  else: (thumb2.MemWord, false)     # pointer, aggregate, register-typed: a word

proc emitMemAccessM*(ctx: var GenContext; rt: thumb2.Register;
                    mem: thumb2.MemoryOperand; width: thumb2.MemWidth;
                    isLoad: bool; signed = false; n: Cursor) =
  ## THE one place a `(mem …)` operand becomes a load or a store, so the scaled
  ## index that `(at …)` folds in cannot be silently dropped by a caller that
  ## only looked at base+offset.
  ##
  ## Thumb-2's register-index form carries no displacement, so a memory operand
  ## with BOTH an index and a non-zero offset is materialized into IP first. IP is
  ## the AAPCS32 scratch and hosts no value, so this needs no spill.
  if not mem.hasIndex:
    if thumb2.fitsLoadStoreImm(mem.offset):
      thumb2.emitLoadStoreImm(ctx.buf.data, rt, mem.base, mem.offset, width,
                              isLoad = isLoad, signed = signed)
      return
    # Past the 12-bit displacement — a frame bigger than 4 KB. The address is
    # computed into IP, the AAPCS32 scratch that hosts no value. Unless IP is
    # already the value being moved, which is the one case with no register left
    # and therefore an error rather than a wrong address.
    if rt == thumb2.IP:
      error("Cortex-M: a " & $mem.offset & "-byte displacement needs the IP " &
            "scratch to compute, and IP already holds the value being moved", n)
    thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(mem.offset))
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
    thumb2.emitLoadStoreImm(ctx.buf.data, rt, thumb2.IP, 0, width,
                            isLoad = isLoad, signed = signed)
  elif mem.offset == 0:
    thumb2.emitLoadStoreReg(ctx.buf.data, rt, mem.base, mem.index, width,
                            isLoad = isLoad, shift = mem.shift, signed = signed)
  else:
    if rt == thumb2.IP:
      error("Cortex-M: indexed access with a displacement cannot target IP", n)
    thumb2.emitAddImm(ctx.buf.data, thumb2.IP, mem.base, uint32(mem.offset))
    thumb2.emitLoadStoreReg(ctx.buf.data, rt, thumb2.IP, mem.index, width,
                            isLoad = isLoad, shift = mem.shift, signed = signed)

const MFpScratch* = thumb2.S30
  ## The FPv4-SP counterpart of IP: a float register the SELECTOR may always use
  ## as a transient. `vcvt` between an integer and a float goes through the FPU,
  ## so `(fcvtzs <gpr> <sreg>)` needs somewhere to put the converted value before
  ## moving it across — and the source may still be live. arkham keeps s30 out of
  ## every pool for this, exactly as it keeps r12 out for IP.

proc emitVfpMemAccessM*(ctx: var GenContext; sd: thumb2.FloatRegister;
                       mem: thumb2.MemoryOperand; isLoad: bool; n: Cursor) =
  ## THE one place a `(mem …)` becomes a VLDR/VSTR, so a folded scaled index
  ## cannot be silently dropped. VLDR has no register-index form at all, so an
  ## indexed operand is materialized into IP first — the AAPCS32 scratch, which
  ## hosts no value.
  if not mem.hasIndex:
    if thumb2.fitsVldrVstrImm(mem.offset):
      thumb2.emitVldrVstr(ctx.buf.data, sd, mem.base, mem.offset, isLoad)
    else:
      # VLDR reaches only +/-1020, so this happens far sooner than it does for an
      # integer access. IP is always free here: the value is in a FLOAT register.
      thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(mem.offset))
      thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
      thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, 0, isLoad)
    return
  if mem.shift == 0:
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, mem.index)
  else:
    thumb2.emitLslImm(ctx.buf.data, thumb2.IP, mem.index, mem.shift)
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
  if not thumb2.fitsVldrVstrImm(mem.offset):
    thumb2.emitAddImm(ctx.buf.data, thumb2.IP, thumb2.IP, uint32(mem.offset))
    thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, 0, isLoad)
    return
  thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, mem.offset, isLoad)

proc loadToRegM*(ctx: var GenContext; dest: thumb2.Register; op: OperandM; n: Cursor) =
  ## Materialize `op` into `dest`. The one place that decides how each operand
  ## KIND reaches a register, so no arm has to repeat it.
  case op.kind
  of okReg, okArg:
    if op.reg != dest: thumb2.emitMovReg(ctx.buf.data, dest, op.reg)
  of okImm:
    thumb2.emitMovImm32(ctx.buf.data, dest, uint32(op.immVal))
  of okSsize:
    # The frame size is not known until the whole proc has been read, so emit a
    # MOVW/MOVT pair with a zero immediate and record the site. The pair is a
    # FIXED 8 bytes whatever the final value, so patching never has to resize an
    # instruction — which is what lets this work at all, since every label
    # position downstream is already fixed by then.
    ctx.ssizePatches.add((ctx.buf.data.len, int(op.immVal)))
    thumb2.emitMovImm16(ctx.buf.data, dest, 0)
    thumb2.emitMovt(ctx.buf.data, dest, 0)
  of okMimg:
    # An image-layout number, for the same reason and by the same means: the
    # value is decided by `writeCortexMImage`, and the MOVW/MOVT pair reserves a
    # fixed 8 bytes so patching never moves a label.
    ctx.mimgSites.add((ctx.buf.data.len, op.mimg))
    thumb2.emitMovImm16(ctx.buf.data, dest, 0)
    thumb2.emitMovt(ctx.buf.data, dest, 0)
  of okMem:
    let (w, sx) = memWidthM(op.typ)
    ctx.emitMemAccessM(dest, op.mem, w, isLoad = true, signed = sx, n = n)
  of okLabel:
    thumb2.emitMovwMovtAbs(ctx.buf, dest, op.label)
  else:
    error("Cortex-M: operand cannot be loaded into a register", n)

proc storeFromRegM*(ctx: var GenContext; src: thumb2.Register; dst: OperandM; n: Cursor) =
  if dst.kind != okMem: error("Cortex-M: expected a memory destination", n)
  # Sized by the DESTINATION's type: a narrow store must write only its low
  # bytes, or it takes the neighbouring fields with it.
  let (w, _) = memWidthM(dst.typ)
  ctx.emitMemAccessM(src, dst.mem, w, isLoad = false, n = n)

proc scratchM*(ctx: GenContext; avoid: varargs[thumb2.Register]): thumb2.Register =
  ## A register the selector may use as a transient. r12 (IP) is reserved for
  ## exactly this by AAPCS32 — it is call-clobbered and no local is ever bound to
  ## it — so a bridge never has to spill anything. Falls back to lr only if the
  ## caller is already using IP for one of the operands.
  result = thumb2.IP
  for a in avoid:
    if a == result: result = thumb2.LR
  discard ctx
