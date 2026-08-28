#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The RV32 operand model: what an asm-NIF operand IS, and how each kind reaches
## a register or a memory access.
##
## Deliberately parallel to `thumb/operands.nim` — the two should read as a diff,
## because the type-driven address folding (`(dot …)`, `(at …)`, `(mem …)`) is
## the same computation on both and any divergence there is a bug in one of them.
## Two things genuinely differ:
##
##  * **There is one addressing mode: `base + imm12`.** No index register, no
##    scale. So where Thumb folds `(at base idx)` into a scaled register-index
##    operand, RV32 has to COMPUTE `base + idx*stride + offset` into a register
##    first. That register is `RvScratch` (`x31`), which no asm-NIF tag can name,
##    so nothing has to prove it is free. The displacement is folded into the same
##    add rather than left on the operand, which is what keeps a second scratch
##    from ever being needed.
##  * **The displacement is ±2048, not 4095**, and it is SIGNED — so a negative
##    offset needs no separate form, and a frame beyond 2 KB needs a materialized
##    address sooner than on Thumb.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, decls, stackslots, relocs, buffers]
import encoder as rv
import regs

type
  MemoryOperandRv* = object
    ## A resolved `base + offset` address. The whole addressing vocabulary of the
    ## ISA — there is nothing else to represent, which is why this is three fields
    ## and not Thumb's six.
    base*: rv.Register
    offset*: int32

  MemWidthRv* = enum
    MemByte, MemHalf, MemWord

  OperandRv* = object
    kind*: OperandKind
    reg*: rv.Register
    freg*: rv.FloatRegister
    isFloat*: bool             ## the operand names an FP register
    fw*: rv.FpWidth            ## its precision — `(dN)` double, `(sN)` single
    typ*: Type
    immVal*: int64
    mem*: MemoryOperandRv
    argName*: SymId
    label*: LabelId
    isCode*: bool              ## the label names CODE (a proc), not data. Unlike
                               ## Thumb there is no state bit to OR in: a RISC-V
                               ## code address is an ordinary even address.
    gvarSym*: Symbol           ## non-nil if the operand is a global's (.bss) address
    mimg*: MimgKind            ## for an `okMimg` operand: WHICH layout number it is

proc rvRegType(): Type {.inline.} =
  ## The "any type that fits a register" type at the RV32 width. 32, not 64:
  ## `compatible` bounds by `regBits div 8`, so declaring 64 would let a `(i 64)`
  ## bind to a 32-bit register unnoticed.
  Type(kind: RegisterT, regBits: 32)

proc checkRegWidthRv*(t: Type; what: string; n: Cursor) =
  ## A register holds at most a word. On a 32-bit target that rules out `(i 64)`,
  ## which arkham lowers into register PAIRS rather than expecting one register to
  ## hold it — so a 64-bit value arriving here is a code-generator bug, not a
  ## program error, and saying which is the point of the message.
  if t == nil: return
  case t.kind
  of TypeKind.IntT, TypeKind.UIntT, TypeKind.FloatT:
    if t.bits > 32:
      error("RV32: " & what & " is " & $t.bits & " bits; a register holds 32 " &
            "(a 64-bit value must be split across two)", n)
  of TypeKind.ObjectT, TypeKind.UnionT, TypeKind.ArrayT:
    if asmSizeOf(t) > 4:
      error("RV32: " & what & " is an aggregate of " & $asmSizeOf(t) &
            " bytes; a register holds 4", n)
  else: discard

proc argWordTypeRv(p: ptr Param): Type =
  ## The type of ONE argument register of `p`. An aggregate spread over several
  ## registers has no per-word Leng type, and neither does a 64-bit scalar split
  ## across a register PAIR — each half is a machine word. Reporting the param's
  ## own `(i 64)` for such a half is what would make `(mov (arg x 0) …)` look like
  ## a 64-bit register move to `checkRegWidthRv`.
  if p.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT} or
     p.regs.len > 1:
    rvRegType()
  else:
    p.typ

proc parseOperandRv*(n: var Cursor; ctx: var GenContext): OperandRv =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsRvFloatReg(t):
      result.isFloat = true
      let (f, w) = parseFloatRegisterRv(n)
      result.freg = f
      result.fw = w
      result.typ = Type(kind: TypeKind.FloatT, bits: (if w == rv.FpD: 64 else: 32))
      if result.freg in ctx.rvFRegBindings:
        error("Register " & $result.freg & " is bound to variable '" &
              ctx.rvFRegBindings[result.freg] & "', use the variable name instead", n)
    elif rawTagIsRvGpr(t):
      result.reg = parseRegisterRv(n)
      result.typ = rvRegType()
      if result.reg in ctx.rvRegBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.rvRegBindings[result.reg] & "', use the variable name instead", n)
    elif t == NilTagId:
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == ArgTagId:
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
        if rawTagIsRvFloatReg(paramPtr.regs[wordIdx]):
          result.isFloat = true
          result.freg = tagToFloatRegisterRv(paramPtr.regs[wordIdx], n)
          result.fw = rvFloatWidth(paramPtr.regs[wordIdx])
        else:
          result.reg = tagToRegisterRv(paramPtr.regs[wordIdx], n)
        result.typ = argWordTypeRv(paramPtr)
    elif t == ResTagId:
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
      if rawTagIsRvFloatReg(resPtr.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterRv(resPtr.reg, n)
        result.fw = rvFloatWidth(resPtr.reg)
      else:
        result.reg = tagToRegisterRv(resPtr.reg, n)
      result.typ = resPtr.typ
    elif t == CsizeTagId:
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okImm
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32, litVal: result.immVal)
      into n:
        while n.hasMore: skip n
    elif t == SsizeTagId:
      result.kind = okSsize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32)
      into n:
        if n.hasMore and n.kind == IntLit:
          result.immVal = getInt(n)
          inc n
    elif t in {DataloadTagId, DatavmaTagId, DatasizeTagId, BsssizeTagId,
               HeapstartTagId, HeapsizeTagId, NoinitstartTagId, NoinitsizeTagId}:
      # The image-layout numbers: where the `.data` initializer image lands, where
      # the region sits at run time, and how much of each to copy and to zero.
      # Same contract as `(ssize)` — a value only the finished layout knows, so
      # what is emitted is a placeholder of FIXED width and a recorded site.
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
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandRv(n, ctx)
      op.typ = castType
      result = op
      return
    elif t == DotTagId:
      # `(dot <base> <field>)` — fold the field's offset onto the base address.
      # Typed `PtrT(fieldType)`, so a nested `(dot (dot o inner) a)` keeps
      # accumulating rather than dereferencing.
      inc n
      let baseOp = parseOperandRv(n, ctx)
      if n.kind != Symbol: error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      var objType: Type
      var baseReg = rv.X0
      var baseOffset: int32 = 0
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        if baseOp.kind == okMem:
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
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
      result.mem = MemoryOperandRv(base: baseReg,
                                   offset: baseOffset + int32(fieldOffset))
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
    elif t == AtTagId:
      # `(at <base> <index>)`, or `(at <base> <index> <scratch>)`.
      #
      # Unlike Thumb, a REGISTER index never folds into the operand — the ISA has
      # no such form — so both spellings compute an address. The 3-operand form
      # says which register to compute it into; the 2-operand form uses
      # `RvScratch`, which nothing can name and therefore nothing can be holding.
      into n:
        let baseOp = parseOperandRv(n, ctx)
        let indexOp = parseOperandRv(n, ctx)
        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)
        var elemType: Type
        var baseReg = rv.X0
        var baseOffset: int32 = 0
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.typ.kind == TypeKind.PtrT and
             resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
          elemType = resolvedBase(baseOp.typ, ctx, n).elem
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseOffset = baseOp.mem.offset
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

        var addrReg = RvScratch
        var hasScratch = false
        if n.hasMore:
          let scratchOp = parseOperandRv(n, ctx)
          if scratchOp.kind notin {okReg, okArg}:
            error("at: 3-operand scratch must be a register", n)
          addrReg = scratchOp.reg
          hasScratch = true

        if indexOp.kind == okImm:
          # A constant index folds straight into the displacement — the one case
          # that needs no arithmetic at all.
          result.kind = okMem
          result.mem = MemoryOperandRv(
            base: baseReg, offset: baseOffset + int32(indexOp.immVal * stride))
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        else:
          if indexOp.kind notin {okReg, okArg}:
            error("at: expected a register or constant index", n)
          if hasScratch and addrReg == baseReg:
            # The scale writes `addrReg`, and if that IS the base then the add
            # that follows reads a base which is already gone.
            error("at: 3-operand scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          if stride > 0 and (stride and (stride - 1)) == 0:
            var k = 0
            var s2 = stride
            while s2 > 1: (s2 = s2 shr 1; inc k)
            if k == 0: rv.emitMv(ctx.buf.data, addrReg, indexOp.reg)
            else: rv.emitSlli(ctx.buf.data, addrReg, indexOp.reg, k)
          elif addrReg == RvScratch:
            error("at: element stride " & $stride & " is not a power of two, so " &
                  "scaling needs a register the selector does not have; use the " &
                  "3-operand form with a scratch register", n)
          else:
            # The stride constant goes into `RvScratch`, never into `addrReg`: the
            # caller may hand a scratch that ALIASES the index, and materializing
            # the stride there would destroy the index before the multiply.
            rv.emitLi(ctx.buf.data, RvScratch, uint32(stride))
            rv.emitMul(ctx.buf.data, addrReg, indexOp.reg, RvScratch)
          rv.emitAdd(ctx.buf.data, addrReg, baseReg, addrReg)
          # Fold the displacement into the SAME address so the operand needs no
          # second scratch downstream (see the module header).
          if baseOffset != 0:
            if rv.fitsImm12(int64(baseOffset)):
              rv.emitAddi(ctx.buf.data, addrReg, addrReg, baseOffset)
            elif addrReg != RvScratch:
              rv.emitLi(ctx.buf.data, RvScratch, cast[uint32](baseOffset))
              rv.emitAdd(ctx.buf.data, addrReg, addrReg, RvScratch)
            else:
              error("at: a " & $baseOffset & "-byte displacement on an indexed " &
                    "access needs a second scratch; use the 3-operand form", n)
          result.kind = okMem
          result.mem = MemoryOperandRv(base: addrReg, offset: 0)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n
      return
    elif t == MemTagId:
      # `(mem <base> [offset | field-symbol | (arg name)])`, or `(mem <lvalue>)`.
      #
      # `into` BOUNDS the cursor to this node's children: without it the optional
      # offset check reads into the following sibling, and a register-bound name
      # after a `(mem base)` destination gets eaten as if it were an offset.
      # Nothing inside may `return` — `into` is a template whose scope bookkeeping
      # a `return` jumps straight past.
      into n:
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          let addrOp = parseOperandRv(n, ctx)
          if addrOp.kind != okMem: error("mem requires an address expression", n)
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)
          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)
        else:
          let baseTok = n
          let base = parseOperandRv(n, ctx)
          if base.kind == okMem:
            result.mem = base.mem
          elif base.kind notin {okReg, okArg}:
            error("(mem ...) base must be a register", n)
          else:
            result.mem = MemoryOperandRv(base: base.reg, offset: 0)
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            let argOff = parseOperandRv(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            result.mem.offset += int32(argOff.immVal)
          elif n.hasMore and n.kind == IntLit:
            let extra = getInt(n)
            if base.kind == okMem and base.typ != nil and
               base.typ.kind == TypeKind.StackOffT:
              let slotSize = asmSizeOf(base.typ)
              if extra < 0 or extra >= slotSize:
                error("offset " & $extra & " is outside stack slot '" &
                      (if baseTok.kind == Symbol: getSym(baseTok) else: "?") &
                      "' (" & $slotSize & " bytes)", n)
            result.mem.offset += int32(extra)
            inc n
          elif n.hasMore and n.kind == Symbol:
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
            else: rvRegType()
        while n.hasMore: skip n
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
        result.mem = MemoryOperandRv(base: rv.Sp, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsRvFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterRv(sym.reg, n)
        result.fw = rvFloatWidth(sym.reg)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterRv(sym.reg, n)
        result.typ = sym.typ
        if result.reg in ctx.clobberedRv:
          error("Variable '" & name & "' lives in " & $result.reg &
                ", which a call clobbered; its value is gone", n)
      else:
        error("Variable has no location: " & name, n)
      inc n
    of skLabel:
      result.reg = rv.X0
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
      result.reg = rv.X0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skGvar:
      result.gvarSym = sym
      result.reg = rv.X0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skTvar:
      error("RV32 has no thread-local storage yet: '" & name & "'", n)
    else:
      error("Cannot use symbol '" & name & "' as an operand", n)
  else:
    error("Expected operand", n)

proc parseDestRv*(n: var Cursor; ctx: var GenContext): OperandRv =
  ## A DESTINATION operand. Not simply `parseOperandRv`: an `(arg …)` destination
  ## RECORDS that the argument was bound, which is what the prepare block checks
  ## on the way out, and a variable destination un-clobbers its register.
  if n.kind == TagLit and rawTagIsRvFloatReg(n.tag):
    result.isFloat = true
    let (f, w) = parseFloatRegisterRv(n)
    result.freg = f
    result.fw = w
    result.typ = Type(kind: TypeKind.FloatT, bits: (if w == rv.FpD: 64 else: 32))
    if result.freg in ctx.rvFRegBindings:
      error("Register " & $result.freg & " is bound to variable '" &
            ctx.rvFRegBindings[result.freg] & "', use the variable name instead", n)
  elif n.kind == TagLit and rawTagIsRvGpr(n.tag):
    result.reg = parseRegisterRv(n)
    result.typ = rvRegType()
    if result.reg in ctx.rvRegBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.rvRegBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # Binding a REGISTER argument inside a prepare block. Unlike an ordinary
    # register destination this deliberately skips the binding check: the argument
    # register is exactly where the value must go, and the call is about to
    # clobber it anyway.
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
    if rawTagIsRvFloatReg(paramPtr.regs[wordIdx]):
      result.isFloat = true
      result.freg = tagToFloatRegisterRv(paramPtr.regs[wordIdx], n)
      result.fw = rvFloatWidth(paramPtr.regs[wordIdx])
    else:
      result.reg = tagToRegisterRv(paramPtr.regs[wordIdx], n)
    result.typ = argWordTypeRv(paramPtr)
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == CastTagId):
    # `(cast T (mem …))` as a DESTINATION retypes — and thereby SIZES — the
    # store, exactly as it does on the read side. This is how a 64-bit value's
    # two halves are addressed on a 32-bit target: the slot is `(i 64)`, each half
    # a `(cast (u 32) (mem slot 0|4))`, and the cast is what says so rather than a
    # silent truncation of a 64-bit typed access down to one word.
    let op = parseOperandRv(n, ctx)
    if op.kind != okMem: error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown symbol: " & name, n)
    if sym.kind in {skVar, skParam}:
      if sym.typ.isOnStack:
        result.kind = okMem
        result.mem = MemoryOperandRv(base: rv.Sp, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsRvFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterRv(sym.reg, n)
        result.fw = rvFloatWidth(sym.reg)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterRv(sym.reg, n)
        result.typ = sym.typ
        ctx.clobberedRv.excl(result.reg)   # writing a fresh value un-clobbers it
      else:
        error("Variable has no location: " & name, n)
      inc n
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc regOfRv*(op: OperandRv; what: string; n: Cursor): rv.Register =
  if op.kind notin {okReg, okArg}:
    error("RV32: " & what & " must be a register", n)
    return rv.X0
  if op.isFloat:
    error("RV32: " & what & " must be an integer register", n)
    return rv.X0
  op.reg

# ── memory access ───────────────────────────────────────────────────────────

proc memWidthRv*(t: Type): tuple[width: MemWidthRv; signed: bool] =
  ## The ACCESS WIDTH a typed memory operand implies, and whether a load of it
  ## sign-extends. A `(mem …)` carries the pointee / field / slot type, so a
  ## narrow integer must load with `lb`/`lh` (or their `u` forms) and store only
  ## its low bits — otherwise reading one byte of a `(u 8)` array returns that
  ## byte and the three after it, which is not a crash and not a type error, just
  ## a wrong value.
  var ty = t
  if ty != nil and ty.kind == TypeKind.StackOffT: ty = ty.offType
  if ty == nil: return (MemWord, false)
  case ty.kind
  of TypeKind.BoolT: (MemByte, false)
  of TypeKind.IntT:
    if ty.bits == 8: (MemByte, true)
    elif ty.bits == 16: (MemHalf, true)
    else: (MemWord, false)
  of TypeKind.UIntT:
    if ty.bits == 8: (MemByte, false)
    elif ty.bits == 16: (MemHalf, false)
    else: (MemWord, false)
  else: (MemWord, false)

proc emitMemAccessRv*(ctx: var GenContext; rt: rv.Register;
                      mem: MemoryOperandRv; width: MemWidthRv;
                      isLoad: bool; signed = false; n: Cursor) =
  ## THE one place a `(mem …)` becomes a load or a store.
  ##
  ## A displacement past ±2048 is computed into `RvScratch` first. `rt` can never
  ## BE `RvScratch` — no tag names it — so unlike the Thumb twin this needs no
  ## "and the scratch already holds the value" arm.
  var base = mem.base
  var off = mem.offset
  if not rv.fitsImm12(int64(off)):
    rv.emitLi(ctx.buf.data, RvScratch, cast[uint32](off))
    rv.emitAdd(ctx.buf.data, RvScratch, mem.base, RvScratch)
    base = RvScratch
    off = 0
  if isLoad:
    case width
    of MemByte: (if signed: rv.emitLb(ctx.buf.data, rt, base, off)
                 else: rv.emitLbu(ctx.buf.data, rt, base, off))
    of MemHalf: (if signed: rv.emitLh(ctx.buf.data, rt, base, off)
                 else: rv.emitLhu(ctx.buf.data, rt, base, off))
    of MemWord: rv.emitLw(ctx.buf.data, rt, base, off)
  else:
    case width
    of MemByte: rv.emitSb(ctx.buf.data, rt, base, off)
    of MemHalf: rv.emitSh(ctx.buf.data, rt, base, off)
    of MemWord: rv.emitSw(ctx.buf.data, rt, base, off)

proc emitFpMemAccessRv*(ctx: var GenContext; fd: rv.FloatRegister;
                        mem: MemoryOperandRv; w: rv.FpWidth;
                        isLoad: bool; n: Cursor) =
  ## The FP twin. `RvScratch` is always available here for the same reason, and
  ## additionally because the value being moved is in a FLOAT register.
  var base = mem.base
  var off = mem.offset
  if not rv.fitsImm12(int64(off)):
    rv.emitLi(ctx.buf.data, RvScratch, cast[uint32](off))
    rv.emitAdd(ctx.buf.data, RvScratch, mem.base, RvScratch)
    base = RvScratch
    off = 0
  if isLoad: rv.emitFpLoad(ctx.buf.data, fd, base, off, w)
  else: rv.emitFpStore(ctx.buf.data, fd, base, off, w)

proc emitAbsPairRv*(ctx: var GenContext; rd: rv.Register) =
  ## A `lui`+`addi` pair with both immediates zero: eight bytes reserved for a
  ## value only the finished layout knows. Fixed width whatever the final number,
  ## which is what lets it be patched after every label position downstream is
  ## already settled.
  rv.emitLui(ctx.buf.data, rd, 0)
  rv.emitAddi(ctx.buf.data, rd, rd, 0)

proc emitGvarAddrRv*(ctx: var GenContext; rd: rv.Register; sym: Symbol) =
  ## A global's address. A global lives in SRAM, nowhere near the code, so this is
  ## materialized ABSOLUTELY rather than PC-relatively — the RV32 twin of
  ## Cortex-M's MOVW/MOVT, sound for the same reason: a firmware image's load
  ## address is fixed at link time, so there is nothing to be relative to.
  ctx.gvarSites.add (ctx.buf.data.len, sym)
  emitAbsPairRv(ctx, rd)

proc emitSsizeRv*(ctx: var GenContext; rd: rv.Register; pad: int) =
  ## The frame size, which is not known until the whole proc has been read.
  ##
  ## Always the pair, never a bare `addi`: `addi` reaches ±2048, so choosing
  ## between the two forms would make the instruction's WIDTH depend on a number
  ## that is still unknown — and a patch that resizes an instruction invalidates
  ## every label position after it. Eight bytes for every frame is the price of
  ## patching being a pure overwrite.
  ctx.ssizePatches.add((ctx.buf.data.len, pad))
  emitAbsPairRv(ctx, rd)

proc imm32Rv*(v: int64; n: Cursor): uint32 =
  ## A 32-bit immediate from an asm-NIF integer literal.
  ##
  ## BOTH readings are accepted — signed down to -2^31 and unsigned up to
  ## 2^32-1 — because a NIF int literal carries no signedness of its own and an
  ## address like 0x8010_0000 is written as an ordinary positive number. A plain
  ## `int32(v)` conversion raises on exactly those, which is a crash where the
  ## program was right.
  if v >= low(int32) and v <= high(int32): cast[uint32](int32(v))
  elif v >= 0 and v <= 0xFFFF_FFFF: uint32(v)
  else:
    error("RV32: " & $v & " does not fit a 32-bit immediate", n)
    0'u32

proc loadToRegRv*(ctx: var GenContext; dest: rv.Register; op: OperandRv; n: Cursor) =
  ## Materialize `op` into `dest`. The one place that decides how each operand
  ## KIND reaches a register, so no instruction arm has to repeat it.
  case op.kind
  of okReg, okArg:
    if op.isFloat:
      error("RV32: expected an integer operand, got a floating-point register", n)
    else:
      rv.emitMv(ctx.buf.data, dest, op.reg)
  of okImm:
    rv.emitLi(ctx.buf.data, dest, imm32Rv(op.immVal, n))
  of okMem:
    let (w, sg) = memWidthRv(op.typ)
    emitMemAccessRv(ctx, dest, op.mem, w, isLoad = true, signed = sg, n = n)
  of okSsize:
    emitSsizeRv(ctx, dest, int(op.immVal))
  of okMimg:
    # An image-layout number, by the same means and for the same reason as
    # `(ssize)`: the value is decided by `writeRv32Image`, and the pair reserves a
    # fixed eight bytes so patching never has to move a label.
    ctx.mimgSites.add((ctx.buf.data.len, op.mimg))
    emitAbsPairRv(ctx, dest)
  of okLabel:
    rv.emitLaAbs(ctx.buf, dest, op.label)
  else:
    if op.gvarSym != nil:
      emitGvarAddrRv(ctx, dest, op.gvarSym)
    elif op.isCode or int(op.label) != 0:
      # A code or rodata label, ABSOLUTELY: like the global above, and unlike
      # AArch64's `adrp`, this has no reach limit to run into. Note there is no
      # state bit to OR in — that is Thumb's problem, not this one.
      rv.emitLaAbs(ctx.buf, dest, op.label)
    else:
      error("RV32: this operand cannot be loaded into a register", n)

proc storeFromRegRv*(ctx: var GenContext; src: rv.Register; dst: OperandRv;
                     n: Cursor) =
  case dst.kind
  of okReg, okArg: rv.emitMv(ctx.buf.data, dst.reg, src)
  of okMem:
    let (w, _) = memWidthRv(dst.typ)
    emitMemAccessRv(ctx, src, dst.mem, w, isLoad = false, n = n)
  else:
    error("RV32: this operand cannot be stored into", n)

proc toRegRv*(ctx: var GenContext; op: OperandRv; n: Cursor;
              scratch = RvScratch): rv.Register =
  ## `op` as a register, materializing it into `scratch` if it is not one already.
  ## The workhorse of the instruction arms: RV32's ALU takes registers and a
  ## 12-bit immediate and nothing else, so anything wider or in memory has to
  ## land somewhere first.
  if op.kind in {okReg, okArg} and not op.isFloat: op.reg
  else:
    loadToRegRv(ctx, scratch, op, n)
    scratch
