#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## AArch64 OPERANDS: what an asm-NIF operand node means here, and the addressing
## forms an instruction can actually reach it through.
##
## `a64IntMemBase` / `a64FpMemBase` are where most of the target's character
## sits: LDR/STR take an unsigned scaled immediate whose range depends on the
## access WIDTH, so an offset the encoding cannot hold has to be materialised
## into a scratch base first — and which scratch is free is a fact about the
## binding tables, not about the instruction.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, decls, 
                    stackslots, relocs]
import encoder as arm64
import regs

type
  OperandA64* = object
    kind*: OperandKind
    reg*: arm64.Register
    typ*: Type
    immVal*: int64
    mem*: arm64.MemoryOperand
    argName*: SymId       # set for okArg (call argument / result binding by name)
    label*: LabelId
    gvarSym*: Symbol       # non-nil if this operand is a global (.bss) address;
                          # its `.size` (the .bss byte offset) is read after all
                          # symbols are processed, so forward refs resolve right
    tlvSym*: Symbol        # non-nil if this operand is a thread-local var address
                          # (arm64/macOS): `adr` lowers it to the TLV descriptor
                          # call sequence, leaving the variable's address in x0

proc fpSymReg(ctx: GenContext; n: Cursor): Symbol =
  ## If `n` is a `Symbol` naming a float local bound to a v-register, return its
  ## symbol; else nil. Float locals are never foreign, so a plain scope lookup suffices.
  if n.kind == Symbol:
    let sym = ctx.scope.lookup(getSymId(n))
    if sym != nil and sym.reg != InvalidTagId and isA64FpRegTag(sym.reg):
      return sym
  return nil

proc isA64FpOperand*(n: Cursor; ctx: GenContext): bool =
  ## True if `n` denotes an fp register operand — a raw `(dN)`/`(sN)` tag or a `Symbol`
  ## naming a float local bound to a v-register. The float handlers dispatch on this
  ## (reg-vs-mem / fmov direction) so a bound float local emitted as its name is
  ## recognized as a register operand.
  isA64FpRegOperand(n) or fpSymReg(ctx, n) != nil

proc isA64FpSingle*(n: Cursor; ctx: GenContext): bool =
  ## Single-precision (`s` view)? For a raw tag, the `(sN)` form; for a bound float
  ## symbol, the recorded type is `(f 32)`. nifasm reads the operand's precision here
  ## to choose single- vs double-precision encodings — so a *named* float operand must
  ## recover it from the binding rather than the (absent) tag.
  if isA64FpRegOperand(n): return isA64SingleRegTag(n.tag)
  let sym = fpSymReg(ctx, n)
  result = sym != nil and sym.typ.kind == FloatT and sym.typ.bits == 32

proc parseFloatOperandA64*(n: var Cursor; ctx: var GenContext): arm64.FloatRegister =
  ## Binding-aware fp register *operand*: a raw `(dN)`/`(sN)` tag is accepted only if
  ## the register is not bound (a bound register must be named so the binding checker
  ## sees the use); a `Symbol` is resolved to the v-register its float local is bound
  ## to. The SIMD twin of `parseGprA64` — turns a raw use of a still-live bound float
  ## register into a build error instead of a silent clobber.
  if isA64FpRegOperand(n):
    result = tagToFloatRegA64(n.tag)
    if result in ctx.a64FRegBindings:
      error("Register " & $result & " is bound to variable '" &
            ctx.a64FRegBindings[result] & "', use the variable name instead", n)
    inc n
  elif n.kind == Symbol:
    let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if sym == nil: error("Unknown symbol: " & getSym(n), n)
    if sym.reg == InvalidTagId or not isA64FpRegTag(sym.reg):
      error("Expected float register variable, got: " & getSym(n), n)
    result = tagToFloatRegA64(sym.reg)
    inc n
  else:
    error("Expected fp register (dN/sN) or float variable", n)

proc parseOperandA64*(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsA64Reg(t):
      result.reg = parseRegisterA64(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # A raw use of a register bound to a live variable is a code-generator bug (a
      # silent clobber of the value it holds): spell the variable by name instead.
      if result.reg in ctx.a64RegBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.a64RegBindings[result.reg] & "', use the variable name instead", n)
    elif t == NilTagId:
      # `(nil)` as a value: the null pointer — a 0 immediate typed `nil` (compatible
      # with any pointer, never a sized integer). See `compatible`'s NilT arm.
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
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
      var baseIndex: arm64.Register
      var baseShift = 0
      var baseHasIndex = false
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        if baseOp.kind == okMem:
          # The base is itself a memory lvalue — a NESTED access whose result type the
          # `(dot …)`/`(at …)` rule tagged `PtrT(fieldType)` (an embedded sub-object/
          # element sits AT base+offset, not behind a loaded pointer). Fold the field
          # offset onto the inner base+offset (+index) instead of treating the inner
          # base register as the pointer — otherwise `(dot (dot o inner) a)` and
          # `(dot (at arr i) f)` lose the inner displacement. Mirrors the x64 parser.
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
        # a stack-resident object/union: unwrap the StackOffT to its object type
        objType = baseOp.typ.offType
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("dot requires pointer to object/union or stack object/union, got " & $baseOp.typ, n)
      var fieldOffset = 0
      var fieldType: Type = nil
      # Offsets are precomputed in parseObjectBody/parseUnionBody (inherited
      # fields carry their base offsets), so a plain name lookup suffices.
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      result.kind = okMem
      result.mem = arm64.MemoryOperand(
        base: baseReg,
        offset: baseOffset + int32(fieldOffset),
        hasIndex: baseHasIndex,
        index: baseIndex,
        shift: baseShift
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
        var baseIndex: arm64.Register
        var baseShift: int = 0
        var baseHasIndex = false
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.typ.kind == TypeKind.PtrT and
             resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
          # (at <base> index) where <base> is a pointer-to-array address
          # `(cast (ptr (array elem N)) base)` — how arkham reaches a global array
          # or a deref'd array field. A nested `(at …)` base carries its own base
          # register + offset (+ a folded index), all folded on here.
          elemType = resolvedBase(baseOp.typ, ctx, n).elem
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseOffset = baseOp.mem.offset
            baseIndex = baseOp.mem.index
            baseShift = baseOp.mem.shift
            baseHasIndex = baseOp.mem.hasIndex
          else:
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
          error("at requires aptr, pointer-to-array, or stack array, got " & $baseOp.typ, n)

        var hasScratch = false
        var scratchReg: arm64.Register
        if n.hasMore:
          # The scratch is a raw `(xN)` or — when arkham `rebind`-bound it to a checked
          # name — the variable name; both resolve through parseOperandA64 to a register.
          let scratchOp = parseOperandA64(n, ctx)
          if scratchOp.kind != okReg:
            error("at: 3-operand scratch must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          # scratch = base + index*stride. arkham only emits this for a register
          # index, so indexOp is in a register; reuse scratch for the stride const.
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # Disjointness: `scratch==base` is fatal — `emitMul(scratch, index, X16)`
          # writes scratch (== base) before `emitAdd(scratch, base, scratch)` reads the
          # base, dropping it (→ a wild address). This is the arkham "Bug J" class; flag
          # it at assemble time. `scratch==index` IS allowed here (the X16 stride trick
          # keeps the index intact through the multiply — see the note below).
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          let stride = asmSizeOf(elemType)
          # The stride constant goes into the RESERVED assembler scratch X16, NOT the
          # output `scratchReg`: arkham may hand a scratch that ALIASES the index (x86
          # tolerates `scratch==idx`, and under register pressure it can be the only free
          # register). Materializing the stride into `scratchReg` first would clobber the
          # index before the multiply; X16 keeps the index intact, so `scratch==idx` stays
          # correct (`scratch = idx*stride` reads idx, writes scratch). X16/X17 are never
          # allocated by arkham, so this can't collide with base/index/scratch.
          # A power-of-two stride — which every aggregate whose size the layout rounded
          # up is — is a SHIFT, so it needs neither the constant nor the multiply:
          # `lsl scratch, idx, #k` replaces `mov x16,#stride; mul scratch, idx, x16`.
          # This is the 3-operand `(at …)` used for a non-scale element size, i.e. an
          # ADDRESS computation inside a loop, so the pair was paying twice over.
          if stride > 0 and (stride and (stride - 1)) == 0:
            var k = 0'u8
            var t = stride
            while t > 1: (t = t shr 1; inc k)
            if k == 0:
              arm64.emitMov(ctx.buf.data, scratchReg, indexOp.reg)      # stride 1
            else:
              arm64.emitLslImm(ctx.buf.data, scratchReg, indexOp.reg, k)
          else:
            arm64.emitMovImm64(ctx.buf.data, arm64.X16, uint64(stride))
            arm64.emitMul(ctx.buf.data, scratchReg, indexOp.reg, arm64.X16) # scratch = idx*stride
          # scratch = base + that. A SP base (a stack array) needs the EXTENDED-register
          # ADD — the shifted-register `emitAdd` would read register 31 as XZR, not SP,
          # zeroing the base (→ a wild address). Other bases use the plain register ADD.
          if baseReg == arm64.SP:
            arm64.emitAddExtended(ctx.buf.data, scratchReg, baseReg, scratchReg)
          else:
            arm64.emitAdd(ctx.buf.data, scratchReg, baseReg, scratchReg)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(base: scratchReg, offset: baseOffset, hasIndex: false)
        elif indexOp.kind == okImm:
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseReg, index: baseIndex, shift: baseShift,
            offset: baseOffset + int32(offset), hasIndex: baseHasIndex)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          if baseHasIndex:
            error("at: two register indices cannot fold into one memory operand", n)
          # Disjointness: base and index of the folded `[base + index<<shift]` are two
          # distinct live values (array address vs element index); aliasing them is a
          # codegen bug, so flag it rather than emit a silently-wrong address.
          if indexOp.reg == baseReg:
            error("at: array base and index occupy the same register (" &
                  $baseReg & ") — distinct values aliased (codegen bug)", n)
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
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
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
      # `into` bounds the cursor to the mem node, so the OPTIONAL index/shift/offset
      # checks below are gated by `hasMore` and never read into the following sibling
      # (there is no ParRi sentinel to stop them otherwise — a register-bound scratch
      # name following a `(mem base)` store dest would otherwise be eaten as an index).
      # Mirrors the x64 `mem` handler.
      into n:
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          var addrOp = parseOperandA64(n, ctx)
          if addrOp.kind != okMem:
            error("mem requires address expression", n)
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)
          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)
        else:
          let baseTok = n                      # peeked for the slot diagnostics
          var baseOp = parseOperandA64(n, ctx)
          if baseOp.kind == okImm:
            error("mem base must be a register", n)
          var memBase = baseOp.reg
          var offset: int32 = 0
          var hasIndex = false
          var indexReg: arm64.Register = arm64.X0
          var shift: int = 0
          var stackVarType: Type = nil
          if baseOp.kind == okMem:
            # `(mem name)` / `(mem name off)` — the base-free slot form. A slot symbol
            # already parses to `[sp + slotOffset]` (the `Symbol` arm of
            # `parseOperandA64`), so the frame base needs no operand of its own. This
            # is what lets a word of a stack aggregate be read or written without
            # first materializing the aggregate's address in a register: the copy
            # costs zero address registers instead of one. The access WIDTH still
            # comes from the operand's type, so a caller reading a raw eightbyte
            # wraps this in `(cast (u 64) …)`.
            if baseOp.typ == nil or baseOp.typ.kind != StackOffT:
              error("mem base must be a register", n)
            memBase = baseOp.mem.base
            offset = baseOp.mem.offset
            stackVarType = baseOp.typ.offType
            if n.hasMore and n.kind == IntLit:
              # Bounds-checked against the slot — the one safety a `(cast (aptr T)
              # <reg>)` access can never have, since the register form has no object
              # to check against.
              let extra = getInt(n)
              let slotSize = asmSizeOf(baseOp.typ)
              if extra < 0 or extra >= slotSize:
                error("offset " & $extra & " is outside stack slot '" &
                      (if baseTok.kind == Symbol: getSym(baseTok) else: "?") &
                      "' (" & $slotSize & " bytes)", n)
              offset += int32(extra)
              inc n
          elif n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (sp) (arg name)) - address of an outgoing stack argument slot
            let argOff = parseOperandA64(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            offset = int32(argOff.immVal)
          elif n.hasMore and (n.kind == IntLit or n.kind == Symbol):
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
                if n.hasMore and n.kind == IntLit:
                  shift = int(getInt(n))
                  if shift notin [0, 1, 2, 3]:
                    error("mem shift must be 0, 1, 2, or 3", n)
                  inc n
                  if n.hasMore and n.kind == IntLit:
                    offset = int32(getInt(n))
                    inc n
              else:
                error("Expected index register or offset in mem", n)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: memBase,
            index: indexReg,
            shift: shift,
            offset: offset,
            hasIndex: hasIndex
          )
          # The deref of `(ptr T)` has type T — no special cases (mirror of the x64 `mem`
          # handler). `memWidthOpc` sizes it from T (a sub-word int/bool → a narrow ldrb/
          # ldrh, e.g. the SSO `(ptr (u 8))` `s[i]` char read; everything ≥8 bytes → a
          # word); `movCompatible` decides whether T can move to/from the chosen register.
          if stackVarType != nil:
            result.typ = stackVarType
          elif baseOp.typ != nil and baseOp.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
            result.typ = resolvedBase(baseOp.typ, ctx, n)
          else:
            result.typ = Type(kind: IntT, bits: 64)
    elif t == SsizeTagId:
      # `(ssize)` is the frame size, filled in at `finalize` once every `(s)` slot is
      # allocated. The optional `(ssize N)` adds N bytes to THIS site only — the
      # prologue/epilogue use it to fold the 16-byte alignment pad into the frame
      # adjustment instead of emitting a second `sub rsp, 8` / `add rsp, 8`.
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      result.immVal = 0
      inc n
      if n.kind == IntLit:
        result.immVal = n.intVal
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
      # (arg name [k]) - argument reference inside a prepare block. `into` bounds the
      # cursor to the arg's children so the optional word index `k` (the k-th register
      # of a ≤16B by-value aggregate) is read without leaking the following sibling.
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
        # Stack argument used as an offset (e.g. inside (mem (sp) (arg name))).
        # The base offset is the running byte position among the stack-passed
        # params; the optional word index `k` selects the k-th eightbyte (8 bytes)
        # of a multi-word stack aggregate so it can be marshalled/read word-by-word.
        var offset = ctx.callContext.stackArgBase   # Win64 extern: above the shadow space
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
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
        result.reg = tagToRegisterA64(paramPtr.regs[wordIdx], n)
        result.typ =
          if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
          else: paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference inside a prepare block (after the call)
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & ctx.nameOf(resName), n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), n)
      ctx.callContext.resultsSet.incl(resName)
      result.reg = tagToRegisterA64(resPtr.reg, n)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64, litVal: result.immVal)
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
        # Reading a register-bound local whose register a prior `(call)` clobbered
        # would read garbage (the value the call overwrote): reject it. The allocator
        # homes cross-call values in callee-saved registers, so this only fires on a
        # code-generator bug — the call-safety guarantee.
        if result.reg in ctx.clobberedA64 and not lenient():
          error("Access to variable '" & name & "' in register " & $result.reg &
                " which was clobbered by a call", n)
        result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      if ctx.arch == Arch.A64 and sym.dataConst:
        # A `dataConst` blob lives in writable __DATA (it is rebased at load), so
        # its address is formed like a global's — adrp+add through the gvar path —
        # not as a PC-relative __TEXT label. `sym.size` becomes its __DATA offset
        # once its body is laid out (generateSymbol).
        result.gvarSym = sym
      elif sym.offset == -1:
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

proc parseGprA64*(n: var Cursor; ctx: var GenContext): arm64.Register =
  ## Resolve a GPR operand that may be a raw `(xN)` tag OR a register-bound variable
  ## name (a `rebind`-bound scratch / register-local), for instruction handlers that
  ## historically accepted only raw registers. Goes through `parseOperandA64`, so a
  ## raw use of a *bound* register is rejected — the name is the legal spelling.
  let op = parseOperandA64(n, ctx)
  if op.kind != okReg:
    error("Expected a register operand", n)
  result = op.reg

proc parseDestA64*(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit and rawTagIsA64Reg(n.tag):
    result.reg = parseRegisterA64(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    if result.reg in ctx.a64RegBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.a64RegBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name [k]) as destination - binds a register argument inside a prepare block.
    # `into` bounds the cursor to the arg's children so the optional word index `k` (the
    # k-th register of a ≤16B by-value aggregate) is read without leaking the sibling.
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
      error("Stack argument '" & ctx.nameOf(argName) & "' cannot be used directly as destination, use (mem (sp) (arg " & ctx.nameOf(argName) & "))", n)
    # Track once per name (on word 0) so the missing-arg check passes; allow later words.
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegisterA64(paramPtr.regs[wordIdx], n)
    result.typ =
      if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
      else: paramPtr.typ
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
        ctx.clobberedA64.excl(result.reg)   # writing a fresh value un-clobbers it
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

proc parse3OperandsA64*(n: var Cursor; ctx: var GenContext; opName: string):
                      tuple[rd, rn: arm64.Register; rm: OperandA64; dstTyp: Type] =
  ## Parse the operands of a 3-operand instruction `(op3 D A B)` → `D = A op B`.
  ## `D` and `A` are registers (`A` is a still-live source read without a prior
  ## `mov D, A`); `B` is the folded operand (register or immediate). Fixed arity, so
  ## no boundary peeking — the reader consumes exactly three operands.
  let dest = parseDestA64(n, ctx)
  if dest.kind == okMem: error(opName & " destination cannot be memory", n)
  let a = parseOperandA64(n, ctx)
  if a.kind != okReg: error(opName & " first source must be a register", n)
  result = (dest.reg, a.reg, parseOperandA64(n, ctx), dest.typ)

proc memWidthOpc*(typ: Type; isLoad: bool): tuple[size, opc: int] =
  ## Access width (0=byte,1=half,2=word,3=dword) and the load/store `opc` for a
  ## typed memory operand. A `(mem (dot …))` / `(mem (at …))` carries the field /
  ## element type, so a narrow integer load sign-/zero-extends and a narrow store
  ## writes only its low bits. Anything non-integer (pointer, raw `(mem reg)`) is a
  ## full 64-bit access.
  ##
  ## A STACK SLOT is its content type behind a `(stackoff …)` wrapper, so unwrap it
  ## and size the access by what the slot HOLDS. A slot always occupies 8 bytes
  ## (`allocSlotUp` rounds every footprint up to the granularity), so this is not
  ## about layout — it is what makes a narrow local's home behave like the variable
  ## it is: `strb` in, `ldrsb`/`ldrb` out. Reading one as a 64-bit cell instead
  ## returns the upper seven bytes as well, which for a local whose address escaped
  ## into a callee holding `ptr int8` is whatever was there before.
  var bits = 64
  var signed = false
  if typ != nil:
    var t = typ
    if t.kind == StackOffT and t.offType != nil: t = t.offType
    case t.kind
    of IntT: bits = t.bits; signed = true         # `(i N)` (and `(c N)` chars)
    of UIntT: bits = t.bits
    of BoolT: bits = 8
    else: bits = 64                                # PtrT / raw mem / aggregate
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

proc emitAddOffsetA64*(ctx: var GenContext; rd, rn: arm64.Register; offset: int64;
                      scratch: arm64.Register) =
  ## `rd = rn + offset`, synthesizing through `scratch` (a reserved assembler
  ## register, X16/X17) when the offset exceeds ADD's 12-bit immediate field.
  ## The old `uint16(offset)` call sites silently MIS-ENCODED 4096..65535 (the
  ## immediate overflowed into the shift/opcode bits).
  if offset >= 0 and offset <= 4095:
    arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(offset))
  else:
    arm64.emitMovImm64(ctx.buf.data, scratch, cast[uint64](offset))
    if rn == arm64.SP:
      arm64.emitAddExtended(ctx.buf.data, rd, rn, scratch)
    else:
      arm64.emitAdd(ctx.buf.data, rd, rn, scratch)

proc a64FpMemBase*(ctx: var GenContext; m: arm64.MemoryOperand;
                  single: bool): (arm64.Register, int32) =
  ## Reduce an FP load/store's memory operand to a (base, offset) pair the scaled
  ## unsigned-offset FP form can actually encode.
  ##
  ## That form has NO index register and only a `0..0xFFF` *scaled* displacement,
  ## while `(at …)` hands us `base + index<<shift (+ offset)` and a big frame hands
  ## us an offset past the field. Both fold into the reserved X16 veneer (arkham
  ## never allocates X16/X17), leaving the access itself a plain `[X16, #0]`.
  ## Before this, an INDEX was silently dropped — `powtens[i]` read `powtens[0]`
  ## for every i — and a large offset raised "FP LDR offset out of range".
  let scale = if single: 4'i32 else: 8'i32
  if not m.hasIndex and (m.offset mod scale) == 0 and
     m.offset >= 0 and (m.offset div scale) <= 0xFFF:
    return (m.base, m.offset)
  if m.hasIndex:
    # A SP base needs the EXTENDED-register ADD: the shifted form reads reg 31 as
    # XZR, not SP (same rule as `lea`).
    if m.base == arm64.SP:
      arm64.emitAddExtended(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
    else:
      arm64.emitAddShifted(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
    if m.offset != 0:
      emitAddOffsetA64(ctx, arm64.X16, arm64.X16, m.offset, arm64.X17)
  else:
    emitAddOffsetA64(ctx, arm64.X16, m.base, m.offset, arm64.X17)
  result = (arm64.X16, 0'i32)

proc a64IntMemBase*(ctx: var GenContext; m: arm64.MemoryOperand;
                   size: int): arm64.MemoryOperand =
  ## Reduce an integer load/store's memory operand to one the register-offset form can
  ## actually encode.
  ##
  ## `[Xn, Xm, LSL #k]` has a single SCALE bit, and it means "shift by the ACCESS
  ## width's log2" — it is not a general shift amount. So the only strides that form
  ## can say are 1 (S=0) and the transfer size itself (S=1). `(at …)` hands us the
  ## ELEMENT stride, which is the same number only while the access IS the element;
  ## an enclosing `(dot …)` narrows it, and `(dot (at arrayOfTuples i) fld)` then wants
  ## stride 8 with a 4-byte load. That was emitted as `LSL #2` — silently reading
  ## element `i/2` — and as `LSL #0` for a `bool` field, reading element `i/8`. It cost
  ## a self-hosted hexer its `processMethods` loop: a `seq[(SymId, bool)]` walked at a
  ## 4-byte stride visited elements 0, 2, 2, 2, … and handed `getOrQuit` a key that was
  ## half a tuple.
  ##
  ## When the stride is not expressible, compute `base + index<<shift (+ offset)` into
  ## the reserved X16 veneer and access `[X16, #0]` — what `a64FpMemBase` and `lea`
  ## already do for the same reason. X16/X17 are never allocated by arkham.
  result = m
  if not m.hasIndex: return
  if m.shift == 0 or m.shift == size: return    # the S bit says what we mean
  if m.base == arm64.SP:
    # A SP base needs the EXTENDED-register ADD; the shifted form reads reg 31 as XZR.
    arm64.emitAddExtended(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
  else:
    arm64.emitAddShifted(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
  if m.offset != 0:
    emitAddOffsetA64(ctx, arm64.X16, arm64.X16, m.offset, arm64.X17)
  result = arm64.MemoryOperand(base: arm64.X16, offset: 0, hasIndex: false)

proc a64CondOf*(inst: A64Inst): arm64.Condition =
  ## The condition code baked into a `csel*`/`cset*` mnemonic (same condition
  ## vocabulary as the `b*` branches).
  case inst
  of CseleqA64, CseteqA64: arm64.CondEQ
  of CselneA64, CsetneA64: arm64.CondNE
  of CselltA64, CsetltA64: arm64.CondLT
  of CselleA64, CsetleA64: arm64.CondLE
  of CselgtA64, CsetgtA64: arm64.CondGT
  of CselgeA64, CsetgeA64: arm64.CondGE
  of CselloA64, CsetloA64: arm64.CondLO
  of CsellsA64, CsetlsA64: arm64.CondLS
  of CselhiA64, CsethiA64: arm64.CondHI
  of CselhsA64, CsethsA64: arm64.CondHS
  else: raiseAssert("not a conditional-select mnemonic: " & $inst)
