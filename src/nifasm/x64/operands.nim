#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## x86-64 OPERANDS: what an asm-NIF operand node means here, and the checks that
## belong to the operand rather than to any one instruction.
##
## `Operand` is the widest of the three targets' operand records because x86
## addressing is: base + index*scale + disp reaches memory directly from almost
## every instruction, so an operand carries a whole `MemoryOperand` and the ALU
## family has to be told, per instruction, whether it may take one.

import std / [tables, sets]
import nifcore
import "../core" / [context, sem, cursors, diagnostics, typecheck, typesem,
                    tags, model, decls, 
                    stackslots, relocs]
import encoder as x86
import regs

type
  Operand* = object
    kind*: OperandKind
    typ*: Type
    reg*: x86.Register
    castBits*: int             # non-zero only for an okReg operand under an EXPLICIT
                              # sub-width int `(cast …)`: the ALU family then operates
                              # at that width (8/16/32). Never inferred from a
                              # symbol's declared type — existing output is unchanged.
    immVal*: int64
    mem*: x86.MemoryOperand
    argName*: SymId
    label*: LabelId
    gvarSym*: Symbol           # non-nil when the operand is a global's address; the
                              # ELF backend patches its `lea` against the .bss segment

proc parseOperand*(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsX64Reg(t):
      result.reg = parseRegister(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # Check if this register is bound to a variable
      if result.reg in ctx.regBindings and not lenient():
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.regBindings[result.reg] & "', use the variable name instead", n)
      # R11 is the codegen's RESERVED staging bridge — never a syscall/call argument
      # or a callee-saved home. A *raw* `(reg r11)` therefore always means a value or
      # address was left in the bridge as an UNTRACKED, untyped register; the codegen
      # must hand it out as a typed `(rebind)` binding (see arkham `pickStagingSealed`).
      # Rejecting it here keeps the staging bridge inside the typed-binding model so a
      # dropped/clobbered operand is an assemble-time error, not a runtime miscompile.
      if result.reg == x86.R11 and not lenient():
        error("raw r11 operand: the staging bridge must be a typed (rebind) binding, " &
              "never a bare (reg) — untracked value/address in the bridge", n)
    elif t == NilTagId:
      # `(nil)` as a value: the null pointer — a 0 immediate typed `nil` (compatible
      # with any pointer, never a sized integer). See `compatible`'s NilT arm.
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
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
      var seg = segNone
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
            seg = baseOp.mem.seg
          else:
            baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
          objType = baseOp.typ
          baseReg = baseOp.mem.base
          baseDisp = baseOp.mem.displacement
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
          # A stack-resident object/union named DIRECTLY: `(dot p.0 x.0)`. The slot
          # symbol already parses to `[rsp+offset]` (see the `Symbol` arm below), so
          # the frame base needs no operand of its own — same as the Arm parsers.
          # The older `(dot (rsp) p.0 x.0)` spelling above stays accepted.
          objType = baseOp.typ.offType
          baseReg = baseOp.mem.base
          baseDisp = baseOp.mem.displacement
        else:
          error("dot requires a stack object/union, a pointer to one, or (base-reg stackvar field), got " &
                $baseOp.typ, n)

      # Find field in object/union type. Offsets are precomputed in
      # parseObjectBody/parseUnionBody — inherited (base) fields carry their base
      # offsets, own fields start at sizeof(base), unions are all 0 — so a plain
      # name lookup yields the right displacement.
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break

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
        seg: seg
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
          elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
            elemType = baseOp.typ.elem
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
          elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
               baseOp.typ.offType.kind == TypeKind.ArrayT:
            # A stack-resident array named DIRECTLY: `(at arr.0 (rcx))`. The slot
            # symbol carries its own `[rsp+offset]`, so the frame base is implicit —
            # same as the Arm parsers. `(at (rsp) arr.0 (rcx))` stays accepted.
            elemType = baseOp.typ.offType.elem
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
          else:
            error("at requires a stack array, an aptr, a pointer-to-array base, or (base-reg stackvar index), got " &
                  $baseOp.typ, n)

        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)

        # Optional third operand: an arkham-supplied scratch register for a stride
        # that can't be a SIB scale.
        var hasScratch = false
        var scratchReg: x86.Register
        if n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
          scratchReg = parseRegister(n)
          hasScratch = true
        elif n.hasMore and n.kind == Symbol:
          # arkham may pass the scratch as a `rebind`-bound temp name rather than a
          # raw `(reg)`; resolve it to its register (a raw `(reg)` for a bound reg is
          # itself rejected elsewhere, so the name is the only legal spelling).
          let scratchOp = parseOperand(n, ctx)
          if scratchOp.kind != okReg:
            error("at: scratch operand must be a register", n)
          scratchReg = scratchOp.reg
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
          # Disjointness: the stride scratch must not alias the base register. The
          # `mov scratch,index` below clobbers `scratch` before the `lea` reads `base`,
          # so `scratch==base` silently drops the base (→ a wild address). This is the
          # arkham allocation bug class ("Bug J") that used to surface only as an
          # ASLR-only runtime segfault; flag it at assemble time. `scratch==index` is
          # fine (the mov is then a no-op) and is intentionally allowed (under register
          # pressure it can be the only free choice).
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          let stride = asmSizeOf(elemType)
          # `base + index*stride` without a multiply wherever the stride allows it.
          # A SIB scale covers {1,2,4,8}; a SUM of two scales covers the strides that
          # actually dominate this compiler — 16 (`HashEntry`, and any pair of words)
          # is 8+8, so two `lea`s replace `mov`+`imul`+`lea`: one instruction fewer,
          # and no 3-cycle `imul` on the address path of every indexed access.
          #
          # The split form reads `index` TWICE, so it needs `scratch != index` —
          # which the disjointness rule above deliberately permits (under pressure
          # arkham may hand us the index register as the scratch). When they alias,
          # the first `lea` would destroy the index before the second reads it, so
          # fall through to the sequential form, where `mov scratch, index` is a
          # no-op and the shift/multiply operates in place.
          var loScale = 0
          var hiScale = 0
          if scratchReg != indexOp.reg:
            if stride in [1, 2, 4, 8]:
              loScale = stride                       # a single `lea` does it all
            else:
              for a in [8, 4, 2, 1]:
                if stride > a and (stride - a) in [1, 2, 4, 8]:
                  loScale = a; hiScale = stride - a; break
          if loScale != 0:
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + index*lo
              x86.MemoryOperand(base: baseReg, index: indexOp.reg, scale: loScale,
                                displacement: baseDisp, hasIndex: true))
            if hiScale != 0:
              x86.emitLea(ctx.buf.data, scratchReg,                 # scratch += index*hi
                x86.MemoryOperand(base: scratchReg, index: indexOp.reg, scale: hiScale,
                                  displacement: 0, hasIndex: true))
          else:
            x86.emitMov(ctx.buf.data, scratchReg, indexOp.reg)      # scratch = index
            if stride > 0 and (stride and (stride - 1)) == 0:
              var sh = 0
              while (1 shl sh) < stride: inc sh
              x86.emitShl(ctx.buf.data, scratchReg, sh)             # scratch <<= log2(stride)
            else:
              x86.emitImulImm(ctx.buf.data, scratchReg, int32(stride))
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + scratch
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
          # Disjointness: in the folded SIB `[base + index*scale]`, base and index are
          # two distinct live values (an array address and an element index); aliasing
          # them computes `base + base*scale` (a codegen bug). Flag it rather than emit
          # a silently-wrong address.
          if indexOp.reg == baseReg:
            error("at: array base and index occupy the same register (" &
                  $baseReg & ") — distinct values aliased (codegen bug)", n)
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
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      if sym == ctx.tlsSizeSym: ctx.tlsSizeUsed = true   # emit the cell (appendTlsSize)
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
      # An explicit sub-width int cast over a REGISTER is a width annotation:
      # the ALU family operates on the low `castBits` of the register (32-bit
      # zero-extends the destination, 8/16 preserve its upper bits, flags at
      # that width). Recorded only here — a symbol's declared sub-width type
      # never sizes a register operation, so existing output is byte-identical.
      if op.kind == okReg and castType != nil and
         castType.kind in {IntT, UIntT} and castType.bits in [8, 16, 32]:
        op.castBits = castType.bits
      else:
        op.castBits = 0
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
        elif n.kind == IntLit and getInt(n) == 0:
          # `(mem 0 index scale [disp])` — the NO-BASE scaled form
          # `[index*scale + disp]` (SIB base=101). The literal 0 base is
          # unambiguous: a plain base is never an immediate. This is how a pure
          # scaled index (`lea D, [S*8]`, gcc's `[rax*4+0]`) is spelled.
          inc n
          var indexReg: x86.Register
          if n.kind == TagLit and rawTagIsX64Reg(n.tag):
            let idxOp = parseOperand(n, ctx)   # keeps the binding guards
            indexReg = idxOp.reg
          elif n.kind == Symbol:
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind in {skVar, skParam} and
               indexSym.reg != InvalidTagId:
              indexReg = tagToRegister(indexSym.reg, n)
              inc n
            else:
              error("Expected register index in no-base mem", n)
          else:
            error("Expected register index in no-base mem", n)
          if not (n.hasMore and n.kind == IntLit):
            error("no-base mem requires an explicit scale", n)
          let scale0 = int(getInt(n))
          if scale0 notin [1, 2, 4, 8]:
            error("mem scale must be 1, 2, 4, or 8", n)
          inc n
          var disp0: int32 = 0
          if n.hasMore and n.kind == IntLit:
            disp0 = int32(getInt(n))
            inc n
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: x86.RAX,          # unused; RAX keeps REX.B-from-base silent
            index: indexReg,
            scale: scale0,
            displacement: disp0,
            hasIndex: true,
            noBase: true
          )
          result.typ = Type(kind: IntT, bits: 64)
        else:
          # Explicit addressing: (mem base) or (mem base offset) or
          # (mem base index scale [offset]) — or the BASE-FREE slot form
          # `(mem <stackvar> [offset])` handled first below.
          let baseTok = n                      # peeked for the slot diagnostics
          var baseOp = parseOperand(n, ctx)
          if baseOp.kind == okImm:
            error("mem base must be a register", n)

          var memBase = baseOp.reg
          var displacement: int32 = 0
          var hasIndex = false
          var indexReg: x86.Register = x86.RAX
          var scale: int = 1

          # Check for an optional offset/index (present only if the mem node has
          # more children).
          var stackVarType: Type = nil
          if baseOp.kind == okMem:
            # `(mem name)` / `(mem name off)` — the base-free slot form. A slot
            # symbol already parses to `[rsp + slotOffset]` (the `Symbol` arm of
            # `parseOperand`), so the frame base carries no information and needs no
            # operand of its own. This is the Thumb-2 and AArch64 spelling; the older
            # `(mem (rsp) name [off])` goes through the `Symbol` branch further down
            # and stays accepted.
            if baseOp.typ == nil or baseOp.typ.kind != StackOffT:
              error("mem base must be a register", n)
            memBase = baseOp.mem.base
            displacement = baseOp.mem.displacement
            stackVarType = baseOp.typ.offType
            if n.hasMore and n.kind == IntLit:
              # A raw byte offset WITHIN the named slot, bounds-checked against it —
              # the one safety a `(cast (aptr T) <reg>)` access can never have. See
              # the twin check in the `(mem <base> <stackvar> <disp>)` branch below.
              let extra = getInt(n)
              let slotSize = asmSizeOf(baseOp.typ)
              if extra < 0 or extra >= slotSize:
                error("offset " & $extra & " is outside stack slot '" &
                      (if baseTok.kind == Symbol: getSym(baseTok) else: "?") &
                      "' (" & $slotSize & " bytes)", n)
              displacement += int32(extra)
              inc n
          elif n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (rsp) (arg name)) — an outgoing stack-argument slot. The arg's
            # byte offset within the reserved area becomes the displacement.
            var an = n; inc an                  # peek the arg name before consuming
            let argName = if an.kind == Symbol: getSymId(an) else: SymId(0)
            let argOff = parseOperand(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            displacement = int32(argOff.immVal)
            if argName != SymId(0): ctx.callContext.argsSet.incl argName
            # The slot IS the parameter, so it carries the parameter's declared type —
            # not the machine word a bare `(rsp)` base would otherwise imply. Without
            # this, storing e.g. a `nil` into a stack-passed `pointer` parameter is a
            # type error against a phantom `(i 64)`. An AGGREGATE keeps the word type:
            # `(arg pN k)` addresses one eightbyte of it, not the whole object.
            if argOff.typ != nil:
              let pt = if argOff.typ.kind == StackOffT: argOff.typ.offType else: argOff.typ
              if pt != nil and pt.kind notin {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}:
                stackVarType = pt
          elif n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
            # `(mem <base> <index-reg> [scale [disp]])` with a raw register index —
            # the general SIB form `[base + index*scale + disp]`. Parsing the index
            # through parseOperand keeps the binding guards (a bound register must be
            # named, r11 stays a typed binding). Base==index is legal here: unlike
            # `(at)`, this form makes no claim that the two are distinct values — it
            # IS the encoding, as a distilled gcc body may spell it.
            let idxOp = parseOperand(n, ctx)
            hasIndex = true
            indexReg = idxOp.reg
            if n.hasMore and n.kind == IntLit:
              scale = int(getInt(n))
              if scale notin [1, 2, 4, 8]:
                error("mem scale must be 1, 2, 4, or 8", n)
              inc n
              if n.hasMore and n.kind == IntLit:
                displacement = int32(getInt(n))
                inc n
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
                if n.hasMore and n.kind == IntLit:
                  # `(mem <base> <stackvar> <disp>)` — a raw byte offset WITHIN the named
                  # slot, folded into the slot's own displacement. This is what lets a
                  # word of a stack aggregate be read/written without first materializing
                  # the aggregate's address in a register: a copy out of a named slot then
                  # costs zero address registers instead of one. The access WIDTH still
                  # comes from the operand's type, so a caller reading a raw eightbyte
                  # wraps this in `(cast (u 64) …)`.
                  #
                  # Bounds-checked against the slot — the one safety a `(cast (aptr T)
                  # <reg>)` access can never have, since the register form has no
                  # object to check against.
                  let extra = getInt(n)
                  let slotSize = asmSizeOf(indexSym.typ)
                  if extra < 0 or extra >= slotSize:
                    error("offset " & $extra & " is outside stack slot '" & indexName &
                          "' (" & $slotSize & " bytes)", n)
                  displacement += int32(extra)
                  inc n
              elif indexSym != nil and indexSym.kind in {skVar, skParam} and
                   indexSym.reg != InvalidTagId:
                # This is the index register (a register-homed local or param —
                # the same {skVar, skParam} convention as every operand path)
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
            base: memBase,
            index: indexReg,
            scale: scale,
            displacement: displacement,
            hasIndex: hasIndex
          )
          # The deref of `(ptr T)` has type T — no special cases (a stack var contributes
          # its own type). `memWidthOpc`/`intMemAccess` size it from T (a sub-word int/bool
          # → a narrow movzx/movsx, e.g. the SSO `(ptr (u 8))` slen byte; everything ≥8
          # bytes → a word); `movCompatible` decides whether T can move to/from the chosen
          # register. A bare register base (no pointer type) is a plain machine word.
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
      # (csize) - call stack argument size
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name [k]) - argument reference in prepare block. Capture the node cursor
      # for diagnostics that run after we've advanced past it. `into` bounds the cursor
      # to the arg's children so the optional word index `k` is read without leaking the
      # following sibling.
      let argTok = n
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", argTok)
      var argName = SymId(0)
      var wordIdx = 0          # selects the k-th register of a ≤16B by-value aggregate arg
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n

      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), argTok)

      if paramPtr.typ.isOnStack:
        # Stack argument - return its byte offset as an immediate. The base offset is
        # the running byte position among the stack-passed params; the optional word
        # index `k` selects the k-th eightbyte of a multi-word stack aggregate (each
        # word is 8 bytes), so a by-value struct that spilled to the stack can be
        # marshalled/read one word at a time the same way a register-passed one is.
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
        # Register argument - return the (word-`wordIdx`) register
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), argTok)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegister(paramPtr.regs[wordIdx], argTok)
        result.typ =
          if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
          else: paramPtr.typ
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
      let resName = getSymId(n)
      inc n

      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", resTok)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & ctx.nameOf(resName), resTok)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), resTok)
      ctx.callContext.resultsSet.incl(resName)

      result.reg = tagToRegister(resPtr.reg, resTok)
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
        result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegister(sym.reg, n)

        # Check if clobbered
        if result.reg in ctx.clobbered and not lenient():
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
      # A thread-local reached through a segment register: `SEG:[sym.offset]`,
      # with the offset allocated in pass2. That is arkham's own FS block on the
      # ELF target; on Windows the only such symbol is the fixed TEB field
      # `arkham.teb.tlsptr.0` (`gs:0x58`), because a PE image's thread-locals
      # live in a loader-allocated block reached THROUGH that field rather than
      # at a fixed segment displacement — see `gsFixedSlot`.
      # RBP as the base is what selects displacement-only addressing.
      if ctx.arch == Arch.WinX64 and not sym.gsFixedSlot:
        # A PE thread-local is NOT at a fixed segment displacement: the loader puts
        # each thread's block wherever it likes and records the address in the TEB,
        # so the producer has to walk there (arkham's `emTvarAddr`) and deref the
        # pointer it gets. Encoding this as `fs:[off]` would read an unrelated
        # address, silently — so it is refused instead of assembled.
        error("thread-local '" & ctx.nameOf(sym.name) &
              "' needs an address-then-deref on win_x64, not a segment operand", n)
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: x86.RBP,  # RBP allows displacement-only addressing
        displacement: int32(sym.offset),
        hasIndex: false,
        seg: (if sym.gsFixedSlot: x86.segGs else: x86.segFs)
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

proc parseDest*(n: var Cursor; ctx: var GenContext;
               allowWidthCast = false): Operand =
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.reg = parseRegister(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings and not lenient():
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
    if result.reg == x86.R11 and not lenient():   # the reserved staging bridge
      error("raw r11 destination: the staging bridge must be a typed (rebind) binding, " &
            "never a bare (reg)", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name [k]) as destination - for register arguments in prepare block. `into`
    # bounds the cursor to the arg's own children so the optional word index `k` is read
    # without leaking the following sibling (the `(mov)` source) into the check.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0                      # selects the k-th register of a ≤16B aggregate arg
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
      error("Stack argument '" & ctx.nameOf(argName) & "' cannot be used directly as destination, use (mem (rsp) (arg " & ctx.nameOf(argName) & "))", n)

    # Track that this argument is being set. A multi-word aggregate fills several words
    # under the same name; count it once (on word 0) so the missing-arg check passes,
    # but allow the later words without a "already set" error.
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)

    # Return the (word-`wordIdx`) register for this argument
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegister(paramPtr.regs[wordIdx], n)
    # A by-value aggregate spread over registers receives a raw 64-bit word per slot,
    # not the whole aggregate — type it as a register so the word `(mov)` type-checks.
    result.typ =
      if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
      else: paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId or
                             n.tag == CastTagId):
    # `(cast T <mem>)` is a legal destination: a cast only retypes an operand, and a
    # memory operand is a legal destination, so retyping one is too. This is how a raw
    # eightbyte is STORED into a named stack slot at an offset — `(cast (u 64) (mem (rsp)
    # v 8))` — where the slot's own declared (aggregate) type would otherwise size the
    # access. `okMem` is still required, so `(cast T (reg))` remains rejected: a register
    # destination must be a typed binding, never a retyped raw register.
    #
    # ONE exception, and only where the instruction opts in (`allowWidthCast` —
    # the ALU family, never `mov`): an explicit SUB-WIDTH int cast over a
    # register destination is a width annotation on the operation, not a
    # retyping — `(add (cast (u 32) (rax)) …)` is a 32-bit add. A 64-bit cast
    # stays rejected everywhere (that is the escape hatch this guard exists
    # for), and `mov` keeps the strict rule so the pointer-store protection
    # cannot be casted away.
    let op = parseOperand(n, ctx)
    if op.kind != okMem and not (allowWidthCast and op.kind == okReg and
                                 op.castBits != 0):
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
       # A thread-local written through a segment register — see the read side for
       # what `gsFixedSlot` selects and why win_x64 refuses the plain form.
       if ctx.arch == Arch.WinX64 and not sym.gsFixedSlot:
         error("thread-local '" & ctx.nameOf(sym.name) &
               "' needs an address-then-deref on win_x64, not a segment operand", n)
       result.kind = okMem
       result.mem = x86.MemoryOperand(
         base: RBP,  # RBP allows displacement-only addressing
         displacement: int32(sym.offset),
         hasIndex: false,
         seg: (if sym.gsFixedSlot: x86.segGs else: x86.segFs)
       )
       result.typ = sym.typ
       inc n
    else:
       if sym == nil:
         # Not in scope — most often because the name's binding ENDED: an explicit
         # `(kill …)`, or a later `(var …)`/`(rebind …)` that took its register and
         # evicted it. That eviction is the point: a read of a value wrongly left in
         # a reused register is an error here rather than a silent clobber at run
         # time. Say which name, or the diagnostic sends the reader hunting.
         error("Unknown variable as destination: '" & name &
               "' — its binding ended (killed, or its register was rebound)", n)
       error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc isXmmOperand*(n: Cursor; ctx: GenContext): bool =
  ## True if `n` denotes an xmm register operand — a raw `(xmmN)` tag or a `Symbol`
  ## naming a float local bound to an xmm register. The float instruction handlers
  ## dispatch on this (reg form vs memory form / movfq direction) so a bound float
  ## local, emitted as its name, is recognized as a register operand.
  if isXmmTag(n): return true
  if n.kind == Symbol:
    let sym = ctx.scope.lookup(getSymId(n))   # float locals are never foreign
    result = sym != nil and sym.reg != InvalidTagId and isXmmTagEnum(sym.reg)

proc parseXmmOperand*(n: var Cursor; ctx: var GenContext): x86.XmmRegister =
  ## Parse an SSE register *operand* in a scalar-float instruction. The SIMD twin
  ## of `parseOperand`'s register arm: a raw `(xmmN)` tag is accepted only if the
  ## register is not bound (a bound register must be named, so the binding checker
  ## sees the use); a `Symbol` is resolved to the xmm register its float local is
  ## bound to. This is how a raw use of a value still live in a bound xmm register
  ## becomes a build error instead of a silent clobber.
  if isXmmTag(n):
    result = tagToXmm(n.tag)
    if result in ctx.xmmBindings:
      error("Register " & $result & " is bound to variable '" &
            ctx.xmmBindings[result] & "', use the variable name instead", n)
    inc n
  elif n.kind == Symbol:
    let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if sym == nil:
      error("Unknown symbol: " & getSym(n), n)
    if sym.reg == InvalidTagId or not isXmmTagEnum(sym.reg):
      error("Expected float register variable, got: " & getSym(n), n)
    result = tagToXmm(sym.reg)
    inc n
  else:
    error("expected xmm register or float variable", n)

proc checkFixedRegFree*(ctx: GenContext; reg: x86.Register; insn: string; n: Cursor) =
  if lenient(): return
  ## A fixed-register instruction (`idiv`/`div` write RDX:RAX) is about to clobber
  ## `reg`. If a live variable is still bound to it, that is a code-generator bug —
  ## the clobber would silently destroy the value. Reject it: the value must be moved
  ## (or the binding `kill`ed / `rebind`ed) first. Without this the raw `(rdx)`/`(rax)`
  ## operands bypass `parseOperand`'s binding check, which is how a live parameter
  ## sitting in RDX/RCX used to be miscompiled in silence.
  if reg in ctx.regBindings:
    error(insn & " clobbers " & $reg & ", still bound to variable '" &
          ctx.regBindings[reg] & "' — move/kill it first", n)

proc leaRegBase*(n: var Cursor; ctx: var GenContext; baseReg: var x86.Register): bool =
  ## Detect and consume a `lea` base register: a raw `(reg)` tag, or a
  ## register-bound local name (a `rebind`'d scratch temp now reaches `lea` by name,
  ## not as a raw reg). Leaves `n` untouched and returns false for any other operand
  ## (label / gvar / mem / dot / at — handled by `parseOperand` instead).
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    baseReg = parseRegister(n); return true
  if n.kind == Symbol:
    let s = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if s != nil and (s.kind == skVar or s.kind == skParam) and
       not s.typ.isOnStack and s.reg != InvalidTagId:
      baseReg = tagToRegister(s.reg, n); inc n; return true
  return false

proc checkDistinctAluRegs*(dest, op: Operand; mnemonic: string; n: Cursor) =
  if lenient(): return
  ## A register `and`/`or`/`sub` whose two operands are the SAME register is never
  ## intentional in arkham's codegen: `x and x == x`, `x or x == x`, `x - x == 0`,
  ## so the real source operand has been dropped — the signature of a staging /
  ## scratch register colliding with the destination (e.g. the set-membership
  ## `setbyte and mask` degrading to `setbyte and setbyte`). nifasm is the strict
  ## checker that must catch such a value-dropping miscompile at assemble time
  ## instead of leaving it to surface at runtime. (`xor`/`test`/`cmp` with equal
  ## registers ARE idioms — zero a register / test for zero — so they are excluded.)
  if dest.kind == okReg and op.kind == okReg and dest.reg == op.reg:
    error("`" & mnemonic & "` with identical register operands (" & $dest.reg &
          ") — dropped source operand (staging/scratch register collided with the " &
          "destination); the value-carrying register must be a distinct typed binding", n)
