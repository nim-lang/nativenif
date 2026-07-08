
import std / [tables]
import tags, x86
import nifcore  # SymId: symbols are keyed by their interned id (main-module pool),
                # not by re-hashing the qualified name string on every lookup.

type
  TypeKind* = enum
    ErrorT, VoidT, BoolT,
    NilT,        # the null-pointer value/type: a 0 that is a *pointer*, compatible with
                 # any pointer (and only pointers — never a sized integer). arkham emits
                 # `(nil)` for a Leng `nil` literal instead of an `(i 64)` 0.
    IntT, UIntT, FloatT, PtrT, AptrT, ArrayT, ObjectT, UnionT,
    RegisterT,   # Pure register usage - accepts any type (effectively untyped)
    StackOffT,   # Stack offset - represents an offset from a base register
    IntLitT,     # Integer literal - compatible with both IntT and UIntT
    ProcT        # Procedure type

  Param* = object
    name*: SymId    # the param symbol's interned id; an `(arg name k)` / `(res name k)`
                    # reference is the SAME interned symbol, so matching is id equality
    typ*: Type      # If kind == StackOffT, param is on stack
    reg*: TagEnum   # the param's first (often only) register; == regs[0] when regs.len > 0
    regs*: seq[TagEnum]
      ## All registers a register-passed param occupies. A scalar/pointer/float param
      ## has exactly one; a ≤16B by-value aggregate spans several (one per eightbyte,
      ## e.g. rdi+rsi). Empty for a stack-passed param (`typ.isOnStack`). `(arg name k)`
      ## / `(res name k)` select the k-th register.
    viaRegs*: bool
      ## True when the location was spelled `(regs …)` (an aggregate param consumed
      ## RAW by the code generator — it moves the incoming registers into its own home).
      ## Such a param is ABI-only: it is NOT entered into `regBindings`, so a raw
      ## `(reg)` use of its register(s) in the body stays legal. A scalar/pointer/float
      ## `(reg)` param has `viaRegs == false` and IS bound to its name.

  Type* = ref object
    case kind*: TypeKind
    of ErrorT, VoidT, BoolT, NilT: discard
    of IntT, UIntT, FloatT, IntLitT: bits*: int
    of PtrT, AptrT:
      base*: Type
      baseName*: string  ## The pointee's qualified type name (its nominal
                         ## identity), for a symbol pointee — empty for a
                         ## structural one (`(ptr (i 32))`). Used for strict,
                         ## name-based pointer compatibility. When `base` is nil
                         ## the type isn't defined yet (a forward reference, e.g.
                         ## a pointer whose pointee is declared later in the same
                         ## still-loading module); it is then resolved & memoized
                         ## into `base` on first structural use.
    of ArrayT:
      elem*: Type
      len*: int64
    of ObjectT, UnionT:
      fields*: seq[(string, Type, int)]  ## name, type, byte offset within the
                                         ## object/union. Inherited fields (from a
                                         ## base object) appear first, carrying
                                         ## their base offsets; own fields follow,
                                         ## starting at `sizeof(base)`.
      size*: int
      align*: int
    of RegisterT:
      regBits*: int  # Size in bits (e.g., 64 for general purpose regs)
    of StackOffT:
      offType*: Type  # The underlying type at this stack location
    of ProcT:
      params*: seq[Param]
      results*: seq[Param]
      clobbers*: set[Register]

  TypeDuo* = object
    want*, got*: Type

  SymKind* = enum
    skUnknown, skType, skVar, skParam, skProc, skLabel, skRodata, skGvar, skTvar, skCfvar, skExtProc,
    skSysProc   ## a Linux syscall: a proctype (params in syscall ABI regs, result, clobbers)
                ## plus a syscall number (stored in `offset`); invoked inline via `(syscall)`/`(svc)`

  Symbol* = ref object
    name*: SymId      # interned identity in the main-module pool; render with
                      # `poolSym(pool, sym.name)` where a string is genuinely needed
                      # (foreign index lookup, dedup, diagnostics, extern emission).
    kind*: SymKind
    typ*: Type        # For procs, this is ProcT; for vars/params, the data type (StackOffT if on stack)
    # Storage
    reg*: TagEnum     # For var/param in register (e.g. RaxTagId)
    offset*: int      # Stack offset, label position, or field offset
    size*: int        # For stack slots
    dataConst*: bool  # skRodata only: this `const` blob has symbol-pointer fields
                      # (`(reloc ...)`), so it must live in writable __DATA and be
                      # rebased by dyld at load (Mach-O). Plain consts stay in __TEXT.

    # Control flow variable tracking
    used*: bool       # For cfvar: has it been used in an ite?

    # Module system
    isForeign*: bool  # True if this symbol comes from a foreign module
    # name field stores the full qualified name (foo.0.moduleSuffix)
    # Use symBasename() to get the lookup key
    isReachable*: bool # True if symbol is reachable from an entry point
    isEntryPoint*: bool # True if this is an entry point (exported)
    moduleName*: string # Module this symbol belongs to (for finding its TokenBuf)
    declStart*: int # Position in module's TokenBuf where declaration starts

    # External proc info (for skExtProc)
    libName*: string  # Library name (e.g. "libSystem.B.dylib")
    extName*: string  # External symbol name (e.g. "_write")
    stubOffset*: int  # Offset into stub section
    gotSlot*: int     # GOT slot index for this symbol

  Scope* = ref object
    parent*: Scope
    syms*: Table[SymId, Symbol]

proc newScope*(parent: Scope = nil): Scope =
  Scope(parent: parent, syms: initTable[SymId, Symbol]())

proc lookup*(s: Scope; name: SymId): Symbol =
  # NIF symbols are nominal: the key is the FULL qualified name's interned id (the
  # main-module pool assigns one id per distinct qualified name, so `foo.0.modA`
  # and `foo.0.modB` are distinct ids — there is no "basename clash"). Comparing
  # interned ids replaces re-hashing the qualified string on every reference.
  var curr = s
  while curr != nil:
    let hit = curr.syms.getOrDefault(name)
    if hit != nil: return hit
    curr = curr.parent
  return nil

proc define*(s: Scope; sym: Symbol) =
  s.syms[sym.name] = sym

proc undefine*(s: Scope; name: SymId) =
  s.syms.del(name)

proc isOnStack*(t: Type): bool {.inline.} =
  ## Returns true if this type represents a stack location
  t != nil and t.kind == StackOffT

proc asmAlignOf*(t: Type): int =
  ## Returns the alignment requirement of a type in bytes
  case t.kind
  of ErrorT, VoidT: 1
  of BoolT: 1
  of NilT: 8 # a pointer-sized null
  of IntT, UIntT, FloatT, IntLitT:
    let size = t.bits div 8
    # Alignment is typically the size, but capped at 8 for x86-64
    if size <= 8: size else: 8
  of PtrT, AptrT: 8 # x86-64 pointer alignment
  of ArrayT: asmAlignOf(t.elem)
  of ObjectT, UnionT: t.align
  of RegisterT: t.regBits div 8
  of StackOffT: asmAlignOf(t.offType)
  of ProcT: 8 # Function pointers are 8 bytes on x86-64

proc alignTo*(offset, alignment: int): int =
  ## Align offset up to the next multiple of alignment
  (offset + alignment - 1) and not (alignment - 1)

proc asmSizeOf*(t: Type): int =
  case t.kind
  of ErrorT, VoidT: 0
  of BoolT: 1
  of NilT: 8 # a pointer-sized null
  of IntT, UIntT, FloatT, IntLitT: t.bits div 8
  of PtrT, AptrT: 8 # x86-64
  of ArrayT: t.len.int * asmSizeOf(t.elem)
  of ObjectT, UnionT: t.size
  of RegisterT: t.regBits div 8
  of StackOffT: asmSizeOf(t.offType)
  of ProcT: 8 # Function pointers are 8 bytes on x86-64

proc `$`*(t: Type): string =
  case t.kind
  of ErrorT: "error"
  of VoidT: "void"
  of BoolT: "bool"
  of NilT: "nil"
  of IntT: "(i " & $t.bits & ")"
  of UIntT: "(u " & $t.bits & ")"
  of FloatT: "(f " & $t.bits & ")"
  of IntLitT: "(lit " & $t.bits & ")"
  of PtrT: "(ptr " & (if t.base != nil: $t.base else: t.baseName) & ")"
  of AptrT: "(aptr " & (if t.base != nil: $t.base else: t.baseName) & ")"
  of ArrayT: "(array " & $t.elem & " " & $t.len & ")"
  of ObjectT: "object" # Simplified
  of UnionT: "union" # Simplified
  of RegisterT: "(reg " & $t.regBits & ")"
  of StackOffT: "(stackoff " & $t.offType & ")"
  of ProcT: "(proc " & $t.params.len & " params)"

proc compatible*(want, got: Type): bool =
  if want == got: return true
  # RegisterT is lenient - accepts/provides any type that fits
  if want.kind == RegisterT:
    result = asmSizeOf(got) <= (want.regBits div 8)
    return
  if got.kind == RegisterT:
    result = asmSizeOf(want) <= (got.regBits div 8)
    return
  case want.kind
  of ErrorT, VoidT:
    result = got.kind == want.kind
  of BoolT:
    # A bool is a 0/1 integer: an integer LITERAL (e.g. the `0` in the canonical
    # `cmp boolReg, 0` "if bool" test) is compatible with it. Still strict against
    # sized int/uint/ptr/etc. — only the literal adapts.
    result = got.kind == BoolT or got.kind == IntLitT
  of NilT:
    # `nil` is the null pointer. It compares/assigns with ANY pointer (the universal
    # `cmp ptr, nil` / `mov ptr, nil`) and with itself, and adapts from a `0` literal
    # (a materialized nil register `mov nilReg, 0`). NEVER compatible with a sized
    # integer — that is the whole point: a `cmp i64reg, ptr` mixup stays an error.
    result = got.kind in {NilT, PtrT, AptrT, IntLitT}
  of IntT, UIntT:
    # Same-WIDTH integers are interchangeable regardless of signedness: the bits are
    # identical, and every operation where signedness matters (idiv/div, sar/shr, the
    # ordered compares) selects signed-vs-unsigned by its INSTRUCTION, not by the operand
    # type. So `i64`↔`u64` (e.g. `or i64, u64`) and an integer literal of the same width
    # all match. (Sub-word width still matters: it sets the access/extend size.)
    result = got.kind in {IntT, UIntT, IntLitT} and want.bits == got.bits
  of IntLitT:
    # Literal is compatible with IntT, UIntT, or another literal of same size, with
    # bool (the `cmp boolReg, 0` test, operands either order), and with a pointer (the
    # `cmp ptr, 0` / nil test — only the *literal* adapts; a sized int reg stays
    # strictly incompatible with a pointer). See the PtrT/AptrT arm for the mirror.
    result = (got.kind in {IntT, UIntT, IntLitT, BoolT} and (got.kind == BoolT or want.bits == got.bits)) or
             got.kind in {PtrT, AptrT}
  of FloatT:
    result = got.kind == want.kind and want.bits == got.bits
  of PtrT, AptrT:
    if got.kind in {IntLitT, NilT}:
      # An integer LITERAL (in practice `0`) or an explicit `(nil)` is compatible with
      # a pointer: the universal `cmp ptr, 0`/`cmp ptr, nil` null test, `mov ptr, nil`
      # init. Only the literal/nil adapts — a SIZED int reg vs a pointer is still
      # rejected (strict typing).
      result = true
    elif got.kind != want.kind:
      result = false
    elif want.base != nil and got.base != nil:
      # Both pointees structurally resolved — compare structurally.
      result = compatible(want.base, got.base)
    else:
      # A lazily-recorded pointee isn't structurally available, but Leng types are
      # nominal: a pointer's pointee identity is its qualified type NAME, so compare
      # those (strict — NOT a blanket "any same-kind pointer is compatible").
      result = want.baseName == got.baseName
  of ArrayT:
    result = got.kind == want.kind and want.len == got.len and compatible(want.elem, got.elem)
  of ObjectT, UnionT:
    result = false # use pointer equivalence for now
  of RegisterT:
    discard # already handled above
  of StackOffT:
    # StackOffT is compatible if the underlying types are compatible
    result = got.kind == StackOffT and compatible(want.offType, got.offType)
  of ProcT:
    # ProcT compatibility: same number of params/results and compatible types
    if got.kind != ProcT: return false
    if want.params.len != got.params.len: return false
    if want.results.len != got.results.len: return false
    for i in 0..<want.params.len:
      if not compatible(want.params[i].typ, got.params[i].typ): return false
    for i in 0..<want.results.len:
      if not compatible(want.results[i].typ, got.results[i].typ): return false
    result = true
