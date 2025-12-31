
import std / [tables]
import instructions, x86

type
  TypeKind* = enum
    ErrorT, VoidT, BoolT, IntT, UIntT, FloatT, PtrT, AptrT, ArrayT, ObjectT, UnionT,
    RegisterT,   # Pure register usage - accepts any type (effectively untyped)
    StackOffT    # Stack offset - represents an offset from a base register

  Type* = ref object
    case kind*: TypeKind
    of ErrorT, VoidT, BoolT: discard
    of IntT, UIntT, FloatT: bits*: int
    of PtrT, AptrT: base*: Type
    of ArrayT:
      elem*: Type
      len*: int64
    of ObjectT, UnionT:
      fields*: seq[(string, Type)]
      size*: int
      align*: int
    of RegisterT:
      regBits*: int  # Size in bits (e.g., 64 for general purpose regs)
    of StackOffT:
      offType*: Type  # The underlying type at this stack location

  TypeDuo* = object
    want*, got*: Type

  SymKind* = enum
    skUnknown, skType, skVar, skParam, skProc, skLabel, skRodata, skGvar, skTvar, skCfvar, skExtProc

  Param* = object
    name*: string
    typ*: Type
    reg*: TagEnum
    onStack*: bool

  Signature* = ref object
    params*: seq[Param]
    result*: seq[Param]
    clobbers*: set[Register]

  Symbol* = ref object
    name*: string
    kind*: SymKind
    typ*: Type
    # Storage
    reg*: TagEnum     # For var/param in register (e.g. RaxTagId)
    onStack*: bool    # True if (s)
    offset*: int      # Stack offset, label position, or field offset
    size*: int        # For stack slots

    # Proc specific
    sig*: Signature

    # Control flow variable tracking
    used*: bool       # For cfvar: has it been used in an ite?

    # Foreign module tracking
    isForeign*: bool  # True if this symbol comes from a foreign module

    # External proc info (for skExtProc)
    libName*: string  # Library name (e.g. "libSystem.B.dylib")
    extName*: string  # External symbol name (e.g. "_write")
    stubOffset*: int  # Offset into stub section
    gotSlot*: int     # GOT slot index for this symbol

  Scope* = ref object
    parent*: Scope
    syms*: Table[string, Symbol]

proc newScope*(parent: Scope = nil): Scope =
  Scope(parent: parent, syms: initTable[string, Symbol]())

proc lookup*(s: Scope; name: string): Symbol =
  var curr = s
  while curr != nil:
    if name in curr.syms: return curr.syms[name]
    curr = curr.parent
  return nil

proc define*(s: Scope; sym: Symbol) =
  s.syms[sym.name] = sym

proc undefine*(s: Scope; name: string) =
  s.syms.del(name)

proc asmAlignOf*(t: Type): int =
  ## Returns the alignment requirement of a type in bytes
  case t.kind
  of ErrorT, VoidT: 1
  of BoolT: 1
  of IntT, UIntT, FloatT:
    let size = t.bits div 8
    # Alignment is typically the size, but capped at 8 for x86-64
    if size <= 8: size else: 8
  of PtrT, AptrT: 8 # x86-64 pointer alignment
  of ArrayT: asmAlignOf(t.elem)
  of ObjectT, UnionT: t.align
  of RegisterT: t.regBits div 8
  of StackOffT: asmAlignOf(t.offType)

proc alignTo*(offset, alignment: int): int =
  ## Align offset up to the next multiple of alignment
  (offset + alignment - 1) and not (alignment - 1)

proc asmSizeOf*(t: Type): int =
  case t.kind
  of ErrorT, VoidT: 0
  of BoolT: 1
  of IntT, UIntT, FloatT: t.bits div 8
  of PtrT, AptrT: 8 # x86-64
  of ArrayT: t.len.int * asmSizeOf(t.elem)
  of ObjectT, UnionT: t.size
  of RegisterT: t.regBits div 8
  of StackOffT: asmSizeOf(t.offType)

proc `$`*(t: Type): string =
  case t.kind
  of ErrorT: "error"
  of VoidT: "void"
  of BoolT: "bool"
  of IntT: "(i " & $t.bits & ")"
  of UIntT: "(u " & $t.bits & ")"
  of FloatT: "(f " & $t.bits & ")"
  of PtrT: "(ptr " & $t.base & ")"
  of AptrT: "(aptr " & $t.base & ")"
  of ArrayT: "(array " & $t.elem & " " & $t.len & ")"
  of ObjectT: "object" # Simplified
  of UnionT: "union" # Simplified
  of RegisterT: "(reg " & $t.regBits & ")"
  of StackOffT: "(stackoff " & $t.offType & ")"

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
  of ErrorT, VoidT, BoolT:
    result = got.kind == want.kind
  of IntT, UIntT:
    result = got.kind in {IntT, UIntT} and want.bits == got.bits
  of FloatT:
    result = got.kind == want.kind and want.bits == got.bits
  of PtrT, AptrT:
    result = got.kind == want.kind and compatible(want.base, got.base)
  of ArrayT:
    result = got.kind == want.kind and want.len == got.len and compatible(want.elem, got.elem)
  of ObjectT, UnionT:
    result = false # use pointer equivalence for now
  of RegisterT:
    discard # already handled above
  of StackOffT:
    # StackOffT is compatible if the underlying types are compatible
    result = got.kind == StackOffT and compatible(want.offType, got.offType)
