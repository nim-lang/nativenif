
import std / [tables]
import instructions, x86

type
  TypeKind* = enum
    ErrorT, VoidT, BoolT, IntT, UIntT, FloatT, PtrT, AptrT, ArrayT, ObjectT, UnionT

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

proc compatible*(want, got: Type): bool =
  if want == got: return true
  if want.kind == ErrorT or got.kind == ErrorT: return true # prevent cascading errors
  if want.kind == VoidT and got.kind == VoidT: return true
  if want.kind == BoolT and got.kind == BoolT: return true
  if want.kind == IntT and got.kind == IntT: return want.bits == got.bits
  if want.kind == UIntT and got.kind == UIntT: return want.bits == got.bits
  if want.kind == FloatT and got.kind == FloatT: return want.bits == got.bits
  if want.kind == PtrT and got.kind == PtrT: return compatible(want.base, got.base)
  if want.kind == AptrT and got.kind == AptrT: return compatible(want.base, got.base)
  if want.kind == ArrayT and got.kind == ArrayT:
    return want.len == got.len and compatible(want.elem, got.elem)
  # Object and union structural equivalence or name based?
  # Using reference equality for now (assuming unique type objects per declaration)
  # If we want structural:
  if want.kind == ObjectT and got.kind == ObjectT:
    # For now, just check size or ref equality
    return want == got
  if want.kind == UnionT and got.kind == UnionT:
    # For now, just check size or ref equality
    return want == got
  return false
