#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF's type rules: what may be moved into what, what may be compared,
## added, masked or exchanged, and how a sub-word integer reaches memory.
##
## These are the checks the instruction selectors call before they encode
## anything, and they take no `GenContext` — the only run state they consult is
## `diagnostics.lenient()`, the `(lenient)` pragma of the proc being assembled.
## That is what keeps them a leaf module three selectors can share.

import nifcore
import sem, context, diagnostics

proc addrWidthMove(a, b: Type): bool {.inline.} =
  ## A pointer — a function pointer (`ProcT`), a data pointer (`PtrT`/`AptrT`) — is an
  ## 8-byte address. Moving it to/from a general 64-bit register, an integer, or
  ## another pointer is a plain address move: loading an indirect-call target or a
  ## pointer field, storing a function's address into a fn-ptr slot, or — pervasive in
  ## arkham's value core — holding a pointer value in a generic `i64` scalar register.
  ## All representationally identical (8 bytes), so accept it in either direction. (A
  ## genuinely narrowing access stays caught by the sized memory-access path.)
  if a == nil or b == nil: return false
  const PtrLike = {ProcT, PtrT, AptrT}
  const AddrLike = {ProcT, PtrT, AptrT, IntT, UIntT}
  (a.kind in PtrLike and b.kind in AddrLike) or (b.kind in PtrLike and a.kind in AddrLike)

proc litFitsWidth(v: int64; bits: int): bool {.inline.} =
  ## Does integer literal `v` fit a `bits`-wide destination, read as either
  ## signed or unsigned? (`0..2^bits-1` ∪ `-2^(bits-1)..-1`.) Both readings are
  ## the same bit pattern in the same register, and which one a value "is" is the
  ## instruction's business, not the literal's.
  if bits >= 64: return true
  v >= -(1'i64 shl (bits - 1)) and v <= (1'i64 shl bits) - 1

proc movCompatible*(want, got: Type): bool =
  ## Type rule for `mov`: strict compatibility, OR a *widening* integer move —
  ## a smaller integer into a larger register (a safe extending move/load).
  ## Narrowing or a kind change (int↔ptr/float) is still rejected.
  if compatible(want, got): return true
  if addrWidthMove(want, got): return true
  # A `mov` to/from a stack slot named directly (`(mov stackvar value)` stores,
  # `(mov reg stackvar)` loads) targets the slot's *content* type, so re-check against
  # the unwrapped element type on either side. (Previously the register operand was
  # always a raw register — lenient `RegisterT`, compatible with any slot — but a
  # `rebind`-bound scratch carries its concrete type, e.g. `(i 64)`.)
  # Re-run `addrWidthMove` after the unwrap too: a caller-save spill of a pointer
  # (`(mov (s)(ptr T) slot, i64-bound-name)` / the restore) is an address-width move
  # through a `StackOffT` wrapper, and the pre-unwrap check sees `StackOffT` which
  # is neither PtrLike nor AddrLike.
  var w = want
  var g = got
  if w.kind == StackOffT: w = w.offType
  if g.kind == StackOffT: g = g.offType
  if compatible(w, g): return true
  if addrWidthMove(w, g): return true
  if w.kind in {IntT, UIntT} and g.kind == IntLitT:
    # A literal carries no width of its own — `parseOperand` types every one as
    # `(lit 64)` — so judge it by its VALUE: it fits when the destination width
    # holds the bit pattern under EITHER reading. `(u 32) ← 2400959708`
    # (0x8F1BBCDC, a SHA-1 round constant) is a plain 32-bit store; so is
    # `(u 32) ← -1`. Only a literal too wide for the destination is narrowing.
    return litFitsWidth(g.litVal, w.bits)
  if w.kind in {IntT, UIntT} and g.kind in {IntT, UIntT}:
    return g.bits <= w.bits
  result = false

proc isIntegerType*(t: Type): bool =
  ## Check if type is an integer type (int, uint, literal) or a register (which is untyped)
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}

proc isFloatType(t: Type): bool =
  ## Check if type is a floating point type
  t.kind == TypeKind.FloatT

proc canDoIntegerArithmetic(t: Type): bool =
  ## May `t` be an operand of `add`/`sub`/`neg`? Integers, integer literals and raw
  ## (untyped) registers — no pointer of any kind.
  ##
  ## `(aptr T)` used to be admitted here as "pointer arithmetic". It is not a legal
  ## Leng form: an `add` says nothing about whether the offset counts BYTES or
  ## ELEMENTS, and the two backends answered differently — nifasm emitted a plain
  ## machine `add` (bytes) while lengc's C output read the same node as scaled C
  ## pointer arithmetic (elements). Offsetting an array pointer is `(at base index)`,
  ## which takes the element type and therefore has one meaning; raw byte work casts
  ## to an integer and back. arkham rejects such a node before it ever gets here
  ## (`checkArithResultType`); this is the assembler's own backstop, and it also
  ## covers hand-written asm-NIF.
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}

proc canCompare(t: Type): bool =
  ## Check if a type may be a `cmp` operand. A superset of integer arithmetic:
  ## any pointer (a comparison, not arithmetic) and — crucially — `bool`, since a
  ## bool is a 0/1 integer and `cmp reg, 0` is the canonical "if bool" test. This is
  ## deliberately SEPARATE from `canDoIntegerArithmetic` (which add/sub share and
  ## must stay strict — adding/subtracting bools is nonsense).
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT,
             TypeKind.PtrT, TypeKind.AptrT, TypeKind.RegisterT, TypeKind.BoolT,
             TypeKind.NilT}  # `cmp ptr, nil` / `cmp nil, ptr` null tests

proc canDoBitwiseOps(t: Type): bool =
  ## May `t` be an operand of `and`/`or`/`xor`/`not`? Integers, literals, raw
  ## registers — and `bool`, for the same reason `canCompare` admits it: a bool is
  ## an 8-bit 0/1 integer, and masking one is meaningful. `and reg, 1` after a
  ## `setcc` is what ESTABLISHES the 0/1 invariant (the byte write leaves the rest
  ## of the register alone), so rejecting it rejected the very sequence that makes a
  ## bool a bool — `arc/t24764` and 74 other native tests died on it.
  ##
  ## Pointers stay out: there is no bit pattern of a pointer a code generator has
  ## business masking without saying so through a cast.
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT,
             TypeKind.BoolT}

proc canExchange(t: Type): bool =
  ## Check if a type may be an `xchg` operand: any register-sized scalar — integer
  ## OR pointer. `xchg` swaps 8 bytes irrespective of the logical type, and an atomic
  ## pointer exchange (lock-free list head swap) is a legitimate, common use. Like
  ## `canCompare`, this is SEPARATE from the arithmetic check (which stays strict).
  ##
  ## `bool` is included. It was once excluded as "swapping a bool through a
  ## pointer is nonsense", but an atomic flag byte is the plainest use an atomic
  ## exchange has — `std/threadpool`'s `stopFlag` is one, and so is every
  ## test-and-set — and a Leng `bool` is a one-byte unsigned value, which is
  ## exactly what the byte-width `xchg` operates on.
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT,
             TypeKind.PtrT, TypeKind.AptrT, TypeKind.RegisterT}

proc checkPtrStore*(dest: Type; srcKind: OperandKind; srcTyp: Type; n: Cursor) =
  if lenient(): return
  ## A `mov` STORES, so it can leave a pointer-typed name holding a non-pointer. The
  ## only integer literals that may be stored into a pointer are `0` and `(nil)`; any
  ## other is a type error. Arch-neutral: both `genMovX64` and the a64 `mov` call it.
  ##
  ## `compatible` cannot make this call, because it also serves COMPARISON, where a
  ## pointer against an arbitrary literal is legitimate — `cmp result, -1` is mmap's
  ## MAP_FAILED test. A compare writes nothing and so cannot corrupt a binding; a store
  ## can. Conflating the two is what left `(mov <ptr-bound name> 32)` assembling
  ## silently: exactly the shape a code generator's stale register binding produces,
  ## which made that whole bug class invisible unless the bad value happened to reach an
  ## instruction carrying its own type rule (`shl`).
  if dest == nil or srcTyp == nil or srcKind != okImm: return
  if srcTyp.kind != TypeKind.IntLitT or srcTyp.litVal == 0: return
  var d = dest
  if d.kind == StackOffT: d = d.offType
  if d.kind in {TypeKind.PtrT, TypeKind.AptrT, TypeKind.ProcT}:
    error("cannot store the non-zero integer " & $srcTyp.litVal &
          " into the pointer-typed destination " & $d & " (only 0 / (nil) may be)", n)

proc intMemAccess*(typ: Type): tuple[bits: int; signed: bool] =
  ## A typed memory operand's access width + signedness, so a sub-word field /
  ## element load sign-/zero-extends and a narrow store writes only its low bits.
  ## Pointers / raw `(mem reg)` are full 64-bit accesses.
  ##
  ## A STACK SLOT is its content type behind a `(stackoff …)` wrapper: unwrap it and
  ## size the access by what the slot HOLDS, exactly as the a64 twin `memWidthOpc`
  ## does. A slot always occupies 8 bytes, so this is not about layout — it is what
  ## makes a narrow local's home behave like the variable it is, instead of reading
  ## back the seven bytes above it.
  if typ == nil: return (64, false)
  var t = typ
  if t.kind == StackOffT and t.offType != nil: t = t.offType
  case t.kind
  of IntT: (t.bits, true)
  of UIntT: (t.bits, false)
  of BoolT: (8, false)
  else: (64, false)

proc movTypeOk*(destKind: OperandKind; destTyp: Type;
               opKind: OperandKind; opTyp: Type): bool =
  ## THE type rule for `mov`, shared by `genMovX64` and the a64 `MovA64` arm so the
  ## two arches accept exactly the same programs. Both used to carry their own
  ## spelling of it and had drifted: only x86-64 admitted the narrowing `(arg …)`
  ## store below, so the same arkham output was legal on one target and a type error
  ## on the other.
  ##
  ## The rule is kind-aware on purpose. A register operand's declared type never
  ## reaches the encoder — a reg↔reg `mov` emits the full-width form either way, and
  ## only a MEMORY operand sizes its access (`intMemAccess` / `memWidthOpc`). So the
  ## width pairings that are safe depend on where the operands live, not just on what
  ## they are:
  ##
  ## * `sizedMemReg` — exactly one side is memory: a load into a 64-bit register
  ##   sign-/zero-extends a narrower field, and a store writes only the low bits. Any
  ##   width pairing is fine; the sized emit does the work.
  ## * `movCompatible` — the strict core: same width (either signedness), a widening
  ##   integer move, a literal that fits by value, the address-width family, and the
  ##   `StackOffT` unwrap for slots named directly.
  ## * `narrowingArg` — a wider value into a NARROWER call argument is the ABI
  ##   truncation C also performs: the callee reads only the low `param.bits` of the
  ##   argument register, which a plain 64-bit mov already leaves correct.
  ##
  ## Everything else stays an error. In particular a narrowing move into a plain
  ## register or variable (`okReg`) is NOT accepted — that is what catches binding an
  ## `i64` call result to a `u8` var (`result_type_mismatch`), and legitimate typed
  ## narrowing in source always carries an explicit `(conv)`.
  if destTyp == nil or opTyp == nil: return true
  proc isIntLike(t: Type): bool =
    ## A STACK SLOT holding an integer is sized integer memory like any `(dot …)` or
    ## `(at …)`: the emit unwraps the `(stackoff …)` and picks the access width from
    ## the content type, so the pairing is as safe here as it is there.
    var u = t
    if u.kind == StackOffT and u.offType != nil: u = u.offType
    u.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.BoolT, TypeKind.IntLitT}
  let sizedMemReg = (destKind == okMem) != (opKind == okMem) and
                    isIntLike(destTyp) and isIntLike(opTyp)
  if sizedMemReg: return true
  if movCompatible(destTyp, opTyp): return true
  let narrowingArg = destKind == okArg and opKind != okMem and
                     destTyp.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.BoolT} and
                     opTyp.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT} and
                     opTyp.bits > intMemAccess(destTyp).bits
  result = narrowingArg

proc checkType(want, got: Type; n: Cursor) =
  if lenient(): return
  if not compatible(want, got):
    typeError(want, got, n)

proc checkIntegerArithmetic*(t: Type; op: string; n: Cursor) =
  if lenient(): return
  if not canDoIntegerArithmetic(t):
    # NOT "integer or pointer": `canDoIntegerArithmetic` admits no pointer of any
    # kind, and saying otherwise sends the reader looking for which pointer was
    # meant. Name the two legal spellings instead — that is what the producer has
    # to change to.
    error("Operation '" & op & "' requires an integer type, got " & $t &
          " — Leng has no arithmetic on pointers: offset an array pointer with " &
          "`(at …)`/`(pat …)`, or cast to an integer, compute, and cast back", n)

proc checkComparable*(t: Type; op: string; n: Cursor) =
  if lenient(): return
  if not canCompare(t):
    error("Operation '" & op & "' requires a comparable type, got " & $t, n)

proc checkIntegerType*(t: Type; op: string; n: Cursor) =
  if lenient(): return
  if not isIntegerType(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkExchangeType*(t: Type; op: string; n: Cursor) =
  if not canExchange(t):
    error("Operation '" & op & "' requires an integer or pointer type, got " & $t, n)

proc checkFloatType(t: Type; op: string; n: Cursor) =
  if not isFloatType(t):
    error("Operation '" & op & "' requires floating point type, got " & $t, n)

proc checkBitwiseType*(t: Type; op: string; n: Cursor) =
  if lenient(): return
  if not canDoBitwiseOps(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkCompatibleTypes*(t1, t2: Type; op: string; n: Cursor) =
  ## Check that two operands have compatible types for an operation
  if not compatible(t1, t2):
    error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkCmpCompatible*(t1, t2: Type; n: Cursor) =
  if lenient(): return
  ## Compatibility rule for `cmp` — looser than arithmetic. Two SIZED integers of
  ## ANY width/signedness compare fine (x86 `cmp` runs at register width; a `u32`
  ## value vs an `i64` constant is a perfectly valid comparison — arkham computes
  ## integers in 64-bit registers). Pointers stay strict (governed by `compatible`:
  ## ptr-vs-ptr or ptr-vs-literal only), so an int-vs-pointer mixup is still caught.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation 'cmp' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkBitwiseCompatible*(t1, t2: Type; op: string; n: Cursor) =
  if lenient(): return
  ## Compatibility rule for `and`/`or`/`xor` — looser than arithmetic, like `cmp`. Two
  ## SIZED integers of ANY width/signedness combine fine: bitwise ops run at register
  ## width on both x86 and AArch64, and arkham canonicalizes integers in 64-bit
  ## registers, so e.g. `i64 and u32` is valid. It emits exactly that for a widening
  ## `conv` over a narrow bitwise expression: the operation runs in the (already
  ## 64-bit-bound) destination register and a following `lsl`/`asr` pair re-extends.
  ## Non-integer kinds (pointers) stay strict via `compatible`.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkArithCompatible*(t1, t2: Type; op: string; n: Cursor) =
  if lenient(): return
  ## Compatibility rule for `add`/`sub` — same as `cmp`/bitwise, on x86 and AArch64
  ## alike: two SIZED integers of ANY width/signedness add fine, because arkham
  ## canonicalizes every integer into a full 64-bit register (a narrow load is
  ## zero/sign-extended), so the op runs at register width and `i64 + u32` (e.g. an
  ## `int` index plus a `uint32` hash) is valid.
  ## A pointer keeps the strict `compatible` rule (ptr+int is handled by callers that
  ## permit it), so an int-vs-pointer mixup is still caught.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)
