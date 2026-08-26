#
#           Arkham — AVR asm-NIF emission primitives
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The layer that knows AVR's shape: a `Reg` is a PAIR, every ALU instruction
## works on one 8-bit HALF of one, and a 16-bit operation is therefore two nodes
## with a carry between them. Everything above this file works in pairs and never
## writes a half itself.
##
## **Naming a half.** A pair bound to a local is spelled `(lo x)` / `(hi x)` —
## by NAME, so nifasm's binding table can check it. Spelling `(r25)` raw instead
## would be rejected, and rightly: the table cannot tell that the register is the
## top of some local. An unbound pair (a bridge) is spelled raw, which is exactly
## the claim `rawReg`'s doc comment describes.

import std / [tables]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, regbind, diag]
import machine

# ── operands ────────────────────────────────────────────────────────────────

proc emPair*(g: var CodeGen; r: Reg) =
  ## A whole 16-bit value: the local's name when one lives here, the raw `(rpN)`
  ## otherwise. `movw`, `adiw` and `sbiw` are the instructions that take one.
  let nm = g.rb.boundName(r)
  if nm.len > 0: g.ab.sym nm
  else:
    # Legitimately raw: the three bridges, the frame pointer, the ABI argument
    # and return pairs, and `mul`'s fixed r1:r0 — which no value can ever be
    # bound to, since the instruction writes it whether or not anything asked.
    assert r in {ValueBridge, StagingBridge, ProduceBridge, Y, MulResult} or
           r in g.md.intArgRegs or r == g.md.intRetReg,
      "arkham avr: unbound pair reached emPair: " & regName(r) &
      " in " & g.curProcName
    g.ab.rawReg r

proc emHalf(g: var CodeGen; r: Reg; high: bool) =
  let nm = g.rb.boundName(r)
  if nm.len > 0:
    g.ab.tree (if high: HiX else: LoX): g.ab.sym nm
  else:
    g.ab.regNamed (if high: highName(r) else: lowName(r))

proc emLo*(g: var CodeGen; r: Reg) = g.emHalf(r, high = false)
proc emHi*(g: var CodeGen; r: Reg) = g.emHalf(r, high = true)

proc ldiOk*(r: Reg): bool {.inline.} = ord(r) >= ord(P16)
  ## Whether `ldi` reaches this pair at all. r0..r15 are simply not encodable in
  ## the immediate forms — the register field is four bits and biased by 16, so a
  ## low register does not fail to encode, it encodes as a DIFFERENT one.

# ── moves and constants ─────────────────────────────────────────────────────

proc emMovw*(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovwAvr: (g.emPair d; g.emPair s)

proc emLdi16*(g: var CodeGen; d: Reg; v: int64) =
  ## A 16-bit constant into a pair. Two `ldi`s where the pair can take them; a
  ## staging `movw` through the value bridge where it cannot, which is every
  ## callee-saved pair on this machine.
  if ldiOk(d):
    g.ab.tree LdiAvr: (g.emLo d; g.ab.intLit(v and 0xFF))
    g.ab.tree LdiAvr: (g.emHi d; g.ab.intLit((v shr 8) and 0xFF))
  else:
    g.ab.tree LdiAvr: (g.emLo ValueBridge; g.ab.intLit(v and 0xFF))
    g.ab.tree LdiAvr: (g.emHi ValueBridge; g.ab.intLit((v shr 8) and 0xFF))
    g.emMovw(d, ValueBridge)

# ── frame slots ─────────────────────────────────────────────────────────────
# A slot is reached as `Y+q`, and only as `Y+q`: SP lives in the I/O space and
# cannot address memory at all. nifasm computes q from the slot's own offset —
# its number, not ours — and the `+1` for the high byte rides in the SAME
# instruction's displacement field, so both halves are one `ldd`/`std` each.

proc emLoadSlot*(g: var CodeGen; d: Reg; name: string) =
  g.ab.tree LdbAvr: (g.emLo d; g.ab.sym name)
  g.ab.tree LdbAvr:
    g.emHi d
    g.ab.tree MemX: (g.ab.sym name; g.ab.intLit 1)

proc emStoreSlot*(g: var CodeGen; name: string; s: Reg) =
  g.ab.tree StbAvr: (g.ab.sym name; g.emLo s)
  g.ab.tree StbAvr:
    g.ab.tree MemX: (g.ab.sym name; g.ab.intLit 1)
    g.emHi s

proc emLeaSlot*(g: var CodeGen; d: Reg; name: string) =
  ## The ADDRESS of a frame slot. One asm-NIF node; nifasm turns it into a `movw`
  ## from Y plus the displacement, because that displacement is ITS number.
  ##
  ## Adding that displacement needs `adiw` or `subi`, and neither reaches the low
  ## callee-saved pairs — so a destination below r16 is served through the value
  ## bridge and a `movw`, exactly as a constant is.
  if ldiOk(d):
    g.ab.tree LeaAvr: (g.emPair d; g.ab.sym name)
  else:
    g.ab.tree LeaAvr: (g.emPair ValueBridge; g.ab.sym name)
    g.emMovw(d, ValueBridge)

# ── through a pointer ───────────────────────────────────────────────────────
# Memory is reachable only through X, Y and Z, and Y is the frame pointer. So a
# pointer VALUE has to be moved into one of the other two before it can be
# followed — which is one `movw`, and then the access itself.

proc emLoadPtr*(g: var CodeGen; d, p: Reg; off: int; width: int) =
  ## Load `width` bytes through the pointer in `p`. The pointer is staged in the
  ## produce bridge (Z) rather than used where it sits: an arbitrary pair cannot
  ## address memory at all.
  g.emMovw(ProduceBridge, p)
  if width >= 2:
    g.ab.tree LdbAvr:
      g.emLo d
      g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit off)
    g.ab.tree LdbAvr:
      g.emHi d
      g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit(off + 1))
  else:
    g.ab.tree LdbAvr:
      g.emLo d
      g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit off)
    # A byte read into a 16-bit value: the high half is zero, and `eor` against
    # itself is how a register is zeroed here.
    g.ab.tree XorAvr: (g.emHi d; g.emHi d)

proc emStorePtr*(g: var CodeGen; p: Reg; off: int; s: Reg; width: int) =
  g.emMovw(ProduceBridge, p)
  g.ab.tree StbAvr:
    g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit off)
    g.emLo s
  if width >= 2:
    g.ab.tree StbAvr:
      g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit(off + 1))
      g.emHi s

proc emMemNode*(g: var CodeGen; c: Cursor) =
  ## Re-emit a Leng `(dot …)`/`(at …)` as the asm-NIF memory operand of the same
  ## shape. The offsets are nifasm's to compute: it has the layout, so arkham
  ## names the field or the index and nothing more.
  case c.kind
  of Symbol:
    let name = symName(c)
    let home = g.plan.locationOfSym(name, cursorToPosition(g.buf[], c))
    if home.kind == NamedStack: g.ab.sym home.name
    elif home.kind == InReg: g.emPair home.r     # already a pointer VALUE
    else:
      lengError c, "AVR: `" & name & "` cannot be addressed (" & $home.kind & ")",
                lengInfo(c)
  of TagLit:
    case c.exprKind
    of DotC:
      var b = c; inc b
      var f = b; skip f
      g.ab.tree DotX:
        g.emMemNode(b)
        if f.kind != Symbol:
          lengError c, "AVR: a field access needs a field name", lengInfo(c)
        g.ab.sym symName(f)
    of AtC:
      var b = c; inc b
      var i = b; skip i
      g.ab.tree AtX:
        g.emMemNode(b)
        if i.kind == IntLit: g.ab.intLit intVal(i)
        elif i.kind == UIntLit: g.ab.intLit cast[int64](uintVal(i))
        else:
          lengError c, "AVR: only a CONSTANT index folds into an address here",
                    lengInfo(c)
    of DerefC, HaddrC:
      var v = c; inc v
      g.emMemNode(v)
    else:
      lengError c, "AVR: `" & $c.exprKind & "` is not an address expression",
                lengInfo(c)
  else:
    lengError c, "AVR: not an address expression", lengInfo(c)

proc emStoreField*(g: var CodeGen; slot, field: string; s: Reg; width: int) =
  ## Store into `slot.field`. Built from PARTS rather than copied from a node: a
  ## constructor's destination is not written anywhere in the input.
  g.ab.tree StbAvr:
    g.ab.tree DotX: (g.ab.sym slot; g.ab.sym field)
    g.emLo s
  if width >= 2:
    g.ab.tree StbAvr:
      g.ab.tree MemX:
        g.ab.tree DotX: (g.ab.sym slot; g.ab.sym field)
        g.ab.intLit 1
      g.emHi s

proc emStoreElem*(g: var CodeGen; slot: string; idx: int; s: Reg; width: int) =
  g.ab.tree StbAvr:
    g.ab.tree AtX: (g.ab.sym slot; g.ab.intLit idx)
    g.emLo s
  if width >= 2:
    g.ab.tree StbAvr:
      g.ab.tree MemX:
        g.ab.tree AtX: (g.ab.sym slot; g.ab.intLit idx)
        g.ab.intLit 1
      g.emHi s

proc emLeaNode*(g: var CodeGen; d: Reg; node: Cursor) =
  ## The ADDRESS of a folded access. `(dot …)`/`(at …)` are memory operands to
  ## nifasm, so `(lea …)` over one resolves against whatever base the fold gave.
  ## A destination below r16 goes through the value bridge, as every offset does.
  if ldiOk(d):
    g.ab.tree LeaAvr: (g.emPair d; g.emMemNode node)
  else:
    g.ab.tree LeaAvr: (g.emPair ValueBridge; g.emMemNode node)
    g.emMovw(d, ValueBridge)

proc emLoadByteAt*(g: var CodeGen; d: Reg; lvSlotName: string; off: int) =
  ## ONE byte out of a frame slot, into the low half of `d`. An aggregate copy on
  ## this machine moves bytes: the word is two of them and the odd sizes are
  ## common, so a byte at a time is both simplest and always right.
  g.ab.tree LdbAvr:
    g.emLo d
    g.ab.tree MemX: (g.ab.sym lvSlotName; g.ab.intLit off)

proc emStoreByteAt*(g: var CodeGen; lvSlotName: string; off: int; s: Reg) =
  g.ab.tree StbAvr:
    g.ab.tree MemX: (g.ab.sym lvSlotName; g.ab.intLit off)
    g.emLo s

proc emLoadByteNode*(g: var CodeGen; d: Reg; node: Cursor; off: int) =
  g.ab.tree LdbAvr:
    g.emLo d
    g.ab.tree MemX: (g.emMemNode node; g.ab.intLit off)

proc emStoreByteNode*(g: var CodeGen; node: Cursor; off: int; s: Reg) =
  g.ab.tree StbAvr:
    g.ab.tree MemX: (g.emMemNode node; g.ab.intLit off)
    g.emLo s

proc emLoadBytePtr*(g: var CodeGen; d, p: Reg; off: int) =
  g.emMovw(ProduceBridge, p)
  g.ab.tree LdbAvr:
    g.emLo d
    g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit off)

proc emStoreBytePtr*(g: var CodeGen; p: Reg; off: int; s: Reg) =
  g.emMovw(ProduceBridge, p)
  g.ab.tree StbAvr:
    g.ab.tree MemX: (g.emPair ProduceBridge; g.ab.intLit off)
    g.emLo s

proc emLoadNode*(g: var CodeGen; d: Reg; node: Cursor; width: int) =
  ## A 16-bit value out of a folded address is TWO `ldb`s, and the `+1` for the
  ## high byte rides in the same instruction's displacement field — which is why
  ## `(mem <addr> 1)` exists.
  g.ab.tree LdbAvr: (g.emLo d; g.emMemNode node)
  if width >= 2:
    g.ab.tree LdbAvr:
      g.emHi d
      g.ab.tree MemX: (g.emMemNode node; g.ab.intLit 1)
  else:
    g.ab.tree XorAvr: (g.emHi d; g.emHi d)

proc emStoreNode*(g: var CodeGen; node: Cursor; s: Reg; width: int) =
  g.ab.tree StbAvr: (g.emMemNode node; g.emLo s)
  if width >= 2:
    g.ab.tree StbAvr:
      g.ab.tree MemX: (g.emMemNode node; g.ab.intLit 1)
      g.emHi s

# ── 16-bit arithmetic and logic ─────────────────────────────────────────────

type
  AvrBinOp* = enum
    ## The 16-bit operations that are exactly two 8-bit instructions. `add` and
    ## `sub` carry between the halves and so must be the carry-aware forms in the
    ## high half; the bitwise three do not and repeat the same instruction.
    boAdd, boSub, boAnd, boOr, boXor

proc emBin16*(g: var CodeGen; op: AvrBinOp; d, s: Reg) =
  ## `d op= s`, on two pairs.
  case op
  of boAdd:
    g.ab.tree AddAvr: (g.emLo d; g.emLo s)
    g.ab.tree AdcAvr: (g.emHi d; g.emHi s)
  of boSub:
    g.ab.tree SubAvr: (g.emLo d; g.emLo s)
    g.ab.tree SbcAvr: (g.emHi d; g.emHi s)
  of boAnd:
    g.ab.tree AndAvr: (g.emLo d; g.emLo s)
    g.ab.tree AndAvr: (g.emHi d; g.emHi s)
  of boOr:
    g.ab.tree OrAvr: (g.emLo d; g.emLo s)
    g.ab.tree OrAvr: (g.emHi d; g.emHi s)
  of boXor:
    g.ab.tree XorAvr: (g.emLo d; g.emLo s)
    g.ab.tree XorAvr: (g.emHi d; g.emHi s)

proc emBinImm16*(g: var CodeGen; op: AvrBinOp; d: Reg; v: int64): bool =
  ## `d op= <constant>` without touching another register, when the machine has a
  ## form for it. Returns false when it does not, and then the caller must load
  ## the constant into a pair first.
  ##
  ## There is no `addi` on AVR: adding a constant is SUBTRACTING its negation,
  ## which is why `subi` carries both directions here.
  let w = v and 0xFFFF
  case op
  of boAdd, boSub:
    let mag = if op == boAdd: (-v) and 0xFFFF else: w
    if not ldiOk(d): return false
    if mag == 0: return true
    g.ab.tree SubiAvr: (g.emLo d; g.ab.intLit(mag and 0xFF))
    g.ab.tree SbciAvr: (g.emHi d; g.ab.intLit((mag shr 8) and 0xFF))
    return true
  of boAnd:
    if not ldiOk(d): return false
    g.ab.tree AndiAvr: (g.emLo d; g.ab.intLit(w and 0xFF))
    g.ab.tree AndiAvr: (g.emHi d; g.ab.intLit((w shr 8) and 0xFF))
    return true
  of boOr:
    if not ldiOk(d): return false
    g.ab.tree OriAvr: (g.emLo d; g.ab.intLit(w and 0xFF))
    g.ab.tree OriAvr: (g.emHi d; g.ab.intLit((w shr 8) and 0xFF))
    return true
  of boXor:
    return false          # no `eori` exists

proc emAdiw*(g: var CodeGen; d: Reg; v: int): bool =
  ## `adiw`/`sbiw` — a whole pair adjusted by 0..63 in ONE instruction, on the
  ## four upper pairs only. Worth trying before the `subi`/`sbci` pair because it
  ## is half the size and does not need an `ldi`-capable register for a constant
  ## it does not have to materialize.
  if d notin {P24, X, Y, Z}: return false
  if v == 0: return true
  if v > 0 and v <= 63:
    g.ab.tree AdiwAvr: (g.emPair d; g.ab.intLit v)
    return true
  if v < 0 and v >= -63:
    g.ab.tree SbiwAvr: (g.emPair d; g.ab.intLit(-v))
    return true
  return false

proc emNeg16*(g: var CodeGen; d: Reg) =
  ## Two's complement of a pair: complement the high half, negate the low, then
  ## borrow. The order matters — `neg` sets the carry, which the `sbci` reads.
  g.ab.tree NotAvr: g.emHi d
  g.ab.tree NegAvr: g.emLo d
  g.ab.tree SbciAvr: (g.emHi d; g.ab.intLit 0xFF)

proc emNot16*(g: var CodeGen; d: Reg) =
  g.ab.tree NotAvr: g.emLo d
  g.ab.tree NotAvr: g.emHi d

proc emMul16*(g: var CodeGen; d, s: Reg) =
  ## `d = d * s`, sixteen bits, from three 8x8 multiplies.
  ##
  ## Every `mul` lands in the fixed pair r1:r0, so the partial sum has to live
  ## somewhere that is neither operand — the value bridge, which is the reason it
  ## exists. Only the low 16 bits of the product are kept, which is what a 16-bit
  ## multiply means; the fourth cross term (`ah*bh`) contributes only above them
  ## and is not emitted at all.
  ##
  ## The trailing `clr r1` is not optional: r1 must hold zero for every borrow
  ## sequence on this machine, and `mul` destroys it.
  assert d != ValueBridge and s != ValueBridge
  g.ab.tree MulbAvr: (g.emLo d; g.emLo s)          # r1:r0 = dl * sl
  g.emMovw(ValueBridge, MulResult)
  g.ab.tree MulbAvr: (g.emHi d; g.emLo s)          # r0 += into the high half
  g.ab.tree AddAvr: (g.emHi ValueBridge; g.ab.regNamed lowName(MulResult))
  g.ab.tree MulbAvr: (g.emLo d; g.emHi s)
  g.ab.tree AddAvr: (g.emHi ValueBridge; g.ab.regNamed lowName(MulResult))
  g.ab.tree XorAvr: (g.ab.regNamed highName(MulResult); g.ab.regNamed highName(MulResult))
  g.emMovw(d, ValueBridge)

proc emShl16*(g: var CodeGen; d: Reg; n: int) =
  ## A shift by a CONSTANT, which is that many instruction pairs — there is no
  ## multi-bit shift on this machine at all.
  for _ in 0 ..< n:
    g.ab.tree Lsl1Avr: g.emLo d
    g.ab.tree Rol1Avr: g.emHi d

proc emShr16*(g: var CodeGen; d: Reg; n: int; signed: bool) =
  ## The high half FIRST, then the low: the bit that falls out of the high half
  ## is the carry the low half's `ror` rotates in, so the order is the algorithm.
  for _ in 0 ..< n:
    g.ab.tree (if signed: Asr1Avr else: Lsr1Avr): g.emHi d
    g.ab.tree Ror1Avr: g.emLo d

# ── comparison ──────────────────────────────────────────────────────────────

proc emCmp16*(g: var CodeGen; a, b: Reg) =
  ## `cmp`+`cpc` — the low half then the high half with borrow, which is what
  ## makes the flags describe the whole 16-bit comparison rather than one byte.
  g.ab.tree CmpAvr: (g.emLo a; g.emLo b)
  g.ab.tree CpcAvr: (g.emHi a; g.emHi b)

proc emCmpImm16*(g: var CodeGen; a: Reg; v: int64): bool =
  if not ldiOk(a): return false
  g.ab.tree CpiAvr: (g.emLo a; g.ab.intLit(v and 0xFF))
  g.ab.tree CpcAvr:
    g.emHi a
    g.ab.regNamed "r1"        # the zero register, for the high half of a small
                              # constant — see `MulResult`'s note on why r1 is
                              # guaranteed to hold zero
  return (v and 0xFFFF) == (v and 0xFF)

# ── control flow ────────────────────────────────────────────────────────────

proc emLab*(g: var CodeGen; name: string) =
  g.ab.tree LabAvr: g.ab.symDef name

proc emJmp*(g: var CodeGen; name: string) =
  g.ab.tree BAvr: g.ab.sym name

type
  AvrCond* = enum
    ## The six comparisons that ARE one branch here. Every AVR branch tests one
    ## status bit, so there is no `<=` and no `>`: those are the other two with
    ## the operands exchanged, and the exchange happens while deciding rather
    ## than while running.
    acEq, acNe, acLt, acGe, acLo, acHs

proc invert*(c: AvrCond): AvrCond =
  case c
  of acEq: acNe
  of acNe: acEq
  of acLt: acGe
  of acGe: acLt
  of acLo: acHs
  of acHs: acLo

proc emBranch*(g: var CodeGen; cond: AvrCond; target: string) =
  ## `blt`/`bge` are the SIGNED pair and `blo`/`bhs` the unsigned one, and they
  ## are different instructions — an unsigned comparison leaves its answer in the
  ## carry and a signed one in S. Picking between them is the caller's job,
  ## because only the caller knows the operand type.
  let t = case cond
          of acEq: BeqAvr
          of acNe: BneAvr
          of acLt: BltAvr
          of acGe: BgeAvr
          of acLo: BloAvr
          of acHs: BhsAvr
  g.ab.tree t: g.ab.sym target

proc freshLabel*(g: var CodeGen; prefix: string): string =
  inc g.labelCount
  result = SynthMark & prefix & $g.labelCount & ".0"

# ── types ───────────────────────────────────────────────────────────────────

proc genTypeBodyAvr*(g: var CodeGen; c: var Cursor) =
  ## A Leng type as asm-NIF, advancing past it. Scalars and pointers only —
  ## everything else is refused BY NAME, which is what makes a partial backend
  ## safe to ship. A named type is inlined, as on the other targets.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, c.symId)
    d.into:
      inc d; skip d                       # the name, then the type pragmas
      g.genTypeBodyAvr(d)
    inc c
  of TagLit:
    case c.typeKind
    of IT:
      var t = c; inc t
      g.ab.intType(if t.kind == IntLit: int(intVal(t)) else: 16); skip c
    of UT:
      var t = c; inc t
      g.ab.uintType(if t.kind == IntLit: int(intVal(t)) else: 16); skip c
    of CT:
      var t = c; inc t
      g.ab.charType(if t.kind == IntLit: int(intVal(t)) else: 8); skip c
    of BoolT:
      g.ab.boolType(); skip c
    of VoidT:
      g.ab.voidType(); skip c
    of PtrT:
      # `(ptr (void))` rather than the real pointee: this backend has no
      # aggregates, so nothing here can reach through the pointer, and emitting
      # the pointee would drag in the object types M4c does not handle.
      g.ab.ptrType: g.ab.voidType()
      skip c
    of AptrT:
      g.ab.aptrType: g.ab.voidType()
      skip c
    of ArrayT:
      c.into:
        g.ab.arrayType:
          g.genTypeBodyAvr(c)
          if c.kind == IntLit: (g.ab.intLit intVal(c); inc c)
          else:
            lengError c, "AVR: an array length must be a literal", lengInfo(c)
    of ObjectT:
      c.into:
        if c.kind == Symbol:
          lengError c, "AVR: object inheritance is not implemented yet", lengInfo(c)
        skip c                                  # the base slot
        g.ab.objectType:
          while c.hasMore:
            # Every child must be a `(fld …)`. An object may also contain a
            # `(union …)` or an anonymous group, and walking one of those as a
            # field asks a tag for its symbol name — which used to be an
            # assertion failure rather than a diagnostic.
            if c.substructureKind != FldU:
              lengError c, "AVR: an object member that is not a plain field " &
                        "(a union or an anonymous group) is not implemented yet " &
                        "(see M5 in doc/internals/avr.md)", lengInfo(c)
            var f = c
            f.into:
              let fname = symName(f); inc f
              skip f                            # the field's pragmas
              g.ab.fldDef fname:
                g.genTypeBodyAvr(f)
              while f.hasMore: skip f
            skip c
    else:
      lengError c, "AVR: the type `" & $c.typeKind & "` is not implemented yet " &
                   "(M5: unions and function pointers)", lengInfo(c)
  else:
    lengError c, "AVR: unsupported type", lengInfo(c)

# ── declarations ────────────────────────────────────────────────────────────

proc emRegPairVar*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## `(var :name (rpN) T)` — declare a local and bind the PAIR to it, so every
  ## later use spells the name and every half spells `(lo name)`/`(hi name)`.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillAvr: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r
  var tc = typeCur
  g.genTypeBodyAvr(tc)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr = false)

proc emSlotVar*(g: var CodeGen; name: string; typeCur: Cursor) =
  ## `(var :name (s) T)` — a frame slot, whose offset nifasm assigns.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  var tc = typeCur
  g.genTypeBodyAvr(tc)
  g.ab.close()

proc emPtrSlot*(g: var CodeGen; name: string) =
  ## A two-byte slot the EMITTER minted for an ADDRESS — the parked hidden
  ## result pointer. Typed `(ptr (void))` rather than `(u 16)` so nifasm knows
  ## what it holds even though the two have the same size here.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.ptrType: g.ab.voidType()
  g.ab.close()
