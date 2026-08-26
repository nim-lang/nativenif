#
#           Arkham — RV32 asm-NIF emission primitives
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The layer that knows RV32's shape, which is mostly a matter of knowing how
## little shape there is: three-operand ALU, one addressing mode, and `x0` doing
## the work four separate instructions do elsewhere.
##
## The one real decision here is `emLi`. A constant that fits twelve signed bits
## is one `addi` against `x0`; anything wider is `lui`+`addi`, and the `+0x800`
## compensation is not optional — `addi`'s immediate is SIGNED, so a low half
## above 0x7FF is a negative addend and the upper half has to be one higher. The
## split is done HERE rather than in the assembler because it is two
## instructions, and choosing between one and two is code generation.

import std / [tables]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, regbind, diag, constdata]
import std / [sets]
import machine

proc emReg*(g: var CodeGen; r: Reg) =
  ## A value register: the local's name when one lives here, the raw `(xN)`
  ## otherwise. `x0` is always raw — nothing is ever bound to a register that
  ## discards its writes.
  if r == Zero:
    g.ab.rawReg r
    return
  let nm = g.rb.boundName(r)
  if nm.len > 0: g.ab.sym nm
  else:
    # Legitimately raw: the two bridges, the ABI argument and return registers,
    # the temp pool, SP, `ra`, and a callee-saved register being SAVED or
    # RESTORED by the frame — which is a store of the register itself, not of any
    # value that lives in it.
    assert r in {StagingBridge, StagingBridge2} or r in g.md.intArgRegs or
           r == g.md.intRetReg or r in g.md.intTempRegs or
           r in g.md.intCalleeSavedSet or r == SP or r == Ra,
      "arkham rv32: unbound register reached emReg: " & abiName(r) &
      " in " & g.curProcName
    g.ab.rawReg r

proc emZero*(g: var CodeGen) = g.ab.rawReg Zero

proc fitsImm12*(v: int64): bool {.inline.} = v >= -2048 and v <= 2047

proc emMv*(g: var CodeGen; d, s: Reg) =
  ## `mv` IS `addi d, s, 0`, and the asm-NIF `(mov D S)` says so.
  if d == s: return
  g.ab.tree MovRv: (g.emReg d; g.emReg s)

proc emLi*(g: var CodeGen; d: Reg; v: int64) =
  ## One instruction or two, decided here — see the module header.
  let w = cast[int32](uint32(v and 0xFFFFFFFF))
  if fitsImm12(int64(w)):
    g.ab.tree AddiRv: (g.emReg d; g.emZero(); g.ab.intLit int64(w))
  else:
    let u = uint32(w)
    let hi = (u + 0x800) shr 12
    let lo = cast[int32](u - (hi shl 12))
    g.ab.tree LuiRv: (g.emReg d; g.ab.intLit int64(hi and 0xFFFFF))
    if lo != 0:
      g.ab.tree AddiRv: (g.emReg d; g.emReg d; g.ab.intLit int64(lo))

# ── memory ──────────────────────────────────────────────────────────────────
# One mode for the whole machine: a base register plus a 12-bit signed offset.
# A frame slot is `sp + q` like any other access — there is no special case and
# no frame pointer.

proc emLoadSlot*(g: var CodeGen; d: Reg; name: string) =
  g.ab.tree LwrRv: (g.emReg d; g.ab.sym name)

proc emStoreSlot*(g: var CodeGen; name: string; s: Reg) =
  g.ab.tree SwrRv: (g.ab.sym name; g.emReg s)

proc emLoadSlotW*(g: var CodeGen; d: Reg; name: string; width: int; signed: bool) =
  ## A slot whose width is the LOCAL's, not the machine's. `lw` on a one-byte
  ## slot reads three bytes that belong to something else and answers with them;
  ## `sw` writes over them. That is what an `(i 8)` local did until this existed.
  let t = case width
          of 1: (if signed: LbrRv else: LburRv)
          of 2: (if signed: LhrRv else: LhurRv)
          else: LwrRv
  g.ab.tree t: (g.emReg d; g.ab.sym name)

proc emStoreSlotW*(g: var CodeGen; name: string; s: Reg; width: int) =
  let t = case width
          of 1: SbrRv
          of 2: Shr32Rv
          else: SwrRv
  g.ab.tree t: (g.ab.sym name; g.emReg s)

proc emLeaSlot*(g: var CodeGen; d: Reg; name: string) =
  ## The ADDRESS of a frame slot — `addi d, sp, q`, with `q` nifasm's own number.
  g.ab.tree LeaRv: (g.emReg d; g.ab.sym name)

proc emLoadPtr*(g: var CodeGen; d, p: Reg; off: int; width: int; signed: bool) =
  ## Load through a pointer register. One addressing mode, so this is one
  ## instruction whatever the width — and the width is what decides whether the
  ## high bits are copies of bit 7 or zeros, which is the whole reason a narrow
  ## load has two spellings.
  let t = case width
          of 1: (if signed: LbrRv else: LburRv)
          of 2: (if signed: LhrRv else: LhurRv)
          else: LwrRv
  g.ab.tree t:
    g.emReg d
    g.ab.tree MemX: (g.emReg p; g.ab.intLit off)

proc emStorePtr*(g: var CodeGen; p: Reg; off: int; s: Reg; width: int) =
  let t = case width
          of 1: SbrRv
          of 2: Shr32Rv
          else: SwrRv
  g.ab.tree t:
    g.ab.tree MemX: (g.emReg p; g.ab.intLit off)
    g.emReg s

proc emMemNode*(g: var CodeGen; c: Cursor) =
  ## Re-emit a Leng `(dot …)`/`(at …)` as the asm-NIF memory operand of the same
  ## shape. The offsets are NOT computed here: nifasm has the layout, so arkham
  ## names the field or the index and nothing more. Same division x86-64 uses.
  case c.kind
  of Symbol:
    let name = symName(c)
    let home = g.plan.locationOfSym(name, cursorToPosition(g.buf[], c))
    if home.kind == NamedStack: g.ab.sym home.name
    elif home.kind == InReg: g.emReg home.r      # already a pointer VALUE
    elif g.prog.globals.hasKey(name): g.ab.sym g.prog.gvarAsmName(name)
    else:
      lengError c, "RV32: `" & name & "` cannot be addressed (" & $home.kind & ")",
                lengInfo(c)
  of TagLit:
    case c.exprKind
    of DotC:
      var b = c; inc b
      var f = b; skip f
      g.ab.tree DotX:
        g.emMemNode(b)
        if f.kind != Symbol:
          lengError c, "RV32: a field access needs a field name", lengInfo(c)
        g.ab.sym symName(f)
    of AtC:
      var b = c; inc b
      var i = b; skip i
      g.ab.tree AtX:
        g.emMemNode(b)
        if i.kind == IntLit: g.ab.intLit intVal(i)
        elif i.kind == UIntLit: g.ab.intLit cast[int64](uintVal(i))
        else:
          lengError c, "RV32: only a CONSTANT index folds into an address here",
                    lengInfo(c)
    of DerefC, HaddrC:
      var v = c; inc v
      g.emMemNode(v)
    else:
      lengError c, "RV32: `" & $c.exprKind & "` is not an address expression",
                lengInfo(c)
  else:
    lengError c, "RV32: not an address expression", lengInfo(c)

proc storeTagFor(width: int): Rv32Inst =
  case width
  of 1: SbrRv
  of 2: Shr32Rv
  else: SwrRv

proc emGlobalAddr*(g: var CodeGen; d: Reg; name: string) =
  ## A global's address into a register. `lui`+`addi`, patched once the data
  ## segment is placed — the address is a final-layout fact, so nifasm carries it
  ## rather than arkham guessing.
  g.ab.tree AdrRv: (g.emReg d; g.ab.sym name)

proc emGlobalAddrLabel*(g: var CodeGen; d: Reg; name: string) =
  ## The address of a CODE-segment label (a rodata blob). Same `(adr …)` node as
  ## a global's, and nifasm tells the two apart by what the symbol resolves to.
  g.ab.tree AdrRv: (g.emReg d; g.ab.sym name)

proc emStoreField*(g: var CodeGen; slot, field: string; s: Reg; width: int) =
  ## Store into `slot.field`. Built from PARTS rather than copied from a node,
  ## because a constructor's destination is not written anywhere in the input —
  ## `(oconstr …)` names the fields and the local, never the access.
  g.ab.tree storeTagFor(width):
    g.ab.tree DotX: (g.ab.sym slot; g.ab.sym field)
    g.emReg s

proc emStoreElem*(g: var CodeGen; slot: string; idx: int; s: Reg; width: int) =
  g.ab.tree storeTagFor(width):
    g.ab.tree AtX: (g.ab.sym slot; g.ab.intLit idx)
    g.emReg s

proc emLeaField*(g: var CodeGen; d: Reg; slot, field: string) =
  ## The ADDRESS of `slot.field`, built from PARTS for the reason `emStoreField`
  ## is: a constructor's destination is not written anywhere in the input.
  g.ab.tree LeaRv:
    g.emReg d
    g.ab.tree DotX: (g.ab.sym slot; g.ab.sym field)

proc emLeaElem*(g: var CodeGen; d: Reg; slot: string; idx: int) =
  g.ab.tree LeaRv:
    g.emReg d
    g.ab.tree AtX: (g.ab.sym slot; g.ab.intLit idx)

proc emLeaNode*(g: var CodeGen; d: Reg; node: Cursor) =
  ## The ADDRESS of a folded access. `(dot …)` and `(at …)` are memory operands
  ## to nifasm, so `(lea …)` over one is a single `addi` against whatever base
  ## the fold resolved to.
  g.ab.tree LeaRv: (g.emReg d; g.emMemNode node)

proc emLoadSlotOff*(g: var CodeGen; d: Reg; name: string; off: int) =
  g.ab.tree LwrRv:
    g.emReg d
    g.ab.tree MemX: (g.ab.sym name; g.ab.intLit off)

proc emStoreSlotOff*(g: var CodeGen; name: string; off: int; s: Reg) =
  g.ab.tree SwrRv:
    g.ab.tree MemX: (g.ab.sym name; g.ab.intLit off)
    g.emReg s

proc emLoadNodeOff*(g: var CodeGen; d: Reg; node: Cursor; off: int; width: int) =
  let t = case width
          of 1: LburRv
          of 2: LhurRv
          else: LwrRv
  g.ab.tree t:
    g.emReg d
    g.ab.tree MemX: (g.emMemNode node; g.ab.intLit off)

proc emStoreNodeOff*(g: var CodeGen; node: Cursor; off: int; s: Reg; width: int) =
  let t = case width
          of 1: SbrRv
          of 2: Shr32Rv
          else: SwrRv
  g.ab.tree t:
    g.ab.tree MemX: (g.emMemNode node; g.ab.intLit off)
    g.emReg s

proc emLoadNode*(g: var CodeGen; d: Reg; node: Cursor; width: int; signed: bool) =
  let t = case width
          of 1: (if signed: LbrRv else: LburRv)
          of 2: (if signed: LhrRv else: LhurRv)
          else: LwrRv
  g.ab.tree t: (g.emReg d; g.emMemNode node)

proc emStoreNode*(g: var CodeGen; node: Cursor; s: Reg; width: int) =
  let t = case width
          of 1: SbrRv
          of 2: Shr32Rv
          else: SwrRv
  g.ab.tree t: (g.emMemNode node; g.emReg s)

# ── ALU ─────────────────────────────────────────────────────────────────────

type
  RvBinOp* = enum
    boAdd, boSub, boMul, boAnd, boOr, boXor, boShl, boShr, boSar,
    boDiv, boDivu, boRem, boRemu

proc emBin*(g: var CodeGen; op: RvBinOp; d, a, b: Reg) =
  ## `d = a op b`. Three operands, so nothing has to be moved into place first —
  ## which is the single biggest difference from every other backend here.
  let t = case op
          of boAdd: Add3Rv
          of boSub: Sub3Rv
          of boMul: Mul3Rv
          of boAnd: And3Rv
          of boOr: Orr3Rv
          of boXor: Eor3Rv
          of boShl: Lsl3Rv
          of boShr: Lsr3Rv
          of boSar: Asr3Rv
          of boDiv: DivsRv
          of boDivu: Divu3Rv
          of boRem: RemsRv
          of boRemu: RemuRv
  g.ab.tree t: (g.emReg d; g.emReg a; g.emReg b)

proc immFormOf(op: RvBinOp): Rv32Inst =
  ## The `i`-suffixed twin, or `NoRv32Inst` where the machine has none. There is
  ## no `subi` and no `muli`: subtracting a constant is adding its negation, and
  ## a multiply by a constant is a multiply.
  case op
  of boAdd: AddiRv
  of boAnd: AndiRv
  of boOr: OriRv
  of boXor: XoriRv
  of boShl: SlliRv
  of boShr: SrliRv
  of boSar: SraiRv
  else: NoRv32Inst

proc emBinImm*(g: var CodeGen; op: RvBinOp; d, a: Reg; v: int64): bool =
  ## `d = a op <constant>` in one instruction where the machine has a form for
  ## it. Returns false when it does not, and then the caller materializes the
  ## constant into a register first.
  var op = op
  var v = v
  if op == boSub:
    # No `subi` exists. Adding the negation is the same instruction, and the
    # range check below is what stops `-(-2048)` from silently wrapping.
    op = boAdd
    v = -v
  let t = immFormOf(op)
  if t == NoRv32Inst: return false
  if op in {boShl, boShr, boSar}:
    if v < 0 or v > 31: return false
  elif not fitsImm12(v):
    return false
  g.ab.tree t: (g.emReg d; g.emReg a; g.ab.intLit v)
  true

# ── comparison ──────────────────────────────────────────────────────────────
# There are no flags, so a comparison PRODUCES a value. `slt`/`sltu` give
# "less than" directly; the other five are built from it and from `x0`.

proc emSlt*(g: var CodeGen; d, a, b: Reg; signed: bool) =
  g.ab.tree (if signed: SltRv else: SltuRv): (g.emReg d; g.emReg a; g.emReg b)

proc emSeqz*(g: var CodeGen; d, a: Reg) =
  ## 1 when `a` is zero. `sltiu d, a, 1` is true exactly then — a value is
  ## unsigned-less-than one precisely when it is zero.
  g.ab.tree SltiuRv: (g.emReg d; g.emReg a; g.ab.intLit 1)

proc emSnez*(g: var CodeGen; d, a: Reg) =
  g.ab.tree SltuRv: (g.emReg d; g.emZero(); g.emReg a)

proc emXorReg*(g: var CodeGen; d, a, b: Reg) =
  g.ab.tree Eor3Rv: (g.emReg d; g.emReg a; g.emReg b)

# ── control flow ────────────────────────────────────────────────────────────

type
  RvCond* = enum
    ## The six the hardware branches on. `>` and `<=` are these with the operands
    ## exchanged, which costs nothing because the exchange happens while
    ## selecting rather than while running.
    rcEq, rcNe, rcLt, rcGe, rcLtu, rcGeu

proc invert*(c: RvCond): RvCond =
  case c
  of rcEq: rcNe
  of rcNe: rcEq
  of rcLt: rcGe
  of rcGe: rcLt
  of rcLtu: rcGeu
  of rcGeu: rcLtu

proc emBranch*(g: var CodeGen; cond: RvCond; a, b: Reg; target: string) =
  ## Compare AND branch, in one instruction. Nothing is left in a flag between
  ## them because there is no flag to leave anything in.
  let t = case cond
          of rcEq: BeqrRv
          of rcNe: BnerRv
          of rcLt: BltrRv
          of rcGe: BgerRv
          of rcLtu: BlturRv
          of rcGeu: BgeurRv
  g.ab.tree t: (g.emReg a; g.emReg b; g.ab.sym target)

proc emLab*(g: var CodeGen; name: string) =
  g.ab.tree LabRv: g.ab.symDef name

proc emJmp*(g: var CodeGen; name: string) =
  g.ab.tree BRv: g.ab.sym name

proc freshLabel*(g: var CodeGen; prefix: string): string =
  inc g.labelCount
  result = SynthMark & prefix & $g.labelCount & ".0"

# ── types and declarations ──────────────────────────────────────────────────

proc genTypeBodyRv*(g: var CodeGen; c: var Cursor)

proc genGlobalRv*(g: var CodeGen; nifName: string; decl: Cursor) =
  ## A top-level `gvar`/`const`. Only a compile-time constant scalar initializer
  ## is laid out statically; a runtime one would need entry-time code that this
  ## backend does not emit yet.
  if nifName in g.prog.importcOnlyGvars: return
  let name = g.prog.gvarAsmName(nifName)
  var c = decl
  c.into:
    inc c                                       # the name
    skip c                                      # the var's pragmas
    let typeCur = c
    skip c
    let hasValue = c.hasMore and c.kind != DotToken
    g.ab.open NifasmDecl.GvarD
    g.ab.symDef name
    var tc = typeCur
    g.genTypeBodyRv(tc)
    g.genGlobalInitValue(name, typeCur, c, hasValue)
    g.ab.close()
    while c.hasMore: skip c

proc genTypeBodyRv*(g: var CodeGen; c: var Cursor) =
  ## Scalars and pointers only — everything else is refused BY NAME, which is
  ## what makes a partial backend safe to ship.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, c.symId)
    d.into:
      inc d; skip d
      g.genTypeBodyRv(d)
    inc c
  of TagLit:
    case c.typeKind
    of IT:
      var t = c; inc t
      g.ab.intType(if t.kind == IntLit: int(intVal(t)) else: 32); skip c
    of UT:
      var t = c; inc t
      g.ab.uintType(if t.kind == IntLit: int(intVal(t)) else: 32); skip c
    of CT:
      var t = c; inc t
      g.ab.charType(if t.kind == IntLit: int(intVal(t)) else: 8); skip c
    of BoolT:
      g.ab.boolType(); skip c
    of VoidT:
      g.ab.voidType(); skip c
    of PtrT:
      g.ab.ptrType: g.ab.voidType()
      skip c
    of AptrT:
      g.ab.aptrType: g.ab.voidType()
      skip c
    of ArrayT:
      c.into:
        g.ab.arrayType:
          g.genTypeBodyRv(c)
          if c.kind == IntLit: (g.ab.intLit intVal(c); inc c)
          else:
            lengError c, "RV32: an array length must be a literal", lengInfo(c)
    of ObjectT:
      c.into:
        # A `.` base means no inheritance; a Symbol base would need the base laid
        # out first, which R5's aggregate work covers.
        if c.kind == Symbol:
          lengError c, "RV32: object inheritance is not implemented yet",
                    lengInfo(c)
        skip c                                  # the base slot
        g.ab.objectType:
          while c.hasMore:
            # Every child must be a `(fld …)`. An object may also contain a
            # `(union …)` or an anonymous group, and walking one of those as a
            # field asks a tag for its symbol name — which used to be an
            # assertion failure rather than a diagnostic.
            if c.substructureKind != FldU:
              lengError c, "RV32: an object member that is not a plain field " &
                        "(a union or an anonymous group) is not implemented yet " &
                        "(see R5c in doc/internals/rv32.md)", lengInfo(c)
            var f = c
            f.into:
              let fname = symName(f); inc f
              skip f                            # the field's pragmas
              g.ab.fldDef fname:
                g.genTypeBodyRv(f)
              while f.hasMore: skip f
            skip c
    else:
      lengError c, "RV32: the type `" & $c.typeKind & "` is not implemented yet " &
                   "(R5: unions and function pointers)", lengInfo(c)
  else:
    lengError c, "RV32: unsupported type", lengInfo(c)

proc emRegVar*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillRv: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r
  var tc = typeCur
  g.genTypeBodyRv(tc)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr = false)

proc emRegPtrVar*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## A register holding a POINTER to an aggregate, declared as `(ptr T)` rather
  ## than as the aggregate.
  ##
  ## The distinction is nifasm's to act on, not decoration: `(dot w f)` folds
  ## against the POINTEE's layout, and a register declared with the object type
  ## says the object is IN the register — which on no machine here it is. A
  ## by-reference parameter looked like that and every field access through it
  ## was rejected.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillRv: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r
  g.ab.ptrType:
    var tc = typeCur
    g.genTypeBodyRv(tc)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr = true)

proc emSlotVar*(g: var CodeGen; name: string; typeCur: Cursor) =
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  var tc = typeCur
  g.genTypeBodyRv(tc)
  g.ab.close()

proc emWordSlot*(g: var CodeGen; name: string) =
  ## A machine-word slot the EMITTER minted — a saved register, or a parked
  ## operand. Typed `(i 32)` because that is what it holds: one word, whatever
  ## the value it came from was.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType 32
  g.ab.close()
