#
#           Arkham — 64-bit integers on a 32-bit target (Cortex-M, M4)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## INCLUDED by `codegen_arm.nim` — not a module of its own, because it is one
## more emitter arm rather than a second code generator, and it needs the whole
## `*2` value core it dispatches out of and back into.
##
## ## Why 64-bit values live in MEMORY
##
## The obvious lowering is a register PAIR, and on a target with a normal
## register file it is the right one. Cortex-M is not that target: the arkham
## machine model gets four allocatable homes (r4–r7) and an EMPTY volatile temp
## pool, because on this ABI the only caller-saved registers ARE the argument
## registers, and emitter scratch is drawn while a call's arguments are staged
## (see `machine_m.nim`). A pair allocator would be competing for two of four
## homes per live 64-bit value, and every consumer in the shared value core
## (`place2`, `storeReg2`, `freeVal`, the binding protocol with a formal model
## behind it) would have to grow a second-register case.
##
## So a 64-bit value here is EIGHT BYTES AT AN ADDRESS, and the ops read and
## write it a word at a time. `slots.inRegClass` already says as much — a
## 64-bit scalar fails it on a 32-bit target, so the allocator gives every such
## local a stack home without being told anything new. What this file adds is
## the arithmetic.
##
## The cost is real (an `x + y` is 6 instructions instead of 2) and it is the
## price of the target's register file, not of the representation. What it buys
## is that the ONE thing a 64-bit lowering must never do — produce a plausible
## wrong number — cannot happen by a register running out.
##
## ## The addressing contract
##
## Each half is spelled `(cast (u 32) (mem <base> <byte offset>))`. The cast is
## load-bearing: the slot's own type is `(i 64)`, and without saying otherwise
## the access would be a 64-bit-typed one that nifasm refuses (`checkRegWidthM`)
## — refuses, note, rather than silently truncating, which is why an arm this
## file forgets shows up as a type error and not as a wrong answer.
##
## ## Flags across a carry chain
##
## `adds`/`adcs` (and `subs`/`sbcs`) are separated here by loads and stores of
## the operand halves. That is sound because `emitLoadStoreImm` on this target
## only ever encodes an LDR/STR — it never materializes an out-of-range offset
## through an arithmetic instruction, it raises — and neither does nifasm's own
## fold of a memory operand into IP. A memory operand carrying an INDEX would
## break that (`emitMemAccessM` computes `base+index` into IP with an `add`), so
## every `WideRef` below is base+displacement and never an indexed one.

type
  WideRefKind = enum
    wrSlot        ## a nifasm `(s)` stack slot, addressed by name
    wrBase        ## `[base + off]`, the address already in a register

  WideRef = object
    ## WHERE a 64-bit value's eight bytes are. Deliberately not a `Location`:
    ## a `Location` describes where a value may go, and every one of these is
    ## already resolved to an address the two halves can be read off.
    off: int
    case kind: WideRefKind
    of wrSlot: name: string
    of wrBase: base: Reg

proc slotWide(name: string; off = 0): WideRef =
  WideRef(kind: wrSlot, name: name, off: off)
proc baseWide(r: Reg; off = 0): WideRef =
  WideRef(kind: wrBase, base: r, off: off)

template WideSlot(): AsmSlot = AsmSlot(cls: AInt, size: 8, align: 8)
  ## The `AsmSlot` of a 64-bit integer temp — the one slot on this target whose
  ## size EXCEEDS the word, which is what `isWideSlot` recognizes. `align: 8` is
  ## the type's natural alignment; nifasm rounds the slot to the target granule.

proc isWideSlot(g: CodeGen; s: AsmSlot): bool {.inline.} =
  ## A scalar too wide for one register on this target — the whole trigger for
  ## everything in this file. False on the 64-bit targets by construction.
  g.thumbM and s.kind in {AInt, AUInt, ABool} and s.size > wordSize()

proc isWideExpr(g: var CodeGen; c: Cursor): bool {.inline.} =
  g.thumbM and g.isWideSlot(g.exprSlot(c))

proc isWideType(g: var CodeGen; t: Cursor): bool {.inline.} =
  g.thumbM and g.isWideSlot(slotOf(g.prog, t))

# ── scratch ─────────────────────────────────────────────────────────────────

proc takeWideRegs(g: var CodeGen; n: int; what: string): seq[Reg] =
  ## `n` scratch GPRs for a wide lowering. The two staging bridges first (they
  ## are withheld from the allocator's pools, so they are the cheap ones), then
  ## callee-saved survivors — which `takeHeld` fails loudly on rather than
  ## handing out a register something else is holding.
  result = @[]
  for _ in 0 ..< n:
    var r = g.tryTakeBridge(ScalarSlot)
    if r == NoReg:
      r = g.takeHeld(what).r
      g.bindTemp(r, ScalarSlot)
    result.add r

proc dropWideRegs(g: var CodeGen; rs: seq[Reg]) =
  for i in countdown(rs.high, 0): g.unbindTemp(rs[i])

# ── the two halves as operands ──────────────────────────────────────────────

proc emWideWord(g: var CodeGen; w: WideRef; i: int) =
  ## Word `i` (0 = low, 1 = high; little-endian) of the 64-bit value at `w`, as a
  ## nifasm memory operand explicitly typed `(u 32)`.
  g.ab.tree CastX:
    g.ab.uintType(32)
    g.ab.tree MemX:
      case w.kind
      of wrSlot: g.ab.sym w.name
      of wrBase: g.emReg w.base
      g.ab.intLit int64(w.off + 4 * i)

proc wideLoad(g: var CodeGen; d: Reg; w: WideRef; i: int) =
  g.ab.tree MovA64: (g.emReg d; g.emWideWord(w, i))

proc wideStore(g: var CodeGen; w: WideRef; i: int; s: Reg) =
  g.ab.tree MovA64: (g.emWideWord(w, i); g.emReg s)

proc wideStoreImm(g: var CodeGen; w: WideRef; i: int; v: int64) =
  ## An immediate into one half. Thumb-2 has no store-immediate, so it goes
  ## through a scratch — but a repeated value (`0` for both halves of a small
  ## positive constant) is materialized once by the caller when it matters.
  let t = g.takeWideRegs(1, "a 64-bit constant half")[0]
  g.movImm(t, v)
  g.wideStore(w, i, t)
  g.dropWideRegs(@[t])

proc wideCopy(g: var CodeGen; dst, src: WideRef) =
  ## `dst = src`, both halves. Aliasing-safe: word 0 is read before word 1 is
  ## written, and no half is written before its own source is read.
  if dst.kind == wrSlot and src.kind == wrSlot and dst.name == src.name and
     dst.off == src.off:
    return
  let t = g.takeWideRegs(1, "a 64-bit copy")[0]
  for i in 0 .. 1:
    g.wideLoad(t, src, i)
    g.wideStore(dst, i, t)
  g.dropWideRegs(@[t])

# ── minting and resolving ───────────────────────────────────────────────────

proc mintWideSlot(g: var CodeGen): string =
  ## A fresh 8-byte `etmp` slot. Declared by the prologue's `spillTemps` loop,
  ## which sizes it from the slot's own `size` — see `emScalarStackVar`.
  result = g.mintSpillName("etmp")
  g.plan.addSpillTemp(result, WideSlot)

proc emitWideInto(g: var CodeGen; c0: Cursor; dst: WideRef)
proc wideDivMod(g: var CodeGen; dst, a, b: WideRef; signed, wantRem: bool)

proc wideSymRef(g: var CodeGen; c: Cursor; scratch: var Reg): WideRef =
  ## The eight bytes of a 64-bit SYMBOL — a local with a stack home, or a
  ## module-level global whose address has to be materialized.
  scratch = NoReg
  let home = g.plan.locationOfSym(symName(c), g.posOf(c))
  case home.kind
  of NamedStack: return slotWide(home.name)
  of NoLoc:
    var cc = c
    let loc = g.asLoc(cc)
    if loc.kind == Glob:
      scratch = g.takeWideRegs(1, "a 64-bit global address")[0]
      g.emGlobalAddr(scratch, loc.name)
      return baseWide(scratch)
    raiseAssert "arkham cortex-m: 64-bit symbol " & symName(c) & " at " & $loc.kind
  else:
    raiseAssert "arkham cortex-m: 64-bit local " & symName(c) & " homed in " & $home.kind

proc wideLvalRef(g: var CodeGen; c: Cursor; scratch: var Reg): WideRef =
  ## The eight bytes an lvalue expression denotes: `(deref p)`, `(dot o f)`,
  ## `(at a i)`. The address goes into a scratch register; the caller frees it.
  scratch = g.takeWideRegs(1, "a 64-bit lvalue address")[0]
  g.emitLvalue2(c)
  g.aggrAddrInto(c, scratch, addrSlot(), doBind = false)
  g.freeLvalTemps2(c)
  baseWide(scratch)

proc stripParens(c: Cursor): Cursor =
  ## Look through `(par …)` / `(suf <value> "sfx")` to the value they wrap. A
  ## plain `inc` rather than `into`: `into` insists its body consume every child,
  ## and only the first one is wanted here.
  result = c
  while result.kind == TagLit and result.exprKind in {SufC, ParC}:
    inc result

proc wideValueSlot(g: var CodeGen; c: Cursor): WideRef =
  ## The eight bytes of ANY 64-bit expression, **in a stack slot**.
  ##
  ## Never a register-relative reference, even when the value already has an
  ## address. A staging bridge is scratch, not a survivor: it does not outlive a
  ## call, and the operand evaluated AFTER this one may contain one — `gs[i] +
  ## f()` would then add through a pointer the callee had overwritten. Paying a
  ## two-word copy for a global or an lvalue is the price of that not being
  ## possible; a plain stack home (which is where every 64-bit local already
  ## lives) costs nothing.
  let cc = stripParens(c)
  if cc.kind == Symbol:
    let home = g.plan.locationOfSym(symName(cc), g.posOf(cc))
    if home.kind == NamedStack: return slotWide(home.name)
  let nm = g.mintWideSlot()
  result = slotWide(nm)
  g.emitWideInto(cc, result)

# ── narrow ↔ wide ───────────────────────────────────────────────────────────

proc wideFromNarrow(g: var CodeGen; dst: WideRef; src: Reg; signed: bool) =
  ## Widen a 32-bit value in `src` to the 64-bit value at `dst`: the low word is
  ## the value, the high word is 0 or its sign.
  g.wideStore(dst, 0, src)
  let t = g.takeWideRegs(1, "a 64-bit widening")[0]
  if signed:
    g.ab.tree Asr3A64: (g.emReg t; g.emReg src; g.ab.intLit 31)
  else:
    g.movImm(t, 0)
  g.wideStore(dst, 1, t)
  g.dropWideRegs(@[t])

proc emitNarrowValueInto(g: var CodeGen; c: Cursor; dest: Reg) =
  ## Emit a NON-wide expression so its value lands in `dest`.
  var v = needsReg(g.valueSlot(c))
  g.emitValue2(c, v)
  g.place2(v, dest)
  g.freeVal(v)

proc wideFromNarrowExpr(g: var CodeGen; dst: WideRef; c: Cursor; signed: bool) =
  ## Widen a NARROWER expression to the 64-bit value at `dst`.
  ##
  ## The source's own width matters as much as its signedness: a `(i 16)` arrives
  ## in a register in its CANONICAL (sign-extended) form, so widening it as
  ## unsigned — which a `cast` does — has to re-normalize the low 32 bits first
  ## or the value is already wrong before the high word is chosen. `cast[int64](
  ## int16(64536))` is 64536, not -1000, and the difference survives into the
  ## answer.
  let t = g.takeWideRegs(1, "a 64-bit widening operand")[0]
  g.emitNarrowValueInto(c, t)
  let (srcW, _) = g.srcWidthSigned(c)
  if srcW < wordBits(): g.extendTo(t, srcW, signed)
  g.wideFromNarrow(dst, t, signed)
  g.dropWideRegs(@[t])

# ── arithmetic ──────────────────────────────────────────────────────────────

proc wideCarryChain(g: var CodeGen; loOp, hiOp: MInst; dst, a, b: WideRef) =
  ## `dst = a <op> b` for the two ops that carry between halves. The store of
  ## the low result and the load of the high operands sit BETWEEN the two
  ## flag-setting instructions; see the module header for why that is safe.
  let t = g.takeWideRegs(1, "a 64-bit carry accumulator")[0]
  g.wideLoad(t, a, 0)
  g.ab.tree loOp: (g.emReg t; g.emReg t; g.emWideWord(b, 0))
  g.wideStore(dst, 0, t)
  g.wideLoad(t, a, 1)
  g.ab.tree hiOp: (g.emReg t; g.emReg t; g.emWideWord(b, 1))
  g.wideStore(dst, 1, t)
  g.dropWideRegs(@[t])

proc wideWordwise(g: var CodeGen; op: A64Inst; dst, a, b: WideRef) =
  ## `dst = a <op> b` for the bitwise ops, which have no inter-half dependency.
  let t = g.takeWideRegs(1, "a 64-bit bitwise accumulator")[0]
  for i in 0 .. 1:
    g.wideLoad(t, a, i)
    g.ab.tree op: (g.emReg t; g.emReg t; g.emWideWord(b, i))
    g.wideStore(dst, i, t)
  g.dropWideRegs(@[t])

proc wideNeg(g: var CodeGen; dst, a: WideRef) =
  ## `dst = -a`, as `0 - a` through the borrow chain.
  let rs = g.takeWideRegs(2, "a 64-bit negation")
  g.movImm(rs[0], 0)
  g.wideLoad(rs[1], a, 0)
  g.ab.tree Subs3M: (g.emReg rs[1]; g.emReg rs[0]; g.emReg rs[1])
  g.wideStore(dst, 0, rs[1])
  g.wideLoad(rs[1], a, 1)
  g.ab.tree Sbcs3M: (g.emReg rs[1]; g.emReg rs[0]; g.emReg rs[1])
  g.wideStore(dst, 1, rs[1])
  g.dropWideRegs(rs)

proc wideNot(g: var CodeGen; dst, a: WideRef) =
  let t = g.takeWideRegs(1, "a 64-bit complement")[0]
  for i in 0 .. 1:
    g.wideLoad(t, a, i)
    g.ab.tree MvnM: (g.emReg t; g.emReg t)
    g.wideStore(dst, i, t)
  g.dropWideRegs(@[t])

proc wideMul(g: var CodeGen; dst, a, b: WideRef) =
  ## The low 64 bits of a 64×64 product:
  ##   `lo:hi = aLo*bLo` (umull), then `hi += aLo*bHi + aHi*bLo`.
  ## The two cross terms only ever contribute to the high word, and the products
  ## above 2^64 are exactly what a wrapping 64-bit multiply discards.
  let rs = g.takeWideRegs(4, "a 64-bit multiply")
  let (t0, t1, t2, t3) = (rs[0], rs[1], rs[2], rs[3])
  g.wideLoad(t0, a, 0)
  g.wideLoad(t1, b, 0)
  g.ab.tree UmullM: (g.emReg t2; g.emReg t3; g.emReg t0; g.emReg t1)
  g.wideStore(dst, 0, t2)                     # the low word is final
  g.wideLoad(t2, b, 1)
  g.ab.tree Mul3A64: (g.emReg t2; g.emReg t0; g.emReg t2)      # aLo*bHi
  g.ab.tree Add3A64: (g.emReg t3; g.emReg t3; g.emReg t2)
  g.wideLoad(t0, a, 1)
  g.ab.tree Mul3A64: (g.emReg t0; g.emReg t0; g.emReg t1)      # aHi*bLo
  g.ab.tree Add3A64: (g.emReg t3; g.emReg t3; g.emReg t0)
  g.wideStore(dst, 1, t3)
  g.dropWideRegs(rs)

proc wideShift(g: var CodeGen; dst, a: WideRef; amount: Cursor; ek: LengExpr;
               signed: bool) =
  ## `dst = a shl/shr n` for a RUNTIME shift count. Branching on `n >= 32` rather
  ## than the branchless mask sequence: this costs two forward branches and saves
  ## two of the four scratch registers, which on this register file is the better
  ## trade — and `asr`'s big-shift case needs a conditional term either way.
  let rs = g.takeWideRegs(4, "a 64-bit shift")
  let (n, lo, hi, t) = (rs[0], rs[1], rs[2], rs[3])
  g.emitNarrowValueInto(amount, n)
  g.wideLoad(lo, a, 0)
  g.wideLoad(hi, a, 1)
  let lBig = g.freshLabel()
  let lEnd = g.freshLabel()
  g.ab.tree CmpA64: (g.emReg n; g.ab.intLit 32)
  g.emBr(BhsA64, lBig)
  # 0 .. 31 — `x shr 32` on Thumb-2's register-shift forms is 0, which is what
  # makes the n = 0 case (a shift by the full width of the other half) correct
  # without a third arm.
  g.movImm(t, 32)
  g.ab.tree Sub3A64: (g.emReg t; g.emReg t; g.emReg n)         # t = 32 - n
  case ek
  of ShlC:
    g.ab.tree Lsl3A64: (g.emReg hi; g.emReg hi; g.emReg n)
    g.ab.tree Lsr3A64: (g.emReg t; g.emReg lo; g.emReg t)
    g.ab.tree Orr3A64: (g.emReg hi; g.emReg hi; g.emReg t)
    g.ab.tree Lsl3A64: (g.emReg lo; g.emReg lo; g.emReg n)
  else:
    g.ab.tree Lsl3A64: (g.emReg t; g.emReg hi; g.emReg t)
    g.ab.tree Lsr3A64: (g.emReg lo; g.emReg lo; g.emReg n)
    g.ab.tree Orr3A64: (g.emReg lo; g.emReg lo; g.emReg t)
    if signed:
      g.ab.tree Asr3A64: (g.emReg hi; g.emReg hi; g.emReg n)
    else:
      g.ab.tree Lsr3A64: (g.emReg hi; g.emReg hi; g.emReg n)
  g.emBr(BA64, lEnd)
  g.emLab(lBig)                                                # 32 .. 63
  g.ab.tree Sub3A64: (g.emReg n; g.emReg n; g.ab.intLit 32)
  case ek
  of ShlC:
    g.ab.tree Lsl3A64: (g.emReg hi; g.emReg lo; g.emReg n)
    g.movImm(lo, 0)
  else:
    if signed:
      g.ab.tree Asr3A64: (g.emReg lo; g.emReg hi; g.emReg n)
      g.ab.tree Asr3A64: (g.emReg hi; g.emReg hi; g.ab.intLit 31)
    else:
      g.ab.tree Lsr3A64: (g.emReg lo; g.emReg hi; g.emReg n)
      g.movImm(hi, 0)
  g.emLab(lEnd)
  g.wideStore(dst, 0, lo)
  g.wideStore(dst, 1, hi)
  g.dropWideRegs(rs)

# ── comparison ──────────────────────────────────────────────────────────────

proc emitWideCmpE(g: var CodeGen; aC, bC: Cursor; ek: LengExpr;
                  whenTrue: bool): A64Inst =
  ## The 64-bit twin of `emitScalarCmpE`: emit the compare, return the branch
  ## that means "the condition holds".
  ##
  ## Equality goes through xor/or rather than the borrow chain, because after a
  ## 64-bit `subs`/`sbcs` the Z flag describes the HIGH word alone — `beq` there
  ## would call `0x1_00000000` equal to `0x2_00000000`. The ordered conditions
  ## read only N/V (signed) or C (unsigned), which the chain does carry, and
  ## `<=` is `>=` with the operands exchanged for the same reason: `ble` reads Z.
  let signed = not (g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC))
  if ek in {EqC, NeqC}:
    let aw = g.wideValueSlot(aC)
    let bw = g.wideValueSlot(bC)
    let rs = g.takeWideRegs(2, "a 64-bit equality test")
    g.wideLoad(rs[0], aw, 0)
    g.ab.tree Eor3A64: (g.emReg rs[0]; g.emReg rs[0]; g.emWideWord(bw, 0))
    g.wideLoad(rs[1], aw, 1)
    g.ab.tree Eor3A64: (g.emReg rs[1]; g.emReg rs[1]; g.emWideWord(bw, 1))
    g.ab.tree Orr3A64: (g.emReg rs[0]; g.emReg rs[0]; g.emReg rs[1])
    g.ab.tree CmpA64: (g.emReg rs[0]; g.ab.intLit 0)
    g.dropWideRegs(rs)
    return if ek == EqC: (if whenTrue: BeqA64 else: BneA64)
           else: (if whenTrue: BneA64 else: BeqA64)
  # `a < b` is the borrow out of `a - b`; `a <= b` is `b >= a`.
  let swapped = ek == LeC
  let lhsC = if swapped: bC else: aC
  let rhsC = if swapped: aC else: bC
  let lw = g.wideValueSlot(lhsC)
  let rw = g.wideValueSlot(rhsC)
  let t = g.takeWideRegs(1, "a 64-bit compare")[0]
  g.wideLoad(t, lw, 0)
  g.ab.tree Subs3M: (g.emReg t; g.emReg t; g.emWideWord(rw, 0))
  g.wideLoad(t, lw, 1)                        # a load never disturbs the flags
  g.ab.tree Sbcs3M: (g.emReg t; g.emReg t; g.emWideWord(rw, 1))
  g.dropWideRegs(@[t])
  # After the chain: "borrow" == lhs < rhs. `swapped` already turned `a <= b`
  # into `b < a`, so the answer for `<=` is the NEGATION of what we test.
  let lt = if signed: BltA64 else: BloA64
  let ge = if signed: BgeA64 else: BhsA64
  if swapped: (if whenTrue: ge else: lt)
  else:       (if whenTrue: lt else: ge)

# ── the wide producer ───────────────────────────────────────────────────────

proc wideCallInto(g: var CodeGen; c: Cursor; dst: WideRef)

proc emitWideInto(g: var CodeGen; c0: Cursor; dst: WideRef) =
  ## Produce the 64-bit value of `c` into the eight bytes at `dst`. THE entry
  ## point: every wide expression form is one arm here, and a form with no arm
  ## is refused by name rather than routed to the 32-bit emitter, which would
  ## compute the low word and call it the answer.
  ##
  ## A NARROWER expression asked for in 64 bits (`f(x32)` where `f` declares an
  ## `int64` parameter) is widened by its OWN signedness. Literals are excluded
  ## from that shortcut and keep their two-halves arm: a literal is materialized
  ## by `movImm`, which is a 32-bit move here, so `4294967296` would widen from a
  ## truncated 0.
  let c = stripParens(c0)
  let isLiteral = c.kind in {IntLit, UIntLit, CharLit} or
                  (c.kind == TagLit and
                   c.exprKind in {TrueC, FalseC, NilC, SizeofC})
  if not isLiteral and g.isFloatExpr(c):
    # `int64(someFloat)`. FPv4-SP converts to a 32-bit integer and no wider, so
    # this needs a runtime routine to be RIGHT for anything past 2^31 — and a
    # `vcvt` plus a sign-extend would be quietly wrong exactly there. Refused by
    # name; `int32(f)` is the conversion this core has.
    lengError c, "arkham cortex-m: converting a float to a 64-bit integer needs a " &
      "runtime routine this backend does not provide — FPv4-SP converts to 32 " &
      "bits (see M5 in doc/cortex_m.md)", lengInfo(c)
  if not isLiteral and not g.isWideExpr(c):
    let sgn = isSignedType(resolveType(g.prog, g.getType(c)))
    g.wideFromNarrowExpr(dst, c, sgn)
    return
  case c.kind
  of IntLit, UIntLit, CharLit:
    let v = case c.kind
            of IntLit: intVal(c)
            of UIntLit: cast[int64](uintVal(c))
            else: int64(ord(charLit(c)))
    let t = g.takeWideRegs(1, "a 64-bit literal")[0]
    g.movImm(t, v and 0xFFFF_FFFF'i64)
    g.wideStore(dst, 0, t)
    g.movImm(t, (v shr 32) and 0xFFFF_FFFF'i64)
    g.wideStore(dst, 1, t)
    g.dropWideRegs(@[t])
  of Symbol:
    var scratch: Reg
    let src = g.wideSymRef(c, scratch)
    g.wideCopy(dst, src)
    if scratch != NoReg: g.unbindTemp(scratch)
  of TagLit:
    case c.exprKind
    of SufC, ParC:
      var inner = c
      inner.into:
        g.emitWideInto(inner, dst)
        skip inner
        while inner.hasMore: skip inner
    of TrueC:  g.wideStoreImm(dst, 0, 1); g.wideStoreImm(dst, 1, 0)
    of FalseC, NilC:
      let t = g.takeWideRegs(1, "a 64-bit zero")[0]
      g.movImm(t, 0)
      g.wideStore(dst, 0, t)
      g.wideStore(dst, 1, t)
      g.dropWideRegs(@[t])
    of SizeofC:
      var t = c
      var sz = 0'i64
      t.into:
        sz = typeSizeAlign(g.prog, t)[0].int64
        while t.hasMore: skip t
      g.wideStoreImm(dst, 0, sz)
      g.wideStoreImm(dst, 1, 0)
    of DerefC, DotC, AtC, PatC:
      var scratch: Reg
      let src = g.wideLvalRef(c, scratch)
      g.wideCopy(dst, src)
      if scratch != NoReg: g.unbindTemp(scratch)
    of AddC, SubC, MulC, DivC, ModC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (isConst, cval) = g.tryConstFold(c)
      if isConst and g.posOf(c) != g.noFoldPos:
        let t = g.takeWideRegs(1, "a folded 64-bit constant")[0]
        g.movImm(t, cval and 0xFFFF_FFFF'i64)
        g.wideStore(dst, 0, t)
        g.movImm(t, (cval shr 32) and 0xFFFF_FFFF'i64)
        g.wideStore(dst, 1, t)
        g.dropWideRegs(@[t])
        return
      var resTypeC, aC, bC: Cursor
      block:
        var cc = c
        cc.into:
          resTypeC = cc; skip cc
          aC = cc; skip cc
          bC = cc; skip cc
          while cc.hasMore: skip cc
      let ek = c.exprKind
      let signed = isSignedType(resolveType(g.prog, resTypeC))
      if ek in {ShlC, ShrC}:
        let aw = g.wideValueSlot(aC)
        g.wideShift(dst, aw, bC, ek, signed)
        return
      let aw = g.wideValueSlot(aC)
      let bw = g.wideValueSlot(bC)
      case ek
      of AddC: g.wideCarryChain(Adds3M, Adcs3M, dst, aw, bw)
      of SubC: g.wideCarryChain(Subs3M, Sbcs3M, dst, aw, bw)
      of BitandC: g.wideWordwise(And3A64, dst, aw, bw)
      of BitorC:  g.wideWordwise(Orr3A64, dst, aw, bw)
      of BitxorC: g.wideWordwise(Eor3A64, dst, aw, bw)
      of MulC: g.wideMul(dst, aw, bw)
      of DivC: g.wideDivMod(dst, aw, bw, signed, wantRem = false)
      of ModC: g.wideDivMod(dst, aw, bw, signed, wantRem = true)
      else: raiseAssert "arkham cortex-m: wide binop " & $ek
    of NegC, BitnotC:
      var resTypeC, innerC: Cursor
      block:
        var cc = c
        cc.into:
          resTypeC = cc; skip cc
          innerC = cc; skip cc
          while cc.hasMore: skip cc
      discard resTypeC
      let aw = g.wideValueSlot(innerC)
      if c.exprKind == NegC: g.wideNeg(dst, aw) else: g.wideNot(dst, aw)
    of CastC, ConvC:
      var targetC, innerC: Cursor
      block:
        var cc = c
        cc.into:
          targetC = cc; skip cc
          innerC = cc; skip cc
          while cc.hasMore: skip cc
      if g.isWideExpr(innerC):
        let src = g.wideValueSlot(innerC)
        g.wideCopy(dst, src)
      elif g.isFloatExpr(innerC):
        lengError c, "arkham cortex-m: converting a float to a 64-bit integer needs " &
          "a runtime routine this backend does not provide — FPv4-SP converts to " &
          "32 bits (see M5 in doc/cortex_m.md)", lengInfo(c)
      else:
        # Widening a narrower value: the SOURCE's signedness decides the high
        # word, not the target's. `uint32(x).int64` must be zero-extended even
        # though `int64` is signed, and `int32(x).uint64` sign-extended even
        # though `uint64` is not — this is the one place where taking the
        # target's sign produces a number wrong by 2^32 that nothing downstream
        # can tell.
        #
        # …and a `cast` is unsigned regardless. `cast` is a REINTERPRETATION of
        # the source's bits, so it zero-extends where `conv` sign-extends; this
        # is `reReprCast2`'s `(not isCast) and srcSigned`, stated again because
        # the wide path does its own widening.
        let it = g.getType(innerC)
        let signedSrc = isSignedType(resolveType(g.prog, it))
        g.wideFromNarrowExpr(dst, innerC, (c.exprKind != CastC) and signedSrc)
    of CallC: g.wideCallInto(c, dst)
    of AddrC, HaddrC, InstrC:
      lengError c, "arkham cortex-m: `" & $c.exprKind &
        "` producing a 64-bit value is not supported", lengInfo(c)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC:
      # A bool widened to 64 bits: emit the 0/1 and zero-extend it.
      g.wideFromNarrowExpr(dst, c, signed = false)
    else:
      lengError c, "arkham cortex-m: 64-bit expression `" & $c.exprKind &
        "` is not supported", lengInfo(c)
  else:
    raiseAssert "arkham cortex-m: 64-bit expression kind " & $c.kind

# ── calls, parameters and returns ───────────────────────────────────────────
#
# A 64-bit scalar travels EXACTLY like a two-word by-value aggregate: two
# consecutive argument registers (`abi.planCall` now sizes a scalar's `words`
# from its slot), or eight bytes of the outgoing stack area, and r0:r1 for a
# result. That is not AAPCS32 — which would even-align the register pair and
# make `f(int32, int64)` use r2:r3 — and it does not have to be: a firmware
# image has nothing to link against, so arkham owns both sides of every call.
# The rule that DOES matter is that the two sides agree, and they agree by
# reading the same `CallPlan`.

proc wideCallInto(g: var CodeGen; c: Cursor; dst: WideRef) =
  ## A 64-bit call result: raw out of r0:r1, straight into memory.
  ##
  ## `dst` must be a SLOT. An address in a register is not a survivor across the
  ## call that just happened — see `wideValueSlot` — so a register-relative
  ## destination lands in a temp and is copied afterwards.
  var d = dontCare
  g.emitCall2(c, d)
  let lo = g.md.intRetReg
  let hi = g.md.intArgRegs[1]
  if dst.kind == wrSlot:
    g.wideStore(dst, 0, lo)
    g.wideStore(dst, 1, hi)
  else:
    let tmp = slotWide(g.mintWideSlot())
    g.wideStore(tmp, 0, lo)
    g.wideStore(tmp, 1, hi)
    g.wideCopy(dst, tmp)

proc emitWideIntoLoc(g: var CodeGen; c: Cursor; dst: Location) =
  ## Produce a 64-bit value into a resolved destination `Location` — the
  ## `genStore2` arm for wide values.
  if dst.kind == NamedStack:
    g.emitWideInto(c, slotWide(dst.name))
    return
  # Anything addressed through a register: compute the VALUE first (its
  # evaluation may contain a call, which the address register would not
  # survive), then take the address and copy.
  let tmp = slotWide(g.mintWideSlot())
  g.emitWideInto(c, tmp)
  let a = g.takeWideRegs(1, "a 64-bit destination address")[0]
  case dst.kind
  of Field: g.emFieldAddr(dst, a)          # &(base.field), however the base is addressed
  of Glob, Tvar, Mem, StackPtr: g.aggrAddrLoc(dst, a)
  else: raiseAssert "arkham cortex-m: 64-bit value into location kind " & $dst.kind
  g.wideCopy(baseWide(a), tmp)
  g.dropWideRegs(@[a])

proc emitWideAsLoc(g: var CodeGen; c: Cursor; dest: var Location) =
  ## The `emitValue2` arm: a 64-bit value has no register to be resolved into,
  ## so it lands in a temp slot and `dest` names that slot.
  ##
  ## `spillTemp` is deliberately FALSE. It means "the emitter must produce into
  ## this through a staging register", and the value is already there. A consumer
  ## that is not wide-aware will try to `mov` the slot into a 32-bit register,
  ## which nifasm rejects as a type mismatch — loudly, and before anything runs.
  if dest.kind == NamedStack and not dest.spillTemp:
    g.emitWideInto(c, slotWide(dest.name))
    return
  let w = g.wideValueSlot(c)
  dest = namedStackLoc(w.name, WideSlot)

proc wideRet(g: var CodeGen; c: Cursor) =
  ## `return <64-bit>` — the value into r0:r1.
  let src = g.wideValueSlot(c)
  g.wideLoad(g.md.intRetReg, src, 0)
  g.wideLoad(g.md.intArgRegs[1], src, 1)

proc wideArgToRegs(g: var CodeGen; slotName: string; firstArg: int) =
  ## A 64-bit call argument into `intArgRegs[firstArg]` and `[firstArg+1]`.
  ##
  ## Takes the SLOT the value was already produced into, not the expression:
  ## producing it here would be inside the `(prepare …)` block, where any
  ## instruction that clobbers r0–r3 destroys the arguments already staged there
  ## — and a 64-bit `div` is a `bl` to the module's divider. See `wideArgSlots`.
  let src = slotWide(slotName)
  g.wideLoad(g.md.intArgRegs[firstArg], src, 0)
  g.wideLoad(g.md.intArgRegs[firstArg + 1], src, 1)

proc wideArgToStack(g: var CodeGen; slotName, paramNm: string) =
  ## A 64-bit call argument into the outgoing stack-argument area, word by word
  ## (`(arg name k)` inside a `(mem (sp) …)` yields byte `k * 4` of the slot).
  let src = slotWide(slotName)
  let t = g.takeWideRegs(1, "a stack-passed 64-bit argument")[0]
  for k in 0 .. 1:
    g.wideLoad(t, src, k)
    g.ab.tree MovA64:
      g.ab.tree MemX:
        g.emReg SP
        g.ab.tree ArgX: (g.ab.sym paramNm; g.ab.intLit k.int64)
      g.emReg t
  g.dropWideRegs(@[t])

proc wideParamToHome(g: var CodeGen; nm: string; firstArg: int) =
  ## The callee side: the two incoming argument registers into the parameter's
  ## stack home. (Its slot was declared by the caller of this proc.)
  let home = slotWide(nm)
  g.wideStore(home, 0, g.md.intArgRegs[firstArg])
  g.wideStore(home, 1, g.md.intArgRegs[firstArg + 1])

# ── the narrowing direction ─────────────────────────────────────────────────

proc emitWideToNarrow(g: var CodeGen; innerC, targetC: Cursor;
                      dest: var Location) =
  ## `(conv (i 32) <64-bit>)` and friends: the low word IS the answer, then
  ## re-normalized to the target's own width so a sub-word result stays
  ## canonically extended in its register.
  let src = g.wideValueSlot(innerC)
  g.forceRegDestE(dest)
  if dest.kind != InReg:
    # The pools were dry, so `dest` is a produce-into slot. Stage through the
    # produce bridge, which exists for exactly this.
    let b = g.produceBridge
    g.bindTemp(b, ScalarSlot)
    g.wideLoad(b, src, 0)
    let tslot = slotOf(g.prog, targetC)
    g.extendTo(b, tslot.size * 8, tslot.kind == AInt)
    g.storeReg2(dest, b)
    g.unbindTemp(b)
    return
  if dest.isTemp and not g.rb.isBoundTemp(dest.r):
    g.bindTemp(dest.r, slotOf(g.prog, targetC))
  g.wideLoad(dest.r, src, 0)
  let tslot = slotOf(g.prog, targetC)
  g.extendTo(dest.r, tslot.size * 8, tslot.kind == AInt)

proc emWideStackVar(g: var CodeGen; name: string) =
  ## `(var :name (s) (i 64))` — the eight-byte cell of a 64-bit expression temp.
  ## `emScalarStackVar` declares a slot at the target WORD, which here is four
  ## bytes: the high half would land on whatever slot the allocator put next.
  g.plan.hasStackVars = true
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc wideArgTruncated(g: var CodeGen; slotName: string; dest: Reg) =
  ## A 64-bit argument passed to a NARROWER declared parameter: the low word,
  ## which is the truncation C performs and Leng's front end relies on
  ## (`exit(x + y)` where `x`/`y` are `int64` and `exit` takes a `cint`).
  ##
  ## Spelled out at the call site because the ABI follows the CALLEE's
  ## declaration — see `calleeParamSlots`. Left to the general value path it
  ## would be a 64-bit value handed a 32-bit register, which has no right answer.
  g.wideLoad(dest, slotWide(slotName), 0)

proc wideValueIntoTemp(g: var CodeGen; valC: Cursor): string =
  ## Produce a 64-bit value into a stack slot and hand back the slot's NAME.
  ##
  ## The name rather than a `WideRef` because the callers are in the shared part
  ## of the emitter, above this include, where the type is not in scope yet — and
  ## because the value has to exist BEFORE its destination address is computed
  ## (its evaluation may contain a call, which a staging bridge does not survive).
  g.wideValueSlot(valC).name

proc wideCopyToAddr(g: var CodeGen; slotName: string; addrReg: Reg) =
  ## The eight bytes of slot `slotName` to `[addrReg]`.
  g.wideCopy(baseWide(addrReg), slotWide(slotName))

# ── 64-bit division ─────────────────────────────────────────────────────────
#
# ARMv7E-M has `sdiv`/`udiv` for 32 bits and nothing for 64, and a firmware
# image has no `libgcc` to borrow `__aeabi_ldivmod` from. So the image carries
# its own: a restoring shift-subtract divider, emitted ONCE per module and only
# when something divides.
#
# The routines are called with a bare `(bl)` and read their arguments raw out of
# r0–r3, like the semihosting shims — arkham owns both sides, and a `(prepare)`
# block would only restate an ABI that is fixed here. What that DOES cost is the
# frame: `bl` overwrites lr, so a proc that looked like a leaf until it divided
# has to be told (see `helperCalls`).

const
  UDivMod64Proc = "`udivmod64.0"
    ## `(N: r0:r1, D: r2:r3)` → quotient in r0:r1, remainder in r2:r3.
  SDivMod64Proc = "`sdivmod64.0"
    ## The signed wrapper: |N| div |D| through the unsigned routine, then the
    ## signs put back. Truncating toward zero, and the remainder takes the
    ## DIVIDEND's sign — C's rule, and Leng's.

proc mReg(g: var CodeGen; r: Reg) {.inline.} = g.ab.reg r
  ## A RAW register in a hand-written body. Not `emReg`: these bodies are not
  ## allocator output, so their r0–r7 uses are correct by construction and must
  ## not trip the unbound-scratch assertion that exists to catch a temp which
  ## escaped the binder.

proc emitUDivMod64(g: var CodeGen) =
  ## The unsigned 64-bit divider.
  ##
  ## One bit per iteration: shift the 128-bit pair `R:N` left, and whenever the
  ## remainder has caught up with the divisor subtract it and set the bit that
  ## just vacated N's bottom. After 64 iterations N has been consumed entirely
  ## and holds the quotient — which is why no separate quotient register exists.
  ##
  ## Division by zero yields zero, matching what the hardware `udiv` on this
  ## core does (with DIV_0_TRP off) rather than the all-ones a shift-subtract
  ## loop would otherwise produce.
  let lZero = g.freshLabel()
  let lLoopEnd = g.freshLabel()
  let lDone = g.freshLabel()
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef UDivMod64Proc
    g.ab.keyword NifasmDecl.ParamsD
    g.ab.keyword NifasmDecl.ResultD
    g.ab.tree NifasmDecl.ClobberD:
      for r in machine_m.ConvClobbersGpr: g.ab.reg r
    g.ab.tree StmtsA64:
      g.ab.tree SubA64: (g.mReg SP; g.ab.intLit 16)
      for i, r in [R4, R5, R6, R7]:
        g.ab.tree StrA64:
          g.ab.tree MemX: (g.mReg SP; g.ab.intLit int64(4 * i))
          g.mReg r
      # D == 0 → everything zero, like `udiv`.
      g.ab.tree MovA64: (g.mReg R7; g.mReg R2)
      g.ab.tree OrrA64: (g.mReg R7; g.mReg R3)
      g.ab.tree CmpA64: (g.mReg R7; g.ab.intLit 0)
      g.emBr(BneA64, lZero)
      g.ab.tree MovA64: (g.mReg R0; g.ab.intLit 0)
      g.ab.tree MovA64: (g.mReg R1; g.ab.intLit 0)
      g.emBr(BA64, lDone)
      g.emLab(lZero)
      g.ab.tree MovA64: (g.mReg R4; g.ab.intLit 0)     # R.lo
      g.ab.tree MovA64: (g.mReg R5; g.ab.intLit 0)     # R.hi
      g.ab.tree MovA64: (g.mReg R6; g.ab.intLit 64)    # bits to go
      g.ab.tree LoopA64:
        g.ab.tree StmtsA64:
          let lSub = g.freshLabel()
          let lSkip = g.freshLabel()
          # R:N <<= 1
          g.ab.tree Lsr3A64: (g.mReg R7; g.mReg R4; g.ab.intLit 31)
          g.ab.tree LslA64:  (g.mReg R5; g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.mReg R5; g.mReg R7)
          g.ab.tree Lsr3A64: (g.mReg R7; g.mReg R1; g.ab.intLit 31)
          g.ab.tree LslA64:  (g.mReg R4; g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.mReg R4; g.mReg R7)
          g.ab.tree Lsr3A64: (g.mReg R7; g.mReg R0; g.ab.intLit 31)
          g.ab.tree LslA64:  (g.mReg R1; g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.mReg R1; g.mReg R7)
          g.ab.tree LslA64:  (g.mReg R0; g.ab.intLit 1)
          # if R >= D
          g.ab.tree CmpA64: (g.mReg R5; g.mReg R3)
          g.emBr(BloA64, lSkip)
          g.emBr(BhiA64, lSub)
          g.ab.tree CmpA64: (g.mReg R4; g.mReg R2)
          g.emBr(BhsA64, lSub)
          g.emBr(BA64, lSkip)
          g.emLab(lSub)
          g.ab.tree Subs3M: (g.mReg R4; g.mReg R4; g.mReg R2)
          g.ab.tree Sbcs3M: (g.mReg R5; g.mReg R5; g.mReg R3)
          g.ab.tree OrrA64: (g.mReg R0; g.ab.intLit 1)
          g.emLab(lSkip)
          g.ab.tree SubA64: (g.mReg R6; g.ab.intLit 1)
          g.ab.tree CmpA64: (g.mReg R6; g.ab.intLit 0)
          g.emBr(BeqA64, lLoopEnd)               # the ONLY way out of the loop
      g.emLab(lLoopEnd)
      g.ab.tree MovA64: (g.mReg R2; g.mReg R4)   # the remainder
      g.ab.tree MovA64: (g.mReg R3; g.mReg R5)
      g.emLab(lDone)
      for i, r in [R4, R5, R6, R7]:
        g.ab.tree LdrA64:
          g.mReg r
          g.ab.tree MemX: (g.mReg SP; g.ab.intLit int64(4 * i))
      g.ab.tree AddA64: (g.mReg SP; g.ab.intLit 16)
      g.ab.keyword RetA64

proc emitSDivMod64(g: var CodeGen) =
  ## The signed wrapper. Negation is `(x xor m) - m` with `m` the sign as a
  ## 0/-1 mask, which is branchless and — unlike a compare-and-negate — right
  ## for the most negative value too.
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef SDivMod64Proc
    g.ab.keyword NifasmDecl.ParamsD
    g.ab.keyword NifasmDecl.ResultD
    g.ab.tree NifasmDecl.ClobberD:
      for r in machine_m.ConvClobbersGpr: g.ab.reg r
    g.ab.tree StmtsA64:
      g.ab.tree SubA64: (g.mReg SP; g.ab.intLit 16)
      for i, r in [R4, R5, R6]:
        g.ab.tree StrA64:
          g.ab.tree MemX: (g.mReg SP; g.ab.intLit int64(4 * i))
          g.mReg r
      g.ab.tree StrA64:
        g.ab.tree MemX: (g.mReg SP; g.ab.intLit 12)
        g.mReg machine_m.LR
      g.ab.tree Asr3A64: (g.mReg R4; g.mReg R1; g.ab.intLit 31)   # sign of N
      g.ab.tree MovA64:  (g.mReg R5; g.mReg R4)                   # remainder's sign
      g.ab.tree EorA64:  (g.mReg R0; g.mReg R4)                   # N = |N|
      g.ab.tree EorA64:  (g.mReg R1; g.mReg R4)
      g.ab.tree Subs3M:  (g.mReg R0; g.mReg R0; g.mReg R4)
      g.ab.tree Sbcs3M:  (g.mReg R1; g.mReg R1; g.mReg R4)
      g.ab.tree Asr3A64: (g.mReg R6; g.mReg R3; g.ab.intLit 31)   # sign of D
      g.ab.tree EorA64:  (g.mReg R4; g.mReg R6)                   # quotient's sign
      g.ab.tree EorA64:  (g.mReg R2; g.mReg R6)                   # D = |D|
      g.ab.tree EorA64:  (g.mReg R3; g.mReg R6)
      g.ab.tree Subs3M:  (g.mReg R2; g.mReg R2; g.mReg R6)
      g.ab.tree Sbcs3M:  (g.mReg R3; g.mReg R3; g.mReg R6)
      g.ab.tree BlA64: g.ab.sym UDivMod64Proc
      g.ab.tree EorA64:  (g.mReg R0; g.mReg R4)
      g.ab.tree EorA64:  (g.mReg R1; g.mReg R4)
      g.ab.tree Subs3M:  (g.mReg R0; g.mReg R0; g.mReg R4)
      g.ab.tree Sbcs3M:  (g.mReg R1; g.mReg R1; g.mReg R4)
      g.ab.tree EorA64:  (g.mReg R2; g.mReg R5)
      g.ab.tree EorA64:  (g.mReg R3; g.mReg R5)
      g.ab.tree Subs3M:  (g.mReg R2; g.mReg R2; g.mReg R5)
      g.ab.tree Sbcs3M:  (g.mReg R3; g.mReg R3; g.mReg R5)
      for i, r in [R4, R5, R6]:
        g.ab.tree LdrA64:
          g.mReg r
          g.ab.tree MemX: (g.mReg SP; g.ab.intLit int64(4 * i))
      g.ab.tree LdrA64:
        g.mReg machine_m.LR
        g.ab.tree MemX: (g.mReg SP; g.ab.intLit 12)
      g.ab.tree AddA64: (g.mReg SP; g.ab.intLit 16)
      g.ab.keyword RetA64

proc wideDivMod(g: var CodeGen; dst, a, b: WideRef; signed, wantRem: bool) =
  ## `dst = a div b` / `a mod b`, through the module's divider.
  ##
  ## Every store-forwarding mirror dies here for the same reason it dies at a
  ## real call: the routine clobbers r0–r3. The proc's frame is forced too — a
  ## `bl` overwrites lr, and nothing in the analyser's view of this expression
  ## says "call".
  g.killAllMirrors()
  g.helperCalls = true
  g.needsUDiv64 = true
  if signed: g.needsSDiv64 = true
  g.wideLoad(g.md.intArgRegs[0], a, 0)
  g.wideLoad(g.md.intArgRegs[1], a, 1)
  g.wideLoad(g.md.intArgRegs[2], b, 0)
  g.wideLoad(g.md.intArgRegs[3], b, 1)
  g.ab.tree BlA64: g.ab.sym (if signed: SDivMod64Proc else: UDivMod64Proc)
  let lo = if wantRem: g.md.intArgRegs[2] else: g.md.intArgRegs[0]
  let hi = if wantRem: g.md.intArgRegs[3] else: g.md.intArgRegs[1]
  if dst.kind == wrSlot:
    g.wideStore(dst, 0, lo)
    g.wideStore(dst, 1, hi)
  else:
    let tmp = slotWide(g.mintWideSlot())
    g.wideStore(tmp, 0, lo)
    g.wideStore(tmp, 1, hi)
    g.wideCopy(dst, tmp)
