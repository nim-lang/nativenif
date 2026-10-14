#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `.assembler` bodies on x86-64: transliteration, not compilation.
##
## A `.assembler` proc is machine code the author wrote; arkham's job is to
## check it and pass it through, not to allocate or schedule anything. So every
## local is pinned where its pragma says, no temp pool is consulted, and an
## instruction arkham does not recognise is a refusal rather than a lowering.

import std / [tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planner, programs, asmbuf,
                    context, diag, asmcommon, 
                    mirrors, regbind, exprpred]
import machine as machine_x64
import emit, mem, value, frame

include compat2   # getOrQuit on host Nim

type
  AsmDeclLoc* = object
    ## Where a `.assembler` param/local was DECLARED to live — the shared
    ## `AsmDeclSpec` with its register name resolved against THIS target's file.
    kind*: AsmDeclKind
    r*: Reg

proc asmStmt*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {})
proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor)

proc x64RegByName(name: string): Reg =
  ## `"rdi"` → `RDI`. The inverse of `x64RegName`, over the 16 GPRs; `NoReg` for
  ## anything else (including `rsp`/`rbp`, which the frame owns — see `asmPinReg`).
  result = NoReg
  for r in [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15]:
    if x64RegName(r) == name: return r

proc asmPinReg*(g: var CodeGen; at: Cursor; name: string): Reg =
  ## Resolve a `.register: "…"` spelling to a register, rejecting the ones the
  ## proc's own frame owns: `rsp`/`rbp` move under the prologue's pushes, so a
  ## value pinned there would be silently destroyed.
  result = x64RegByName(name)
  if result == NoReg:
    lengError at, "`" & name & "` is not an x86-64 general-purpose register", g.asmInfo
  if result in {RSP, RBP}:
    lengError at, "`" & name & "` is reserved for the stack frame and cannot hold a value",
              g.asmInfo

proc asmDeclLoc*(g: var CodeGen; prag: Cursor): AsmDeclLoc =
  ## `(pragmas (register "rax"))` / `(pragmas (stack))`, read by `asmDeclSpec` and
  ## resolved here: which spelling names a register is the one part of a location
  ## pragma that is not target-neutral.
  let spec = asmDeclSpec(prag)
  case spec.kind
  of aslNone: AsmDeclLoc(kind: aslNone, r: NoReg)
  of aslReg: AsmDeclLoc(kind: aslReg, r: g.asmPinReg(spec.at, spec.name))
  of aslStack: AsmDeclLoc(kind: aslStack, r: NoReg)

proc x64FlagOf(op: IntrinsicOp): X64Flag =
  ## The nifasm condition tag a flag-read row denotes. `(ite (zf) …)` already
  ## exists in the assembler with all ten x86 conditions, so a flag intrinsic is
  ## no new mechanism — the row says which bit and which polarity, and this maps
  ## the one enum to the other. Name-for-name, `of`/`no` included (they were once
  ## `ovf`/`novf`, for want of a keyword in ident position).
  case op
  of ZfOp: ZfO
  of NotZfOp: NzO
  of CfOp: CfO
  of NotCfOp: NcO
  of SfOp: SfO
  of NotSfOp: NsO
  of OfOp: OfO
  of NotOfOp: NoO
  of PfOp: PfO
  of NotPfOp: NpO
  else: NoFlag

proc asmScanLocs*(g: var CodeGen; c: Cursor; used: var set[Reg]; anyStack: var bool) =
  ## Pre-pass over the body: which registers the locals pin (so the prologue knows
  ## which callee-saved ones to push) and whether any `(s)` slot exists (so the
  ## prologue reserves the `(ssize)` region the epilogue releases). Both facts are
  ## needed BEFORE the first statement is emitted, and both are pure declaration
  ## reading — no evaluation is involved.
  if c.kind != TagLit: return
  if c.stmtKind == VarS:
    var cc = c
    cc.into:
      inc cc                                     # name
      let loc = g.asmDeclLoc(cc)
      case loc.kind
      of aslReg: used.incl loc.r
      of aslStack: anyStack = true
      of aslNone: discard
      while cc.hasMore: skip cc
    return
  if c.stmtKind in {ProcS, TypeS}: return
  var cc = c
  cc.into:
    while cc.hasMore: (g.asmScanLocs(cc, used, anyStack); skip cc)

# ── flag liveness ────────────────────────────────────────────────────────────
# A flag is a value with no register behind it, written by nearly every ALU
# instruction as a side effect. In a carry chain or a `cmov` the flag IS the
# data, and the classic way to get such code wrong is an instruction between
# definition and use that overwrites it: a `mul` or a rotate between two `adc`s
# silently breaks a bignum add. So the body is walked with the set of flags
# that hold a known definition, and a read of any other is rejected. The
# effects below are x86-64's, stated per instruction rather than read from the
# intrinsic table's `defs` column, which records what a row SETS but not what
# it leaves undefined.

const AllFlags = {mfZF, mfCF, mfSF, mfOF, mfPF}

proc asmFlagEffect(op: IntrinsicOp; c: Cursor): tuple[clobber, define: set[MachineFlag]] =
  ## What executing `op` does to the flags: `clobber` loses its definition,
  ## `define` gains one.
  case op
  of CmpOp, TestOp, AddOp, SubOp, AndOp, OrOp, XorOp, NegOp, AdcOp, SbbOp, PopcntOp:
    (AllFlags, AllFlags)
  of IncOp, DecOp:
    (AllFlags - {mfCF}, AllFlags - {mfCF})          # CF is preserved
  of ShlOp, ShrOp, SarOp:
    # a count of 0 leaves every flag alone, any other count defines all but OF
    # (OF only for a count of 1); a register count may be either
    var count = c
    var lit = false
    var nonZero = false
    if c.kind == TagLit:
      count.into:
        skip count                                   # callee
        if count.hasMore: skip count                 # destination
        if count.hasMore:
          let a = asmAtom(count)
          if a.kind == IntLit: (lit = true; nonZero = intVal(a) != 0)
          elif a.kind == UIntLit: (lit = true; nonZero = uintVal(a) != 0'u64)
        while count.hasMore: skip count
    if lit and not nonZero: ({}, {})
    elif lit: (AllFlags, AllFlags - {mfOF})
    else: (AllFlags, {})
  of NotOp, BswapPinnedOp, StackPointerOp, TraceTableOp, TlsSizeOp,
     CmovzOp..CmovleOp:
    ({}, {})
  of RolOp, RorOp:
    ({mfCF, mfOF}, {mfCF})
  of BsfOp, BsrOp:
    (AllFlags, {mfZF})
  of MulOp, ImulOp:
    (AllFlags, {mfCF, mfOF})
  of ZfOp, NotZfOp, CfOp, NotCfOp, SfOp, NotSfOp, OfOp, NotOfOp, PfOp, NotPfOp:
    ({}, {})                                         # a flag READ changes nothing
  else:
    (AllFlags, {})                                   # unknown lowering: assume the worst

proc flagNames(fs: set[MachineFlag]): string =
  result = ""
  for f in fs:
    if result.len > 0: result.add ", "
    result.add (case f
                of mfZF: "ZF"
                of mfCF: "CF"
                of mfSF: "SF"
                of mfOF: "OF"
                of mfPF: "PF")

const CarryProducers = {AddOp, SubOp, AdcOp, SbbOp, NegOp, CmpOp,
                        # a logic op CLEARS CF: `xor(t, t)` before an `adc`
                        # chain is the idiom for a carry-in of zero
                        AndOp, OrOp, XorOp, TestOp}
  ## The instructions whose CF is an arithmetic CARRY (or borrow). `mul`, a
  ## rotate, a shift or `bsf` also set CF, but to something else entirely —
  ## the bit shifted out, "the high half is non-zero" — which is fine for `cf()`
  ## and never what an `adc` means.

proc asmUseFlags(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## Reject a read of a flag that has no known definition here.
  let uses = IntrinsicRows[op].uses
  let missing = uses - g.asmFlags
  if missing != {}:
    lengError c, "`" & IntrinsicNames[op] & "` reads " & flagNames(missing) &
              ", which is not defined here: no instruction on every path to this " &
              "one sets it, or one in between (a `mul`, a rotate, a shift, …) " &
              "overwrote it", g.asmInfo
  if op in {AdcOp, SbbOp} and g.asmCfBy notin CarryProducers:
    lengError c, "`" & IntrinsicNames[op] & "` reads CF as a carry, but the last " &
              "instruction to set CF was `" & IntrinsicNames[g.asmCfBy] &
              "`, whose CF is not one", g.asmInfo

proc asmApplyFlags(g: var CodeGen; op: IntrinsicOp; c: Cursor) =
  let (clobber, define) = asmFlagEffect(op, c)
  g.asmFlags = (g.asmFlags - clobber) + define
  if mfCF in define: g.asmCfBy = op
  elif mfCF in clobber: g.asmCfBy = NoIntrinsicOp

proc isAsmMemExpr(c: Cursor): bool {.inline.} =
  ## A memory access through a pointer: `p[i]` on a `ptr UncheckedArray`
  ## (`(pat p i)`), `p[]` (`(deref p)`) or `p.f` (`(dot (deref p) f)`).
  c.kind == TagLit and c.exprKind in {PatC, DerefC, DotC}

proc asmPtrBase(g: var CodeGen; c: Cursor) =
  ## The base of an address: a pointer that already sits in a declared
  ## register. Anything else would have to be computed into a register first,
  ## and `.assembler` does not invent registers.
  if c.kind != Symbol or g.isAsmStackSym(c):
    lengError c, "an `.assembler` memory operand must be addressed through a " &
              "pointer held in a `{.register: \"…\".}` local or parameter", g.asmInfo
  g.emReg g.asmRegOf(c)

proc asmAddr(g: var CodeGen; c: Cursor) =
  ## The ADDRESS a memory expression denotes, as nifasm's typed address forms:
  ## `(at base idx)` for an array element and `(dot base field)` for a field.
  ## nifasm checks the types — `at` only through an `aptr`, a field only of the
  ## pointee's object type — so a wrong access is a type error, not a wrong
  ## displacement.
  case c.exprKind
  of PatC:
    var cc = c
    cc.into:
      let base = cc
      skip cc
      let idx = asmAtom(cc)
      g.ab.tree AtX:
        g.asmPtrBase(base)
        case idx.kind
        of IntLit: g.ab.intLit intVal(idx)
        of UIntLit: g.ab.intLit cast[int64](uintVal(idx))
        of Symbol:
          # a register index; nifasm folds it into the addressing mode when the
          # element size is a legal scale and rejects the access otherwise
          g.emReg g.asmRegOf(idx)
        else:
          lengError idx, "an `.assembler` index must be a literal or a register local",
                    g.asmInfo
      skip cc
      while cc.hasMore: skip cc
  of DerefC:
    var cc = c
    cc.into:
      g.asmPtrBase(cc)
      skip cc
      while cc.hasMore: skip cc
  of DotC:
    var cc = c
    cc.into:
      let obj = cc
      skip cc
      let fld = cc
      if not (obj.kind == TagLit and obj.exprKind == DerefC) or fld.kind != Symbol:
        lengError c, "an `.assembler` field access must be `p.field` through a " &
                  "pointer in a register", g.asmInfo
      g.ab.tree DotX:
        var oc = obj
        oc.into:
          g.asmPtrBase(oc)
          skip oc
          while oc.hasMore: skip oc
        g.ab.sym fld.symId
      skip cc
      while cc.hasMore: skip cc
  else:
    lengError c, "unsupported `.assembler` memory operand", g.asmInfo

proc asmMem(g: var CodeGen; c: Cursor) {.inline.} =
  g.ab.tree MemX: g.asmAddr(c)

proc isMemOperand(g: CodeGen; c: Cursor): bool {.inline.} =
  isAsmMemExpr(c) or g.isAsmStackSym(c)

proc asmOperand*(g: var CodeGen; cur: Cursor) =
  ## One source operand of a flag-defining instruction: a register local, a stack
  ## slot, or a literal. Unlike `asmRegOf` this permits memory and immediates,
  ## because `cmp`/`test` take them directly — no materialisation involved.
  let c = asmAtom(cur)
  case c.kind
  of Symbol:
    if g.isAsmStackSym(c): g.emStackMem(c.symId)
    else: g.emReg g.asmRegOf(c)
  of IntLit: g.ab.intLit intVal(c)
  of UIntLit: g.ab.intLit cast[int64](uintVal(c))
  of TagLit:
    if isAsmMemExpr(c): g.asmMem(c)
    else:
      lengError c, "an `.assembler` operand must be a variable, a literal or a " &
                "memory access through a pointer register", g.asmInfo
  else:
    lengError c, "an `.assembler` operand must be a variable or a literal", g.asmInfo

proc asmNarrowType(g: CodeGen; c: Cursor): Cursor =
  ## The Leng type of a register destination declared narrower than 64 bits,
  ## or nil. A `uint32` local takes a 32-bit `add`: the declared type says what
  ## the instruction is, exactly as it does for a load or a store.
  result = default(Cursor)
  var d = c
  if d.kind == TagLit and d.exprKind == HaddrC: inc d
  if d.kind != Symbol or d.symId in g.asmStack: return
  let t = g.symType.getOrDefault(d.symId, default(Cursor))
  if cursorIsNil(t) or t.kind != TagLit or t.typeKind notin {LengType.IT, LengType.UT, LengType.CT}: return
  let bits = typeBits(t)
  if bits > 0 and bits < 64: result = t

proc asmInoutDest*(g: var CodeGen; c: Cursor) =
  ## Emit the destination of a two-address row. The operand arrives as
  ## `(haddr d)` — the compiler binding d's LOCATION for a `var` parameter, not
  ## the user taking a pointer (see nimony/doc/tags.md). So it resolves to d's
  ## DECLARED home and nothing is materialised: that tag is the whole reason this
  ## needs no "an `addr` here means something else" rule.
  if c.kind != TagLit or c.exprKind != HaddrC:
    lengError c, "the destination of a two-address instruction must be a `var` " &
              "argument naming a local", g.asmInfo
  var inner = c
  var sym = c
  inner.into:
    sym = inner; skip inner
    while inner.hasMore: skip inner
  if isAsmMemExpr(sym):
    # `add(p[i], x)`: the destination is memory, read and written in place
    g.asmMem(sym)
    return
  if sym.kind != Symbol:
    lengError sym, "the destination of a two-address instruction must be a local " &
              "with a declared location", g.asmInfo
  let nm = sym.symId
  if nm in g.asmStack: g.emStackMem(nm)
  else: g.emReg g.asmRegOf(sym)

proc asmFixedDest(g: var CodeGen; c: Cursor; want: Reg; what: string) =
  ## A `var` operand the instruction writes in a register of its own choosing.
  var d = c
  if d.kind == TagLit and d.exprKind == HaddrC: inc d
  if d.kind != Symbol or g.isAsmStackSym(d) or g.asmRegOf(d) != want:
    lengError c, what & " of `mul` must be a local pinned to " & x64RegName(want) &
              " — the instruction writes it there and nowhere else", g.asmInfo

proc asmMul(g: var CodeGen; c: Cursor; args: seq[Cursor]) =
  ## `mul(lo, hi, s)`: `rdx:rax = rax * s`. The signature names all three, so the
  ## two results are visible to the reader, and the pins are CHECKED rather than
  ## implied — the one-operand encoding has nowhere else to put them.
  g.asmFixedDest(args[0], RAX, "the first operand (the low half, and the multiplicand)")
  g.asmFixedDest(args[1], RDX, "the second operand (the high half)")
  let s = args[2]
  if s.kind in {IntLit, UIntLit}:
    lengError c, "`mul` takes no immediate; load the multiplier into a register",
              g.asmInfo
  if s.kind == Symbol and not g.isAsmStackSym(s) and g.asmRegOf(s) == RDX:
    lengError c, "the multiplier of `mul` cannot be rdx: the instruction overwrites " &
              "it with the high half", g.asmInfo
  g.ab.tree MulX64: g.asmOperand(s)

proc asmInoutInstrImpl(g: var CodeGen; c: Cursor; op: IntrinsicOp)

proc asmInoutInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `add(d, s)` / `neg(d)` — a row that writes THROUGH operand 0 and returns
  ## nothing. Statement-only, since there is no value to bind.
  g.asmUseFlags(c, op)
  g.asmInoutInstrImpl(c, op)
  g.asmApplyFlags(op, c)

proc asmInoutInstrImpl(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let row = IntrinsicRows[op]
  if argCurs.len != row.arity:
    lengError c, "`" & IntrinsicNames[op] & "` takes " & $row.arity & " operand(s)",
              g.asmInfo
  if op == MulOp:
    g.asmMul(c, argCurs)
    return
  let tag = inoutInst(op)
  if tag == NopX64:
    lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 two-address form",
              g.asmInfo
  if row.arity == 1:
    g.ab.tree tag: g.asmInoutDest(argCurs[0])
  else:
    var d = argCurs[0]
    if d.kind == TagLit and d.exprKind == HaddrC: inc d
    if g.isMemOperand(argCurs[1]) and g.isMemOperand(d):
      # `(add [mem], [mem])` does not exist. Only flagged when BOTH are memory;
      # a memory destination with a register or immediate source is fine.
      lengError c, "`" & IntrinsicNames[op] & "` cannot take two memory operands",
                g.asmInfo
    if op in {AddOp, SubOp, AndOp, OrOp, XorOp}:
      let narrow = g.asmNarrowType(argCurs[0])
      if not cursorIsNil(narrow):
        # nifasm's width-cast destination: the operation runs at the declared
        # width (a 32-bit one zero-extends), flags included
        g.ab.tree tag:
          g.ab.tree CastX:
            var tc = narrow
            g.genTypeBody(tc)
            var d = argCurs[0]
            if d.kind == TagLit and d.exprKind == HaddrC: inc d
            g.emReg g.asmRegOf(d)
          g.asmOperand(argCurs[1])
        return
    if op in {CmovzOp..CmovleOp, ImulOp}:
      # a conditional move and a two-operand multiply write a REGISTER and take
      # no immediate: the encodings do not exist
      if g.isMemOperand(d):
        lengError c, "the destination of `" & IntrinsicNames[op] &
                  "` must be a register", g.asmInfo
      if op != ImulOp and argCurs[1].kind in {IntLit, UIntLit}:
        lengError c, "`" & IntrinsicNames[op] & "` takes no immediate; load it " &
                  "into a register first", g.asmInfo
    g.ab.tree tag: (g.asmInoutDest(argCurs[0]); g.asmOperand(argCurs[1]))

proc asmFlagInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `cmp(a, b)` / `test(a, b)` — an instruction whose entire output is flags.
  ## It is a statement, never a value: there is nothing to bind.
  g.asmApplyFlags(op, c)
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  if argCurs.len != 2:
    lengError c, "`" & IntrinsicNames[op] & "` takes two operands", g.asmInfo
  if g.isAsmStackSym(argCurs[0]) and g.isAsmStackSym(argCurs[1]):
    lengError c, "`" & IntrinsicNames[op] & "` cannot take two memory operands",
              g.asmInfo
  let tag = if op == CmpOp: CmpX64 else: TestX64
  g.ab.tree tag: (g.asmOperand(argCurs[0]); g.asmOperand(argCurs[1]))

proc asmAsgn*(g: var CodeGen; c: Cursor) =
  ## `(asgn dest src)` — the only shape that produces a value. `dest` is an atom
  ## with a declared home; `src` is an atom, a literal, or ONE `(instr …)`.
  var cc = c
  cc.into:
    let destC = cc
    skip cc
    let srcC = asmAtom(cc)
    if isAsmMemExpr(destC):
      # a STORE: `p[i] = x`. The source must be a register or an immediate —
      # memory to memory needs a scratch register no one declared.
      if g.isMemOperand(srcC):
        lengError srcC, "a memory-to-memory move needs a scratch register; " &
                  "assign through a `{.register: \"…\".}` local", g.asmInfo
      g.ab.tree MovX64:
        g.asmMem(destC)
        case srcC.kind
        of Symbol: g.emReg g.asmRegOf(srcC)
        of IntLit: g.ab.intLit intVal(srcC)
        of UIntLit: g.ab.intLit cast[int64](uintVal(srcC))
        else:
          lengError srcC, "a store needs a register or a literal", g.asmInfo
      skip cc
      while cc.hasMore: skip cc
      return
    # A `{.stack.}` local is a memory operand, so a move touching one is `mov
    # [slot], reg` / `mov reg, [slot]`. Memory on BOTH sides would take a scratch
    # register no one declared — the one thing `.assembler` will not invent.
    if g.isAsmStackSym(destC):
      if g.isAsmStackSym(srcC):
        lengError srcC, "a memory-to-memory move needs a scratch register; " &
                  "assign through a `{.register: \"…\".}` local", g.asmInfo
      let nm = destC.symId
      case srcC.kind
      of Symbol:
        g.ab.tree MovX64: (g.emStackMem(nm); g.emReg g.asmRegOf(srcC))
      of IntLit:
        g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit intVal(srcC))
      of UIntLit:
        g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit cast[int64](uintVal(srcC)))
      else:
        lengError srcC, "a `{.stack.}` local can only be assigned a variable or a literal",
                  g.asmInfo
      skip cc
      while cc.hasMore: skip cc
      return
    let dst = g.asmRegOf(destC)
    case srcC.kind
    of Symbol:
      if g.isAsmStackSym(srcC):
        g.ab.tree MovX64: (g.emReg dst; g.emStackMem(srcC.symId))
      else:
        g.movReg(dst, g.asmRegOf(srcC))
    of IntLit:
      g.movImm(dst, intVal(srcC))
    of UIntLit:
      g.movImm(dst, cast[int64](uintVal(srcC)))
    of TagLit:
      if isAsmMemExpr(srcC):
        # a LOAD: `x = p[i]`
        g.ab.tree MovX64: (g.emReg dst; g.asmMem(srcC))
      elif srcC.exprKind != InstrC:
        lengError srcC, "an `.assembler` statement must be one instruction; `" &
                  $srcC.exprKind & "` would need temporaries", g.asmInfo
      else:
        g.asmInstr(destC, dst, srcC)
    else:
      lengError srcC, "unsupported `.assembler` operand", g.asmInfo
    skip cc
    while cc.hasMore: skip cc

proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor) =
  ## `(instr SYM X*)` in an `.assembler` body: the operands are already where the
  ## user put them, so this is the row's opcode over `dst` and the operand
  ## registers — the same `emitIntrinsicOps` the allocated path ends in.
  var fsym = NoSymId
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    fsym = fc.symId; skip fc
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if tgX64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no x86-64 lowering; an " &
              "`.assembler` proc has no fallback path", g.asmInfo
  g.asmApplyFlags(tgt.op, c)          # value rows clobber flags too (`rol`, `bsf`)
  if row.isFlagRead:
    # The rule of §6, at its one enforcement point: a flag has no register behind
    # it, and `setcc` — the instruction that would give it one — reads the same
    # bit that everything emitted in between may already have destroyed.
    lengError c, "`" & IntrinsicNames[tgt.op] & "()` is a flag, not a value; " &
              "it can only be an `if` condition", g.asmInfo
  if row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` produces no value, only flags; " &
              "use it as a statement", g.asmInfo
  if row.inoutOperand >= 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` writes through its first " &
              "operand and returns nothing; use it as a statement", g.asmInfo
  if tgt.op.isMachineQuery:
    # A zero-operand row whose result IS a register value. It is the shape the
    # operand loop below cannot express (it starts at `argCurs[0]`), and the one
    # an `.assembler` body most wants: `result = stackPointer()` in a `{.naked.}`
    # proc reads the caller's frame, which nothing else can.
    g.emitIntrinsicOps(tgt.op, tgt.argBits, dst, dst, 0)
    return
  if argCurs.len == 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` takes no operands here", g.asmInfo
  var rotCount = 0'i64
  if tgt.op in {RolOp, RorOp}:
    if argCurs.len < 2 or argCurs[1].kind notin {IntLit, UIntLit}:
      lengError c, "`" & IntrinsicNames[tgt.op] & "` needs a literal rotate count",
                g.asmInfo
    rotCount = (if argCurs[1].kind == IntLit: intVal(argCurs[1])
                else: cast[int64](uintVal(argCurs[1])))
  # An in-place form reads and writes one register, so the destination must be
  # seeded with operand 0 first. Outside `.assembler` the allocator arranges the
  # tie; here the user did, and if they did not the seeding `mov` is the honest
  # transliteration of what they wrote.
  let src0 = if inPlaceIntrinsicX64(tgt.op): dst else: g.asmRegOf(argCurs[0])
  if inPlaceIntrinsicX64(tgt.op):
    g.movReg(dst, g.asmRegOf(argCurs[0]))
  g.emitIntrinsicOps(tgt.op, tgt.argBits, dst, src0, rotCount)

proc asmVarDecl*(g: var CodeGen; c: Cursor) =
  ## `(var :nm (pragmas (register "rax")) T init?)` — a DECLARATION of a location,
  ## not an allocation request. Several locals may name the same register (the user
  ## pinned them together); only the first declares a nifasm binding.
  var cc = c
  cc.into:
    let nameC = cc
    let nm = cc.symId; inc cc
    let loc = g.asmDeclLoc(cc)
    skip cc                                      # pragmas
    let typeCur = cc
    skip cc                                      # type
    let hasInit = cc.hasMore and cc.kind != DotToken
    let initC = asmAtom(cc)
    g.symType[nm] = typeCur
    case loc.kind
    of aslReg:
      g.asmReg[nm] = loc.r
      # The signature already bound the ABI registers (`p0.0`, `ret.0`); pinning a
      # local onto one of those is legal — it is the same machine register under a
      # second source name — and needs no new binding while the TYPE is the same.
      # A different type is a different value in that register: `hi` of a `mul`
      # landing in rdx after the pointer that arrived there was copied away. Then
      # the register is re-declared, which ends the old binding, so nifasm types
      # every later use as what the register now holds.
      let prev = g.asmRegType.getOrDefault(loc.r, default(Cursor))
      if not g.rb.isBound(loc.r) or cursorIsNil(prev) or not sameTree(prev, typeCur):
        g.emRegLocalVar(nm, loc.r, typeCur)
        g.asmRegType[loc.r] = typeCur
    of aslStack:
      g.asmStack.incl nm
      g.emTypedStackVar(nm, typeCur)
    of aslNone:
      if g.isResultName(nm):
        # The result is pinned to the ABI return register, derived rather than
        # annotated: Nimony has no syntax for annotating `result`, and the ABI
        # leaves no choice anyway.
        g.asmReg[nm] = g.md.intRetReg
      else:
        lengError nameC, "`" & g.userName(nm) & "` needs `{.register: \"…\".}` or `{.stack.}` — an " &
                  "`.assembler` proc declares every location", g.asmInfo
    if hasInit:
      # `var r {.register: "rax".} = x` is an assignment like any other.
      if loc.kind == aslStack:
        case initC.kind
        of Symbol:
          if g.isAsmStackSym(initC):
            lengError initC, "a memory-to-memory move needs a scratch register; " &
                      "assign through a `{.register: \"…\".}` local", g.asmInfo
          g.ab.tree MovX64: (g.emStackMem(nm); g.emReg g.asmRegOf(initC))
        of IntLit:
          g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit intVal(initC))
        of UIntLit:
          g.ab.tree MovX64: (g.emStackMem(nm); g.ab.intLit cast[int64](uintVal(initC)))
        else:
          lengError initC, "a `{.stack.}` local can only be initialized with a " &
                    "variable or a literal", g.asmInfo
      else:
        case initC.kind
        of Symbol:
          if g.isAsmStackSym(initC):
            g.ab.tree MovX64: (g.emReg g.asmReg.getOrQuit(nm); g.emStackMem(initC.symId))
          else:
            g.movReg(g.asmReg.getOrQuit(nm), g.asmRegOf(initC))
        of IntLit: g.movImm(g.asmReg.getOrQuit(nm), intVal(initC))
        of UIntLit: g.movImm(g.asmReg.getOrQuit(nm), cast[int64](uintVal(initC)))
        of TagLit:
          if initC.exprKind != InstrC:
            lengError initC, "an `.assembler` initializer must be one instruction or an atom",
                      g.asmInfo
          g.asmInstr(nameC, g.asmReg.getOrQuit(nm), initC)
        else:
          lengError initC, "unsupported `.assembler` initializer", g.asmInfo
      skip cc
    while cc.hasMore: skip cc

proc asmStmt*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {}) =
  if c.kind == DotToken: return
  g.asmNoteInfo(c)
  # Tail position, tracked exactly as `genStmt` does: only the LAST statement of
  # a straight-line `stmts`/`scope` inherits it. A `ret` there falls through to the
  # epilogue instead of jumping to it — in a mode whose premise is one-to-one, a
  # `jmp` to the very next label is an instruction the user did not write.
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx                     # only the LAST statement stays in tail position
        g.asmStmt(cc, if not nx.hasMore: flags else: {}); skip cc
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx                     # only the LAST statement stays in tail position
        g.asmStmt(cc, if not nx.hasMore: flags else: {}); skip cc
    g.exitScope()
  of VarS: g.asmVarDecl(c)
  of AsgnS: g.asmAsgn(c)
  of InstrS:
    # An instruction in statement position produces no value, so the rows that
    # belong here are the three that have no result: one that writes through an
    # `inout` operand, one whose whole output is the flags, and one that has no
    # output of any kind (`cpuRelax`).
    let op = g.instrOpAt(c)
    if op != NoIntrinsicOp and IntrinsicRows[op].inoutOperand >= 0:
      g.asmInoutInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isFlagWrite:
      g.asmFlagInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isNullaryVoid:
      if tgX64 notin IntrinsicRows[op].targets:
        lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      g.emitNullaryIntrinsicX64(op)
      g.asmApplyFlags(op, c)
    else:
      lengError c, "an instruction used as a statement must have a destination",
                g.asmInfo
  of WhileS:
    # `while true` only. A conditional loop would need the condition evaluated into
    # flags, which is §6's flag intrinsics — not yet available, so it is rejected
    # rather than silently compiled through the ordinary (allocating) path.
    var cc = c
    cc.into:
      let condC = cc
      if not (condC.kind == TagLit and condC.exprKind == TrueC):
        lengError condC, "an `.assembler` loop must be `while true`; use `break` to leave it",
                  g.asmInfo
      skip cc
      let lEnd = g.freshLabel()
      g.loopEnds.add lEnd
      # the loop head is also reached by the back edge, where the flags are
      # whatever the body's end left — so nothing is known on entry, and after
      # the loop (reached by `break`s from anywhere in it) nothing either
      g.asmFlags = {}
      g.asmCfBy = NoIntrinsicOp
      g.emitLoop:
        while cc.hasMore: (g.asmStmt(cc); skip cc)
      g.emLab(lEnd)
      g.asmFlags = {}
      g.asmCfBy = NoIntrinsicOp
      discard g.loopEnds.pop()
  of IfS:
    # `if <flag>(): … else: …` → nifasm's `(ite (zf) then else)`, which already
    # exists with all ten x86 conditions. A flag is the ONLY condition allowed:
    # anything else would have to be computed into a register first, and the
    # instruction that computed it would clobber the very bit an enclosing flag
    # test might be reading. `elif` is a nested `if` on the machine, and writing
    # it that way keeps every `(ite …)` one flag test.
    var cc = c
    var branches = 0
    cc.into:
      while cc.hasMore:
        case cc.substructureKind
        of ElifU:
          inc branches
          if branches > 1:
            lengError cc, "an `.assembler` `if` takes one condition; write a " &
                      "nested `if` for the next flag test", g.asmInfo
          var bc = cc
          bc.into:
            let condC = bc
            let op = g.instrOpAt(condC)
            if op == NoIntrinsicOp or not IntrinsicRows[op].isFlagRead:
              lengError condC, "an `.assembler` condition must be a flag " &
                        "intrinsic such as `zf()`; any other condition would " &
                        "need an instruction that clobbers the flags", g.asmInfo
            let flag = x64FlagOf(op)
            if flag == NoFlag:
              lengError condC, "`" & IntrinsicNames[op] &
                        "` has no x86-64 condition code", g.asmInfo
            g.asmUseFlags(condC, op)
            let atIf = g.asmFlags
            let cfAtIf = g.asmCfBy
            skip bc
            # `(ite cond then else)`: nifasm reads exactly two statements, so an
            # `if` with no `else` gets an empty one.
            var peek = cc; skip peek
            let hasElse = peek.hasMore and peek.substructureKind == ElseU
            g.ab.tree IteX64:
              g.ab.keyword flag
              g.ab.tree StmtsX64:
                g.enterScope()
                while bc.hasMore: (g.asmStmt(bc); skip bc)
                g.exitScope()
              let afterThen = g.asmFlags
              let cfAfterThen = g.asmCfBy
              g.asmFlags = atIf
              g.asmCfBy = cfAtIf
              g.ab.tree StmtsX64:
                if hasElse:
                  var ec = peek
                  ec.into:
                    g.enterScope()
                    while ec.hasMore: (g.asmStmt(ec); skip ec)
                    g.exitScope()
              # only what both arms leave defined is defined after the `if`
              g.asmFlags = g.asmFlags * afterThen
              if g.asmCfBy != cfAfterThen: g.asmCfBy = NoIntrinsicOp
        of ElseU:
          discard                                # emitted inside the `elif` above
        else:
          lengError cc, "unsupported `if` shape in an `.assembler` proc", g.asmInfo
        skip cc
  of BreakS:
    if g.loopEnds.len == 0:
      lengError c, "`break` outside a loop", g.asmInfo
    g.emJmp(g.loopEnds[^1])
  of LabS:
    g.asmFlags = {}                  # reachable by a jump from anywhere
    g.asmCfBy = NoIntrinsicOp
    var cc = c
    cc.into:
      g.emLab(cc.symId); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emJmp(cc.symId); skip cc
      while cc.hasMore: skip cc
  of RetS:
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isAsmStackSym(cc):
          g.ab.tree MovX64: (g.emReg g.md.intRetReg; g.emStackMem(cc.symId))
        else:
          g.movReg(g.md.intRetReg, g.asmRegOf(cc))  # a no-op when already pinned there
        skip cc
      while cc.hasMore: skip cc
    if TailStmt notin flags:
      g.retLabelUsed2 = true
      g.emJmp(g.retLabel2)
  else:
    lengError c, "`" & $c.stmtKind & "` is not allowed in an `.assembler` proc", g.asmInfo

proc genAsmProc*(g: var CodeGen; info: ProcInfo) =
  ## Emit an `.assembler` proc: no allocator, no analyser, no value core. The
  ## signature is the ordinary declarative one (that is what lets ordinary Nimony
  ## call it), and the `.register` annotations on the parameters are checked
  ## AGAINST it — in an `.assembler` proc a location constraint is an assertion,
  ## not a request.
  g.varType.clear(); g.symType.clear(); g.stackSlots.clear()
  g.rb.resetProc(); g.aliasToDecl.clear()
  g.rawHomeRegs = {}; g.narrowHomes = false   # no allocator, no temp pool here
  g.asmReg.clear(); g.asmStack.clear(); g.asmRegType.clear()
  g.asmFlags = {}                    # the caller's flags are not ours to read
  g.asmCfBy = NoIntrinsicOp
  g.asmInfo = lengInfo(info.decl)
  g.loopEnds = @[]
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.plan = Plan()
  if info.isEntry:
    lengError info.decl, "the program entry point cannot be an `.assembler` proc", g.asmInfo
  # Parameters: bind each ABI register to the signature's `pN.0` (as the allocated
  # path does) and map the param's own Leng name onto the same register, so the
  # body may spell it either way and `emReg` renders the one nifasm knows.
  var used: set[Reg] = {}
  block:
    var pc = info.decl
    inc pc; inc pc                               # head → name → params
    var ord = 0
    if pc.kind == TagLit:
      pc.into:
        while pc.hasMore:
          var nameC = pc
          pc.into:                               # (param :nm pragmas type)
            nameC = pc
            let nm = pc.symId; inc pc
            let loc = g.asmDeclLoc(pc)
            skip pc                              # pragmas
            g.symType[nm] = pc
            if ord >= g.md.intArgRegs.len:
              lengError nameC, "an `.assembler` proc takes at most " &
                        $g.md.intArgRegs.len & " parameters (the 7th and beyond " &
                        "arrive on the stack)", g.asmInfo
            let abiReg = g.md.intArgRegs[ord]
            case loc.kind
            of aslNone:
              lengError nameC, "parameter `" & g.userName(nm) & "` needs `{.register: \"" &
                        x64RegName(abiReg) & "\".}` — an `.assembler` proc's " &
                        "annotations ARE its ABI", g.asmInfo
            of aslStack:
              lengError nameC, "parameter `" & g.userName(nm) & "` arrives in " &
                        x64RegName(abiReg) & ", so it cannot be `{.stack.}`", g.asmInfo
            of aslReg:
              if loc.r != abiReg:
                lengError nameC, "parameter `" & g.userName(nm) & "` is passed in " &
                          x64RegName(abiReg) & " by the C ABI, but is pinned to " &
                          x64RegName(loc.r), g.asmInfo
            g.asmReg[nm] = abiReg
            g.rb.bindParam(abiReg, g.paramName(ord))
            g.asmRegType[abiReg] = pc               # the param's Leng type
            used.incl abiReg
            while pc.hasMore: skip pc
          inc ord
  # The result register. The signature's `(result :ret.0 (rax) …)` is the CALLER's
  # view; inside the proc rax stays an ordinary register the body may pin a local
  # onto — exactly what the allocated path does when it writes the result.
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                      # → return type
    if not (rc.kind == DotToken or (rc.kind == TagLit and rc.typeKind == VoidT)):
      used.incl g.md.intRetReg
  var anyStack = false
  block:                                         # scan the BODY (`asmScanLocs` stops at a `proc`)
    var bc = info.decl
    bc.into:
      inc bc; skip bc; skip bc; skip bc          # name, params, ret, pragmas
      if bc.stmtKind == StmtsS: g.asmScanLocs(bc, used, anyStack)
      while bc.hasMore: skip bc
  g.plan.usedCallee = used * g.md.intCalleeSavedSet
  g.plan.hasStackVars = anyStack
  if info.isNaked:
    # `{.naked.}` is a promise about SP, and these two are the only ways an
    # `.assembler` body can break it. Both are rejected rather than silently
    # honoured: a `{.stack.}` local would need the frame the pragma just removed,
    # and a callee-saved register whose `push` never happened is a value returned
    # to the caller's own home — corruption that surfaces arbitrarily far away.
    if anyStack:
      lengError info.decl, "a `{.naked.}` proc has no stack frame, so it cannot " &
                "declare a `{.stack.}` local", g.asmInfo
    if g.plan.usedCallee != {}:
      var names = ""
      for r in g.md.intCalleeSaved:
        if r in g.plan.usedCallee:
          if names.len > 0: names.add ", "
          names.add x64RegName(r)
      lengError info.decl, "a `{.naked.}` proc emits no prologue, so it cannot " &
                "use the callee-saved register(s) " & names &
                " — the caller's value there would be destroyed", g.asmInfo
  g.pickStackArgBaseX64(hasStackParams = false)
  g.computeFrameX64(isEntry = false, hasCall = false)
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl)
    g.ab.tree StmtsX64:
      g.enterScope()
      if not info.isNaked:
        g.framePush()
        g.emitFrameSub()
      g.retLabel2 = g.freshLabel()
      g.retLabelUsed2 = false
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c            # name, params, ret, pragmas
        # the whole body is in tail position
        if c.stmtKind == StmtsS: g.asmStmt(c, {TailStmt})
        while c.hasMore: skip c
      # The label FIRST, then the scope kills: every `ret` jumps here, so the kills
      # belong on the path that actually reaches the epilogue (emitting them before
      # the label would leave them stranded after the body's final `jmp`).
      if g.retLabelUsed2: g.emLab(g.retLabel2)
      g.exitScope()
      # `{.naked.}` drops the epilogue but NOT the `ret`: without a return the
      # proc would fall into whatever code the linker put next, and "no
      # prologue/epilogue" is a statement about the frame, not about returning.
      if not info.isNaked: g.framePop()
      g.ab.keyword RetX64
