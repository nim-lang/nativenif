#
#            Arkham — `.assembler` procs on the Arm targets (a64, Cortex-M)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## INCLUDED by `codegen_arm.nim` — the Arm arm of `doc/intrinsics.md` §8, and the
## twin of `codegen_x64.nim`'s `genAsmProc`.
##
## ## What this mode is
##
## A transliteration, not a compilation. There is no allocator and no value core
## here: in an `.assembler` body every location is DECLARED (`{.register: "…".}`
## / `{.stack.}` on a parameter or local), so there is nothing to allocate, and
## every statement must map to ONE instruction, so there is nothing to lower.
## What is left is a checker plus a literal transcription — and arkham is the
## only checker there is, since nimony's sem only forwards the pragmas. Hence
## every rejection below is a user-facing `lengError` carrying the offending
## node's own file/line/col, never a `raiseAssert`.
##
## The target-neutral half — what a location pragma says, what counts as an atom,
## which row a call names — lives in `core/asmcommon`, so the x86-64 and Arm
## modes accept the same source language rather than two subsets that drift.
##
## ## Why one file serves both Arm targets
##
## Everything that differs between AArch64 and Cortex-M is already a fact in
## `g.md` — argument registers, the return register, the callee-saved list the
## prologue can actually save — and the two share an instruction VOCABULARY in
## asm-NIF (`(mov …)`, `(cmp …)`, `(ite …)` are one tag apiece, dispatched by
## arch inside nifasm). What is left target-specific is exactly two things: how a
## register is SPELLED (`x0` vs `r0`), and which registers a body may not claim.
## Both live in `armRegByName`/`asmPinReg` below and nowhere else.
##
## ## Which registers a body may claim
##
## Not "anything but sp". A pin is only sound if arkham can either clobber the
## register freely or SAVE it, and on both Arm targets there are registers that
## are neither — dedicated to a role the emitter needs somewhere else. AArch64
## keeps x8 (the indirect result pointer), x16/x17 (the assembler's veneers) and
## x18 (the platform register); Cortex-M keeps r12 (nifasm's own operand-folding
## scratch, written at sites arkham never sees) and r8–r11 (the produce bridge,
## the indirect result pointer and the two staging bridges).
##
## r8–r11 deserve the specific mention they get below: they are callee-saved
## under AAPCS32, but `computeFrame` walks `md.intCalleeSaved`, which is r4–r7 —
## so a value pinned there is NOT saved by the prologue and the caller's own
## value in it is destroyed. That is a corruption with no local symptom, which is
## why it is a rejection naming the register rather than a rule left implicit.

import std / [tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, asmcommon, 
                    mirrors, regbind, abi]
import machine_a64 as machine
from machine_m as machine_m import nil
import emit, value, frame

proc armFrameSaved*(g: CodeGen): set[Reg] =
  ## The callee-saved registers this back end's prologue actually saves — the
  ## same list `computeFrame` walks, which is the ARCHITECTURAL one and not
  ## `md.intCalleeSaved`. The two differ under `-d:arkhamStress`, where the
  ## allocator's pools are starved: a stressed build allocates out of fewer
  ## homes, but a `.assembler` body does not allocate at all, so a register it
  ## NAMES must still be saved. Reading the same list in both places is what
  ## keeps "the pin is legal" and "the prologue saves it" one fact.
  result = {}
  for r in g.md.abiCalleeSaved: result.incl r

proc armVolatile*(g: CodeGen): set[Reg] =
  ## The registers a callee may destroy without saving. AAPCS32 gives Cortex-M
  ## exactly four (its argument registers; r12 is volatile too but is nifasm's),
  ## AAPCS64 gives x0–x17.
  g.md.intCallerSavedSet

proc armRegByName*(g: CodeGen; name: string): Reg =
  ## `"x9"` → `R9` on AArch64, `"r5"` → `R5` on Cortex-M. `NoReg` for a spelling
  ## this target does not have — including the OTHER Arm target's, which is why
  ## the lookup goes through the very renderer the emitter spells registers with
  ## (`ab.renderReg`, set once per target) instead of a second table that could
  ## disagree with it. A slot this target does not map renders as
  ## `<unmapped:N>`, which no `{.register: "…"}` spelling can equal, so walking
  ## the whole slot range is safe on the narrower target too.
  result = NoReg
  for r in R0 .. R30:
    if g.ab.renderReg(r) == name: return r
  if name == "sp": return SP

proc asmPinReg*(g: var CodeGen; at: Cursor; name: string): Reg =
  ## Resolve a `{.register: "…"}` spelling, rejecting every register a body may
  ## not own. Each rejection names the ROLE rather than saying "reserved": the
  ## user picked that register for a reason, and what they need to know is which
  ## other thing already lives there.
  let target = g.md.targetName
  result = g.armRegByName(name)
  if result == NoReg:
    lengError at, "`" & name & "` is not a " & target & " general-purpose " &
              "register — this target's are " &
              g.md.gprRangeText, g.asmInfo
  if result == SP:
    lengError at, "`sp` is the stack pointer and cannot hold a value", g.asmInfo
  if g.thumbM:
    if result == g.md.linkReg:
      lengError at, "`lr` holds the return address, which every `bl` overwrites " &
                "and the epilogue reads back", g.asmInfo
    if result == machine_m.IP:
      lengError at, "`r12` is the assembler's own scratch: nifasm folds an " &
                "out-of-range operand through it at sites this back end never " &
                "sees, so a value left there dies to an instruction nobody emitted",
                g.asmInfo
    if result == g.md.produceBridge:
      lengError at, "`r8` is arkham's produce bridge — the register it can " &
                "always take when a value has to be staged", g.asmInfo
    if result == g.md.indirectResultReg:
      lengError at, "`r9` carries `&result` for a callee returning an aggregate " &
                "too wide for registers", g.asmInfo
    if result in {g.md.bridgeRegs[0], g.md.bridgeRegs[1]}:
      lengError at, "`" & name & "` is one of arkham's two staging bridges " &
                "(r10/r11): a folded memory operand has to be loaded somewhere, " &
                "and this target has no spare volatile at all", g.asmInfo
  else:
    if result == g.md.linkReg:
      lengError at, "`x30` is the link register: every `bl` overwrites it and " &
                "the epilogue reads it back", g.asmInfo
    if result == g.md.framePtrReg:
      lengError at, "`x29` is the frame pointer, which addresses the caller's " &
                "stack arguments for the whole body", g.asmInfo
    if result == g.md.indirectResultReg:
      lengError at, "`x8` carries `&result` for a callee returning an aggregate " &
                "too wide for registers", g.asmInfo
    if result in {R16, R17}:
      lengError at, "`" & name & "` is an assembler veneer register (IP0/IP1); " &
                "the linker writes it in branch thunks this back end never sees",
                g.asmInfo
    if result == R18:
      lengError at, "`x18` is the platform register and belongs to the OS, not " &
                "to this program", g.asmInfo
  # Anything still standing must be a register the proc can ACCOUNT for: one the
  # ABI lets a callee destroy, or one the prologue saves. A callee-saved register
  # outside that second set is the quiet failure this whole check exists for —
  # nothing preserves the caller's value in it, and the damage surfaces in the
  # CALLER, arbitrarily far from the body that did it.
  if result notin g.armVolatile and result notin g.armFrameSaved:
    lengError at, "`" & name & "` is callee-saved on this ABI, and not one of " &
              "the homes this back end's prologue saves — the caller's value in " &
              "it would be destroyed with no local symptom", g.asmInfo

type
  AsmDeclLoc = object
    ## Where a `.assembler` param/local was DECLARED to live — the shared
    ## `AsmDeclSpec` with its register name resolved against THIS target's file.
    kind: AsmDeclKind
    r: Reg

proc asmDeclLoc*(g: var CodeGen; prag: Cursor): AsmDeclLoc =
  ## `(pragmas (register "x9"))` / `(pragmas (stack))`, read by `asmDeclSpec` and
  ## resolved here: which spelling names a register is the one part of a location
  ## pragma that is not target-neutral.
  let spec = asmDeclSpec(prag)
  case spec.kind
  of aslNone: AsmDeclLoc(kind: aslNone, r: NoReg)
  of aslReg: AsmDeclLoc(kind: aslReg, r: g.asmPinReg(spec.at, spec.name))
  of aslStack: AsmDeclLoc(kind: aslStack, r: NoReg)

proc armFlagOf*(op: IntrinsicOp): X64Flag =
  ## The nifasm condition tag a flag-read row denotes. asm-NIF spells conditions
  ## with the x86 flag vocabulary on EVERY target (that is what `tagToX64Flag`
  ## reads), so this is the same one-enum-to-another map the x64 backend has —
  ## and Arm's NZCV covers the same ground under other names. Parity is the
  ## exception: no Arm profile has such a bit, so `pf`/`np` map to `NoFlag` and
  ## are refused by name.
  case op
  of ZfOp: ZfO
  of NotZfOp: NzO
  of CfOp: CfO
  of NotCfOp: NcO
  of SfOp: SfO
  of NotSfOp: NsO
  of OfOp: OfO
  of NotOfOp: NoO
  else: NoFlag

proc armFlagSupported*(g: CodeGen; f: X64Flag): bool {.inline.} =
  ## Which conditions the ASSEMBLER can turn into a branch. Cortex-M maps all
  ## eight of Arm's (`condOfFlagM`); AArch64's `genIteA64` implements only the
  ## zero flag so far. Asking here rather than emitting and hoping is what keeps
  ## an unimplemented condition a named compile error instead of a nifasm crash
  ## in the middle of an otherwise valid image.
  if f == NoFlag: false
  elif AllFlagBranches in g.md.caps: f in {ZfO, NzO, CfO, NcO, SfO, NsO, OfO, NoO}
  else: f in {ZfO, NzO}

proc asmStmt*(g: var CodeGen; c: Cursor)
proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor)

proc emAsmSlot*(g: var CodeGen; name: string) {.inline.} =
  ## A `{.stack.}` local as an OPERAND. On Arm a frame slot is addressed by its
  ## own symbol — `(mov t.0 (r2))` stores, `(mov (r2) t.0)` loads — which is what
  ## every hand-written body in this back end already does.
  g.ab.sym name

proc asmMovReg*(g: var CodeGen; d, s: Reg) {.inline.} =
  if d != s: g.ab.tree MovA64: (g.emReg d; g.emReg s)

proc asmAddrOf*(g: var CodeGen; dst: Reg; c: Cursor) =
  ## `p = addr(x)` — §8's one operand that is neither a register nor a literal.
  ##
  ## Two spellings, because Arm addresses the two kinds of storage differently
  ## and neither needs anything materialised: a frame slot is `(lea D slot)`,
  ## whose displacement off SP nifasm knows once the frame is sized, and a global
  ## is `(adr D sym)`, a link-time address the image writer patches. A REGISTER
  ## has no address at all, and saying so is the useful answer — the body would
  ## have had to spill it first, which is the one thing this mode never does
  ## behind the author's back.
  var inner = c
  var sym = c
  inner.into:
    sym = inner; skip inner
    while inner.hasMore: skip inner
  if sym.kind != Symbol:
    lengError c, "`addr` in an `.assembler` body takes a `{.stack.}` local or a " &
              "global, not a computed lvalue", g.asmInfo
  let nm = symName(sym)
  if nm in g.asmStack:
    g.ab.tree LeaA64: (g.emReg dst; g.emAsmSlot(nm))
  elif g.asmReg.hasKey(nm):
    lengError sym, "`" & userName(nm) & "` lives in a register, which has no " &
              "address — give it `{.stack.}` if something must point at it",
              g.asmInfo
  elif g.prog.globals.hasKey(nm) or isForeignSym(g.prog, nm):
    g.emAdr(dst, g.prog.gvarRefName(nm))
  else:
    lengError sym, "`" & userName(nm) & "` is neither a local of this proc nor a " &
              "global, so it has no address to take", g.asmInfo

proc asmScanLocs*(g: var CodeGen; c: Cursor; used: var set[Reg]; anyStack: var bool) =
  ## Pre-pass over the body: which registers the locals pin (so the prologue knows
  ## which callee-saved ones to save) and whether any `(s)` slot exists (so the
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

proc asmOperand*(g: var CodeGen; cur: Cursor) =
  ## One source operand of a flag-defining instruction: a register local, a stack
  ## slot, or a literal. Unlike `asmRegOf` this permits memory and immediates,
  ## because `(cmp …)` takes them directly — no materialisation involved.
  let c = asmAtom(cur)
  case c.kind
  of Symbol:
    if g.isAsmStackSym(c): g.emAsmSlot(symName(c))
    else: g.emReg g.asmRegOf(c)
  of IntLit: g.ab.intLit intVal(c)
  of UIntLit: g.ab.intLit cast[int64](uintVal(c))
  else:
    lengError c, "an `.assembler` operand must be a variable or a literal", g.asmInfo

proc asmInoutDest*(g: var CodeGen; c: Cursor) =
  ## The destination of a two-address row. It arrives as `(haddr d)` — the
  ## compiler binding d's LOCATION for a `var` parameter, not the user taking a
  ## pointer — so it resolves to d's declared home and nothing is materialised.
  if c.kind != TagLit or c.exprKind != HaddrC:
    lengError c, "the destination of a two-address instruction must be a `var` " &
              "argument naming a local", g.asmInfo
  var inner = c
  var sym = c
  inner.into:
    sym = inner; skip inner
    while inner.hasMore: skip inner
  if sym.kind != Symbol:
    lengError sym, "the destination of a two-address instruction must be a local " &
              "with a declared location", g.asmInfo
  let nm = symName(sym)
  if nm in g.asmStack:
    # Arm is a load/store machine: `(add t.0 (r1))` where `t.0` is a frame slot
    # is not an instruction, and letting nifasm fold it would need the very
    # scratch register this mode refuses to invent.
    lengError sym, "`" & userName(nm) & "` lives on the stack, and Arm arithmetic " &
              "reads and writes registers only — load it into a " &
              "`{.register: \"…\".}` local first", g.asmInfo
  g.emReg g.asmRegOf(sym)

proc asmInoutInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `add(d, s)` / `neg(d)` — a row that writes THROUGH operand 0 and returns
  ## nothing. Statement-only, since there is no value to bind.
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let row = IntrinsicRows[op]
  if argCurs.len != row.arity:
    lengError c, "`" & IntrinsicNames[op] & "` takes " & $row.arity & " operand(s)",
              g.asmInfo
  let tag = armInoutTag(op)
  if tag == NopA64:
    lengError c, "`" & IntrinsicNames[op] & "` has no " &
              g.md.targetName & " two-address form",
              g.asmInfo
  if row.arity == 1:
    g.ab.tree tag: g.asmInoutDest(argCurs[0])
  else:
    g.ab.tree tag: (g.asmInoutDest(argCurs[0]); g.asmOperand(argCurs[1]))
  # Arm's arithmetic is where the flags become unanswerable: nifasm asks for the
  # non-flag-setting form, and Thumb's narrow encoding — the one it prefers when
  # every operand is a low register — sets them anyway. So after this the flags
  # depend on which registers the body pinned, which is not something to read.
  g.asmFlagsFresh = false

proc asmVoidInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## A row with no result and no `inout` operand, whose operands the INSTRUCTION
  ## encodes rather than reads from registers: `bkpt #imm8`. It is a statement
  ## for the same reason a flag row is — there is nothing to bind — but for the
  ## opposite reason: not because the output is somewhere a register cannot go,
  ## but because there is no output this row can describe. `bkpt`'s answer comes
  ## back in r0, which is precisely why a semihosting call is written in a body
  ## that can say `r0` out loud.
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let row = IntrinsicRows[op]
  if argCurs.len != row.arity:
    lengError c, "`" & IntrinsicNames[op] & "` takes " & $row.arity & " operand(s)",
              g.asmInfo
  case op
  of BkptOp:
    let imm = argCurs[0]
    if imm.kind notin {IntLit, UIntLit}:
      # There is no register form: the comment field lives in the instruction
      # word, so a computed value could not be encoded at all.
      lengError imm, "`bkpt` takes a literal immediate — the instruction encodes " &
                "it, so there is no register form to compute one into", g.asmInfo
    let v = (if imm.kind == IntLit: intVal(imm) else: cast[int64](uintVal(imm)))
    if v < 0 or v > 255:
      lengError imm, "`bkpt` takes an 8-bit immediate (0..255); " & $v &
                " does not fit the instruction", g.asmInfo
    g.ab.tree BkptM: g.ab.intLit v
  elif op.isAtomic:
    # A fence lands here — void, and its one operand is a memory-order knob the
    # back ends do not evaluate. Every atomic is an instruction SEQUENCE (an
    # LL/SC retry loop on Arm), and a mode whose contract is one instruction per
    # statement cannot honestly emit one.
    lengError c, "`" & IntrinsicNames[op] & "` is an instruction SEQUENCE, not " &
              "an instruction; an `.assembler` body emits exactly what it says",
              g.asmInfo
  else:
    lengError c, "`" & IntrinsicNames[op] & "` has no Arm lowering as a statement",
              g.asmInfo
  # A `bkpt` runs a debug agent, which may do anything to r0 and to memory. It
  # leaves NZCV alone architecturally, but nothing that far outside this back
  # end's sight is worth claiming a flag is still readable after.
  g.asmFlagsFresh = false

proc asmFlagInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `cmp(a, b)` — an instruction whose entire output is flags. A statement,
  ## never a value: there is nothing to bind.
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    skip fc                                      # the callee symbol
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  if argCurs.len != 2:
    lengError c, "`" & IntrinsicNames[op] & "` takes two operands", g.asmInfo
  if op != CmpOp:
    # `test` is x86's and-without-a-destination; Arm's `tst` exists in the
    # Cortex-M vocabulary but no row claims it yet, so saying so beats emitting
    # a `cmp` that computes a different condition.
    lengError c, "`" & IntrinsicNames[op] & "` has no Arm lowering; use `cmp`",
              g.asmInfo
  if g.isAsmStackSym(argCurs[0]):
    lengError c, "Arm has no memory-operand compare: load the left-hand side " &
              "into a `{.register: \"…\".}` local first", g.asmInfo
  g.ab.tree CmpA64: (g.asmOperand(argCurs[0]); g.asmOperand(argCurs[1]))
  g.asmFlagsFresh = true

proc asmStore*(g: var CodeGen; nm: string; srcC: Cursor) =
  ## `slot = <atom>`. Memory on both sides would take a scratch register no one
  ## declared — the one thing this mode will not invent.
  g.asmFlagsFresh = false
  case srcC.kind
  of Symbol:
    if g.isAsmStackSym(srcC):
      lengError srcC, "a memory-to-memory move needs a scratch register; " &
                "assign through a `{.register: \"…\".}` local", g.asmInfo
    g.ab.tree MovA64: (g.emAsmSlot(nm); g.emReg g.asmRegOf(srcC))
  of IntLit:
    g.ab.tree MovA64: (g.emAsmSlot(nm); g.ab.intLit intVal(srcC))
  of UIntLit:
    g.ab.tree MovA64: (g.emAsmSlot(nm); g.ab.intLit cast[int64](uintVal(srcC)))
  else:
    lengError srcC, "a `{.stack.}` local can only be assigned a variable or a literal",
              g.asmInfo

proc asmLoad*(g: var CodeGen; dst: Reg; srcC: Cursor) =
  ## `reg = <atom>`, where the atom is not an `(instr …)`.
  case srcC.kind
  of Symbol:
    if g.isAsmStackSym(srcC):
      g.ab.tree MovA64: (g.emReg dst; g.emAsmSlot(symName(srcC)))
    else:
      g.asmMovReg(dst, g.asmRegOf(srcC))
  of IntLit: g.movImm(dst, intVal(srcC))
  of UIntLit: g.movImm(dst, cast[int64](uintVal(srcC)))
  else:
    lengError srcC, "unsupported `.assembler` operand", g.asmInfo

proc asmAsgn*(g: var CodeGen; c: Cursor) =
  ## `(asgn dest src)` — the only shape that produces a value. `dest` is an atom
  ## with a declared home; `src` is an atom, a literal, or ONE `(instr …)`.
  var cc = c
  cc.into:
    let destC = cc
    skip cc
    let srcC = asmAtom(cc)
    if g.isAsmStackSym(destC):
      g.asmStore(symName(destC), srcC)
      skip cc
      while cc.hasMore: skip cc
      return
    let dst = g.asmRegOf(destC)
    if srcC.kind == TagLit:
      case srcC.exprKind
      of InstrC: g.asmInstr(destC, dst, srcC)
      of AddrC, HaddrC:
        g.asmAddrOf(dst, srcC)
        g.asmFlagsFresh = false
      else:
        lengError srcC, "an `.assembler` statement must be one instruction; `" &
                  $srcC.exprKind & "` would need temporaries", g.asmInfo
    else:
      g.asmLoad(dst, srcC)
      g.asmFlagsFresh = false
    skip cc
    while cc.hasMore: skip cc

proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor) =
  ## `(instr SYM X*)` in an `.assembler` body: the operands are already where the
  ## user put them, so this is the row's opcode over `dst` and the operand
  ## registers — no placement, no freeing, none of `emitInstr2`'s machinery.
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    fsym = symName(fc); skip fc
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  let here = g.hereTarget
  if here notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no " &
              g.md.targetName & " lowering; an " &
              "`.assembler` proc has no fallback path", g.asmInfo
  if row.isFlagRead:
    lengError c, "`" & IntrinsicNames[tgt.op] & "()` is a flag, not a value; " &
              "it can only be an `if` condition", g.asmInfo
  if row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` produces no value, only flags; " &
              "use it as a statement", g.asmInfo
  if row.inoutOperand >= 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` writes through its first " &
              "operand and returns nothing; use it as a statement", g.asmInfo
  if argCurs.len == 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` takes no operands here", g.asmInfo
  let src = g.asmRegOf(argCurs[0])
  # The operand width, from the row's own declared parameter — the same
  # `tgt.argBits` the allocated path reads. Cortex-M has 32-bit registers and
  # nothing else, so a row asking for 64 there is refused by nifasm's width check
  # rather than encoded as something narrower.
  let bits = if tgt.argBits in {8, 16, 32}: 32 else: 64
  case tgt.op
  of ClzPinnedOp, ClzOp:
    g.ab.tree ClzA64: (g.emReg dst; g.emReg src; g.ab.intLit bits)
  of RbitOp:
    g.ab.tree RbitA64: (g.emReg dst; g.emReg src; g.ab.intLit bits)
  of CtzOp:
    # Two instructions for one row, and the one place this mode emits more than
    # one: Arm has no count-trailing-zeros, `rbit` + `clz` IS it, and both write
    # the destination the user named. Nothing is materialised and no register the
    # body did not declare is touched, which is the property that matters.
    g.ab.tree RbitA64: (g.emReg dst; g.emReg src; g.ab.intLit bits)
    g.ab.tree ClzA64: (g.emReg dst; g.emReg dst; g.ab.intLit bits)
  of RevOp, BswapOp:
    g.ab.tree RevA64: (g.emReg dst; g.emReg src; g.ab.intLit bits)
  else:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no `.assembler` lowering " &
              "on this target yet", g.asmInfo
  g.asmFlagsFresh = false

proc asmVarDecl*(g: var CodeGen; c: Cursor) =
  ## `(var :nm (pragmas (register "x9")) T init?)` — a DECLARATION of a location,
  ## not an allocation request. Several locals may name the same register (the
  ## user pinned them together); only the first declares a nifasm binding.
  var cc = c
  cc.into:
    let nameC = cc
    let nm = symName(cc); inc cc
    let loc = g.asmDeclLoc(cc)
    skip cc                                      # pragmas
    let typeCur = cc
    skip cc                                      # type
    let hasInit = cc.hasMore and cc.kind != DotToken
    let initC = asmAtom(cc)
    case loc.kind
    of aslReg:
      g.asmReg[nm] = loc.r
      # The signature already bound the ABI registers; pinning a local onto one
      # of those is legal — the same machine register under a second source name
      # — but must not redeclare the binding.
      if not g.rb.isBound(loc.r):
        g.emRegLocalVar(nm, loc.r, typeCur)
    of aslStack:
      let s = slotOf(g.prog, typeCur)
      if s.kind in {AInt, AUInt, ABool} and s.size > wordSize():
        # A 64-bit `{.stack.}` local would be a 64-bit-typed access, which nifasm
        # refuses on this target (`checkRegWidthM`) — refuses rather than
        # truncating. Saying so here names the local instead of pointing at a
        # `(mov …)` the user did not write.
        lengError nameC, "`" & userName(nm) & "` is " & $s.size & " bytes, and a " &
                  "Cortex-M `.assembler` body moves one 4-byte word at a time — " &
                  "declare the halves", g.asmInfo
      g.asmStack.incl nm
      g.emTypedStackVar(nm, typeCur)
    of aslNone:
      if isResultName(nm):
        # The result is pinned to the ABI return register, derived rather than
        # annotated: Nimony has no syntax for annotating `result`, and the ABI
        # leaves no choice anyway.
        g.asmReg[nm] = g.md.intRetReg
      else:
        lengError nameC, "`" & userName(nm) & "` needs `{.register: \"…\".}` or " &
                  "`{.stack.}` — an `.assembler` proc declares every location",
                  g.asmInfo
    if hasInit:
      if loc.kind == aslStack: g.asmStore(nm, initC)
      elif initC.kind == TagLit:
        case initC.exprKind
        of InstrC: g.asmInstr(nameC, g.asmReg[nm], initC)
        of AddrC, HaddrC:
          g.asmAddrOf(g.asmReg[nm], initC)
          g.asmFlagsFresh = false
        else:
          lengError initC, "an `.assembler` initializer must be one instruction, " &
                    "an `addr`, or an atom", g.asmInfo
      else:
        g.asmLoad(g.asmReg[nm], initC)
        g.asmFlagsFresh = false
      skip cc
    while cc.hasMore: skip cc

proc asmIf*(g: var CodeGen; c: Cursor) =
  ## `if <flag>(): … else: …` → `(ite <flag> then else)`. A flag is the ONLY
  ## condition allowed: anything else would have to be computed into a register
  ## first, and the instruction that computed it would clobber the very bit an
  ## enclosing flag test is reading. `elif` is a nested `if` on the machine, and
  ## writing it that way keeps every `(ite …)` one flag test.
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
          let here = g.hereTarget
          if here notin IntrinsicRows[op].targets:
            lengError condC, "`" & IntrinsicNames[op] & "` has no " &
                      g.md.targetName & " lowering",
                      g.asmInfo
          let flag = armFlagOf(op)
          if not g.armFlagSupported(flag):
            lengError condC, "`" & IntrinsicNames[op] & "` is not a condition " &
                      (if g.thumbM: "Cortex-M" else: "the AArch64 assembler") &
                      " can branch on", g.asmInfo
          if not g.asmFlagsFresh:
            # The rule Arm forces and x86-64 does not need. There, `add` defines
            # every flag and the row's `defs` column says so, so a body may put
            # instructions between a compare and its use. Here `cmp` is the only
            # instruction whose effect on NZCV this back end can promise: Arm has
            # a flag-setting and a non-flag-setting form of everything else, and
            # Thumb's narrow encodings set the flags without being asked. A body
            # that reads a flag further down is not reading a stale value — it is
            # reading one that depends on register allocation, so it is refused.
            lengError condC, "on Arm a flag can only be read by the `if` that " &
                      "immediately follows the `cmp` which set it — every other " &
                      "instruction here has a flag-setting encoding the assembler " &
                      "may pick, so NZCV in between is not something this back " &
                      "end can promise", g.asmInfo
          skip bc
          var peek = cc; skip peek
          let hasElse = peek.hasMore and peek.substructureKind == ElseU
          g.asmFlagsFresh = false
          g.ab.tree IteA64:
            g.ab.keyword flag
            g.ab.tree StmtsA64:
              g.enterScope()
              while bc.hasMore: (g.asmStmt(bc); skip bc)
              g.exitScope()
            g.ab.tree StmtsA64:
              if hasElse:
                var ec = peek
                ec.into:
                  g.enterScope()
                  while ec.hasMore: (g.asmStmt(ec); skip ec)
                  g.exitScope()
      of ElseU:
        discard                                  # emitted inside the `elif` above
      else:
        lengError cc, "unsupported `if` shape in an `.assembler` proc", g.asmInfo
      skip cc

proc asmStmt*(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return
  g.asmNoteInfo(c)
  # Tail position, tracked exactly as `genStmt2` does: only the LAST statement of
  # a straight-line `stmts`/`scope` inherits it. A `ret` there falls through to
  # the epilogue instead of branching to it — in a mode whose premise is
  # one-to-one, a `b` to the very next label is an instruction nobody wrote.
  let myTail = g.tailStmt
  g.tailStmt = false
  case c.stmtKind
  of StmtsS:
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore
        g.asmStmt(cc); skip cc
  of ScopeS:
    g.enterScope()
    var cc = c
    cc.into:
      while cc.hasMore:
        var nx = cc; skip nx
        g.tailStmt = myTail and not nx.hasMore
        g.asmStmt(cc); skip cc
    g.exitScope()
  of VarS: g.asmVarDecl(c)
  of AsgnS: g.asmAsgn(c)
  of InstrS:
    # An instruction in statement position produces no value, so the rows that
    # belong here are the three with no result: one that writes through an
    # `inout` operand, one whose whole output is the flags, and one that has no
    # output of any kind (`cpuRelax`).
    let op = g.instrOpAt(c)
    if op != NoIntrinsicOp and IntrinsicRows[op].inoutOperand >= 0:
      g.asmInoutInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isFlagWrite:
      let here = g.hereTarget
      if here notin IntrinsicRows[op].targets:
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      g.asmFlagInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isVoidResult and
         IntrinsicRows[op].arity > 0:
      let here = g.hereTarget
      if here notin IntrinsicRows[op].targets:
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      g.asmVoidInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isNullaryVoid:
      let here = g.hereTarget
      if here notin IntrinsicRows[op].targets:
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      case op
      of CpuRelaxOp:
        g.ab.keyword YieldA64      # one spelling, hence one interned tag
      else:
        lengError c, "`" & IntrinsicNames[op] & "` has no Arm lowering", g.asmInfo
    else:
      lengError c, "an instruction used as a statement must have a destination",
                g.asmInfo
  of WhileS:
    # `while true` only. A conditional loop would need its condition evaluated
    # into flags at the TOP of every iteration, which is a shape the flag rows
    # can express and this mode deliberately does not infer: write the `cmp` and
    # the `if <flag>(): break` yourself.
    var cc = c
    cc.into:
      let condC = cc
      if not (condC.kind == TagLit and condC.exprKind == TrueC):
        lengError condC, "an `.assembler` loop must be `while true`; use `break` to leave it",
                  g.asmInfo
      skip cc
      let lEnd = g.freshLabel()
      g.loopEnds.add lEnd
      g.asmFlagsFresh = false          # the back edge arrives with other flags
      g.emitLoop:
        while cc.hasMore: (g.asmStmt(cc); skip cc)
      g.emLab(lEnd)
      discard g.loopEnds.pop()
  of IfS: g.asmIf(c)
  of BreakS:
    if g.loopEnds.len == 0:
      lengError c, "`break` outside a loop", g.asmInfo
    g.emBr(BA64, g.loopEnds[^1])
    g.asmFlagsFresh = false
  of LabS:
    # A label is a merge point: what NZCV holds here does not follow from the
    # instructions above it, because some other path branched in.
    g.asmFlagsFresh = false
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emBr(BA64, symName(cc)); skip cc
      while cc.hasMore: skip cc
  of RetS:
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isAsmStackSym(cc):
          g.ab.tree MovA64: (g.emReg g.md.intRetReg; g.emAsmSlot(symName(cc)))
        else:
          g.asmMovReg(g.md.intRetReg, g.asmRegOf(cc))  # a no-op when already pinned there
        skip cc
      while cc.hasMore: skip cc
    if not myTail:
      g.retLabelUsed2 = true
      g.emBr(BA64, g.retLabel2)
  else:
    lengError c, "`" & $c.stmtKind & "` is not allowed in an `.assembler` proc", g.asmInfo

proc asmCheckAbi*(g: var CodeGen; info: ProcInfo; used: var set[Reg]) =
  ## Check every `.register` pin on a parameter against the ABI, and bind the
  ## incoming registers to the signature's `pN.0` names.
  ##
  ## The plan comes from `planCall`, not from indexing `md.intArgRegs`: it is the
  ## same plan `emitSignature` writes and every CALL SITE reads, so a parameter
  ## this mode accepts is one the caller will actually stage where the body looks
  ## for it. It is also what makes the shapes an `.assembler` body cannot describe
  ## — a stack-passed parameter, a float, an aggregate, and (on Cortex-M) a
  ## 64-bit scalar spanning a register PAIR — rejections by name instead of a
  ## silent half-read.
  var pc = info.decl
  inc pc; inc pc                                 # head → name → params
  if pc.kind != TagLit: return
  let plan = planCall(g.md, paramSlots(g.prog, pc), retByRef = false)
  var ord = 0
  var retReg = NoReg
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                      # → return type
    if not (rc.kind == DotToken or (rc.kind == TagLit and rc.typeKind == VoidT)):
      retReg = g.md.intRetReg
  pc.into:
    while pc.hasMore:
      let pl = plan.args[ord]
      var nameC = pc
      pc.into:                                   # (param :nm pragmas type)
        nameC = pc
        let nm = symName(pc); inc pc
        let loc = g.asmDeclLoc(pc)
        skip pc                                  # pragmas
        g.symType[nm] = pc
        if pl.onStack:
          lengError nameC, "parameter `" & userName(nm) & "` is passed on the " &
                    "stack by this target's ABI, and an `.assembler` body names " &
                    "registers", g.asmInfo
        if pl.isFloat:
          lengError nameC, "parameter `" & userName(nm) & "` is passed in a " &
                    "floating-point register, which this mode cannot name yet",
                    g.asmInfo
        if pl.words != 1 or pl.isAgg:
          lengError nameC, "parameter `" & userName(nm) & "` spans " & $pl.words &
                    " registers on this target; an `.assembler` parameter must " &
                    "be one word", g.asmInfo
        let abiReg = g.md.gprAt(pl)
        case loc.kind
        of aslNone:
          lengError nameC, "parameter `" & userName(nm) & "` needs `{.register: \"" &
                    g.ab.renderReg(abiReg) &
                    "\".}` — an `.assembler` proc's annotations ARE its ABI", g.asmInfo
        of aslStack:
          lengError nameC, "parameter `" & userName(nm) & "` arrives in " &
                    g.ab.renderReg(abiReg) &
                    ", so it cannot be `{.stack.}`", g.asmInfo
        of aslReg:
          if loc.r != abiReg:
            lengError nameC, "parameter `" & userName(nm) & "` is passed in " &
                      g.ab.renderReg(abiReg) &
                      " by this target's ABI, but is pinned to " &
                      g.ab.renderReg(loc.r),
                      g.asmInfo
        g.asmReg[nm] = abiReg
        used.incl abiReg
        # r0/x0 is BOTH the first argument register and the return register. Left
        # bound to `p0.0`, a later `result = …` would render as a store to the
        # PARAMETER's name and be type-checked against the parameter's type. The
        # register is the identity in this mode, so the honest answer is to leave
        # it raw and let both names mean the machine register they name.
        if not (abiReg == retReg):
          g.rb.bindParam(abiReg, paramName(pl.ord))
        while pc.hasMore: skip pc
      inc ord

proc genAsmProc2*(g: var CodeGen; info: ProcInfo) =
  ## Emit an `.assembler` proc: no allocator, no analyser, no value core. The
  ## signature is the ordinary declarative one (that is what lets ordinary Nimony
  ## call it), and the `.register` annotations on the parameters are checked
  ## AGAINST it — in an `.assembler` proc a location constraint is an assertion,
  ## not a request.

  g.varType.clear(); g.symType.clear()
  g.rb.resetProc(); g.aliasToDecl.clear(); g.savedHomes.clear()
  g.rawHomeRegs = {}
  g.pickedRegs = {}; g.pickedFRegs = {}
  g.asmReg.clear(); g.asmStack.clear()
  g.asmInfo = lengInfo(info.decl)
  g.asmFlagsFresh = false
  g.loopEnds = @[]
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.helperCalls = false
  g.plan = Plan()
  if info.isEntry:
    lengError info.decl, "the program entry point cannot be an `.assembler` proc", g.asmInfo
  if not isDeclarativeAbi(g.prog, info.decl):
    lengError info.decl, "an `.assembler` proc's parameters and result must be " &
              "integers or pointers (float and small-aggregate boundaries are not " &
              "modelled in the typed signature yet)", g.asmInfo
  var used: set[Reg] = {}
  g.asmCheckAbi(info, used)
  block:                                         # the result register
    var rc = info.decl
    inc rc; inc rc; skip rc                      # → return type
    if not (rc.kind == DotToken or (rc.kind == TagLit and rc.typeKind == VoidT)):
      let rs = slotOf(g.prog, rc)
      if g.isWideSlot(rs):
        lengError info.decl, "a " & $rs.size & "-byte result travels in a register " &
                  "PAIR on this target, which an `.assembler` body cannot name yet",
                  g.asmInfo
      used.incl g.md.intRetReg
  var anyStack = false
  block:                                         # scan the BODY for pins and slots
    var bc = info.decl
    bc.into:
      inc bc; skip bc; skip bc; skip bc          # name, params, ret, pragmas
      if bc.stmtKind == StmtsS: g.asmScanLocs(bc, used, anyStack)
      while bc.hasMore: skip bc
  g.plan.usedCallee = used * g.armFrameSaved
  g.plan.hasStackVars = anyStack
  if info.isNaked:
    # `{.naked.}` is a promise about SP, and these two are the only ways an
    # `.assembler` body can break it. Both are rejected rather than silently
    # honoured: a `{.stack.}` local would need the frame the pragma just removed,
    # and a callee-saved register whose save never happened is a value returned
    # to the caller's own home — corruption that surfaces arbitrarily far away.
    if anyStack:
      lengError info.decl, "a `{.naked.}` proc has no stack frame, so it cannot " &
                "declare a `{.stack.}` local", g.asmInfo
    if g.plan.usedCallee != {}:
      var names = ""
      for r in g.armFrameSaved:
        if r in g.plan.usedCallee:
          if names.len > 0: names.add ", "
          names.add g.ab.renderReg(r)
      lengError info.decl, "a `{.naked.}` proc emits no prologue, so it cannot " &
                "use the callee-saved register(s) " & names &
                " — the caller's value there would be destroyed", g.asmInfo
  g.computeFrame(hasCall = false)
  if info.isNaked: g.hasFrame = false
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative = true)
    g.ab.tree StmtsA64:
      g.enterScope()
      if not info.isNaked:
        if g.hasFrame: framePush(g)
        if g.plan.hasStackVars:
          g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.keyword SsizeX)
      g.retLabel2 = g.freshLabel()
      g.retLabelUsed2 = false
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c            # name, params, ret, pragmas
        g.tailStmt = true                        # the whole body is in tail position
        if c.stmtKind == StmtsS: g.asmStmt(c)
        while c.hasMore: skip c
      # The label FIRST, then the scope kills: every `ret` branches here, so the
      # kills belong on the path that actually reaches the epilogue.
      if g.retLabelUsed2: g.emLab(g.retLabel2)
      g.exitScope()
      if not info.isNaked:
        if g.plan.hasStackVars:
          g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.keyword SsizeX)
        if g.hasFrame: framePop(g)
      # `{.naked.}` drops the epilogue but NOT the `ret`: without a return the
      # proc would fall into whatever the linker put next, and "no
      # prologue/epilogue" is a statement about the FRAME, not about returning.
      g.ab.keyword RetA64
