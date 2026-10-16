#
#            Arkham — `.assembler` procs on the load/store targets
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The load/store half of `doc/intrinsics.md` §8, and the twin of
## `x64/asmproc`'s `genAsmProc`.
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
import "../core" / [asmslots, machinedesc, planner, programs, asmbuf,
                    context, diag, asmcommon, 
                    mirrors, regbind, abi, exprpred]
import machine_a64 as machine
from machine_cortexm import nil
import emit, value, frame
from a64 import nil
from cortexm import nil
from rv32 import nil

include compat2   # getOrQuit on host Nim

proc armFrameSaved(g: CodeGen): set[Reg] =
  ## The callee-saved registers this back end's prologue actually saves — the
  ## same list `computeFrame` walks, which is the ARCHITECTURAL one and not
  ## `md.intCalleeSaved`. The two differ under `-d:arkhamStress`, where the
  ## allocator's pools are starved: a stressed build allocates out of fewer
  ## homes, but a `.assembler` body does not allocate at all, so a register it
  ## NAMES must still be saved. Reading the same list in both places is what
  ## keeps "the pin is legal" and "the prologue saves it" one fact.
  result = {}
  for r in g.md.abiCalleeSaved: result.incl r

proc armVolatile(g: CodeGen): set[Reg] =
  ## The registers a callee may destroy without saving. AAPCS32 gives Cortex-M
  ## exactly four (its argument registers; r12 is volatile too but is nifasm's),
  ## AAPCS64 gives x0–x17.
  g.md.intCallerSavedSet

proc armRegByName(g: CodeGen; name: string): Reg =
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
  case g.md.arch
  of ThumbM: cortexm.rejectReservedPin(g, at, name, result)
  of Rv32: rv32.rejectReservedPin(g, at, name, result)
  else: a64.rejectReservedPin(g, at, name, result)
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

proc armFlagOf(op: IntrinsicOp): X64Flag =
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

proc armFlagSupported(g: CodeGen; f: X64Flag): bool {.inline.} =
  ## Which conditions the ASSEMBLER can turn into a branch. Cortex-M maps all
  ## eight of Arm's (`condOfFlagM`); AArch64's `genIteA64` implements only the
  ## zero flag so far. Asking here rather than emitting and hoping is what keeps
  ## an unimplemented condition a named compile error instead of a nifasm crash
  ## in the middle of an otherwise valid image.
  if f == NoFlag: false
  elif AllFlagBranches in g.md.caps: f in {ZfO, NzO, CfO, NcO, SfO, NsO, OfO, NoO}
  elif g.md.arch == Rv32:
    # FOUR, which is why neither arm above fits and this one exists. RV32 has no
    # condition flags at all: its selector fuses `(cmp a b)` into the branch that
    # consumes it, so `zf`/`nz` are equality and `cf`/`nc` are the unsigned
    # `<`/`>=` a borrow denotes. `sf`/`of` have no equivalent — the sign of a
    # difference agrees with `<` only when the subtraction did not overflow, which
    # is why AArch64's `blt` tests `N != V` — and `relOfFlagRv` refuses them by
    # name. Answering `{ZfO, NzO}` here (the pre-RV32 default) was SAFE but a
    # subset: it turned `cf` into "this target has no such thing", which is the
    # wrong sentence about a target whose branches are exactly comparisons.
    f in {ZfO, NzO, CfO, NcO}
  else: f in {ZfO, NzO}

# ── AArch64: flag liveness ───────────────────────────────────────────────────
# Cortex-M cannot promise anything about NZCV between a `cmp` and its use, which
# is the `asmFlagsFresh` rule below: Thumb's narrow encodings set the flags
# whether asked to or not. AArch64 has no such encodings. Its flag-setting
# instructions are separate mnemonics (`adds`, `adcs`, `subs`, `sbcs`, `cmp`),
# and every other instruction this mode emits leaves NZCV alone — so on AArch64
# the flags are tracked exactly as on x86-64: a read of a flag that no
# instruction on every path defined is rejected, and anything else is allowed
# in between. That is what a carry chain interleaved with `mul`/`umulh` needs.

const A64Nzcv = {mfZF, mfCF, mfSF, mfOF}

proc a64Flags(g: CodeGen): bool {.inline.} =
  ## Whether this target tracks flags precisely (AArch64) rather than by the
  ## "only right after a `cmp`" rule (Cortex-M, RV32).
  g.md.arch == Arm64

proc a64FlagDefs(op: IntrinsicOp): set[MachineFlag] =
  case op
  of CmpOp, Adds3Op, Adcs3Op, Subs3Op, Sbcs3Op: A64Nzcv
  else: {}

proc a64FlagNames(fs: set[MachineFlag]): string =
  result = ""
  for f in fs:
    if result.len > 0: result.add ", "
    result.add (case f
                of mfZF: "Z"
                of mfCF: "C"
                of mfSF: "N"
                of mfOF: "V"
                of mfPF: "P")

proc asmUseFlags(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## AArch64: reject a read of a flag with no known definition here.
  let missing = IntrinsicRows[op].uses - g.asmFlags
  if missing != {}:
    lengError c, "`" & IntrinsicNames[op] & "` reads " & a64FlagNames(missing) &
              ", which is not defined here: no `cmp`, `adds3`, `adcs3`, `subs3` " &
              "or `sbcs3` on every path to this instruction sets it", g.asmInfo

proc asmApplyFlags(g: var CodeGen; op: IntrinsicOp) {.inline.} =
  let d = a64FlagDefs(op)
  if d != {}:
    g.asmFlags = d
    g.asmCfBy = op

proc asmForgetFlags(g: var CodeGen) {.inline.} =
  ## A merge point: a label, a loop head, the code after a loop.
  g.asmFlags = {}
  g.asmCfBy = NoIntrinsicOp
  g.asmFlagsFresh = false

# ── memory operands ─────────────────────────────────────────────────────────
# Arm is a load/store machine: memory is reached by `mov` (a load or a store)
# and nothing else, always through a pointer that already sits in a declared
# register. The address is nifasm's typed `(at base idx)` / `(dot base field)`,
# so a wrong access is a type error, not a wrong displacement, and the width of
# the access is the element's.

proc isAsmMemExpr(c: Cursor): bool {.inline.} =
  ## `p[i]` on a `ptr UncheckedArray` (`(pat p i)`), `p[]` (`(deref p)`) or
  ## `p.f` (`(dot (deref p) f)`).
  c.kind == TagLit and c.exprKind in {PatC, DerefC, DotC}

proc asmRegOrZero(g: var CodeGen; c: Cursor) =
  ## A register operand where the literal 0 is AArch64's zero register: the
  ## encodings that take a register there read 31 as `xzr`, so `adcs3(t, 0)` is
  ## "add the carry" and `p[i] = 0` stores zero, with no register spent on it.
  let a = asmAtom(c)
  if a.kind in {IntLit, UIntLit} and g.md.arch == Arm64 and
     (if a.kind == IntLit: intVal(a) == 0 else: uintVal(a) == 0'u64):
    g.ab.zeroReg()
  elif a.kind == Symbol and not g.isAsmStackSym(a):
    g.emReg g.asmRegOf(a)
  else:
    lengError c, "this operand must be a register local" &
              (if g.md.arch == Arm64: " or the literal 0 (`xzr`)" else: ""),
              g.asmInfo

proc asmPtrBase(g: var CodeGen; c: Cursor) =
  if c.kind != Symbol or g.isAsmStackSym(c):
    lengError c, "an `.assembler` memory operand must be addressed through a " &
              "pointer held in a `{.register: \"…\".}` local or parameter", g.asmInfo
  let r = g.asmRegOf(c)
  let t = g.symType.getOrDefault(c.symId, default(Cursor))
  if not g.rb.isBound(r) and not cursorIsNil(t):
    # A register with no name on it — `x0` when it carries a parameter AND the
    # result, which `asmCheckAbi` leaves raw — has no type nifasm could index
    # through, so the access says which pointer it is reading.
    var tc = t
    g.ab.tree CastX:
      g.genTypeBody(tc)
      g.ab.rawReg r
  else:
    g.emReg r

proc asmAddr(g: var CodeGen; c: Cursor) =
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
          if g.isAsmStackSym(idx):
            lengError idx, "an `.assembler` index must be a literal or a register " &
                      "local", g.asmInfo
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

proc asmMem(g: var CodeGen; c: Cursor) =
  if g.md.arch != Arm64:
    # The address forms are nifasm's on every Arm/RISC-V target, but only the
    # AArch64 lowering of them in this mode has been run; a target that has
    # not is told so by name rather than handed an untested encoding.
    lengError c, "a memory operand in an `.assembler` body is implemented for " &
              "AArch64 and x86-64 so far, not for " & g.md.targetName, g.asmInfo
  g.ab.tree MemX: g.asmAddr(c)

proc asmNarrow(g: CodeGen; c: Cursor): bool =
  ## Is the register local `c` (possibly under `(haddr …)`) declared narrower
  ## than 64 bits? Its declared type is the operand width, as on x86-64.
  var d = c
  if d.kind == TagLit and d.exprKind == HaddrC: inc d
  if d.kind != Symbol or d.symId in g.asmStack: return false
  let t = g.symType.getOrDefault(d.symId, default(Cursor))
  if cursorIsNil(t) or t.kind != TagLit or
     t.typeKind notin {LengType.IT, LengType.UT, LengType.CT}:
    return false
  let bits = typeBits(t)
  result = bits > 0 and bits < 64

proc asmStmt*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {})
proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor)

proc emAsmSlot(g: var CodeGen; name: SymId) {.inline.} =
  ## A `{.stack.}` local as an OPERAND. On Arm a frame slot is addressed by its
  ## own symbol — `(mov t.0 (r2))` stores, `(mov (r2) t.0)` loads — which is what
  ## every hand-written body in this back end already does.
  g.ab.sym name

proc asmMovReg(g: var CodeGen; d, s: Reg) {.inline.} =
  if d != s: g.ab.tree MovA64: (g.emReg d; g.emReg s)

proc asmAddrOf(g: var CodeGen; dst: Reg; c: Cursor) =
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
  let nm = sym.symId
  if nm in g.asmStack:
    g.ab.tree LeaA64: (g.emReg dst; g.emAsmSlot(nm))
  elif g.asmReg.hasKey(nm):
    lengError sym, "`" & g.userName(nm) & "` lives in a register, which has no " &
              "address — give it `{.stack.}` if something must point at it",
              g.asmInfo
  elif g.prog.globals.hasKey(nm) or isForeignSym(g.prog, nm):
    g.emAdr(dst, g.prog.gvarRefName(nm))
  else:
    lengError sym, "`" & g.userName(nm) & "` is neither a local of this proc nor a " &
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
    if g.isAsmStackSym(c): g.emAsmSlot(c.symId)
    else: g.emReg g.asmRegOf(c)
  of IntLit: g.ab.intLit intVal(c)
  of UIntLit: g.ab.intLit cast[int64](uintVal(c))
  else:
    if isAsmMemExpr(c):
      lengError c, "Arm arithmetic reads registers only; load the value into a " &
                "`{.register: \"…\".}` local with an assignment first", g.asmInfo
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
  let nm = sym.symId
  if nm in g.asmStack:
    # Arm is a load/store machine: `(add t.0 (r1))` where `t.0` is a frame slot
    # is not an instruction, and letting nifasm fold it would need the very
    # scratch register this mode refuses to invent.
    lengError sym, "`" & g.userName(nm) & "` lives on the stack, and Arm arithmetic " &
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
  var tag = inoutInst(op)
  if tag == NopA64:
    lengError c, "`" & IntrinsicNames[op] & "` has no " &
              g.md.targetName & " two-address form",
              g.asmInfo
  if g.md.arch == Arm64 and g.asmNarrow(argCurs[0]):
    # A local declared narrower than 64 bits takes the 32-bit form, as on
    # x86-64: `add` carries out of bit 31 into nothing and the result stays
    # zero-extended. The bitwise rows and `lsr` keep a zero-extended value
    # zero-extended at 64 bits; `lsl`, `asr` and `neg` would not, and there is
    # no `w` two-address form for them here, so they are refused by name.
    case op
    of AddOp: tag = AddwA64
    of SubOp: tag = SubwA64
    of AndOp, OrOp, XorOp, ShrOp: discard
    else:
      lengError c, "`" & IntrinsicNames[op] & "` on a 32-bit local has no " &
                "AArch64 two-address form; declare the local `uint64`", g.asmInfo
  if row.arity == 1:
    g.ab.tree tag: g.asmInoutDest(argCurs[0])
  else:
    g.ab.tree tag: (g.asmInoutDest(argCurs[0]); g.asmOperand(argCurs[1]))
  # Arm's arithmetic is where the flags become unanswerable: nifasm asks for the
  # non-flag-setting form, and Thumb's narrow encoding — the one it prefers when
  # every operand is a low register — sets them anyway. So after this the flags
  # depend on which registers the body pinned, which is not something to read.
  # (AArch64 has no narrow encodings: its `add` leaves NZCV alone, which is
  # what `asmFlags` keeps track of.)
  g.asmFlagsFresh = false

proc asmVoidInstr(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
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
  if op == BkptOp:
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
  g.asmApplyFlags(op)

proc asmStore(g: var CodeGen; nm: SymId; srcC: Cursor) =
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

proc asmLoad(g: var CodeGen; dst: Reg; srcC: Cursor) =
  ## `reg = <atom>`, where the atom is not an `(instr …)`.
  case srcC.kind
  of Symbol:
    if g.isAsmStackSym(srcC):
      g.ab.tree MovA64: (g.emReg dst; g.emAsmSlot(srcC.symId))
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
    if isAsmMemExpr(destC):
      # a STORE, `p[i] = x`: the source is a register (or the literal 0, which
      # is `xzr` on AArch64) — memory to memory needs a scratch nobody declared
      if isAsmMemExpr(srcC) or g.isAsmStackSym(srcC):
        lengError srcC, "a memory-to-memory move needs a scratch register; " &
                  "assign through a `{.register: \"…\".}` local", g.asmInfo
      g.asmFlagsFresh = false
      g.ab.tree MovA64:
        g.asmMem(destC)
        g.asmRegOrZero(srcC)
      skip cc
      while cc.hasMore: skip cc
      return
    if g.isAsmStackSym(destC):
      g.asmStore(destC.symId, srcC)
      skip cc
      while cc.hasMore: skip cc
      return
    let dst = g.asmRegOf(destC)
    if isAsmMemExpr(srcC):
      # a LOAD, `x = p[i]`, at the element's width
      g.ab.tree MovA64: (g.emReg dst; g.asmMem(srcC))
      g.asmFlagsFresh = false
    elif srcC.kind == TagLit:
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

proc a64CselTag(op: IntrinsicOp): RiscInst =
  case op
  of CseleqOp: CseleqA64
  of CselneOp: CselneA64
  of CselltOp: CselltA64
  of CselleOp: CselleA64
  of CselgtOp: CselgtA64
  of CselgeOp: CselgeA64
  of CselloOp: CselloA64
  of CsellsOp: CsellsA64
  of CselhiOp: CselhiA64
  else: CselhsA64

proc asmA64Value(g: var CodeGen; dst: Reg; c: Cursor; op: IntrinsicOp;
                 argBits: int; args: seq[Cursor]): bool =
  ## The AArch64 value rows with TWO sources: `d = op(a, b)` is one three-address
  ## instruction, so nothing is copied into `d` first and `d` may be `a` or `b`.
  ## `false` for a row this does not handle (the unary ones below).
  result = true
  template literalSecond(what: string) =
    if args[1].kind in {IntLit, UIntLit}:
      lengError c, "`" & IntrinsicNames[op] & "` takes " & what, g.asmInfo
  case op
  of Adds3Op, Subs3Op:
    # A 12-bit immediate is encodable as the second source; the first must be a
    # register, because `adds`'s immediate form reads register 31 as `sp`.
    if args[0].kind != Symbol:
      lengError c, "the first operand of `" & IntrinsicNames[op] & "` must be a " &
                "register local", g.asmInfo
    g.ab.tree (if op == Adds3Op: Adds3A64 else: Subs3A64):
      g.emReg dst
      g.emReg g.asmRegOf(args[0])
      let b = asmAtom(args[1])
      if b.kind in {IntLit, UIntLit}:
        let v = (if b.kind == IntLit: intVal(b) else: cast[int64](uintVal(b)))
        if v < 0 or v > 4095:
          lengError b, "`" & IntrinsicNames[op] & "` takes a 12-bit immediate " &
                    "(0..4095); load a larger constant into a register", g.asmInfo
        g.ab.intLit v
      else:
        g.asmRegOrZero(b)
  of Adcs3Op, Sbcs3Op:
    g.ab.tree (if op == Adcs3Op: Adcs3A64 else: Sbcs3A64):
      g.emReg dst
      g.asmRegOrZero(args[0])
      g.asmRegOrZero(args[1])
  of Mul3Op:
    literalSecond "register operands only"
    g.ab.tree (if argBits <= 32: Mulw3A64 else: Mul3A64):
      g.emReg dst
      g.asmRegOrZero(args[0])
      g.asmRegOrZero(args[1])
  of UmulhOp:
    literalSecond "register operands only"
    g.ab.tree Umulh3A64:
      g.emReg dst
      g.asmRegOrZero(args[0])
      g.asmRegOrZero(args[1])
  of CseleqOp..CselhsOp:
    g.ab.tree a64CselTag(op):
      g.emReg dst
      g.asmRegOrZero(args[0])
      g.asmRegOrZero(args[1])
  of RorOp:
    if argBits notin [32, 64]:
      lengError c, "AArch64 rotates 32- and 64-bit values only", g.asmInfo
    let n = asmAtom(args[1])
    g.ab.tree (if argBits == 32: Rorw3A64 else: Ror3A64):
      g.emReg dst
      g.emReg g.asmRegOf(args[0])
      case n.kind
      of IntLit, UIntLit:
        let v = (if n.kind == IntLit: intVal(n) else: cast[int64](uintVal(n)))
        if v < 0 or v >= argBits:
          lengError n, "a rotate count must be 0.." & $(argBits - 1), g.asmInfo
        g.ab.intLit v
      else:
        g.emReg g.asmRegOf(n)
  else:
    result = false
  if result:
    g.asmApplyFlags(op)
    g.asmFlagsFresh = false

proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor) =
  ## `(instr SYM X*)` in an `.assembler` body: the operands are already where the
  ## user put them, so this is the row's opcode over `dst` and the operand
  ## registers — no placement, no freeing, none of `emitInstr`'s machinery.
  var fsym = NoSymId
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    fsym = fc.symId; skip fc
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if not g.hasHereLowering(row.targets):
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no " &
              g.md.targetName & " lowering; an " &
              "`.assembler` proc has no fallback path", g.asmInfo
  if row.isFlagRead:
    lengError c, "`" & IntrinsicNames[tgt.op] & "()` is a flag, not a value; " &
              "it can only be an `if` condition", g.asmInfo
  if g.a64Flags: g.asmUseFlags(c, tgt.op)
  if row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` produces no value, only flags; " &
              "use it as a statement", g.asmInfo
  if row.inoutOperand >= 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` writes through its first " &
              "operand and returns nothing; use it as a statement", g.asmInfo
  if argCurs.len == 0:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` takes no operands here", g.asmInfo
  if argCurs.len != row.arity:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` takes " & $row.arity &
              " operand(s)", g.asmInfo
  if g.md.arch == Arm64 and g.asmA64Value(dst, c, tgt.op, tgt.argBits, argCurs):
    return
  let src = g.asmRegOf(argCurs[0])
  # The operand width, from the row's own declared parameter — the same
  # `tgt.argBits` the allocated path reads. Cortex-M has 32-bit registers and
  # nothing else, so a row asking for 64 there is refused by nifasm's width check
  # rather than encoded as something narrower.
  let bits = if tgt.argBits in [8, 16, 32]: 32 else: 64
  if tgt.op in {ClzPinnedOp, ClzOp, RbitOp, CtzOp, RevOp, BswapOp} and
     BitScanOps notin g.md.caps:
    # Refused BY NAME rather than lowered. There is a software sequence for each
    # of these, but this is `{.assembler.}` — the mode whose whole contract is
    # that every construct maps one-to-one and nothing is materialised — so
    # expanding one row into a loop is the one thing it must not do. The
    # ORDINARY path may lower them in software; this one says no.
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no single instruction on " &
              g.md.targetName & ", and `.assembler` will not expand one row into " &
              "a sequence; use it outside an `{.assembler.}` proc", g.asmInfo
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
      # The signature already bound the ABI registers; pinning a local onto one
      # of those is legal — the same machine register under a second source name
      # — and needs no new binding while the TYPE is the same. A different type
      # is a different value in that register (a carry word landing in x1 after
      # the pointer that arrived there is spent): the register is re-declared,
      # which ends the old binding, and nifasm types every later use as what the
      # register now holds.
      let prev = g.asmRegType.getOrDefault(loc.r, default(Cursor))
      if not g.rb.isBound(loc.r) or cursorIsNil(prev) or not sameTree(prev, typeCur):
        g.emRegLocalVar(nm, loc.r, typeCur)
        g.asmRegType[loc.r] = typeCur
    of aslStack:
      let s = slotOf(g.prog, typeCur)
      if s.kind in {AInt, AUInt, ABool} and s.size > wordSize():
        # A 64-bit `{.stack.}` local would be a 64-bit-typed access, which nifasm
        # refuses on this target (`checkRegWidthM`) — refuses rather than
        # truncating. Saying so here names the local instead of pointing at a
        # `(mov …)` the user did not write.
        lengError nameC, "`" & g.userName(nm) & "` is " & $s.size & " bytes, and a " &
                  g.md.targetName & " `.assembler` body moves one " &
                  $wordSize() & "-byte word at a time — " &
                  "declare the halves", g.asmInfo
      g.asmStack.incl nm
      g.emTypedStackVar(nm, typeCur)
    of aslNone:
      if g.isResultName(nm):
        # The result is pinned to the ABI return register, derived rather than
        # annotated: Nimony has no syntax for annotating `result`, and the ABI
        # leaves no choice anyway.
        g.asmReg[nm] = g.md.intRetReg
      else:
        lengError nameC, "`" & g.userName(nm) & "` needs `{.register: \"…\".}` or " &
                  "`{.stack.}` — an `.assembler` proc declares every location",
                  g.asmInfo
    if hasInit:
      if loc.kind == aslStack: g.asmStore(nm, initC)
      elif initC.kind == TagLit:
        case initC.exprKind
        of InstrC: g.asmInstr(nameC, g.asmReg.getOrQuit(nm), initC)
        of AddrC, HaddrC:
          g.asmAddrOf(g.asmReg.getOrQuit(nm), initC)
          g.asmFlagsFresh = false
        else:
          lengError initC, "an `.assembler` initializer must be one instruction, " &
                    "an `addr`, or an atom", g.asmInfo
      else:
        g.asmLoad(g.asmReg.getOrQuit(nm), initC)
        g.asmFlagsFresh = false
      skip cc
    while cc.hasMore: skip cc

proc asmIf(g: var CodeGen; c: Cursor) =
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
          if not g.hasHereLowering(IntrinsicRows[op].targets):
            lengError condC, "`" & IntrinsicNames[op] & "` has no " &
                      g.md.targetName & " lowering",
                      g.asmInfo
          let flag = armFlagOf(op)
          if not g.armFlagSupported(flag):
            lengError condC, "`" & IntrinsicNames[op] & "` is not a condition " &
                      (if g.thumbM: "Cortex-M" else: "the AArch64 assembler") &
                      " can branch on", g.asmInfo
          if g.a64Flags:
            g.asmUseFlags(condC, op)
          elif not g.asmFlagsFresh:
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
          let atIf = g.asmFlags
          let cfAtIf = g.asmCfBy
          g.ab.tree IteA64:
            g.ab.keyword flag
            g.ab.tree StmtsA64:
              g.enterScope()
              while bc.hasMore: (g.asmStmt(bc); skip bc)
              g.exitScope()
            let afterThen = g.asmFlags
            g.asmFlags = atIf
            g.asmCfBy = cfAtIf
            g.ab.tree StmtsA64:
              if hasElse:
                var ec = peek
                ec.into:
                  g.enterScope()
                  while ec.hasMore: (g.asmStmt(ec); skip ec)
                  g.exitScope()
            # only what both arms leave defined is defined after the `if`
            g.asmFlags = g.asmFlags * afterThen
            g.asmFlagsFresh = false
      of ElseU:
        discard                                  # emitted inside the `elif` above
      else:
        lengError cc, "unsupported `if` shape in an `.assembler` proc", g.asmInfo
      skip cc

proc asmStmt*(g: var CodeGen; c: Cursor; flags: set[StmtFlag] = {}) =
  if c.kind == DotToken: return
  g.asmNoteInfo(c)
  # Tail position, tracked exactly as `genStmt` does: only the LAST statement of
  # a straight-line `stmts`/`scope` inherits it. A `ret` there falls through to
  # the epilogue instead of branching to it — in a mode whose premise is
  # one-to-one, a `b` to the very next label is an instruction nobody wrote.
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
    # belong here are the three with no result: one that writes through an
    # `inout` operand, one whose whole output is the flags, and one that has no
    # output of any kind (`cpuRelax`).
    let op = g.instrOpAt(c)
    if op != NoIntrinsicOp and IntrinsicRows[op].inoutOperand >= 0:
      g.asmInoutInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isFlagWrite:
      if not g.hasHereLowering(IntrinsicRows[op].targets):
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      g.asmFlagInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isVoidResult and
         IntrinsicRows[op].arity > 0:
      if not g.hasHereLowering(IntrinsicRows[op].targets):
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      g.asmVoidInstr(c, op)
    elif op != NoIntrinsicOp and IntrinsicRows[op].isNullaryVoid:
      if not g.hasHereLowering(IntrinsicRows[op].targets):
        lengError c, "`" & IntrinsicNames[op] & "` has no " &
                  g.md.targetName & " lowering; an " &
                  "`.assembler` proc has no fallback path", g.asmInfo
      case op
      of CpuRelaxOp:
        g.ab.keyword YieldA64      # one spelling, hence one interned tag
      of SemihostOp:
        # RISC-V semihosting: nifasm emits the whole `slli x0,x0,0x1f` / `ebreak`
        # / `srai x0,x0,7` triple from this one keyword. The outer two are
        # architectural no-ops that exist only so a debug agent recognises the
        # middle one as a request rather than an ordinary breakpoint, so they are
        # not separable and there is nothing to give an operand to. a0/a1 were set
        # by the surrounding `.assembler` body, which is the whole reason a
        # semihosting call is written in one.
        g.ab.keyword SemihostRv
      else:
        lengError c, "`" & IntrinsicNames[op] & "` has no " & g.md.targetName &
                  " lowering", g.asmInfo
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
      g.asmForgetFlags()               # the back edge arrives with other flags
      g.emitLoop:
        while cc.hasMore: (g.asmStmt(cc); skip cc)
      g.emLab(lEnd)
      g.asmForgetFlags()               # reached by `break`s from anywhere in it
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
    g.asmForgetFlags()
    var cc = c
    cc.into:
      g.emLab(cc.symId); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emBr(BA64, cc.symId); skip cc
      while cc.hasMore: skip cc
  of RetS:
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isAsmStackSym(cc):
          g.ab.tree MovA64: (g.emReg g.md.intRetReg; g.emAsmSlot(cc.symId))
        else:
          g.asmMovReg(g.md.intRetReg, g.asmRegOf(cc))  # a no-op when already pinned there
        skip cc
      while cc.hasMore: skip cc
    if TailStmt notin flags:
      g.retLabelUsed2 = true
      g.emBr(BA64, g.retLabel2)
  else:
    lengError c, "`" & $c.stmtKind & "` is not allowed in an `.assembler` proc", g.asmInfo

proc asmCheckAbi(g: var CodeGen; info: ProcInfo; used: var set[Reg]) =
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
        let nm = pc.symId; inc pc
        let loc = g.asmDeclLoc(pc)
        skip pc                                  # pragmas
        g.symType[nm] = pc
        if pl.onStack:
          lengError nameC, "parameter `" & g.userName(nm) & "` is passed on the " &
                    "stack by this target's ABI, and an `.assembler` body names " &
                    "registers", g.asmInfo
        if pl.isFloat:
          lengError nameC, "parameter `" & g.userName(nm) & "` is passed in a " &
                    "floating-point register, which this mode cannot name yet",
                    g.asmInfo
        if pl.words != 1 or pl.isAgg:
          lengError nameC, "parameter `" & g.userName(nm) & "` spans " & $pl.words &
                    " registers on this target; an `.assembler` parameter must " &
                    "be one word", g.asmInfo
        let abiReg = g.md.gprAt(pl)
        case loc.kind
        of aslNone:
          lengError nameC, "parameter `" & g.userName(nm) & "` needs `{.register: \"" &
                    g.ab.renderReg(abiReg) &
                    "\".}` — an `.assembler` proc's annotations ARE its ABI", g.asmInfo
        of aslStack:
          lengError nameC, "parameter `" & g.userName(nm) & "` arrives in " &
                    g.ab.renderReg(abiReg) &
                    ", so it cannot be `{.stack.}`", g.asmInfo
        of aslReg:
          if loc.r != abiReg:
            lengError nameC, "parameter `" & g.userName(nm) & "` is passed in " &
                      g.ab.renderReg(abiReg) &
                      " by this target's ABI, but is pinned to " &
                      g.ab.renderReg(loc.r),
                      g.asmInfo
        g.asmReg[nm] = abiReg
        g.asmRegType[abiReg] = pc                 # the param's Leng type
        used.incl abiReg
        # r0/x0 is BOTH the first argument register and the return register. Left
        # bound to `p0.0`, a later `result = …` would render as a store to the
        # PARAMETER's name and be type-checked against the parameter's type. The
        # register is the identity in this mode, so the honest answer is to leave
        # it raw and let both names mean the machine register they name.
        if not (abiReg == retReg):
          g.rb.bindParam(abiReg, g.paramName(pl.ord))
        while pc.hasMore: skip pc
      inc ord

proc genAsmProc*(g: var CodeGen; info: ProcInfo) =
  ## Emit an `.assembler` proc: no allocator, no analyser, no value core. The
  ## signature is the ordinary declarative one (that is what lets ordinary Nimony
  ## call it), and the `.register` annotations on the parameters are checked
  ## AGAINST it — in an `.assembler` proc a location constraint is an assertion,
  ## not a request.

  g.varType.clear(); g.symType.clear()
  g.rb.resetProc(); g.aliasToDecl.clear(); g.savedHomes.clear()
  g.rawHomeRegs = {}
  g.pickedRegs = {}; g.pickedFRegs = {}
  g.asmReg.clear(); g.asmStack.clear(); g.asmRegType.clear()
  g.asmInfo = lengInfo(info.decl)
  g.asmFlagsFresh = false
  g.asmFlags = {}                    # the caller's flags are not ours to read
  g.asmCfBy = NoIntrinsicOp
  g.loopEnds = @[]
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.helperCalls = false
  g.plan = Plan()
  if info.isEntry:
    lengError info.decl, "the program entry point cannot be an `.assembler` proc", g.asmInfo
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
    g.emitSignature(info.decl)
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
        # the whole body is in tail position
        if c.stmtKind == StmtsS: g.asmStmt(c, {TailStmt})
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
