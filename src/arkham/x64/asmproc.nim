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
import "../core" / [machinedesc, planer, programs, asmbuf,
                    context, diag, asmcommon, 
                    mirrors, regbind]
import machine as machine_x64
import emit, mem, value, frame

type
  AsmDeclLoc* = object
    ## Where a `.assembler` param/local was DECLARED to live — the shared
    ## `AsmDeclSpec` with its register name resolved against THIS target's file.
    kind*: AsmDeclKind
    r*: Reg

proc asmStmt*(g: var CodeGen; c: Cursor)
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

proc asmOperand*(g: var CodeGen; cur: Cursor) =
  ## One source operand of a flag-defining instruction: a register local, a stack
  ## slot, or a literal. Unlike `asmRegOf` this permits memory and immediates,
  ## because `cmp`/`test` take them directly — no materialisation involved.
  let c = asmAtom(cur)
  case c.kind
  of Symbol:
    if g.isAsmStackSym(c): g.emStackMem(symName(c))
    else: g.emReg g.asmRegOf(c)
  of IntLit: g.ab.intLit intVal(c)
  of UIntLit: g.ab.intLit cast[int64](uintVal(c))
  else:
    lengError c, "an `.assembler` operand must be a variable or a literal", g.asmInfo

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
  if sym.kind != Symbol:
    lengError sym, "the destination of a two-address instruction must be a local " &
              "with a declared location", g.asmInfo
  let nm = symName(sym)
  if nm in g.asmStack: g.emStackMem(nm)
  else: g.emReg g.asmRegOf(sym)

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
  let tag = x64InoutTag(op)
  if tag == NopX64:
    lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 two-address form",
              g.asmInfo
  if row.arity == 1:
    g.ab.tree tag: g.asmInoutDest(argCurs[0])
  else:
    if g.isAsmStackSym(argCurs[1]) and
       argCurs[0].kind == TagLit and argCurs[0].exprKind == HaddrC:
      # `(add [mem], [mem])` does not exist. Only flagged when BOTH are memory;
      # a memory destination with a register or immediate source is fine.
      var d = argCurs[0]; inc d
      if d.kind == Symbol and symName(d) in g.asmStack:
        lengError c, "`" & IntrinsicNames[op] & "` cannot take two memory operands",
                  g.asmInfo
    g.ab.tree tag: (g.asmInoutDest(argCurs[0]); g.asmOperand(argCurs[1]))

proc asmFlagInstr*(g: var CodeGen; c: Cursor; op: IntrinsicOp) =
  ## `cmp(a, b)` / `test(a, b)` — an instruction whose entire output is flags.
  ## It is a statement, never a value: there is nothing to bind.
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
    # A `{.stack.}` local is a memory operand, so a move touching one is `mov
    # [slot], reg` / `mov reg, [slot]`. Memory on BOTH sides would take a scratch
    # register no one declared — the one thing `.assembler` will not invent.
    if g.isAsmStackSym(destC):
      if g.isAsmStackSym(srcC):
        lengError srcC, "a memory-to-memory move needs a scratch register; " &
                  "assign through a `{.register: \"…\".}` local", g.asmInfo
      let nm = symName(destC)
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
        g.ab.tree MovX64: (g.emReg dst; g.emStackMem(symName(srcC)))
      else:
        g.movReg(dst, g.asmRegOf(srcC))
    of IntLit:
      g.movImm(dst, intVal(srcC))
    of UIntLit:
      g.movImm(dst, cast[int64](uintVal(srcC)))
    of TagLit:
      if srcC.exprKind != InstrC:
        lengError srcC, "an `.assembler` statement must be one instruction; `" &
                  $srcC.exprKind & "` would need temporaries", g.asmInfo
      g.asmInstr(destC, dst, srcC)
    else:
      lengError srcC, "unsupported `.assembler` operand", g.asmInfo
    skip cc
    while cc.hasMore: skip cc

proc asmInstr*(g: var CodeGen; destC: Cursor; dst: Reg; c: Cursor) =
  ## `(instr SYM X*)` in an `.assembler` body: the operands are already where the
  ## user put them, so this is the row's opcode over `dst` and the operand
  ## registers — the same `emitIntrinsicOps` the allocated path ends in.
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  var fc = c
  fc.into:
    fsym = symName(fc); skip fc
    while fc.hasMore: (argCurs.add asmAtom(fc); skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if tgX64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no x86-64 lowering; an " &
              "`.assembler` proc has no fallback path", g.asmInfo
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
      # The signature already bound the ABI registers (`p0.0`, `ret.0`); pinning a
      # local onto one of those is legal — it is the same machine register under a
      # second source name — but must not redeclare the binding.
      if not g.rb.isBound(loc.r):
        g.emRegLocalVar(nm, loc.r, typeCur)
    of aslStack:
      g.asmStack.incl nm
      g.emTypedStackVar(nm, typeCur)
    of aslNone:
      if isResultName(nm):
        # The result is pinned to the ABI return register, derived rather than
        # annotated: Nimony has no syntax for annotating `result`, and the ABI
        # leaves no choice anyway.
        g.asmReg[nm] = g.md.intRetReg
      else:
        lengError nameC, "`" & userName(nm) & "` needs `{.register: \"…\".}` or `{.stack.}` — an " &
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
            g.ab.tree MovX64: (g.emReg g.asmReg[nm]; g.emStackMem(symName(initC)))
          else:
            g.movReg(g.asmReg[nm], g.asmRegOf(initC))
        of IntLit: g.movImm(g.asmReg[nm], intVal(initC))
        of UIntLit: g.movImm(g.asmReg[nm], cast[int64](uintVal(initC)))
        of TagLit:
          if initC.exprKind != InstrC:
            lengError initC, "an `.assembler` initializer must be one instruction or an atom",
                      g.asmInfo
          g.asmInstr(nameC, g.asmReg[nm], initC)
        else:
          lengError initC, "unsupported `.assembler` initializer", g.asmInfo
      skip cc
    while cc.hasMore: skip cc

proc asmStmt*(g: var CodeGen; c: Cursor) =
  if c.kind == DotToken: return
  g.asmNoteInfo(c)
  # Tail position, tracked exactly as `genStmt2` does: only the LAST statement of
  # a straight-line `stmts`/`scope` inherits it. A `ret` there falls through to the
  # epilogue instead of jumping to it — in a mode whose premise is one-to-one, a
  # `jmp` to the very next label is an instruction the user did not write.
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
      g.emitLoop:
        while cc.hasMore: (g.asmStmt(cc); skip cc)
      g.emLab(lEnd)
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
              g.ab.tree StmtsX64:
                if hasElse:
                  var ec = peek
                  ec.into:
                    g.enterScope()
                    while ec.hasMore: (g.asmStmt(ec); skip ec)
                    g.exitScope()
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
    var cc = c
    cc.into:
      g.emLab(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of JmpS:
    var cc = c
    cc.into:
      g.emJmp(symName(cc)); skip cc
      while cc.hasMore: skip cc
  of RetS:
    var cc = c
    cc.into:
      if cc.hasMore and cc.kind != DotToken:
        if g.isAsmStackSym(cc):
          g.ab.tree MovX64: (g.emReg g.md.intRetReg; g.emStackMem(symName(cc)))
        else:
          g.movReg(g.md.intRetReg, g.asmRegOf(cc))  # a no-op when already pinned there
        skip cc
      while cc.hasMore: skip cc
    if not myTail:
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
  g.asmReg.clear(); g.asmStack.clear()
  g.asmInfo = lengInfo(info.decl)
  g.loopEnds = @[]
  g.retAggrSym = NoTypeSym; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.plan = Plan()
  if info.isEntry:
    lengError info.decl, "the program entry point cannot be an `.assembler` proc", g.asmInfo
  if not isDeclarativeAbi(g.prog, info.decl):
    lengError info.decl, "an `.assembler` proc's parameters and result must be " &
              "integers or pointers (float and small-aggregate boundaries are not " &
              "modelled in the typed signature yet)", g.asmInfo
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
            let nm = symName(pc); inc pc
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
              lengError nameC, "parameter `" & userName(nm) & "` needs `{.register: \"" &
                        x64RegName(abiReg) & "\".}` — an `.assembler` proc's " &
                        "annotations ARE its ABI", g.asmInfo
            of aslStack:
              lengError nameC, "parameter `" & userName(nm) & "` arrives in " &
                        x64RegName(abiReg) & ", so it cannot be `{.stack.}`", g.asmInfo
            of aslReg:
              if loc.r != abiReg:
                lengError nameC, "parameter `" & userName(nm) & "` is passed in " &
                          x64RegName(abiReg) & " by the C ABI, but is pinned to " &
                          x64RegName(loc.r), g.asmInfo
            g.asmReg[nm] = abiReg
            g.rb.bindParam(abiReg, paramName(ord))
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
        g.tailStmt = true                        # the whole body is in tail position
        if c.stmtKind == StmtsS: g.asmStmt(c)
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
