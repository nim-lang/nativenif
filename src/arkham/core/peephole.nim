#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## A peephole pass over the FINISHED asm-NIF, run between the emitters and
## `render`.
##
## Why here and not in the emitters: the shapes below are produced by half a
## dozen unrelated paths (a store's rhs, an argument's marshalling, a `(var …)`
## initializer), each of which asks for a value in a register because that is
## almost always what it needs. Teaching every one of them the exception is six
## edits and a seventh path tomorrow; recognising the finished shape is one.
##
## Two rules:
##
##  1. `(mov D imm)` + `(mov X D)` with `D` dead ⇒ `(mov X imm)` — the
##     materializing move for a constant that a store could have carried
##     itself. x86-64 only (`immAnyDest`).
##  2. `(mov T S)` + an instruction that only READS `T` ⇒ that instruction
##     reading `S` directly, and the copy dropped. This is the whole
##     "address in a scratch register" idiom: the emitters ask for an address
##     in a register because that is what they need when it has to be
##     COMPUTED, and pay a `mov` when it is already sitting in one with a name.
##     Six of the twenty-four instructions in `mmIkj64`'s vectorized inner loop
##     were that. The consumer need not be adjacent — see `passable`.
##
## Why it is safe against the class of mistake a bit-level peephole makes: the
## pass rewrites the very NIF that nifasm then type-checks, so an operand it
## types wrongly is an assembly-time ERROR naming the proc and the node. Every
## rule is therefore stated as "this node is exactly that node with one operand
## substituted", never as a machine-level equivalence. That property is real and
## it caught a bad rewrite here (`(cast T (reg))` is not a legal destination),
## but it is NOT a safety net for the two questions the type checker cannot
## ask, and each of those cost a miscompile:
##
##  * **Is the value dead?** See `deadAfter`. A redefinition is not proof; only
##    a `(kill …)` is, because a branch can jump over the redefinition and
##    reach a use of the old value.
##  * **Does the register survive?** See `declSkippable`. A declaration emits
##    no instruction and yet ends another name's binding, by taking its
##    register.
##
## The value table follows `shoggoth/trackers.nim`: facts are recorded per
## symbol and INVALIDATED at every point that could change them, and nothing is
## carried across a boundary where control flow could rejoin. This pass is the
## degenerate (straight-line) case of that — it never merges branches — so a
## fact lives only inside one sibling list, and the liveness question it needs
## is answered from the whole proc, not from the window.
##
## "From the whole PROC" is load-bearing and was not free: the scratch names are
## `tmpN.0`, and the counter behind them RESTARTS in every proc, so one SymId is
## every proc's `tmp0.0` at once. Answered from the whole buffer, `deadAfter`
## reads the next proc's `(kill tmp0.0)` as proof that THIS proc's `tmp0.0` is
## dead, and folds away a store the value is still read from. `Ctx.limit` is
## what confines the answer.
##
## `-d:arkhamNoPeephole` turns the whole pass off for a bisect.

import std / [tables, sets, assertions]
import nifcore

when defined(arkhamPeepDbg):
  import std / syncio
  var dbgCand*, dbgPair*: int


type
  OccKind = enum
    okRead     ## a plain operand: the value is still wanted
    okWrite    ## a destination operand: the old value is gone from here on
    okDef      ## a `(var :x …)` / `(rebind :x …)` head
    okKill     ## a `(kill x)` operand: the binding ends HERE — which is NOT
               ## the same as the value being dead, see `deadAfter`

  Occ = object
    pos: int         ## token index of a mention of the symbol
    kind: OccKind

  Occs = Table[SymId, seq[Occ]]

  Home = object
    ## What the declaration currently in force says about a symbol. Only two
    ## things are asked of it, and both are things a use site cannot read off
    ## its own node:
    ##
    ##  * `gpr` — is the symbol homed in a general-purpose register? A memory
    ##    BASE must be. `(mem <stack slot>)` is a legal but entirely different
    ##    operand — nifasm reads it as the slot's own address — so substituting
    ##    a stack-homed name for a register-homed one is the one mistake in this
    ##    pass that would not be an assembly-time error.
    ##  * the declared TYPE, as a token span. `(mem x)` takes its access width
    ##    from `x`'s declared type, so a substitution is type-preserving exactly
    ##    when the two names are declared the same — see `sameDeclaredType`.
    known: bool      ## a declaration for this symbol has been SEEN; without one
                     ## nothing below may assume anything about where it lives
    gpr: bool
    reg: TagId       ## the home register's tag, so "does this instruction write
                     ## the register the copy reads" is answerable by name
    typePos, typeLen: int

  Ctx = object
    ## Threaded through the walk instead of six parameters. `homes` is the part
    ## that MUTATES as the walk proceeds: it is cleared at each `(proc …)` and
    ## updated at each declaration, so it always answers with the declaration
    ## nifasm's own lexical lookup would find. That matters because the scratch
    ## names restart per proc (`tmp0.0` is every proc's) and because a
    ## `(rebind …)` deliberately re-declares a name with a new type and home.
    occs: Occs
    homes: Table[SymId, Home]
    gprs: HashSet[string]
    limit: int       ## end of the enclosing proc, for `deadAfter`
    immAnyDest: bool
    folds: int       ## instructions removed

const
  BarrierTags = ["scope", "loop", "lab", "proc", "stmts", "var", "rebind",
                 "param", "call", "tcall", "syscall", "extcall", "kill"]
    ## Consuming one of these would take the rewrite across a control-flow join
    ## or a call, where "nothing between the two nodes changes `S`" stops being
    ## true by inspection. The consumer must be one flat instruction.

  AddrTags = ["mem", "at", "dot"]
    ## Address expressions. Every register they name is READ, whatever the
    ## operand as a whole is to the instruction: `(mov (mem b) x)` writes memory
    ## and reads `b`. One exception, below.

  AtScratchIndex = 2
    ## …the exception: `(at <base> <index> <scratch>)`. nifasm COMPUTES
    ## `base + index*stride` into that third operand when the stride is not a
    ## legal SIB scale, so the scratch is written, not read.

  ReadsFromSecond = [
    # The asm-NIF vocabulary is written `(op D S …)` throughout, so for these
    # the operands from index 1 on are pure reads. Spelled out rather than
    # derived from the shape, because the exceptions are exactly the ones that
    # would miscompile silently: `(xchg D S)`, `(xadd D S)` and `(cmpxchg D S)`
    # WRITE their second operand, `(idiv D S R)` writes its third, and
    # `(umull L H A B)` writes its first two.
    "mov", "movzx", "movsx", "movsd", "movss", "movapd", "movupd", "movups",
    "movdqu", "movfq", "movfd", "movw", "lea",
    "add", "sub", "imul", "and", "or", "xor", "eor", "orr", "adc", "sbc",
    "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "lsl", "lsr", "asr",
    "addsd", "subsd", "mulsd", "divsd", "addss", "subss", "mulss", "divss",
    "addpd", "subpd", "mulpd", "addps", "subps", "mulps",
    "punpcklqdq", "shufps",
    "cvtsd2ss", "cvtss2sd", "cvtsi2sd", "cvtsi2ss", "cvttsd2si", "cvttss2si",
    "bsf", "bsr", "popcnt", "bt", "bts", "btr", "btc", "bswap", "mvn",
    "sxtb", "sxth", "uxtb", "uxth", "clz", "rbit", "rev",
    "add3", "sub3", "mul3", "and3", "orr3", "eor3", "bic3",
    "lsl3", "lsr3", "asr3", "addw3", "subw3", "mulw3", "adds3", "subs3",
    "addw", "subw", "mulw", "mls",
    "cmp", "test", "comisd", "comiss", "fcmp", "tst"]

  ReadsFromFirst = ["cmp", "test", "comisd", "comiss", "fcmp", "tst", "push"]
    ## …and these read their FIRST operand too: they produce flags, not a value.

  PureDestTags = [
    # Mnemonics whose first operand is written WITHOUT being read. Only these
    # may be counted as killing a previous value in `deadAfter`; `(add D S)`,
    # `(neg O)` and every other read-modify-write reads it first, and an
    # over-eager "the value is overwritten here" is the same mistake, one step
    # later, as the ones `deadAfter` documents.
    "mov", "movzx", "movsx", "movsd", "movss", "movapd", "movupd", "movups",
    "movdqu", "movfq", "movfd", "movw", "lea",
    "cvtsd2ss", "cvtss2sd", "cvtsi2sd", "cvtsi2ss", "cvttsd2si", "cvttss2si",
    "add3", "sub3", "mul3", "and3", "orr3", "eor3", "bic3",
    "lsl3", "lsr3", "asr3", "addw3", "subw3", "mulw3", "adds3", "subs3"]

proc operandIsRead(mnemonic: string; i: int): bool {.inline.} =
  if i == 0: mnemonic in ReadsFromFirst
  else: mnemonic in ReadsFromSecond

proc collectOccs(buf: var TokenBuf; c: var Cursor; isWrite, inKill: bool;
                 occs: var Occs) =
  ## Every mention of every symbol, in token order, classified. Only a first
  ## operand of a `PureDestTags` mnemonic counts as a WRITE; every other
  ## position is recorded as a read, which is the direction that makes
  ## `deadAfter` refuse rather than fold.
  case c.kind
  of Symbol:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c),
      kind: if inKill: okKill elif isWrite: okWrite else: okRead)
    inc c
  of SymbolDef:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c), kind: okDef)
    inc c
  of TagLit:
    let nm = buf.tags.tagName(c.cursorTagId)
    let isKill = nm == "kill"
    let pureDest = nm in PureDestTags
    var i = 0
    c.loopInto:
      collectOccs(buf, c, pureDest and i == 0, isKill, occs)
      inc i
  else:
    inc c

proc deadAfter(occs: Occs; s: SymId; pos, limit: int): bool =
  ## Is the value in `s` dead after token `pos`, asking only up to `limit` (the
  ## end of the enclosing proc)?
  ##
  ## Two things have to hold, and BOTH were learned from a miscompile.
  ##
  ## **The next mention must be a `(kill …)`.** A redefinition is not proof: a
  ## branch can jump over it and reach a use of the old value —
  ##
  ##     (mov result.45 (cast (ptr Trunk) `x.162))
  ##     (cmp result.45 (nil))
  ##     (jne `L98.0)          ; …to the (mov (rax) result.45) below
  ##     (rebind :result.45 …) ; the "proof", on the path NOT taken
  ##     (lab :`L98.0)
  ##     (mov (rax) result.45) ; the value the fold deleted
  ##
  ## **And the kill must not be a rename in disguise.** `(kill x)` ends the
  ## BINDING, not the value: arkham re-declares the same name in the same
  ## register afterwards and READS it, with nothing in between assigning it —
  ##
  ##     (mov `cse.1 (r12))      ; the only assignment
  ##     … (kill `cse.1)         ; inside a (prepare panic …) on a cold branch
  ##     (rebind :`cse.1 (aptr Match) (rsi))
  ##     (lea `tmp16.0 (at (cast (aptr Match)`cse.1) result.26 `tmp16.0))
  ##
  ## So after the kill the name must be WRITTEN before it is read (or never
  ## mentioned again in this proc). That is the shape of a genuine scratch
  ## binding — `(rebind :tmp4.0 …)` then `(mov tmp4.0 …)` — and it is what
  ## separates one from a value that merely changed names.
  let lst = occs.getOrDefault(s)
  var i = 0
  while i < lst.len and lst[i].pos <= pos: inc i
  if i >= lst.len or lst[i].pos >= limit or lst[i].kind != okKill: return false
  inc i
  while i < lst.len and lst[i].pos < limit:
    case lst[i].kind
    of okRead: return false
    of okWrite: return true
    of okDef, okKill: inc i
  true                        # nothing more in this proc

# ---------------------------------------------------------------------------
# Declarations: the home and the type a use site cannot read off its own node
# ---------------------------------------------------------------------------

proc noteDecl(buf: var TokenBuf; c: Cursor; homes: var Table[SymId, Home];
              gprs: HashSet[string]) =
  ## Record what a `(var :s <home> <type> …)`, `(rebind :s <type> <home>)` or
  ## `(param :s <home> <type>)` says about `s`. The two orders are spelled out
  ## rather than sniffed: guessing which child is the home from its SHAPE is how
  ## a `(bool)` type would be mistaken for a register.
  let nm = buf.tags.tagName(c.cursorTagId)
  let isRebind = nm == "rebind"
  if not (isRebind or nm == "var" or nm == "param"): return
  var b = sub(c)
  if not b.hasMore or b.kind != SymbolDef: return
  let s = b.symId
  skip b
  if not b.hasMore: return
  var homeC, typeC: Cursor
  if isRebind:
    typeC = b; skip b
    if not b.hasMore: return
    homeC = b
  else:
    homeC = b; skip b
    if not b.hasMore: return
    typeC = b
  var h = Home(known: true, gpr: false, typePos: cursorToPosition(buf, typeC),
               typeLen: subtreeWidth(typeC))
  if homeC.kind == TagLit:
    # A register is a CHILDLESS tag named for the machine's own spelling.
    # `(s 3)` (a stack slot) and `(regs (rsi)(rdx))` (an aggregate in two
    # registers) both have children; `(xmm8)` is childless but is not a name the
    # target hands out as a GPR.
    let hb = sub(homeC)
    h.gpr = not hb.hasMore and buf.tags.tagName(homeC.cursorTagId) in gprs
    if h.gpr: h.reg = homeC.cursorTagId
  homes[s] = h

proc sameDeclaredType(buf: TokenBuf; a, b: Home): bool =
  ## Are the two declared types the same tree? Compared token by token rather
  ## than as raw words: a `TagLit` token carries its subtree WIDTH in the high
  ## bits, so two identical types at different positions are not bit-identical.
  if a.typeLen != b.typeLen or a.typeLen == 0: return false
  for i in 0 ..< a.typeLen:
    let x = buf[a.typePos + i]
    let y = buf[b.typePos + i]
    if x.kind != y.kind: return false
    if x.kind == TagLit:
      if ((uint32(x) shr TagShift) and TagMask) !=
         ((uint32(y) shr TagShift) and TagMask): return false
    elif uoperand(x) != uoperand(y):
      return false
  true

# ---------------------------------------------------------------------------
# Rule 1: `(mov D imm)` + `(mov X D)` with D dead  ⇒  `(mov X imm)`
# ---------------------------------------------------------------------------

proc movImmDest(buf: var TokenBuf; c: Cursor; dst: var SymId; imm: var Cursor): bool =
  ## Is `c` a `(mov <symbol> <immediate>)`? `imm` is left at the value node so the
  ## caller can copy it verbatim — an `(intlit)`, or `(nil)`, whose *type* is the
  ## whole point of copying rather than re-synthesizing it.
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore or b.kind != Symbol: return false
  dst = b.symId
  skip b
  if not b.hasMore: return false
  if b.kind == IntLit or b.kind == UIntLit or
     (b.kind == TagLit and buf.tags.tagName(b.cursorTagId) == "nil"):
    imm = b
    skip b
    result = not b.hasMore   # exactly two children
  else:
    result = false

proc immFoldable(imm: Cursor): bool =
  ## x86 carries an immediate into MEMORY only as a sign-extended imm32
  ## (`mov r/m64, imm32`), and whether a destination IS memory is not readable
  ## from the node: a bare symbol is a stack slot or a register home depending on
  ## a `(var …)` far above. So the width rule is applied unconditionally — a
  ## 64-bit constant keeps its materializing `mov`, which is one instruction
  ## either way. (Learned from nifasm: "Immediate too large for memory move".)
  case imm.kind
  of IntLit: imm.intVal >= low(int32).int64 and imm.intVal <= high(int32).int64
  of UIntLit: imm.intVal >= 0 and imm.intVal <= high(int32).int64
  else: true                       # `(nil)` is a zero

proc movFromSym(buf: var TokenBuf; c: Cursor; src: SymId; destNode: var Cursor): bool =
  ## Is `c` a `(mov <anything> src)` whose SOURCE is exactly the symbol `src`?
  ## `destNode` is left at the destination operand. "Exactly" matters: a source
  ## wrapped in a `(cast …)` is a different node and is left alone.
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore: return false
  destNode = b
  skip b
  if not b.hasMore or b.kind != Symbol or b.symId != src: return false
  skip b
  result = not b.hasMore

# ---------------------------------------------------------------------------
# Rule 2: `(mov T S)` + an instruction addressing through `T`  ⇒  address
#         through `S` directly
# ---------------------------------------------------------------------------
#
# The shape arkham produces on every access through a pointer it holds in a
# register — the vectorizer's loop bodies are made of it:
#
#     (rebind :`tmp4.0 (ptr (f 64)) (r10))
#     (mov `tmp4.0 (cast (ptr (f 64)) vec.p.1))
#     (movups (mem `tmp4.0) vec.bc.3)
#     (kill `tmp4.0)
#
# The copy exists because the emitters ask for an ADDRESS in a scratch register,
# which is what they need when the address has to be computed. When it does not
# — when it is already sitting in a register with a name — the copy is the whole
# instruction. Six of the twenty-four instructions in `mmIkj64`'s vectorized
# inner loop are this.
#
# Why it is a rewrite of `(mem …)` specifically and not general copy
# propagation: the base of a memory operand is the one operand position that is
# a pure READ on every instruction of every target. Position 0 of `add` is a
# destination, position 1 of `xadd` is written too, and a rule that has to know
# which is which per mnemonic is a rule that is wrong for the mnemonic added
# next year.

type
  UseScan = object
    hits: int      ## mentions of `t` at a pure-read position — the ones being
                   ## rewritten
    castHits: int  ## …of those, the ones that are the VALUE of a `(cast T …)`,
                   ## i.e. the ones whose type comes from the node above them
                   ## rather than from `t`'s own declaration
    bad: bool      ## `t` mentioned anywhere it is WRITTEN, `s` mentioned at all,
                   ## or a barrier tag met: any of them refuses the fold

proc scanUse(buf: var TokenBuf; c: var Cursor; t, s: SymId; isRead, underCast: bool;
             r: var UseScan) =
  ## Walk the consumer and answer the side conditions at once: every mention of
  ## `t` is at a position the instruction only READS, `s` is not mentioned at
  ## all, and — for the caller that needs it — each mention is covered by a
  ## `(cast …)`. The `s` half is what makes "nothing changes `S` in between"
  ## hold for the consumer itself as well as for the (empty) gap before it.
  case c.kind
  of Symbol:
    if c.symId == t:
      if isRead:
        inc r.hits
        if underCast: inc r.castHits
      else: r.bad = true
    elif c.symId == s:
      r.bad = true
    inc c
  of SymbolDef:
    r.bad = true
    inc c
  of TagLit:
    let nm = buf.tags.tagName(c.cursorTagId)
    if nm in BarrierTags: r.bad = true
    let isAddr = nm in AddrTags
    let isCast = nm == "cast"
    var i = 0
    c.loopInto:
      let childRead =
        if isAddr: not (nm == "at" and i == AtScratchIndex)
        elif isCast: isRead
        else: operandIsRead(nm, i)
      scanUse(buf, c, t, s, childRead, isCast and i == 1, r)
      inc i
  else:
    inc c

proc emitRebased(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf;
                 t: SymId; repl: Cursor) =
  ## Copy the consumer, replacing every mention of `t` with `repl`. Every one of
  ## them is a read — `scanUse` refused the fold otherwise — so this needs no
  ## second opinion about operand positions.
  case c.kind
  of Symbol:
    if c.symId == t: dest.addSubtree repl else: dest.addSubtree c
    inc c
  of TagLit:
    dest.openTag c.cursorTagId
    c.loopInto:
      emitRebased(buf, c, dest, t, repl)
    dest.closeTag()
  else:
    dest.addSubtree c
    inc c

type
  CopySrc = object
    ## What a foldable `(mov T …)` puts into the consumer's operand slot.
    node: Cursor    ## the operand to splice — a `Symbol` token or a raw `(rN)`
    sym: SymId      ## the symbol behind it; `SymId(0)` when `node` is raw
    raw: bool

proc movCopy(buf: var TokenBuf; c: Cursor; dst: var SymId;
             src: var CopySrc; gprs: HashSet[string]): bool =
  ## Is `c` a `(mov <symbol> X)` whose source X already denotes a REGISTER —
  ## a symbol, a `(cast T <symbol>)`, or a raw `(rN)`? Those are the movs that
  ## carry a value the consumer could have read where it already is.
  ##
  ## A raw register is admitted because arkham reads the second eightbyte of an
  ## aggregate parameter that way, and `(mov T (rdx))` + `(lea D (at (cast …) T))`
  ## is the whole address-of-a-seq-element idiom. It is legal in the consumer's
  ## operand slot for the same reason it was legal here: nifasm's operand checks
  ## (a bound register must be named, `r11` must stay a typed binding) do not
  ## depend on which instruction the operand sits in, and nothing between the two
  ## nodes — there is nothing between them — can change a binding.
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore or b.kind != Symbol: return false
  dst = b.symId
  skip b
  if not b.hasMore: return false
  src = CopySrc(node: b, sym: SymId(0), raw: false)
  if b.kind == Symbol:
    src.sym = b.symId
  elif b.kind == TagLit and buf.tags.tagName(b.cursorTagId) == "cast":
    var cb = sub(b)
    if not cb.hasMore: return false
    skip cb                        # the cast type
    if not cb.hasMore or cb.kind != Symbol: return false
    src.node = cb
    src.sym = cb.symId
    skip cb
    if cb.hasMore: return false
  elif b.kind == TagLit and buf.tags.tagName(b.cursorTagId) in gprs:
    var cb = sub(b)
    if cb.hasMore: return false    # a register tag is childless
    src.raw = true
  else:
    return false
  skip b
  result = not b.hasMore

proc declSkippable(buf: var TokenBuf; c: Cursor; a, b: SymId; srcReg: TagId): bool =
  ## Is `c` a declaration that emits nothing, renames neither `a` nor `b`, and
  ## leaves the register `srcReg` alone? `(var :x <home> <type>)` and
  ## `(rebind :x <type> <home>)` — exactly three children, so a `(var …)` with
  ## an INITIALIZER (which does emit) is not one.
  ##
  ## The `srcReg` clause is the one that is not obvious and cost a miscompile:
  ## a declaration emits no instruction, but it does HAND THE REGISTER TO
  ## ANOTHER NAME, and nifasm then reads the old name as invalid. Moving a copy
  ## of `first.0` (homed in r15) past `(var :lf.1 (r15) (i 64))` produced an
  ## asm-NIF that named `first.0` after its binding was gone.
  let nm = buf.tags.tagName(c.cursorTagId)
  if nm != "var" and nm != "rebind": return false
  var k = sub(c)
  if not k.hasMore or k.kind != SymbolDef: return false
  if k.symId == a or k.symId == b: return false
  skip k
  if not k.hasMore: return false
  let second = k
  skip k
  if not k.hasMore: return false
  let third = k
  skip k
  if k.hasMore: return false
  let home = if nm == "rebind": third else: second
  result = not (home.kind == TagLit and home.cursorTagId == srcReg)

proc mentionsSym(buf: var TokenBuf; c: Cursor; s: SymId): bool =
  var probe = c
  var found = false
  proc walk(buf: var TokenBuf; c: var Cursor; s: SymId; found: var bool) =
    case c.kind
    of Symbol, SymbolDef:
      if c.symId == s: found = true
      inc c
    of TagLit:
      c.loopInto:
        walk(buf, c, s, found)
    else: inc c
  walk(buf, probe, s, found)
  result = found

proc writesReg(buf: var TokenBuf; c: Cursor; r: TagId; ctx: Ctx;
               seen: Table[SymId, Home]): bool =
  ## Does this instruction write the register `r`? Answered from its FIRST
  ## operand alone, which is why `passable` admits only mnemonics whose written
  ## register is that operand — `div`, `mul`, `cmpxchg` and friends write
  ## registers no operand names, and are refused there rather than guessed at
  ## here.
  let nm = buf.tags.tagName(c.cursorTagId)
  if nm in ReadsFromFirst: return false        # cmp/test/push write no register
  var b = sub(c)
  if not b.hasMore: return false
  # Peel a retyping cast; an address expression is a MEMORY destination and
  # writes no register.
  while b.kind == TagLit and buf.tags.tagName(b.cursorTagId) == "cast":
    var cb = sub(b)
    if not cb.hasMore: return true             # malformed: assume the worst
    skip cb
    if not cb.hasMore: return true
    b = cb
  case b.kind
  of Symbol:
    # An unknown symbol is assumed to write `r`: "no declaration seen" is not
    # "declared somewhere harmless".
    let h = if seen.hasKey(b.symId): seen[b.symId]
            else: ctx.homes.getOrDefault(b.symId)
    result = not h.known or h.reg == r
  of TagLit:
    let dn = buf.tags.tagName(b.cursorTagId)
    if dn in AddrTags: result = false
    elif dn in ctx.gprs: result = b.cursorTagId == r
    else: result = true                        # an operand shape not understood
  else: result = false

proc passable(buf: var TokenBuf; c: Cursor; t: SymId; src: CopySrc;
              srcReg: TagId; ctx: Ctx; seen: var Table[SymId, Home]): bool =
  ## May the copy be moved DOWN past this node, so that it lands next to the
  ## consumer that reads it? Only two kinds of node qualify: a declaration,
  ## which emits nothing at all, and a plain data-movement/ALU instruction that
  ## neither mentions the copy's destination nor overwrites the register the
  ## copy reads. Anything else — a call, a label, a branch, a scope, an
  ## instruction with implicit register effects — ends the search, because
  ## moving a write across it is no longer a statement about two adjacent
  ## nodes.
  if declSkippable(buf, c, t, src.sym, srcReg):
    # Record it: the very next instruction may be the one whose destination
    # this declaration just named, and `writesReg` has to know where it lives.
    noteDecl(buf, c, seen, ctx.gprs)
    return true
  if buf.tags.tagName(c.cursorTagId) notin ReadsFromSecond: return false
  if mentionsSym(buf, c, t): return false
  result = not writesReg(buf, c, srcReg, ctx, seen)

const MaxWindow = 6
  ## How far the consumer may be. A bound rather than a rule: the conditions
  ## above are what make the move legal, this only keeps the search linear.

proc trNode(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; ctx: var Ctx)

proc tryRebase(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf;
               ctx: var Ctx): bool =
  var t: SymId
  var src: CopySrc
  if not movCopy(buf, c, t, src, ctx.gprs): return false
  if not src.raw and src.sym == t: return false
  let ht = ctx.homes.getOrDefault(t)
  # `t` must be GPR-homed, because one of the positions its mentions may occupy
  # is a memory BASE and `(mem <stack slot>)` is a different operand entirely.
  if not ht.gpr: return false
  # Does the spliced operand carry `t`'s TYPE with it? A symbol declared exactly
  # as `t` is does. A raw register carries no type at all, and a symbol declared
  # differently carries the wrong one — the access width of `(mem x)` and the
  # width of an ALU operation both come from the operand's type, so those two
  # may only go where a `(cast …)` above them says what the type is. Retyping
  # them HERE is not the way out: nifasm rejects `(cast T (reg))` in a
  # destination slot outright, which is the check that caught the first attempt.
  var selfTyped = false
  if not src.raw:
    let hs = ctx.homes.getOrDefault(src.sym)
    if not hs.gpr: return false
    selfTyped = sameDeclaredType(buf, ht, hs)
  # Look PAST the declarations arkham interleaves with its instructions. A
  # `(var …)` / `(rebind …)` is a naming directive that emits no machine code,
  # so the consumer is still the next thing to RUN — and arkham routinely
  # announces the consumer's own scratch binding between the two:
  #     (mov `tmp4.0 (r8))
  #     (rebind :`tmp5.0 (i 64) (r11))
  #     (mov `tmp5.0 (mem i.0x6))
  #     (lea `x.8 (at (cast (aptr (f 64)) `tmp4.0) `tmp5.0))
  # A declaration OF either name is not skipped: that one does change what the
  # names mean.
  let srcReg = if src.raw: src.node.cursorTagId
               else: ctx.homes.getOrDefault(src.sym).reg
  var la = c
  skip la
  var skipped = 0
  var seen = initTable[SymId, Home]()
  var scan = UseScan()
  while true:
    if not la.hasMore or la.kind != TagLit or skipped > MaxWindow: return false
    # `passable` is asked FIRST and is decisive: a node the copy may move past
    # cannot be its consumer, because passing it required that it not mention
    # the copy's destination at all.
    if not passable(buf, la, t, src, srcReg, ctx, seen): break
    skip la
    inc skipped
  block:
    var probe = la
    scanUse(buf, probe, t, src.sym, false, false, scan)
  if scan.hits == 0 or scan.bad: return false
  if not selfTyped and scan.castHits != scan.hits: return false
  # PAST the consumer, not at it: the consumer's own operand is a mention of
  # `t`, and asking from its start position finds that one.
  if not deadAfter(ctx.occs, t, cursorToPosition(buf, la) + subtreeWidth(la) - 1,
                   ctx.limit): return false
  skip c                            # the copy: dropped
  for _ in 0 ..< skipped:           # what it moved past: kept as it was, and
    trNode(buf, c, dest, ctx)       # declarations still recorded by `noteDecl`
  var e = la
  emitRebased(buf, e, dest, t, src.node)
  skip c                            # the consumer: replaced above
  inc ctx.folds
  result = true

# ---------------------------------------------------------------------------

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; ctx: var Ctx)

proc trNode(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; ctx: var Ctx) =
  if c.kind == TagLit:
    # A `(proc …)` head is where the scratch-name counter restarts, so it is
    # also where both memories have to stop looking: everything inside this
    # subtree asks about `tmp0.0` and means THIS proc's.
    let isProc = buf.tags.tagName(c.cursorTagId) == "proc"
    let outer = ctx.limit
    if isProc:
      ctx.limit = cursorToPosition(buf, c) + subtreeWidth(c)
      ctx.homes.clear()
    noteDecl(buf, c, ctx.homes, ctx.gprs)
    dest.openTag c.cursorTagId
    c.loopInto:
      trList(buf, c, dest, ctx)
    dest.closeTag()
    if isProc:
      ctx.limit = outer
      ctx.homes.clear()
  else:
    dest.addSubtree c
    inc c

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; ctx: var Ctx) =
  ## One step of a sibling walk, with the one-node lookahead the rules need.
  var dst: SymId
  var immNode: Cursor
  if ctx.immAnyDest and movImmDest(buf, c, dst, immNode):
    when defined(arkhamPeepDbg): inc dbgCand
    var la = c
    skip la
    var destNode: Cursor
    when defined(arkhamPeepDbg):
      if la.hasMore and movFromSym(buf, la, dst, destNode): inc dbgPair
    if la.hasMore and movFromSym(buf, la, dst, destNode) and
       immFoldable(immNode) and
       # PAST the consumer, not at it: the consumer's own source operand is a
       # mention of `dst`, and asking from its start position finds that one.
       deadAfter(ctx.occs, dst, cursorToPosition(buf, la) + subtreeWidth(la) - 1,
                 ctx.limit):
      # `(mov D imm)` + `(mov X D)` with D dead ⇒ `(mov X imm)`. The scratch
      # register's `(rebind …)` above stays: it is a naming directive, costs no
      # machine code, and its `(kill …)` below still balances it.
      dest.openTag la.cursorTagId
      dest.addSubtree destNode
      dest.addSubtree immNode
      dest.closeTag()
      inc ctx.folds
      skip c                 # the materializing mov
      skip c                 # the consumer
      return
  if tryRebase(buf, c, dest, ctx): return
  trNode(buf, c, dest, ctx)

proc peephole*(buf: var TokenBuf; immAnyDest: bool; gprs: HashSet[string]): int =
  ## Rewrite `buf` in place; returns the number of instructions removed.
  ##
  ## `immAnyDest` states that the target can carry an immediate into ANY `mov`
  ## destination. x86-64 can (`mov r/m, imm32`); AArch64 cannot — a store there
  ## is `str <reg>, [addr]` with no immediate form, so the constant has to reach
  ## a register regardless and folding would only move the work, not remove it.
  ## Since a bare-symbol destination is a stack slot or a register home depending
  ## on a `(var …)` far above, the two cannot be told apart HERE; the target
  ## answers for both. Rule 2 needs no such permission — every target addresses
  ## memory through a register — but it does need `gprs`, the target's own
  ## spellings for the registers a base may live in.
  var ctx = Ctx(homes: initTable[SymId, Home](), gprs: gprs,
                limit: buf.len, immAnyDest: immAnyDest, folds: 0)
  block:
    var c = beginRead(buf)
    while c.hasMore:
      collectOccs(buf, c, false, false, ctx.occs)
    endRead c
  var res = createTokenBuf(buf.len, buf.pool, buf.tags)
  block:
    var c = beginRead(buf)
    while c.hasMore:
      trList(buf, c, res, ctx)
    endRead c
  buf = ensureMove res
  result = ctx.folds
  when defined(arkhamPeepDbg):
    stderr.writeLine "PEEP cand=" & $dbgCand & " pair=" & $dbgPair &
                     " folded=" & $result
