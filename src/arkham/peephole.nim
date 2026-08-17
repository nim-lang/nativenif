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
## Why it is safe: the pass rewrites the very NIF that nifasm then type-checks.
## It cannot produce a silent miscompile of the kind a bit-level peephole can —
## an operand it types wrongly is an assembly-time ERROR, naming the proc and
## the node. Every rule below is therefore stated as "this node is exactly that
## node with one operand substituted", never as a machine-level equivalence.
##
## The value table follows `shoggoth/trackers.nim`: facts are recorded per
## symbol and INVALIDATED at every point that could change them, and nothing is
## carried across a boundary where control flow could rejoin. This pass is the
## degenerate (straight-line) case of that — it never merges branches — so a
## fact lives only inside one sibling list, and the liveness question it needs
## is answered from the whole proc, not from the window.

import std / [tables, sets, assertions, strutils, os, syncio]
import nifcore, nifcoreparse
import bodylib

when defined(arkhamPeepDbg):
  import std / syncio
  var dbgCand*, dbgPair*: int
  var dbgCopyCand*, dbgCopyFolded*, dbgLeaFolded*: int
  var dbgFailSever*, dbgFailUnsafe*, dbgFailNoMention*, dbgFailDead*: int

type
  Occ = object
    pos: int         ## token index of a mention of the symbol
    benign: bool     ## a `(kill …)` operand or a definition — i.e. NOT a read

  Occs = Table[SymId, seq[Occ]]

  Homes = Table[SymId, string]
    ## symbol → the GPR its binding lives in, from its `(var …)`/`(rebind …)`/
    ## `(param …)`/`(result …)` declaration. "" is POISON: declared more than
    ## once with different registers, homed in a register pair, or a stack
    ## binding — any case where "the value IS that register" does not hold.

const
  GprNames = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    ## rsp deliberately absent: it is never a value home.
  DeclTags = ["var", "rebind", "param", "result"]

proc homeScan(buf: var TokenBuf; c: var Cursor; sym: var SymId; haveSym: var bool;
              reg: var string; nregs: var int) =
  case c.kind
  of SymbolDef:
    if not haveSym:
      sym = c.symId
      haveSym = true
    inc c
  of TagLit:
    let name = buf.tags.tagName(c.cursorTagId)
    if name in GprNames:
      inc nregs
      reg = name
    c.loopInto:
      homeScan(buf, c, sym, haveSym, reg, nregs)
  else:
    inc c

proc recordHome(buf: var TokenBuf; decl: Cursor; homes: var Homes) =
  ## Read a declaration subtree: its defined symbol and the register tags in it.
  ## Exactly one GPR means the binding lives there; anything else poisons the
  ## symbol (a `(s …)` stack home, a `(regs …)` pair, or a re-declaration at a
  ## different register — rebinding the same register again is the common,
  ## harmless case and keeps the home).
  var sym = SymId(0)
  var haveSym = false
  var reg = ""
  var nregs = 0
  var d = sub(decl)
  while d.hasMore:
    homeScan(buf, d, sym, haveSym, reg, nregs)
  if haveSym:
    if nregs != 1:
      homes[sym] = ""
    elif homes.getOrDefault(sym, reg) != reg:
      homes[sym] = ""
    else:
      homes[sym] = reg

proc collectOccs(buf: var TokenBuf; c: var Cursor; parentIsKill: bool; occs: var Occs;
                 homes: var Homes) =
  ## Every mention of every symbol, in token order, tagged with whether it is a
  ## READ. `(kill x)` and a definition are not reads, and they are what lets a
  ## value be declared dead without a liveness analysis of our own: arkham kills
  ## each scratch binding at its last use, so the kill IS the liveness statement.
  case c.kind
  of Symbol:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c), benign: parentIsKill)
    inc c
  of SymbolDef:
    occs.mgetOrPut(c.symId, @[]).add Occ(pos: cursorToPosition(buf, c), benign: true)
    inc c
  of TagLit:
    let name = buf.tags.tagName(c.cursorTagId)
    if name in DeclTags:
      recordHome(buf, c, homes)
    let isKill = name == "kill"
    c.loopInto:
      collectOccs(buf, c, isKill, occs, homes)
  else:
    inc c

proc deadAfter(occs: Occs; s: SymId; pos: int): bool =
  ## Is `s` dead after token `pos`? True when its next mention is not a read.
  ## Conservative by construction: an unknown symbol, or one whose next mention
  ## is a plain operand, answers false.
  let lst = occs.getOrDefault(s)
  for o in lst:
    if o.pos > pos: return o.benign
  false                       # nothing follows: the binding outlives the proc's
                              # view here, so do not assume it is dead

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

proc movSymSym(buf: var TokenBuf; c: Cursor; dst, src: var SymId): bool =
  ## Is `c` a `(mov <symbol> <symbol>)` — a plain register-to-register copy at
  ## the model level — with exactly two bare children?
  if c.kind != TagLit or buf.tags.tagName(c.cursorTagId) != "mov": return false
  var b = sub(c)
  if not b.hasMore or b.kind != Symbol: return false
  dst = b.symId
  skip b
  if not b.hasMore or b.kind != Symbol: return false
  src = b.symId
  skip b
  result = not b.hasMore

proc rebindReg(buf: var TokenBuf; c: Cursor; defined: var SymId): string =
  ## For a `(rebind :X … (reg))` node: the register and the name it defines;
  ## "" when it is not a single-GPR rebind.
  var sym = SymId(0)
  var haveSym = false
  var reg = ""
  var nregs = 0
  var d = sub(c)
  while d.hasMore:
    homeScan(buf, d, sym, haveSym, reg, nregs)
  if haveSym and nregs == 1:
    defined = sym
    result = reg
  else:
    result = ""

const
  CopyConsumers = ["mov", "lea", "movzx", "movsx", "add", "sub", "and", "or",
                   "xor", "cmp", "test", "imul", "push"]
    ## Instructions the copy may be folded into. Shifts are ABSENT on purpose:
    ## their count operand must live in RCX, so substituting the copy's source
    ## there would trade a correct `mov rcx, S` for an assemble-time error.
  ReadsFirstOperand = ["cmp", "test", "push"]
    ## Tags whose first operand is read, not written.
  AddrTags = ["mem", "dot", "at"]

proc scanMentions(buf: var TokenBuf; c: var Cursor; t: SymId;
                  underAddr, underCast, writeDest: bool;
                  ok: var bool; count: var int) =
  ## Classify every mention of `t` inside one operand node. A mention is
  ## substitutable when it is a plain value READ whose width does not depend on
  ## `t`'s declared type:
  ##   * the write destination (bare or cast-wrapped first operand) is not a
  ##     read at all;
  ##   * inside `mem`/`dot`/`at` the ACCESS width (or `at`'s element stride) is
  ##     derived from the base's type, so a mention there is only safe under a
  ##     `(cast …)` — above the address node (retyping the access) or above the
  ##     base (retyping the pointer), either pins the width explicitly;
  ##   * everywhere else the operation width is never inferred from a symbol's
  ##     declared type (nifasm's sub-width model spells widths as casts), so a
  ##     bare register read substitutes freely.
  case c.kind
  of Symbol:
    if c.symId == t:
      if writeDest and not underAddr:
        ok = false
      elif underAddr and not underCast:
        ok = false
      else:
        inc count
    inc c
  of TagLit:
    let name = buf.tags.tagName(c.cursorTagId)
    let isAddr = name in AddrTags
    let addr2 = underAddr or isAddr
    let cast2 = underCast or name == "cast"
    let wd2 = writeDest and not isAddr
    c.loopInto:
      scanMentions(buf, c, t, addr2, cast2, wd2, ok, count)
  else:
    inc c

proc consumerMentions(buf: var TokenBuf; n: Cursor; t: SymId): int =
  ## How many substitutable read mentions of `t` the instruction `n` has;
  ## -1 when any mention is unsafe or the instruction is not a known consumer.
  let tag = buf.tags.tagName(n.cursorTagId)
  if tag notin CopyConsumers: return -1
  let readsFirst = tag in ReadsFirstOperand
  var ok = true
  var count = 0
  var b = sub(n)
  var idx = 0
  while b.hasMore:
    scanMentions(buf, b, t, false, false, idx == 0 and not readsFirst, ok, count)
    inc idx
  result = if ok: count else: -1

proc readsFlags(name: string): bool =
  (name.len > 1 and name[0] == 'j' and name != "jmp") or
  name.startsWith("set") or name.startsWith("cmov") or
  name in ["adc", "sbb", "rcl", "rcr", "ite", "jtrue"]

proc writesFlags(name: string): bool =
  name in ["cmp", "test", "add", "sub", "and", "or", "xor", "neg", "inc", "dec",
           "shl", "shr", "sar", "sal", "imul", "mul", "idiv", "div",
           "bsf", "bsr", "bt", "bts", "btr", "btc", "popcnt",
           "call", "extcall", "prepare", "syscall"]

proc flagNeutral(name: string): bool =
  name in ["mov", "lea", "movzx", "movsx", "rebind", "kill", "lab", "push",
           "pop", "movdqu", "movsd", "movss", "movfq", "movfd", "var"]

proc flagsDeadAfter(buf: var TokenBuf; after: Cursor): bool =
  ## May an instruction at `after` be replaced by a flags-neutral equivalent?
  ## Scan the following siblings: a flags reader before the next writer means
  ## no. An unknown or structured node answers no (conservative); the list
  ## ending answers yes — arkham's structured codegen always recomputes a
  ## condition (`cmp`/`test`) right before consuming it, never across a scope.
  var la = after
  skip la
  var steps = 0
  while la.hasMore and steps < 64:
    if la.kind != TagLit: return false
    let name = buf.tags.tagName(la.cursorTagId)
    if readsFlags(name): return false
    if writesFlags(name): return true
    if not flagNeutral(name): return false
    skip la
    inc steps
  result = steps < 64

# ── whole-proc body replacement ("the cheat") ────────────────────────────────
# `bodylib` holds distilled gcc -O3 bodies for a handful of known-hot procs,
# keyed by a STRUCTURAL fingerprint of the proc arkham just generated. The
# fingerprint is alpha-blind: every symbol DEFINED inside the proc (params,
# result, locals, labels) is numbered by first occurrence instead of hashed by
# name, so the global counters in `x.47`-style names cannot break a match.
# Symbols NOT defined inside the proc (types, fields, called procs) keep their
# names — a same-shaped proc over different types must not match.
#
# Fail-safe by construction: any codegen change alters the fingerprint and the
# entry silently stops matching — the proc then just compiles as generated.
# Refresh workflow: set ARKHAM_BODYFP=1, recompile the module, and copy the
# printed `BODYFP` line for the proc into `bodylib.nim`.

let bodyFpDump = getEnv("ARKHAM_BODYFP").len > 0

proc fpDefs(buf: var TokenBuf; c: var Cursor; defs: var HashSet[SymId]) =
  case c.kind
  of SymbolDef:
    defs.incl c.symId
    inc c
  of TagLit:
    c.loopInto:
      fpDefs(buf, c, defs)
  else:
    inc c

proc fpMix(h: var uint64; s: string) {.inline.} =
  for ch in s:
    h = (h xor uint64(ch)) * 0x100000001b3'u64

proc fpWalk(buf: var TokenBuf; c: var Cursor; defs: HashSet[SymId];
            ids: var Table[SymId, int]; h: var uint64; toks: var int) =
  inc toks
  case c.kind
  of TagLit:
    fpMix h, "("
    fpMix h, buf.tags.tagName(c.cursorTagId)
    c.loopInto:
      fpWalk(buf, c, defs, ids, h, toks)
    fpMix h, ")"
  of SymbolDef, Symbol:
    let marker = if c.kind == SymbolDef: ":" else: "&"
    if c.symId in defs:
      let n = ids.mgetOrPut(c.symId, ids.len)
      fpMix h, marker & $n
    else:
      # External name, hashed module-blind: the reader completes a trailing-dot
      # symbol with the CURRENT module's suffix, so the same generic instance
      # spells `seq.0.Izimvvd1.<moduleA>` in one build and `.<moduleB>` in the
      # next. Drop that final segment (empty for a raw trailing-dot spelling,
      # non-numeric for a completed one); a numeric final segment is an overload
      # ordinal and stays.
      var name = buf.pool.syms[c.symId]
      let k = rfind(name, '.')
      if k >= 0:
        var numericTail = k < name.len - 1
        for i in k + 1 ..< name.len:
          if name[i] notin {'0' .. '9'}:
            numericTail = false
            break
        if not numericTail: name.setLen k
      fpMix h, "@" & name
    inc c
  of IntLit, UIntLit:
    fpMix h, "#" & $c.intVal
    inc c
  else:
    fpMix h, "|" & $c.kind
    inc c

proc procFingerprint(buf: var TokenBuf; procNode: Cursor): tuple[fp: uint64; toks: int] =
  var defs = initHashSet[SymId]()
  var d = procNode
  fpDefs(buf, d, defs)
  var ids = initTable[SymId, int]()
  var h = 0xcbf29ce484222325'u64          # FNV-1a offset basis
  var toks = 0
  var w = procNode
  fpWalk(buf, w, defs, ids, h, toks)
  (h, toks)

proc procDeclName(buf: var TokenBuf; procNode: Cursor): string =
  var d = sub(procNode)
  if d.hasMore and d.kind == SymbolDef:
    result = buf.pool.syms[d.symId]
  else:
    result = "?"

proc emitBodyReplacement(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf;
                         entry: int) =
  ## Emit the proc at `c` with its header (name, params, result, clobber) kept
  ## verbatim and its body swapped for the library's `(lenient)`-mode text.
  dest.openTag c.cursorTagId
  var child = 0
  c.loopInto:
    if child < 4:                # :name (params …) (result …) (clobber …)
      dest.addSubtree c
    skip c
    inc child
  var rep = parseFromBuffer(BodyLib[entry].body, "bodylib", 4096,
                            buf.pool, buf.tags)
  var rc = beginRead(rep)
  var d = sub(rc)                # unwrap the `(stmts …)` shipping container
  while d.hasMore:
    dest.addSubtree d
    skip d
  endRead rc
  dest.closeTag()

proc matchBody(buf: var TokenBuf; procNode: Cursor): int =
  ## Library index whose fingerprint matches the proc at `procNode`, or -1.
  result = -1
  if BodyLib.len == 0 and not bodyFpDump: return
  let (fp, toks) = procFingerprint(buf, procNode)
  if bodyFpDump:
    stderr.writeLine "BODYFP " & procDeclName(buf, procNode) &
      " fp=0x" & toHex(fp) & " toks=" & $toks
  for i in 0 ..< BodyLib.len:
    if BodyLib[i].fp == fp and BodyLib[i].toks == toks:
      return i

proc emitSubst(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; t, s: SymId) =
  ## Copy the node at `c`, replacing every read of `t` with `s`.
  case c.kind
  of TagLit:
    dest.openTag c.cursorTagId
    c.loopInto:
      emitSubst(buf, c, dest, t, s)
    dest.closeTag()
  of Symbol:
    if c.symId == t:
      dest.addSymUse s
    else:
      dest.addSubtree c
    inc c
  else:
    dest.addSubtree c
    inc c

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            homes: Homes; folded: var int)

proc trNode(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            homes: Homes; folded: var int) =
  if c.kind == TagLit:
    if buf.tags.tagName(c.cursorTagId) == "proc":
      let mi = matchBody(buf, c)
      if mi >= 0:
        emitBodyReplacement(buf, c, dest, mi)
        return
      # Rescope the fact tables to THIS proc: locals of different procs share
      # names (`x.47`, `ap.1`, …), so module-wide tables poison almost every
      # register home and blur liveness across proc boundaries.
      var scan = c
      var procOccs = initTable[SymId, seq[Occ]]()
      var procHomes = initTable[SymId, string]()
      collectOccs(buf, scan, false, procOccs, procHomes)
      dest.openTag c.cursorTagId
      c.loopInto:
        trList(buf, c, dest, procOccs, procHomes, folded)
      dest.closeTag()
    else:
      dest.openTag c.cursorTagId
      c.loopInto:
        trList(buf, c, dest, occs, homes, folded)
      dest.closeTag()
  else:
    dest.addSubtree c
    inc c

proc trList(buf: var TokenBuf; c: var Cursor; dest: var TokenBuf; occs: Occs;
            homes: Homes; folded: var int) =
  ## One step of a sibling walk, with the one-node lookahead the rules need.
  var dst: SymId
  var immNode: Cursor
  if movImmDest(buf, c, dst, immNode):
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
       deadAfter(occs, dst, cursorToPosition(buf, la) + subtreeWidth(la) - 1):
      # `(mov D imm)` + `(mov X D)` with D dead ⇒ `(mov X imm)`. The scratch
      # register's `(rebind …)` above stays: it is a naming directive, costs no
      # machine code, and its `(kill …)` below still balances it.
      dest.openTag la.cursorTagId
      dest.addSubtree destNode
      dest.addSubtree immNode
      dest.closeTag()
      inc folded
      skip c                 # the materializing mov
      skip c                 # the consumer
      return
  var src: SymId
  if movSymSym(buf, c, dst, src) and dst != src and
     homes.getOrDefault(src, "").len > 0:
    # `(mov T S)` + next instruction reading T, T dead there ⇒ substitute S.
    # S must be REGISTER-homed: substituting a stack symbol could pair two
    # memory operands in one instruction, and its value could not be read
    # without the load this rule deletes. Between the copy and its consumer,
    # retyping `(rebind …)`s of T's register are the common idiom (a pointer
    # deref retypes its base first) and are followed through by renaming T; a
    # rebind of S's register would sever the copied value and stops the rule.
    when defined(arkhamPeepDbg): inc dbgCopyCand
    let srcHome = homes.getOrDefault(src, "")
    var curT = dst
    let curReg = homes.getOrDefault(dst, "")
    var la = c
    skip la
    var nwin = 0
    var severed = false
    var winRegs: seq[string] = @[]
    while la.hasMore and la.kind == TagLit and
          buf.tags.tagName(la.cursorTagId) == "rebind" and nwin < 8:
      var defined = SymId(0)
      let r = rebindReg(buf, la, defined)
      if r.len == 0 or r == srcHome:
        severed = true
        break
      if curReg.len > 0 and r == curReg:
        curT = defined
      winRegs.add r
      skip la
      inc nwin
    when defined(arkhamPeepDbg):
      if severed: inc dbgFailSever
    if not severed and la.hasMore:
      let m = consumerMentions(buf, la, curT)
      when defined(arkhamPeepDbg):
        if m < 0: inc dbgFailUnsafe
        elif m == 0: inc dbgFailNoMention
        elif not deadAfter(occs, curT, cursorToPosition(buf, la) + subtreeWidth(la) - 1):
          inc dbgFailDead
      if m > 0 and
         deadAfter(occs, curT, cursorToPosition(buf, la) + subtreeWidth(la) - 1):
        when defined(arkhamPeepDbg): inc dbgCopyFolded
        skip c                       # the copy
        for i in 0 ..< nwin:         # the retyping rebinds: naming directives,
          dest.addSubtree c          # no machine code — carried through so the
          skip c                     # `(kill …)` below still balances
        emitSubst(buf, c, dest, curT, src)
        inc folded
        return
      # Copy-then-accumulate: `(mov T S)` + one arithmetic step on T is one
      # address computation —
      #   `(add|sub T imm)` ⇒ `(lea T S ±imm)`
      #   `(add T S2)`      ⇒ `(lea T (mem S S2 1))`   (S2 = S when T doubled)
      #   `(shl T 1)`       ⇒ `(lea T (mem S S 1))`
      #   `(shl T 2|3)`     ⇒ `(lea T (mem 0 S 4|8))`  (the no-base scaled form)
      # T stays live (it holds the result), so no deadness is needed; what IS
      # needed is that nobody reads the arithmetic's flags, which the lea no
      # longer sets.
      if la.kind == TagLit:
        let cname = buf.tags.tagName(la.cursorTagId)
        if cname == "add" or cname == "sub" or cname == "shl":
          var b = sub(la)
          if b.hasMore and b.kind == Symbol and b.symId == curT:
            skip b
            template foldToLea(emitOperands: untyped) =
              when defined(arkhamPeepDbg): inc dbgLeaFolded
              skip c               # the copy
              for i in 0 ..< nwin:
                dest.addSubtree c
                skip c
              dest.openTag registerTag(buf.tags, "lea")
              dest.addSymUse curT
              emitOperands
              dest.closeTag()
              skip c               # the accumulate
              inc folded
              return
            if b.hasMore and (b.kind == IntLit or b.kind == UIntLit):
              var imm = b.intVal
              skip b
              if not b.hasMore:
                if cname == "shl":
                  if imm >= 1 and imm <= 3 and flagsDeadAfter(buf, la):
                    if imm == 1:
                      foldToLea:
                        dest.openTag registerTag(buf.tags, "mem")
                        dest.addSymUse src
                        dest.addSymUse src
                        dest.addIntLit 1
                        dest.closeTag()
                    else:
                      foldToLea:
                        dest.openTag registerTag(buf.tags, "mem")
                        dest.addIntLit 0
                        dest.addSymUse src
                        dest.addIntLit 1'i64 shl imm
                        dest.closeTag()
                else:
                  var immOk = imm >= low(int32).int64 and imm <= high(int32).int64
                  if cname == "sub":
                    # negate only inside the range, so `-imm` cannot overflow
                    immOk = immOk and imm > low(int32).int64
                    if immOk: imm = -imm
                  if immOk and flagsDeadAfter(buf, la):
                    foldToLea:
                      dest.addSymUse src
                      dest.addIntLit imm
            elif cname == "add" and b.kind == Symbol:
              var s2 = b.symId
              skip b
              if not b.hasMore:
                if s2 == curT: s2 = src         # `add T T` after the copy = 2*S
                let s2home = homes.getOrDefault(s2, "")
                if s2home.len > 0 and s2home notin winRegs and
                   flagsDeadAfter(buf, la):
                  foldToLea:
                    dest.openTag registerTag(buf.tags, "mem")
                    dest.addSymUse src
                    dest.addSymUse s2
                    dest.addIntLit 1
                    dest.closeTag()
  trNode(buf, c, dest, occs, homes, folded)

proc peephole*(buf: var TokenBuf; immAnyDest: bool): int =
  ## Rewrite `buf` in place; returns the number of instructions removed.
  ##
  ## `immAnyDest` states that the target can carry an immediate into ANY `mov`
  ## destination. x86-64 can (`mov r/m, imm32`); AArch64 cannot — a store there
  ## is `str <reg>, [addr]` with no immediate form, so the constant has to reach
  ## a register regardless and folding would only move the work, not remove it.
  ## Since a bare-symbol destination is a stack slot or a register home depending
  ## on a `(var …)` far above, the two cannot be told apart HERE; the target
  ## answers for both.
  if not immAnyDest: return 0
  var occs = initTable[SymId, seq[Occ]]()
  var homes = initTable[SymId, string]()
  block:
    var c = beginRead(buf)
    while c.hasMore:
      collectOccs(buf, c, false, occs, homes)
    endRead c
  var res = createTokenBuf(buf.len, buf.pool, buf.tags)
  result = 0
  block:
    var c = beginRead(buf)
    while c.hasMore:
      trList(buf, c, res, occs, homes, result)
    endRead c
  buf = ensureMove res
  when defined(arkhamPeepDbg):
    stderr.writeLine "PEEP cand=" & $dbgCand & " pair=" & $dbgPair & " folded=" & $result &
      " copyCand=" & $dbgCopyCand & " copyFolded=" & $dbgCopyFolded &
      " leaFolded=" & $dbgLeaFolded &
      " sever=" & $dbgFailSever & " unsafe=" & $dbgFailUnsafe &
      " noMention=" & $dbgFailNoMention & " notDead=" & $dbgFailDead
