#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Addressing on Arm: turning an lvalue into a `(mem …)` operand.
##
## LDR/STR take an unsigned immediate scaled by the ACCESS WIDTH, so whether an
## offset fits depends on how wide the load is — and an offset that does not fit
## has to be materialised into a scratch base first. That is the recurring shape
## below, and it is why so much of this asks the binding tables which register is
## free rather than picking one.

import std / [assertions, tables, sets, strformat, strutils]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, 
                    exprpred, regbind]
import machine_a64 as machine
from machine_m as machine_m import nil
import emit

proc takeBridge*(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg   # defined below

proc bindTemp*(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(xN)` the binding
  ## checker can't see. The binding is recorded as a transient temp; released by
  ## `unbindTemp`.
  let name = g.rb.freshTmpName()
  g.ab.tree RebindA64:
    g.ab.symDef name
    g.emBindType(typ)
    g.ab.rawReg r
  g.rb.bindScratch(r, name, g.slotIsPointer(typ))
  g.tmpBindTyp[r] = typ                 # what the register is TYPED as, for a later
                                        # `(rebind …)` and for `mirrorStored`, which
                                        # may only forward a value whose binding type
                                        # is the slot's own (x64's `bindTemp` twin)

proc emitLvalue2*(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false)

proc tryTakeBridge*(g: var CodeGen; typ = ScalarSlot; avoid = NoReg;
                   lastResort = false): Reg =
  ## `takeBridge` for a caller that HAS another answer when every bridge is
  ## already staging: reports exhaustion as `NoReg` instead of asserting.
  ##
  ## I2 is enforced HERE, the one choke point every bridge take goes through, and
  ## it is checked BEFORE the search rather than after it fails: a step that
  ## exceeds its declaration is wrong even on a machine roomy enough to have
  ## satisfied it, and that is precisely the bug a fixed reservation hides until
  ## some unrelated target or stress level runs out.
  ## `lastResort` says the caller has already tried everything else it has — a
  ## pool register, a callee-saved survivor — and this take is the difference
  ## between emitting and failing. That is NOT the quiet overrun the cap exists to
  ## catch, so it is counted rather than asserted: a step that exhausts its
  ## alternatives and says so is behaving correctly, and refusing it here would
  ## trade a budget overrun for a hard out-of-registers, which is strictly worse.
  ## `lastResortBridges` is what makes the escape visible instead of silent.
  when BridgeCheck:
    if not g.bridgeTakeAllowed():
      if lastResort: inc lastResortTakes
      else: bridgeOverDeclared(g)
  for r in g.bridgeRegs:
    if r != avoid and not g.rb.isBoundTemp(r) and r notin g.pickedRegs:
      g.bindTemp(r, typ)
      if lastResort: g.lastResortBridges.incl r
      when defined(arkhamBridgeDbg): g.dbgNoteBridges(r)
      return r
  NoReg

proc takeBridge*(g: var CodeGen; typ = ScalarSlot; avoid = NoReg): Reg =
  ## A scratch GPR from the reserved set (x14/x15/x16 on AArch64, r10/r11/r8 on
  ## Cortex-M). Bound to a typed name so `emReg` emits a checked symbol and a
  ## typed memory base type-checks. Released by `dropBridge`.
  ##
  ## Three nest — an address, an index and the word passing between them, which is
  ## the deepest of the enumerated shapes (design.md, "How many registers the
  ## emitter actually needs"). A fourth asserts, and that assert is a statement
  ## about the RESERVATION being too small for a shape nobody enumerated, not
  ## about the allocator having been unlucky: none of these registers is ever
  ## assigned to anything else.
  result = g.tryTakeBridge(typ, avoid)
  if result == NoReg:
    raiseAssert "arkham arm: every scratch bridge in use in proc " & g.curProcName

proc placeImmTyped*(g: var CodeGen; dest: Reg; loc: Location; typeCur: Cursor) =
  ## `placeImm` for a `dest` bound with `typeCur`'s slot. When that slot is a POINTER
  ## and the literal is a non-zero integer, the bare `(mov dest <imm>)` is exactly the
  ## shape nifasm's `checkPtrStore` rejects — it cannot tell it from a code generator's
  ## stale register binding. Spell the intent out with an explicit `(cast …)`, which
  ## opts out of that rule: `cast[pointer](-1)`, mmap's MAP_FAILED, is a deliberate
  ## non-zero pointer literal.
  if not isNilImm(loc) and loc.ival != 0 and not cursorIsNil(typeCur) and
      isPtrType(resolveType(g.prog, typeCur)):
    var tc = typeCur
    g.ab.tree MovA64:
      g.emReg dest
      g.ab.tree CastX: (g.genTypeBody(tc); g.ab.intLit loc.ival)
  else:
    g.placeImm(dest, loc)

proc bindStrideScratch*(g: var CodeGen; atPos: int; recycle: Reg) =
  ## Bind the stride scratch `reserveStrideScratch` reserved for the access at
  ## `atPos`, taking the staging bridge now if that is what it settled for.
  ##
  ## `recycle` is the index's own register when `strideRecycle` proved it reusable —
  ## the last resort when BOTH bridges already carry this same operand's reloaded
  ## base and index. Three spilled operands in one `(mem …)` is what a `-d:release`
  ## build reaches (shoggoth's inlining and CSE make expressions dense enough that
  ## nothing is left in the pools).
  ##
  ## A POOL REGISTER FIRST, a bridge only if there is none. This scratch has other
  ## answers; a reloaded base or a spilled compare operand does not. Taking the
  ## bridge first was free while three were reserved and one was always idle, and it
  ## stopped being free the moment the third was spent: the stride scratch would sit
  ## on a bridge for the whole `(mem …)`, and a `produceIntoMem2` inside the index
  ## then left an enclosed step with none. `pickStagingA64` judges by what is BOUND
  ## right now rather than by the whole-proc home union `reserveStrideScratch`
  ## consulted, so it routinely finds a register that walk could not — this is the
  ## same preference `emLvalGlobalBase`'s late-base cascade already states, for the
  ## same reason.
  if atPos in g.lvalStrideOnBridge:
    var r = g.pickStagingA64()
    if r != NoReg:
      g.pickedRegs.incl r
      g.bindTemp(r, ScalarSlot)
      g.lvalStrideOnBridge.excl atPos   # not a bridge: nothing for the release to drop
    else:
      r = g.tryTakeBridge()
    if r == NoReg:
      if recycle == NoReg:
        raiseAssert "arkham a64n: no stride scratch for the indexed access in proc " &
                    g.curProcName
      # nifasm ALLOWS `scratch == index`: it stages the stride constant in its own
      # reserved x16, so `scratch = idx*stride` reads the index in the very
      # instruction that overwrites it. Only `scratch == base` is rejected there
      # (that one would destroy the base before `add scratch, base, scratch`).
      r = recycle
      g.lvalStrideOnBridge.excl atPos   # no bridge of its own to release
    g.plan.aux[atPos] = ExprAux(scratch: @[r])
  else:
    g.bindTemp(g.plan.aux[atPos].scratch[0], ScalarSlot)

proc freeExpr*(g: var CodeGen; c: Cursor) =
  ## PHASE B release: give back whatever `getExpr` homed at `c`'s position, once the
  ## consuming `(mem …)`/`(lea …)` has read it. The counterpart of the planner's
  ## `freeSym`, and the asymmetry between the two is the phase difference itself.
  ##
  ## `freeSym` takes a NAME because a local may have been demoted out from under its
  ## register between acquire and release. Nothing can demote an expression home — it
  ## is minted and released inside one lvalue emission — so this one can be strict:
  ## look the position up and release exactly what is there. `restoreMemBase2` first,
  ## because a memory-homed base is on loan to a staging register at this point and the
  ## loan has to be unwound before the home is read back. A home that is not a temp
  ## (the common case: the value sat in its own register) releases nothing.
  let pos = g.posOf(c)
  g.restoreMemBase2(pos)                             # demoted (stolen) base/index reload
  let l = g.plan.planned(pos)
  if l.kind == InReg and l.isTemp: g.unbindTemp(l.r)

proc unbindLvalTemps2*(g: var CodeGen; c: Cursor) =
  ## Release scratch an lvalue's embedded value used (a reloaded base/index), AFTER
  ## the consuming `(mem …)`/`(lea …)` instruction.
  if c.kind == Symbol:
    let pos = g.posOf(c)
    if g.lvalGlobBase.hasKey(pos):
      if pos in g.lateBaseBorrowedAt:
        g.lateBaseBorrowedAt.excl pos     # the caller's register; the caller releases it
      else:
        g.dropBridge g.lvalGlobBase[pos]
      g.lvalGlobBase.del pos
    return
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = g.posOf(c)
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc); skip cc
        if cc.kind notin {IntLit, UIntLit}: g.freeExpr(cc)   # register index temp
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(atPos) and g.plan.aux[atPos].scratch.len > 0:
        g.unbindTemp(g.plan.aux[atPos].scratch[0])
    of DerefC:
      var cc = c
      cc.into:
        g.freeExpr(cc)                                       # the pointer
        while cc.hasMore: skip cc
    of PatC:
      let patPos = g.posOf(c)
      var cc = c
      cc.into:
        g.freeExpr(cc)                                       # the pointer
        skip cc
        if cc.kind notin {IntLit, UIntLit}: g.freeExpr(cc)   # register index temp
        while cc.hasMore: skip cc
      if g.plan.aux.hasKey(patPos) and g.plan.aux[patPos].scratch.len > 0:
        g.unbindTemp(g.plan.aux[patPos].scratch[0])
    of BaseobjC:                                          # transparent: release inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                                 # base type, depth
        g.unbindLvalTemps2(cc)
        while cc.hasMore: skip cc
    else: discard

proc bindLvalGlobalBases*(g: var CodeGen; c: Cursor; bound: var seq[Reg]) =
  ## Bind every UNBOUND global-base address register in lvalue `c` so `prematLval2` leas
  ## `&global` into a bound register (`emReg` rejects an unbound scratch). Skips an
  ## already-bound base reg (a caller — e.g. `emitAddr2` — may reuse its bound result reg).
  if c.kind == Symbol:
    let loc = g.plan.planned(g.posOf(c))
    if loc.kind == InReg and loc.isTemp and not g.rb.isBoundTemp(loc.r) and
       g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:
      g.bindTemp(loc.r, ScalarSlot)
      bound.add loc.r
  elif c.kind == TagLit and c.exprKind in {AtC, DotC, DerefC, PatC}:
    var cc = c
    cc.into:
      g.bindLvalGlobalBases(cc, bound); skip cc          # the base only
      while cc.hasMore: skip cc

proc ensureFAccum2*(g: var CodeGen; resF: FReg; loc: Location; bits: int) =
  ## Make `resF` hold the value just produced at `loc` (usually a no-op — the
  ## allocator dest-passed the operand into resF; otherwise move/load it in).
  case loc.kind
  of InFReg:
    if loc.f != resF:
      g.fmovF(resF, loc.f, bits)
      if loc.isTemp: g.unbindFTmp(loc.f)
  of NamedStack: g.emFloatScalarLoad(resF, loc.name, bits)
  else: raiseAssert "arkham a64n: float accumulator source " & $loc.kind

proc emitAtomicInstrRv(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                       argCurs: seq[Cursor]; res: Location) =
  ## RV32's atomics. `lr.w`/`sc.w` carry their own ordering in the `aq`/`rl` bits
  ## — which is what `AcqRelExclusives` names — so unlike the Cortex-M twin there
  ## is no `dmb` bracketing anything; the pair IS the ordering.
  ##
  ## A plain load and a plain store are the load/store cases, and each is a single
  ## machine access, which is the only property an atomic load or store of a
  ## naturally-aligned word has to have on this ISA.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword DmbA64                    # `fence rw,rw`
    return
  of AtomicSignalFenceOp:
    return                                 # a compiler barrier only; see the a64 twin
  else: discard
  let bits = g.atomicBits(argCurs[0])
  if bits != 32:
    lengError c, "a " & $bits & "-bit atomic has no RV32 lowering: the A " &
              "extension has `lr.w`/`sc.w` and no byte, halfword or doubleword " &
              "form at all. Widening a byte cell to the word it sits in would " &
              "make the access a read-modify-write of its three neighbours, " &
              "which is not the atom that was asked for", lengInfo(c)
  let p = g.instrOperandReg(argCurs[0])
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  case op
  of AtomicLoadOp:
    g.ab.tree MovA64:
      g.emReg res.r
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
  of AtomicStoreOp:
    g.ab.tree MovA64:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg g.instrOperandReg(argCurs[1])
  of AtomicExchangeOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), NopA64, true, false)
  of AtomicFetchAddOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, false)
  of AtomicFetchSubOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, false)
  of AtomicFetchAndOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), AndA64, false, false)
  of AtomicFetchOrOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), OrrA64, false, false)
  of AtomicFetchXorOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), EorA64, false, false)
  of AtomicAddFetchOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, true)
  of AtomicSubFetchOp:
    g.emitAtomicRmwRv(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, true)
  of AtomicCompareExchangeOp:
    g.emitAtomicCasRv(res.r, p, g.instrOperandReg(argCurs[1]),
                      g.instrOperandReg(argCurs[2]))
  else:
    lengError c, "`" & IntrinsicNames[op] & "` has no RV32 lowering — " &
              "guard the call with a `when`", lengInfo(c)
  # Release the operand temps' bindings, exactly as the other two arms do.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.plan.planned(g.posOf(argCurs[i]))
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

proc emitAtomicInstrM(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                      argCurs: seq[Cursor]; res: Location) =
  ## The Cortex-M twin of `emitAtomicInstr2`. Every variant is bracketed by `dmb`
  ## — the strongest ordering this profile can express, and the one every memory
  ## order the row carries is satisfied by.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword DmbM
    return
  of AtomicSignalFenceOp:
    # A compiler barrier only: it orders nothing in hardware, and what it forbids
    # — hoisting a memory access across it — arkham does not do to begin with.
    return
  else: discard
  for r in g.bridgeRegs: g.releaseStaleName(r)
  let bits = g.atomicBits(argCurs[0])
  if bits notin {8, 16, 32}:
    lengError c, "a " & $bits & "-bit atomic has no Cortex-M lowering: ARMv7-M " &
              "has no `ldrexd`/`strexd`, and two exclusive pairs over the halves " &
              "would be two claims rather than one atom", lengInfo(c)
  let p = g.instrOperandReg(argCurs[0])
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  g.ab.keyword DmbM
  case op
  of AtomicLoadOp: g.emAtomicLoadM(res.r, p, bits)
  of AtomicStoreOp: g.emAtomicStoreM(p, g.instrOperandReg(argCurs[1]), bits)
  of AtomicExchangeOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), NopA64, true, false, bits)
  of AtomicFetchAddOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, false, bits)
  of AtomicFetchSubOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, false, bits)
  of AtomicFetchAndOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), AndA64, false, false, bits)
  of AtomicFetchOrOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), OrrA64, false, false, bits)
  of AtomicFetchXorOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), EorA64, false, false, bits)
  of AtomicAddFetchOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, true, bits)
  of AtomicSubFetchOp:
    g.emitAtomicRmwM(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, true, bits)
  of AtomicCompareExchangeOp:
    g.emitAtomicCasM(res.r, p, g.instrOperandReg(argCurs[1]),
                     g.instrOperandReg(argCurs[2]), bits)
  else:
    # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
    # empty, so this is the message that column promises.
    lengError c, "`" & IntrinsicNames[op] & "` has no Cortex-M lowering — " &
              "guard the call with a `when`"
  g.ab.keyword DmbM
  # Release the operand temps' nifasm bindings — see the AArch64 twin.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.plan.planned(g.posOf(argCurs[i]))
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

proc emitAtomicInstr2*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                      argCurs: seq[Cursor]; res: Location) =
  ## An atomic row's AArch64 sequence, on operands the ALLOCATOR placed. Every
  ## variant is the strong acquire/release form, so the memory-order operands are
  ## not evaluated at all (see `evaluatedOperands`) — whatever order was asked for,
  ## this satisfies it.
  if g.md.atomicScratch[2] == NoReg:
    # No reserved triple, so there is no lowering to reach — and reaching one
    # anyway would emit another ISA's exclusives. Refused by NAME here rather than
    # discovered as a wrong mnemonic in an otherwise valid image.
    lengError c, "`" & IntrinsicNames[op] & "` has no " & g.md.targetName &
      " lowering — this target reserves no atomic scratch triple, so its " &
      "load-reserved/store-conditional loop cannot be built; guard the call " &
      "with a `when`"
  if g.md.arch == Rv32:
    g.emitAtomicInstrRv(c, op, argCurs, res)
    return
  if AcqRelExclusives notin g.md.caps:
    # A different instruction set, not a different width: ARMv7-M has `ldrex`/
    # `strex` and an explicit `dmb` where AArch64 has `ldaxr`/`stlxr`.
    g.emitAtomicInstrM(c, op, argCurs, res)
    return
  # A fence has no cell operand, and its memory order is not evaluated, so it must
  # be answered before anything reads `argCurs[0]`.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword DmbA64
    return
  of AtomicSignalFenceOp:
    # A compiler barrier only: it orders nothing in hardware, and what it forbids —
    # hoisting a memory access across it — arkham does not do to begin with.
    return
  else: discard
  for r in g.md.bridgeRegs: g.releaseStaleName(r)
  let bits = g.atomicBits(argCurs[0])
  let p = g.instrOperandReg(argCurs[0])
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  case op
  of AtomicLoadOp: g.emLdar(res.r, p, bits)
  of AtomicStoreOp: g.emStlr(g.instrOperandReg(argCurs[1]), p, bits)
  of AtomicExchangeOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "", true, false, bits)
  of AtomicFetchAddOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, false, bits)
  of AtomicFetchSubOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, false, bits)
  of AtomicFetchAndOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "and", false, false, bits)
  of AtomicFetchOrOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "orr", false, false, bits)
  of AtomicFetchXorOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "eor", false, false, bits)
  of AtomicAddFetchOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, true, bits)
  of AtomicSubFetchOp:
    g.emitAtomicRmw2(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, true, bits)
  of AtomicCompareExchangeOp:
    let lSucc = g.freshLabel()
    let lFail = g.freshLabel()
    let lDone = g.freshLabel()
    let pp = g.emOp p
    let ep = g.emOp g.instrOperandReg(argCurs[1])   # `expected`, a POINTER
    let d = g.emOp g.instrOperandReg(argCurs[2])
    let exp = g.emOp g.md.atomicScratch[0]
    let old = g.emOp g.md.atomicScratch[1]
    let st = g.emOp g.md.atomicScratch[2]
    let ret = g.emOp res.r
    let w = wsfx(bits)
    # Two FORWARD exits from the loop body: `(bne lFail)` when the cell no longer
    # holds `expected`, `(beq lSucc)` when the exclusive store succeeded. A non-zero
    # `st` (another agent won the line) falls through to the internal back-edge and
    # re-reads. The failure path MUST publish what was actually there — that is the
    # whole protocol: the caller retries against the value it now holds.
    g.ab.splice(
      &"(ldar {exp} {ep}{w}) (loop (stmts (ldaxr {old} {pp}{w}) " &
      &"(cmp {old} {exp}) (bne {lFail}) (stlxr {st} {d} {pp}{w}) " &
      &"(cmp {st} 0) (beq {lSucc}))) " &
      &"(lab :{lSucc}) (mov {ret} 1) (b {lDone}) " &
      &"(lab :{lFail}) (clrex) (stlr {old} {ep}{w}) (mov {ret} 0) (lab :{lDone})")
  else:
    # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
    # empty, so this is the message that column promises.
    lengError c, "`" & IntrinsicNames[op] & "` has no AArch64 lowering — " &
              "guard the call with a `when`"
  # Release the operand temps' nifasm bindings. Ordinarily a volatile temp's binding
  # dies when the register is rebound for the next value, but an operand that had to
  # be escalated to a CALLEE-SAVED register (`reserveInstrReg`) may see no such rebind
  # before the epilogue's `ldp` — which nifasm rejects while the register is still
  # bound to a name.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.plan.planned(g.posOf(argCurs[i]))
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

proc emLvalFieldMem*(g: var CodeGen; lhs: Cursor; field: string) =
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.emLvalAddr2(lhs)
      g.ab.sym field

proc emLvalElemMem*(g: var CodeGen; lhs: Cursor; idx: int) =
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.emLvalAddr2(lhs)
      g.ab.intLit idx

proc emLvalElemAt*(g: var CodeGen; lhs: Cursor; idx: int) =
  ## Bare `(at <lvalue address> idx)` address tree — for `lea` of an lvalue element.
  g.ab.tree AtX:
    g.emLvalAddr2(lhs)
    g.ab.intLit idx

proc emFieldOperand*(g: var CodeGen; dst: Location) =
  ## The `(mem (dot <base> field))` operand for a `Field` destination, dispatching on
  ## how its base aggregate is addressed (a pointer reg / a named stack slot / an
  ## lvalue subtree). nifasm sizes the access from the field's declared type.
  case dst.base.kind
  of FbReg:  g.emPtrFieldMem(dst.base.reg, dst.aggrType, dst.field)
  of FbSlot: g.emAggrFieldMem(dst.base.sym, dst.field)
  of FbLval: g.emLvalFieldMem(dst.base.lval, dst.field)
  of FbGlob, FbTvar:
    raiseAssert "arkham a64n: FbGlob/FbTvar field base must be pre-materialized"

proc emFieldDot(g: var CodeGen; dst: Location) =
  ## The bare `(dot <base> field)` ADDRESS tree (no `(mem …)` wrapper) — what a64's
  ## `lea` takes (unlike x86, which leas a memory operand).
  case dst.base.kind
  of FbReg:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(dst.aggrType)
        g.emReg dst.base.reg
      g.ab.sym dst.field
  of FbSlot:
    g.emAggrDot(dst.base.sym, dst.field)
  of FbLval:
    g.ab.tree DotX:
      g.emLvalAddr2(dst.base.lval)
      g.ab.sym dst.field
  of FbGlob, FbTvar:
    raiseAssert "arkham a64n: FbGlob/FbTvar field base must be pre-materialized"

proc emFieldAddr*(g: var CodeGen; dst: Location; into: Reg) =
  ## `&(base.field)` → `into`: `lea` over the field's address tree.
  g.ab.tree LeaA64: (g.emReg into; g.emFieldDot(dst))

proc getExpr*(g: var CodeGen; n: var Cursor; held: bool; what: string) =
  ## PHASE B acquire: home the lvalue-embedded value at `n` and plan it there,
  ## advancing `n` past it. The twin of the planner's `getSym`, and the difference is
  ## the KEY: a declaration has a name, an expression has only a POSITION. Everything
  ## else follows from that — no `symPos` alias, and no undo, because phase A is over
  ## and every local home this reads is already final.
  ##
  ## `held` = an enclosing index CALLS, so the scratch must be a callee-saved survivor
  ## rather than a volatile that call would clobber; `what` names it for the
  ## out-of-registers message.
  ##
  ## This lives in the backend rather than in `planer` only because the phase-B pool
  ## (`takeHeld`) still does. It is a relocation away, not a redesign: the door already
  ## speaks positions, and `emitLvalWalk` — which calls it — is already a pure
  ## pick-and-record pass with no emission in it.
  let pos = g.posOf(n)
  var d = if held: g.takeHeld(what) else: needsReg(ScalarSlot)
  g.resolveLvalVal(n, d)
  g.plan.planAtEmitTime(pos, d)
  skip n

proc emitLvalWalk*(g: var CodeGen; n: var Cursor; globBase: Location; isStore: bool;
                  heldBase = false; asBase = false) =
  ## FUSED port of the allocator's `allocLvalue2` (a64 flavour): decide the
  ## lvalue's embedded values' locations into the `plan.locs` memo, reserving the
  ## a64 stride scratch (the `(at base idx scratch)` 3-operand form) into
  ## `plan.aux` where `atNeedsScratch`/nested-base rules demand one. Pure
  ## pick-and-record. `heldBase`: an enclosing at/pat index CALLS — base
  ## scratches must be callee-saved survivors (075b051). `asBase`: this node is
  ## the BASE of an enclosing indexed access (one index register per operand).
  case n.kind
  of Symbol:
    let nm = symName(n)
    if g.plan.locationOfSym(nm, cursorToPosition(g.buf[], n)).kind == NoLoc:         # a module-level global aggregate base
      let pos = g.posOf(n)
      if globBase.kind == InReg:
        # The caller donated its result register; it owns (and frees) that pick —
        # record it non-temp so freeLvalTemps2 won't unbind the live result.
        g.plan.planAtEmitTime(pos, regLoc(globBase.r, globBase.typ))
      else:
        # a64 always materializes &global into an allocator-visible register
        # (no x64-style staging marker): a survivor under a calling index or
        # for a store held across the rhs, else an ordinary temp.
        if isStore or heldBase:
          # A survivor if one is going spare; otherwise record NOTHING and let
          # `prematLval2` derive `&g` into a bridge after the index (`lateGlobalBase`).
          # This step used to assert here, and it is the one place the assert was
          # avoidable rather than a real shortage: the address has no inputs, so
          # holding it across the call was a choice, not a requirement.
          let h = g.tryTakeHeld()
          if h.kind == InReg:
            g.plan.planAtEmitTime(pos, h)
        else:
          var d = g.takeTmp(ScalarSlot)
          if d.kind != InReg:
            d = g.tryTakeHeld()                 # pool dry: survivor beats a bridge
          if d.kind == InReg:
            g.plan.planAtEmitTime(pos, d)       # else: nothing recorded ⇒ late-derive
    inc n
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        g.emitLvalWalk(n, globBase, isStore, heldBase, asBase)  # offset-transparent base
        while n.hasMore: skip n
    of DerefC:
      n.into:
        g.getExpr(n, heldBase, "a deref base held across an index call")
        while n.hasMore: skip n
    of AtC:
      let atPos = g.posOf(n)
      let needsScratch = g.atNeedsScratch(n) or (asBase and g.atIndexIsReg(n))
      n.into:
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCall(idxPeek)
        g.emitLvalWalk(n, globBase, isStore, held, asBase = true)  # the indexed base
        if n.kind in {IntLit, UIntLit}: skip n
        else: g.getExpr(n, false, "")
        while n.hasMore: skip n
      if needsScratch:
        g.reserveStrideScratch(atPos)
    of PatC:
      let patPos = g.posOf(n)
      let needsScratch = g.atNeedsScratch(n) or (asBase and g.atIndexIsReg(n))
      n.into:
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCall(idxPeek)
        g.getExpr(n, held, "a pat base held across an index call")   # a clean value base
        if n.kind in {IntLit, UIntLit}: skip n
        else: g.getExpr(n, false, "")
        while n.hasMore: skip n
      if needsScratch:
        g.reserveStrideScratch(patPos)
    of BaseobjC:
      n.into:
        skip n                                       # base type
        skip n                                       # depth
        g.emitLvalWalk(n, globBase, isStore, heldBase, asBase)
        while n.hasMore: skip n
    of AconstrC, OconstrC:
      # A constructor base: `prematLval2`'s consumer builds it into its aggtmp
      # via the (fused) genStore2 — nothing to decide here.
      skip n
    else:
      raiseAssert "arkham a64n: computed lvalue base not supported: " & $n.exprKind
  else:
    inc n

proc emitLvalue2*(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false) =
  g.bridgeStep("`emitLvalue2`")                         # I1 + I2
  var n = c
  g.emitLvalWalk(n, globBase, isStore)

proc retypeBinDest*(g: var CodeGen; rD: Reg; resTypeC: Cursor;
                   inheritedOperand: bool) =
  ## Give `rD`'s nifasm binding the type of the arithmetic result about to land in
  ## it. The register is a named local's home (or a bound temp) whose declared type
  ## may be a pointer while the value being computed into it is an integer — the
  ## `(var :c.0 (ptr T) (cast (ptr T) (bitand (i 64) …)))` shape, where an enclosing
  ## cast puts the pointer type back on. The `rebind` is zero machine code: the
  ## register never moves, only its declared type does.
  ##
  ## A POINTER result type is not handled here — `checkArithResultType` has already
  ## rejected the node. Retyping the binding to `(i 64)` and back around the
  ## instruction would make an ill-typed `(add (ptr T) …)` assemble by hiding it from
  ## nifasm's `checkIntegerArithmetic`, under a raw-byte reading of `+` that the C
  ## backend does not share.
  if not isPtrType(resolveType(g.prog, resTypeC)):
    let nm = g.rb.boundName(rD)
    if g.rb.isBoundTemp(rD):
      if inheritedOperand:                               # inherited an operand's binding
        var rtc = resTypeC
        g.bindTemp(rD, slotOf(g.prog, rtc))
    elif nm.len > 0:
      g.rebindLocalAs(nm, rD, resTypeC)

proc reReprCast2*(g: var CodeGen; res: var Location; inner, targetCur, tc: Cursor;
                 isCast: bool; preRetyped: string) =
  ## Convert the INNER value now held in register `res.r` into the cast's TARGET
  ## representation, in place: the pointer-kind rebind, the `extendTo` shift pair
  ## that IS the widening/narrowing, and the binding retype that records the new
  ## type on the name.
  ##
  ## Split out of `emitCast2` so the SPILLED result path can run it too, staged
  ## through the produce bridge. That path used to `return` with the conversion
  ## never emitted — a silent miscompile, since the extend is the whole cast:
  ## `cast[uint32](zi)` in `formatfloat.toDecimal64` kept all 64 bits whenever the
  ## register pools happened to be dry at that expression.
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  let kindChange = ptrTarget or srcPtr
  if kindChange:
    if res.isTemp:
      g.bindTemp(res.r, (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot))
    elif g.rb.isBoundTemp(res.r):
      # The register is not a pool temp (a call dest-threads its argument straight
      # into the ABI register), yet the value in it was bound as a SCRATCH `tmpN.0`.
      # `rebindLocalAs` would drop the temp bit, and the `unbindTemp` the call path
      # runs next then finds no scratch to kill: the name stays bound to that argument
      # register for the rest of the proc, so the NEXT call still spells it — and
      # `(mov <name typed (ptr void)> 7)` is a nifasm error (`rStr`, whose `min(x, 7)`
      # follows a `copyMem(…: pointer, …)`). Retype it as the temp it is.
      g.rebindTempAs(res.r, targetCur)
    else:
      let nm = g.rb.boundName(res.r)
      if nm.len > 0: g.rebindLocalAs(nm, res.r, targetCur)
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if kindChange:
    if ptrTarget and not srcPtr and srcW < 64 and
       not g.arrivesNormalized(inner, srcW, signed = false):
      g.extendTo(res.r, srcW, signed = false)
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW:
      let sgn = (not isCast) and srcSigned
      if not g.arrivesNormalized(inner, srcW, sgn):
        g.extendTo(res.r, srcW, sgn)                                 # widen
    else:
      let sgn = isSignedType(tc)
      if not g.arrivesNormalized(inner, targetW, sgn):
        g.extendTo(res.r, targetW, sgn)                              # narrow / equal
  # The register now holds the TARGET's value, so put the target type back on the
  # name the pre-retype above widened. `kindChange` already did it.
  if not kindChange:
    if preRetyped.len > 0:
      g.rebindLocalAs(preRetyped, res.r, targetCur)
    elif res.isTemp:
      if g.rb.isBoundTemp(res.r): g.rebindTempAs(res.r, targetCur)
      else: g.bindTemp(res.r, slotOf(g.prog, targetCur))
      res.typ = slotOf(g.prog, targetCur)

proc takeWideRegs*(g: var CodeGen; n: int; what: string): seq[Reg] =
  ## `n` scratch GPRs for a wide lowering. The two staging bridges first (they
  ## are withheld from the allocator's pools, so they are the cheap ones), then
  ## callee-saved survivors — which `takeHeld` fails loudly on rather than
  ## handing out a register something else is holding.
  ## A wide lowering juggles PAIRS — the low and high halves of one 64-bit value
  ## live at once, by definition, on a target whose word is four bytes — so it
  ## raises the enclosing step's declaration to two the way `prematLval2` does:
  ## the demand is discovered here, the registers are released by the CALLER, and
  ## the scope that has to cover them is therefore the caller's.
  ##
  ## But it never takes the LAST bridge. `n` reaches four here (a 64-bit multiply,
  ## a 64-bit shift) and this proc has an alternative that no bridge-taker in the
  ## `(mem …)` or `cmp` paths has: a callee-saved survivor, or failing that a
  ## `heldN.0` slot. Spending the reservation down to nothing on a step that could
  ## have used something else is what leaves a nested step — a spilled compare
  ## operand, a reloaded memory base — with no answer at all. Same preference
  ## `bindStrideScratch` and `emLvalGlobalBase` state, and the reason this one was
  ## worth finding: it only shows up on the 64-bit-on-32-bit corpus, which is the
  ## `cortex-m 64` pass that needs `qemu-system-arm` to run.
  g.bridgeRaise(bdTwoInRegs, "a 64-bit lowering juggling register pairs")
  # The cascade is PREFERENCE, not restriction: declining the last bridge must
  # never turn into a failure. Bridge while one is still left, then a survivor,
  # then the last bridge after all, and only then the loud `takeHeld`. Written the
  # short way — decline, then `takeHeld` — it traded a budget overrun for a hard
  # out-of-registers in `setit.0` of `at_scratch_deref_base`, which is worse.
  result = @[]
  for _ in 0 ..< n:
    var r = NoReg
    if g.liveBridges() + 1 < g.distinctBridges():
      r = g.tryTakeBridge(ScalarSlot)
    if r == NoReg:
      let h = g.tryTakeHeld()
      if h.kind == InReg:
        r = h.r
        g.bindTemp(r, ScalarSlot)
    if r == NoReg:
      # The last one, after a pool register and a survivor both came up empty.
      r = g.tryTakeBridge(ScalarSlot, lastResort = true)
    if r == NoReg:
      r = g.takeHeld(what).r              # fails loudly, as it always did
      g.bindTemp(r, ScalarSlot)
    result.add r

proc wideArgToRegs*(g: var CodeGen; slotName: string; firstArg: int) =
  ## A 64-bit call argument into `intArgRegs[firstArg]` and `[firstArg+1]`.
  ##
  ## Takes the SLOT the value was already produced into, not the expression:
  ## producing it here would be inside the `(prepare …)` block, where any
  ## instruction that clobbers r0–r3 destroys the arguments already staged there
  ## — and a 64-bit `div` is a `bl` to the module's divider. See `wideArgSlots`.
  let src = slotWide(slotName)
  g.wideLoad(g.md.intArgRegs[firstArg], src, 0)
  g.wideLoad(g.md.intArgRegs[firstArg + 1], src, 1)

proc wideArgTruncated*(g: var CodeGen; slotName: string; dest: Reg) =
  ## A 64-bit argument passed to a NARROWER declared parameter: the low word,
  ## which is the truncation C performs and Leng's front end relies on
  ## (`exit(x + y)` where `x`/`y` are `int64` and `exit` takes a `cint`).
  ##
  ## Spelled out at the call site because the ABI follows the CALLEE's
  ## declaration — see `calleeParamSlots`. Left to the general value path it
  ## would be a 64-bit value handed a 32-bit register, which has no right answer.
  g.wideLoad(dest, slotWide(slotName), 0)
