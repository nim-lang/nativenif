#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Aggregates, and the byte loops that move them.
##
## Struct <-> register marshalling for the SysV ABI (a small aggregate travels in
## up to two registers, a large one by reference), whole-struct copies, the
## inline `mem*` intrinsics — arkham emits its own loops rather than calling
## libc, because there is no libc — and the lock-prefixed atomic sequences.

import std / [assertions, sets]
import nifcore
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, 
                    mirrors, regbind]
import machine as machine_x64
import emit, mem

proc genMemIntrinBody*(g: var CodeGen; builtin: string) =
  ## The inline `mem*` loop, assuming the args are already loaded (dst→rdi,
  ## src/val→rsi, n→rdx) and rsi/rdx/rcx are bound to checked names. Result → RAX.
  ## Shared by the legacy `genMemIntrin` (reactive `genInto` arg-load) and the
  ## value-core `emitMemIntrin2` (args placed by `emitValue2` into the ABI regs).
  ## The dest pointer (rdi) and the byte/result (rax) stay raw — irreducible ABI regs.
  case builtin
  of "memcpy":                                 # (dst, src, n) → dst
    # `rep movs` has a steep per-invocation startup (microcode assist, and two
    # `rep`s even when n < 8). The bif writer does tens of thousands of 1–7 byte
    # copies (varints, `endStore`'s 7-byte prefix); sending those through `rep`
    # is why bif sat ~3× behind gcc. Split:
    #   n < 64  → qword loop + byte tail (same shape as memset; no overrun)
    #   n ≥ 64  → `rep movsq` + `rep movsb` (the 1.4 MB token block, etc.)
    # A compile-time n ≤ 64 is unrolled in `emitMemIntrin2` and never reaches here.
    let qwordDone = g.freshLabel()
    let byteLoop = g.freshLabel()
    let smallDone = g.freshLabel()
    let large = g.freshLabel()
    let done = g.freshLabel()
    g.ab.tree CmpX64: (g.emReg RDX; g.ab.intLit 64)
    g.emJcc(JaeX64, large)
    g.bindTemp(R8, ScalarSlot)
    g.movImm(RCX, 0)
    g.ab.tree CmpX64: (g.emReg RDX; g.ab.intLit 8)
    g.emJcc(JbX64, byteLoop)                   # n < 8: skip qword setup (varints, prefix)
    g.movReg(R8, RDX)
    g.binImm(ShrX64, R8, 3)                    # quadwords = n div 8
    g.emitLoop:
      g.emCmpReg(RCX, R8)
      g.emJcc(JaeX64, qwordDone)
      g.emLoadQwordAt(RAX, RSI, RCX)
      g.emStoreQword(RDI, RCX, RAX)
      g.binImm(AddX64, RCX, 1)
    g.emLab(qwordDone)
    g.binImm(ShlX64, RCX, 3)                   # i = n and not 7, now counting BYTES
    g.emLab(byteLoop)
    g.emitLoop:
      g.emCmpReg(RCX, RDX)
      g.emJcc(JaeX64, smallDone)
      g.emLoadByte(RAX, RSI, RCX)
      g.emStoreByte(RDI, RCX, RAX)
      g.binImm(AddX64, RCX, 1)
    g.emLab(smallDone)
    g.movReg(RAX, RDI)
    g.unbindTemp(R8)
    g.emJmp(done)
    g.emLab(large)
    g.movReg(RAX, RDI)                         # the return value, BEFORE `movs` eats rdi
    g.genRepMovsFwd(RDX)
    g.emLab(done)
  of "memmove":                                # (dst, src, n) → dst; overlap-safe
    # An ascending copy is safe unless the destination starts strictly INSIDE the
    # source block — i.e. it is safe when `dst <= src` (the classic case) and also
    # when `dst >= src + n` (disjoint; very common, e.g. shifting a block UP in a
    # seq). Only a genuinely overlapping `src < dst < src+n` needs the descending
    # copy, and that one keeps the byte loop: `rep movs` would run downward only
    # with DF=1, and arkham deliberately never emits `std` (SysV requires DF clear
    # at entry and at every call boundary, so setting it would have to be undone on
    # every path out — including the ones an exit or a trap takes).
    g.bindTemp(R8, ScalarSlot)
    g.movReg(R8, RDI)                          # saved dest: `rep movs` destroys rdi
    let fwd = g.freshLabel()
    let done = g.freshLabel()
    g.emCmpReg(RDI, RSI)
    g.emJcc(JbeX64, fwd)                       # dst <= src → ascending is safe
    g.movReg(RAX, RSI)
    g.binReg(AddX64, RAX, RDX)                 # rax = src + n
    g.emCmpReg(RDI, RAX)
    g.emJcc(JaeX64, fwd)                       # dst >= src+n → disjoint, ascending is safe
    # backward: i = n; while i != 0: i -= 1; dst[i] = src[i]
    g.movReg(RCX, RDX)                         # i = n
    g.emitLoop:
      g.cmpZero RCX
      g.emJcc(JeX64, done)
      g.binImm(SubX64, RCX, 1)
      g.emLoadByte(RAX, RSI, RCX)
      g.emStoreByte(RDI, RCX, RAX)
    g.emLab(fwd)
    g.genRepMovsFwd(RDX)
    g.emLab(done)
    g.movReg(RAX, R8)                          # memmove returns dest
    g.unbindTemp(R8)
  of "memset":                                 # (dst, val, n) → dst
    # Quadword bulk + byte tail, mirroring `genRepMovsFwd`'s split: eight bytes per
    # iteration instead of one. The byte loop this replaces cost ~1.7 cycles per byte,
    # which showed up as a ~50x gap against gcc's vectorized `memset` — and `zeroMem`
    # sits behind every zeroed allocation in the runtime.
    #
    # `rep stosq` would be shorter still, but nifasm has no `stos` instruction (only
    # `Repmovsb/w/d/q`), and its per-`rep` startup cost is poor at the small sizes
    # (tens of bytes) the runtime actually memsets.
    let tail = g.freshLabel()
    let done = g.freshLabel()
    g.bindTemp(R8, ScalarSlot)                 # the broadcast scratch, then the qword count
    g.emBroadcastByte(RAX, RSI, R8)            # rax = val's low byte in all 8 lanes
    g.movReg(R8, RDX)
    g.binImm(ShrX64, R8, 3)                    # quadwords = n div 8
    g.movImm(RCX, 0)                           # i = 0, counting QUADWORDS
    g.emitLoop:
      g.emCmpReg(RCX, R8)
      g.emJcc(JaeX64, tail)
      g.emStoreQword(RDI, RCX, RAX)            # dst64[i] = the broadcast value
      g.binImm(AddX64, RCX, 1)
    g.emLab(tail)
    # The loop leaves i == n div 8, so `i*8` is where the ≤7-byte tail starts.
    g.binImm(ShlX64, RCX, 3)                   # i = n and not 7, now counting BYTES
    g.emitLoop:
      g.emCmpReg(RCX, RDX)
      g.emJcc(JaeX64, done)
      g.emStoreByte(RDI, RCX, RSI)             # dst[i] = low byte of val
      g.binImm(AddX64, RCX, 1)
    g.emLab(done)
    g.movReg(RAX, RDI)
    g.unbindTemp(R8)
  of "memcmp":                                 # (a, b, n) → first byte difference
    g.bindTemp(R8, ScalarSlot)                 # the second byte/quadword (held across the loop)
    let byteLoop = g.freshLabel()
    let diff = g.freshLabel()
    let equal = g.freshLabel()
    let done = g.freshLabel()
    # Bulk: compare EIGHT bytes per iteration. A quadword mismatch does not say which
    # byte differs, so it just falls into the byte loop below WITHOUT advancing the
    # pointers — that loop then rescans those same eight bytes and finds the first one.
    # A mismatch happens at most once, so the rescan is paid once per call; the common
    # case in this compiler is `cmpMem` on EQUAL strings, which scans to the end.
    # Both pointers and the remaining count advance in place; memcmp returns a value,
    # so nothing downstream needs rdi/rsi/rdx afterwards (see `memcpy`, which likewise
    # lets `rep movs` eat rdi).
    g.emitLoop:
      g.ab.tree CmpX64: (g.emReg RDX; g.ab.intLit 8)
      g.emJcc(JbX64, byteLoop)                 # fewer than 8 left → tail
      g.emLoadQword(RAX, RDI)
      g.emLoadQword(R8, RSI)
      g.emCmpReg(RAX, R8)
      g.emJcc(JneX64, byteLoop)                # differs somewhere in these 8
      g.binImm(AddX64, RDI, 8)
      g.binImm(AddX64, RSI, 8)
      g.binImm(SubX64, RDX, 8)
    g.emLab(byteLoop)
    g.movImm(RCX, 0)                           # i = 0
    g.emitLoop:
      g.emCmpReg(RCX, RDX)
      g.emJcc(JaeX64, equal)                   # ran off the end, no diff → 0
      g.emLoadByte(RAX, RDI, RCX)              # ba = a[i] (zero-extended, 0..255)
      g.emLoadByte(R8, RSI, RCX)               # bb = b[i]
      g.emCmpReg(RAX, R8)
      g.emJcc(JneX64, diff)
      g.binImm(AddX64, RCX, 1)
    g.emLab(diff)                              # bytes are 0..255 → signed sub gives sign
    g.binReg(SubX64, RAX, R8)                  # rax = ba - bb
    g.emJmp(done)
    g.emLab(equal)
    g.movImm(RAX, 0)
    g.emLab(done)
    g.unbindTemp(R8)
  else:
    raiseAssert "arkham x64 v0: unsupported mem intrinsic: " & builtin
  g.unbindTemp(RCX); g.unbindTemp(RDX); g.unbindTemp(RSI)

proc transferAggrWords(g: var CodeGen; varName: string; typeSym: SymId;
                       regs: openArray[Reg]; toRegs: bool) =
  ## Move an aggregate between memory and the GPRs that carry it, one register per
  ## 8-byte ABI eightbyte (the by-value aggregate ABI). `toRegs` picks the direction
  ## — `regs[i] ← word i` (load) or `word i ← regs[i]` (store).
  ##
  ## EVERY eightbyte (full OR a trailing partial one) is moved as a RAW `(u 64)` word:
  ## the slot's address goes into the R11 staging bridge (a by-ref aggregate already has
  ## its pointer in a reg) and `emWordThroughPtr` reads/writes the whole 8 bytes. A raw
  ## word is what makes fields PACKED into one eightbyte (e.g. `{int32; int32}` or a
  ## partial `{int16; int16}`) all transfer — a field-TYPED per-field move would carry
  ## only the field at the eightbyte boundary and silently drop the rest. It also
  ## subsumes the old pointer-field `(cast (ptr T) reg)` dance.
  ##
  ## Reading/writing the WHOLE 8 bytes of a trailing partial eightbyte is sound because
  ## the aggregate's storage is always rounded up to a multiple of 8 (`alignedSize`): the
  ## bytes past the partial are this slot's own padding (the register side's extra high
  ## bytes are dead — only the aggregate's real bytes are ever consumed).
  let loc = g.plan.homeOfSym(varName)
  if loc.kind == InRegPair:
    # The aggregate IS the word registers — no memory round-trip.
    for i in 0 ..< aggrWordCount(g.prog, typeSym):
      let w = pairWord(loc, i)
      if toRegs:
        if regs[i] != w: g.movReg(regs[i], w)
      else:
        if w != regs[i]: g.movReg(w, regs[i])
    return
  var baseReg = NoReg
  var addrTmp = NoReg
  # A NAMED STACK SLOT needs no address at all: `(mem (rsp) name off)` folds the
  # offset into the slot's own rsp displacement. Materializing `&slot` into the R11
  # bridge first cost a `lea` per transfer AND held a register across it — and it
  # cost the READER too, since `(at (cast (aptr (u 64)) tmp) k)` and `(mem (rsp)
  # name off)` are two spellings of one address that no later pass can equate.
  # nifasm bounds-checks the slot-relative form against the slot; it cannot check
  # the pointer form at all.
  #
  # A SPILLED BY-REF POINTER (`StackPtr`) has a slot too, but it holds `&aggregate`,
  # not the aggregate — reading it slot-directly would transfer the pointer's own
  # bytes as if they were the struct. It takes the pointer path below.
  let slotDirect = loc.kind == NamedStack
  if loc.kind == InReg:
    baseReg = loc.r                                    # a by-ref aggregate's pointer
  elif not slotDirect:
    addrTmp = g.pickStaging("an aggregate reg<->slot address")  # R11 bridge ← &slot
    g.bindTemp(addrTmp, AddrSlot)                       # typed+tracked (giveBack unbinds)
    if loc.kind == StackPtr:
      g.ab.tree MovX64: (g.emReg addrTmp; g.emStackMem(loc.ptrName))  # LOAD the pointer
    else:
      # A module-level global / `const` / tvar: its address is RIP-relative or FS+off,
      # NEVER rsp-relative, so it has to go through a register.
      g.emSymAddrByName(addrTmp, varName)
    baseReg = addrTmp
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    g.ab.tree MovX64:
      if toRegs:
        g.emReg regs[i]
        if slotDirect: g.emWordAtSlot(varName, i * 8) else: g.emWordThroughPtr(baseReg, i)
      else:
        if slotDirect: g.emWordAtSlot(varName, i * 8) else: g.emWordThroughPtr(baseReg, i)
        g.emReg regs[i]
  if addrTmp != NoReg: g.giveBack addrTmp

proc structToRegs*(g: var CodeGen; varName: string; typeSym: SymId; regs: openArray[Reg]) =
  ## aggregate → regs[i] (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeSym, regs, toRegs = true)

proc regsToStruct*(g: var CodeGen; varName: string; typeSym: SymId; regs: openArray[Reg]) =
  ## regs[i] → aggregate (one GPR per 8-byte word).
  g.transferAggrWords(varName, typeSym, regs, toRegs = false)

proc genAtomicXadd(g: var CodeGen; dst, pReg, work: Reg; val: Location;
                   pointee: Cursor; returnNew, sub: bool) =
  ## `lock xadd [p], work` with `work` seeded from `val` — the exchange leaves the
  ## OLD value in `work`. For `sub` the addend is negated first, so memory is
  ## decremented; `returnNew` then recomputes `old ± delta`, for which `val` is still
  ## available (the sequence writes only `work` and `dst`).
  g.seedWork(work, val)
  if sub:
    g.ab.tree NegX64: g.emReg work            # work ← -delta
  g.ab.tree LockX64:
    g.ab.tree XaddX64:
      g.emMemAt(pReg, pointee)
      g.emReg work                             # work ← old; [p] += work
  if returnNew:
    g.workOp(if sub: SubX64 else: AddX64, work, val)   # new = old ± delta
  g.movReg(dst, work)

proc emitAtomicInstr2*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                      argCurs: seq[Cursor]; res: Location) =
  ## An atomic row's x86-64 sequence, on operands the ALLOCATOR placed (see the
  ## section header above for the register discipline). `res` is the row's result
  ## home, and is `Undef` for the rows that produce no value.
  # A fence has no cell operand at all — and its memory order is not evaluated —
  # so it must be answered before anything reads `argCurs[0]`.
  case op
  of AtomicThreadFenceOp:
    g.ab.keyword MfenceX64
    return
  of AtomicSignalFenceOp:
    # A compiler barrier only: it orders nothing in hardware, and what it forbids
    # — hoisting a memory access across it — arkham does not do to begin with.
    return
  else: discard
  # The registers THIS row claims are about to be raw scratch. A dead local can still
  # be sitting in `regLocal` under its typed name, which `emReg` would emit instead of
  # the raw tag — a type mismatch against the pointee-typed `(mem …)` operand. Only
  # the claimed ones: a register the row does not touch may legitimately be hosting
  # one of its own operands, and killing that binding is the corruption this guards
  # against.
  for r in atomicRegClaims(op): g.releaseStaleName(r)
  let pointee = g.atomicPointee(argCurs[0])
  let p = g.instrOperandReg(argCurs[0])
  # The VALUE operand of every row but the compare-exchange (whose operand 1 is the
  # `expected` POINTER). It may be a folded immediate — see `atomicValueMayBeImm`.
  let val = if op in {AtomicLoadOp, AtomicCompareExchangeOp}: default(Location)
            else: g.plan.planned(cursorToPosition(g.buf[], argCurs[1]))
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  # The working register, for the forms that need one — a load reads straight into
  # its destination and a compare-exchange works out of `rax`, so those two take no
  # `r11` and get no binding for it. Bound to the CELL's type, not a generic scalar:
  # nifasm type-checks `xchg`/`cmpxchg` against their memory operand, and the cell may
  # well be a pointer (a lock-free list head is the common case) — an `(i 64)` binding
  # is rejected against a `(ptr (ptr T))` access.
  let needsWork = R11 in atomicRegClaims(op)
  if needsWork: g.bindTemp(R11, slotOf(g.prog, pointee))
  block:
    case op
    of AtomicLoadOp:
      # An aligned `mov` IS the atomic load here; the strong memory model does the
      # acquire for us.
      g.ab.tree MovX64: (g.emReg res.r; g.emMemAt(p, pointee))
    of AtomicStoreOp:
      # `xchg` with a memory operand carries an implicit LOCK, which is what makes
      # the store sequentially consistent; a plain `mov` would need a trailing
      # `mfence` to match, for the same cost.
      g.seedWork(R11, val)
      g.ab.tree XchgX64: (g.emMemAt(p, pointee); g.emReg R11)
    of AtomicExchangeOp:
      g.seedWork(R11, val)
      g.ab.tree XchgX64: (g.emMemAt(p, pointee); g.emReg R11)   # r11 ↔ [p]; r11 ← old
      g.movReg(res.r, R11)
    of AtomicFetchAddOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = false, sub = false)
    of AtomicFetchSubOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = false, sub = true)
    of AtomicAddFetchOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = true, sub = false)
    of AtomicSubFetchOp:
      g.genAtomicXadd(res.r, p, R11, val, pointee, returnNew = true, sub = true)
    of AtomicFetchAndOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, AndX64)
    of AtomicFetchOrOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, OrX64)
    of AtomicFetchXorOp:
      g.genAtomicLoopRmw(res.r, p, R11, val, pointee, XorX64)
    of AtomicCompareExchangeOp:
      let ep = g.instrOperandReg(argCurs[1])          # `expected`, a POINTER
      let des = g.instrOperandReg(argCurs[2])
      g.ab.tree MovX64: (g.emReg RAX; g.emMemAt(ep, pointee))    # rax = *expected
      g.ab.tree LockX64:
        g.ab.tree CmpxchgX64:
          g.emMemAt(p, pointee)
          g.emReg des                    # if [p]==rax: [p]=des,ZF=1 else rax=[p]
      let lFail = g.freshLabel()
      let lDone = g.freshLabel()
      g.emJcc(JneX64, lFail)
      g.movImm(res.r, 1)                                         # success
      g.emJmp(lDone)
      g.emLab(lFail)
      # The failure path MUST publish what was actually there: that is the whole
      # protocol — the caller retries against the value it now holds.
      g.ab.tree MovX64: (g.emMemAt(ep, pointee); g.emReg RAX)
      g.movImm(res.r, 0)
      g.emLab(lDone)
    else:
      # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
      # empty, so this is the message that column promises.
      lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 lowering — " &
                "guard the call with a `when`"
  if needsWork: g.unbindTemp(R11)
  # Release the operand temps' nifasm bindings. Ordinarily a volatile temp's binding
  # dies when the register is rebound for the next value, but an operand that had to
  # be escalated to a CALLEE-SAVED register (`reserveInstrReg`) may see no such rebind
  # before the epilogue's `pop` — which nifasm rejects while the register is still
  # bound to a name.
  for i in 0 ..< min(IntrinsicRows[op].evaluatedOperands, argCurs.len):
    let a = g.plan.planned(cursorToPosition(g.buf[], argCurs[i]))
    if a.kind == InReg and a.isTemp and not (res.kind == InReg and a.r == res.r):
      g.unbindTemp(a.r)

proc genAggrCopy2*(g: var CodeGen; dstVar, srcVar: string; typeSym: SymId; tmp: Reg) =
  ## Whole-aggregate copy `dstVar ← srcVar`, one FIELD at a time through the allocator-
  ## provided scratch GPR `tmp` (typed per field, so a pointer field keeps `(ptr T)`).
  ## Both operands address by name via emAggrFieldMem (a stack `(s)` slot's dot form,
  ## or a by-ref param's pointer). A per-field copy (vs. per-8-byte-word) moves every
  ## field at its own type, so a struct with two fields PACKED into one eightbyte
  ## (e.g. `{int32; int32}`) copies BOTH — a word-by-word copy carried only the field
  ## at the eightbyte boundary and dropped the rest. (The register-ABI marshalling
  ## `transferAggrWords` must stay word-granular and handles packing via raw u64
  ## words; a memory→memory copy has no such constraint, so per-field is simplest.)
  var srcR = NoReg
  var dstR = NoReg
  let srcHome = g.plan.homeOfSym(srcVar)
  let dstHome = g.plan.homeOfSym(dstVar)
  if srcHome.kind == StackPtr:
    srcR = g.pickStagingSealed("a spilled by-ref copy src", AddrSlot)
    g.ab.tree MovX64: (g.emReg srcR; g.emStackMem(srcHome.ptrName))
  if dstHome.kind == StackPtr:
    dstR = g.pickStagingSealed("a spilled by-ref copy dst", AddrSlot, avoid = srcR)
    g.ab.tree MovX64: (g.emReg dstR; g.emStackMem(dstHome.ptrName))
  for f in aggrLayout(g.prog, typeSym):
    g.bindTemp(tmp, g.fieldSlotByName(typeSym, f.name))
    g.ab.tree MovX64:
      g.emReg tmp
      if srcR != NoReg: g.emPtrFieldMem(srcR, srcHome.pointeeType, f.name)
      else: g.emAggrFieldMem(srcVar, f.name)
    g.ab.tree MovX64:
      if dstR != NoReg: g.emPtrFieldMem(dstR, dstHome.pointeeType, f.name)
      else: g.emAggrFieldMem(dstVar, f.name)
      g.emReg tmp
    g.unbindTemp(tmp)
  if srcR != NoReg: g.giveBack srcR
  if dstR != NoReg: g.giveBack dstR

proc aggrSrcEnd*(g: var CodeGen; name: string; staged: var Reg): AggrEnd =
  ## The copy-source form of the aggregate `name`, and how many registers it costs:
  ##   * an rsp-relative `(s)` slot — an allocator-homed `NamedStack` local OR an emitter-
  ##     synthesized temp (`stackSlots`) — costs NOTHING;
  ##   * a by-ref aggregate param, whose pointer is ALREADY in a register, costs nothing
  ##     either (the old code copied that register into a fresh staging one);
  ##   * only a module-level global/const/threadvar genuinely needs an address, because its
  ##     `lea` is RIP-relative and there is no rsp-relative form of it.
  ## `staged` receives the register to `giveBack`, or `NoReg`.
  staged = NoReg
  let home = g.plan.homeOfSym(name)
  case home.kind
  of NamedStack: return slotEnd(name)
  of StackPtr:
    staged = g.pickStagingSealed("a spilled by-ref src pointer", AddrSlot)
    g.ab.tree MovX64: (g.emReg staged; g.emStackMem(home.ptrName))
    return regEnd(staged)
  of InReg: return regEnd(home.r)
  of InRegPair:
    raiseAssert "arkham x64n: aggrSrcEnd of InRegPair " & name
  else:
    if name in g.stackSlots: return slotEnd(name)
    staged = g.pickStagingSealed("an aggregate-copy source address", AddrSlot)
    g.emSymAddrByName(staged, name)
    return regEnd(staged)

proc flatCopyToPtr(g: var CodeGen; srcVar: string; sizeBytes: int; dstPtr, tmp: Reg) =
  ## Copy the `sizeBytes`-byte aggregate stack slot `srcVar` into `[dstPtr]`, through
  ## scratch `tmp`, by the one `copyAggr` (word bulk + byte tail — any size,
  ## layout-agnostic). `srcVar` is a synthetic `(s)` slot at every call site, so the
  ## source is addressed straight off rsp and the copy holds TWO registers, not three.
  ## Three was the count that exhausted the staging pool in `toDecimal64` under
  ## `-d:danger`, and it was never a machine requirement — only a consequence of forcing
  ## every source into a register first.
  g.bindTemp(tmp, addrSlot())
  var sp = NoReg
  let src = g.aggrSrcEnd(srcVar, sp)
  g.copyAggr(regEnd(dstPtr), src, sizeBytes, tmp)
  g.giveBack sp
  g.unbindTemp(tmp)

proc copyNestedAggrTemp*(g: var CodeGen; tmpName: string; sizeBytes: int; dstPtr: Reg) =
  g.bridgeStep("a nested-aggregate temp copy", bdTwoInRegs)
  ## Copy a `buildNestedAggrTemp` temp into the sub-aggregate at `[dstPtr]`.
  let scratch = g.pickStagingSealed("a nested-aggregate-field copy word", AddrSlot)
  g.flatCopyToPtr(tmpName, sizeBytes, dstPtr, scratch)
  g.giveBack scratch

proc emFieldOperand*(g: var CodeGen; dst: Location) =
  ## The `(mem (dot <base> field))` operand for a `Field` destination, dispatching on
  ## how its base aggregate is addressed (a pointer register / a named stack slot / an
  ## lvalue subtree). nifasm sizes the access from the field's declared type. A
  ## `FbGlob`/`FbTvar` (survivor-spill) base must be pre-materialized into an `FbReg`
  ## by the caller BEFORE the enclosing store instruction opens — `emGlobalAddr` is a
  ## separate `lea`, so re-deriving it inside this operand would corrupt the open tree.
  case dst.base.kind
  of FbReg:  g.emPtrFieldMem(dst.base.reg, dst.aggrType, dst.field)
  of FbSlot: g.emAggrFieldMem(dst.base.sym, dst.field)
  of FbLval: g.emLvalFieldMem(dst.base.lval, dst.field)
  of FbGlob, FbTvar:
    raiseAssert "arkham x64n: FbGlob/FbTvar field base must be pre-materialized " &
                "(materializeGlobBase) before the operand opens"

proc emFieldAddr*(g: var CodeGen; dst: Location; into: Reg) =
  ## `&(base.field)` → `into`: just `lea` over the field's own memory operand, so the
  ## base forms need no special handling. The recursion base for a nested aggregate
  ## field.
  g.ab.tree LeaX64: (g.emReg into; g.emFieldOperand(dst))

proc materializeGlobBase*(g: var CodeGen; dst: Location; avoid: Reg): (Location, Reg) =
  ## If `dst` is a survivor-spill `baseGlob` field (the `reserveHeldScratch` totality
  ## backstop: `&g` could not be held in a callee-saved register), re-`lea` `&g` into a
  ## fresh transient and return an equivalent `baseReg` field over it (plus the transient
  ## to `giveBack`). Otherwise pass `dst` through unchanged (`NoReg` cleanup).
  ##
  ## For a SCALAR field this must be called AFTER the value is evaluated, so the transient
  ## need not survive the value's possible call (a global address is re-derivable, so we
  ## simply recompute it here instead of holding it across the call).
  if dst.base.kind notin {FbGlob, FbTvar}: return (dst, NoReg)
  let t = g.pickStagingSealed("a re-derived global field base", AddrSlot, avoid = avoid)
  g.emSymAddr(t, (if dst.base.kind == FbTvar: tvarLoc(dst.base.sym, dst.typ)
                  else: globLoc(dst.base.sym, dst.typ)))
  (fieldLocReg(dst.aggrType, dst.field, t, dst.typ), t)
