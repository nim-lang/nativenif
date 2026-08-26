#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Aggregates, atomics, and the byte loops that move memory.
##
## AAPCS64 marshalling (an aggregate of 16 bytes or less travels in up to two
## registers, a larger one by reference), whole-struct copies, the inline `mem*`
## intrinsics — arkham emits its own loops, there being no libc — and the two
## atomic lowerings: AArch64's LDAXR/STLXR pairs and Cortex-M's LDREX/STREX,
## where the barrier is a separate instruction rather than part of the access.

import std / [assertions, tables, sets, strformat, strutils]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, analyser, planer, programs, asmbuf,
                    stress, context, diag, asmcommon, typeutil, constdata,
                    mirrors, select, temps, exprpred, typenav, regbind, abi,
                    layout, peephole]
import machine_a64 as machine
from machine_m as machine_m import nil
from "../../nifasm/arm64/encoder" as arm64 import isLogicalImm
from thumbimm import nil
import emit, mem

proc loadAggrTail*(g: var CodeGen; dst, base: Reg; aggrSize, byteOff: int) =
  ## `dst ←` the aggregate's trailing `aggrSize - byteOff` bytes at `[base + byteOff]`,
  ## right-justified in `dst` (the by-value ABI leaves the word's padding bits
  ## unspecified, so the high bytes are free).
  ##
  ## Reads NOTHING outside the aggregate. The word a small value ends in may be the
  ## last mapped bytes of a page — a heap `seq` payload, the tail of a `.bss`
  ## section — and a lazy full-word over-read there is a segfault that only shows up
  ## on the allocation that happens to land at the boundary.
  let n = aggrSize - byteOff
  let w = wordSize()
  if byteOff >= w:
    # A whole word precedes this one, so the aggregate's LAST `w` bytes are all in
    # bounds: read them as one word and shift the tail down into place.
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, aggrSize - w, w))
    g.binImm(LsrA64, dst, int64((w - n) * 8))
  elif n in {1, 2, 4} and n <= w:
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, byteOff, n))
  else:
    # A 3/5/6/7-byte aggregate: no single load covers it and there is no full word to
    # borrow from, so assemble it from the top byte down.
    let tmp = g.takeBridge(avoid = base)
    g.ab.tree MovA64: (g.emReg dst; g.emScalarAtOff(base, byteOff + n - 1, 1))
    for b in countdown(n - 2, 0):
      g.binImm(LslA64, dst, 8)
      g.ab.tree MovA64: (g.emReg tmp; g.emScalarAtOff(base, byteOff + b, 1))
      g.binReg(OrrA64, dst, tmp)
    g.dropBridge tmp

proc storeAggrTail*(g: var CodeGen; base, src: Reg; aggrSize, byteOff: int) =
  ## `[base + byteOff] ←` the low `aggrSize - byteOff` bytes of `src`. The write-side
  ## twin of `loadAggrTail`, and the reason it cannot simply store a full word: the
  ## bytes past the aggregate belong to whatever sits next to it.
  let n = aggrSize - byteOff
  if n in {1, 2, 4} and n <= wordSize():
    g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff, n); g.emReg src)
  else:
    let tmp = g.takeBridge(avoid = base)
    g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff, 1); g.emReg src)
    for b in 1 ..< n:
      g.binImm3(LsrA64, tmp, src, int64(8 * b))
      g.ab.tree MovA64: (g.emScalarAtOff(base, byteOff + b, 1); g.emReg tmp)
    g.dropBridge tmp

proc aggrWordsToFromRegs*(g: var CodeGen; varName: string; typeSym: SymId;
                         firstArg: int; toRegs: bool) =
  ## Move a ≤16-byte aggregate between its memory home and x{firstArg+i} (the by-value
  ## aggregate ABI). The whole transfer is positional: the slot's address goes into a
  ## staging bridge (a by-ref aggregate already has its pointer in a reg) and each
  ## eightbyte moves as a RAW `(u 64)` word, so fields PACKED into one word
  ## (`{int32; int32}`) all transfer and a non-object aggregate — a tuple, an array —
  ## needs no layout at all. A trailing PARTIAL eightbyte goes through
  ## `loadAggrTail` / `storeAggrTail`: exact bytes, no over-read, no over-write.
  let byteSize = aggrByteSize(g.prog, typeSym)
  let loc = g.plan.homeOfSym(varName)
  if loc.kind == InRegPair:
    # The aggregate IS the word registers — no memory round-trip.
    for i in 0 ..< aggrWordCount(g.prog, typeSym):
      let w = pairWord(loc, i)
      let arg = g.md.intArgRegs[firstArg + i]
      if toRegs:
        if arg != w: g.movReg(arg, w)
      else:
        if w != arg: g.movReg(w, arg)
    return
  var baseReg = NoReg
  var bridge = NoReg
  if loc.kind == InReg:
    baseReg = loc.r                                    # a by-ref aggregate's pointer
  else:
    bridge = g.takeBridge()
    case (if loc.kind == NoLoc: g.lookupSym(varName).cat else: scNone)
    of scGlobal: g.emGlobalAddr(bridge, varName)       # `(ret NoNifLineInfo)`: a global
    of scTvar: g.genTlvAddr(varName, bridge)           # source, addressed with `adr`
    else:
      if loc.kind == StackPtr:
        g.emScalarLoad(bridge, loc.ptrName)            # slot holds &aggregate
      else:
        g.ab.tree LeaA64: (g.emReg bridge; g.ab.sym varName)  # bridge ← &slot
    baseReg = bridge
  let w = wordSize()
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    let argReg = g.md.intArgRegs[firstArg + i]
    if byteSize - i * w >= w:                          # a full word → raw uWORD move
      g.ab.tree MovA64:
        if toRegs: (g.emReg argReg; g.emWordThroughPtr(baseReg, i))
        else: (g.emWordThroughPtr(baseReg, i); g.emReg argReg)
    elif toRegs:
      g.loadAggrTail(argReg, baseReg, byteSize, i * w)
    else:
      g.storeAggrTail(baseReg, argReg, byteSize, i * w)
  if bridge != NoReg: g.dropBridge bridge

proc structToRegs*(g: var CodeGen; varName: string; typeSym: SymId; firstArg: int) =
  ## Aggregate → x{firstArg+i} (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeSym, firstArg, toRegs = true)

proc regsToStruct*(g: var CodeGen; varName: string; typeSym: SymId; firstArg: int) =
  ## x{firstArg+i} → aggregate (one GPR per 8-byte eightbyte).
  g.aggrWordsToFromRegs(varName, typeSym, firstArg, toRegs = false)

proc globalToRegs*(g: var CodeGen; name: string; typeSym: SymId; firstArg: int; isTvar = false) =
  ## Read a GLOBAL (or THREADVAR) aggregate's words into x{firstArg+i}. It is a label,
  ## not a stack slot, so its address goes into a staging bridge and each word is read
  ## through that pointer — a FULL eightbyte as a raw `(u 64)` word (handles packed
  ## fields), a trailing PARTIAL eightbyte through `loadAggrTail`. For a global passed
  ## by value as a call argument (`equalStrings(s, "")` where `s` is a global `string`).
  let bridge = g.takeBridge()
  if isTvar: g.genTlvAddr(name, bridge) else: g.emGlobalAddr(bridge, name)
  let byteSize = aggrByteSize(g.prog, typeSym)
  let mw = wordSize()          # the ABI marshalling word (see aggrWordCount)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * mw >= mw:
      g.ab.tree MovA64: (g.emReg g.md.intArgRegs[firstArg + i]; g.emWordThroughPtr(bridge, i))
    else:
      g.loadAggrTail(g.md.intArgRegs[firstArg + i], bridge, byteSize, i * mw)
  g.dropBridge bridge

proc takeProduceBridge*(g: var CodeGen; typ = ScalarSlot): Reg =
  ## The PRODUCE bridge — the scratch a value is staged through on its way into
  ## memory — if it is free, and any other reserved bridge if it is not.
  ##
  ## Its call sites are written against "the produce bridge is free on entry", and
  ## for four of the five that is a local fact: they take it, emit two or three
  ## instructions, and release it. The fifth (`produceIntoMem2`) holds it across
  ## the evaluation of a whole node, which is where the claim stops being local —
  ## a combining node re-enters and would scribble on the partial. Going through
  ## the protocol makes the claim a CHECK: a register that is still bound is not
  ## handed out twice, so the shape that used to be a silent wrong value is now
  ## either a different bridge or a loud failure.
  let p = g.produceBridge
  if not g.rb.isBoundTemp(p):
    g.bindTemp(p, typ)
    return p
  result = g.takeBridge(typ)

proc takeInstrReg*(g: var CodeGen; slot: AsmSlot; atomic: bool): Location =
  ## A register an `(instr …)` operand or result MUST have (never a spill slot).
  ## Pools, then a callee-saved survivor, then — for a NON-atomic intrinsic — a
  ## staging bridge.
  ##
  ## The bridges are off-limits to the ATOMIC lowerings, which is where the blanket
  ## "never a bridge" rule came from: their `ldaxr`/`stlxr` retry loops use
  ## x14/x15/x16 themselves, so an operand parked there would be destroyed between
  ## the exclusive load and the store. `clz`/`rbit`/`rev`/`bswap` are ONE
  ## instruction with nothing in between, and at most a result plus one operand —
  ## exactly what two bridges cover. Under `-d:release` (shoggoth's denser
  ## expressions leave the pools empty) a bridge is sometimes the only register
  ## left, and the alternative was a hard failure.
  let r = g.pickTempReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, slot, isTemp = true)
  if atomic:
    let s = g.pickStagingA64()
    if s == NoReg:
      result = g.takeHeld("an atomic intrinsic operand")  # fails loudly
      result.typ = slot                        # keep the precise type for the binding
      return
    g.pickedRegs.incl s
    return regLoc(s, slot, isTemp = true)
  let h = g.pickHeldReg()
  if h != NoReg:
    g.pickedRegs.incl h
    return regLoc(h, slot, isTemp = true)
  let b = g.takeBridge(slot)                   # binds it; `freeVal` releases it
  g.pickedRegs.incl b
  result = regLoc(b, slot, isTemp = true)

proc flatCopyToPtr2*(g: var CodeGen; srcVar: string; sizeBytes: int; dstPtr, tmp: Reg) =
  ## Copy the `sizeBytes`-byte aggregate stack slot `srcVar` into `[dstPtr]` through the
  ## (already bound) word scratch `tmp` — the a64 twin of x64's `flatCopyToPtr`. The
  ## source address goes into the reserved produce bridge (x16 on AArch64, r8 on
  ## Cortex-M): it is never allocator-assigned, and the copy's own instructions
  ## synthesize only through the ASSEMBLER's scratch (x17 / r12) for large
  ## load/store offsets, so it cannot be clobbered mid-copy. A flat word copy is
  ## byte-accurate whatever the field layout — a PER-FIELD copy would mis-load a field
  ## that is itself an aggregate (e.g. a 16-byte `seq`) as one scalar.
  let srcPtr = g.takeProduceBridge(addrSlot())
  g.ab.tree LeaA64: (g.emReg srcPtr; g.ab.sym srcVar)
  g.copyAggr(dstPtr, srcPtr, sizeBytes, tmp)
  g.unbindTemp(srcPtr)

proc regsToStructThroughPtr*(g: var CodeGen; ptrReg: Reg; typeSym: SymId; firstArg: int) =
  ## `[ptrReg] ← x{firstArg+i}` — marshal a ≤16B aggregate held in the return registers
  ## into the memory `ptrReg` points at: a FULL eightbyte as a raw `(u 64)` word
  ## (handles packed fields), a trailing PARTIAL eightbyte through `storeAggrTail`. The
  ## through-pointer twin of `regsToStruct` — stores an aggregate call result into a
  ## global.
  let byteSize = aggrByteSize(g.prog, typeSym)
  let mw = wordSize()          # the ABI marshalling word (see aggrWordCount)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * mw >= mw:
      g.ab.tree MovA64: (g.emWordThroughPtr(ptrReg, i); g.emReg g.md.intArgRegs[firstArg + i])
    else:
      g.storeAggrTail(ptrReg, g.md.intArgRegs[firstArg + i], byteSize, i * mw)

proc marshalAggrFromAddr*(g: var CodeGen; addrReg: Reg; typeSym: SymId; firstArg: int) =
  ## `x{firstArg+i} ← [addrReg]` — load a ≤16B aggregate at `[addrReg]` into the by-value
  ## ABI argument registers (reverse of `regsToStructThroughPtr`); lets an aggregate CALL
  ## ARGUMENT marshal straight from its address (`aggrAddrInto`) with no copy temp.
  let byteSize = aggrByteSize(g.prog, typeSym)
  let mw = wordSize()          # the ABI marshalling word (see aggrWordCount)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * mw >= mw:
      g.ab.tree MovA64: (g.emReg g.md.intArgRegs[firstArg + i]; g.emWordThroughPtr(addrReg, i))
    else:
      g.loadAggrTail(g.md.intArgRegs[firstArg + i], addrReg, byteSize, i * mw)

proc emitInoutInstr2*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                     argCurs: seq[Cursor]) =
  ## `add(d, s)` in an ORDINARY proc: `(add <d's home> <s>)`. The destination is
  ## `(haddr d)` and d's home is whatever the allocator gave it.
  ##
  ## The x86-64 twin can stop there, because an x86 ALU instruction takes a
  ## memory destination. Arm is a load/store machine: a spilled `d` has to be
  ## brought into a register, operated on, and stored back, which is three
  ## instructions and needs scratch nobody asked for. That is what the staging
  ## bridges are for — reserved out of every pool precisely so a transient is
  ## always available — so the spilled case is SERVED rather than refused. A
  ## rejection here would fire only under register pressure, which is the worst
  ## possible shape for a diagnostic: the same source compiles or does not
  ## depending on how many locals surround it.
  let row = IntrinsicRows[op]
  let tag = armInoutTag(op)
  if tag == NopA64:
    lengError c, "`" & IntrinsicNames[op] & "` has no " &
              g.md.targetName & " two-address form",
              lengInfo(c)
  var destSym = argCurs[0]
  if destSym.kind == TagLit and destSym.exprKind == HaddrC:
    var inner = destSym
    inner.into:
      destSym = inner; skip inner
      while inner.hasMore: skip inner
  if destSym.kind != Symbol:
    lengError argCurs[0], "the destination of `" & IntrinsicNames[op] & "` must " &
              "be a `var` argument naming a local", lengInfo(c)
  let home = g.plan.locationOfSym(symName(destSym), g.posOf(destSym))
  # The source was already emitted and memo'd by the fused `emitInstr2`.
  var src = Location(kind: Undef)
  if row.arity > 1: src = g.plan.planned(g.posOf(argCurs[1]))
  proc emitSrc(g: var CodeGen; src: Location; at: Cursor) =
    case src.kind
    of InReg: g.emReg src.r
    of Imm: g.ab.intLit src.ival
    else:
      lengError at, "unsupported source operand for a two-address instruction",
                lengInfo(at)
  case home.kind
  of InReg:
    if row.arity == 1:
      g.ab.tree tag: g.emReg home.r
    else:
      g.ab.tree tag: (g.emReg home.r; g.emitSrc(src, argCurs[1]))
  of NamedStack:
    let b = g.takeBridge(home.typ)
    g.ab.tree MovA64: (g.emReg b; g.ab.sym home.name)
    if row.arity == 1:
      g.ab.tree tag: g.emReg b
    else:
      g.ab.tree tag: (g.emReg b; g.emitSrc(src, argCurs[1]))
    g.ab.tree MovA64: (g.ab.sym home.name; g.emReg b)
    g.dropBridge b
  else:
    lengError argCurs[0], "the destination of `" & IntrinsicNames[op] &
              "` has no register or stack home", lengInfo(c)

proc wideStoreImm*(g: var CodeGen; w: WideRef; i: int; v: int64) =
  ## An immediate into one half. Thumb-2 has no store-immediate, so it goes
  ## through a scratch — but a repeated value (`0` for both halves of a small
  ## positive constant) is materialized once by the caller when it matters.
  let t = g.takeWideRegs(1, "a 64-bit constant half")[0]
  g.movImm(t, v)
  g.wideStore(w, i, t)
  g.dropWideRegs(@[t])

proc wideCopy*(g: var CodeGen; dst, src: WideRef) =
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

proc wideSymRef*(g: var CodeGen; c: Cursor; scratch: var Reg): WideRef =
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
    if loc.kind == Tvar:
      # A thread-local, which on this target is a global (`genTvar` emitted a
      # `(gvar …)` because the board declares one thread) — but addressed the way
      # every other thread-local reference is, so the one decision stays in the
      # declaration. `genTlvAddr` is the plain `(adr …)`; `emGlobalAddr`'s
      # importc-name mapping and address mirror belong to gvars.
      scratch = g.takeWideRegs(1, "a 64-bit thread-local address")[0]
      g.genTlvAddr(loc.name, scratch)
      return baseWide(scratch)
    raiseAssert "arkham cortex-m: 64-bit symbol " & symName(c) & " at " & $loc.kind
  else:
    raiseAssert "arkham cortex-m: 64-bit local " & symName(c) & " homed in " & $home.kind

proc wideFromNarrow*(g: var CodeGen; dst: WideRef; src: Reg; signed: bool) =
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

proc wideCarryChain*(g: var CodeGen; loOp, hiOp: MInst; dst, a, b: WideRef) =
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

proc wideWordwise*(g: var CodeGen; op: A64Inst; dst, a, b: WideRef) =
  ## `dst = a <op> b` for the bitwise ops, which have no inter-half dependency.
  let t = g.takeWideRegs(1, "a 64-bit bitwise accumulator")[0]
  for i in 0 .. 1:
    g.wideLoad(t, a, i)
    g.ab.tree op: (g.emReg t; g.emReg t; g.emWideWord(b, i))
    g.wideStore(dst, i, t)
  g.dropWideRegs(@[t])

proc wideNeg*(g: var CodeGen; dst, a: WideRef) =
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

proc wideNot*(g: var CodeGen; dst, a: WideRef) =
  let t = g.takeWideRegs(1, "a 64-bit complement")[0]
  for i in 0 .. 1:
    g.wideLoad(t, a, i)
    g.ab.tree MvnM: (g.emReg t; g.emReg t)
    g.wideStore(dst, i, t)
  g.dropWideRegs(@[t])

proc wideMul*(g: var CodeGen; dst, a, b: WideRef) =
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

proc wideArgToStack*(g: var CodeGen; slotName, paramNm: string) =
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

proc wideCopyToAddr*(g: var CodeGen; slotName: string; addrReg: Reg) =
  ## The eight bytes of slot `slotName` to `[addrReg]`.
  g.wideCopy(baseWide(addrReg), slotWide(slotName))

proc wideDivMod*(g: var CodeGen; dst, a, b: WideRef; signed, wantRem: bool) =
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
  g.ab.tree BlA64: g.ab.sym (if signed: g.sDivMod64Proc else: g.uDivMod64Proc)
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
