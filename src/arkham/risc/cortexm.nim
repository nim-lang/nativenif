#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## What only Cortex-M (ARMv7E-M) has: the `ldrex`/`strex` atomics bracketed by
## `dmb`, the FPU enable a reset path owes an M4F, the interrupt table as slots
## of the ARMv7-M vector table, and the refusals — module-level and per pinned
## register — for what the profile lacks or reserves. The shared load/store emitter reaches these
## qualified — `cortexm.emitAtomic` — so the target is visible at the call site.

import std / syncio
import std / [assertions, tables]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planner, programs, asmbuf,
                    context, diag, typeutil, mirrors, regbind]
import machine_a64 as machine
from machine_cortexm import nil
import emit

const
  CpacrAddr* = 0xE000ED88'i64
    ## The Coprocessor Access Control Register.
  CpacrFullAccessCp10Cp11* = 0x00F00000'i64
    ## Full access for CP10 and CP11 — the two coprocessor slots the FPU lives in.

proc emAtomicLoad(g: var CodeGen; dst, p: Reg; bits: int) =
  ## `dst ← the bits-wide cell at [p]`, zero-extended. Not an exclusive load:
  ## nothing is claimed, because nothing is going to be stored back.
  # Each arm emits its own tree: `ldrb`/`ldrh` are `MInst` members and `ldr` is an
  # `RiscInst` one (the shared spelling lives in the A64 enum), so there is no
  # common variable to select into — the tag IDS are what nifasm reads, and those
  # agree.
  case bits
  of 8:
    g.ab.tree LdrbM:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
  of 16:
    g.ab.tree LdrhM:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
  else:
    g.ab.tree LdrA64:
      g.emReg dst
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)

proc emAtomicStore(g: var CodeGen; p, src: Reg; bits: int) =
  case bits
  of 8:
    g.ab.tree StrbM:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src
  of 16:
    g.ab.tree StrhM:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src
  else:
    g.ab.tree StrA64:
      g.ab.tree MemX: (g.emReg p; g.ab.intLit 0)
      g.emReg src

proc emitAtomicRmw(g: var CodeGen; dst, p, v: Reg; opTag: RiscInst;
                   isXchg, returnNew: bool; bits: int) =
  ## `loop: ldrex old,[p]; new = old op v (or v); strex st,new,[p]; cmp st,0;
  ## beq done` — a non-zero status means another agent won the line, so the loop
  ## falls through to nifasm's internal back-edge and re-reads.
  ##
  ## `old`/`new`/`st` are the three reserved bridges; `p` and `v` are only ever
  ## read, which is what lets `dst` alias either of them.
  let old = g.md.atomicScratch[0]
  let neu = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lDone = g.freshLabel()
  g.emitLoop:
    g.ab.tree LdrexM: (g.emReg old; g.emReg p; g.ab.intLit bits)
    if isXchg:
      g.ab.tree MovA64: (g.emReg neu; g.emReg v)
    else:
      g.ab.tree MovA64: (g.emReg neu; g.emReg old)
      g.ab.tree opTag: (g.emReg neu; g.emReg v)
    g.ab.tree StrexM: (g.emReg st; g.emReg neu; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lDone)
  g.emLab(lDone)
  # A sub-word RMW computed on a zero-extended `old`, so the result needs no
  # narrowing: `strex{b,h}` stores the low bits and the returned value is what
  # the cell holds.
  g.movReg(dst, if returnNew: neu else: old)

proc emitAtomicCas(g: var CodeGen; ret, p, ep, d: Reg; bits: int) =
  ## Compare-and-swap. The FAILURE path is the whole protocol: it publishes what
  ## the cell actually held through `ep`, so the caller retries against the value
  ## it now holds — and it must `clrex` first, because it leaves the pair without
  ## the store and the monitor would otherwise stay armed on this address.
  let exp = g.md.atomicScratch[0]
  let old = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lSucc = g.freshLabel()
  let lFail = g.freshLabel()
  let lDone = g.freshLabel()
  g.emAtomicLoad(exp, ep, bits)
  g.emitLoop:
    g.ab.tree LdrexM: (g.emReg old; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg old; g.emReg exp)
    g.emBr(BneA64, lFail)
    g.ab.tree StrexM: (g.emReg st; g.emReg d; g.emReg p; g.ab.intLit bits)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lSucc)
  g.emLab(lSucc)
  g.movImm(ret, 1)
  g.emBr(BA64, lDone)
  g.emLab(lFail)
  g.ab.keyword ClrexM
  g.emAtomicStore(ep, old, bits)
  g.movImm(ret, 0)
  g.emLab(lDone)

proc emitAtomic*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                 argCurs: seq[Cursor]; res: Location) =
  ## Cortex-M's atomics (see `mem.emitAtomicInstr`). Every variant is bracketed
  ## by `dmb` — the strongest ordering this profile can express, and the one every
  ## memory order the row carries is satisfied by.
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
  if bits notin [8, 16, 32]:
    lengError c, "a " & $bits & "-bit atomic has no Cortex-M lowering: ARMv7-M " &
              "has no `ldrexd`/`strexd`, and two exclusive pairs over the halves " &
              "would be two claims rather than one atom", lengInfo(c)
  let p = g.instrOperandReg(argCurs[0])
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  g.ab.keyword DmbM
  case op
  of AtomicLoadOp: g.emAtomicLoad(res.r, p, bits)
  of AtomicStoreOp: g.emAtomicStore(p, g.instrOperandReg(argCurs[1]), bits)
  of AtomicExchangeOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), NopA64, true, false, bits)
  of AtomicFetchAddOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, false, bits)
  of AtomicFetchSubOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, false, bits)
  of AtomicFetchAndOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AndA64, false, false, bits)
  of AtomicFetchOrOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), OrrA64, false, false, bits)
  of AtomicFetchXorOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), EorA64, false, false, bits)
  of AtomicAddFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, true, bits)
  of AtomicSubFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, true, bits)
  of AtomicCompareExchangeOp:
    g.emitAtomicCas(res.r, p, g.instrOperandReg(argCurs[1]),
                    g.instrOperandReg(argCurs[2]), bits)
  else:
    # `AtomicTestAndSet` / `AtomicClear`: the rows exist and their `targets` is
    # empty, so this is the message that column promises.
    lengError c, "`" & IntrinsicNames[op] & "` has no Cortex-M lowering — " &
              "guard the call with a `when`"
  g.ab.keyword DmbM

proc emitEnableFpu*(g: var CodeGen) =
  ## Turn the FPU on, first thing in the entry proc.
  ##
  ## Cortex-M4F comes out of reset with the FPU DISABLED: CPACR grants no access
  ## to CP10/CP11, and the first VFP instruction takes a UsageFault (NOCP) —
  ## which, with no handler installed, is a lockup at the top of `main` with
  ## nothing to say why. Every image gets this, because whether it uses a float
  ## is not known when the entry proc is emitted, and twenty bytes once is not
  ## worth being clever about.
  ##
  ## The DSB/ISB pair is not decoration: CPACR changes how LATER instructions
  ## behave, so the write has to complete and the pipeline be re-fetched before
  ## the first floating-point instruction. QEMU forgives its absence; silicon
  ## does not.
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit CpacrAddr)
  g.ab.tree LdrA64:
    g.ab.rawReg g.argReg(1)
    g.ab.tree MemX: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
  g.ab.tree OrrA64: (g.ab.rawReg g.argReg(1); g.ab.intLit CpacrFullAccessCp10Cp11)
  g.ab.tree StrA64:
    g.ab.tree MemX: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
    g.ab.rawReg g.argReg(1)
  g.ab.keyword DsbM
  g.ab.keyword IsbM

proc rejectUnsupported*(g: var CodeGen) =
  ## Everything the Cortex-M target does NOT have, refused by name at the module
  ## level before a single instruction is emitted. Each of these would otherwise
  ## reach an AArch64-shaped emitter and produce something plausible and wrong.
  if g.prog.tvars.len > 0 and not g.oneThread:
    # A board with more than one stack slot has more than one thread, and each
    # needs its own copy. The mechanism the layout was designed around is in
    # place on the nifasm side — `(stacks (slots N) (bytes S) (tvar (bytes T)))`
    # reserves T bytes at the top of every slot, and `S` is a power of two
    # precisely so a thread reaches its own by masking SP — but arkham does not
    # yet emit that masked base at a reference, and nifasm does not yet allocate
    # offsets within the reservation. Refusing here is the honest report; what is
    # missing is the addressing, not the target's ability to have threads.
    quit "arkham cortex-m: this board declares " & $g.board.slotCount &
         " stack slots, so a thread-local needs one copy per thread — and the " &
         "SP-masked thread-local base that would reach it is not implemented " &
         "yet. Declare `(stacks (slots 1) …)` for a single-core image, where a " &
         "thread-local IS a global."
  if g.prog.externOrder.len > 0:
    quit "arkham cortex-m: `importc` of \"" & g.prog.externOrder[0].extName &
         "\" cannot be satisfied — a firmware image has nothing to link against."

proc emitInterruptTable*(g: var CodeGen) =
  ## `(interrupts (irq <slot> <handler>)*)` — the ARMv7-M vector table, as slots
  ## rather than names. WHICH slot a name denotes is the machine model's answer
  ## (`machine_cortexm.interruptSlot`), and nifasm's job is to place an address in
  ## a word — so the name is resolved here and never leaves. It is a declaration
  ## and its position in the module carries no meaning.
  var handlers: seq[(int, string)] = @[]
  for info in g.prog.procs:
    if info.irqName.len == 0: continue
    let slot = machine_cortexm.interruptSlot(info.irqName)
    if slot < 0:
      quit "arkham cortex-m: `" & info.irqName & "` is not an interrupt of " &
           "this target. Expected one of NMI, HardFault, MemManage, BusFault, " &
           "UsageFault, SVCall, DebugMon, PendSV, SysTick, or IRQ<n>."
    for (s, other) in handlers:
      if s == slot:
        quit "arkham cortex-m: interrupt `" & info.irqName & "` is claimed by " &
             "both " & other & " and " & info.asmName &
             " — a table word holds one address."
    handlers.add (slot, info.asmName)
  if handlers.len > 0:
    g.ab.tree NifasmDecl.InterruptsD:
      for (slot, nm) in handlers:
        g.ab.tree NifasmDecl.IrqD:
          g.ab.intLit int64(slot)
          g.ab.sym nm

proc rejectReservedPin*(g: var CodeGen; at: Cursor; name: string; r: Reg) =
  ## The Cortex-M registers an `.assembler` body may not pin (`asmproc.asmPinReg`),
  ## each refused by the ROLE that already lives there.
  if r == g.md.linkReg:
    lengError at, "`lr` holds the return address, which every `bl` overwrites " &
              "and the epilogue reads back", g.asmInfo
  if r == machine_cortexm.IP:
    lengError at, "`r12` is the assembler's own scratch: nifasm folds an " &
              "out-of-range operand through it at sites this back end never " &
              "sees, so a value left there dies to an instruction nobody emitted",
              g.asmInfo
  if r == g.md.produceBridge:
    lengError at, "`r8` is arkham's produce bridge — the register it can " &
              "always take when a value has to be staged", g.asmInfo
  if r == g.md.indirectResultReg:
    lengError at, "`r9` carries `&result` for a callee returning an aggregate " &
              "too wide for registers", g.asmInfo
  if r in {g.md.bridgeRegs[0], g.md.bridgeRegs[1]}:
    lengError at, "`" & name & "` is one of arkham's two staging bridges " &
              "(r10/r11): a folded memory operand has to be loaded somewhere, " &
              "and this target has no spare volatile at all", g.asmInfo
