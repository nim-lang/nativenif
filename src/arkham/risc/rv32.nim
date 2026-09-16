#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## What only RV32 has: the `lr.w`/`sc.w` atomics, and the machine-mode reset
## path a RISC-V image has to build for itself — `sp`, `mstatus.FS`, and the
## vectored `mtvec` trampoline table its interrupts go through; and the registers
## an `.assembler` body may not pin. The shared
## load/store emitter reaches these qualified — `rv32.emitAtomic` — so the target
## is visible at the call site.

import std / [assertions, tables, strformat]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planner, programs, asmbuf,
                    context, diag, typeutil, mirrors, regbind]
import machine_a64 as machine
from machine_rv32 import nil
import emit

const
  DefaultStackTop* = 0x8020_0000'i64
    ## The top of QEMU `virt`'s SRAM region, used when no `--layout:` names one.
    ## MUST agree with `nifasm/image/writerv32`'s `Rv32SramAddr + Rv32SramSize` —
    ## a stack pointer above the region the image declares is not a diagnosable
    ## error, it is a store into nothing.
  CsrMstatus* = 0x300'i64
  MstatusFsDirty* = 0x6000'i64
    ## `mstatus.FS = Dirty`. Any non-zero FS enables the FP unit; `Dirty` is
    ## chosen because it is the state the first FP instruction would move it to
    ## anyway, so nothing has to reason about a later transition.

proc emitAtomicRmw(g: var CodeGen; dst, p, v: Reg; opTag: RiscInst;
                   isXchg, returnNew: bool) =
  ## `loop: lr.w old,(p); new = old op v (or v); sc.w st,new,(p); cmp st,0;
  ## beq done` — a non-zero status means the reservation was lost, so the loop
  ## falls through to nifasm's internal back-edge and re-reads.
  ##
  ## Structurally the Cortex-M twin, and deliberately so: `ldrex`/`strex` and
  ## `lr.w`/`sc.w` are the same instruction pair with different names, down to
  ## the status register's sense (zero is success on both). What differs is the
  ## ORDERING — RISC-V carries it in the `aq`/`rl` bits of the pair, which is what
  ## `AcqRelExclusives` names, so no fence is emitted around the loop.
  ##
  ## Word-only. RV32's A extension has `lr.w`/`sc.w` and no byte or halfword form
  ## at all, so a narrower atomic is refused by name before reaching here rather
  ## than widened — a byte cell widened to a word is a read-modify-write of the
  ## three neighbours it shares the word with.
  let old = g.md.atomicScratch[0]
  let neu = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lDone = g.freshLabel()
  g.emitLoop:
    g.ab.tree LrwRv: (g.emReg old; g.emReg p)
    if isXchg:
      g.ab.tree MovA64: (g.emReg neu; g.emReg v)
    else:
      g.ab.tree MovA64: (g.emReg neu; g.emReg old)
      g.ab.tree opTag: (g.emReg neu; g.emReg v)
    g.ab.tree ScwRv: (g.emReg st; g.emReg neu; g.emReg p)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lDone)
  g.emLab(lDone)
  g.movReg(dst, if returnNew: neu else: old)

proc emitAtomicCas(g: var CodeGen; ret, p, ep, d: Reg) =
  ## Compare-and-exchange. `ep` points at the EXPECTED value and the failure path
  ## must publish what was actually there — that is the protocol, not a detail:
  ## the caller retries against the value it now holds.
  ##
  ## No `clrex` on the failure path. AArch64 and ARMv7-M both have to abandon the
  ## claim their exclusive load took; on RISC-V a reservation is broken implicitly
  ## — by any `sc.w`, by a trap, and in the worst case by the next `lr.w` — so
  ## there is no instruction to emit and nothing left holding a line.
  let exp = g.md.atomicScratch[0]
  let old = g.md.atomicScratch[1]
  let st = g.md.atomicScratch[2]
  let lSucc = g.freshLabel()
  let lFail = g.freshLabel()
  let lDone = g.freshLabel()
  g.ab.tree MovA64:
    g.emReg exp
    g.ab.tree MemX: (g.emReg ep; g.ab.intLit 0)
  g.emitLoop:
    g.ab.tree LrwRv: (g.emReg old; g.emReg p)
    g.ab.tree CmpA64: (g.emReg old; g.emReg exp)
    g.emBr(BneA64, lFail)
    g.ab.tree ScwRv: (g.emReg st; g.emReg d; g.emReg p)
    g.ab.tree CmpA64: (g.emReg st; g.ab.intLit 0)
    g.emBr(BeqA64, lSucc)
  g.emLab(lSucc)
  g.movImm(ret, 1)
  g.emBr(BA64, lDone)
  g.emLab(lFail)
  g.ab.tree MovA64:
    g.ab.tree MemX: (g.emReg ep; g.ab.intLit 0)
    g.emReg old
  g.movImm(ret, 0)
  g.emLab(lDone)

proc emitAtomic*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
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
    return                                 # a compiler barrier only; see `a64.emitAtomic`
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
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), NopA64, true, false)
  of AtomicFetchAddOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, false)
  of AtomicFetchSubOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, false)
  of AtomicFetchAndOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AndA64, false, false)
  of AtomicFetchOrOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), OrrA64, false, false)
  of AtomicFetchXorOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), EorA64, false, false)
  of AtomicAddFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), AddA64, false, true)
  of AtomicSubFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), SubA64, false, true)
  of AtomicCompareExchangeOp:
    g.emitAtomicCas(res.r, p, g.instrOperandReg(argCurs[1]),
                    g.instrOperandReg(argCurs[2]))
  else:
    lengError c, "`" & IntrinsicNames[op] & "` has no RV32 lowering — " &
              "guard the call with a `when`", lengInfo(c)

const TrapTableName* = "`mtvec.0"
  ## The trampoline table's symbol. Back-quoted like the other runtime shims so it
  ## cannot collide with a Leng name.

const MstatusMie* = 0x8'i64      ## `mstatus.MIE`: interrupts enabled in M-mode at all

const CsrMie* = 0x304'i64        ## the per-cause enable register

const CsrMtvec* = 0x305'i64      ## trap vector base + mode

const MtvecVectored* = 1'i64     ## mode 1: cause `c` traps to base + 4*c

proc emitTrapTable(g: var CodeGen; handlers: seq[(int, string)]) =
  ## The `mtvec` trampoline table, emitted as ORDINARY CODE under a symbol.
  ##
  ## This is where RISC-V and Cortex-M stop resembling each other. An M-profile
  ## core reads a table of ADDRESSES that the image writer bakes at the flash
  ## base, and the reset vector is one of its words. A RISC-V core resets to a
  ## fixed PC, and `mtvec` — written by the code that runs there — holds a base
  ## plus a two-bit MODE. In vectored mode a trap with cause `c` jumps to
  ## `base + 4*c`, so each entry is one WORD that has to be an INSTRUCTION.
  ##
  ## A table of jumps is therefore just code, which is why nothing in the image
  ## writer knows about this: it is emitted like any other proc, and the reset
  ## path takes its address with the same `(adr …)` any other symbol gets. The
  ## alternative — a new image-layout number for the base — would have cost a
  ## shared tag id on every target to describe something only this one has.
  ##
  ## Sixteen entries, one per standard cause, and every cause the module did not
  ## claim jumps to a PARK loop rather than falling through. Falling through would
  ## run the next cause's handler, which is the worst available answer: an
  ## unexpected trap would be silently misrouted to a handler written for
  ## something else, and only sometimes.
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef TrapTableName
    g.ab.tree NifasmDecl.ParamsD: discard
    g.ab.tree StmtsA64:
      let park = g.freshLabel()
      for cause in 0 ..< machine_rv32.InterruptCauseCount:
        var target = park
        for (c, nm) in handlers:
          if c == cause: target = nm
        g.emBr(BA64, target)
      g.emLab(park)
      g.emBr(BA64, park)             # an unclaimed trap stops here, visibly

proc emitEnableInterrupts(g: var CodeGen; causes: set[uint8]) =
  ## Point `mtvec` at the table and enable exactly the causes the module declared.
  ##
  ## Enabling is done HERE, at reset, and not left to the program, because on this
  ## target the two halves of "this handler runs" are a CSR write and a pragma,
  ## and only one of them is visible in the source. Cortex-M's `{.interrupt.}` for
  ## a core exception needs no enable at all — PendSV is pended and taken — so a
  ## handler that never ran would be a difference between the targets with nothing
  ## in the program to explain it. Declaring the handler IS the enable; a program
  ## that wants finer control clears the bit itself.
  g.ab.tree AdrA64: (g.ab.rawReg g.argReg(0); g.ab.sym TrapTableName)
  g.ab.tree OrrA64: (g.ab.rawReg g.argReg(0); g.ab.intLit MtvecVectored)
  g.ab.tree CsrwRv: (g.ab.intLit CsrMtvec; g.ab.rawReg g.argReg(0))
  var mie = 0'i64
  for c in causes: mie = mie or (1'i64 shl int(c))
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit mie)
  g.ab.tree CsrsRv: (g.ab.intLit CsrMie; g.ab.rawReg g.argReg(0))
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit MstatusMie)
  g.ab.tree CsrsRv: (g.ab.intLit CsrMstatus; g.ab.rawReg g.argReg(0))

proc emitResetPath*(g: var CodeGen; stackTop: int64) =
  ## What a RISC-V core does NOT do for an image, in the order it must be done.
  ##
  ## An M-profile core reads its initial SP out of vector-table word 0 and enters
  ## the reset handler with a usable stack. A RISC-V core does neither: `sp` holds
  ## whatever reset left there, and `mstatus.FS` is clear, so the first stack
  ## access is wild and the first floating-point instruction raises an
  ## illegal-instruction exception into an `mtvec` that has not been set either.
  ##
  ## Both failures present as a HANG rather than a fault, which is what makes them
  ## expensive: the image simply stops, at an instruction that is spelled and
  ## encoded correctly. So both are established unconditionally, before anything
  ## else, and neither is conditional on whether the program looks like it needs
  ## one — that is not knowable when this is emitted.
  g.ab.tree MovA64: (g.ab.rawReg SP; g.ab.intLit stackTop)
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit MstatusFsDirty)
  g.ab.tree CsrsRv: (g.ab.intLit CsrMstatus; g.ab.rawReg g.argReg(0))
  if g.rvIrqCauses != {}: g.emitEnableInterrupts(g.rvIrqCauses)

proc emitInterruptTable*(g: var CodeGen) =
  ## `(interrupts (irq <cause> <handler>)*)` for RV32 — the same declaration
  ## Cortex-M emits, carrying a different number.
  ##
  ## The slot is a trap CAUSE here, not a word index into a table of addresses:
  ## `mtvec` in vectored mode sends cause `c` to `base + 4*c`, and a word there
  ## has to be an INSTRUCTION. Which name denotes which cause stays a machine
  ## model question (`machine_rv32.interruptCause`), exactly as it is on
  ## Cortex-M, so the name is resolved here and never reaches nifasm.
  var handlers: seq[(int, string)] = @[]
  for info in g.prog.procs:
    if info.irqName.len == 0: continue
    let cause = machine_rv32.interruptCause(info.irqName)
    if cause < 0:
      quit "arkham rv32: `" & info.irqName & "` is not an interrupt of this " &
           "target. Expected one of MachineSoftware, MachineTimer or " &
           "MachineExternal — the three M-mode interrupts of the privileged " &
           "spec. Supervisor and user modes do not exist in an image that never " &
           "leaves M-mode, and an EXCEPTION (a misaligned load, an illegal " &
           "instruction) is reached through mtvec's other mode, not this table."
    for (c, other) in handlers:
      if c == cause:
        quit "arkham rv32: interrupt `" & info.irqName & "` is claimed by both " &
             other & " and " & info.asmName &
             " — a table word holds one jump."
    handlers.add (cause, info.asmName)
  if handlers.len > 0:
    # The declaration is what makes nifasm mark each handler USED: nothing CALLS
    # one, so the reachability walk would otherwise drop it and leave the table
    # jumping at a proc that was never emitted. Its Cortex-M meaning — build a
    # table of addresses — does not apply here and `writeRv32Image` ignores it.
    g.ab.tree NifasmDecl.InterruptsD:
      for (cause, nm) in handlers:
        g.ab.tree NifasmDecl.IrqD:
          g.ab.intLit int64(cause)
          g.ab.sym nm
    g.emitTrapTable(handlers)
    for (cause, _) in handlers: g.rvIrqCauses.incl uint8(cause)

proc rejectReservedPin*(g: var CodeGen; at: Cursor; name: string; r: Reg) =
  ## The RV32 registers an `.assembler` body may not pin (`asmproc.asmPinReg`),
  ## each refused by the ROLE that already lives there.
  # RV32's own list. It used to fall into the AArch64 one (`a64.rejectReservedPin`),
  # which answers about a different register file: `x16`/`x17` are IP0/IP1 there and the
  # ARGUMENT registers a6/a7 here, `x18` is the platform register there and the
  # callee-saved home `s2` here, and the link-register message names `x30` in
  # prose while `md.linkReg` is `x1`. Every one of those is a confident sentence
  # about the wrong register.
  if r == g.md.linkReg:
    lengError at, "`x1` is the link register (`ra`): every `jal` overwrites it " &
              "and the epilogue reads it back", g.asmInfo
  if r == R0:
    lengError at, "`x0` reads as zero and discards every write — a value put " &
              "there is not stored, it is deleted", g.asmInfo
  if r in {R3, R4}:
    lengError at, "`" & name & "` is reserved by the RISC-V ABI (`gp`/`tp`); " &
              "nothing here establishes one, but a proc that clobbered it " &
              "would break any object linked in that does", g.asmInfo
  if r == g.md.indirectResultReg:
    lengError at, "`x9` carries `&result` for a callee returning an aggregate " &
              "too wide for registers", g.asmInfo
  if r == R8:
    lengError at, "`x8` is the ABI's frame pointer (`s0`), kept off the file " &
              "so a debugger's frame walk and a hand-written body have a fixed " &
              "place to stand", g.asmInfo
  if r in {g.md.bridgeRegs[0], g.md.bridgeRegs[1]}:
    lengError at, "`" & name & "` is one of arkham's two staging bridges " &
              "(x29/x30): a folded memory operand has to be loaded somewhere, " &
              "and this target reserves exactly as many as one emitter step " &
              "may hold at once", g.asmInfo
