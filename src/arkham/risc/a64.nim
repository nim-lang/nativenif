#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## What only AArch64 has: the exclusive-access atomics (`ldaxr`/`stlxr`, which
## carry their own ordering), the Linux `(syproc …)` declarations, whose
## syscall numbers are the asm-generic ones, and the registers an `.assembler`
## body may not pin. The shared load/store emitter reaches
## these qualified — `a64.emitAtomic` — so the target is visible at the call site.

import std / [assertions, tables, strformat]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planner, programs, asmbuf,
                    context, diag, typeutil, mirrors, regbind]
import machine_a64 as machine
import emit
from symparser import derivedName

proc emLdar(g: var CodeGen; rt, rn: Reg; bits = 64) =   # rt ← acquire [rn] (sized)
  g.ab.tree LdarA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits

proc emStlr(g: var CodeGen; rt, rn: Reg; bits = 64) =   # release store rt→[rn] (sized)
  g.ab.tree StlrA64:
    g.emReg rt; g.emReg rn
    if bits != 64: g.ab.intLit bits

proc emitAtomicRmw(g: var CodeGen; dst, p, v: Reg; opStr: string;
                   isXchg, returnNew: bool; bits: int) =
  ## `loop: ldaxr old,[p]; new = old op v (or v, for an exchange); stlxr st,new,[p];
  ## cmp st,0; beq done` — a non-zero status means another agent won the line, so
  ## the loop falls through to nifasm's internal back-edge and re-reads.
  ##
  ## `old`/`new`/`st` are the dedicated scratch (`AtomicScratchRegs`); `p` and `v`
  ## are only ever read, which is what lets `dst` alias either of them.
  let lDone = g.freshLabel()
  let (pS, vS) = (g.emOp p, g.emOp v)
  let old = g.emOp g.md.atomicScratch[0]
  let neu = g.emOp g.md.atomicScratch[1]
  let st = g.emOp g.md.atomicScratch[2]
  let w = wsfx(bits)
  let update = if isXchg: &"(mov {neu} {vS})" else: &"(mov {neu} {old}) ({opStr} {neu} {vS})"
  # Structured `(loop …)`: nifasm emits the back-edge internally. The exclusive
  # store SUCCEEDS when `st == 0` → the forward `(beq lDone)` leaves the loop.
  g.ab.splice &"(loop (stmts (ldaxr {old} {pS}{w}) " & update & " " &
              &"(stlxr {st} {neu} {pS}{w}) (cmp {st} 0) (beq {lDone}))) (lab :{lDone})"
  g.movReg(dst, g.md.atomicScratch[if returnNew: 1 else: 0])

proc emitAtomic*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                 argCurs: seq[Cursor]; res: Location) =
  ## AArch64's atomics. Every variant is the strong acquire/release form, so the
  ## memory-order operands are not evaluated at all (see `evaluatedOperands`) —
  ## whatever order was asked for, this satisfies it.
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
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "", true, false, bits)
  of AtomicFetchAddOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, false, bits)
  of AtomicFetchSubOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, false, bits)
  of AtomicFetchAndOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "and", false, false, bits)
  of AtomicFetchOrOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "orr", false, false, bits)
  of AtomicFetchXorOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "eor", false, false, bits)
  of AtomicAddFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "add", false, true, bits)
  of AtomicSubFetchOp:
    g.emitAtomicRmw(res.r, p, g.instrOperandReg(argCurs[1]), "sub", false, true, bits)
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

proc emitSyproc*(g: var CodeGen; sp: SyscallProc) =
  ## Emit a `(syproc :name (params …) (result …)? NR)` decl for a Linux syscall:
  ## params in the syscall ABI registers (x0–x5, identical to AAPCS64's arg regs),
  ## result in x0, and the AArch64 syscall number. A `svc` preserves every register
  ## but x0, so no `(clobber …)` is emitted (the `(svc)` marker marks x0 itself).
  ## Invoked inline at call sites via the `(svc 0)` marker; emits no code.
  var c = sp.decl
  c.into:
    inc c                                        # name
    var pc = c; skip c                           # params slot; c → return type
    g.ab.tree SyprocD:
      g.ab.symDef sp.asmName
      var idx = 0
      g.ab.tree ParamsD:
        if pc.kind == TagLit:                    # (params (param …) …)
          pc.into:
            while pc.hasMore:
              pc.into:                           # (param :name pragmas type)
                inc pc                           # name → positional pN.0
                skip pc                          # pragmas
                if idx >= g.md.intArgRegs.len:
                  raiseAssert "arkham a64: syscall with too many arguments"
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  g.ab.rawReg g.md.intArgRegs[idx]
                  g.genTypeBody(pc)
                while pc.hasMore: skip pc
              inc idx
      g.ab.tree ResultD:                         # c at the return type
        if not retIsVoid(c):
          g.ab.symDef synth("ret.0")
          g.ab.rawReg g.md.intRetReg
          g.genTypeBody(c)
      if sp.sysNrA64 < 0:
        # A row whose AArch64 column is `-1` (a legacy call the asm-generic ABI
        # dropped: `open`, `stat`, `fork`, …). Emitting it anyway would trap with
        # x8 = -1, i.e. a silent ENOSYS that surfaces as `fileExists` always false
        # rather than as a build error. std/posix routes each of these through the
        # `*at`/`*2` form under `linuxA64Raw`; reaching here means one was missed.
        raiseAssert "arkham a64: no AArch64 syscall for " & sp.asmName
      g.ab.intLit sp.sysNrA64.int64
    while c.hasMore: skip c                       # drain the importc decl's pragmas + body

proc rejectReservedPin*(g: var CodeGen; at: Cursor; name: string; r: Reg) =
  ## The AArch64 registers an `.assembler` body may not pin (`asmproc.asmPinReg`),
  ## each refused by the ROLE that already lives there.
  if r == g.md.linkReg:
    lengError at, "`x30` is the link register: every `bl` overwrites it and " &
              "the epilogue reads it back", g.asmInfo
  if r == g.md.framePtrReg:
    lengError at, "`x29` is the frame pointer, which addresses the caller's " &
              "stack arguments for the whole body", g.asmInfo
  if r == g.md.indirectResultReg:
    lengError at, "`x8` carries `&result` for a callee returning an aggregate " &
              "too wide for registers", g.asmInfo
  if r in {R16, R17}:
    lengError at, "`" & name & "` is an assembler veneer register (IP0/IP1); " &
              "the linker writes it in branch thunks this back end never sees",
              g.asmInfo
  if r == R18:
    lengError at, "`x18` is the platform register and belongs to the OS, not " &
              "to this program", g.asmInfo

proc variadicTarget*(g: var CodeGen; asmName: string; slots: openArray[AsmSlot];
                     fixed: int): string =
  ## The symbol a Darwin call to the `{.varargs.}` extern `asmName` goes through:
  ## the extern's own name with the variadic tail's SHAPE folded in, registered in
  ## `g.variadicExterns` so the driver declares it. Two calls with the same shape
  ## share one declaration; the slots are 8-byte words on Apple's stack (a double,
  ## an integer or pointer, a ≤16B aggregate's words, a larger one's pointer), so
  ## that is all the shape records.
  var key = ""
  for s in slots.toOpenArray(fixed, slots.len - 1):
    case s.kind
    of AFloat: key.add 'f'
    of AMem:
      if s.size > g.md.aggrByRefThreshold: key.add 'r'
      else: key.add 'a' & $((s.size + 7) div 8)
    else: key.add 'i'
  let ex = block:
    var found = -1
    for i, e in g.prog.externOrder:
      if e.asmName == asmName: found = i
    assert found >= 0, "arkham a64: a variadic call to an unknown extern " & asmName
    g.prog.externOrder[found]
  result = derivedName(cNameOfAsmName(asmName) & ".0", "cva" & key) & "." &
           thisModuleSuffix(g.prog)
  for v in g.variadicExterns:
    if v.asmName == result: return
  g.variadicExterns.add VariadicExtern(asmName: result, extName: ex.extName, decl: ex.decl,
                                       tail: @(slots.toOpenArray(fixed, slots.len - 1)))
