#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## The Arm stack frame, and everything a proc needs before its body.
##
## AAPCS64 and AAPCS32 share this shape, which is why one module serves both:
## the return address arrives in a register rather than on the stack, the caller
## leaves SP at the first stack argument, and the outgoing argument area is
## reserved ONCE at the bottom of the frame — so SP is constant from prologue to
## epilogue and a stack-passed value keeps a stable address. What differs is
## which registers are callee-saved and how wide a word is, and both are facts
## in `g.md`.

import std / [assertions, tables]
import nifcore
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, 
                    mirrors, regbind, abi]
import machine_a64 as machine
from machine_m as machine_m import nil
import emit, mem, aggr, value

proc wideParamToHome(g: var CodeGen; nm: string; firstArg: int)

proc isWideType(g: var CodeGen; t: Cursor): bool {.inline.}

proc emPair(g: var CodeGen; op: RiscInst; r1, r2: Reg; off: int) =
  # stp/ldp save/restore *physical* callee-saved registers (which may also be
  # named-local homes), so emit raw register nodes, not the local names.
  g.ab.tree op: g.ab.rawReg r1; g.ab.rawReg r2; g.ab.rawReg SP; g.ab.intLit off

proc emFPair(g: var CodeGen; op: RiscInst; f1, f2: FReg; off: int) =
  g.ab.tree op: g.ab.dreg f1; g.ab.dreg f2; g.emReg SP; g.ab.intLit off

proc frameSaveSlot(g: var CodeGen; r: Reg; off: int; storing: bool) =
  ## One callee-saved register into (or out of) its prologue slot. Thumb-2 has
  ## PUSH/POP with a register list, which would be shorter, but asm-NIF has no
  ## register-list operand shape — and a plain `str`/`ldr` per register needs no
  ## new vocabulary and is what the epilogue's reverse walk already expects.
  if storing:
    g.ab.tree StrA64:
      g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit off)
      g.ab.rawReg r
  else:
    g.ab.tree LdrA64:
      g.ab.rawReg r
      g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit off)

proc frameSaveFSlot(g: var CodeGen; f: FReg; off: int; storing: bool) =
  ## One callee-saved FPv4-SP register into (or out of) its prologue slot. A raw
  ## `(sN)`, not `emFReg`: this is the physical register being preserved, and it
  ## may be a named local's home — the name would be wrong here and the binding
  ## checker would be right to complain.
  if storing:
    g.ab.tree FstrA64:
      g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit off)
      g.ab.freg(f, 32)
  else:
    g.ab.tree FldrA64:
      g.ab.freg(f, 32)
      g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit off)

proc framePushBytesBlock(g: CodeGen): int {.inline.} =
  ## lr + every saved callee-saved register, integer and float, rounded to the
  ## 8-byte alignment AAPCS32 wants at a public interface.
  ((1 + g.frameRegs.len + g.frameFRegs.len) * 4 + 7) and not 7

proc framePushBlock(g: var CodeGen) =
  ## The `BlockFrame` prologue: lower SP once, then store the link register and
  ## each used callee-saved register into the block just carved.
  ##
  ## There is no fp/lr PAIR instruction and no frame pointer here: lr is just
  ## another word to save, and only when this proc actually calls something (`bl`
  ## is what overwrites it). AAPCS32 wants SP 8-aligned at a public interface, so
  ## the block is rounded up.
  g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.intLit g.framePushBytesBlock)
  g.frameSaveSlot(g.md.linkReg, 0, storing = true)
  for i, r in g.frameRegs:
    g.frameSaveSlot(r, 4 * (i + 1), storing = true)
  for i, f in g.frameFRegs:
    g.frameSaveFSlot(f, 4 * (1 + g.frameRegs.len + i), storing = true)

proc framePopBlock(g: var CodeGen) =
  for i, f in g.frameFRegs:
    g.frameSaveFSlot(f, 4 * (1 + g.frameRegs.len + i), storing = false)
  for i, r in g.frameRegs:
    g.frameSaveSlot(r, 4 * (i + 1), storing = false)
  g.frameSaveSlot(g.md.linkReg, 0, storing = false)
  g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.intLit g.framePushBytesBlock)

proc framePush*(g: var CodeGen) =
  ## `PairFrame`: push fp/lr, then the used callee-saved GPRs, then the
  ## callee-saved SIMD registers — a LIFO stack of pairs.
  if g.md.frameStyle == BlockFrame:
    g.framePushBlock()
    return
  g.emPair(StpA64, g.md.framePtrReg, g.md.linkReg, -16)
  if g.plan.hasStackParams:
    # Establish the AAPCS64 frame pointer, and with it the base for the incoming
    # stack arguments: the caller left SP pointing at its first stack argument, and
    # the `stp` above lowered SP by 16, so `fp = sp` here means argument `k` sits at
    # `[fp, #16 + byteOff]` for the whole body — through every later `sub sp`.
    #
    # x29 is the base rather than a spare callee-saved register (which is what x64
    # has to do, having no such register to spare) because it is in NO allocation
    # pool, is already saved and restored by this very pair, and so costs the body
    # nothing. Reserving a callee-saved one instead cost exactly the procs that need
    # it — many parameters means high pressure — and pushed `nifcoreparse`'s
    # 11-parameter `emitValueIndexed` off the end of the register file.
    g.ab.tree LeaA64: (g.ab.rawReg g.md.framePtrReg; g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit 0))
  var i = 0
  while i < g.frameRegs.len:
    g.emPair(StpA64, g.frameRegs[i], g.frameRegs[i+1], -16)
    i += 2
  i = 0
  while i < g.frameFRegs.len:
    g.emFPair(FstpA64, g.frameFRegs[i], g.frameFRegs[i+1], -16)
    i += 2

proc framePop*(g: var CodeGen) =
  ## Restore in reverse (post-index): SIMD, then callee-saved GPRs, then fp/lr.
  if g.md.frameStyle == BlockFrame:
    g.framePopBlock()
    return
  var i = g.frameFRegs.len - 2
  while i >= 0:
    g.emFPair(FldpA64, g.frameFRegs[i], g.frameFRegs[i+1], 16)
    i -= 2
  i = g.frameRegs.len - 2
  while i >= 0:
    g.emPair(LdpA64, g.frameRegs[i], g.frameRegs[i+1], 16)
    i -= 2
  g.emPair(LdpA64, g.md.framePtrReg, g.md.linkReg, 16)

proc killFrameRegLocals(g: var CodeGen) =
  ## Before an explicit-`ret` `framePop`, release any register-local bound to a
  ## callee-saved register the epilogue restores raw — nifasm forbids a raw use of
  ## a still-bound register, and at a return every local is dead. The binding is
  ## dropped so the trailing `exitScope` does not double-kill it. (A second `ret`
  ## on another path needing the same callee register bound is the pre-existing
  ## multi-`ret` limitation — out of scope here.)
  for r in g.frameRegs:
    let dead = g.rb.takeBinding(r)
    if dead.len > 0:
      g.ab.tree KillA64: g.ab.sym dead

proc framePushBytes(g: CodeGen): int =
  ## Bytes `framePush` lowers SP by: the fp/lr pair plus each saved callee-saved
  ## GPR / SIMD pair (16 bytes apiece). Used to address incoming stack arguments
  ## relative to SP right after the prologue's pushes (before locals are carved).
  if not g.hasFrame: 0
  elif g.md.frameStyle == BlockFrame: g.framePushBytesBlock
  else: 16 * (1 + g.frameRegs.len div 2 + g.frameFRegs.len div 2)

proc emByRefPtrStackVar*(g: var CodeGen; name: string; typeSym: SymId) =
  ## `(var :name (s) (ptr T))` — the 8-byte slot holding a spilled by-ref
  ## aggregate's incoming pointer.
  g.plan.hasStackVars = true
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.ptrType: g.emTypeSym(typeSym)
  g.ab.close()

proc emitSyprocA64*(g: var CodeGen; sp: SyscallProc) =
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

proc emRegLocalVar*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## `(var :name (reg) type)` + bind `r` to `name` for its scope. arkham keeps
  ## scalars 64-bit in registers (width/signedness via explicit extends), so an
  ## int/uint/bool/char local is declared `(i 64)`; a pointer keeps `(ptr T)`.
  ##
  ## No prior `(kill …)`: binding a register ENDS whatever binding it had, and a
  ## register `(var …)` is a binding — the same rule `(rebind …)` follows, which is
  ## why `emFRegLocalVar` below could always spell itself that way. If `r` still
  ## holds an earlier, now-dead local (the allocator early-freed it at its last use
  ## and reassigned the register here), this declaration evicts it.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r
  let rt = resolveType(g.prog, typeCur)
  let isPtr = isPtrType(rt)
  # The local's OWN type — `(u 8)` stays `(u 8)`. arkham still keeps every scalar
  # 64-bit-wide in the register and normalizes with explicit extends; the declared
  # type is what the VARIABLE is, and a register operand's type never reaches the
  # encoder (nifasm's `movTypeOk`), so it costs nothing and makes a wide value
  # landing in a narrow local without its extend an error rather than an invisible
  # truncation. This used to flatten every non-pointer to `(i 64)`.
  var tc = typeCur
  g.genTypeBody(tc)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr)

proc emFRegLocalVar*(g: var CodeGen; name: string; f: FReg; bits: int) =
  ## Declare a float register local `(var :name (dN|sN) (f B))` and bind v-register
  ## `f` to `name` for the rest of its scope, so subsequent uses emit the typed name
  ## instead of a raw `(dN)`/`(sN)`. The SIMD twin of `emRegLocalVar`, and now spelled
  ## the same way: this used to be a `(rebind …)` purely because a declaration REFUSED
  ## a still-bound register while a rebind evicted it. Both evict now.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.freg(f, bits)
  g.ab.floatType(bits)
  g.ab.close()
  g.rb.bindFLocal(f, name)
  g.freeFTmp.excl f                             # a local's home is no longer scratch

proc enterScope*(g: var CodeGen) =
  g.rb.enterScope()

proc exitScope*(g: var CodeGen) =
  ## Skip any local whose register was already rebound to a later one (already
  ## killed at that rebind via emRegLocalVar).
  let dead = g.rb.exitScope()
  for name in dead.gprs:
    g.ab.tree KillA64: g.ab.sym name
  for name in dead.fprs:
    g.ab.tree KillA64: g.ab.sym name

proc computeFrame*(g: var CodeGen; hasCall: bool) =
  g.frameRegs = @[]
  for r in g.md.intCalleeSaved:
    if r in g.plan.usedCallee: g.frameRegs.add r
  if g.md.frameStyle == PairFrame and g.frameRegs.len mod 2 == 1:   # saved in PAIRS → pad
    # The FILLER comes from the ABI list, not from `intCalleeSaved`: it is a slot
    # in an `stp`, not a home, so it need not be a register the allocator would
    # hand out — and under `-d:arkhamStress` the allocator's pool can be smaller
    # than the set already saved, leaving nothing to pad WITH and `framePush`
    # walking off the end of an odd-length list.
    for r in g.md.abiCalleeSaved:
      if r notin g.frameRegs: (g.frameRegs.add r; break)
  if g.isInterrupt:
    # A trap arrives on top of arbitrary code and NOTHING was stacked for it, so
    # what an ordinary proc may destroy freely is exactly what a handler may not.
    # `convClobbersGpr` is that set — the ABI's own answer to "what does a call
    # destroy" — and saving all of it is the only description that does not
    # require knowing which registers the body and the emitter between them
    # happened to touch. `linkReg` is already word 0 of the block.
    for r in g.md.convClobbersGpr:
      if r != g.md.linkReg and r notin g.frameRegs: g.frameRegs.add r
  g.frameFRegs = @[]
  for f in g.md.floatCalleeSaved:
    if f in g.plan.usedCalleeF: g.frameFRegs.add f
  if g.md.frameStyle == PairFrame and g.frameFRegs.len mod 2 == 1:  # pad SIMD saves too
    for f in g.md.abiFloatCalleeSaved:            # the ABI list, as above
      if f notin g.plan.usedCalleeF: (g.frameFRegs.add f; break)
  # Stack-passed parameters are addressed off the FRAME POINTER (see `framePush`),
  # so a proc that has them needs the fp/lr pair pushed even if nothing else forces
  # a frame — a leaf with more arguments than registers is exactly that shape.
  g.hasFrame = hasCall or g.frameRegs.len > 0 or g.frameFRegs.len > 0 or
               g.plan.hasStackParams
  if g.md.frameStyle == BlockFrame and g.plan.hasStackParams:
    # `emIncomingArgBase` reads the caller's SP as `sp + (ssize) + pushes`, which
    # is only true if that `sub sp, (ssize)` was actually emitted. Force it; when
    # the frame is empty it is a `sub sp, #0`.
    g.plan.hasStackVars = true

proc emIncomingArgBase(g: var CodeGen; dest: Reg) =
  ## `dest ← the SP the caller entered this proc with` — the base nifasm numbers
  ## the incoming stack arguments from (parameter `k` at byte offset `k`'s
  ## `alignedSize` sum, starting at 0).
  ##
  ## A `PairFrame` keeps that address in the frame pointer for the whole body. A
  ## `BlockFrame` has no register to spare for one — Cortex-M has four allocatable
  ## homes, and r8/r9/r10/r11 already have jobs — so it is RE-DERIVED at each of
  ## the handful of prologue sites that need it: the current SP, plus the frame
  ## nifasm sized (`(ssize)`), plus the bytes this backend's own prologue pushed.
  ## That is only correct AFTER both subs have run, which is why a `BlockFrame`
  ## target's stack-parameter loads live in the prologue rather than at the top
  ## of the body.
  g.ab.tree Add3A64:
    g.emReg dest
    g.ab.rawReg SP
    g.ab.tree SsizeX: g.ab.intLit int64(g.framePushBytes)

proc emIncomingArgMem(g: var CodeGen; base: Reg; byteOff: int) =
  ## The memory operand of the incoming stack argument at `byteOff`.
  if g.md.frameStyle == BlockFrame:
    g.ab.tree MemX: (g.emReg base; g.ab.intLit int64(byteOff))
  else:
    g.ab.tree MemX: (g.ab.rawReg g.md.framePtrReg; g.ab.intLit int64(StackArgFpBias + byteOff))

proc emLoadIncomingArg(g: var CodeGen; dest: Reg; byteOff: int) =
  ## `dest ← [incoming stack argument area + byteOff]`.
  if g.md.frameStyle == BlockFrame:
    let b = g.takeBridge(avoid = dest)
    g.emIncomingArgBase(b)
    g.ab.tree MovA64: (g.emReg dest; g.emIncomingArgMem(b, byteOff))
    g.dropBridge b
  else:
    g.ab.tree MovA64: (g.emReg dest; g.emIncomingArgMem(NoReg, byteOff))

proc emLeaIncomingArg(g: var CodeGen; dest: Reg; byteOff: int) =
  ## `dest ← &(incoming stack argument area + byteOff)`.
  if g.md.frameStyle == BlockFrame:
    g.emIncomingArgBase(dest)
    if byteOff != 0:
      g.ab.tree AddA64: (g.emReg dest; g.ab.intLit int64(byteOff))
  else:
    g.ab.tree LeaA64: (g.emReg dest; g.emIncomingArgMem(NoReg, byteOff))

proc bridgeStackParam(g: var CodeGen; slotName: string; byteOff: int; typ: AsmSlot) =
  ## `[slotName] <- [fp + StackArgFpBias + byteOff]`, through a transient GPR: AArch64 has
  ## no memory-to-memory move, so a stack-passed parameter whose home is a stack slot
  ## has to be bridged. The bridge is BOUND (`bindTemp`) for its two instructions —
  ## `emReg` refuses a raw scratch-pool register, which is the invariant that keeps an
  ## unbound temp from being silently clobbered — and released immediately after.
  if g.md.frameStyle == BlockFrame:
    # A STAGING pick would be fatal here. A `BlockFrame` emits these loads from
    # the prologue (that is where the incoming-argument base is legible), and the
    # prologue is written AFTER `computeFrame` has frozen `usedCallee` — so a
    # callee-saved register taken now would be used without being saved, and the
    # caller's value in it destroyed. The bridges are in no pool and need no
    # save, which is exactly why they exist.
    let base = g.takeBridge()
    let v = g.takeBridge(typ, avoid = base)
    g.emIncomingArgBase(base)
    g.ab.tree MovA64: (g.emReg v; g.emIncomingArgMem(base, byteOff))
    g.emScalarStore(slotName, v)
    g.dropBridge v
    g.dropBridge base
    return
  let s = g.pickStagingA64()
  if s == NoReg:
    raiseAssert "arkham a64: no register to bridge stack parameter " & slotName &
                " in proc " & g.curProcName
  g.pickedRegs.incl s
  g.bindTemp(s, typ)
  g.emLoadIncomingArg(s, byteOff)
  g.emScalarStore(slotName, s)
  g.unbindTemp(s)
  g.pickedRegs.excl s

proc emitStackParamLoads*(g: var CodeGen; decl: Cursor) =
  ## Bring in the parameters AAPCS64 passed on the stack (the 9th integer/pointer
  ## argument onward) from the caller's outgoing argument area.
  ##
  ## Addressed off the FRAME POINTER, which `framePush` set to the incoming-args base
  ## (`StackArgFpBias`), and emitted into the BODY buffer — after `emitParamMoves`,
  ## before any body statement. It used to be written into the prologue, addressing
  ## `[sp + …]`
  ## directly because the base was still SP-relative there; that is why it could only
  ## ever fill a REGISTER home, and asserted on anything else. A parameter whose home
  ## is a stack slot has to be STORED to that slot, and the slot only exists after the
  ## prologue's `sub sp` — which the prologue position could not express, so
  ## `emitParamMoves` met the same parameter with no register to move from and died
  ## with ">8 integer params (stack TODO)". `deps.wantTool` is the shape that reaches
  ## it in the compiler itself: four `string` parameters are two eightbytes apiece, so
  ## they consume x0-x7 outright and all four `var Table` pointers land on the stack.
  ##
  ## Every home kind the allocator can choose is handled here, matching the x64 twin:
  ## a register home, a spilled scalar's `(s)` slot, a spilled by-ref aggregate's
  ## `(ptr T)` slot, and a by-value aggregate passed whole on the stack (whose home is
  ## a POINTER to the incoming bytes — no copy).
  if not g.plan.hasStackParams: return
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # (params) is `.` → no parameters
  # THE plan (see abi.nim): which params are stack-passed and at what byte offset
  # within the incoming-arg area — the same answer the signature and the caller got.
  let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
  var pIdx = 0
  c.into:
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
      var nm = ""
      var tn = NoTypeSym
      var typeCur: Cursor
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        typeCur = c
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = c.symId
        while c.hasMore: skip c               # type (+ anything else)
      if not pl.onStack: continue
      if pl.isFloat:
        # `emitParamMoves` skips every stack-passed parameter, so if this one is
        # skipped here too it is silently never loaded. Say so instead.
        lengError decl, "arkham: a stack-passed FLOAT parameter (`" & nm &
                  "`) is not supported yet", lengInfo(decl)
      let loc = g.plan.homeOfSym(nm)
      if g.isWideType(typeCur):
        # A stack-passed 64-bit parameter: eight bytes of the incoming area into
        # the slot the allocator gave it (a scalar wider than a register never
        # gets a register home).
        if loc.kind != NamedStack:
          raiseAssert "arkham cortex-m: stack-passed 64-bit parameter " & nm &
                      " homed in " & $loc.kind
        g.emTypedStackVar(nm, typeCur)
        let b = g.takeBridge()
        let v = g.takeBridge(avoid = b)
        g.emIncomingArgBase(b)
        for k in 0 .. 1:
          g.ab.tree MovA64: (g.emReg v; g.emIncomingArgMem(b, pl.byteOff + 4 * k))
          g.ab.tree MovA64:
            g.ab.tree CastX:
              g.ab.uintType(32)
              g.ab.tree MemX: (g.ab.sym nm; g.ab.intLit int64(4 * k))
            g.emReg v
        g.dropBridge v
        g.dropBridge b
        continue
      if pl.isAgg and not pl.byRef:
        # A ≤16B by-value aggregate that went entirely on the stack. The incoming bytes
        # are the callee's own copy, so where the home is a POINTER nothing needs
        # moving — point it at them and let field reads go straight there.
        g.varType[nm] = tn
        case loc.kind
        of InReg:
          g.emLeaIncomingArg(loc.r, pl.byteOff)          # home ← base + byteOff
        of InRegPair:
          # The aggregate lives IN a register pair (the ABI eightbytes ARE the
          # fields): load each eightbyte straight into its word register.
          for k in 0 ..< pl.words:
            g.emLoadIncomingArg(pairWord(loc, k), pl.byteOff + k * wordSize())
        of NamedStack:
          # The allocator gave it a real `(s)` slot: declare it and copy the incoming
          # eightbytes across, one reused value register at a time (as x64's twin does)
          # rather than a held register per word.
          g.emStackVar(nm, tn)
          if g.md.frameStyle == BlockFrame:
            # Two bridges is all this target has, and the incoming-argument base
            # takes one — so the destination is addressed by SLOT NAME rather
            # than through a third register holding its address.
            let base = g.takeBridge()
            let v = g.takeBridge(avoid = base)
            g.emIncomingArgBase(base)
            for k in 0 ..< pl.words:
              g.ab.tree MovA64:
                g.emReg v
                g.emIncomingArgMem(base, pl.byteOff + k * wordSize())
              g.ab.tree MovA64:
                g.ab.tree CastX:
                  g.ab.uintType(wordBits())
                  g.ab.tree MemX: (g.ab.sym nm; g.ab.intLit int64(k * wordSize()))
                g.emReg v
            g.dropBridge v
            g.dropBridge base
            continue
          let homeAddr = g.takeBridge()
          g.ab.tree LeaA64: (g.emReg homeAddr; g.ab.sym nm)
          let v = g.takeBridge(avoid = homeAddr)
          for k in 0 ..< pl.words:
            g.emLoadIncomingArg(v, pl.byteOff + k * wordSize())   # v ← incoming word k
            g.ab.tree MovA64:                 # home word k ← v
              g.emWordThroughPtr(homeAddr, k)
              g.emReg v
          g.dropBridge v
          g.dropBridge homeAddr
        of StackPtr:
          # The pointer at the incoming bytes found no register home either: give it
          # its `(ptr T)` slot and store the computed address there. Same no-copy
          # deal as `InReg`, one indirection further out.
          g.emByRefPtrStackVar(nm, tn)
          let a = g.takeBridge()
          g.emLeaIncomingArg(a, pl.byteOff)   # a ← base + byteOff
          g.emScalarStore(loc.ptrName, a)
          g.dropBridge a
        else:
          raiseAssert "arkham a64: stack-passed by-value aggregate home " &
                      $loc.kind & ": " & nm & " in " & g.curProcName
        continue
      case loc.kind
      of InReg:
        g.emLoadIncomingArg(loc.r, pl.byteOff)           # home ← [base + byteOff]
      of NamedStack:
        # A spilled / address-taken scalar: declare its `(s)` slot before filling it,
        # or the store — and every later body reference — names a slot nifasm never
        # saw. The register-passed twin declares it in `emitParamMoves`.
        g.emTypedStackVar(nm, typeCur)
        g.bridgeStackParam(nm, pl.byteOff, loc.typ)
      of StackPtr:
        # A >16B by-ref aggregate whose incoming POINTER found no register home: the
        # eightbyte on the stack IS the pointer, so both the bridge and the slot are
        # pointer-width — `loc.typ` describes what it points AT, not the slot.
        g.varType[nm] = tn
        g.emByRefPtrStackVar(nm, tn)
        g.bridgeStackParam(loc.ptrName, pl.byteOff, ScalarSlot)  # the eightbyte IS the pointer
      else:
        raiseAssert "arkham a64: stack parameter home " & $loc.kind & ": " & nm

proc emitParamMoves*(g: var CodeGen; decl: Cursor) =
  ## Move each parameter from its incoming ABI register to the home the
  ## allocator chose (callee-saved for cross-call params; arg regs stay put for
  ## leaf procs). Emitted after the prologue saved the homes. Stack-passed params
  ## (9th integer arg onward) are loaded separately by `emitStackParamLoads` and
  ## skipped here.
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # (params) is `.` → no parameters
  # THE plan (see abi.nim): register indices below read it — no local counting.
  let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
  var pIdx = 0
  c.into:                                     # into (params …)
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
      var nm = ""
      var tn = NoTypeSym
      var typeCur: Cursor
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        typeCur = c
        g.symType[nm] = typeCur               # record the param's type for getType
        # Only true aggregates get a `varType` entry; a named *enum* (or scalar
        # typedef), local or cross-module, resolves to a scalar and stays in the
        # register path. `slotOf` loads a foreign module if the type lives there.
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = c.symId
        while c.hasMore: skip c               # type (+ anything else)
      let loc = g.plan.homeOfSym(nm)
      # A PARAMETER's home register, stated where the claim is made rather than
      # inferred from a pool it happens not to be in (design.md, "Fixed-register
      # roles must be stated, not assumed" — the same rule the atomics broke).
      #
      # `takeHeld`'s second chance and `pickStagingA64` judge a callee-saved register
      # by `rb.isBound`, deliberately bypassing the whole-proc `regHoldsHome` union
      # because it is too conservative for an ordinary local (disjoint scopes). A
      # plain scalar/pointer parameter is moved into its home with a raw `mov` and
      # read raw after that — it is never `rb`-bound — so it was invisible to that
      # test and those draws handed it out from under a live value.
      #
      # Measured in `nifconfig.isDefined` on a `-d:release` native build: the
      # `config` pointer reads `cpu=15 os=4` at entry and `cpu=0 os=0` three
      # conditions later, and the run dies in `platform.OS[targetOS]` with
      # "index out of bounds: 0 notin 1..34". x64 reserves its own unnamed homes the
      # same way and for the same reason; this is a64 catching up.
      case loc.kind
      of InReg: g.rawHomeRegs.incl loc.r
      of InRegPair:
        g.rawHomeRegs.incl loc.r0
        g.rawHomeRegs.incl loc.r1
      else: discard
      if pl.onStack:
        # Loaded from the incoming argument area by `emitStackParamLoads`, which
        # also declares the slot. Reaching the arms below would use `gprAt(pl)`,
        # and a stack-passed place has no register — `gpFirst` is 0 — so the
        # "move" would store argument ZERO's register over the value that was
        # just loaded correctly. (It takes more than eight parameters to see this
        # on AArch64, which is why it stayed hidden; Cortex-M has four argument
        # registers.) The bookkeeping above still has to run: it is about where
        # the parameter LIVES, not about how it got there.
        if tn != NoTypeSym: g.varType[nm] = tn
        continue
      if tn != NoTypeSym and loc.kind == StackPtr:
        # A >16B by-ref aggregate whose POINTER found no register home: its slot is
        # `(ptr T)`, filled from the incoming arg register. (The home's KIND says the
        # slot holds an address — formerly this asked the ABI plan's `pl.byRef` while
        # every reader asked `spilledByRefPtr`, two answers to one question.)
        g.varType[nm] = tn
        g.emByRefPtrStackVar(nm, tn)
        g.emScalarStore(nm, g.md.gprAt(pl))
      elif tn != NoTypeSym and loc.kind == NamedStack:
        # A register-passed ≤16B by-value aggregate that could not stay in a GPR pair:
        # its slot IS the struct, filled word by word from the arg registers.
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        g.regsToStruct(nm, tn, pl.gpFirst)
      elif tn != NoTypeSym and loc.kind == InRegPair:
        # ≤16B by-value aggregate kept in GPRs (the ABI eightbytes ARE the fields).
        g.varType[nm] = tn
        for k in 0 ..< pl.words:
          let home = pairWord(loc, k)
          let arg = g.md.gprAt(pl, k)
          if home != arg: g.movReg(home, arg)
      elif tn != NoTypeSym and loc.kind == InReg:
        # A pointer-homed aggregate: a >16B by-reference one, OR a stack-passed ≤16B
        # by-value one (whose home is a pointer to its incoming bytes). Field accesses
        # route through the pointer (recorded in varType). Register-passed → move the
        # pointer from its incoming arg register; STACK-passed → `emitStackParamLoads`
        # already loaded/computed the pointer into the home, and the param consumed
        # NO register (the plan's skip rule), so there is nothing to move.
        g.varType[nm] = tn
        if not pl.onStack:
          g.movReg(loc.r, g.md.gprAt(pl))
      elif g.isWideType(typeCur):
        # A 64-bit parameter. Its home is ALWAYS a stack slot — a scalar wider
        # than a register fails `inRegClass`, so the allocator never offers one
        # — and it is filled from the two consecutive incoming argument
        # registers the shared `CallPlan` assigned. A stack-PASSED one is left
        # to `emitStackParamLoads`, which is where the incoming area is legible.
        if loc.kind != NamedStack:
          raiseAssert "arkham cortex-m: 64-bit parameter " & nm & " homed in " &
                      $loc.kind
        if not pl.onStack:
          g.emTypedStackVar(nm, typeCur)
          g.wideParamToHome(nm, pl.gpFirst)
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming v{fpIndex}; if
        # the allocator gave it a callee-saved home, move it there. A STACK-passed
        # float has no `v{fpIndex}` to read — `FloatArgRegs[pl.fpIndex]` would name
        # another parameter's register and silently move the wrong value, so say so
        # instead. (>8 float params; the integer side is handled above.)
        assert not pl.onStack, "arkham v1: >8 float params (stack TODO): " & nm &
          " in " & g.curProcName
        g.fmovF(loc.f, g.md.floatArgRegs[pl.fpIndex], loc.typ.size * 8)
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming SIMD arg register into it so `addr`/loads/stores work.
        assert not pl.onStack, "arkham v1: >8 float params (stack TODO): " & nm &
          " in " & g.curProcName
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, g.md.floatArgRegs[pl.fpIndex], bits)
      elif loc.kind == NamedStack:
        # An address-taken scalar param: declare its `(s)` slot and spill the
        # incoming argument register into it so `addr`/loads/stores work. The slot
        # carries the PARAMETER's type (as on x64), so a narrow one is stored and
        # reloaded at its own width instead of as a raw 64-bit cell.
        g.emTypedStackVar(nm, typeCur)
        g.emScalarStore(nm, g.md.gprAt(pl))
      else:
        case loc.kind
        of InReg:
          g.movReg(loc.r, g.md.gprAt(pl))
        else: raiseAssert "arkham v1: stack-resident parameter: " & nm

proc emitSignature*(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## Emit the proc's `(params)/(result)/(clobber)`. When `declarative`, the ABI
  ## is stated explicitly — positional `p{i}` register params and an `x0` result
  ## — so nifasm cross-checks every call site; otherwise both stay empty and
  ## arkham marshals by hand (floats/aggregates/by-ref/>8/named types). The
  ## clobber set is always the convention's, derived here (never per-proc
  ## precomputed), which is reliable across modules.
  if declarative:
    var c = decl
    c.into:
      inc c                                   # name → params slot
      # A >16B by-reference aggregate RESULT travels through the AAPCS64 indirect-result
      # register x8 (set by the caller, moved to a callee-saved home in the prologue) —
      # NOT through a signature param, unlike x86-64's hidden-pointer-in-rdi. So the
      # result slot is just empty; x8 is handled raw on both sides.
      var retC = c
      skip retC                               # params slot → return type
      var retByRef = false
      if not retIsVoid(retC):
        let rs = slotOf(g.prog, retC)
        retByRef = rs.kind == AMem and rs.size > 2 * wordSize()
      g.ab.tree ParamsD:
        if c.kind == TagLit:                  # (params (param …) …)
          # THE plan (see abi.nim); AArch64's hidden result pointer is x8, off the
          # argument file, so the plan is never shifted (retByRef=false).
          let plan = planCall(g.md, paramSlots(g.prog, c), retByRef = false)
          var pIdx = 0
          c.into:
            while c.hasMore:
              let pl = plan.args[pIdx]
              inc pIdx
              c.into:                         # (param :name pragmas type)
                inc c                         # name → use positional p{ord}
                skip c                        # pragmas
                if pl.isFloat:
                  raiseAssert "arkham a64: float param in signature not yet supported"
                if pl.isWideScalar:
                  # A scalar too wide for one register (`(i 64)` on Cortex-M).
                  # `(regs …)` is the SAME location form a multi-word aggregate
                  # uses, and for the same reason: the halves have no Leng type
                  # of their own, so the param is ABI-only and the body reads
                  # `(arg pN k)`.
                  g.ab.tree ParamD:
                    g.ab.symDef paramName(pl.ord)
                    if pl.onStack:
                      g.ab.keyword SO
                    else:
                      g.ab.tree RegsD:
                        for k in 0 ..< pl.words: g.ab.rawReg g.md.gprAt(pl, k)
                    g.genTypeBody(c)
                elif pl.isAgg:
                  # An aggregate param: a >16B aggregate is a by-ref pointer in one x-reg;
                  # a ≤16B by-value aggregate spans `pl.words` consecutive x-regs (one per
                  # eightbyte). Emitted with `(regs …)` (ABI-only); `(arg pN k)` at a call
                  # selects word k. The body reads the registers raw into its own home.
                  if pl.onStack:
                    # Doesn't fit the remaining arg registers → stack-passed `(s)`. A >16B
                    # aggregate travels as ONE pointer (`(s) (ptr T)`, 8 bytes); a ≤16B
                    # by-value one occupies its eightbytes (`(s) T`). The plan's skip rule:
                    # a later smaller param can still take a free register.
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.keyword SO
                      if pl.byRef:
                        g.ab.ptrType: g.genTypeBody(c)
                      else:
                        g.genTypeBody(c)
                  else:
                    g.ab.tree ParamD:
                      g.ab.symDef paramName(pl.ord)
                      g.ab.tree RegsD:
                        for k in 0 ..< pl.words: g.ab.rawReg g.md.gprAt(pl, k)
                      if pl.byRef:
                        g.ab.ptrType: g.genTypeBody(c)
                      else:
                        g.genTypeBody(c)
                else:
                  g.ab.tree ParamD:
                    g.ab.symDef paramName(pl.ord)
                    if not pl.onStack:
                      g.ab.rawReg g.md.gprAt(pl)   # x0–x7: raw reg *location*
                    else:
                      g.ab.keyword SO           # 9th+ → stack-passed `(s)`
                    g.genTypeBody(c)            # the param type (consumes it)
                while c.hasMore: skip c
        else:
          skip c                              # no params slot → consume it
      g.ab.tree ResultD:                      # c now at the return type
        if retIsVoid(c) or retByRef:
          skip c                              # void, or returned via the x8 indirect pointer
        else:
          let rs = slotOf(g.prog, c)
          if rs.kind == AFloat:
            raiseAssert "arkham a64: float result in signature not yet supported"
          if g.isWideSlot(rs):
            # A 64-bit result travels in r0:r1 with an EMPTY result slot, exactly
            # as a two-word aggregate does: nifasm's `(ret …)` names ONE register,
            # and declaring only the low half is how a truncated return would look
            # legal. Both sides read the pair raw instead.
            skip c
          elif rs.kind == AMem:
            # A ≤16B by-value aggregate result travels in x0:x1 with an EMPTY result slot
            # (like a >16B by-ref result via x8): the callee marshals it into x0:x1 (the
            # body's `structToRegs`) and the caller reads those raw after the call — no
            # `(res ret.0)` binding to declare here (mirrors the x64 rax:rdx result).
            skip c
          else:
            g.ab.symDef synth("ret.0")
            g.ab.rawReg g.md.intRetReg                   # raw reg *location* of the result
            g.genTypeBody(c)                  # the result type (consumes it)
      while c.hasMore: skip c                 # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  g.ab.tree ClobberD:
    # A diverging callee returns to nobody, so no caller can observe what it
    # destroyed — declaring clobbers only forces every proc with a cold guard onto
    # callee-saved homes. See the x64 twin in `emitSignature`.
    if not declIsNoReturn(decl):
      g.emConvClobbers()

proc storeFReg2(g: var CodeGen; dst: Location; src: FReg; bits: int) =
  case dst.kind
  of InFReg: g.fmovF(dst.f, src, bits)
  of NamedStack: g.emFloatScalarStore(dst.name, src, bits)
  of Glob:
    let b = g.takeBridge(); g.emAdr(b, g.prog.gvarRefName(dst.name))
    g.emFStore(src, b, bits); g.dropBridge b
  of Mem:
    g.prematLval2(dst.cur)
    g.ab.tree FstrA64:
      g.ab.tree MemX: g.emLvalAddr2(dst.cur)
      g.emFReg(src, bits)
    g.unbindLvalTemps2(dst.cur)
  else: raiseAssert "arkham a64n: storeFReg2 dst " & $dst.kind

proc copyStructThroughPtr2*(g: var CodeGen; srcVar: string; typeSym: SymId; ptrReg: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at (the >16B aggregate hidden-result-
  ## pointer return). This runs at the `ret` and crosses NO call, so both scratch
  ## registers it needs — the source address and the word-transfer temp — come from the
  ## two staging bridges, never an allocator-reserved callee-saved survivor (mirrors the
  ## x64 `pickStagingSealed` pair). Leas the source's address into one bridge and funnels
  ## through the one `copyAggr` with the other bridge as the word temp.
  let sp = g.takeBridge()
  let home = g.plan.homeOfSym(srcVar)
  if home.kind == InReg: g.movReg(sp, home.r)
  elif home.kind == StackPtr: g.emScalarLoad(sp, home.ptrName)
  else:
    g.ab.tree LeaA64: (g.emReg sp; g.ab.sym srcVar)        # sp = &srcVar
  let tmp = g.takeBridge(avoid = sp)
  g.copyAggr(ptrReg, sp, aggrByteSize(g.prog, typeSym), tmp)
  g.dropBridge tmp
  g.dropBridge sp

proc isWideType(g: var CodeGen; t: Cursor): bool {.inline.} =
  g.isWideSlot(slotOf(g.prog, t))

proc wideParamToHome(g: var CodeGen; nm: string; firstArg: int) =
  ## The callee side: the two incoming argument registers into the parameter's
  ## stack home. (Its slot was declared by the caller of this proc.)
  let home = slotWide(nm)
  g.wideStore(home, 0, g.md.intArgRegs[firstArg])
  g.wideStore(home, 1, g.md.intArgRegs[firstArg + 1])
