#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## The x86-64 emitter's primitives — the layer everything above is written in.
##
## Three things live here that are easy to mistake for three modules: the
## scratch pools (which register may hold a transient right now), the
## register-BINDING calls that tell nifasm a physical register now carries a
## named, typed local, and the type shapes nifasm needs declared before it will
## accept either. They are one module because they call each other: a `mov`
## between two registers has to re-declare the destination's type, which is type
## emission; and choosing a staging register has to know what is bound, which is
## the binding table.
##
## Also here: the condition-code tables (which `jcc` means "true", how to mirror
## or invert one), because they are pure lookup and everything branch-shaped
## needs them.

import std / [assertions, tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    stress, context, typeutil, 
                    mirrors, temps, exprpred, regbind, abi, bridges]
import machine as machine_x64

const FloatRet* = F0    # xmm0: SysV scalar-float return + first float argument

const StagingCandidates* = [R11, RAX, RDI, RSI, RDX, RCX, R8, R9]
  ## Registers `pickStagingScratch` may hand out as a transient compute register for a
  ## spill / mem←mem bridge. R11 is FIRST and is the RESERVED bridge: it is kept out of
  ## the allocator's temp pool (`intTempRegs`), so it is never a live local/temp home —
  ## always pickable. The ABI caller-saved regs follow as extra staging slots for nested
  ## staging (each guarded by `liveAccums`/`regHoldsLiveLocal`/`sealed` so a live value
  ## is never hit).
  ##
  ## MEASURED DEMAND IS **THREE** in 1 % of procs and two in 17 % (see design.md,
  ## "How many registers the emitter actually needs" — `-d:arkhamStagingDbg` counts
  ## it), and R11 is the only one of these that is GUARANTEED —
  ## see design.md, "How many registers the emitter actually needs". Every step that
  ## must hold an ADDRESS in a register while a VALUE passes through another wants two:
  ## a load through a materialized global base, an `(at …)` stride fold, an aggregate
  ## copy word between computed ends, a `casejmp` base, an atomic row that claims R11
  ## as its own `work` register, a chain of spilled pointer loads at ANY depth
  ## (`tests/arkham/addr_chain_depth`). No step in the corpus wants three.
  ##
  ## So the second one is luck — an ABI volatile that happens to be free, or the
  ## callee-saved backstop below. Closing that gap needs a register taken from the
  ## allocator, and on x86-64 there is none going spare: R9 was tried and is a live
  ## PARAMETER home in any proc with six integer parameters.

const FloatStagingBridge* = F15
  ## The reserved float staging bridge — kept out of `floatTempRegs` so it is always
  ## free for `pickFStaging` to hand out, making `produceIntoFMem2` total (the SIMD
  ## twin of R11 in `StagingCandidates`).

const x64RetRegs* = [RAX, RDX]   # SysV ≤16B aggregate result: rax (word 0), rdx (word 1)

type AggrEnd* = object
  ## One end (source or destination) of a whole-aggregate copy, in the form the MACHINE
  ## can actually address it:
  ##   * a NAMED rsp-relative `(s)` slot — costs ZERO registers, each word addressed as
  ##     `(mem (rsp) slot off)`;
  ##   * an address already materialized in a register — costs one.
  ## Making the form explicit is what TIERS the copy's register demand: a copy between
  ## two named slots needs only the transfer register, one named end needs two, and only
  ## a copy between two computed addresses needs the three that used to be demanded
  ## unconditionally. That last tier is what exhausted the emit-time staging pool under
  ## `-d:danger` (every volatile hosting a call-free local), and it is now rare rather
  ## than universal.
  slot*: string        ## non-empty ⇒ an rsp-relative named slot
  reg*: Reg            ## else, the register holding the aggregate's address

template AddrSlot*(): AsmSlot = addrSlot()
  ## A template, not a `let`: a module-level `let` is evaluated at module INIT,
  ## before any backend has called `setTargetWord`, so it would snapshot whatever
  ## the default happened to be. Harmless while x86-64 is the only user and the
  ## default is already 64-bit — and exactly the kind of thing that stops being
  ## harmless the day a second word size shares the file.
  ## The binding type for a staging register that holds a raw machine address / word
  ## (a pointer the consumer always `(cast (aptr T) …)`s before dereferencing, or a
  ## whole eightbyte copied verbatim). A well-typed `(u 64)` — NOT an untyped escape:
  ## nifasm still tracks the register and rejects a raw reuse; the cast supplies the
  ## element type at the point of the actual load/store.


proc slotEnd*(name: string): AggrEnd {.inline.} = AggrEnd(slot: name, reg: NoReg)
proc regEnd*(r: Reg): AggrEnd {.inline.} = AggrEnd(slot: "", reg: r)

proc genTypeBody*(g: var CodeGen; c: var Cursor)

proc releaseStaleName*(g: var CodeGen; r: Reg)

proc unbindTemp*(g: var CodeGen; r: Reg)

proc liveStaging*(g: CodeGen): int {.inline.} =
  ## How many transients the emitter is holding right now — this step's and every
  ## enclosing one's. x86-64's counterpart of the RISC `liveBridges`.
  card(g.stagingHeld)

const StagingGuaranteed* = 1
  ## What x86-64 promises REGARDLESS of what the allocator did: R11, kept out of
  ## `intTempRegs` so it is never a local's home. Everything else in
  ## `StagingCandidates` is opportunistic.
  ##
  ## design.md: "On x86-64, only one of the two is guaranteed... Closing it means
  ## taking a register from the allocator, and nothing is going spare... that is a
  ## measurement to make, not a decision to take from the register file's shape."
  ## `tightCompositions` is that measurement — it counts every step whose declared
  ## demand exceeded this number.

proc heldStagingNames*(g: CodeGen): string =
  for r in StagingCandidates:
    if r in g.stagingHeld:
      if result.len > 0: result.add ", "
      result.add x64RegName(r)

proc stagingNote*(g: var CodeGen; r: Reg; what: string) {.inline.} =
  ## Record that a staging register was handed out. The PEAK of this — how many
  ## transients the emitter ever holds AT ONCE — is the number that decides whether
  ## R11 can leave `StagingCandidates`: the reservation exists so that a pick can
  ## never fail, and the allocator can only take over that guarantee if it knows how
  ## many to reserve. `design.md` asserts the answer is two, from chibicc; this
  ## measures THIS emitter. Debug-only: the field does not exist otherwise.
  if r != NoReg: g.stagingHeld.incl r
  when defined(arkhamStagingDbg):
    if r != NoReg:
      g.stagingLive.add (r, what)
      if g.stagingLive.len > g.stagingPeak:
        g.stagingPeak = g.stagingLive.len
        var s = ""
        for it in g.stagingLive:
          if s.len > 0: s.add " + "
          s.add it[1]
        g.stagingPeakWhat = s
  else:
    discard

proc stagingRelease(g: var CodeGen; r: Reg) {.inline.} =
  g.stagingHeld.excl r
  when defined(arkhamStagingDbg):
    for i in countdown(g.stagingLive.high, 0):
      if g.stagingLive[i][0] == r:
        g.stagingLive.delete i
        return
  else:
    discard

proc giveBack*(g: var CodeGen; r: Reg) {.inline.} =
  ## Release a transient register obtained during premat / value evaluation. Its
  ## scratch binding (`bindTemp`) is `(kill)`'d first; then a staging register
  ## (caller-saved, sealed while it held an address/index so a sibling pick couldn't
  ## reuse it) is unsealed. Unbinding/unsealing a reg that carries neither is a
  ## harmless no-op.
  if r == NoReg: return
  g.stagingRelease(r)
  g.unbindTemp(r)
  g.plan.unseal {r}

proc emFReg*(g: var CodeGen; f: FReg) {.inline.} =
  ## A float value register operand. If `f` currently hosts a named float local /
  ## scratch temp, emit its *name* (a typed symbol nifasm checks); otherwise the raw
  ## `(xmmN)` tag. The SIMD twin of `emReg`: the xmm8–15 scratch pool is the only
  ## register class the allocator hands out for arbitrary computed floats, and every
  ## such hand-out — pool temp (`bindFTmp`) and register-local (`emFRegLocalVar`) —
  ## is bound, so a *raw* pool register reaching here is an unbound scratch slipping
  ## past the binder. The xmm0–7 arg/return/staging registers have structural raw
  ## uses (ABI float args, the float return, a spill's transient `pickFStaging`).
  let nm = g.rb.boundFName(f)
  if nm.len > 0: g.ab.sym nm
  else:
    assert f notin g.md.floatTempRegs,
      "arkham x64: unbound float scratch-pool register reached emFReg: xmm" & $ord(f)
    g.ab.xmmReg f

proc bindFTmp*(g: var CodeGen; f: FReg) =
  ## Give scratch xmm register `f` a typed nifasm name `ftmpN.0` via `(rebind …)`, so
  ## every later `emFReg f` emits a checked symbol the binding checker sees rather than
  ## a raw `(xmmN)`. The SIMD twin of `bindTemp`.
  ## The precision is a generic `(f 64)` — the operand carries no width to nifasm (the
  ## instruction tag selects movss/movsd), so the binding type is just a placeholder.
  let name = g.rb.freshFTmpName()
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.ab.floatType(64)
    g.ab.xmmReg f
  g.rb.bindFScratch(f, name)

proc unbindFTmp*(g: var CodeGen; f: FReg) =
  ## Release a scratch binding made by `bindFTmp`: `(kill)` the name and drop the
  ## binding. A no-op when `f` carries no temp binding. Also clears the fused
  ## core's reserve flag (see `unbindTemp`).
  g.pickedFRegs.excl f
  let dead = g.rb.takeFScratch(f)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead

proc fmovF*(g: var CodeGen; d, s: FReg; bits: int) =                # movss/movsd d, s
  if d == s: return
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fbin*(g: var CodeGen; op32, op64: X64Inst; d, s: FReg; bits: int) =  # d = d op s
  let op = if bits == 32: op32 else: op64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc emFcvt*(g: var CodeGen; d, s: FReg; dstBits, srcBits: int) =   # precision convert
  if dstBits == srcBits: (g.fmovF(d, s, dstBits); return)
  let op = if dstBits == 32: Cvtsd2ssX64 else: Cvtss2sdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc emFloatScalarLoad*(g: var CodeGen; dest: FReg; name: string; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.emFReg dest
    g.ab.tree MemX: g.ab.sym name

proc emFloatScalarStore*(g: var CodeGen; name: string; src: FReg; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.ab.tree MemX: g.ab.sym name
    g.emFReg src

proc flushArgResidentParams*(g: var CodeGen) =
  ## Called right after the FIRST call/syscall in a proc. Every `ArgResident` param
  ## (kept in its incoming arg register) is dead by now — the analyser guarantees it is
  ## never used after any call returns — and the call just clobbered its register. Kill
  ## the lingering `regLocal` name binding so a later RAW reuse of that arg register (an
  ## exit syscall, a fresh marshal) emits `(reg)` rather than the dead param's typed name
  ## (which would be a nifasm type mismatch, e.g. i32 argc reused as a 64-bit syscall arg).
  # Bindings `restoreBindings` re-established on caller-saved registers after a
  # DIVERGING call die here too, and unlike `argResidentParams` this drain is not
  # one-shot — a proc can have several panics, each restoring afresh.
  if g.postDivergeBinds.len > 0:
    for (r, name) in g.postDivergeBinds:
      if g.rb.takeBindingIf(r, name):
        g.ab.tree KillX64: g.ab.sym name
    g.postDivergeBinds.setLen 0
  if g.argResidentFlushed or g.argResidentParams.len == 0: return
  g.argResidentFlushed = true
  for (r, name) in g.argResidentParams:
    # Only kill if the register STILL holds this param. If it was rebound to a scratch
    # temp meanwhile (e.g. an indirect-call fn-ptr), that rebind already released the
    # param binding — killing the current tenant here would be a double / wrong kill.
    if g.rb.takeBindingIf(r, name):
      g.ab.tree KillX64: g.ab.sym name
  g.argResidentParams.setLen 0

proc releaseArgDest*(g: var CodeGen; r: Reg; valueSym: string) =
  ## An argument value is about to be MATERIALIZED into argument register `r`. Any name
  ## still bound to `r` is stale — the marshalling overwrites the register — and `emReg`
  ## would write the new value under that stale name, whose type generally does not admit
  ## it. THREE shapes reach here, all nifasm type errors:
  ##
  ## * an `ArgResident` param (one that kept its incoming arg register): its binding
  ##   carries the param's PRECISE ABI type, so `(mov p1.0 92)` into an `(i 8)` param is
  ##   rejected. This is exactly what `flushArgResidentParams` guards against — but that
  ##   flush only runs AFTER the first call, too late for that call's OWN arguments.
  ## * a leftover `bindTemp` scratch, e.g. the `(nil)`-typed binding a nil argument left
  ##   on an arg register: a later `(u 64)` word marshalled through it does not fit.
  ## * an ordinary register-homed LOCAL. `intLocalTempRegs` on x86-64 IS the argument
  ##   register set (rdi/rsi/r8/r9), so a call-free local routinely homes in one — e.g. a
  ##   `(ptr T)` local in rdi, then `(mov <that name> (mem …))` of an integer argument.
  ##   This shape is the reason the doc above used to say "two".
  ##
  ## All three are dead here by construction, and for the same reason: the allocator hands
  ## a caller-saved register to another value only when nothing live occupies it, and it
  ## homes a local in one only under `AllRegs` — the analyser's proof that the local's
  ## live range crosses NO call. This IS a call. So the value being built cannot read the
  ## bound name either, which is what makes killing it before `emitValue2` safe. Skipped
  ## when the value IS that symbol, which legitimately reads through the name.
  let bound = g.rb.boundName(r)
  if bound.len == 0 or bound == valueSym: return
  if g.rb.isBoundTemp(r):
    g.unbindTemp(r)                                 # kills the name, drops the binding
    return
  for i in 0 ..< g.argResidentParams.len:
    if g.argResidentParams[i].r == r and g.argResidentParams[i].name == bound:
      g.releaseStaleName(r)
      g.argResidentParams.del i
      return
  g.releaseStaleName(r)                             # a register-homed local, dead at a call

proc emLab*(g: var CodeGen; name: string) =
  ## THE control-flow invalidation point for the store-forwarding mirrors. What a
  ## register holds at a label does not follow from the instructions above it —
  ## some other path jumped here — so every mirror dies. Hooking it at the label
  ## DEFINITION rather than at each of `if`/`case`/`and`/`or`/cond-fusion is what
  ## makes this one line instead of a survey: arkham emits no merge point that is
  ## not a label. (The one exception is `(loop …)`, whose back edge nifasm emits
  ## internally — `emitLoop` clears there for the same reason.)
  g.killAllMirrors()
  g.ab.tree LabX64: g.ab.symDef name

proc emJmp*(g: var CodeGen; name: string) =
  g.ab.tree JmpX64: g.ab.sym name

proc emJcc*(g: var CodeGen; tag: X64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name

template emitLoop*(g: var CodeGen; body: untyped) =
  ## Structured infinite loop `(loop (stmts …))`: nifasm emits the back-edge INTERNALLY,
  ## so no backward `jmp` reaches the asm-NIF (keeps the "every jmp forward, back-edges
  ## are loops" invariant). `body` must jump FORWARD to a break/exit label defined AFTER
  ## the loop (a condition-false or `break` exit).
  ##
  ## The implicit back edge is why the mirrors are cleared here: the top of the body
  ## is a merge point with no label of its own, so nothing a register held before the
  ## loop may be assumed inside it.
  g.killAllMirrors()
  g.ab.tree LoopX64:
    g.ab.tree StmtsX64:
      body

proc freshLabel*(g: var CodeGen): string =
  result = synth("L") & $g.labelCount & ".0"
  inc g.labelCount

proc binArithOp*(c: Cursor): tuple[op: X64Inst, isBin: bool] =
  ## Map a binary-arith rvalue to its x86 opcode. `isBin = false` for div/mod
  ## (rax:rdx, no memory dest) and any non-arith expression.
  if c.kind != TagLit: return (AddX64, false)
  case c.exprKind
  of AddC: (AddX64, true)
  of SubC: (SubX64, true)
  of MulC: (ImulX64, true)
  of BitandC: (AndX64, true)
  of BitorC: (OrX64, true)
  of BitxorC: (XorX64, true)
  of ShlC: (ShlX64, true)
  of ShrC:
    var tc = c; inc tc                            # result-type child → signedness
    ((if isSignedType(tc): SarX64 else: ShrX64), true)
  else: (AddX64, false)

proc isDivergingCall*(g: CodeGen; c: Cursor): bool =
  if c.kind != TagLit: return false
  var fc = c
  inc fc                                     # → the callee
  result = fc.kind == Symbol and fc.symId in g.noReturnProcs

proc namedBindings*(g: CodeGen): seq[tuple[r: Reg, name: string]] =
  ## Every NAMED local/param binding (not a transient `bindTemp` scratch — that one
  ## belongs to an expression the diverging call is not inside of, and its
  ## `unbindTemp` is the emitter's own business).
  result = @[]
  for r, nm in g.rb.gprBindings():
    if not g.rb.isBoundTemp(r) and g.nameBindTyp.hasKey(nm):
      result.add (r: r, name: nm)

proc restoreBindings*(g: var CodeGen; saved: seq[tuple[r: Reg, name: string]]) =
  for it in saved:
    if g.rb.isBound(it.r): continue           # still ours, or legitimately re-let
    let bt = g.nameBindTyp[it.name]
    g.ab.tree RebindX64:                      # zero machine code: a naming directive
      g.ab.symDef it.name
      if bt.aggrSym != NoTypeSym:
        g.ab.ptrType: g.emTypeSym(bt.aggrSym)
      else:
        # The name's OWN type, pointer or not. Re-establishing a `(u 32)` param as
        # a flat `(i 64)` is what `emRegLocalVar` stopped doing at the declaration
        # and this had to stop doing at the restore: nifasm checks `mov` operand
        # types now, and `tagLitToken`'s `(mov `tmp12.0 `p1.0)` — a `(u 32)` param
        # read after a diverging `failVal` call — was rejected outright.
        var tc = bt.typ
        g.genTypeBody(tc)
      g.ab.rawReg it.r
    g.rb.rebindLocal(it.r, it.name, bt.isPtr)
    if it.r notin g.md.intCalleeSaved:
      # A caller-saved home: the name is good until a call that RETURNS clobbers the
      # register. Leaving it past that point is how a by-ref param homed in rdx ends up
      # renaming the SECOND RETURN WORD of a later call (`(mov (mem …) n.8)` where
      # arkham means rdx). `AllRegs` guarantees no returning call sits in the value's
      # live range, so killing it at the next one costs nothing.
      g.postDivergeBinds.add it

proc emTypedStackVar*(g: var CodeGen; name: string; t: Cursor) =
  ## `(var :name (s) T)` with `T` the value's actual Leng type. Use this (not the
  ## generic `(i 64)` slot) for a homed/spilled scalar whose type matters to
  ## nifasm — e.g. a pointer param that the body later derefs, where an `(i 64)`
  ## slot would both reject the typed store and forbid the deref (nifasm is strict).
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  if isNilValue(t):                          # a spilled nil → `(s) (nil)` (8-byte, align 8)
    g.ab.keyword SO
    g.ab.nilValue()
    g.ab.close()
    return
  let sa = stackSlotAlign(g.prog, t)
  if sa > 8:                                  # over-aligned slot → `(s (align N))`
    g.ab.tree X64Flag.SO:
      g.ab.tree AlignX: g.ab.intLit sa.int64
  else:
    g.ab.keyword SO                           # ordinary 8-granular slot → `(s)`
  var tc = t
  if tc.kind == Symbol: g.ab.sym symName(tc)
  else: g.genTypeBody(tc)
  g.ab.close()

proc emFloatStackVar*(g: var CodeGen; name: string; bits: int) =
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.floatType(bits)
  g.ab.close()

proc emScalarStackVar*(g: var CodeGen; name: string) =
  ## `(var :name (s) (i 64))` — a spilled/address-taken scalar's 8-byte slot.
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc declSpillSlot*(g: var CodeGen; name: string; typ: AsmSlot; isFloat: bool) =
  ## Declare one totality spill slot — an `etmp`/`eftmp`/`held` the value core minted
  ## when the register pools ran dry, or a `csave` the planner minted for a
  ## caller-saved home. A pointer slot keeps its precise `(ptr T)` type so a later
  ## deref/cmp type-checks; an integer slot is the generic `(s)(i 64)`.
  ##
  ## THE single place a spill slot is spelled, so the emitter can declare one where it
  ## mints it and the prologue can declare the planner's from the same rule.
  when defined(arkhamSpillDbg):
    stderr.writeLine "SPILLTEMP proc=" & g.curProcName & " name=" & name &
      " float=" & $isFloat
  if isFloat:
    g.emFloatStackVar(name, typ.size * 8)
  elif isNilSlot(typ) or
       (not cursorIsNil(typ.typ) and isPtrType(resolveType(g.prog, typ.typ))):
    g.emTypedStackVar(name, typ.typ)
  else:
    g.emScalarStackVar(name)

proc emBindType*(g: var CodeGen; typ: AsmSlot) =
  ## Emit the Leng type for a scratch binding: the slot's own type when known, else
  ## the generic `(i 64)` (a register/immediate dont-care placeholder carries no
  ## cursor). Mirrors `emTypedStackVar`'s type emission.
  if isNilSlot(typ):
    g.ab.nilValue()                  # `(nil)` — a null pointer, not an `(i 64)` 0
  elif cursorIsNil(typ.typ):
    g.ab.intType(64)
  else:
    var tc = typ.typ
    if tc.kind == Symbol: g.ab.sym symName(tc)
    else: g.genTypeBody(tc)

proc bindTemp*(g: var CodeGen; r: Reg; typ: AsmSlot) =
  ## Give scratch register `r` a typed nifasm name `tmpN.0` via `(rebind …)`, so every
  ## later `emReg r` emits a checked symbol rather than a raw `(reg)` the binding
  ## checker can't see. The binding is recorded as a temp, not a named local.
  ## Released by `unbindTemp`.
  let name = g.rb.freshTmpName()
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.emBindType(typ)
    g.ab.rawReg r
  let isPtr = isNilSlot(typ) or
              (not cursorIsNil(typ.typ) and isPtrType(resolveType(g.prog, typ.typ)))
  g.rb.bindScratch(r, name, isPtr)
  g.tmpBindTyp[r] = typ                 # a later `(rebind …)` must name the same type
  when defined(arkhamBindTrace): dbgRegSite[ord(r)] = getStackTrace()

proc unbindTemp*(g: var CodeGen; r: Reg) =
  ## Release a scratch binding made by `bindTemp`: `(kill)` the name and drop the
  ## binding. A no-op when `r` carries no temp binding (so it is safe on every
  ## `giveBack`, whether or not the reg was a bound temp). Also clears the fused
  ## core's reserve flag, so every legacy release site frees a `takeTmp` pick.
  g.pickedRegs.excl r
  let dead = g.rb.takeScratch(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead

proc releaseAsMirror*(g: var CodeGen; r: Reg; dst: Location): bool =
  ## `mirrorStored` plus this backend's staging census: a register that becomes a
  ## mirror is no longer HELD, so it must leave `stagingLive` or the peak-demand
  ## measurement (`-d:arkhamStagingDbg`) counts it forever.
  result = g.mirrorStored(r, dst)
  if result: g.stagingRelease r

proc releaseFAsMirror*(g: var CodeGen; f: FReg; dst: Location): bool {.inline.} =
  g.mirrorFStored(f, dst)

proc emStackMem*(g: var CodeGen; name: string) =       # (mem name)
  ## The slot symbol carries its own rsp displacement, so the frame base is
  ## implicit — the same spelling both Arm backends use.
  g.ab.tree MemX:
    g.ab.sym name

proc emFieldMem*(g: var CodeGen; base, field: string) =   # (mem (dot base field))
  # A sub-word field (e.g. a `cint`) is fine: nifasm sizes the `(mem (dot …))` access
  # from the field's declared type (a 4-byte mov for a 32-bit field, sign/zero-extended
  # on load). A field-by-field aggregate copy (copyStructThroughPtr2 / genConstr2)
  # therefore handles packed structs; the word-by-word path (genAggrCopy2) keeps its
  # own `fieldAtOffset` guard for genuinely word-misaligned packing.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.sym base
      g.ab.sym field

proc emAggrElemMem*(g: var CodeGen; base: string; idx: int) =  # (mem (at base idx))
  ## Element `idx` of the stack array `base`; nifasm folds the constant `idx*elemSize`
  ## into the displacement (an immediate index needs no stride scratch) and sizes the
  ## access from the array's element type.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.sym base
      g.ab.intLit idx

proc atNeedsScratch*(g: var CodeGen; atNode: Cursor): bool =
  ## Does this `(at base idx)` level need an explicit scratch register? x86 can fold
  ## `base + idx*scale` into one operand only for scale ∈ {1,2,4,8} and a single
  ## index; a register index whose element stride is anything else (a multi-
  ## dimensional array's outer dimension, stride = the inner array's size) cannot
  ## fold, so arkham hands nifasm a scratch and nifasm computes `base + idx*stride`
  ## into it (the `(at base idx scratch)` 3-operand form). An immediate index always
  ## folds to a displacement → never needs one. This is the x86 SIB rule; the arm64
  ## backend's analogue always returns true (it materializes every indexed address).
  let stride = typeSizeAlign(g.prog, resolveType(g.prog, g.getType(atNode)))[0]
  if stride in [1, 2, 4, 8]: return false
  var n = atNode
  var idxIsReg = false
  n.into:
    skip n                                      # the array base
    idxIsReg = n.kind != IntLit                 # a non-literal index lives in a register
    while n.hasMore: skip n
  result = idxIsReg

proc atIndexIsReg*(g: var CodeGen; atNode: Cursor): bool =
  ## Whether the index of an `(at base idx)` / `(pat ptr idx)` lives in a register (any
  ## non-literal) rather than an immediate that folds to a displacement.
  var n = atNode
  result = false
  n.into:
    skip n                                       # the array base (at) / pointer (pat)
    if n.hasMore: result = n.kind notin {IntLit, UIntLit}
    while n.hasMore: skip n

proc releaseStaleName*(g: var CodeGen; r: Reg) =
  ## A register about to be reused as raw scratch/staging must carry no stale
  ## named-local binding. A dead parameter often lingers in `regLocal` under its
  ## signature name `pN.0` (with its original type); `emReg` would then wrongly
  ## emit that typed name for the new value (e.g. `(mov p1.0 <ptr>)` where p1.0 is
  ## the i64 `start` param → nifasm strict-type mismatch). `(kill)` the binding and
  ## drop it so `emReg` falls back to the raw `(reg)` tag (untyped scratch).
  if r != NoReg:
    let dead = g.rb.takeBinding(r)               # also clears a stale pointer-typed bit
    if dead.len > 0:
      g.ab.tree KillX64: g.ab.sym dead

proc regHoldsLiveLocal(g: var CodeGen; r: Reg): bool =
  ## Is a local/param LIVE in `r` right now? A *param* can sit in a caller-saved
  ## arg register (`p0.0` in rdi), so staging must not clobber it just because it
  ## is caller-saved.
  ##
  ## This used to answer from `regHoldsHome`, the immutable per-proc UNION of every
  ## register any local is ever homed in. That threw away the allocator's whole
  ## point: it frees a register at `closeScope` and at `freeAfter`, so one register
  ## homes many locals across disjoint scopes (`lruTouchBody`: 42 register-homed
  ## symbols packed into 7 registers). The union then refused all 7 for the WHOLE
  ## body, including where those locals are dead or not yet declared — the failure
  ## census showed five registers rejected as "live local" with no bound name at
  ## all. It is why inlining starved the emitter: inlining multiplies the number of
  ## distinct locals while their scopes keep peak pressure flat, so the union grows
  ## and the free set shrinks even though nothing is more live than before.
  ##
  ## `rb` is the authority on what is live: the emitter binds a register local at
  ## its `(var :name (reg) T)` and releases it at scope exit, and nifasm's binding
  ## checker validates the result. Ask that instead.
  ##
  ## NAMED bindings only. A bound TEMP is anonymous — reachable solely through a
  ## `Location` held further up the Nim call stack — so it is not a "live local"
  ## in this sense; its own owner is responsible for it. A MIRROR is not one
  ## either: its value is still in memory, so the register is free for the taking
  ## (`RegMapping` rule 1) and the taker's own bind retires it.
  g.rb.isBound(r) and not g.rb.isBoundTemp(r) and not g.rb.isMirror(r)

proc pickStagingScratch*(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## The first non-sealed caller-saved GPR that is not the scratch pool (r10/r11,
  ## exhausted by the time we get here), not a live local/param home (a param may
  ## live in its caller-saved arg register), not a live expression accumulator
  ## (`liveAccums` — e.g. rax holding the return value while a deep right operand
  ## spills), and not `avoid`. Clobbering it transiently is then safe; any stale
  ## (dead-param) name binding on it is released first so `emReg` emits the raw
  ## `(reg)` rather than the dead param's typed name. Returns `NoReg` when none is
  ## free (the genuinely-out-of-registers case).
  ##
  ## TOTALITY BACKSTOP: when every volatile is taken, a *free* callee-saved
  ## register is drawn instead. That is not the demotion design.md rules out
  ## (no local moves, the allocator's decisions stand) — it is the same inline
  ## callee-saved draw `pickTempReg`/`takeHeld` already make, and it is legal
  ## for the same reason: the body-buffer model finalizes the prologue AFTER
  ## the body, so a register named in `usedCallee` during emission still gets
  ## its push/pop. It costs one save/restore pair in the procs that need it.
  ## The step whose demand exceeds the r10/r11 budget is a `(mem …)` address
  ## chain: every nesting level holds its result register from before its own
  ## address is materialized, so a `((a.b).c).d` chain of spilled loads wants
  ## one register per level (`cmpStringPtrs`, `-d:danger`).
  # The temp pool first, when it happens to be free: "exhausted by the time we
  # get here" holds for a spill mid-expression, but NOT for a statement-level
  # step that already released its pool picks (an aggregate copy whose two ends
  # are sealed staging regs while r10 — used for an end's address value, then
  # given back — sits idle). A free pool register costs nothing and keeps the
  # R11 bridge available for a deeper pick that has no alternative.
  for r in g.md.intTempRegs:
    if r != avoid and regFreeForTemp(g, r) and not g.regHoldsLiveLocal(r):
      g.releaseStaleName(r)
      return r
  for r in StagingCandidates.toOpenArray(0, stressLimit(StagingCandidates.len) - 1):
    if r != avoid and not g.plan.isSealed(r) and not g.rb.isAccum(r) and
       not g.rb.isBoundTemp(r) and not g.regHoldsLiveLocal(r) and
       r notin g.rawHomeRegs:
      # not `isBoundTemp`: a register holding a live scratch temp (`bindTemp`'d)
      # must not be handed out as staging — that would clobber the temp's value.
      #
      # not `rawHomeRegs` either, for the same reason one register further out:
      # a param whose home is written and read as a bare `(reg)` carries NO `rb`
      # binding, so every filter above answers "free" for it. `regFreeForTemp`
      # guards the pool and callee-saved loops with exactly this set; this loop
      # walked the ABI arg registers without it, and an `openArray`'s data
      # pointer lives in one of them (rdi) — `s[i] in Digits` staged the set byte
      # into rdi and the next `s[i]` dereferenced the byte.
      g.releaseStaleName(r)
      return r
  for r in g.md.intCalleeSaved:
    if r != avoid and regFreeForTemp(g, r) and not g.regHoldsLiveLocal(r):
      g.plan.usedCallee.incl r                  # the prologue must now save it
      g.releaseStaleName(r)
      return r
  return NoReg

proc stagingCapacity*(g: var CodeGen): int =
  ## How many transients could be drawn AT THIS MOMENT: the ones already held plus
  ## the candidates still free. Unlike the RISC targets, where the reservation is
  ## fixed, x86-64's capacity is DYNAMIC — R11 is reserved outright and the ABI
  ## volatiles are extra room when the allocator has not filled them. That is the
  ## whole asymmetry design.md names, and it is why capacity and guarantee are two
  ## numbers here and one there.
  ## Mirrors `pickStagingScratch`'s three loops, and must keep mirroring them:
  ## counting only `StagingCandidates` understates the answer, because that proc
  ## also falls through to a FREE CALLEE-SAVED register — legal because the
  ## body-buffer model finalizes the prologue after the body, so a register named
  ## in `usedCallee` during emission still gets its push/pop. Leaving the backstop
  ## out reported `addr_chain_depth` as having nowhere to go at `ARKHAM_STRESS=2`
  ## when a take there would have succeeded.
  result = card(g.stagingHeld)
  for r in g.md.intTempRegs:
    if r notin g.stagingHeld and regFreeForTemp(g, r) and not g.regHoldsLiveLocal(r):
      inc result
  for r in StagingCandidates.toOpenArray(0, stressLimit(StagingCandidates.len) - 1):
    if r notin g.stagingHeld and not g.plan.isSealed(r) and not g.rb.isAccum(r) and
       not g.rb.isBoundTemp(r) and not g.regHoldsLiveLocal(r) and
       r notin g.rawHomeRegs:
      inc result
  for r in g.md.intCalleeSaved:
    if r notin g.stagingHeld and regFreeForTemp(g, r) and not g.regHoldsLiveLocal(r):
      inc result

export bridges

template withBridges*(g: var CodeGen; demand: BridgeDemand; what: string;
                      body: untyped) =
  ## Declare this step's transient demand around the takes that realise it — the
  ## x86-64 twin of the RISC template, answering `core/bridges` with THIS target's
  ## numbers: a dynamic capacity and a guarantee of one.
  when BridgeCheck:
    bridgeScopePush(g, demand, what, g.liveStaging(), g.stagingCapacity(),
                    StagingGuaranteed, g.heldStagingNames())
    try:
      body
    finally:
      bridgeScopePop(g, g.liveStaging(), g.heldStagingNames())
  else:
    body

template bridgeStep*(g: var CodeGen; what: string; demand = bdTransient) =
  ## The implicit scope a recursive emit entry opens, `defer`-scoped to the rest
  ## of the proc because those procs return from many places.
  when BridgeCheck:
    bridgeScopePush(g, demand, what, g.liveStaging(), g.stagingCapacity(),
                    StagingGuaranteed, g.heldStagingNames())
    defer: bridgeScopePop(g, g.liveStaging(), g.heldStagingNames())

proc bridgeRaise*(g: var CodeGen; demand: BridgeDemand; what: string) {.inline.} =
  bridges.bridgeRaise(g, demand, what, StagingGuaranteed)

proc bridgeOverDeclared*(g: var CodeGen) {.noinline.} =
  bridges.bridgeOverDeclared(g, g.liveStaging())

proc bridgeTakeAllowed*(g: var CodeGen): bool {.inline.} =
  bridges.bridgeTakeAllowed(g, g.liveStaging())

proc stagingCensus*(g: var CodeGen; avoid: Reg): string =
  ## Why every staging candidate was unavailable. "Out of registers" is otherwise
  ## indistinguishable from "a filter is wrong / a seal was never released", and
  ## those need opposite fixes.
  when defined(arkhamBindTrace):
    # `-d:arkhamBindTrace`: name the SITE that bound/sealed each occupied
    # register (recorded at bindTemp/seal/takeTmp time), so a stale hold — a
    # pick made before the work that needed the register — is readable straight
    # off the failure instead of reconstructed from the emit paths.
    stderr.writeLine "=== bind/seal sites of occupied registers ==="
    for r in g.md.intTempRegs:
      stderr.writeLine "--- pool " & $r & ": picked=" & $(r in g.pickedRegs) &
        " bound=" & g.rb.boundName(r) & " site:"
      stderr.writeLine dbgRegSite.getOrDefault(ord(r), "  <no record>")
    for r in StagingCandidates:
      if g.plan.isSealed(r) or g.rb.isBoundTemp(r):
        stderr.writeLine "--- " & $r & " bound/sealed at:"
        stderr.writeLine dbgRegSite.getOrDefault(ord(r), "  <no record>")
    for r in g.md.intCalleeSaved:
      if g.plan.isSealed(r):
        stderr.writeLine "--- " & $r & " sealed at:"
        stderr.writeLine dbgRegSite.getOrDefault(ord(r), "  <no record>")
  result = ""
  for r in StagingCandidates.toOpenArray(0, stressLimit(StagingCandidates.len) - 1):
    result.add "\n    " & $r & ": "
    if r == avoid: result.add "avoid"
    elif g.plan.isSealed(r): result.add "sealed (" & g.rb.boundName(r) & ")"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBoundTemp(r): result.add "boundTemp " & g.rb.boundName(r)
    elif g.regHoldsLiveLocal(r): result.add "live local " & g.rb.boundName(r)
    else: result.add "FREE (unreachable)"
  for r in g.md.intCalleeSaved:               # the callee-saved backstop's view
    result.add "\n    " & $r & ": "
    if r == avoid: result.add "avoid"
    elif r in g.pickedRegs: result.add "picked"
    elif g.plan.isSealed(r): result.add "sealed"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBound(r): result.add "bound " & g.rb.boundName(r)
    elif g.regHoldsHome(r) or g.regHoldsLiveLocal(r): result.add "home"
    else: result.add "FREE (unreachable)"

proc pickStaging*(g: var CodeGen; what: string; avoid: Reg = NoReg): Reg =
  ## A transient compute register for a spill (see `pickStagingScratch`). Every
  ## caller MUST `giveBack` the result. NOT total: when the register file is
  ## genuinely full this fails loudly rather than spilling somebody else's value
  ## behind their back.
  when BridgeCheck:
    if not g.bridgeTakeAllowed(): bridgeOverDeclared(g)
  result = g.pickStagingScratch(avoid)
  if result == NoReg:
    raiseAssert "arkham x64: no staging register available for " & what &
                " in proc " & g.curProcName & g.stagingCensus(avoid)
  g.stagingNote(result, what)

proc regHoldsLiveFLoc(g: var CodeGen; f: FReg): bool =
  ## True if a float local/param currently lives in SIMD register `f` (per the
  ## allocator's view). A leaf-proc float param sits in its incoming arg register
  ## (xmm0–7), so the float staging pick must not clobber it.
  for name, pos in g.plan.symPos:
    let loc = g.plan.planned(pos)
    if loc.kind == InFReg and loc.f == f: return true

proc pickFStaging(g: var CodeGen; avoid: FReg = NoFReg): FReg =
  ## The float analogue of `pickStagingScratch`: the first SIMD arg register
  ## (xmm0–7) that is not the scratch pool (xmm8–15, exhausted by the time we get
  ## here), not an in-flight float arg / held staging reg (`sealedF`), not a live
  ## float local/param home, and not `avoid`. Clobbering it transiently is then safe.
  ## `FloatStagingBridge` (xmm15) is tried FIRST and is the RESERVED float bridge:
  ## it is kept out of the allocator's float temp pool (`floatTempRegs`), so it is
  ## never a live float local/temp home — always pickable. That guarantees
  ## `pickFStaging` never fails, making `produceIntoFMem2` total (every spilled float
  ## value position has a staging xmm). The arg registers follow for nested staging.
  if FloatStagingBridge != avoid and not g.rb.isSealedF(FloatStagingBridge):
    return FloatStagingBridge
  for f in g.md.floatArgRegs:
    if f != avoid and not g.rb.isSealedF(f) and not g.regHoldsLiveFLoc(f):
      return f
  return NoFReg

proc pickFStagingSealed*(g: var CodeGen; what: string; avoid: FReg = NoFReg): FReg =
  ## A transient staging xmm, sealed (`sealF`) so a nested pick cannot reuse it;
  ## the caller releases it with `g.rb.unsealF`. Fails loudly when none is free.
  ## The float twin of `pickStagingSealed`.
  result = g.pickFStaging(avoid)
  if result == NoFReg: raiseAssert "arkham x64n: no staging xmm for " & what
  g.rb.sealF result

proc takeTmp*(g: var CodeGen; slot: AsmSlot): Location =
  ## Reserve an expression-temp GPR (lazy-bound by its consumer); an `etmp`
  ## spill-slot Location when the pools are dry (the produce-into path
  ## materializes into it via the staging bridge).
  let r = g.pickTempReg()
  if r == NoReg:
    let nm = g.mintSpillName("etmp")
    when defined(arkhamTempDbg):
      stderr.writeLine "ETMP " & g.curProcName & " " & nm & g.tempCensus()
    g.declSpillSlot(nm, slot, isFloat = false)   # HERE: exhaustion is a statement position
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedRegs.incl r
  when defined(arkhamBindTrace): dbgRegSite[ord(r)] = getStackTrace()
  result = regLoc(r, slot, isTemp = true)

proc takeFTmp*(g: var CodeGen; slot: AsmSlot): Location =
  ## The SIMD twin of `takeTmp` (an `eftmp` slot when the float pools are dry).
  let f = g.pickFTempReg()
  if f == NoFReg:
    let nm = g.mintSpillName("eftmp")
    g.declSpillSlot(nm, slot, isFloat = true)
    return namedStackLoc(nm, slot, spillTemp = true)
  g.pickedFRegs.incl f
  result = fregLoc(f, slot, isTemp = true)

proc takeHeld*(g: var CodeGen; what: string; canSpill = false): Location =
  ## A SURVIVOR scratch (outlives a call / stays off the staging bridge):
  ## callee-saved only. Demoting a local mid-emission is impossible in the
  ## merged core (its uses are already emitted), so exhaustion either spills
  ## the (re-derivable) survivor to a `heldN.0` slot (`canSpill` consumers
  ## re-derive at each use) or fails loudly.
  let r = g.pickHeldReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, ScalarSlot, isTemp = true)
  if canSpill:
    let nm = g.mintSpillName("held")
    g.declSpillSlot(nm, AsmSlot(cls: AInt, size: 8, align: 8), isFloat = false)
    return namedStackLoc(nm, ScalarSlot, spillTemp = true)
  raiseAssert "arkham x64n: out of registers for " & what &
              " in proc " & g.curProcName & " (nothing to spill)"

proc freeVal*(g: var CodeGen; loc: Location) {.inline.} =
  ## Release a reserved/resolved temp — the emit-time `releaseTmp`: clear the
  ## pick flag and, if a consumer bound it, `(kill)` the binding so the
  ## freeness filters see the register free again. A no-op for every other
  ## location kind (a home, an immediate, a slot).
  ##
  ## A register that has become a MIRROR was already released — by the store that
  ## made it one — and its binding is now the map's, not this value's. Killing it
  ## here would undo the forwarding at the very moment it becomes useful (the
  ## caller of `storeScalar2` frees the value it just stored).
  if loc.kind == InReg and loc.isTemp:
    g.pickedRegs.excl loc.r
    if not g.rb.isMirror(loc.r): g.unbindTemp(loc.r)
  elif loc.kind == InFReg and loc.isTemp:
    g.pickedFRegs.excl loc.f
    if not g.rb.isFMirror(loc.f): g.unbindFTmp(loc.f)

proc resolveDest*(g: var CodeGen; dest: var Location; natural: Location) =
  ## Resolve a LEAF destination constraint against the value's natural
  ## location (an immediate / a symbol's home) — the emit-time twin of the
  ## allocator's `resolveDest`. A fresh temp is bound (caller must not rebind).
  case dest.kind
  of Undef: dest = natural
  of NeedsReg:
    dest = (if natural.kind == InReg: natural else: g.takeTmp(natural.typ))
  of RegOrImm:
    dest = (if natural.kind in {InReg, Imm}: natural else: g.takeTmp(natural.typ))
  else: discard                              # fixed InReg/InFReg/NamedStack/…: keep

proc forceRegDest*(g: var CodeGen; dest: var Location) =
  ## Ensure a value's `dest` is a register (or, pool-dry, an etmp slot the
  ## produce-into path serves) — the emit-time twin of `forceRegDest`.
  case dest.kind
  of NeedsReg, RegOrImm: dest = g.takeTmp(dest.typ)
  of Undef:
    # A bare `dontCare` carries no slot (size 0) and defaults to the machine word.
    # A caller that KNOWS the value's precise slot may hand it over on the Undef
    # dest — pointer operands must, because a pool-dry `etmp` is DECLARED with this
    # slot and nifasm then type-checks every use of it.
    dest = g.takeTmp(if dest.typ.size > 0: dest.typ else: ScalarSlot)
  else: discard

proc rebindLocalAs*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Re-establish register `r`'s binding to the named local `name`, retyped to
  ## `typeCur`, via a zero-machine-code `(rebind …)`. `rebind` auto-kills the transient
  ## tenant `r` currently carries, so no manual `kill` is needed. The scope already
  ## tracks `name` (declared by `emRegLocalVar`), so `scopeLocals` is NOT touched. Type
  ## emission mirrors `emRegLocalVar`: the type given is the type declared, pointer or
  ## not (it used to flatten every non-pointer to `(i 64)`).
  let isPtr = isPtrType(resolveType(g.prog, typeCur))
  g.ab.tree RebindX64:
    g.ab.symDef name
    var t = typeCur
    g.genTypeBody(t)
    g.ab.rawReg r
  g.rb.rebindLocal(r, name, isPtr)
  # The name's binding type is now `typeCur`, so the record has to move with it:
  # `restoreBindings` re-emits from it after a diverging call, and `bindTypeOf`
  # answers from it. Leaving the declaration-time entry made both name a type the
  # binding no longer has.
  g.nameBindTyp[name] = NameBindTyp(isPtr: isPtr, typ: typeCur)

proc bindTypeOf*(g: var CodeGen; r: Reg): Cursor =
  ## The Leng type `r`'s CURRENT nifasm binding declares, or a nil cursor when it
  ## declares none: a raw register, an aggregate-pointer binding (whose type is a
  ## name, not a cursor), or a dont-care temp. This is what an operand ARRIVES as,
  ## which is not always what its expression's static type says — see `emitCast2`.
  result = default(Cursor)
  if g.rb.isBoundTemp(r):
    if g.tmpBindTyp.hasKey(r): result = g.tmpBindTyp[r].typ
  else:
    let nm = g.rb.boundName(r)
    if nm.len > 0 and g.nameBindTyp.hasKey(nm):
      let bt = g.nameBindTyp[nm]
      if bt.aggrSym == NoTypeSym: result = bt.typ

proc rebindTempAs*(g: var CodeGen; r: Reg; typeCur: Cursor) =
  ## Retype an already-bound scratch on `r` to `typeCur`, keeping it a temp
  ## (unlike `rebindLocalAs`, which would drop the `boundTemps` bit). Used after
  ## a narrowing cast: the temp was bound at 64-bit so the source could land,
  ## `extendTo` has now truncated, and a later `(mov u32dst tmp)` needs the
  ## target width on the name.
  let name = g.rb.boundName(r)
  if name.len == 0: return
  let slot = slotOf(g.prog, typeCur)
  let isPtr = isPtrType(resolveType(g.prog, typeCur))
  g.ab.tree RebindX64:
    g.ab.symDef name
    var t = typeCur
    g.genTypeBody(t)
    g.ab.rawReg r
  g.rb.bindScratch(r, name, isPtr)
  g.tmpBindTyp[r] = slot

proc cmpOperandUnsigned*(g: var CodeGen; c: Cursor): bool =
  ## Does comparison/`case` operand `c` carry an unsigned (or char) type? This
  ## drives the unsigned-vs-signed condition code. A bare signed literal is
  ## ambiguous (→ false, let the other operand decide); a `UIntLit`/`CharLit` is
  ## unsigned; every other operand is typed through `getType` — so unsigned
  ## *fields*, array elements, derefs, casts, computed expressions, and an unsigned
  ## symbol in *either* operand position are all detected, not just a bare unsigned
  ## symbol in the first position (the old check missed all of these → a wrong
  ## signed compare, e.g. `5 < UINT64_MAX` computed as `5 < -1`).
  case c.kind
  of UIntLit, CharLit: result = true
  of IntLit: result = false
  else: result = not isSignedType(resolveType(g.prog, g.getType(c)))

proc cmpJccTag*(ek: LengExpr; whenTrue, signed: bool): X64Inst =
  ## The `jcc` opcode for a Leng comparison `ek`, taken when the condition is
  ## `whenTrue`. `signed` selects signed vs unsigned ordering for `<`/`<=`; a float
  ## compare passes `signed = false`, since `comisd` sets CF/ZF like an unsigned
  ## compare (so ordered `<`/`<=` map to below / below-or-equal).
  case ek
  of EqC:  (if whenTrue: JeX64 else: JneX64)
  of NeqC: (if whenTrue: JneX64 else: JeX64)
  of LtC:  (if whenTrue: (if signed: JlX64 else: JbX64)
            else:        (if signed: JgeX64 else: JaeX64))
  of LeC:  (if whenTrue: (if signed: JleX64 else: JbeX64)
            else:        (if signed: JgX64 else: JaX64))
  else: raiseAssert "arkham x64 v0: condition not supported: " & $ek

proc cmpSetccTag*(jcc: X64Inst): X64Inst =
  ## The `setcc` that MATERIALIZES the condition `jcc` would branch on. Total over
  ## everything `cmpJccTag` can return, so the two stay in step by construction
  ## rather than by a second copy of the signed/unsigned rule.
  case jcc
  of JeX64:  SeteX64
  of JneX64: SetneX64
  of JlX64:  SetlX64
  of JleX64: SetleX64
  of JgX64:  SetgX64
  of JgeX64: SetgeX64
  of JbX64:  SetbX64
  of JbeX64: SetbeX64
  of JaX64:  SetaX64
  of JaeX64: SetaeX64
  else: raiseAssert "arkham x64: no setcc for " & $jcc

proc mirrorJcc*(jcc: X64Inst): X64Inst =
  ## The condition that holds for `cmp b, a` given `jcc` holds for `cmp a, b`.
  ## Equality is symmetric; the orderings change side.
  case jcc
  of JeX64:  JeX64
  of JneX64: JneX64
  of JlX64:  JgX64
  of JleX64: JgeX64
  of JgX64:  JlX64
  of JgeX64: JleX64
  of JbX64:  JaX64
  of JbeX64: JaeX64
  of JaX64:  JbX64
  of JaeX64: JbeX64
  else: raiseAssert "arkham x64: no mirror for " & $jcc

proc invertJcc*(jcc: X64Inst): X64Inst =
  ## The condition that holds exactly when `jcc` does not. Total over everything
  ## `cmpJccTag`/`mirrorJcc` can produce, so a fused branch (`scanCondFusions`) can
  ## take either sense of a compare that has already executed.
  case jcc
  of JeX64:  JneX64
  of JneX64: JeX64
  of JlX64:  JgeX64
  of JgeX64: JlX64
  of JleX64: JgX64
  of JgX64:  JleX64
  of JbX64:  JaeX64
  of JaeX64: JbX64
  of JbeX64: JaX64
  of JaX64:  JbeX64
  else: raiseAssert "arkham x64: no inverse for " & $jcc

proc isCmpImmLeaf*(c: Cursor): bool =
  ## A bare integer literal, `(suf …)`/`(par …)` wrappers included: what `cmp`
  ## can take as an immediate operand — and, on the left, what costs a `mov`.
  var cur = c
  if cur.kind == TagLit and cur.exprKind in {SufC, ParC}: inc cur
  result = cur.kind in {IntLit, UIntLit, CharLit}

proc releaseRetRegs*(g: var CodeGen) =
  ## The ≤16B aggregate result pair (rax:rdx) is about to be written as the ABI result,
  ## or read back as a call's result. Any name still bound to one of them is stale, and
  ## `emReg` would move the ABI word through THAT name, at that name's type:
  ##
  ##   (var :`x.396 (rdx) (bool))            … the dead bool that once lived there
  ##   (mov `x.396 (cast (u 64) (mem …)))    … the return sequence's word 1
  ##   (mov (mem … `x.397 8) `x.396)         … and word 1 of a later call's result
  ##   [Error] Access to variable `x.396` in register RDX which was clobbered
  ##
  ## Dead by construction on both sides: a call destroys rax/rdx (anything live there
  ## was parked by the caller-save window first), and at a `ret` nothing outlives the
  ## return. Same treatment `dropStaleBinding(RDI)` gives the hidden result pointer and
  ## `releaseStaleName(divRemReg)` gives rdx at a div — this was the third fixed-role
  ## use of a register that had not got it.
  for r in x64RetRegs: g.releaseStaleName(r)

proc dropStaleBinding*(g: var CodeGen; r: Reg) =
  ## `r` is about to be WRITTEN with a value of an unrelated type — the hidden
  ## result pointer. A binding still sitting on it makes `emReg` name that local
  ## instead of the register, so the write comes out as `(lea `x.64 …)` into a
  ## name declared `(bool)` — which nifasm rejects now that it checks operand
  ## types, and which was a silent lie before. Whatever was still LIVE there was
  ## parked by the caller-save window that opens first; this only surrenders the
  ## name of a value that is already dead.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead

proc indirectRetType*(g: var CodeGen; gvarDecl: Cursor): Cursor =
  ## The return-type cursor of a function-pointer variable's proctype, for the
  ## declarative call path's `retIsVoid`/result handling. Leng's
  ## `(proctype Empty Params RetType Pragmas)` always carries the RetType node — a
  ## `.` (DotToken, `retIsVoid`-true) / `(void)` for a void proc — so it is simply
  ## the third child.
  var d = gvarDecl
  result = gvarDecl                             # overwritten below (always a proctype here)
  d.into:
    inc d; skip d                               # name, pragmas
    let pt = resolveType(g.prog, d)             # the (proctype …) body
    assert pt.kind == TagLit and pt.typeKind == ProctypeT,
           "arkham: indirect call through a non-proctype value"
    var q = pt                                  # consume a copy; `result` keeps a cursor
    q.into:
      skip q                                    # Empty (the proc-name slot)
      skip q                                    # Params
      result = q                                # RetType (`.` / `(void)` / a real type)
      while q.hasMore: skip q                   # drain RetType + Pragmas
    while d.hasMore: skip d

proc genPointee*(g: var CodeGen; c: var Cursor) =
  ## Emit a pointer's pointee / element type. A *named* type is referenced by
  ## symbol rather than inlined: this breaks the infinite recursion of
  ## self-referential types (a `(ptr T)` field inside `T`) and lets nifasm
  ## resolve — and auto-import across modules — the type declaration by name.
  if c.kind == Symbol:
    g.ab.sym symName(c); inc c
  else:
    g.genTypeBody(c)

proc emitParamsAndResult*(g: var CodeGen; c: var Cursor; byRef: bool;
                         amd: MachineDesc): int =
  ## Emit the `(params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (rax) T))?` of a
  ## signature under the calling convention `amd` describes, consuming the params slot
  ## and the return type at `c`, and returning the count of integer arg registers
  ## consumed (for the clobber set). `byRef` selects how a *named* type is emitted: by
  ## reference (`genPointee`, so a self-referential proctype can't recurse forever) or
  ## inline (`genTypeBody`). Shared by `genProctypeSig` and `emitSignature`.
  ##
  ## `amd` is `g.md` (arkham's own SysV convention) for everything arkham generates,
  ## and `win64Machine` for a `stdcall` proctype — a pointer to foreign code, whose
  ## signature must state where WINDOWS puts the arguments. See `isForeignAbiProctype`.
  ##
  ## A >16B by-ref aggregate RETURN is modelled as a synthetic leading pointer
  ## param `paramName(0)` in rdi — chibicc's hidden return pointer (`push_args`'s
  ## `gp++`). Real params then shift to rsi… naturally; the result slot stays empty
  ## (the value travels through the pointer, not rax).
  var retC = c
  skip retC                                     # params slot → return type
  var retByRef = false
  if not retIsVoid(retC):
    let rs = slotOf(g.prog, retC)
    retByRef = rs.kind == AMem and rs.size > amd.aggrByRefThreshold
  # THE plan (see abi.nim): register indices and name ordinals below read it —
  # a param's NAME ordinal advances by exactly 1 per param, decoupled from the
  # GPR index (a stack/float param consumes 0 GPRs, an aggregate several).
  let plan = planCall(amd, paramSlots(g.prog, c), retByRef)
  var pIdx = 0
  g.ab.tree ParamsD:
    if retByRef:                                # synthetic hidden result pointer in rdi
      g.ab.tree ParamD:
        g.ab.symDef paramName(0)
        g.ab.rawReg amd.intArgRegs[0]
        g.ab.ptrType:
          var rc = retC
          if byRef: g.genPointee(rc) else: g.genTypeBody(rc)
    if c.kind == TagLit:                        # (params (param …) …)
      c.into:
        while c.hasMore:
          let pl = plan.args[pIdx]
          inc pIdx
          c.into:                               # (param :name pragmas type)
            inc c                               # name → positional pN.0
            skip c                              # pragmas
            if pl.isFloat:
              raiseAssert "arkham x64: float param in signature not yet supported"
            if pl.isAgg:
              # An aggregate param. Its NAME is `paramName(pl.ord)`; the body never
              # reads it by name (the prologue moves it into a stack home / pointer
              # reg raw), so it is emitted with the `(regs …)` location, which nifasm
              # treats as ABI-only — NOT bound — so a raw `(reg)` consumption stays
              # legal. A >16B aggregate travels by-ref as a pointer in ONE GPR; a
              # ≤16B by-value aggregate spans `pl.words` consecutive GPRs (one per
              # eightbyte). `(arg pN k)` at a call site selects word k.
              g.ab.tree ParamD:
                g.ab.symDef paramName(pl.ord)
                if not pl.onStack:
                  g.ab.tree RegsD:
                    for k in 0 ..< pl.words: g.ab.rawReg amd.gprAt(pl, k)
                else:
                  g.ab.keyword SO              # doesn't fit → entirely on the stack
                if pl.byRef:
                  g.ab.ptrType:
                    if byRef: g.genPointee(c) else: g.genTypeBody(c)
                else:
                  if byRef: g.genPointee(c) else: g.genTypeBody(c)
            else:
              g.ab.tree ParamD:
                g.ab.symDef paramName(pl.ord)
                if not pl.onStack: g.ab.rawReg amd.gprAt(pl)
                else: g.ab.keyword SO           # past the arg registers → stack-passed
                if byRef: g.genPointee(c) else: g.genTypeBody(c)
            while c.hasMore: skip c
    else:
      skip c                                    # no params slot
  g.ab.tree ResultD:                            # c now at the return type
    if retIsVoid(c) or retByRef:
      skip c                                    # void, or returned via the hidden pointer
    else:
      let rs = slotOf(g.prog, c)
      if rs.kind == AFloat:
        raiseAssert "arkham x64: float result in signature not yet supported"
      if rs.kind == AMem:
        # A ≤16B by-value aggregate result travels in rax:rdx with an EMPTY result slot
        # (like a >16B by-ref result): the callee marshals it into rax:rdx and the caller
        # reads those raw after the call — no `(res ret.0)` binding to declare here.
        skip c
      else:
        g.ab.symDef synth("ret.0")
        g.ab.rawReg RAX
        if byRef: g.genPointee(c) else: g.genTypeBody(c)
  result = plan.gpUsed

proc emitAbiClobber*(g: var CodeGen; numArgRegs: int;
                    amd: MachineDesc = x64Machine) =
  ## `(clobber …)` listing the volatile GPRs EXCEPT the first `numArgRegs` integer
  ## arg registers of `amd`'s convention — they hold live params on entry, and nifasm
  ## treats a declared clobber as clobbered there, so listing them would stop the
  ## body/callee reading its own params.
  var paramRegs: set[Reg] = {}
  for i in 0 ..< min(numArgRegs, amd.intArgRegs.len): paramRegs.incl amd.intArgRegs[i]
  g.ab.tree ClobberD:
    for r in x64ClobbersGpr:
      if r notin paramRegs: g.ab.rawReg r

proc genProctypeSig*(g: var CodeGen; c: var Cursor) =
  ## Lower a Leng `(proctype Empty Params [RetType] Pragmas)` to a concrete asm-NIF
  ## signature `(proctype (params (param :pN.0 <reg|s> T)…) (result (res :ret.0 (rax)
  ## T))? (clobber …))` — the SysV ABI assignment, identical in shape to a
  ## declarative proc's signature, so nifasm can resolve an *indirect* `(prepare …)`
  ## call through a function pointer against it. A function pointer is still 8 bytes
  ## (nifasm sizes `ProcT` as a pointer); the signature is metadata for call sites.
  ## Param/result types are emitted BY REFERENCE (`genPointee`) for named types so a
  ## self-referential closure/continuation signature can't recurse forever.
  ##
  ## The signature mirrors `emitSignature` EXACTLY — including its declarative split.
  ## A DECLARATIVE proctype (all single-GPR scalar params + scalar/void result) states
  ## the positional `pN.0`/`ret.0` ABI so an indirect `(prepare …)` is cross-checked
  ## via `(arg pN)`/`(res ret.0)`. A NON-declarative one (a float/aggregate param or an
  ## aggregate return — e.g. a CPS continuation `proc(c): Continuation`) emits EMPTY
  ## `(params)`/`(result)`, exactly as a non-declarative concrete proc does, so nifasm
  ## requires no per-param bindings and the call site marshals args into raw ABI
  ## registers itself. Without this, a call through such a fn-ptr fails nifasm's
  ## "Missing argument: p0.0" check.
  let declarative = isDeclarativeAbi(g.prog, c)
  # A `stdcall` proctype points at foreign code, so its signature must state where
  # WINDOWS reads the arguments, not where arkham's own convention puts them.
  let amd = if isForeignAbiProctype(g.prog, c): win64Machine else: g.md
  g.ab.proctypeType:
    if declarative:
      c.into:
        skip c                                  # the Empty slot (a proc has its name here)
        let numParams = g.emitParamsAndResult(c, byRef = true, amd)
        while c.hasMore: skip c                  # pragmas
        g.emitAbiClobber(numParams, amd)        # mirrors `emitSignature`
    else:
      g.ab.keyword ParamsD
      g.ab.keyword ResultD
      g.emitAbiClobber(0, amd)                  # a call destroys every volatile GPR
      skip c                                     # advance past the whole proctype node

proc genTypeBody*(g: var CodeGen; c: var Cursor) =
  ## Translate a Leng type at `c` into asm-NIF, advancing past it. Named types
  ## are inlined; object field pragmas are dropped. v0: int/uint/bool/ptr + objects.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, c.symId)
    d.into:
      inc d; skip d                           # name, type-pragmas
      g.genTypeBody(d)
    inc c
  of TagLit:
    case c.typeKind
    of IT:
      var t = c; inc t
      g.ab.intType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of UT:
      var t = c; inc t
      g.ab.uintType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of CT:
      var t = c; inc t
      g.ab.charType(if t.kind == IntLit: int(intVal(t)) else: 8); skip c
    of FT:
      var t = c; inc t
      g.ab.floatType(if t.kind == IntLit: int(intVal(t)) else: 64); skip c
    of BoolT:
      g.ab.boolType(); skip c
    of VoidT:
      g.ab.voidType(); skip c
    of PtrT:
      g.ab.ptrType:
        c.into: g.genPointee(c)               # pointee (named → by-reference)
    of AptrT:                                 # pointer to (array of) — a scalar ptr
      g.ab.aptrType:
        c.into: g.genPointee(c)               # element type (named → by-reference)
    of FlexarrayT:                            # variable-length array tail (last fld)
      g.ab.flexarrayType:
        c.into: g.genTypeBody(c)              # element type
    of ProctypeT:
      # A function pointer (8 bytes). Emit its full ABI signature — not an opaque
      # `(ptr (void))` — so nifasm can type-check and resolve an indirect call
      # `(prepare <fnptr> … (call))` against it. Recursion through self-referential
      # closure/continuation param types is broken by `genProctypeSig`'s
      # by-reference (`genPointee`) type emission.
      g.genProctypeSig(c)
    of ArrayT:
      c.into:
        g.ab.arrayType:
          g.genTypeBody(c)
          if c.kind == IntLit: (g.ab.intLit intVal(c); inc c)
          else: raiseAssert "arkham x64 v0: array length must be a literal"
    of ObjectT:
      c.into:
        # Inheritance: a Symbol base is emitted by reference (so nifasm resolves
        # it and lays the base out first); a `.` means no base. Keeping the base
        # lets nifasm compute inherited-field offsets — the `(cast (ptr Derived)
        # x).baseField` idiom (Nim's allocator) depends on it.
        var baseName = ""
        if c.kind == Symbol: baseName = symName(c)
        skip c                                # inheritance slot (`.` or base sym)
        g.ab.objectType:
          if baseName.len > 0: g.ab.sym baseName
          while c.hasMore:
            if c.kind == TagLit and c.typeKind == UnionT:
              # An object VARIANT's union part. Each branch is `(of RANGES BODY)` /
              # `(else BODY)` whose body is an object with sequential fields; branches
              # overlap (nifasm lays the union out as max branch size). The asm-NIF
              # union is UNTAGGED, so emit only the bodies — the discriminant lives in
              # the `fld` preceding the union, which is emitted as an ordinary field.
              # A body-less branch (`of x: nil`) contributes no member.
              g.ab.unionType:
                c.into:
                  while c.hasMore:
                    var bodyc = unionBranchBody(c)
                    if bodyc.kind != DotToken: g.genTypeBody(bodyc)
                    skip c
            else:
              c.into:                         # (fld :name pragmas type)
                let fn = symName(c); inc c
                skip c                        # field pragmas (dropped)
                g.ab.fldDef(fn):
                  g.genTypeBody(c)
    of EnumT:                                 # an enum is just its base integer type
      c.into:
        g.genTypeBody(c)                      # (enum <base> (efld …)…) → <base>
        while c.hasMore: skip c               # efld declarations (dropped)
    of VarargsT:
      # A C `{.varargs.}` importc marker materialises as a synthetic trailing
      # param `(param :vanon . . (varargs))` — e.g. posix `open`/`fcntl`. It owns
      # no storage of its own; the variadic slot is just one ABI/syscall register
      # wide. Emit it as a 64-bit uint so the param maps to exactly one register
      # (`emitSyproc` then binds it to the next syscall arg reg). `skip` drains the
      # whole `(varargs …)` node, with or without a recorded element type.
      g.ab.uintType(64); skip c
    else:
      raiseAssert "arkham x64 v0: type not supported: " & $c.typeKind
  else:
    raiseAssert "arkham x64 v0: malformed type"

proc emImm*(g: var CodeGen; loc: Location) =
  ## Emit an immediate VALUE operand: `(nil)` for a null pointer, else the integer.
  if isNilImm(loc): g.ab.nilValue()
  else: g.ab.intLit loc.ival

proc binStoreSuppressPos*(g: var CodeGen; rhs: Cursor; storeWidth: int): int =
  ## `rhs`'s token position when it is a sub-64-bit integer `add`/`sub`/`mul`/`shl`
  ## whose `normalizeBinWidth` fixup is made redundant by a truncating store of
  ## `storeWidth` bytes; else -1. SOUND: `normalize` (`shl;sar`) only rewrites bits
  ## AT/ABOVE the type width B, while the store keeps only the low `storeWidth`≤B
  ## bytes — identical stored bytes with or without it. The bin result is the store's
  ## RHS (single use), so no other reader observes the un-normalized register.
  result = -1
  if rhs.kind != TagLit or storeWidth <= 0: return
  let (op, isBin) = binArithOp(rhs)
  if not isBin or op notin {AddX64, SubX64, ImulX64, ShlX64}: return
  var resTy = rhs
  inc resTy                                              # step into `(op …` → result type
  let slot = typeToSlot(resTy)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8 and
     storeWidth <= slot.size:
    result = cursorToPosition(g.buf[], rhs)

proc instrOperandReg*(g: CodeGen; cur: Cursor): Reg =
  ## The register an already-emitted `(instr …)` operand landed in. `allocInstr`
  ## asked for `NeedsReg` on every operand a lowering reads, so anything else here
  ## is an allocator bug, not a source-level condition.
  let l = g.plan.planned(cursorToPosition(g.buf[], cur))
  if l.kind != InReg:
    raiseAssert "arkham x64n: intrinsic operand is not in a register"
  l.r

proc atomicPointee*(g: var CodeGen; ptrArg: Cursor): Cursor =
  ## The type an atomic accesses: the pointee of its cell operand. Sizing the
  ## `(mem …)` by it is not a refinement — an untyped operand defaults to a 64-bit
  ## access, so an atomic on a `uint32` lock word would read and WRITE the four
  ## adjacent bytes and corrupt whatever field sits next to it (see `emMemAt`).
  result = g.getType(ptrArg)
  if isPtrType(result): inc result
  else: result = g.prog.intType

proc atomicRegClaims*(op: IntrinsicOp): set[Reg] =
  ## The registers an atomic row's lowering takes FOR ITSELF, and which therefore
  ## must not host one of its operands (`emitInstr2` seals these across the operand
  ## picks). Per-row rather than per-class, which is what keeps the exclusion
  ## affordable: a compare-exchange has three register operands plus a result, so
  ## reserving a register it never touches would exhaust the pools under pressure.
  ##
  ##  * `rax` — `cmpxchg`'s comparand is architecturally RAX, so every row that spins
  ##    on one owns it: the compare-exchange itself, and the and/or/xor retry loops
  ##    (`genAtomicLoopRmw`), which have no lock-prefixed fetch form.
  ##  * `r11` — the staging bridge, used as the `work` register by every row that
  ##    needs one. A load reads straight into its destination and a compare-exchange
  ##    works out of `rax`, so those two claim no `work` (this is exactly the
  ##    `needsWork` test below, and the two must stay in step).
  if op in {AtomicCompareExchangeOp, AtomicFetchAndOp, AtomicFetchOrOp,
            AtomicFetchXorOp}:
    result.incl RAX
  if op notin {AtomicLoadOp, AtomicCompareExchangeOp, AtomicThreadFenceOp,
               AtomicSignalFenceOp}:
    result.incl R11

proc inPlaceIntrinsicX64*(op: IntrinsicOp): bool {.inline.} =
  ## Which lowerings write their destination IN PLACE is a fact about *this*
  ## target, not about the opcode: a pinned row records it as `tie`, but a
  ## portable row (`Bswap`) has no tie and still lands on x86's in-place BSWAP.
  ## So the backend decides, and the caller seeds the destination with operand 0.
  ## Safe for every form here: they have a single register operand (`rol`/`ror`
  ## take their count as an immediate — the row's `tie` made the allocator keep it
  ## one), so that seeding copy can clobber no other operand.
  op in {BswapOp, BswapPinnedOp, RolOp, RorOp}

proc emitNullaryIntrinsicX64*(g: var CodeGen; op: IntrinsicOp) =
  ## A row with no operands and no result (`isNullaryVoid`): the opcode, and
  ## nothing else. Kept apart from `emitIntrinsicOps` because there is no
  ## `dst`/`src0` to hand it — nothing here is placed, sealed, bound or freed,
  ## which is exactly why the two call sites below can take it before any of that
  ## machinery runs.
  case op
  of CpuRelaxOp:
    # `pause` is a `rep nop`: architecturally a no-op, so it needs no CPU feature
    # test, and it clobbers nothing — not a register, not a flag, not memory. The
    # register allocator therefore has nothing to hear about this node.
    g.ab.keyword PauseX64
  of SyscallOp:
    # The bare instruction. Unlike a `(syproc …)` call site — where arkham marshals
    # the arguments into the syscall ABI registers and declares the clobbers — this
    # says only "trap now": the number, the arguments and the reading of the result
    # are the surrounding `.assembler` body's, which is the whole point (see the
    # row's comment in `lib/intrinsics`).
    g.ab.keyword SyscallX64
  else:
    raiseAssert "arkham x64n: no lowering for the nullary intrinsic `" &
                IntrinsicNames[op] & "`"

proc x64InoutTag*(op: IntrinsicOp): X64Inst =
  ## The nifasm tag a two-address row emits. Name-for-name throughout — the row's
  ## name IS the assembler's mnemonic — so this crosses the two ENUMS and nothing
  ## else; a row that reaches here without a tag is one the table gained and this
  ## did not, which `NopX64` turns into the caller's `lengError`. (It once also
  ## reconciled two vocabularies: `bitand` → `(and)`, because the pragma argument
  ## was an ident and could not be a Nim keyword. It is a string now, and the cover
  ## names are gone.)
  case op
  of AddOp: AddX64
  of SubOp: SubX64
  of AndOp: AndX64
  of OrOp: OrX64
  of XorOp: XorX64
  of ShlOp: ShlX64
  of ShrOp: ShrX64
  of SarOp: SarX64
  of NegOp: NegX64
  of NotOp: NotX64
  of IncOp: IncX64
  of DecOp: DecX64
  else: NopX64

proc proctypeOfTarget*(g: var CodeGen; targetCur: Cursor): Cursor =
  ## The resolved proctype body of an indirect call target, for ABI queries. The target
  ## is just an EXPRESSION whose type IS the proctype — a proc-typed local/param, a
  ## closure's `(dot clo fld.0)` field, or a vtable `(cast Proctype …)` (`getType` of a
  ## cast yields its target type). One rule: `getType(target)`, peel a `(ptr proctype)`.
  result = resolveType(g.prog, g.getType(targetCur))
  if result.kind == TagLit and result.typeKind != ProctypeT:
    var inner = result; inc inner                        # peel `(ptr proctype)` → proctype
    result = resolveType(g.prog, inner)
  assert result.kind == TagLit and result.typeKind == ProctypeT,
    "arkham x64n: indirect call target is not a proctype"

proc transparentCastInner*(g: var CodeGen; c: Cursor; home: Location): tuple[hit: bool, inner: Cursor] =
  ## A conv/cast is a NO-OP when the allocator dest-threaded the SAME stack home onto
  ## both it and its inner operand (they denote one value) and the conversion is a
  ## non-narrowing, non-pointer int relabel. For a register home the emitter already
  ## folds this in place; but when the shared home is a spill SLOT, re-emitting the
  ## cast round-trips the value through the staging bridge (load slot→reg; store
  ## reg→slot), once PER level of a nested `cast(conv(field))` chain — the store/reload
  ## NOP storms in spilled rawAlloc/rawDealloc code. Return the inner cursor so the
  ## caller can emit it straight into the shared home instead. Non-narrowing only: the
  ## inner's sized slot store/reload already preserves its value at the source width
  ## (a 32-bit field load zero/sign-extends), so widen/identity needs no fixup; a
  ## NARROWING cast emits a real `shl;shr` truncation and must NOT be skipped.
  result = (false, default(Cursor))
  if home.kind != NamedStack: return
  if not (c.kind == TagLit and c.exprKind in {ConvC, CastC}): return
  var tgtC, innerC: Cursor
  block:
    var cc = c
    cc.into:
      tgtC = cc; skip cc
      innerC = cc; skip cc
      while cc.hasMore: skip cc
  let innerLoc = g.plan.planned(cursorToPosition(g.buf[], innerC))
  if innerLoc.kind != NamedStack or innerLoc.name != home.name: return
  let tc = resolveType(g.prog, tgtC)
  if isPtrType(tc) or isPtrType(resolveType(g.prog, g.getType(innerC))): return
  let (srcW, _) = g.srcWidthSigned(innerC)
  if intTypeWidth(tc) >= srcW: result = (true, innerC)

proc lvalHasComputedPart*(c: Cursor): bool =
  ## Does materializing this lvalue's address require EMITTING a value first — a
  ## deref'd pointer or an index that is a computed expression rather than a
  ## symbol's home or a literal?
  ##
  ## This is the question `emitMemLoad2`'s `late` mode is the answer to: `late`
  ## keeps the transfer register out of the address recursion (one register per
  ## nesting level saved), and pays for it with the global-base fusion — the
  ## `lea &g` that would otherwise land straight in the result register. With no
  ## recursion to protect, that trade is a pure loss of one register, and a plain
  ## `(dot <global> f)` load then wants TWO staging registers where one suffices.
  if c.kind != TagLit: return false
  case c.exprKind
  of DotC:
    var cc = c
    cc.into:
      result = lvalHasComputedPart(cc)                # the base
      while cc.hasMore: skip cc
  of BaseobjC:
    var cc = c
    cc.into:
      skip cc; skip cc                                # base type, depth
      result = lvalHasComputedPart(cc)                # the inner lvalue
      while cc.hasMore: skip cc
  of DerefC:
    var cc = c
    cc.into:
      result = cc.kind == TagLit                      # a computed pointer
      while cc.hasMore: skip cc
  of AtC:
    var cc = c
    cc.into:
      result = lvalHasComputedPart(cc); skip cc       # the base
      if not result and cc.kind == TagLit: result = true   # a computed index
      while cc.hasMore: skip cc
  of PatC:
    var cc = c
    cc.into:
      result = cc.kind == TagLit; skip cc             # a computed pointer
      if not result and cc.kind == TagLit: result = true   # a computed index
      while cc.hasMore: skip cc
  else: result = true                                 # a constructor base: it emits

proc fbinOps*(ek: LengExpr): (X64Inst, X64Inst) =
  ## (32-bit, 64-bit) SSE instruction pair for a float binary-arith node.
  case ek
  of AddC: (AddssX64, AddsdX64)
  of SubC: (SubssX64, SubsdX64)
  of MulC: (MulssX64, MulsdX64)
  of DivC: (DivssX64, DivsdX64)
  else: raiseAssert "arkham x64n: fbinOps " & $ek

proc restoreMemBase2*(g: var CodeGen; pos: int) =
  ## Undo `reloadMemBase2`: release the staging reg and restore the local's stack home.
  if g.savedHomes.hasKey(pos):
    g.giveBack g.plan.planned(pos).r
    g.plan.planAtEmitTime(pos, g.savedHomes[pos])
    g.savedHomes.del pos

proc lvalUsesReg*(g: var CodeGen; c: Cursor; r: Reg): bool =
  ## Does any already-materialized part of lvalue `c`'s ADDRESS occupy `r`? Used
  ## to keep a borrowed stride scratch off the base register (nifasm rejects
  ## `scratch == base`: the scratch is written before the base is read).
  case c.kind
  of Symbol:                                        # a global base's `lea` register
    let l = g.plan.planned(cursorToPosition(g.buf[], c))
    result = (l.kind == InReg and l.r == r) or
             g.lvalGlobBase.getOrDefault(cursorToPosition(g.buf[], c), NoReg) == r
  of TagLit:
    case c.exprKind
    of DotC, BaseobjC:
      var cc = c
      cc.into:
        if c.exprKind == BaseobjC: (skip cc; skip cc)  # base type, depth
        result = g.lvalUsesReg(cc, r)
        while cc.hasMore: skip cc
    of DerefC:
      var cc = c
      cc.into:
        let l = g.plan.planned(cursorToPosition(g.buf[], cc))
        result = l.kind == InReg and l.r == r
        while cc.hasMore: skip cc
    of AtC, PatC:
      if g.lvalStride.getOrDefault(cursorToPosition(g.buf[], c), NoReg) == r:
        return true
      var cc = c
      cc.into:
        if c.exprKind == PatC:                      # the pointer is a VALUE
          let l = g.plan.planned(cursorToPosition(g.buf[], cc))
          result = l.kind == InReg and l.r == r
        else:
          result = g.lvalUsesReg(cc, r)             # the base is an lvalue
        skip cc
        if not result and cc.hasMore and cc.kind notin {IntLit, UIntLit}:
          let l = g.plan.planned(cursorToPosition(g.buf[], cc))
          result = l.kind == InReg and l.r == r
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc lvalGlobBaseReg*(g: var CodeGen; c: Cursor): Reg =
  ## The emit-time staging register `prematLval2` parked for a TRANSIENT global
  ## base (`lea s, &global`), or `NoReg` when this lvalue has no such base. The
  ## address it holds is dead once the consuming `mov` has read it, so `s` can
  ## double as that `mov`'s destination when nothing else is free. Only a base
  ## reached through `dot`/`at` qualifies: a `deref`/`pat` pointer is a VALUE the
  ## allocator homed, not a transient this walk owns.
  result = NoReg
  case c.kind
  of Symbol:
    result = g.lvalGlobBase.getOrDefault(cursorToPosition(g.buf[], c), NoReg)
  of TagLit:
    case c.exprKind
    of DotC, AtC:
      var cc = c
      cc.into:
        result = g.lvalGlobBaseReg(cc)
        while cc.hasMore: skip cc
    else: discard
  else: discard

proc dropLvalStride*(g: var CodeGen; atPos: int) =
  ## Release a `takeLvalStride` scratch after the consuming `(mem …)`/`(lea …)`.
  if g.lvalStride.hasKey(atPos):
    let s = g.lvalStride[atPos]
    if atPos in g.lvalStrideBorrowed:
      # The consumer's destination register: it owns it, so it frees it.
      g.lvalStrideBorrowed.excl atPos
    else:
      g.unbindTemp(s)
      g.plan.unseal s
    g.lvalStride.del atPos

proc derefDispSplit*(g: var CodeGen; c: Cursor): (Cursor, int32, bool) =
  ## For a `(deref P)` lvalue: is `P` a pointer plus a compile-time constant BYTE
  ## offset? If so, return the sub-expression that actually needs a register and the
  ## displacement, which x86 carries in the address operand for free — so
  ## `mov r,base; add r,K; mov x,[r]` becomes `mov x,[base+K]`, two instructions and
  ## one register temp lighter.
  ##
  ## A PURE function of the subtree, deliberately: `prematLval2` consults it to decide
  ## what to materialize and `emMemLval2` consults it to decide whether to emit the
  ## displacement. Being one function, they cannot disagree — the same discipline
  ## `constFold` is under. Both are gated on the caller's `foldDisp`, so a `deref`
  ## nested under a `(dot …)`/`(at …)`/`(lea …)` (where a trailing IntLit would be read
  ## as a field/index or not read at all) never reaches either.
  ##
  ## Requirements beyond the shape: the add must be at full register width (a narrower
  ## one wraps where an address does not), the constant must fit disp32, and it must be
  ## non-zero (nothing to fold otherwise).
  result = (c, 0'i32, false)
  if c.kind != TagLit or c.exprKind != DerefC: return
  var p: Cursor
  block:
    var dd = c
    dd.into:
      p = dd; skip dd
      while dd.hasMore: skip dd
  # Peel the value-preserving wrappers the pointer arrives in — hexer spells the
  # address arithmetic `cast[ptr T](cast[uint](base) + k)`.
  var core = p
  var guard = 0
  while core.kind == TagLit and guard < 8:
    inc guard
    let ek = core.exprKind
    if ek in {CastC, ConvC}:
      var t = core
      t.into:
        skip t                                  # the target type
        core = t
        while t.hasMore: skip t
    elif ek in {SufC, ParC}:
      var t = core
      t.into:
        core = t
        while t.hasMore: skip t
    else: break
  if core.kind != TagLit or core.exprKind notin {AddC, SubC}: return
  let isSub = core.exprKind == SubC
  var a, b: Cursor
  var widthOk = false
  block:
    var t = core
    t.into:
      if t.kind == TagLit:
        case t.typeKind
        of IT, UT:
          let bits = typeBits(t)
          widthOk = bits == 64 or bits <= 0   # `(i -1)` is the platform int
        else: discard
      skip t                                    # result type
      a = t; skip t
      b = t; skip t
      while t.hasMore: skip t
  if not widthOk: return
  # The constant is the right operand; for `add` it may equally be the left one.
  var baseCur = a
  var (ok, k) = g.tryConstFold(b)
  if not ok and not isSub:
    (ok, k) = g.tryConstFold(a)
    baseCur = b
  if not ok: return
  if isSub: k = -k
  if k == 0 or k < low(int32).int64 or k > high(int32).int64: return
  if g.tryConstFold(baseCur)[0]: return         # wholly constant: not our fold
  result = (baseCur, int32(k), true)

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
  let pos = cursorToPosition(g.buf[], c)
  g.restoreMemBase2(pos)                             # demoted (stolen) base/index reload
  let l = g.plan.planned(pos)
  if l.kind == InReg and l.isTemp: g.unbindTemp(l.r)

proc fieldSlotByName*(g: var CodeGen; typeSym: SymId; field: string): AsmSlot =
  ## The asm slot of `typeSym.field` — so an aggregate-copy scratch can be typed to
  ## match the field (nifasm is strict: a `(ptr T)` field can't move through an
  ## `(i 64)` register). Resolves the object body from the type's decl like aggrLayout.
  var d = lookupType(g.prog, typeSym)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = slotOf(g.prog, fieldType(g.prog, d, field))
    while d.hasMore: skip d

proc emWordAtSlot*(g: var CodeGen; name: string; off: int) =
  ## `(cast (u 64) (mem name off))` — the eightbyte at byte offset `off` of the
  ## NAMED stack slot `name`, typed as a raw word. The pointer twin `emWordThroughPtr`
  ## needs the slot's ADDRESS in a register first; this needs no register at all,
  ## because nifasm folds `off` into the slot's own frame displacement (and bounds-checks
  ## it against the slot, which the register form cannot).
  g.ab.tree CastX:
    g.ab.uintType(64)
    g.ab.tree MemX:
      g.ab.sym name
      g.ab.intLit off.int64

proc emByteAtSlot*(g: var CodeGen; name: string; off: int) =
  ## The byte-granular `emWordAtSlot`, for a copy's sub-word tail.
  g.ab.tree CastX:
    g.ab.uintType(8)
    g.ab.tree MemX:
      g.ab.sym name
      g.ab.intLit off.int64

proc fieldTypeByName*(g: var CodeGen; typeSym: SymId; field: string): Cursor =
  ## The declared (nominal) type cursor of `typeSym.field` — resolves the object body
  ## from the type's decl like `fieldSlotByName`.
  var d = lookupType(g.prog, typeSym)
  d.into:
    inc d; skip d                              # name, type-pragmas → the body
    result = fieldType(g.prog, d, field)
    while d.hasMore: skip d

proc isAggrCopySrc*(c: Cursor): bool =
  ## An aggregate-valued source that is COPIED (not produced): a symbol or a memory lvalue.
  c.kind == Symbol or (c.kind == TagLit and c.exprKind in {DotC, DerefC, AtC, PatC})

proc dstAggrInfo*(g: var CodeGen; dst: Location): (bool, int) =
  ## (is `dst` an aggregate location?, its byte size). A global / thread-local aggregate
  ## both reduce to an address (`aggrAddrLoc` → `emSymAddr`) for the whole-aggregate copy.
  case dst.kind
  of NamedStack: (dst.typ.kind == AMem, dst.typ.size)
  of StackPtr: (true, dst.typ.size)      # `typ` is the pointee: always an aggregate
  of Glob, Tvar: (dst.typ.kind == AMem, dst.typ.size)
  of InRegPair: (true, dst.typ.size)
  of Mem:
    let s = g.exprSlot(dst.cur)
    (s.kind == AMem, s.size)
  else: (false, 0)

proc foldableFloatLeaf*(g: var CodeGen; c: Cursor): bool =
  c.kind == Symbol and g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind in {InFReg, NamedStack}

proc emCallerSaveStore(g: var CodeGen; varName: string) =
  ## Save a caller-saved value into its permanent slot, then release the register.
  g.ab.tree MovX64:                                  # (mov (mem (rsp) slot) name)
    g.emStackMem(callerSaveSlotName(varName))
    g.ab.sym varName
  # Then RELEASE the register. The home is an argument register, and marshalling is
  # about to write it; nifasm rejects a write to a register that still carries a live
  # binding ("use the variable name instead"). Releasing here is exactly what makes an
  # argument register a legal caller-saved home: between this kill and the restore the
  # value lives only in the slot, so the ABI partition is intact for the whole call.
  g.ab.tree KillX64: g.ab.sym varName
  discard g.rb.takeBinding(g.plan.homeOfSym(varName).r)

proc emCallerSaveRestore(g: var CodeGen; slotName, varName: string; r: Reg) =
  ## Reload a caller-saved value after the call. The call CLOBBERS every volatile, and
  ## nifasm drops the bindings of clobbered registers with it — so the name is no longer
  ## a legal destination and must be re-bound first (same register, same type it was
  ## declared with) before the reload can name it.
  let dead = g.rb.takeBinding(r)                     # whatever the call left there
  if dead.len > 0 and dead != varName:
    g.ab.tree KillX64: g.ab.sym dead
  var isPtr = false
  g.ab.tree RebindX64:
    g.ab.symDef varName
    if g.symType.hasKey(varName):
      # Its declared type, whatever it is — see `restoreBindings` for why a blanket
      # `(i 64)` is not good enough for a non-pointer either.
      isPtr = isPtrType(resolveType(g.prog, g.symType[varName]))
      var tc = g.symType[varName]
      g.genTypeBody(tc)
    else:
      g.ab.intType(64)
    g.ab.rawReg r
  g.rb.rebindLocal(r, varName, isPtr)
  g.ab.tree MovX64:
    g.ab.sym varName
    g.emStackMem(slotName)

proc emCallerSaveOpen*(g: var CodeGen): CallerSaveWindow =
  ## Open a call's caller-save window: store every caller-saved local BOUND right now
  ## into its slot, release the binding, and redirect its reads there
  ## (`plan.callerSaveActive`). Idempotent with respect to an ENCLOSING window — a value
  ## already active is skipped, since its register may already be clobbered, so
  ## re-saving would store garbage, and reads already resolve to the outer slot.
  for it in g.callerSaveSetAt():
    if not g.plan.callerSaveActive.hasKey(it.name): result.saved.add it
  if result.saved.len == 0: return
  # Types BEFORE the redirects are installed: `locationOfSym` answers with the slot
  # once a name is active, and the restore needs the register's declared type.
  var types: seq[AsmSlot] = @[]
  for it in result.saved: types.add g.plan.homeOfSym(it.name).typ
  result.prevActive = g.plan.callerSaveActive          # nested calls restore, never clear
  for it in result.saved: g.emCallerSaveStore(it.name)
  for i, it in result.saved:
    g.plan.callerSaveActive[it.name] =
      Location(kind: NamedStack, name: callerSaveSlotName(it.name), typ: types[i])

proc emCallerSaveClose*(g: var CodeGen; w: CallerSaveWindow; dest: Location) =
  if w.saved.len == 0: return
  g.plan.callerSaveActive = w.prevActive
  for it in w.saved:
    # The result settling into this very register means the call overwrote the home;
    # restoring would clobber the result. Unreachable for a valid caller-saved value
    # (single-def, never born from a call), kept as a guard.
    if dest.kind == InReg and dest.r == it.reg: continue
    g.emCallerSaveRestore(callerSaveSlotName(it.name), it.name, it.reg)

proc takeInstrReg*(g: var CodeGen; slot: AsmSlot): Location =
  ## A register an `(instr …)` operand or result MUST have (no memory form).
  ## Pools first; exhausted, draw from the emit-time STAGING set — an intrinsic
  ## crosses no call, so a transient serves (sealed so a nested pick can't
  ## reuse it; the consumer's `giveBack` unseals). This is strictly better than
  ## the old allocator's answer, which had to DEMOTE a local to memory here.
  let r = g.pickTempReg()
  if r != NoReg:
    g.pickedRegs.incl r
    return regLoc(r, slot, isTemp = true)
  # What this draw must NOT return — the registers the row's own lowering claims —
  # is a SEAL held by `emitInstr2` (`atomicRegClaims`) rather than an `avoid`
  # argument: there can be two of them, and the seal also covers the nested
  # `pickStaging` calls inside `emitValue2`, which an `avoid` here would not reach.
  let s = g.pickStagingScratch()
  if s == NoReg:
    raiseAssert "arkham x64n: out of registers for an intrinsic operand in proc " &
                g.curProcName & g.stagingCensus(NoReg)
  g.plan.seal {s}
  result = regLoc(s, slot, isTemp = true)

proc instrOperandInPlace*(g: var CodeGen; a: Cursor; avoid: set[Reg]): Location =
  ## An intrinsic operand that is a SYMBOL already living in a register is read
  ## WHERE IT LIES, instead of `takeInstrReg`-ing a second register and `mov`ing
  ## the value across. The copy is free on a wide machine and ruinous on this one:
  ## the emitter's whole budget is r10 + r11 (design.md, "keep each step's demand
  ## inside that budget"), and a compare-exchange needs THREE registers at once
  ## plus its rax claim. Under `-d:danger` the allocator homes a local in every
  ## other volatile, so the third pick had nothing left and the `atomicCompareExchange`
  ## inlined into `realloc` did not compile at all.
  ##
  ## Sound because every row reaching here treats its operands as pure input: a
  ## two-address `roInout` row returns before this, the atomic sequences write only
  ## their `work` register, rax and the result (see `genAtomicXadd`'s note), and
  ## `emitIntrinsicOps` only ever reads `src0`. `avoid` is what the lowering DOES
  ## write — its claims and the result — since an operand read after the row
  ## clobbered its home would read the row's own output.
  ##
  ## `isTemp` stays false: this register is a local's home, not something the row
  ## may bind, unbind or give back. That is what the `d.isTemp` guards on the two
  ## release loops below are for.
  result = Location(kind: Undef)
  if a.kind != Symbol: return
  let home = g.plan.locationOfSym(symName(a), cursorToPosition(g.buf[], a))
  if home.kind == InReg and home.r notin avoid:
    result = home

proc atomicValueMayBeImm*(op: IntrinsicOp; i: int): bool {.inline.} =
  ## May an atomic's operand `i` stay a literal on x86-64? (Port of the
  ## allocator's `atomicValueMayBeImm`, x64 half.)
  i == 1 and op in {AtomicStoreOp, AtomicExchangeOp, AtomicFetchAddOp,
                    AtomicFetchSubOp, AtomicAddFetchOp, AtomicSubFetchOp,
                    AtomicFetchAndOp, AtomicFetchOrOp, AtomicFetchXorOp}

proc resolveLvalVal*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED: decide (only) where an lvalue-embedded VALUE — a deref'd pointer, a
  ## computed index — will live; `prematLval2` materializes it into the decided
  ## location right before the consuming `(mem …)` opens. A symbol resolves to
  ## its home, a literal to an immediate, a computed subtree to a reserved temp
  ## (its own computation emits at premat time, dest-threaded).
  case c.kind
  of Symbol:
    let home = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    if home.kind == NoLoc: g.forceRegDest(dest)     # a global/tvar value read
    elif home.kind in {NamedStack, Mem} and dest.kind in {NeedsReg, RegOrImm} and
         g.tempPoolDry():
      # A stack-homed symbol IS its own natural location. Honouring `NeedsReg`
      # with the temp pool dry mints an `etmpN.0` SLOT — which cannot satisfy
      # "needs a register" in the first place. `prematAddrVal2` then copies one
      # stack slot into the other through the staging bridge, and
      # `reloadMemBase2` loads it straight back out:
      #     mov R, [home] ; mov [etmp], R ; mov R, [etmp]
      # Three instructions, a wasted frame slot, and staging taken TWICE, to end
      # up exactly where the first instruction already was. Every consumer of an
      # lvalue-embedded value goes through `reloadMemBase2`, whose whole job is
      # bringing a memory home into a staging register — and it does that just as
      # well from the symbol's OWN slot, in one load and one staging pick. So
      # record the home and reserve nothing.
      #
      # Gated on the pool being dry so this changes NOTHING while a temp is free:
      # there `takeTmp` gives a real register, the value lands in it, and holding
      # it across the address computation is what we want.
      dest = home
    else: g.resolveDest(dest, home)
  of IntLit: g.resolveDest(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.resolveDest(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.resolveDest(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  else: g.forceRegDest(dest)                        # computed: reserve the result

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
  let pos = cursorToPosition(g.buf[], n)
  var d = if held: g.takeHeld(what) else: needsReg(ScalarSlot)
  g.resolveLvalVal(n, d)
  g.plan.planAtEmitTime(pos, d)
  skip n

proc freeLvalTemps2*(g: var CodeGen; c: Cursor) =
  ## FUSED port of `releaseLvalTemps`: release the reserved scratch of an
  ## lvalue's address computation — a computed index (`at`/`pat`), a computed
  ## pointer (`deref`/`pat`) — dead once the consuming access used the address.
  ## `freeVal` is a no-op on a symbol's home (non-temp). The stride scratch /
  ## global-base staging are released by `unbindLvalTemps2` (staging-managed).
  if c.kind != TagLit: return
  case c.exprKind
  of DotC:
    var cc = c
    cc.into:
      g.freeLvalTemps2(cc)                           # base
      while cc.hasMore: skip cc
  of DerefC:
    var cc = c
    cc.into:
      g.freeVal(g.plan.planned(cursorToPosition(g.buf[], cc)))   # the pointer value
      while cc.hasMore: skip cc
  of AtC:
    var cc = c
    cc.into:
      g.freeLvalTemps2(cc)                           # base (by-value: does not advance)
      skip cc                                        # → the index operand
      if cc.kind notin {IntLit, UIntLit}:
        g.freeVal(g.plan.planned(cursorToPosition(g.buf[], cc))) # the computed index
      while cc.hasMore: skip cc
  of PatC:
    var cc = c
    cc.into:
      g.freeVal(g.plan.planned(cursorToPosition(g.buf[], cc)))   # the pointer value
      skip cc
      if cc.kind notin {IntLit, UIntLit}:
        g.freeVal(g.plan.planned(cursorToPosition(g.buf[], cc))) # the computed index
      while cc.hasMore: skip cc
  of BaseobjC:                                       # transparent: free the inner lvalue's temps
    var cc = c
    cc.into:
      skip cc; skip cc                               # base type, depth
      g.freeLvalTemps2(cc)                           # the inner lvalue
      while cc.hasMore: skip cc
  else: discard
