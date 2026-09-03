#
#           Arkham — x86-64 / System V (Linux) code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3 (x86-64 backend). A first, scalar-integer code generator: it shares the
## front-end (`codegen_common`: the `CodeGen` state, the Leng type/lvalue
## analysis) and the (arch-neutral) register allocator with the AArch64 backend,
## and emits System V / Linux asm-NIF that `nifasm` assembles+links to an ELF
## executable. Process exit is lowered to the Linux `exit` syscall (rax=60), so
## the produced binaries run without libc.
##
## v0 scope (mirrors arkham's AArch64 v1): integer/pointer scalars held in
## registers, arithmetic / bitops, `while`, comparisons, and a `main` that
## `exit`s. Floats, aggregates, memory lvalues, parameters, `if`/`case`, div/mod
## and shifts `raiseAssert` for now.

import std / [assertions, tables, sets, os, strutils]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, analyser, planer, programs, asmbuf,
                    stress, context, diag, typeutil, constdata,
                    mirrors, temps, exprpred, abi]
import "../core/typenav"
export typenav   # SymCat / SymInfo / getType / exprSlot; re-exported so the
                 # backends' `g.lookupSym(...).cat` keeps resolving
import "../core/regbind"
export regbind   # the emitter's register-binding state (`g.rb`) — the single
                 # owner of reg<->name bindings, see regbind.nim
import machine as machine_x64
import emit, mem, aggr

let x64MachineA* = stressed(x64Machine)
  ## The machine arkham allocates against: `x64Machine` itself, unless the
  ## `-d:arkhamStress` shrink is armed (see `stress.nim`). A module-level `let`
  ## so the environment is read and the pools rebuilt once, not per proc.

# ── scratch register pool ────────────────────────────────────────────────────


# ── SSE / floating-point scratch pool + emit helpers ─────────────────────────
# x86-64 floats live in xmm0..xmm15 (the FReg slots F0..F15). The register operand
# is always `(xmmN)`; the precision is carried by the instruction tag (movss vs
# movsd, addss vs addsd, …), unlike AArch64 where `(sN)`/`(dN)` encode it.

# A spilled float scalar lives in an `(s) (f N)` stack slot (x64 has no callee-
# saved xmm registers, so a float that must survive a call has nowhere else to
# go). It is loaded/stored with movss/movsd against `(mem (rsp) name)`.
# ── low-level emit helpers ───────────────────────────────────────────────────


proc emSyscall*(g: var CodeGen) = g.ab.keyword SyscallX64

# ── expressions ──────────────────────────────────────────────────────────────

# value-core emitters (defined far below) used by the shared memory-move helpers
# (`scalarMemMov`/`floatMemMov`) to emit a folded access chain:
proc prematLval2*(g: var CodeGen; c: Cursor; asBase = false; hint = NoReg;
                 foldDisp = false)
# ── fused value core (step 3): decide-and-emit overloads ─────────────────────
# These carry the destination as a threaded parameter (constraint in, resolved
# location out); every register decision is made inline at the point of
# emission.
proc emitValue2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitBin2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitDivMod2(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondValue2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCondE*(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool)
proc emitScalarCmpE*(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool): X64Inst
proc emitMemLoad2*(g: var CodeGen; c: Cursor; dest: var Location; late = false)
proc emitAddr2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCast2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitCall2*(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false;
               tail = false)
proc emitInstr2*(g: var CodeGen; c: Cursor; dest: var Location)
proc emitFValue2*(g: var CodeGen; c: Cursor; dest: var Location)
# ── named local variables (nifasm type-checks them; raw scratch stays `(reg)`) ─

when not defined(arkhamNoNarrowHomes):
  let nhFilter = getEnv("ARKHAM_NH", "*")
    ## `ARKHAM_NH`: "*" (default) = the narrow-home filter everywhere; "-" = nowhere;
    ## otherwise a comma-separated allowlist of proc asm-names. The bisect driver
    ## halves the list until one proc alone reproduces the crash.
  proc nhEnabledFor*(name: string): bool =
    if nhFilter == "*": return true
    if nhFilter == "-": return false
    for it in nhFilter.split(','):
      if it == name: return true
    false

# ── bindings across a DIVERGING call ────────────────────────────────────────
# A `(attr "noreturn")` callee never comes back, so the statement after its call is
# reached only by a branch that jumped OVER the whole `(prepare …)` — at which point
# every register still holds what it held before. Nothing has to survive the call;
# what has to survive is the NAME. `rb` is linear and cannot say "not this path", so
# the `(kill nm)`s the marshalling must emit (nifasm rejects a raw write to a bound
# register) erase names that are still live, and the reads after fall back to raw
# `(reg)` operands nothing can check. Snapshot, then re-establish.

# ── stack-slot declarations + memory operands (x86 addressing) ───────────────
# nifasm keeps field names / element types, so a memory operand stays symbolic:
#  * a spilled/address-taken scalar or aggregate is a `(var :name (s) T)` slot,
#    addressed `(mem (rsp) name)` / `(mem (dot (rsp) name field))`;
#  * a pointer in a register is dereferenced `(mem reg)`.
# Storing an immediate to memory is unimplemented in nifasm, so callers
# materialize the value into a register first.

# ── store forwarding: writing and reading the mirror map ────────────────────
# The map, its invalidation rules and the two safety predicates live in
# regbind.nim / codegen_common.nim; these are the two doors the x86-64 emitter
# uses them through.

proc scalarMemMov(g: var CodeGen; loc: Location; reg: Reg; load: bool) =
  ## The one GPR scalar memory move over every lvalue kind, both directions:
  ## `load` → `reg ← <loc>`; else `<loc> ← reg`. Load and store are mirror images
  ## — the value register and the memory operand swap order in the `(mov …)` — apart
  ## from `Glob`, which folds its address into the access where it can (`(gload …)`/
  ## `(gstore …)`, no scratch at all) and otherwise has to materialize the address
  ## first: a store must stage that address in a SEPARATE register, since `reg` still
  ## holds the value being stored, while a load can fall back to staging it in `reg`
  ## itself. See the branch.
  case loc.kind
  of InReg:
    if load: g.movReg(reg, loc.r) else: g.movReg(loc.r, reg)
  of Tvar:                                        # nifasm resolves a tvar to FS:[off]
    g.ab.tree MovX64:
      if load: (g.emReg reg; g.ab.sym loc.name)
      else:    (g.ab.sym loc.name; g.emReg reg)
  of Glob:
    if g.globalFoldsIntoAccess(loc.name):
      # The address folds INTO the access: one RIP-relative `mov` instead of an
      # `(lea T &g)` and a `(mov D (mem T))`, and no staging register at all — which
      # is the half that matters inside an address computation that has already spent
      # every scratch it has. nifasm sizes and extends the access from the gvar's own
      # declared type, exactly as the `(mem …)` form did.
      g.ab.tree (if load: GloadX64 else: GstoreX64):
        g.emReg reg
        g.ab.sym g.prog.gvarRefName(loc.name)
      return
    if load:                                       # &g into a typed staging temp, then deref
      # The address temp is `(ptr <globalType>)` so the `(mem p)` deref yields the
      # global's PRECISE type. Mirror of the store branch below, and the form to prefer:
      # `reg` keeps one binding for the whole step.
      var pSlot = ScalarSlot
      if not cursorIsNil(loc.typ.typ):
        pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
      var p = g.pickStagingScratch()
      if p == NoReg and g.rb.isBoundTemp(reg):
        # NOTHING free — and this step must not be the one that fails, because it is
        # reached from inside an address computation that already owns every staging
        # register (`-d:danger` `toDecimal64`: an `(at <global> <expr>)` whose base
        # address is staged and whose index reads a second global). So drop the demand
        # to ZERO extra registers instead of hunting for one, per design.md's "keep
        # each step's demand inside that budget".
        #
        # `reg` is the LOAD's destination: whatever it holds is dead, so it can carry
        # the address for the two instructions before the value lands in it. The
        # pointer level that costs — nifasm would deref a `(ptr T)`-bound `reg` to `T`
        # while the destination wants `T` — is supplied by the `(cast (aptr T) …)` the
        # element operand already wraps its address register in, which reads `reg`
        # whatever its binding says. So `reg` is bound as a raw address across the
        # `lea` and as the value's own type across the `mov`; both rebinds are
        # zero machine code.
        g.releaseStaleName(reg)
        g.bindTemp(reg, AddrSlot)                  # a raw `(u 64)` address for the lea
        g.emGlobalAddr(reg, loc.name)
        g.releaseStaleName(reg)
        g.bindTemp(reg, loc.typ)                   # the value's own type for the mov
        g.ab.tree MovX64:
          g.emReg reg
          if cursorIsNil(loc.typ.typ): g.emWordThroughPtr(reg, 0)
          else: g.emPtrElemMem(reg, loc.typ.typ, 0)
      else:
        p = g.pickStagingSealed("a global load address", pSlot)
        g.emGlobalAddr(p, loc.name)
        g.ab.tree MovX64:
          g.emReg reg
          g.ab.tree MemX: g.emReg p
        g.giveBack p
    else:                                          # &g into a staging temp, then store
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries
      # the global's PRECISE type — a store of a typed pointer value into a pointer
      # global would otherwise mismatch a generic `(i 64)` mem (nifasm is strict).
      var pSlot = ScalarSlot
      if not cursorIsNil(loc.typ.typ):
        pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
      let p = g.pickStagingSealed("a global store address", pSlot)
      g.emGlobalAddr(p, loc.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg p
        g.emReg reg
      g.giveBack p
  of NamedStack:                                  # spilled scalar / synthetic spill slot
    g.ab.tree MovX64:
      if load: (g.emReg reg; g.emStackMem(loc.name))
      else:    (g.emStackMem(loc.name); g.emReg reg)
  of Mem:
    let wr = g.pairFieldReg(loc.cur)
    if wr != NoReg:
      if load:
        if wr != reg: g.movReg(reg, wr)
      else:
        if wr != reg: g.movReg(wr, reg)
      return
    # A folded access chain: materialize the embedded base/index values (statements
    # BEFORE the consuming `mov`), emit the chain as one nifasm address operand,
    # then release the address temps — the value-core lvalue machinery.
    g.prematLval2(loc.cur, foldDisp = true)
    g.ab.tree MovX64:
      if load:
        g.emReg reg
        g.emMemLval2(loc.cur)
      else:
        g.emMemLval2(loc.cur)
        g.emReg reg
    g.unbindLvalTemps2(loc.cur)
  else: raiseAssert "arkham x64: scalarMemMov on location kind " & $loc.kind

proc emitLoadLoc*(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← <scalar Location>` (the one scalar load, over every lvalue kind).
  g.scalarMemMov(loc, dest, load = true)

proc emitStoreLoc*(g: var CodeGen; loc: Location; src: Reg) =
  ## `<scalar Location> ← src` (GPR). The store counterpart of `emitLoadLoc`.
  ##
  ## THE invalidation point for a store: whatever mirrored this slot's old value
  ## is stale from here on. It sits at the lowest level on purpose — every scalar
  ## store funnels through here, so no store path can forget it. (A store to a
  ## COMPUTED lvalue cannot invalidate anything else: only an address-taken local
  ## can be reached that way, and those are never mirrored — see `mayMirror`.)
  if loc.kind == NamedStack: g.killMirrorsOf loc.name
  g.scalarMemMov(loc, src, load = false)

proc floatMemMov(g: var CodeGen; loc: Location; reg: FReg; bits: int; load: bool) =
  ## The one SIMD scalar memory move, both directions: `load` → `reg ← <loc>`; else
  ## `<loc> ← reg`. The float twin of `scalarMemMov`; floats occur only as InFReg /
  ## NamedStack / Mem (no Tvar/Glob), and the `Mem` arm is the mirror-image swap.
  case loc.kind
  of InFReg:
    if load: g.fmovF(reg, loc.f, bits) else: g.fmovF(loc.f, reg, bits)
  of NamedStack:
    if load: g.emFloatScalarLoad(reg, loc.name, bits)
    else:    g.emFloatScalarStore(loc.name, reg, bits)
  of Tvar:                                        # nifasm resolves a tvar to FS:[off]
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.ab.tree op:
      if load: (g.emFReg reg; g.ab.sym loc.name)
      else:    (g.ab.sym loc.name; g.emFReg reg)
  of Glob:
    # &g into a typed staging GPR, then movss/movsd through it. The address temp is
    # `(ptr <floatType>)` so the `(mem p)` deref yields the float's precise width.
    var pSlot = ScalarSlot
    if not cursorIsNil(loc.typ.typ):
      pSlot = typeToSlot(g.prog.ptrTypeOf(loc.typ.typ))
    let p = g.pickStagingSealed("a global float address", pSlot)
    g.emGlobalAddr(p, loc.name)
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.ab.tree op:
      if load:
        g.emFReg reg
        g.ab.tree MemX: g.emReg p
      else:
        g.ab.tree MemX: g.emReg p
        g.emFReg reg
    g.giveBack p
  of Mem:
    let op = if bits == 32: MovssX64 else: MovsdX64
    g.prematLval2(loc.cur, foldDisp = true)
    g.ab.tree op:
      if load:
        g.emFReg reg
        g.emMemLval2(loc.cur)
      else:
        g.emMemLval2(loc.cur)
        g.emFReg reg
    g.unbindLvalTemps2(loc.cur)
  else: raiseAssert "arkham x64: floatMemMov on location kind " & $loc.kind

proc emitStoreFLoc(g: var CodeGen; loc: Location; src: FReg; bits: int) =
  ## `<float Location> ← src`.
  if loc.kind == NamedStack: g.killMirrorsOf loc.name   # see `emitStoreLoc`
  g.floatMemMov(loc, src, bits, load = false)

# MODEL: the `pickStaging` action in proofs/arkham_bindings.tla — only ever returns a
# register with no live owner (the `Free` guard); staging on an occupied reg breaks
# NoSharedRegister. Change this ⇒ re-check that action.
# ── fused value core: emit-time destination protocol (step 3) ────────────────
# The merged emitter decides registers at the point of emission: `dest` flows
# down as a constraint (dontCare / needsReg / regOrImm / a fixed location) and
# comes back resolved — vmgen's dest threading. The temp lifecycle keeps the
# LAZY-BIND convention the emitter bodies already follow: `takeTmp` RESERVES a
# register (the `pickedRegs` flag makes it invisible to every freeness filter,
# so a nested pick can't steal a reserved accumulator), and the consumer binds
# it (`bindTemp`, which emits the `(rebind …)`) only when it materializes a
# value into it — exactly the allocator's reserve→(bind…unbind)→release shape,
# so the ported decision code keeps its structure and the serial staging-
# bridge reuse of deep spill chains keeps working. `freeVal` releases: clears
# the pick flag and unbinds if bound. An exhausted pool mints an `etmpN.0`
# spill slot (declared by the prologue, which the body-buffer model writes
# after the body), keeping temp allocation total.

# ── conditions / branches ────────────────────────────────────────────────────

# Linux syscalls are recognised in `programs.collect` (the `LinuxSyscalls` table)
# and emitted as `(syproc …)` declarations whose proctype puts args in the syscall
# ABI registers (arg4 → r10, not the C ABI's rcx) and declares the kernel's
# clobbers (rcx, r11). A call site then uses the ordinary declarative `(prepare …)`
# path with a `(syscall)` marker — see `emitSyproc` and `emitCall2`.

# ── the atomic rows (`{.intrinsic: "AtomicX".}` → x86 lock-prefixed sequences) ──
# x86-64 has a strong memory model: a plain aligned `mov` is already an atomic
# load/store, `xchg` with memory is implicitly locked, and an RMW that returns the
# old value uses `lock xadd` / a `lock cmpxchg` retry loop. The memory-order
# operands are not evaluated at all (see `evaluatedOperands`): every sequence here
# is at least acquire/release, which satisfies whichever order was asked for.
#
# An atomic arrives as `(instr …)`, so its operands are wherever the ALLOCATOR put
# them and the sequence must not assume an ABI. The only registers it takes for
# itself are `rax` — architecturally required as `cmpxchg`'s comparand — and `r11`,
# the reserved staging bridge, as the working register; which of the two a given row
# claims is `atomicRegClaims`. That claim is ENFORCED by a seal `emitInstr2` holds
# across the operand picks: it used to rest on "the allocator never hands those out",
# which is true of the pools and false of `takeInstrReg`'s staging fallback.
# The `work` register removes every aliasing question among the operands themselves —
# the caller's `p`, `val` and destination registers may coincide freely, because the
# sequence reads them and writes only its own.

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers inline. Sizes are runtime values; the
# result lands in RAX (memcpy/memmove/memset return dest, memcmp the first byte
# difference). Unlike the AArch64 backend these can't use the 2-register scratch
# pool (it can't hold dst+src+n+i+b at once), so they evaluate operands into
# fixed caller-saved registers (rdi/rsi/rdx/rcx/r8): free scratch since a mem*
# sequence contains no calls.
#
# memcpy splits on size: n < 64 is a qword loop + byte tail (no 8-byte overrun),
# n ≥ 64 is `rep movsq`/`rep movsb`. A compile-time n ≤ 64 unrolls instead.
# `rep` startup dominates the bif writer's tens of thousands of 1–7 byte copies.

# ── by-value aggregate marshalling (SysV) ────────────────────────────────────
# A ≤16-byte aggregate of full 8-byte fields travels in 1–2 GPRs (word i ↔ the
# field at byte offset 8·i); a >16-byte aggregate is passed/returned by reference
# (a pointer). This is self-consistent arkham↔arkham — NOT strict SysV, which
# would pass a >16B argument as a stack copy (MEMORY class) and return it via a
# hidden pointer in the first integer arg. A ≤16B result travels in rax:rdx.

# ── whole-aggregate copy (struct assignment / copy-init) ─────────────────────

# ── stack frame: callee-saved save/restore + incoming stack parameters ───────
# x86-64 has no pair store, so each used callee-saved GPR is a single `push`/`pop`.
# Frames are needed when the proc uses a callee-saved register (for a cross-call
# local or a stack-param home). Saved registers stay RAW (`(rbx)`), never named
# locals, so the epilogue can pop them without nifasm's bound-register guard.

# ── thread-local storage ─────────────────────────────────────────────────────
# nifasm accesses an x86-64 thread-local as `FS:[off]` (it resolves a tvar symbol
# to a displacement-only FS-segment memory operand). nifasm (the linker) owns the
# unified per-thread block `arkham.tls.0` across all bundled modules and points FS
# at it via `arch_prctl(ARCH_SET_FS, &block)` in the entry prologue it synthesizes;
# arkham only references the block for `&tvar`. The block is `.bss`, so a literal
# initializer is baked into its image bytes (nifasm's `allocTlsSlotX64`) — nothing
# runs before `main` that could store one.


# ── value core: shared helpers of the fused emitter ──────────────────────────
# Single-pass: every register decision is made inline at the point of emission
# (dest threading); `g.plan` carries only the decl-only pre-pass (param/local
# homes) plus the emitter-private `locs`/`aux` memo the fused lvalue walk
# writes. Every proc body is emitted through `genProc` → `emitProcBody2`.

proc place2*(g: var CodeGen; src: Location; dest: Reg) =
  ## Materialize `src` into register `dest` (no-op when it is already there).
  ##
  ## `dest` is about to be WRITTEN, so whatever it mirrored is stale — and a
  ## memory `src` may still be in a register, which turns the load into a move.
  ## Both are the same one-line consultation of the map; the invalidation is the
  ## half that is not optional.
  let s = g.forwardOf(src)
  if s.kind == InReg and s.r == dest: (g.killMirror(dest); return)  # already there
  g.killMirror(dest)
  case s.kind
  of InReg: (if s.r != dest: g.movReg(dest, s.r))
  of Imm: g.placeImm(dest, s)
  of NamedStack, Mem, Glob, Tvar: g.emitLoadLoc(s, dest)
  else: raiseAssert "arkham x64n: place2 src " & $s.kind

proc aggrAddrInto*(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool)
proc aggrArgAddr*(g: var CodeGen; a: Cursor; recorded: Reg; avoid: openArray[Reg]): (Reg, bool) =
  ## Materialize `&a` (an aggregate-LVALUE call argument) into a bound register, ready to
  ## marshal from. `recorded` is the allocator's reserved callee-saved survivor; `NoReg`
  ## means it spilled (the `reserveHeldScratch` totality backstop), so re-derive the
  ## address into a transient staging register instead — sealing the marshal destinations
  ## `avoid` (the arg registers about to receive the words, not yet sealed here) so the
  ## pick cannot alias a word being written. Returns `(addr reg, wasSpilled)`; the caller
  ## releases with `giveBack` (spilled) or `unbindTemp`.
  let slot = addrSlot()
  if recorded != NoReg:
    g.aggrAddrInto(a, recorded, slot, doBind = true)
    return (recorded, false)
  for r in avoid: g.plan.seal r
  let s = g.pickStagingSealed("an aggregate-arg address", slot)
  for r in avoid: g.plan.unseal r
  g.aggrAddrInto(a, s, slot, doBind = false)   # already bound by pickStagingSealed
  (s, true)
proc genConstr2*(g: var CodeGen; c: Cursor; dst: Location)
proc genStore2*(g: var CodeGen; rhs: Cursor; dst: Location)
proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor)

proc aggrArgSource(g: var CodeGen; a: Cursor; tcur: Cursor; tn: SymId):
                  (string, Reg, bool) =
  ## Reach the bytes of a NON-LVALUE aggregate call argument `a` of nominal type `tn`,
  ## and describe where they are as `(home, ptrReg, isTvar)`: a named stack slot
  ## (`home`), a pointer already in a register (`ptrReg` — a >16B by-ref param), or a
  ## module-level symbol read through its address (both empty/`NoReg`; `isTvar` picks
  ## FS-relative over RIP-relative). An `(oconstr …)`/`(aconstr …)` is BUILT here into a
  ## synthetic slot and reported as that `home`. Shared by the register-passed and the
  ## stack-passed marshalling in `emitCall2Inner` — only the destination differs.
  var home = ""
  var ptrReg = NoReg
  var isTvar = false
  if a.kind == Symbol:
    let sloc = g.plan.locationOfSym(symName(a), cursorToPosition(g.buf[], a))
    if sloc.kind in {NamedStack, StackPtr}:
      # By NAME either way: the readers (`transferAggrWords`, `aggrSrcEnd`,
      # `emAggrSrcAddr`, `genAggrCopy2`) re-ask the home and load the pointer for a
      # `StackPtr` — this only has to not lose the symbol.
      home = symName(a)
    elif sloc.kind == InRegPair:
      home = symName(a)                           # structToRegs reads the pair from the name
    elif sloc.kind == InReg:
      ptrReg = sloc.r                             # a >16B by-ref param: its pointer is already in a reg
    elif g.lookupSym(symName(a)).cat == scGlobal:
      discard                                     # a global: read through &global (home == "")
    elif g.lookupSym(symName(a)).cat == scTvar:
      isTvar = true                               # a thread-local: read through &threadvar
    else:
      raiseAssert "arkham x64: aggregate symbol arg neither local nor global: " & symName(a) &
        " (locKind=" & $sloc.kind & ")"
  else:                                           # oconstr/aconstr: build into a temp
    let pos = cursorToPosition(g.buf[], a)
    home = synth("aggtmp") & $pos & ".0"
    g.emTypedStackVar(home, tcur)
    g.varType[home] = tn
    g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
  (home, ptrReg, isTvar)

proc binFold(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location; opCur: Cursor) =
  ## `dest op= <memory operand>` (a `NamedStack` slot or a `Mem` access chain `opCur`),
  ## EXCEPT a sub-8-byte field: it has no 64-bit ALU memory form (`add r64, m32` doesn't
  ## exist, and a folded 64-bit read would over-read the field). Such a field is loaded
  ## through a staging reg first — the sized `mov` sign/zero-extends it to the full
  ## 64-bit register — then `op dest, reg`.
  if g.exprSlot(opCur).size < 8:
    # `dest` already holds the other operand (the accumulator); the staging reg that
    # receives the sized load must NOT be `dest`, or the load clobbers it and the
    # `op dest, s` degenerates to `op dest, dest` — dropping this operand (the set
    # membership `setbyte and (1 shl bit)` miscompiled to `setbyte and setbyte`).
    # The sub-width operand is sign/zero-extended into a full 64-bit register by the
    # sized load below, so bind the staging reg to the WIDE type of the operand's
    # class (a char/uint → `(u 64)`, a signed int → `(i 64)`).
    # The staging pick comes AFTER the address is materialized: `prematLval2`
    # needs registers of its own (a spilled address chain stages through
    # `produceIntoMem2`), and a pick held across it is one register the chain
    # cannot have — the pick-before-use ordering that ran `semBodyCheckBody`
    # dry. The rebind only has to precede the `mov` that uses `s`.
    let wide = AsmSlot(cls: g.exprSlot(opCur).cls, size: 8, align: 8)
    if loc.kind == NamedStack:
      let s = g.pickStagingSealed("a sub-width operand", wide, avoid = dest)
      g.emitLoadLoc(loc, s)                       # sized load → sign/zero-extended
      g.binReg(op, dest, s)
      g.giveBack s
    else:                                         # Mem: load via the lvalue (premat base)
      g.prematLval2(opCur, foldDisp = true)
      var s = g.pickStagingScratch(avoid = dest)
      if s != NoReg:
        g.plan.seal s
        g.bindTemp(s, wide)
        g.stagingNote(s, "a sub-width operand")
        g.ab.tree MovX64: (g.emReg s; g.emMemLval2(opCur))
        g.unbindLvalTemps2(opCur)
        g.binReg(op, dest, s)
        g.giveBack s
      else:
        # Nothing free, because the premat just took the last register for the
        # global's address. That address is dead as soon as the `mov` below has
        # read it, so let its register BE the destination — the zero-extra-demand
        # trick `emitLoadLoc` already uses for a global scalar. `-d:danger`
        # `parseBiggestFloat` tests a `set[char]` held in a `const` with every
        # other register live, and hunting for a spare one is not an option here
        # (design.md: the emitter has no spiller, so each step's demand must fit).
        s = g.lvalGlobBaseReg(opCur)
        if s == NoReg or s == dest:
          raiseAssert "arkham x64n: no staging register for a sub-width operand" &
                      " in proc " & g.curProcName & g.stagingCensus(dest)
        # Bound as the VALUE's type across the `mov`: the address side reads `s`
        # through the `(cast (ptr T) …)` `emLvalAddr2` wraps a global base in, so
        # it does not care what the binding says.
        g.releaseStaleName(s)
        g.bindTemp(s, wide)
        g.ab.tree MovX64: (g.emReg s; g.emMemLval2(opCur))
        g.unbindLvalTemps2(opCur)                 # drops the base binding, `s` with it
        g.releaseStaleName(s)
        g.bindTemp(s, wide)                       # `s` now carries the loaded value
        g.binReg(op, dest, s)
        g.unbindTemp(s)
  elif loc.kind == NamedStack:
    g.binMem(op, dest, loc)
  else:
    g.binMemLval2(op, dest, opCur)

proc emitMemIntrin2*(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core `mem*` intrinsic: allocCall placed the 3 args in rdi/rsi/rdx (a
  ## normal int-arg call), so just emit them, bind the loop scratch (rsi/rdx/rcx),
  ## and run the shared inline loop. Result → rax (moved to its home by emitCall2).
  ##
  ## A compile-time memcpy size of 0..64 bytes unrolls into sized `mov`s (no
  ## `rep`, no 8-byte overrun of a 7-byte dest such as the string prefix cache).
  let s = AsmSlot(cls: AInt, size: 8, align: 8)
  var unroll = false
  var nUnroll = 0'i64
  if builtin == "memcpy" and argCurs.len >= 3:
    let (ok, n) = g.tryConstFold(argCurs[2])
    if ok and n >= 0 and n <= 64:
      unroll = true
      nUnroll = n
  let nArgs = if unroll: 2 else: min(3, argCurs.len)
  for idx in 0 ..< nArgs:
    var aD = regLoc(g.md.intArgRegs[idx], s)
    g.releaseArgDest(aD.r, (if argCurs[idx].kind == Symbol: symName(argCurs[idx]) else: ""))
    g.emitValue2(argCurs[idx], aD)              # → rdi / rsi / rdx
  # rdi (dest ptr) and rax (result/byte) are used RAW by the inline loop; a call-free
  # local the allocator homed in one of them leaves a stale typed name that `emReg`
  # would emit. Kill it so the loop sees raw registers (rsi/rdx/rcx get fresh temps).
  g.releaseStaleName(RDI); g.releaseStaleName(RAX)
  if unroll:
    if nUnroll > 0:
      g.copyAggr(RDI, RSI, int(nUnroll), RAX)
    g.movReg(RAX, RDI)
  else:
    g.bindTemp(RSI, s); g.bindTemp(RDX, s); g.bindTemp(RCX, s)
    g.genMemIntrinBody(builtin)

proc atomicValueIsImm(loc: Location): bool {.inline.} = loc.kind == Imm

proc emitBitBuiltin2(g: var CodeGen; argCurs: seq[Cursor]; builtin: string) =
  ## Value-core GCC bit builtin: the single integer argument goes to rdi (a
  ## normal int-arg call), then the inline scan. Result → rax (moved to its
  ## home by emitCall2). The legacy twin is `genBitBuiltin`.
  var aD = regLoc(RDI, AsmSlot(cls: AInt, size: 8, align: 8))
  g.releaseArgDest(aD.r, (if argCurs[0].kind == Symbol: symName(argCurs[0]) else: ""))
  g.emitValue2(argCurs[0], aD)                        # → rdi
  let ar = RDI
  case builtin
  of "__builtin_ctzll", "__builtin_ctz":
    # count trailing zeros == index of the least-significant set bit == BSF.
    # (x == 0 is UB in C and never reached: nimony callers guard the zero case.)
    g.ab.tree BsfX64: (g.emReg RAX; g.emReg ar)
  of "__builtin_bswap64":
    # reverse all 8 bytes: move the arg into rax, BSWAP it in place (64-bit).
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 64)
  of "__builtin_bswap32":
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 32)
  of "__builtin_bswap16":
    # x86 BSWAP r16 is undefined; reverse as a 32-bit bswap then take the high half
    # back down (the two low bytes end up swapped in bits 0..15).
    g.movReg(RAX, ar)
    g.ab.tree BswapX64: (g.emReg RAX; g.ab.intLit 32)
    g.ab.tree ShrX64: (g.emReg RAX; g.ab.intLit 16)
  else:
    raiseAssert "arkham x64n: bit builtin not yet implemented: " & builtin

proc produceIntoMem2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## Totality bridge of the FUSED core: `dst` is an `(s)` spill slot (`etmpN.0`,
  ## minted when `takeTmp` found the pools dry). Materialize the value into a
  ## transient staging register — the reserved bridge guarantees one is always
  ## free — then store it to the slot. No `locs` override: the fused
  ## `emitValue2` takes the destination as a parameter, so the recursion simply
  ## passes the bound staging register.
  g.bridgeStep("a produce-into-memory", bdTwoInRegs)
  block:
    let ti = g.transparentCastInner(c, dst)
    if ti.hit:
      var d = dst                        # the inner produces into the shared slot
      g.emitValue2(ti.inner, d)
      return
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoMem2 slot=" & dst.name
  if c.kind == TagLit and c.exprKind in {DerefC, DotC, AtC, PatC} and
     lvalHasComputedPart(c):
    # A LOAD into the slot whose ADDRESS is itself computed: the address must be
    # materialized before any transfer register is needed, and the address
    # registers die with the `(mem …)` tree. Taking the transfer register up
    # front (below) would hold it across that materialization — one register per
    # level of a spilled address chain, which overruns the r10/r11 budget at
    # depth 3. See `emitMemLoad2`'s `late`.
    #
    # An address with NO computed part takes the path below instead: there is no
    # recursion for `late` to protect, and the staging register taken up front is
    # the one a global base leas into (`globBase`), so the load costs ONE
    # register rather than two.
    var d = needsReg(dst.typ)
    g.emitMemLoad2(c, d, late = true)
    g.emitStoreLoc(dst, d.r)
    # The staging register still holds what the slot now holds — keep it as a
    # mirror so the read this spill exists to serve costs no reload.
    if not g.releaseAsMirror(d.r, dst): g.giveBack d.r
    return
  # The staging reg is NOT bound/sealed across the recursion: a leaf/combine
  # binds it only when it materializes the value, so a deep right-nested
  # spilled chain reuses the SAME bridge register level-by-level — one
  # always-free bridge keeps produce-into total at ANY depth.
  # Statement position: nothing is half-emitted here, so `pickStaging` may fall
  let s = g.pickStaging("a produce-into-memory spill")
  var d = regLoc(s, dst.typ, isTemp = true)
  g.emitValue2(c, d)
  # `s` carries the produced value into the spill store and MUST be a tracked
  # binding. A bin/combine producer already bound it; a LEAF (symbol/load/imm)
  # produced into a register does not — bind it here so `emitStoreLoc`'s
  # `emReg s` emits the checked name. `giveBack` unbinds.
  if not g.rb.isBoundTemp(s): g.bindTemp(s, dst.typ)
  g.emitStoreLoc(dst, s)                 # spill the produced value to its `(s)` slot
  if not g.releaseAsMirror(s, dst): g.giveBack s   # else: kept as a mirror, still bound

proc emitLeafImm*(g: var CodeGen; dest: var Location; natural: Location) =
  ## FUSED literal leaf: resolve the constraint against the immediate; a
  ## register destination gets it materialized (binding a fresh temp first —
  ## an already-bound temp, e.g. the produce staging, is left as is).
  ##
  ## A Leng literal carries no type of its own — `42` and `'a'` are typed by where
  ## they go — so the callers hand one over as a dont-care slot. Take the type from
  ## the DESTINATION when it has one, or the temp minted below is bound `(i 64)`
  ## and a `(c 8)` value loses its range and signedness on the way in.
  var natural = natural
  if cursorIsNil(natural.typ.typ) and not cursorIsNil(dest.typ.typ):
    natural.typ = dest.typ
  g.resolveDestE(dest, natural)
  if dest.kind == InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.movImm(dest.r, natural.ival)
  elif dest.kind == NamedStack and dest.spillTemp:
    # `needsReg` under a dry pool minted an etmp slot: the literal MUST be
    # stored into it (silently skipping it hands the consumer's reload
    # garbage) — through staging, like produceIntoMem2.
    let s = g.pickStagingSealed("a literal spill", dest.typ)
    g.movImm(s, natural.ival)
    g.emitStoreLoc(dest, s)
    g.giveBack s

proc emitValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED decide-and-emit (vmgen dest threading): resolve `dest` — a
  ## constraint (dontCare / needsReg / regOrImm) or a fixed location — against
  ## `c`, emit the code that materializes the value there, and return the
  ## resolved location in `dest` for the consumer. An `Imm` / in-home leaf
  ## stays put (the consumer folds or reads it). Callers route float-typed
  ## values to `emitFValue2`.
  g.bridgeStep("`emitValue2`")
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest)
    return
  # THE place dont-care destinations acquire a type. A caller that asks for "some
  # register" with a placeholder slot is not saying the value is an `(i 64)` — it is
  # saying it does not care WHERE the value goes. What the value IS, is `c`'s own
  # type, and every temp minted for this destination downstream binds from this
  # slot. Filling it here types them all at one site instead of at each mint, and
  # keeps a `(c 8)` a `(c 8)` instead of flattening it to the register's width.
  if dest.kind in {Undef, NeedsReg, RegOrImm} and cursorIsNil(dest.typ.typ):
    let s = g.exprSlot(c)
    if not cursorIsNil(s.typ) and s.cls notin {AFloat, AMem}:
      dest.typ = s
  let pos = cursorToPosition(g.buf[], c)          # for the keepovf no-fold guard
  case c.kind
  of IntLit: g.emitLeafImm(dest, immLoc(intVal(c), ScalarSlot))
  of UIntLit: g.emitLeafImm(dest, immLoc(cast[int64](uintVal(c)), ScalarSlot))
  of CharLit: g.emitLeafImm(dest, immLoc(int64(ord(charLit(c))), ScalarSlot))
  of Symbol:
    # THE read side of store forwarding: a value whose home is a stack slot may
    # still be sitting in the register that stored it there, and then this leaf
    # costs nothing at all (`resolveDestE` folds it, or the load below turns into
    # a register move — or vanishes, when the accumulator IS that register).
    #
    # Which door depends on where the location GOES. An unconstrained `dest` is
    # returned to the caller, which may evaluate more code before consuming it,
    # so the register has to be handed over (`takeForwarded`, released by the
    # caller's `freeVal` like any temp). A FIXED destination is served by the
    # very next instruction, so the cheaper unowned read is enough — and it
    # leaves the mirror alive for the reads after this one.
    let symHome = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    let home = (if dest.kind in {Undef, NeedsReg, RegOrImm}: g.takeForwarded(symHome)
                else: g.forwardOf(symHome))
    if home.kind != NoLoc:                        # a function-local: its (frozen) home
      g.resolveDestE(dest, home)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return        # takeTmp went dry
      if dest.kind == InReg and dest.isTemp and home.kind == InReg and
         home.r == dest.r and g.rb.isMirror(dest.r):
        # The accumulator IS the register still mirroring this value — the load
        # is already done. Take the register over from the mirror (a `(rebind …)`,
        # zero machine code) because the consumer may now write it in place; a
        # mirror the consumer overwrites is the one way this map goes wrong.
        g.bindTemp(dest.r, dest.typ)
      if dest.kind == InReg and not (home.kind == InReg and home.r == dest.r):
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        if dest.isTemp and home.kind == InReg and isSubWidthIntSlot(dest.typ):
          # A REGISTER-homed local into a SUB-WIDTH temp: reinterpret through
          # `(cast …)` (zero machine code) — a plain mov would be a narrowing
          # move nifasm rejects; the real truncation is the consumer's extendTo.
          var tc = dest.typ.typ
          g.ab.tree MovX64:
            g.emReg dest.r
            g.ab.tree CastX:
              g.genTypeBody(tc)
              g.emReg home.r
        else:
          g.place2(home, dest.r)
    else:
      g.forceRegDestE(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      let si = g.lookupSym(symName(c))
      if si.cat == scProc:                        # a proc as a value → its code pointer
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        g.ab.tree LeaX64: (g.emReg dest.r; g.ab.sym si.asmName)
      else:                                       # a module-level global / tvar: load it
        var cc = c
        let loc = g.asLoc(cc)
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, loc.typ)
        g.place2(loc, dest.r)
  of StrLit:
    g.forceRegDestE(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let nm = "msg." & $g.rodata.len & "." & g.prog.thisModuleSuffix
    # The blob is NUL-TERMINATED. A Leng string literal reaches a call as a bare
    # address, and nothing downstream says whether the callee reads it as a `cstring`
    # (`nimGetProcAddr("WriteFile")`, `nimLoadLibrary("kernel32")`) or as the payload of
    # a length-carrying `string` — so the terminator the C backend gets for free from
    # its C literal has to be here. It is invisible to the length-carrying use, whose
    # size travels separately.
    g.rodata.add (nm, strVal(c) & '\0')
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.ab.tree LeaX64: (g.emReg dest.r; g.ab.sym nm)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitBin2(c, dest)
    of DivC, ModC:
      let (isConst, cval) =
        (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
      if isConst: g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
      else: g.emitDivMod2(c, dest)
    of EqC, NeqC, LtC, LeC, AndC, OrC, NotC: g.emitCondValue2(c, dest)
    of DerefC, DotC, AtC, PatC: g.emitMemLoad2(c, dest)
    of AddrC, HaddrC: g.emitAddr2(c, dest)
    of CastC, ConvC: g.emitCast2(c, dest)
    of CallC: g.emitCall2(c, dest)
    of InstrC: g.emitInstr2(c, dest)
    of NegC, BitnotC:
      block:
        let (isConst, cval) =
          (if pos != g.noFoldPos: g.tryConstFold(c) else: (false, 0'i64))
        if isConst:
          g.emitLeafImm(dest, immLoc(cval, ScalarSlot))
          return
      # Unary in-place: the operand computes into the result register, the op
      # applies in place (the fused port of allocValue's NegC + emitValue2's).
      g.forceRegDestE(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      var resType, inner: Cursor
      block:
        var cc = c
        cc.into:
          resType = cc; skip cc                   # result type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      var iv = dest                               # dest-thread into the operand
      g.emitValue2(inner, iv)
      if dest.kind == InReg:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r) and
           not (iv.kind == InReg and iv.r == dest.r):
          g.bindTemp(dest.r, dest.typ)
        if iv.kind == InReg and iv.r != dest.r: g.movReg(dest.r, iv.r)
        elif iv.kind != InReg: g.place2(iv, dest.r)
        if c.exprKind == NegC:
          g.ab.tree NegX64: g.emReg dest.r
        else:
          g.ab.tree NotX64: g.emReg dest.r
        g.normalizeUnaryWidth(resType, dest.r)
        if not (iv.kind == InReg and iv.r == dest.r): g.freeVal(iv)
    of SufC, ParC:                                # wrapper → the inner value
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitValue2(inner, dest)
    of TrueC: g.emitLeafImm(dest, immLoc(1, ScalarSlot))
    of FalseC: g.emitLeafImm(dest, immLoc(0, ScalarSlot))
    of NilC:
      # nil is a 0 of the `(nil)` type (a null pointer): keep the nil slot so
      # the consumer emits/binds `(nil)`, not an `(i 64)` 0.
      g.resolveDestE(dest, immLoc(0, g.exprSlot(c)))
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
      if dest.kind == InReg:
        if dest.isTemp:
          if not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
        elif g.rb.isBound(dest.r) and not g.rb.isPtrBound(dest.r):
          g.bindTemp(dest.r, g.exprSlot(c))       # displace the stale int-typed name
        g.ab.tree MovX64: (g.emReg dest.r; g.ab.nilValue())
    of OvfC:
      # Wrapping arithmetic: `(ovf)` is always false as a VALUE; materializing
      # it into a register would be a flag-read hazard — reject like before.
      g.resolveDestE(dest, immLoc(0, ScalarSlot))
      if dest.kind == InReg:
        raiseAssert "arkham x64n: (ovf) is only valid as an if/ite condition right after keepovf"
    of SizeofC:
      var t = c; var sz = 0'i64
      t.into:
        sz = typeSizeAlign(g.prog, t)[0].int64
        while t.hasMore: skip t
      g.emitLeafImm(dest, immLoc(sz, ScalarSlot))
    else: raiseAssert "arkham x64n: emitValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitValue2(fused) kind " & $c.kind

proc reloadMemBase2*(g: var CodeGen; pos: int) =
  ## A `deref`/`pat`/`at` pointer base or register index the allocator left in a
  ## `NamedStack`/`Mem` home (a genuinely spilled pointer) must be in a register for
  ## `[reg]` addressing. Load it into a sealed staging reg, point its location at that
  ## reg for the lval emission, and park the original home in `savedHomes` so
  ## `restoreMemBase2` (via `unbindLvalTemps2`) puts it back. (A register-homed base is
  ## the common case and returns immediately — no steal can move it under us anymore.)
  let loc = g.plan.planned(pos)
  if loc.kind notin {NamedStack, Mem}: return
  # `prematLval2` calls this at STATEMENT position (its whole job is to emit the
  # base/index materialization before the consuming instruction), so an
  let s = g.pickStagingSealed("a memory address base/index", loc.typ)
  g.emitLoadLoc(loc, s)
  g.savedHomes[pos] = loc
  g.plan.planAtEmitTime(pos, regLoc(s, loc.typ))

proc prematAddrVal2*(g: var CodeGen; c: Cursor) =
  ## Materialize an lvalue base/index value `c` into a register for the enclosing
  ## `(mem …)`. A register-homed base materializes in place; a genuinely spilled base
  ## (`NamedStack`/`Mem`) is brought into a staging reg by `reloadMemBase2`. Scoped to
  ## the lvalue tree (NOT general `emitValue2`). The destination was decided by
  ## `emitLvalue2` (`resolveLvalVal`) and parked in the memo; thread it.
  let pos = cursorToPosition(g.buf[], c)
  var d = g.plan.planned(pos)
  g.emitValue2(c, d)
  g.plan.planAtEmitTime(pos, d)
  g.reloadMemBase2(pos)

proc prematAddrValAs2(g: var CodeGen; c, valueCur: Cursor) =
  ## `prematAddrVal2` with the emitted VALUE decoupled from the POSITION whose register
  ## receives it: the address operand of a displacement-folded `(deref (… + K))` holds
  ## only the base, but it lives in the register the allocator reserved for the whole
  ## pointer expression. Everything downstream (`emLvalAddr2`, `unbindLvalTemps2`) keys
  ## off that position and is unchanged — only the value in the register differs.
  let pos = cursorToPosition(g.buf[], c)
  var d = g.plan.planned(pos)
  g.emitValue2(valueCur, d)
  g.plan.planAtEmitTime(pos, d)
  g.reloadMemBase2(pos)

proc prematLval2*(g: var CodeGen; c: Cursor; asBase = false; hint = NoReg;
                 foldDisp = false) =
  ## Materialize an lvalue's embedded values (a `deref` pointer, an index, a global
  ## base's address) into their allocated registers BEFORE the consuming `(mem …)` /
  ## `(lea …)` tree opens (an emit-inside-the-tree would corrupt it). For a stack /
  ## register-pointer symbol base this is a no-op.
  ##
  ## `hint` is the consuming instruction's DESTINATION register: reserved but not
  ## yet written, so an `(at)`/`(pat)` stride scratch may borrow it instead of
  ## taking a third staging register (see `takeLvalStride`).
  if c.kind == Symbol:
    # A module-level global aggregate base: `lea baseReg, &global`. The base register
    # (the access result for a load/addr, or a store scratch) was assigned by the
    # allocator and is already bound by the caller — see emitMemLoad2 / emitAddr2.
    let pos = cursorToPosition(g.buf[], c)
    let loc = g.plan.planned(pos)
    let home = g.plan.homeOfSym(symName(c))
    if g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:        # a module-level global / threadvar base
      if loc.kind == InReg:
        g.emSymAddrByName(loc.r, symName(c))                # allocator-assigned base reg (glob or tvar)
      else:
        # transient base (the allocator reserved nothing): lea &sym into an emit-time
        # staging GPR (R11 bridge), parked in `lvalGlobBase` for `emLvalAddr2`, released
        # by `unbindLvalTemps2`. Sealed+bound BEFORE any sibling premat picks staging.
        let s = g.pickStagingScratch()
        if s == NoReg: raiseAssert "arkham x64: no staging register for a global base address"
        g.plan.seal s
        g.bindTemp(s, addrSlot())
        g.lvalGlobBase[pos] = s
        g.emSymAddrByName(s, symName(c))                    # &global (RIP-rel) / &threadvar (FS+off)
    elif home.kind == StackPtr:
      # spilled by-ref POINTER: load it into emit-time staging, parked in
      # `lvalGlobBase` for `emLvalAddr2` (same lifecycle as a transient global base).
      let s = g.pickStagingScratch()
      if s == NoReg: raiseAssert "arkham x64: no staging register for a spilled by-ref pointer"
      g.plan.seal s
      g.bindTemp(s, AddrSlot)
      g.lvalGlobBase[pos] = s
      g.ab.tree MovX64:
        g.emReg s
        g.emStackMem(home.ptrName)
    return
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.prematLval2(cc, asBase, hint)                 # a dot over an indexed base propagates
        while cc.hasMore: skip cc
    of DerefC:
      let (baseCur, _, folded) = (if foldDisp: g.derefDispSplit(c)
                                  else: (c, 0'i32, false))
      var cc = c
      cc.into:
        # Folded: only the BASE goes into the register the allocator reserved for the
        # whole pointer expression; `emMemLval2` re-derives the same displacement.
        if folded: g.prematAddrValAs2(cc, baseCur)
        else: g.prematAddrVal2(cc)                      # the pointer → its register (follow steals)
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.prematLval2(cc, asBase = true, hint = hint); skip cc  # base IS indexed by THIS at
        if cc.kind notin {IntLit, UIntLit}:             # register index → its reg
          g.prematAddrVal2(cc)                          # follow steals
        while cc.hasMore: skip cc
      g.takeLvalStride(c, atPos, asBase, hint)          # stride / nested-base scratch ← staging
    of PatC:
      let patPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.prematAddrVal2(cc)                            # the pointer → its register (follow steals)
        skip cc
        if cc.kind notin {IntLit, UIntLit}:             # register index → its reg
          g.prematAddrVal2(cc)                          # follow steals
        while cc.hasMore: skip cc
      g.takeLvalStride(c, patPos, asBase, hint)         # stride / nested-base scratch ← staging
    of BaseobjC:                                        # transparent: materialize the inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                               # base type, depth
        g.prematLval2(cc, hint = hint)                 # the inner lvalue
        while cc.hasMore: skip cc
    of AconstrC, OconstrC:
      # A constructor used as an lvalue base (`[a,b][i]`): build it into a synthetic stack
      # temp `aggtmp<pos>` HERE (before the access instruction opens), then address that
      # temp in `emLvalAddr2`. Mirrors the aggregate call-arg materialization.
      let pos = cursorToPosition(g.buf[], c)
      let home = synth("aggtmp") & $pos & ".0"
      var tcur = c; inc tcur                            # the constructed (array/object) type
      g.emTypedStackVar(home, tcur)
      if tcur.kind == Symbol: g.varType[home] = tcur.symId
      g.genStore2(c, namedStackLoc(home, g.exprSlot(c)))
    else: discard

proc binMemLval2(g: var CodeGen; op: X64Inst; dest: Reg; c: Cursor) =
  ## `dest op= [<lvalue c>]` — fold a memory-load operand into an ALU op via the
  ## value-core address machinery (prematLval2 / emLvalAddr2 / unbindLvalTemps2).
  ## The mirror of emitMemLoad2 with an ALU op in place of the load `mov`.
  let wr = g.pairFieldReg(c)
  if wr != NoReg:
    g.binReg(op, dest, wr)
    return
  g.prematLval2(c, foldDisp = true)
  g.ab.tree op:
    g.emReg dest
    g.emMemLval2(c)
  g.unbindLvalTemps2(c)

proc aggrAddrInto*(g: var CodeGen; lv: Cursor; dest: Reg; aslot: AsmSlot; doBind: bool) =
  ## THE address-of any lvalue into register `dest`: `&(deref p)`
  ## is `p` itself; a global/threadvar leas its absolute address; a `baseobj` is the inner
  ## lvalue's address (base sub-object at offset 0), retyped; anything else leas the
  ## `emLvalAddr2` subtree. `doBind` names a fresh temp `dest` (ptr-typed via `aslot`,
  ## except a deref carries the pointer's own nominal type). The single source of truth
  ## for "where does this aggregate/lvalue live", shared by `(addr …)`, the aggregate
  ## marshalling, and the aggregate copy.
  if lv.kind == TagLit and lv.exprKind == DerefC:
    # &(deref p) == p — produce the pointer directly into dest. Carry p's own (named,
    # unresolved) pointer type, not `aslot`'s structural spelling, so a peer `ptr Named`
    # in a later compare/store matches.
    var p: Cursor
    block:
      var dd = lv
      dd.into:
        p = dd; skip dd
        while dd.hasMore: skip dd
    var pLoc = g.plan.planned(cursorToPosition(g.buf[], p))  # the CALLER's walk decided p's spot
    g.emitValue2(p, pLoc)
    g.plan.planAtEmitTime(cursorToPosition(g.buf[], p), pLoc)
    if doBind:
      g.bindTemp(dest, AsmSlot(cls: AUInt, size: 8, align: 8, typ: g.getType(p)))
    g.place2(pLoc, dest)
    if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
  elif lv.kind == TagLit and lv.exprKind == BaseobjC:
    # `&(baseobj BaseT depth inner)`: base sub-object at offset 0, so the address is
    # `&inner` retyped to `(ptr BaseT)`.
    var inner: Cursor
    block:
      var bc = lv
      bc.into:
        skip bc; skip bc                                  # base type, depth
        inner = bc
        while bc.hasMore: skip bc
    if inner.kind == TagLit and inner.exprKind == DerefC:
      var p: Cursor
      block:
        var dd = inner
        dd.into:
          p = dd; skip dd
          while dd.hasMore: skip dd
      var pLoc = g.plan.planned(cursorToPosition(g.buf[], p)) # the CALLER's walk decided p's spot
      g.emitValue2(p, pLoc)
      g.plan.planAtEmitTime(cursorToPosition(g.buf[], p), pLoc)
      if doBind: g.bindTemp(dest, aslot)                  # (ptr BaseT)
      g.place2(pLoc, dest)
      if pLoc.kind == InReg and pLoc.isTemp and pLoc.r != dest: g.unbindTemp(pLoc.r)
    else:
      if doBind: g.bindTemp(dest, aslot)
      g.prematLval2(inner)
      g.ab.tree LeaX64: (g.emReg dest; g.emLvalAddr2(inner))
      g.unbindLvalTemps2(inner)
  elif lv.kind == Symbol and g.lookupSym(symName(lv)).cat in {scGlobal, scTvar}:
    # &global / &threadvar (no stack base / embedded value to materialize).
    if doBind: g.bindTemp(dest, aslot)
    var lc = lv
    let loc = g.asLoc(lc)                                # Glob/Tvar with the global's precise type
    case loc.kind
    of Glob: g.emGlobalAddr(dest, loc.name)             # &global → RIP-relative lea
    of Tvar:                                            # &threadvar = this thread's block + offset
      # A foreign tvar (other module) resolves the same way — nifasm whole-program-links
      # and folds its unified-block FS offset into the lea (see `emTvarAddr`).
      g.emTvarAddr(dest, loc.name)
    else: raiseAssert "arkham x64n: &sym resolved to " & $loc.kind
  elif lv.kind == Symbol:                               # a LOCAL aggregate var
    let home = g.plan.locationOfSym(symName(lv), cursorToPosition(g.buf[], lv))
    if doBind: g.bindTemp(dest, aslot)
    case home.kind
    of NamedStack: g.emStackAddr(dest, home.name)       # &local stack slot
    of StackPtr:
      g.ab.tree MovX64: (g.emReg dest; g.emStackMem(home.ptrName))  # slot holds &aggregate
    of InReg: g.movReg(dest, home.r)                    # by-ref aggregate param: reg holds &it
    of InRegPair:
      raiseAssert "arkham x64n: aggrAddr of InRegPair local " & symName(lv)
    else: raiseAssert "arkham x64n: aggrAddr of local " & symName(lv) & " home " & $home.kind
  else:
    if doBind: g.bindTemp(dest, aslot)                  # bind first: a global base leas &g into dest
    var bound: seq[Reg] = @[]
    g.bindLvalGlobalBases(lv, bound)                    # bind any UNBOUND global-base reg first
    g.prematLval2(lv, hint = dest)                      # `dest` is still empty: it may host the stride
    g.ab.tree LeaX64:
      g.emReg dest
      g.emLvalAddr2(lv)
    g.unbindLvalTemps2(lv)
    for r in bound: g.unbindTemp(r)

proc buildNestedAggrTemp(g: var CodeGen; valC, fty: Cursor): (string, int) =
  ## Build an aggregate field/element value `valC` (an inline `(oconstr/aconstr …)`, an
  ## aggregate symbol, or a memory lvalue) — of declared nominal type `fty` — into a
  ## synthetic stack temp through the general `genStore2` (which recurses for deeper
  ## nesting), and return the temp's name + byte size.
  ##
  ## The caller derives the DESTINATION pointer only AFTER this returns (then calls
  ## `copyNestedAggrTemp`): a pointer held across the build costs one staging register
  ## per nesting level, and a depth-4 nest exhausted the pool. Computing it afterwards
  ## keeps only two staging registers live at once — the destination pointer and the
  ## word-transfer scratch — so nesting is no longer depth-bounded by the pool size.
  ## (a64's `genNestedAggrField` already orders it this way; this is the x64 twin.)
  if fty.kind != Symbol:
    raiseAssert "arkham x64n: nested aggregate field of non-nominal type"
  let ntn = fty.symId
  let pos = cursorToPosition(g.buf[], valC)
  let tmpName = synth("nctmp") & $pos & ".0"
  g.emTypedStackVar(tmpName, fty)
  g.varType[tmpName] = ntn
  g.genStore2(valC, namedStackLoc(tmpName, g.exprSlot(valC)))   # build (no staging held)
  (tmpName, aggrByteSize(g.prog, ntn))

proc genFieldStore2*(g: var CodeGen; dst: Location; valC: Cursor) =
  ## Store value `valC` into the aggregate-field destination `dst` — the `Field` case
  ## of `genStore2`, and the ONE per-field store behind `genConstr2`. A scalar/float/
  ## pointer field emits its value and moves it into the field operand (a POINTER field
  ## reinterprets a scalar register via `(cast (ptr …) reg)` for nifasm's strict
  ## typing); a nested aggregate field recurses (`genNestedAggrField` builds/copies the
  ## value into the field's address). No per-field special-casing at the call site.
  if dst.typ.kind == AMem:                              # nested aggregate field
    # Build the value into its own stack temp FIRST, holding nothing (see
    # `buildNestedAggrTemp`), and only then derive the field address for the copy.
    # A `baseGlob` (spilled-survivor) base is likewise re-derived AFTER the build, so
    # its transient crosses no call rather than being held across the whole recursion.
    let ftyCur = g.fieldTypeByName(dst.aggrType, dst.field)
    let (tmpName, sizeBytes) = g.buildNestedAggrTemp(valC, ftyCur)
    let (d, gbTmp) = g.materializeGlobBase(dst, NoReg)
    let fptr = g.pickStagingSealed("a nested-aggregate-field pointer", AddrSlot)
    g.emFieldAddr(d, fptr)
    g.copyNestedAggrTemp(tmpName, sizeBytes, fptr)
    g.giveBack fptr
    if gbTmp != NoReg: g.giveBack gbTmp
  else:                                                 # scalar / float / pointer field
    var v: Location
    if g.isFloatExpr(valC):
      # Seed the rhs target with the FIELD's slot rather than leaving it
      # `dontCare`. `emitFValue2` picks a float LITERAL's bit pattern from the
      # destination slot, and the `movss`/`movsd` choice below reads `v.typ`
      # too; with neither known both default to 64, so a `float32` field got
      # the DOUBLE pattern stored eight bytes wide, over whatever field
      # follows it. `dst.typ` is the field's own slot here (the `AMem` case
      # returned above), so the destination type is the authority.
      v = (if dst.typ.kind == AFloat: Location(kind: Undef, typ: dst.typ)
           else: dontCare)
      g.emitFValue2(valC, v)
    else:
      v = needsReg(ScalarSlot)                          # single-use (allocSingleUse's shape)
      g.emitValue2(valC, v)
    # Re-derive a spilled-survivor `&g` AFTER the value eval (so it survives no call).
    let (d, gbTmp) = g.materializeGlobBase(dst, if v.kind == InReg: v.r else: NoReg)
    if v.kind == InFReg:                                # float field
      let bits = if v.typ.size == 4: 32 else: 64
      g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
        g.emFieldOperand(d)
        g.emFReg v.f
      if v.isTemp: g.unbindFTmp(v.f)
    elif v.kind == NamedStack:
      # A foldable stack-homed scalar/pointer rhs — e.g. a demoted local/param read
      # straight from its `(s)` slot. x86 has no mem→mem `mov`, so bridge the value
      # through a staging register before storing it into the field operand.
      var fty = resolveType(g.prog, g.fieldTypeByName(d.aggrType, d.field))
      let s = g.pickStagingSealed("a constr field stack rhs", v.typ)
      g.emitLoadLoc(v, s)
      g.ab.tree MovX64:
        g.emFieldOperand(d)
        if isPtrType(fty):
          g.ab.tree CastX:
            g.genTypeBody(fty)
            g.emReg s
        else:
          g.emReg s
      g.giveBack s
    else:
      var fty = resolveType(g.prog, g.fieldTypeByName(d.aggrType, d.field))
      g.ab.tree MovX64:
        g.emFieldOperand(d)
        case v.kind
        of Imm: g.emImm(v)
        of InReg:
          if isPtrType(fty):
            g.ab.tree CastX:
              g.genTypeBody(fty)
              g.emReg v.r
          else:
            g.emReg v.r
        else: raiseAssert "arkham x64n: constr field rhs " & $v.kind
      if v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
    if gbTmp != NoReg: g.giveBack gbTmp

proc constrFieldStores*(g: var CodeGen; c: Cursor; base: Location) =
  ## The ONE field-store loop behind `genConstr2`/`genConstrIntoLval2`/nested fields:
  ## walk `(oconstr T child*)` and store each value into its field via the uniform
  ## `genFieldStore2`. `base` names the destination aggregate — a stack slot
  ## (`NamedStack`), a pointer in a register (`InReg`), or an lvalue subtree (`Mem`,
  ## pre-materialized by the caller).
  ##
  ## A child is one of: a `(kv field value)` (store at that field); a nested
  ## `(oconstr BaseT …)` (an INHERITED base sub-object — recurse, storing the base's
  ## fields BY NAME into the same destination: nifasm flattens inherited fields, so
  ## each resolves to its offset-0-relative slot in the derived aggregate); or a
  ## leading BARE value (the inherited base's positional initializer, in practice the
  ## RTTI/vtable header pointer at offset 0 — `aggrLayout` lists base fields first, so
  ## it fills the next positional field). This mirrors the leng C backend's oconstr.
  var base = base
  var loaded = NoReg
  if base.kind == StackPtr:
    loaded = g.pickStagingSealed("an oconstr spilled by-ref base", AddrSlot)
    g.ab.tree MovX64: (g.emReg loaded; g.emStackMem(base.ptrName))
    base = regLoc(loaded, AddrSlot)
  var tc = c; inc tc                                    # the constructed type symbol
  let typeSym = tc.symId
  var cc = c
  cc.into:
    skip cc                                             # the constructed type
    var posIdx = 0                                      # positional (inherited-base) value index
    template storeField(field: string; valC: Cursor) =
      let fSlot = g.fieldSlotByName(typeSym, field)
      let fdst =
        case base.kind
        of NamedStack: fieldLoc(typeSym, field, base.name, fSlot)
        of InReg:      fieldLocReg(typeSym, field, base.r, fSlot)
        of Mem:        fieldLocLval(typeSym, field, base.cur, fSlot)
        of Glob, Tvar: fieldLocGlob(typeSym, field, base.name, fSlot,  # addr re-derived per store
                                    isTvar = base.kind == Tvar)
        else: raiseAssert "arkham x64n: bad oconstr base " & $base.kind
      g.genStore2(valC, fdst)
    while cc.hasMore:
      if cc.kind == TagLit and cc.exprKind == OconstrC:
        g.constrFieldStores(cc, base)                  # nested inherited-base sub-object
      elif cc.substructureKind == KvU:
        var kv = cc
        kv.into:
          let field = symName(kv); inc kv
          storeField(field, kv)
          while kv.hasMore: skip kv                     # optional inherited-depth INTLIT
      else:                                             # leading bare inherited-base value
        storeField(aggrLayout(g.prog, typeSym)[posIdx].name, cc)
        inc posIdx
      skip cc
  if loaded != NoReg: g.giveBack loaded

proc genConstrIntoLval2*(g: var CodeGen; c: Cursor; lhs: Cursor) =
  ## Emit `(oconstr T (kv field value)*)` straight into the memory aggregate addressed
  ## by lvalue `lhs` (e.g. `n->chunks[0] = (p, size)`). The address-targeted twin of
  ## `genConstr2`: collapse the destination to ONE address register, then store each
  ## field through it (`fieldLocReg`).
  ##
  ## The former shape — premat the lvalue's embedded regs and hold them across ALL
  ## the field stores (base reload + stride + embedded value = up to three staging
  ## registers) — ran the pool dry the moment a nested-aggregate field needed its
  ## field pointer + copy scratch on top (3 held + 2 = 5 concurrent; a proc with
  ## enough live locals has 4 free). One lea up front costs a single held register
  ## however deep the lvalue is, the same "reduce to an address" move the aggregate
  ## assignment above made for the same reason. Field values are flat operands
  ## (xelim hoisted calls), so nothing clobbers the address across the stores.
  let addrReg = g.pickStagingSealed("an oconstr destination address", AddrSlot)
  g.aggrAddrInto(lhs, addrReg, AddrSlot, doBind = false) # premats + releases internally
  g.freeLvalTemps2(lhs)                                  # release computed index/pointer values
  g.constrFieldStores(c, regLoc(addrReg, ScalarSlot))    # base = &lhs in one register
  g.giveBack addrReg

template aconstrElemStores*(g: var CodeGen; c: Cursor; destOp: untyped) =
  ## The ONE element-store loop behind `genAconstr2`/`genAconstrIntoLval2`: walk
  ## `(aconstr ArrayT e0 e1 …)`, emit each (bare) element value and store it at the
  ## destination operand `destOp(i)` emits. nifasm sizes each store from the array's
  ## element type; a pointer element is reinterpreted via `(cast (ptr …) reg)` for
  ## nifasm's strict typing. The array twin of `constrFieldStores`.
  block:
    var tc = c; inc tc                                  # the array type
    let elemTyRaw = innerType(g.prog, resolveType(g.prog, tc))  # nominal element type
    let elemSlot = slotOf(g.prog, elemTyRaw)
    let et = resolveType(g.prog, elemTyRaw)
    let etIsPtr = isPtrType(et)
    var cc = c
    cc.into:
      skip cc                                           # the array type
      var i = 0
      while cc.hasMore:
        let valC = cc
        if elemSlot.kind == AMem:                       # nested aggregate element
          # Build first, lea `&element[i]` after — the field twin's depth-independence
          # (see `buildNestedAggrTemp`) applies to array elements just the same.
          let (tmpName, sizeBytes) = g.buildNestedAggrTemp(valC, elemTyRaw)
          let eptr = g.pickStagingSealed("an aconstr aggregate-element pointer", AddrSlot)
          g.ab.tree LeaX64: (g.emReg eptr; destOp(i))   # &element[i]
          g.copyNestedAggrTemp(tmpName, sizeBytes, eptr)
          g.giveBack eptr
          inc i
          skip cc
          continue
        var v: Location
        if g.isFloatExpr(valC):
          # The ELEMENT's slot, not `dontCare`: `elemSlot` is the authority
          # for a float literal's bit pattern and for the store width below,
          # so an unseeded `[1.5'f32, …]` initializer wrote the double
          # pattern and every element read back as 0.0.
          v = (if elemSlot.kind == AFloat: Location(kind: Undef, typ: elemSlot)
               else: dontCare)
          g.emitFValue2(valC, v)
        else:
          v = needsReg(ScalarSlot)
          g.emitValue2(valC, v)
        if v.kind == InFReg:                            # float element
          let bits = if v.typ.size == 4: 32 else: 64
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            destOp(i)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
        else:
          # scalar/ptr element. The element must be in a GPR to store (no mem→mem
          # mov); load a spilled (NamedStack) value into a staging register first.
          var vReg: Reg
          var ownV = false
          if v.kind == InReg:
            vReg = v.r
          else:
            vReg = g.pickStagingSealed("aconstr scalar element", v.typ)
            g.emitLoadLoc(v, vReg)
            ownV = true
          var etc = et
          g.ab.tree MovX64:
            destOp(i)
            if etIsPtr:
              g.ab.tree CastX: (g.genTypeBody(etc); g.emReg vReg)
            else:
              g.emReg vReg
          if ownV: g.giveBack(vReg)
          elif v.isTemp: g.unbindTemp(v.r)
        inc i
        skip cc

proc genAconstrIntoLval2*(g: var CodeGen; c: Cursor; lhs: Cursor) =
  ## Emit `(aconstr ArrayT e0 e1 …)` straight into the array addressed by lvalue `lhs`.
  ## The address-targeted twin of `genAconstr2` (cf. `genConstrIntoLval2` for objects).
  g.prematLval2(lhs)                                     # the lvalue's base/index regs, once
  template dest(i) = g.emLvalElemMem(lhs, i)
  g.aconstrElemStores(c, dest)
  g.unbindLvalTemps2(lhs)                                # release the lvalue's base/index temps

proc genConstr2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## Emit `(oconstr T (kv field value)*)` into the aggregate destination `dst`: each
  ## value was placed in a register temp by the allocator (a SIMD temp for a float
  ## field); store it at the field's offset. `dst` is the destination's own location —
  ## a `NamedStack` slot, or a `StackPtr` whose pointer `constrFieldStores` loads into
  ## a base register. (It used to take the NAME and rebuild a `NamedStack` from it,
  ## erasing that difference for a predicate to re-derive downstream.)
  g.constrFieldStores(c, dst)

proc genAconstr2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## Emit `(aconstr ArrayT e0 e1 …)` into the aggregate destination `dst`: store each
  ## (bare) element value at its index. The array twin of `genConstr2`, and it takes
  ## the same `Location` for the same reason — a `NamedStack` slot IS the array, while
  ## a `StackPtr` slot holds a POINTER to it (a by-ref aggregate param whose pointer
  ## the allocator could not keep in a register). Addressing `(at (rsp) name idx)` in
  ## the second case would write the elements over the pointer's own 8 bytes and on up
  ## the stack, so load the pointer and store through it — exactly what
  ## `constrFieldStores` does for the `oconstr` twin.
  if dst.kind == StackPtr:
    let base = g.pickStagingSealed("an aconstr spilled by-ref base", AddrSlot)
    g.ab.tree MovX64: (g.emReg base; g.emStackMem(dst.ptrName))
    var atc = c; inc atc                                # the array type
    let elemTy = innerType(g.prog, resolveType(g.prog, atc))
    template destThroughPtr(i) = g.emPtrElemMem(base, elemTy, i)
    g.aconstrElemStores(c, destThroughPtr)
    g.giveBack base
  else:
    template destInSlot(i) = g.emAggrElemMem(dst.name, i)
    g.aconstrElemStores(c, destInSlot)

proc genBaseobj2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## `(baseobj BaseType depth value)` — an object→base up-conversion (slicing). Inheritance
  ## lays the base sub-object FIRST (offset 0), so the base view is the value's prefix:
  ## build the (derived) `value` into a synthetic temp, then copy only the BaseType fields
  ## into the aggregate destination `dst`. `depth` is informational (BaseType is the target).
  assert dst.kind == NamedStack, "arkham x64n: baseobj into " & $dst.kind
  var cc = c
  cc.into:
    let baseTy = cc; skip cc                              # the base type (a Symbol)
    skip cc                                               # depth (intlit) — ignored
    let valC = cc
    let pos = cursorToPosition(g.buf[], valC)
    let derivedTy = g.getType(valC)
    let derivedTn = derivedTy.symId
    let dtmp = synth("botmp") & $pos & ".0"
    g.emTypedStackVar(dtmp, derivedTy)
    g.varType[dtmp] = derivedTn
    g.genStore2(valC, namedStackLoc(dtmp, g.exprSlot(valC)))  # build derived (no held temp)
    let scratch = g.pickStagingSealed("a baseobj prefix copy", AddrSlot)
    g.genAggrCopy2(dst.name, dtmp, baseTy.symId, scratch)        # copy the base prefix
    g.giveBack scratch
    while cc.hasMore: skip cc

proc storeScalar2*(g: var CodeGen; dst, v: Location) =
  ## Move a just-computed scalar `v` into a scalar home `dst` (InReg / InFReg /
  ## NamedStack), releasing `v` if it is a temp. When BOTH `dst` and `v` are memory
  ## — a stolen-victim local stored into a stack-homed var/lhs, which x86 cannot do
  ## directly — the value is bridged through a transient staging register.
  case dst.kind
  of InReg: g.place2(v, dst.r)                          # dest-passed ⇒ usually a no-op
  of InFReg:
    let bits = dst.typ.size * 8
    if v.kind in {NamedStack, Mem}: g.floatMemMov(v, dst.f, bits, load = true)
    elif v.kind == InFReg and v.f != dst.f: g.fmovF(dst.f, v.f, bits)
  of NamedStack:
    let bits = dst.typ.size * 8
    # The bridge is DECIDED by `memToMemBridgeDemand` and only executed here, so
    # the allocator can ask the same question without emitting (machinedesc.nim).
    let need = memToMemBridgeDemand(g.md, dst, v)
    if dst.typ.isFloat:
      if need.fregs > 0:
        let fs = g.pickFStagingSealed("a scalar store")
        g.floatMemMov(v, fs, bits, load = true)
        g.emitStoreFLoc(dst, fs, bits)
        g.rb.unsealF fs
      elif v.kind == InFReg:
        g.emitStoreFLoc(dst, v.f, bits)
        # The register still holds what the slot now holds: keep that instead of
        # killing the binding, and the next read of `dst` comes from the register.
        if v.isTemp and not g.releaseFAsMirror(v.f, dst): g.unbindFTmp(v.f)
      else: raiseAssert "arkham x64n: float scalar store rhs " & $v.kind
    else:
      if need.gprs > 0:
        let s = g.pickStagingSealed("a scalar store", need.slot)
        g.emitLoadLoc(v, s)
        g.emitStoreLoc(dst, s)
        if not g.releaseAsMirror(s, dst): g.giveBack s
      elif v.kind == InReg:
        g.emitStoreLoc(dst, v.r)
        if v.isTemp and not g.releaseAsMirror(v.r, dst): g.unbindTemp(v.r)
      else: raiseAssert "arkham x64n: scalar store rhs " & $v.kind
  else: raiseAssert "arkham x64n: scalar store dst " & $dst.kind

proc aggrAddrLoc*(g: var CodeGen; loc: Location; dest: Reg) =
  ## Address of an aggregate DESTINATION location into the (bound) `dest` — the dst twin
  ## of `aggrAddrInto`: a named stack slot / global leas its address; a complex lvalue
  ## (`Mem`) routes through `aggrAddrInto` on its captured subtree.
  case loc.kind
  of NamedStack: g.emStackAddr(dest, loc.name)
  of StackPtr:
    g.ab.tree MovX64: (g.emReg dest; g.emStackMem(loc.ptrName))  # the slot IS the address
  of Glob, Tvar: g.emSymAddr(dest, loc)   # &global (RIP-rel) / &threadvar (FS base + offset)
  of Mem: g.aggrAddrInto(loc.cur, dest, addrSlot(), doBind = false)
  else: raiseAssert "arkham x64n: aggrAddrLoc of " & $loc.kind

proc aggrDstEnd(g: var CodeGen; loc: Location; staged: var Reg): AggrEnd =
  ## The copy-destination twin of `aggrSrcEnd`: a `NamedStack` slot is written straight
  ## through `(mem (rsp) name off)` and costs no register; a global/threadvar/computed
  ## lvalue must have its address materialized. `staged` receives the register to
  ## `giveBack`, or `NoReg`.
  staged = NoReg
  if loc.kind == NamedStack:
    return slotEnd(loc.name)
  if loc.kind == StackPtr:
    staged = g.pickStagingSealed("a spilled by-ref dst pointer", AddrSlot)
    g.ab.tree MovX64: (g.emReg staged; g.emStackMem(loc.ptrName))
    return regEnd(staged)
  staged = g.pickStagingSealed("an aggregate-copy dst address", ScalarSlot)
  g.aggrAddrLoc(loc, staged)
  regEnd(staged)

proc genAggrCopyStore*(g: var CodeGen; rhs: Cursor; dst: Location; size: int) =
  ## THE whole-aggregate copy `dst = rhs`: reduce each side to the form the machine can
  ## address it in (`aggrDstEnd`/`aggrSrcEnd`), then `copyAggr`. ONE path for every
  ## (destination form × source form). The working registers come from the emit-time
  ## STAGING set (the R11 bridge + free caller-saved), NOT the allocator pool, so the copy
  ## never starves when register-homed locals fill the pool; each is sealed before the next
  ## is picked (and before address computation, which may itself stage), so they stay
  ## disjoint.
  ##
  ## The count is TIERED by operand form rather than fixed at three: a named `(s)` slot on
  ## either side is addressed straight off rsp and needs no register at all, so two named
  ## ends cost one register (the transfer), one named end costs two, and only a copy
  ## between two COMPUTED addresses costs three. Three-for-everything was self-inflicted —
  ## the price of "reduce both sides to an address" — and it is what ran the staging pool
  ## dry once `-d:danger` filled every volatile with a call-free local.
  g.bridgeStep("a whole-aggregate copy", bdTwoInRegs)
  if dst.kind == InRegPair:
    var tn = NoTypeSym
    if not cursorIsNil(dst.typ.typ) and dst.typ.typ.kind == Symbol:
      tn = dst.typ.typ.symId
    elif rhs.kind == Symbol:
      tn = g.varType.getOrDefault(symName(rhs), NoTypeSym)
    if tn == NoTypeSym:
      let t = g.getType(rhs)
      if t.kind == Symbol: tn = t.symId
    var dwords: seq[Reg] = @[dst.r0]
    if dst.r1 != NoReg: dwords.add dst.r1
    if rhs.kind == Symbol:
      g.structToRegs(symName(rhs), tn, dwords)
    else:
      g.emitLvalue2(rhs)
      let srcAddr = g.pickStagingSealed("an InRegPair copy src address", ScalarSlot)
      g.aggrAddrInto(rhs, srcAddr, addrSlot(), doBind = false)
      g.marshalAggrFromAddr(srcAddr, tn, dwords)
      g.freeLvalTemps2(rhs)
      g.giveBack srcAddr
    return
  if rhs.kind == Symbol:
    let sh = g.plan.homeOfSym(symName(rhs))   # an InRegPair is a whole-proc param home
    if sh.kind == InRegPair:
      let tn = g.varType.getOrDefault(symName(rhs))
      var words: seq[Reg] = @[sh.r0]
      if sh.r1 != NoReg: words.add sh.r1
      if dst.kind == NamedStack:
        g.regsToStruct(dst.name, tn, words)
      else:
        var dstAddr = NoReg
        let dstE = g.aggrDstEnd(dst, dstAddr)
        if dstE.slot.len > 0:
          g.regsToStruct(dstE.slot, tn, words)
        else:
          g.regsToStructThroughPtr(dstE.reg, tn, words)
        g.giveBack dstAddr
      return
  if dst.kind == Mem:
    g.emitLvalue2(dst.cur)                 # pick the dst lvalue's embedded values
  var dstAddr = NoReg
  let dstE = g.aggrDstEnd(dst, dstAddr)                                  # &dst (or its slot)
  if dst.kind == Mem: g.freeLvalTemps2(dst.cur)
  var srcAddr = NoReg
  let srcE =
    if rhs.kind == Symbol: g.aggrSrcEnd(symName(rhs), srcAddr)
    else:
      g.emitLvalue2(rhs)                   # pick the src lvalue's embedded values
      srcAddr = g.pickStagingSealed("an aggregate-copy src address", ScalarSlot)
      g.aggrAddrInto(rhs, srcAddr, addrSlot(), doBind = false)
      g.freeLvalTemps2(rhs)
      regEnd(srcAddr)
  # In the top tier both addresses have already consumed the R11 bridge, so the per-word
  # transfer register is a third staging pick and can genuinely fail under pressure. Fall
  # back to the pool register `allocAggrCopy` reserved for exactly this (it can demote a
  # local; the emitter cannot). Staging succeeds in the common case, and then the
  # reserved register simply goes unused.
  var tmp = g.pickStagingScratch()
  if tmp == NoReg:
    tmp = g.pickHeldReg()        # non-demoting callee-saved grab (freed right after)
  if tmp == NoReg:
    tmp = g.pickStagingSealed("an aggregate-copy transfer register", AddrSlot)
  else:
    g.releaseStaleName(tmp)      # drop a dead binding so `(rebind)` is legal
    g.plan.seal tmp
    g.bindTemp(tmp, AddrSlot)
  g.copyAggr(dstE, srcE, size, tmp)
  g.giveBack tmp                                                 # unbinds + unseals the bridge
  g.giveBack srcAddr; g.giveBack dstAddr                         # unbind + unseal (NoReg ⇒ no-op)

let rmwFoldOn = not existsEnv("ARKHAM_NO_RMW")
  ## Off switch for the read-modify-write fold below, for A/B measurement.

proc rmwMemOp(ek: LengExpr): tuple[op: X64Inst, ok: bool] =
  ## The ALU ops nifasm will encode with a MEMORY destination — see the
  ## `dest.kind == okMem` arms of `x64/instr.nim`. `mul` is absent because x86-64
  ## has no `imul m, r`, and the shifts because nifasm refuses one outright
  ## ("Shift destination cannot be memory": the count would have to be `cl`).
  case ek
  of AddC: (AddX64, true)
  of SubC: (SubX64, true)
  of BitandC: (AndX64, true)
  of BitorC: (OrX64, true)
  of BitxorC: (XorX64, true)
  else: (AddX64, false)

proc rmwIntOperand(g: var CodeGen; c: Cursor): bool =
  ## May `c` take part in a folded ALU op — as its memory destination or as its
  ## source? nifasm's `checkIntegerArithmetic`/`checkArithCompatible` admit exactly
  ## the SIZED integers: no pointer of any kind (Leng has no pointer arithmetic),
  ## and no `(c 8)` either — a char is `AUInt` in a slot but its own kind to nifasm,
  ## so the slot class alone is not the question to ask.
  if c.kind in {IntLit, UIntLit}: return true      # a literal is typed by where it goes
  if c.kind == TagLit and c.exprKind in {SufC, ParC}:
    # `(suf 1 "i32")` is how a front end spells a typed literal, and `exprSlot`
    # deliberately does NOT honour an integer suffix — it recurses to the bare
    # literal, whose slot carries no type cursor at all. So ask the literal.
    var t = c; inc t
    return g.rmwIntOperand(t)
  let s = g.exprSlot(c)
  if s.cls notin {AInt, AUInt} or cursorIsNil(s.typ): return false
  var t = s.typ
  result = resolveType(g.prog, t).typeKind in {LengType.IT, LengType.UT}

proc rmwStripConv(g: var CodeGen; c: Cursor; memBits: int): Cursor =
  ## Peel a `(conv (i W) x)` / `(cast (i W) x)` off an RMW source when `W >= memBits`.
  ## The folded instruction reads only the DESTINATION's width, and the low `memBits`
  ## bits of `x` and of `intW(x)` are the same bits — so the conversion is dead, and
  ## with it the `mov`+`movsx` pair that materializes it. `c.free += int32(size)`
  ## becomes the one `add %r9d, 0x30(%rcx)` gcc emits, instead of three instructions.
  ## A NARROWING conversion (`W < memBits`) is not dead: there the truncated value
  ## would have to be re-extended to the destination's width first.
  result = c
  while result.kind == TagLit and result.exprKind in {ConvC, CastC}:
    var t = result; inc t                          # the target type
    let tt = resolveType(g.prog, t)
    if tt.typeKind notin {LengType.IT, LengType.UT}: break
    if typeBits(tt) < memBits: break
    var inner = t; skip inner
    if not inner.hasMore or not g.rmwIntOperand(inner): break
    result = inner

proc tryRmwStore2*(g: var CodeGen; lhs: Cursor): bool =
  ## `x.f = x.f <op> v` as ONE instruction — `(add (mem x.f) v)` — instead of the
  ## load, the ALU op on a temp and the store back that `genStore2` would emit.
  ##
  ## Three instructions become one, and the sign extensions go with them: an `(i 32)`
  ## field read into a 64-bit temp needs a `movsx` in and a truncating `mov` out,
  ## while the folded form runs at the field's own width (`intMemAccess(dest.typ).bits`).
  ## In the allocator's `rawDealloc` the three sites `a.occ -= size`,
  ## `c.free += size` and `inc c.foreignCells` cost 14 instructions unfolded and 3
  ## folded — 33 % of that proc's hot path.
  ##
  ## `lhs` is the assignment target and its sibling is the rhs. Returns false — having
  ## emitted nothing — for every shape that does not fold, and the caller falls through
  ## to the general store.
  ##
  ## WHAT MAKES IT SOUND. The fold moves the destination's READ from before the rhs
  ## to the instruction itself, so the rhs must not be able to write that location:
  ## hence no call in it. It also evaluates the address ONCE instead of twice, which
  ## is strictly safer. Flags are the other thing an ALU op costs that a `mov` does
  ## not, and `scanCondFusions` only ever fuses a compare across statements that emit
  ## NO machine code — an assignment is not one of those either way, so a fold here
  ## can never be the statement that separates a fused compare from its branch.
  if not rmwFoldOn: return false
  if not g.isFoldableMemLeaf(lhs): return false     # dot/deref/at/pat, and not a
                                                    # field of a register-homed pair
  var rhs = lhs; skip rhs
  if rhs.kind != TagLit: return false
  let (op, ok) = rmwMemOp(rhs.exprKind)
  if not ok: return false
  var aC, bC: Cursor
  block:
    var cc = rhs
    cc.into:
      skip cc                                       # the result type
      if not cc.hasMore: return false
      aC = cc; skip cc
      if not cc.hasMore: return false
      bC = cc; skip cc
      if cc.hasMore: return false                   # not the (op T a b) shape
  # Which operand IS the destination? Position 0 always; position 1 only when the
  # operator is commutative — `x.f = v - x.f` is not a read-modify-write of `x.f`.
  var srcC: Cursor
  if sameTreeE(aC, lhs): srcC = bC
  elif commutativeExpr(rhs.exprKind) and sameTreeE(bC, lhs): srcC = aC
  else: return false
  if subtreeHasCallE(srcC): return false            # see WHAT MAKES IT SOUND
  if not g.rmwIntOperand(lhs) or not g.rmwIntOperand(srcC): return false
  srcC = g.rmwStripConv(srcC, g.exprSlot(lhs).size * 8)
  # The source value FIRST, then the lvalue's address parts — the order (and the
  # reason for it) that `genStore2`'s scalar arm spells out. `regOrImm` is the
  # operand-B constraint this instruction shape was written for: x86 allows one
  # memory operand, so a stack-homed source is loaded rather than folded.
  var v = regOrImm(ScalarSlot)
  g.emitValue2(srcC, v)
  var staging = NoReg
  if v.kind in {NamedStack, Mem}:                   # demoted (stolen) local → a register
    staging = g.pickStagingSealed("an rmw source", v.typ)
    g.emitLoadLoc(v, staging)
    v = regLoc(staging, v.typ)
  elif v.kind == Imm and (v.ival < low(int32).int64 or v.ival > high(int32).int64):
    # nifasm's memory-destination arm encodes the immediate as an `int32`; a wider
    # one has to travel in a register (`emitBin2` guards its own imm fold the same way).
    staging = g.pickStagingSealed("an rmw imm64 source", ScalarSlot)
    g.movImm(staging, v.ival)
    v = regLoc(staging, ScalarSlot)
  g.emitLvalue2(lhs, dontCare, isStore = false)
  g.prematLval2(lhs, foldDisp = true)
  g.ab.tree op:
    g.emMemLval2(lhs)
    case v.kind
    of Imm: g.emImm(v)
    of InReg: g.emReg v.r
    else: raiseAssert "arkham x64n: rmw source " & $v.kind
  g.freeLvalTemps2(lhs)
  if staging != NoReg: g.giveBack staging
  elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
  return true

proc genStore2*(g: var CodeGen; rhs: Cursor; dst: Location) =
  ## The general destination-passing store of the value core. An aggregate COPY (symbol /
  ## lvalue source) goes through the ONE `genAggrCopyStore` regardless of destination form;
  ## constructors/calls/baseobj PRODUCE into the destination per-form; a scalar/float
  ## destination goes through `storeScalar2`.
  g.bridgeStep("`genStore2`")
  let (dstAggr, aggrSize) = g.dstAggrInfo(dst)
  if dstAggr and isAggrCopySrc(rhs):                     # the ONE whole-aggregate copy path
    g.genAggrCopyStore(rhs, dst, aggrSize)
    return
  if rhs.kind == TagLit and rhs.exprKind in {ConvC, CastC} and
     g.exprSlot(rhs).kind == AMem:
    # A distinct / representation-preserving conversion of an AGGREGATE (`Path(s)` for
    # `Path = distinct string`) is byte-transparent — store its underlying operand into
    # the same destination (allocator twin in `allocStore`).
    var inner = rhs
    inner.into:
      skip inner                                         # the target type
      g.genStore2(inner, dst)                    # the operand → same dest
      while inner.hasMore: skip inner
    return
  if dst.kind in {NamedStack, StackPtr} and dst.typ.kind == AMem:
    # `StackPtr` reaches its aggregate through the slot's pointer; `NamedStack` IS it.
    let dstVar = (if dst.kind == StackPtr: dst.ptrName else: dst.name)
    let tn = (if dst.kind == StackPtr: dst.pointeeType else: g.varType[dstVar])
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.genConstr2(rhs, dst)                             # build object field-by-field
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.genAconstr2(rhs, dst)                             # build array element-by-element
    elif rhs.kind == TagLit and rhs.exprKind == CallC:   # call-returned aggregate
      if g.aggrByRef(tn):                                # >16B: pass &dst as the hidden result ptr
        # The window opens BEFORE `&dst` is written into rdi. rdi is an ABI argument
        # register and may be a caller-saved local's home; writing it here — outside
        # `emitCall2`, which is where the save would otherwise happen — destroys that
        # value in place. (nifasm forbids naming a register that carries a live
        # binding, so the write comes out as `(lea <thatlocal> …)` and the corruption
        # is invisible to any scan for raw register operands.)
        let w = g.emCallerSaveOpen()
        g.dropStaleBinding(RDI)
        if dst.kind == StackPtr:
          g.ab.tree MovX64: (g.emReg RDI; g.emStackMem(dst.ptrName))  # slot holds &aggregate
        else:
          g.emStackAddr(RDI, dstVar)
        var d = dontCare
        g.emitCall2(rhs, d, hiddenPtr = true)            # the callee writes through rdi
        g.emCallerSaveClose(w, d)
      else:
        var d = dontCare
        g.emitCall2(rhs, d)                              # ≤16B result in rax:rdx
        g.releaseRetRegs()
        g.regsToStruct(dstVar, tn, x64RetRegs)
    elif rhs.kind == TagLit and rhs.exprKind == BaseobjC:
      g.genBaseobj2(rhs, dst)                   # object→base slice
    else: raiseAssert "arkham x64n: aggregate store rhs " & $rhs.exprKind
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AFloat:  # float global / threadvar
    # `dst.typ` is the global's own float slot and `gbits` below already
    # trusts it; the VALUE has to trust it too, or a float literal builds the
    # double pattern and the store writes its low half — `gf = 3.5'f32` on a
    # `float32` global stored 0.0.
    var fv = Location(kind: Undef, typ: dst.typ)
    g.emitFValue2(rhs, fv)                               # rhs → an xmm
    assert fv.kind == InFReg, "arkham x64n: float global store rhs " & $fv.kind
    let gbits = if dst.typ.size == 4: 32 else: 64
    let op = if gbits == 32: MovssX64 else: MovsdX64
    # &dst is re-derived into a transient here (no call since the rhs), so the allocator
    # reserves nothing — matching the scalar global store. Type the address `(ptr (f N))`
    # so the `(mem p)` deref carries the precise float type (nifasm is strict). `emSymAddr`
    # handles a global (RIP-rel lea) or a thread-local (FS base + offset) uniformly.
    var pSlot = ScalarSlot
    if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
    let addrT = g.pickStagingSealed("a float global store address", pSlot)
    g.emSymAddr(addrT, dst)
    g.ab.tree op:
      g.ab.tree MemX: g.emReg addrT
      g.emFReg fv.f
    g.giveBack addrT
    if fv.isTemp: g.unbindFTmp(fv.f)
  elif dst.kind in {Glob, Tvar} and dst.typ.kind == AMem:
    # Aggregate store into a module-level symbol — a global OR a thread-local. Compute
    # `&dst` into a pointer (via `emSymAddr`, the ONE address-of for either kind) and
    # build/copy the aggregate THROUGH that pointer — an `oconstr` field-by-field, an
    # array by element, a call by its ABI (>16B → &dst as the hidden result pointer in
    # rdi; ≤16B → the result regs stored through &dst). The build dispatches only on the
    # RHS kind; global-vs-threadvar lives entirely in `emSymAddr`. The address temp
    # is a callee-saved survivor picked at emission (`takeHeld`).
    if rhs.kind == TagLit and rhs.exprKind == CallC and
       dst.typ.size > g.md.aggrByRefThreshold:
      let w = g.emCallerSaveOpen()                       # rdi first: see the sibling site
      g.dropStaleBinding(RDI)
      g.emSymAddr(RDI, dst)                              # >16B: &dst is the hidden result ptr
      var d = dontCare
      g.emitCall2(rhs, d, hiddenPtr = true)              # callee writes through rdi
      g.emCallerSaveClose(w, d)
    else:
      # `spilled`: the address survivor could not get a callee-saved register
      # (totality backstop), so no register holds `&dst` across the build —
      # re-derive it per use instead (the address is re-derivable for either kind).
      var survivor = NoReg                               # the callee-saved &dst holder
      let heldLoc = g.takeHeld("an aggregate global &g", canSpill = true)
      let spilled = heldLoc.kind == NamedStack
      if not spilled: survivor = heldLoc.r
      if rhs.kind == TagLit and rhs.exprKind == OconstrC:
        if spilled:
          g.constrFieldStores(rhs, dst)                  # Glob/Tvar base: &dst re-derived per field
        else:
          g.bindTemp(survivor, ScalarSlot)
          g.emSymAddr(survivor, dst)
          g.constrFieldStores(rhs, regLoc(survivor, dst.typ))  # build field-by-field through &dst
          g.unbindTemp(survivor)
      elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
        # &dst held for the element loop: a transient when spilled (correct unless an
        # element value itself calls under genuine exhaustion — astronomically rare; a
        # literal-element array has none), else the reserved survivor.
        let addrT = if spilled: g.pickStagingSealed("a spilled aconstr sym base", AddrSlot)
                    else: (g.bindTemp(survivor, ScalarSlot); survivor)
        g.emSymAddr(addrT, dst)
        var atc = rhs; inc atc                            # the array type
        let elemTy = innerType(g.prog, resolveType(g.prog, atc))
        template dest(i) = g.emPtrElemMem(addrT, elemTy, i)  # element i through &dst
        g.aconstrElemStores(rhs, dest)
        if spilled: g.giveBack addrT else: g.unbindTemp(addrT)
      elif rhs.kind == TagLit and rhs.exprKind == CallC:  # ≤16B result in rax:rdx
        var d = dontCare
        g.emitCall2(rhs, d)
        g.releaseRetRegs()
        # lea AFTER the call (rax:rdx hold the result): a transient when spilled, sealing
        # the result regs so the pick avoids them; else the reserved survivor.
        var addrT: Reg
        if spilled:
          g.plan.seal {RAX, RDX}
          addrT = g.pickStagingSealed("a spilled call-result sym base", AddrSlot)
          g.plan.unseal {RAX, RDX}
        else:
          addrT = survivor; g.bindTemp(addrT, ScalarSlot)
        g.emSymAddr(addrT, dst)
        g.regsToStructThroughPtr(addrT, g.getType(rhs).symId, x64RetRegs)
        if spilled: g.giveBack addrT else: g.unbindTemp(addrT)
      else: raiseAssert "arkham x64n: aggregate sym store rhs " & $rhs.exprKind
      g.freeVal(heldLoc)
  elif dst.kind in {Glob, Tvar}:                         # scalar/pointer global / threadvar
    var v = needsReg(ScalarSlot)                         # single-use rhs (allocSingleUse's shape)
    g.emitValue2(rhs, v)
    var glbStaging = NoReg
    if v.kind in {NamedStack, Mem}:                      # demoted (stolen) local rhs → reg
      glbStaging = g.pickStagingSealed("a global store rhs", v.typ)
      g.emitLoadLoc(v, glbStaging)
      v = regLoc(glbStaging, v.typ)
    assert v.kind == InReg, "arkham x64n: global store rhs " & $v.kind
    case dst.kind
    of Tvar:                                             # nifasm resolves FS:[off]
      g.ab.tree MovX64:
        g.ab.sym dst.name
        g.emReg v.r
    of Glob:                                             # &g into a transient, then store
      if g.globalFoldsIntoAccess(dst.name):
        g.ab.tree GstoreX64: (g.emReg v.r; g.ab.sym g.prog.gvarRefName(dst.name))
        if glbStaging != NoReg: g.giveBack glbStaging
        elif v.isTemp: g.unbindTemp(v.r)
        return
      # Type the address temp as `(ptr <globalType>)` so the `(mem p)` deref carries the
      # global's PRECISE type — a typed-pointer value into a pointer global would
      # otherwise mismatch a generic mem (nifasm is strict; see `scalarMemMov`).
      var pSlot = ScalarSlot
      if not cursorIsNil(dst.typ.typ): pSlot = typeToSlot(g.prog.ptrTypeOf(dst.typ.typ))
      # The address is re-derived here (no call since the rhs), so a transient staging
      # register suffices — no allocator-reserved survivor.
      let addrT = g.pickStagingSealed("a global store address", pSlot,
                    avoid = (if v.kind == InReg: v.r else: NoReg))
      g.emGlobalAddr(addrT, dst.name)
      g.ab.tree MovX64:
        g.ab.tree MemX: g.emReg addrT
        g.emReg v.r
      g.giveBack addrT
    else: discard
    if glbStaging != NoReg: g.giveBack glbStaging
    elif v.isTemp: g.unbindTemp(v.r)
  elif dst.kind == Mem:                                  # store through a complex lvalue (dot/deref/at)
    let wr = g.pairFieldReg(dst.cur)
    if wr != NoReg:
      var v = regLoc(wr, if dst.typ.size > 0: dst.typ else: ScalarSlot)
      g.emitValue2(rhs, v)
      return
    # (A whole-aggregate copy through an `Mem` lvalue went through `genAggrCopyStore` at
    # the top; here the rhs PRODUCES into the address — a constructor or a scalar/float.)
    let lhs = dst.cur
    # A global aggregate base needs an address scratch, held across the rhs; bind it so
    # prematLval2's `lea scratch, &g` emits a checked name.
    # Only a CONSTRUCTOR build needs `&g` held across the rhs; a scalar store
    # emits the rhs FIRST (fused order), so its global base is a transient
    # premat staging pick (the dontCare marker) — no survivor, no exhaustion.
    var globScratch = NoReg
    var globHeld = dontCare
    if (rhs.kind == TagLit and rhs.exprKind in {OconstrC, AconstrC}) and
       g.lvalueGlobalBaseE(lhs):
      globHeld = g.takeHeld("a global address")
      globScratch = globHeld.r
    if globScratch != NoReg: g.bindTemp(globScratch, AsmSlot(cls: AInt, size: 8, align: 8))
    let globBaseLoc = (if globScratch != NoReg: regLoc(globScratch, ScalarSlot)
                       else: dontCare)
    if rhs.kind == TagLit and rhs.exprKind == OconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genConstrIntoLval2(rhs, lhs)                      # build field-by-field into the address
      g.freeLvalTemps2(lhs)
    elif rhs.kind == TagLit and rhs.exprKind == AconstrC:
      g.emitLvalue2(lhs, globBaseLoc, isStore = true)
      g.genAconstrIntoLval2(rhs, lhs)                     # build array element-by-element
      g.freeLvalTemps2(lhs)
    else:
      # Evaluate the rhs BEFORE materializing the lhs base. A stack-homed `deref`/`at`
      # base pointer is reloaded into a fresh STAGING register at emit time (see
      # `reloadMemBase2`), which the register allocator does not track — so if the base
      # were materialized first, evaluating the rhs (whose value-core temps the
      # allocator DID place) could land on that staging register and clobber the base.
      # This is exactly the self-referencing field store `x.f = g(x.f)` (e.g. the
      # allocator's `next.prevSize = size or (next.prevSize and 1)`): the rhs re-reads
      # `next.prevSize` through its own base, overwriting the not-yet-consumed store
      # base. Emitting the base AFTER the rhs makes `pickStagingScratch` avoid the live
      # rhs value (it is a `boundTemp`) and reuse a now-dead rhs intermediate's register.
      # Safe to reorder: hexer un-nests, so every lvalue-embedded value is an idempotent
      # symbol/immediate load. `prematLval2(lhs)` therefore moves down to just before
      # each store's `emLvalAddr2(lhs)`.
      # If the rhs is a sub-width int bin-arith stored into this (same-or-narrower)
      # integer field, the store truncates → its `shl;sar` re-normalize is dead.
      let savedSuppress = g.binNormSuppressPos
      block:
        let dstTyR = resolveType(g.prog, g.getType(lhs))
        let w = if isPtrType(dstTyR): 8 else: typeToSlot(dstTyR).size
        g.binNormSuppressPos = g.binStoreSuppressPos(rhs, w)
      var v: Location
      if g.isFloatExpr(rhs):
        # The DESTINATION's slot, not `dontCare` — the same reason as in
        # `genFieldStore2`: a float literal takes its bit pattern from the
        # destination slot and the store below takes its width from `v.typ`,
        # so an unseeded `a[0] = 1.0'f32` wrote the double pattern over the
        # element's neighbour and read back as 0.0.
        let lhsSlot = g.exprSlot(lhs)
        v = (if lhsSlot.kind == AFloat: Location(kind: Undef, typ: lhsSlot)
             else: dontCare)
        g.emitFValue2(rhs, v)                             # rhs value FIRST
      else:
        v = needsReg(ScalarSlot)
        g.emitValue2(rhs, v)
      # lvalue picks AFTER the rhs: the live rhs value is a bound temp, so the
      # picks (and later premat staging) cannot land on it. `isStore=false`:
      # a global base stages transiently — nothing to survive, the rhs is done.
      g.emitLvalue2(lhs, globBaseLoc, isStore = false)
      g.binNormSuppressPos = savedSuppress
      let floatRhs = v.kind == InFReg or
                     (v.kind in {NamedStack, Mem} and v.typ.isFloat)
      if floatRhs:                                        # float store
        let bits = if v.typ.size == 4: 32 else: 64
        if v.kind != InFReg:                              # demoted (stolen) float local → staging xmm
          let fs = g.pickFStagingSealed("a memory store rhs")
          g.floatMemMov(v, fs, bits, load = true)
          g.prematLval2(lhs, foldDisp = true)                              # base regs AFTER the rhs is secured
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.emMemLval2(lhs)
            g.emFReg fs
          g.rb.unsealF fs
        else:
          g.prematLval2(lhs, foldDisp = true)
          g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
            g.emMemLval2(lhs)
            g.emFReg v.f
          if v.isTemp: g.unbindFTmp(v.f)
      else:                                               # integer/immediate store
        # A POINTER destination field reinterprets the source register via
        # `(cast <fieldType> reg)`: nifasm is strict, so an `(i 64)` reg (e.g. a
        # materialized `nil`, or pointer arithmetic) cannot move into a `(ptr T)`
        # field without it (mirrors genConstr2's pointer-field store).
        var dstTy = resolveType(g.prog, g.getType(lhs))
        let dstPtr = isPtrType(dstTy)
        var rhsStaging = NoReg
        if v.kind in {NamedStack, Mem}:                   # demoted (stolen) local → staging reg
          rhsStaging = g.pickStagingSealed("a memory store rhs", v.typ)
          g.emitLoadLoc(v, rhsStaging)
          v = regLoc(rhsStaging, v.typ)
        g.prematLval2(lhs, foldDisp = true)                                 # base regs AFTER the rhs is secured
        g.ab.tree MovX64:
          g.emMemLval2(lhs)
          case v.kind
          of Imm: g.emImm(v)
          of InReg:
            if dstPtr:
              g.ab.tree CastX:
                g.genTypeBody(dstTy)
                g.emReg v.r
            else:
              g.emReg v.r
          else: raiseAssert "arkham x64n: store rhs " & $v.kind
        if rhsStaging != NoReg: g.giveBack rhsStaging
        elif v.kind == InReg and v.isTemp: g.unbindTemp(v.r)
      g.unbindLvalTemps2(lhs)                             # release embedded base/index temps
      g.freeLvalTemps2(lhs)
    if globScratch != NoReg: g.unbindTemp(globScratch)
    g.freeVal(globHeld)
  elif dst.kind == Field:                                # a field within an aggregate
    g.genFieldStore2(dst, rhs)
  else:                                                  # scalar / float home (reg or `(s)` slot)
    # Dest threading: a register home receives the rhs DIRECTLY (the store
    # collapses); a slot home takes a single-use temp then stores. Never
    # thread a NamedStack dest into emitValue2 — leaves would emit nothing.
    if dst.kind == InFReg:
      var v = dst
      g.emitFValue2(rhs, v)
      g.storeScalar2(dst, v)
    elif dst.kind == InReg:
      var v = dst
      g.emitValue2(rhs, v)
      g.storeScalar2(dst, v)
    elif dst.typ.isFloat:
      var v = g.takeFTmp(dst.typ)            # carry the precise (f N) width
      g.emitFValue2(rhs, v)
      g.storeScalar2(dst, v)
    else:
      var v = needsReg(dst.typ)
      g.emitValue2(rhs, v)
      g.storeScalar2(dst, v)

# ── conditional-move (branchless select) ─────────────────────────────────────

# ── computed-goto case dispatch (issue #32) ──────────────────────────────────

# ── fused value core: unconverted-proc stubs (die as each case lands) ────────
proc emitBin2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED binary-arith: allocBin's placement policy (Sethi–Ullman swap,
  ## destination passthrough, rhs-temp recycling, aliasRhs hazard) decided
  ## right here, then emitted — one ladder, no replay hints.
  let pos = cursorToPosition(g.buf[], c)
  let (op, isBin) = binArithOp(c)
  assert isBin, "arkham x64n: emitBin2 on a non-bin node"
  let ek = c.exprKind
  let suppressNorm = pos >= 0 and pos == g.binNormSuppressPos
  var lhsC, rhsC, resTypeC: Cursor
  block:
    var cc = c
    cc.into:
      resTypeC = cc; skip cc                             # result type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  checkArithResultType(g.prog, resTypeC, lengInfo(c))
  # ── Sethi–Ullman swap: foldable/memory lhs + computed rhs → rhs first, into
  # the accumulator; the leaf lhs folds after (sub completes with a neg).
  let lhsMem = g.isFoldableMemLeaf(lhsC)
  let swap = ek notin {ShlC, ShrC} and (commutativeExpr(ek) or ek == SubC) and
             (g.isFoldableLeafE(lhsC) or lhsMem) and
             not (g.isFoldableLeafE(rhsC) or g.isFoldableMemLeaf(rhsC)) and
             not (dest.kind == InReg and g.symInRegE(lhsC, dest.r))
  if swap:
    var acc = dest
    # The accumulator receives the RHS first and only becomes the result's type at
    # `normalizeBinWidth` below, so it is minted at the RHS's type and retyped after
    # the normalizer. Minting it at the result type made the rhs fill a narrowing
    # reg→reg move; same rule as the general path below.
    let accIncoming = g.exprSlot(rhsC)
    if acc.kind != InReg: acc = g.takeTmp(accIncoming)
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoMem2(c, acc)                          # pools dry: whole node via staging
      dest = acc
      return
    let rD = acc.r
    var rdst = acc
    g.emitValue2(rhsC, rdst)                             # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundTemp(rD): g.bindTemp(rD, acc.typ)
    var lLoc = dontCare                                  # the leaf lhs: its natural place
    if lhsMem:
      g.emitLvalue2(lhsC)                                # pick embedded base/index regs
      lLoc = memLoc(lhsC, ScalarSlot)
    else:
      g.resolveLvalVal(lhsC, lLoc)                       # imm / register / stack home
    let foldOp = if op == SubX64: AddX64 else: op        # sub folds as add (after neg)
    let rdSeal = not g.plan.isSealed(rD) and not g.rb.isBoundTemp(rD)
    if rdSeal: g.plan.seal {rD}
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # rD := -rhs
    case lLoc.kind                                       # rD := rD <foldOp> lhs
    of Imm:
      if lLoc.ival < low(int32).int64 or lLoc.ival > high(int32).int64:
        let s = g.pickStagingSealed("a bin imm64", acc.typ)
        g.movImm(s, lLoc.ival)
        g.binReg(foldOp, rD, s)
        g.giveBack s
      else: g.binImm(foldOp, rD, lLoc.ival)
    of InReg: g.binReg(foldOp, rD, lLoc.r)
    of NamedStack, Mem: g.binFold(foldOp, rD, lLoc, lhsC) # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin(swapped) lhs " & $lLoc.kind
    if lhsMem: g.freeLvalTemps2(lhsC)                    # embedded picks die with the fold
    if not suppressNorm: g.normalizeBinWidth(resTypeC, rD, op)
    if acc.isTemp and g.rb.isBoundTemp(rD) and
       slotTypeDiffers(g.prog, accIncoming, resTypeC):
      var rtcS = resTypeC
      g.bindTemp(rD, slotOf(g.prog, rtcS))               # now it holds the result
    if rdSeal: g.plan.unseal {rD}
    dest = acc
    return
  # ── canonical order: lhs into a register (or straight into a pinned dest
  # when safe), rhs folds in place.
  # Mint the lhs temp at the OPERATOR's result type, not a dont-care `(i 64)`.
  # A Leng literal has no type of its own — `1` in `(or (u 32) 1 x)` is a u32
  # operand — and `place2` of an `(i 64)` temp into a `(u 32)` named dest is a
  # narrowing move nifasm rejects (encodeInlineStr: `result = 1 or (uint32(len) shl 1)`).
  var lDest = needsReg(g.binResultSlot(resTypeC))
  # A shift is excluded only because a VARIABLE count is pinned to cl below; with
  # a constant count no fixed register is involved and the passthrough is as safe
  # as for any other op. Excluding every shift cost a `mov` per shift whose result
  # has a home: the lhs landed in a fresh temp and the result then had to be moved
  # out of it. `(asgn x (and (shr y 4) 511))` came out as
  #     mov y,T ; shr $4,T ; mov T,x ; and $511,x
  # where three instructions do the work (nifbench: 117 M executions of the
  # `mov`+const-shift pair, 1.5 % of all instructions).
  # `isImmLeaf` rather than `isFoldableLeafE` for the rhs: the latter only knows
  # BARE literals, and a front-end spells a typed one `(suf 511u "u32")` — so the
  # passthrough was dead for every op with a suffixed operand, which is most of
  # them. (The swap branch above must keep the narrow test: there the lhs is only
  # RESOLVED, by `resolveLvalVal`, which materializes bare literals and symbol
  # homes and nothing else.)
  # `isFoldableMemLeaf`, not `isMemLeaf`: a field of a register-homed ≤16B
  # aggregate IS a GPR, so folding it as `[mem]` would address a slot that does
  # not exist.
  if dest.kind == InReg and (ek notin {ShlC, ShrC} or isConstShiftCount(rhsC)) and
     not g.isFoldableLeafE(lhsC) and
     (g.isFoldableLeafE(rhsC) or isImmLeaf(rhsC) or g.isFoldableMemLeaf(rhsC)) and
     not g.exprReadsRegE(lhsC, dest.r) and not g.exprReadsRegE(rhsC, dest.r):
    lDest = dest                                         # compute lhs straight into dest
  g.emitValue2(lhsC, lDest)
  # The rhs may be FORCED to overwrite a fixed register — `div`/`idiv` take rax and
  # rdx, a variable shift takes cl — and the seal below is no defence against that.
  # A seal keeps the POOLS and the staging picker off a register; it cannot keep the
  # ISA off one, and `emitDivMod2` writes rax unconditionally. So a live lhs partial
  # sitting in such a register has to MOVE, before the rhs runs.
  #
  # The call marshaller has parked its already-placed arguments off exactly these
  # registers for as long as `fixedRegsClobberedByE` has existed; this side never
  # did. Reaching it needs pressure high enough to leave a partial in rax at all:
  #     (add (div a b) (div c d))       every pool register held by a live local
  # left the first quotient in rax, and the second `div` overwrote it. The `add` then
  # added the second quotient to itself. Not silent, but only by luck — the partial
  # happened to carry a temp binding, so nifasm rejected the `div` ("clobbers RAX,
  # still bound to `tmp1.0") instead of assembling the wrong answer.
  if lDest.kind == InReg and lDest.r in g.fixedRegsClobberedByE(rhsC):
    let old = lDest
    var safe = g.takeTmp(old.typ)                        # R10, or an etmp slot when dry
    assert not (safe.kind == InReg and
                safe.r in g.fixedRegsClobberedByE(rhsC)),
      "arkham x64n: the temp pool handed out a fixed-role register"
    if safe.kind == InReg:
      g.bindTemp(safe.r, old.typ)
      g.movReg(safe.r, old.r)
    else:
      g.emitStoreLoc(safe, old.r)                        # pools dry: park it in the slot
    g.freeVal(old)                                       # `(kill)`s the binding on rax
    lDest = safe
  # The lhs partial is LIVE in `lDest` across the rhs evaluation, and that
  # evaluation recurses into arbitrary emission. A bound TEMP is already off
  # limits to a staging pick (`isBoundTemp`); a FIXED destination is not — the
  # proc's result register carries no binding at all, so nothing stopped
  # `pickStagingScratch` handing out the rax holding a half-built `(ret …)`
  # value, and an address temp of the rhs overwrote it (`addr_chain_depth`).
  # Seal states what the register is doing; `regFreeForTemp` honours it too, so
  # the allocator's own pool picks stay off it as well.
  let lSeal = lDest.kind == InReg and not g.plan.isSealed(lDest.r) and
              not g.rb.isBoundTemp(lDest.r)
  if lSeal: g.plan.seal {lDest.r}
  var rDest = dontCare
  if ek in {ShlC, ShrC} and g.md.shiftCountReg != NoReg and
     not isConstShiftCount(rhsC):
    # x86 variable shift: the count must be in cl. A live bound TEMP there is a
    # real hazard; a (`ShiftRegOk`) HOME is interval-proved dead at every
    # variable shift, and a committed call argument in rcx was PARKED off it
    # by the marshaller — so only a temp is asserted.
    if g.rb.isBoundTemp(g.md.shiftCountReg):
      raiseAssert "arkham: variable shift while the count register holds a live value"
    # A `ShiftRegOk` home in rcx is interval-proved DEAD here, but "dead" is arkham's
    # word: nifasm still sees the NAME bound to the register, so `emitValue2` writes
    # the count out under that name — at that name's type. `rawLineInfo` homes a
    # `(ptr (u 32))` there and then shifts by 14: `(mov `cse.1 14)`, rejected as
    # "cannot store the non-zero integer 14 into the pointer-typed destination".
    # Retire the binding so the count lands in a raw `(rcx)` instead. Exactly what
    # the div/mod path does for rdx (see `releaseStaleName` there) — this side was
    # missing it, and only register pressure high enough to home a local in rcx at
    # all made the difference visible.
    g.releaseStaleName(g.md.shiftCountReg)
    rDest = regLoc(g.md.shiftCountReg, ScalarSlot)
  g.emitValue2(rhsC, rDest)                              # rhs → wherever (may stay imm/home)
  if lSeal: g.plan.unseal {lDest.r}                        # the partial is consumed below
  # ── result placement: keep a fixed dest; else in-place RMW on a dead lhs
  # temp; else recycle the dead rhs temp (aliasRhs); else a fresh temp.
  var res = dest
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    if lDest.kind == InReg and lDest.isTemp: res = lDest
    elif rDest.kind == InReg and rDest.isTemp and lDest.kind == InReg and
         ek notin {ShlC, ShrC}:
      res = rDest
    else: res = g.takeTmp(g.binResultSlot(resTypeC))
  else: discard
  let aliasRhs = res.kind == InReg and rDest.kind == InReg and res.r == rDest.r and
                 not (lDest.kind == InReg and res.kind == InReg and lDest.r == res.r)
  if aliasRhs and ek in {ShlC, ShrC}:
    raiseAssert "arkham: variable shift whose destination aliases the count register"
  # ── emission (the old emitBin2 body over the freshly decided locations).
  var resStaging = NoReg
  var rD: Reg
  if res.kind in {NamedStack, Mem}:                      # incl. a takeTmp-dry etmp slot
    resStaging = g.pickStagingSealed("a memory bin result", res.typ)
    rD = resStaging
  else:
    assert res.kind == InReg, "arkham x64n: bin result " & $res.kind
    rD = res.r
  let reusedLhs = lDest.kind == InReg and lDest.r == rD  # in-place RMW on the left temp
  let reusedRhs = rDest.kind == InReg and rDest.r == rD  # dest recycled the RHS temp
  # A TEMP destination is bound at the type of what LANDS IN IT — the lhs `place2`
  # moves in below — not at the result type. The register only becomes the result's
  # type at `normalizeBinWidth` (the `movzx` after the op), and the retype for that
  # happens down there. Binding it at the result type up front made the lhs move
  # narrowing: `(rebind tmp1 (u 32))` then `(mov tmp1 (i 64)tmp0)`, which nifasm
  # rejects — and rightly, since nothing has converted anything yet.
  # A dont-care lhs slot is not "no information": it is the `(i 64)` its own temp
  # is bound as, which is precisely what arrives here.
  let incoming = (if lDest.kind == InReg: lDest.typ else: res.typ)
  if res.kind == InReg and res.isTemp and not g.rb.isBoundTemp(rD):
    g.bindTemp(rD, incoming)
  if not isPtrType(resolveType(g.prog, resTypeC)):
    let nm = g.rb.boundName(rD)
    if g.rb.isBoundTemp(rD):
      if reusedLhs or reusedRhs:                         # inherited an operand's binding
        var rtc = resTypeC
        g.bindTemp(rD, slotOf(g.prog, rtc))
    elif nm.len > 0:
      g.rebindLocalAs(nm, rD, resTypeC)
  let rdSeal = not g.plan.isSealed(rD) and not g.rb.isBoundTemp(rD)
  if rdSeal: g.plan.seal {rD}
  if aliasRhs:
    assert lDest.kind == InReg, "arkham x64n: aliasRhs lhs " & $lDest.kind
    g.binReg(op, rD, lDest.r)                            # dest := rhs op lhs
    if op == SubX64:
      g.ab.tree NegX64: g.emReg rD                       # dest := lhs - rhs
  else:
    # `rD` may be a NAMED destination whose type is not ours to change (the retype
    # above put the result type back on it), while the lhs partial sits in a temp
    # minted at the dont-care `(i 64)`. Retype the TEMP instead — in Leng both
    # operands of an integer op already have the node's result type, and a rebind
    # is zero machine code — so the move below is not a narrowing one. Without it
    # `(or (u 32) 1 …)` into a `(u 32)` result emitted `(mov result.71 `tmp5.0)`
    # with `tmp5.0` bound `(i 64)`, which nifasm rejects.
    if lDest.kind == InReg and lDest.isTemp and lDest.r != rD and
       g.rb.isBoundTemp(lDest.r) and not g.rb.isBoundTemp(rD) and
       slotTypeDiffers(g.prog, lDest.typ, resTypeC):
      var rtcL = resTypeC
      g.bindTemp(lDest.r, slotOf(g.prog, rtcL))
    g.place2(lDest, rD)                                  # dest := lhs
    case rDest.kind                                      # dest op= rhs
    of Imm:
      if rDest.ival < low(int32).int64 or rDest.ival > high(int32).int64:
        let s = g.pickStagingSealed("a bin imm64", res.typ)
        g.movImm(s, rDest.ival)
        g.binReg(op, rD, s)
        g.giveBack s
      else: g.binImm(op, rD, rDest.ival)
    of InReg: g.binReg(op, rD, rDest.r)
    of NamedStack, Mem: g.binFold(op, rD, rDest, rhsC)   # sub-width field → load+extend
    else: raiseAssert "arkham x64n: bin rhs " & $rDest.kind
  if not suppressNorm: g.normalizeBinWidth(resTypeC, rD, op)
  # The op ran and the width was normalized, so the register now holds the RESULT.
  # Put the result's type on the temp that was bound at the incoming type above.
  if res.kind == InReg and res.isTemp and g.rb.isBoundTemp(rD) and
     slotTypeDiffers(g.prog, incoming, resTypeC):
    var rtc2 = resTypeC
    g.bindTemp(rD, slotOf(g.prog, rtc2))
  if rdSeal: g.plan.unseal {rD}
  if not reusedRhs: g.freeVal(rDest)                     # freeVal frees only temps
  if not reusedLhs: g.freeVal(lDest)
  if resStaging != NoReg:                                # store the result to its memory home
    g.emitStoreLoc(res, resStaging)
    g.giveBack resStaging
  dest = res
proc settleResultReg(g: var CodeGen; dest: var Location; resReg: Reg) =
  ## FUSED result settling: move/store a value produced in the fixed register
  ## `resReg` (rax after a div/mem-intrinsic, rdx for a remainder) into `dest`,
  ## resolving an unconstrained dest to `resReg` itself as a bound temp.
  case dest.kind
  of Undef, NeedsReg, RegOrImm:
    dest = regLoc(resReg, ScalarSlot, isTemp = true)
    if not g.rb.isBoundTemp(resReg): g.bindTemp(resReg, dest.typ)
  of InReg:
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    if dest.r != resReg: g.movReg(dest.r, resReg)
  of NamedStack, Mem:                                   # a memory home / spill slot
    let bound = g.rb.isBoundTemp(resReg)
    if not bound: g.bindTemp(resReg, ScalarSlot)
    g.emitStoreLoc(dest, resReg)
    if not bound: g.unbindTemp(resReg)
  else: raiseAssert "arkham x64n: fixed-reg result dest " & $dest.kind

proc emitDivMod2(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED x86 `idiv`/`div`: dividend → rax (fixed), divisor → a register
  ## (never rax/rdx — the temp pools exclude both); the result (rax quotient /
  ## rdx remainder) moves/stores to `dest`. A constant power-of-two divisor
  ## strength-reduces to shifts.
  let wantRem = c.exprKind == ModC
  var tc, divC, dvsC: Cursor
  block:
    var cc = c
    cc.into:
      tc = cc; skip cc                                  # result type
      divC = cc; skip cc                                # dividend
      dvsC = cc; skip cc                                # divisor
      while cc.hasMore: skip cc
  let signed = isSignedType(resolveType(g.prog, tc))
  # rdx is clobbered. A live bound TEMP there is a real hazard; a (`DivRegOk`)
  # home is interval-proved dead at every div, and a committed call argument in
  # rdx cannot coexist with a later-arg div — the marshaller PARKED it off rdx
  # (`fixedRegsClobberedByE`), so an accum seal on rdx here is the protected case.
  if g.rb.isBoundTemp(g.md.divRemReg):
    raiseAssert "arkham: div/mod while the remainder register holds a live value"
  # A `DivRegOk` home in rdx is interval-proved DEAD here, but "dead" is arkham's
  # word: nifasm still sees the name bound to the register, and `idiv`'s raw
  # `(rdx)` operand bypasses the binding check that would otherwise catch it
  # (`checkFixedRegFree`). Retire the binding so the clobber is declared rather
  # than silent — the same treatment every other raw reuse of a register gets.
  g.releaseStaleName(g.md.divRemReg)
  let acc = g.md.intRetReg                              # rax: dividend, then result

  # Constant power-of-two divisor → shifts (~20-40 cycles saved). Signed mod
  # keeps `idiv` (bias is fiddly); a huge unsigned-mod mask falls through.
  let (dvsIsConst, dval) = g.tryConstFold(dvsC)
  let isPow2 = dvsIsConst and dval >= 2 and (dval and (dval - 1)) == 0
  if isPow2 and not (signed and wantRem) and
     (not wantRem or dval - 1 <= high(int32).int64):
    var k = 0'i64
    var t = dval
    while t > 1: (t = t shr 1; inc k)                   # k = log2(divisor)
    var aD = regLoc(acc, ScalarSlot)
    g.emitValue2(divC, aD)                              # dividend → rax
    if wantRem:                                         # unsigned mod: acc &= 2^k - 1
      g.binImm(AndX64, acc, dval - 1)
    elif not signed:                                    # unsigned div: acc >>>= k
      g.binImm(ShrX64, acc, k)
    else:                                               # signed div: bias, then sar
      let tmp = g.pickStagingSealed("a pow2-div sign bias", ScalarSlot, avoid = acc)
      g.movReg(tmp, acc)
      g.binImm(SarX64, tmp, 63)                         # tmp = sign mask
      g.binImm(ShrX64, tmp, 64 - k)                     # tmp = bias if negative
      g.binReg(AddX64, acc, tmp)
      g.binImm(SarX64, acc, k)
      g.giveBack tmp
    g.settleResultReg(dest, acc)
    return
  var aD = regLoc(acc, ScalarSlot)
  g.emitValue2(divC, aD)                                # dividend → rax
  var dD = needsReg(ScalarSlot)
  g.emitValue2(dvsC, dD)                                # divisor → a register
  if dD.kind == InReg and (dD.r == g.md.intRetReg or dD.r == g.md.divRemReg):
    raiseAssert "arkham: div/mod divisor aliases rax/rdx"
  var dvsLoc = dD
  var dvsStaging = NoReg
  if dvsLoc.kind != InReg:                              # spilled divisor → staging (not rax/rdx)
    dvsStaging = g.pickStagingSealed("an idiv divisor", dvsLoc.typ)
    g.emitLoadLoc(dvsLoc, dvsStaging)
    dvsLoc = regLoc(dvsStaging, dvsLoc.typ)
  let op = if signed: IdivX64 else: DivX64
  g.ab.tree op:
    g.ab.rawReg g.md.divRemReg                             # (rdx): high half / remainder
    g.ab.rawReg g.md.intRetReg                             # (rax): low half / quotient
    g.emReg dvsLoc.r                                    # divisor, by its bound name
  if dvsStaging != NoReg: g.giveBack dvsStaging
  else: g.freeVal(dD)
  g.settleResultReg(dest, if wantRem: g.md.divRemReg else: g.md.intRetReg)
proc emitScalarCmpE*(g: var CodeGen; aC0, bC0: Cursor; ek: LengExpr;
                    whenTrue: bool): X64Inst =
  ## FUSED integer `cmp` for the relation `ek`: operand placement (allocCond's
  ## memory-fold rules) decided inline, flags set, staging released; returns
  ## the `jcc` tag taken when the relation holds as `whenTrue`.
  var aC = aC0
  var bC = bC0
  let unsigned = g.cmpOperandUnsigned(aC) or g.cmpOperandUnsigned(bC)
  result = cmpJccTag(ek, whenTrue, signed = not unsigned)
  if isCmpImmLeaf(aC) and not isCmpImmLeaf(bC):
    # `cmp`'s LEFT operand must be a register or memory, so a literal there is
    # first materialised with a `mov`. Leng has no `>`/`>=` — they ARE `<`/`<=`
    # with the operands exchanged — so `0 <= i` reaches us as `(le 0 i)` and
    # every lower-bound check paid that `mov`. Exchange the operands and mirror
    # the condition instead; the literal then folds as the immediate, and if the
    # new left is a memory leaf the `cmp [mem], imm` path below takes it.
    swap(aC, bC)
    result = mirrorJcc(result)
  if g.isFoldableMemLeaf(aC) and not g.isFoldableMemLeaf(bC):
    # left is a memory load, right is not → fold the LEFT: `cmp [mem], reg/imm`
    # (x86 allows a memory destination; only one memory operand).
    g.emitLvalue2(aC)                                  # pick embedded base/index
    var rD = dontCare
    g.emitValue2(bC, rD)                               # right → reg / imm / its home
    var bLoc = rD
    var bigImmStaging = NoReg
    if bLoc.kind == Imm and
       (bLoc.ival < low(int32).int64 or bLoc.ival > high(int32).int64):
      bigImmStaging = g.pickStagingSealed("a cmp imm64", bLoc.typ)
      g.movImm(bigImmStaging, bLoc.ival)
      bLoc = regLoc(bigImmStaging, bLoc.typ)
    var aBound: seq[Reg] = @[]
    g.bindLvalGlobalBases(aC, aBound)                  # bind a global base before the lea
    g.prematLval2(aC, foldDisp = true)                                  # materialize the lhs base first
    var rhsStaging = NoReg
    if bLoc.kind == NamedStack:                        # no `cmp [mem], [mem]`
      rhsStaging = g.pickStagingSealed("a cmp(memlhs) rhs", bLoc.typ)
      g.emitLoadLoc(bLoc, rhsStaging)
    g.ab.tree CmpX64:
      g.emMemLval2(aC)
      case bLoc.kind
      of Imm: g.emImm(bLoc)
      of InReg: g.emReg bLoc.r
      of NamedStack: g.emReg rhsStaging
      else: raiseAssert "arkham x64n: cmp(memlhs) rhs " & $bLoc.kind
    if rhsStaging != NoReg: g.giveBack rhsStaging
    g.unbindLvalTemps2(aC)
    for r in aBound: g.unbindTemp(r)
    if bigImmStaging != NoReg: g.giveBack bigImmStaging
    g.freeVal(rD)
    g.freeLvalTemps2(aC)
    return
  # A pointer-typed lhs carries its precise slot so a pool-dry etmp spill and
  # its staged reload stay ptr-typed — `cmp (i 64) (nil)` is a nifasm error
  # (the a64 twin's cmpBridgeSlot rule).
  var lD = needsReg(
    if isPtrType(resolveType(g.prog, g.getType(aC))): g.exprSlot(aC)
    else: ScalarSlot)
  g.emitValue2(aC, lD)                                 # left → a register
  # The RHS needs the SAME rule, and did not have it: a pointer-typed operand that
  # goes pool-dry lands in an `etmp` declared `(i 64)`, and the `cmp reg, [rsp+slot]`
  # arm below is then `(ptr …)` vs `(i 64)` — a nifasm type error. Carrying the slot
  # on the dont-care dest keeps the register/immediate/memory folds intact; it only
  # types the temp IF one is taken.
  var rD = dontCare
  if isPtrType(resolveType(g.prog, g.getType(bC))):
    rD = Location(kind: Undef, typ: g.exprSlot(bC))
  let rhsMemFold = g.isFoldableMemLeaf(bC)
  if rhsMemFold:
    g.emitLvalue2(bC)                                  # fold the right: cmp reg, [mem]
  else:
    g.emitValue2(bC, rD)                               # right → reg / imm / home slot
  var aLoc = lD
  var bLoc = rD
  var bigImmStaging = NoReg
  if bLoc.kind == Imm and
     (bLoc.ival < low(int32).int64 or bLoc.ival > high(int32).int64):
    bigImmStaging = g.pickStagingSealed("a cmp imm64", bLoc.typ)
    g.movImm(bigImmStaging, bLoc.ival)
    bLoc = regLoc(bigImmStaging, bLoc.typ)
  var cmpStaging = NoReg
  if aLoc.kind == NamedStack:                          # pool-dry etmp lhs: load it
    cmpStaging = g.pickStagingSealed("a cmp lhs", aLoc.typ)
    g.emitLoadLoc(aLoc, cmpStaging)
    aLoc = regLoc(cmpStaging, aLoc.typ)
  assert aLoc.kind == InReg, "arkham x64n: cmp lhs " & $aLoc.kind
  when defined(arkhamR11Dbg):
    if aLoc.r == R11:
      stderr.writeLine "R11DBG cmp lhs in " & gArkhamCurProc &
        " isTemp=" & $aLoc.isTemp & " exprKind=" & $aC.exprKind &
        " kind=" & $aC.kind &
        (if aC.kind == Symbol: " sym=" & symName(aC) else: "")
  if rhsMemFold:
    var bBound: seq[Reg] = @[]
    g.bindLvalGlobalBases(bC, bBound)
    g.prematLval2(bC, foldDisp = true)
    g.ab.tree CmpX64:
      g.emReg aLoc.r
      g.emMemLval2(bC)
    g.unbindLvalTemps2(bC)
    for r in bBound: g.unbindTemp(r)
    g.freeLvalTemps2(bC)
  else:
    case bLoc.kind
    of Imm:
      # `cmp r, 0` is `test r, r` — same flags, 3 bytes instead of 7. A nil literal
      # is an Imm too but is emitted as `(nil)`, so exclude it explicitly.
      if not isNilImm(bLoc) and bLoc.ival == 0:
        g.cmpZero aLoc.r
      else:
        g.ab.tree CmpX64: (g.emReg aLoc.r; g.emImm(bLoc))
    of InReg:
      g.ab.tree CmpX64: (g.emReg aLoc.r; g.emReg bLoc.r)
    of NamedStack:                                     # spilled scalar: cmp reg, [rsp+slot]
      g.ab.tree CmpX64:
        g.emReg aLoc.r
        g.emStackMem(bLoc.name)
    else: raiseAssert "arkham x64n: cmp rhs " & $bLoc.kind
  if bigImmStaging != NoReg: g.giveBack bigImmStaging
  g.freeVal(rD)
  if cmpStaging != NoReg: g.giveBack cmpStaging
  g.freeVal(lD)

proc emitCondE*(g: var CodeGen; c: Cursor; toLabel: string; whenTrue: bool) =
  ## FUSED branch test: jump to `toLabel` when the condition holds
  ## (`whenTrue`) — short-circuit and/or/not, `cmp`/`jcc` relations, `(ovf)`,
  ## or `cmp v, 0` for a plain boolean value. Operand placement inline.
  ##
  ## A CONSTANT condition decides the branch here, with no code. It is not a rare
  ## case: hexer lowers `while <cond>: …` with the exit inside the body to
  ## `(while (true) …)`, so without this every such loop pays `mov r, 1; cmp r, 0;
  ## jcc` on EVERY iteration — three instructions and a branch to re-derive
  ## something already known at compile time.
  if c.kind == TagLit and c.exprKind in {TrueC, FalseC}:
    if (c.exprKind == TrueC) == whenTrue: g.emJmp(toLabel)   # always taken
    return                                                   # else: never taken
  if c.kind == TagLit and c.exprKind == OvfC:
    let tag =
      if g.ovfSigned: (if whenTrue: JoX64 else: JnoX64)
      else:           (if whenTrue: JbX64 else: JaeX64)
    g.emJcc(tag, toLabel)
    return
  if c.kind == TagLit and c.exprKind in {AndC, OrC, NotC}:
    let ek = c.exprKind
    var aC, bC: Cursor
    block:
      var cc = c
      cc.into:
        if cc.hasMore: (aC = cc; skip cc)
        if cc.hasMore: (bC = cc; skip cc)
        while cc.hasMore: skip cc
    case ek
    of NotC:
      g.emitCondE(aC, toLabel, not whenTrue)
    of AndC:
      if whenTrue:
        let lSkip = g.freshLabel()
        g.emitCondE(aC, lSkip, false)
        g.emitCondE(bC, toLabel, true)
        g.emLab(lSkip)
      else:
        g.emitCondE(aC, toLabel, false)
        g.emitCondE(bC, toLabel, false)
    else:                                              # OrC
      if whenTrue:
        g.emitCondE(aC, toLabel, true)
        g.emitCondE(bC, toLabel, true)
      else:
        let lSkip = g.freshLabel()
        g.emitCondE(aC, lSkip, true)
        g.emitCondE(bC, toLabel, false)
        g.emLab(lSkip)
    return
  if c.kind == TagLit and c.exprKind in {EqC, NeqC, LtC, LeC}:
    let ek = c.exprKind
    var aC, bC: Cursor
    block:
      var cc = c
      cc.into:
        aC = cc; skip cc
        bC = cc; skip cc
        while cc.hasMore: skip cc
    if g.isFloatExpr(aC):
      # FLOAT comparison: comisd/comiss; both operands in xmm registers.
      #
      # `comisd` reports an UNORDERED pair (either operand NaN) as ZF=PF=CF=1 —
      # which reads exactly like "equal" and like "below or equal" to the plain
      # unsigned tags. IEEE says every one of `==`, `<`, `<=` is FALSE against a
      # NaN (and `!=` is true), so the tags cannot be taken as-is:
      #   * `<` / `<=`: emit the compare with the operands SWAPPED and test the
      #     above/above-or-equal side. Those need CF=0, which unordered never
      #     produces, so the relation comes out false — no extra branch. The
      #     evaluation order of the operands is untouched; only the two register
      #     fields of the `comisd` trade places.
      #   * `==` / `!=`: ZF alone cannot separate "equal" from "unordered", so PF
      #     decides. `==`-taken needs one guard jump around the `je`; the three
      #     other combinations are a two-jump disjunction or a single jump.
      let fbits = g.floatBits(aC)
      let swapped = ek in {LtC, LeC}
      # Both operands take the compare's OWN float slot rather than
      # `dontCare`: a float LITERAL picks its bit pattern from the
      # destination slot, so an unseeded one builds the DOUBLE pattern and
      # the `comiss` below — correctly `fbits` wide — reads the wrong half
      # of it. `f > 1.4'f32` compared garbage while `f > g` with a `float32`
      # variable was right, since only the literal had no width to go on.
      let cmpSlot = g.exprSlot(aC)
      let seed = (if cmpSlot.kind == AFloat: Location(kind: Undef, typ: cmpSlot)
                  else: dontCare)
      var fa = seed
      g.emitFValue2(aC, fa)
      var fb = seed
      g.emitFValue2(bC, fb)
      assert fa.kind == InFReg and fb.kind == InFReg, "arkham x64n: float cmp operands"
      g.ab.tree (if fbits == 32: ComissX64 else: ComisdX64):
        if swapped: (g.emFReg fb.f; g.emFReg fa.f)
        else:       (g.emFReg fa.f; g.emFReg fb.f)
      case ek
      of LtC:                                          # a < b  ⟺  b > a (ordered)
        g.emJcc((if whenTrue: JaX64 else: JbeX64), toLabel)
      of LeC:                                          # a <= b ⟺  b >= a (ordered)
        g.emJcc((if whenTrue: JaeX64 else: JbX64), toLabel)
      of EqC:
        if whenTrue:
          let lNot = g.freshLabel()
          g.emJcc(JpX64, lNot)                         # unordered ⇒ not equal
          g.emJcc(JeX64, toLabel)
          g.emLab(lNot)
        else:
          g.emJcc(JneX64, toLabel)
          g.emJcc(JpX64, toLabel)                      # unordered ⇒ take the false arm
      else:                                            # NeqC
        if whenTrue:
          g.emJcc(JneX64, toLabel)
          g.emJcc(JpX64, toLabel)                      # unordered ⇒ `!=` holds
        else:
          let lNot = g.freshLabel()
          g.emJcc(JpX64, lNot)
          g.emJcc(JeX64, toLabel)
          g.emLab(lNot)
      g.freeVal(fb)
      g.freeVal(fa)
      return
    let tag = g.emitScalarCmpE(aC, bC, ek, whenTrue)
    g.emJcc(tag, toLabel)
  elif c.kind == Symbol and g.condFuse.tag.hasKey(symName(c)):
    # `scanCondFusions` proved this bool has one def and one use, that its defining
    # compare has already run, and that nothing since has emitted a single machine
    # instruction. The flags still hold the answer — take the branch straight off
    # them and never materialize the 0/1 at all.
    let nm = symName(c)
    let tag = g.condFuse.tag[nm]
    g.emJcc((if whenTrue: tag else: invertJcc(tag)), toLabel)
    g.condFuse.tag.del nm
  else:
    var v = needsReg(ScalarSlot)
    g.emitValue2(c, v)
    if v.kind == InReg:
      g.cmpZero v.r
      g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
      g.freeVal(v)
    else:
      # a pool-dry etmp bool value: load it staged, compare against zero.
      let s = g.pickStagingSealed("a bool cond operand", v.typ)
      g.emitLoadLoc(v, s)
      g.cmpZero s
      g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
      g.giveBack s

proc emitCondValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED comparison / and/or/not as a 0/1 VALUE. The condition is emitted
  ## FIRST (jump protocol), the result register is resolved and written only
  ## AFTER it: a result taken up front is a register held across the whole
  ## condition — operand evaluation that deep (a spilled bin chain, a premat'd
  ## address) then runs the transient file dry (`semBodyCheckBody`). Taken
  ## late, the carrier is dead during the condition, so operand picks may use
  ## it freely; there is no clobber hazard because every write happens after
  ## every operand read. Dynamic cost is unchanged (2 instrs on either path);
  ## static cost is one extra `jmp` + label over the assume-1 scheme.
  ##
  ## A PLAIN INTEGER COMPARISON skips all of that: `cmp` already left the answer
  ## in the flags, and `setcc` reads it straight into the result's low byte — two
  ## instructions, no branches, no labels, where the diamond needs five and two
  ## label sites. (`and $1` clears the rest: `setcc` writes ONE byte and leaves
  ## the upper 56 bits as they were, which a consumer's `cmp r, 0` would read.)
  ##
  ## It is sound only because NOTHING may be emitted between the `cmp` and the
  ## `setcc`. `takeTmp` (a pool pick, or a spill-slot Location the produce-into
  ## path fills later) and `bindTemp` (a `(rebind …)` declaration) emit no
  ## instructions, so the flags survive both — that is exactly why the carrier can
  ## still be taken LATE here, keeping the register-pressure property above. The
  ## pool-dry path's `pickStagingSealed` CAN spill and must not come between, so
  ## that case keeps the branch form — consuming the very same live flags via the
  ## `jcc` tag `emitScalarCmpE` handed back.
  block setccFastPath:
    if c.kind != TagLit or c.exprKind notin {EqC, NeqC, LtC, LeC}: break setccFastPath
    var aC, bC: Cursor
    block:
      var cc = c
      cc.into:
        aC = cc; skip cc
        bC = cc; skip cc
        while cc.hasMore: skip cc
    if g.isFloatExpr(aC): break setccFastPath   # comisd + the xmm dance: unchanged
    let tag = g.emitScalarCmpE(aC, bC, c.exprKind, whenTrue = true)
    if dest.kind in {Undef, NeedsReg, RegOrImm}: dest = g.takeTmp(ScalarSlot)
    if dest.kind == NamedStack and dest.spillTemp:
      let lT = g.freshLabel()
      let lE = g.freshLabel()
      g.emJcc(tag, lT)                          # flags are still live here
      let s = g.pickStagingSealed("a cond value spill", ScalarSlot)
      g.movImm(s, 0)
      g.emJmp lE
      g.emLab lT
      g.movImm(s, 1)
      g.emLab lE
      g.emitStoreLoc(dest, s)
      g.giveBack s
      return
    let res = dest
    assert res.kind == InReg, "arkham x64n: cond-value result " & $res.kind
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
    g.ab.tree cmpSetccTag(tag): g.emReg res.r
    g.binImm(AndX64, res.r, 1)                  # the byte write left the rest alone
    dest = res
    return
  let lTrue = g.freshLabel()
  let lEnd = g.freshLabel()
  g.emitCondE(c, lTrue, whenTrue = true)
  if dest.kind in {Undef, NeedsReg, RegOrImm}: dest = g.takeTmp(ScalarSlot)
  if dest.kind == NamedStack and dest.spillTemp:
    # pool-dry etmp result: materialize through staging (free now — the
    # condition's operand temps are dead), then store to the slot.
    let s = g.pickStagingSealed("a cond value spill", ScalarSlot)
    g.movImm(s, 0)
    g.emJmp lEnd
    g.emLab lTrue
    g.movImm(s, 1)
    g.emLab lEnd
    g.emitStoreLoc(dest, s)
    g.giveBack s
    return
  let res = dest
  assert res.kind == InReg, "arkham x64n: cond-value result " & $res.kind
  if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
  g.movImm(res.r, 0)
  g.emJmp lEnd
  g.emLab lTrue
  g.movImm(res.r, 1)
  g.emLab lEnd
  dest = res
proc emitMemLoad2*(g: var CodeGen; c: Cursor; dest: var Location; late = false) =
  ## FUSED addressing expr in VALUE position → load `[addr]` into a register.
  ## Decisions inline (allocValue's Deref/Dot/At/Pat case): force a register
  ## result, seal a fixed dest across the embedded-value picks (an index temp
  ## landing on it would mistype the load), pick the embedded values
  ## (`emitLvalue2`; a global base reuses the result register), then the old
  ## emission body.
  ##
  ## `late` (the produce-into-memory caller, see `produceIntoMem2`): the caller
  ## does not care WHICH register carries the value — it only stores it to an
  ## `(s)` slot. Then the transfer register is taken AFTER the address is
  ## materialized, and `dest` is an out-parameter. That is what keeps a chain of
  ## spilled loads (`((a.more).data)[0]`, `cmpStringPtrs`) inside the r10/r11
  ## budget: taken up front, the result register is held across the recursion
  ## that materializes the address, so every nesting level costs one register —
  ## while the address registers themselves die at each level's `(mem …)` tree.
  ## `late` is only viable because the global-base optimization (`globBase`, one
  ## `lea &g` straight into the result register) is skipped with it; a global
  ## base then takes its own staging register via `prematLval2`'s `dontCare`
  ## marker, which is the pre-existing transient path.
  let wr = g.pairFieldReg(c)
  if wr != NoReg:
    if not late:
      g.forceRegDestE(dest)
      if dest.kind == NamedStack and dest.spillTemp:
        g.produceIntoMem2(c, dest); return
    var res = dest
    if late:
      let slot = if dest.typ.size > 0: dest.typ else: ScalarSlot
      res = regLoc(g.pickStaging("a late pair-field load"), slot, isTemp = true)
      g.bindTemp(res.r, slot)
    elif res.isTemp and not g.rb.isBoundTemp(res.r):
      g.bindTemp(res.r, res.typ)
    if res.r != wr: g.movReg(res.r, wr)
    dest = res
    return
  if not late:
    g.forceRegDestE(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
  var res = dest
  let sealedHere = not late and res.kind == InReg and not res.isTemp and
                   not g.plan.isSealed(res.r)
  if sealedHere: g.plan.seal {res.r}
  g.emitLvalue2(c, globBase = (if late: dontCare else: res))
  if sealedHere: g.plan.unseal {res.r}
  let cty = resolveType(g.prog, g.getType(c))
  if cty.typeKind in {LengType.ArrayT, LengType.FlexarrayT}:
    # An array / flexible-array-member lvalue DECAYS to its address: `lea`.
    if not late and res.isTemp and not g.rb.isBoundTemp(res.r):
      g.bindTemp(res.r, ScalarSlot)
    g.prematLval2(c, hint = (if late: NoReg else: res.r))
    if late:
      res = regLoc(g.pickStaging("a late array-decay address"),
                   ScalarSlot, isTemp = true)
      g.bindTemp(res.r, ScalarSlot)
    g.ab.tree LeaX64:
      g.emReg res.r
      g.emLvalAddr2(c)
    g.unbindLvalTemps2(c)
  else:
    var bindSlot = res.typ
    if isPtrType(cty): bindSlot = g.exprSlot(c)
    if not late and res.isTemp and not g.rb.isBoundTemp(res.r):
      g.bindTemp(res.r, bindSlot)                       # bind first: a global base leas &g
    g.prematLval2(c, hint = (if late: NoReg else: res.r), foldDisp = true)  # into res before the (mem …) tree
    if late:
      res = regLoc(g.pickStaging("a late memory-load address"),
                   bindSlot, isTemp = true)
      g.bindTemp(res.r, bindSlot)
    g.ab.tree MovX64:
      g.emReg res.r
      g.emMemLval2(c)
    g.unbindLvalTemps2(c)                               # release staging/stride
  g.freeLvalTemps2(c)                                   # release the picked embedded temps
  dest = res

proc emitAddr2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(addr lvalue)` → a pointer in a register. Identity `&(deref p)`
  ## with a register-homed `p` and a transient dest is `p`'s register itself —
  ## no temp, no copy (kept non-temp so a consuming binop won't clobber it).
  var lv: Cursor
  block:
    var cc = c
    cc.into:
      lv = cc; skip cc
      while cc.hasMore: skip cc
  if dest.kind in {NeedsReg, RegOrImm, Undef}:
    if lv.kind == TagLit and lv.exprKind == DerefC:
      var p = lv; inc p
      if p.kind == Symbol:
        let home = g.plan.locationOfSym(symName(p), cursorToPosition(g.buf[], p))
        if home.kind == InReg:
          dest = home                                   # the address IS p's register
          return
  g.forceRegDestE(dest)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoMem2(c, dest); return
  let res = dest
  # Call-arg dest-threading puts `&stackAgg` in rdi/rsi/… while a dead scalar
  # local is still bound there (`AllRegs` homes). `doBind` is false (the dest
  # is the ABI register, not a temp), so the lea would keep that name's type.
  # Kill a non-pointer tenant.
  if res.kind == InReg and not res.isTemp and g.rb.isBound(res.r) and
     not g.rb.isBoundTemp(res.r) and not g.rb.isPtrBound(res.r):
    g.releaseStaleName(res.r)
  g.emitLvalue2(lv, globBase = res)                     # a global base reuses the lea dest
  # …but do NOT also bind a fresh temp when the register is raw. A non-temp dest
  # here IS the in-flight ABI argument register, and nothing releases such a
  # binding: the marshaller seals an argument only AFTER emitting it, so there is
  # no point at which this one is dropped, and it survives the `(call)` that
  # clobbers the register. nifasm then rejects the next read —
  #   Access to variable `tmp299.0` in register RDX which was clobbered
  # — which is how `nifbench` and three `cps` tests stopped building natively.
  # The binding is only wanted to type the `lea`; the argument is transferred
  # immediately afterwards, so a raw dest is what this position can support.
  g.aggrAddrInto(lv, res.r, g.exprSlot(c), doBind = res.isTemp)
  g.freeLvalTemps2(lv)
  dest = res

proc produceIntoFMem2*(g: var CodeGen; c: Cursor; dst: Location) =
  ## FUSED SIMD produce-into: `dst` is an `(s)(f N)` `eftmp` slot. Materialize
  ## into a staging xmm (the reserved bridge first) and store. The staging xmm
  ## IS sealed across the recursion (destructive SSE writes the accumulator
  ## before the rhs — see the legacy twin's staging-depth note).
  when defined(arkhamDbgSpill):
    stderr.writeLine "DBG produceIntoFMem2 slot=" & dst.name
  let bits = dst.typ.size * 8
  let fs = g.pickFStagingSealed("a spilled float result (deep float nest > staging pool)")
  var d = fregLoc(fs, dst.typ, isTemp = true)
  g.emitFValue2(c, d)
  g.emitStoreFLoc(dst, fs, bits)
  g.unbindFTmp(fs)                       # release the staging name (the recursion bound it)
  g.rb.unsealF fs

proc emitFBinE*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED float binary-arith (allocFBin's policy inline): destructive SSE —
  ## `a` computes straight into the result xmm, `b` folds in place (a float
  ## local in a register) or draws a SIMD temp; a commutative op with a
  ## foldable float leaf lhs and a computed rhs swaps (rhs first).
  let (op32, op64) = fbinOps(c.exprKind)
  let ek = c.exprKind
  var lhsC, rhsC: Cursor
  var fslot = AsmSlot(cls: AFloat, size: 8, align: 8)
  block:
    var cc = c
    cc.into:
      fslot = slotOf(g.prog, cc); skip cc                # result float type
      lhsC = cc; skip cc
      rhsC = cc; skip cc
      while cc.hasMore: skip cc
  let lHome = (if lhsC.kind == Symbol: g.plan.locationOfSym(symName(lhsC), cursorToPosition(g.buf[], lhsC)) else: noLoc)
  let swap = ek in {AddC, MulC} and g.foldableFloatLeafE(lhsC) and
             not g.foldableFloatLeafE(rhsC) and
             not (dest.kind == InFReg and lHome.kind == InFReg and lHome.f == dest.f)
  if swap:
    var acc = dest
    if acc.kind != InFReg: acc = g.takeFTmp(fslot)
    if acc.kind == NamedStack and acc.spillTemp:
      g.produceIntoFMem2(c, acc); dest = acc; return
    let bits = if acc.typ.size == 4: 32 else: 64
    var rdst = acc
    g.emitFValue2(rhsC, rdst)                            # rhs → the accumulator
    if acc.isTemp and not g.rb.isBoundFTmp(acc.f): g.bindFTmp(acc.f)
    if lHome.kind == InFReg:
      g.fbin(op32, op64, acc.f, lHome.f, bits)
    else:                                                # spilled float local: staged load
      let lt = g.pickFStagingSealed("a spilled float operand", avoid = acc.f)
      g.bindFTmp(lt)
      g.emFloatScalarLoad(lt, lHome.name, bits)
      g.fbin(op32, op64, acc.f, lt, bits)
      g.unbindFTmp(lt)
      g.rb.unsealF lt
    dest = acc
    return
  if dest.kind != InFReg: dest = g.takeFTmp(fslot)
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let res = dest
  let bits = if res.typ.size == 4: 32 else: 64
  var lD = res
  g.emitFValue2(lhsC, lD)                                # a → the result xmm
  if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
  if rhsC.kind == Symbol and g.plan.locationOfSym(symName(rhsC), cursorToPosition(g.buf[], rhsC)).kind == InFReg:
    let rHome = g.plan.locationOfSym(symName(rhsC), cursorToPosition(g.buf[], rhsC))
    if rHome.f == res.f and
       not (lhsC.kind == Symbol and symName(lhsC) == symName(rhsC)):
      raiseAssert "arkham: float operand fold aliases the destination register"
    g.fbin(op32, op64, res.f, rHome.f, bits)             # in-place local fold
  else:
    var rD = g.takeFTmp(fslot)
    g.emitFValue2(rhsC, rD)
    if rD.kind == InFReg:
      g.fbin(op32, op64, res.f, rD.f, bits)
      g.freeVal(rD)
    else:                                                # eftmp-spilled rhs: staged fold
      let fs2 = g.pickFStagingSealed("a spilled float operand", avoid = res.f)
      g.emFloatScalarLoad(fs2, rD.name, bits)
      g.fbin(op32, op64, res.f, fs2, bits)
      g.rb.unsealF fs2
  dest = res

proc emitCast2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(conv|cast Type inner)`. Decisions inline (allocValue CastC/ConvC):
  ## float targets/sources force the SIMD/GPR shapes; a NARROWING cast whose
  ## inner is a symbol with a frozen home forces a fresh temp (narrow-in-place
  ## would corrupt the live variable); otherwise the inner dest-threads (the
  ## identity) and the result is re-represented in place.
  let isCast = c.exprKind == CastC
  var tc, targetCur, inner: Cursor
  block:
    var cc = c
    cc.into:
      targetCur = cc                                     # target type AS WRITTEN (nominal)
      tc = resolveType(g.prog, cc); skip cc              # target type (resolved)
      inner = cc; skip cc
      while cc.hasMore: skip cc
  if g.isFloatExpr(c):
    # conversion TO float: the result is an xmm (int source → cvtsi2sd; float
    # source → precision convert).
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ
                        else: AsmSlot(cls: AFloat, size: 8, align: 8))
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoFMem2(c, dest); return
    let res = dest
    # The width comes from the conversion's TARGET TYPE, never from the
    # destination register's slot: `dest` is frequently a generic 8-byte float
    # temp (see the `takeFTmp` above), and reading `res.typ.size` then made every
    # `float32(x)` emit `cvtss2sd` instead of `cvtsd2ss` — reinterpreting the low
    # half of a double as a single. `float64(float32(4.5))` came out 0.0, and
    # with it `sigmatch.checkFloatLitRange`, so a self-hosted compiler rejected
    # `printF32 1.0'f32 + 4.5` (tests/nimony/typeconversions).
    let dstBits = if slotOf(g.prog, targetCur).size == 4: 32 else: 64
    if g.isFloatExpr(inner):
      var fv = res                                       # dest-pass into the operand
      g.emitFValue2(inner, fv)
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
      g.emFcvt(res.f, res.f, dstBits, g.floatBits(inner))
    else:
      var iv = needsReg(ScalarSlot)
      g.emitValue2(inner, iv)
      var ivReg: Reg
      var ownIv = false
      if iv.kind == InReg:
        ivReg = iv.r
      else:                                              # spilled operand → staging
        ivReg = g.pickStagingSealed("int→float operand", iv.typ)
        g.emitLoadLoc(iv, ivReg)
        ownIv = true
      if res.isTemp and not g.rb.isBoundFTmp(res.f): g.bindFTmp(res.f)
      if isCast:
        g.fmovFromGpr(res.f, ivReg, dstBits)             # bit reinterpret, no rounding
      else:
        let (srcW, srcSigned) = g.srcWidthSigned(inner)
        g.extendTo(ivReg, srcW, srcSigned)               # normalize to the full int value
        if srcSigned or srcW < 64: g.fcvtI2F(res.f, ivReg, dstBits)
        else: g.fcvtU2F(res.f, ivReg, dstBits)           # 2^63.. has no cvtsi2sd
      if ownIv: g.giveBack(ivReg)
      else: g.freeVal(iv)
    dest = res
    return
  if g.isFloatExpr(inner):
    # FLOAT source → int/ptr target: `(conv)` is cvttsd2si and a narrow target
    # extends; `(cast)` is a BIT REINTERPRET (movq/movd out of the xmm), so it
    # neither rounds nor re-extends — the bits are the value.
    g.forceRegDestE(dest)
    if dest.kind == NamedStack and dest.spillTemp:
      g.produceIntoMem2(c, dest); return
    let res = dest
    var fv = dontCare
    g.emitFValue2(inner, fv)
    assert fv.kind == InFReg, "arkham x64n: float→int operand " & $fv.kind
    if res.isTemp and not g.rb.isBoundTemp(res.r): g.bindTemp(res.r, res.typ)
    let fbits = if fv.typ.size == 4: 32 else: 64
    if isCast:
      g.fmovToGpr(res.r, fv.f, fbits)
    else:
      g.fcvtF2I(res.r, fv.f, fbits)
      if not isPtrType(tc):
        let targetW = intTypeWidth(tc)
        if targetW < 64: g.extendTo(res.r, targetW, signed = isSignedType(tc))
    g.freeVal(fv)
    dest = res
    return
  # ── int↔int / pointer reinterpret. Narrowing over a frozen symbol home
  # forces a fresh temp (copy-then-narrow, source intact).
  block:
    if inner.kind == Symbol:
      let sh = g.plan.locationOfSym(symName(inner), cursorToPosition(g.buf[], inner))
      var tgc = targetCur
      if sh.kind in {InReg, NamedStack} and slotOf(g.prog, tgc).size < sh.typ.size:
        g.forceRegDestE(dest)
      elif sh.kind == InReg and dest.kind in {Undef, NeedsReg, RegOrImm} and
           (isPtrType(tc) or (not cursorIsNil(sh.typ.typ) and
                              isPtrType(resolveType(g.prog, sh.typ.typ)))):
        # A pointer-ness change over a register-homed local, with no destination
        # of our own: without a temp the value would be threaded up in the
        # SYMBOL's home and the re-representation below would `rebindLocalAs`
        # that home — retyping the local itself for the rest of its scope. A
        # later use at its declared type then fails the binding checker
        # (measured: `(cast (i 64) p)` for a chunk mask, then `p == nil`).
        g.forceRegDestE(dest)
  # A memory-home destination: compute into a temp, re-represent, store.
  if dest.kind in {NamedStack, Mem} and not (dest.kind == NamedStack and dest.spillTemp):
    var tmp = needsReg(dest.typ)
    g.emitCast2(c, tmp)
    let s = (if tmp.kind == InReg: tmp.r
             else: g.pickStagingSealed("a cast result", tmp.typ))
    if tmp.kind != InReg: g.emitLoadLoc(tmp, s)
    g.emitStoreLoc(dest, s)
    if tmp.kind != InReg: g.giveBack s
    else: g.freeVal(tmp)
    return
  if dest.kind == NamedStack and dest.spillTemp:
    # A SPILL-SLOT destination (`takeTmp` found the pools dry). Threading the slot
    # down as the inner's destination and returning is what the tail of this proc
    # used to do — and the `extendTo` below IS the cast, so the conversion was
    # simply dropped: `cast[uint32](z)` reached its consumer with all 64 bits. It
    # hides behind `+`/`-`/`*`, which are congruent mod 2^n; `div`, `shr` and
    # comparisons are not (`a64_cast_narrow_spilled` divides, which is why it
    # catches this and ordinary arithmetic does not).
    #
    # Route the whole node through the bridge instead: `produceIntoMem2` re-enters
    # with a REGISTER destination, so the cast takes the normal path below and its
    # result is stored converted. Exactly the shape the two float arms above already
    # use, and the x86 twin of `eaaafa7`'s AArch64 fix.
    g.produceIntoMem2(c, dest); return
  # Pre-retype a register-homed named dest to the INNER's type while the inner
  # emits, and put the target type back after the extend below. Two reasons, one
  # rule: int arithmetic under an int→ptr reinterpret must run int-typed, and the
  # register genuinely HOLDS the inner's value until `extendTo` converts it — a
  # `(u 8)` local receiving an `(i 64)` value is a narrowing move nifasm rejects,
  # and rightly: the narrowing is the `movzx` that follows, not the move.
  # Zero machine code either way; only the declared type moves.
  var preRetyped = ""
  if dest.kind == InReg and not dest.isTemp:
    let nm = g.rb.boundName(dest.r)
    var st = g.getType(inner)
    # What the value ARRIVES as, which is not always the inner's static type: an
    # inner symbol that shares another local's home (an identity-cast alias) comes
    # out of THAT name's binding. `(cast (u -1) exprKind.0)` whose `exprKind.0`
    # lives in an `(i 64)` local retyped the destination to the enum's `(u 16)` and
    # then moved 64 signed bits into it — a mismatch nifasm rejects.
    if inner.kind == Symbol:
      let sh = g.plan.locationOfSym(symName(inner), cursorToPosition(g.buf[], inner))
      if sh.kind == InReg:
        let bt = g.bindTypeOf(sh.r)
        if not cursorIsNil(bt): st = bt
    if nm.len > 0 and bindTypeDiffers(g.prog, st, targetCur):
      g.rebindLocalAs(nm, dest.r, st)
      preRetyped = nm
  var iv = dest                                          # identity: thread dest down
  if iv.kind == Undef:
    # An unconstrained dest could resolve to the inner's memory home — but the
    # cast re-represents (rebind/extend) in a REGISTER. Demand reg-or-imm: a
    # foldable literal stays an Imm (returned above), a memory home loads.
    iv = regOrImm(dest.typ)
  if iv.typ.cls in {ABool, AInt, AUInt} and iv.typ.size < 8 and not isPtrType(tc) and
     (iv.kind in {NeedsReg, RegOrImm} or
      (iv.kind == InReg and iv.isTemp and not g.rb.isBoundTemp(iv.r))):
    # An int↔int re-representation happens IN a register and is FINISHED by the
    # explicit `extendTo` below, so the register that receives the source must be
    # bound at the canonical 64-bit width. Binding it at the TARGET's narrow width
    # instead made `(mov u8tmp 4000)` — a literal that does not fit `(u 8)`, which
    # nifasm rejects, even though the very next `movzx` is what performs the
    # narrowing. Mirrors the a64 twin.
    iv.typ = ScalarSlot
  g.emitValue2(inner, iv)
  dest = iv
  if dest.kind == Imm:
    # A folded constant reinterprets freely, but a narrowing cast must keep only
    # the target width (`cast[byte](4000)` → 160), else a later `(mov (u 8) 4000)`
    # fails nifasm's literal-fits-width check.
    if not isPtrType(tc):
      let tw = intTypeWidth(tc)
      if tw < 64:
        dest.ival = truncateImm(dest.ival, tw, isSignedType(tc))
    return
  var innerSlot = default(Location)
  if dest.kind == NamedStack and dest.spillTemp:
    # The INNER produced into a spill slot despite the register demand above
    # (`takeTmp` found the pools dry inside the recursion). Returning here is the
    # same dropped conversion as the spilled-DESTINATION case, one level down, and
    # it is not hypothetical: `shift_count_clobbers_mask` reaches it on x86-64
    # today. The re-representation below is a register operation, so bring the
    # value into the bridge, let the tail convert it there, and store it back.
    innerSlot = dest
    let s = g.pickStagingSealed("a spilled cast inner", ScalarSlot)
    g.emitLoadLoc(innerSlot, s)
    if not g.rb.isBoundTemp(s): g.bindTemp(s, ScalarSlot)
    dest = regLoc(s, ScalarSlot, isTemp = true)
  assert dest.kind == InReg, "arkham x64n: cast result " & $dest.kind
  let res2 = dest
  let ptrTarget = isPtrType(tc)
  let srcPtr = isPtrType(resolveType(g.prog, g.getType(inner)))
  let kindChange = ptrTarget or srcPtr
  if kindChange:
    let reboundAs = (if ptrTarget: slotOf(g.prog, targetCur) else: ScalarSlot)
    if res2.isTemp:
      g.bindTemp(res2.r, reboundAs)
    else:
      let nm = g.rb.boundName(res2.r)                    # the register's named local
      if nm.len > 0: g.rebindLocalAs(nm, res2.r, targetCur)
    # And say so in the LOCATION, not only in the binding. They are two records of
    # one fact and the caller reads the Location: `emitBin2` binds its result temp
    # at `lDest.typ`, so a cast that left the inner's slot there had the ADD's
    # destination declared as the inner's type. `cast[ptr char](cast[uint](p) + n)`
    # — the sanctioned way to offset a pointer — came out as `(add <aptr> …)`, which
    # is exactly the arithmetic-on-a-pointer nifasm rejects. Only reachable with a
    # bigger `InlineTinyBound`, which is what put this shape in one basic block.
    dest.typ = reboundAs
  let (srcW, srcSigned) = g.srcWidthSigned(inner)
  if kindChange:
    if ptrTarget and not srcPtr and srcW < 64 and
       not g.arrivesNormalized(inner, srcW, signed = false):
      g.extendTo(res2.r, srcW, signed = false)
  else:
    let targetW = intTypeWidth(tc)
    if srcW < targetW:
      let sgn = (not isCast) and srcSigned
      if not g.arrivesNormalized(inner, srcW, sgn):
        g.extendTo(res2.r, srcW, sgn)                                 # widen
    else:
      let sgn = isSignedType(tc)
      if not g.arrivesNormalized(inner, targetW, sgn):
        g.extendTo(res2.r, targetW, sgn)                              # narrow / equal
  # The register now holds the TARGET's value, so put the target type back on the
  # name the pre-retype above widened (see there). `kindChange` already did it.
  if not kindChange:
    if preRetyped.len > 0:
      g.rebindLocalAs(preRetyped, res2.r, targetCur)
    elif res2.isTemp:
      # Same lesson as the `kindChange` branch above: say the target type in the
      # LOCATION as well as the binding, or the consumer mints its own temp at
      # the INNER's width.
      if g.rb.isBoundTemp(res2.r): g.rebindTempAs(res2.r, targetCur)
      else: g.bindTemp(res2.r, slotOf(g.prog, targetCur))
      dest.typ = slotOf(g.prog, targetCur)
  if innerSlot.kind == NamedStack:
    # Converted in the bridge (see above): put it back in the slot the caller was
    # handed, and give the Location back as that slot — now carrying the TARGET's
    # type, which is what the value in it is.
    g.emitStoreLoc(innerSlot, res2.r)
    g.giveBack res2.r
    innerSlot.typ = dest.typ
    dest = innerSlot

proc emitCall2Inner(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false;
                    tail = false) =
  ## FUSED call. allocCall's placement decisions run inline: each scalar arg
  ## dest-threads straight into its ABI register (or a parked callee-saved
  ## survivor when a later argument's shift/div would clobber it — decided by
  ## `fixedRegsClobberedByE` right here); aggregate args reserve their held
  ## scratches at the point of use; the result settles from rax/xmm0 into
  ## `dest`. `hiddenPtr` documents a >16B-result call whose rdi the caller
  ## pre-loaded; the plan derives the same fact from the callee's return type.
  ##
  ## `tail` marks a call in `(ret (call …))` position. Leng binds every call and
  ## forbids nesting them, so that shape is not an expression the backend gets to
  ## second-guess — it is the producer saying "tail-call this", and the legality
  ## question (nothing of ours may outlive the frame) was answered there. Here it
  ## means only: after the arguments are in place, undo the prologue and JUMP. The
  ## callee then returns to our caller with our return value already in rax/xmm0,
  ## so nothing is bound afterwards and nothing follows.
  ##
  ## `(popframe)` rather than an inline teardown because arkham does not know its
  ## own frame yet: `usedCallee`/`hasStackVars` are final only after the whole body
  ## is emitted. nifasm has assembled the prologue by the time it reaches the
  ## marker and can simply reverse it.
  g.bridgeStep("a call", bdTwoInRegs)
  discard hiddenPtr
  var argCurs: seq[Cursor] = @[]
  var fsym = ""
  var targetCur: Cursor
  var indirect = false
  block:
    var fc = c
    fc.into:
      targetCur = fc
      indirect = isIndirectCallTarget(g.typeCtx, fc)
      if not indirect: fsym = symName(fc)
      skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  var tgt: CallTarget
  var fnptrReg = NoReg
  var fnTargetName = ""
  var stagedFnptr = NoReg
  var fnptrLoc = dontCare                            # the held fn-ptr value (freed post-call)
  if indirect:
    let proctype = g.proctypeOfTarget(targetCur)
    let declarative = isDeclarativeAbi(g.prog, proctype)
    var retType = proctype
    block:
      var q = proctype
      q.into:
        skip q; skip q
        retType = q
        while q.hasMore: skip q
    fnptrLoc = needsReg(ScalarSlot)
    g.emitValue2(targetCur, fnptrLoc)              # fn-ptr target → a held register
    if fnptrLoc.kind == InReg:
      fnptrReg = fnptrLoc.r
    else:                                          # pool-dry etmp: staged reload
      assert fnptrLoc.kind == NamedStack, "arkham x64n: indirect call target loc " & $fnptrLoc.kind
      stagedFnptr = g.pickStagingSealed("an indirect call target", AddrSlot)
      g.emitLoadLoc(fnptrLoc, stagedFnptr)
      fnptrReg = stagedFnptr
    let foreignAbi = isForeignAbiProctype(g.prog, proctype)
    if targetCur.kind == Symbol and g.rb.boundName(fnptrReg) == symName(targetCur):
      tgt = CallTarget(declarative: declarative, asmName: symName(targetCur),
                       retType: retType, foreignAbi: foreignAbi)
    else:
      let nm = g.rb.freshTmpName("fntmp")
      g.ab.tree RebindX64:
        g.ab.symDef nm
        var pc = proctype
        g.genTypeBody(pc)
        g.ab.rawReg fnptrReg
      g.rb.bindScratch(fnptrReg, nm, isPtr = false)
      fnTargetName = nm
      tgt = CallTarget(declarative: declarative, asmName: nm, retType: retType,
                       foreignAbi: foreignAbi)
  else:
    if not g.callTarget.hasKey(fsym):
      let si = g.lookupSym(fsym)
      if si.cat in {scGlobal, scTvar}:
        var d = si.decl
        var proctype: Cursor
        d.into:
          inc d; skip d
          proctype = resolveType(g.prog, d)
          while d.hasMore: skip d
        g.callTarget[fsym] = CallTarget(declarative: isDeclarativeAbi(g.prog, proctype),
          indirect: true, asmName: fsym, retType: g.indirectRetType(si.decl),
          foreignAbi: isForeignAbiProctype(g.prog, proctype))
      else:
        g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    tgt = g.callTarget[fsym]
    if tgt.memIntrin.len > 0:                      # C mem* intrinsic → inline loop
      g.emitMemIntrin2(argCurs, tgt.memIntrin)     # (fused arg emission inside)
      g.settleResultReg(dest, RAX)
      return
    if tgt.bitBuiltin.len > 0:                     # GCC bit builtin → inline bsf/…
      g.emitBitBuiltin2(argCurs, tgt.bitBuiltin)
      g.settleResultReg(dest, RAX)
      return
  let isSyscall = tgt.syscall
  let hasResult = not retIsVoid(tgt.retType)
  let resSlot = if hasResult: slotOf(g.prog, tgt.retType) else: AsmSlot(cls: AInt, size: 8, align: 8)
  let resultIsFloat = hasResult and resSlot.kind == AFloat
  let resultByRef = hasResult and resSlot.kind == AMem and resSlot.size > g.md.aggrByRefThreshold
  var callArgSlots: seq[AsmSlot] = @[]
  for a in argCurs: callArgSlots.add g.exprSlot(a)
  # The CALLEE's argument convention. It is arkham's own (SysV) for everything arkham
  # generates, and the OS's for the one foreign boundary: a call out to an `importc`'d
  # Windows API. Only the argument REGISTERS differ — the temp / callee-saved pools
  # below stay `g.md`'s, because those describe this caller's own register file.
  let foreignCall = tgt.foreignAbi or (tgt.extern and g.prog.windows)
  let amd = if foreignCall: win64Machine else: g.md
  let plan = planCall(amd, callArgSlots, resultByRef)
  if foreignCall:
    # A Win64 call ALWAYS has an outgoing stack-argument area — the 32-byte shadow
    # space — even with no stack-passed argument, so the frame must carry the
    # `(ssize)` region nifasm reserved it in. (The stack-arg arms below set this too,
    # but only when an argument actually spills; four arguments or fewer would leave
    # the callee spilling its registers over this frame's return address.)
    g.plan.hasStackVars = true
  # A tail call is a DIRECTIVE, not a shape to be validated — whether anything of
  # ours may outlive the frame was decided by whoever wrote `(ret (call …))`. What
  # is checked here is only what arkham cannot MECHANICALLY do: an outgoing stack
  # argument is written at `[rsp, …]` that `(popframe)` moves rsp out from under; an
  # external target goes through the IAT/GOT and an indirect one through a register
  # `(popframe)` restores, so neither reaches a plain `jmp rel32`; a syscall is not a
  # branch at all; a >16B result travels through a hidden pointer that is not ours to
  # forward; and a Win64 call always owns a 32-byte shadow area in this frame.
  # Declining is silent and costs nothing — the call is emitted as an ordinary one.
  # (`tailCallEmitted` is cleared by the WRAPPER, not here: the mem-intrinsic and
  # bit-builtin paths above return early, and a stale `true` from an earlier call
  # would make `RetS` skip the epilogue jump.)
  var doTail = tail and not indirect and not tgt.extern and not tgt.syscall and
               not tgt.indirect and not resultByRef and not foreignCall
  if doTail:
    for pl in plan.args:
      if pl.onStack: doTail = false
  # Which ABI argument registers does a LATER argument overwrite by ISA fiat?
  var laterClob: seq[set[Reg]] = @[]
  block:
    var per: seq[set[Reg]] = @[]
    for a in argCurs: per.add g.fixedRegsClobberedByE(a)
    laterClob = newSeq[set[Reg]](per.len + 1)
    for i in countdown(per.len - 1, 0): laterClob[i] = laterClob[i+1] + per[i]
  var heldArgs: seq[Location] = @[]                # parked survivors, freed post-call

  proc settleCallResult(g: var CodeGen; dest: var Location) =
    ## Move the call result (rax / xmm0) into `dest`.
    if not hasResult: return
    if resultIsFloat:
      if dest.kind != InFReg:
        dest = g.takeFTmp(resSlot)                 # the float pool excludes xmm0
      if dest.kind == InFReg:
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
        if dest.f != FloatRet:
          g.fmovF(dest.f, FloatRet, (if dest.typ.size == 4: 32 else: 64))
      else:                                        # eftmp slot: store xmm0 straight
        g.emitStoreFLoc(dest, FloatRet, dest.typ.size * 8)
    elif resSlot.kind == AMem:
      discard                                      # aggregate result: consumed by the caller
    else:
      case dest.kind
      of Undef, NeedsReg, RegOrImm:
        dest = regLoc(RAX, resSlot, isTemp = true)
        if not g.rb.isBoundTemp(RAX): g.bindTemp(RAX, resSlot)
      of InReg:
        if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, resSlot)
        if dest.r != RAX: g.movReg(dest.r, RAX)
      of NamedStack, Mem:
        let bound = g.rb.isBoundTemp(RAX)
        if not bound: g.bindTemp(RAX, resSlot)
        g.emitStoreLoc(dest, RAX)
        if not bound: g.unbindTemp(RAX)
      else: raiseAssert "arkham x64n: call result dest " & $dest.kind

  if not tgt.declarative:
    # ── Manual-marshalling path (empty signature: float params/results, ≤16B
    # by-value aggregate results). Args go straight into raw ABI registers.
    var sealedArgs: set[Reg] = {}
    var pendingRestores: seq[tuple[dst, src: Reg]] = @[]
    if resultByRef: (g.rb.sealAccum amd.intArgRegs[0]; sealedArgs.incl amd.intArgRegs[0])
    for j in 0 ..< argCurs.len:
      let a = argCurs[j]
      let pl = plan.args[j]
      if pl.isAgg:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham x64: aggregate call-arg of non-nominal type"
        let tn = tcur.symId
        var exposed = false
        if not pl.onStack:
          for k in 0 ..< pl.words:
            if amd.gprAt(pl, k) in laterClob[j+1]: exposed = true
        var parked: seq[Reg] = @[]
        if exposed:
          for k in 0 ..< pl.words:
            let h = g.takeHeld("a clobber-exposed aggregate call argument")
            heldArgs.add h
            parked.add h.r
        var marshalRegs = @(amd.intArgRegs[pl.gpFirst ..< pl.gpFirst + pl.words])
        if parked.len > 0:
          marshalRegs = parked
          for k in 0 ..< pl.words:
            g.releaseStaleName(parked[k])
            pendingRestores.add (dst: amd.gprAt(pl, k), src: parked[k])
            g.rb.sealAccum parked[k]; sealedArgs.incl parked[k]
        if a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}:
          let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
          heldArgs.add addrHeld
          let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
          g.emitLvalue2(a)                         # pick embedded base/index regs
          let (srcAddr, spillAddr) = g.aggrArgAddr(a, recorded, marshalRegs)
          if not pl.byRef:
            g.marshalAggrFromAddr(srcAddr, tn, marshalRegs)
          else:
            g.movReg(marshalRegs[0], srcAddr)
          if spillAddr: g.giveBack srcAddr else: g.unbindTemp srcAddr
          g.freeLvalTemps2(a)
        else:
          var home = ""
          var ptrReg = NoReg
          if a.kind == Symbol:
            let sloc = g.plan.locationOfSym(symName(a), cursorToPosition(g.buf[], a))
            if sloc.kind in {NamedStack, StackPtr}: home = symName(a)  # readers re-ask the home
            elif sloc.kind == InRegPair: home = symName(a)
            elif sloc.kind == InReg: ptrReg = sloc.r
            elif g.lookupSym(symName(a)).cat == scGlobal: discard
            else:
              raiseAssert "arkham x64: aggregate symbol arg neither local nor global: " & symName(a)
          else:
            let pos = cursorToPosition(g.buf[], a)
            home = synth("aggtmp") & $pos & ".0"
            g.emTypedStackVar(home, tcur)
            g.varType[home] = tn
            g.genStore2(a, namedStackLoc(home, g.exprSlot(a)))
          if not pl.byRef:
            if ptrReg != NoReg: g.marshalAggrFromAddr(ptrReg, tn, marshalRegs)
            elif home.len > 0: g.structToRegs(home, tn, marshalRegs)
            else: g.globalToRegs(symName(a), tn, marshalRegs)
          else:
            if ptrReg != NoReg: g.movReg(marshalRegs[0], ptrReg)
            elif home.len > 0: g.emStackAddr(marshalRegs[0], home)
            else: g.emGlobalAddr(marshalRegs[0], symName(a))
      elif g.isFloatExpr(a):
        # The argument's OWN float width, not a fixed 8 — the twin of the same
        # fix on a64, which this side never got. SysV passes a `float` in the
        # low half of an xmm and a `double` in the whole register, so the move
        # is right either way and the hardcoded 8 looked harmless; but
        # `emitFValue2` picks a LITERAL's bit pattern from the destination
        # slot's width, so a `float32` literal was materialized as the DOUBLE
        # pattern, whose low 32 bits — the half the callee reads — are zero for
        # every value with an empty mantissa tail.
        #
        # A variadic float argument reaches here already promoted to double by
        # the front end, so its `exprSlot` is `(f 64)` and this keeps passing it
        # full-width.
        var fSlot = g.exprSlot(a)
        if fSlot.kind != AFloat:
          fSlot = AsmSlot(cls: AFloat, size: 8, align: 8)
        var fD = fregLoc(amd.floatArgRegs[pl.fpIndex], fSlot)
        g.emitFValue2(a, fD)                       # → its xmm arg register
      else:
        let abiReg = amd.gprAt(pl)
        g.releaseArgDest(abiReg, (if a.kind == Symbol: symName(a) else: ""))
        var aD = regLoc(abiReg, ScalarSlot)
        g.emitValue2(a, aD)                        # → its GPR arg register
      if not pl.isFloat and not pl.onStack:
        for k in 0 ..< pl.words:
          g.rb.sealAccum amd.gprAt(pl, k); sealedArgs.incl amd.gprAt(pl, k)
    for pr in pendingRestores:                     # parked words → their raw ABI registers
      g.releaseStaleName(pr.dst)
      g.movReg(pr.dst, pr.src)
    g.ab.tree PrepareX64:
      g.ab.sym tgt.asmName
      if isSyscall: g.emSyscall()
      elif tgt.extern: g.ab.keyword ExtcallX64   # dynamic import → indirect via the IAT/GOT
      elif doTail:
        # The arguments are in their ABI registers; from here nothing of ours is
        # live, so undo the prologue and branch. `(popframe)` is inside the prepare
        # block on purpose: it must follow the last argument store and precede the
        # jump, and it touches only rsp and callee-saved registers — never the
        # argument registers the arguments now sit in.
        g.ab.keyword PopframeX64
        g.ab.keyword TailcallX64
        g.tailCallEmitted = true
      else: g.ab.keyword CallX64
    g.flushArgResidentParams()
    g.rb.unsealAccums(sealedArgs)
    if fnTargetName.len > 0:
      g.ab.tree KillX64: g.ab.sym fnTargetName
      discard g.rb.takeBinding(fnptrReg)
    if stagedFnptr != NoReg: g.giveBack stagedFnptr
    g.freeVal(fnptrLoc)
    for h in heldArgs: g.freeVal(h)
    if not doTail: g.settleCallResult(dest)
    return
  # ── the unified declarative path: every argument binds via `(arg pN [k])`.
  var sealedArgs: set[Reg] = {}
  var pendingArgBinds: seq[tuple[nameIdx: int, src: Reg, wordIdx: int]] = @[]
  var pendingSpillArgs: seq[tuple[nameIdx: int, slot: Location]] = @[]
  g.ab.tree PrepareX64:
    g.ab.sym tgt.asmName
    if resultByRef:
      g.ab.tree MovX64:
        g.ab.tree ArgX: g.ab.sym paramName(0)
        g.emReg amd.intArgRegs[0]
      g.rb.sealAccum amd.intArgRegs[0]; sealedArgs.incl amd.intArgRegs[0]
    for j in 0 ..< argCurs.len:
      let a = argCurs[j]
      let pl = plan.args[j]
      let nameIdx = pl.ord
      if pl.isAgg:
        let tcur = g.getType(a)
        if tcur.kind != Symbol:
          raiseAssert "arkham x64: aggregate call-arg of non-nominal type"
        let tn = tcur.symId
        let byRef = pl.byRef
        let gprWords = pl.words
        let fits = not pl.onStack
        let isLval = a.kind == TagLit and a.exprKind in {DotC, DerefC, AtC, PatC}
        var exposed = false
        if fits:
          for k in 0 ..< gprWords:
            if amd.gprAt(pl, k) in laterClob[j+1]: exposed = true
        var parked: seq[Reg] = @[]
        if exposed:
          for k in 0 ..< gprWords:
            let h = g.takeHeld("a clobber-exposed aggregate call argument")
            heldArgs.add h
            parked.add h.r
        var dst: seq[Reg] = @[]
        if fits:
          if parked.len > 0:
            for r in parked:
              g.releaseStaleName(r)
              dst.add r
          else:
            let aSym = if a.kind == Symbol: symName(a) else: ""
            for k in 0 ..< gprWords:
              let r = amd.gprAt(pl, k)
              g.releaseArgDest(r, aSym)
              dst.add r
        if not fits:
          g.plan.hasStackVars = true           # outgoing stack-arg area ⇒ frame sub
          var srcAddr = NoReg
          var srcSpilled = false
          var srcOwned = true
          if isLval:
            let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
            heldArgs.add addrHeld
            let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
            g.emitLvalue2(a)
            (srcAddr, srcSpilled) = g.aggrArgAddr(a, recorded, [])
          else:
            let (home, ptrReg, isTvar) = g.aggrArgSource(a, tcur, tn)
            if ptrReg != NoReg:
              srcAddr = ptrReg; srcOwned = false
            else:
              srcAddr = g.pickStagingSealed("a stack aggregate-arg address", AddrSlot)
              srcSpilled = true
              if home.len > 0: g.emAggrHomeAddr(srcAddr, home)
              elif isTvar: g.emTvarAddr(srcAddr, symName(a))
              else: g.emGlobalAddr(srcAddr, symName(a))
          template outgoingSlot(k: int; indexed: bool) =
            g.ab.tree MemX:
              g.ab.rawReg RSP
              g.ab.tree ArgX:
                g.ab.sym paramName(nameIdx)
                if indexed: g.ab.intLit k.int64
          if byRef:
            g.ab.tree MovX64: (outgoingSlot(0, false); g.emReg srcAddr)
          else:
            for k in 0 ..< gprWords:
              let w = g.pickStagingSealed("a stack aggregate-arg word", AddrSlot)
              g.ab.tree MovX64: (g.emReg w; g.emWordThroughPtr(srcAddr, k))
              g.ab.tree MovX64: (outgoingSlot(k, true); g.emReg w)
              g.giveBack w
          if srcOwned:
            if srcSpilled: g.giveBack srcAddr else: g.unbindTemp srcAddr
          if isLval: g.freeLvalTemps2(a)
        elif isLval:
          let addrHeld = g.takeHeld("an aggregate-arg address", canSpill = true)
          heldArgs.add addrHeld
          let recorded = (if addrHeld.kind == InReg: addrHeld.r else: NoReg)
          g.emitLvalue2(a)
          let (srcAddr, spillAddr) = g.aggrArgAddr(a, recorded, dst)
          if byRef: g.movReg(dst[0], srcAddr)
          else: g.marshalAggrFromAddr(srcAddr, tn, dst)
          if spillAddr: g.giveBack srcAddr else: g.unbindTemp srcAddr
          g.freeLvalTemps2(a)
        else:
          let (home, ptrReg, isTvar) = g.aggrArgSource(a, tcur, tn)
          if byRef:
            if ptrReg != NoReg: g.movReg(dst[0], ptrReg)
            elif home.len > 0: g.emAggrHomeAddr(dst[0], home)
            elif isTvar: g.emTvarAddr(dst[0], symName(a))
            else: g.emGlobalAddr(dst[0], symName(a))
          else:
            if ptrReg != NoReg: g.marshalAggrFromAddr(ptrReg, tn, dst)
            elif home.len > 0: g.structToRegs(home, tn, dst)
            elif isTvar: g.tvarToRegs(symName(a), tn, dst)
            else: g.globalToRegs(symName(a), tn, dst)
        if fits:
          if parked.len > 0:
            for k in 0 ..< gprWords:
              pendingArgBinds.add (nameIdx: nameIdx, src: dst[k],
                                   wordIdx: (if byRef: -1 else: k))
              g.rb.sealAccum dst[k]; sealedArgs.incl dst[k]
          else:
            for k in 0 ..< gprWords:
              g.ab.tree MovX64:
                g.ab.tree ArgX:
                  g.ab.sym paramName(nameIdx)
                  if not byRef: g.ab.intLit k.int64
                g.emReg dst[k]
      elif g.isFloatExpr(a):
        var fD = fregLoc(amd.floatArgRegs[pl.fpIndex],
                         AsmSlot(cls: AFloat, size: 8, align: 8))
        g.emitFValue2(a, fD)
        g.ab.tree MovX64:
          g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
          g.emFReg fD.f
      else:
        # Scalar arg. Clobber-exposed → compute into a parked survivor and bind
        # at the end; else straight into the ABI register.
        var aD: Location
        var parkSpilled = false
        if not pl.onStack and amd.gprAt(pl) in laterClob[j+1]:
          let hr = g.pickHeldReg()
          if hr != NoReg:
            g.pickedRegs.incl hr
            aD = regLoc(hr, ScalarSlot, isTemp = true)
          else:
            # No survivor free. A bound POOL temp parks just as safely: the
            # later-arg clobbers are the FIXED cl/rdx only, and every later
            # pick avoids bound temps. Both pools dry → produce into a minted
            # slot and reload at the bind-flush point (memory survives all).
            aD = g.takeTmp(ScalarSlot)
          heldArgs.add aD
          g.emitValue2(a, aD)
          if aD.kind != InReg:
            pendingSpillArgs.add (nameIdx: nameIdx, slot: aD)
            parkSpilled = true
        elif not pl.onStack:
          let abiReg = amd.gprAt(pl)
          g.releaseArgDest(abiReg, (if a.kind == Symbol: symName(a) else: ""))
          aD = regLoc(abiReg, ScalarSlot)
          g.emitValue2(a, aD)
        else:
          aD = needsReg(ScalarSlot)
          g.emitValue2(a, aD)                      # 7th+ arg: any register
        if not parkSpilled:
          var srcReg = NoReg
          var ownSrc = false
          if aD.kind == InReg:
            srcReg = aD.r
          else:                                    # pool-dry etmp: staged reload
            srcReg = g.pickStaging("a spilled call-arg reload")
            g.bindTemp(srcReg, ScalarSlot)
            g.emitLoadLoc(aD, srcReg)
            ownSrc = true
          if not pl.onStack:
            if not ownSrc and srcReg != amd.gprAt(pl):
              pendingArgBinds.add (nameIdx: nameIdx, src: srcReg, wordIdx: -1)
              g.rb.sealAccum srcReg; sealedArgs.incl srcReg
            else:
              g.ab.tree MovX64:
                g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
                g.emReg srcReg
          else:
            g.plan.hasStackVars = true         # outgoing stack-arg area ⇒ frame sub
            g.ab.tree MovX64:
              g.ab.tree MemX:
                g.ab.rawReg RSP
                g.ab.tree ArgX: g.ab.sym paramName(nameIdx)
              g.emReg srcReg
            if not ownSrc: g.freeVal(aD)           # the stack-arg temp dies with its store
          if ownSrc: g.giveBack srcReg
      if not pl.isFloat and not pl.onStack:
        for k in 0 ..< pl.words:
          g.rb.sealAccum amd.gprAt(pl, k); sealedArgs.incl amd.gprAt(pl, k)
    for ps in pendingSpillArgs:
      # A clobber-exposed arg that had to park in a minted slot: reload through
      # staging and bind now, after every clobbering computation ran.
      let s = g.pickStaging("a parked call-arg reload")
      g.bindTemp(s, ScalarSlot)
      g.emitLoadLoc(ps.slot, s)
      g.ab.tree MovX64:
        g.ab.tree ArgX: g.ab.sym paramName(ps.nameIdx)
        g.emReg s
      g.giveBack s
    for pb in pendingArgBinds:
      g.ab.tree MovX64:
        g.ab.tree ArgX:
          g.ab.sym paramName(pb.nameIdx)
          if pb.wordIdx >= 0: g.ab.intLit pb.wordIdx.int64
        g.emReg pb.src
    if isSyscall: g.emSyscall()
    elif tgt.extern: g.ab.keyword ExtcallX64     # dynamic import → indirect via the IAT/GOT
    elif doTail:
      g.ab.keyword PopframeX64                   # see the manual path above
      g.ab.keyword TailcallX64
      g.tailCallEmitted = true
    else: g.ab.keyword CallX64
    g.flushArgResidentParams()
    if not doTail and hasResult and not resultByRef and not resultIsFloat and
       resSlot.kind != AMem:
      g.ab.tree MovX64:
        g.emReg RAX
        g.ab.tree ResX: g.ab.sym synth("ret.0")
  g.rb.unsealAccums(sealedArgs)
  if fnTargetName.len > 0:
    g.ab.tree KillX64: g.ab.sym fnTargetName
    discard g.rb.takeBinding(fnptrReg)
  if stagedFnptr != NoReg: g.giveBack stagedFnptr
  g.freeVal(fnptrLoc)
  for h in heldArgs: g.freeVal(h)
  if not doTail: g.settleCallResult(dest)

when defined(arkhamCallerSaveDbg):
  proc csDbgCall(g: var CodeGen; c: Cursor;
                 saveSet, nested: seq[tuple[reg: Reg, name: string]]) =
    ## One `CSCALL` line per emitted call: WHERE the emitter actually saves, in the
    ## same token-position space the analyser measures intervals in. Joined against
    ## the `CSVAR` lines by `scratchpad/csdiff.py`; a call inside a value's interval
    ## with the value in neither `saved` nor `nested` is a save the emitter owed and
    ## did not make. `unbound` is the interesting residue: the allocator thinks the
    ## value is live here, the emitter holds no binding for it.
    var saved, nest, unbound = ""
    var seen = initHashSet[string]()
    for it in saveSet: (seen.incl it.name; (if saved.len > 0: saved.add ','); saved.add it.name)
    for it in nested: (seen.incl it.name; (if nest.len > 0: nest.add ','); nest.add it.name)
    for name in g.plan.callerSaveHomes.keys:
      if name notin seen:
        if unbound.len > 0: unbound.add ','
        unbound.add name
    stderr.write "CSCALL proc=" & gArkhamCurProc & " pos=" &
      $cursorToPosition(g.buf[], c) & " saved=" & saved & " nested=" & nest &
      " unbound=" & unbound & "\n"

proc emitCall2*(g: var CodeGen; c: Cursor; dest: var Location; hiddenPtr = false;
               tail = false) =
  ## Caller-save wrapper: every caller-saved local bound right now is stored before
  ## this call's ABI marshalling clobbers its volatile home, and reloaded after the
  ## call returns. Between the two, `plan.callerSaveActive` redirects every read of
  ## those names to the save slot — so an argument whose source is one of them is
  ## marshalled from memory instead of from a register that marshalling itself is
  ## about to overwrite. That is what keeps `design.md`'s partition intact without a
  ## parallel-copy analysis. No caller-saved vars bound ⇒ not one extra instruction.
  ##
  ## A caller that writes an ABI register for THIS call before getting here (the
  ## hidden result pointer in rdi) must open the window itself — see
  ## `emCallerSaveOpen`; this one then finds everything already active and adds
  ## nothing.
  when defined(arkhamCallerSaveDbg):
    if g.plan.callerSaveHomes.len > 0:
      var bound, act: seq[tuple[reg: Reg, name: string]] = @[]
      # `active` comes from the redirect table, NOT from the bindings: a window opened
      # early (the hidden-result-pointer sites) has already released the binding, so
      # the value is covered yet invisible to `callerSaveSetAt`.
      for name in g.plan.callerSaveActive.keys: act.add (reg: NoReg, name: name)
      for it in g.callerSaveSetAt():
        if not g.plan.callerSaveActive.hasKey(it.name): bound.add it
      g.csDbgCall(c, bound, act)
  # A DIVERGING call executes only on a path that never rejoins, so at the statement
  # after it every register still holds exactly what it held before — the marshalling
  # simply did not run. `rb` cannot express that: it is linear, and the `(kill nm)`s
  # `releaseArgDest` must emit (nifasm rejects a raw write to a bound register) erase
  # the names for the rest of the proc. Every later read of a still-live local then
  # falls back to a raw `(reg)` that no checker can see — ~96 operands per nifbench
  # build, and the reason `AllRegs`/`DivRegOk` had to be conservative around panics.
  #
  # So snapshot the bindings, and re-establish whatever the call dropped.
  # Every store-forwarding mirror dies at a call, and it dies BEFORE the
  # marshalling: the callee clobbers the volatiles a mirror lives in, and — for a
  # value whose address escaped — could write the slot itself. (Address-taken
  # locals are never mirrored, so only the clobber is load-bearing; clearing the
  # whole map anyway costs a call-free straight-line region nothing and removes
  # the callee-saved case from the argument.)
  g.killAllMirrors()
  g.tailCallEmitted = false               # every early return in `Inner` leaves it clear
  # A TAIL call diverges in exactly the same way, and for the same reason wants the
  # same treatment: control never comes back, so at whatever statement follows in the
  # emission order — the other arm of the `if` this `return f(x)` sat in — every
  # register still holds what it held before, and the names must still be there.
  let diverging = g.isDivergingCall(c) or tail
  var savedBinds: seq[tuple[r: Reg, name: string]] = @[]
  if diverging: savedBinds = g.namedBindings()
  let w = g.emCallerSaveOpen()
  g.emitCall2Inner(c, dest, hiddenPtr, tail)
  if g.tailCallEmitted:
    # The window still OPENED: the marshalling reads a caller-saved local through
    # `plan.callerSaveActive`, which only redirects while the window is open, and
    # the store is what makes that redirect true. It must not CLOSE as code — the
    # reloads would land after the `jmp`, unreachable, addressing slots `(popframe)`
    # has just given back. Only the redirect map is rolled back, and the bindings
    # are re-established by `restoreBindings`, which is naming, not machine code.
    g.plan.callerSaveActive = w.prevActive
    g.restoreBindings(savedBinds)
  else:
    g.emCallerSaveClose(w, dest)
    if diverging: g.restoreBindings(savedBinds)

when declared(FldrqOp):
  # The SSE lowering of the vectorizer's 128-bit rows (`lib/intrinsics`,
  # `shoggoth/vectorizer.nim`). Same rows as the AArch64 back end, but SSE is a
  # TWO-ADDRESS ISA: `addpd D, S` computes `D = D + S`, so where AdvSIMD reads
  # three registers and writes a fourth, every non-destructive op here needs a
  # 128-bit register-register copy first. That copy is what `vecMove` is; the
  # a64 path deliberately has none.
  const VecOps = {FldrqOp, FstrqOp, VfaddOp, VfsubOp, VfmulOp, VfmlaOp, VdupOp,
                  VaddvOp}

  template Vec128Slot(): AsmSlot = AsmSlot(cls: AFloat, size: 16, align: 16)

  proc vecHomeF(g: var CodeGen; a: Cursor): FReg =
    ## A 128-bit vector operand: the vectorizer spells every one as a plain local,
    ## and a local of type `(f 128)` lives in an xmm register or fails loudly at
    ## its declaration, so the home lookup here cannot miss.
    if a.kind != Symbol:
      lengError a, "a 128-bit vector operand must be a plain local"
    let home = g.plan.locationOfSym(symName(a), cursorToPosition(g.buf[], a))
    if home.kind != InFReg:
      lengError a, "128-bit vector local `" & symName(a) &
                "` has no SIMD register home"
    result = home.f

  proc vecLaneBits(g: var CodeGen; a: Cursor): int =
    ## The trailing lane-width knob: an int LITERAL, read here and folded into the
    ## chosen opcode — never evaluated into a register.
    if a.kind != IntLit or int(intVal(a)) notin {32, 64}:
      lengError a, "a vector op's lane-bits operand must be the literal 32 or 64"
    result = int(intVal(a))

  proc vecByteOff(g: var CodeGen; a: Cursor): int =
    ## A vector load/store's byte-offset operand: an int literal, multiple of 16.
    if a.kind != IntLit or (int(intVal(a)) and 15) != 0 or intVal(a) < 0:
      lengError a, "a vector load/store offset must be a non-negative literal multiple of 16"
    result = int(intVal(a))

  proc vecTakeDest(g: var CodeGen; c: Cursor; dest: var Location; slot: AsmSlot) =
    ## Resolve `dest` to an xmm register, minting a pool temp when the caller had
    ## no home for it.
    if dest.kind != InFReg:
      dest = g.takeFTmp(slot)
      if dest.kind == NamedStack:
        lengError c, "out of SIMD registers for a 128-bit vector value"
    if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)

  proc vecMove(g: var CodeGen; dst, src: FReg) =
    ## 128-bit register-register copy, elided when the registers coincide.
    if dst != src:
      g.ab.tree MovupsX64:
        g.emFReg dst
        g.emFReg src

  proc vecShuf(g: var CodeGen; d: FReg; imm: int) =
    g.ab.tree ShufpsX64:
      g.emFReg d
      g.emFReg d
      g.ab.intLit imm

  proc emitVecInstr2(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                     argCurs: seq[Cursor]; dest: var Location) =
    case op
    of FstrqOp:
      # (instr fstrq p off v) — statement position, no result.
      let off = g.vecByteOff(argCurs[1])
      let vf = g.vecHomeF(argCurs[2])
      var pd = g.takeInstrReg(g.exprSlot(argCurs[0]))
      g.emitValue2(argCurs[0], pd)
      g.ab.tree MovupsX64:
        g.ab.tree MemX:
          g.emReg pd.r
          if off != 0: g.ab.intLit off
        g.emFReg vf
      g.freeVal(pd)
    of FldrqOp:
      let off = g.vecByteOff(argCurs[1])
      var pd = g.takeInstrReg(g.exprSlot(argCurs[0]))
      g.emitValue2(argCurs[0], pd)
      g.vecTakeDest(c, dest, Vec128Slot)
      g.ab.tree MovupsX64:
        g.emFReg dest.f
        g.ab.tree MemX:
          g.emReg pd.r
          if off != 0: g.ab.intLit off
      g.freeVal(pd)
    of VdupOp:
      # Scalar into lane 0, then splat. `punpcklqdq X, X` = [X.lo, X.lo] for
      # doubles; `shufps X, X, 0` picks lane 0 four times for singles.
      let bits = g.vecLaneBits(argCurs[1])
      var fv = dontCare
      g.emitFValue2(argCurs[0], fv)
      g.vecTakeDest(c, dest, Vec128Slot)
      # `dontCare` always resolves to an xmm on this target (the x64 float path
      # has no eftmp fallback the way AArch64's does), so there is no bridge.
      if fv.kind != InFReg:
        lengError c, "a vdup scalar operand must resolve to a SIMD register"
      let srcF = fv.f
      if srcF != dest.f:
        g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
          g.emFReg dest.f
          g.emFReg srcF
      if bits == 64:
        g.ab.tree PunpcklqdqX64:
          g.emFReg dest.f
          g.emFReg dest.f
      else:
        g.vecShuf(dest.f, 0)
      if fv.isTemp and fv.f != dest.f: g.unbindFTmp(fv.f)
    of VaddvOp:
      # Horizontal add — the reduction epilogue. The result is an ORDINARY scalar
      # float, so it composes with the surrounding scalar expression tree.
      # f64: dest = [v.hi, v.hi]; dest.lo += v.lo.
      # f32: fold [a b c d] -> [a+c b+d ..] -> (a+c)+(b+d), which needs one
      # scratch for the final lane-1 pick.
      let bits = g.vecLaneBits(argCurs[1])
      let srcF = g.vecHomeF(argCurs[0])
      g.vecTakeDest(c, dest, AsmSlot(cls: AFloat, size: bits div 8, align: bits div 8))
      if bits == 64:
        g.vecMove(dest.f, srcF)
        # `shufps X, X, 0xEE` selects 32-bit lanes 2,3,2,3 — i.e. it duplicates
        # the HIGH 8 bytes down into the low half, which is `punpckhqdq X, X`
        # bit for bit. Spelled with `shufps` so the lowering needs one packed
        # shuffle mnemonic rather than two; `punpckhqdq` would buy nothing.
        g.vecShuf(dest.f, 0xEE)
        g.ab.tree AddsdX64:
          g.emFReg dest.f
          g.emFReg srcF
      else:
        g.vecMove(dest.f, srcF)
        g.vecShuf(dest.f, 0xEE)                    # [c d c d]
        g.ab.tree AddpsX64:
          g.emFReg dest.f
          g.emFReg srcF                            # [a+c b+d ..]
        var tmp = g.takeFTmp(Vec128Slot)
        if tmp.kind == NamedStack:
          lengError c, "out of SIMD registers for a vaddv result"
        if tmp.isTemp and not g.rb.isBoundFTmp(tmp.f): g.bindFTmp(tmp.f)
        g.vecMove(tmp.f, dest.f)
        g.vecShuf(tmp.f, 0x55)                     # lane 1 -> lane 0
        g.ab.tree AddssX64:
          g.emFReg dest.f
          g.emFReg tmp.f
        if tmp.isTemp: g.unbindFTmp(tmp.f)
        g.freeVal(tmp)
    of VfmlaOp:
      # acc += a*b. SSE has no FMA (that is AVX2/FMA3), so this is a multiply
      # into a scratch followed by an add — TWO roundings where AArch64's `fmla`
      # has one. The vectorizer already documents that its lane split reorders a
      # float sum; this is a second, smaller deviation on this target only.
      let bits = g.vecLaneBits(argCurs[3])
      let accF = g.vecHomeF(argCurs[0])
      if dest.kind != InFReg or dest.f != accF:
        lengError c, "vfmla accumulates in place: spell it `acc = vfmla(acc, a, b, bits)`"
      let aF = g.vecHomeF(argCurs[1])
      let bF = g.vecHomeF(argCurs[2])
      var tmp = g.takeFTmp(Vec128Slot)
      if tmp.kind == NamedStack:
        lengError c, "out of SIMD registers for a vfmla product"
      if tmp.isTemp and not g.rb.isBoundFTmp(tmp.f): g.bindFTmp(tmp.f)
      g.vecMove(tmp.f, aF)
      g.ab.tree (if bits == 32: MulpsX64 else: MulpdX64):
        g.emFReg tmp.f
        g.emFReg bF
      g.ab.tree (if bits == 32: AddpsX64 else: AddpdX64):
        g.emFReg accF
        g.emFReg tmp.f
      if tmp.isTemp: g.unbindFTmp(tmp.f)
      g.freeVal(tmp)
    of VfaddOp, VfsubOp, VfmulOp:
      let bits = g.vecLaneBits(argCurs[2])
      let aF = g.vecHomeF(argCurs[0])
      let bF = g.vecHomeF(argCurs[1])
      g.vecTakeDest(c, dest, Vec128Slot)
      let tag = case op
                of VfaddOp: (if bits == 32: AddpsX64 else: AddpdX64)
                of VfsubOp: (if bits == 32: SubpsX64 else: SubpdX64)
                else: (if bits == 32: MulpsX64 else: MulpdX64)
      if dest.f == bF and aF != bF:
        if op == VfsubOp:
          # `subp[sd]` is not commutative, so a destination already holding B
          # cannot absorb the operation: compute `A - B` in a scratch and move
          # it over. The two commutative rows below need neither.
          var tmp = g.takeFTmp(Vec128Slot)
          if tmp.kind == NamedStack:
            lengError c, "out of SIMD registers for a vfsub operand"
          if tmp.isTemp and not g.rb.isBoundFTmp(tmp.f): g.bindFTmp(tmp.f)
          g.vecMove(tmp.f, aF)
          g.ab.tree tag:
            g.emFReg tmp.f
            g.emFReg bF
          g.vecMove(dest.f, tmp.f)
          if tmp.isTemp: g.unbindFTmp(tmp.f)
          g.freeVal(tmp)
        else:
          # Commutative, so a destination that already holds B needs no
          # scratch: `D = D op A` is the same value.
          g.ab.tree tag:
            g.emFReg dest.f
            g.emFReg aF
      else:
        g.vecMove(dest.f, aF)
        g.ab.tree tag:
          g.emFReg dest.f
          g.emFReg bF
    else:
      lengError c, "not a vector row"

proc emitInstr2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED `(instr SYM X*)`: allocInstr's operand/result placement decided
  ## inline; each evaluated operand's resolved Location is written to the
  ## `plan.locs` memo so the shared transliteration bodies (`emitAtomicInstr2`,
  ## `emitInoutInstr2`, `instrOperandReg`) read them unchanged.
  ##
  ## An intrinsic row may write memory (the atomics), claim fixed registers of its
  ## own (`atomicRegClaims`) and run a retry loop — none of which the mirror map
  ## models. It clears, like a call.
  g.killAllMirrors()
  var fsym = ""
  var argCurs: seq[Cursor] = @[]
  block:
    var fc = c
    fc.into:
      fsym = symName(fc); skip fc
      while fc.hasMore: (argCurs.add fc; skip fc)
  let tgt = instrTargetOf(g.prog, fsym)
  let row = IntrinsicRows[tgt.op]
  if tgX64 notin row.targets:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` has no x86-64 lowering — " &
              "guard the call with a `when`"
  when declared(VecOps):
    if tgt.op in VecOps:
      g.emitVecInstr2(c, tgt.op, argCurs, dest)
      return
  if row.isFlagRead or row.isFlagWrite:
    lengError c, "`" & IntrinsicNames[tgt.op] & "` is a flag instruction; flags " &
              "are only legal inside an `{.assembler.}` proc, where no " &
              "instruction may be inserted between one and its use",
              lengInfo(c)
  if row.inoutOperand >= 0:
    # Two-address row: the destination operand IS its home; sources are
    # immediates (per the row) or registers.
    var ops: seq[Location] = @[]
    var i = 0
    for a in argCurs:
      if i != row.inoutOperand:
        var d = regOrImm(ScalarSlot)
        g.emitValue2(a, d)
        g.plan.planAtEmitTime(cursorToPosition(g.buf[], a), d)
        ops.add d
      inc i
    g.emitInoutInstr2(c, tgt.op, argCurs)
    for d in ops:
      if d.kind == InReg: g.giveBack d.r
    dest = Location(kind: Undef)                # no value: nothing consumes this node
    return
  if row.isNullaryVoid:
    # Nothing to place, nothing to bind, nothing to give back. Taken before the
    # seal/pick machinery below for the same reason `isMachineQuery` is: that
    # machinery is written around `argCurs[0]` existing, and here there is no
    # operand at all. `dest` stays `Undef` — the node yields no value, so nothing
    # downstream consumes it.
    g.emitNullaryIntrinsicX64(tgt.op)
    dest = Location(kind: Undef)
    return
  if tgt.op.isMachineQuery:
    # No operands to place and no flags to preserve: the whole node is "put this
    # machine fact in a register". Taken before the seal/pick machinery below
    # because that machinery is written around `argCurs[0]` existing.
    case dest.kind
    of NeedsReg, RegOrImm: dest = g.takeInstrReg(dest.typ)
    of Undef: dest = g.takeInstrReg(ScalarSlot)
    else: discard
    if dest.kind != InReg:
      raiseAssert "arkham x64n: intrinsic result is not in a register"
    if dest.isTemp and not g.rb.isBoundTemp(dest.r): g.bindTemp(dest.r, dest.typ)
    g.emitIntrinsicOps(tgt.op, tgt.argBits, dest.r, dest.r, 0)
    return
  # Seal what the LOWERING claims, before anything is picked. `takeInstrReg`'s
  # staging fallback draws from `StagingCandidates`, and RAX sits second there — so
  # starve the pools and a compare-exchange's `desired` lands in RAX, the
  # `mov rax, *expected` emitted between them destroys it, and the CAS compares the
  # cell against ITSELF: it reports success and stores the old value back. RDX
  # (idiv) and RCX (shift count) are fixed roles in `MachineDesc`; RAX's atomic role
  # has no such home, so it is stated here. A non-atomic row claims only the R11
  # bridge, as before.
  let claims = if tgt.op.isAtomic: atomicRegClaims(tgt.op) else: {R11}
  let sealedClaims = claims - g.plan.sealed
  g.plan.seal sealedClaims
  # Resolve the result and seal it too, so an operand pick cannot land on it.
  var res = Location(kind: Undef)
  if not row.isVoidResult:
    case dest.kind
    of NeedsReg, RegOrImm: dest = g.takeInstrReg(dest.typ)
    of Undef: dest = g.takeInstrReg(ScalarSlot)
    else: discard
    res = dest
  let sealedHere = res.kind == InReg and not res.isTemp and not g.plan.isSealed(res.r)
  if sealedHere: g.plan.seal {res.r}
  # What the row's own lowering writes, and which an operand may therefore not be
  # read out of. The seals above already keep the PICKS off these; this set is for
  # `instrOperandInPlace`, which does not pick at all.
  var written = claims
  if res.kind == InReg: written.incl res.r
  var ops: seq[Location] = @[]
  let inPlace = inPlaceIntrinsicX64(tgt.op)
  block:
    var i = 0
    for a in argCurs:
      if i >= row.evaluatedOperands: break      # trailing memory-order knobs: never evaluated
      var d =
        if (row.tie >= 0 and i != row.tie) or atomicValueMayBeImmE(tgt.op, i):
          regOrImm(g.exprSlot(a))
        else:
          g.instrOperandInPlace(a, written)
      if d.kind == Undef:
        # An in-place row `mov`s operand 0 INTO the result register below, so the
        # two bindings have to agree on type. Taking the operand at the
        # expression's own slot types a bare literal `(i 64)`, and `bswap`'s
        # `(mov `x.8 `tmp33.0)` into a `(u 32)` local is a mismatch nifasm rejects.
        let slot = if i == 0 and inPlace and res.kind == InReg: res.typ
                   else: g.exprSlot(a)
        d = g.takeInstrReg(slot)
      g.emitValue2(a, d)
      g.plan.planAtEmitTime(cursorToPosition(g.buf[], a), d)
      ops.add d
      inc i
  if sealedHere: g.plan.unseal {res.r}
  g.plan.unseal sealedClaims
  if tgt.op.isAtomic:
    g.emitAtomicInstr2(c, tgt.op, argCurs, res)
    for d in ops:
      if d.kind == InReg and d.isTemp and not (res.kind == InReg and d.r == res.r):
        g.giveBack d.r
    return
  if tgt.op.isVolatile:
    # ONE access, at exactly the pointee's width. `emMemAt` is the same typed
    # deref the atomics use, and for the same reason: an untyped `(mem p)` is a
    # 64-bit access, so a sub-word device register would be read or written eight
    # bytes wide.
    #
    # The POINTER decides the width, not the value or the result — those agree
    # whenever the source came through `volatileStore[T](dest: ptr T; val: T)`,
    # and where they do not the pointer is still the operand that cannot be wrong
    # about the cell it addresses.
    var ptrTyp = g.prog.resolveType(g.getType(argCurs[0]))
    let cellTyp =
      if ptrTyp.kind == TagLit and ptrTyp.typeKind in {LengType.PtrT, LengType.AptrT}:
        g.prog.innerType(ptrTyp)
      elif tgt.op == VolatileLoadOp: g.getType(c)
      else: g.getType(argCurs[1])
    let cell = slotOf(g.prog, cellTyp)
    if cell.kind == AMem or cell.kind == AFloat or cell.size > wordSize() or
       cell.size notin {1, 2, 4, 8}:
      lengError c, "a volatile access must be ONE machine access, and a " &
                $cell.size & "-byte cell is not one on this target — no " &
                "widening, no splitting into halves, because for a device " &
                "register the difference is what the device sees",
                lengInfo(c)
    if tgt.op == VolatileLoadOp:
      g.ab.tree MovX64: (g.emReg res.r; g.emMemAt(ops[0].r, cellTyp))
    else:
      g.ab.tree MovX64: (g.emMemAt(ops[0].r, cellTyp); g.emReg ops[1].r)
    for d in ops:
      if d.kind == InReg and d.isTemp and not (res.kind == InReg and d.r == res.r):
        g.giveBack d.r
    dest = res
    return
  if res.kind != InReg:
    raiseAssert "arkham x64n: intrinsic result is not in a register"
  # The transliteration (the old emitInstr2 tail, over the fresh decisions).
  let a0 = if argCurs.len > 0: g.plan.planned(cursorToPosition(g.buf[], argCurs[0]))
           else: default(Location)
  let aliasesA0 = a0.kind == InReg and a0.r == res.r
  if res.isTemp and not aliasesA0 and not g.rb.isBoundTemp(res.r):
    g.bindTemp(res.r, res.typ)
  if inPlace and not aliasesA0:
    if a0.kind == InReg: g.movReg(res.r, a0.r)
    else: g.place2(a0, res.r)
  let src0 = if inPlace: res.r else: g.instrOperandReg(argCurs[0])
  var rotCount = 0'i64
  if tgt.op in {RolOp, RorOp}:
    let cnt = g.plan.planned(cursorToPosition(g.buf[], argCurs[1]))
    if cnt.kind != Imm:
      raiseAssert "arkham x64n: `" & IntrinsicNames[tgt.op] &
                  "` needs a compile-time rotate count"
    rotCount = cnt.ival
  g.emitIntrinsicOps(tgt.op, tgt.argBits, res.r, src0, rotCount)
  for d in ops:
    # `isTemp`: an operand read in place (`instrOperandInPlace`) is a LOCAL'S HOME —
    # `giveBack` would kill a binding and break a seal this row never made.
    if d.kind == InReg and d.isTemp and d.r != res.r: g.giveBack d.r
  dest = res
proc emitFValue2*(g: var CodeGen; c: Cursor; dest: var Location) =
  ## FUSED SIMD value: resolve `dest` (an xmm constraint / fixed register /
  ## `eftmp` slot) against `c` and materialize the float value there.
  if dest.kind == NamedStack and dest.spillTemp:
    g.produceIntoFMem2(c, dest); return
  let f64 = AsmSlot(cls: AFloat, size: 8, align: 8)
  case c.kind
  of FloatLit:
    if dest.kind != InFReg:
      dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
      if dest.kind == NamedStack:
        g.produceIntoFMem2(c, dest); return
    let bits = if dest.typ.size == 4: 32 else: 64
    if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
    let gpr = g.pickStagingSealed("a float literal bit pattern",
                                  AsmSlot(cls: AInt, size: 8, align: 8))
    if bits == 32: g.movImm(gpr, int64(cast[uint32](float32(floatVal(c)))))
    else: g.movImm(gpr, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest.f, gpr, bits)
    g.giveBack gpr
  of Symbol:
    # Store forwarding matters most here: SysV has no callee-saved xmm, so EVERY
    # float local is stack-homed and every read of one is a reload unless the
    # register that stored it still has it (`forwardFOf` turns the `NamedStack`
    # home into that `InFReg` — the arm below it then never runs).
    let fSymHome = g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c))
    let home = (if dest.kind != InFReg: g.takeFForwarded(fSymHome)
                else: g.forwardFOf(fSymHome))
    case home.kind
    of InFReg:
      if dest.kind != InFReg:
        dest = home                                      # use the home in place
      elif home.f != dest.f:
        let bits = if dest.typ.size == 4: 32 else: 64
        if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
        g.fmovF(dest.f, home.f, bits)
      elif dest.isTemp and g.rb.isFMirror(dest.f):
        # the accumulator IS the mirroring register: take it over (see the GPR
        # twin in `emitValue2`), because the consumer may write it in place
        g.bindFTmp(dest.f)
    of NamedStack:                                       # spilled float local
      if dest.kind != InFReg:
        dest = g.takeFTmp(home.typ)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      g.emFloatScalarLoad(dest.f, home.name, bits)
    else:                                                # a float global / tvar read
      if dest.kind != InFReg:
        dest = g.takeFTmp(g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      var cc = c
      let loc = g.asLoc(cc)
      g.floatMemMov(loc, dest.f, bits, load = true)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC: g.emitFBinE(c, dest)
    of NegC:
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          skip cc                                        # result float type
          inner = cc; skip cc
          while cc.hasMore: skip cc
      var iv = dest
      g.emitFValue2(inner, iv)                           # operand → dest
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      let z = g.pickFStagingSealed("a float neg temp")
      g.bindFTmp(z)
      g.fmovF(z, dest.f, bits)                           # z = operand
      let gpr = g.pickStagingSealed("a float neg zero",
                                    AsmSlot(cls: AInt, size: 8, align: 8))
      g.movImm(gpr, 0)
      g.fmovFromGpr(dest.f, gpr, bits)                   # dest = 0.0
      g.giveBack gpr
      g.fbin(SubssX64, SubsdX64, dest.f, z, bits)        # dest = 0.0 - operand
      g.unbindFTmp(z); g.rb.unsealF z
    of InfC, NeginfC, NanC:
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: f64)
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      let gpr = g.pickStagingSealed("a float special-value bit pattern",
                                    AsmSlot(cls: AInt, size: 8, align: 8))
      g.movImm(gpr, specialFloatBits(c.exprKind, bits))
      g.fmovFromGpr(dest.f, gpr, bits)
      g.giveBack gpr
    of ConvC, CastC: g.emitCast2(c, dest)                # conversion TO float
    of CallC: g.emitCall2(c, dest)                       # float-result call → xmm0
    of DerefC, DotC, AtC, PatC:
      # float lvalue load → movss/movsd res, [addr]
      if dest.kind != InFReg:
        dest = g.takeFTmp(if dest.typ.kind == AFloat: dest.typ else: g.exprSlot(c))
        if dest.kind == NamedStack:
          g.produceIntoFMem2(c, dest); return
      let bits = if dest.typ.size == 4: 32 else: 64
      g.emitLvalue2(c)                                   # pick embedded base/index
      g.prematLval2(c, foldDisp = true)
      if dest.isTemp and not g.rb.isBoundFTmp(dest.f): g.bindFTmp(dest.f)
      g.ab.tree (if bits == 32: MovssX64 else: MovsdX64):
        g.emFReg dest.f
        g.emMemLval2(c)
      g.unbindLvalTemps2(c)
      g.freeLvalTemps2(c)
    of InstrC: g.emitInstr2(c, dest)             # a vector row / float intrinsic
    of SufC, ParC:
      var inner: Cursor
      block:
        var cc = c
        cc.into:
          inner = cc; skip cc
          while cc.hasMore: skip cc
      g.emitFValue2(inner, dest)
    else: raiseAssert "arkham x64n: emitFValue2(fused) expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emitFValue2(fused) kind " & $c.kind
# ── `.assembler` procs: transliteration, not compilation ────────────────────
# doc/intrinsics.md §8. Everything below deliberately bypasses `allocateProc` and
# the whole value core: in an `.assembler` body every location is DECLARED, so
# there is nothing to allocate, and every construct must map one-to-one to an
# instruction, so there is nothing to lower. What is left is a checker plus a
# literal transcription — and arkham is the only checker there is (nimony's sem
# just forwards the pragmas), so each rejection below is a user-facing error with
# the offending node's own file/line/col, not a `raiseAssert`.

# MODEL: the `StartEmit` per-proc reset in proofs/arkham_bindings.tla. Every per-proc
# table (regLocal/boundTemps + the ra.locs snapshot) must be reset here or
# RegisterBindingsMatchLoc breaks.