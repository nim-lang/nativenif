#
#           Arkham — x86-64 / System V (Linux) code generator for NIFC
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Pass 3 (x86-64 backend). A first, scalar-integer code generator: it shares the
## front-end (`codegen_common`: the `CodeGen` state, the NIFC type/lvalue
## analysis) and the (arch-neutral) register allocator with the AArch64 backend,
## and emits System V / Linux asm-NIF that `nifasm` assembles+links to an ELF
## executable. Process exit is lowered to the Linux `exit` syscall (rax=60), so
## the produced binaries run without libc.
##
## v0 scope (mirrors arkham's AArch64 v1): integer/pointer scalars held in
## registers, arithmetic / bitops, `while`, comparisons, and a `main` that
## `exit`s. Floats, aggregates, memory lvalues, parameters, `if`/`case`, div/mod
## and shifts `raiseAssert` for now.

import std / [assertions, tables, sets]
import nifcore, nifcdecl
import slots, machinedesc, analyser, register_allocator, programs
import asmbuf, codegen_common, machine_x64

# ── scratch register pool ────────────────────────────────────────────────────

proc emReg(g: var CodeGen; r: Reg) {.inline.} =
  ## A value register operand. If `r` currently hosts a named local, emit the
  ## local's *name* (a typed symbol nifasm type-checks); otherwise the raw `(reg)`
  ## tag (a transient scratch register).
  if g.regLocal.hasKey(r): g.ab.sym g.regLocal[r]
  else: g.ab.reg r

proc initFreeTmp(g: var CodeGen) =
  g.freeTmp = {}
  for r in g.md.intTempRegs: g.freeTmp.incl r
  g.freeFTmp = {}
  for f in g.md.floatTempRegs: g.freeFTmp.incl f
  for name, pos in g.ra.symPos:               # registers held by a local/param
    let loc = g.ra.locs[pos]
    if loc.kind == InReg: g.freeTmp.excl loc.r
    elif loc.kind == InFReg: g.freeFTmp.excl loc.f

proc tryBorrowTmp(g: var CodeGen): Reg =
  ## Like `borrowTmp` but returns `NoReg` when the scratch pool is exhausted
  ## (instead of failing). The caller then spills the value to a stack slot. The
  ## reg-or-`NoReg` outcome is recorded/replayed like any borrow decision.
  if not g.ab.planning:                          # emit pass: replay the planned decision
    result = g.borrowLog[g.borrowIdx]; inc g.borrowIdx
    return
  for r in g.md.intTempRegs:                      # plan pass: real pool allocation
    if r in g.freeTmp and not g.ra.isSealed(r):
      excl g.freeTmp, r
      g.borrowLog.add r
      return r
  g.borrowLog.add NoReg                           # exhausted → caller spills (cannot fail)
  result = NoReg

# Order in which a codegen-time steal looks for a victim register-local: prefer
# volatile temps (R10/R11 — call-free locals the allocator put there, the common
# case), then callee-saved. Fixed order ⇒ the plan and emit passes pick the same
# victim deterministically.
const StealOrder = [R10, R11, RBX, R12, R13, R14, R15]

proc emScalarStackVar(g: var CodeGen; name: string)
proc emStackMem(g: var CodeGen; name: string)

proc stealReg(g: var CodeGen; logIdx: int): Reg =
  ## `freeTmp` is exhausted. Evict a register-bound local that is *not* in flight
  ## (not sealed, not a live accumulator) to a fresh stack slot and hand its
  ## register over as scratch — the codegen-side analogue of the allocator's
  ## `trySteal`, but driven by codegen's own scratch demand. The eviction is
  ## decided in the plan pass and replayed (with the spill store) in the emit
  ## pass, keyed by the borrow-log index, so both passes stay byte-consistent.
  if g.ab.planning:
    var vreg = NoReg
    var victim = ""
    for r in StealOrder:
      if g.regLocal.hasKey(r) and not g.ra.isSealed(r) and r notin g.liveAccums:
        vreg = r; victim = g.regLocal[r]; break
    if vreg == NoReg: return NoReg                 # nothing safe to steal
    let typ = g.ra.locationOfSym(victim).typ
    let slot = "evict" & $g.spillCount & ".0"; inc g.spillCount
    g.stealEvents[logIdx] = StealEvent(victim: victim, slot: slot, reg: vreg, typ: typ)
    # Evict in the allocator's view so every later `locationOfSym(victim)` reads
    # the stack slot. (`g.ra.locs` is snapshot/restored across the two passes.)
    g.ra.locs[g.ra.symPos[victim]] = namedStackLoc(slot, typ)
    g.ra.hasStackVars = true
    g.regLocal.del vreg
    result = vreg
  else:
    if logIdx notin g.stealEvents: return NoReg
    let ev = g.stealEvents[logIdx]
    g.emScalarStackVar(ev.slot)                    # (var :evictN.0 (s) (i 64))
    g.ab.tree MovX64:                              # store the victim's live value
      g.emStackMem(ev.slot)
      g.emReg ev.reg                               # bound to `victim` ⇒ emits its name
    if g.regLocal.getOrDefault(ev.reg, "") == ev.victim:
      g.ab.tree KillX64: g.ab.sym ev.victim        # release the register binding
    g.ra.locs[g.ra.symPos[ev.victim]] = namedStackLoc(ev.slot, ev.typ)
    g.regLocal.del ev.reg
    result = ev.reg

proc borrowTmp(g: var CodeGen): Reg =
  result = g.tryBorrowTmp()
  if result == NoReg:
    # The plan pass just logged `NoReg` (it is at `borrowLog.len-1`); the emit
    # pass replayed it (`borrowIdx-1`). Steal at that same logical position.
    let idx = if g.ab.planning: g.borrowLog.len - 1 else: g.borrowIdx - 1
    result = g.stealReg(idx)
    if result == NoReg:
      raiseAssert "arkham x64 v0: out of registers (no local to steal for scratch)"

proc giveBack(g: var CodeGen; r: Reg) {.inline.} =
  if r != NoReg: g.freeTmp.incl r

# ── SSE / floating-point scratch pool + emit helpers ─────────────────────────
# x86-64 floats live in xmm0..xmm15 (the FReg slots F0..F15). The register operand
# is always `(xmmN)`; the precision is carried by the instruction tag (movss vs
# movsd, addss vs addsd, …), unlike AArch64 where `(sN)`/`(dN)` encode it.

const FloatRet = F0    # xmm0: SysV scalar-float return + first float argument

proc emFReg(g: var CodeGen; f: FReg) {.inline.} = g.ab.xmmReg f

proc borrowFTmp(g: var CodeGen): FReg =
  if not g.ab.planning:                          # emit pass: replay the planned decision
    result = g.borrowLogF[g.borrowIdxF]; inc g.borrowIdxF
    return
  for f in g.md.floatTempRegs:                    # plan pass: real pool allocation
    if f in g.freeFTmp:
      excl g.freeFTmp, f
      g.borrowLogF.add f
      return f
  raiseAssert "arkham x64 v0: out of SIMD scratch registers"  # M2: spill instead of failing

proc giveBackF(g: var CodeGen; f: FReg) {.inline.} =
  if f in g.md.floatTempRegs: g.freeFTmp.incl f

proc fmovF(g: var CodeGen; d, s: FReg; bits: int) =                # movss/movsd d, s
  if d == s: return
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fmovFromGpr(g: var CodeGen; d: FReg; s: Reg; bits: int) =     # movfd/movfq xmm ← gpr
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fmovToGpr(g: var CodeGen; d: Reg; s: FReg; bits: int) =       # movfd/movfq gpr ← xmm
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc fbin(g: var CodeGen; op32, op64: X64Inst; d, s: FReg; bits: int) =  # d = d op s
  let op = if bits == 32: op32 else: op64
  g.ab.tree op: g.emFReg d; g.emFReg s

proc fcvtI2F(g: var CodeGen; d: FReg; s: Reg; bits: int) =         # cvtsi2ss/sd xmm ← gpr
  let op = if bits == 32: Cvtsi2ssX64 else: Cvtsi2sdX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fcvtF2I(g: var CodeGen; d: Reg; s: FReg; bits: int) =         # cvttss2si/sd2si gpr ← xmm
  let op = if bits == 32: Cvttss2siX64 else: Cvttsd2siX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc emFcvt(g: var CodeGen; d, s: FReg; dstBits, srcBits: int) =   # precision convert
  if dstBits == srcBits: (g.fmovF(d, s, dstBits); return)
  let op = if dstBits == 32: Cvtsd2ssX64 else: Cvtss2sdX64
  g.ab.tree op: g.emFReg d; g.emFReg s

# A spilled float scalar lives in an `(s) (f N)` stack slot (x64 has no callee-
# saved xmm registers, so a float that must survive a call has nowhere else to
# go). It is loaded/stored with movss/movsd against `(mem (rsp) name)`.
proc emFloatStackVar(g: var CodeGen; name: string; bits: int) =
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.floatType(bits)
  g.ab.close()

proc emFloatScalarLoad(g: var CodeGen; dest: FReg; name: string; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.emFReg dest
    g.ab.tree MemX: (g.ab.reg RSP; g.ab.sym name)

proc emFloatScalarStore(g: var CodeGen; name: string; src: FReg; bits: int) =
  let op = if bits == 32: MovssX64 else: MovsdX64
  g.ab.tree op:
    g.ab.tree MemX: (g.ab.reg RSP; g.ab.sym name)
    g.emFReg src

# ── low-level emit helpers ───────────────────────────────────────────────────

proc movImm(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovX64: g.emReg d; g.ab.intLit v

proc movReg(g: var CodeGen; d, s: Reg) =
  if d == s: return
  g.ab.tree MovX64: g.emReg d; g.emReg s

proc binReg(g: var CodeGen; op: X64Inst; d, s: Reg) =      # d op= s
  g.ab.tree op: g.emReg d; g.emReg s

proc binImm(g: var CodeGen; op: X64Inst; d: Reg; v: int64) =  # d op= imm
  g.ab.tree op: g.emReg d; g.ab.intLit v

proc extendTo(g: var CodeGen; dest: Reg; width: int; signed: bool) =
  ## Normalize the low `width` bits of `dest` to its full 64-bit register form
  ## (sign- or zero-extended). No-op for 64-bit. Done with the `shl #(64-w);
  ## sar|shr #(64-w)` shift pair (immediate shifts), matching the A64 backend —
  ## arkham keeps every scalar 64-bit-wide in a register, so widths are normalized
  ## explicitly rather than relying on sized loads.
  if width <= 0 or width >= 64: return
  let sh = int64(64 - width)
  g.binImm(ShlX64, dest, sh)
  g.binImm(if signed: SarX64 else: ShrX64, dest, sh)

proc emLab(g: var CodeGen; name: string) =
  g.ab.tree LabX64: g.ab.symDef name

proc emJmp(g: var CodeGen; name: string) =
  g.ab.tree JmpX64: g.ab.sym name

proc emJcc(g: var CodeGen; tag: X64Inst; name: string) =
  g.ab.tree tag: g.ab.sym name

proc emSyscall(g: var CodeGen) = g.ab.keyword SyscallX64

proc freshLabel(g: var CodeGen): string =
  result = "L" & $g.labelCount & ".0"
  inc g.labelCount

# ── expressions ──────────────────────────────────────────────────────────────

proc gen(g: var CodeGen; c: var Cursor; dest: var Location)
proc genInto(g: var CodeGen; c: var Cursor; dest: Reg)
proc genCall(g: var CodeGen; c: var Cursor)
proc genAddr(g: var CodeGen; c: var Cursor; dest: Reg)
proc emitCondJump(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool)
proc genVal(g: var CodeGen; c: var Cursor): Location
proc forceReg(g: var CodeGen; v: Location): tuple[r: Reg, owns: bool]
proc genTypeBody(g: var CodeGen; c: var Cursor)
proc emitGlobalInits(g: var CodeGen)
proc framePop(g: var CodeGen)
proc killFrameRegLocals(g: var CodeGen)
proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int)
proc genConstr(g: var CodeGen; c: var Cursor; dstPtr: Reg)
proc genStore(g: var CodeGen; c: var Cursor; dst: Location)
proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg
proc place(g: var CodeGen; v: Location; dest: Reg)

# ── named local variables (nifasm type-checks them; raw scratch stays `(reg)`) ─

proc emRegLocalVar(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Declare `(var :name (reg) type)` and bind `r` to `name` for the rest of its
  ## scope, so subsequent uses emit the typed name instead of `(reg)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register. The kill lands at this rebind,
  # past the dead var's coarse free point, hence on its post-dominating path.
  if g.regLocal.hasKey(r):
    g.ab.tree KillX64: g.ab.sym g.regLocal[r]
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.reg r                                   # the concrete register (the binding)
  # arkham keeps scalars 64-bit in registers and handles width/signedness via
  # explicit extends, so an int/uint/bool/char local is declared as plain
  # `(i 64)` (a logical `i8`/`u8` would mismatch a 64-bit `mov`, and nifasm also
  # rejects an `i`↔`u` move); a pointer keeps its `(ptr T)` so deref/field typing
  # works. Signed-vs-unsigned comparisons still pick `jb`/`jl` from the slot.
  let rt = resolveType(g.prog, typeCur)
  if isPtrType(rt):
    var tc = typeCur
    g.genTypeBody(tc)
  else: g.ab.intType(64)
  g.ab.close()
  g.regLocal[r] = name
  g.scopeLocals[^1].add (name: name, reg: r)

proc enterScope(g: var CodeGen) = g.scopeLocals.add @[]

proc exitScope(g: var CodeGen) =
  ## `kill` each register local declared in the closing scope so the allocator's
  ## register reuse in a sibling scope rebinds cleanly (nifasm forbids binding a
  ## still-live register). Skip any whose register was already rebound to a later
  ## local (already killed at that rebind).
  for it in g.scopeLocals.pop():
    if g.regLocal.getOrDefault(it.reg, "") == it.name:
      g.ab.tree KillX64: g.ab.sym it.name
      g.regLocal.del it.reg

# ── stack-slot declarations + memory operands (x86 addressing) ───────────────
# nifasm keeps field names / element types, so a memory operand stays symbolic:
#  * a spilled/address-taken scalar or aggregate is a `(var :name (s) T)` slot,
#    addressed `(mem (rsp) name)` / `(mem (dot (rsp) name field))`;
#  * a pointer in a register is dereferenced `(mem reg)`.
# Storing an immediate to memory is unimplemented in nifasm, so callers
# materialize the value into a register first.

proc emStackVar(g: var CodeGen; name, typeName: string) =
  ## `(var :name (s) typeName)` — a nifasm-managed aggregate stack slot.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.sym typeName
  g.ab.close()

proc emScalarStackVar(g: var CodeGen; name: string) =
  ## `(var :name (s) (i 64))` — a spilled/address-taken scalar's 8-byte slot.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.intType(64)
  g.ab.close()

proc emStackMem(g: var CodeGen; name: string) =       # (mem (rsp) name)
  g.ab.tree MemX:
    g.ab.reg RSP
    g.ab.sym name

proc emFieldMem(g: var CodeGen; base, field: string) =   # (mem (dot (rsp) base field))
  for fi in aggrLayout(g.prog, g.varType[base]):  # v0: only full 8-byte fields
    if fi.name == field:
      if fi.size != 8:
        raiseAssert "arkham x64 v0: sub-word field not supported: " & base & "." & field
      break
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.reg RSP
      g.ab.sym base
      g.ab.sym field

proc fieldOffset(g: var CodeGen; base, field: string): int =
  for fi in aggrLayout(g.prog, g.varType[base]):
    if fi.name == field: return fi.off
  raiseAssert "arkham x64: field not found: " & base & "." & field

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string)

proc loadOperandReg(g: var CodeGen; v: Location; tmps: var seq[Reg]): Reg =
  ## Materialize `v` into a register for a single memory-operand instruction
  ## (`emAccessAddr`). Such a register is transient — it lives only for the one
  ## load/store/cmp the operand feeds, with no calls in between — so when the
  ## scratch pool is exhausted a caller-saved staging register is safe, keeping
  ## indexed/global access total under register pressure.
  if v.kind == InReg:
    if v.owns: tmps.add v.r
    return v.r
  result = g.tryBorrowTmp()
  if result != NoReg: tmps.add result
  else: result = g.pickStaging()
  g.place(v, result)

proc emAccessAddr(g: var CodeGen; n: var Cursor; tmps: var seq[Reg]) =
  ## Recursively re-emit the NIFC lvalue subtree `n` as a nifasm address
  ## expression, letting nifasm collapse the whole chain to `base+offset` from the
  ## declared types. Borrowed temps (deref pointers, computed array indices) are
  ## pushed onto `tmps` for the caller to free after the instruction. A stack var
  ## contributes `(rsp) name`; a pointer in a register contributes the register.
  case n.kind
  of Symbol:
    let nm = symName(n); inc n
    let loc = g.ra.locationOfSym(nm)
    case loc.kind
    of NamedStack: (g.ab.reg RSP; g.ab.sym nm)   # a stack var: rsp + slot offset
    of InReg:
      if g.varType.hasKey(nm):
        # a by-reference aggregate: the register holds a pointer; type it with a
        # cast so a `(dot …)` / `(at …)` can compute the field/element offset.
        g.ab.tree CastX:
          g.ab.ptrType: g.ab.sym g.varType[nm]
          g.emReg loc.r
      else:
        g.emReg loc.r                              # a plain pointer in a register
    else:
      # A global aggregate (this module or foreign): materialize its address in
      # a temp and type it as `(ptr <type>)` so a `(dot …)`/`(at …)` can offset.
      let si = g.lookupSym(nm)
      if si.cat == scGlobal:
        # The global's address only needs to live for the single load/store/cmp
        # instruction this operand feeds (no calls in between), so when the
        # scratch pool is exhausted a transient caller-saved staging register is
        # safe — keeping a global-indexed access total under register pressure.
        var r = g.tryBorrowTmp()
        if r != NoReg: tmps.add r
        else: r = g.pickStaging()
        g.emGlobalAddr(r, nm)
        var d = si.decl
        inc d; skip d; skip d                      # enter (gvar …): name, pragmas → type
        g.ab.tree CastX:
          g.ab.ptrType:
            if d.kind == Symbol: g.ab.sym symName(d)
            else: g.genTypeBody(d)
          g.emReg r
      else: raiseAssert "arkham x64 v0: unsupported lvalue base: " & nm
  of TagLit:
    case n.exprKind
    of DotC:
      g.ab.tree DotX:
        n.into:
          g.emAccessAddr(n, tmps)                # base (recursive)
          let field = symName(n); inc n          # field name (offset is nifasm's job)
          g.ab.sym field                         # nifasm sizes the access by field type
          while n.hasMore: skip n                # depth selector
    of AtC:
      g.ab.tree AtX:
        n.into:
          g.emAccessAddr(n, tmps)                # array base (recursive)
          if n.kind == IntLit: (g.ab.intLit intVal(n); inc n)
          else:
            g.emReg g.loadOperandReg(g.genVal(n), tmps)
          while n.hasMore: skip n
    of DerefC:
      n.into:
        g.emReg g.loadOperandReg(g.genVal(n), tmps)  # the pointer → a register
        while n.hasMore: skip n                  # (cppref)?
    else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.exprKind
  else: raiseAssert "arkham x64 v0: not an lvalue: " & $n.kind

proc emMemOperandLoc(g: var CodeGen; loc: Location): seq[Reg] =
  ## `(mem <addr>)` for a memory `Location` (a `Val`-of-old `vkMem`). `NamedStack`
  ## is a by-name slot (spilled local or synthetic spill — no cursor) → `(mem (rsp)
  ## name)`; `Mem` re-emits its captured lvalue subtree so nifasm folds the chain.
  result = @[]
  case loc.kind
  of NamedStack: g.emStackMem(loc.name)
  of Mem:
    var nn = loc.cur
    g.ab.tree MemX:
      g.emAccessAddr(nn, result)
  else: raiseAssert "arkham x64: emMemOperandLoc on non-memory location " & $loc.kind

proc emitLoadLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← <scalar Location>` (the one scalar load, over every lvalue kind).
  case loc.kind
  of InReg: g.movReg(dest, loc.r)
  of Tvar:                                        # thread-local → FS:[off] mem operand
    g.ab.tree MovX64:                             # nifasm resolves a tvar symbol to FS:[off]
      g.emReg dest
      g.ab.sym loc.name
  of Glob:                                        # &g into dest, then deref dest
    g.emGlobalAddr(dest, loc.name)
    g.ab.tree MovX64:
      g.emReg dest
      g.ab.tree MemX: g.emReg dest                # dest ← [dest]
  of NamedStack, Mem:                             # rsp slot / folded access chain
    var tmps: seq[Reg]
    g.ab.tree MovX64:
      g.emReg dest
      tmps = g.emMemOperandLoc(loc)
    for t in tmps: g.giveBack t
  else: raiseAssert "arkham x64: emitLoadLoc on location kind " & $loc.kind

proc emitStoreLoc(g: var CodeGen; loc: Location; src: Reg) =
  ## `<scalar Location> ← src` (GPR). The store counterpart of `emitLoadLoc`.
  case loc.kind
  of InReg: g.movReg(loc.r, src)
  of Tvar:                                        # thread-local → FS:[off] store
    g.ab.tree MovX64:
      g.ab.sym loc.name
      g.emReg src
  of Glob:                                        # &g into a temp, then store
    let p = g.borrowTmp()
    g.emGlobalAddr(p, loc.name)
    g.ab.tree MovX64:
      g.ab.tree MemX: g.emReg p
      g.emReg src
    g.giveBack p
  of NamedStack, Mem:
    var tmps: seq[Reg]
    g.ab.tree MovX64:
      tmps = g.emMemOperandLoc(loc)
      g.emReg src
    for t in tmps: g.giveBack t
  else: raiseAssert "arkham x64: emitStoreLoc on location kind " & $loc.kind

proc emGlobalAddr(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &global` — RIP-relative `lea` (nifasm resolves the gvar to a
  ## `.bss`/`.data` address). x86-64 has no typed RIP-relative memory operand, so
  ## a global is always accessed by first materializing its address.
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym name)

proc binMem(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location) =
  ## `dest op= <memory operand>` — x86 folds a memory source into the ALU op.
  var tmps: seq[Reg]
  g.ab.tree op:
    g.emReg dest
    tmps = g.emMemOperandLoc(loc)
  for t in tmps: g.giveBack t

proc emitAddrLoc(g: var CodeGen; loc: Location; dest: Reg) =
  ## `dest ← &<Location>`.
  case loc.kind
  of NamedStack:                              # (lea dest (rsp) name)
    g.ab.tree LeaX64: (g.emReg dest; g.ab.reg RSP; g.ab.sym loc.name)
  of Glob: g.emGlobalAddr(dest, loc.name)     # &global → RIP-relative lea
  of Mem:
    var nn = loc.cur
    if nn.kind == TagLit and nn.exprKind == DerefC:   # &(deref p) == p
      nn.into:
        g.genInto(nn, dest)
        while nn.hasMore: skip nn
    else:                                     # &(dot …)/&arr[idx] — re-emit the chain
      var tmps: seq[Reg] = @[]                # nifasm computes base+offset (+ index scale)
      g.ab.tree LeaX64:
        g.emReg dest
        g.emAccessAddr(nn, tmps)
      for t in tmps: g.giveBack t
  else: raiseAssert "arkham x64: emitAddrLoc on location kind " & $loc.kind

proc addrOfLoc(g: var CodeGen; loc: Location): (Reg, bool) =
  ## `&loc` in a register. A register-resident value already IS its address (a
  ## by-reference aggregate param) and is returned as-is; else borrow a temp.
  if loc.kind == InReg: return (loc.r, false)
  let r = g.borrowTmp()
  g.emitAddrLoc(loc, r)
  result = (r, true)

proc emitLoadFLoc(g: var CodeGen; loc: Location; dest: FReg; bits: int) =
  ## `dest ← <float Location>`.
  case loc.kind
  of InFReg: g.fmovF(dest, loc.f, bits)
  of NamedStack: g.emFloatScalarLoad(dest, loc.name, bits)
  of Mem:
    let op = if bits == 32: MovssX64 else: MovsdX64
    var tmps: seq[Reg]
    g.ab.tree op:
      g.emFReg dest
      tmps = g.emMemOperandLoc(loc)
    for t in tmps: g.giveBack t
  else: raiseAssert "arkham x64: emitLoadFLoc on location kind " & $loc.kind

proc emitStoreFLoc(g: var CodeGen; loc: Location; src: FReg; bits: int) =
  ## `<float Location> ← src`.
  case loc.kind
  of InFReg: g.fmovF(loc.f, src, bits)
  of NamedStack: g.emFloatScalarStore(loc.name, src, bits)
  of Mem:
    let op = if bits == 32: MovssX64 else: MovsdX64
    var tmps: seq[Reg]
    g.ab.tree op:
      tmps = g.emMemOperandLoc(loc)
      g.emFReg src
    for t in tmps: g.giveBack t
  else: raiseAssert "arkham x64: emitStoreFLoc on location kind " & $loc.kind

proc place(g: var CodeGen; v: Location; dest: Reg) =
  ## Materialize `v` into `dest`, releasing any owned scratch it occupied.
  case v.kind
  of Imm: g.movImm(dest, v.ival)
  of InReg:
    g.movReg(dest, v.r)
    if v.owns and v.r != dest: g.giveBack v.r
  of NamedStack, Mem: g.emitLoadLoc(v, dest)
  else: raiseAssert "arkham x64 v0: cannot place a value of kind " & $v.kind

proc forceReg(g: var CodeGen; v: Location): tuple[r: Reg, owns: bool] =
  ## Ensure `v` is in a register (an immediate / memory operand is loaded into a
  ## fresh temp).
  case v.kind
  of InReg: (v.r, v.owns)
  of Imm:
    let t = g.borrowTmp(); g.movImm(t, v.ival); (t, true)
  of NamedStack, Mem:
    let t = g.borrowTmp(); g.emitLoadLoc(v, t); (t, true)
  else: raiseAssert "arkham x64 v0: cannot force a value of kind " & $v.kind & " into a register"

const StagingCandidates = [RAX, RDI, RSI, RDX, RCX, R8, R9]

proc pickStaging(g: var CodeGen; avoid: Reg = NoReg): Reg =
  ## A transient compute register for a spill: the first non-sealed caller-saved
  ## GPR that is neither the scratch pool (r10/r11, exhausted at a spill) nor a
  ## local home (those are callee-saved), is not a live expression accumulator
  ## (`liveAccums` — e.g. rax holding the return value while a deep right operand
  ## spills), and is not `avoid`. Clobbering it transiently is then safe.
  for r in StagingCandidates:
    if r != avoid and not g.ra.isSealed(r) and r notin g.liveAccums: return r
  raiseAssert "arkham x64: no staging register available for a spill"

proc spillComputed(g: var CodeGen; c: var Cursor): Location =
  ## The scratch pool is exhausted: materialize `c`'s value into a fresh `(s)` slot
  ## via a transient staging register, and hand it back as a *foldable memory
  ## operand* (a `NamedStack` location) — which every value consumer (`binMem`/
  ## `place`/`forceReg`) already handles. This is what makes register allocation
  ## total: a deep
  ## expression spills instead of failing. The staging reg is sealed across the
  ## recursive eval so the inner walk can't clobber the value being built; that
  ## inner `genInto` is itself total (genBin's pool-exhausted path spills its left
  ## operand and reuses the staging reg as its own `dest` rather than consuming a
  ## fresh staging reg per level), so spill nesting no longer cascades and this
  ## path is reached only at isolated spill points (the divisor / the lighter
  ## operand of an SU swap), never recursively.
  let slotName = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let stage = g.pickStaging()
  g.ra.seal stage
  g.emScalarStackVar(slotName)                  # (var :spill.N (s) (i 64))
  g.genInto(c, stage)                           # compute the value into the staging reg
  g.ab.tree MovX64:                             # store it to the slot
    g.emStackMem(slotName)
    g.emReg stage
  g.ra.unseal {stage}
  result = namedStackLoc(slotName, AsmSlot(kind: AInt, size: 8, align: 8))

const ScalarSlot = AsmSlot(kind: AInt, size: 8, align: 8)
  ## The placeholder slot for a register/immediate dont-care result: the old `Val`
  ## carried no type at all, and no consumer of an `InReg`/`Imm` value reads `.typ`.

proc genVal(g: var CodeGen; c: var Cursor): Location =
  ## The dont-care evaluator: produce `c`'s value wherever it naturally lives — a
  ## literal as an `Imm`, a register-resident local in place (`InReg`, not owned),
  ## a memory operand as a foldable `NamedStack`/`Mem` — materializing any
  ## *computed* value into a scratch register (`InReg`, owned), or (when the pool
  ## is exhausted) a spill slot. The counterpart of `gen(…, InReg dest)`.
  case c.kind
  of IntLit:
    result = immLoc(intVal(c), ScalarSlot); inc c
  of UIntLit:
    result = immLoc(cast[int64](uintVal(c)), ScalarSlot); inc c
  of CharLit:
    result = immLoc(int64(ord(charLit(c))), ScalarSlot); inc c
  of Symbol:
    let si = g.lookupSym(symName(c))
    if si.cat == scProc:                        # proc as a value → its code address
      let t = g.borrowTmp()
      g.ab.tree LeaX64: (g.emReg t; g.ab.sym si.asmName)
      inc c
      return regLoc(t, ScalarSlot, owns = true)
    let loc = g.asLoc(c)
    case loc.kind
    of InReg: result = regLoc(loc.r, loc.typ, owns = false)
    of NamedStack: result = loc                 # foldable spilled scalar in place
    of Glob, Tvar:                              # load through its address into a scratch
      let t = g.borrowTmp(); g.emitLoadLoc(loc, t)
      result = regLoc(t, loc.typ, owns = true)
    else: raiseAssert "arkham x64 v0: operand of kind " & $loc.kind
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC:                       # a memory lvalue used as a value
      result = g.asLoc(c)                        # a foldable `Mem` operand
    else:
      let t = g.tryBorrowTmp()                  # a computed value → a scratch reg…
      if t == NoReg: result = g.spillComputed(c)  # …or a spill slot if exhausted
      else:
        g.genInto(c, t)
        result = regLoc(t, ScalarSlot, owns = true)
  else:
    let t = g.tryBorrowTmp()
    if t == NoReg: result = g.spillComputed(c)
    else:
      g.genInto(c, t)
      result = regLoc(t, ScalarSlot, owns = true)

proc gen(g: var CodeGen; c: var Cursor; dest: var Location) =
  ## The single value/destination entry point. `dest` says where `c`'s value must
  ## go; every value-producing call can route through here instead of picking one
  ## of `genInto` / `genIntoF` / `genVal` / a hand-rolled store by hand:
  ##   * `InReg` / `InFReg` → into that register (the int / float worker);
  ##   * `Undef` → the dont-care target: pick the cheapest home and write the
  ##     chosen `Location` back through `dest` (its `var`-out channel);
  ##   * `NamedStack` / `Mem` → store the computed value at that memory operand.
  ## `Imm`/`OnStack` are not destinations.
  case dest.kind
  of InReg: g.genInto(c, dest.r)
  of InFReg: g.genIntoF(c, dest.f, dest.typ.size * 8)
  of Undef: dest = g.genVal(c)
  of NamedStack, Mem, Glob, Tvar:
    if dest.typ.isFloat:
      let bits = dest.typ.size * 8
      let f = g.borrowFTmp()
      g.genIntoF(c, f, bits)
      g.emitStoreFLoc(dest, f, bits)
      g.giveBackF f
    else:
      let (r, owns) = g.forceReg(g.genVal(c))
      g.emitStoreLoc(dest, r)
      if owns: g.giveBack r
  else: raiseAssert "arkham x64: gen() cannot target dest kind " & $dest.kind

proc commutativeOp(op: X64Inst): bool {.inline.} =
  ## Integer ops for which `a op b == b op a`, so Sethi–Ullman may evaluate the
  ## heavier operand first and fold the lighter one. (sub/shl/shr/div/mod are
  ## position-sensitive and stay in source order.)
  op in {AddX64, ImulX64, AndX64, OrX64, XorX64}

const SuCallWeight = 1000          # a call dominates demand → sorts first

proc suWeight(c: Cursor): int =
  ## Sethi–Ullman register label of the subtree at `c`: an estimate of how many
  ## registers evaluating it needs, used to decide which operand of a commutative
  ## op to evaluate first. Reads a *copy* of the cursor (never advances `c`). Only
  ## the integer arithmetic/logic tree is modeled precisely; memory loads and
  ## anything unmodeled count as leaves (weight 1); a call gets a large weight.
  var c = c
  if c.kind != TagLit:
    return 1                                   # IntLit / Symbol / StrLit leaf
  case c.exprKind
  of AddC, SubC, MulC, BitandC, BitorC, BitxorC, ShlC, ShrC, DivC, ModC:
    var la = 1
    var lb = 1
    c.into:
      skip c                                   # result type
      la = suWeight(c); skip c                 # left
      lb = suWeight(c); skip c                 # right
    result = if la == lb: la + 1 else: max(la, lb)
  of NegC, BitnotC, ConvC, CastC:
    var w = 1
    c.into:
      skip c                                   # type child
      if c.hasMore: w = suWeight(c)
      while c.hasMore: skip c                  # operand (+ trailing tokens)
    result = max(w, 1)
  of NotC:                                     # boolean not has NO type child
    var w = 1
    c.into:
      if c.hasMore: w = suWeight(c)
      while c.hasMore: skip c
    result = max(w, 1)
  of CallC:
    result = SuCallWeight
  else:
    result = 1                                 # Dot/At/Deref/Addr/comparisons/…

proc hasCall(c: Cursor): bool =
  ## True if the subtree at `c` contains a call (atomics lower through the call
  ## path too). Reordering two *pure* operands is observation-preserving; a call
  ## anywhere disables the Sethi–Ullman swap. Reads a copy of the cursor.
  var c = c
  if c.kind != TagLit: return false
  if c.exprKind == CallC: return true
  result = false
  c.into:
    while c.hasMore:
      if not result and hasCall(c): result = true
      skip c

proc refsReg(g: var CodeGen; c: Cursor; r: Reg): bool =
  ## Does evaluating the subtree at `c` read register `r`? True when any symbol
  ## in it is register-resident with home `r`. Keeps the operand swap sound:
  ## evaluating the heavy operand into `dest` first must not clobber a register
  ## the light operand still needs. Reads a copy of the cursor.
  var c = c
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    return loc.kind == InReg and loc.r == r
  if c.kind != TagLit: return false
  result = false
  c.into:
    while c.hasMore:
      if not result and g.refsReg(c, r): result = true
      skip c

proc accessBaseSym(c: Cursor): string =
  ## The innermost base symbol of a `(dot|at|deref …)` access chain, or "".
  var n = c
  while n.kind == TagLit and n.exprKind in {DotC, AtC, DerefC}:
    inc n                                      # descend to the access's base
  result = if n.kind == Symbol: symName(n) else: ""

proc isComputedOperand(g: var CodeGen; c: Cursor): bool =
  ## Mirrors `genVal`: the operand kinds it materializes into a fresh register
  ## (and would spill on pool exhaustion), as opposed to those it reads in place
  ## (literal, register/stack local, memory lvalue). genBin intercepts these so a
  ## deep right operand spills without pinning `dest`.
  case c.kind
  of IntLit, UIntLit, CharLit, Symbol: result = false
  of TagLit:
    if c.exprKind in {DotC, AtC, DerefC}:
      # A stack/pointer access folds in place (rsp- or register-relative), but a
      # *global*-based access needs its address `lea`'d into a register first —
      # not free under pressure. Treat it as computed so genBin frees `dest` via
      # the spill path before materializing it.
      let b = accessBaseSym(c)
      result = b.len > 0 and g.lookupSym(b).cat == scGlobal
    else:
      result = true
  else: result = true

proc spillOperandAround(g: var CodeGen; c: var Cursor; dest: Reg; op: X64Inst) =
  ## Pool-exhausted evaluation of genBin's right operand that keeps register
  ## allocation TOTAL. The left operand is already in `dest`; spill it to a fresh
  ## slot so `dest` is free, evaluate the (possibly deep) right operand into `dest`
  ## — the recursion reuses `dest`, never pinning a register per nesting level —
  ## then reassemble `dest = a op b` with a single transient staging reg taken only
  ## here, after the recursion has fully unwound (so it never nests → one reg covers
  ## any depth). Evaluation order a-before-b is preserved (correct for impure
  ## operands too). `c` is consumed past the right operand.
  let slotA = spillName(g.spillCount); inc g.spillCount
  g.ra.hasStackVars = true
  let slotLoc = namedStackLoc(slotA, AsmSlot(kind: AInt, size: 8, align: 8))
  g.emScalarStackVar(slotA)
  g.ab.tree MovX64:                            # store a → slotA (free dest)
    g.emStackMem(slotA)
    g.emReg dest
  g.genInto(c, dest)                           # b → dest (recursion reuses dest)
  let s = g.pickStaging(avoid = dest)          # transient; recursion done → never nests
  g.movReg(s, dest)                            # s = b
  g.emitLoadLoc(slotLoc, dest)                 # dest = a (reload)
  g.binReg(op, dest, s)                        # dest = a op b

proc genBin(g: var CodeGen; c: var Cursor; dest: Reg; op: X64Inst; immOk: bool) =
  ## `dest = a op b` in x86's destructive form: normally `a` into `dest`, then
  ## `dest op= b`, with `b` folded as an immediate / memory / register operand.
  ## For a commutative op whose RIGHT operand needs strictly more registers than
  ## the left (Sethi–Ullman), the operands are swapped: the heavier one is
  ## evaluated into `dest` first and the lighter folded after — so a right-nested
  ## chain like `1+(2+(4+…))` collapses into `dest` with no scratch temp (and
  ## therefore never spills). The swap is taken only when both operands are pure
  ## (no call, so reordering is observation-preserving) and the light operand does
  ## not read `dest` (which the heavy evaluation overwrites first). If instead `b`
  ## lives in `dest`, it is saved before `a` overwrites it.
  ##
  ## When `b` is a computed operand that must occupy a register and the scratch
  ## pool is exhausted, `spillOperandAround` takes over: it spills the just-computed
  ## `a` (in `dest`) to a slot, evaluates `b` into the freed `dest`, and reassembles
  ## — so even a deep NON-commutative right-nest (`a-(b-(c-…))`, which SU can't
  ## reorder) allocates with O(1) live registers and O(depth) slots instead of
  ## asserting. Register allocation is total.
  # `dest` accumulates the result across both operand evaluations; seal it so a
  # scratch steal during the right operand can't evict it (if `dest` is a
  # register-local). A scratch `dest` is not a steal candidate anyway, so this
  # only matters — and is only ever a no-op otherwise — for local-reg targets.
  let destWasSealed = g.ra.isSealed(dest)
  g.ra.seal dest
  defer:
    if not destWasSealed: g.ra.unseal {dest}
  c.into:
    skip c                                    # result type; c at a
    var aPeek = c
    var bPeek = c; skip bPeek                  # bPeek at b
    var other: Location                       # the operand folded into dest last
    var combined = false                      # the spill path emits its own combine
    if commutativeOp(op) and suWeight(bPeek) > suWeight(aPeek) and
       not hasCall(aPeek) and not hasCall(bPeek) and not g.refsReg(aPeek, dest):
      g.genInto(bPeek, dest)                   # heavier operand (b) → dest first
      other = g.genVal(c)                      # lighter operand (a) folded after
      skip c                                   # consume b in the real cursor
    elif g.operandInReg(bPeek, dest):
      let saved = g.borrowTmp()
      g.movReg(saved, dest)                   # preserve b before `a` clobbers dest
      g.genInto(c, dest)                      # a → dest
      skip c                                  # consume b
      other = regLoc(saved, ScalarSlot, owns = true)
    else:
      g.genInto(c, dest)                      # a → dest; c now at b
      if g.isComputedOperand(c):              # b must be materialized into a register
        let t = g.tryBorrowTmp()
        if t == NoReg:                         # pool exhausted → total spill path
          g.spillOperandAround(c, dest, op)
          combined = true
        else:
          g.genInto(c, t)                      # b → scratch temp
          other = regLoc(t, ScalarSlot, owns = true)
      else:
        other = g.genVal(c)                    # b is a leaf / memory / in-place value
    if not combined:
      if immOk and other.kind == Imm and other.ival >= 0 and other.ival <= 0xFFFF:
        g.binImm(op, dest, other.ival)
      elif other.kind in {NamedStack, Mem}:
        g.binMem(op, dest, other)             # fold the memory operand: op dest, [mem]
      else:
        let (br, owns) = g.forceReg(other)
        g.binReg(op, dest, br)
        if owns: g.giveBack br

proc materializeCond(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## A comparison/logic used as a 0/1 value: assume true, jump over the reset.
  let lEnd = g.freshLabel()
  g.movImm(dest, 1)
  g.emitCondJump(c, lEnd, whenTrue = true)
  g.movImm(dest, 0)
  g.emLab(lEnd)

proc genDivMod(g: var CodeGen; c: var Cursor; dest: Reg; signed, wantRemainder: bool) =
  ## x86 division: dividend in RAX, divisor in a register; quotient → RAX,
  ## remainder → RDX. nifasm's `(idiv|div (rdx)(rax) src)` emits the cqo / xor-rdx
  ## itself. RAX/RDX are never live locals (not in the allocator's pool), so
  ## clobbering them is safe; the divisor lives in a borrowed temp (idiv has no
  ## immediate form).
  c.into:
    skip c                                    # result type
    g.genInto(c, RAX)                          # dividend → rax
    g.ra.seal RAX                              # protect it while materializing the divisor
    let (br, owns) = g.forceReg(g.genVal(c))   # divisor → a register
    g.ra.unseal {RAX}
    g.ab.tree (if signed: IdivX64 else: DivX64):
      g.ab.reg RDX                             # (rdx): high half of the dividend
      g.ab.reg RAX                             # (rax): low half
      g.emReg br
    if owns: g.giveBack br
  g.movReg(dest, if wantRemainder: RDX else: RAX)

# ── floating-point expressions (single + double precision) ──────────────────
# `bits` (32/64) is the value's precision, threaded top-down: it selects movss vs
# movsd / addss vs addsd, etc. A bare literal has no inherent width, so it adopts
# the contextual `bits`.

proc genFReg(g: var CodeGen; c: var Cursor; bits: int): tuple[f: FReg, owns: bool] =
  ## A float operand in an xmm register: a float local stays in place; anything
  ## else is materialized into a borrowed SIMD temp.
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InFReg:
      inc c
      return (loc.f, false)
  let f = g.borrowFTmp()
  g.genIntoF(c, f, bits)
  (f, true)

proc genFBin(g: var CodeGen; c: var Cursor; dest: FReg; op32, op64: X64Inst; bits: int) =
  ## `(op (f N) a b)` → `dest = a op b` (addss/sd, subss/sd, mulss/sd, divss/sd).
  c.into:
    skip c                                    # result float type
    g.genIntoF(c, dest, bits)                  # a → dest
    let (fr, ft) = g.genFReg(c, bits)          # b → fp temp (or in place)
    g.fbin(op32, op64, dest, fr, bits)
    if ft: g.giveBackF fr

proc genConvToF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## `(conv (f N) Expr)` — int→float (cvtsi2ss/sd) or float→float (cvt precision).
  c.into:
    skip c                                    # target float type
    if g.isFloatExpr(c):
      let srcBits = g.floatBits(c)
      if srcBits == bits:
        g.genIntoF(c, dest, bits)              # same precision: copy
      else:
        let (sf, st) = g.genFReg(c, srcBits)
        g.emFcvt(dest, sf, bits, srcBits)      # precision convert
        if st: g.giveBackF sf
    else:
      let (srcW, srcSigned) = g.srcWidthSigned(c)
      let tmp = g.borrowTmp()
      g.genInto(c, tmp)                          # int value → GPR
      g.extendTo(tmp, srcW, srcSigned)           # normalize to its full int value
      g.fcvtI2F(dest, tmp, bits)                 # cvtsi2ss/sd (signed; u64 edge: TODO)
      g.giveBack tmp
    while c.hasMore: skip c

proc genCastToF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## `(cast (f N) Expr)` — reinterpret an integer's bits as a float (or copy a
  ## same-precision float unchanged).
  c.into:
    skip c                                    # target float type
    if g.isFloatExpr(c):
      g.genIntoF(c, dest, bits)
    else:
      let tmp = g.borrowTmp()
      g.genInto(c, tmp)                          # integer bit pattern → GPR
      g.fmovFromGpr(dest, tmp, bits)             # reinterpret as float
      g.giveBack tmp
    while c.hasMore: skip c

proc genIntoF(g: var CodeGen; c: var Cursor; dest: FReg; bits: int) =
  ## Evaluate a `bits`-wide float expression into the SIMD register `dest`.
  case c.kind
  of FloatLit:
    let tmp = g.borrowTmp()                     # materialize the bit pattern via a GPR
    if bits == 32:
      g.movImm(tmp, int64(cast[uint32](float32(floatVal(c)))))
    else:
      g.movImm(tmp, cast[int64](floatVal(c)))
    g.fmovFromGpr(dest, tmp, bits)
    g.giveBack tmp
    inc c
  of Symbol:
    let loc = g.asLoc(c)
    g.emitLoadFLoc(loc, dest, bits)
  of TagLit:
    case c.exprKind
    of AddC: g.genFBin(c, dest, AddssX64, AddsdX64, bits)
    of SubC: g.genFBin(c, dest, SubssX64, SubsdX64, bits)
    of MulC: g.genFBin(c, dest, MulssX64, MulsdX64, bits)
    of DivC: g.genFBin(c, dest, DivssX64, DivsdX64, bits)
    of NegC:
      # No scalar SSE negate; flip the sign bit by subtracting from +0.0.
      c.into:
        skip c                                # result type
        let (sf, st) = g.genFReg(c, bits)
        let zero = g.borrowFTmp()
        let z = g.borrowTmp(); g.movImm(z, 0)
        g.fmovFromGpr(zero, z, bits); g.giveBack z   # zero ← +0.0
        g.fbin(SubssX64, SubsdX64, zero, sf, bits)   # 0 - x
        g.fmovF(dest, zero, bits)
        g.giveBackF zero
        if st: g.giveBackF sf
        while c.hasMore: skip c
    of ConvC: g.genConvToF(c, dest, bits)
    of CastC: g.genCastToF(c, dest, bits)
    of CallC:
      g.genCall(c)                            # float result lands in xmm0 …
      g.fmovF(dest, FloatRet, bits)           # … move it to the destination
    of DotC, AtC, DerefC:                      # float field / element / deref: dest ← [mem]
      let loc = g.asLoc(c); g.emitLoadFLoc(loc, dest, bits)
    else: raiseAssert "arkham x64 v0: float expression not supported: " & $c.exprKind
  else:
    raiseAssert "arkham x64 v0: float operand not supported: " & $c.kind

proc genCoerce(g: var CodeGen; c: var Cursor; dest: Reg; isCast: bool) =
  ## `(conv Type Expr)` / `(cast Type Expr)`: evaluate `Expr` into `dest`, then
  ## re-represent it in `Type`'s 64-bit register form. Widening extends from the
  ## *source* width (conv follows the source signedness; cast zero-extends the
  ## bits); narrowing/equal truncates to the target width and extends per the
  ## *target*; an int→ptr target zero-extends a narrower source. Integer/char/
  ## bool/pointer only (no floats in x64 v0).
  c.into:
    let tc = resolveType(g.prog, c)           # resolve named types / enums
    let targetSigned = isSignedType(tc)
    let targetW = intTypeWidth(tc)
    let targetPtr = isPtrType(tc)
    skip c                                    # target type
    if g.isFloatExpr(c):
      # float source → integer/pointer target (`dest` is a GPR).
      let fbits = g.floatBits(c)
      let (sf, st) = g.genFReg(c, fbits)
      if isCast:
        g.fmovToGpr(dest, sf, fbits)          # reinterpret the float's bits
      else:
        g.fcvtF2I(dest, sf, fbits)            # cvtt* (truncate toward zero)
        if targetW < 64 and not targetPtr:
          g.extendTo(dest, targetW, signed = targetSigned)
      if st: g.giveBackF sf
      while c.hasMore: skip c
      return
    let (srcW, srcSigned) = g.srcWidthSigned(c)
    g.genInto(c, dest)                        # value → dest
    if targetPtr:
      if srcW < 64: g.extendTo(dest, srcW, signed = false)   # int→ptr: zero-extend
    elif srcW < targetW:                      # widening int→int
      g.extendTo(dest, srcW, signed = (not isCast) and srcSigned)
    else:                                     # narrowing or equal width
      g.extendTo(dest, targetW, signed = targetSigned)
    while c.hasMore: skip c

proc genInto(g: var CodeGen; c: var Cursor; dest: Reg) =
  # While `dest` holds the value being built, a deep sub-operand may exhaust the
  # scratch pool and spill — its transient staging register must not clobber
  # `dest`. The scratch pool (r10/r11) is never a staging candidate, but a caller-
  # saved accumulator (rax = the return value, or a call-argument register) IS, and
  # is no named local — so record it as a live accumulator for the duration.
  # Save/restore (not unconditional excl) so a nested `genInto` into the same reg
  # (SU swap / operandInReg) keeps it protected.
  let protect = dest in StagingCandidates and dest notin g.liveAccums
  if protect: g.liveAccums.incl dest
  case c.kind
  of IntLit, UIntLit, CharLit, Symbol:
    g.place(g.genVal(c), dest)               # literal / register-resident local
  of StrLit:                                 # string literal → rodata + RIP-relative lea
    let nm = "msg." & $g.rodata.len
    g.rodata.add (nm, strVal(c)); inc c
    g.ab.tree LeaX64:
      g.emReg dest
      g.ab.sym nm                            # `(lea dest msg.N)` → nifasm RIP-relative
  of TagLit:
    case c.exprKind
    of AddC: g.genBin(c, dest, AddX64, immOk = true)
    of SubC: g.genBin(c, dest, SubX64, immOk = true)
    of MulC: g.genBin(c, dest, ImulX64, immOk = false)
    of BitandC: g.genBin(c, dest, AndX64, immOk = true)
    of BitorC: g.genBin(c, dest, OrX64, immOk = true)
    of BitxorC: g.genBin(c, dest, XorX64, immOk = true)
    of DivC, ModC:
      let wantRemainder = c.exprKind == ModC
      var tc = c; inc tc                      # the result-type child
      g.genDivMod(c, dest, signed = isSignedType(tc), wantRemainder = wantRemainder)
    of ShlC:
      g.genBin(c, dest, ShlX64, immOk = true)
    of ShrC:                                  # arithmetic for signed, logical for unsigned
      var tc = c; inc tc
      g.genBin(c, dest, (if isSignedType(tc): SarX64 else: ShrX64), immOk = true)
    of NegC:
      c.into:
        skip c                                # type
        g.genInto(c, dest)
        g.ab.tree NegX64: g.emReg dest
    of BitnotC:
      c.into:
        skip c                                # type
        g.genInto(c, dest)
        g.ab.tree NotX64: g.emReg dest        # x86 has a real `not`
    of NotC:                                  # boolean not: a ∈ {0,1} → a xor 1
      c.into:
        g.genInto(c, dest)
        g.binImm(XorX64, dest, 1)
    of EqC, NeqC, LtC, LeC, AndC, OrC:
      g.materializeCond(c, dest)
    of ConvC: g.genCoerce(c, dest, isCast = false)
    of CastC: g.genCoerce(c, dest, isCast = true)
    of DotC, AtC, DerefC:                     # field / element / pointer load: dest ← [mem]
      g.place(g.genVal(c), dest)
    of AddrC:                                 # (addr lvalue) → dest ← &lvalue
      c.into:
        g.genAddr(c, dest)
        while c.hasMore: skip c               # (cppref)?
    of CallC:
      g.genCall(c)
      g.movReg(dest, RAX)
    of TrueC: g.movImm(dest, 1); skip c       # boolean / nil literals → immediate
    of FalseC: g.movImm(dest, 0); skip c
    of NilC: g.movImm(dest, 0); skip c
    of SufC, ParC:                            # `(suf v "type")` / `(par v)` wrap one value
      c.into:
        g.genInto(c, dest)
        while c.hasMore: skip c                # the type suffix / trailing tokens
    of SizeofC:                               # compile-time constant: the type's byte size
      c.into:
        g.movImm(dest, typeSizeAlign(g.prog, c)[0].int64)
        while c.hasMore: skip c
    else: raiseAssert "arkham x64 v0: expression not supported: " & $c.exprKind
  else: raiseAssert "arkham x64 v0: operand not supported: " & $c.kind
  if protect: g.liveAccums.excl dest

proc genAddr(g: var CodeGen; c: var Cursor; dest: Reg) =
  ## `dest ← &lvalue`. Parse the addressing mode once, then form the address.
  let loc = g.asLoc(c)
  g.emitAddrLoc(loc, dest)

# ── conditions / branches ────────────────────────────────────────────────────

proc emitCmpBranch(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## `c` is a comparison `(op a b)` (NO type child): `cmp a, b` then a `jcc` to
  ## `toLabel` when the condition is true/false. Ordering signedness comes from
  ## the first operand's slot (an unsigned operand → an unsigned condition).
  let ek = c.exprKind
  var tag: X64Inst
  c.into:
    if g.isFloatExpr(c):
      # `comisd a, b` sets CF/ZF like an unsigned compare, so ordered </<= map to
      # the below/below-or-equal conditions (NaN makes them spuriously true, but
      # NIFC's compares assume non-NaN, matching the A64 backend).
      let fbits = g.floatBits(c)
      tag =
        case ek
        of EqC:  (if whenTrue: JeX64 else: JneX64)
        of NeqC: (if whenTrue: JneX64 else: JeX64)
        of LtC:  (if whenTrue: JbX64 else: JaeX64)
        of LeC:  (if whenTrue: JbeX64 else: JaX64)
        else: raiseAssert "arkham x64 v0: float condition not supported: " & $ek
      let (fa, fat) = g.genFReg(c, fbits)
      let (fb, fbt) = g.genFReg(c, fbits)
      let op = if fbits == 32: ComissX64 else: ComisdX64
      g.ab.tree op: g.emFReg fa; g.emFReg fb
      if fbt: g.giveBackF fb
      if fat: g.giveBackF fa
    else:
      var signed = true
      if c.kind == Symbol and g.ra.locationOfSym(symName(c)).typ.kind == AUInt:
        signed = false
      tag =
        case ek
        of EqC:  (if whenTrue: JeX64 else: JneX64)
        of NeqC: (if whenTrue: JneX64 else: JeX64)
        of LtC:  (if whenTrue: (if signed: JlX64 else: JbX64)
                  else:        (if signed: JgeX64 else: JaeX64))
        of LeC:  (if whenTrue: (if signed: JleX64 else: JbeX64)
                  else:        (if signed: JgX64 else: JaX64))
        else: raiseAssert "arkham x64 v0: condition not supported: " & $ek
      let (ar, aOwns) = g.forceReg(g.genVal(c))   # a must be in a register for cmp
      # `a` is now live in `ar` across `b`'s evaluation; seal it so a scratch
      # steal during `b` cannot evict it (it may be a register-local).
      let arWasSealed = g.ra.isSealed(ar)
      g.ra.seal ar
      let bv = g.genVal(c)
      if not arWasSealed: g.ra.unseal {ar}
      # `b` need not occupy a register: x86 `cmp` folds an immediate or a memory
      # operand directly (`cmp ar, imm` / `cmp ar, [mem]`), like `binMem`. Forcing
      # a spilled/memory `b` into a fresh temp here was the source of the scratch-
      # pool exhaustion on deep conditions.
      var bTmps: seq[Reg] = @[]
      g.ab.tree CmpX64:
        g.emReg ar
        if bv.kind == Imm and bv.ival >= 0 and bv.ival <= 0xFFFF:
          g.ab.intLit bv.ival
        elif bv.kind == InReg:
          g.emReg bv.r
          if bv.owns: bTmps.add bv.r
        elif bv.kind in {NamedStack, Mem}:
          bTmps = g.emMemOperandLoc(bv)           # cmp ar, [mem] — folded, no extra reg
        else:                                     # large/negative immediate → load it
          let (t, owns) = g.forceReg(bv)
          g.emReg t
          if owns: bTmps.add t
      for t in bTmps: g.giveBack t
      if aOwns: g.giveBack ar
  g.emJcc(tag, toLabel)

proc emitCondJump(g: var CodeGen; c: var Cursor; toLabel: string; whenTrue: bool) =
  ## Short-circuit conditional jump (and/or/not, comparisons, plain bool value).
  if c.kind == TagLit:
    case c.exprKind
    of AndC:
      c.into:
        if whenTrue:
          let lSkip = g.freshLabel()
          g.emitCondJump(c, lSkip, false)
          g.emitCondJump(c, toLabel, true)
          g.emLab(lSkip)
        else:
          g.emitCondJump(c, toLabel, false)
          g.emitCondJump(c, toLabel, false)
      return
    of OrC:
      c.into:
        if whenTrue:
          g.emitCondJump(c, toLabel, true)
          g.emitCondJump(c, toLabel, true)
        else:
          let lSkip = g.freshLabel()
          g.emitCondJump(c, lSkip, true)
          g.emitCondJump(c, toLabel, false)
          g.emLab(lSkip)
      return
    of NotC:
      c.into:
        g.emitCondJump(c, toLabel, not whenTrue)
      return
    of EqC, NeqC, LtC, LeC:
      g.emitCmpBranch(c, toLabel, whenTrue)
      return
    else: discard
  # plain boolean value: branch on `v != 0` / `v == 0`
  let (r, t) = g.forceReg(g.genVal(c))
  g.ab.tree CmpX64: (g.emReg r; g.ab.intLit 0)
  g.emJcc(if whenTrue: JneX64 else: JeX64, toLabel)
  if t: g.giveBack r

# ── calls ─────────────────────────────────────────────────────────────────────

proc externCName(g: var CodeGen; asmName: string): string =
  for ex in g.prog.externOrder:
    if ex.asmName == asmName:
      result = ex.extName
      if result.len > 0 and result[0] == '_': result = result[1 .. ^1]  # strip Darwin '_'
      return
  result = ""

# libc functions arkham lowers to raw Linux/x86-64 syscalls — nifasm's ELF backend
# is static (no dynamic linker / PLT), so an `importc`'d libc call is served by the
# kernel directly. The C ABI arg registers (rdi, rsi, rdx, …) already match the
# syscall ABI for ≤3 args; the 4th syscall arg is r10 (not rcx), handled by the
# dedicated arg-register list in `genCall`.
const LinuxSyscalls = {
  "read": 0, "write": 1, "open": 2, "close": 3, "exit": 60, "exit_group": 231}

proc linuxSyscallNr(name: string): int =
  for (n, nr) in LinuxSyscalls:
    if n == name: return nr
  result = -1

# ── atomic builtins (GCC `__atomic_*` → x86 lock-prefixed instructions) ──────
# x86-64 has a strong memory model: a plain aligned `mov` is already an atomic
# load/store, `xchg` with memory is implicitly locked, and an RMW that returns the
# old value uses `lock xadd` / a `lock cmpxchg` retry loop. The `memorder` arg is
# ignored (all sequences are at least acquire/release), matching the A64 backend.
# Inside a sequence there are no calls, so RAX/RCX/RDX (not in the allocator pool)
# are free scratch; the result lands in RAX (the integer return register).

proc genReg(g: var CodeGen; c: var Cursor): tuple[r: Reg, owns: bool] =
  var d = dontCare                            # dont-care: gen writes back where it landed
  g.gen(c, d)
  g.forceReg(d)

proc emMemAt(g: var CodeGen; p: Reg) =        # `(mem p)` — dereference the pointer in p
  g.ab.tree MemX: g.emReg p

proc genAtomicXadd(g: var CodeGen; pReg, val: Reg; returnNew, sub: bool) =
  ## `lock xadd [p], val` (val ← old). For `sub`, negate val first so memory is
  ## decremented. `returnNew` recomputes old±delta into rax; otherwise returns old.
  if returnNew: g.movReg(RDX, val)            # save the original delta (non-pool scratch)
  if sub:
    g.ab.tree NegX64: g.emReg val             # val ← -val
  g.ab.tree LockX64:
    g.ab.tree XaddX64:
      g.emMemAt pReg
      g.emReg val                              # val ← old; [p] += val
  if returnNew:
    let op = if sub: SubX64 else: AddX64
    g.ab.tree op: g.emReg val; g.emReg RDX     # new = old ± delta
  g.movReg(RAX, val)

proc genAtomicLoopRmw(g: var CodeGen; pReg, val: Reg; op: X64Inst) =
  ## `rax = [p]; loop: rdx = rax op val; lock cmpxchg [p], rdx; jne loop`. There
  ## is no lock-fetch form for and/or/xor that yields the old value, so spin on
  ## cmpxchg. Result (old) ends up in rax.
  let lab = g.freshLabel()
  g.ab.tree MovX64: (g.emReg RAX; g.emMemAt pReg)   # rax = [p]
  g.emLab(lab)
  g.movReg(RDX, RAX)
  g.ab.tree op: g.emReg RDX; g.emReg val             # rdx = rax op val (the new value)
  g.ab.tree LockX64:
    g.ab.tree CmpxchgX64:
      g.emMemAt pReg
      g.emReg RDX                                     # if [p]==rax: [p]=rdx else rax=[p]
  g.emJcc(JneX64, lab)                                # retry until cmpxchg succeeds

proc genAtomic(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower one `__atomic_*` builtin; `c` is at the first argument. Result → rax.
  case builtin
  of "__atomic_load_n":                        # (ptr, memorder) → *ptr
    let (p, pT) = g.genReg(c); skip c
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt p)
    if pT: g.giveBack p
  of "__atomic_store_n":                        # (ptr, val, memorder) → void
    let (p, pT) = g.genReg(c)
    let (v, vT) = g.genReg(c); skip c
    g.ab.tree MovX64: (g.emMemAt p; g.emReg v)
    if vT: g.giveBack v
    if pT: g.giveBack p
  of "__atomic_clear":                          # (ptr, memorder) → void; *ptr = 0
    let (p, pT) = g.genReg(c); skip c
    g.movImm(RDX, 0)
    g.ab.tree MovX64: (g.emMemAt p; g.emReg RDX)
    if pT: g.giveBack p
  of "__atomic_thread_fence":                   # (memorder) → void
    skip c
    g.ab.keyword MfenceX64
  of "__atomic_signal_fence":                   # (memorder) → void; compiler barrier only
    skip c
  of "__atomic_exchange_n":                     # (ptr, val, memorder) → old
    let (p, pT) = g.genReg(c)
    let (v, vT) = g.genReg(c); skip c
    g.ab.tree XchgX64: (g.emMemAt p; g.emReg v)  # v ↔ [p] (implicitly locked); v ← old
    g.movReg(RAX, v)
    if vT: g.giveBack v
    if pT: g.giveBack p
  of "__atomic_fetch_add", "__atomic_fetch_sub",
     "__atomic_add_fetch", "__atomic_sub_fetch",
     "__atomic_fetch_and", "__atomic_fetch_or", "__atomic_fetch_xor":
    let (p, pT) = g.genReg(c)
    let (v, vT) = g.genReg(c); skip c
    case builtin
    of "__atomic_fetch_add": g.genAtomicXadd(p, v, returnNew = false, sub = false)
    of "__atomic_fetch_sub": g.genAtomicXadd(p, v, returnNew = false, sub = true)
    of "__atomic_add_fetch": g.genAtomicXadd(p, v, returnNew = true, sub = false)
    of "__atomic_sub_fetch": g.genAtomicXadd(p, v, returnNew = true, sub = true)
    of "__atomic_fetch_and": g.genAtomicLoopRmw(p, v, AndX64)
    of "__atomic_fetch_or":  g.genAtomicLoopRmw(p, v, OrX64)
    of "__atomic_fetch_xor": g.genAtomicLoopRmw(p, v, XorX64)
    else: discard
    if vT: g.giveBack v
    if pT: g.giveBack p
  of "__atomic_test_and_set":                   # (ptr, memorder) → bool (old != 0)
    let (p, pT) = g.genReg(c); skip c
    g.movImm(RDX, 1)
    g.ab.tree XchgX64: (g.emMemAt p; g.emReg RDX)   # rdx ← old; [p] = 1
    let lSkip = g.freshLabel()
    g.movImm(RAX, 0)
    g.ab.tree CmpX64: (g.emReg RDX; g.ab.intLit 0)
    g.emJcc(JeX64, lSkip)
    g.movImm(RAX, 1)
    g.emLab(lSkip)
    if pT: g.giveBack p
  of "__atomic_compare_exchange_n":             # (ptr, exp_ptr, des, weak, succ, fail) → bool
    let (p, pT) = g.genReg(c)
    let (ep, eT) = g.genReg(c)
    g.genInto(c, RCX)                            # desired → rcx (non-pool scratch)
    skip c; skip c; skip c                       # weak, success order, failure order
    g.ab.tree MovX64: (g.emReg RAX; g.emMemAt ep)   # rax = *exp (the comparand)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt p
        g.emReg RCX                              # if [p]==rax: [p]=rcx,ZF=1 else rax=[p],ZF=0
    let lFail = g.freshLabel()
    let lDone = g.freshLabel()
    g.emJcc(JneX64, lFail)
    g.movImm(RAX, 1); g.emJmp(lDone)             # success → 1
    g.emLab(lFail)
    g.ab.tree MovX64: (g.emMemAt ep; g.emReg RAX)   # *exp = actual old value (rax)
    g.movImm(RAX, 0)                             # failure → 0
    g.emLab(lDone)
    if eT: g.giveBack ep
    if pT: g.giveBack p
  else:
    raiseAssert "arkham x64 v0: unsupported atomic builtin: " & builtin

# ── mem* intrinsics: inline byte loops (no libc) ─────────────────────────────
# memcpy/memmove/memset/memcmp masquerade as importc calls (see programs.collect).
# arkham has no C runtime, so each lowers to a short inline byte loop. Sizes are
# runtime values; the result lands in RAX (memcpy/memmove/memset return dest,
# memcmp the first byte difference). Unlike the AArch64 backend these can't use
# the 2-register scratch pool (it can't hold dst+src+n+i+b at once), so — like the
# atomics — they evaluate operands into fixed caller-saved registers (rdi/rsi/rdx/
# rcx/r8): free scratch since a mem* sequence contains no calls.

proc emByteAt(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 8)) base) idx))` — the byte at `base[idx]`. The cast
  ## types the raw register as a byte-array pointer so nifasm sizes the access to
  ## one byte (a load zero-extends into the 64-bit register, a store writes the
  ## low byte only — see `intMemAccess` in the assembler).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg base
      g.emReg idx

proc emLoadByte(g: var CodeGen; dest, base, idx: Reg) =
  g.ab.tree MovX64: (g.emReg dest; g.emByteAt(base, idx))

proc emStoreByte(g: var CodeGen; base, idx, src: Reg) =
  g.ab.tree MovX64: (g.emByteAt(base, idx); g.emReg src)

proc emCmpReg(g: var CodeGen; a, b: Reg) =
  g.ab.tree CmpX64: (g.emReg a; g.emReg b)

proc genMemIntrin(g: var CodeGen; c: var Cursor; builtin: string) =
  ## Lower one `mem*` intrinsic call. `c` is at the first argument; this consumes
  ## all of them. Result → RAX.
  case builtin
  of "memcpy":                                 # (dst, src, n) → dst
    g.genInto(c, RDI); g.genInto(c, RSI); g.genInto(c, RDX)   # dst, src, n
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)                      # i >= n (unsigned) → done
    g.emLoadByte(RAX, RSI, RCX)                # b = src[i]
    g.emStoreByte(RDI, RCX, RAX)               # dst[i] = b
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(done)
    g.movReg(RAX, RDI)                         # memcpy returns dest
  of "memmove":                                # (dst, src, n) → dst; overlap-safe
    g.genInto(c, RDI); g.genInto(c, RSI); g.genInto(c, RDX)   # dst, src, n
    let fwd = g.freshLabel()
    let bwd = g.freshLabel()
    let done = g.freshLabel()
    g.emCmpReg(RDI, RSI)
    g.emJcc(JbeX64, fwd)                        # dst <= src → forward copy is safe
    # backward: i = n; while i != 0: i -= 1; dst[i] = src[i]
    g.movReg(RCX, RDX)                          # i = n
    g.emLab(bwd)
    g.ab.tree CmpX64: (g.emReg RCX; g.ab.intLit 0)
    g.emJcc(JeX64, done)
    g.binImm(SubX64, RCX, 1)
    g.emLoadByte(RAX, RSI, RCX)
    g.emStoreByte(RDI, RCX, RAX)
    g.emJmp(bwd)
    # forward: i = 0; while i < n: dst[i] = src[i]; i += 1
    g.emLab(fwd)
    g.movImm(RCX, 0)
    let fwdLoop = g.freshLabel()
    g.emLab(fwdLoop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)
    g.emLoadByte(RAX, RSI, RCX)
    g.emStoreByte(RDI, RCX, RAX)
    g.binImm(AddX64, RCX, 1)
    g.emJmp(fwdLoop)
    g.emLab(done)
    g.movReg(RAX, RDI)
  of "memset":                                 # (dst, val, n) → dst
    g.genInto(c, RDI); g.genInto(c, RSI); g.genInto(c, RDX)   # dst, val, n
    let loop = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, done)
    g.emStoreByte(RDI, RCX, RSI)               # dst[i] = low byte of val
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(done)
    g.movReg(RAX, RDI)
  of "memcmp":                                 # (a, b, n) → first byte difference
    g.genInto(c, RDI); g.genInto(c, RSI); g.genInto(c, RDX)   # pa, pb, n
    let loop = g.freshLabel()
    let diff = g.freshLabel()
    let equal = g.freshLabel()
    let done = g.freshLabel()
    g.movImm(RCX, 0)                           # i = 0
    g.emLab(loop)
    g.emCmpReg(RCX, RDX)
    g.emJcc(JaeX64, equal)                     # ran off the end, no diff → 0
    g.emLoadByte(RAX, RDI, RCX)                # ba = a[i] (zero-extended, 0..255)
    g.emLoadByte(R8, RSI, RCX)                 # bb = b[i]
    g.emCmpReg(RAX, R8)
    g.emJcc(JneX64, diff)
    g.binImm(AddX64, RCX, 1)
    g.emJmp(loop)
    g.emLab(diff)                              # bytes are 0..255 → signed sub gives sign
    g.binReg(SubX64, RAX, R8)                  # rax = ba - bb
    g.emJmp(done)
    g.emLab(equal)
    g.movImm(RAX, 0)
    g.emLab(done)
  else:
    raiseAssert "arkham x64 v0: unsupported mem intrinsic: " & builtin

# ── by-value aggregate marshalling (SysV) ────────────────────────────────────
# A ≤16-byte aggregate of full 8-byte fields travels in 1–2 GPRs (word i ↔ the
# field at byte offset 8·i); a >16-byte aggregate is passed/returned by reference
# (a pointer). This is self-consistent arkham↔arkham — NOT strict SysV, which
# would pass a >16B argument as a stack copy (MEMORY class) and return it via a
# hidden pointer in the first integer arg. A ≤16B result travels in rax:rdx.

const x64RetRegs = [RAX, RDX]   # SysV ≤16B aggregate result: rax (word 0), rdx (word 1)

proc emStackAddr(g: var CodeGen; dest: Reg; name: string) =   # dest ← &stackvar
  g.ab.tree LeaX64: (g.emReg dest; g.ab.reg RSP; g.ab.sym name)

proc freshAggrTemp(g: var CodeGen; typeName: string): string =
  ## Declare a fresh nifasm-managed aggregate stack slot `(var :ctmp.N (s) T)`
  ## and return its name — a place to materialize an inline constructor whose
  ## result an aggregate-by-value ABI then reads from memory.
  result = "ctmp." & $g.spillCount & ".0"; inc g.spillCount
  g.emStackVar(result, typeName)
  g.varType[result] = typeName

proc emPtrFieldMem(g: var CodeGen; ptrReg: Reg; typeName, field: string) =
  ## `(mem (dot (cast (ptr T) reg) field))` — a field through a register holding a
  ## pointer to the aggregate (a >16B by-ref param / the indirect-result buffer).
  ## The cast types the bare register so nifasm can compute the field offset.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.ab.sym typeName
        g.emReg ptrReg
      g.ab.sym field

proc emAggrFieldMem(g: var CodeGen; base, field: string) =
  ## Field memory operand for aggregate `base`: a `(s)` stack struct → direct dot;
  ## a pointer in a register (a by-ref param) → through the pointer.
  let loc = g.ra.locationOfSym(base)
  case loc.kind
  of NamedStack: g.emFieldMem(base, field)
  of InReg:      g.emPtrFieldMem(loc.r, g.varType[base], field)
  else:
    # a synthetic nifasm `(s)` slot (e.g. a constructor temp) is rsp-relative by
    # name, just like a `NamedStack` var — the allocator simply doesn't track it.
    if g.varType.hasKey(base): g.emFieldMem(base, field)
    else: raiseAssert "arkham x64 v0: aggregate base neither stack nor pointer: " & base

proc genConstr(g: var CodeGen; c: var Cursor; dstPtr: Reg) =
  ## The single destination-passing constructor emitter: materialize
  ## `(oconstr T (kv field value)*)` into the aggregate `dstPtr` points at,
  ## storing each field at its offset. The constructed type is read from the
  ## constructor itself, so every caller (var-init, assignment, call argument)
  ## just supplies a destination address. Consumes `c`.
  assert c.exprKind == OconstrC,
    "arkham x64 v0: runtime (aconstr …) not supported (constant arrays go to rodata)"
  var tc = c; inc tc                           # the constructed type symbol
  let typeName = symName(tc)
  c.into:
    skip c                                     # the constructed type
    while c.hasMore:
      assert c.substructureKind == KvU, "arkham x64 v0: oconstr expects (kv …)"
      c.into:
        let field = symName(c); inc c
        let (r, owns) = g.forceReg(g.genVal(c))
        g.ab.tree MovX64: (g.emPtrFieldMem(dstPtr, typeName, field); g.emReg r)
        if owns: g.giveBack r
        while c.hasMore: skip c                 # optional inherited-depth INTLIT

proc structToRegs(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## aggregate → regs[i] (one GPR per 8-byte word).
  let lay = aggrLayout(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham x64 v0: sub-word-packed aggregate ABI unsupported"
    g.ab.tree MovX64: (g.emReg regs[i]; g.emAggrFieldMem(varName, fn))

proc regsToStruct(g: var CodeGen; varName, typeName: string; regs: openArray[Reg]) =
  ## regs[i] → aggregate (one GPR per 8-byte word).
  let lay = aggrLayout(g.prog, typeName)
  for i in 0 ..< aggrWordCount(g.prog, typeName):
    let fn = fieldAtOffset(lay, i * 8)
    if fn.len == 0: raiseAssert "arkham x64 v0: sub-word-packed aggregate ABI unsupported"
    g.ab.tree MovX64: (g.emAggrFieldMem(varName, fn); g.emReg regs[i])

proc copyStructThroughPtr(g: var CodeGen; srcVar, typeName: string; ptrReg: Reg) =
  ## field-wise copy of aggregate `srcVar` → the memory `ptrReg` points at.
  for f in aggrLayout(g.prog, typeName):
    let t = g.borrowTmp()
    g.ab.tree MovX64: (g.emReg t; g.emAggrFieldMem(srcVar, f.name))
    g.ab.tree MovX64: (g.emPtrFieldMem(ptrReg, typeName, f.name); g.emReg t)
    g.giveBack t

proc genCall(g: var CodeGen; c: var Cursor) =
  ## `(call f arg…)`. The C `exit` extern lowers to the Linux exit syscall; a
  ## declarative user proc uses the SysV register ABI via a `(prepare …)` block
  ## (args → rdi/rsi/…, result ← rax). Each committed arg register is sealed so
  ## marshalling can't clobber it.
  c.into:
    let fsym = symName(c); inc c
    if not g.callTarget.hasKey(fsym):
      # A call into another module: resolve its signature from the owning
      # module's embedded index and cache it. nifasm auto-imports the foreign
      # `<module>.s.nif` and links the definition.
      g.callTarget[fsym] = foreignCallTarget(g.prog, fsym)
    let tgt = g.callTarget[fsym]
    let sysNr = if tgt.extern: linuxSyscallNr(g.externCName(tgt.asmName)) else: -1
    if tgt.atomic.len > 0:                     # GCC `__atomic_*` builtin → inline
      g.genAtomic(c, tgt.atomic)               # consumes the args; result in rax
    elif tgt.memIntrin.len > 0:                # C mem* intrinsic → inline byte loop
      g.genMemIntrin(c, tgt.memIntrin)         # consumes the args; result in rax
    elif sysNr >= 0:
      # Lower to a raw Linux syscall: args in the syscall ABI registers, number
      # in rax, `syscall`. The result lands in rax (used by the `CallC` path in
      # `genInto`; discarded at statement level).
      const SyscallArgRegs = [RDI, RSI, RDX, R10, R8, R9]
      var idx = 0
      while c.hasMore:
        if idx >= SyscallArgRegs.len:
          raiseAssert "arkham x64 v0: syscall with more than 6 arguments"
        g.genInto(c, SyscallArgRegs[idx]); inc idx
      g.movImm(RAX, sysNr.int64)
      g.emSyscall()
    elif tgt.declarative and not tgt.extern:
      var sealedHere: set[Reg] = {}
      var argCurs: seq[Cursor] = @[]           # one cursor per argument expression
      while c.hasMore: (argCurs.add c; skip c)
      let nReg = min(argCurs.len, g.md.intArgRegs.len)
      let nStack = argCurs.len - nReg          # 7th+ args go through the stack
      g.ab.tree PrepareX64:
        g.ab.sym tgt.asmName
        # Phase 1 — register args → rdi…r9, each bound to the callee's param and
        # sealed so later marshalling can't clobber it. Evaluated before rsp moves.
        for idx in 0 ..< nReg:
          var a = argCurs[idx]
          if g.isFloatExpr(a): raiseAssert "arkham x64 v0: float call argument"
          let ar = g.md.intArgRegs[idx]
          g.genInto(a, ar)
          g.ab.tree MovX64:                    # bind it to the callee's param p.idx
            g.ab.tree ArgX: g.ab.sym paramName(idx)
            g.emReg ar
          g.ra.seal ar; sealedHere.incl ar
        # Phase 2 — reserve the outgoing stack area (`csize` keeps rsp 16-aligned),
        # then evaluate each stack arg into a reused temp and store it; nifasm
        # resolves `(arg p.k)` to its byte offset. x64 has only two scratch GPRs,
        # so args are materialized one at a time rather than all held at once —
        # hence the evaluation happens after the `sub rsp`, which is fine for the
        # literals/register locals the flattener leaves (an rsp-relative stack
        # local would read at the wrong offset and is rejected below).
        if nStack > 0:
          g.ab.tree SubX64: g.ab.reg RSP; g.ab.keyword CsizeX
          for k in 0 ..< nStack:
            let idx = nReg + k
            var a = argCurs[idx]
            if g.isFloatExpr(a): raiseAssert "arkham x64 v0: float call argument"
            if a.kind == Symbol and
               g.ra.locationOfSym(symName(a)).kind in {NamedStack, OnStack}:
              raiseAssert "arkham x64 v0: rsp-relative local as a stack call argument"
            let t = g.borrowTmp()
            g.genInto(a, t)
            g.ab.tree MovX64:
              g.ab.tree MemX:
                g.ab.reg RSP
                g.ab.tree ArgX: g.ab.sym paramName(idx)
              g.emReg t
            g.giveBack t
        g.ab.keyword CallX64
        if nStack > 0:
          g.ab.tree AddX64: g.ab.reg RSP; g.ab.keyword CsizeX
        if not retIsVoid(tgt.retType):
          g.ab.tree MovX64:
            g.emReg RAX
            g.ab.tree ResX: g.ab.sym "ret.0"
      g.ra.unseal sealedHere
    else:
      # Non-declarative ABI: marshal args by hand (aggregates / by-ref), then a
      # bare `(prepare f (call))` (the callee's signature is empty). The scalar
      # result lands in rax (read by the CallC path in `genInto`).
      var idx = 0
      var fidx = 0
      var sealedHere: set[Reg] = {}
      while c.hasMore:
        if g.isFloatExpr(c):
          # A float argument goes in xmm{fidx}. The float arg registers (xmm0–7)
          # are disjoint from the GPR scratch pool and from the xmm scratch temps
          # (xmm8–15) a later float arg's evaluation uses, so no sealing is needed.
          assert fidx < g.md.floatArgRegs.len, "arkham x64 v0: >8 float args (stack TODO)"
          g.genIntoF(c, g.md.floatArgRegs[fidx], g.floatBits(c))
          inc fidx
        elif c.kind == Symbol and g.varType.hasKey(symName(c)):
          let vn = symName(c)
          let tn = g.varType[vn]
          if aggrByteSize(g.prog, tn) > g.md.aggrByRefThreshold:
            # >16B → by reference: pass a pointer to it in the next arg reg.
            assert idx < g.md.intArgRegs.len, "arkham x64 v0: >6 args (stack TODO)"
            let ar = g.md.intArgRegs[idx]
            let loc = g.ra.locationOfSym(vn)
            case loc.kind
            of NamedStack: g.emStackAddr(ar, vn)        # lea ar, &vn
            of InReg: g.movReg(ar, loc.r)               # already a pointer
            else: raiseAssert "arkham x64 v0: by-ref arg neither stack nor pointer: " & vn
            g.ra.seal ar; sealedHere.incl ar
            inc idx
          else:
            # ≤16B → by value: marshal its words into the next GPR(s).
            let nw = aggrWordCount(g.prog, tn)
            assert idx + nw <= g.md.intArgRegs.len, "arkham x64 v0: aggregate arg exceeds GPRs"
            g.structToRegs(vn, tn, g.md.intArgRegs[idx ..< idx + nw])
            for k in 0 ..< nw:
              g.ra.seal g.md.intArgRegs[idx + k]; sealedHere.incl g.md.intArgRegs[idx + k]
            idx += nw
          inc c
        elif c.kind == TagLit and c.exprKind in {OconstrC, AconstrC}:
          # An inline aggregate constructor: build it into a temp slot, then
          # marshal that temp like any aggregate var (by value in GPRs, or by
          # reference) — no constructor-specific ABI logic.
          var tc = c; inc tc                    # the constructed type
          let tn = symName(tc)
          let tmpName = g.freshAggrTemp(tn)
          let p = g.borrowTmp(); g.emStackAddr(p, tmpName)
          g.genConstr(c, p)                     # consumes the constructor
          g.giveBack p
          if aggrByteSize(g.prog, tn) > g.md.aggrByRefThreshold:
            assert idx < g.md.intArgRegs.len, "arkham x64 v0: >6 args (stack TODO)"
            let ar = g.md.intArgRegs[idx]
            g.emStackAddr(ar, tmpName)
            g.ra.seal ar; sealedHere.incl ar
            inc idx
          else:
            let nw = aggrWordCount(g.prog, tn)
            assert idx + nw <= g.md.intArgRegs.len, "arkham x64 v0: aggregate arg exceeds GPRs"
            g.structToRegs(tmpName, tn, g.md.intArgRegs[idx ..< idx + nw])
            for k in 0 ..< nw:
              g.ra.seal g.md.intArgRegs[idx + k]; sealedHere.incl g.md.intArgRegs[idx + k]
            idx += nw
        else:
          assert idx < g.md.intArgRegs.len, "arkham x64 v0: >6 integer args (stack TODO)"
          let ar = g.md.intArgRegs[idx]
          g.genInto(c, ar)
          g.ra.seal ar; sealedHere.incl ar
          inc idx
      g.ab.tree PrepareX64:
        g.ab.sym tgt.asmName
        g.ab.keyword CallX64
      g.ra.unseal sealedHere

# ── whole-aggregate copy (struct assignment / copy-init) ─────────────────────

proc byteCopyConst(g: var CodeGen; dst, src: Reg; size: int) =
  ## `dst[0..<size] ← src[0..<size]`, `size` a compile-time constant (the same
  ## inline byte loop as `memcpy`). Used for whole-aggregate assignment / copy-
  ## init; `dst`/`src` stay live. No calls inside, so RAX/RCX (not in the
  ## allocator pool, and never an `aggrAddr` result) are free scratch for the
  ## byte value / loop counter.
  let loop = g.freshLabel()
  let done = g.freshLabel()
  g.movImm(RCX, 0)                              # i = 0
  g.emLab(loop)
  g.ab.tree CmpX64: (g.emReg RCX; g.ab.intLit size)
  g.emJcc(JaeX64, done)                         # i >= size (unsigned) → done
  g.emLoadByte(RAX, src, RCX)                   # b = src[i]
  g.emStoreByte(dst, RCX, RAX)                  # dst[i] = b
  g.binImm(AddX64, RCX, 1)
  g.emJmp(loop)
  g.emLab(done)

proc aggrAddr(g: var CodeGen; c: var Cursor): (Reg, bool) =
  ## Address of an aggregate lvalue (consumes it). A by-reference aggregate param
  ## (InReg) already *is* the address; otherwise borrow a temp and `genAddr`.
  if c.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(c))
    if loc.kind == InReg:
      result = (loc.r, false); inc c; return
  let r = g.borrowTmp()
  g.genAddr(c, r)
  result = (r, true)

proc genStore(g: var CodeGen; c: var Cursor; dst: Location) =
  ## Destination-passing store: emit expression `c` so its value lands at `dst`,
  ## consuming `c`. An aggregate is built/copied in place; every scalar and float
  ## store goes through the unified `gen`, which selects register vs memory vs the
  ## float path purely from `dst`'s kind/type. Callers (`genAsgn`, var-init) just
  ## hand it a `dst`.
  if dst.typ.kind == AMem:                       # aggregate destination
    let (dp, downs) = g.addrOfLoc(dst)
    if c.kind == TagLit and c.exprKind in {OconstrC, AconstrC}:
      g.genConstr(c, dp)                          # build the aggregate in place
    else:                                         # copy from another aggregate lvalue
      let (sp, sowns) = g.aggrAddr(c)
      g.byteCopyConst(dp, sp, dst.typ.size)
      if sowns: g.giveBack sp
    if downs: g.giveBack dp
  else:                                           # scalar / float → the one entry point
    var d = dst; g.gen(c, d)

# ── statements ─────────────────────────────────────────────────────────────────

proc genStmt(g: var CodeGen; c: var Cursor)

proc genVarDecl(g: var CodeGen; c: var Cursor) =
  c.into:
    let name = symName(c); inc c
    skip c                                    # pragmas
    g.symType[name] = c                       # record the type for getType
    let typeCur = c
    skip c                                    # type
    let loc = g.ra.locationOfSym(name)
    case loc.kind
    of InReg:
      g.emRegLocalVar(name, loc.r, typeCur)   # (var :name (reg) type) — typed for nifasm
      if c.hasMore and c.kind != DotToken:
        var d = loc; g.gen(c, d)              # init value → the local's register
    of InFReg:                                # float local in an xmm register
      if c.hasMore and c.kind != DotToken:
        var d = loc; g.gen(c, d)
    of NamedStack:
      if loc.typ.kind == AFloat:              # a spilled float scalar
        let bits = loc.typ.size * 8
        g.emFloatStackVar(name, bits)
        if c.hasMore and c.kind != DotToken:
          let f = g.borrowFTmp()
          g.genIntoF(c, f, bits)
          g.emFloatScalarStore(name, f, bits)
          g.giveBackF f
      elif loc.typ.kind == AMem:              # an aggregate stack object
        g.ab.open NifasmDecl.VarD             # (var :name (s) <type>)
        g.ab.symDef name
        g.ab.keyword SO
        var tc = typeCur                      # named type ref, or inline structural type
        if tc.kind == Symbol: g.ab.sym symName(tc)
        else: g.genTypeBody(tc)               # e.g. an inline `(array (i N) len)`
        g.ab.close()
        if tc.kind == Symbol: g.varType[name] = symName(tc)  # object field-offset lookups
        if c.hasMore and c.kind != DotToken:
          if c.kind == TagLit and c.exprKind == CallC:
            # receive an aggregate return value into this var's slot (the callee
            # writes it, so this can't go through the generic `genStore`).
            assert tc.kind == Symbol, "arkham x64 v0: call-returned aggregate needs a named type"
            let typeName = symName(tc)
            if aggrByteSize(g.prog, typeName) > g.md.aggrByRefThreshold:
              # >16B: hand the callee a pointer to this var via rdi; it writes there.
              g.emStackAddr(RDI, name)
              g.genCall(c)
            else:
              g.genCall(c)                     # result in rax:rdx
              g.regsToStruct(name, typeName, x64RetRegs)
          else:                                # construct in place / copy from an lvalue
            g.genStore(c, namedStackLoc(name, loc.typ))
      else:                                   # a spilled / address-taken scalar
        g.emScalarStackVar(name)              # (var :name (s) (i 64))
        if c.hasMore and c.kind != DotToken:
          var d = loc; g.gen(c, d)            # init value → the slot (NamedStack store)
    else: raiseAssert "arkham x64 v0: local '" & name & "' has location " & $loc.kind
    while c.hasMore: skip c

proc genAsgn(g: var CodeGen; c: var Cursor) =
  c.into:
    let dst = g.asLoc(c)                        # lhs → the destination location ("fills")
    g.genStore(c, dst)                          # rhs value into it ("binds")
    while c.hasMore: skip c

proc genWhile(g: var CodeGen; c: var Cursor) =
  let lStart = g.freshLabel()
  let lEnd = g.freshLabel()
  g.loopEnds.add lEnd
  c.into:
    let condStart = c
    skip c                                    # `c` → first body statement
    g.emLab(lStart)
    var cond = condStart
    g.emitCondJump(cond, lEnd, whenTrue = false)
    while c.hasMore: genStmt(g, c)
    g.emJmp(lStart)
  g.emLab(lEnd)
  discard g.loopEnds.pop()

proc genBreak(g: var CodeGen; c: var Cursor) =
  assert g.loopEnds.len > 0, "arkham x64 v0: `break` outside a loop"
  g.emJmp(g.loopEnds[^1])
  skip c

# ── if / case ────────────────────────────────────────────────────────────────

proc genActionStmts(g: var CodeGen; c: var Cursor) =
  ## The body of an `(elif … body)` / `(else body)` / case branch — a `(stmts …)`
  ## list (not a fresh scope) or a single statement.
  if c.stmtKind == StmtsS:
    c.into:
      while c.hasMore: genStmt(g, c)
  else:
    genStmt(g, c)

proc emitChain(g: var CodeGen; c: var Cursor; lEnd: string) =
  if not c.hasMore: return
  case c.substructureKind
  of ElifU:
    var branch = c
    skip c                                    # `c` → the rest of the chain
    let lNext = g.freshLabel()
    branch.into:
      g.emitCondJump(branch, lNext, whenTrue = false)
      g.genActionStmts(branch)
      g.emJmp(lEnd)
    g.emLab(lNext)
    g.emitChain(c, lEnd)
  of ElseU:
    c.into:
      g.genActionStmts(c)
  else:
    skip c

proc genIf(g: var CodeGen; c: var Cursor) =
  let lEnd = g.freshLabel()
  c.into:
    g.emitChain(c, lEnd)
  g.emLab(lEnd)

proc branchImm(c: var Cursor): int64 =
  ## A NIFC `BranchValue` (Number | CharLiteral | (true) | (false)); advance past it.
  case c.kind
  of IntLit:  result = intVal(c); inc c
  of UIntLit: result = cast[int64](uintVal(c)); inc c
  of CharLit: result = int64(ord(charLit(c))); inc c
  of TagLit:
    case c.exprKind
    of TrueC:  result = 1; skip c
    of FalseC: result = 0; skip c
    else: raiseAssert "arkham x64 v0: unsupported case branch value: " & $c.exprKind
  else: raiseAssert "arkham x64 v0: unsupported case branch value kind: " & $c.kind

proc cmpImm(g: var CodeGen; selReg: Reg; v: int64) =
  ## `cmp selReg, v` — immediate when small, else via a scratch register.
  if v >= 0 and v <= 0xFFFF:
    g.ab.tree CmpX64: (g.emReg selReg; g.ab.intLit v)
  else:
    let tmp = g.borrowTmp()
    g.movImm(tmp, v)
    g.ab.tree CmpX64: (g.emReg selReg; g.emReg tmp)
    g.giveBack tmp

proc emitRangeTest(g: var CodeGen; selReg: Reg; c: var Cursor;
                   lBody: string; signed: bool) =
  ## One `BranchRange` against `selReg`; jump to `lBody` on a match.
  if c.kind == TagLit and c.substructureKind == RangeU:
    c.into:
      let lo = branchImm(c)
      let hi = branchImm(c)
      let lSkip = g.freshLabel()              # match iff lo <= sel <= hi
      g.cmpImm(selReg, lo)
      g.emJcc(if signed: JlX64 else: JbX64, lSkip)
      g.cmpImm(selReg, hi)
      g.emJcc(if signed: JgX64 else: JaX64, lSkip)
      g.emJmp(lBody)
      g.emLab(lSkip)
  else:
    g.cmpImm(selReg, branchImm(c))
    g.emJcc(JeX64, lBody)

proc genCase(g: var CodeGen; c: var Cursor) =
  ## `(case Expr (of (ranges BranchRange+) StmtList)* (else StmtList)?)`. Selector
  ## → a register; each branch's tests jump to its body; a non-match falls through
  ## to `else` (or the end). NIFC `case` has no fall-through, so bodies end in a jmp.
  let lEnd = g.freshLabel()
  c.into:
    var signed = true
    if c.kind == Symbol and g.ra.locationOfSym(symName(c)).typ.kind == AUInt:
      signed = false
    let (selReg, selTemp) = g.forceReg(g.genVal(c))   # selector, live across all tests
    var bodies: seq[(string, Cursor)] = @[]
    var elseBody = c
    var hasElse = false
    while c.hasMore:
      case c.substructureKind
      of OfU:
        let lBody = g.freshLabel()
        var branch = c
        skip c
        branch.into:                          # branch → (ranges …) then StmtList
          assert branch.substructureKind == RangesU, "arkham x64: case `of` needs `ranges`"
          branch.into:
            while branch.hasMore:
              g.emitRangeTest(selReg, branch, lBody, signed)
          bodies.add (lBody, branch)
          skip branch
      of ElseU:
        elseBody = c; hasElse = true; skip c
      else: skip c
    if selTemp: g.giveBack selReg
    if hasElse:
      elseBody.into:
        g.genActionStmts(elseBody)
    g.emJmp(lEnd)
    for (lBody, bc) in bodies:
      g.emLab(lBody)
      var body = bc
      g.genActionStmts(body)
      g.emJmp(lEnd)
  g.emLab(lEnd)

proc genStmt(g: var CodeGen; c: var Cursor) =
  if c.kind == DotToken:                       # an empty statement (e.g. `(stmts .)`)
    inc c; return
  case c.stmtKind
  of ScopeS:                                  # only `scope` is a fresh scope
    g.enterScope()                            # register locals here `kill` at close
    c.into:
      while c.hasMore: genStmt(g, c)
    g.exitScope()
  of StmtsS:                                  # a statement list — not a fresh scope
    c.into:
      while c.hasMore: genStmt(g, c)
  of VarS, GvarS, TvarS, ConstS:
    genVarDecl(g, c)
  of CallS:
    genCall(g, c)
  of AsgnS:
    genAsgn(g, c)
  of WhileS:
    genWhile(g, c)
  of IfS:
    genIf(g, c)
  of CaseS:
    genCase(g, c)
  of BreakS:
    genBreak(g, c)
  of RetS:
    # The Linux entry must terminate the process; a normal proc returns in rax.
    if g.isEntryProc:
      c.into:
        if c.hasMore and c.kind != DotToken: g.genInto(c, RDI)  # exit code → rdi
        else: g.movImm(RDI, 0)
        while c.hasMore: skip c                # void `(ret .)` → drop the `.`
      g.movImm(RAX, 60)
      g.emSyscall()
    else:
      c.into:
        if c.hasMore and c.kind != DotToken:
          if g.retIndirect:
            # >16B: copy the result into the caller's buffer (parked in rbx) and
            # return its address in rax (SysV: the hidden pointer is also returned).
            assert c.kind == Symbol, "arkham x64 v0: aggregate ret value must be a local"
            g.copyStructThroughPtr(symName(c), g.retAggrName, g.indirectReg)
            g.movReg(RAX, g.indirectReg)
            inc c
          elif g.retAggrName.len > 0:         # ≤16B aggregate → rax:rdx
            assert c.kind == Symbol, "arkham x64 v0: aggregate ret value must be a local"
            g.structToRegs(symName(c), g.retAggrName, x64RetRegs)
            inc c
          elif g.retIsFloat:
            g.genIntoF(c, FloatRet, g.retFloatBits)   # float result in xmm0
          else:
            g.genInto(c, RAX)
        while c.hasMore: skip c               # void `(ret .)` → drop the `.`
      g.killFrameRegLocals()                  # release locals bound to popped regs
      g.framePop()                            # restore callee-saved before returning
      g.ab.keyword RetX64
  of LabS:                                    # `(lab :name)` — a goto target
    c.into:
      g.emLab(symName(c)); inc c
      while c.hasMore: skip c
  of JmpS:                                     # `(jmp name)` — unconditional goto
    c.into:
      g.emJmp(symName(c)); inc c
      while c.hasMore: skip c
  else:
    raiseAssert "arkham x64 v0: statement not supported: " & $c.stmtKind

# ── type + proc + module emission ───────────────────────────────────────────
# genTypeBody/genType emit nifasm `NifasmType` tags (arch-neutral). TODO: share
# with codegen_a64 by lifting these into codegen_common.

proc genPointee(g: var CodeGen; c: var Cursor) =
  ## Emit a pointer's pointee / element type. A *named* type is referenced by
  ## symbol rather than inlined: this breaks the infinite recursion of
  ## self-referential types (a `(ptr T)` field inside `T`) and lets nifasm
  ## resolve — and auto-import across modules — the type declaration by name.
  if c.kind == Symbol:
    g.ab.sym symName(c); inc c
  else:
    g.genTypeBody(c)

proc genTypeBody(g: var CodeGen; c: var Cursor) =
  ## Translate a NIFC type at `c` into asm-NIF, advancing past it. Named types
  ## are inlined; object field pragmas are dropped. v0: int/uint/bool/ptr + objects.
  case c.kind
  of Symbol:
    var d = lookupType(g.prog, symName(c))
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
      # A function pointer: 8 bytes, ABI-identical to a plain pointer. Emit an
      # opaque `(ptr (void))` and do NOT descend into the param/result types —
      # those routinely refer back to the enclosing aggregate (closures,
      # continuations), which would otherwise recurse forever.
      g.ab.ptrType: g.ab.voidType()
      skip c
    of ArrayT:
      c.into:
        g.ab.arrayType:
          g.genTypeBody(c)
          if c.kind == IntLit: (g.ab.intLit intVal(c); inc c)
          else: raiseAssert "arkham x64 v0: array length must be a literal"
    of ObjectT:
      c.into:
        skip c                                # inheritance (`.`)
        g.ab.objectType:
          while c.hasMore:
            c.into:                           # (fld :name pragmas type)
              let fn = symName(c); inc c
              skip c                          # field pragmas (dropped)
              g.ab.fldDef(fn):
                g.genTypeBody(c)
    of EnumT:                                 # an enum is just its base integer type
      c.into:
        g.genTypeBody(c)                      # (enum <base> (efld …)…) → <base>
        while c.hasMore: skip c               # efld declarations (dropped)
    else:
      raiseAssert "arkham x64 v0: type not supported: " & $c.typeKind
  else:
    raiseAssert "arkham x64 v0: malformed type"

proc genType(g: var CodeGen; name: string; decl: Cursor) =
  ## `(type :name <body>)` — nifasm's stack-slot allocator consults it for field
  ## offsets.
  var c = decl
  c.into:
    inc c                                     # name
    skip c                                    # type-pragmas
    g.ab.tree TypeD:
      g.ab.symDef name
      g.genTypeBody(c)

proc numIncomingArgRegs(g: var CodeGen; decl: Cursor): int =
  ## How many leading integer arg registers carry incoming values: a hidden
  ## result pointer (>16B return) + one per scalar / by-ref-aggregate param + one
  ## per 8-byte word of a ≤16B by-value aggregate param. These hold live values on
  ## entry, so they're excluded from the clobber set (a clobbered register can't
  ## be read — and a named local bound to one would be rejected).
  result = if g.retIndirect: 1 else: 0
  var c = decl
  inc c; inc c                                # head → name → params
  if c.kind != TagLit: return
  c.into:
    while c.hasMore:
      var tn = ""
      c.into:                                 # (param :name pragmas type)
        inc c; skip c                         # name, pragmas
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = symName(c)
        while c.hasMore: skip c
      if tn.len > 0:
        if aggrByteSize(g.prog, tn) > g.md.aggrByRefThreshold: inc result
        else: result += aggrWordCount(g.prog, tn)
      else: inc result

proc emitSignature(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## `(params)/(result)/(clobber)`. Declarative procs state the SysV register ABI
  ## — positional `p.i` params in rdi/rsi/… and an rax result — so nifasm
  ## cross-checks every call site; the clobber set is always the convention's.
  var numParams = 0
  if declarative:
    var c = decl
    c.into:
      inc c                                   # name → params slot
      g.ab.tree ParamsD:
        if c.kind == TagLit:                  # (params (param …) …)
          var idx = 0
          c.into:
            while c.hasMore:
              c.into:                         # (param :name pragmas type)
                inc c                         # name → use positional p{idx}
                skip c                        # pragmas
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  if idx < g.md.intArgRegs.len:
                    g.ab.reg g.md.intArgRegs[idx]   # rdi,rsi,rdx,rcx,r8,r9
                  else:
                    g.ab.keyword SO            # 7th+ → stack-passed `(s)` (caller marshals)
                  g.genTypeBody(c)            # the param type (consumes it)
                while c.hasMore: skip c
              inc idx
          numParams = idx
        else:
          skip c                              # no params slot
      g.ab.tree ResultD:                      # c now at the return type
        if retIsVoid(c):
          skip c
        else:
          g.ab.symDef "ret.0"
          g.ab.reg RAX
          g.genTypeBody(c)                    # the result type (consumes it)
      while c.hasMore: skip c                 # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  # The clobber set excludes the parameter registers: those hold live params on
  # entry, and nifasm treats a declared-clobbered register as clobbered there, so
  # listing them would make the body unable to read its own params. The caller
  # already accounts for the arg/result registers via the ABI.
  var paramRegs: set[Reg] = {}
  for i in 0 ..< min(g.numIncomingArgRegs(decl), g.md.intArgRegs.len):
    paramRegs.incl g.md.intArgRegs[i]
  g.ab.tree ClobberD:
    for r in x64ClobbersGpr:
      if r notin paramRegs: g.ab.reg r

proc emitParamMoves(g: var CodeGen; decl: Cursor; declarative: bool) =
  ## Settle each register-passed parameter into its allocated home. A param the
  ## allocator left in its incoming arg register becomes the named local `p.i`
  ## (x64 refers to a bound register by name); one the allocator relocated to a
  ## callee-saved register (because it lives across a call) is `mov`'d there as a
  ## *raw* register — never a named local, so the epilogue can `pop` that
  ## callee-saved reg without a "kill it first" binding conflict. Stack-passed
  ## params (7th+) are handled by `emitStackParamLoadsX64`.
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # no parameters
  var idx = if g.retIndirect: 1 else: 0       # rdi = hidden result ptr for a >16B return
  var fidx = 0                                # float params consume xmm0–7, not GPRs
  c.into:
    while c.hasMore:
      var nm = ""
      var tn = ""                             # non-empty → an aggregate param type
      var typeCur = c
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        g.symType[nm] = c                     # record the param's type for getType
        typeCur = c
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = symName(c)
        while c.hasMore: skip c
      let loc = g.ra.locationOfSym(nm)
      if tn.len > 0 and loc.kind == NamedStack:
        # ≤16B by-value aggregate: declare its `(s)` home, fill from its GPR word(s).
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        let nw = aggrWordCount(g.prog, tn)
        g.regsToStruct(nm, tn, g.md.intArgRegs[idx ..< idx + nw])
        idx += nw
      elif tn.len > 0 and loc.kind == InReg:
        # >16B by-reference aggregate: a pointer homed like a scalar; field
        # accesses route through it (recorded in varType).
        g.varType[nm] = tn
        g.movReg(loc.r, g.md.intArgRegs[idx])
        inc idx
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming xmm{fidx}; if the
        # allocator gave it a (callee-saved-equivalent) home, move it there. SysV has
        # no callee-saved xmm, so a float crossing a call instead spills (next branch).
        g.fmovF(loc.f, g.md.floatArgRegs[fidx], loc.typ.size * 8)
        inc fidx
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming xmm arg register into it so `addr`/loads/stores work.
        assert fidx < g.md.floatArgRegs.len, "arkham x64 v0: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, g.md.floatArgRegs[fidx], bits)
        inc fidx
      elif idx < g.md.intArgRegs.len:           # register-passed scalar parameter
        let argReg = g.md.intArgRegs[idx]
        if loc.kind == InReg and loc.r == argReg:
          if declarative:
            g.regLocal[argReg] = paramName(idx) # the signature binds it as `pN.0`
          else:
            # no signature binding (empty params) → bind the param's own name to
            # its arg register so the body can refer to it by name.
            g.emRegLocalVar(nm, argReg, typeCur)
            g.regLocal[argReg] = nm
        elif loc.kind == InReg:
          g.movReg(loc.r, argReg)               # relocated to a callee-saved home (raw)
        elif loc.kind == NamedStack and loc.typ.kind != AFloat:
          # an address-taken scalar param: declare its `(s)` slot and spill the
          # incoming argument register into it so `addr`/loads/stores work. In the
          # declarative path the arg reg is bound to `pN.0`, so the value must be
          # referenced by that name (a raw `(reg)` is rejected as "bound"); in the
          # non-declarative path there is no binding, so the raw register is used.
          g.emScalarStackVar(nm)                # (var :nm (s) (i 64))
          g.ab.tree MovX64:
            g.emStackMem(nm)
            if declarative: g.ab.sym paramName(idx) else: g.ab.reg argReg
        else:
          raiseAssert "arkham x64 v0: spilled / float parameter: " & nm
        inc idx
      # else: stack-passed (7th+) — loaded by emitStackParamLoadsX64.

# ── stack frame: callee-saved save/restore + incoming stack parameters ───────
# x86-64 has no pair store, so each used callee-saved GPR is a single `push`/`pop`.
# Frames are needed when the proc uses a callee-saved register (for a cross-call
# local or a stack-param home). Saved registers stay RAW (`(rbx)`), never named
# locals, so the epilogue can pop them without nifasm's bound-register guard.

proc computeFrameX64(g: var CodeGen; isEntry, hasCall: bool) =
  g.frameRegs = @[]
  for r in g.md.intCalleeSaved:
    if r in g.ra.usedCallee: g.frameRegs.add r
  # SysV requires rsp ≡ 0 (mod 16) at a `call`. The kernel enters the entry with
  # rsp ≡ 0; a normal callee is entered with rsp ≡ 8 (the caller's pushed return
  # address). Each saved reg is 8 bytes, so after the pushes the parity may be
  # wrong — pad with an extra 8 when this proc itself makes a call.
  g.framePad = 0
  if hasCall:
    let entryBias = if isEntry: 0 else: 8
    if (entryBias + 8 * g.frameRegs.len) mod 16 != 0: g.framePad = 8
  g.hasFrame = g.frameRegs.len > 0 or g.framePad > 0

proc framePushBytesX64(g: CodeGen): int =
  ## Bytes between the current rsp (after the callee-saved pushes, before the pad)
  ## and the caller's first stack argument: the return address (8) plus each saved
  ## register (8). Used to address incoming stack params.
  8 + 8 * g.frameRegs.len

proc framePush(g: var CodeGen) =
  for r in g.frameRegs:
    g.ab.tree PushX64: g.ab.reg r                          # raw push

proc killFrameRegLocals(g: var CodeGen) =
  ## Before an explicit-`ret` `framePop`, release any register-local bound to a
  ## callee-saved register the epilogue is about to `pop` raw — nifasm forbids a
  ## raw use of a still-bound register, and at a return every local is dead. The
  ## binding is dropped so the trailing `exitScope` does not double-kill it.
  ## (A second `ret` reached on another path that needs the same callee register
  ## bound is the pre-existing multi-`ret` limitation — out of scope here.)
  for r in g.frameRegs:
    if g.regLocal.hasKey(r):
      g.ab.tree KillX64: g.ab.sym g.regLocal[r]
      g.regLocal.del r

proc framePop(g: var CodeGen) =
  # Release the nifasm-managed `(s)` slot region first (reverse of the prologue,
  # which lowered rsp by the pad then the `(ssize)` block), then the alignment pad
  # and the callee-saved registers.
  if g.ra.hasStackVars:
    g.ab.tree AddX64: g.ab.reg RSP; g.ab.keyword SsizeX
  if g.framePad > 0: g.binImm(AddX64, RSP, g.framePad.int64)
  for i in countdown(g.frameRegs.high, 0):
    g.ab.tree PopX64: g.ab.reg g.frameRegs[i]             # raw pop, reverse order

proc emitStackParamLoadsX64(g: var CodeGen; decl: Cursor) =
  ## Load the 7th+ integer/pointer parameters from the caller's outgoing argument
  ## area into their allocated (callee-saved) register homes. Emitted right after
  ## `framePush` and before the alignment pad, so each arg sits at the statically
  ## known offset `framePushBytes + k*8` from the current rsp.
  var c = decl
  inc c; inc c                                # → params slot
  if c.kind != TagLit: return
  let base = g.framePushBytesX64()
  var idx = 0
  var stackOrd = 0
  c.into:
    while c.hasMore:
      var nm = ""
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c
        while c.hasMore: skip c
      if idx >= g.md.intArgRegs.len:
        let loc = g.ra.locationOfSym(nm)
        assert loc.kind == InReg,
          "arkham x64 v0: stack parameter without a register home: " & nm
        g.ab.tree MovX64:                     # home ← [rsp + base + stackOrd*8]
          g.emReg loc.r                       # raw callee-saved reg
          g.ab.tree MemX:
            g.ab.reg RSP
            g.ab.intLit (base + stackOrd * 8)
        inc stackOrd
      inc idx

# ── thread-local storage ─────────────────────────────────────────────────────
# nifasm accesses an x86-64 thread-local as `FS:[off]` (it resolves a tvar symbol
# to a displacement-only FS-segment memory operand). The kernel zeroes the FS base
# at process entry, so arkham points it at a static `.bss` block via
# `arch_prctl(ARCH_SET_FS, &block)` in the entry prologue. Single-threaded, so
# per-thread == per-process. Non-zero literal initializers are stored at entry
# (the block is zero-filled); nifasm bakes no x64 TLS init template.

const TlsBlockName = "arkham.tls.0"  # distinct basename so nifasm's scope keys it uniquely
const ArchSetFs = 0x1002             # arch_prctl(2) subfunction
const ArchPrctlNr = 158              # Linux x86-64 syscall number

proc tlsBlockSize(g: var CodeGen): int =
  ## Total bytes the FS block must cover: the sum of each tvar's aligned size,
  ## matching nifasm's sequential `tlsOffset += alignedSize` allocation (summing
  ## over *all* tvars is an upper bound on its reachable subset).
  result = 0
  for name, decl in g.tvars:
    var c = decl
    c.into:
      inc c; skip c                              # name, pragmas
      let s = slotOf(g.prog, c)
      let a = max(s.align, 1)
      result += (s.size + a - 1) and not (a - 1)
      while c.hasMore: skip c
  if result < 16: result = 16                     # keep the block 16-byte sized/aligned

proc genTvar(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(tvar :name <type> <intlit>?)`. nifasm allocates the FS offset; the
  ## optional literal is carried (parsed but unused on x64 — `emitTlsSetup` stores
  ## non-zero initializers at runtime since `.bss` defaults to zero).
  var c = decl
  c.into:                                         # (tvar SymbolDef VarPragmas Type Value?)
    inc c; skip c                                 # name, pragmas
    g.ab.open NifasmDecl.TvarD
    g.ab.symDef name
    g.genTypeBody(c)                              # type
    if c.kind == IntLit:
      g.ab.intLit intVal(c)
    elif c.kind != DotToken:
      raiseAssert "arkham x64: thread-local initializer must be an integer literal: " & name
    g.ab.close()
    while c.hasMore: skip c

proc emitTlsSetup(g: var CodeGen) =
  ## Entry prologue: point FS at the TLS block, then run literal initializers.
  g.emGlobalAddr(RSI, TlsBlockName)               # rsi ← &block
  g.movImm(RDI, ArchSetFs)
  g.movImm(RAX, ArchPrctlNr)
  g.emSyscall()                                   # arch_prctl(ARCH_SET_FS, &block)
  for name, decl in g.tvars:
    var c = decl
    c.into:
      inc c; skip c; skip c                       # name, pragmas, type
      if c.hasMore and c.kind == IntLit:
        let v = intVal(c)
        if v != 0:
          let r = g.borrowTmp()
          g.movImm(r, v)
          g.ab.tree MovX64:                       # FS:[off] ← r  (tvar symbol resolves to mem)
            g.ab.sym name
            g.emReg r
          g.giveBack r
      while c.hasMore: skip c

proc emitProcBody(g: var CodeGen; info: ProcInfo; declarative: bool) =
  ## Emit one proc's `(proc …)` (signature + body). Run twice by `genProc`: once
  ## in planning mode (emission suppressed, scratch decisions recorded), once for
  ## real (decisions replayed). Reads the per-proc `ret*`/frame state set up by
  ## `genProc`; touches only state `genProc` resets between the two passes.
  g.ab.tree ProcD:
    g.ab.symDef info.asmName
    g.emitSignature(info.decl, declarative)
    g.ab.tree StmtsX64:
      g.enterScope()                          # the proc body's scope
      g.framePush()                           # save the used callee-saved GPRs
      g.emitStackParamLoadsX64(info.decl)      # incoming 7th+ args → their reg homes
      if g.framePad > 0:                      # 16-byte alignment for outgoing calls
        g.binImm(SubX64, RSP, g.framePad.int64)
      if g.ra.hasStackVars:                   # reserve nifasm-managed `(s)` slots so
        g.ab.tree SubX64: g.ab.reg RSP; g.ab.keyword SsizeX  # they sit above rsp (call-safe)
      if g.retIndirect: g.movReg(g.indirectReg, RDI)   # park the hidden result ptr
      g.emitParamMoves(info.decl, declarative)         # settle register params
      if info.isEntry and g.tvars.len > 0:
        g.emitTlsSetup()                      # set FS base + thread-local initializers
      if info.isEntry: g.emitGlobalInits()    # run module-level var initializers
      var c = info.decl
      c.into:
        inc c; skip c; skip c; skip c         # name, params, return type, pragmas
        if c.stmtKind == StmtsS:
          genStmt(g, c)
      g.exitScope()                           # `kill` the proc's register locals
      # Fallthrough terminator: the entry exits the process; a normal proc
      # restores its frame and returns.
      if info.isEntry:
        g.movImm(RAX, 60); g.movImm(RDI, 0); g.emSyscall()
      else:
        g.framePop()
        g.ab.keyword RetX64

proc genProc(g: var CodeGen; info: ProcInfo) =
  # Unlike A64 (where a thread-local goes through a TLV-descriptor thunk call), x64
  # reads/writes a tvar directly as an FS-segment operand — no call — so tvar
  # accesses must NOT mark the proc non-leaf. Hence the empty tvar set here.
  let an = analyseProc(g.buf[], info.decl)
  g.varType.clear()                           # reuse the backing storage across procs
  g.symType.clear()
  g.retAggrName = ""; g.retIndirect = false; g.retIsFloat = false
  g.indirectReg = NoReg
  g.isEntryProc = info.isEntry
  g.regLocal.clear()                          # per-proc named-local bindings
  g.scopeLocals = @[]
  g.spillCount = 0
  # Aggregate return convention (before allocation): a named object ≤16B → rax:rdx;
  # >16B → a hidden pointer the caller passes in rdi, parked in a callee-saved reg
  # (rbx) for the proc's lifetime and written through on `ret`.
  block:
    var rc = info.decl
    inc rc; inc rc; skip rc                    # head → name → params, skip → ret type
    if rc.kind == Symbol and slotOf(g.prog, rc).kind == AMem:
      g.retAggrName = symName(rc)
      g.retIndirect = aggrByteSize(g.prog, g.retAggrName) > g.md.aggrByRefThreshold
    elif rc.kind == TagLit and rc.typeKind == FT:
      g.retIsFloat = true                       # float return → xmm0
      g.retFloatBits = if slotOf(g.prog, rc).size == 4: 32 else: 64
  let preseal = if g.retIndirect: {RBX} else: {}
  g.ra = allocateProc(g.buf[], info.decl, an, g.prog, x64Machine, preseal)
  if g.retIndirect:
    g.indirectReg = RBX
    g.ra.usedCallee.incl RBX                   # saved/restored like any callee reg
  g.initFreeTmp()
  g.computeFrameX64(info.isEntry, an.hasCall)
  let declarative = isDeclarativeAbi(g.prog, info.decl)
  # Single walk, two modes. The plan pass runs `emitProcBody` with emission
  # suppressed (`ab.planning`), so every scratch borrow is decided and recorded
  # in `borrowLog`/`borrowLogF` (with the real pool + ABI seals) while no bytes
  # are produced; the emit pass replays those decisions verbatim. Because the
  # walk and its register decisions are identical, the emit pass reproduces the
  # exact bytes a single inline-borrow pass would have — provably byte-identical.
  # (Spill-on-exhaustion and control-flow/cmov planning build on this seam.)
  let labelSnapshot = g.labelCount
  let rodataSnapshot = g.rodata.len
  let sealedSnapshot = g.ra.sealed
  # A codegen-time steal evicts a local by mutating `g.ra.locs` mid-walk; snapshot
  # it so the emit pass starts from the same allocation the plan pass saw and
  # re-applies the (identically replayed) evictions itself.
  let locsSnapshot = g.ra.locs
  g.stealEvents.clear()
  g.borrowLog.setLen 0; g.borrowLogF.setLen 0
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.ab.planning = true
  g.emitProcBody(info, declarative)
  g.ab.planning = false
  g.ra.locs = locsSnapshot                     # undo plan-pass evictions for the emit pass
  # Reset the per-proc emission state the plan pass dirtied, so the emit pass
  # reproduces a single-pass result. (The `ret*`/frame fields were fixed in setup
  # above and stay constant across the two passes.)
  g.labelCount = labelSnapshot
  g.rodata.setLen rodataSnapshot
  g.ra.sealed = sealedSnapshot
  g.varType.clear()
  g.symType.clear()
  g.regLocal.clear()
  g.scopeLocals = @[]
  g.loopEnds = @[]
  g.initFreeTmp()
  g.borrowIdx = 0; g.borrowIdxF = 0
  g.spillCount = 0
  g.emitProcBody(info, declarative)            # emit for real, replaying the plan

proc genGlobal(g: var CodeGen; name: string; decl: Cursor) =
  ## `(gvar :name <type>)` — a zero-initialized `.bss` global (also `const`); any
  ## initializer is run at program entry by `emitGlobalInits`.
  var c = decl
  let isConst = c.stmtKind == ConstS
  c.into:                                       # (gvar SymbolDef VarPragmas Type Value?)
    inc c                                       # name
    skip c                                      # pragmas
    let typeCur = c
    skip c                                      # type
    let hasValue = c.hasMore and c.kind != DotToken
    if isConst and hasValue:
      # A compile-time constant: lay it out as a read-only data blob (no `.bss`
      # slot, no entry-time initialiser — see `emitGlobalInits`, which skips it).
      var bytes = ""
      constToBytes(g.prog, typeCur, c, bytes)
      g.ab.tree RodataD:
        g.ab.symDef name
        g.ab.str bytes
    else:
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef name
      var tc2 = typeCur
      g.genTypeBody(tc2)                         # type
      g.ab.close()
    while c.hasMore: skip c                      # value (initialized at entry)

proc emitGlobalInits(g: var CodeGen) =
  ## At program entry, store each global's initializer (if any) into its slot.
  for name, decl in g.globals:
    var c = decl
    if c.stmtKind == ConstS: continue           # emitted as a rodata data blob
    c.into:
      inc c; skip c                             # name, pragmas
      let gslot = slotOf(g.prog, c)             # the global's declared type
      skip c                                    # type
      if c.hasMore and c.kind != DotToken:
        if gslot.kind == AFloat:                 # float global → movss/movsd [&g], xmm
          let gbits = if gslot.size == 4: 32 else: 64
          let fv = g.borrowFTmp()
          g.genIntoF(c, fv, gbits)
          let p = g.borrowTmp()
          g.emGlobalAddr(p, name)
          let op = if gbits == 32: MovssX64 else: MovsdX64
          g.ab.tree op:
            g.ab.tree MemX: g.emReg p
            g.emFReg fv
          g.giveBack p
          g.giveBackF fv
        else:
          let v = g.borrowTmp()
          g.genInto(c, v)                          # evaluate the initializer
          let p = g.borrowTmp()
          g.emGlobalAddr(p, name)
          g.ab.tree MovX64:
            g.ab.tree MemX: g.emReg p
            g.emReg v
          g.giveBack p
          g.giveBack v
      while c.hasMore: skip c

proc generateX64*(buf: var TokenBuf; inputPath: string; tags: TagPool): string =
  ## Compile a parsed NIFC module to x86-64 / Linux asm-NIF text.
  var g = CodeGen(ab: initAsmBuf(), buf: addr buf, md: x64Machine)
  g.ab.renderReg = x64RegName                 # render register slots as x86 names
  g.prog = collect(buf, inputPath, tags)
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
  g.ab.tree StmtsX64:
    g.ab.tree ArchD: g.ab.ident "x64"
    for (name, decl) in g.prog.mainTypeList:
      g.genType(name, decl)
    for name, decl in g.prog.globals:
      g.genGlobal(name, decl)
    if g.tvars.len > 0:
      # The static FS-segment block backing all thread-locals (see `emitTlsSetup`).
      g.ab.open NifasmDecl.GvarD
      g.ab.symDef TlsBlockName
      g.ab.arrayType:
        g.ab.uintType(8)
        g.ab.intLit g.tlsBlockSize()
      g.ab.close()
    for name, decl in g.prog.tvars:
      g.genTvar(name, decl)
    for info in g.prog.procs:
      genProc(g, info)
    for (nm, bytes) in g.rodata:
      g.ab.tree RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render()
