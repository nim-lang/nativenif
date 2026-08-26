#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## The x86-64 stack frame, and everything a proc needs before its body: the
## signature nifasm type-checks, where each incoming parameter actually arrives,
## which callee-saved registers this proc owes back, and how big the frame is.
##
## The frame SIZE is not known here — `(ssize)` is nifasm's own number, patched
## once the body has been assembled — which is why the prologue emits a
## placeholder and the epilogue emits the matching one.

import std / [assertions, tables, sets]
import nifcore
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, 
                    mirrors, regbind, abi]
import machine as machine_x64
import emit, mem, aggr, value

const X64SyscallArgRegs* = [RDI, RSI, RDX, R10, R8, R9]
  ## The x86-64 Linux syscall argument registers. Identical to the C ABI EXCEPT
  ## arg4: the kernel takes it in r10, not rcx (rcx is destroyed by the `syscall`
  ## instruction). Placing it in the syproc's param decl moves the r10 mapping into
  ## nifasm, so arkham marshals args through the normal C-ABI staging registers and
  ## never has to emit a raw r10 (which its scratch-pool guard forbids).


proc emFloatStackVar*(g: var CodeGen; name: string; bits: int) =
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.floatType(bits)
  g.ab.close()

proc emRegLocalVar*(g: var CodeGen; name: string; r: Reg; typeCur: Cursor) =
  ## Declare `(var :name (reg) type)` and bind `r` to `name` for the rest of its
  ## scope, so subsequent uses emit the typed name instead of `(reg)`.
  # If `r` still holds an earlier, now-dead local (the allocator early-freed it at
  # its last use and reassigned the register here), `kill` that binding first —
  # nifasm forbids binding a still-live register. The kill lands at this rebind,
  # past the dead var's coarse free point, hence on its post-dominating path.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r                                   # the concrete register (the binding)
  # A local is declared with its OWN type — `(u 8)` stays `(u 8)`. arkham still keeps
  # every scalar 64-bit-wide in the register and normalizes with explicit extends;
  # the declared type is what the VARIABLE is, and a register operand's type never
  # reaches the encoder (nifasm's `movTypeOk`), so saying `(u 8)` costs nothing and
  # buys a real check: a wide value landing in a narrow local without the extend
  # that converts it is now an error rather than an invisible truncation. Widening
  # reads out of it stay legal; the narrowing write is the `movzx`/`movsx` itself,
  # which `emitCast2` retypes around (see the pre-retype there).
  #
  # This used to declare every non-pointer as a flat `(i 64)`, which made the width
  # and signedness of every register-homed local invisible to nifasm.
  let rt = resolveType(g.prog, typeCur)
  let isPtr = isPtrType(rt)                    # a ptr binding admits `(nil)` (see `NilC`)
  var tc = typeCur
  g.genTypeBody(tc)                            # the local's OWN type — see the note above
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr)
  g.nameBindTyp[name] = NameBindTyp(isPtr: isPtr, typ: typeCur)

proc emRegAggrPtrVar*(g: var CodeGen; name: string; r: Reg; typeSym: SymId) =
  ## Declare `(var :name (reg) (ptr T))` for a register holding a POINTER to the
  ## aggregate `T`, and bind `r` to `name`. The by-reference aggregate parameter had
  ## no declaration at all: its pointer was `mov`'d into the home register and every
  ## later field access named the bare register (`(cast (ptr T) (rdi))`). With no
  ## symbol, `rb` could not see the register was occupied and neither could nifasm's
  ## binding checker — the reservation lived only in `regFreeForTemp`'s per-proc
  ## `regHoldsHome` union. Declaring it is what lets the readers name it.
  let dead = g.rb.takeBinding(r)
  if dead.len > 0:
    g.ab.tree KillX64: g.ab.sym dead
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.rawReg r
  g.ab.ptrType: g.emTypeSym(typeSym)
  g.ab.close()
  g.rb.bindLocal(r, name, isPtr = true)
  g.nameBindTyp[name] = NameBindTyp(aggrSym: typeSym, isPtr: true)

proc emFRegLocalVar*(g: var CodeGen; name: string; f: FReg; bits: int) =
  ## Declare a float register local: bind xmm `f` to `name` via `(rebind …)` for the
  ## rest of its scope, so subsequent uses emit the typed name instead of `(xmmN)`.
  ## The SIMD twin of `emRegLocalVar`. `rebind` kills `f`'s prior tenant itself (an
  ## earlier, now-dead local the allocator reassigned the register to), so no manual
  ## kill is needed first.
  g.ab.tree RebindX64:
    g.ab.symDef name
    g.ab.floatType(bits)
    g.ab.xmmReg f
  g.rb.bindFLocal(f, name)

proc enterScope*(g: var CodeGen) =
  g.rb.enterScope()

proc exitScope*(g: var CodeGen) =
  ## `kill` each register local declared in the closing scope so the allocator's
  ## register reuse in a sibling scope rebinds cleanly (nifasm forbids binding a
  ## still-live register). Skip any whose register was already rebound to a later
  ## local (already killed at that rebind).
  let dead = g.rb.exitScope()
  for name in dead.gprs:
    g.ab.tree KillX64: g.ab.sym name
  for name in dead.fprs:
    g.ab.tree KillX64: g.ab.sym name

proc emStackVar*(g: var CodeGen; name: string; typeSym: SymId) =
  ## `(var :name (s) typeSym)` — a nifasm-managed aggregate stack slot.
  g.plan.hasStackVars = true                   # a `(s)` var exists ⇒ frame sub needed
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.emTypeSym(typeSym)
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

proc emByRefPtrStackVar*(g: var CodeGen; name: string; typeSym: SymId) =
  ## `(var :name (s) (ptr T))` — the 8-byte slot holding a spilled by-ref
  ## aggregate's incoming pointer. Not `(s) T`: the aggregate itself lives
  ## wherever the caller pointed, and field access loads this pointer first.
  g.plan.hasStackVars = true
  g.stackSlots.incl name
  g.ab.open NifasmDecl.VarD
  g.ab.symDef name
  g.ab.keyword SO
  g.ab.ptrType: g.emTypeSym(typeSym)
  g.ab.close()

proc emitSyproc*(g: var CodeGen; sp: SyscallProc) =
  ## Emit a `(syproc :name (params …) (result …)? (clobber (rcx) (r11)) NR)` decl:
  ## the syscall's proctype with params bound to the syscall ABI registers and the
  ## registers the `syscall` instruction clobbers. It carries the x86-64 number and
  ## emits no code — the inline `(syscall)` marker at each call site reads it.
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
                if idx >= X64SyscallArgRegs.len:
                  raiseAssert "arkham x64: syscall with more than 6 arguments"
                g.ab.tree ParamD:
                  g.ab.symDef paramName(idx)
                  g.ab.rawReg X64SyscallArgRegs[idx]
                  g.genTypeBody(pc)
                while pc.hasMore: skip pc
              inc idx
      g.ab.tree ResultD:                         # c at the return type
        if not retIsVoid(c):
          g.ab.symDef synth("ret.0")
          g.ab.rawReg RAX
          g.genTypeBody(c)
      g.ab.tree ClobberD:                        # x86-64 `syscall` destroys rcx, r11
        g.ab.rawReg RCX
        g.ab.rawReg R11
      g.ab.intLit sp.sysNr.int64
    while c.hasMore: skip c                       # drain the importc decl's pragmas + body

proc emitWinExtproc*(g: var CodeGen; ex: Extern) =
  ## Emit a Windows extern's declaration:
  ## `(extproc :<name>.c.<mod> "<name>" "<dll>" (params (param :pN.0 <reg|s> T)…)
  ##  (result …)? (clobber …))`.
  ##
  ## The dll is named ON the decl, not merely inferred from the `(imp …)` this sits
  ## under. Enclosure is a property of a POSITION in the stream, and a module's
  ## decls do not stay in a stream: nifasm reaches a foreign module's by indexed
  ## jump, one at a time, where no enclosing group exists to consult. So the decl
  ## states it. (The Darwin form omits the operand — one library, no grouping.)
  ##
  ## Unlike the Darwin extern decl — a bare name/string pair whose call sites marshal
  ## into raw ABI registers — this carries the callee's FULL Win64 signature, so the
  ## call goes through nifasm's declarative `(arg pN)` path. Two things fall out of
  ## that which the raw path cannot express: nifasm CHECKS each argument against the
  ## declared parameter, and it reserves the call's outgoing stack-argument area
  ## (Win64 shadow space plus the 5th+ arguments) in the caller's fixed frame. The
  ## `WriteFile` the freestanding `writeErr` calls has five parameters and needs both.
  var c = ex.decl
  c.into:
    inc c                                        # name
    var pc = c; skip c                           # params slot; c → return type
    # THE plan (abi.nim), against the Win64 register file — the ONE place the
    # convention of a call out to the OS differs from arkham's internal SysV one.
    # `retByRef` is false: an aggregate return is rejected below.
    let plan = planCall(win64Machine, paramSlots(g.prog, pc), retByRef = false)
    g.ab.tree ExtprocD:
      g.ab.symDef ex.asmName
      g.ab.str ex.extName
      g.ab.str ex.dll
      var idx = 0
      g.ab.tree ParamsD:
        if pc.kind == TagLit:                    # (params (param …) …)
          pc.into:
            while pc.hasMore:
              let pl = plan.args[idx]
              pc.into:                           # (param :name pragmas type)
                inc pc                           # name → positional pN.0
                skip pc                          # pragmas
                if pl.isFloat or pl.isAgg:
                  # Not modelled — see `win64Machine`. No Windows API arkham binds
                  # takes either, and guessing would miscompile silently.
                  raiseAssert "arkham win_x64: float/aggregate parameter in extern " &
                              ex.extName
                g.ab.tree ParamD:
                  g.ab.symDef paramName(pl.ord)
                  if not pl.onStack: g.ab.rawReg win64Machine.gprAt(pl)
                  else: g.ab.keyword SO          # past rcx/rdx/r8/r9 → stack-passed
                  g.genTypeBody(pc)
                while pc.hasMore: skip pc
              inc idx
      g.ab.tree ResultD:                         # c at the return type
        if not retIsVoid(c):
          if slotOf(g.prog, c).kind in {AFloat, AMem}:
            raiseAssert "arkham win_x64: float/aggregate result in extern " & ex.extName
          g.ab.symDef synth("ret.0")
          g.ab.rawReg RAX
          g.genTypeBody(c)
      # The volatiles a Win64 call destroys, EXCEPT this callee's own argument
      # registers (nifasm treats a declared clobber as already dead, so listing one
      # would stop the call site binding its `(arg pN)`) — the same rule as
      # `emitAbiClobber`. Declaring arkham's whole SysV volatile set is safe and
      # deliberate: Win64 additionally PRESERVES rdi/rsi, so this over-states what is
      # lost and can only make the caller more careful, never less.
      var paramRegs: set[Reg] = {}
      for i in 0 ..< min(plan.gpUsed, win64Machine.intArgRegs.len):
        paramRegs.incl win64Machine.intArgRegs[i]
      g.ab.tree ClobberD:
        for r in x64ClobbersGpr:
          if r notin paramRegs: g.ab.rawReg r
    while c.hasMore: skip c                       # drain the importc decl's pragmas + body

proc genType*(g: var CodeGen; name: string; decl: Cursor) =
  ## `(type :name <body>)` — nifasm's stack-slot allocator consults it for field
  ## offsets.
  var c = decl
  c.into:
    inc c                                     # name
    skip c                                    # type-pragmas
    g.ab.tree TypeD:
      g.ab.symDef name
      g.genTypeBody(c)

proc numIncomingArgRegs*(g: var CodeGen; decl: Cursor): int =
  ## How many leading integer arg registers carry incoming values: a hidden
  ## result pointer (>16B return) + one per scalar / by-ref-aggregate param + one
  ## per 8-byte word of a ≤16B by-value aggregate param. These hold live values on
  ## entry, so they're excluded from the clobber set (a clobbered register can't
  ## be read — and a named local bound to one would be rejected).
  var c = decl
  inc c; inc c                                # head → name → params
  # Only register-passed integer/aggregate params (and the hidden result pointer)
  # occupy incoming GPRs; a stack-passed param consumes none, a float uses an xmm.
  result = planCall(g.md, paramSlots(g.prog, c), g.retIndirect).gpUsed

proc emitSignature*(g: var CodeGen; decl: Cursor) =
  ## Emit `(params …) (result …)? (clobber …)`. A FULL-signature proc (scalar /
  ## aggregate params, void / scalar / >16B by-ref result) states the complete SysV
  ## register ABI — positional `p.i` params in rdi/rsi/…, a hidden result pointer in
  ## rdi for a >16B return, an rax result — so nifasm knows the full layout (incl.
  ## stack-passed args) and cross-checks every call site. A proc whose boundary is NOT
  ## yet modelled in the typed signature (float params/results, ≤16B by-value aggregate
  ## results) emits an EMPTY `(params)/(result)`; its caller marshals arguments into
  ## raw ABI registers manually.
  if isDeclarativeAbi(g.prog, decl):
    var c = decl
    c.into:
      inc c                                 # name → params slot
      # arkham's own convention (`g.md`): this is a proc arkham GENERATES, so both
      # sides of every call to it are its own — see `generateX64`.
      discard g.emitParamsAndResult(c, byRef = false, g.md)  # types inline (concrete proc)
      while c.hasMore: skip c               # pragmas, body
  else:
    g.ab.keyword ParamsD
    g.ab.keyword ResultD
  if declIsNoReturn(decl):
    # A diverging callee (`panic`, `raiseAssert`, the bound-check failure path) returns
    # to nobody, so NO caller can observe what it destroyed. The clobber list exists to
    # tell nifasm which registers a call site must treat as dead afterwards — and there
    # is no afterwards. Declaring the volatile set anyway is what forced every proc
    # containing a cold guard to home its live values in callee-saved registers and push
    # them in the prologue: `nifcore.kind` paid three pushes, three pops and a frame for
    # one `assert`.
    g.ab.tree ClobberD: discard
  else:
    # `numIncomingArgRegs` (not the param *count*) — it accounts for an aggregate
    # spanning several GPRs and a float consuming none.
    g.emitAbiClobber(g.numIncomingArgRegs(decl))

proc emitParamMoves*(g: var CodeGen; decl: Cursor) =
  ## Settle each register-passed parameter into its allocated home. A param the
  ## allocator left in its incoming arg register becomes the named local `p.i`
  ## (x64 refers to a bound register by name); one the allocator relocated to a
  ## callee-saved register (because it lives across a call) is `mov`'d there as a
  ## *raw* register — never a named local, so the epilogue can `pop` that
  ## callee-saved reg without a "kill it first" binding conflict. Stack-passed
  ## params (7th+) are handled by `emitStackParamLoadsX64`.
  let declarative = isDeclarativeAbi(g.prog, decl)  # full signature ⇒ params bound as `pN.0`
  var c = decl
  inc c                                       # proc head → name
  inc c                                       # name → params slot
  if c.kind != TagLit: return                 # no parameters
  # THE plan (see abi.nim): register indices / name ordinals below read it.
  # rdi = hidden result ptr for a >16B return; floats consume xmm0–7, not GPRs.
  let plan = planCall(g.md, paramSlots(g.prog, c), g.retIndirect)
  var pIdx = 0
  c.into:
    while c.hasMore:
      let pl = plan.args[pIdx]
      inc pIdx
      var nm = ""
      var tn = NoTypeSym                      # set → an aggregate param type
      var typeCur = c
      c.into:                                 # (param :name pragmas type)
        nm = symName(c); inc c
        skip c                                # pragmas
        g.symType[nm] = c                     # record the param's type for getType
        typeCur = c
        if c.kind == Symbol and slotOf(g.prog, c).kind == AMem: tn = c.symId
        while c.hasMore: skip c
      let loc = g.plan.homeOfSym(nm)
      if tn != NoTypeSym and loc.kind == StackPtr and not pl.onStack:
        # A >16B by-ref POINTER spilled to its own `(ptr T)` slot because no
        # callee-saved register was free (totality). The home's KIND says so —
        # formerly this asked the ABI plan's `pl.byRef` while every reader asked
        # the `spilledByRefPtr` predicate: two answers to one question.
        g.varType[nm] = tn
        g.emByRefPtrStackVar(nm, tn)
        let argReg = g.md.gprAt(pl)
        g.ab.tree MovX64:
          g.emStackMem(nm)
          if declarative: g.ab.sym paramName(pl.ord) else: g.ab.rawReg argReg
        if declarative: g.ab.tree KillX64: g.ab.sym paramName(pl.ord)
      elif tn != NoTypeSym and loc.kind == NamedStack and not pl.onStack:
        # A register-passed ≤16B by-value aggregate in a `(s)` home: the slot IS the
        # struct, filled from its GPR word(s).
        g.varType[nm] = tn
        g.emStackVar(nm, tn)
        g.regsToStruct(nm, tn, g.md.intArgRegs[pl.gpFirst ..< pl.gpFirst + pl.words])
      elif tn != NoTypeSym and loc.kind == InRegPair:
        # ≤16B by-value aggregate kept in GPRs (the ABI eightbytes ARE the fields).
        # Relocate each incoming arg word to its home; no stack copy.
        g.varType[nm] = tn
        for k in 0 ..< pl.words:
          let home = pairWord(loc, k)
          let arg = g.md.gprAt(pl, k)
          if home != arg: g.movReg(home, arg)
          # A pair word is written RAW and read back RAW (`pairFieldReg` hands out
          # the bare register), so `rb` cannot see it and `isBound` answers "free".
          # That is precisely what `rawHomeRegs` is for — without it the emitter
          # hands the word out as an expression temp while the parameter is still
          # live: `(rebind :tmp13.0 (rbx))` on top of a `string` param's word 0,
          # and the very next call marshals `(mov (rdx) (rbx))` from the clobbered
          # register. Same shape as the by-ref pointer in `emRegAggrPtrVar`, which
          # solves it by NAMING the register instead.
          g.rawHomeRegs.incl home
      elif tn != NoTypeSym and loc.kind == InReg and not pl.onStack:
        # >16B by-reference aggregate passed in a register: a pointer homed like a
        # scalar; field accesses route through it (recorded in varType). A stack-
        # passed pointer (past the regs) is loaded by `emitStackParamLoadsX64`.
        g.varType[nm] = tn
        g.movReg(loc.r, g.md.gprAt(pl))
        # Give the pointer a NAME so every field access can address it by symbol
        # (`emPtrFieldMemSym` / the lvalue base) instead of naming the bare register.
        if arkhamNameAggrBase:
          g.emRegAggrPtrVar(nm, loc.r, tn)
          if loc.r == g.md.gprAt(pl):
            # The pointer STAYED in its incoming argument register, which is
            # caller-saved. `allocParams` only allows that under `AllRegs` — the
            # analyser's proof that the param's last use precedes the FIRST call — so
            # the value is dead by that call, but the NAME BINDING is not: without a
            # flush it outlives every call that clobbers the register, and the next
            # raw use of that register (a marshal, or reading the SECOND return word
            # of a 2-eightbyte result out of rdx) renders under the dead param's name.
            # Same lifetime and same remedy as an `ArgResident` scalar param, so use
            # the same list: `flushArgResidentParams` kills it after the first call,
            # and `releaseArgDest` releases it should a marshal reach the register
            # first. A relocated pointer is in a callee-saved home and needs neither.
            g.argResidentParams.add (loc.r, nm)
        else: g.rawHomeRegs.incl loc.r        # unnamed ⇒ the union must reserve it
      elif tn != NoTypeSym:
        # Stack-passed aggregate (by-value that didn't fit, or a by-ref pointer past
        # the arg regs): record its type so the body can navigate it; the bytes /
        # pointer are brought in by `emitStackParamLoadsX64`. Consumes no GPR.
        g.varType[nm] = tn
      elif loc.kind == InFReg:
        # Float parameter: in a leaf proc it stays in its incoming xmm{fpIndex}; if
        # the allocator gave it a (callee-saved-equivalent) home, move it there. SysV
        # has no callee-saved xmm, so a float crossing a call instead spills (next branch).
        g.fmovF(loc.f, g.md.floatArgRegs[pl.fpIndex], loc.typ.size * 8)
      elif loc.kind == NamedStack and loc.typ.kind == AFloat:
        # An address-taken / spilled float param: declare its `(s) (f N)` slot and
        # spill the incoming xmm arg register into it so `addr`/loads/stores work.
        assert not pl.onStack, "arkham x64 v0: >8 float params (stack TODO)"
        let bits = loc.typ.size * 8
        g.emFloatStackVar(nm, bits)
        g.emFloatScalarStore(nm, g.md.floatArgRegs[pl.fpIndex], bits)
      elif not pl.onStack:                      # register-passed scalar parameter
        let argReg = g.md.gprAt(pl)
        if loc.kind == InReg and loc.r == argReg:
          if declarative:
            g.rb.bindParam(argReg, paramName(pl.ord)) # the signature binds it as `pN.0`
            # Record the type so `restoreBindings` can re-establish this name after a
            # DIVERGING call. Without it the param is nameless from the first panic
            # onward and every later read of it emits a raw `(reg)` — `inc.0.nifisob2`
            # reading its `(ptr Cursor)` out of a bare rdi is the canonical case.
            g.nameBindTyp[paramName(pl.ord)] =
              NameBindTyp(isPtr: isPtrType(resolveType(g.prog, typeCur)), typ: typeCur)
          else:
            # no signature binding (empty params) → bind the param's own name to its
            # arg register so the body can refer to it by name.
            g.emRegLocalVar(nm, argReg, typeCur)
          # An ArgResident param (kept in its arg reg though the proc has calls) is dead
          # after the first call clobbers the reg; record it so `flushArgResidentParams`
          # kills the binding then. In a LEAF proc no call fires, so it never flushes and
          # the binding persists for the whole body — the existing leaf behavior.
          g.argResidentParams.add (argReg, g.rb.boundName(argReg))
        elif loc.kind == InReg:
          # Relocated to a callee-saved or caller-save volatile home. In the declarative
          # path the signature binds argReg to `pN.0`, so the relocation move must
          # *read* it by name (a raw `(reg)` use of a bound register is rejected); the
          # binding is then killed so the now-dead arg register is free. The empty-
          # signature path has no binding, so it moves the raw register.
          if declarative:
            g.ab.tree MovX64: (g.emReg loc.r; g.ab.sym paramName(pl.ord))
            g.ab.tree KillX64: g.ab.sym paramName(pl.ord)
          else:
            g.movReg(loc.r, argReg)
          # Then DECLARE the home under the param's own name — after the move, never
          # before it (a binding created ahead of its value is the stillborn shape).
          #
          # This used to be a `rawHomeRegs` entry instead: the home stayed unbound for
          # the whole proc "for epilogue pops", and every read of the param emitted a
          # bare `(rbx)`. That was 2780 of the 2956 raw register operands in a nifbench
          # build — a nimony `var T` param is lowered to a plain `(ptr T)`, so the vast
          # majority of pointer params take THIS branch, not the aggregate one above.
          # The pops are the only thing that needed the register raw, and `framePop`
          # now kills whatever is bound to a frame register just before them.
          g.emRegLocalVar(nm, loc.r, typeCur)
        elif loc.kind == NamedStack and loc.typ.kind != AFloat:
          # an address-taken / spilled scalar param: declare its `(s)` slot and spill the
          # incoming argument register into it so `addr`/loads/stores work. Type the slot
          # with the param's real type (e.g. a pointer) — a generic `(i 64)` slot would
          # reject the typed store and forbid a later deref. In the declarative path the
          # arg reg is bound to `pN.0`, so reference it by that name (and kill it); the
          # empty-signature path uses the raw register.
          g.emTypedStackVar(nm, typeCur)        # (var :nm (s) <param type>)
          g.ab.tree MovX64:
            g.emStackMem(nm)
            if declarative: g.ab.sym paramName(pl.ord) else: g.ab.rawReg argReg
          if declarative: g.ab.tree KillX64: g.ab.sym paramName(pl.ord)
        else:
          raiseAssert "arkham x64 v0: spilled / float parameter: " & nm
      # else: stack-passed (7th+) — loaded by emitStackParamLoadsX64.

proc pickStackArgBaseX64*(g: var CodeGen; hasStackParams: bool) =
  ## A proc with stack-passed parameters needs the incoming-args base in a register
  ## that survives the frame `sub`s (rsp moves). Pick a callee-saved reg the body
  ## isn't using. Split out of `computeFrameX64` because the body-buffer emitter
  ## needs the register's IDENTITY before the body (its stack-param loads name it)
  ## while the frame SHAPE is finalized only after.
  g.stackArgBaseReg = NoReg
  if hasStackParams:
    for r in g.md.intCalleeSaved:
      if r notin g.plan.usedCallee:
        g.stackArgBaseReg = r
        break
    # The allocator reserved a non-sealed callee-saved reg when it set `hasStackParams`,
    # so the pick above always finds one. (Belt-and-braces: a genuine miss would be an
    # allocator/emitter classification drift — both must read `g.plan.hasStackParams`.)
    assert g.stackArgBaseReg != NoReg, "arkham x64n: no callee-saved reg for stackArgBaseReg"

proc computeFrameX64*(g: var CodeGen; isEntry, hasCall: bool) =
  ## Finalize the frame shape. Runs AFTER the body is emitted (body-buffer model):
  ## only then are `plan.usedCallee` / `hasStackVars` final. `stackArgBaseReg` was
  ## picked up front (`pickStackArgBaseX64`) and is pushed with the frame regs.
  g.frameRegs = @[]
  for r in g.md.intCalleeSaved:
    if r in g.plan.usedCallee: g.frameRegs.add r
  if g.stackArgBaseReg != NoReg:
    g.frameRegs.add g.stackArgBaseReg
  # Both ABIs require rsp ≡ 0 (mod 16) at a `call`. A normal callee is entered with
  # rsp ≡ 8 (the caller's pushed return address). The Linux ENTRY is the exception —
  # the kernel jumps to it with rsp ≡ 0 and no return address; the Windows entry is
  # not: ntdll's thread-start thunk `call`s it, so it is biased like any other callee.
  # Each saved reg is 8 bytes, so after the pushes the parity may be wrong — pad with
  # an extra 8 when this proc itself makes a call.
  g.framePad = 0
  if hasCall:
    let entryBias = if isEntry and not g.prog.windows: 0 else: 8
    if (entryBias + 8 * g.frameRegs.len) mod 16 != 0: g.framePad = 8
  g.hasFrame = g.frameRegs.len > 0 or g.framePad > 0

proc framePushBytesX64*(g: CodeGen): int =
  ## Bytes between the current rsp (after the callee-saved pushes, before the pad)
  ## and the caller's first stack argument: the return address (8) plus each saved
  ## register (8). Used to address incoming stack params.
  8 + 8 * g.frameRegs.len

proc framePush*(g: var CodeGen) =
  for r in g.frameRegs:
    g.ab.tree PushX64: g.ab.rawReg r                          # raw push

proc emitFrameSub*(g: var CodeGen) =
  ## Lower rsp by the `(s)` slot region PLUS the 16-alignment pad, in ONE
  ## instruction. `(ssize N)` tells nifasm — which is what sizes and aligns the
  ## slot region — to add N to the frame size at this site.
  ##
  ## These used to be two instructions, `sub rsp, 8` then `sub rsp, (ssize)`, with
  ## the matching pair on the way out. 177 of nifbench's 442 procs emit both (the
  ## pad is needed exactly when the pushes leave rsp at 8 mod 16), so the redundant
  ## half cost 107 M instructions — 1.2 % of the whole program — for an addition.
  if g.plan.hasStackVars:
    g.ab.tree SubX64:
      g.ab.rawReg RSP
      g.ab.tree SsizeX:
        if g.framePad > 0: g.ab.intLit g.framePad.int64
  elif g.framePad > 0:
    g.binImm(SubX64, RSP, g.framePad.int64)

proc emitFrameAdd*(g: var CodeGen) =
  ## Exact mirror of `emitFrameSub`.
  if g.plan.hasStackVars:
    g.ab.tree AddX64:
      g.ab.rawReg RSP
      g.ab.tree SsizeX:
        if g.framePad > 0: g.ab.intLit g.framePad.int64
  elif g.framePad > 0:
    g.binImm(AddX64, RSP, g.framePad.int64)

proc framePop*(g: var CodeGen) =
  # Release the frame (slot region + alignment pad) first, then the callee-saved
  # registers — reverse of the prologue.
  g.emitFrameAdd()
  # A `pop` names its register RAW, which nifasm rejects while something is bound to
  # it. Callee-saved registers are exactly the homes `emitParamMoves` gives relocated
  # parameters (and `allocLocals` gives cross-call locals), and a param's home is
  # never early-freed — its binding is still live here. Kill it. Safe to do
  # unconditionally at this one site: the epilogue is emitted ONCE at the proc tail
  # (every proc in a nifbench build has exactly one `(ret)`), so nothing downstream
  # can read the name afterwards.
  for i in countdown(g.frameRegs.high, 0):
    let dead = g.rb.takeBinding(g.frameRegs[i])
    if dead.len > 0:
      g.ab.tree KillX64: g.ab.sym dead
  for i in countdown(g.frameRegs.high, 0):
    g.ab.tree PopX64: g.ab.rawReg g.frameRegs[i]             # raw pop, reverse order

proc emitStackParamLoadsX64*(g: var CodeGen; decl: Cursor) =
  ## Load the 7th+ integer/pointer parameters from the caller's outgoing argument
  ## area into their allocated (callee-saved) register homes. Emitted right after
  ## `framePush` and before the alignment pad, so each arg sits at the statically
  ## known offset `framePushBytes + k*8` from the current rsp.
  var c = decl
  inc c; inc c                                # → params slot
  if c.kind != TagLit: return
  # Stack params are addressed relative to `stackArgBaseReg` (the incoming-args base,
  # captured before the frame `sub`s), so this runs AFTER those `sub`s and after the
  # arg registers are freed — `pl.byteOff` is the offset within the stack-arg area.
  # Collect each param's name, aggregate-type-name (if any) and ABI slot, then run
  # THE shared classifier so "which params are stack-passed and at what byte offset"
  # matches the signature, the caller and the allocator exactly.
  var nms: seq[string] = @[]
  var tns: seq[SymId] = @[]
  var tcurs: seq[Cursor] = @[]
  var slots: seq[AsmSlot] = @[]
  block:
    var pc = c
    pc.into:
      while pc.hasMore:
        var nm = ""
        var tn = NoTypeSym
        var tcur = pc
        pc.into:                              # (param :name pragmas type)
          nm = symName(pc); inc pc
          skip pc                             # pragmas
          tcur = pc
          if pc.kind == Symbol and slotOf(g.prog, pc).kind == AMem: tn = pc.symId
          while pc.hasMore: skip pc
        nms.add nm; tns.add tn; tcurs.add tcur; slots.add slotOf(g.prog, tcur)
  # On Windows every caller reserves the Win64 shadow space at the bottom of its
  # outgoing area (nifasm does this uniformly — see its `WinShadowSpace`), so the
  # incoming stack arguments start that far above the base.
  let argAreaBase = (if g.prog.windows: WinShadowSpace else: 0).int64
  for i, pl in planCall(g.md, slots, g.retIndirect).args:
    if not pl.onStack: continue
    let nm = nms[i]
    let off = argAreaBase + pl.byteOff.int64
    if pl.isAgg and not pl.byRef:
      # A by-value aggregate passed entirely on the stack: declare its `(s)` home and
      # copy its eightbytes in from the incoming area `[stackArgBaseReg + byteOff + k*8]`
      # (the offset nifasm gave the caller's `(arg pN k)` writes).
      g.varType[nm] = tns[i]
      g.emStackVar(nm, tns[i])
      # Copy the incoming bytes into the home with MINIMAL register pressure: the home
      # address goes into the staging bridge, and ONE reused value register carries each
      # word — rather than `regsToStruct`, which needs a held register per word.
      let homeAddr = g.pickStagingSealed("a stack-param aggregate home", AddrSlot)
      g.emStackAddr(homeAddr, nm)
      let v = g.pickStaging("a stack-param aggregate word")
      g.bindTemp(v, AddrSlot)
      for k in 0 ..< pl.words:
        g.ab.tree MovX64:                       # v ← incoming word k
          g.emReg v
          g.ab.tree MemX: (g.ab.rawReg g.stackArgBaseReg; g.ab.intLit (off + (k * 8).int64))
        g.ab.tree MovX64:                       # home word k ← v
          g.emWordThroughPtr(homeAddr, k)
          g.emReg v
      g.giveBack v
      g.giveBack homeAddr
    else:
      # A scalar / pointer (incl. a by-ref aggregate's pointer): one word from the
      # incoming area into its home — a callee-saved register, or (totality, under full
      # register pressure) its own `(s)` slot, bridged through a staging reg.
      let loc = g.plan.homeOfSym(nm)
      case loc.kind
      of InReg:
        g.rawHomeRegs.incl loc.r               # RAW home (see `emitParamMoves`)
        g.ab.tree MovX64:
          g.emReg loc.r
          g.ab.tree MemX: (g.ab.rawReg g.stackArgBaseReg; g.ab.intLit off)
        if arkhamNameAggrBase and g.varType.hasKey(nm):
          # A by-reference aggregate whose pointer arrived on the stack: name it, for
          # the same reason `emitParamMoves` does (see `emRegAggrPtrVar`).
          g.emRegAggrPtrVar(nm, loc.r, g.varType[nm])
        # The 8-byte load above reads the whole eightbyte, but a sub-8-byte
        # scalar's upper bits are NOT the value's extension: our own callers
        # store through the arg slot's declared width (a 4-byte `mov` for a
        # cint) and a C caller leaves them undefined outright. Re-extend to the
        # canonical 64-bit register form (`cint mapFlags = -1` arrived as
        # 0x00000000FFFFFFFF and `mapFlags == -1` compared false — memfiles).
        let sl = slots[i]
        if sl.kind in {AInt, AUInt, ABool} and sl.size < 8:
          g.extendTo(loc.r, sl.size * 8, signed = sl.kind == AInt)
      of NamedStack:                            # spilled stack param: incoming → `(s)` slot
        # Declare the `(s)` home before filling it — otherwise the store below (and
        # every later body reference) names an undeclared slot and nifasm rejects it
        # ("Expected index register or stack variable in mem"). Register-passed
        # spilled scalar params already do this via `emTypedStackVar` (emitParamMoves).
        g.emTypedStackVar(nm, tcurs[i])
        let s = g.pickStagingSealed("a spilled stack-param bridge", loc.typ)
        g.ab.tree MovX64:
          g.emReg s
          g.ab.tree MemX: (g.ab.rawReg g.stackArgBaseReg; g.ab.intLit off)
        g.emitStoreLoc(loc, s)
        g.giveBack s
      of StackPtr:
        # Spilled by-ref POINTER: declare the 8-byte `(ptr T)` slot. The
        # register-passed twin does this in emitParamMoves; the stack-passed
        # path must too, else the store below names an undeclared slot. The
        # incoming eightbyte IS the pointer, so both the bridge and the store are
        # pointer-width — `loc.typ` is the AGGREGATE it points at, not the slot.
        g.varType[nm] = tns[i]
        g.emByRefPtrStackVar(nm, tns[i])
        let s = g.pickStagingSealed("a spilled stack-param pointer bridge", AddrSlot)
        g.ab.tree MovX64:
          g.emReg s
          g.ab.tree MemX: (g.ab.rawReg g.stackArgBaseReg; g.ab.intLit off)
        g.ab.tree MovX64: (g.emStackMem(loc.ptrName); g.emReg s)
        g.giveBack s
      else:
        raiseAssert "arkham x64 v0: stack parameter home " & $loc.kind & ": " & nm

proc genTvar*(g: var CodeGen; name: string; decl: Cursor) =
  ## Emit `(tvar :name <type> <intlit>?)`. nifasm allocates the FS offset and
  ## honours the optional literal by initializing the block's image.
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

proc emProcessExit*(g: var CodeGen; code: Location) =
  ## Terminate the process with exit status `code` — the LINUX entry proc's
  ## tail, which returns to nobody (the kernel entered it with no return
  ## address): the `exit_group` trap. Windows needs no counterpart: its entry
  ## is `call`ed by ntdll's thread-start thunk, so it returns like any other
  ## proc and the thunk exits the thread with the returned status — the entry
  ## is not special-cased there at all. (nimony's synthesized `main` never
  ## reaches either path: it terminates through a declared call to `cExit`.)
  assert not g.prog.windows, "arkham x64: emProcessExit on a win_x64 target"
  g.place2(code, RDI)
  g.movImm(RAX, LinuxX64ExitNr); g.emSyscall()

proc ensureFAccum*(g: var CodeGen; resF: FReg; loc: Location; bits: int) =
  ## Make the destructive-SSE accumulator `resF` hold the value just produced at
  ## `loc`. Normally the allocator fixed the producing operand's dest to the result
  ## register, so `loc` IS `resF` and this is a no-op; but when `resF` is a produce-into
  ## staging register (a spilled bin RESULT) the allocator placed the operand in its own
  ## location — move/load it in (the float analogue of the integer `place2`).
  case loc.kind
  of InFReg:
    if loc.f != resF:
      g.fmovF(resF, loc.f, bits)
      if loc.isTemp: g.unbindFTmp(loc.f)
  of NamedStack: g.emFloatScalarLoad(resF, loc.name, bits)
  else: raiseAssert "arkham x64n: float accumulator source " & $loc.kind

proc emAggrSrcAddr*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &name` for an aggregate SOURCE that may be a local stack slot, a by-ref
  ## aggregate param (its pointer is already in a register), OR a module-level
  ## global / `const` / threadvar. `locationOfSym` yields NamedStack/InReg for a local
  ## and `NoLoc` for a module-level symbol (disambiguated by category in
  ## `emSymAddrByName`). Crucially, the rsp-base `emStackAddr` must NOT be used for a
  ## global/const — its address is RIP-relative, not stack-relative (e.g. copying a
  ## global `const` aggregate like `NoNifLineInfo` out via a `return`).
  let home = g.plan.homeOfSym(name)
  case home.kind
  of NamedStack: g.emStackAddr(dest, name)
  of StackPtr:
    g.ab.tree MovX64: (g.emReg dest; g.emStackMem(home.ptrName))
  of InReg: g.movReg(dest, home.r)
  else: g.emSymAddrByName(dest, name)

proc copyStructThroughPtr2*(g: var CodeGen; srcVar: string; typeSym: SymId; ptrReg: Reg) =
  ## Copy `srcVar` → the memory `ptrReg` points at (the >16B aggregate hidden-result-
  ## pointer return). This runs at the `ret` and crosses NO call, so its scratch comes
  ## from the transient staging pool, never a callee-saved survivor (a survivor would
  ## force the allocator to find a stealable callee-saved local, which can spuriously
  ## fail). Usually that is ONE register — the word-transfer temp — because the source
  ## is a stack slot or an already-held pointer (`aggrSrcEnd`); only a global source
  ## stages a second.
  var sp = NoReg
  let src = g.aggrSrcEnd(srcVar, sp)
  let tmp = g.pickStagingSealed("a struct-through-ptr word", AddrSlot, avoid = sp)
  g.copyAggr(regEnd(ptrReg), src, aggrByteSize(g.prog, typeSym), tmp)
  g.giveBack tmp
  g.giveBack sp
