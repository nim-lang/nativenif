#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `CodeGen` — everything one emitter run carries, and nothing else.
##
## Nim has no cyclic imports, so the state the whole backend threads through
## itself cannot live in any module that also *does* something with it: the
## value core, the frame builder, the aggregate marshaller and the driver all
## need it, and they need each other. It therefore sits here, in a module that
## imports only what the record's own field types require and that nothing below
## it imports back. Every other module takes `g: var CodeGen` as a parameter.
##
## `newCodeGen` and `adoptProgram` are the "plus some creation logic" half: the
## three targets build their `CodeGen` differently (different machine model,
## different `collect` flags) but read the loaded program model identically, and
## that identical part is what a divergence would hide in.

import std / [tables, sets]
import nifcore
import asmslots, machinedesc, planer, programs
import "../risc/machine_m"                # the Cortex-M machine model
import layout                            # Layout: the `--layout:` board file
import asmbuf

import regbind
import "../../nifasm/core/model"         # X64Inst: the fused-compare tag

type
  OvfMode* = enum
    OvfNone,                                  ## no pending keepovf predicate
    OvfSign,                                  ## overflow iff `ovfReg` is negative (signed add/sub)
    OvfCmpLo,                                 ## overflow iff `ovfReg <u ovfReg2` (unsigned carry/borrow)
    OvfNeqZero                                ## overflow iff `ovfReg != 0` (a64 mul: smulh/umulh high half)

  NameBindTyp* = object
    ## How to re-emit the TYPE of a named local/param binding. `RegBind` keeps only
    ## the name and the pointer bit, but `(rebind :name TYPE (reg))` must name the
    ## same type the `(var …)` declared, so the two producers record theirs here.
    aggrSym*: SymId                          ## set ⇒ `(ptr <that type>)`, by pool id
                                             ## (`emRegAggrPtrVar`: a pointer to an aggregate)
    isPtr*: bool                             ## else `emRegLocalVar`'s rule: a pointer keeps its
    typ*: Cursor                             ## declared `(ptr T)`, everything else is `(i 64)`

  CondFusion* = object
    ## The bool that is never materialised: `(asgn b <cmp>)` … `(if b …)` emits the
    ## compare, skips the `setcc`/`and $1` that would build `b`, and lets the branch
    ## read the FLAGS. **328 of the 511 `setcc`+`and` sites in a nifbench build are
    ## this shape** — hexer's inliner turning a one-expression `proc (a, b: int):
    ## bool` into a declaration, an `(asgn b (lt …))`, a return label and a branch.
    ##
    ## x86-64 ONLY: `tag` is an `X64Inst` (the `jcc` that means "true"), and AArch64
    ## has its own condition handling. `scanCondFusions` and the emitter that reads
    ## these both live in `codegen_x64`.
    ##
    ## Two halves, with different lifetimes — which is why they are one object but
    ## not one table:
    ##  * the PLAN — `cmp` / `link` / `decl`, token positions `scanCondFusions`
    ##    decides ONCE per proc and only reads thereafter;
    ##  * the in-flight STATE — `tag`, written when the compare is emitted and taken
    ##    by the branch that consumes it, live only across statements that emit no
    ##    machine code (an unreferenced `(lab …)`, a value-less declaration, a
    ##    `(scope …)` boundary). Reset per proc, ahead of the scan.
    cmp*: HashSet[int]                       ## `(asgn b <cmp>)` — the compare that STAYS put
                                             ## (moving it to the branch would name operands
                                             ## whose scope has closed); only the ANSWER travels,
                                             ## in the flags, which is sound because `setcc`
                                             ## never writes them
    link*: HashSet[int]                      ## `(asgn b2 b1)` / `(asgn b2 (not b1))` LINKS in the
                                             ## chain: the inliner renames the bool once per
                                             ## splice level, so the compare and the branch are
                                             ## rarely adjacent. A link emits nothing — it re-keys
                                             ## (and maybe inverts) the pending tag
    decl*: HashSet[int]                      ## the matching `(var :b . bool .)` declarations —
                                             ## nothing reads `b`, so it need not reserve a
                                             ## register either
    tag*: Table[string, X64Inst]             ## bool symbol → the `jcc` that means "true"

  CodeGen* = object
    ab*: AsmBuf
    plan*: Plan
    buf*: ptr TokenBuf
    md*: MachineDesc                         ## target register file + ABI
    prog*: Program                           ## the whole program (cross-module type env)
    callTarget*: Table[string, CallTarget]
    globals*: Table[string, Cursor]          ## global var name → its decl cursor
    tvars*: Table[string, Cursor]            ## thread-local var name → its decl cursor (macOS TLV)
    tvarNames*: HashSet[string]              ## tvar names, for the per-proc analyser
    freeTmp*: set[Reg]                       ## volatile temps free for scratch
    freeFTmp*: set[FReg]                     ## volatile SIMD/FP temps free for scratch
    retIsFloat*: bool                        ## current proc returns a float (in v0)
    retFloatBits*: int                       ## width (32/64) of the float return type
    rodata*: seq[(string, string)]           ## module-level string literals
    hasFrame*: bool                          ## current proc needs a stack frame
    frameRegs*: seq[Reg]                     ## callee-saved GPRs to save (even count)
    frameFRegs*: seq[FReg]                   ## callee-saved SIMD regs to save (even count)
    framePad*: int                           ## x64: extra prologue `sub rsp` for 16-byte call alignment
    stackArgBaseReg*: Reg                     ## x64: callee-saved reg holding the incoming stack-args
                                              ## base (rsp after pushes), captured before the frame
                                              ## `sub`s so stack params survive rsp moving; else NoReg
    labelCount*: int                         ## fresh-label counter
    emitTmpSpills*: int                      ## step-3 value core: fresh counter for emit-time
                                             ## minted spill slots (`etmpN.0`/`eftmpN.0`/
                                             ## `heldN.0`) — the merged emitter's analogue of
                                             ## the allocator's `tmpSpills`. Reset per proc.
    lastResortBridges*: set[Reg]             ## bridges taken PAST a step's declaration
                                             ## because every alternative was gone.
                                             ## While one is held the emitter is
                                             ## knowingly past its budget, so the I1
                                             ## progress check downgrades to a count
                                             ## rather than asserting: the shortfall
                                             ## is the escape working, not a
                                             ## composition nobody accounted for.
                                             ## Cleared by `unbindTemp`, the single
                                             ## release point.
    bridgeScopes*: seq[tuple[base, cap: int; what: string]]
                                             ## I2: the declared bridge budget of each emitter
                                             ## step currently on the stack. `base` is how many
                                             ## reserved bridges were already live when the step
                                             ## was entered (its ENCLOSING holders), `cap` how
                                             ## many it declared for itself. `emit.takeBridge`
                                             ## refuses a take past `base + cap`, so an
                                             ## over-budget step is caught AT the step that is
                                             ## wrong rather than at whichever later take found
                                             ## nothing left. Empty in a release build, where
                                             ## `emit.BridgeCheck` compiles the whole mechanism
                                             ## out.
    pickedRegs*: set[Reg]                    ## step-3 value core: GPRs handed out by `takeTmp`/
                                             ## `takeHeld` but not yet BOUND — the reserve→bind
                                             ## gap of the lazy-bind convention (a consumer
                                             ## binds a temp only when it materializes a value
                                             ## into it). Freeness filters exclude these so a
                                             ## nested pick can't steal a reserved accumulator.
                                             ## `freeVal` clears the flag on release.
    pickedFRegs*: set[FReg]                  ## the SIMD twin of `pickedRegs`
    noFoldPos*: int                          ## token pos of a `keepovf`'s op node: it must
                                             ## EMIT even when constant-foldable, because the
                                             ## `(ovf)` test that follows reads the hardware
                                             ## flag that very instruction sets. -1 = none.
                                             ## Set by genStmt2's KeepovfS around its store,
                                             ## mirrored by the allocator's walk (same rule,
                                             ## same position). Checked wherever a fold would
                                             ## replace the op with an immediate.
    binNormSuppressPos*: int                 ## token pos of the ONE bin-arith node whose
                                             ## canonical sub-width `shl;sar` re-normalization is
                                             ## dead because its result feeds a truncating store of
                                             ## width <= the bin's type (set by genStore2, read by
                                             ## emitBin2). -1 = none. Never suppresses a result that
                                             ## feeds `shr`/unsigned-cmp/div (those aren't stores).
    tailStmt*: bool                          ## the statement about to be emitted is in TAIL
                                             ## position: control falls straight through to the
                                             ## proc epilogue afterwards, so a `ret` here needs no
                                             ## `jmp retLabel2`. Propagated to the last child of a
                                             ## `stmts`/`scope`; reset to false for any nested
                                             ## compound so a mid-body `ret` still jumps.
    loopEnds*: seq[string]                   ## stack of enclosing-loop end labels (for `break`)
    retLabel2*: string                       ## value-core: shared epilogue label a mid-proc `ret` jumps to
    retLabelUsed2*: bool                     ## value-core: a `ret` jumped to retLabel2 ⇒ emit the label
    retAggrSym*: SymId                       ## POOL ID of the current proc's aggregate return
                                             ## type, `NoTypeSym` when the result is not an
                                             ## aggregate
    retIndirect*: bool                       ## return type is >16B (x8 indirect result)
    isEntryProc*: bool                       ## the proc currently emitted is the entry
    helperCalls*: bool                       ## Cortex-M: the proc being emitted calls a
                                             ## runtime helper (the 64-bit divider) with a
                                             ## bare `bl`. `bl` overwrites lr, and nothing
                                             ## in the analyser's view of a `div` node says
                                             ## "call" — so the frame has to be forced from
                                             ## here. Reset per proc; read by `computeFrame`.
    needsUDiv64*, needsSDiv64*: bool         ## Cortex-M, MODULE-scope: emit the 64-bit
                                             ## division routines, and only if something
                                             ## divides
    board*: layout.Layout                    ## the `--layout:` board, when one was
                                             ## given. arkham reads it and forwards it;
                                             ## nifasm places segments from the forward.
    rvStackTop*: int64                       ## RV32 only: the value the reset path
                                             ## loads into `sp`.
                                             ##
                                             ## A number arkham must know at CODEGEN
                                             ## time, because on this target the
                                             ## initial stack pointer is an
                                             ## INSTRUCTION rather than a word the
                                             ## image writer fills in. Cortex-M gets
                                             ## its from vector-table slot 0, which
                                             ## is why nothing like this exists
                                             ## there.
    thumbM*: bool                            ## the SAME emitter, targeting Cortex-M
                                             ## (ARMv7E-M) instead of AArch64. The two
                                             ## share the asm-NIF vocabulary by design —
                                             ## `add3`, `cmp`, `beq`, `ldr`, `adr` mean
                                             ## the same thing on both — so what differs
                                             ## is the register file (`md`), the word
                                             ## size (`slots.setTargetWord`), and the
                                             ## features Cortex-M does not have, which
                                             ## are rejected by name rather than
                                             ## silently mis-emitted.
    oneThread*: bool                         ## this image has exactly ONE thread of
                                             ## execution, so a thread-local IS a
                                             ## global and is emitted as one. True
                                             ## for a static ELF (per-thread ==
                                             ## per-process) and for a bare-metal
                                             ## image whose board declares a single
                                             ## stack slot. NOT a property of the
                                             ## ISA: a Cortex-M part with four cores
                                             ## has four threads and needs real
                                             ## thread-local storage, which is why
                                             ## this is asked of the BOARD rather
                                             ## than assumed of the target.
    entryExits*: bool                        ## the ENTRY proc exits instead of
                                             ## returning: there is nobody to return
                                             ## TO. True on static Linux (the kernel
                                             ## entered `_start`, so the epilogue is
                                             ## replaced by an exit syscall) and on
                                             ## bare metal (reset entered it, and a
                                             ## `bx lr` from there returns into
                                             ## nothing). False on Darwin, where the
                                             ## entry is called by libSystem's start
                                             ## and returns its status normally.
    a64Linux*: bool                          ## a64 backend: target Linux/ELF (svc-based
                                             ## syscalls, no Darwin TLV/dyld) instead of
                                             ## the default Darwin/Mach-O — lets the arm64
                                             ## output run under qemu-aarch64 on Linux
    rb*: RegBind                              ## the emitter's register-binding state: reg↔name
                                              ## bindings, temp/pointer flags, scope stacks and
                                              ## the accumulator/SIMD seals. Fields are private
                                              ## to regbind.nim — every mutation goes through
                                              ## its transition procs, which keep the tables
                                              ## consistent as one atomic step (the historic
                                              ## Cat-1 bug source was ad-hoc partial updates).
    indirectReg*: Reg                        ## callee-saved reg holding the x8 dest pointer
    varType*: Table[string, SymId]           ## aggregate var/param name → the POOL ID of its
                                             ## nominal type: the key every layout query takes
                                             ## (`aggrLayout`/`aggrByteSize`/`lookupType`), so a
                                             ## lookup here hands one straight on without
                                             ## minting a name
    stackSlots*: HashSet[string]             ## names declared as a nifasm `(var :name (s) …)`
                                             ## slot, hence addressable straight off rsp. Same
                                             ## lifetime as `varType` (arkham symbol names are
                                             ## module-unique, so it need not be per-proc; and a
                                             ## stale hit would make nifasm reject an rsp-relative
                                             ## reference to a non-stack symbol, never miscompile
                                             ## it). The allocator's `NamedStack` locals are
                                             ## only part of it: the emitter also synthesizes
                                             ## slots (constructor temps, `nctmp…`) that no
                                             ## `symPos` knows about, and `locationOfSym`
                                             ## reports those as `NoLoc` — indistinguishable
                                             ## from a module-level global, which is NOT
                                             ## rsp-relative. A copy that wants the zero-register
                                             ## `(mem (rsp) name off)` form must tell them apart.
    symType*: Table[string, Cursor]          ## local/param name → its Leng type cursor (for getType)
    aliasToDecl*: Table[string, string]      ## param ABI alias `pN.0` → the param's own decl
                                             ## name (its `symPos` key). A register-passed
                                             ## param binds its arg reg to the signature alias
                                             ## `pN.0`, which is NOT a `symPos` key; this lets
                                             ## `recordEviction` recover the decl name from the
                                             ## point-in-time binding with no `plan.locs`
                                             ## reverse scan. Populated at the param prologue.
    tmpBindTyp*: Table[Reg, AsmSlot]         ## the `AsmSlot` each `bindTemp` bound a register
                                             ## with. `RegBind` keeps only the name and the
                                             ## pointer bit, and a `(rebind …)` has to name the
                                             ## same type the register was bound with.
    condFuse*: CondFusion                    ## x64: the compare-into-branch fusion — its plan
                                             ## (which statement positions to skip) and the
                                             ## pending flags tag. See `CondFusion`.
    postDivergeBinds*: seq[tuple[r: Reg, name: string]]
                                             ## bindings on CALLER-SAVED registers that
                                             ## `restoreBindings` re-established after a diverging
                                             ## call. Valid only until the next call that actually
                                             ## RETURNS clobbers the register — `AllRegs` says no
                                             ## such call is in the value's range, so killing them
                                             ## there loses nothing and stops a stale name from
                                             ## renaming an ABI result register.
    nameBindTyp*: Table[string, NameBindTyp] ## the twin of `tmpBindTyp` for NAMED locals and
                                             ## params: what type to re-emit when a binding has
                                             ## to be re-established. Only consumer so far is
                                             ## `restoreBindingsAfterDiverging`.
    when defined(arkhamStagingDbg):
      stagingLive*: seq[(Reg, string)]  ## staging registers handed out and not yet given
                                        ## back, with the label of what asked for each
      stagingPeak*: int                 ## the most that were ever live AT ONCE in this proc
      stagingPeakWhat*: string          ## and which labels those were — the SHAPE to reserve for
    curProcName*: string                     ## the proc currently being emitted. arkham's input
                                             ## carries no line info, so a bare register-pressure
                                             ## or typing assert names nothing actionable; this
                                             ## pins it to one routine (same reason nifasm's
                                             ## `error` reports `in proc …`).
    rawHomeRegs*: set[Reg]                   ## x64: the registers hosting a home that the
                                             ## `rb` binding table CANNOT see — a param whose
                                             ## home is written as a RAW `(reg)` and read back
                                             ## raw for the rest of the body. These, and only
                                             ## these, need a per-proc reservation; see
                                             ## `regFreeForTemp`. Populated by `emitParamMoves`
                                             ## / `emitStackParamLoadsX64` / the hidden-result
                                             ## and stack-arg-base setup, and reset per proc.
    narrowHomes*: bool                       ## the backend populated `rawHomeRegs` and wants
                                             ## `regFreeForTemp` to consult it INSTEAD of the
                                             ## whole-proc `regHoldsHome` union. x64 only —
                                             ## a64 has not been audited for raw param homes,
                                             ## so it keeps the coarse (safe) filter.
    argResidentParams*: seq[tuple[r: Reg, name: string]]
                                             ## x64: (arg register, bound name) for each
                                             ## `ArgResident` param (kept in its incoming reg
                                             ## despite the proc making calls). The binding is
                                             ## live until the param's consuming call; after the
                                             ## FIRST call clobbers the arg regs the param is
                                             ## dead, so its `regLocal` binding is `(kill)`'d
                                             ## then — else a later raw reuse of the reg (e.g. an
                                             ## exit syscall) would emit the dead param's typed
                                             ## name. Only killed if the reg STILL holds `name`
                                             ## (a rebind to a temp already released the param).
    argResidentFlushed*: bool                ## the post-first-call kill above has run
    cleanSigProcs*: HashSet[string]          ## x64: decl names of clean-signature procs
                                             ## (all-scalar-GPR params, non-aggregate result);
                                             ## a same-position param arg to one is a self-move.
                                             ## Computed once (see `cleanSigComputed`).
    noReturnProcs*: HashSet[SymId]           ## pool ids of called `(attr "noreturn")` procs;
                                             ## a call to one is not a liveness call point.
                                             ## Computed once, alongside `cleanSigProcs`.
    cleanSigComputed*: bool
    savedHomes*: Table[int, Location]        ## value-core pure path: a deref/at/pat base or
                                             ## index left in its stack home by the allocator is
                                             ## loaded into a transient staging reg for the lval
                                             ## emission; its original `NamedStack`/`Mem` home is
                                             ## parked here (keyed by value position) and restored
                                             ## by `unbindLvalTemps2`.
    lvalStride*: Table[int, Reg]             ## x64: the non-SIB `(at/pat base idx scratch)` stride
                                             ## scratch is picked from the emit-time STAGING set
                                             ## (the always-free R11 bridge + free caller-saved),
                                             ## NOT reserved by the allocator from the local-
                                             ## competing temp pool — so it never starves under
                                             ## register pressure. Keyed by the at/pat position,
                                             ## populated in `prematLval2`, consumed by
                                             ## `emLvalAddr2`, released by `unbindLvalTemps2`.
    lvalStrideBorrowed*: HashSet[int]        ## x64: the `lvalStride` entries that BORROW the
                                             ## consuming instruction's destination register
                                             ## instead of taking a staging reg of their own.
                                             ## The consumer owns that register, so
                                             ## `dropLvalStride` must not unbind it.
    lvalStrideOnBridge*: HashSet[int]        ## a64: the `(at/pat)` positions whose stride scratch
                                             ## must come from a STAGING BRIDGE at emission time
                                             ## because the allocation walk found the temp pool AND
                                             ## the callee-saved file fully live (register-homed
                                             ## locals do not compete for a bridge). Recorded by
                                             ## `emitLvalWalk`, honoured in `prematLval2`, released
                                             ## with the rest of the scratch in `freeLvalTemps2`.
    lvalGlobBase*: Table[int, Reg]           ## x64: the address of a module-level global
                                             ## aggregate base used in a transient LOAD (e.g. a
                                             ## float field read whose result is an xmm, so the
                                             ## GPR address can't be the result reg). Sourced from
                                             ## emit-time STAGING (R11 bridge), NOT a survivor pool
                                             ## reg — same lifecycle/rationale as `lvalStride`.
    ovfSigned*: bool                          ## signedness of the most recent `keepovf` op, so
                                             ## the `(ovf)` test that immediately follows it picks
                                             ## the right hardware-flag branch (`jo`/`jno` for a
                                             ## signed op, `jb`/`jae` = CF for an unsigned op)
    ovfMode*: OvfMode                         ## a64: how the pending `(ovf)` test reads the
                                             ## overflow predicate (no flag-setting arithmetic in
                                             ## the nifasm a64 vocabulary — see genStmt2 KeepovfS)
    ovfReg*: Reg                              ## a64 OvfSign: the register holding the sign-bit
                                             ## predicate; OvfCmpLo: the cmp's LHS
    ovfReg2*: Reg                             ## a64 OvfCmpLo: the cmp's RHS
    ovfBridges*: seq[Reg]                     ## a64: staging bridges the `(ovf)` test releases
    tailCallEmitted*: bool                    ## the call just emitted was a TAIL call
                                              ## (`(popframe)` + `(tailcall)`), so control
                                              ## has left the proc — the caller must not
                                              ## also branch to the epilogue.
    lateBaseSpare*: Reg                       ## a64: a register the CALLER knows is dead across
                                              ## the lvalue premat it is about to run — offered to
                                              ## `lateGlobalBase` as a home for `&g` when neither a
                                              ## free volatile nor a staging bridge is left. Set
                                              ## around one `prematLval2` call and cleared right
                                              ## after; never read anywhere else.
    lateBaseBorrowedAt*: HashSet[int]         ## a64: lvalue positions whose global base went into
                                              ## `lateBaseSpare` rather than into scratch of its
                                              ## own. The register belongs to the CALLER, so the
                                              ## matching `unbindLvalTemps2` must leave it bound.
    # ── `.assembler` transliteration (doc/intrinsics.md §8) ──
    # In an `.assembler` proc there is no allocator: every value's home is DECLARED
    # (`.register`/`.stack` on the param or local), so the register IS the identity
    # and these two tables are the whole location model. Several Leng names may map
    # to one register — that is the user pinning them together, not a conflict —
    # so `emReg` renders whichever nifasm binding is live there.
    asmReg*: Table[string, Reg]               ## Leng local/param name → its pinned register
    asmStack*: HashSet[string]                ## Leng local names pinned to an `(s)` slot
    asmInfo*: string                          ## last `file(line, col)` seen while walking an
                                              ## `.assembler` body: the fallback location for a
                                              ## rejection on a node with no line info of its own
    stagedArgs*: set[Reg]                     ## ABI argument registers whose value is
                                              ## CLAIMED right now: a call's arguments
                                              ## between the `(prepare …)` and its `(call)`,
                                              ## and the incoming parameters for as long as
                                              ## the prologue runs. Emit-time only — argument
                                              ## marshalling is an emitter activity, and the
                                              ## allocator never sees it. Read by the
                                              ## last-resort scratch draw on a target whose
                                              ## only volatiles ARE the argument registers.
    asmFlagsFresh*: bool                      ## Arm only: the flags were set by the instruction
                                              ## JUST emitted (a `cmp`) and nothing has run since.
                                              ## Arm has a flag-setting and a non-flag-setting form
                                              ## of every arithmetic instruction, and which one an
                                              ## assembler picks is an ENCODING choice — Thumb's
                                              ## narrow 16-bit forms set the flags whether or not
                                              ## anyone asked. So "what is in NZCV here" is only
                                              ## answerable immediately after the compare, and this
                                              ## is what makes reading them anywhere else an error
                                              ## instead of a value that depends on which registers
                                              ## the body happened to pin.

proc resetPlan*(cf: var CondFusion) {.inline.} =
  ## Drop the previous proc's fusion PLAN, ahead of `scanCondFusions` deciding this
  ## one's. Deliberately not `tag`: that is emit-time state with its own reset, and
  ## clearing it here would tie two different lifetimes to one call.
  cf.cmp.clear()
  cf.link.clear()
  cf.decl.clear()

type
  CallerSaveWindow* = object
    ## One open save window: what was stored, and the redirect table to put back when
    ## it closes. Opened at `emitCall2` — or EARLIER by a caller that writes an ABI
    ## register for the call itself (the hidden result pointer in rdi), which must
    ## happen after the save or it clobbers the value it was supposed to preserve.
    saved*: seq[tuple[reg: Reg, name: string]]
    prevActive*: Table[string, Location]

proc newCodeGen*(buf: var TokenBuf; md: MachineDesc): CodeGen =
  ## The parts every target starts from. What differs — the machine model, the
  ## register renderer, whether immediates may address memory, which target the
  ## `BodyLib` splices are keyed on — is set by the caller, because it IS the
  ## difference between the targets.
  checkMachine(md)
  CodeGen(ab: initAsmBuf(), buf: addr buf, md: md)

proc adoptProgram*(g: var CodeGen) =
  ## Read the loaded program model into the fields the emitter consults directly.
  ## `collect` is called per target (its flags differ); everything after it is
  ## the same on all three, which is exactly why it belongs here rather than
  ## three times over.
  g.callTarget = g.prog.callTarget
  g.globals = g.prog.globals
  g.tvars = g.prog.tvars
  for nm in g.tvars.keys: g.tvarNames.incl nm
