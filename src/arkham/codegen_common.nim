#
#           Arkham — shared front-end for the native code generators
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Architecture-neutral front-end shared by the per-target backends
## (`codegen_a64`, `codegen_x64`). Holds the `CodeGen` state object, the Leng
## type/lvalue analysis (`getType` / `exprSlot` / `asLoc` and friends) and
## the type predicates. None of this emits instructions — instruction selection
## and the machine frame live in the backends. The `md` field carries the
## target `MachineDesc` so the backends drive the (shared) register allocator
## and scratch pools from it.

import std / [tables, sets, assertions, algorithm, strutils, os]
import symparser
import nifcore, nifcdecl
import slots, machinedesc, analyser, register_allocator, programs
import asmbuf
import typenav
export typenav   # SymCat / SymInfo / getType / exprSlot moved here; re-export so
                 # the backends' `g.lookupSym(...).cat` etc. keep resolving
import regbind
export regbind   # the emitter's register-binding state (`g.rb`); the single
                 # owner of reg↔name bindings — see regbind.nim

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
    ra*: RegAlloc
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
                                             ## point-in-time binding with no `ra.locs`
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

proc resetPlan*(cf: var CondFusion) {.inline.} =
  ## Drop the previous proc's fusion PLAN, ahead of `scanCondFusions` deciding this
  ## one's. Deliberately not `tag`: that is emit-time state with its own reset, and
  ## clearing it here would tie two different lifetimes to one call.
  cf.cmp.clear()
  cf.link.clear()
  cf.decl.clear()

# ── user-facing diagnostics ─────────────────────────────────────────────────
# Most of arkham's internal consistency checks are `raiseAssert`s: they can only
# fire on a compiler bug, so a stack trace is the useful output. An `.assembler`
# body is different — arkham is the ONLY checker of that source-level subset (see
# `doc/intrinsics.md` §8), so its rejections are ordinary user errors and must
# read like one. NIF carries the original file/line/col on the very node that is
# wrong, which is why delegating the checking here costs no diagnostic quality.

proc userName*(sym: string): string =
  ## `r.0.mymod` → `r`. A NIF symbol is `<name>.<disambiguator>[.<module>]`; both
  ## suffixes belong to the front end, so neither may appear in a message a human
  ## reads — they would name something the user never wrote.
  result = splitSymName(sym).name             # drops the module suffix
  var i = result.len - 1
  while i > 0 and result[i] in {'0' .. '9'}: dec i
  if i > 0 and i < result.len - 1 and result[i] == '.': result.setLen i

proc lengInfo*(c: Cursor): string =
  ## `file(line, col)` for the Leng node `c`, or "" when it carries no line info
  ## (NIF line info is sparse: only nodes the front end stamped have it).
  let li = rawLineInfo(c)
  if not li.file.isValid: return ""
  result = lineInfoFile(c) & "(" & $li.line & ", " & $li.col & ")"

proc lengError*(c: Cursor; msg: string; fallback = "") {.noreturn.} =
  ## Report a user error against the Leng node `c` and stop. `fallback` is a
  ## previously-seen `lengInfo` used when `c` itself is uninformative, so a
  ## rejection always points at least at the enclosing statement.
  var where = lengInfo(c)
  if where.len == 0: where = fallback
  if where.len == 0: where = "arkham"
  quit where & " Error: " & msg, QuitFailure

# ── type predicates ─────────────────────────────────────────────────────────

proc isSignedType*(c: Cursor): bool =
  ## Leng arithmetic carries its result type as the first child; treat it as
  ## signed unless it is an unsigned/char integer. (A `case` disambiguates the
  ## LengType enum members, which share spellings with nifasm's NifasmType.)
  if c.kind != TagLit: return true
  case c.typeKind
  of UT, CT: false
  else: true

proc intTypeWidth*(c: Cursor): int =
  ## Bit width of an integer/char type; 64 for pointer/bool/other (register width).
  if c.kind != TagLit: return 64
  case c.typeKind
  of IT, UT, CT:
    var t = c; inc t
    if t.kind == IntLit and intVal(t) > 0: int(intVal(t)) else: 64
  else: 64

proc slotWidthSigned*(s: AsmSlot): tuple[width: int, signed: bool] =
  ## A scalar slot's significant bit width and signedness (for extension).
  case s.kind
  of AInt:  (s.size * 8, true)
  of AUInt: (s.size * 8, false)
  of ABool: (8, false)
  else:     (64, true)                      # float/aggregate: no widening extend

proc isPtrType*(c: Cursor): bool =
  ## A `case` (not an `in {…}` set) so the discriminant type picks nifcdecl's
  ## `LengType.PtrT`, not nifasm's same-spelled `NifasmType` member.
  if c.kind != TagLit: return false
  case c.typeKind
  of PtrT, AptrT, ProctypeT: true
  else: false

proc binResultSlot*(g: var CodeGen; resTypeC: Cursor): AsmSlot =
  ## The slot for the register a binary-arith result lands in: the node's OWN
  ## result type, so the temp is bound `(c 8)`/`(u 16)`/… rather than a dont-care
  ## `(i 64)`. The register is 64 bits wide either way — that is where the value
  ## lives, not what it is, and binding it as `(i 64)` discards the range and the
  ## signedness the rest of the pipeline is entitled to check.
  var t = resTypeC
  result = slotOf(g.prog, t)

proc bindTypeDiffers*(prog: var Program; a, b: Cursor): bool =
  ## Would nifasm see two different BINDING types for `a` and `b`? Compares exactly
  ## what a register binding declares — pointer-ness, width, signedness — so a
  ## caller can skip a retype that would emit the same type it already has.
  ## Two pointers always count as differing: the pointee drives field/element
  ## typing, and a retype between them is free (zero machine code).
  let ra = resolveType(prog, a)
  let rb = resolveType(prog, b)
  let pa = isPtrType(ra)
  let pb = isPtrType(rb)
  if pa or pb: return true
  result = intTypeWidth(ra) != intTypeWidth(rb) or isSignedType(ra) != isSignedType(rb)
  if not result:
    # `intTypeWidth` answers 64 for anything that is not a literal `(i|u|c N)`, so
    # every ENUM looks the same width as every other. nifasm types an enum binding
    # by its BASE, and `(u 16)` vs `(u 8)` is exactly the mismatch that reached it:
    # `(cast NimonyType e)` out of a `TagEnum` skipped the pre-retype in `emitCast2`
    # and emitted a bare narrowing move. The SLOT does carry the base width.
    var ac = a
    var bc = b
    result = slotOf(prog, ac).size != slotOf(prog, bc).size

proc slotTypeDiffers*(prog: var Program; s: AsmSlot; t: Cursor): bool =
  ## `bindTypeDiffers` for a slot that may carry no cursor at all. A dont-care slot
  ## binds as `(i 64)`, so it differs from anything that is not that.
  if cursorIsNil(s.typ):
    let rt = resolveType(prog, t)
    return isPtrType(rt) or intTypeWidth(rt) != 64 or not isSignedType(rt)
  var a = s.typ
  result = bindTypeDiffers(prog, a, t)

proc checkArithResultType*(prog: var Program; resTypeC: Cursor; fallback = "") =
  ## An arithmetic node states its result type as its first child, and that type is
  ## an integer or a float. NO pointer is legal — not `(ptr T)`, not `(aptr T)`, not
  ## a proc type. Arithmetic on a pointer is not a Leng form.
  ##
  ## The reason is that an `add` does not say whether the offset counts BYTES or
  ## ELEMENTS, and the backends answered differently: nifasm emitted a plain machine
  ## `add` (bytes) while lengc compiles the same node as `((T)(a + b))` — C pointer
  ## arithmetic, SCALED by the pointee. Nothing in the program says which the
  ## producer meant, so there is no reinterpretation that is safe to pick.
  ##
  ## Both well-typed spellings already exist. Offsetting an array pointer is
  ## `(at base index)` / `(pat p i)`, which carry the element type and so have ONE
  ## meaning; raw byte work casts to an integer, computes, and casts back — the
  ## shape `cast_ptr_local_retype` exercises in the corpus.
  ##
  ## (`(aptr T)` was admitted here at first, on the theory that the array pointer's
  ## element stride made its arithmetic well-defined. It does not: the stride tells
  ## you what one element is, not whether `+ 8` meant eight of them.)
  let rt = resolveType(prog, resTypeC)
  if isPtrType(rt):
    lengError(resTypeC, "arithmetic result type is a pointer (" & $rt.typeKind &
              "); Leng has no arithmetic on pointers. Offset an array pointer with " &
              "`(at …)`/`(pat …)`, or cast to an integer, compute, and cast back.",
              fallback)

proc isNilValue*(c: Cursor): bool {.inline.} =
  ## True if `c` is the synthesized Leng `(nil)` node (a null-pointer value/type).
  not cursorIsNil(c) and c.kind == TagLit and c.exprKind == NilC

proc isNilSlot*(s: AsmSlot): bool {.inline.} =
  ## True if `s` carries the synthesized Leng `(nil)` type (a null pointer) — its
  ## register binds to the asm `(nil)` type and its immediate emits `(nil)`, not `0`.
  isNilValue(s.typ)

proc isSubWidthIntSlot*(s: AsmSlot): bool {.inline.} =
  ## A sized integer slot NARROWER than a register — `(i 32)`, `(u 8)`, … — that also
  ## carries its Leng type (so it can be re-emitted in a `(cast …)`). arkham keeps every
  ## register-homed local a full `(i 64)` binding and expresses width through explicit
  ## extends, so a temp bound to one of these is a deliberate narrow BRIDGE: a value
  ## arriving from a full-width register must be reinterpreted into it, never `mov`ed
  ## (nifasm allows only widening moves).
  s.kind in {AInt, AUInt} and s.size > 0 and s.size < 8 and not cursorIsNil(s.typ)

proc isNilImm*(loc: Location): bool {.inline.} =
  ## A `nil` value resolved to an immediate (`p = nil`, `p == nil`): emit `(nil)`.
  loc.kind == Imm and isNilSlot(loc.typ)

proc aggrByRef*(g: var CodeGen; typeSym: SymId): bool {.inline.} =
  ## SysV/AAPCS: an aggregate larger than the by-value threshold is passed AND
  ## returned by reference (a hidden pointer) instead of in registers — the single
  ## predicate behind every "by-ref vs by-value" branch (call marshalling, a
  ## call-returned-aggregate var, param moves, incoming-arg-reg counting).
  aggrByteSize(g.prog, typeSym) > g.md.aggrByRefThreshold

proc emTypeSym*(g: var CodeGen; id: SymId) {.inline.} =
  ## Emit the nominal type `id` as an asm-NIF symbol — THE boundary where a pool id
  ## becomes text, and now the only one. The asm buffer gets its own pool
  ## (`initAsmBuf` calls `createTokenBuf` with no `sharedPool`), so an INPUT-pool id
  ## is meaningless there and the name has to cross as characters; `addSymUse`
  ## re-interns it on the far side.
  ##
  ## Everything upstream of this call is keyed by the id: `lookupType` and the
  ## layout API over it, `varType`, `Location.StackPtr.pointeeType` /
  ## `Location.Field.aggrType`, `retAggrSym`. `pool.syms[]` yields `lent string`, so
  ## the operand costs no copy.
  g.ab.sym g.prog.pool.syms[id]

proc truncateImm*(v: int64; bits: int; signed: bool): int64 {.inline.} =
  ## Keep the low `bits` of `v`, sign-extending when `signed`. A Leng
  ## `cast[byte](4000)` is this truncation, not a nifasm-illegal
  ## `(mov (u 8) 4000)`.
  if bits <= 0 or bits >= 64: return v
  let mask = (1'i64 shl bits) - 1
  result = v and mask
  if signed and (result and (1'i64 shl (bits - 1))) != 0:
    result = result or (not mask)

# ── structural type / slot analysis ─────────────────────────────────────────

proc typeCtx*(g: var CodeGen): TypeCtx {.inline.} =
  ## A `TypeCtx` view over this `CodeGen`'s symbol tables, so `getType` / `exprSlot`
  ## (which now live in `typenav`, below both the allocator and the emitter) read
  ## the same storage. The fields are stable for the lifetime of the call.
  TypeCtx(prog: addr g.prog, callTarget: addr g.callTarget,
          globals: addr g.globals, tvars: addr g.tvars, symType: addr g.symType)

proc lookupSym*(g: var CodeGen; nm: string): SymInfo {.inline.} =
  g.typeCtx.lookupSym(nm)

proc getType*(g: var CodeGen; c: Cursor): Cursor {.inline.} =
  g.typeCtx.getType(c)

proc exprSlot*(g: var CodeGen; c: Cursor): AsmSlot {.inline.} =
  g.typeCtx.exprSlot(c)

proc declType*(g: var CodeGen; typeCur, valueCur: Cursor): Cursor =
  ## The type a local should be DECLARED with. Shoggoth's SROA / cse /
  ## induction-variable passes synthesize `(var :t . . <value>)` with the type
  ## slot LEFT EMPTY and the type implied by the initializer — a form lengc
  ## already infers (`codegen.genVarDecl`'s `getNominalType` fallback), so
  ## arkham must too. An empty slot otherwise sizes as `AMem 0` (which asserts
  ## in `typeSizeAlign`) and, worse, an `(addr x)` initializer silently loses
  ## its `(ptr T)`-ness so every later deref/field access mistypes.
  ## `allocVarDecl` already infers the SLOT this way (`typeIsOmitted`); this
  ## gives the emitter and `symType` the matching type CURSOR, so the two
  ## passes agree.
  if typeCur.kind != DotToken: return typeCur
  if not valueCur.hasMore or valueCur.kind == DotToken: return typeCur
  result = g.getType(valueCur)

proc tryConstFold*(g: var CodeGen; c: Cursor): (bool, int64) =
  ## Evaluate a compile-time-constant INTEGER expression to its value WITHOUT
  ## advancing the cursor or emitting anything. Delegates to `constFold`
  ## (programs.nim) — the ONE width-masked evaluator the allocator and both
  ## emitters consult, so a fold decision is a pure function of the subtree and
  ## the passes cannot disagree about it. The caller materializes the result as
  ## a single `Imm` Location — one immediate, foldable into the consuming
  ## `cmp`/`add`/… — instead of the runtime mov/sub sequence a tree-walk would
  ## emit (e.g. `SmallChunkSize - sizeof(SmallChunk)` → `0xFC0`, not a
  ## load-load-subtract).
  constFold(g.prog, c)

proc isFloatExpr*(g: var CodeGen; c: Cursor): bool =
  ## Whether `c` has floating-point type (so it flows through the SIMD path).
  g.exprSlot(c).kind == AFloat

proc floatBits*(g: var CodeGen; c: Cursor): int =
  ## Bit width (32 or 64) of a float expression; 64 when undeterminable (e.g. a
  ## bare literal — the caller's context width should be used instead).
  if g.exprSlot(c).size == 4: 32 else: 64

proc srcWidthSigned*(g: var CodeGen; c: Cursor): tuple[width: int, signed: bool] =
  ## Best-effort source scalar (bit width, signedness) of the expression at `c`,
  ## *without* consuming it — used to pick sign- vs zero-extension when a
  ## conversion *widens*. Unknown → (64, true): treated as full register width,
  ## i.e. no widening extension is applied (the pre-source-aware behaviour).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.ra.locationOfSym(nm, cursorToPosition(g.buf[], c))
    if loc.kind != NoLoc:
      return slotWidthSigned(loc.typ)        # a local/param: the allocator knows it
    let si = g.lookupSym(nm)                   # a global / thread-local: read its decl type
    case si.cat
    of scProc: return (64, true)               # a code pointer
    of scGlobal, scTvar:
      var d = si.decl
      d.into:
        inc d; skip d                          # name, pragmas
        return slotWidthSigned(slotOf(g.prog, d))
    of scNone: return (64, true)
  of UIntLit, CharLit:
    # An UNSIGNED literal. The width is the full register (nothing to extend), but
    # the signedness decides `scvtf` vs `ucvtf`: `float(0xFFFF_FFFF_FFFF_FFFF'u64)`
    # is 1.8446744073709552e19, not -1.0.
    return (64, false)
  of TagLit:
    case c.exprKind
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC,
       BitandC, BitorC, BitxorC, BitnotC, NegC, ConvC, CastC:
      var t = c                               # these carry their result type first
      t.into:
        return slotWidthSigned(slotOf(g.prog, t))
    of SufC, ParC:                            # wrappers: the inner value decides
      var t = c
      t.into:
        return g.srcWidthSigned(t)
    of TrueC, FalseC: return (64, false)
    else: return (64, true)
  else: return (64, true)

# ── unified location model (addressing modes + computed values) ─────────────
# `Location` (machinedesc) is THE descriptor for "where a value lives, or should
# go" — a register, a stack slot, a global/thread-local, a foldable memory operand
# (`Mem`, carrying the lvalue subtree to re-emit), an immediate, or `Undef` (the
# dont-care target). It is shared by the register
# allocator (long-lived storage) and the backends (just-computed values + lvalue
# destinations). `asLoc` parses a Leng lvalue cursor into one; `genVal` produces a
# computed value as one; the `gen`/load-store family consume it. This replaces the
# former separate `Lvalue` + `Val` descriptors that flowed through codegen.

proc asLoc*(g: var CodeGen; c: var Cursor): Location =
  ## Classify and consume an lvalue (Symbol / dot / at / deref) into a `Location`.
  ## `typ` records float-ness/width for the caller. A `Mem` captures the lvalue
  ## subtree (`cur`) so a backend re-emits it as a `(dot …)`/`(at …)`/`(deref …)`
  ## operand; a `NamedStack` is addressed by the *location's* name, not the
  ## variable's (a codegen-time steal renames an evicted register-local's slot to
  ## `evictN.0`; for an un-evicted local the two coincide).
  let slot = g.exprSlot(c)
  let nCur = c                                 # capture the subtree before consuming
  case c.kind
  of Symbol:
    let nm = symName(c); inc c
    let si = g.lookupSym(nm)
    case si.cat
    of scTvar: result = tvarLoc(nm, slot)
    of scGlobal: result = globLoc(nm, slot)
    of scProc:
      # A proc as a value is its address, not an lvalue; `genVal` emits the `lea`.
      raiseAssert "arkham: proc used as an lvalue: " & nm
    of scNone:
      let loc = g.ra.homeOfSym(nm)
      case loc.kind
      of InReg: result = regLoc(loc.r, slot)
      of InRegPair: result = loc
      of InFReg: result = fregLoc(loc.f, slot)
      of NamedStack: result = namedStackLoc(loc.name, slot)  # aggregate or scalar; `typ` tells apart
      of StackPtr: result = stackPtrLoc(loc.ptrName, loc.pointeeType, slot)
      else: raiseAssert "arkham: symbol is not an lvalue: " & nm
  of TagLit:
    case c.exprKind
    of DotC, AtC, DerefC, PatC: (result = memLoc(nCur, slot); skip c)
    else: raiseAssert "arkham: not an lvalue: " & $c.exprKind
  else: raiseAssert "arkham: not an lvalue: " & $c.kind

proc retIsVoid*(t: Cursor): bool {.inline.} =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

# ── static constant data layout (shared) ───────────────────────────────────
# Lower a Leng compile-time constant (`scalar` / `(oconstr …)` / `(aconstr …)` /
# string) to the raw little-endian bytes of its in-memory representation, so a
# backend can emit it as one read-only `(rodata …)` blob instead of zeroing
# `.bss` and running an initialiser at entry. Arch-neutral: the layout follows
# the same `typeSizeAlign` the ABI uses.

proc specialFloatBits*(ek: LengExpr; bits: int): int64 =
  ## IEEE-754 bit pattern of `(inf)` / `(-inf)` / `(nan)` at `bits` width. Both
  ## backends materialize these through a GPR: the exponent-all-ones patterns are
  ## outside what either ISA's float immediate encoding reaches (a64's `fmov`
  ## 8-bit immediate covers normal values only; x64 has no float immediate at
  ## all). `nan` is the quiet NaN — the sign bit is clear and the payload is the
  ## leading quiet bit, matching what every other backend emits for it.
  if bits == 32:
    case ek
    of InfC: 0x7F80_0000'i64
    of NeginfC: 0xFF80_0000'i64
    else: 0x7FC0_0000'i64
  else:
    case ek
    of InfC: 0x7FF0_0000_0000_0000'i64
    of NeginfC: cast[int64](0xFFF0_0000_0000_0000'u64)
    else: 0x7FF8_0000_0000_0000'i64

proc constLitBits*(c: Cursor): uint64 =
  ## Raw bits of a scalar literal, unwrapping `(suf value "type")` / `(par …)` and
  ## reinterprets `(cast Type value)` (e.g. `cast[ptr CFile](1)` collapses to the bits
  ## of `1`). A `(conv Type value)` is value-preserving for a same-class conversion, but
  ## a class-CHANGING conversion — int↔float — is a NUMERIC conversion (`(conv (f 64) 123)`
  ## ⇒ the bits of `123.0`, NOT of the integer `123`), so the outermost conv's target
  ## class is tracked and applied to the base literal.
  var v = c
  var convTargetFloat = -1                             # -1 unknown / 0 int-class / 1 float-class
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind == ConvC:
      var t = v; inc t                                 # → target type
      if convTargetFloat < 0:                          # remember the OUTERMOST conv's target class
        convTargetFloat = (if t.kind == TagLit and t.typeKind == FT: 1 else: 0)
      skip t; v = t                                    # → the wrapped value
    elif v.exprKind == CastC: (inc v; skip v)          # bit-reinterpret: past tag + target type
    else: inc v                                        # suf/par: descend to the wrapped value
  var rawFloat = false
  case v.kind
  of IntLit:   result = cast[uint64](intVal(v))
  of UIntLit:  result = uintVal(v)
  of CharLit:  result = uint64(ord(charLit(v)))
  of FloatLit: (result = cast[uint64](floatVal(v)); rawFloat = true)
  of TagLit:
    case v.exprKind
    of TrueC:  result = 1'u64
    of FalseC: result = 0'u64
    of NilC:   result = 0'u64
    of NegC:   (inc v; result = cast[uint64](-cast[int64](constLitBits(v))))
    of InfC, NeginfC, NanC:
      # Always the f64 pattern; the FT case of `constToBytes` narrows it when the
      # constant's type is `(f 32)`, exactly as it does for a plain float literal.
      result = cast[uint64](specialFloatBits(v.exprKind, 64)); rawFloat = true
    else: raiseAssert "arkham const: unsupported scalar " & $v.exprKind
  else: raiseAssert "arkham const: unsupported literal kind " & $v.kind
  # Apply a class-changing int↔float conversion against the base literal's class.
  if convTargetFloat == 1 and not rawFloat:
    result = cast[uint64](float64(cast[int64](result)))   # int → float (123 ⇒ 123.0)
  elif convTargetFloat == 0 and rawFloat:
    result = cast[uint64](int64(cast[float64](result)))   # float → int (truncating)

proc branchImm*(c: var Cursor): int64 =
  ## A Leng `BranchValue` for a `case`: a Number / CharLiteral / `(true)` / `(false)`
  ## or a typed/wrapped constant `(suf 3 +Enum)` / `(cast …)` / `(neg …)`. Advance
  ## past it. (Symbol branch values — enum consts — are not yet supported.) Shared
  ## by both backends; wrapped forms unwrap through `constLitBits`.
  case c.kind
  of IntLit:  result = intVal(c); inc c
  of UIntLit: result = cast[int64](uintVal(c)); inc c
  of CharLit: result = int64(ord(charLit(c))); inc c
  of TagLit:
    case c.exprKind
    of TrueC:  result = 1; skip c
    of FalseC: result = 0; skip c
    of SufC, ParC, CastC, ConvC, NegC:                  # typed/wrapped enum-or-int
      result = cast[int64](constLitBits(c)); skip c     # `(suf 3 +Enum)` → 3
    else: raiseAssert "arkham: unsupported case branch value: " & $c.exprKind
  else: raiseAssert "arkham: unsupported case branch value kind: " & $c.kind

proc isConstScalarInit*(c: Cursor): bool =
  ## Whether an initializer is a compile-time-constant SCALAR — a literal, a
  ## bool/nil literal, or a (negate / cast / conv / suf / par) wrapping one. Such a
  ## gvar initializer can be laid out as static data (see the backend `genGlobal`),
  ## so it is correct even for a FOREIGN module's gvar in a bundle, where the
  ## module's entry-time initializer code never runs. (Aggregate constructors and
  ## address-of initializers — which need a relocation — are NOT covered here.)
  var v = c
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC, NegC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)   # past the tag + target type
    else: inc v                                        # descend to the wrapped value
  case v.kind
  of IntLit, UIntLit, CharLit, FloatLit: true
  of TagLit: v.exprKind in {TrueC, FalseC, NilC}
  else: false

proc constAddrSym*(c: Cursor): string =
  ## If `c` is a static-ADDRESS initializer — a bare symbol naming a proc or
  ## global (a link-time constant address), possibly wrapped in the same
  ## conv/cast/par peels as `isConstScalarInit` — return that symbol's name; else
  ## "". A function-pointer hook (`var gExitFlush = nimNoopFlush`) is the canonical
  ## case. The backend `genGlobal` emits it as the gvar's value and nifasm bakes
  ## the resolved address into the `.bss` slot (see nifasm `bssSymInits`), so it is
  ## correct even for a FOREIGN module's gvar in a bundle whose entry-time
  ## initializer code never runs — unlike the runtime `(asgn)` path.
  result = ""
  var v = c
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)
    else: inc v
  # An explicit address-of a global/const/proc symbol — `(addr strlit.0)` is the
  # canonical case (a string literal's `more` field points at the data const). The
  # symbol's address is a link-time constant, so it bakes as a reloc exactly like a
  # bare symbol. Peel the `(addr …)` then any further conv/cast/par wrappers.
  if v.kind == TagLit and v.exprKind in AddrKinds:
    inc v                                              # past the (addr tag
    while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
      if v.exprKind in {CastC, ConvC}: (inc v; skip v)
      else: inc v
  if v.kind == Symbol: result = symName(v)

proc isStaticConstInit*(c: Cursor): bool =
  ## Whether an initializer is a compile-time constant that `constToBytes` can lay
  ## out as raw bytes: a scalar literal, a static address, a string, or an
  ## `(aconstr …)`/`(oconstr …)` built recursively out of those.
  ##
  ## This is the IR CONTRACT for a `gvar`'s value. Anything else is code, and code
  ## is not arkham's to schedule: hexer lowers a runtime initializer to an `(asgn …)`
  ## in the module's init proc (`lengcgen`'s `trToplevel`), which reaches arkham as
  ## an ordinary statement. `genGlobal` rejects a violation rather than guessing.
  if c.kind == StrLit: return true
  if isConstScalarInit(c): return true
  if constAddrSym(c).len > 0: return true
  if c.kind == TagLit and c.exprKind in {AconstrC, OconstrC}:
    result = true
    var vc = c
    vc.into:
      skip vc                                  # the constructed type
      while vc.hasMore:
        if vc.kind == TagLit and vc.substructureKind == KvU:
          var kv = vc
          kv.into:
            inc kv                             # field name
            if kv.hasMore and not isStaticConstInit(kv): result = false
            while kv.hasMore: skip kv
        elif not isStaticConstInit(vc):
          result = false
        skip vc
  else:
    result = false

proc appendLE(buf: var string; bits: uint64; size: int) =
  for i in 0 ..< size: buf.add char((bits shr (8 * i)) and 0xFF'u64)

proc constScalarBits*(p: var Program; typ, val: Cursor): uint64 =
  ## `constLitBits`, narrowed to the width of the DECLARED type. `constLitBits`
  ## speaks f64 throughout, so an `(f 32)` constant needs its value ROUNDED to
  ## single precision: truncating the double bits to four bytes yields 0 for
  ## every literal whose mantissa fits in a double's low word — i.e. all of them.
  result = constLitBits(val)
  let rt = resolveType(p, typ)
  if rt.kind == TagLit and rt.typeKind == FT and typeSizeAlign(p, rt)[0] == 4:
    result = uint64(cast[uint32](float32(cast[float64](result))))

proc constToBytes*(p: var Program; typ, val: Cursor; buf: var string;
                   relocs: var seq[(int, string)]) =
  ## Append the in-memory bytes of constant `val` (of Leng type `typ`) to `buf`.
  ## A pointer/proc field whose value is a *symbol address* (e.g. a vtable/RTTI
  ## const pointing at another const or a proc — `(cast (ptr …) Foo.0.vt)`) cannot
  ## be baked at compile time; record `(blob-offset, symbol-name)` in `relocs` and
  ## reserve 8 placeholder bytes. The backend emits these as `(reloc off sym)`
  ## children of the `(rodata …)` blob and nifasm bakes the resolved address into
  ## `.text` in `writeElf`. `relocs` offsets are relative to the blob start, so the
  ## top-level caller must pass a `buf` that begins empty (the blob).
  let rt = resolveType(p, typ)
  if rt.kind != TagLit: raiseAssert "arkham const: unresolved type"
  case rt.typeKind
  of IT, UT, CT, BoolT, FT, EnumT:
    let (sz, _) = typeSizeAlign(p, rt)
    appendLE(buf, constScalarBits(p, rt, val), sz)
  of PtrT, AptrT, ProctypeT:
    let addrSym = constAddrSym(val)
    if addrSym.len > 0:
      relocs.add (buf.len, addrSym)          # link-time address (baked by nifasm)
      for i in 0 ..< 8: buf.add '\0'         # placeholder reserved for the address
    else:
      appendLE(buf, constLitBits(val), 8)    # nil / integer-encoded address
  of FlexarrayT:
    var et = rt; inc et                      # element type
    if val.kind == StrLit:
      buf.add strVal(val)
    else:
      var vc = val                           # (aconstr T elem*)
      vc.into:
        skip vc                              # the constructed type
        while vc.hasMore: (constToBytes(p, et, vc, buf, relocs); skip vc)
  of ArrayT:
    var et = rt; inc et                      # element type
    let elemType = et
    skip et                                  # past element type → length
    let n = if et.kind == IntLit: int(intVal(et)) else: 0
    let (esz, _) = typeSizeAlign(p, elemType)
    var count = 0
    var vc = val                             # (aconstr T elem*)
    vc.into:
      skip vc                                # the constructed type
      while vc.hasMore: (constToBytes(p, elemType, vc, buf, relocs); skip vc; inc count)
    for k in count ..< n:                    # zero-fill trailing elements
      for i in 0 ..< esz: buf.add '\0'
  of ObjectT:
    # Match each `(oconstr … (kv field value) …)` value to a type field
    # *positionally* (hexer emits constructor fields in declaration order). This
    # avoids decoding field-name symbols, which sidesteps the foreign-module
    # string-pool of a cross-module type (the value literals live in *our* pool;
    # the type only supplies sizes/offsets via `typeSizeAlign`). A trailing
    # `flexarray` field (size 0) appends its bytes past the fixed part.
    let startLen = buf.len
    var vals: seq[Cursor] = @[]
    var vc = val
    vc.into:
      skip vc                                # the constructed type
      while vc.hasMore:
        vc.into:                             # (kv field value)
          inc vc                             # skip field name (atom → no pool)
          vals.add vc
          while vc.hasMore: skip vc
    var oc = rt
    var off = 0
    var maxAl = 1
    var fi = 0
    oc.into:
      # An object *constant* of an inherited type would need the base's fields
      # laid out first (positionally matched against the leading oconstr values),
      # like objSizeAlign/aggrLayout do for runtime layout. Not yet implemented —
      # fail loudly rather than emit silently-misaligned bytes.
      if oc.kind == Symbol:
        raiseAssert "arkham: object constant of an inherited type not yet supported"
      skip oc                                # base / inheritance
      while oc.hasMore:
        oc.into:                             # (fld :name pragmas type)
          inc oc                             # skip field name (atom → no pool)
          skip oc                            # field pragmas
          let ftype = oc
          let (fsz, fal) = typeSizeAlign(p, oc)
          skip oc
          off = align(off, fal)
          if fal > maxAl: maxAl = fal
          while buf.len < startLen + off: buf.add '\0'   # pad to field offset
          if fi < vals.len:
            constToBytes(p, ftype, vals[fi], buf, relocs)
          else:
            for i in 0 ..< fsz: buf.add '\0'
          inc fi
          off += fsz
    while (buf.len - startLen) < align(off, maxAl): buf.add '\0'  # tail padding
  else:
    raiseAssert "arkham const: unsupported const type " & $rt.typeKind

proc genGlobalInitValue*(g: var CodeGen; name: string; typ, val: Cursor; hasValue: bool) =
  ## Emit a gvar's initial VALUE into the open `(gvar :name <type> …)` as STATIC
  ## data: nifasm prefills the (writable) slot from the on-disk image, so the value
  ## is there before any code runs — correct for a foreign module's gvar in a bundle
  ## just as much as for the main module's.
  ##
  ## Three shapes, cheapest first: a scalar's raw bits; a symbol whose address only
  ## the final layout knows, which nifasm bakes into the slot; and an object / array
  ## / string constant, laid out by `constToBytes` as bytes plus one `(reloc off
  ## sym)` per address-valued field.
  ##
  ## A value that is NOT a compile-time constant is a contract violation, not a case
  ## to fall back on: hexer lowers a runtime initializer to an `(asgn …)` in the
  ## module's init proc (`lengcgen`'s `trToplevel`), so it reaches arkham as an
  ## ordinary statement and never as a gvar value. Say so rather than guess.
  if not hasValue: return
  if isConstScalarInit(val):
    g.ab.intLit cast[int64](constScalarBits(g.prog, typ, val))
  else:
    let addrSym = constAddrSym(val)
    if addrSym.len > 0:
      g.ab.sym addrSym
    elif isStaticConstInit(val):
      var bytes = ""
      var relocs: seq[(int, string)] = @[]
      constToBytes(g.prog, typ, val, bytes, relocs)
      g.ab.str bytes
      for (off, sym) in relocs:
        g.ab.tree RelocX:
          g.ab.intLit off
          g.ab.sym sym
    else:
      lengError val, "the initializer of the global `" & name & "` is not a compile-time " &
        "constant. Runtime initialization belongs in the module\'s init proc as an " &
        "assignment, which is where hexer lowers it"

proc paramName*(idx: int): string {.inline.} =
  ## The asm-NIF symbol for positional call parameter `idx`. nifasm scopes a
  ## symbol by its full name, so the ordinal has to live in the *name*: `p.0`
  ## and `p.1` are two names for the same thing to a reader and buy nothing
  ## here, whereas `pN.0` is unambiguous. `SynthMark` keeps the whole family out
  ## of the Leng namespace — see its doc comment for the bug that proved it must.
  result = synth("p") & $idx & ".0"

proc operandInReg*(g: var CodeGen; operand: Cursor; dest: Reg): bool =
  ## Does the (peeked, not consumed) `operand` resolve to a register-resident
  ## local whose home register is `dest`? The accumulator codegen evaluates a
  ## binary op's left operand into `dest`; if the *right* operand lives in `dest`
  ## that would clobber it before use, so the caller must save it first. Only
  ## a bare register symbol can alias — a literal has no register, and a nested
  ## expression is materialized into a fresh scratch (never a live local's home).
  result = false
  if operand.kind == Symbol:
    let loc = g.ra.locationOfSym(symName(operand), cursorToPosition(g.buf[], operand))
    result = loc.kind == InReg and loc.r == dest

# ── select-diamond recognition (shared by a64 `csel` & x64 `cmov`) ────────────

type
  SelectDiamond* = object
    ## A recognised `(if (elif COND (asgn DST A)) (else (asgn DST B)))` where COND is
    ## an integer relation, DST a register-homed scalar, and A/B are side-effect-free
    ## simple values — lowered branchlessly (a64 `csel`, x64 `cmov`).
    ek*: LengExpr                 # relation kind: EqC / NeqC / LtC / LeC
    a*, b*: Cursor                # relation operands
    dst*: Location                # the shared register-homed destination
    thenAsgn*, elseAsgn*: Cursor  # the two `(asgn …)` nodes (for their positions)
    thenRhs*, elseRhs*: Cursor    # the assigned values (A, B)

proc simpleSelectValue(g: var CodeGen; rhs: Cursor): bool =
  ## A side-effect-free scalar RHS that materialises with plain `mov`/`ldr`/`lea`
  ## only — never touching the condition flags, so it may sit between the compare and
  ## the `csel`/`cmov`: an integer immediate, or a register-/stack-homed local.
  ## Peels `(suf …)` / `(par …)` / identity `(cast …)` / `(conv …)` wrappers that
  ## xelim / typed lowering leave around literals and symbols (e.g. `max(16, alignment)`
  ## after hexer), matching the peels used elsewhere in this module.
  var v = rhs
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)   # past tag + target type
    else: inc v                                        # descend to the wrapped value
  case v.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: g.ra.locationOfSym(symName(v), cursorToPosition(g.buf[], v)).kind in {InReg, NamedStack}
  else: false

proc selectAsgnDstRhs(asgn: Cursor; dstName: var string; rhs: var Cursor): bool =
  ## `(asgn DST RHS)` with a symbol DST → its name and the RHS cursor. False for a
  ## complex (memory) lvalue. `sub` reads the children without a leave obligation.
  var a = sub(asgn)
  if a.kind != Symbol: return false
  dstName = symName(a); skip a
  if not a.hasMore: return false
  rhs = a
  return true

proc singleAsgnOf(stmt: Cursor; asgn: var Cursor): bool =
  ## The lone `(asgn …)` a select-diamond arm carries: the statement itself, or the
  ## single child of nested `(stmts …)` wrappers. Hexer/xelim often wrap an arm as
  ## `(stmts (stmts (stmts (asgn …))))`; peel until one assignment remains. False for
  ## anything else (zero/multiple statements, a non-assignment) — those keep the
  ## branch lowering.
  var s = stmt
  while s.stmtKind == StmtsS:
    var inner = sub(s)
    if not inner.hasMore: return false
    let first = inner; skip inner
    if inner.hasMore: return false          # more than one statement in the arm
    s = first
  if s.stmtKind == AsgnS:
    asgn = s; return true
  return false

proc matchSelectDiamond*(g: var CodeGen; c: Cursor; sd: var SelectDiamond): bool =
  ## Recognise `(if (elif COND (asgn DST A)) (else (asgn DST B)))` — exactly one
  ## elif and one else, each arm a single assignment to the SAME register-homed
  ## scalar DST from a side-effect-free simple value, with COND a plain integer
  ## relation (eq/ne/lt/le). Fills `sd` and returns true; false (→ the caller's
  ## branch lowering) for anything that does not fit. Arch-independent: the a64
  ## backend lowers a match to `csel`, the x64 backend to `cmov`.
  var condC, thenAsgn, elseAsgn: Cursor
  var haveElif, haveElse = false
  var ok = true
  var cc = c
  cc.into:
    while cc.hasMore:
      case cc.substructureKind
      of ElifU:
        if haveElif or haveElse: ok = false
        var bc = sub(cc)                       # (elif COND ARM) — read only
        condC = bc; skip bc
        if not bc.hasMore: ok = false
        else:
          thenAsgn = bc; skip bc
          if bc.hasMore: ok = false            # more than one statement in the arm
        haveElif = true
      of ElseU:
        if not haveElif or haveElse: ok = false
        var bc = sub(cc)                       # (else ARM)
        if not bc.hasMore: ok = false
        else:
          elseAsgn = bc; skip bc
          if bc.hasMore: ok = false
        haveElse = true
      else: ok = false
      skip cc
  if not (ok and haveElif and haveElse): return false
  var thenBody, elseBody: Cursor
  if not singleAsgnOf(thenAsgn, thenBody): return false
  if not singleAsgnOf(elseAsgn, elseBody): return false
  if condC.kind != TagLit or condC.exprKind notin {EqC, NeqC, LtC, LeC}: return false
  var aC, bC: Cursor
  block:
    var pc = sub(condC)
    aC = pc; skip pc
    bC = pc
  if g.isFloatExpr(aC): return false
  var thenDst, elseDst: string
  var thenRhs, elseRhs: Cursor
  if not selectAsgnDstRhs(thenBody, thenDst, thenRhs): return false
  if not selectAsgnDstRhs(elseBody, elseDst, elseRhs): return false
  if thenDst != elseDst: return false
  let dst = g.ra.homeOfSym(thenDst)
  if dst.kind != InReg: return false
  if not g.simpleSelectValue(thenRhs) or not g.simpleSelectValue(elseRhs): return false
  sd = SelectDiamond(ek: condC.exprKind, a: aC, b: bC, dst: dst,
                     thenAsgn: thenBody, elseAsgn: elseBody,
                     thenRhs: thenRhs, elseRhs: elseRhs)
  return true

proc selectStagingSlot*(g: var CodeGen; sd: SelectDiamond): AsmSlot =
  ## The slot for the register that stages the THEN value. It receives a COPY of DST,
  ## so it must be bound with DST's *asm* type — which is simply DST's own slot: both
  ## backends' `emRegLocalVar` declares a register-homed local with its OWN type
  ## (`(u 8)` stays `(u 8)`). This used to answer a flat `(i 64)` for every
  ## non-pointer, matching the older declaration rule; once that rule changed, an
  ## `enum`/`uint8` DST declared `(u 8)` made the `csel DST, staging, DST` against an
  ## `(i 64)` staging register a type error (`posixToErrorCode`, whose `ErrorCode`
  ## result the select-diamond lowering reaches).
  sd.dst.typ

# ── emit-time temp allocation (step-3 merged value core) ─────────────────────
# The merged emitter DECIDES expression registers at the point of emission
# (vmgen-style dest threading) instead of reading a pre-pass plan. Register
# freeness is DERIVED per pick from the live state the emitter already owns —
# RegBind bindings, the pre-pass homes (symPos, immutable per proc), and the
# call seals — the same filter discipline `pickStagingScratch` has always used.
# No second pool-set state machine, hence no walk-synchronization invariant.
# Homes for named locals/params remain the decl-only allocator pre-pass.

proc regHoldsHome*(g: var CodeGen; r: Reg): bool =
  ## A named local/param is homed in `r` (a pre-pass decision, immutable for the
  ## whole proc — steals/demotes resolve before emission starts). Served from the
  ## cached mask: a full `symPos` scan per query made emission quadratic in proc size.
  if g.ra.homesDirty: rebuildHomes(g.ra)
  r in g.ra.homeRegs

proc fregHoldsHome*(g: var CodeGen; f: FReg): bool =
  ## The SIMD twin of `regHoldsHome`.
  if g.ra.homesDirty: rebuildHomes(g.ra)
  f in g.ra.homeFRegs

when not defined(arkhamNoNarrowHomes):
  let nhRegs = getEnv("ARKHAM_NH_REGS", "*")
    ## `ARKHAM_NH_REGS`: which registers the narrow filter may NEWLY admit (ones the
    ## `regHoldsHome` union would refuse). "*" = all; otherwise a comma-separated list
    ## of `Reg` names. Bisecting the crash down to one register inside one proc.
  proc nhRegAllowed*(r: Reg; isHome: bool): bool =
    if not isHome: return true            # not a home at all — nothing to decide
    if nhRegs == "*": return true
    for it in nhRegs.split(','):
      if it == $r: return true
    false
else:
  proc nhRegAllowed*(r: Reg; isHome: bool): bool {.inline.} = not isHome

proc regFreeForTemp*(g: var CodeGen; r: Reg): bool =
  ## May the merged emitter hand `r` out as an expression temp right now? Not
  ## picked-but-unbound (the reserve→bind gap), not pinned to an in-flight call
  ## (sealed), not a live accumulator, not carrying any named binding (a local
  ## in scope or a temp in flight), not a home.
  ##
  ## The reservation it asks about is `rawHomeRegs`, NOT the old whole-proc
  ## `regHoldsHome` union — the union was the largest single reason a temp fell
  ## through to a callee-saved register (`-d:arkhamTempDbg`: 3.05 of the ~5.75
  ## volatiles refused at each fall-through, ahead of a live binding at 1.51 and the
  ## reserve->bind gap at 1.12), and the pushes those fall-throughs cause were 3.82 %
  ## of all executed instructions.
  ##
  ## Retiring it took four fixes, and each one was a place where a LIVE value sat in a
  ## register carrying no `rb` binding, so `isBound` answered "free":
  ##
  ##  1. a by-reference aggregate param had NO declaration at all — its pointer was
  ##     `mov`'d into the home and every field access named the bare register
  ##     (`emRegAggrPtrVar` + `emPtrFieldMemSym`);
  ##  2. a RELOCATED param's home was left unbound on purpose, "for the epilogue
  ##     pops" — and a nimony `var T` is a plain `(ptr T)`, so that was MOST pointer
  ##     params (`emRegLocalVar` in `emitParamMoves`; `framePop` kills before popping);
  ##  3. the hidden indirect-result pointer (`synth("retptr.0")`);
  ##  4. a DIVERGING call's marshalling `(kill …)`s a still-live home, because `rb` is
  ##     linear and cannot say "this path is not taken" (`restoreBindings`).
  ##
  ## Raw pointer operands per nifbench build: **2956 -> 45**, and the 45 are the fixed
  ## rdi/rsi/rdx of the self-contained `mem*` sequences, which allocate no temps.
  ## `-d:arkhamNoNarrowHomes` restores the union; `-d:arkhamHomeAudit` prints every
  ## register the narrow filter admits that the union would refuse, and `ARKHAM_NH` /
  ## `ARKHAM_NH_REGS` narrow it to named procs / registers, which is how each of the
  ## four shapes above was bisected out of a whole-program segfault.
  result = r notin g.pickedRegs and not g.ra.isSealed(r) and not g.rb.isAccum(r) and
    not g.rb.isBound(r) and
    (if g.narrowHomes: r notin g.rawHomeRegs and nhRegAllowed(r, g.regHoldsHome(r))
     else: not g.regHoldsHome(r))
  when defined(arkhamHomeAudit):
    # Every register the narrow filter ADMITS but the old union would have refused:
    # each one must be a home whose symbol is provably not live here, i.e. `rb` would
    # have told us. Printing the symbol names living there is how the missing raw-home
    # shapes were enumerated (a `(ptr object)` param read raw is the classic one).
    if result and g.narrowHomes and g.regHoldsHome(r):
      var who = ""
      for name, pos in g.ra.symPos:
        let l = g.ra.locs[pos]
        if l.kind == InReg and l.r == r:
          who.add (if who.len > 0: "," else: "") & name & ":" & $l.typ.kind &
                  (if l.typ.size > 0: "/" & $l.typ.size else: "")
      stderr.writeLine "HOMEAUDIT " & g.curProcName & " " & $r & " admits [" & who & "]"

template forEachVolatileTempCand(g: var CodeGen; r, body: untyped) =
  ## The volatile GPRs `pickTempReg` may hand out, in preference order, BEFORE the
  ## callee-saved fallback. `intTempRegs` is `r10` ALONE on x86-64, so the second
  ## simultaneously-live expression temp went straight to a callee-saved register —
  ## a push and a pop in a prologue that may run millions of times — while rdi, rsi,
  ## r8, r9, rcx and rdx sat idle. Measured: `tokenWidth`, a CALL-FREE leaf, pushes
  ## rbx and r12 for `tmp2`/`tmp4` with five volatiles free; its push/pop is 28.8 %
  ## of its own executed instructions.
  ##
  ## SAFETY is the same class as `r10`'s, not a new one. `r10` is itself a
  ## caller-saved register in `x64ClobbersGpr`, so "an expression temp does not
  ## survive a call" is already a load-bearing invariant of this pool (a temp that
  ## must outlive a call comes from `pickHeldReg`, callee-saved only). Adding more
  ## volatiles cannot break an invariant the first candidate already relies on, and
  ## `regFreeForTemp` still refuses anything picked, sealed (an in-flight call's
  ## marshalling), bound, accumulating, or hosting a named home.
  ##
  ## The two FIXED-ROLE volatiles are the exception, and they are gated on the
  ## analyser's whole-proc facts: rdx is destroyed by `idiv`, rcx by a variable
  ## shift (and by `rep movs`, which only ever runs inside a call — where no temp
  ## is live anyway). A proc that contains neither has no second use for them.
  block:
    for r in g.md.intTempRegs: body            # r10
    for r in g.md.intLocalTempRegs: body       # rdi, rsi, r8, r9 — no fixed role
    if g.md.divRemReg != NoReg and not g.ra.divRegClobbered:
      let r = g.md.divRemReg; body
    if g.md.shiftCountReg != NoReg and not g.ra.shiftRegClobbered:
      let r = g.md.shiftCountReg; body
    # R11, the staging bridge, is NOT here — TRIED AND REVERTED. Adding it last (only
    # where the alternative is a callee-saved push and pop) looks free, because
    # `pickStagingScratch` has a callee-saved totality backstop of its own. It is not:
    # `tests/arkham/addr_chain_depth` then dies with "no staging register available
    # for a late memory-load address in proc chain.0", because that backstop asks
    # `regFreeForTemp`, which refuses every callee-saved register via `regHoldsHome`.
    # So the union blocks the temp pool AND the staging fallback; R11 only becomes
    # spare once register-homed params carry an `rb` binding. One root cause, two
    # symptoms — see `regFreeForTemp`.

proc tempCensus*(g: var CodeGen): string =
  ## Why every candidate was refused, in `pickTempReg`'s own order — the temp-pool
  ## twin of `stagingCensus`. `pickTempReg` returning `NoReg` means the register
  ## file is FULL, and "genuinely full" and "a filter is too coarse" want opposite
  ## fixes; only naming the refusing filter per register tells them apart.
  result = ""
  forEachVolatileTempCand(g, r):
    result.add "\n    " & $r & ": "
    if r in g.pickedRegs: result.add "picked (reserve->bind gap)"
    elif g.ra.isSealed(r): result.add "sealed (in-flight call)"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBound(r): result.add "bound " & g.rb.boundName(r)
    elif g.regHoldsHome(r): result.add "HOME UNION (per-proc, not liveness)"
    else: result.add "FREE (unreachable)"
  for r in g.md.intCalleeSaved:
    result.add "\n    " & $r & ": "
    if r in g.pickedRegs: result.add "picked (reserve->bind gap)"
    elif g.ra.isSealed(r): result.add "sealed (in-flight call)"
    elif g.rb.isAccum(r): result.add "liveAccum"
    elif g.rb.isBound(r): result.add "bound " & g.rb.boundName(r)
    elif g.regHoldsHome(r): result.add "HOME UNION (per-proc, not liveness)"
    else: result.add "FREE (unreachable)"

when defined(arkhamTempDbg):
  ## `-d:arkhamTempDbg`: when `pickTempReg` falls through the WHOLE volatile pool and
  ## takes a callee-saved register — a push and a pop — which filter refused each
  ## volatile? "Out of registers" and "a filter is too coarse" need opposite fixes,
  ## and only this tells them apart. It is what showed that `regHoldsHome` (the
  ## per-proc union) refuses 3.05 of the ~5.75 candidates at every fall-through.
  ## `arkham.nim` calls `dumpTempStats` once per module at exit.
  var tempRefusals*: array[5, int]   ## picked, sealed, accum, bound, home
  var tempFallbacks*: int
  var tempVolatileHits*: int
  proc dumpTempStats*() =
    stderr.writeLine "TEMPSTATS volatileHits=" & $tempVolatileHits &
      " calleeFallbacks=" & $tempFallbacks &
      " refusedBy picked=" & $tempRefusals[0] & " sealed=" & $tempRefusals[1] &
      " accum=" & $tempRefusals[2] & " bound=" & $tempRefusals[3] &
      " home=" & $tempRefusals[4]

proc pickTempReg*(g: var CodeGen): Reg =
  ## An expression-temp GPR: the volatile temp pool first, then a callee-saved
  ## register (recorded in `ra.usedCallee` so the prologue saves it — the frame
  ## is finalized AFTER body emission in the merged core). `NoReg` when every
  ## candidate is live; the caller then mints a spill slot (`mintSpillName` +
  ## the backend's produce-into path), keeping temp allocation total exactly
  ## like the old `reserveTmp` fallback.
  forEachVolatileTempCand(g, r):
    if regFreeForTemp(g, r):
      when defined(arkhamTempDbg): inc tempVolatileHits
      return r
  when defined(arkhamTempDbg):
    # Charge each refused volatile to the FIRST filter that rejected it — the order
    # `regFreeForTemp` itself evaluates them in.
    inc tempFallbacks
    forEachVolatileTempCand(g, r):
      if r in g.pickedRegs: inc tempRefusals[0]
      elif g.ra.isSealed(r): inc tempRefusals[1]
      elif g.rb.isAccum(r): inc tempRefusals[2]
      elif g.rb.isBound(r): inc tempRefusals[3]
      elif g.regHoldsHome(r): inc tempRefusals[4]
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r):
      g.ra.usedCallee.incl r
      return r
  NoReg

proc tempPoolDry*(g: var CodeGen): bool =
  ## Would `pickTempReg` fail right now? Same census, no side effect — it must
  ## not mark a callee-saved register `usedCallee` (that would add a push/pop for
  ## a register we then decline to take). For callers that can serve a value from
  ## its existing home and only want a temp when one is genuinely free.
  forEachVolatileTempCand(g, r):
    if regFreeForTemp(g, r): return false
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r): return false
  true

proc pickFTempReg*(g: var CodeGen): FReg =
  ## The SIMD twin of `pickTempReg`: volatile float pool first, then the
  ## callee-saved float pool (empty on x86-64 SysV).
  for f in g.md.floatTempRegs:
    if f notin g.pickedFRegs and not g.rb.isSealedF(f) and
       g.rb.boundFName(f).len == 0 and
       not g.rb.isBoundFTmp(f) and not g.fregHoldsHome(f):
      if f in g.md.floatCalleeSavedSet: g.ra.usedCalleeF.incl f
      return f
  NoFReg

proc pickHeldReg*(g: var CodeGen): Reg =
  ## A SURVIVOR scratch: must outlive a call, so callee-saved only. `NoReg`
  ## when the callee-saved file is fully live — the caller either spills the
  ## (re-derivable) value to a `heldN.0` slot or fails loudly; demoting a local
  ## mid-emission is impossible in the merged core (its uses are already
  ## emitted), and the corpus needed that demotion exactly once.
  for r in g.md.intCalleeSaved:
    if regFreeForTemp(g, r):
      g.ra.usedCallee.incl r
      return r
  NoReg

proc mintSpillName*(g: var CodeGen; prefix: string): string =
  ## A fresh emit-time spill-slot name (`etmp`/`eftmp`/`held` + counter). The
  ## backend declares the `(var :name (s) T)` inline at first use — mid-body
  ## slot decls are legal nifasm (the aggtmp constructor temps already rely on
  ## that) — and flags `ra.hasStackVars` so the frame `sub` is emitted when the
  ## prologue is finalized.
  result = synth(prefix) & $g.emitTmpSpills & ".0"
  inc g.emitTmpSpills
  g.ra.hasStackVars = true

# ── fused value core: syntactic operand predicates (shared by both backends) ─
# Ports of the allocator's private Builder predicates; these become the only
# copies once the allocator's expression walk is deleted.

proc commutativeExpr*(ek: LengExpr): bool {.inline.} =
  ## Integer ops for which `a op b == b op a` (so the heavier operand may be
  ## evaluated first and the lighter one folded after). `sub` is handled too —
  ## via a `neg` after the swap — but is NOT commutative, so it is separate.
  ek in {AddC, MulC, BitandC, BitorC, BitxorC}

proc isMemLeaf*(n: Cursor): bool {.inline.} =
  ## A foldable memory-load operand: a `dot`/`deref`/`at`/`pat` addressing
  ## chain in value position (folds as `op reg, [mem]` instead of pinning a
  ## register across a sibling — operands are pure, hexer un-nests calls).
  n.kind == TagLit and n.exprKind in {DotC, DerefC, AtC, PatC}

proc isFoldableLeafE*(g: var CodeGen; n: Cursor): bool =
  ## A value needing NO register held across a sibling subtree: an immediate,
  ## or a function-local symbol read (folds as its reg / stack-home operand).
  case n.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: g.ra.locationOfSym(symName(n), cursorToPosition(g.buf[], n)).kind in {InReg, NamedStack}
  else: false

proc symInRegE*(g: var CodeGen; n: Cursor; reg: Reg): bool {.inline.} =
  ## Is `n` a symbol homed in `reg`? (Forbids a Sethi–Ullman swap whose
  ## rhs-into-dest evaluation would clobber a lhs homed in dest.)
  if n.kind != Symbol: return false
  let h = g.ra.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
  h.kind == InReg and h.r == reg

proc exprReadsRegImplE(g: var CodeGen; n: var Cursor; reg: Reg): bool =
  if n.kind == Symbol:
    let h = g.ra.locationOfSym(symName(n), cursorToPosition(g.buf[], n))
    inc n
    return h.kind == InReg and h.r == reg
  elif n.kind == TagLit:
    n.into:
      while n.hasMore:
        if g.exprReadsRegImplE(n, reg): return true
  else:
    inc n
  return false

proc exprReadsRegE*(g: var CodeGen; n: Cursor; reg: Reg): bool =
  ## True iff the subtree at `n` reads a symbol homed in `reg` — the guard for
  ## computing a binop's left operand straight into a pinned `dest` register.
  var c = n
  g.exprReadsRegImplE(c, reg)

proc lvalueGlobalBaseE*(g: var CodeGen; n: Cursor): bool =
  ## Does the lvalue chain `n` (a `dot`/`at` over a symbol) bottom out at a
  ## module-level global aggregate? Such a base needs its address materialized
  ## into a scratch register. A `deref`/`pat` base is a pointer VALUE, not a
  ## global lvalue, so it stops the search. (Fused port of the allocator's
  ## private `lvalueGlobalBase`.)
  var c = n
  case c.kind
  of Symbol: result = g.ra.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc
  of TagLit:
    case c.exprKind
    of DotC, AtC:
      var cc = c
      cc.into:
        result = g.lvalueGlobalBaseE(cc)
        while cc.hasMore: skip cc
    else: result = false
  else: result = false

proc fixedRegsClobberedByE*(g: var CodeGen; n: Cursor): set[Reg] =
  ## Registers this expression is FORCED to overwrite because the ISA pins
  ## them: `cl` (rcx) for a runtime shift count, rdx (+rax) for `idiv`. An
  ## already-marshalled call argument sitting in one of them is destroyed with
  ## no diagnostic, so the fused call marshaller parks such arguments off
  ## their ABI register. Empty on AArch64. (Fused port of the allocator's
  ## `fixedRegsClobberedBy`.)
  result = {}
  if g.md.shiftCountReg == NoReg and g.md.divRemReg == NoReg: return
  var stack = @[n]
  while stack.len > 0:
    var c = stack.pop()
    if c.kind != TagLit: continue
    case c.exprKind
    of ShlC, ShrC:
      if g.md.shiftCountReg != NoReg:
        var count = c; inc count                 # tag → result type
        skip count                               # result type → lhs
        skip count                               # lhs → count
        if count.hasMore and not isConstShiftCount(count):
          result.incl g.md.shiftCountReg
    of DivC, ModC:
      if g.md.divRemReg != NoReg:
        result.incl g.md.divRemReg
        if g.md.intRetReg != NoReg: result.incl g.md.intRetReg
    else: discard
    var ch = c
    ch.into:
      while ch.hasMore:
        stack.add ch
        skip ch

proc subtreeHasCallE*(n: Cursor): bool =
  ## Does this expression subtree contain a CALL? Read-only. An `(at base idx)`
  ## whose INDEX calls — a bounds check, say — evaluates the base FIRST and
  ## reads it back AFTER the call, so the base's scratch must be a callee-saved
  ## survivor rather than a volatile the call clobbers. (Fused port of the
  ## allocator's `subtreeHasCall`.)
  if n.kind != TagLit: return false
  if n.exprKind == CallC: return true
  var cc = n
  cc.into:
    while cc.hasMore:
      if subtreeHasCallE(cc): return true
      skip cc
  return false
# ── caller-save rescue (see `RegAlloc.callerSaveHomes`) ─────────────────────

proc callerSaveSetAt*(g: var CodeGen): seq[tuple[reg: Reg, name: string]] =
  ## The caller-saved locals currently BOUND to a register — the ones this call is
  ## about to clobber. The trigger is live binding, not the coarse `freeAfter`
  ## interval: a value live across a control-flow merge is still bound at a call in a
  ## predecessor branch, which an interval test under-approximates. The allocator only
  ## hands out a caller-saved home to a value that is valid wherever it is bound, so
  ## "save whenever bound" is always well-defined. Sorted for deterministic output.
  if g.ra.callerSaveHomes.len == 0: return
  for reg, name in g.rb.gprBindings:
    if g.ra.callerSaveHomes.hasKey(name):
      result.add (reg: reg, name: name)
  result.sort(proc (a, b: tuple[reg: Reg, name: string]): int = cmp(ord(a.reg), ord(b.reg)))

type
  CallerSaveWindow* = object
    ## One open save window: what was stored, and the redirect table to put back when
    ## it closes. Opened at `emitCall2` — or EARLIER by a caller that writes an ABI
    ## register for the call itself (the hidden result pointer in rdi), which must
    ## happen after the save or it clobbers the value it was supposed to preserve.
    saved*: seq[tuple[reg: Reg, name: string]]
    prevActive*: Table[string, Location]

proc callerSaveSlotName*(varName: string): string {.inline.} =
  ## ONE permanent slot per caller-saved value, declared with the value itself. A
  ## per-call slot inside the call's own `(scope …)` does not work: the call's result
  ## binding is created in that scope and consumed after it closes.
  "csave." & varName

proc pairFieldReg*(g: var CodeGen; c: Cursor): Reg =
  ## If `c` is `(dot S f)` and `S` is a register-homed ≤16B by-value aggregate
  ## whose field `f` is a full 8-byte ABI word, return that word's register.
  ## Otherwise `NoReg` — the caller uses the memory path.
  result = NoReg
  if c.kind != TagLit or c.exprKind != DotC: return
  var cc = c
  cc.into:
    if cc.kind != Symbol: return
    let base = symName(cc)
    let home = g.ra.homeOfSym(base)
    if home.kind != InRegPair: return
    skip cc
    if cc.kind != Symbol: return
    let field = symName(cc)
    let tn = g.varType.getOrDefault(base, NoTypeSym)
    if tn == NoTypeSym: return
    for f in aggrLayout(g.prog, tn):
      if f.name == field:
        if f.size == 8 and (f.off and 7) == 0:
          result = pairWord(home, f.off div 8)
        return

proc isFoldableMemLeaf*(g: var CodeGen; n: Cursor): bool {.inline.} =
  ## `isMemLeaf`, except a field of a register-homed ≤16B aggregate: that field
  ## IS a GPR, so folding it as `[mem]` would address a stack slot that does
  ## not exist.
  isMemLeaf(n) and g.pairFieldReg(n) == NoReg
