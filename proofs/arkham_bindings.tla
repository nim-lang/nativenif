---- MODULE arkham_bindings ----
\* TLA+ model of Arkham/nifasm register-binding safety.
\*
\* This is the *extended* model. The original only covered the rebind/kill
\* bookkeeping plus fixed-register (idiv/byte-copy) eviction and a two-pass replay
\* in which local bind/kill were unlogged (so the passes could silently diverge and
\* CHECK_DEADLOCK was off). That model could not express the bug classes that the
\* arkham backend actually hit, so it found nothing interesting. This version adds:
\*
\*   1. Scratch STEAL: a temp borrow that evicts a live register-local to a stack
\*      slot and reuses its register (the analogue of arkham's stealReg /
\*      recordEviction). Borrowing no longer requires a *free* register.
\*   2. Raw STAGING occupancy: a register can hold a live, *unbound* scratch value
\*      (the staging-register fallback). These have no nifasm binding, so they are a
\*      separate occupancy notion, and `NoSharedRegister` forbids two live values
\*      (local / temp / staging) from sharing a register — the class the forceReg
\*      collision lived in.
\*   3. Two-pass replay that FORCES plan == emit: every codegen event (locals
\*      included) is logged and the emit pass replays the exact sequence. If a
\*      recorded decision cannot be replayed against the per-proc-reset state, the
\*      model goes to a distinguished `stuck` phase and `NotStuck` flags it — so the
\*      "emit can always replay what plan recorded" guarantee (and the completeness
\*      of the per-proc StartEmit reset) is actually checked, not left to a disabled
\*      action under CHECK_DEADLOCK FALSE.
\*
\* It also models the value-write-into-a-register-home hazard (genInto dest-steal):
\* a local is *declared* with a register home and *then* its initializer runs; the
\* write lands in the home captured at declaration. Sealing the home (the real fix)
\* keeps a steal from evicting it mid-initializer; without the seal a steal moves
\* the local to a stack slot while the write still targets the now-stale register,
\* which `ValueConsistency` catches.
\*
\* Bug-injection (see proofs/README.md) confirms the invariants have teeth: dropping
\* the seal, the steal's stack write, the staging free-check, or part of the
\* StartEmit reset each makes TLC produce a counterexample.
\*
\* The abstracted code carries back-pointers: grep `MODEL:` in src/arkham/codegen_*.nim
\* for the procs each action/invariant corresponds to (stealReg, pickStagingScratch,
\* forceReg, genInto, genProc, evictFixedReg). Change one side, re-check the other.

EXTENDS FiniteSets, Sequences, Naturals

CONSTANTS
    Regs,           \* finite set of physical registers
    FixedRegs,      \* registers an instruction may clobber implicitly (idiv, byte-copy)
    Locals,         \* long-lived source variables
    Temps,          \* transient *bound* scratch names (nifasm `rebind`)
    Staging,        \* transient *raw/unbound* scratch values (staging-register fallback)
    NoName,         \* sentinel: register has no nifasm binding
    NoLoc, NoReg, NoTmp, NoStg,  \* event-field "absent" sentinels
    Stack,          \* a value lives in a stack slot
    Pending,        \* a local's value is mid-computation (not yet written)
    Dead,           \* a local is no longer live
    MaxLog          \* TLC bound on the event-log length

ASSUME IsFiniteSet(Regs) /\ IsFiniteSet(Locals) /\ IsFiniteSet(Temps) /\ IsFiniteSet(Staging)
ASSUME FixedRegs \subseteq Regs
ASSUME Locals \cap Temps = {}
ASSUME MaxLog \in Nat

Names    == Locals \cup Temps \cup {NoName}
ValueLoc == Regs \cup {Stack, Pending, Dead}
Phases   == {"plan", "emit", "done", "stuck"}

EvOp == {"bindLocal", "killLocal", "beginInit", "finishInit",
         "borrowTemp", "killTemp", "steal", "pickStaging", "dropStaging", "fixedUse"}

\* A uniform event record; ops set the fields they do not use to the sentinels.
Event == [op: EvOp,
          l:  Locals  \cup {NoLoc},
          r:  Regs    \cup {NoReg},
          t:  Temps   \cup {NoTmp},
          s:  Staging \cup {NoStg}]

VARIABLES
    binding,      \* [Regs -> Names]            nifasm's register binding table
    loc,          \* [Locals -> Regs \cup {Stack, Dead}]   allocator's view of each local
    valueAt,      \* [Locals -> ValueLoc]       where each local's VALUE physically is
    expected,     \* subset of Locals still live
    liveTemp,     \* subset of Temps currently borrowed (bound scratch)
    liveStaging,  \* subset of Staging currently live (raw scratch)
    stagingPin,   \* [Staging -> Regs \cup {NoReg}]   register each live staging value occupies
    sealedRegs,   \* subset of Regs protected from a steal (init homes / in-flight)
    initing,      \* subset of Locals whose initializer has not yet written its value
    initHome,     \* [Locals -> Regs \cup {NoReg}]    the home a local was declared with
    phase,        \* "plan" | "emit" | "done" | "stuck"
    log,          \* Seq(Event): every codegen event recorded by the plan pass
    logIdx        \* emit cursor into log

vars == <<binding, loc, valueAt, expected, liveTemp, liveStaging, stagingPin,
          sealedRegs, initing, initHome, phase, log, logIdx>>

CleanBinding   == [r \in Regs    |-> NoName]
CleanLoc       == [l \in Locals  |-> Dead]
CleanValueAt   == [l \in Locals  |-> Dead]
CleanStagingPin== [s \in Staging |-> NoReg]
CleanInitHome  == [l \in Locals  |-> NoReg]

Init ==
    /\ binding     = CleanBinding
    /\ loc         = CleanLoc
    /\ valueAt     = CleanValueAt
    /\ expected    = {}
    /\ liveTemp    = {}
    /\ liveStaging = {}
    /\ stagingPin  = CleanStagingPin
    /\ sealedRegs  = {}
    /\ initing     = {}
    /\ initHome    = CleanInitHome
    /\ phase       = "plan"
    /\ log         = <<>>
    /\ logIdx      = 0

\* A register is free iff nifasm has no binding for it AND no live staging value
\* occupies it. (Staging values are raw, so they escape `binding`; this is exactly
\* why the forceReg collision was invisible to a binding-only model.)
Free(r) == binding[r] = NoName /\ ~ \E sv \in liveStaging : stagingPin[sv] = r

ClearBinding(nm) == [r \in Regs |-> IF binding[r] = nm THEN NoName ELSE binding[r]]

\* ---- whether event `e` may be applied against the current state --------------
Applicable(e) ==
    CASE e.op = "bindLocal"   -> e.l \notin expected /\ Free(e.r)
      [] e.op = "beginInit"   -> e.l \notin expected /\ Free(e.r)
      [] e.op = "finishInit"  -> e.l \in initing
      [] e.op = "killLocal"   -> e.l \in expected /\ e.l \notin initing
      [] e.op = "borrowTemp"  -> e.t \notin liveTemp /\ Free(e.r)
      [] e.op = "killTemp"    -> e.t \in liveTemp
      [] e.op = "steal"       -> /\ e.t \notin liveTemp
                                 /\ binding[e.r] \in Locals      \* a register-local (never a bound temp)
                                 /\ binding[e.r] \in expected
                                 /\ e.r \notin sealedRegs        \* not an in-flight / init home
      [] e.op = "pickStaging" -> e.s \notin liveStaging /\ Free(e.r)
      [] e.op = "dropStaging" -> e.s \in liveStaging
      [] e.op = "fixedUse"    -> /\ e.r \in FixedRegs
                                 /\ binding[e.r] \notin Temps     \* cannot silently clobber a bound temp
                                 /\ e.r \notin sealedRegs         \* nor a sealed in-flight / init home
      [] OTHER -> FALSE

\* ---- the semantic effect of applying event `e` (shared by plan and emit) ------
SemEffect(e) ==
    /\ binding' =
        CASE e.op \in {"bindLocal","beginInit"} -> [binding EXCEPT ![e.r] = e.l]
          [] e.op \in {"borrowTemp","steal"}    -> [binding EXCEPT ![e.r] = e.t]
          [] e.op = "killLocal"                 -> ClearBinding(e.l)
          [] e.op = "killTemp"                  -> ClearBinding(e.t)
          [] e.op = "fixedUse"                  -> IF binding[e.r] \in Locals
                                                   THEN [binding EXCEPT ![e.r] = NoName]
                                                   ELSE binding
          [] OTHER                              -> binding
    /\ loc' =
        CASE e.op \in {"bindLocal","beginInit"} -> [loc EXCEPT ![e.l] = e.r]
          [] e.op = "killLocal"                 -> [loc EXCEPT ![e.l] = Dead]
          [] e.op = "steal"                     -> [loc EXCEPT ![binding[e.r]] = Stack]
          [] e.op = "fixedUse"                  -> IF binding[e.r] \in Locals
                                                   THEN [loc EXCEPT ![binding[e.r]] = Stack]
                                                   ELSE loc
          [] OTHER                              -> loc
    /\ valueAt' =
        CASE e.op = "bindLocal"   -> [valueAt EXCEPT ![e.l] = e.r]
          [] e.op = "beginInit"   -> [valueAt EXCEPT ![e.l] = Pending]
          [] e.op = "finishInit"  -> [valueAt EXCEPT ![e.l] = initHome[e.l]]  \* write to the captured home
          [] e.op = "killLocal"   -> [valueAt EXCEPT ![e.l] = Dead]
          [] e.op = "steal"       -> [valueAt EXCEPT ![binding[e.r]] = Stack]
          [] e.op = "fixedUse"    -> IF binding[e.r] \in Locals
                                     THEN [valueAt EXCEPT ![binding[e.r]] = Stack]
                                     ELSE valueAt
          [] OTHER                -> valueAt
    /\ expected' =
        CASE e.op \in {"bindLocal","beginInit"} -> expected \cup {e.l}
          [] e.op = "killLocal"                 -> expected \ {e.l}
          [] OTHER                              -> expected
    /\ liveTemp' =
        CASE e.op \in {"borrowTemp","steal"} -> liveTemp \cup {e.t}
          [] e.op = "killTemp"               -> liveTemp \ {e.t}
          [] OTHER                           -> liveTemp
    /\ liveStaging' =
        CASE e.op = "pickStaging" -> liveStaging \cup {e.s}
          [] e.op = "dropStaging" -> liveStaging \ {e.s}
          [] OTHER                -> liveStaging
    /\ stagingPin' =
        CASE e.op = "pickStaging" -> [stagingPin EXCEPT ![e.s] = e.r]
          [] OTHER                -> stagingPin
    /\ sealedRegs' =
        CASE e.op = "beginInit"  -> sealedRegs \cup {e.r}            \* THE FIX: seal the init home
          [] e.op = "finishInit" -> sealedRegs \ {initHome[e.l]}
          [] OTHER               -> sealedRegs
    /\ initing' =
        CASE e.op = "beginInit"  -> initing \cup {e.l}
          [] e.op = "finishInit" -> initing \ {e.l}
          [] OTHER               -> initing
    /\ initHome' =
        CASE e.op = "beginInit" -> [initHome EXCEPT ![e.l] = e.r]
          [] OTHER              -> initHome

\* ---- plan pass: choose an applicable event and record it ---------------------
PlanStep(e) ==
    /\ phase = "plan"
    /\ Len(log) < MaxLog
    /\ Applicable(e)
    /\ SemEffect(e)
    /\ log' = Append(log, e)
    /\ UNCHANGED <<phase, logIdx>>

MkEv(op, l, r, t, s) == [op |-> op, l |-> l, r |-> r, t |-> t, s |-> s]

PlanBindLocal  == \E l \in Locals, r \in Regs : PlanStep(MkEv("bindLocal",  l, r,     NoTmp, NoStg))
PlanKillLocal  == \E l \in Locals             : PlanStep(MkEv("killLocal",  l, NoReg, NoTmp, NoStg))
PlanBeginInit  == \E l \in Locals, r \in Regs : PlanStep(MkEv("beginInit",  l, r,     NoTmp, NoStg))
PlanFinishInit == \E l \in Locals             : PlanStep(MkEv("finishInit", l, NoReg, NoTmp, NoStg))
PlanBorrowTemp == \E t \in Temps, r \in Regs  : PlanStep(MkEv("borrowTemp", NoLoc, r, t,     NoStg))
PlanKillTemp   == \E t \in Temps              : PlanStep(MkEv("killTemp",   NoLoc, NoReg, t,  NoStg))
PlanSteal      == \E t \in Temps, r \in Regs  : PlanStep(MkEv("steal",      NoLoc, r, t,     NoStg))
PlanPickStg    == \E s \in Staging, r \in Regs: PlanStep(MkEv("pickStaging",NoLoc, r, NoTmp, s))
PlanDropStg    == \E s \in Staging            : PlanStep(MkEv("dropStaging",NoLoc, NoReg, NoTmp, s))
PlanFixedUse   == \E r \in FixedRegs          : PlanStep(MkEv("fixedUse",   NoLoc, r, NoTmp, NoStg))

\* ---- emit pass: replay the next recorded event exactly -----------------------
\* If the recorded decision cannot be applied against the (per-proc-reset) emit
\* state, the protocol is broken: go to `stuck` so `NotStuck` reports it.
EmitStep ==
    /\ phase = "emit"
    /\ logIdx < Len(log)
    /\ LET e == log[logIdx + 1] IN
         IF Applicable(e)
         THEN /\ SemEffect(e)
              /\ logIdx' = logIdx + 1
              /\ UNCHANGED <<phase, log>>
         ELSE /\ phase' = "stuck"
              /\ UNCHANGED <<binding, loc, valueAt, expected, liveTemp, liveStaging,
                             stagingPin, sealedRegs, initing, initHome, log, logIdx>>

\* End planning; reset the whole per-proc state for the emit pass (the analogue of
\* arkham clearing regLocal/boundTemps/liveAccums/freeTmp and restoring the
\* allocator snapshot). Keep only the replay log.
StartEmit ==
    /\ phase = "plan"
    /\ liveTemp = {} /\ liveStaging = {} /\ initing = {}   \* plan ended its transients
    /\ binding'     = CleanBinding
    /\ loc'         = CleanLoc
    /\ valueAt'     = CleanValueAt
    /\ expected'    = {}
    /\ liveTemp'    = {}
    /\ liveStaging' = {}
    /\ stagingPin'  = CleanStagingPin
    /\ sealedRegs'  = {}
    /\ initing'     = {}
    /\ initHome'    = CleanInitHome
    /\ phase'       = "emit"
    /\ logIdx'      = 0
    /\ UNCHANGED log

FinishEmit ==
    /\ phase = "emit"
    /\ logIdx = Len(log)
    /\ liveTemp = {} /\ liveStaging = {} /\ initing = {}
    /\ phase' = "done"
    /\ UNCHANGED <<binding, loc, valueAt, expected, liveTemp, liveStaging,
                   stagingPin, sealedRegs, initing, initHome, log, logIdx>>

Next ==
    \/ PlanBindLocal \/ PlanKillLocal \/ PlanBeginInit \/ PlanFinishInit
    \/ PlanBorrowTemp \/ PlanKillTemp \/ PlanSteal
    \/ PlanPickStg \/ PlanDropStg \/ PlanFixedUse
    \/ EmitStep \/ StartEmit \/ FinishEmit

Spec == Init /\ [][Next]_vars

\* ============================== invariants ====================================

TypeOK ==
    /\ binding     \in [Regs -> Names]
    /\ loc         \in [Locals -> Regs \cup {Stack, Dead}]
    /\ valueAt     \in [Locals -> ValueLoc]
    /\ expected    \subseteq Locals
    /\ liveTemp    \subseteq Temps
    /\ liveStaging \subseteq Staging
    /\ stagingPin  \in [Staging -> Regs \cup {NoReg}]
    /\ sealedRegs  \subseteq Regs
    /\ initing     \subseteq Locals
    /\ initHome    \in [Locals -> Regs \cup {NoReg}]
    /\ phase       \in Phases
    /\ log         \in Seq(Event)
    /\ logIdx      \in 0..Len(log)
    /\ Len(log)    <= MaxLog

\* Every live local has a home; a register home is named by nifasm for that local.
LiveLocalsHaveHomes ==
    \A l \in expected :
        /\ loc[l] # Dead
        /\ loc[l] \in Regs => binding[loc[l]] = l

\* Every local nifasm still has in a register is live and agrees with the allocator.
RegisterBindingsMatchLoc ==
    \A r \in Regs :
        binding[r] \in Locals => /\ binding[r] \in expected
                                 /\ loc[binding[r]] = r

\* Bound scratch temps are one-to-one with borrowed temps.
TempBindingsMatchBorrows ==
    /\ \A r \in Regs : binding[r] \in Temps => binding[r] \in liveTemp
    /\ \A t \in liveTemp : Cardinality({r \in Regs : binding[r] = t}) = 1

\* No two live values share a physical register: a raw staging value sits on a
\* register nifasm thinks is free, distinct staging values occupy distinct
\* registers, and a staging value never lands on a live local's home. (This is the
\* class the forceReg collision — two raw staging values on the same reg — lives in.)
NoSharedRegister ==
    /\ \A sv \in liveStaging :
         /\ binding[stagingPin[sv]] = NoName
         /\ \A sv2 \in liveStaging : sv2 # sv => stagingPin[sv2] # stagingPin[sv]
    /\ \A l \in expected :
         loc[l] \in Regs => ~ \E sv \in liveStaging : stagingPin[sv] = loc[l]

\* A finished local's value is exactly where the allocator says it lives. A steal
\* that moved the local to a stack slot while its initializer still wrote into the
\* (now stale) register home breaks this — the genInto dest-steal miscompile.
ValueConsistency ==
    /\ \A l \in expected : l \notin initing => /\ valueAt[l] = loc[l]
                                               /\ valueAt[l] # Pending
    /\ \A l \in initing  : valueAt[l] = Pending

\* The emit pass could always replay what the plan pass recorded.
NotStuck == phase # "stuck"

\* Reaching `done` means the whole log replayed and all transients were released.
ReplayComplete ==
    phase = "done" => /\ logIdx = Len(log)
                      /\ liveTemp = {} /\ liveStaging = {} /\ initing = {}

Safety ==
    /\ LiveLocalsHaveHomes
    /\ RegisterBindingsMatchLoc
    /\ TempBindingsMatchBorrows
    /\ NoSharedRegister
    /\ ValueConsistency
    /\ NotStuck
    /\ ReplayComplete

====
