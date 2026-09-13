---- MODULE call_marshal ----
\* TLA+ model of arkham's CALL-ARGUMENT MARSHALLING under register pressure —
\* the x86-64 `emitCall2Inner` / `takeParked` protocol (src/arkham/x64/value.nim,
\* emit.nim; grep MODEL:). Two phases, chibicc's shape (codegen.c `push_args`,
\* `ND_FUNCALL`): first EVERY argument expression runs, then the ABI registers
\* are loaded. A later argument's expression may destroy a register by ISA fiat
\* — `idiv` writes rdx, a variable shift reads its count from `cl` — and the
\* phase split is what keeps that away from marshalled arguments: no ABI
\* register holds a value while an expression can still run.
\*
\* Phase 1 reduces each argument to a SOURCE nothing later disturbs:
\*   leaf       a literal or a symbol — already one, nothing runs;
\*   comp       a computed scalar: its value goes into a PARK. The one liberty:
\*              when no later argument clobbers its ABI register, that register
\*              IS the park (sealed from then on);
\*   aggr       an aggregate in memory is a source; an aggregate LVALUE's address
\*              is computed and parked (the words are read through it later).
\* A park (`takeParked`) is a callee-saved survivor, else a pool temp, else a
\* spill slot. The pool hands out r10 and the argument registers themselves
\* (`intLocalTempRegs`), rdx/rcx only in a proc with no division / variable
\* shift (the whole-proc gate), nothing bound, and nothing in `avoid`: the
\* call's CLAIMS (its argument registers, loaded or not) plus the later
\* arguments' clobbers. An argument register is otherwise refused only once
\* something is BOUND to it, which happens when it is loaded — too late for a
\* park taken for an earlier argument. (The whole-proc gate is `pickTempReg`'s
\* rule for every temp and is not a park rule: with the later clobbers in
\* `avoid`, what it adds is protection inside the argument's OWN expression,
\* below this model's granularity — dropping it here produces no counterexample,
\* so it is not offered as an injection.)
\* Phase 2 loads each argument's ABI register(s) from its source, in order, and
\* writes nothing else.
\*
\* Why this exists (proofs/README.md, "call_marshal"): the park used to be a
\* callee-saved-only `takeHeld` that asserted "out of registers" when the file
\* was dry, and neither `arkham_bindings` nor `aggr_marshal` could state that
\* (the former enables a borrow only when a register is free, under
\* `CHECK_DEADLOCK FALSE`; the latter has no registers as a resource). Here an
\* argument that needs a park DEMANDS one; a park that cannot be served is the
\* `stuck` phase, and deadlock checking is on.
\*
\* Bug injection (`Bug`, proofs/run_call_marshal_tlc.sh — the correct spec
\* passes, each injection produces a counterexample):
\*   "survivorOnly"  the old `takeHeld(canSpill = false)`: tier one only
\*                   -> NotStuck (the aggr_arg_parked assert, #98 .. 2026-09-13)
\*   "noAvoid"       the pool ignores the call's claims
\*                   -> ParksIntact: a phase-2 load lands on the park
\*   "noBound"       the pool ignores what a register holds
\*                   -> ParksIntact
\*   "noLaterClob"   every computed scalar goes into its own ABI register
\*                   -> ParksIntact: a later expression destroys it
\*   "earlyLoad"     leaves and memory aggregates are loaded in PHASE 1, as the
\*                   fused loop did before the split
\*                   -> LoadedIntact: a later expression destroys the loaded word
\*
\* Layouts: every call of 1..MaxArgs arguments from `Shapes`: a leaf, a computed
\* scalar with any clobber set, a 1- or 2-word aggregate in memory or behind a
\* computed address (with any clobber set for that computation); an argument
\* past the register file is stack-passed — its expression still runs (and
\* clobbers) in phase 1, but it is stored to the outgoing area and never loaded.
\* Values are word IDENTITIES; `[j, 2]` is the ADDRESS of aggregate argument j.

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    A0, A1, A2, A3,   \* the ABI argument registers, in order (rdi rsi rdx rcx)
    S0,               \* the callee-saved survivor the planer reserves for the emitter
    T0,               \* the volatile expression temp outside the argument file (r10)
    MaxArgs,          \* arguments per call, 1..MaxArgs
    Free, Garbage,    \* what a register holds when it holds no live word
    Mem, None,        \* a park in a spill slot / no park
    Bug               \* see above

ArgRegs   == <<A0, A1, A2, A3>>
Fixed     == {A2, A3}                 \* rdx (idiv), rcx (shift count)
Survivors == {S0}
Pool      == {T0}
Regs      == {A0, A1, A2, A3, S0, T0}
Bugs      == {"none", "survivorOnly", "noAvoid", "noBound", "noLaterClob", "earlyLoad"}
ASSUME Bug \in Bugs
ASSUME MaxArgs \in Nat \ {0}

Shapes ==
    {[kind |-> "leaf", words |-> 1, viaAddr |-> FALSE, clob |-> {}]} \cup
    {[kind |-> "comp", words |-> 1, viaAddr |-> FALSE, clob |-> c] : c \in SUBSET Fixed} \cup
    {[kind |-> "aggr", words |-> w, viaAddr |-> FALSE, clob |-> {}] : w \in {1, 2}} \cup
    {[kind |-> "aggr", words |-> w, viaAddr |-> TRUE, clob |-> c] :
        w \in {1, 2}, c \in SUBSET Fixed}

WordIds == [j: 1..MaxArgs, k: 0..2]   \* k = 2: the address of aggregate j
Word(j, k) == [j |-> j, k |-> k]
AddrWord(j) == [j |-> j, k |-> 2]
Range(s) == {s[i] : i \in 1..Len(s)}

VARIABLES
    args,       \* the call: seq of shapes with `first` (index into ArgRegs)
    phase,      \* "eval" | "load" | "call" | "done" | "stuck"
    j,          \* the argument in hand (Len(args)+1: the phase is complete)
    evaluated,  \* phase 1: argument j's expression has run (its clobbers landed)
    placed,     \* words whose value has landed in their park
    parkOf,     \* [WordIds -> Regs \cup {Mem, None}]
    regVal,     \* [Regs -> WordIds \cup {Free, Garbage}]
    slots,      \* memory-parked words whose slot holds the word
    loaded      \* words sitting in their ABI register (phase 2 ran for them)

vars == <<args, phase, j, evaluated, placed, parkOf, regVal, slots, loaded>>

\* ---- the call shape ------------------------------------------------------------
RECURSIVE WordsBefore(_, _)
WordsBefore(ws, i) == IF i = 1 THEN 0 ELSE WordsBefore(ws, i - 1) + ws[i - 1]

N          == Len(args)
OnStack(i) == args[i].first + args[i].words - 1 > Len(ArgRegs)
Abi(i, k)  == ArgRegs[args[i].first + k]
Ks(i)      == 0..(args[i].words - 1)
Kind(i)    == args[i].kind
LaterClob(i) == UNION {args[m].clob : m \in (i + 1)..N}
ProcClob     == UNION {args[m].clob : m \in 1..N}
Claims == UNION {{Abi(i, k) : k \in Ks(i)} : i \in {m \in 1..N : ~OnStack(m)}}

Init ==
    \E n \in 1..MaxArgs :
      \E sh \in [1..n -> Shapes] :
        LET ws == [i \in 1..n |-> sh[i].words] IN
        /\ args = [i \in 1..n |-> [kind |-> sh[i].kind, words |-> sh[i].words,
                                   viaAddr |-> sh[i].viaAddr, clob |-> sh[i].clob,
                                   first |-> WordsBefore(ws, i) + 1]]
        /\ phase = "eval" /\ j = 1 /\ evaluated = FALSE
        /\ placed = {} /\ loaded = {} /\ slots = {}
        /\ parkOf = [w \in WordIds |-> None]
        /\ regVal = [r \in Regs |-> Free]

\* ---- parks -------------------------------------------------------------------------
Holds(r) == regVal[r] \in WordIds        \* bound: a live word sits (or is reserved) there
Avoid(i) == IF Bug = "noAvoid" THEN {} ELSE Claims \cup LaterClob(i)

\* `pickHeldReg`
SurvivorOK(r) == r \in Survivors /\ ~Holds(r)
\* `pickTempReg(avoid)`
PoolOK(i, r) ==
    /\ Bug # "survivorOnly"
    /\ r \in Pool \cup Range(ArgRegs)
    /\ Bug = "noBound" \/ ~Holds(r)
    /\ r \notin Avoid(i)
    /\ r \in Fixed => r \notin ProcClob
MemOK == Bug # "survivorOnly"

\* What argument j parks in phase 1: a computed scalar its VALUE, an aggregate
\* lvalue its ADDRESS; a leaf and a memory aggregate nothing. A stack-passed
\* argument is stored to the outgoing area at once and parks nothing.
ParkWord(i) ==
    IF OnStack(i) THEN None
    ELSE IF Kind(i) = "comp" THEN Word(i, 0)
    ELSE IF Kind(i) = "aggr" /\ args[i].viaAddr THEN AddrWord(i)
    ELSE None
NeedsPark == /\ phase = "eval" /\ j <= N /\ ~evaluated
             /\ IF ParkWord(j) = None THEN FALSE ELSE parkOf[ParkWord(j)] = None
\* The liberty: a computed scalar's own ABI register, when nothing later
\* clobbers it. `Bug = "noLaterClob"` takes it unconditionally.
OwnAbiOK == /\ Kind(j) = "comp"
            /\ Bug = "noLaterClob" \/ Abi(j, 0) \notin LaterClob(j)

ParkReg(r) ==
    /\ NeedsPark
    /\ \/ SurvivorOK(r) \/ PoolOK(j, r)
       \/ (r = Abi(j, 0) /\ OwnAbiOK)
    /\ parkOf' = [parkOf EXCEPT ![ParkWord(j)] = r]
    /\ regVal' = [regVal EXCEPT ![r] = ParkWord(j)]     \* reserved: bound on hand-out
    /\ UNCHANGED <<args, phase, j, evaluated, placed, slots, loaded>>

ParkMem ==
    /\ NeedsPark /\ MemOK
    /\ parkOf' = [parkOf EXCEPT ![ParkWord(j)] = Mem]
    /\ UNCHANGED <<args, phase, j, evaluated, placed, regVal, slots, loaded>>

\* The demand cannot be served: the hole this model exists for.
ParkStuck ==
    /\ NeedsPark /\ ~MemOK
    /\ ~\E r \in Regs : SurvivorOK(r) \/ PoolOK(j, r) \/ (r = Abi(j, 0) /\ OwnAbiOK)
    /\ phase' = "stuck"
    /\ UNCHANGED <<args, j, evaluated, placed, parkOf, regVal, slots, loaded>>

\* ---- phase 1: the expression runs, the value lands in its park ---------------------
Evaluate ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated
    /\ IF ParkWord(j) = None THEN TRUE ELSE parkOf[ParkWord(j)] # None
    /\ regVal' = [r \in Regs |-> IF r \in args[j].clob THEN Garbage ELSE regVal[r]]
    /\ evaluated' = TRUE
    /\ UNCHANGED <<args, phase, j, placed, parkOf, slots, loaded>>

Place ==
    /\ phase = "eval" /\ j <= N /\ evaluated
    /\ ParkWord(j) # None /\ ParkWord(j) \notin placed
    /\ LET w == ParkWord(j) IN
         /\ placed' = placed \cup {w}
         /\ IF parkOf[w] = Mem
            THEN slots' = slots \cup {w} /\ UNCHANGED regVal
            ELSE regVal' = [regVal EXCEPT ![parkOf[w]] = w] /\ UNCHANGED slots
    /\ UNCHANGED <<args, phase, j, evaluated, parkOf, loaded>>

ArgEvaluated(i) == evaluated /\ (ParkWord(i) = None \/ ParkWord(i) \in placed)

NextArg ==
    /\ phase = "eval" /\ j <= N /\ ArgEvaluated(j)
    /\ j' = j + 1 /\ evaluated' = FALSE
    /\ UNCHANGED <<args, phase, placed, parkOf, regVal, slots, loaded>>

BeginLoad ==
    /\ phase = "eval" /\ j = N + 1
    /\ phase' = "load" /\ j' = 1
    /\ UNCHANGED <<args, evaluated, placed, parkOf, regVal, slots, loaded>>

\* ---- phase 2: load argument i's ABI register(s) from its source ------------------
\* A parked word is read from its park (a register still holding it, or its
\* slot); an aggregate behind a parked address needs that address intact; a leaf
\* or a memory aggregate reads its home. Only the argument's own registers are
\* written — `releaseArgDest` kills whatever was bound there.
ParkVal(w) == IF parkOf[w] = Mem THEN (IF w \in slots THEN w ELSE Garbage)
              ELSE IF regVal[parkOf[w]] = w THEN w ELSE Garbage
LoadVal(i, k) ==
    IF Kind(i) = "comp" THEN ParkVal(Word(i, 0))
    ELSE IF Kind(i) = "aggr" /\ args[i].viaAddr THEN
         (IF ParkVal(AddrWord(i)) = AddrWord(i) THEN Word(i, k) ELSE Garbage)
    ELSE Word(i, k)
LoadArg(i) ==
    /\ regVal' = [r \in Regs |-> IF \E k \in Ks(i) : r = Abi(i, k)
                                 THEN LoadVal(i, CHOOSE k \in Ks(i) : Abi(i, k) = r)
                                 ELSE regVal[r]]
    /\ loaded' = loaded \cup {Word(i, k) : k \in Ks(i)}

Load ==
    /\ phase = "load" /\ j <= N
    /\ IF OnStack(j) \/ (\E k \in Ks(j) : Word(j, k) \in loaded)
       THEN UNCHANGED <<regVal, loaded>>          \* nothing to load (or loaded early)
       ELSE LoadArg(j)
    /\ j' = j + 1
    /\ UNCHANGED <<args, phase, evaluated, placed, parkOf, slots>>

\* `Bug = "earlyLoad"`: the fused loop — a leaf or a memory aggregate is
\* marshalled into its ABI register as soon as its turn comes in phase 1.
EarlyLoad ==
    /\ Bug = "earlyLoad"
    /\ phase = "eval" /\ j <= N /\ ArgEvaluated(j) /\ ~OnStack(j)
    /\ Kind(j) = "leaf" \/ (Kind(j) = "aggr" /\ ~args[j].viaAddr)
    /\ ~\E k \in Ks(j) : Word(j, k) \in loaded
    /\ LoadArg(j)
    /\ UNCHANGED <<args, phase, j, evaluated, placed, parkOf, slots>>

Call ==
    /\ phase = "load" /\ j = N + 1
    /\ phase' = "call"
    /\ UNCHANGED <<args, j, evaluated, placed, parkOf, regVal, slots, loaded>>

Finish == phase = "call" /\ phase' = "done" /\
          UNCHANGED <<args, j, evaluated, placed, parkOf, regVal, slots, loaded>>
Done   == phase = "done" /\ UNCHANGED vars      \* deadlock checking is on: `done` is not one

Next ==
    \/ \E r \in Regs : ParkReg(r)
    \/ ParkMem \/ ParkStuck
    \/ Evaluate \/ Place \/ NextArg \/ EarlyLoad
    \/ BeginLoad \/ Load \/ Call \/ Finish \/ Done

Spec == Init /\ [][Next]_vars

\* ============================== invariants ====================================

TypeOK ==
    /\ Len(args) \in 1..MaxArgs
    /\ phase \in {"eval", "load", "call", "done", "stuck"}
    /\ j \in 1..(MaxArgs + 1)
    /\ placed \subseteq WordIds /\ loaded \subseteq WordIds /\ slots \subseteq WordIds
    /\ parkOf \in [WordIds -> Regs \cup {Mem, None}]
    /\ regVal \in [Regs -> WordIds \cup {Free, Garbage}]

\* A placed park not yet consumed still holds its word.
ParksIntact ==
    phase \in {"eval", "load"} =>
        \A w \in placed : (w.k = 2 \/ w \notin loaded) =>
            IF parkOf[w] = Mem THEN w \in slots ELSE regVal[parkOf[w]] = w

\* A word loaded into its ABI register stays there until the call.
LoadedIntact ==
    phase \in {"eval", "load"} =>
        \A w \in loaded : regVal[Abi(w.j, w.k)] = w

\* At the call every register-passed word is in its ABI register.
ArgsInPlace ==
    phase \in {"call", "done"} =>
        \A i \in 1..N : ~OnStack(i) => \A k \in Ks(i) : regVal[Abi(i, k)] = Word(i, k)

NotStuck == phase # "stuck"

\* Reachability probes, expected to FAIL (run_call_marshal_tlc.sh asserts it):
\* the correct spec takes pool and memory parks, so those tiers are exercised.
NoPoolPark == \A w \in WordIds : parkOf[w] \notin (Pool \cup Range(ArgRegs)) \/
                                 parkOf[w] = Abi(w.j, 0)
NoMemPark  == \A w \in WordIds : parkOf[w] # Mem

====
