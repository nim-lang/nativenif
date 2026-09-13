---- MODULE call_marshal ----
\* TLA+ model of arkham's CALL-ARGUMENT MARSHALLING under register pressure —
\* the x86-64 `emitCall2Inner` / `takeParked` protocol (src/arkham/x64/value.nim,
\* emit.nim; grep MODEL:). Arguments are marshalled left to right into the ABI
\* registers. A LATER argument's expression may destroy an argument register by
\* ISA fiat — `idiv` writes rdx, a variable shift reads its count from `cl` —
\* so an earlier argument whose register a later one clobbers is EXPOSED and
\* every word of it must PARK somewhere until the last argument has run, then be
\* delivered to its register just before the `(call)`.
\*
\* Why this exists (proofs/README.md, "call_marshal"): the park was taken with a
\* callee-saved-only `takeHeld` that asserted "out of registers" when the file
\* was dry, and neither `arkham_bindings` nor `aggr_marshal` could state that.
\* The former enables a borrow only when a register is free, under
\* `CHECK_DEADLOCK FALSE`, so "a value MUST be held and nothing is free" is not
\* a state it reaches; the latter has no registers as a resource. This model has
\* a DEMAND: an exposed word must park, and a park that cannot be served is the
\* `stuck` phase, which `NotStuck` reports. Deadlock checking is ON.
\*
\* The parking policy under test (`takeParked`), three tiers, any of which the
\* emitter may take (reaching for a survivor first is a preference):
\*   survivor  a callee-saved register the planer left the emitter (`pickHeldReg`)
\*   pool      a volatile expression temp (`pickTempReg`): r10 and the argument
\*             registers themselves (`intLocalTempRegs`), plus rdx / rcx only in
\*             a proc that contains no division / variable shift (the whole-proc
\*             gate) — and never a register in `avoid`: every register the CALL
\*             has a claim on (its argument registers, marshalled or not) and the
\*             registers its later arguments clobber. An argument register is
\*             otherwise refused only once something is BOUND to it, and that
\*             happens when the argument's value lands — too late for a park
\*             taken for an earlier argument.
\*   memory    a spill slot: the word is marshalled into its own ABI register,
\*             stored before the next argument runs (`stashParks`), reloaded at
\*             delivery (`deliverParks`).
\*
\* Bug injection (`Bug`, see proofs/run_call_marshal_tlc.sh — the correct spec
\* passes, each injection produces a counterexample):
\*   "survivorOnly"  the old `takeHeld(canSpill = false)`: tier one only
\*                   -> NotStuck (the aggr_arg_parked assert, #98 .. 2026-09-13)
\*   "noAvoid"       the pool ignores the call's claims
\*                   -> ParksIntact: the next argument lands on the park
\*   "noProcGate"    the pool hands out rdx/rcx in a proc that divides/shifts
\*                   -> ParksIntact: the clobber hits the park
\*   "noBound"       the pool ignores what a register holds
\*                   -> ParksIntact / MarshalledIntact
\*   "lateStash"     a memory park is stored whenever, not before the next argument
\*                   -> ParksIntact: the word is gone from its register
\*   "noExpose"      nothing is exposed (`laterClob` empty)
\*                   -> MarshalledIntact / ArgsInPlace
\*
\* Layouts: every call of 1..MaxArgs arguments, each 1 or 2 words (a scalar, or
\* a <=2-word aggregate) with any subset of the fixed registers as what its
\* expression clobbers; an argument past the register file is stack-passed —
\* nothing to park, but it still clobbers. Values are word IDENTITIES: the model
\* is about which register holds which word when, not about bytes.

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    A0, A1, A2, A3,   \* the ABI argument registers, in order (rdi rsi rdx rcx)
    S0,               \* the callee-saved survivor the planer reserves for the emitter
    T0,               \* the volatile expression temp outside the argument file (r10)
    MaxArgs,          \* arguments per call, 1..MaxArgs
    Free, Garbage,    \* what a register holds when it holds no live word
    Mem,              \* a park's location when it is a spill slot
    Bug               \* see above

ArgRegs   == <<A0, A1, A2, A3>>
Fixed     == {A2, A3}                 \* rdx (idiv), rcx (shift count)
Survivors == {S0}
Pool      == {T0}
Regs      == {A0, A1, A2, A3, S0, T0}
Bugs      == {"none", "survivorOnly", "noAvoid", "noProcGate", "noBound",
              "lateStash", "noExpose"}
ASSUME Bug \in Bugs
ASSUME MaxArgs \in Nat \ {0}

WordIds == [j: 1..MaxArgs, k: 0..1]
Word(j, k) == [j |-> j, k |-> k]
Range(s) == {s[i] : i \in 1..Len(s)}

VARIABLES
    args,       \* the call: seq of [words, clob, first]; `first` indexes ArgRegs
    j,          \* the argument being marshalled (Len(args)+1: all done)
    evaluated,  \* argument j's expression has run (its clobbers landed)
    placed,     \* words that reached their marshalling register
    stashed,    \* memory-parked words stored to their slot
    parks,      \* seq of [w, loc, abi], in the order taken
    delivered,  \* prefix of `parks` already moved to its ABI register
    regVal,     \* [Regs -> WordIds \cup {Free, Garbage}]
    slots,      \* memory-parked words whose slot holds the word
    phase       \* "marshal" | "deliver" | "call" | "done" | "stuck"

vars == <<args, j, evaluated, placed, stashed, parks, delivered, regVal, slots, phase>>

\* ---- the call shape ------------------------------------------------------------
RECURSIVE WordsBefore(_, _)
WordsBefore(ws, i) == IF i = 1 THEN 0 ELSE WordsBefore(ws, i - 1) + ws[i - 1]

N         == Len(args)
OnStack(i) == args[i].first + args[i].words - 1 > Len(ArgRegs)
Abi(i, k)  == ArgRegs[args[i].first + k]
Ks(i)      == 0..(args[i].words - 1)
LaterClob(i) == UNION {args[m].clob : m \in (i + 1)..N}
ProcClob     == UNION {args[m].clob : m \in 1..N}
Claims == UNION {{Abi(i, k) : k \in Ks(i)} : i \in {m \in 1..N : ~OnStack(m)}}
Exposed(i) == /\ Bug # "noExpose"
              /\ ~OnStack(i)
              /\ \E k \in Ks(i) : Abi(i, k) \in LaterClob(i)

Init ==
    \E n \in 1..MaxArgs :
      \E ws \in [1..n -> {1, 2}], cl \in [1..n -> SUBSET Fixed] :
        /\ args = [i \in 1..n |-> [words |-> ws[i], clob |-> cl[i],
                                   first |-> WordsBefore(ws, i) + 1]]
        /\ j = 1 /\ evaluated = FALSE
        /\ placed = {} /\ stashed = {} /\ parks = <<>> /\ delivered = 0
        /\ regVal = [r \in Regs |-> Free]
        /\ slots = {}
        /\ phase = "marshal"

\* ---- parks -------------------------------------------------------------------------
Parked(w)  == \E p \in Range(parks) : p.w = w
ParkOf(w)  == CHOOSE p \in Range(parks) : p.w = w
Holds(r)   == regVal[r] \in WordIds        \* bound: a live word sits (or is reserved) there

Avoid(i) == IF Bug = "noAvoid" THEN {} ELSE Claims \cup LaterClob(i)

\* `pickHeldReg`
SurvivorOK(r) == r \in Survivors /\ ~Holds(r)
\* `pickTempReg(avoid)`: r10 and the argument registers, rdx/rcx behind the
\* whole-proc gate, nothing bound, nothing the call still claims
PoolOK(i, r) ==
    /\ Bug # "survivorOnly"
    /\ r \in Pool \cup Range(ArgRegs)
    /\ Bug = "noBound" \/ ~Holds(r)
    /\ r \notin Avoid(i)
    /\ r \in Fixed => (Bug = "noProcGate" \/ r \notin ProcClob)
MemOK == Bug # "survivorOnly"

NextWord(i) == CHOOSE k \in Ks(i) : ~Parked(Word(i, k)) /\
                                    \A k2 \in Ks(i) : k2 < k => Parked(Word(i, k2))
NeedsPark == /\ phase = "marshal" /\ j <= N /\ ~evaluated /\ Exposed(j)
             /\ \E k \in Ks(j) : ~Parked(Word(j, k))

\* A park is DEMANDED for the next unparked word of argument j. Reserving a
\* register binds it to the word at once (`takeParked` binds on hand-out).
ParkReg(r) ==
    /\ NeedsPark
    /\ SurvivorOK(r) \/ PoolOK(j, r)
    /\ LET k == NextWord(j) w == Word(j, k) IN
         /\ parks' = Append(parks, [w |-> w, loc |-> r, abi |-> Abi(j, k)])
         /\ regVal' = [regVal EXCEPT ![r] = w]
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, delivered, slots, phase>>

ParkMem ==
    /\ NeedsPark /\ MemOK
    /\ LET k == NextWord(j) w == Word(j, k) IN
         parks' = Append(parks, [w |-> w, loc |-> Mem, abi |-> Abi(j, k)])
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, delivered, regVal, slots, phase>>

\* The demand cannot be served: the hole this model exists for.
ParkStuck ==
    /\ NeedsPark
    /\ ~MemOK
    /\ ~\E r \in Regs : SurvivorOK(r) \/ PoolOK(j, r)
    /\ phase' = "stuck"
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, parks, delivered, regVal, slots>>

\* ---- the argument itself ---------------------------------------------------------
AllParked(i) == ~Exposed(i) \/ \A k \in Ks(i) : Parked(Word(i, k))

\* Its expression runs: whatever the ISA pins it to is destroyed.
Evaluate ==
    /\ phase = "marshal" /\ j <= N /\ ~evaluated /\ AllParked(j)
    /\ regVal' = [r \in Regs |-> IF r \in args[j].clob THEN Garbage ELSE regVal[r]]
    /\ evaluated' = TRUE
    /\ UNCHANGED <<args, j, placed, stashed, parks, delivered, slots, phase>>

\* Word k lands: in its register park (already reserved), or in its ABI register
\* (an unparked word, or a memory park on its way to the slot). Landing in a
\* register overwrites whatever was there — `releaseArgDest` kills any binding.
Place(k) ==
    /\ phase = "marshal" /\ j <= N /\ evaluated /\ ~OnStack(j)
    /\ k \in Ks(j)
    /\ LET w == Word(j, k) IN
         /\ w \notin placed
         /\ placed' = placed \cup {w}
         /\ IF Parked(w) /\ ParkOf(w).loc # Mem
            THEN UNCHANGED regVal
            ELSE regVal' = [regVal EXCEPT ![Abi(j, k)] = w]
    /\ UNCHANGED <<args, j, evaluated, stashed, parks, delivered, slots, phase>>

\* `stashParks`: a memory-parked word is stored from its ABI register — right
\* after its argument is complete, or (lateStash) whenever.
Stash(w) ==
    /\ phase = "marshal" /\ w \in placed /\ w \notin stashed
    /\ Parked(w) /\ ParkOf(w).loc = Mem
    /\ Bug = "lateStash" \/ (j = w.j)
    /\ stashed' = stashed \cup {w}
    /\ slots' = IF regVal[ParkOf(w).abi] = w THEN slots \cup {w} ELSE slots
    /\ UNCHANGED <<args, j, evaluated, placed, parks, delivered, regVal, phase>>

ArgDone(i) ==
    /\ OnStack(i) \/ \A k \in Ks(i) : Word(i, k) \in placed
    /\ Bug = "lateStash" \/
       \A p \in Range(parks) : (p.w.j = i /\ p.loc = Mem) => p.w \in stashed

NextArg ==
    /\ phase = "marshal" /\ j <= N /\ evaluated /\ ArgDone(j)
    /\ j' = j + 1 /\ evaluated' = FALSE
    /\ UNCHANGED <<args, placed, stashed, parks, delivered, regVal, slots, phase>>

\* ---- after the last argument ----------------------------------------------------
BeginDeliver ==
    /\ phase = "marshal" /\ j = N + 1
    /\ (Bug = "lateStash" => \A p \in Range(parks) : p.loc = Mem => p.w \in stashed)
    /\ phase' = "deliver"
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, parks, delivered, regVal, slots>>

\* `deliverParks`: each park to its ABI register, in the order taken.
Deliver ==
    /\ phase = "deliver" /\ delivered < Len(parks)
    /\ LET p == parks[delivered + 1] IN
         regVal' = [regVal EXCEPT ![p.abi] =
                      IF p.loc = Mem THEN (IF p.w \in slots THEN p.w ELSE Garbage)
                      ELSE regVal[p.loc]]
    /\ delivered' = delivered + 1
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, parks, slots, phase>>

Call ==
    /\ phase = "deliver" /\ delivered = Len(parks)
    /\ phase' = "call"
    /\ UNCHANGED <<args, j, evaluated, placed, stashed, parks, delivered, regVal, slots>>

Finish == phase = "call" /\ phase' = "done" /\
          UNCHANGED <<args, j, evaluated, placed, stashed, parks, delivered, regVal, slots>>
Done   == phase = "done" /\ UNCHANGED vars      \* deadlock checking is on: `done` is not one

Next ==
    \/ \E r \in Regs : ParkReg(r)
    \/ ParkMem \/ ParkStuck
    \/ Evaluate
    \/ \E k \in 0..1 : Place(k)
    \/ \E w \in WordIds : Stash(w)
    \/ NextArg \/ BeginDeliver \/ Deliver \/ Call \/ Finish \/ Done

Spec == Init /\ [][Next]_vars

\* ============================== invariants ====================================

TypeOK ==
    /\ args \in Seq([words: {1, 2}, clob: SUBSET Fixed, first: 1..(2 * MaxArgs)])
    /\ Len(args) \in 1..MaxArgs
    /\ j \in 1..(MaxArgs + 1)
    /\ placed \subseteq WordIds /\ stashed \subseteq WordIds /\ slots \subseteq WordIds
    /\ regVal \in [Regs -> WordIds \cup {Free, Garbage}]
    /\ delivered \in 0..Len(parks)
    /\ phase \in {"marshal", "deliver", "call", "done", "stuck"}

\* A park not yet delivered still holds its word: a register park in its
\* register; a memory park in its ABI register until stored, in its slot after.
ParksIntact ==
    phase \in {"marshal", "deliver"} =>
        \A i \in (delivered + 1)..Len(parks) :
            LET p == parks[i] IN
              IF p.loc # Mem THEN regVal[p.loc] = p.w
              ELSE /\ (p.w \in placed /\ p.w \notin stashed) => regVal[p.abi] = p.w
                   /\ p.w \in stashed => p.w \in slots

\* An unparked word, once placed, stays in its ABI register through the rest
\* of the marshalling.
MarshalledIntact ==
    phase \in {"marshal", "deliver"} =>
        \A w \in placed : ~Parked(w) => regVal[Abi(w.j, w.k)] = w

\* At the call every register-passed word is in its ABI register.
ArgsInPlace ==
    phase \in {"call", "done"} =>
        \A i \in 1..N : ~OnStack(i) => \A k \in Ks(i) : regVal[Abi(i, k)] = Word(i, k)

NotStuck == phase # "stuck"

\* Reachability probes, expected to FAIL (run_call_marshal_tlc.sh asserts it):
\* the correct spec does take pool and memory parks, so the tiers the
\* invariants above are checked against are not vacuous.
NoPoolPark == \A p \in Range(parks) : p.loc \notin Pool \cup Range(ArgRegs)
NoMemPark  == \A p \in Range(parks) : p.loc # Mem

====
