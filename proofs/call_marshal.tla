---- MODULE call_marshal ----
\* TLA+ model of arkham's CALL-ARGUMENT MARSHALLING: chibicc's two phases with
\* a parallel-move resolver (x64 `emitCall2Inner`, RISC `emitCall2`; grep MODEL:).
\*
\* Phase 1 runs EVERY argument expression and reduces each register-passed word
\* to a MOVE — a source that is no longer computed (a register, a memory place,
\* an address) and the ABI register it belongs in. Phase 2 performs the moves
\* as ONE PARALLEL MOVE. Everything else is two rules:
\*
\*   A source must SURVIVE phase 1. Memory does. A register does unless a later
\*   argument destroys it by ISA fiat (`idiv` writes rdx): such a source is
\*   copied into a PARK now (`redirect`). A computed value goes into a park, or
\*   straight into its own ABI register when the next rule allows it.
\*
\*   A move may go EARLY, during phase 1, when no later argument destroys its
\*   register and no other argument READS it (`placeNow`). Early is an
\*   optimization: every move may also wait for phase 2, and the model lets
\*   it choose either way (`ARKHAM_STRESS_MOVES=late` is the corpus's half).
\*
\* The resolver takes any move whose destination no other remaining move reads;
\* when none can go, every remaining destination is read — a cycle — and one
\* destination's readers are redirected to a STASH: a copy in any register
\* nothing live occupies, or memory. (It need not avoid the remaining moves'
\* destinations: a stash that lands on one is a source like any other, and the
\* resolver will not load that destination while the stash is still read. The
\* x86-64 emitter seals them anyway; this spec does not, and passes — a margin,
\* not a rule.)
\*
\* What varies (the whole protocol, not the last bug's axis):
\*   - 1..MaxArgs arguments, integer or float; an argument past its register
\*     file is stack-passed (its expression still runs and clobbers);
\*   - an optional hidden result pointer, preloaded into the first argument
\*     register by the caller and claimed like an argument;
\*   - integer leaves / computed scalars read a HOME: memory or a register
\*     (possibly ANOTHER argument's ABI register — a parameter passed to a
\*     diverging callee stays where it arrived); two arguments may read the
\*     same local; a computed scalar may clobber the fixed register;
\*   - float leaves / computed floats read a float home; a computed float may
\*     still clobber an integer register (`float(a div b)`);
\*   - aggregates: in memory, behind a computed address (reading a pointer
\*     home, clobbering), behind a by-reference POINTER homed in a register,
\*     or homed in a register PAIR — one or two words;
\*   - parks: survivor, pool (the argument registers count, outside the call's
\*     claims), memory; stashes: any register of the class nothing touches, or
\*     memory.
\* Values are identities: a register holds one value or Garbage.
\*
\* Bug injection (`Bug`, proofs/run_call_marshal_tlc.sh — the correct spec
\* passes, each injection fails the named invariant):
\*   "survivorOnly"  a park is callee-saved or nothing (the old takeHeld)  -> NotStuck
\*   "noAvoid"       a pool park may sit in a register the call claims     -> SourcesIntact
\*   "noBound"       a pool park ignores what a register holds             -> SourcesIntact
\*   "noLaterClob"   an early move ignores later arguments' clobbers       -> LoadedIntact
\*   "noReads"       an early move ignores other arguments' reads — the
\*                   diverging-call clobber (tests/arkham/noreturn_*)       -> SourcesIntact
\*   "noExposure"    a source a later argument destroys is not parked      -> SourcesIntact
\*   "noOrder"       the resolver ignores a remaining move's read          -> SourcesIntact
\*   "stashBound"    a stash ignores what a register holds                 -> SourcesIntact
\* Probes, expected to FAIL on the correct spec (so the paths are reached):
\*   NoStash, NoFloatStash, NoPoolPark, NoMemPark.

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxArgs,          \* arguments per call, 1..MaxArgs
    Fixed,            \* the argument registers an instruction may write by fiat
                      \* ({"A2"}: rdx on x86-64; {} on every RISC machine)
    Bug

IntArgs   == <<"A0", "A1", "A2">>
FltArgs   == <<"F0", "F1">>
Survivors == {"S0"}
IntPool   == {"T0"}                    \* r10; the argument registers join the pool
FltPool   == {"FT"}                    \* xmm8..; never an argument register
IntRegs   == {"A0", "A1", "A2", "S0", "T0"}
FltRegs   == {"F0", "F1", "FT"}
Regs      == IntRegs \cup FltRegs
NoReg     == "none"
Mem       == "mem"
Bugs == {"none", "survivorOnly", "noAvoid", "noBound", "noLaterClob", "noReads",
         "noExposure", "noOrder", "stashBound"}
ASSUME Bug \in Bugs /\ MaxArgs \in Nat \ {0} /\ Fixed \subseteq {"A2"}

\* ---- values -----------------------------------------------------------------
Free    == 0
Garbage == -1
Hidden  == 1
RegNum  == [A0 |-> 0, A1 |-> 1, A2 |-> 2, S0 |-> 3, T0 |-> 4, F0 |-> 5, F1 |-> 6, FT |-> 7]
V(h)    == 100 + RegNum[h]             \* the local homed in register h
MV(i)   == 200 + i                     \* argument i's local in memory
W(i, k) == 10 * i + k                  \* word k of aggregate i
P(i)    == 10 * i + 2                  \* the address of aggregate i
C(i)    == 10 * i + 3                  \* the computed value of argument i

\* ---- argument shapes -----------------------------------------------------------
IntHomes == {"A0", "A1", "A2", "T0", Mem}
RegHomes == IntHomes \ {Mem}
FltHomes == {"F0", "F1", Mem}
Clobs    == {{}, Fixed}
Shape(cls, kind, words, home, home2, clob) ==
    [cls |-> cls, kind |-> kind, words |-> words, home |-> home, home2 |-> home2, clob |-> clob]
Shapes ==
    {Shape("int", "leaf", 1, h, NoReg, {}) : h \in IntHomes} \cup
    {Shape("int", "comp", 1, h, NoReg, c) : h \in IntHomes, c \in Clobs} \cup
    {Shape("flt", "leaf", 1, h, NoReg, {}) : h \in FltHomes} \cup
    {Shape("flt", "comp", 1, h, NoReg, c) : h \in FltHomes, c \in Clobs} \cup
    {Shape("int", "mem", w, Mem, NoReg, {}) : w \in {1, 2}} \cup
    {Shape("int", "addr", w, h, NoReg, c) : w \in {1, 2}, h \in {"A0", "A1", Mem}, c \in Clobs} \cup
    {Shape("int", "ptr", w, h, NoReg, {}) : w \in {1, 2}, h \in RegHomes} \cup
    {Shape("int", "pair", 2, hh[1], hh[2], {}) : hh \in {x \in RegHomes \X RegHomes : x[1] # x[2]}}

VARIABLES
    args,       \* the call: seq of shapes, with `first` (ABI position) and `hidden`
    phase,      \* "eval" | "resolve" | "call" | "stuck"
    j,          \* the argument in hand
    evaluated,  \* its expression has run
    regVal,     \* [Regs -> value]
    bound,      \* registers something live occupies: homes, parks, loaded arguments
    slots,      \* values memory parks hold
    queue,      \* moves resolving NOW (an early group)
    pending,    \* moves waiting for phase 2
    want,       \* [Regs -> value] what a loaded argument register must keep
    stashes,    \* stashes taken
    used        \* park/stash tiers reached (probes)

vars == <<args, phase, j, evaluated, regVal, bound, slots, queue, pending, want, stashes, used>>

\* ---- the call shape ---------------------------------------------------------------
N           == Len(args)
HasHidden   == N > 0 /\ args[1].hidden
Cls(i)      == args[i].cls
Kind(i)     == args[i].kind
Ks(i)       == 0..(args[i].words - 1)
OnStack(i)  == IF Cls(i) = "flt" THEN args[i].first > Len(FltArgs)
               ELSE args[i].first + args[i].words - 1 > Len(IntArgs)
Dst(i, k)   == IF Cls(i) = "flt" THEN FltArgs[args[i].first] ELSE IntArgs[args[i].first + k]
Want(i, k)  == CASE Kind(i) = "leaf" -> (IF args[i].home = Mem THEN MV(i) ELSE V(args[i].home))
                 [] Kind(i) = "comp" -> C(i)
                 [] OTHER            -> W(i, k)
\* what `exprReadsReg` / `exprReadsFReg` see: the registers the expression reads
Reads(i)    == (IF Kind(i) = "mem" THEN {} ELSE {args[i].home, args[i].home2}) \cap Regs
LaterClob(i) == UNION {args[m].clob : m \in (i + 1)..N}
ProcClob     == UNION {args[m].clob : m \in 1..N}
RegPassed    == {i \in 1..N : ~OnStack(i)}
Claims == UNION {{Dst(i, k) : k \in Ks(i)} : i \in RegPassed} \cup
          (IF HasHidden THEN {"A0"} ELSE {})

RECURSIVE Before(_, _, _)
Before(sh, cls, i) == IF i = 1 THEN 0
                      ELSE Before(sh, cls, i - 1) +
                           (IF sh[i - 1].cls = cls THEN sh[i - 1].words ELSE 0)

Init ==
    \E n \in 1..MaxArgs, hid \in BOOLEAN :
      \E sh \in [1..n -> Shapes] :
        LET homeOf(i) == {sh[i].home, sh[i].home2} \cap Regs
            \* a register holding a value that is ARGUMENT-SPECIFIC (a pointer, a pair word)
            owned(i)  == IF sh[i].kind \in {"ptr", "pair"} THEN homeOf(i) ELSE {}
        IN
        \* a value an argument reads is not already destroyed by an earlier (or its
        \* own) expression — the reactive eviction moves such a local first. A
        \* LATER argument may destroy it: that is the exposure `redirect` answers.
        /\ \A i \in 1..n : homeOf(i) \cap UNION {sh[m].clob : m \in 1..i} = {}
        \* two arguments may read the same local, but an argument-specific value
        \* sits in a register nothing else uses
        /\ \A i, m \in 1..n : i # m => owned(i) \cap homeOf(m) = {}
        \* the caller wrote the hidden pointer into A0: nothing lives there
        /\ hid => \A i \in 1..n : "A0" \notin homeOf(i)
        /\ args = [i \in 1..n |->
                     [cls |-> sh[i].cls, kind |-> sh[i].kind, words |-> sh[i].words,
                      home |-> sh[i].home, home2 |-> sh[i].home2, clob |-> sh[i].clob,
                      first |-> Before(sh, sh[i].cls, i) + 1 +
                                (IF hid /\ sh[i].cls = "int" THEN 1 ELSE 0),
                      hidden |-> hid]]
        /\ regVal = [r \in Regs |->
              IF hid /\ r = "A0" THEN Hidden
              ELSE IF \E i \in 1..n : sh[i].kind = "ptr" /\ sh[i].home = r
                   THEN P(CHOOSE i \in 1..n : sh[i].kind = "ptr" /\ sh[i].home = r)
              ELSE IF \E i \in 1..n : sh[i].kind = "pair" /\ sh[i].home = r
                   THEN W(CHOOSE i \in 1..n : sh[i].kind = "pair" /\ sh[i].home = r, 0)
              ELSE IF \E i \in 1..n : sh[i].kind = "pair" /\ sh[i].home2 = r
                   THEN W(CHOOSE i \in 1..n : sh[i].kind = "pair" /\ sh[i].home2 = r, 1)
              ELSE IF \E i \in 1..n : r \in homeOf(i) THEN V(r)
              ELSE Free]
        /\ bound = UNION {homeOf(i) : i \in 1..n} \cup (IF hid THEN {"A0"} ELSE {})
        /\ want = [r \in Regs |-> IF hid /\ r = "A0" THEN Hidden ELSE Free]
        /\ phase = "eval" /\ j = 1 /\ evaluated = FALSE
        /\ slots = {} /\ queue = {} /\ pending = {} /\ stashes = 0 /\ used = {}

\* ---- sources and moves ---------------------------------------------------------
Move(dst, rd, slot, expect, val) ==
    [dst |-> dst, rd |-> rd, slot |-> slot, expect |-> expect, val |-> val]
SrcOK(m)   == /\ (m.rd = NoReg \/ regVal[m.rd] = m.expect)
              /\ (m.slot = Garbage \/ m.slot \in slots)
Clobbered(i) == [r \in Regs |-> IF r \in args[i].clob THEN Garbage ELSE regVal[r]]
ClassRegs(r) == IF r \in FltRegs THEN FltRegs ELSE IntRegs

\* `placeNow`
PlaceNow(i, dst) ==
    /\ Bug = "noLaterClob" \/ dst \notin LaterClob(i)
    /\ Bug = "noReads" \/ \A k \in 1..N : k # i => dst \notin Reads(k)

Range(s) == {s[x] : x \in 1..Len(s)}

\* The park tiers (`takeParked` / `pickTempReg(avoid = claims)` / a spill slot;
\* the float twin `takeFTmp`, whose pool holds no argument register).
ParkRegs(i, cls) ==
    IF cls = "flt"
    THEN {r \in FltPool : r \notin bound}
    ELSE {r \in Survivors : r \notin bound} \cup
         (IF Bug = "survivorOnly" THEN {}
          ELSE {r \in IntPool \cup Range(IntArgs) :
                  /\ Bug = "noBound" \/ r \notin bound
                  /\ Bug = "noAvoid" \/ r \notin Claims \cup LaterClob(i)})
ParkLocs(i, cls) == ParkRegs(i, cls) \cup (IF Bug = "survivorOnly" THEN {} ELSE {Mem})
Tier(p) == IF p = Mem THEN "mem" ELSE IF p \in Survivors THEN "survivor" ELSE "pool"

\* Put value `v` (read now) into park `p`; the move then reads the park.
ParkedMove(m, p, v) ==
    IF p = Mem THEN [m EXCEPT !.rd = NoReg, !.slot = m.expect]
    ELSE [m EXCEPT !.rd = p, !.slot = Garbage]
ParkWrite(rv, p, v) == IF p = Mem THEN rv ELSE [rv EXCEPT ![p] = v]
SlotWrite(p, v)     == IF p = Mem /\ v # Garbage THEN slots \cup {v} ELSE slots
BoundWrite(p)       == IF p = Mem THEN bound ELSE bound \cup {p}

\* Early or late — both are the protocol. A group goes early only as a whole.
Route(i, ms) ==
    \/ /\ \A m \in ms : PlaceNow(i, m.dst)
       /\ queue' = ms /\ UNCHANGED pending
    \/ /\ queue' = {} /\ pending' = pending \cup ms

\* The moves of a leaf / pointer / pair / memory aggregate, before exposure.
HomeMoves(i) ==
    CASE Kind(i) = "leaf" ->
           {Move(Dst(i, 0), IF args[i].home = Mem THEN NoReg ELSE args[i].home, Garbage,
                 Want(i, 0), Want(i, 0))}
      [] Kind(i) = "mem"  -> {Move(Dst(i, k), NoReg, Garbage, W(i, k), W(i, k)) : k \in Ks(i)}
      [] Kind(i) = "ptr"  -> {Move(Dst(i, k), args[i].home, Garbage, P(i), W(i, k)) : k \in Ks(i)}
      [] Kind(i) = "pair" -> {Move(Dst(i, k), IF k = 0 THEN args[i].home ELSE args[i].home2,
                                   Garbage, W(i, k), W(i, k)) : k \in Ks(i)}

\* ---- phase 1 ------------------------------------------------------------------------
Unchanged1 == UNCHANGED <<args, phase, j, stashes>>

EvalStack ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated /\ OnStack(j)
    /\ regVal' = Clobbered(j) /\ evaluated' = TRUE
    /\ UNCHANGED <<bound, slots, queue, pending, want, used>> /\ Unchanged1

\* A leaf, a pointer, a pair, a memory aggregate: nothing computes. A source a
\* later argument destroys is copied into a park now (`redirect`); at most one
\* home per argument is exposed (Fixed is one register).
EvalHome ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated /\ ~OnStack(j)
    /\ Kind(j) \in {"leaf", "mem", "ptr", "pair"}
    /\ LET ms == HomeMoves(j)
           exposed == IF Bug = "noExposure" THEN {} ELSE {m \in ms : m.rd \in LaterClob(j)}
       IN IF exposed = {}
          THEN /\ Route(j, ms)
               /\ UNCHANGED <<regVal, bound, slots, used>>
          ELSE \E p \in ParkLocs(j, Cls(j)) :
                 LET e  == CHOOSE m \in exposed : TRUE
                     v  == IF SrcOK(e) THEN e.expect ELSE Garbage
                     ms2 == {IF m.rd = e.rd THEN ParkedMove(m, p, v) ELSE m : m \in ms}
                 IN /\ regVal' = ParkWrite(regVal, p, v)
                    /\ slots' = SlotWrite(p, v) /\ bound' = BoundWrite(p)
                    /\ used' = used \cup {Tier(p)}
                    /\ Route(j, ms2)
    /\ evaluated' = TRUE
    /\ UNCHANGED want /\ Unchanged1

HomeOK(i) == args[i].home = Mem \/ regVal[args[i].home] = V(args[i].home)

\* A computed scalar: straight into its own register (early), or into a park.
EvalComp ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated /\ ~OnStack(j) /\ Kind(j) = "comp"
    /\ LET d == Dst(j, 0)
           v == IF HomeOK(j) THEN C(j) ELSE Garbage     \* read first, then clobber
       IN \/ /\ PlaceNow(j, d) /\ d \notin Reads(j)
             /\ regVal' = [Clobbered(j) EXCEPT ![d] = v]
             /\ want' = [want EXCEPT ![d] = C(j)]
             /\ bound' = bound \cup {d}
             /\ UNCHANGED <<slots, queue, pending, used>>
          \/ \E p \in ParkLocs(j, Cls(j)) :
               /\ regVal' = ParkWrite(Clobbered(j), p, v)
               /\ slots' = SlotWrite(p, v) /\ bound' = BoundWrite(p)
               /\ used' = used \cup {Tier(p)}
               /\ queue' = {}
               /\ pending' = pending \cup
                    {IF p = Mem THEN Move(d, NoReg, C(j), C(j), C(j))
                     ELSE Move(d, p, Garbage, C(j), C(j))}
               /\ UNCHANGED want
    /\ evaluated' = TRUE
    /\ Unchanged1

\* An aggregate behind a computed address: when every word may go now, the
\* address lives in a transient staging register and the words load at once;
\* otherwise the address parks and the words wait.
EvalAddr ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated /\ ~OnStack(j) /\ Kind(j) = "addr"
    /\ LET a == IF HomeOK(j) THEN P(j) ELSE Garbage
           cl == Clobbered(j)
       IN \/ /\ \A k \in Ks(j) : PlaceNow(j, Dst(j, k))
             /\ regVal' = [r \in Regs |-> IF \E k \in Ks(j) : r = Dst(j, k)
                            THEN (IF a = P(j) THEN W(j, CHOOSE k \in Ks(j) : r = Dst(j, k))
                                  ELSE Garbage)
                            ELSE cl[r]]
             /\ want' = [r \in Regs |-> IF \E k \in Ks(j) : r = Dst(j, k)
                          THEN W(j, CHOOSE k \in Ks(j) : r = Dst(j, k)) ELSE want[r]]
             /\ bound' = bound \cup {Dst(j, k) : k \in Ks(j)}
             /\ UNCHANGED <<slots, queue, pending, used>>
          \/ \E p \in ParkLocs(j, "int") :
               /\ regVal' = ParkWrite(cl, p, a)
               /\ slots' = SlotWrite(p, a) /\ bound' = BoundWrite(p)
               /\ used' = used \cup {Tier(p)}
               /\ queue' = {}
               /\ pending' = pending \cup
                    {IF p = Mem THEN Move(Dst(j, k), NoReg, P(j), P(j), W(j, k))
                     ELSE Move(Dst(j, k), p, Garbage, P(j), W(j, k)) : k \in Ks(j)}
               /\ UNCHANGED want
    /\ evaluated' = TRUE
    /\ Unchanged1

\* A park demand nothing can serve.
NeedsPark(i) ==
    \/ Kind(i) = "comp" /\ ~(PlaceNow(i, Dst(i, 0)) /\ Dst(i, 0) \notin Reads(i))
    \/ Kind(i) = "addr" /\ ~\A k \in Ks(i) : PlaceNow(i, Dst(i, k))
    \/ Kind(i) \in {"leaf", "ptr", "pair"} /\ Bug # "noExposure" /\
       \E m \in HomeMoves(i) : m.rd \in LaterClob(i)
EvalStuck ==
    /\ phase = "eval" /\ j <= N /\ ~evaluated /\ ~OnStack(j)
    /\ NeedsPark(j) /\ ParkLocs(j, Cls(j)) = {}
    /\ phase' = "stuck"
    /\ UNCHANGED <<args, j, evaluated, regVal, bound, slots, queue, pending, want, stashes, used>>

NextArg ==
    /\ phase = "eval" /\ j <= N /\ evaluated /\ queue = {}
    /\ j' = j + 1 /\ evaluated' = FALSE
    /\ UNCHANGED <<args, phase, regVal, bound, slots, queue, pending, want, stashes, used>>

BeginResolve ==
    /\ phase = "eval" /\ j = N + 1
    /\ phase' = "resolve"
    /\ UNCHANGED <<args, j, evaluated, regVal, bound, slots, queue, pending, want, stashes, used>>

\* ---- the resolver (an early group in phase 1, everything else in phase 2) ----------
Resolving == IF phase = "eval" THEN queue ELSE pending
SetResolving(q) == IF phase = "eval" THEN queue' = q /\ UNCHANGED pending
                   ELSE pending' = q /\ UNCHANGED queue
Active == (phase = "eval" /\ evaluated /\ queue # {}) \/ (phase = "resolve" /\ pending # {})

Eligible(m, q) == Bug = "noOrder" \/ \A k \in q \ {m} : k.rd # m.dst

Load ==
    /\ Active
    /\ \E m \in Resolving :
         /\ Eligible(m, Resolving)
         /\ regVal' = [regVal EXCEPT ![m.dst] = IF SrcOK(m) THEN m.val ELSE Garbage]
         /\ want' = [want EXCEPT ![m.dst] = m.val]
         /\ bound' = bound \cup {m.dst}
         /\ SetResolving(Resolving \ {m})
    /\ UNCHANGED <<args, phase, j, evaluated, slots, stashes, used>>

Stash ==
    /\ Active
    /\ ~\E m \in Resolving : Eligible(m, Resolving)
    /\ \E m \in Resolving :
         LET d == m.dst IN
         \E s \in {r \in ClassRegs(d) :
                     Bug = "stashBound" \/ r \notin bound}
                  \cup {Mem} :
           LET c == regVal[d] IN
              /\ regVal' = ParkWrite(regVal, s, c)
              /\ slots' = SlotWrite(s, c) /\ bound' = BoundWrite(s)
              /\ used' = used \cup {IF d \in FltRegs THEN "fstash" ELSE "stash"}
              /\ SetResolving({IF k.rd = d THEN ParkedMove(k, s, c) ELSE k : k \in Resolving})
    /\ stashes' = stashes + 1
    /\ UNCHANGED <<args, phase, j, evaluated, want>>

Call ==
    /\ phase = "resolve" /\ pending = {}
    /\ phase' = "call"
    /\ UNCHANGED <<args, j, evaluated, regVal, bound, slots, queue, pending, want, stashes, used>>

Done == phase \in {"call", "stuck"} /\ UNCHANGED vars

Next ==
    \/ EvalStack \/ EvalHome \/ EvalComp \/ EvalAddr \/ EvalStuck
    \/ NextArg \/ BeginResolve
    \/ Load \/ Stash
    \/ Call \/ Done

Spec == Init /\ [][Next]_vars

\* ============================== invariants ====================================

TypeOK ==
    /\ phase \in {"eval", "resolve", "call", "stuck"}
    /\ bound \subseteq Regs
    /\ stashes \in 0..(2 * MaxArgs)

\* Every remaining move's source still holds what the move will deliver.
SourcesIntact == \A m \in queue \cup pending : SrcOK(m)

\* A loaded argument register keeps its word until the call.
LoadedIntact == \A r \in Regs : want[r] # Free => regVal[r] = want[r]

\* At the call every register-passed word is in its ABI register, and the
\* hidden pointer is still in A0.
ArgsInPlace ==
    phase = "call" =>
        /\ \A i \in RegPassed : \A k \in Ks(i) : regVal[Dst(i, k)] = Want(i, k)
        /\ HasHidden => regVal["A0"] = Hidden

NotStuck == phase # "stuck"

\* Probes, expected to FAIL.
NoStash      == "stash" \notin used
NoFloatStash == "fstash" \notin used
NoPoolPark   == "pool" \notin used
NoMemPark    == "mem" \notin used

====
