---- MODULE aggr_marshal ----
\* TLA+ model of arkham's BY-VALUE AGGREGATE MARSHALLING: a ≤2-word aggregate
\* travels in general-purpose registers, one register per word (SysV / AAPCS64 /
\* AAPCS32). The full words are trivial; the model is about the trailing PARTIAL
\* word — the part of the object that does not fill its last register — and about
\* what the code is allowed to touch while moving it.
\*
\* Why this exists: the same "trailing partial eightbyte" loop was written FIVE
\* times in the x86-64 backend (`transferAggrWords`, `globalToRegs`, `tvarToRegs`,
\* `regsToStructThroughPtr`, `marshalAggrFromAddr`). One copy was fixed to move the
\* partial as a raw word (correct because a NAMED SLOT is padded to a word multiple);
\* the other four kept moving "the field at the word's offset" — which carries only
\* that ONE field. `{u32, u32, u8 mode, bool needsHeap}` (12 bytes) marshalled from
\* an address arrived with `needsHeap` zeroed; `{enum, char}` out of a `seq` lost the
\* `char`. Two commits (a64 first, then x64 #170) fixed it with an exact-bytes
\* strategy. This model states the contract all five copies must meet and shows
\* which strategies meet it under which storage assumption:
\*
\*   Algo = "widest"   x64 `loadPartialThroughPtr`/`storePartialThroughPtr`:
\*                     4-, then 2-, then 1-byte accesses inside the partial.
\*   Algo = "a64tail"  a64 `loadAggrTail`/`storeAggrTail`: when a whole word
\*                     precedes the partial, load the object's LAST word and shift
\*                     the tail down; else a single 1/2/4 access or bytes.
\*   Algo = "field"    the OLD code: the single field that starts at the word's
\*                     offset. (The bug: any second field in the partial is lost.)
\*   Algo = "fullword" `transferAggrWords`: move the whole word. Correct ONLY when
\*                     `Padded` (a named stack slot); through an arbitrary pointer
\*                     it reads/writes the neighbour — the last element of a
\*                     `seq[Alph]` ends two bytes before its allocation does.
\*
\* The model is the code's LOOP STRUCTURE, one memory access per step, so an
\* off-by-one in the width/offset bookkeeping shows up, not just the final policy.
\* (The a64 byte assembly is modelled low byte first; the code goes top-down and
\* shifts. Same bytes, same accesses — only the order differs, and no invariant here
\* depends on order.)
\*
\* Checked per configuration (see proofs/run_aggr_marshal_tlc.sh):
\*   NoOverRead / NoOverWrite — every access stays inside the object's STORAGE
\*                              (the object itself, or its padded slot when Padded);
\*   RegsHoldObject           — after the load pass every object byte sits at its
\*                              position in its word register;
\*   RoundTrip                — after the store pass the destination holds the
\*                              object byte for byte;
\*   NotStuck                 — the strategy could always make its next access.
\*
\* Layouts: every naturally-aligned object of 1..4 scalar fields drawn from `Sizes`
\* that fits in `MaxWords` words (arkham's `typeSizeAlign`: tail-padded to the
\* largest field's alignment). Arrays and nested objects are not enumerated; a
\* `(array (u 8) n)` behaves like n byte fields except under "field", where
\* `fieldAtOffset` finds NO field on an array layout — that case is "stuck" here.

EXTENDS Naturals, FiniteSets

CONSTANTS
    W,          \* target word size in bytes: 8 on x86-64 / AArch64, 4 on Cortex-M
    MaxWords,   \* by-value threshold in words (2: a ≤16-byte aggregate rides in GPRs)
    Sizes,      \* scalar field sizes a layout is built from: {1, 2, 4, 8}
    Algo,       \* the partial-word strategy under test, see above
    Padded,     \* TRUE: storage is a named slot padded to a word multiple;
                \* FALSE: an arbitrary address — the object may end where the mapping does
    Pad,        \* a register byte carrying no object byte
    Untouched   \* a destination byte no store has written

Algos == {"widest", "a64tail", "field", "fullword"}
ASSUME Algo \in Algos
ASSUME Padded \in BOOLEAN
ASSUME W \in {4, 8} /\ MaxWords \in Nat \ {0}

MaxSize == W * MaxWords
Sizes0  == Sizes \cup {0}
Bytes   == 0..(MaxSize - 1)
RegPos  == 0..(W - 1)
Words   == 0..(MaxWords - 1)
DestIdx == 0..(MaxSize + W - 1)     \* room to observe an over-write past the object

Align(x, a) == ((x + a - 1) \div a) * a
Max(a, b)   == IF a >= b THEN a ELSE b
Range(o, n) == o..(o + n - 1)

VARIABLES
    fields,   \* set of [off, size] records: the layout
    size,     \* aggrByteSize: the object's size including tail padding
    phase,    \* "load" | "store" | "done" | "stuck"
    word,     \* the word being transferred
    off,      \* next byte offset a partial-word strategy accesses
    regs,     \* [Words -> [RegPos -> Bytes ∪ {Pad}]]: which object byte each register byte holds
    dest,     \* [DestIdx -> Bytes ∪ {Untouched}]: the store side's memory
    reads,    \* every byte offset any load touched
    writes    \* every byte offset any store touched

vars == <<fields, size, phase, word, off, regs, dest, reads, writes>>

\* ---- the layout: 1..4 naturally aligned fields, tail-padded like typeSizeAlign ----
Init ==
    \E f1 \in Sizes, f2 \in Sizes0, f3 \in Sizes0, f4 \in Sizes0 :
        /\ (f2 = 0 => f3 = 0) /\ (f3 = 0 => f4 = 0)
        /\ LET e1 == f1
               o2 == IF f2 = 0 THEN e1 ELSE Align(e1, f2)
               e2 == o2 + f2
               o3 == IF f3 = 0 THEN e2 ELSE Align(e2, f3)
               e3 == o3 + f3
               o4 == IF f4 = 0 THEN e3 ELSE Align(e3, f4)
               e4 == o4 + f4
               al == Max(Max(f1, f2), Max(f3, f4))
               sz == Align(e4, al)
           IN /\ sz <= MaxSize
              /\ fields = {[off |-> 0, size |-> f1]}
                          \cup (IF f2 = 0 THEN {} ELSE {[off |-> o2, size |-> f2]})
                          \cup (IF f3 = 0 THEN {} ELSE {[off |-> o3, size |-> f3]})
                          \cup (IF f4 = 0 THEN {} ELSE {[off |-> o4, size |-> f4]})
              /\ size = sz
        /\ phase = "load" /\ word = 0 /\ off = 0
        /\ regs = [w \in Words |-> [k \in RegPos |-> Pad]]
        /\ dest = [o \in DestIdx |-> Untouched]
        /\ reads = {} /\ writes = {}

WordCount == (size + W - 1) \div W          \* aggrWordCount
Base      == word * W                       \* the current word's first byte
Rem       == size - Base                    \* object bytes from Base on
IsFull    == Rem >= W                       \* the code's `byteSize - i*8 >= 8`
Storage   == IF Padded THEN 0..(Align(size, W) - 1) ELSE 0..(size - 1)

\* ---- one memory access -------------------------------------------------------
\* LOAD `n` bytes at `o` into the current word register, at position `o - Base`.
LoadBytes(o, n) ==
    /\ regs' = [regs EXCEPT ![word] =
                 [k \in RegPos |-> IF k \in Range(o - Base, n) THEN Base + k ELSE regs[word][k]]]
    /\ reads' = reads \cup Range(o, n)
\* STORE `n` bytes from register position `o - Base` to `o`.
StoreBytes(o, n) ==
    /\ dest' = [j \in DestIdx |-> IF j \in Range(o, n) THEN regs[word][j - Base] ELSE dest[j]]
    /\ writes' = writes \cup Range(o, n)

NextWordLoad  == /\ word' = word + 1 /\ off' = (word + 1) * W
                 /\ UNCHANGED <<fields, size, phase, dest, writes>>
NextWordStore == /\ word' = word + 1 /\ off' = (word + 1) * W
                 /\ UNCHANGED <<fields, size, phase, regs, reads>>

\* x64 `loadPartialThroughPtr`: step(32) step(16) step(8) — widest access that fits.
Width(n) == IF n >= 4 THEN 4 ELSE IF n >= 2 THEN 2 ELSE 1

\* ---- load pass ------------------------------------------------------------------
LoadFull ==
    /\ phase = "load" /\ word < WordCount /\ IsFull
    /\ LoadBytes(Base, W)
    /\ NextWordLoad

LoadWidest ==
    /\ phase = "load" /\ word < WordCount /\ ~IsFull /\ Algo = "widest"
    /\ LET n == size - off  wd == Width(n) IN
         /\ LoadBytes(off, wd)
         /\ IF off + wd = size THEN NextWordLoad
            ELSE /\ off' = off + wd
                 /\ UNCHANGED <<fields, size, phase, word, dest, writes>>

LoadA64 ==
    /\ phase = "load" /\ word < WordCount /\ ~IsFull /\ Algo = "a64tail"
    /\ IF Base >= W THEN
          \* a whole word precedes: the object's LAST W bytes are in bounds — read
          \* them as one word and shift the tail down into place
          /\ regs' = [regs EXCEPT ![word] = [k \in RegPos |-> IF k < Rem THEN Base + k ELSE Pad]]
          /\ reads' = reads \cup Range(size - W, W)
          /\ NextWordLoad
       ELSE IF Rem \in {1, 2, 4} THEN
          /\ LoadBytes(Base, Rem)
          /\ NextWordLoad
       ELSE \* 3/5/6/7 bytes with no word to borrow: assemble byte by byte
          /\ LoadBytes(off, 1)
          /\ IF off + 1 = size THEN NextWordLoad
             ELSE /\ off' = off + 1
                  /\ UNCHANGED <<fields, size, phase, word, dest, writes>>

LoadField ==
    /\ phase = "load" /\ word < WordCount /\ ~IsFull /\ Algo = "field"
    /\ IF \E f \in fields : f.off = Base THEN
          LET f == CHOOSE f \in fields : f.off = Base IN
            /\ LoadBytes(Base, f.size)      \* ...and nothing else in this word
            /\ NextWordLoad
       ELSE /\ phase' = "stuck"             \* fieldAtOffset returned ""
            /\ UNCHANGED <<fields, size, word, off, regs, dest, reads, writes>>

LoadFullword ==
    /\ phase = "load" /\ word < WordCount /\ ~IsFull /\ Algo = "fullword"
    /\ LoadBytes(Base, W)                   \* the whole word, padding included
    /\ NextWordLoad

BeginStore ==
    /\ phase = "load" /\ word = WordCount
    /\ phase' = "store" /\ word' = 0 /\ off' = 0
    /\ UNCHANGED <<fields, size, regs, dest, reads, writes>>

\* ---- store pass (the mirror: the same widths, from the same register positions) ----
StoreFull ==
    /\ phase = "store" /\ word < WordCount /\ IsFull
    /\ StoreBytes(Base, W)
    /\ NextWordStore

StoreWidest ==
    /\ phase = "store" /\ word < WordCount /\ ~IsFull /\ Algo = "widest"
    /\ LET n == size - off  wd == Width(n) IN
         /\ StoreBytes(off, wd)
         /\ IF off + wd = size THEN NextWordStore
            ELSE /\ off' = off + wd
                 /\ UNCHANGED <<fields, size, phase, word, regs, reads>>

StoreA64 ==
    /\ phase = "store" /\ word < WordCount /\ ~IsFull /\ Algo = "a64tail"
    /\ IF Rem \in {1, 2, 4} THEN
          /\ StoreBytes(Base, Rem)
          /\ NextWordStore
       ELSE \* storeAggrTail: byte 0, then bytes 1..n-1 — never a word past the object
          /\ StoreBytes(off, 1)
          /\ IF off + 1 = size THEN NextWordStore
             ELSE /\ off' = off + 1
                  /\ UNCHANGED <<fields, size, phase, word, regs, reads>>

StoreField ==
    /\ phase = "store" /\ word < WordCount /\ ~IsFull /\ Algo = "field"
    /\ IF \E f \in fields : f.off = Base THEN
          LET f == CHOOSE f \in fields : f.off = Base IN
            /\ StoreBytes(Base, f.size)
            /\ NextWordStore
       ELSE /\ phase' = "stuck"
            /\ UNCHANGED <<fields, size, word, off, regs, dest, reads, writes>>

StoreFullword ==
    /\ phase = "store" /\ word < WordCount /\ ~IsFull /\ Algo = "fullword"
    /\ StoreBytes(Base, W)
    /\ NextWordStore

Finish ==
    /\ phase = "store" /\ word = WordCount
    /\ phase' = "done"
    /\ UNCHANGED <<fields, size, word, off, regs, dest, reads, writes>>

Next ==
    \/ LoadFull \/ LoadWidest \/ LoadA64 \/ LoadField \/ LoadFullword \/ BeginStore
    \/ StoreFull \/ StoreWidest \/ StoreA64 \/ StoreField \/ StoreFullword \/ Finish

Spec == Init /\ [][Next]_vars

\* ============================== invariants ====================================

TypeOK ==
    /\ fields \subseteq [off: Bytes, size: Sizes]
    /\ size \in 1..MaxSize
    /\ phase \in {"load", "store", "done", "stuck"}
    /\ word \in 0..MaxWords
    /\ regs \in [Words -> [RegPos -> Bytes \cup {Pad}]]
    /\ dest \in [DestIdx -> Bytes \cup {Untouched}]
    /\ reads \subseteq Nat /\ writes \subseteq Nat

\* Nothing outside the object's storage is ever touched.
NoOverRead  == reads  \subseteq Storage
NoOverWrite == writes \subseteq Storage

\* After the load pass, register word w holds object byte w*W+k at position k.
RegsHoldObject ==
    phase \in {"store", "done"} =>
        \A w \in Words, k \in RegPos : w * W + k < size => regs[w][k] = w * W + k

\* After the store pass, the destination holds the object byte for byte.
RoundTrip == phase = "done" => \A o \in 0..(size - 1) : dest[o] = o

NotStuck == phase # "stuck"

Safety == NoOverRead /\ NoOverWrite /\ RegsHoldObject /\ RoundTrip /\ NotStuck

====
