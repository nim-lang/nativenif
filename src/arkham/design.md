# Arkham register strategy

Ordinary expression evaluation can be done with a total of one or two *working*
registers (ignoring the ABI call constraints) if it is allowed to use the
stack. We exploit this: the few registers expression evaluation needs are kept
out of the way, and *all* the remaining registers are mapped to local variables
in a pre-pass. When we run out of registers for a local, we steal from an
existing mapping (demote the coldest local to a stack slot).

## Why one or two registers suffice

A left-leaning chain already collapses to a single accumulator:

```
a = b + c * d * e + f
--->
mov  r1, c
mul  r1, d
mul  r1, e
add  r1, f
add  r1, b
mov  a, r1
```

The interesting case is an operator whose **both** operands are themselves
computed, e.g.

```
a = (b + c) * (d + e)
```

The two sub-sums cannot share one accumulator — while we compute `d + e` we must
keep `b + c` somewhere. With a *second* register that somewhere is a register;
with only *one* it is the stack:

```
mov  r1, b
add  r1, c        ; r1 = b + c
mov  [t], r1      ; spill the left partial to a stack slot
mov  r1, d
add  r1, e        ; r1 = d + e
mul  r1, [t]      ; r1 = (d + e) * (b + c)
mov  a, r1
```

`[t]` is a synthetic stack temporary. Nesting only ever deepens the spill chain;
it never needs a third register, because every partial that is not the live
accumulator goes to the stack. So the working-register budget is a small
constant, independent of the expression's size — which is exactly what frees the
rest of the register file for locals.

A right-nested chain (`b + (c + (d + …))`) would naively need one register per
level; arkham's value core applies a **Sethi–Ullman swap** in `allocBin`
(evaluate the computed operand first, straight into the accumulator, then fold
the leaf operand), collapsing it back to O(1) live registers.

## What the codegen actually does

The pre-pass (`allocateProc`) assigns every value position a `Location` and
every local a home; the pure-emit core (`genProc2`/`emitProcBody2`) then walks
the tree and emits bytes with no further allocation. Each backend partitions its
register file into the same four roles:

| role                     | AArch64 (AAPCS64)          | x86-64 (System V)        |
|--------------------------|----------------------------|--------------------------|
| arg / return             | x0–x7 (return x0)          | rdi, rsi, rdx, rcx, r8, r9 (return rax) |
| working temps (the pool) | x9–x13                     | r10                      |
| **staging bridge**       | x14, x15 (float v31)       | r11 (float xmm15)        |
| locals across a call     | x19–x28 (callee-saved)     | rbx, r12–r15 (callee-saved) |

The **accumulator** of an expression is a register drawn from the working pool.
When the pool is exhausted, the allocator *produces the value into memory*: it
synthesizes an `etmp` stack slot (`(var :etmpN (s) T)`) and the emitter writes
the value there through a **staging bridge** register — the `[t]` of the example
above. The bridge is reserved permanently *out of the pool* precisely so this is
always emittable: a `mem ← mem` move, the reload of a spilled operand into an
ALU that has no memory form (AArch64's three-operand `mul`/`add`), and a global
or stack address all need a scratch register that is guaranteed free. AArch64
reserves **two** bridges (x14/x15) because a single `cmp` of two spilled operands
must load both into registers (it has no memory-operand compare); x86-64 needs
only **one** (r11) because its instructions take a memory operand directly.

Note how lopsided x86-64 is: a *single* working temp (r10) plus the r11 bridge.
That is only viable because of the principle above — any expression reduces to
an accumulator plus stack spills — and it lets all five of rbx/r12–r15 home
locals.

Locals are mapped to **callee-saved** registers so they survive calls inside the
expression; a local with no live range across a call may instead sit in
`intLocalTempRegs` — the volatile registers with no fixed instruction role
(AArch64 x9–x13; x86-64 rdi/rsi/r8/r9, i.e. the argument registers, but never
r10/r11, which are the emitter's scratch and bridge). When the callee-saved pool
is exhausted, `reserveHeldScratch`/the steal logic demotes the coldest
register-homed local to a stack slot and reuses its register.

### How many registers the emitter actually needs

The budget above is a claim about *values*. The steps that overrun it are the ones
that hold an **address** in a register while a value passes through another one, and
they are enumerable: a load through a materialized global base (`lea &g` then
`mov dst, [base+off]`), an `(at …)` stride fold, an aggregate copy word between two
computed ends, a `casejmp` base, an atomic row that claims R11 as its own `work`
register. Each wants **two**. None wants three.

**MEASURED, and the last sentence was wrong.** `-d:arkhamStagingDbg` counts the
staging registers handed out and not yet given back, and reports the PEAK per
proc. Over a whole `nimony n -d:release` build of nimsem — 3,792 procs, zero
leaked registers:

| peak concurrent staging registers | procs |
|---|---|
| 0 | 1,320 (34.8 %) |
| 1 | 1,800 (47.5 %) |
| 2 | 633 (16.7 %) |
| **3** | **39 (1.0 %)** |

Every shape that needs two is *address + word* — an aggregate copy holding a
pointer while a word passes through it. The three-register shape is one of those
nested inside another: `an oconstr destination address + a nested-aggregate-field
pointer + a nested-aggregate-field copy word`. The others, in order of how many
procs hit them: nested-aggregate-field pointer + copy word (495), aggregate-copy
dst + src address (39), stack-param aggregate home + word (35), casejmp index +
base (15), aconstr element pointer + copy word (15).

Three is therefore the size of the Arm scratch set: the measurement above is what
says a fixed reservation of that size covers the enumerated shapes, and the Arm
targets can afford it because their third register (x16 / r8) was already spoken
for and idle. This is the number the allocator needs in order to take over the guarantee that a
staging pick can never fail. R11 is reserved today precisely because nobody knew
it; reserving THREE where these shapes occur, and nothing elsewhere, is what lets
the reservation go — and with it the register the spill census wants back.

Depth does not enter. A chain of spilled pointer loads — `p->a->b->c->…` — costs two
registers at depth 4 and two at depth 10, because `emitMemLoad2`'s `late` mode takes
the transfer register *after* the address is materialized, so it is not held across
the recursion, and each level's address registers die with its `(mem …)` tree.
`late` is not free, though: it gives up the global-base fusion that leas `&g`
straight into the result register, so it is taken only when the address HAS a
computed part (`lvalHasComputedPart`). Applied unconditionally it made a plain
`(dot <global> f)` load — which has no recursion to protect — want two registers
where one suffices, and that was a measured out-of-registers failure, not a
hypothetical. `tests/arkham/addr_chain_depth` is the fixture; it passes at
`ARKHAM_STRESS=2` at chain depth 5 and at depth 10.

**On x86-64, only one of the two is guaranteed.** R11 is reserved; the second is
whichever ABI volatile happens to be free, falling back to `pickStagingScratch`'s
callee-saved draw. The Arm targets no longer have that gap — all three of their
scratch registers are reserved outright, so a draw there never depends on what the
allocator left over. Closing it on x86-64 means taking a register from the
allocator, and nothing is going spare: rax is the return/div/mul register, rcx and rdx have fixed instruction
roles, rdi–r9 are argument registers that hold live *parameters* (R9 was tried as a
second reserved bridge and is a live param home in any six-parameter proc), rbx/r12–r15
are the callee-saved local homes, and r10 is the allocator's entire temp pool. The
second bridge therefore has to be bought from the callee-saved set — one fewer local
home, plus a push/pop in the procs that use it — and that is a measurement to make,
not a decision to take from the register file's shape.

Note what that costs on x86-64: those same volatiles are the emitter's
`StagingCandidates`, so every call-free local homed there is one fewer register the
emitter can transiently borrow. Under `-d:danger` (SROA + inlining) a hot leaf can
home a local in *all* of rdi/rsi/r8/r9 — and rcx/rdx too, via the `ShiftRegOk`/
`DivRegOk` extensions — leaving the emitter only r10/r11. Any emitter step that needs
a third register is then non-total. Keeping each step's demand inside that budget is
still the *first* answer — see the copy tiering below — because it costs nothing at
run time. But it cannot be the whole answer: the demand of a `(mem …)` address chain,
and of a right-nested spilled expression that holds its partial in the bridge while it
evaluates the other side, grows with nesting depth, and no fixed reservation covers an
unbounded demand.

### Out of registers is an ERROR, not a second allocator

The obvious answer to that unbounded demand — give the emitter a last resort — was
built and then **removed**, and the reason it went is worth more than the mechanism
was. It had two halves:

- `intEmergencyRegs` (rbp on x86-64): a private reserve the emitter drew from once the
  real pools ran dry, invisible to the allocator that is supposed to own register
  assignment.
- `borrowEmergency`/`restoreEmergency`: freeing a register by picking a victim,
  spilling it to a minted frame slot, killing and re-creating its binding, and
  reloading on `giveBack`.

That second one **is spilling** — the allocator's job, done a second time in a second
place with a second set of rules about who may be displaced (not sealed, not a named
local, not an accumulator, only at statement position…). Two allocators disagreeing
about who owns a register is a worse failure mode than running out of them, so
`pickStaging`/`pickStagingSealed` are deliberately **not total**: out of registers
fails loudly, and the fix belongs upstream in the allocator or in the demand of the
step that asked.

Removing the relief immediately exposed a real bug it had been masking, which is the
usual shape of this argument: the `cmp` emitter gave its LEFT operand a precise slot
when pointer-typed and never did the same for the RIGHT, so a pointer RHS that went
pool-dry landed in an `etmp` DECLARED `(i 64)` and nifasm rejected the comparison. It
only ever bit `nifreader`'s `while p < sentinel`, and only once the borrow stopped
supplying a register. `dontCare` now carries an optional slot that `forceRegDestE`
honours, so the register/immediate/memory folds are untouched and only the spilled
temp is typed.

The cost, measured and accepted: one register fewer. nifbench does not regress —
the pool was a last resort, not a hot-path home — and the compiler builds itself to a
byte-identical fixpoint with no emergency relief anywhere.

What remains non-total is the step that wants a third register while holding two
*sealed* addresses — `genAggrCopyStore`'s per-word transfer register. It has no
eligible victim by construction; making it total means giving that step a way to
release one of its two ends, not a bigger pool.

## How this deals with the ABI

The calling convention is handled by *partitioning*, not by special-casing the
expression evaluator:

- **Arguments and the return value** live in registers the pool never hands out
  (x0–x7 / rdi…r9, return in x0 / rax). Because argument shuffling and
  expression evaluation use disjoint register sets, marshalling a call's
  arguments can never collide with evaluating them. The convention's full
  caller-saved clobber set is emitted as the proc's `(clobber …)`.

- **Values that must survive a call** are exactly the locals, which already live
  in callee-saved registers; a temporary that the allocator sees crossing a call
  is given a callee-saved home (or spilled) rather than a pool register.

  This is load-bearing, not a preference. The moment a value that is live across a
  call is homed in an *argument* register, the first bullet's disjointness is gone
  and the marshalling of a single call can overwrite the source of one of its own
  later arguments — the general fix for which is a parallel-copy (shuffle)
  algorithm with cycle breaking. Partitioning is how this codegen avoids needing
  one. `rescueHomeRegs` (x86-64 r8/r9, AArch64 x6/x7) is therefore reserved for the
  **caller-save rescue** alone, where each crossed call is bracketed with an explicit
  save/restore; it must never host a value that is merely live across a call.
  `callerSaveHomeCandidates` enforces exactly that.

- **Whole-aggregate copies are tiered by operand FORM, not given a fixed budget.** A
  copy needs a per-word transfer register plus one register per end whose address
  must be computed. A *named* `(s)` slot is not such an end: nifasm folds a byte
  offset into the slot's own frame displacement (`(mem (rsp) name off)`, bounds-checked
  against the slot), so each named end costs **zero** registers. Two named ends
  therefore cost one register, one named end two, and only a copy between two computed
  addresses costs three. Reducing every source to an address in a register first —
  "one path for all forms" — made three the price of *every* copy, which is what ran
  the emit-time staging pool dry once optimization filled the volatiles with call-free
  locals. The tier is picked by `aggrSrcEnd`/`aggrDstEnd` and carried in `AggrEnd`.

- **Aggregate results.** A ≤16-byte aggregate is returned by value in the result
  registers (x0:x1 / rax:rdx); a larger one is returned through a hidden pointer
  (x8 on AArch64 / a synthetic first parameter in rdi on x86-64), which the
  prologue parks in a callee-saved register for the body to fill.

- **The frame is fixed.** The prologue saves the used callee-saved registers
  (AArch64 pairs them with fp/lr via `stp`) and lowers SP **once**, by an amount
  that already includes the local/`etmp` slots **and** the largest outgoing
  stack-argument area any call in the body needs. SP is then constant between
  prologue and epilogue. This is what lets stack-passed call arguments be written
  straight to `(mem sp (arg pN k))` at the reserved bottom of the frame with **no
  per-call `sub sp`**, and it keeps every `(s)` slot at a statically known offset.

- **Stack-passed arguments and parameters** appear once the integer arg registers
  are exhausted. An argument that does not fit the *remaining* arg registers goes
  entirely on the stack and consumes none (the AAPCS64 skip rule), so a later,
  smaller argument can still take a free register. On the callee side a
  stack-passed scalar or >16-byte aggregate (a pointer) is loaded from the
  incoming-args region above the frame into its callee-saved home in the
  prologue, before SP moves; a stack-passed ≤16-byte by-value aggregate is left
  in place and its home holds the *address* of those incoming bytes, so the body
  reads its fields through that pointer with no copy.

## Testing the pool-dry arms

Everything above has a *pool-dry* arm — produce-into-memory, the staging chain,
survivor parking, `mintSpillName` — and the `tests/arkham` fixtures are too small
to take any of them. `-d:arkhamStress` reaches that regime without bigger
fixtures: `ARKHAM_STRESS=k` keeps only the first `k` registers of each allocatable
pool (`src/arkham/stress.nim`), so the *same* corpus runs against a starved
register file.

The ABI and the reserved emitter bridges (r11/xmm15, x14/x15/v31) are not shrunk —
they are the guarantee the emitters are written against.

Each fixture's own `.exitcode`/`.output` stays the oracle, which is the point:
fewer registers may cost performance, or hit a documented out-of-registers assert,
but can never legitimately change what a program computes. A changed answer is
therefore a codegen bug by construction — the half a totality argument cannot
supply, since it proves a register is always available, not that the value
arriving in it is the right one.

### Fixed-register roles must be stated, not assumed

The first defect this mode found is the shape to watch for. `MachineDesc` models
the roles the *allocator* has to respect — `divRemReg` (rdx, clobbered by `idiv`),
`shiftCountReg` (rcx) — and the pools then simply omit rax. Every atomic lowering
read that omission as "rax is mine", which held right up to the point where the
pools ran dry and `takeInstrReg` fell through to the staging set, where rax is the
second candidate. A compare-exchange's `desired` landed there, the `mov rax,
*expected` that precedes the `cmpxchg` destroyed it, and the CAS compared the cell
against itself: reported success, stored the old value back.

The rule this leaves behind: **a register an emitter claims must be excluded where
the claim is made, not inferred from a pool it happens not to be in.** The
exclusion belongs to the *row*, not the opcode class — `atomicRegClaims` names rax
only for the rows that spin on a `cmpxchg` and r11 only for the rows that need a
`work` register, so a compare-exchange gets the bridge back in exchange for rax.
A blanket claim would have made three-operand atomics stop compiling under
pressure instead.

## Store forwarding: the value is in memory AND in a register

A value that lives in a stack slot got there somehow — a register held it and
stored it. Reading it back the way the allocator describes it (`NamedStack`)
reloads what a register still contains. The `RegMapping` in `regbind.nim` is the
one table that remembers otherwise: *which registers currently MIRROR a value
whose home is memory*. `mirrorStored` writes an entry at the release of a store's
source register; `forwardOf`/`takeForwarded` read it; every read site already
asks the right question, because `locationOfSym(name, pos)` is "where is the
VALUE, here" and this is a third answer to it, next to `callerSaveActive`
(dynamic, window-scoped) and `segs` (static, still empty).

Four rules carry the correctness, and each is structural rather than a discipline
to remember:

1. **An entry is an observation, never a reservation.** A mirrored register stays
   fully allocatable — `regFreeForTemp`/`regHoldsLiveLocal` consult `isMirror`
   for exactly that — so forwarding can never cause an out-of-registers. What it
   removes is a *load*, never a register.
2. **An entry keeps its nifasm binding alive.** The register still carries the
   `tmpN.0` it was bound with, so a read of it is a checked symbol and any write
   that does not go through a `RegBind` transition is an assembly-time error
   rather than a silent clobber.
3. **Only the pool and the bridge may hold one** (`mirrorableReg`). That is the
   whole safety argument: most registers have structural RAW uses — ABI
   marshalling, the syscall registers, a frame push — that no transition sees,
   while `emReg`/`emFReg` ASSERT that every use of the pool and the bridge is a
   typed binding. Machine-checked, not argued.
4. **A location that outlives the next instruction transfers ownership**
   (`takeForwarded`: `isTemp` + a `pickedRegs` reservation, released by the
   consumer's own `freeVal`). Handing out an unowned register instead is wrong in
   a way that looks right — the consumer holds it, evaluates the other operand,
   that evaluation legitimately takes the free mirror register, and the held
   location now names a different value.

Invalidation is deliberately coarse, because a missed kill is a miscompile and a
spurious one costs a reload:

 * a store to the name re-keys it (hooked at `emitStoreLoc`/`emScalarStore`, the
   one place every scalar store funnels through);
 * a CALL or an `(instr …)` row clears the map;
 * **every label DEFINITION clears the map** — which is what makes structured
   control flow a non-issue here. arkham emits no merge point that is not a
   label, so `emLab` is the single hook that covers `if`/`case`/`and`/`or`/the
   cond-fusion/`break`, and the one exception (`(loop …)`, whose back edge nifasm
   emits internally) clears in `emitLoop`.
 * a register event needs no hook at all: the entry lives in `RegBind`, so each
   of its ~10 transitions drops what it invalidates as one atomic step. A
   separate table invalidated by hand at those sites is the Cat-1 bug class that
   module exists to close.

**ADDRESS-taken locals are never mirrored** (`Plan.aliasable`, copied from the
analyser's props). They are the only ones a store through a pointer — or a callee
handed that pointer — can write without naming, and arkham has no points-to
analysis to bound that. Every other memory-homed local is alias-immune by
definition, and that one filter is what keeps the invalidation rules finite
instead of requiring a store classifier.

The second kind of entry is an **address** mirror: `r` holds `&g`. AArch64 has no
PC-relative memory operand, so a global's address costs `adrp`+`add` *every* time
it is needed; remembering it makes the next access to the same global a `mov`, or
free when the walk's pick lands on the register that already holds it. It has no
counterpart on x86-64, where the address is a single RIP-relative `lea`. Its
create site is narrower than a value mirror's, and for a reason worth keeping:
the address is only known to survive where the consuming instruction merely READ
it — a store through the address (`freeLvalTemps2`'s `addrIntact`), never a load,
whose `mov base, [base]` reuses the base register as its destination.

Measured on the fixture corpus: about 0.9 % fewer emitted instructions on both
targets, concentrated exactly where the model predicts — every float local on
x86-64 is stack-homed (SysV has no callee-saved xmm), so every float read was a
reload. `ARKHAM_NO_FORWARD=1` is the A/B switch. What is NOT implemented is
load→load forwarding: an entry is created only at a store's release point, where
the previous owner provably cannot modify the register again. Recording one at a
load means knowing that nothing wrote the register between the load and the
release, and that question has no cheap chokepoint today.

## Two questions, not one: `homeOfSym` vs `locationOfSym`

A local used to be looked up one way — `locationOfSym(name)` — because there was
one answer: the allocator gives a local a single home for its whole live range,
and returns registers to the pool by *scope*. That is what makes the allocator
fragile under inlining. Inlining lengthens live ranges, moves calls into ranges
that had none, and adds the callee's locals to the same pool; the classification
that decides a home is binary (does the range cross a call?) and the scarce class
it selects — the callee-saved registers — is five wide. So demand grows roughly
additively while supply does not, and the measured result is that **90 % of
spills are cross-call values while six or seven volatile registers sit idle**.
Nothing is spilled for want of registers; it is spilled for want of registers of
the right *kind*, and one home per local means a value can never change kind.

Fixing that means splitting a range — a volatile between calls, the save slot
across one — which makes "where does this value live" depend on WHERE the
question is asked. So the question is now asked in two forms, and every caller
has to say which it means:

 * **`homeOfSym(name)`** — the declared STORAGE. Addressing a stack slot, asking
   whether a name has a slot at all, saving and restoring it around a call, the
   parameter prologue moving an incoming value into its home. These are about the
   place, not the value, and they stay right no matter how the range is split.
 * **`locationOfSym(name, pos)`** — where the VALUE is, at token position `pos`.
   Every read of a local in an expression is one of these, and every such site
   already has a cursor, so it already knows its position.

Today the two answer identically: `RegAlloc.segs` is empty, so `locationOfSym`
falls through to the one home. The split was landed on its own, with the emitted
asm-NIF proven byte-identical, precisely so that the allocator change after it is
an ADDITION — fill `segs` — rather than a rewrite of eighty call sites whose
correctness could then only be argued, not diffed.

It is also what lets the allocator eventually decide locations for *expression*
positions and not just for symbol definitions: `locs` is already indexed by token
position, and the query is now asked that way too.

## What belongs in the machine description

The allocator has always been arch-neutral: `planer`, `regbind`, `analyser` and
`programs` contain no target test at all, and the whole planner asks `md.arch`
seven times, every one of them x86-vs-RISC. The seam is real. What leaked past it
is the EMITTER, and one flag — `CodeGen.thumbM` — was carrying facts of five
quite different kinds.

The first three are not target questions and are gone:

 * **Register roles.** Which register carries `&result` for a wide aggregate
   return, which one the emitter stages a value through, which is the link
   register, which set a call clobbers, which registers are withheld from every
   pool. These read `if g.thumbM: machine_m.X else: X`, which is how slot `R16`
   — not even MAPPED on Cortex-M — once reached the output. They are
   `MachineDesc` fields now, and a role a target lacks is `NoReg`, stated rather
   than defaulted: `Reg`'s zero value is `R0`, so an omitted role would silently
   name a register in use.

   Two of them are deliberately NOT the allocator's pools. `abiCalleeSaved` is
   what the ABI defines, `intCalleeSaved` what the allocator draws homes from;
   they coincide in a shipped build and differ under `-d:arkhamStress`. An
   `.assembler` body does not allocate, so a register it NAMES must still be
   legal and still be saved; and an AArch64 pair-save PAD is a slot in an `stp`,
   not a home, so it too comes from the ABI list. Conflating the two is a bug
   that byte-identical output cannot catch — only the stress suite can.

 * **One spelling per job.** There are exactly two ways to write a register down.
   `ab.rawReg` is the PHYSICAL register — a `(clobber …)` or `(param …)`
   declaration, a frame save, `SP`, a hand-written body. `emReg` is the VALUE:
   a bound register by its checked name, a raw tag otherwise, and in between the
   assertion that catches a temporary which escaped the binder. They are not
   interchangeable, and reaching for the wrong one compiles. The names now say
   which is which — `reg`, `mReg` and the raw arm of `emReg` were three names for
   one of them — and the float `fmov`/`fcvt` operand, which used to be raw on
   AArch64 and named on Cortex-M, is a value on both. That split was never
   arkham's decision: nifasm's AArch64 handlers read it with `parseRegisterA64`,
   which takes a tag and nothing else, while its Thumb-2 handlers had always
   taken either. The emitter was carrying a branch to paper over an asymmetry one
   level down, and the value check had a hole on the target with the LARGER
   register file.

 * **Narrow words.** A value too wide for one register is `size > wordSize()`,
   false by construction wherever the word is eight bytes. Every call site used
   to write `g.thumbM and g.isWideExpr(…)`, which said it twice and said it in
   terms of the wrong fact. `codegen_m64`'s `int64` arithmetic is now inherited by
   the next 32-bit back end rather than rewritten for it.

Two kinds remain, and they are the honest ones: **capability** (hardware divide,
`csel`, tail calls, the modified-immediate predicate — a target either has the
instruction or does not) and **frame shape** (pair saves with their padding
versus a register at a time, fp-relative versus SP-relative stack arguments).
The first wants a set and a couple of predicates in the description; the second
wants a handful of overridable procs. Neither is a place where a third target
should have to re-derive what the second already knows.
