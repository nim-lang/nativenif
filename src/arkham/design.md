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

### The emergency borrow

So the transient staging picks have a last resort: `borrowEmergency` frees a register
by **spilling its current owner to a frame slot** for the duration of the pick, and
`giveBack` reloads it. One 8-byte slot per active borrow suffices because the borrows
nest — depth is bounded by the expression, the slots are minted on demand
(`mintSpillName`, so the prologue declares them after the body) and reused across the
body. This is what makes those steps total at any pressure, rather than merely at the
pressure the corpus happens to reach.

Two conditions, and both are load-bearing:

- **The pick must be at STATEMENT position.** The borrow injects `mov` instructions;
  a pick made while an operand tree is half-built would splice them into the middle of
  it. So it is opt-in per site (`stmtPos = true`), granted only where the emitter is
  between statements: `produceIntoMem2`, and `reloadMemBase2` (whose caller
  `prematLval2` exists precisely to emit statements before the consuming instruction).
- **The victim must be an unsealed BOUND TEMP.** Such a value is anonymous — reachable
  only through a `Location` its owner captured further up the Nim call stack — and the
  window is nested inside that owner's step, so the owner cannot read the register
  before the value is back. A register homing a *named* local is excluded because code
  inside the window can name it. A **sealed** register is excluded because the seal
  means "the step now emitting still needs this": `genAggrCopyStore` seals its source
  and destination addresses and then reads both throughout `copyAggr`, so displacing
  one there is a silent miscompile — which is exactly what `ARKHAM_STRESS_EMERGENCY`
  reported as `baseobj_slice` the first time that site was (wrongly) opted in.

### The copy that holds two sealed addresses

`genAggrCopyStore`'s per-word transfer register is the step that wants a third register
while its own two end addresses are sealed — so the borrow above has no eligible victim
by construction whenever those ends are all that is left. It escalates:
`pickStagingScratch` → `pickHeldReg` → `borrowEmergency` → **spilled ends**.

The last arm is the same tiering argument once more. A copy is expensive in registers
only because it wants both addresses live at once, and *an address parked in a frame
slot is not live*: `copyAggrSpilledEnds` writes each staged end's address to an 8-byte
slot and reloads it per word, handing the copy back exactly the registers those
addresses were occupying — the source's becomes the value register, the destination's
the reloaded address. Four instructions per word instead of two, which is the right
trade for a path that is otherwise a compile error.

It needs the SOURCE address to be one we staged (that register is what carries the
value). A *named-slot* source into a *computed* destination has no such register, and
is served by the step before it instead — the borrow, in **closed-window** mode.

### Open vs closed windows

Whether a borrow may displace a given value is decided by the WINDOW, not by the
value. An **open** window — `produceIntoMem2` recurses into arbitrary expression
emission — can emit a use of any named local, and can reach an enclosing step's parked
base through `ra.locs`; so there the victim must be an unsealed bound temp, nothing
else. A **closed** window is a fixed instruction sequence the caller can enumerate:
`copyAggr`'s load/store loop names only `srcE`, `dstE` and `tmp`. There "nothing inside
reads the victim" is decidable, the caller lists its own registers in `avoid`, and
*every other candidate* — sealed, accumulator, even a named local's home — is fair
game. That is what makes the closed-window callers total: running out of registers
would require the caller to own them all.

The two knobs are not optional decoration. `ARKHAM_STRESS_EMERGENCY` runs a preference
pass that takes a sealed / local-home victim when one exists, because those arms are
otherwise unreachable from the corpus — measured: zero such victims without it. Every
rule stated above was established by that pass reporting a wrong answer, not by
reading the code.

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

`ARKHAM_STRESS_EMERGENCY=1` is a second, independent knob for the emergency borrow
above, and it deliberately does NOT shrink anything: the borrow fires only when every
staging candidate is *occupied*, so taking registers away from the allocator makes it
less reachable, not more. Instead it takes the borrow wherever one is available, in
preference to a free register (binding an otherwise-free victim first, so the emitted
sequence is byte-for-byte the production one). Without it that path would be exercised
by nothing but full compiler builds — and it is what caught the sealed-victim
miscompile above. The ABI and the reserved emitter bridges (r11/xmm15, x14/x15/v31)
are not shrunk — they are the guarantee the emitters are written against.

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
