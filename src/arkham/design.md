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
expression; a local with no live range across a call may instead sit in the
working pool on AArch64 (`intLocalTempRegs`), but never on x86-64 (r10/r11 are
the emitter's scratch, so a local there would starve it). When the callee-saved
pool is exhausted, `reserveHeldScratch`/the steal logic demotes the coldest
register-homed local to a stack slot and reuses its register.

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
