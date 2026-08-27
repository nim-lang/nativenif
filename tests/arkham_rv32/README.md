# The RV32 codegen pass

The POSITIVE fixtures live in **`tests/arkham_m/`** — the Cortex-M corpus — because
the two targets are the same shape (32-bit word, `BlockFrame`, bare metal,
semihosting exit) and a second copy of 130 fixtures would drift from the first
rather than test anything the first does not.

What IS in this directory is the set that cannot be shared: rejection fixtures
whose whole content is a register name. A `{.register: "r0".}` pin says nothing
about RV32 except that `r0` is not one of its registers, so those are written
here against `x0`..`x30` — see "Rejections, checked by message" below.

`tester.rv32CodegenTests` runs that corpus through
`arkham --os:embedded --cpu:riscv32` → `nifasm` → `qemu-system-riscv32`, checking
each fixture's exit code against its `.exitcode` file. The quarantine list lives
in `tester.nim` beside the pass.

## 126 of 130 shared, plus 2 RV32-native

The pass no longer runs `err_*` fixtures — those must NOT compile, on any target,
and `rv32RejectionTests` checks them by message instead. Two of the four still
quarantined are Cortex-M's telling of a test this directory now has its own of;
the other two are genuinely absent features.

**Replaced, not missing (2).** `assembler_m` and `semihost_writec` pin Cortex-M
registers and use a Thumb `bkpt`. `assembler_rv32` and `semihost_writec_rv32`
here are the same tests told in RV32's register file and instruction set. Both
targets keep theirs.

**Atomics (1).** `atomics`. RV32's `A` extension has `lr.w`/`sc.w`, so the ISA is
not the obstacle: arkham has no lowering for them (its two are AArch64's
`ldaxr`/`stlxr` and ARMv7-M's `ldrex`/`strex`), and this target reserves no
`atomicScratch` triple for one — it spent its third bridge. Whoever lowers RV32
atomics has to reserve three registers explicitly and say so; `checkMachine`
refuses a partial triple.

**Interrupts (1).** `interrupt_pendsv`. `rejectForRv32` turns `{.interrupt.}` away
by name: a RISC-V core reaches its handlers through `mtvec`, which in vectored
mode holds JUMP INSTRUCTIONS rather than addresses, and the trampoline table that
builds is outstanding (see `writerv32.nim`). This is the one of the four with no
fixture to write — the feature has to exist first, and a fixture asserting the
refusal is already what `rv32Rejections` covers through `err_interrupt_*`.

## The RV32-native positive fixtures

`assembler_rv32` is `assembler_m`'s test of the `{.assembler.}` mode: pinned
parameters, a callee-saved pin, a `{.stack.}` local, `while`/`break`, `{.naked.}`,
`(addr g)` of a global — and a `cmp` read through all FOUR conditions RV32 can
fuse. That last part is why it could not simply be `assembler_m` with the register
names swapped: RV32 has no condition flags at all. Its selector fuses `(cmp a b)`
into the branch that consumes it, so `zf`/`nz` are equality and `cf`/`nc` are the
unsigned `<`/`>=` a borrow denotes, while `sf`/`of` are refused by name — the sign
of a difference agrees with `<` only when the subtraction did not overflow. The
intrinsic rows say so now, and `armFlagSupported` grew a third arm for it: the
`{ZfO, NzO}` default was safe but told `cf` it did not exist, which is the wrong
sentence about a target whose branches ARE comparisons.

`semihost_writec_rv32` prints through the RISC-V semihosting protocol. It needed a
`semihost` intrinsic row of its own rather than `bkpt` with another encoding,
because a semihosting call there is not one instruction but a fixed three —
`slli x0,x0,0x1f`, `ebreak`, `srai x0,x0,7` — whose outer two are architectural
no-ops that exist only so a debug agent recognises the middle one as a request.
`bkpt` takes its magic number as an operand; here the magic IS the surrounding
instructions, so there is nothing to give an operand to.

Writing it found a nifasm bug: `pass2` resets `clobbered`, `clobberedA64` and
`clobberedM` at every proc — "each proc is a fresh control flow" — and
`clobberedRv` was never added to that list. Procs are generated in REACHABILITY
order, so `main` was emitted first, its calls marked a0 clobbered, and the
`{.assembler.}` `putc` that followed was told its own parameter's value was gone.
It needs a callee reached from a caller that clobbers a register the callee pins,
which is exactly this fixture and nothing in the corpus before it.

## Rejections, checked by message

`rv32RejectionTests` runs eleven. Four are `tests/arkham_m/err_*` fixtures judged
by what RV32 says: the volatile-width rule (identical wording to Cortex-M's — the
rule is the ROW's, not the target's), a foreign register spelling, and the two
interrupt fixtures, which on this target cover `rejectForRv32` rather than what
they cover on Cortex-M.

The other seven are RV32-native, in this directory. They exist because the four
`err_asm_*` fixtures of `tests/arkham_m/` pin Cortex-M register NAMES, so on RV32
they are refused by the first arm of the cascade — "`r0` is not a RV32
general-purpose register" — and never reach the rule they were written to test. A
fixture that fails for the wrong reason is worse than no fixture: it reports green.

Writing them found that `asmPinReg`'s cascade had a Thumb arm and an AArch64
`else`, and RV32 fell into the second. That arm answers about a different register
file: `x16`/`x17` are IP0/IP1 there and the ARGUMENT registers a6/a7 here, `x18` is
the platform register there and the callee-saved home `s2` here, and the
link-register message names `x30` in prose while `md.linkReg` is `x1`. Confident
sentences about the wrong register, every one.

Three of the seven have no Cortex-M counterpart at all, because the register file
differs rather than the rule: `x0` discards writes, `gp`/`tp` belong to the whole
program, and `s0` is kept off the file so a debugger's frame walk has somewhere to
stand. Two Cortex-M rejections have no RV32 counterpart for the same reason —
there is no "assembler's own scratch" pin to refuse (nifasm's `x31` has no asm-NIF
tag, so a code generator cannot spell it even by mistake), and no callee-saved
register outside the prologue's saved set.

## The "64-bit constants" group was not about 64-bit values

Three fixtures (`a64_logical_imm`, `bitand_imm64`, `overflow_check`) were parked
here as "a literal wider than 32 bits is not split across the register pair". It
was nothing to do with the wide path. Each declares a `(u 32)` local and
initialises it out of range — `(var :x.0 . (u 32) 9223372036854775807)` — and
arkham passed the literal through unclamped into `(mov x.0 …)` on a register that
holds 32 bits.

Both 32-bit back ends were handed the SAME asm-NIF and disagreed about it: the
Thumb selector truncated with a bare `uint32(…)` conversion, silent only because
release builds have range checks off, and the RV32 selector refused it by name.
Neither has the Leng type to decide with. `emit.movImm` does, and clamps there —
the single place a literal becomes `(mov reg <imm>)`. The wide path is unaffected:
`wideConstHalf` splits a 64-bit constant before it reaches `movImm`, and each half
fits by construction.

The emitted code moved on Cortex-M for exactly those three fixtures — the literal
is now written truncated instead of being truncated later — and all three still
pass there. Both 64-bit targets are byte-identical, since `wordSize()` is 8.

## What the corpus found

**Three** bugs, all the same shape, and none visible on any target that existed
before: a register ROLE read from the AArch64 machine MODULE instead of from the
machine DESCRIPTION, which is correct on both Arm targets and on x86-64 because
all three answer the same slot.

* **`IntRet`/`FloatRet`**, at ~20 sites. RV32 returns in `a0`, and `x0` discards
  every write, so *every proc returned zero*. Fixing it took the corpus from 71
  to 104.
* **The `memcpy`/`memset` lowering**, which named `R0`–`R5` as literal slots.
  Those are `zero`, `ra`, `sp`, `gp`, `tp` and `t0` on RISC-V — two of them
  reserved for the whole program.
* **`IntArgRegs`/`FloatArgRegs`**, at 18 sites in `value.nim`/`frame.nim` — the
  manual argument-marshalling path a call takes when the declarative `(arg pN k)`
  signature cannot describe it (`isDeclarativeAbi` returns false for a float
  parameter or result). Integer calls never reached it, which is why 120 fixtures
  passed while `fp32_call`/`fp32_spill` did not: a float argument was staged into
  AArch64's `v0`, which is `ft0` on RV32 rather than `fa0`. It failed LOUDLY only
  because `emFReg` asserts that every float-temp-pool register carries a typed
  binding — the same check design.md argues for under "One spelling per job".

A fourth of these will look the same: grep `src/arkham/risc/` for a bare `R<n>`,
`F<n>`, or an unqualified name from `machine_a64`.

## What it did NOT find

A totality failure. The seven fixtures that used to sit here under "register
pressure — every scratch bridge in use" were a one-line machine-model defect:
`ProduceBridge` was spelled `R30`, which is also `IntBridgeRegs[1]`, so
`bridgeRegs` read `[R29, R30, R30]` and this target had TWO bridges where the
shared emitter is written against three. Every one of the seven asserted at the
same call site. `machinedesc.checkMachine` now rejects a duplicate at startup,
and `machine_rv32.ProduceBridge` carries the argument.
