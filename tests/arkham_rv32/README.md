# The RV32 codegen pass

There are no fixtures in this directory, on purpose. The RV32 back end is
exercised against **`tests/arkham_m/`** — the Cortex-M corpus — because the two
targets are the same shape (32-bit word, `BlockFrame`, bare metal, semihosting
exit) and a second copy of 138 fixtures would drift from the first rather than
test anything the first does not.

`tester.rv32CodegenTests` runs that corpus through
`arkham --os:embedded --cpu:riscv32` → `nifasm` → `qemu-system-riscv32`, checking
each fixture's exit code against its `.exitcode` file. The quarantine list lives
in `tester.nim` beside the pass.

## 122 of 138 pass

Every one of the 16 that do not is an explicit REFUSAL — a named diagnostic from
arkham or from nifasm. Nothing hangs and nothing computes a wrong answer, which
is the property worth protecting: a quarantine of refusals is a to-do list, and a
quarantine of wrong answers is a pile of unfound bugs.

**Cortex-M-specific by construction (11).** `err_asm_*`, `err_interrupt_*`,
`assembler_m`, `interrupt_pendsv`, `volatile_mmio`, `semihost_writec`. These pin
`{.register: "r4".}`, name Cortex-M interrupts, or assert a Cortex-M diagnostic.
They are not RV32 tests and never will be; the RV32 equivalents belong here as
their own files.

**Intrinsics (2).** `atomics`, `err_volatile_wide`. nimony's `IntrinsicTarget`
has no `tgRv32` member, so no row in the shared table can *claim* RV32 and
`{.instruction.}` / `{.intrinsic.}` are refused by name. That enum lives in the
nimony repo; adding a member is its change to make.

**64-bit constants (3).** `a64_logical_imm`, `bitand_imm64`, `overflow_check`. A
literal wider than 32 bits reaches the selector as a single `(mov reg <imm>)`
rather than split across the register pair the wide-integer lowering uses
elsewhere. nifasm refuses it by name, which is the right failure — the fix is
upstream of it, in the emitter.

## Two passes, not one

`rv32CodegenTests` runs the shipped `bin/arkham`. `rv32StressTests` re-runs the
same corpus at `ARKHAM_STRESS=1` against a `-d:arkhamStress` build, and that
second pass is the only one on this host that executes a binary with the **I1
bridge-budget assertions** compiled in (`emit.BridgeCheck` compiles them out of a
release build). Both are 122/122; the stress pass has no known-failures list.

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
