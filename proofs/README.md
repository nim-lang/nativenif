# Arkham Binding Protocol Model

A TLA+ model of the Arkham/nifasm register-binding protocol. Lightweight setup
like `../yrc-proof`: a `.tla` spec, a TLC `.cfg`, and a shell runner.

The model abstracts away instruction selection and treats codegen as a sequence
of register-ownership events. It deliberately models the parts of the allocator
where the real backend bugs lived, so the invariants have teeth (see the
bug-injection table below) rather than just restating a self-consistent protocol.

## What it models

Per-proc codegen events, each recorded in a single `log` by the plan pass and
replayed in order by the emit pass:

- **locals**: bind a live local to a register; kill it.
- **initialize-into-home**: *declare* a local with a register home, then *finish*
  its initializer — the write lands in the home captured at declaration. The home
  is **sealed** while the initializer runs.
- **bound scratch** (`rebind`/`kill`): borrow a temp into a register; release it.
- **steal**: when scratch is needed, evict a live register-local to a stack slot
  and reuse its register (the analogue of arkham's `stealReg`/`recordEviction`).
  Borrowing does **not** require a free register.
- **raw staging**: occupy a register with a live *unbound* scratch value — the
  staging-register fallback. These have no nifasm binding, so they are a separate
  occupancy notion from the binding table.
- **fixed-register clobber**: an idiv/byte-copy instruction that may implicitly
  overwrite a fixed register, evicting a live local first (and never a sealed one).

Two passes, with `plan` forced equal to `emit`:

- `plan`: choose applicable events and append each to `log`.
- `emit`: reset the whole per-proc state (the analogue of clearing
  `regLocal`/`boundTemps`/`freeTmp` and restoring the allocator snapshot), then
  replay `log` exactly. A recorded decision that cannot be replayed against the
  reset state sends the model to `stuck`.
- `done`: the log fully replayed and all transients were released.

## Checked invariants

- `LiveLocalsHaveHomes`, `RegisterBindingsMatchLoc`, `TempBindingsMatchBorrows` —
  the binding table stays consistent with the allocator view (the original
  property).
- `NoSharedRegister` — no two live values (local / bound temp / raw staging) share
  a physical register; a staging value sits only on a register nifasm thinks is
  free; distinct staging values occupy distinct registers.
- `ValueConsistency` — a finished local's value is exactly where the allocator says
  it lives. A steal that moved the local to a stack slot while its initializer still
  wrote into the (now stale) register home breaks this.
- `NotStuck` / `ReplayComplete` — the emit pass can always replay what the plan pass
  recorded, and reaching `done` consumed the whole log. (In the current model the
  structural invariants above already catch an incomplete per-proc reset first, so
  `NotStuck` is a backstop; it makes the replay-completeness intent explicit instead
  of leaving it to a disabled action, which is what the previous model did under
  `CHECK_DEADLOCK FALSE`.)

## It actually catches bugs

These invariants are not vacuous. Injecting each backend bug class into the spec
makes TLC produce a counterexample (the correct spec passes):

| injected bug | invariant that fails |
|---|---|
| `steal` doesn't move the evicted victim to a stack slot | `LiveLocalsHaveHomes` |
| staging pick skips the free-register check (two raw scratch values collide) | `NoSharedRegister` |
| an init home is **not** sealed, so a steal evicts it mid-initializer (the genInto dest-steal miscompile) | `ValueConsistency` |
| `StartEmit` leaves part of the per-proc state un-reset | `RegisterBindingsMatchLoc` |

The middle two correspond directly to the two miscompiles fixed in the AArch64
backend (`forceReg` handing out an unsealed staging register; `genInto` letting a
register-local home be stolen during its own initializer).

## Bounds

The TLC config uses 3 registers, 2 locals, 2 temps, 2 staging values, 1 fixed
register, and `MaxLog = 5` (~0.58M states, ~10 s). Raising `MaxLog` deepens the
explored interleavings (`MaxLog = 6` is ~5.3M states / ~70 s).

## Run

```bash
./proofs/run_arkham_bindings_tlc.sh
```

The runner uses `tlc` from `PATH`, `../yrc-proof/tlc`,
`../yrc-proof/tla/tla2tools.jar`, or `~/tla2tools.jar`, in that order.

Latest local run:

```text
Model checking completed. No error has been found.
584507 states generated, 584507 distinct states found, 0 states left on queue.
```
