# Arkham models

Two TLA+ models of the arkham backend, each in two dialects: classic TLA+ for TLC
(`.tla` + `.cfg`) and the NIF dialect for [tlanif](../../tlanif) (`.nif`). Both
checkers must agree on the distinct-state count; `run_tlanif.sh` asserts it.

| model | what it abstracts | TLC | tlanif |
|---|---|---|---|
| `arkham_bindings` | the register-binding protocol: locals, bound temps, steals, raw staging, fixed-register clobbers, plan/emit replay | `run_arkham_bindings_tlc.sh` | `run_tlanif.sh` |
| `aggr_marshal` | by-value aggregate marshalling: the trailing partial word, four strategies, two storage kinds | `run_aggr_marshal_tlc.sh` | `run_tlanif.sh` |

```bash
./proofs/run_arkham_bindings_tlc.sh   # ~9 s
./proofs/run_aggr_marshal_tlc.sh      # 8 configurations, expected verdicts asserted
./proofs/run_tlanif.sh                # both models, ~5 s with --jobs (all cores)
```

The TLC runners use `tlc` from `PATH`, `../yrc-proof/tlc`,
`../yrc-proof/tla/tla2tools.jar`, or `~/tla2tools.jar`, in that order. The tlanif
runner uses `tlanif` from `PATH` or `../../tlanif/bin/tlanif`.

---

## 1. `arkham_bindings` — the binding protocol

The model abstracts away instruction selection and treats codegen as a sequence
of register-ownership events. It deliberately models the parts of the allocator
where the real backend bugs lived, so the invariants have teeth (see the
bug-injection table below) rather than just restating a self-consistent protocol.

### What it models

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

### Checked invariants

- `LiveLocalsHaveHomes`, `RegisterBindingsMatchLoc`, `TempBindingsMatchBorrows` —
  the binding table stays consistent with the allocator view.
- `NoSharedRegister` — no two live values (local / bound temp / raw staging) share
  a physical register; a staging value sits only on a register nifasm thinks is
  free; distinct staging values occupy distinct registers.
- `ValueConsistency` — a finished local's value is exactly where the allocator says
  it lives. A steal that moved the local to a stack slot while its initializer still
  wrote into the (now stale) register home breaks this.
- `NotStuck` / `ReplayComplete` — the emit pass can always replay what the plan pass
  recorded, and reaching `done` consumed the whole log.

### It actually catches bugs

Injecting each backend bug class into the spec makes TLC produce a counterexample
(the correct spec passes):

| injected bug | invariant that fails |
|---|---|
| `steal` doesn't move the evicted victim to a stack slot | `LiveLocalsHaveHomes` |
| staging pick skips the free-register check (two raw scratch values collide) | `NoSharedRegister` |
| an init home is **not** sealed, so a steal evicts it mid-initializer (the genInto dest-steal miscompile) | `ValueConsistency` |
| `StartEmit` leaves part of the per-proc state un-reset | `RegisterBindingsMatchLoc` |

### Bounds

3 registers, 2 locals, 2 temps, 2 staging values, 1 fixed register, `MaxLog = 5`:
584,507 distinct states. TLC ~9 s; tlanif 3 m 20 s sequential, **5.6 s** with
`--jobs:8`. `MaxLog = 6` is ~5.3M states.

---

## 2. `aggr_marshal` — by-value aggregate marshalling

A ≤2-word aggregate travels in general-purpose registers, one per word. The model
is about the **trailing partial word** — the part of the object that does not fill
its last register — and what the code may touch while moving it. It is the code's
loop structure, one memory access per step, so an off-by-one in the width/offset
bookkeeping shows up, not just the final policy.

Why it exists: the "trailing partial eightbyte" loop was written five times in
the x86-64 backend. One copy (`transferAggrWords`) was fixed to move the partial
as a raw word — sound only because a *named slot* is padded to a word multiple.
The other four kept moving "the field at the word's offset", which carries exactly
one field: `{u32, u32, u8 mode, bool needsHeap}` (hexer's `CurrentEnv`, 12 bytes)
marshalled from an address arrived with `needsHeap` zeroed; lexim's `{enum, char}`
out of a `seq` lost the `char`. Commit `5e46eb9` (#170) replaced the four with an
exact-bytes strategy, as AArch64 already had.

### Strategies and storage kinds

| `Algo` | code | through an address | on a padded slot |
|---|---|---|---|
| `widest` | x64 `loadPartialThroughPtr` / `storePartialThroughPtr` (4, 2, 1) | pass, 1170 states | pass |
| `a64tail` | a64 `loadAggrTail` / `storeAggrTail` (borrow the last word, or 1/2/4, or bytes) | pass, 1268 | pass |
| `field` | the **old** field-at-offset code | **FAIL** | **FAIL** |
| `fullword` | `transferAggrWords` (the whole word) | **FAIL** | pass, 1144 |

`field` fails `RegsHoldObject` on the very first two-field partial, `{u8, u8}` —
the lexim `Alph` / test `Two` shape. `fullword` through an address fails
`NoOverRead` on a 1-byte object (reads `0..7`). The a64 strategy also passes with
`W = 4` (Cortex-M, 339 states).

### Layouts and invariants

Every naturally aligned object of 1..4 scalar fields from `{1, 2, 4, 8}` that fits
in two words, tail-padded like `typeSizeAlign`. Arrays are not enumerated: an
`(array (u 8) n)` behaves like `n` byte fields except under `field`, where
`fieldAtOffset` finds no field on an array layout — that is the `stuck` phase.

- `NoOverRead` / `NoOverWrite` — every access stays inside the object's storage
  (the object itself, or its word-padded slot when `Padded`).
- `RegsHoldObject` — after the load pass every object byte sits at its position in
  its word register.
- `RoundTrip` — after the store pass the destination holds the object byte for byte.
- `NotStuck` — the strategy could always make its next access.

The procs carry `MODEL:` back-pointers (`grep MODEL: src/arkham`). Change one
side, re-check the other.

### Why the bug slipped through validation (2026-09-10)

The census was run with a `-d:arkhamPartialDbg`-style hook in the four call sites,
over the 495-file `tests/arkham` corpus and 3,325 `.c.nif` files from every nimony
`nimcache*`:

- The **test corpus** hit the partial-from-address path in **zero** files before
  #170 added the cases. The old `aggr_partial_eightbyte` test had the right type
  (`Three`, three byte fields) only on the named-local path, and the address path
  (`gpacked`) only with a type whose partial is a single field — where the bug is
  invisible. Type shape and source path were each covered, never together.
- The **compiler corpus** contains the bug shape in exactly one module,
  `src/hexer/lambdalifting.nim` (six sites: `CurrentEnv` passed by value to
  `untypedEnv`/`typedEnv`). The old code loaded `mode` with a byte `mov`, which
  nifasm encodes as `movzx`, so a natively built hexer read `needsHeap` as
  **false**: escaping closure envs were cast to `pointer`/`ptr` instead of
  `(ref RootObj)`/`ref`. The compiler has few escaping closures, and the native
  `hastur boot` checks that stage 1 == stage 2 == stage 3 byte for byte — a
  consistently wrong hexer converges. `hastur tiers native` compiles the test
  programs with the **host-built** (C) compiler, so hexer ran correctly there.
  No gate runs programs compiled by a *natively built* compiler against a
  host-built reference.

---

## tlanif dialect notes (learned porting)

- Comments are `#text#` attached directly to a token (`(def#text# :X.0.`,
  `Locals.0.#text#`). A comment after `)` or on its own line swallows the file:
  "beginRead with unclosed tags".
- No operator parameters: a def reads let-bound free symbols, supplied at the call
  site with `(let (bind :e.0. …) Def.0.)`. No `CASE` (nest `if`), no `\div`/`%`
  (table lookups), no `[A -> B]`/`Seq(S)` type sets (check domains and elements).
- Strings are model values; `--sym` must not be used on these specs (`FixedRegs`,
  the sentinel and op groups are not symmetric).
- The port found a tlanif bug: the compiled (`--jobs`) `unchanged` captured the
  loop variable of its slot readers by a shared cell, so `(unchanged phase logIdx)`
  copied `phase` into `logIdx`. Fixed in `tlanif/src/compile.nim` (`slotReader`).

## Candidates for further models

Recent miscompiles whose fix was a *protocol* rule rather than an encoding detail:

- the peephole that trusted a jumped-over `(kill …)` — a deadness model over a
  tiny CFG with `kill` markers, invariant: a forwarded/deleted value is dead on
  every path (the two "deadness holes" of the copy-forwarding peephole belong here);
- the fixed-role interval proof that copy-inherit and `trySteal` skipped — extend
  `arkham_bindings` with a fixed-role register whose name may be stale;
- the frame-base setup that ended nifasm's prologue run before the frame `sub`'s
  CFI step — a prologue/epilogue state machine with `(popframe)` tail calls.
