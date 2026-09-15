# Arkham models

Three TLA+ models of the arkham backend. The first two exist in two dialects:
classic TLA+ for TLC (`.tla` + `.cfg`) and the NIF dialect for
[tlanif](../../tlanif) (`.nif`); both checkers must agree on the distinct-state
count, and `run_tlanif.sh` asserts it. `call_marshal` is TLC-only so far.

| model | what it abstracts | TLC | tlanif |
|---|---|---|---|
| `arkham_bindings` | the register-binding protocol: locals, bound temps, steals, raw staging, fixed-register clobbers, plan/emit replay | `run_arkham_bindings_tlc.sh` | `run_tlanif.sh` |
| `aggr_marshal` | by-value aggregate marshalling: the trailing partial word, four strategies, two storage kinds | `run_aggr_marshal_tlc.sh` | `run_tlanif.sh` |
| `call_marshal` | call-argument marshalling, both backends: phase 1 reduces arguments to moves (early or late, parks for exposure), phase 2 is one parallel move with stashes; integer and float, hidden pointer, pair / pointer homes, a park DEMAND that must be served | `run_call_marshal_tlc.sh` | — |

```bash
./proofs/run_arkham_bindings_tlc.sh   # ~9 s
./proofs/run_aggr_marshal_tlc.sh      # 8 configurations, expected verdicts asserted
./proofs/run_call_marshal_tlc.sh      # 14 rows: x64 + RISC + 8 injections + 4 probes, ~4 min
./proofs/run_tlanif.sh                # the first two models, ~5 s with --jobs (all cores)
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

## 3. `call_marshal` — call-argument marshalling: two phases and a parallel move

The call emitters of both backends (x86-64 `emitCallInner`, RISC `emitCall`)
in chibicc's shape (codegen.c `push_args` / `ND_FUNCALL`), with registers.
Phase 1 runs EVERY argument expression and reduces each register-passed word to a
**move**: a source that is no longer computed — a register, a memory place, an
address — and the ABI register it belongs in. Phase 2 performs the moves as ONE
**parallel move**.

Why it exists: the first revisions of this model followed the emitter's cases —
parks for a computed scalar, an early load "when no later argument clobbers it", a
phase 0 for an argument homed in another argument's register — and each revision
was the shape of the hole just found. The hole underneath was always the same: an
argument's SOURCE may sit in another argument's DESTINATION (a parameter still in
its incoming register, a pair home, a by-reference pointer), which is a parallel
move, and was being solved one case at a time. The emitters now solve it as one;
this model states the protocol, with a DEMAND (a park that must be served; the
`stuck` phase; deadlock checking on) as before.

### The protocol

- **A source must survive phase 1.** Memory does. A register does unless a later
  argument destroys it by ISA fiat (`idiv` writes rdx): such a source is copied
  into a **park** now (`redirect`). A computed value goes into a park, or straight
  into its own ABI register when the next rule allows it.
- **A move may go early** — during phase 1 — when no later argument destroys its
  register and no other argument READS it (`placeNow`). Early is an optimization;
  the model may always take the late branch instead (`Route`), and the corpus holds
  the emitters to the same with `ARKHAM_STRESS_MOVES=late`.
- **The resolver** takes any move whose destination no other remaining move reads.
  When none can go every remaining destination is read — a cycle — and one
  destination's readers are redirected to a **stash**, a copy in a register nothing
  live occupies, or memory.

The park tiers (`takeParked`; `pickTempReg(avoid = claims)` on RISC; `takeFTmp`
for a float), any of which the emitter may take:

| tier | code | what makes it sound |
|---|---|---|
| survivor | `pickHeldReg` | callee-saved; the planner reserves one for the emitter |
| pool | `pickTempReg(avoid)` | r10 and the argument registers themselves, nothing bound, nothing in `avoid` — the call's **claims** (its argument registers and the hidden result pointer) plus the later arguments' clobbers. The float pool holds no argument register on any target |
| memory | spill slot | read back through staging in phase 2 |

### What varies

Every call of 1..3 arguments, integer or float (an argument past its register file
is stack-passed: its expression still runs and clobbers), with or without a hidden
result pointer preloaded into the first argument register. Integer leaves and
computed scalars read a **home**: memory or a register — possibly ANOTHER argument's
ABI register — and two arguments may read the same local; a computed value may
clobber the fixed register. Float leaves and computed floats read a float home (a
computed float may still clobber an integer register). Aggregates of one or two
words live in memory, behind a computed address (whose base is a home), behind a
by-reference pointer homed in a register, or in a register pair. A home may sit in
a register a LATER argument destroys (the exposure `redirect` answers), never in
one an earlier argument already destroyed (the reactive eviction moves such a local
first). Values are identities; a register holds one value or garbage. The `risc`
row is the same spec with no fixed register.

### Invariants and bug injections

`SourcesIntact` (every remaining move's source still holds what it will deliver),
`LoadedIntact` (a loaded argument register keeps its word until the call),
`ArgsInPlace` (at the call every register-passed word is in its ABI register and
the hidden pointer is intact), `NotStuck`. The correct spec passes for x86-64
(16,465,724 states) and for RISC (5,026,508); each injection fails the invariant
it should:

| `Bug` | injected | fails |
|---|---|---|
| `survivorOnly` | a park is callee-saved or nothing — the old `takeHeld(canSpill = false)` | `NotStuck` |
| `noAvoid` | a pool park may sit in a register the call claims | `SourcesIntact` — an early move lands on it |
| `noBound` | a pool park ignores what a register holds | `SourcesIntact` |
| `noLaterClob` | an early move ignores later arguments' clobbers | `LoadedIntact` |
| `noReads` | an early move ignores other arguments' reads — the diverging-call clobber (`tests/arkham/noreturn_arg_clobber`, `noreturn_pair_arg_clobber`) | `SourcesIntact` |
| `noExposure` | a source a later argument destroys is not parked | `SourcesIntact` |
| `noOrder` | the resolver loads a move another remaining move still reads | `SourcesIntact` |
| `stashBound` | a stash ignores what a register holds | `SourcesIntact` |

Four probe rows assert that `NoStash`, `NoFloatStash`, `NoPoolPark` and `NoMemPark`
FAIL on the correct spec: cycles (integer and float), pool parks and memory parks
are all reached, so the invariants are not vacuous for them.

The stash rule surprised: an injection letting a stash alias a remaining move's
destination was expected to fail and passed, and the model was right — a stash
that avoids only what is live is sound, which is now the correct spec's rule. A
stash that lands on a pending destination is a source like any other, and the
resolver will not load that destination while the stash is still read. The x86-64
emitter seals those destinations anyway; that is a margin, not a rule.

Float conflicts are reachable in the model but not, today, in the corpus: a proc
that makes a call spills its float locals, so no float source sits in an argument
register at a call. The float half of the resolver is there for totality — and the
`NoFloatStash` probe is the only thing that exercises its cycle break.

Not modelled: byte layout (that is `aggr_marshal`), the inside of an argument's own
expression beyond which homes it reads, Darwin's variadic tail (laid out by the call
site after phase 2), and the value core's spill tier — a computed argument parked
at `ARKHAM_STRESS=2` on RV32 exhausts the two bridges inside its own expression
(`nested_at_read`), which is why the late-moves stress mode leaves computed
arguments in their own register. The procs carry `MODEL:` back-pointers.

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
  CFI step — a prologue/epilogue state machine with `(popframe)` tail calls;
- the 13 remaining `takeHeld` sites — `call_marshal` covers the park; each of
  those holds a value across something else (a call, an index expression that
  calls) and needs its own demand modelled the same way;
- the value core's spill tier under a starved pool: a computed call argument
  parked at `ARKHAM_STRESS=2` on RV32 runs out of bridges inside its own
  expression (`nested_at_read`) — a demand model for produce-into-memory;
- a tlanif port of `call_marshal`.
