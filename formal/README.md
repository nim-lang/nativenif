# Formal model of the fused-emitter register/temp protocol

`regproto.nif` is a TLA-style safety model (checked with
[tlanif](../../tlanif)) of the register/temp protocol that the fused
emitters in `src/arkham/codegen_x64.nim` / `codegen_a64.nim` implement.
The step-3 merge replaced the allocator's globally-planned expression walk
with per-site emit-time decisions; the price is that totality and
non-interference became *distributed* obligations. This model makes them
checkable again in one place.

Run (needs `tlanif` built: `nim c ~/projects/tlanif/src/tlanif.nim`):

    formal/check.sh

or individually:

    ~/projects/tlanif/src/tlanif formal/regproto.nif            # must pass
    ~/projects/tlanif/src/tlanif formal/regproto_bug_leafimm.nif # must fail

The main spec passes (~58k states, < 1 min). Each `regproto_bug_*.nif`
reinstates one of the five 2026-07-30 nimsem regressions and must produce a
counterexample — they pin the invariant set to the failure classes we have
actually shipped.

## What is modeled

A finite fleet of values (`v1..v4`), each walking
free → wants → reserved → bound → dead, over one held (callee-saved)
register, one pool temp, one bridge, and four spill slots. State per value:
`loc` (its location), `written` (was it actually materialized — the
produce-into obligation), plus the global `picked` set (the reserve→bind
gap guard), `callPending` and the `badRead` flag.

Action ↔ code mapping:

| action | code site |
|---|---|
| `Want` | a `takeTmp`/`takeHeld`/dest-resolution demand |
| `ResolveHeld/Pool/Bridge/Spill` | `pickHeldReg` → `pickTempReg` → `takeBridge` → `mintSpillName` fallback chain |
| `Materialize` | `bindTemp` + the actual store/mov; for slots, produce-into via staging/x16 |
| `Cancel` | tolerant `freeVal` on a reserved temp (`freeLvalTemps2`) |
| `Consume` | the use site reading the value |
| `RequestCall`/`CallExec` | call emission clobbering caller-saved regs (pool + bridges) |
| `ParkToHeld`/`ParkToSlot` | marshaller survivor parking / `pendingSpillArgs` |

## Invariants ↔ regressions

| invariant | meaning | historical bug it catches |
|---|---|---|
| `Excl` | no two live values share a location | (baseline sanity) |
| `PickAccounted` | `picked` = regs backing reserved values, exactly | aggrAddrInto double-walk pick leak (`regproto_bug_pickleak`) |
| `not badRead` | no value is consumed unmaterialized | emitLeafImm silent miscompile (`regproto_bug_leafimm`) |
| `DemandTotal` | the resolution chain always has an enabled arm | a64 aggregate-arg `takeHeld` exhaustion (`regproto_bug_nospill`) |
| `ParkTotal` | pending calls can always park exposed values | x64 clobber-exposed arg exhaustion (`regproto_bug_noparkslot`) |

Note the checker has no deadlock detection, so totality is expressed as a
state invariant ("an arm is enabled"), matching the code's behavior: a
missing arm there is a `quit`/assert (or, for produce-into, silence). When
you add or remove an arm in the code, mirror it in the spec **and** in the
corresponding `*Total` invariant — the invariant must list exactly the arms
the implementation has.

## Abstractions (what a pass does NOT prove)

- One unified demand chain held→pool→bridge→slot; the code uses different
  arm *orders* per site (plain `takeTmp` prefers the pool). Order affects
  codegen quality, not the safety properties checked here.
- Slots are bounded (4) but values are too (4), so the minted-spill arm is
  total as in reality (`mintSpillName` cannot fail).
- Type-level obligations are out of scope: the emitCast2 Undef-dest bug and
  the emitScalarCmpE ptr-slot bug would not appear in this model.
- Arg-register assignment, laterClob analysis and the pendingArgBinds flush
  order are not modeled; parking is collapsed to "move to held or slot".

NIF gotcha: standalone `#...#` comments are not valid in this dialect
(comments may only ride a `@line-info` annotation), so the spec files are
comment-free.

## TLC cross-validation

`regproto.tla` is a hand-kept TLA+ mirror of `regproto.nif` for checking
with TLC (`tla2tools.jar`, needs a JRE):

    java -XX:+UseParallelGC -jar tla2tools.jar -workers 16 -deadlock \
         -checkpoint 0 -config regproto.cfg regproto.tla

(`-deadlock` *disables* TLC's deadlock check — the model has terminal
all-dead states, and tlanif does not check deadlock either.)

TLC independently confirms the tlanif result: 58,174 distinct states with
`regproto.cfg`, invariant holds. `regproto_stress.cfg` (6 values, 2 pool
regs, 6 slots) is the full pressure model: 67,363,106 distinct states,
invariant holds over the complete space (TLC, 16 workers, ~2 min). If you
edit one spec, edit the other; a diverging state count is the alarm bell.
Note TLC dedups on 64-bit fingerprints (it reports a tiny probability of
missed states per run); tlanif's dedup is exact.
