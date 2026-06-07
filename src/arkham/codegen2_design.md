# arkham value-core rewrite — "allocate everything, emit purely"

## Why

The current x64 (and a64) value core makes register decisions **reactively during
emission** (`borrowTmp`/`stealReg`/`recordEviction`/`spillComputed`), and a
two-pass *plan/replay* seam (`ab.planning`, `borrowLog`, `stealEvents`,
`fixedEvicts`) exists only to make those reactive decisions reproducible
byte-for-byte across the suppressed (plan) and real (emit) walks.

That seam rests on one invariant: **walk order == execution order == dominance.**
An eviction is modeled as a *single, permanent demotion* of a symbol's location
(`ra.locs` has exactly one slot per symbol). For straight-line code the demotion
point dominates every later read, so a permanent mutation is correct.

**A branch breaks the invariant.** A reactive eviction inside one arm mutates
`ra.locs[c]` globally; the sibling arm and the merge then read `c` from a slot
that was never written on their path. This is exactly the `rawAlloc` SIGSEGV:
`c` (a `ptr SmallChunk`, planned into callee-saved `r14`) is stolen for scratch
in the `if c==nil` arm around the atomic `xchg`/`compensateCounters`/`listAdd`
calls; the `else` (freelist-reuse) arm reads `c` from `[rsp+0x40]`, garbage.
Repro: two long-string concats of the same size class in one proc — first works,
second crashes (`tests/nimony/strings/tconcat_chain.nim`, and minimal
`a&b&c` twice with a ≥15-byte result).

Sealing the live locals during a branch is **unsound**: `evictFixedReg`
(idiv→RDX, byteCopyConst→RCX) *must* evict when the ISA forces a clobber, so
in-branch evictions cannot simply be forbidden. Per-branch reconcile-reload
works but piles more machinery on the hack. The principled fix is to retire the
hack.

## Target design (Andreas)

The register allocator assigns a Location not just to variables but to **every
value-producing expression position**. To do that for `binOp`/`call`/etc. it
needs instruction selection; that enters as an **arch-neutral callback** so the
allocator core stays target-independent. The callback does the
`dest: var Location` destination-passing we keep circling. After allocation,
**every position has an immutable, precomputed target**, and the code generator
becomes a *pure emitter*: read `locs[posOf(c)]`, emit bytes. No emit-time
borrow/steal/spill ⇒ **the plan/replay seam disappears entirely**, and with it
`borrowLog`/`borrowLogF`/`stealEvents`/`fixedEvicts`/`spillCount`-at-emit.

### Why it kills the bug by construction

The allocator runs once with full liveness + CFG. `c` gets one Location for its
whole live range. In `r14` (callee-saved) it survives the calls — so there is no
reason to evict it; the reactive steal that demotes it on one path simply does
not exist (scratch comes from allocator-reserved temps). If the allocator ever
genuinely *must* spill `c`, it assigns `c` a stack Location (or a split with
explicit reloads it emits) uniformly across all paths, and the emitter
reproduces it identically on every edge. Same reasoning retires the
idiv-in-a-branch hazard.

## Data model

`RegAlloc.locs: seq[Location]` (already `cursorToPosition`-indexed, sized
`buf.len`) is extended to be filled for **all** value positions, not just
`SymbolDef`s. Selection decisions the emitter must replay that don't fit in the
result Location go in a parallel per-position aux table:

```nim
type
  ExprAux* = object
    scratch*: seq[Reg]     # extra GPRs the op reserved (e.g. idiv's RDX, a stride temp)
    fscratch*: seq[FReg]   # extra SIMD scratch
    swapped*: bool         # operands evaluated in swapped (Sethi–Ullman) order
    foldB*: bool           # operand B stays a folded memory operand (no load)
    # grows as forms are migrated; one record per op position that needs it
  RegAlloc:
    ...
    aux*: Table[int, ExprAux]   # pos -> selection aux (sparse; only ops that need it)
```

`locs[pos]` for an expression = its **result** location (InReg / InFReg / Imm /
Mem(folded) / NamedStack(spilled) / Glob / Tvar). Leaves: a literal → `Imm`, a
resident local/global → its storage Location, a foldable lvalue → `Mem`.

## Liveness used by the walk

* **Named locals/params**: already placed by the existing decl walk
  (`allocStorage`/`allocParams`/`trySteal`), keyed in `symPos`, freed by
  `flushFree`/`closeScope` at `freeAfter` granularity. Unchanged.
* **Expression temporaries**: single-use by construction (a computed sub-result
  feeds exactly one parent), so their register frees the moment the parent op
  consumes it — classic tree/stack discipline. The walk hands out a temp from
  the pool, recursing operands, and reclaims after the op. No analyser change.

## The arch-neutral selector callback

Stored as proc fields on `MachineDesc` (or a sibling `SelectorDesc`), invoked by
the allocator *after* operand Locations are assigned. Each receives a `var SelCtx`
exposing the allocator's pool + liveness, and refines `dest`:

```nim
type
  SelCtx* = object              # the allocator hands the selector a controlled view
    # reserve()/reserveFixed(r)/free(r)/spillVictim()/isPoolEmpty()/...
  Selector* = object
    selectBin*:   proc(op: NifcBinOp; lhs, rhs: Location; dest: var Location; cx: var SelCtx)
    selectCall*:  proc(sig: CallSig; args: openArray[Location]; dest: var Location; cx: var SelCtx)
    selectAddr*:  proc(...)
    selectDeref*: proc(...)
    # ... one per value-producing form that has arch constraints
```

The x64 selector encodes: 2-operand RMW (`dest := dest op src`, reuse `lhs`'s reg
iff `lhs` is dead here, else fresh+mov); fixed-reg ops (idiv pins RAX/RDX, var
shift pins RCX → `reserveFixed` + evict consistently); memory-operand folding
(an operand may stay `Mem`, recorded via `foldB`); call ABI (args→arg regs,
result→rax/xmm0, caller-saved clobbered ⇒ cross-call values are callee-saved or
spilled — liveness already drives this). Folding is kept **from day one** (per
the brief): the selector decides load-vs-fold and the emitter honours it.

## Migration (contained rewrite, on branch `araq-bufixes`)

Build the new path **gated** (e.g. arch tag `x64n`) so the suite stays green
while it grows; flip to default and delete the old reactive value core +
plan/replay seam once it passes 89/89 x64 + 89/89 qemu + tsso + the
arc/string corpus (esp. the two-3-chain concat crash).

1. `RegAlloc`: add `aux` + fill `locs` for all positions (this file's data model).
2. Selector callback types + a no-op default; x64 selector skeleton.
3. Allocator **expression walk**: operands→liveness→folding→fixed regs→call
   ABI→spill, writing `locs`/`aux`. Reuse `allocStorage`/`trySteal` for symbols.
4. New x64 **emitter**: pure consumer of `locs`/`aux`, reusing the asmbuf tree
   builders + type/aggregate/float/call **emission** primitives (those don't make
   decisions). No `borrowTmp`/`stealReg`/`spill` at emit time.
5. Validate, flip default, delete: `borrowLog*`, `stealEvents`, `fixedEvicts`,
   `recordEviction`/`replayEviction`/`stealReg`/`evictFixedReg`/`spillComputed`,
   `ab.planning`, and the genProc two-pass.

Emit primitives that are pure and reusable as-is: `asmbuf` tree builders,
`genTypeBody`, signature/frame emission, the `fmov*`/`fcvt*` float ops, the call
ABI byte-emission. What gets rewritten is the **decision** half of
`genVal`/`gen`/`genInto`/`genBin`/`genCall`/`genAddr`/`asLoc`.

a64 mirrors x64 after x64 is proven (same `MachineDesc`/selector seam; a64 has
no 2-operand RMW constraint, fewer fixed-reg ops — generally simpler).
