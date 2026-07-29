# Ithaqua — the Leng → wasm32 code generator

Ithaqua translates a Leng `.c.nif` main module into one self-contained
`.wasm` binary. It is whole-program: starting from the entry proc (and every
other `exportc` proc, which are external entry points and wasm exports),
reachable declarations from every dependent module are pulled in through the
embedded-index loader and emitted into the same wasm module. There is no C
compiler, no linker and no external wasm toolchain in the loop.

## Position in the toolchain

The native path splits code generation and assembly/linking across two
tools: arkham emits asm-NIF, nifasm assembles and links it. Ithaqua is
deliberately both in one, because a wasm module is a single self-contained
artifact — whole-program emission *is* the link step.

```
nimony front/middle end        backend
nifler → nimsem → hexer → dce ─┬→ arkham → nifasm → ELF/Mach-O/PE
        (.c.nif, Leng)         └→ ithaqua         → .wasm
```

Ithaqua reuses arkham's language-neutral program model — the lazy
foreign-module loader (`programs.nim`) and the `slots`/`typenav` layout
queries, with the target pointer/word size parameterized to 4 — plus
nimony's NIF reader libraries, in the same sibling-repo arrangement arkham
uses. The driver side (a `nimony w` command that runs the pipeline and
invokes ithaqua) lives in the nimony repository.

## Lowering model

- Target is wasm32 (`--cpu:wasm32 --os:standalone --bits:32`). A memory64
  arm can come later; Safari still lacks memory64, so 32-bit is the
  deployable target.
- Leng locals become wasm locals, unless address-taken or aggregate — those
  live on a shadow stack in linear memory, maintained through a mutable
  `sp` global. Aggregate parameters are passed as address-of-a-fresh-copy
  on the shadow stack (reclaimed after the call); aggregate results use a
  hidden first parameter (sret).
- Gvars sit at fixed linear-memory addresses (they must be addressable);
  `errv`/`ovf` are wasm globals. String literals and other constant
  aggregates become data segments with absolute-address fixups — ithaqua
  owns the final layout, so no relocations exist.
- `lab`/`jmp` lower to `block`+`br` (forward-only), loops and `ite`/`case`
  to structured control flow. Exception landing pads nest their label/pad
  blocks in reverse close-event order, because a wasm `end` is positional.
- Static function-pointer initializers resolve to funcref-table slots
  through a proc/global discovery fixpoint. Capture-free `{.closure.}`
  procs get synthetic bridge thunks: C ABIs tolerate the unused env
  argument, but `call_indirect` type-checks the signature.
- RootObj-derived environments carry their RTTI (vtable, method table,
  destroy info) as const data, so closures and method dispatch work.
- Checked arithmetic widens ≤32-bit operations to i64 where the overflow
  check needs it; narrow integers keep a canonical sign-/zero-extended
  i32 form.

## Host ABI

A produced module imports a fixed, tiny env set — `nim_write` and
`nim_exit` — and exports `_start` plus every `exportc` proc of the entry
module under its C name. In host-imports mode, bodyless `importc` procs
become env imports as well, so a host page can provide arbitrary bridge
functions (fetch, WebSocket, GPU calls) without ithaqua knowing anything
about them. Linux syscall names that arkham would lower natively map onto
the host import set where meaningful (`write`, `exit`) and trap loudly
otherwise.

## Intrinsics: `(instr …)` rows

An `(instr SYM args…)` application is typed exactly like a call, so the
operand walk and typenav queries are the call path's. On wasm32:

- The portable bit rows (`ctz`/`clz`/`popcount`) map to the native wasm
  opcodes, with the count converted from the operand's width to the
  declared return width.
- The atomic rows lower to plain memory operations — the target is
  single-threaded, so `fetch_add` and friends collapse to load/op/store
  sequences with the correct old/new-value result.
- Everything else — target-pinned rows, flags, two-address arithmetic —
  has no wasm equivalent (no flags, no register ties) and errors loudly
  rather than miscompiling.

## Debugging

- `ITHAQUA_DEBUG=1` dumps the function-index map and gvar addresses.
- `ITHAQUA_EXPORT_ALL=1` exports every proc as `dbg$<sym>`, so a host
  script can drive internals directly with crafted memory.
- A finalize-time static-layout invariant requires every data segment to
  fit its owning allocation, turning silent global-overwrite layout bugs
  into hard errors.
- Modules disassemble with any standard wasm tooling (e.g. wabt's
  `wasm2wat`); there is no custom container format.

## Verification

The differential harness lives in nimony (`hastur wasmdiff`): each fixture
is the same source pushed through the native backend (as the executable
oracle) and through `nimony w`, requiring byte-identical stdout and
matching exit codes. The harness has also caught pre-existing
native-backend bugs where the wasm output was correct — the oracle cuts
both ways.

## Non-goals

Ithaqua performs no optimization of its own. The machine-independent work
(inlining, dead-code elimination, ARC optimization) belongs to hexer's
passes upstream of it, and the machine-dependent work belongs to the wasm
engine's JIT at load time. This keeps the emitter small, fast and
deterministic.
