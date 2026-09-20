# The web back end — Leng → wasm32 and JavaScript

The web back end translates a Leng `.c.nif` main module into one
self-contained program for a web host: `jorogumo w` writes a `.wasm` binary,
`jorogumo j` a `.js` file. One tool, one back end. There is ONE code
generator, which lowers Leng to a typed tree, the *web IR*, and two
renderers that print that tree. Nothing target-specific is decided while
Leng is lowered, so a construct either works on both targets or on neither.
The one exception is the `importjs` bridge, which only a JavaScript host
can serve.

```
nimony front/middle end        backend
nifler → nimsem → hexer → dce ─┬→ arkham → nifasm → ELF/Mach-O/PE
        (.c.nif, Leng)         └→ src/web/codegen → web IR ─┬→ wasmrender → .wasm  (jorogumo w)
                                                            └→ jsrender   → .js    (jorogumo j)
```

It is whole-program. Starting from the entry proc (and every other
`exportc` proc of the main module, which are external entry points), it
pulls reachable declarations from every dependent module through arkham's
lazy foreign-module loader (`core/programs.nim`), and emits them into one
artifact. There is no C compiler, no linker and no external toolchain in the
loop. The driver side (`nimony w`, `nimony j`) lives in the nimony
repository.

## Layout

| file | role |
|---|---|
| `src/web/webnif.nim` | the web IR: the tag enum, the builder, `WebModule` |
| `src/web/codegen.nim` | Leng → web IR + `WebModule`; owns the static layout |
| `src/web/wasmrender.nim` | web IR → wasm32, through `wasmenc` |
| `src/web/wasmenc.nim` | the wasm binary encoder (LEB128, sections) |
| `src/web/jsrender.nim` | web IR → JavaScript text, with the JS host preamble |
| `src/jorogumo/jorogumo.nim` | the CLI: `w` is `generate(…, wtWasm)` + `renderWasm`, `j` is `generate(…, wtJs)` + `renderJs` |

The target's width facts come from arkham's `setTargetWord Wasm32`, set once
before anything is parsed. `Wasm32` narrows the pointer and Leng's platform
`int` to 4 bytes but leaves the scalar and float bounds at 8, because `i64`
and `f64` are value types on both targets (a JS `BigInt`, a double). Both
targets share one memory layout and one set of layout answers.

## The web IR

The web IR is a NIF tree over its own tag pool (`createWebTagPool`). It is
typed, so a renderer never guesses:

- every arithmetic, comparison, conversion and memory node carries a
  `WidthCode` (`i8 … u64`, `f32`, `f64`);
- a function is `(func NAME (params (param N W)*) RET (locals (param N W)*) STMT*)`,
  with every local hoisted to function scope and starting at zero;
- an indirect call is `(icall (sig RET W*) TARGET ARG*)`;
- a bare literal token is typed by its position, and a 64-bit integer
  literal is always `(bigint "digits")`.

Control flow is structured and forward-only apart from `while`: `label` +
`break NAME` are Leng's `lab`/`jmp`, and an unnamed `break` leaves the
innermost `while`. The machine-level operations are nodes of their own:
`hload`/`hstore`, `memcopy`, `memfill`, `memsize`, `memgrow`,
`frame`/`leave` (the shadow stack), `ctz`/`clz`/`popcnt` and `unreachable`.
wasm has an instruction for each. JavaScript has a preamble helper.

Next to the tree, `WebModule` holds what is not code. That is the host
imports, the scalar globals (`errv`, `ovf`), the static image as
`(address, bytes)` segments, the function table, the entry point and the
exports.

## Lowering model

- Target memory is 32-bit linear memory. Pointers are offsets into it.
- A scalar Leng local becomes a function local, unless its address is taken.
  An aggregate local, or one whose address is taken, lives in the function's
  shadow-stack frame (`(frame N)` on entry, `(leave)` on every exit). The
  frame layout, including a fixed slot for every temporary a call or a
  constructor needs, is planned before the body is lowered. Codegen consumes
  that plan in the same preorder, so the two cannot disagree silently.
- Aggregate parameters are passed as the address of a fresh copy. Aggregate
  results use a hidden first parameter, whose address the callee returns.
- Gvars sit at fixed linear-memory addresses. String literals and other
  constant aggregates become image segments with absolute-address fixups.
  The generator owns the final layout, so no relocations exist. Every segment
  must fit the allocation that owns it; an overrun is an error at emit time.
- Static function-pointer initializers resolve to function-table slots,
  through a proc/global discovery fixpoint. A capture-free proc stored in a
  closure slot gets a synthetic bridge (`lowerThunk`) with the closure's
  signature. C ABIs tolerate the unused env argument, but `call_indirect`
  checks the signature.
- `memcmp` has no machine form on either target, so it is a synthesized IR
  function (`memcmp_synth`).
- Narrow integers keep a canonical form, sign- or zero-extended per their
  width. The renderers re-canonicalize after arithmetic that can leave the
  range (JS: `<< 24 >> 24`; wasm: `extend8_s`/`and`). Checked arithmetic
  (`keepovf`) widens ≤32-bit operations to 64 bits for the overflow test.
- A float → integer conversion traps when the truncated value does not fit
  (wasm's `trunc`; the JS `ftoi` helper throws the same way). Integer
  division by zero traps on both.
- Exception landing pads nest their label/pad blocks in reverse close-event
  order, because a wasm `end` is positional.

## Host ABI

Both targets import the same two host functions, `nim_write` and `nim_exit`.
On wasm they are the `env` imports; in JS they are functions of the preamble.
Linux syscall names that arkham would lower natively map onto them where
meaningful (`write`, `exit`), and trap loudly otherwise.

- **wasm**: the module exports `_start`, `memory`, `table`, and every
  `exportc` proc of the entry module under its C name. `_start` runs `main`
  and hands its result to `nim_exit` as the exit code, the same as a native
  program. If the module has exports, `_start` is only the module init: it
  runs `main` and does not exit. In host-imports mode
  (`--host-imports`), a bodyless `importc` proc becomes an `env`
  import under its C name, so a host page can provide bridge functions
  (fetch, WebSocket, GPU calls) that the back end knows nothing about.
- **JavaScript**: one file for `node`, or for a browser with
  `--target:browser` (output goes to `console.log`, `nim_exit` throws, and
  the exports land on `globalThis.NIF` instead of `module.exports`). A
  bodyless `importjs` proc splices its template at the call site, and Nim
  strings, cstrings, JS object handles and callbacks are bridged across it.
  The wasm target refuses `importjs` by name.

## Intrinsics: `(instr …)` rows

An `(instr SYM args…)` application is typed exactly like a call. Both
targets are single-threaded:

- the portable bit rows (`ctz`/`clz`/`popcount`) map to the IR count nodes;
- the atomic rows lower to plain memory operations, and compound rows become
  a `seq` over temporaries that yields the correct old/new value;
- `CpuRelax` lowers to nothing;
- everything else (target-pinned rows, flags, two-address arithmetic) has no
  web equivalent and is refused by name rather than miscompiled.

## Debugging

- `jorogumo w --export-all` exports every function as `dbg$<name>`, so a host
  script can drive internals directly with crafted memory.
- The JS output is readable: every function of the IR is a `function` of
  the same name, which is the quickest way to see what the tree says.
- wasm modules disassemble with any standard tool (e.g. wabt's `wasm2wat`).

## Verification

`webTests` in `tests/tester.nim` pushes every `tests/arkham/*.c.nif` fixture
through BOTH targets. Each one must produce a module, apart from an explicit
refusal list, and with `node` on PATH each module RUNS and must match the
native oracle's recorded exit code and output. The two renderers print one
tree, and running both is what proves they print it the same way. It also
runs the unit tests of `src/web`:

- `twasmenc` covers the encoder;
- `tjsrender` has goldens for the JS renderer;
- `tcodegen` checks the static layout, read back by a JS engine.

The differential harness in nimony (`hastur wasmdiff`) covers realistic
programs. Each fixture is the same source pushed through the native backend
(the oracle) and through `nimony w`/`nimony j`, requiring byte-identical
stdout and matching exit codes.


## Non-goals

The back end performs no optimization of its own. The machine-independent
work (inlining, dead-code elimination, ARC optimization) belongs to hexer's
passes upstream of it. The machine-dependent work belongs to the engine's
JIT at load time.
