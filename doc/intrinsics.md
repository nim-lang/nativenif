# Modelling intrinsics

*Proposal — replaces the `importc`-sniffing + `(call …)` encoding currently used
for `__builtin_*`, `__atomic_*` and `mem*`.*

## 0. Two use cases, one mechanism

Two things must be built on the intrinsic design, and they pull in different
directions — which is exactly why getting the middle right matters.

**(a) C/C++-style intrinsics in ordinary code.** Write `bsf(x)` or a SIMD
intrinsic in a perfectly normal proc, and get *that instruction*, while register
allocation, spilling, ABI and temporaries stay arkham's job. The user overrides
**instruction selection** and nothing else.

**(b) `.assembler` procs.** Every construct maps one-to-one to assembler, no
heuristics: locations are explicit (`.register`, `.stack`), control flow is
`while true` / `if cond` / named blocks + `break`, and any expression that would
need a materialisation slot is rejected.

These are **independent axes**, not two points on a scale:

|                     | portable intrinsic (fallback exists) | target-pinned instruction |
|---------------------|--------------------------------------|---------------------------|
| **normal proc**     | `ctz(x)` — any target                | **(a)** `bsf(x)` — arkham allocates |
| **`.assembler` proc**     | only if it expands without temporaries | **(b)** transliteration |

The same declaration, the same call-site node, and the same operand table serve
all four cells. The only thing that changes between cells is how the operand
constraints are *read*: in a normal proc they are **requests** the allocator
satisfies (by copying, loading, spilling); in an `.assembler` proc they are
**assertions** the checker verifies.

So the design question is: **what must an intrinsic declaration say, such that
arkham can either satisfy or verify it with no guesswork?** The current
`importc`-string design says none of it.

Two facts from the existing code shape the answer:

- **nifasm is already the machine model.** Registers are tags (`(rax)`, `(rcx)`,
  `doc/instructions.md:262`), CPU flags are tags (`(zf)`, `(cf)`, `:367-376`),
  a variable's location is a slot in `(var D L T)` (`(rax)` or `(s)`),
  if-then-else branches on a hardware flag or a single-use control-flow variable
  (`(ite …)`, `assembler.nim:2159`), and `(loop (stmts …))` is the bare infinite
  loop. arkham already emits `LoopX64` (`codegen_x64.nim:335`) and consumes
  `break`/`lab`/`jmp`/`if` (`codegen_x64.nim:4864, 5023, 5028, 4895`).
- **nifasm is also the backstop.** It is a *typed* assembler whose stated job is
  catching codegen bugs. So an operand-table row that is wrong or too loose
  produces a nifasm type error at build time, not bad machine code. The table
  can start coarse and be refined without risking correctness.

## 1. What is wrong today

An intrinsic is declared as an ordinary external proc and used as an ordinary
call:

```
(proc :ctz64.0.bitops (params (param :x.0 . (u 64))) (i 32)
      (pragmas (importc "__builtin_ctzll")) .)
...
(call ctz64.0.bitops v.0)
```

Nothing in either tree says "this is an instruction". The information is
recovered by *string-matching the C name*, and that costs us:

1. **Classification by hardcoded name lists.** `programs.nim:427-476` tests
   `importcN` against four ad-hoc tables (`__atomic_*` prefix, `mem*` set,
   `__builtin_*` set, the syscall table). The same cascade is duplicated for
   cross-module references in `foreignCallTarget` (`programs.nim:596-624`).

2. **`CallTarget` is an unfolded variant.** Four mutually exclusive string
   fields — `atomic`, `memIntrin`, `bitBuiltin`, `asmName`+`syscall`
   (`programs.nim:37-41`) — and every consumer re-tests `.len > 0`
   (`codegen_x64.nim:2361-2374`, `codegen_a64.nim:2430-2441`).

3. **The `call` shape lies about cost, so the allocator is told the truth out of
   band.** `allocCall` places arguments in ABI registers, the result in `rax`,
   and marks a call point. So the analyser takes an extra `atomicCalls` set of
   *names* (`codegen_x64.nim:5179`, built at `:5376`); the a64 emitter
   re-derives the same fact during emission (`callIsInlinedAtomic`,
   `codegen_a64.nim:2649`); and `emitBitBuiltin2` (`codegen_x64.nim:2223`)
   emits `bsf rax, rdi` plus `mov home, rax` — two wasted moves around a single
   instruction. **This is use case (a) done badly**: the instruction is right,
   the allocation is forced into a call ABI it never needed.

4. **Gaps are runtime failures, not typed alternatives.** a64 has no bit-builtin
   lowering: `raiseAssert "bit builtin not yet implemented"`
   (`codegen_a64.nim:2441`).

5. **The name is ambiguous by construction.** `memcpy` is both "inline as
   `rep movsb`" and "a real libc symbol to call on Darwin". Resolved today by a
   `darwin` flag inside the classifier.

6. **Every other consumer is blind.** To `nj` a `(call …)` is an opaque
   effectful node — no CSE, no folding, no DCE. `ghast` (SPIR-V) cannot map a C
   name to `OpBitCount`; it skips the attributes (`ghast/translate.nim:107`).

7. **It cannot describe an instruction at all** — no operand roles, no pins, no
   flag effects, no immediate widths, no multi-result forms — so neither (a) nor
   (b) is buildable on it. The intrinsic set can only ever be a fixed list the
   compiler knows.

The one thing that *does* work is type checking: an intrinsic is a proc, so
overload resolution, `sigmatch` and `getType` need no special cases. **That
property must be kept.**

## 2. Design principles

- **The declaration is the typing contract.** Anything a proc signature already
  expresses stays in the signature. No new type rules per intrinsic in any
  checker.
- **The call site is the cost contract.** Whether something is an ABI call must
  be answerable *syntactically*, without resolving a symbol into another module.
- **One table holds what a signature cannot express**: operand roles, location
  classes, pins, ties, flag effects, clobbers, purity. Checked once at the
  declaration.
- **The table dictates the spelling.** There is exactly one legal way to declare
  a given instruction (§4.1). No author choice, no reconciliation.
- **Constraints are requests in a normal proc, assertions in an `.assembler` proc.**
- **The opcode is the user's; the operands are arkham's.** An `(instr …)` node
  fixes *which* instruction. Where its operands live stays allocation's job.
- **Prefer rejecting to analysing, in v1.** Where a correctness question needs
  dataflow (flags, §6), reject the shape that would need the analysis instead of
  performing it. Rejection is conservative and forward-compatible; a later
  version can relax it without changing the surface syntax.
- **Do not invent a second machine model.** `doc/instructions.md` is already the
  target table; it gains columns. nifasm remains the verifier.

## 3. Portable vs target-pinned

| | Target-pinned | Portable |
|---|---|---|
| Pragma | `{.instruction: bsf.}` | `{.intrinsic: Memcpy.}` |
| Names | a nifasm instruction tag | a target-neutral opcode |
| Expands to | exactly one instruction | any number |
| Table | `doc/instructions.md` (+ new columns) | `doc/abstract-instructions.md` |
| Availability | the existing `X64Inst`/`A64Inst` column | per-target lowering |
| Wrong target | compile error | fallback body |

The consequence of making target-pinned intrinsics work in **normal** procs
(use case (a)) is that the portable layer stops being compiler surface. It
becomes the ordinary C pattern — a normal `inline` proc with a `when`:

```nim
proc ctz(x: uint64): int32 {.inline.} =
  when defined(x64):   bsf(x)
  elif defined(arm64): clz(rbit(x))
  else:                <portable loop>
```

No `.assembler`, no compiler table entry, no backend `case`. That deletes
`emitBitBuiltin2` from both backends and turns `codegen_a64.nim:2441`'s
`raiseAssert` into a `when` branch. **Adding an intrinsic becomes a library
edit.**

Only intrinsics that genuinely need allocator cooperation stay compiler-side:
`memcpy`/`memset` (scratch-register clobbers plus a size-dependent expansion)
and the atomics (a constant ordering operand plus a barrier effect).

## 4. The three pieces

### 4.1 The declaration — one spelling, derived from the row

The operand roles determine the signature. There is no choice:

| Row | Spelling | Example |
|---|---|---|
| one pure `out`, rest `in` | result | `d = bsf(x)` |
| first operand `inout` | `var` first param | `add(d, s)` |
| ≥2 pure `out` | tuple result, destructured at the call site | `let (q, r) = divmod(a, b)` |

```nim
proc bsf(src: uint64): uint64 {.instruction: bsf.}                # (bsf D S), D out
proc add(dst: var uint64; src: uint64) {.instruction: add.}       # (add D S), D inout
proc add3(a, b: uint64): uint64 {.instruction: add3.}             # a64 (add3 D A B)
proc divmod(a, b: uint64): (uint64, uint64) {.instruction: div.}  # rax=quot, rdx=rem
```

`sempragmas` derives the required form from the row and errors if the
declaration does not match — the same declaration-site check as the shape
unification in §4.4. This is deliberately rigid: the x64 `add` being two-address
and the a64 `add3` being three-address is a fact about the machine, and for a
*target-pinned* intrinsic the source should show it rather than hide it behind
a uniform spelling that implies a free `mov`.

NIF:

```
(proc :bsf.0.x64 (params (param :src.0 . (u 64))) (u 64)
      (pragmas (instruction bsf)) .)
```

- New tags `(instruction IDENT)` and `(intrinsic IDENT)`, registered for
  `LengPragma` and `NimonyPragma`, **appended** to `nimony/doc/tags.md` (ids are
  positional in `tools/gen_tags.nim`, so new tags must never be inserted).
- The argument is an **ident from a generated enum**, like `magic` — not a free
  string. A typo is a front-end error, not an "unsupported intrinsic" assert
  three passes later.
- Body slot: `.` (none) or a fallback body (portable tier only).
- `importc` may be given *in addition*, meaning "a real C symbol of this name
  also exists" — this is how `memcpy` becomes inline on static ELF and a call on
  Darwin, declaratively, instead of via a `darwin` branch in the classifier.

*(Footnote on `bsf`: x86 leaves the destination unmodified when the source is
zero, so it is strictly `inout`. The row declares it `out` with "src = 0 is
undefined", matching `__builtin_ctz`. That is a per-row judgement the table
records once, instead of every caller rediscovering it.)*

### 4.2 Tuples are surface syntax only

A multi-output instruction is spelled with a tuple result, but **no tuple ever
exists in the IR** — that would mean an aggregate, i.e. exactly the
materialisation we are avoiding. Sem destructures at the call site and the outs
become leading operands:

```nim
let (q, r) = divmod(a, b)
```
```
(instr divmod.0.x64 q.0 r.0 a.0 b.0)      # outs first; the row says there are 2
```

One sem rule: an intrinsic with ≥2 outs **must** be destructured immediately —
it cannot be assigned to a tuple variable, returned, or passed on. So "tuple
support" costs a destructuring rule in sem and an operand count in the table.
Nothing in Leng, nothing in the allocator, nothing in nifasm.

The single-pure-out case keeps the expression form (`d = bsf(x) + 1` works in a
normal proc), which is just the special case *k* = 1.

This is what unlocks instructions the current design cannot express at all:
`div`/`idiv` (quotient in `rax`, remainder in `rdx`, both pinned), `mul` (the
128-bit product across `rdx:rax`), and every add-with-carry / multiply-with-
overflow form (§6).

### 4.3 `(instr SYM X*)` — the call site

```
| `(instr SYM X*)` | LengExpr, LengStmt | intrinsic/instruction application |
```

Typed **exactly** like `(call SYM X*)` — same code path, `SYM`'s params and
return type drive everything — but a distinct tag, so:

- the allocator sees "not an ABI call" from the tag alone, with no symbol
  resolution and no cross-module load;
- `nj` can treat it as a CSE/fold candidate without whole-program effect
  analysis;
- a verifier gets one new rule: *`SYM` must carry `(instruction …)` or
  `(intrinsic …)`, and the arguments must match `SYM`'s parameters plus the
  row's leading out operands*;
- it is **selection-final**: no pass may substitute a different opcode. Passes
  may still choose operand placement, fold a load into a memory operand, or DCE
  it when it is `pure` and its result is dead.

Registered as both `LengExpr` and `LengStmt`, mirroring `call`.

Keeping `SYM` rather than emitting `(bsf d s)` directly is what makes typing
free, keeps fallback bodies reachable, and keeps the tag space constant — an
instruction set is hundreds of entries and target-specific; it cannot be a tag
space (see §9).

### 4.4 The operand model

| Field | Values | Purpose |
|---|---|---|
| `role` | `in`, `out`, `inout` | determines the spelling (§4.1) and the out count (§4.2) |
| `loc` | `reg`, `mem`, `rm`, `imm8`, `imm32`, `label`, `sym` | what nifasm will accept in that slot |
| `pin` | a physical register, per target | `rcx` for variable shifts, `rax`/`rdx` for `div` |
| `tie` | operand index | two-address forms: `dst` occupies operand *N*'s location |
| `defs` / `uses` / `kills` | flag sets | `defs {zf,sf,cf,of}` for `sub`; `uses {cf}` for `adc` |
| `clobbers` | register set | `rcx,rsi,rdi` for `rep movsb` |
| `effects` | `pure`, `reads N`, `writes N`, `rmw N`, `barrier`, `traps` | CSE/fold/DCE eligibility and memory ordering |
| `const` | operand indices | must be compile-time constants (atomic ordering) |

`loc` describes what *nifasm* accepts, not an encoding: nifasm already selects
the encoding from the operand kinds (arkham emits the same `(add D S)` tag with
a register or an immediate today — `binReg`/`binImm`). So the column can be
coarse, and a mistake in it surfaces as a nifasm type error rather than as wrong
code.

Target-pinned rows live in `doc/instructions.md`, which already carries the tag,
the operand arity (`(bsf D S)`) and target availability (`X64Inst, A64Inst`); it
gains the columns above. Portable rows live in a parallel table whose extra
column is the per-target lowering (a nifasm instruction sequence, or empty =
"use the fallback body").

### 4.5 Signature shapes — the declarative type rules

Portable rows also carry a **shape**, matched against the proc signature *once,
at the declaration*:

| Opcode | Shape | Effects | Const | Fold |
|---|---|---|---|---|
| `Ctz` | `(u W) -> (i 32)`, `W in {32,64}` | pure | – | yes |
| `Bswap` | `(u W) -> (u W)`, `W in {16,32,64}` | pure | – | yes |
| `Memcpy` | `(ptr T) (ptr U) (u 64) -> (ptr T)` | writes 0, reads 1 | – | no |
| `AtomicFetchAdd` | `(ptr T) T (i 32) -> T` | rmw 0, barrier | 2 | no |
| `AtomicCas` | `(ptr T) (ptr T) T (i 32) (i 32) -> bool` | rmw 0, rmw 1, barrier | 3,4 | no |

Shape is a small pattern language over Leng types: literals `(i W)`, `(u W)`,
`(f W)`, `(c W)`, `bool`, `void`, `(ptr T)`, `(aptr T)`; variables `T`, `U` (any
type) and `W` (bit width, optionally constrained). Matching is plain
unification. (A vector form will be needed for SIMD; it extends the same
grammar.)

> When `sempragmas` sees `{.intrinsic: Ctz.}`, it unifies the proc's `(params …)`
> and return type against row `Ctz`. Mismatch → error at the declaration.
> Success → nothing downstream ever needs the shape again.

Target-pinned rows need no shape column — the operand model *is* the shape.

## 5. Intrinsics in a normal proc — use case (a)

`allocInstr` reads the row and turns each field into an allocation request:

| Row field | What the allocator does |
|---|---|
| `loc = reg` | ensure the operand is in a register — load a stack home if needed |
| `loc = rm` | free choice; prefer folding a memory home into the operand |
| `loc = imm*` | a literal in range stays immediate; otherwise materialise into a register (if a `reg` alternative exists) or error |
| `role = out` | allocate the destination *as the value's home* — no `rax` round-trip |
| `tie = N` | insert the copy the two-address form needs — the *same* service the existing accumulator model uses for built-in operators, not bespoke code |
| `pin = rcx` | a one-register mini-ABI: move the value in, evict what was there |
| `clobbers` | mark those registers dead across the node — what `atomicCallNames` approximates today |
| `effects` | `pure` ⇒ CSE/fold/DCE eligible; `barrier` ⇒ no memory reordering across it |

Two properties fall out that the current design cannot offer:

- **No ABI cost.** `d = bsf(x)` with `x` in `r12` and `d` homed in `r13` emits
  `bsf r13, r12` — one instruction. Compare §1.3.
- **Spilling still works.** The user constrained *selection*, not allocation, so
  nothing about register pressure changes.

An intrinsic used on a target that lacks it is a **compile error at the call
site** naming the target — same as C. Portability is opt-in via the portable
tier or a `when`, never silent.

`.register`/`.stack` on a local are legal in a normal proc too, as a hard pin
the allocator honours (it drops that register from the pool). That is the
"influence" dial short of full `.assembler`.

## 6. Flags are intrinsics, not variables

There is no `.flag` pragma and no flag-typed variable. A flag is reached in
exactly two ways, both of them ordinary intrinsics:

**Read the last instruction's flag** — an intrinsic with `uses {zf}` and a
`bool` result:

```nim
proc zf(): bool {.instruction: zf.}     # uses {zf}
...
test(n, n)
if zf(): break outer
```

**Write a flag** — the instruction that writes it, e.g. `stc()`, `clc()`,
`cmc()` (`defs {cf}`). There is no flag *variable* to assign, so `eq = false`
never arises and no `setzf`-shaped special case is needed. (x86 in fact has
direct set/clear/complement only for CF; the table records that rather than
leaving callers to guess.)

**Better where it fits: bind the flag at the instruction site**, using the
tuple form of §4.2, so it is not positional:

```nim
let (sum, carry) = addCarry(a, b)      # (add D S) with defs {cf}, cf as out 1
if carry: ...
```

The two are complementary: `zf()` is the general escape hatch (pick any flag of
whatever ran last, unchecked); the tuple form binds the flag at its definition
and is preferred whenever the row makes it natural.

### Why this needs no new machinery

**arkham already implements exactly this pattern**, for `(ovf)`
(`codegen_x64.nim:2957-2963`): the flag read is valid *only* as an if/ite
condition, is lowered to `jo`/`jb` in `emitCond2`, and is **rejected loudly in
value position** — with precisely the right justification recorded in the
source: materialising it would mean a flag-clobbering instruction ran between
the definition and the read. Leng even has the ad-hoc statement form of "keep
the previous op's flag", `keepovf`.

So the v1 rule is not a new invention, it is `OvfC`'s rule generalised:

> A flag-valued result is legal only where it can be consumed **without
> materialisation** — as an `if`/`while` condition, or by an instruction that
> `uses` that flag. Anywhere else is an error.

One line, no dataflow analysis, and conservative: it rejects rather than
silently miscompiles. The `defs`/`kills` columns exist, so v2 can relax this to
"materialise with `setcc` when the table proves nothing clobbered the flag in
between" — without changing any surface syntax. Precise flag-lifetime checking
is explicitly **out of scope for v1**.

A pleasant side effect: `keepovf` + `(ovf)` becomes a special case of the
general mechanism rather than its own pair of tags.

## 7. Worked example

**Before**

```
(proc :ctz64.0.bitops (params (param :x.0 . (u 64))) (i 32)
      (pragmas (importc "__builtin_ctzll")) .)
(asgn r.0 (call ctz64.0.bitops v.0))
```
→ classify by string, `allocCall`, operand into `rdi`, mark a call point:
```
mov  rdi, r12
bsf  rax, rdi
mov  r13, rax
```

**After** — library-level `ctz` is a normal `inline` proc calling a
target-pinned intrinsic (§3), so what reaches arkham is:

```
(proc :bsf.0.x64 (params (param :src.0 . (u 64))) (u 64)
      (pragmas (instruction bsf)) .)
(asgn r.0 (instr bsf.0.x64 v.0))
```
→ tag says "not a call"; `role = out` puts the result in its home:
```
bsf  r13, r12
```

## 8. `.assembler` mode — use case (b)

Spelled `assembler`, not `asm`: Nim's parser reads a pragma entry as an
*expression*, so a keyword cannot appear there and `{.asm.}` does not parse at
all. The tag is `(assembler)`, unrelated to the `(asm X+)` statement.

```nim
proc memzero(p {.register: "rdi".}: pointer;
             n {.register: "rcx".}: uint64) {.assembler.} =
  var z {.register: "rax".}: uint64
  xor(z, z)
  block outer:
    while true:
      test(n, n)
      if zf(): break outer
      store8(p, z)
      add(p, 8)
      sub(n, 8)
```

**Variables.** `.register: "rax"` and `.stack` map onto nifasm's `(var D L T)`
location slot — `(rax)` and `(s)`. An unannotated local is an error. Parameters
and the result are annotated the same way, which *is* the proc's ABI — and is
what lets an `.assembler` proc be called from ordinary Nimony (arkham marshals at the
boundary only, never inside).

**Control flow.** `while true` → `(loop (stmts …))`, which arkham already emits.
`if zf(): … else: …` → `(ite (zf) … …)`. Named blocks and `break` → labels and
jumps, which arkham already consumes. Any other `if` condition, any conditional
`while`, any `case`, any `for` — rejected.

**No materialization.** Each argument must be an **atom**: a `.register`
variable, a `.stack` variable (where `loc` permits `mem`), a literal in the
operand's immediate range, `addr` of a global, or a label. Nested
`(instr (instr …))` is rejected; one instruction per statement. Assignment sugar
is not needed — §4.1 already forces the spelling that matches the machine.

**No fallbacks.** Inside `.assembler`, an instruction the target lacks is a compile
error, not a call to a fallback body.

**Calls.** Only to procs whose parameters and result are fully
register-annotated, i.e. whose ABI is declared rather than inferred.

**Optimizer.** `nj` treats an `.assembler` body as verbatim: source order is the
contract.

**Non-goal:** `.assembler` + `.inline` into ordinary code (the GCC
inline-asm-with-constraints problem). Use case (a) covers the "fast path in a
portable wrapper" pattern directly (§3).

## 9. Alternatives considered

**A — keep `(call SYM …)`, only replace the pragma.** Fixes classification, not
cost: the allocator still cannot tell without resolving the callee, possibly
across modules, so the `atomicCallNames`-style side channels survive. Rejected.

**B — one dedicated tag per intrinsic: `(ctz T x)`, `(bsf d s)`.** Best for
consumers, and it is what `(ovf)` does today. But every checker needs a built-in
rule per opcode; tag ids are positional and shared across two repositories; and
the tag space would have to cover an entire instruction set per target, SIMD
included. Rejected as the general mechanism — right only for the small closed
set the optimizer must understand deeply, which is why `add`/`ovf` are tags and
`bsf` must not be.

**D — flags as annotated `bool` variables (`var eq {.flag: zf.}: bool`).**
Rejected in favour of §6: it needs a new variable kind, a new pragma, a rule for
what assigning to one means, and a flag-lifetime dataflow analysis to be sound —
all to express something two ordinary intrinsics already say. The intrinsic form
also degrades gracefully: unchecked in v1, checkable in v2, same syntax.

**C — `(instr SYM X*)` + pragma + table.** Proposed.

## 10. Impact per component

| Component | Change |
|---|---|
| `doc/instructions.md` | add the operand-model columns (§4.4); it becomes the target-pinned table |
| `nimony/doc/tags.md` | append `(instruction …)`, `(intrinsic …)`, `(instr SYM X*)`, `(register STR)`, `(stack)`; regenerate |
| `nimony/sempragmas.nim` | parse the pragmas; check the spelling against the row (§4.1); unify portable signatures against shapes |
| `nimony` sem | one destructuring rule for multi-out intrinsics (§4.2); otherwise nothing — intrinsics are procs |
| `hexer/lengcgen.nim` | pass the pragmas through (next to `MagicP`); emit `(instr …)` when the callee carries one, outs first |
| `arkham/programs.nim` | delete the four name lists and the duplicated cascade; `CallTarget` loses `atomic`/`memIntrin`/`bitBuiltin`; intrinsics become a separate `InstrTarget{opcode, decl}` |
| `arkham/analyser.nim`, `register_allocator.nim` | `allocInstr` (§5), reusing the existing accumulator/two-address machinery; drop the `atomicCalls` parameter |
| `arkham/codegen_{x64,a64}.nim` | table-driven emit; generalise `OvfC`'s condition-only handling to any flag-valued intrinsic (§6); drop `atomicCallNames`, `callIsInlinedAtomic`, the string cases, `emitBitBuiltin2` |
| `nifasm` | unchanged — `bsf`, `bswap`, `lock`, `cmpxchg`, `repmovsb`, `set*`, flags, `ite`, `loop` all already exist |
| `nj` | `pure` opcodes become CSE/fold/DCE candidates; `(instr …)` is selection-final |
| `ghast` (SPIR-V) | opcode → `OpBitCount`/`FindILsb`/… becomes expressible |
| Nimony stdlib | `ctz`/`clz`/`popcount`/`bswap` become `inline` + `when` wrappers |

## 11. Migration

Each phase is independently shippable, and (a) lands well before (b).

0. **arkham-only refactor, no NIF change.** Collapse the four name lists into
   one `cname → Opcode` table and one classifier shared by `collect` and
   `foreignCallTarget`. `CallTarget` gains `opcode`, loses the three strings.
1. **Extend `doc/instructions.md`** with the operand-model columns and generate
   the descriptor table. No behaviour change; it documents what the backends
   already do by hand.
2. **Add the pragmas.** `(instruction …)`/`(intrinsic …)` in nimony + hexer;
   arkham prefers them, keeps C-name sniffing as a legacy fallback. Spelling and
   shape checking land here.
3. **Add the call tag and `allocInstr`** — use case (a) working: `(instr …)`,
   table-driven allocation and emit, `atomicCallNames` and `callIsInlinedAtomic`
   deleted, a64 bit builtins land as table rows. Single-out only.
4. **Multi-out + flag intrinsics**: the destructuring rule, outs-first operands,
   and `OvfC`'s handling generalised. `div`/`mul`/add-with-carry become
   expressible.
5. **Move the portable layer to the stdlib** as `inline` + `when` wrappers;
   delete `emitBitBuiltin2` and friends.
6. **`.assembler` mode**: `.register`/`.stack`, the atom rule, the control-flow subset.
7. **Delete the legacy path**, move syscalls to an explicit `{.syscall: "write".}`
   pragma (they stay call-shaped — they clobber like calls — but stop being
   sniffed; the per-arch number table stays in arkham, keyed by the pragma), and
   let `nj` fold `pure` opcodes.

## 12. Implementation status

**Phases 2, 3 and 6 are implemented, and phase 4's flag half** — use case (a)
works end to end on both targets through both backends, use case (b) works on
x86-64 for the subset listed below, and flags are reachable there. Phases 0, 1,
5 and 7 are not started, nor is phase 4's multi-out half; the legacy
`importc`-sniffing path is untouched and still carries `memcpy`, the atomics and
the syscalls.

### What exists

| Piece | Where |
|---|---|
| The row table | `nimony/src/lib/intrinsics.nim` — one file, no NIF API, read by nimony's sem *and* by arkham |
| The pragmas | `(instruction X)` / `(intrinsic X)`, appended to `nimony/doc/tags.md` and regenerated |
| The call node | `(instr SYM X*)`, registered for `LengExpr` and `LengStmt` |
| Declaration check | `sempragmas.intrinsicSignatureError` — unifies the row's shape against the signature; the message lands in the routine's `effects` slot, the one slot that already accepts an `(err …)` |
| `(instr …)` emission | `hexer/lengcgen.applicationTag` — resolves the callee ONCE and bakes "not an ABI call" into the tag |
| C backend | `lengc/genexprs.genInstr` — portable rows → `__builtin_ctz`/`clz`/`popcount`/`bswap`; a target-pinned row is a compile error naming the reason |
| Allocation | `arkham/register_allocator.allocInstr` — operands are register *requests*, the result is the value's own home |
| Emission | `arkham/codegen_{x64,a64}.emitInstr2` |
| New nifasm instructions | x64 `(popcnt D S N)`; a64 `(clz D S N)`, `(rbit D S N)`, `(rev D S N)` |

The rows implemented: portable `Ctz`, `Clz`, `Popcount`, `Bswap`; x86-64
`bsf`, `bsr`, `popcnt`, `bswap`, `rol`, `ror`; AArch64 `clz`, `rbit`, `rev`.

`d = ctz64(x)` with `x` in `r12` and `d` homed in `r13` now emits exactly
`bsf r13, r12` — §1.3's three instructions became one, and `codegen_a64.nim`'s
`raiseAssert "bit builtin not yet implemented"` became `rbit` + `clz`.

Tests: `tests/arkham/intrinsics.c.nif` (portable, runs on x86-64 *and* under the
`linux_arm64` qemu path), `tests/arkham/intrinsics_x64.c.nif` (target-pinned),
`nimony/tests/nimony/intrinsics/{tintrinsics,tbadintrinsic}.nim` (the C backend
plus every declaration-site rejection). `tintrinsics` is also in hastur's
`NativeTestFiles`, so the two backends are checked to agree on results they
reach by different instructions.

### Deliberate v1 gaps

- **Only the `d = ins(x)` spelling.** A row with an `inout` operand is rejected
  *at the declaration* with a message saying so, rather than half-lowered. In
  Leng a `var` parameter is a pointer and the call site passes `(addr d)`, so
  the `ins(var d, x)` form needs arkham to recognise `(addr <local>)` in an
  operand slot and bind the local's home directly — otherwise the local is
  marked `AddrTaken` and forced to the stack, losing the entire point. That is
  a self-contained piece of work, not a design gap.
- **Two-address forms use `tie`, not `inout`.** x86's `bswap`/`rol`/`ror` are
  written `d = bswap(x)`; the row records `tie = 0` and the emitter seeds the
  destination. `tie` is a property of a *pinned* row; a portable row's lowering
  may be in-place on one target and not another (`Bswap` → x86 `bswap` vs a64
  `rev`), so that copy is the backend's decision, not the row's.
- **`rol`/`ror` need a compile-time count.** A variable count must live in `cl`,
  which is a `pin` the operand model can describe but `allocInstr` cannot yet
  request. A register count is a loud error, not a silent miscompile.
- **`Popcount` is x86-64 only.** The row's `targets` says so and a call on a64
  is a compile error naming the target. AArch64 has no scalar population count;
  the NEON `cnt`/`addv` pair needs FP encodings nifasm lacks, and the scalar
  SWAR expansion needs a scratch register `allocInstr` cannot yet reserve.
- **No LLVM-backend lowering.** `llvm.cttz`/`ctlz`/`ctpop`/`bswap` each need a
  `declare` and (for cttz/ctlz) an extra `i1` operand that `genCallWithType`
  cannot express. It rejects rather than substituting something else.
- **Multi-out is untouched** (§4.2) — the tuple form that would bind a flag at
  its definition site (`let (sum, carry) = addCarry(a, b)`). Only §6's other
  half, the general `zf()` escape hatch, exists.

### Flags (§6)

The row gained two columns, `uses` and `defs` over a `MachineFlag` set, and §6's
claim that this needs no new machinery held up: nifasm already had `(ite (zf) …)`
with all ten x86 conditions, so a flag intrinsic is a rename, not a mechanism.
`arkham/codegen_x64.x64FlagOf` is the whole of the mapping.

```nim
proc cmp64(a, b: uint64) {.instruction: cmp.}
proc zf(): bool {.instruction: zf.}

proc pick(x {.register: "rdi".}: uint64,
          y {.register: "rsi".}: uint64): uint64 {.assembler.} =
  cmp64(x, y)
  if zf(): result = 100
  else: result = 7
```

emits exactly `(cmp p0.0 p1.0)` and `(ite (zf) (stmts (mov (rax) 100)) (stmts
(mov (rax) 7)))`.

Two shapes, as §6 describes. An instruction that DEFINES flags and returns
nothing (`cmp`, `test`): `ret` is void, `defs` is non-empty, and it is a
statement. And a zero-operand `bool` that READS one (`zf`, `nz`, `cf`, `nc`,
`sf`, `ns`, `ovf`, `novf`, `pf`, `np`): `uses` names the bit, and it is legal
only as an `if` condition.

Notice what the columns buy. A `cmp` is deliberately **not** `efPure` — a "pure"
row with a void result is dead by definition and DCE would be right to delete
it; `defs` is what makes a flag-only instruction non-removable. And `uses` is
what lets `isFlagRead` be a property of the row rather than a hardcoded list of
opcode names.

The v1 rule is enforced at exactly one point per backend, and is stricter than
§6 in one way worth stating: flags are legal **only inside an `{.assembler.}`
proc**. §6's rule ("legal only where it can be consumed without materialisation")
is about the *placement*; but in an ordinary proc the placement is not the whole
story, because arkham may schedule a spill or a reload between the `cmp` and the
`if` and nothing promises it will not. `.assembler` is the context where source
order is the contract, so that is where flags work. Everywhere else — the
allocated path in both backends, and the C backend — rejects them by name.

Two deviations from "the name is the nifasm tag", both forced by Nim's grammar
rather than chosen: `ovf`/`novf` are spelled that way because nifasm's tags are
`of`/`no` and `of` is a keyword, so `{.instruction: of.}` does not parse. Same
collision as `{.asm.}`. The backend maps them back, so the assembler still sees
`(of)`/`(no)`.

Two passes needed the `.assembler` gate that `xelim` already had. `njvl`'s
Final-IR lowering (`nj`, the contract analysis) asserts that every call was
already hoisted to a location, which is precisely the normalization an
`.assembler` body must not undergo — so a flag as an `if` condition tripped it.
Such a body now lowers to a bodyless declaration there: no contracts to check,
and no vocabulary to check them in. This is §8's "`nj` treats an `.assembler`
body as verbatim" reaching the second of the two passes that must honour it.

Not yet: flag WRITERS (`stc`/`clc`/`cmc` — nifasm has no tags for them), `elif`
(one condition per `if`; a nested `if` is the machine's own spelling), and a
flag as a `while` condition (§8 keeps loops at `while true` + `break`, and
`if zf(): break` covers it).

### `.assembler` mode (phase 6)

The pragmas are `{.assembler.}` on the routine and `{.register: "…".}` /
`{.stack.}` on a parameter or local, all three forwarded to Leng verbatim.
Nimony's sem checks only their *shape* (routine-only; the register name is a
string literal); every other rule is arkham's, per the design's premise that the
machine model is where the checking belongs.

That premise binds hexer too, and cost one real change: `xelim` was rewriting
`r = bsf(x)` into `var tmp = bsf(x); r = tmp` — inventing exactly the
materialisation slot the mode forbids. `trProc` now takes an `{.assembler.}`
body verbatim. "Source order is the contract" is not only `nj`'s obligation.

| Piece | Where |
|---|---|
| The pragmas | `(assembler)`, `(register STR)`, `(stack)` in `nimony/doc/tags.md` |
| Verbatim body | `hexer/xelim.trProc` — no hoisting, no temporaries, no reordering |
| C / LLVM refusal | `lengc/codegen.genProcDecl`, `lengc/llvmcodegen.genProcDeclLLVM` — by name, pointing at `doc/asm-c-interop.md`, rather than a prototype that fails to link |
| Transliteration | `arkham/codegen_x64.genAsmProc` — no `allocateProc`, no analyser, no value core |
| Diagnostics | `arkham/codegen_common.lengError` — `file(line, col) Error: …` off the offending node's own NIF line info |

Spelled `assembler` because `{.asm.}` does not parse: Nim reads a pragma entry as
an expression, so a keyword cannot appear there.

What the x86-64 path accepts: `.register`/`.stack` locals (a register may carry
several names — that is the user pinning them together), `result` pinned to the
ABI return register (derived, since Nimony cannot annotate `result`), parameters
whose pins are *checked against* the SysV registers, `d = ins(x)`, flag
instructions and `if <flag>()` (see *Flags* below), moves between
registers/slots/literals, `while true` + `break`, `(lab)`/`(jmp)`, and `ret`.
Callee-saved pins are pushed and popped from the used-register set. A `conv` of a
*literal* is folded — the front end inserts it for typing and there is no
instruction behind it — while a `conv` of a value is a real extension and is
rejected like any other computed expression.

Everything else is a user error with precise line info — a computed expression
(`r = bsf(x) + 1`), a conditional `while`, an unannotated local, a pin to
`rsp`/`rbp`, a memory-to-memory move, a parameter past the sixth, an opcode with
no x86-64 lowering. Tests: `tests/arkham/assembler_x64.c.nif` for the code
generation, `tests/arkham/err_*.c.nif` for the rejections (arkham owns these
rules outright, so its refusals are regression-tested like its output), and
`nimony/tests/nimony/assembler/*.nim` for the front-end and C-backend halves.

Not yet, and each is a real gap rather than a rejection-by-design:

- **AArch64.** `codegen_a64.genProc2` refuses an `.assembler` proc rather than
  ignoring the pins. The x86-64 register names in a body have no target-neutral
  reading, so an a64 version is a different `when` branch either way — but the
  a64 backend still needs its own `genAsmProc` before that branch can exist.
- **Calls.** In §8's subset; a call needs the callee's ABI checked against the
  caller's live pins. (`if <flag>` now works — see *Flags* above.)
- **Globals.** §8's operand list includes `addr` of a global; only locals and
  parameters are accepted so far. `p = addr(g)` is one `lea`, but a pointer is
  only worth having once loads and stores through it work too, so the two go in
  together. (A pointer *parameter* already works: it keeps its `(ptr T)` in the
  binding, so nifasm type-checks it.)
- **No `inout` rows**, so the body cannot yet do arithmetic — the same gap as
  use case (a) above, and the reason §8's `memzero` example does not compile
  yet. `.assembler` is where it is *easiest* to close: `(addr <local>)` in an
  operand slot binds straight to the declared home, because there is no
  allocator to confuse with `AddrTaken`.
