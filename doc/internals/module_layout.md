# Refactoring plan: per-CPU subdirectories, `import` instead of `include`

Status: **S0–S1 done.** See §12 for the running log.

## 1. Why

Four files carry 78% of the tree:

| file | lines |
|---|---|
| `src/nifasm/assembler.nim` | 11383 |
| `src/arkham/codegen_x64.nim` | 9969 |
| `src/arkham/codegen_arm.nim` | 8295 (+ 1867 `include`d) |
| `src/arkham/codegen_common.nim` | 2056 |
| *everything else in `src/`* | 20883 |

`assembler.nim` alone holds the x86-64, AArch64 and Thumb-2 instruction
selectors, the type checker, the module loader, both passes, and all four image
writers. `codegen_x64.nim` and `codegen_arm.nim` are near-parallel emitters that
share `codegen_common.nim`, and `codegen_arm.nim` reaches its Cortex-M and
`.assembler` halves through `include` — two files that cannot be compiled,
read, or reasoned about on their own.

Goal: no source file over ~2500 lines except where a single irreducible
recursive core says otherwise, one subdirectory per target CPU, and `import`
everywhere.

## 2. The constraint that decides the whole shape

Nim (2.3.1, verified in this tree) rejects cyclic module dependencies:

```
Error: undeclared identifier: 'evalA'
This might be caused by a recursive module dependency
```

So a set of mutually recursive procs **cannot** be split across modules by
`import` alone. Splitting is therefore governed by the call graph's strongly
connected components, not by taste. Measured SCCs (Tarjan over the top-level
routines of each file):

| file | largest SCC | of total body lines |
|---|---|---|
| `assembler.nim` | 3444 (14 routines, spans **all three** arches) | 10923 |
| `codegen_x64.nim` | 3660 (49 routines, the fused value core) | 9530 |
| `codegen_arm.nim` (+includes) | 3639 (56 routines, the fused value core) | 9793 |

Two consequences:

* **≈62% of each big file is already leaf code** and can be lifted out by plain
  `import` with no design work at all.
* The remaining core is the emitter's value/lvalue/store recursion. That stays
  one module per backend (~3700 lines). It is the honest floor, and it is a 2.7×
  improvement over today.

The one SCC that is *not* irreducible is `assembler.nim`'s — see §5.

### The pattern this forces

> The context type must live in its own module, together with just enough
> creation logic, and nothing else.

`core/context.nim` holds the state record and its constructor and imports only
modules that will never want to import it back. Every other module takes
`ctx: var GenContext` / `g: var CodeGen` as its first parameter. That makes the
whole tree below the emitter a DAG, and `import` sufficient.

A precondition: **module-level mutable state has to go onto the context**,
otherwise the split silently changes behaviour. Today `assembler.nim` carries
`gCurProc` and `gLenient` as globals — and `GenContext` *already* has a
`lenient` field, so the global is a duplicate of a field. Both fold into the
context in stage S2.

## 3. Import and naming conventions (new)

* **Path-qualified imports** — `import ../core/context`, `import ./operands`.
  `--path` stays reserved for genuinely external roots (nimony's `src/lib`,
  `src/common`). `src/arkham/layout.nim` already does this
  (`import "../nifasm" / [model, tagconv, tagpool, tags]`); it becomes the
  house style.
* This removes the current basename-uniqueness hazard: `slots.nim` exists in
  **both** `src/nifasm` and `src/arkham`, and `src/arkham/nim.cfg` puts
  `../nifasm` on the path — so which one `import slots` resolves to today
  depends on Nim's search order. Renamed anyway for readability:
  `nifasm/core/stackslots.nim` (the `SlotManager`) and
  `arkham/core/asmslots.nim` (the `AsmSlot` classifier).
* Main modules keep their paths: `src/nifasm/nifasm.nim`,
  `src/arkham/arkham.nim`. Nothing outside the repo has to change.
* No proc is renamed by this refactor. Bodies move verbatim; a stage that
  cannot be verified by "the sorted set of routine bodies is unchanged" is a
  stage that is doing two things at once.

## 4. Target tree — nifasm

```
src/nifasm/
  nifasm.nim              CLI driver                                      124
  core/                   arch-neutral
    tags.nim  model.nim                       generated, moved     1143 / 796
    tagconv.nim  tagpool.nim  decls.nim  buffers.nim         71/70/196/106
    relocs.nim            arch-neutral relocation machinery            ~560
    stackslots.nim        was slots.nim                                  88
    sem.nim               Type / Symbol / Scope / compatibility         331
    context.nim     NEW   GenContext, Arch, CallContext, LoadedModule,
                          ListingRow, Operand, CortexMBoard, MimgKind,
                          + newGenContext                              ~330
    diagnostics.nim NEW   error / typeError / nodeRepr / infoStr         ~90
    typesem.nim     NEW   parseType, parseObject/UnionBody, parseParams,
                          parseResult, parsePtrType, parseExtprocSig,
                          resolveForeignSym, lookupWithAutoImport
                          (one 9-routine SCC — must stay together)      ~560
    typecheck.nim   NEW   movCompatible, checkType, every check*        ~340
    modules.nim     NEW   openForeignModule, importOrdinal, extprocLib,
                          markSymbolUsed, dedup, getCanonicalName       ~150
    listing.nim     NEW   listing rows, remapListing, writeListing,
                          and the `withListingRow` template (see §5)    ~110
    pass1.nim       NEW   pass1 / pass1Proc / pass1Syproc / handleArch  ~200
    pass2.nim       NEW   pass2 / pass2Proc / collectLabels /
                          scanStackArgArea / shiftCodePositions         ~380
    driver.nim      NEW   assemble, generateSymbol,
                          processReachableSymbols, setup*Entry, setupTls ~460
  x64/
    encoder.nim           was x86.nim                                  2228
    relax.nim       NEW   shortenX64Jumps, alignCodeX64, invertCondJumps,
                          emitX64Nops, threadJumps (out of relocs.nim)  ~430
    regs.nim        NEW   tagToRegister, parseRegister, xmm helpers      ~90
    operands.nim    NEW   parseOperand, parseDest, leaRegBase,
                          checkDistinctAluRegs, isXmmOperand            ~950
    calls.nim       NEW   genPrepare/CallMarker/Tailcall/Syscall/
                          Extcall/Iat                                   ~300
    frame.nim       NEW   genPopframeX64, TLS slot allocation            ~90
    instr.nim       NEW   genInstX64 + ite/loop/jtrue/kill/withreg/
                          rebind/mov/casejmp/aluSubWidth + genStmtX64   ~2100
  arm64/
    encoder.nim           was arm64.nim                                 1040
    regs.nim        NEW                                                 ~130
    operands.nim    NEW   OperandA64, parseOperandA64, parseDestA64,
                          parse3OperandsA64, memWidthOpc, mem bases     ~800
    calls.nim       NEW                                                 ~240
    frame.nim       NEW   genPopframeA64, cfiStep, emitAddOffsetA64      ~90
    instr.nim       NEW   genInstA64 + ite/loop/jtrue/… + genStmtA64    ~1500
  thumb/
    encoder.nim           was thumb2.nim                                 741
    regs.nim        NEW                                                  ~60
    operands.nim    NEW   OperandM, parseOperandM/DestM, memWidthM,
                          emitMemAccessM, emitVfpMemAccessM, load/store ~700
    calls.nim       NEW   genPrepareM, genCallMarkerM                   ~120
    board.nim       NEW   handleLayout, handleInterrupts, readLayout*,
                          interruptTableBytes                           ~130
    instr.nim       NEW   genInstM + ite/loop/jtrue + genStmtM          ~700
  image/
    elf.nim  elf32.nim  macho.nim  pe.nim
    dwarf.nim  tracetable.nim                        154/226/1109/894/261/94
    writeelf.nim     NEW  writeElf + appendTraceTable / fillTraceTable   ~450
    writemacho.nim   NEW  writeMachO, writeMachOObject, machoName        ~250
    writepe.nim      NEW  writeExe                                       ~110
    writecortexm.nim NEW  writeCortexMImage                              ~240
```

`assembler.nim` ceases to exist. The largest file left is the x86 encoder
(2228, a flat table of encoders) and `x64/instr.nim` (~2100).

## 5. Breaking nifasm's cross-arch SCC

This is the only genuinely *reducible* cycle in the tree, and it is worth
spelling out because it buys 3444 → 1964 / 1426 / 672.

Today: `genInstX64` → `genIteX64` → `genStmt` → `genInst` → `genInstDispatch`
→ `genInstX64`. `genStmt` is 7 lines and `genInstDispatch` 9; the coupling that
welds the three arches into one component is `genInst`'s 38-line
`--listing` wrapper, shared by all of them.

Fix, in two moves, no runtime indirection:

1. `core/listing.nim` exports the wrapper as a **template**:
   ```nim
   template withListingRow*(ctx: var GenContext; n: var Cursor; dispatch: untyped) = ...
   ```
2. Each arch module grows its own three-line statement entry — Cortex-M already
   has exactly this shape (`genStmtM`):
   ```nim
   proc genStmtX64*(n: var Cursor; ctx: var GenContext) =
     if atTag(n, StmtsTagId): (loopInto n: genInstNode(n, ctx))
     else: genInstNode(n, ctx)
   ```
   where `genInstNode` is the local `withListingRow(ctx, n): genInstX64(n, ctx)`.

`core/pass2.nim` then dispatches on `ctx.arch` to `genStmtX64` / `genStmtA64` /
`genStmtM` once, at the top, instead of once per instruction.

## 6. Target tree — arkham

```
src/arkham/
  arkham.nim              CLI                                            150
  core/
    asmslots.nim (was slots.nim)  machinedesc.nim  typenav.nim
    regbind.nim  asmbuf.nim  abi.nim  analyser.nim  planer.nim
    programs.nim  peephole.nim  layout.nim  lengdecl.nim  stress.nim
                          (all moved unchanged — they already form a DAG)
    context.nim     NEW   CodeGen + OvfMode / NameBindTyp / CondFusion /
                          CallerSaveWindow + newCodeGen                 ~360
    diag.nim        NEW   userName / lengInfo / lengError                ~35
    typeutil.nim    NEW   type predicates, slot analysis, widths        ~420
    constdata.nim   NEW   static constant data layout                   ~270
    mirrors.nim     NEW   store forwarding (the mirror map)             ~200
    temps.nim       NEW   emit-time temp allocation + census            ~230
    select.nim      NEW   select-diamond recognition (csel / cmov)      ~130
    exprpred.nim    NEW   syntactic operand predicates                  ~120
    asmcommon.nim   NEW   `.assembler` bodies, target-neutral half      ~120
  x64/
    machine.nim           was machine_x64.nim                            194
    emit.nim        NEW   emReg/emFReg, movImm/movReg, binReg/binImm,
                          extendTo, cmpZero, labels, jcc, emitLoop,
                          fmov/fbin/fcvt                                ~430
    staging.nim     NEW   the staging scratch pool + the destination
                          protocol (pickStaging*, take{Tmp,FTmp,Held},
                          freeVal, resolveDestE, bind/unbindTemp)       ~560
    mem.nim         NEW   stack-var declarations, `(mem …)` shapes,
                          emGlobalAddr/emTvarAddr/emSymAddr, binMem     ~430
    cond.nim        NEW   jcc/setcc/cmov tag tables, mirror/invert      ~120
    aggr.nim        NEW   SysV by-value marshalling, AggrEnd, copyAggr  ~700
    intrin.nim      NEW   mem* byte loops, rep movs, atomics, bit
                          builtins, nullary/inout intrinsic tags        ~650
    types.nim       NEW   genTypeBody, genProctypeSig, emitParamsAndResult,
                          genType, genTvar, emitSyproc, emitWinExtproc  ~430
    frame.nim       NEW   computeFrameX64, framePush/Pop, emitSignature,
                          emitParamMoves, stack params, caller-save     ~700
    value.nim       NEW   **the fused value/lvalue/store core (the SCC)** ~3700
    stmt.nim        NEW   genStmt2, genVarDecl2, emitCaseTest2,
                          tryEmitCmov, tryEmitCaseJmp, scanCondFusions,
                          emitProcBody2                                 ~900
    asmproc.nim     NEW   `.assembler` transliteration                  ~600
    driver.nim      NEW   genProc, genGlobal, recordSymTypes,
                          generateX64                                   ~400
  arm/                    AArch64 (Darwin/Linux) + Cortex-M — see §7
    machine_a64.nim (was machine.nim)   machine_m.nim              204/267
    emit.nim  staging.nim  mem.nim  cond.nim  frame.nim  aggr.nim
    intrin.nim  types.nim                    ~470/380/330/120/900/600/700/330
    value.nim       NEW   the fused core, incl. the 349 recursive lines
                          of the Cortex-M wide-64 lowering             ~3650
    stmt.nim        NEW                                                 ~600
    asmproc.nim           was `include codegen_arm_asm`                  917
    driver.nim      NEW   genProc2, genAsmProc2, genType/Global/Tvar,
                          generateA64, generateM, rejectForThumbM       ~450
  cortexm/                Cortex-M-only, imported by arm/
    wide64.nim      NEW   the leaf half of `codegen_m64`: slot/word
                          helpers, wideLoad/Store/Copy, wideNeg/Not/Mul,
                          carry chains, arg/param/ret plumbing,
                          emitUDivMod64 / emitSDivMod64                 ~600
    semihost.nim    NEW   semihosting runtime + exit shim               ~250
    startup.nim     NEW   emStartupInitM, emEnableFpuM, EntryExitShim   ~120
```

`stmt.nim` imports `value.nim` (measured: the edge is one-way — `genStmt2`
calls the value core, the value core never calls `genStmt2`), and `driver.nim`
imports `stmt.nim`.

Two placements are forced by the SCC and should not be argued with later:

* `scalarMemMov` / `floatMemMov` / `emitLoadLoc` / `emitStoreLoc` *look* like
  `mem.nim` but call `prematLval2` / `emMemLval2`, so they live in `value.nim`.
* 349 of `codegen_m64.nim`'s 950 lines (`emitWideInto`, `wideShift`,
  `emitWideCmpE`, `wideCallInto`, `wideRet`, …) are inside the Arm value core.
  Only the other ~600 move to `cortexm/wide64.nim`.

## 7. Why arkham gets `arm/` and not `arm64/` + `thumb/`

`codegen_arm.nim`'s header states the reason and it still holds: one emitter
serves AArch64/Darwin, AArch64/Linux and bare-metal Cortex-M because a second
emitter would have to reimplement the register-binding protocol — the part with
a formal model behind it (`proofs/arkham_bindings.tla`). The measurement agrees:
the wide-64 lowering that is Cortex-M's alone is 36% inside the shared value
core.

So the per-CPU split arkham can actually honour is `x64/` vs `arm/`, with the
target-specific machine models (`machine_a64.nim`, `machine_m.nim`) and the
Cortex-M-only lowering (`cortexm/`) called out by name. nifasm, whose selectors
genuinely *are* three independent programs, gets the full `x64/ arm64/ thumb/`.

## 8. Fallout outside `src/`

| what | change |
|---|---|
| `src/nifasm/nim.cfg` | unchanged — Nim reads the config beside the *project file* (`src/nifasm/nifasm.nim`), so it still covers every module under it |
| `tests/nim.cfg` | unchanged |
| `tests/tester.nim:9` | `import "../src/nifasm/arm64"` → `.../arm64/encoder` |
| `tests/tester.nim:10` | `import "../src/nifasm/buffers"` → `.../core/buffers` |
| `tests/thumb2_selftest.nim:12-15` | `thumb2` → `thumb/encoder`; `buffers`, `relocs` → `core/…`; `elf32` → `image/elf32` |
| `tools/gen_instructions.nim:208-210` | writes `src/nifasm/tags.nim` / `model.nim` → `src/nifasm/core/…` |
| `src/arkham/core/layout.nim` | `import "../nifasm" / [model, tagconv, tagpool, tags]` → `import "../../nifasm/core" / [model, tagconv, tagpool, tags]` |
| `src/arkham/core/asmbuf.nim` | `import model`, `import tagpool` → `import "../../nifasm/core" / [model, tagpool]` |
| `src/arkham/arm/*` | `from arm64 import isLogicalImm` → `from "../../nifasm/arm64/encoder" import isLogicalImm` (the quoted-path form `layout.nim` already uses) |
| `src/arkham/{x64,arm}/*` | `import tracetable` → `import "../../nifasm/image/tracetable"` |
| `src/arkham/nim.cfg` | `--path: "../nifasm"` dropped — the four cross-tree imports above are now path-qualified, so the search-path entry (and the `slots.nim` ambiguity it created) goes away |
| `src/ghast/` | untouched (923 lines total, already small) |
| `src/common/` | untouched |

## 9. The equivalence gate

This refactor must not change a single emitted byte, so the gate is exactly
that, and it comes **before** the first move:

`tools/refactor_gate.sh`
1. builds `bin/arkham` and `bin/nifasm`;
2. runs every `tests/*.nif` fixture and every arkham corpus input through the
   full pipeline;
3. writes `sha256` of every produced `.asm.nif` and every produced image to
   `refgate.sums`, sorted.

`refgate.sums` is captured once on `master` and compared after every stage.
Any difference fails the stage — a pure code move has no licence to produce a
different byte. `tests/tester` (including the `-d:arkhamStress` pass) runs on
top of that, unchanged.

## 10. Stages

Each stage is: move, build, `refactor_gate.sh` clean, `tests/tester` green,
commit. Never more than one file's worth of motion per commit.

| # | stage | leaves behind |
|---|---|---|
| S0 | write `tools/refactor_gate.sh`, capture the baseline sums | no source change |
| S1 | create the directories, move the *existing* files, fix imports, `nim.cfg`, tests, `gen_instructions` | nothing renamed except `slots.nim` ×2 |
| S2 | nifasm: extract `core/context.nim` + `core/diagnostics.nim`; fold `gCurProc` / `gLenient` into `GenContext` | assembler.nim ≈ 10900 |
| S3 | nifasm: peel the leaves — `typesem`, `typecheck`, `modules`, `listing`, then the four `image/write*.nim` | ≈ 8500 |
| S4 | nifasm: break the cross-arch cycle (§5), then split `x64/`, `arm64/`, `thumb/` operands + instr + calls + frame + board | ≈ 1500 |
| S5 | nifasm: `core/pass1.nim`, `core/pass2.nim`, `core/driver.nim` — `assembler.nim` deleted | — |
| S6 | nifasm: split `relocs.nim` → `core/relocs.nim` + `x64/relax.nim` | — |
| S7 | arkham: split `codegen_common.nim` → `core/context.nim` + 8 leaf modules | codegen_common deleted |
| S8 | arkham: convert both `include`s to modules — `arm/asmproc.nim`, `cortexm/wide64.nim` (+ the 349 lines that stay) | no `include` left in `src/` |
| S9 | arkham x64: peel `emit`, `staging`, `mem`, `cond`, `aggr`, `intrin`, `types`, `frame`, then `stmt` + `driver` | `x64/value.nim` ≈ 3700 |
| S10 | arkham arm: the same peel | `arm/value.nim` ≈ 3650 |
| S11 | *optional* — split the `genInstX64` / `genInstA64` mega-`case` by instruction family (mov / alu / shift / float / branch), each family a leaf proc returning `handled: bool` | `x64/instr.nim` ≈ 400 + 5 families |

S11 is listed separately because it is the first stage that edits control flow
rather than moving text; it should not be bundled with a move.

## 11. Non-goals

* No behaviour change, no diagnostics reworded, no output byte moved.
* No proc renamed. The two file renames (`slots.nim`) are forced by the
  basename collision that exists today.
* The two ~3700-line value cores are **not** split further by this plan.
  Splitting them requires either indirection through a hook table on the
  context or a redesign of the emitter's recursion, and neither is a
  refactoring — both are design changes that deserve their own proposal, with
  the register-binding proof re-checked afterwards.
* `src/ghast` and `src/common` are out of scope.

## 12. Log

| stage | commit | gate |
|---|---|---|
| S0 plan + `tools/refactor_gate.sh` | `0c51e8c` | baseline: 2052 hashes + 405 diagnostics, deterministic across two runs |
| S1 directories, moves, import rewrite | | clean — 2457/2457 identical; `tests/tester` green |

### Decisions taken while executing

* **The encoders keep their old module names at the use site.** The files are
  `x64/encoder.nim`, `arm64/encoder.nim`, `thumb/encoder.nim` as planned, but
  they are imported `as x86` / `as arm64` / `as thumb2`, because the several
  hundred qualified references (`x86.Register`, `arm64.Condition`,
  `thumb2.MemWidth`) say which *instruction set* they mean — `encoder.Register`
  would not. Same for `from image/elf32 as elf32 import nil`. Verified that both
  `import a/b as c` and `from a/b as c import nil` compile under Nim 2.3.1.
* **`elf.nim` was not renamed to `elf64.nim`.** It is imported unqualified and
  the rename bought nothing.
* **`core/asmbuf.nim` keeps a lone `core → arm` edge**: its `renderReg` field
  defaults to AArch64's `regName`. The x64 and Cortex-M backends install their
  own, so this is a default-argument dependency and nothing more. Removing it
  means naming the renderer at each construction site — a behaviour-visible
  edit, so it waits for its own stage rather than riding along with a move.
* **`--path: "../nifasm"` is gone from `src/arkham/nim.cfg`**, as planned. The
  four cross-tree imports are path-qualified, and with it goes the ambiguity
  that let `import slots` resolve to either tool's module.
* `core/lengdecl.nim` and `core/programs.nim` reach nimony by relative path, so
  their `../../../nimony` became `../../../../nimony` — the one edit a move of
  this kind always needs and always forgets.
