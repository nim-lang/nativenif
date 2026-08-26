# Getting `.asm` procs into a clang/gcc build

*Companion to `doc/intrinsics.md` — how an `.asm` proc reaches the linker when
the bulk of the program is compiled by a C backend.*

## 1. Short answer

Route the `.asm` procs through arkham → nifasm → a **relocatable object**, and
let the C driver link it. Not because emitting GNU-as text is impossible, but
because **the object route already exists and works**: `nifasm --emit-obj`
(`nifasm.nim:16`) emits a relocatable `MH_OBJECT` via `writeMachOObject`
(`assembler.nim:6549`, `macho.nim:896`), in which "defined procs / globals become
exported symbols, external `extproc` references become undefined symbols, and
every fixup the executable path would resolve in-place becomes a relocation the
system linker resolves."

It already emits the four arm64 relocation kinds (`macho.nim:176-179`:
`UNSIGNED`, `BRANCH26`, `PAGE21`, `PAGEOFF12`), already turns a gvar `adrp`/`add`
pair into `PAGE21` + `PAGEOFF12` (`assembler.nim:6626`), and — this is the part
that matters for the `const` question — already relocates **pointer fields
embedded inside constant data** (`rodataSymInits`, `bssSymInits`,
`rodataRebases`, `assembler.nim:6632-6650`).

So this is a porting job, not a design job. What is missing:

| | status |
|---|---|
| Mach-O / arm64 | **done** |
| ELF | `elf.nim` writes `ET_EXEC` only (`elf.nim:100`) — needs `ET_REL`: section headers, `.symtab`/`.strtab`, `.rela.text`/`.rela.data`, `.note.GNU-stack` |
| x86-64 relocations | none yet — needs `R_X86_64_PC32`, `PLT32`, `64`, and `REX_GOTPCRELX` if non-hidden symbols are allowed |
| aarch64 ELF relocations | the Mach-O kinds map 1:1 to `R_AARCH64_ADR_PREL_PG_HI21` / `ADD_ABS_LO12_NC` / `CALL26` / `ABS64` |
| thread-locals | `--emit-obj` explicitly rejects them (`assembler.nim:6565`) |
| COFF | not started |
| unwind info | none (§7) |

## 2. The alternatives, honestly

**(B) Emit GNU-as text (`.s`).** Its one real advantage is that `as` supplies
everything *around* the bytes: relocation arithmetic, section flags, COMDAT,
alignment, `.cfi_*` → `.eh_frame`, DWARF line directives, `.note.GNU-stack`. The
cost is a second emitter that can silently disagree with nifasm's byte encoder.

**(B′) The hybrid: `.byte` + relocation directives.** Emit nifasm's own encoded
bytes, dropping to a data directive only where a relocation is needed:

```
foo:
  .byte 0x48,0x8d,0x05          # lea rax, [rip+bigTable]
  .long bigTable - . - 4        # as emits R_X86_64_PC32
```

This keeps the byte encoder as the single source of truth and outsources only
the object plumbing. **But it does not generalise off x86.** On x86-64 a
relocated field is a contiguous little-endian byte field, so a data directive can
express it. On AArch64 the relocations patch *bitfields inside the instruction
word* — `ADR_PREL_PG_HI21` patches ADRP's immhi/immlo, `ADD_ABS_LO12_NC` patches
ADD's imm12 — which no `.long` can express. a64 would need real mnemonics for
every reloc-carrying form (`adrp`, `add`/`ldr`/`str` with `:lo12:`, `b`, `bl`,
`adr`). That is a small set (~10 forms), so B′ stays viable, but it is no longer
"no second printer".

**(C) Embed the code as a top-level `asm("…")` in the generated C.** Preserves
the single-artifact property and makes symbol references trivial. Rejected:
symbols defined inside top-level asm are invisible to LTO's symbol resolution,
and the technique is fragile across compilers.

**Recommendation:** finish (A). Keep (B′) in reserve for COFF, and as the escape
hatch if hand-rolling `.eh_frame` (§7) turns out worse than printing `.cfi_*`.

Note that (A) breaks nativenif's "single output file" invariant — but only for
the *C* pipeline, which is a different pipeline. The native path is unaffected
and must stay single-output.

## 3. The pipeline split

arkham and `lengc` (nimony's Leng → C backend) are **siblings on the same
input**: both consume the Leng NIF that `hexer/lengcgen` produces. So the split
is a filter on one pragma, on both sides:

- `lengc` skips the body of an `.asm` proc and emits only its prototype.
  Precedent: `lengcgen` already drops `MagicP`/`DynlibP` procs entirely
  (`lengcgen.nim:974`).
- arkham compiles **only** the `.asm` procs; everything else — every proc, every
  global, every const — becomes an undefined symbol reference.

That second half is a new arkham *mode*. Today `collect` walks the whole module
and emits every global (`programs.nim:385`); the new mode emits no data and no
non-`.asm` proc, and routes every other symbol through the same path
`foreignCallTarget` already uses for cross-module references.

## 4. The `const` question — who owns the data

This is the real difficulty, and it splits by who reads the data.

**Rule: data reachable from C is owned by the C backend; data reachable only
from `.asm` may be owned by arkham.** Default to C on any doubt.

The reason is not symmetry, it is **layout agreement**. If both sides emit the
same aggregate, they must agree byte-for-byte on padding, alignment and field
order — arkham's `aggrLayout` versus the C compiler's struct layout, including
whatever `-fpack-struct`, bitfields or attributes are in play. A mismatch is
silent memory corruption, not a link error. One owner removes the question
entirely: only one layout is ever materialised, and the other side merely
addresses it.

For the C-owned case, five things must hold:

1. **Materialisation.** `const x = 5` may be folded and never emitted at all.
   A reference from an `.asm` proc must force it into a real object with a real
   symbol — an implicit `exportc`, triggered by the reference.

2. **A stable, agreed name.** The `.asm` reference must use exactly the C name
   that `lengc/mangler.nim` produces (plus the Mach-O leading `_`, which nifasm
   already applies — `assembler.nim:6547`). arkham has the mechanism already:
   `gvarCName` + `CLinkageGvars` (`programs.nim:385-410`) is precisely "these
   symbols are promoted to bare C linkage so two compilation units agree". The
   `.asm` reference set joins that table; the ad-hoc allowlist becomes computed.

3. **Hidden visibility.** Promote to non-`static` but
   `__attribute__((visibility("hidden")))`. Without it, a symbol in a shared
   library is preemptible, and x86-64 must reach it through the GOT
   (`REX_GOTPCRELX`) rather than `lea`-rip-relative — a *different instruction
   sequence*, not just a different relocation. Hidden visibility keeps
   PC-relative addressing correct under PIE and keeps the emitted code shape
   independent of the link mode.

4. **Explicit alignment.** A `movaps`/`ld1` against under-aligned data faults.
   The operand table (`doc/intrinsics.md` §4.4) knows the alignment the
   instruction requires; the C side must carry the matching
   `__attribute__((aligned(N)))`. This must be *checked*, not hoped for.

5. **Offset agreement, verified.** Where an `.asm` proc indexes into a C-owned
   aggregate, emit `_Static_assert(offsetof(T, f) == N, …)` into the generated C,
   with `N` taken from arkham's computed layout. Cheap, and it converts the one
   silent-corruption failure mode into a compile error.

Addressing it from the `.asm` side is then the existing gvar path: on x86-64
`lea rax,[rip+sym]` → `R_X86_64_PC32`; on a64 the `adrp`/`add` pair → PAGE21 +
PAGEOFF12, which `--emit-obj` **already emits today** (`assembler.nim:6626`).

For `.asm`-private data — a jump table, a SIMD constant pool — arkham owns it,
emits it into its own section, and the C side never learns of it. That is
strictly simpler and needs none of 1–5.

## 5. The reverse direction: C data with pointers in it

Worth calling out because it is where naive schemes break: a `const` whose
initialiser contains *addresses* (an array of `cstring`, a vtable, an object
graph) needs relocations *inside the data*. Under the ownership rule above this
is the C backend's problem and it already solves it. The only case arkham must
handle is `.asm`-private data containing addresses — and `rodataSymInits` /
`rodataRebases` (`assembler.nim:6632-6650`) already do exactly that.

## 6. The call boundary

**ABI.** An `.asm` proc called from C must follow the platform C ABI. Since its
parameters carry `.register` annotations, the compiler can *compute* the expected
SysV/AAPCS64 assignment from the signature and **check** the annotations match —
error on mismatch. No adapter shim, no inference. That is the honest reading of
"no heuristics": the ABI is derived, the annotation is verified against it.

**Callee-saved registers.** An `.asm` proc that touches `rbx`/`r12`–`r15`/`rbp`
(or `x19`–`x28`) must save and restore them. The used-register set is known, so
the prologue/epilogue is *derived* — not guessed — and should be reportable so
the cost is visible rather than hidden.

**Stack alignment.** SysV requires `rsp % 16 == 0` at a `call`. An `.asm` proc
that calls anything must maintain it; arkham knows the frame size and can check.

## 7. Unwinding, and the one place the `.s` route wins

The object path emits no `.eh_frame`. Consequences: an exception cannot
propagate through an `.asm` frame, and `gdb`/`perf` cannot walk past one.

Two options:

- **v1: forbid it.** Declare `.asm` procs non-unwindable and check that nothing
  which can raise is reachable from one. Cheap and honest; costs backtrace
  quality through the frame.
- **v2: emit minimal CFI.** Derivable from the frame layout arkham already
  computes — but on the object route it means hand-writing `.eh_frame` CIE/FDE
  bytes, whereas the `.s` route gets it from three `.cfi_*` directives.

This is the strongest argument for (B′), and the reason to keep it in reserve
rather than discard it.

## 8. Loose ends

- **Thread-locals.** `--emit-obj` rejects them outright (`assembler.nim:6565`).
  TLS models differ per platform (`__thread` GD/LE, Mach-O TLV) and the
  relocations are a separate family. Either forbid TLS access in `.asm` for v1,
  or route it through a C-owned accessor.
- **LTO.** A separate `.o` is opaque to LTO — correct and safe. Mixing it into
  an `-flto` link is fine; there is simply no cross-inlining into asm, which is
  what is wanted anyway.
- **`.note.GNU-stack`.** ELF objects lacking it make the linker mark the stack
  executable. Classic hand-written-asm bug; must be emitted.
- **COMDAT.** Only needed if an `.asm` proc can be emitted from several TUs.
  Since `.asm` + `.inline` is already a non-goal (`intrinsics.md` §8), forbid
  `.asm` on generic/inline procs and the question does not arise.
- **The LLVM backend.** `lengc` also emits LLVM IR (`llvmcodegen.nim`). The same
  split applies unchanged — it links objects like any other C toolchain.
- **Debug info.** arkham emits no DWARF, so `.asm` procs get a name from the
  symbol table and no line numbers. Acceptable; worth stating so it is not
  discovered in a debugger.

## 9. Suggested order

1. ELF `ET_REL` writer + x86-64 relocations (`PC32`, `PLT32`, `64`) — unlocks
   Linux/x86-64, the common case.
2. arkham's "compile only the `.asm` procs, extern everything else" mode.
3. The C-linkage promotion for referenced symbols (generalise `CLinkageGvars`)
   plus the `_Static_assert` offset checks.
4. The ABI-annotation check at the call boundary.
5. aarch64 ELF relocations (mechanical — the Mach-O kinds map 1:1).
6. Unwind info, or the documented restriction instead.
7. TLS and COFF, as needed.
