# nativenif

`nativenif` is a toolchain to translate NIF code directly to machine code. No external tools are required, the system ships with an assembler and linker. Much complexity is avoided as the system is not based on ELF and DWARF but instead exploits NIF's many benefits.

The input language is **Leng**, the mid-level NIF dialect nimony compiles to
(nimony's [doc/leng-spec.md](https://github.com/nim-lang/nimony/blob/master/doc/leng-spec.md)).

## The two stages

```
foo.c.nif  --[ arkham ]-->  foo.asm.nif  --[ nifasm ]-->  foo (executable)
  Leng                       typed asm-NIF
```

Both stages read and write NIF, so the intermediate is inspectable text at every
point. Nothing becomes bytes until the final write.

### `arkham` — the code generator

`src/arkham`. One Leng module in (`.c.nif`, or `.oc.nif` when nimony's optimizer
ran), one asm-NIF module out. It is a simple tree-walking code generator with an
unusual register strategy: a pre-pass gives every local a home and every value
position a location, and the emit pass then allocates nothing — running out of
registers is an error, deliberately, rather than a second spilling allocator
disagreeing with the first. [src/arkham/design.md](../src/arkham/design.md) is
the full argument, including what the ABI, the frame layout and the pool-dry
paths cost.

Targets are chosen with `--os`/`--cpu`: `linux/amd64`, `windows/amd64`,
`linux/arm64`, `macosx/arm64`.

### `nifasm` — the assembler and linker

`src/nifasm`. An assembler with a static type system: its job is to catch code
generator bugs before they become runtime failures. That makes it far more
complex than a typical assembler, and also far more convenient — you get the
safety of a typed language with all the control an assembler offers. It computes
what is "easy enough" to compute (field offsets, stack slot offsets, frame
sizes) so those never have to be verified at all.

It also *is* the linker. Foreign modules are pulled in on demand by symbol
suffix, generic instances are deduplicated across modules, unreferenced symbols
are never generated, and the finished image is written directly: a static,
libc-free ELF on Linux, a Mach-O linked against libSystem on macOS, a PE with an
import table on Windows. `--emit-obj` produces a relocatable object for the
system linker instead (macOS arm64, Linux x86-64, Windows x86-64).

On Linux x86-64 that is how a program links foreign objects (Nimony's
`.compile`/`.link`) and libc: `nimony n -d:useLibc` runs `arkham --crt` and
`nifasm --emit-obj`, then the system linker. Everything the executable writer
resolves itself becomes a relocation instead (`image/writeelfobj.nim`): a
global's RIP-relative access is `R_X86_64_PC32`, an extern call
`R_X86_64_GOTPCRELX`, an absolute address in a rodata blob or a global's
initializer `R_X86_64_64`, and a thread-local's offset `R_X86_64_TPOFF32`. libc
owns the thread pointer then, and the program's thread-locals are one
`.tdata`/`.tbss` module of its static TLS block. With `--crt` arkham treats the
entry as crt's `main` (called, so biased like any callee, and returning its
status), declares each `importc` as a SysV `(extproc …)` and calls libc for it
rather than lowering it to a syscall. A static executable refuses an extern call
instead of leaving it unbound.

Windows x86-64 works the same way, with MinGW's gcc or clang as the system
linker: `arkham -a:win_x64 --crt`, `nifasm --emit-obj` (a COFF object,
`image/writecoffobj.nim`), then `gcc`. An `importc` without `dynlib` is legal
there and becomes a direct call the linker binds (libc through the crt's import
library, or a foreign object). One with `dynlib` calls through `__imp_<name>`,
so its import library must be on the link line. The crt calls `main` with the
Win64 convention, so nifasm emits a `main` stub that saves rdi/rsi/xmm6–15 and
calls `main.0` with its arguments in the internal registers. The crt also owns
the TLS directory: `_tls_index` replaces the image's own index cell, and the
program's thread-locals are one `.tls$` contribution to the crt's template. Their
offset in it would be a `SECREL`, but GNU ld also gives a `SECREL` in code a base
relocation, which ASLR then applies. So the stub stores `&.tls$ - &_tls_start` in
a cell instead, and every thread-local address adds it. Without `--emit-obj` a
`dynlib`-less extern is refused, as before.

[doc/nifasm.md](nifasm.md) is the language; [doc/instructions.md](instructions.md)
is the complete tag vocabulary.


## Also in this repository

* `src/ghast` — an experimental GPU code generator (Leng → SPIR-V), built on
  demand by nimony's `.build` pragma.
* `proofs` — a TLA+ model of the register-binding protocol between arkham and
  nifasm, with the bug classes it catches.
* `tools/gen_instructions.nim` — generates the tag/enum modules from the two
  vocabulary tables in `doc`.
