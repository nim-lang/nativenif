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
system linker instead (macOS arm64).

[doc/nifasm.md](nifasm.md) is the language; [doc/instructions.md](instructions.md)
is the complete tag vocabulary.


## Also in this repository

* `src/ghast` — an experimental GPU code generator (Leng → SPIR-V), built on
  demand by nimony's `.build` pragma.
* `proofs` — a TLA+ model of the register-binding protocol between arkham and
  nifasm, with the bug classes it catches.
* `tools/gen_instructions.nim` — generates the tag/enum modules from the two
  vocabulary tables in `doc`.
