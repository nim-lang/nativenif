# nativenif

A native backend for **Leng**, the mid-level NIF dialect that
[nimony](https://github.com/nim-lang/nimony) compiles to. It turns a Leng module
into a running executable with no external toolchain: no GNU assembler, no
system linker, no LLVM.

`nimony n` uses it as its all-native code path. Leng itself is specified in
nimony's [doc/leng-spec.md](https://github.com/nim-lang/nimony/blob/master/doc/leng-spec.md).

## The pipeline

```
foo.c.nif  --[ arkham ]-->  foo.asm.nif  --[ nifasm ]-->  foo (executable)
  Leng                       typed asm-NIF
```

* **`src/arkham`** — the code generator: Leng in, typed asm-NIF out. Simple
  instruction selection over a register allocator that maps locals to registers
  in a pre-pass and never spills at emit time. See
  [src/arkham/design.md](src/arkham/design.md).
* **`src/nifasm`** — the assembler *and* the linker: it type-checks the asm-NIF,
  encodes it, and writes the finished ELF / Mach-O / PE image itself. See
  [doc/nifasm.md](doc/nifasm.md).

Targets: `linux/amd64`, `windows/amd64`, `linux/arm64`, `macosx/arm64`.

## Also here

* **`src/ghast`** — an experimental GPU code generator (Leng → SPIR-V).
* **`proofs`** — a TLA+ model of the arkham/nifasm register-binding protocol.

## Building and testing

The tools reuse nimony's NIF libraries, so nimony must be checked out as a
sibling directory (`../nimony`). Then, from the repository root:

```sh
nim c src/arkham/arkham.nim      # -> bin/arkham
nim c src/nifasm/nifasm.nim      # -> src/nifasm/nifasm
nim r tests/tester.nim           # builds both and runs the whole corpus
```

## Documentation

| | |
|---|---|
| [doc/nativenif.md](doc/nativenif.md) | how the pieces fit together |
| [doc/nifasm.md](doc/nifasm.md) | the assembler language: types, control flow, calls, modules |
| [doc/instructions.md](doc/instructions.md) | the complete asm-NIF tag vocabulary (generated from) |
| [doc/tracetable.md](doc/tracetable.md) | the runtime stack-trace table `getStackTrace()` reads |
| [src/arkham/design.md](src/arkham/design.md) | arkham's register strategy |
| [doc/internals/terms.md](doc/internals/terms.md) | glossary: `bridge`, `home`, `volatile`, `eightbyte`, … |
| [doc/internals/avr.md](doc/internals/avr.md) | the AVR target: register pairs, ABI, milestones |
| [doc/internals/rv32.md](doc/internals/rv32.md) | the RISC-V 32 target: no flags, hosted under qemu-riscv32 |
