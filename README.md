# nativenif

A native backend for **Leng**, the mid-level NIF dialect that
[nimony](https://github.com/nim-lang/nimony) compiles to. It turns a Leng module
into a running executable with no external toolchain: no GNU assembler, no
system linker, no LLVM.

`nimony n` uses it as its all-native code path. Leng itself is specified in
nimony's [doc/leng-spec.md](https://github.com/nim-lang/nimony/blob/master/doc/internals/leng-spec.md).

## The pipeline

```
foo.c.nif  --[ arkham ]-->  foo.asm.nif  --[ nifasm ]-->  foo (executable)
  Leng     \                 typed asm-NIF
            `-[ jorogumo ]->  web IR -+-[ w ]->  foo.wasm
                                      `-[ j ]->  foo.js
```

* **`src/arkham`** — the code generator: Leng in, typed asm-NIF out. Simple
  instruction selection over a register allocator that maps locals to registers
  in a pre-pass and never spills at emit time. See
  [src/arkham/design.md](src/arkham/design.md).
* **`src/nifasm`** — the assembler *and* the linker: it type-checks the asm-NIF,
  encodes it, and writes the finished ELF / Mach-O / PE image itself. See
  [doc/nifasm.md](doc/nifasm.md).
* **`src/web`** — the web back end: ONE code generator from Leng to a typed
  tree (the web IR), and two renderers of that tree — wasm32 bytecode and
  JavaScript text. `src/jorogumo` is the one tool over it: `jorogumo w` writes
  a self-contained `.wasm`, `jorogumo j` a self-contained `.js`. Codegen and
  link in one tool, because a whole-program module *is* the link step. See
  [doc/web.md](doc/web.md).

Targets: `linux/amd64`, `windows/amd64`, `linux/arm64`, `macosx/arm64`,
plus the bare-metal `arm32` / `riscv32` / `avr` ones, `wasm32` and JavaScript.

## Also here

* **`src/ghast`** — an experimental GPU code generator (Leng → SPIR-V).
* **`proofs`** — a TLA+ model of the arkham/nifasm register-binding protocol.

## Building and testing

The tools reuse nimony's NIF libraries, so nimony must be checked out as a
sibling directory (`../nimony`). Then, from the repository root:

```sh
nim c src/arkham/arkham.nim      # -> bin/arkham
nim c src/nifasm/nifasm.nim      # -> src/nifasm/nifasm
nim c src/jorogumo/jorogumo.nim  # -> bin/jorogumo (both web renderers)
nim r tests/tester.nim           # builds them all and runs the whole corpus
```

## Documentation

| | |
|---|---|
| [doc/nativenif.md](doc/nativenif.md) | how the pieces fit together |
| [doc/nifasm.md](doc/nifasm.md) | the assembler language: types, control flow, calls, modules |
| [doc/instructions.md](doc/instructions.md) | the complete asm-NIF tag vocabulary (generated from) |
| [doc/tracetable.md](doc/tracetable.md) | the runtime stack-trace table `getStackTrace()` reads |
| [src/arkham/design.md](src/arkham/design.md) | arkham's register strategy |
| [doc/web.md](doc/web.md) | the web back end (wasm32 + JavaScript): the web IR, lowering model, host ABI, verification |
| [doc/internals/terms.md](doc/internals/terms.md) | glossary: `bridge`, `home`, `volatile`, `eightbyte`, … |
| [doc/internals/avr.md](doc/internals/avr.md) | the AVR target: register pairs, ABI, milestones |
| [tests/arkham_rv32/README.md](tests/arkham_rv32/README.md) | the RISC-V 32 target: bare-metal RV32IMAFD under qemu-system-riscv32, and what its corpus shares with Cortex-M |
