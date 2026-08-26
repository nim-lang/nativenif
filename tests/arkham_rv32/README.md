# `tests/arkham_rv32` — the RV32 Leng corpus

Each fixture compiles with `arkham -a:rv32`, assembles with `nifasm`, and runs
under `qemu-riscv32` with the exit code in its `.exitcode` file.

Eight of them are the AVR corpus with `(i 16)` rewritten to `(i 32)` — the same
programs on a machine with four times the word and thirty registers instead of
sixteen pairs, which is exactly the comparison worth having. `divmod` and `wide`
are RV32's own: a divide and a modulo, which AVR has no instruction for at all,
and a constant that needs `lui`+`addi`.

What is NOT here is aggregates, wide scalars, floats and globals — all refused by
name. See `doc/internals/rv32.md` for what R5 covers.
