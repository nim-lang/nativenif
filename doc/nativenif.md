# Native NIF

`nativenif` is a toolchain to translate NIF code directly to machine code. No external tools are required, the system ships with an assembler and linker. Much complexity is avoided as the system is not based on ELF and DWARF but instead exploits NIF's many benefits.


# `nativeopt` - Native NIF Optimizer

The optimizer is based on NJVL. It consists of these passes (which are applied in this order):

1. Inliner. Inlines procs marked with `inline` and also inlines function calls it deems worthy. This includes the computation of inlining costs, explored callsite information and performs partial inlining.
2. Copy propagation. The goal of copy propagation is to detect a pattern like `var x = y; use x` and replace it with `var x = y; use y`. If no other uses of `x` exist, `var x = y` can be elided.
3. CSE: Common subexpression elimination. Also performs constant evaluation of expressions.
4. Induction variable detection. This typically leads to the simplification of address computations.


# `nativegen` - Native NIF code generator

The code generator's job is to translate the optimized NJVL to `nifasm` code. `nativegen` is a pretty simple code generator but it has an advanced register allocation strategy that avoids the complexities of "spilling" and is generally aware of x86's benefits and quirks.


# `nifasm` - Native NIF assembler

`nifasm` is an assembler with a static type system. Its job is to detect code generator bugs before they manifest as runtime failures. Thus it is much more complex than a typical assembler. But it is also much more convenient to use and you get the safety of a language like Nim with all the control an assembler offers!

`nifasm` produces binary machine code and also performs the linking step.

