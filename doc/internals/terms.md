# Terms used in this codebase

A glossary, not a tutorial. Each entry says what the word means *here*; the
module named after it is where the real explanation lives.

For the file layout these names live in, see
[module_layout.md](module_layout.md).

## The pipeline

**NIF** — the token/tree format everything is written in. Text on disk,
cursors in memory.

**Leng** — the mid-level NIF dialect nimony compiles to. arkham's input
(`foo.c.nif`, or `foo.oc.nif` when nimony's optimizer ran).

**asm-NIF** — typed assembly, still NIF. arkham's output and nifasm's input.
Registers, memory operands and instructions are tags; locals are named and
typed, so nifasm can type-check them.

**arkham** — `src/arkham`. Leng in, asm-NIF out. The code generator.

**nifasm** — `src/nifasm`. asm-NIF in, an executable out. Type checker,
assembler and linker in one; emits ELF, Mach-O, PE or a bare-metal ELF32
firmware image.

**ghast** — `src/ghast`. An experimental GPU code generator (Leng to SPIR-V),
run as a separate process the same way nifasm is.

**target** — an OS/CPU pair, spelled `x64`, `win_x64`, `arm64`,
`linux_arm64`, `cortex_m`.

## Registers

**volatile** / **caller-saved** — a register a call may destroy. A value that
must outlive a call cannot stay in one.

**callee-saved** — a register a callee must restore before returning. Where a
value that outlives a call goes; the prologue saves it and the epilogue
restores it.

**argument register** — where the ABI puts argument *n*. Also the return
register for argument 0.

**indirect result register** — where the caller leaves `&result` for an
aggregate return too wide for registers. x8 on AArch64, r9 on Cortex-M; on
x86-64 it is a hidden first argument instead.

**bridge** — a register withheld from every allocation pool so the emitter can
always take a transient without asking the allocator. Because no value ever
lives in one, nothing has to prove that a use of it is safe. AArch64 has
x14/x15 plus x16; Cortex-M has r10/r11 plus r8; x86-64 reserves r11 alone
(`stagingBridgeReg`) and has no bridge list.

**staging bridge** — a bridge used to hold a value in transit: a memory
operand a three-operand ALU has to load first, a global's address, an operand
of a compare whose other operand also spilled.

**produce bridge** — the bridge used to stage a value on its way *into* memory:
x16 on AArch64, r8 on Cortex-M. Always the last entry of the bridge list.

**float bridge** — the SIMD/FP counterpart: v31 on AArch64, s31 on Cortex-M.
x86-64 keeps xmm15 for the same job as a backend constant rather than a machine
model field.

**reserved register** — one arkham never allocates because something else owns
it. On AArch64: x16/x17 (the assembler's veneers), x18 (the platform
register), x8 (indirect result), fp, lr and sp.

**scratch** / **temp** — a register holding a value with no name, for the
length of one expression. Drawn from the volatile temp pool, or from a bridge
when the pool is dry.

**survivor** — a scratch that has to outlive a call, so it must be
callee-saved rather than volatile.

**accumulator** — a register a chain of arithmetic is being built up in. Marked
live so nothing else takes it mid-chain.

**clobber** — a register a call or an instruction destroys. Declared per proc
in asm-NIF (`(clobber (rax) …)`), so a custom convention is expressible and
nifasm can check reads against it.

## Where a value lives

**home** — the place a named local lives for its whole life: a register or a
stack slot. Decided once, by the planner, before any code is emitted.

**Location** — the record describing where a value is or must go. `InReg`,
`NamedStack`, `Glob`, `Imm` and so on. Also used as a *destination constraint*
(`NeedsReg`, `RegOrImm`, `Undef` = caller does not care), filled in with the
concrete answer by the code that satisfies it.

**slot** (`AsmSlot`) — a Leng type reduced to what code generation needs: value
class, size, alignment. Drives register-class and width decisions.

**stack slot** — a named, typed stack location. Written `(s)` in asm-NIF
instead of a register tag; nifasm computes the offset.

**`(ssize)`** — the frame size of the current proc. nifasm patches it once the
body is assembled, since the peak is not known before then.

**`(csize)`** — the stack-argument area the current call needs. Same idea, per
call site.

**spill** — moving a value out of a register into a stack slot because the
register is needed. A *spill temp* is a slot minted for one, named `etmp`,
`eftmp` or `held`.

**park** — keeping a value that would otherwise be clobbered in a callee-saved
register across a call (the hidden result pointer, for instance).

**steal** — taking a register back from a local that already had it as its
home, at plan time. The local's home is rewritten in one place, so every use
follows.

**demote** — undoing a register home entirely: the local's home becomes a stack
slot.

**mirror** / **store forwarding** — after `mov [x], r`, the value is in two
places, so reading `x` back can use the register. The mirror map records that,
and every way it stops being true (register rewritten, memory rewritten, call,
scope exit).

**arg-resident** — a parameter left in the register it arrived in, rather than
moved to a home, even though the proc makes calls. The binding lives until the
call that consumes the parameter.

**narrow home** — x86-64 only: a home written and read as a raw `(reg)` rather
than a name, so the temp filter needs to know about it specifically.

## The passes

**analyser** — pass 1. Counts definitions and uses per local, and records what
would disqualify it from a given register class.

**plan** / **planer** — pass 2. Gives every local a home. Keyed by token
*position*, not by name; a name is an alias for the position of its
declaration.

**phase A / phase B** — the two halves of allocation. Phase A (the planner)
places declarations by name; phase B (the emitter) takes expression temps by
position. Phase B reads what phase A settled and can never perturb it.

**value core** — the emitter's recursive middle: value, lvalue and store
emission. One strongly connected component of ~50 routines per backend, which
is why it is one module (`x64/value.nim`, `arm/value.nim`).

**decide-and-emit** — the value core's shape: one walk that chooses where a
value goes and emits it, rather than a decide pass followed by an emit pass.

**prematerialise** (`premat`) — emitting the address parts of an lvalue into
registers *before* walking the tree that uses them, so the operand can be
folded into one instruction.

**produce-into-memory** — emitting a value directly into a stack slot instead
of a register, taken when no register is available.

**condition fusion** — recognising a bool that is only ever branched on, so the
compare's answer travels in the flags and the `setcc` that would build the bool
is never emitted.

**select diamond** — `if c: x = a else: x = b`. Recognised so it can become one
branchless instruction: `csel` on AArch64, `cmov` on x86-64.

**peephole** — rewrites over the finished asm-NIF, between the emitters and the
render.

**stress mode** — `-d:arkhamStress` / `ARKHAM_STRESS=k`. Shrinks the register
file so the existing test corpus reaches the pool-dry paths.

## asm-NIF vocabulary

**binding** — the association of a physical register with a typed name. nifasm
tracks it, so reading a register whose binding a call destroyed is an error
rather than a wrong answer.

**`rebind`** — bind a register to a name and type, ending whatever binding it
had. **`withreg`** does the same for the extent of a block. **`kill`** ends a
binding.

**`prepare`** — the block that sets up a call. Arguments are written to
`(arg <name>)` by name, then a `(call)`, `(tailcall)`, `(extcall)` or
`(syscall)` marker, then results are read from `(res <name>)`. Naming both is
what lets nifasm check that every parameter was supplied exactly once.

**`ite`**, **`loop`**, **`jtrue`**, **`lab`**, **`scope`** — the structured
control flow. Every emitted branch goes forward; a back edge must be `(loop)`.

**`gvar`** / **`tvar`** / **`rodata`** — a global, a thread-local, a read-only
data blob.

**`extproc`** — a proc imported from a dynamic library. **`syproc`** — a proc
that is really a syscall; the marker inlines the trap instead of calling.

**`lenient`** — a per-proc pragma that relaxes the structural checks, for
ported code whose register discipline predates nifasm's.

**escape tag** — asm-NIF has more tags than the 9-bit tag field holds, so ids
past 511 are written as `(other <id> …)`. Invisible on both sides.

## ABI

**eightbyte** — the word-sized granule the ABI classifier works in (8 bytes on
the 64-bit targets). An aggregate of two granules or less travels in registers;
a larger one goes by reference.

**HFA** — homogeneous float aggregate. On AArch64 it goes in SIMD registers
rather than GPRs.

**hidden result pointer** — the extra argument for an aggregate return too wide
for registers.

**shadow space** — 32 bytes a Win64 caller reserves below its outgoing
arguments for the callee to spill its four register arguments into. Reserved
for every call, whether or not it has arguments.

**call plan** — the one classification of a signature, produced once and read
by the allocator, both emitters and the marshalling code, so their register
counting cannot drift.

## Assembling and linking

**relocation** — a position in the code whose value is not known until layout:
a branch target, a global's address.

**relaxation** — shrinking `jmp rel32` to `rel8` once distances are known. A
fixpoint, since each shrink moves everything after it. x86-64 only
(`x64/relax.nim`).

**jump threading** — retargeting a branch whose target is itself a branch, and
deleting jumps to the next instruction.

**position map** — the old-to-new byte mapping each layout pass returns.
Everything the assembler still tracks (unwind rows, listing rows, patch sites)
is carried through it.

**pool** — the interned string/symbol table. A symbol's identity is its pool id
(`SymId`); names are turned back into strings only at the edges.

**foreign module** — another module a name refers to. Opened lazily: only the
embedded index is read up front, and a declaration is parsed when something
reaches it.

**dedup key** (COMDAT) — a generic instantiation's identity across modules, so
the same instantiation emitted by two modules is generated once.

**unwind** / **CFA** / **CFI** — the tables that let a debugger walk a stack
that keeps no frame pointer. `.eh_frame` on ELF, `.pdata`/`.xdata` on PE, where
the OS itself reads them.

**trace table** — the same per-proc facts in a form the running program can
read, for `getStackTrace`. See [tracetable.md](../tracetable.md).

**listing** — `--listing:FILE`. One row per instruction node in the *finished*
image, so a profile can be joined back to the construct that produced it.

## Cortex-M

**board** / **layout** — the `(layout …)` file describing a board's memory
regions, stacks, heap and where each section goes. See
[layout.md](../layout.md).

**interrupt table** — the architectural vector table at the image's head. Word
0 is the initial stack pointer (a value, not a handler), word 1 is reset. Words
0–15 are the architectural exceptions; a slot no handler claimed stays zero,
which faults rather than branching into whatever followed.

**mimg** — the layout numbers the startup code needs and only the image writer
knows: where `.data`'s initializer image sits in flash, where it belongs at run
time, how big `.data` and `.bss` are, and where the heap and the no-init region
start. arkham asks for them by name; nifasm patches the values in.

**semihosting** — how a firmware image with no OS prints and exits: a trap the
debugger or emulator services.

**wide / 64-bit lowering** — a 64-bit value on Cortex-M is eight bytes at an
address, read and written a word at a time. There are no register pairs.

## Testing

**corpus** — `tests/arkham/*.c.nif` and `tests/arkham_m/*.c.nif`, each with an
expected exit code and output.

**gate** — `tools/refactor_gate.sh`. Drives the whole corpus through both tools
for every target and hashes the results, so a change that must not alter output
can be checked byte for byte.

**fixture** — one test input.
