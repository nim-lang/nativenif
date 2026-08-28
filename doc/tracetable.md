# The runtime stack-trace table

`.eh_frame` (see `src/nifasm/image/dwarf.nim`) tells a *debugger* how to walk our
stack. This tells the *program itself*. It is what `getStackTrace()` reads —
nimony's `lib/std/stacktraces`.

## Why not just parse the CFI

Because we do not have to. A runtime DWARF-CFI unwinder is a known quantity,
and it is also a few hundred lines of state machine, living in the standard
library, that must run correctly while the program is already in trouble.

Every fact it would recover is a **constant** here, because of the property
`src/arkham/design.md` states and `dwarf.nim` already leans on:

> **The frame is fixed.** The prologue lowers SP once and SP is constant until
> the epilogue.

So "where is my return address" is a per-PROC number, not a per-PC program. One
`u32` per proc replaces the interpreter, and the walk becomes repeated address
lookup:

```
slot = <address of the caller's return-address slot>
loop:
  pc  = *slot                      # a code address in the frame above
  e   = lookup(pc)                 # binary search this table
  emit e.name
  slot = slot + e.cfaOff           # ... and the next frame's slot
```

`cfaOff` is the DWARF CFA offset in the proc's body (`CFA = SP + cfaOff`). Since
the return address sits at `CFA - 8` on x86-64 and a `call` pushed it at
`SP - 8`, the same number is also the distance from one frame's return-address
slot to the next one's — which is why the loop needs nothing else.

## Layout

One blob at the end of `.text`, everything inside it self-relative:

| | field | |
|---|---|---|
| Header | `u32 magic` | `'N','T','R','C'` (`0x4352544E`) |
| | `u32 version` | 1 |
| | `u32 count` | number of entries |
| | `u32 entrySize` | 16 |
| Entry[count] | `i32 codeOff` | proc start, **as a distance from the table** |
| sorted by `codeOff` | `u32 codeLen` | proc length in bytes |
| | `u32 cfaOff` | `CFA = SP + this`, anywhere past the prologue |
| | `u32 nameOff` | distance from the table to a NUL-terminated name |
| names | | in entry order |

Two consequences of "distance from the table" rather than "address":

- **No relocation, on any of the three formats.** The reader gets the table's
  address from a RIP-relative `lea`, so it is right under PIE, ASLR and whatever
  base the loader picks. An absolute-pointer table would need a `.reloc`
  section on PE that nifasm does not otherwise emit.
- **The table is written after layout and read before anything moves.** Only its
  SPACE is reserved before the jump shortener and the alignment pass run (so the
  label that addresses it moves with the code); `fillTraceTable` writes the bytes
  once every proc's final position is known.

The blob's final alignment is therefore whatever the layout passes leave it at.
Every field is a `u32` and both supported targets permit unaligned word loads, so
the reader does not depend on it.

`codeLen` is the proc's whole extent *including* any alignment padding that
follows it — the same extent `.symtab` reports — so an address in the padding
attributes to the proc before it rather than to nothing.

## How it gets emitted

Only when something references it, so a program that never asks for a stack
trace carries none of this:

1. nimony's `lib/std/stacktraces` calls the `TraceTable` intrinsic
   (`nimony/src/lib/intrinsics.nim`).
2. arkham lowers `(instr traceTable.0)` to `(lea D (lab arkham.traceinfo.0))`.
3. nifasm owns that label: it defines the symbol up front (so the reference
   resolves like any other label), notes the reference, and appends the blob
   after all reachable code has been generated.

`--no-debug-info` does **not** turn it off. That flag governs what a debugger
reads out of the file; this is a program feature, and a program that asks for it
must get it.

## The seed: `{.naked.}`

The walk above starts from "the address of my caller's return-address slot", and
a proc with a prologue cannot produce that — by the time its first instruction
runs, SP has already moved and describes its own frame.

A `{.naked.}` proc emits no prologue and no epilogue, so on entry SP still points
exactly at the return address the `call` pushed:

```nim
proc callerFrame(): pointer {.assembler, naked.} =
  result = stackPointer()
```

`{.naked.}` is only legal together with `{.assembler.}`, and arkham rejects the
three ways a naked body could still need the frame it just gave up: an allocated
(non-`assembler`) body, a `{.stack.}` local, and a callee-saved register whose
`push` never happened.

## What is missing

- **Line numbers.** The table names procs, not source positions. Adding them
  means a second side table (or a DWARF line program) and is a separate piece of
  work.
- **AArch64.** The table is emitted on every target — `cfaOff` is collected the
  same way — but the walk in `lib/std/stacktraces` is x86-64 only, and the
  `TraceTable` row's `targets` says so. AArch64 needs the link-register case: a
  leaf proc's return address is in `x30` and not on the stack at all.
