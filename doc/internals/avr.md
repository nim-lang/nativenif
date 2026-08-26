# AVR support

Status: **M0–M4d complete.**

| Milestone | State |
|---|---|
| M0 target contract | done — `tools/avr_probe.nim`, 18 checks |
| M1 arch + word-size plumbing | done — `Arch.Avr`, `TargetArch.Avr`, `Word16` |
| M2a encoder + relocations | done — `src/nifasm/avr/encoder.nim`, 59-check self-test |
| M2b ELF32 image writer | done — `src/nifasm/image/writeavr.nim` |
| M3 assembler integration | **working** — 6 fixtures run end to end |
| M4a arkham machine model | done — `src/arkham/avr/machine.nim` |
| M4b arkham driver + the return path | done — the program walk and the exit path |
| M4c the value core | done — 8 Leng fixtures run end to end |
| M4d aggregates, arrays, pointers | done — 5 more Leng fixtures |
| M4e aggregate parameters and returns | done — a hidden result pointer |
| M5a scalar globals | done — SRAM storage, values stored at entry |
| M5 wide scalars, stack arguments, divide | not started |
| M6 aggregate globals, flash constants, interrupts | not started |

### What M4c has

`src/arkham/avr/gen.nim`, driven by the arch-neutral `allocateProc`. Locals in
pairs or frame slots, 16-bit arithmetic and logic, the multiply, shifts by a
constant, comparisons both as values and as branches, `if`/`while`/`break`,
calls with up to four register arguments, and recursion. Eight fixtures in
`tests/arkham_avr`, checked by `.exitcode` like every other corpus, including one
with twelve live locals — more than the seven callee-saved pairs, so the
allocator spills and every access goes through `Y+q`.

**It is a destination-passing walker, not a fused decide-and-emit.** The other
two backends thread a `Location` constraint through the walk, which buys store
forwarding, in-place immediates and register-level fusion. This one takes a
concrete pair and materializes into it.

That is a deliberate trade. The fused core is four thousand lines whose
register-binding protocol has a formal model behind it, and the machine it would
be buying code quality for has 32 KB of flash and no pipeline to speak of. What
matters here is that the answer is right and that every gap is a diagnostic. The
optimizations are recoverable later; a wrong 16-bit carry is not.

**Totality without a spiller.** An operand that has to be computed rather than
read is parked in a frame slot the emitter mints, so the register demand of a
nested expression is constant: the destination, plus the staging bridge for the
one operand being loaded. That is why this core cannot run out of registers, and
why it needs none of the reserve/steal machinery the fused one has.

The one case worth naming, because it is easy to get wrong: `x - y` where the
destination already IS `y`'s home would compute `x` into `y` and then subtract
the result from itself. `classifyB` parks the second operand whenever its home
is the destination.

### Why M4 is not the Cortex-M arrangement

`generateM` is the AArch64 emitter driven with a different machine model, not a
second code generator — Thumb-2 and AArch64 share the asm-NIF vocabulary at the
instruction level, so a third target needed only a register file, a word size
and honest refusals.

**AVR cannot be reached that way**, and the reason is the thing that makes the
target interesting. One asm-NIF node is one 8-bit instruction here, so a 16-bit
add is `(add)` + `(adc)` on the halves and a 16-bit compare is `(cmp)` + `(cpc)`.
That decomposition has to happen inside the value core, and the value core is not
layered over a primitive emitter a machine model could redirect: `x64/value.nim`
and `arm/value.nim` emit directly in 114 and 143 places respectively.

So AVR needs its own value core. That is the irreducible piece
[module_layout.md](module_layout.md) measures at roughly four thousand lines per
backend, and the piece whose register-binding protocol has a formal model behind
it. It is M4c, and it is the largest single item left on this list.

The register ALLOCATOR is reusable as it stands — `planer.allocateProc` is
arch-neutral and takes a `MachineDesc` — so M4c is the emitter, not the
allocator.

### What M4b has

The spine: the program walk, the proc signature, the ABI clobber list emitted at
the signature, and the entry proc's exit path. A proc whose body is `ret <const>`
compiles, assembles and runs — `tests/arkham_avr`, two fixtures with `.exitcode`
files, driven exactly like every other target's corpus.

Everything else is refused BY NAME with the milestone that covers it, and
`tester.nim`'s `arkhamAvrRejections` pins the refusals. That is the property that
makes a partial backend safe to ship: the gap has to be a diagnostic rather than
a wrong answer.

The entry proc's `ret` becomes `(bkpt 30)` rather than a return, for the reason
Cortex-M's becomes a semihosting `SYS_EXIT_EXTENDED`: this is a freestanding
image and there is nothing to return to, so the entry's result IS the exit
status.

### What M3 has

`src/nifasm/avr/` — `regs.nim`, `operands.nim`, `instr.nim` — assembles
hand-written AVR asm-NIF into a firmware image that runs under AVRtest and exits
with a value it computed. Six fixtures in `tests/tester`: the ALU, an `ite`, a
`loop` closed by a forward `beq`, a frame with a slot addressed through Y, a
proc call with register arguments, and a `hello` that prints.

Implemented: the typed operand model over the `(rN)`/`(rpN)` tag set, the
`avrRegBindings` table and `clobberedAvr` call-clobber tracking, `(var …)` in a
register, a pair or a stack slot, every ALU form, the one-bit shifts,
`movw`/`adiw`/`sbiw`, `ldb`/`stb`/`ldpi`/`stpi`/`inb`/`outb`/`lpm`, the skips,
`ite`/`loop`/`jtrue`/`lab`, the branches, `(proc …)` with register parameters,
`(prepare …)`/`(call)`/`(arg …)`/`(res …)`, and `(ssize)`-sized frames.

### What M3 still needs

* **Stack-passed arguments** are rejected by name. Four pairs go in registers;
  the rest need the incoming-argument area, which is `Y + framesize + 5` — a
  distance only the frame patch knows, so the `ldd` displacement would have to
  be a patch site of its own.
* **A frame over 63 bytes** is rejected by name, twice over: `adiw`/`sbiw` carry
  the frame size in six bits, and 63 is also the whole displacement range of
  `ldd`/`std`. A larger frame needs the pointer advanced, which is not one
  instruction.
* **A global's initial value is a STORE, not an image** (M5a). Everywhere else
  in this tree the initializer is baked into a writable segment and the loader
  maps it, and `.bss` is zero because a segment whose `p_memsz` exceeds its
  `p_filesz` is zero-filled by definition. On a chip there is no loader: the
  writable space is SRAM, whose contents at reset are whatever the last power
  cycle left there, and the bytes would have to ship in FLASH and be copied
  across — a different address space, reached by `lpm`. So the entry proc's
  preamble stores every global's initial value, zero included, and nothing in
  the image is relied on to be anything. An AGGREGATE global is refused by name
  for the same reason: its image would be hundreds of stores, and copying it
  from flash is M6.
* **A global's ADDRESS is two `ldi`s**, spelled `(lea D <gvar>)` and patched by
  the image writer once the SRAM block is placed — the same exception `(ssize)`
  and a frame slot's displacement live under. It reaches r16..r31 only, which
  `ldi` decides and not this backend.
* **A rodata blob's address is refused.** It is a FLASH address, and a `ld`
  through it would read SRAM at the same number — so the value is never
  produced rather than produced and misused. Reading one needs `lpm`, which is
  M6, and it is why a string literal is refused too.
* **A comparison carries no type child**, unlike `(add T a b)` — and this
  backend read one anyway until the RV32 corpus sweep found the same mistake in
  its twin. See doc/internals/rv32.md; the fix is shared in shape if not in code.
* **A narrow local is loaded and stored at its own width.** The two-byte form
  reads `name+1` as the high half, and for an `(i 8)` local that byte belongs to
  whatever the slot manager put next to it. A signed byte is widened with
  `sbrc`+`com`, which is how this machine spells a conditional one-instruction
  fixup — there is no `sxtb` here.
* **A conditional branch always costs two words**: the direct form reaches ±128
  bytes and the assembler cannot know the distance when it emits one, so it
  inverts the condition and branches over an `rjmp`. Shrinking that back down is
  a relaxation pass, exactly like `x64/relax.nim`.

### Two things M3 changed outside the AVR tree

**AVR's register tags are escaped.** They are numbered past the 511 that fit
NIF's 9-bit tag field — see `LateEnums` in `tools/gen_instructions.nim` for why
AVR pays for its own register file rather than pushing the current targets'
mnemonics over — so `(rp24)` arrives spelled through the `(other …)` escape with
its real id in a leading child. Every site that reads a register tag therefore
has to use the RESOLVED `n.tag` rather than `rawTag`, and step past such a node
with `skip` rather than `inc`. The other targets never met this because all
their register spellings predate the overflow.

**`(lo S)` and `(hi S)`.** A 16-bit value lives in a pair and every ALU
instruction works on one half, so a 16-bit add is `(add (lo d) (lo s))` then
`(adc (hi d) (hi s))`. Naming the halves is what lets that be written at all:
spelling `(r25)` raw is rejected by the binding table, and rightly — it cannot
tell that the register is the top of some local.

### Pointers and aggregates

A pointer is an ordinary value; `(addr x)` is the address of a local, which the
analyser has already forced into a frame slot by marking it `AddrTaken`.

**The offsets are nifasm's to compute, not arkham's.** A `(dot p f)` or
`(at a 2)` is re-emitted as an asm-NIF memory operand of the same shape and
folded by the assembler, which has the layout — the same division x86-64 already
uses. So a field access is ONE instruction, and arkham never learns a field
offset at all. A computed index is the exception: there is no scaled address mode
on either of these machines, so arkham emits the shift and the add itself.

Constructors are built from PARTS rather than copied from a node, because a
constructor's destination is not written anywhere in the input — `(oconstr …)`
names the fields and the local, never the access. They are also TOTAL: sem names
every field of the type, so nothing has to be zeroed first.

The bug worth recording: scaling a variable index in place destroys the index.
`materializeB` may hand back a local's HOME register, and `a[i]` shifted it left
by two — so the read got the wrong element AND `i` came back multiplied by four.
`scaledIndex` copies into a bridge first whenever the index is not already in one.

### What the RV32 sweep found here too

Three of the bugs `rv32CorpusSweep` turned up were in code this backend shares
the shape of, and were fixed in both: parking a binary op's second operand into
the destination (which destroys the local whose home it is), taking a nested
array's VALUE where its address was wanted, and asking a tag for its symbol name
when an object contains a union. AVR has no corpus wide enough to have found
them on its own — its word is 16 bits, so the 32-bit fixtures refuse on width
long before they reach any of this.

## Target

| | |
|---|---|
| Spelled | `-a:avr` |
| Core | **avr5** — the ATmega328P/ATmega32 class |
| Why this one | It is what "AVR" means in practice: every Arduino Uno-class part, and the whole ATmega range. It has `mul`, `movw`, `lpm`, `jmp`/`call` and the displaced load/store, which is the instruction set everything below assumes. |
| Not this one | `avr2`/`avr25` (ATtiny) lack `mul` and sometimes `movw` — the two instructions the register model is built on. `avr6` (ATmega2560) adds `EIND` and 3-byte return addresses, which changes the frame, not the code generator. Both are later flags, not separate backends. |
| Word | **2 bytes.** A pointer, an `int` and a logical register are all 16 bits. |
| Flash | Harvard: program memory is a separate address space reached only by `lpm`. See "Constants" below. |
| Divide | None, in any form. M5. |
| Float | No FPU. Not planned. |

## Test host

```
bin/avrtest -q -mmcu=avr5 -s 32k image.elf
```

[AVRtest](https://github.com/sprintersb/atest) — the simulator the AVR-GCC test
suite runs. It is not packaged, and does not need to be: it has no dependencies
beyond a C compiler and `bin/` is gitignored, so it is built in place.

```
git clone --depth 1 https://github.com/sprintersb/atest.git
make -C atest && cp atest/avrtest atest/avrtest_log bin/
```

(`make` also tries to build its own test suite against `avr-gcc` and prints
`... not supported by avr-gcc` when that is absent. The simulators are built
regardless; the messages are harmless.)

It is chosen for the same reason Cortex-M is tested through semihosting rather
than through an emulated UART: it provides an exit STATUS and a character sink
directly, so a fixture's oracle is the value it computed.

The interface is a pseudo-instruction. `SYSCALL N` is `CPSE rN, rN` followed by
the invalid opcode `0xFFFF` — "always skip the thing that would trap" — which
the simulator recognises and real silicon merely skips. Two of the 32 matter
here:

| | |
|---|---|
| `SYSCALL 29` | `putchar(r24)` |
| `SYSCALL 30` | `exit(r25:r24)`, forwarded as AVRtest's own process exit status |

`-q` is what makes the status pass through; without it AVRtest prints a summary
and exits 0.

The two apt-installable alternatives were rejected on the same point.
`qemu-system-avr` has no semihosting on AVR at all: stdout would need a real
USART driver in the runtime and there is no exit channel, so every fixture would
need a sentinel in its output plus a timeout to kill the process. `simavr` exits
only on "sleep with interrupts off" or on a crash, so it cannot carry a computed
status either.

`binutils-avr` is not required, but `avr-objdump -b binary -m avr5 -D` is the
encoding oracle the Cortex-M work never had, and is worth having installed.

## A pair is one register

AVR has 32 8-bit registers. The backend treats **an even-aligned pair as one
logical 16-bit register**, so `Reg` slots `R0..R15` map onto `r1:r0 .. r31:r30`.

This is not a fiction imposed on the machine. `movw` copies a pair in one
instruction, `adiw`/`sbiw` add and subtract a small constant on a pair, and the
three pointer registers X, Y and Z are pairs by construction. What the ISA does
*not* provide is a 16-bit ALU: an add is `add`+`adc`, a subtract is `sub`+`sbc`,
and the carry between the halves is the reason the two cannot be emitted
independently.

| `Reg` | AVR | `ldi` | `adiw` | pointer | role |
|---|---|---|---|---|---|
| `R0` | r1:r0 | | | | **reserved** — `mul` writes it, `lpm` reads into it, and r1 is the zero register |
| `R1`–`R7` | r3:r2 … r15:r14 | | | | callee-saved |
| `R8` | r17:r16 | ✓ | | | callee-saved |
| `R9`–`R11` | r19:r18 … r23:r22 | ✓ | | | volatile — arguments 3, 2, 1 |
| `R12` | r25:r24 | ✓ | ✓ | | volatile — **return value** and argument 0 |
| `R13` | r27:r26 = X | ✓ | ✓ | ✓ | **staging bridge** |
| `R14` | r29:r28 = Y | ✓ | ✓ | ✓ +q | **frame pointer** |
| `R15` | r31:r30 = Z | ✓ | ✓ | ✓ +q | **produce bridge** |

Three operand restrictions run through everything and are why the table is not
uniform:

* **`ldi` reaches only r16..r31**, i.e. slots `R8..R15`. A constant destined for
  a low pair goes through a high one and a `movw`. The allocator's volatile pool
  is therefore entirely `ldi`-capable, and the low callee-saved pairs receive
  their values by `movw` rather than by materialization.
* **`adiw`/`sbiw` reach only the four upper pairs**, and only 0..63. Pointer
  arithmetic that stays in `R12..R15` is one instruction; anywhere else it is
  `subi`+`sbci`, which is two and needs an `ldi`-capable register anyway.
* **Memory is addressed only through X, Y or Z**, and only Y and Z have a
  displaced form (`ldd rd, Y+q`, q in 0..63). That is three pointer registers
  for the whole machine, one of which is the frame pointer. X and Z are
  therefore the bridges — withheld from every allocation pool — and not
  candidates for it: a target with three address registers cannot also let
  values live in them.

r1 must hold zero. `mul` destroys it, so every `mul` is followed by a `clr r1`;
this is AVR-GCC's convention and there is no cheaper one, since `sbc`-style
sequences need a known-zero register and no other is free.

## asm-NIF stays 8-bit

The pair abstraction lives **entirely in arkham**. asm-NIF for this target names
the 32 real 8-bit registers, and every instruction node is one AVR opcode.

This follows from the policy that nifasm never invents instructions: an
`(add (w9) (w10))` on a logical pair would have to become `add`+`adc`, which is
a lowering, in the assembler, of an operand the code generator supplied. So a
16-bit add is two nodes that arkham emits, and nifasm assembles what it is
given.

The exception is the forms that genuinely *are* one instruction on a pair —
`movw`, `adiw`, `sbiw`, and the pointer-register operands. Those take a pair
tag, which doubles as the unit nifasm binds a 16-bit name to, so the register
binding table still tracks a logical register rather than two halves that happen
to be adjacent.

## Calling convention

AVR-GCC's, restricted to what the pair model expresses:

| | |
|---|---|
| Arguments | `R12`, `R11`, `R10`, `R9` (r25:r24 down to r19:r18), then the stack |
| Return | `R12` |
| Callee-saved | `R1`–`R8` (r2..r17), plus Y |
| Volatile | `R9`–`R12`, plus X and Z |
| Aggregate return | by hidden first argument, as on x86-64 — not a dedicated register, of which there is none to spare |
| Frame | `BlockFrame`: SP lowered once, one `push` per saved register. Y is the frame pointer, and unlike the Cortex-M case a real one — every stack slot is reached as `Y+q`, because SP itself cannot address memory at all. |

Saving a callee-saved pair costs two `push`es and two `pop`s, so four
instructions per pair. That is expensive enough that the planner should prefer
the volatile pool for a call-free local exactly as x86-64 does, even though
callee-saved is the larger class here.

## Where AVR sits in the arch branches

`TargetArch` gains `Avr`. The `md.arch` tests in the planner and the machine
model are few, and AVR answers **like `X86` at all but one of them** — the ALU
is destructive and two-operand, the return register is an ordinary scratch, and
an aggregate return goes by a hidden first argument.

The exception is the memory-bridge question (`machinedesc.scratchDemand`), where
it answers like `Arm64`: there is no store-immediate and no PC-relative data
operand, so an immediate, a global and a thread-local each pass through a
register on the way to a stack home.

## Constants

A string literal or a `rodata` blob lives in **SRAM**, copied from flash by the
startup code, and is read with ordinary `ld`. Putting it in flash would save the
RAM but make every read of it a different instruction (`lpm`) selected by where
the pointer came from — a distinction Leng does not draw and the type system
here has no way to carry. AVR-GCC makes the same default choice and offers
`PROGMEM` as the opt-out; an equivalent is M6, not a precondition.

## What M2b established

`src/nifasm/image/writeavr.nim`. Two things differ from every other image writer
here.

The **reset vector is an instruction**, not an address: an AVR core begins
executing at flash 0, so word 0 is a `jmp` to the entry proc. `e_entry` in the
ELF header stays 0 for the same reason — a real part reads no ELF header, and
declaring the proc's address there would work under a simulator that honours it
and fail on silicon.

Those four bytes are also why `buf.absBase` is `ResetVectorBytes`: a label's
position is measured inside the code buffer, which does not contain the vector,
while the image prepends it. Without that every `call` resolves four bytes low —
two words on this machine, so it lands on a real instruction inside the intended
proc and runs. That is precisely the bug the first `avr_call` run had.

`writeElf32` grew `machine`/`flags`/`entryTag` parameters, all defaulting to what
ARM already passed. `entryTag` is the interesting one: bit 0 of an ARM code
address is the Thumb-state marker, and the same bit here would name an odd
address, which is not an instruction address at all.

## What M2a established

`src/nifasm/avr/encoder.nim` is dependency-free, in the shape of
`thumb/encoder.nim`: `emitXxx(dest: var Bytes; …)` for everything that needs no
relocation, `emitXxx(dest: var Buffer; …; target: LabelId)` for everything that
does. Six relocation kinds carry the word-vs-byte conversion that is this
target's signature hazard, and their reach is short enough to matter:

| kind | form | reach |
|---|---|---|
| `rkAvrBrcond` | one word, all 14 conditions | ±128 **bytes** |
| `rkAvrRjmp` / `rkAvrRcall` | one word | ±4 KB |
| `rkAvrJmp` / `rkAvrCall` | two words, absolute | all of flash |
| `rkAvrLdiAddr` | an `ldi` pair carrying a data address | none |

`tests/avr_selftest.nim` builds one image that computes 59 expressions and exits
with the index of the first wrong one. It then rebuilds that image 59 more times
with one check's *expected* value corrupted each time, and requires every one of
those runs to fail with exactly that index — so a check whose emitter writes no
bytes, or which compares against a value the harness itself left in the pair,
cannot pass quietly. `tests/tester` runs the whole sweep.

It has already earned its keep. `ld rd, Z` was encoded on the 0x9000 opcode,
where the plain `ld` exists only for X; on Y and Z it is the `q = 0` case of
`ldd`, on 0x8000. The wrong value is `lds` — a two-word direct load that
swallows the following instruction as its address operand.

## What M0 established

`tools/avr_probe.nim` hand-builds an ELF32 that self-checks 18 encodings and
exits with a value it computed. Each check exits with its own 1-based index on
mismatch, so a failure names the broken encoding. It predates the backend on
purpose: if it stops working, the fault is in the target contract, not in the
code generator.

```
nim c -o:bin/avr_probe tools/avr_probe.nim
bin/avr_probe /tmp/probe.elf 42
bin/avrtest -q -mmcu=avr5 -s 32k /tmp/probe.elf ; echo $?    # 42
```

Covered: the ELF shape (`EM_AVR`, one PT_LOAD at flash 0), both AVRtest
syscalls, `ldi`/`movw`, `add`+`adc` and `sub`+`sbc` across the halves,
`subi`/`sbci`, `adiw`/`sbiw`, the `com`/`neg`/`sbci` negation, `lsl`+`rol` and
`asr`+`ror`, `mul` and its r1 fixup, all three pointer registers including
`Y+q`, `sts`/`lds`, `push`/`pop`, `rcall`, the 32-bit `call`, `ret`, and a
backward `brne` loop.
