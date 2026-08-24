# Cortex-M support

Status: **M0, M1, M2a/b complete; M2c in progress.**

| Milestone | State |
|---|---|
| M0 target contract | done — `tools/cortexm_probe.nim` |
| M1 word-size parameterization | done — `slots.setTargetWord` / `sem.setAsmWordSize` |
| M2a Thumb-2 encoder + relocations | done — `src/nifasm/thumb2.nim`, 45-check self-test |
| M2b ELF32 firmware writer | done — `src/nifasm/elf32.nim` |
| M2c assembler integration | done — selector, frames, calls, marshalling |
| M3 arkham backend | **working** — 119 Leng fixtures run end to end |
| M4 64-bit integers | not started |
| M5 floating point | not started |
| M6 embedded features | not started |

### What M2c has

The instruction selector (`genInstM` in `assembler.nim`) works end to end:
`tests/hello_cortex_m.nif` and `tests/cortex_m_alu.nif` are assembled by nifasm
into firmware images that run under QEMU and exit with a value they computed.

Implemented: the typed operand model (`parseOperandM` / `parseDestM`) over the
`MReg` tag set, the `mRegBindings` register-binding table and `clobberedM`
call-clobber tracking, `(var …)` in a register or a stack slot, `mov`, `adr`,
2- and 3-operand ALU forms, `sdiv`/`udiv`/`mls`/`umull`/`smull`, the shifts,
extends, `clz`/`rbit`/`rev`, `cmp`/`tst`, every load/store width including the
sign-extending ones, `ite`/`loop`/`jtrue`, `b`/`bl`/`bx`/`blx`/`cbz`/`cbnz`,
`bkpt`, `ret`, `nop`, `wfi` and `kill`.

Frames and calls are in too: `(proc …)` with AAPCS32 register and stack
parameters, `(ssize)`-sized frames, `(prepare …)`/`(call)`, `(arg …)`/`(res …)`
marshalling, `(csize)`, and indirect calls through a register-held function
pointer. Four fixtures run under QEMU in `tests/tester`.

The frame follows AArch64's shape rather than x86-64's: the return address
arrives in LR, the caller leaves SP at the first stack argument, and the
outgoing argument area is reserved ONCE at the bottom of the frame so SP is
constant from prologue to epilogue.

`(ssize)` is emitted as a MOVW/MOVT pair with a zero immediate and patched once
the frame size is known. The pair is a fixed 8 bytes whatever the value, so
patching never resizes an instruction — and unlike the AArch64 path there is no
12-/16-bit immediate ceiling on the frame.

Globals, aggregates and indirect calls are in too. A `.bss` region is emitted as
a SECOND ELF32 segment at `SramBase` (0x20000000) while code stays at the flash
base, and `(adr D <gvar>)` materializes a global's ABSOLUTE address with a
MOVW/MOVT pair patched once that layout is fixed — the analogue of the AArch64
backend's adrp+add patch. `(dot …)` and `(at …)` fold onto a base+offset(+scaled
index) memory operand, nesting the way the other backends do.

`.bss` is emitted FILE-BACKED (filesz == memsz) rather than as NOBITS. That costs
image size but is correct everywhere: a NOBITS segment relies on the loader
zeroing it, which QEMU's `-kernel` does and a real chip emphatically does not.
Real firmware zeroes `.bss` in its reset handler — that startup code is M6, and
until it exists the two behave identically.

The stack grows DOWN from `DefaultStackTop` and the globals UP from `SramBase`;
they share one RAM region, so the writer errors when they would meet rather than
letting the first deep call frame quietly overwrite a global.

### What M2c still needs

Nothing structural. Remaining gaps are named at their sites:

* `extproc`/`syproc` are rejected: a bare-metal image has nothing to link
  against and no OS to call.
* 64-bit scalars and floats are rejected BY NAME (`checkRegWidthM`) rather than
  truncated; they are M4 and M5.
* An `(at …)` whose element stride is not 1/2/4/8 needs the 3-operand scratch
  form, exactly as on AArch64.

## Target

| | |
|---|---|
| Core | Cortex-M4F, **ARMv7E-M** (Thumb-2 only — there is no A32 state on M-profile) |
| Why this one | The dominant 32-bit MCU class: STM32F3/F4/L4, nRF52832/52840, SAMD51, Kinetis K, LPC4000. Binaries run unchanged on Cortex-M7 and M33; a Cortex-M3 subset is a config flag, not a second backend. |
| Not this one | Cortex-M0/M0+ is ARMv6-M: no `sdiv`/`udiv`, crippled high registers, 16-bit Thumb-1 subset. That is a separate backend, not a subset of this one. |
| ABI | AAPCS32 — r0–r3 args/return, r4–r11 callee-saved, r12=IP scratch, r13=sp, r14=lr, r15=pc. 4-byte word, 8-byte stack alignment at public interfaces. |
| Divide | `sdiv`/`udiv` in hardware (ARMv7-M and up). |
| FPU | FPv4-SP: `(f 32)` in s0–s15. `(f 64)` has no hardware here — see milestone M5. |

## Test host

```
qemu-system-arm -M mps2-an386 -cpu cortex-m4 \
  -display none -serial none -monitor none \
  -chardev stdio,id=semi \
  -semihosting-config enable=on,target=native,chardev=semi \
  -kernel <image.elf>
```

QEMU has no faithful STM32F4 machine; `mps2-an386` is the identical core, and
since all I/O goes through semihosting no peripheral is ever touched.

**The `-chardev stdio` routing is not optional.** With a bare
`-semihosting-config enable=on,target=native`, QEMU writes the semihosting
console to its own **stderr**, interleaved with its diagnostics — where it
cannot be compared against a fixture's expected stdout. Routing it through an
explicit stdio chardev puts guest output on stdout and leaves stderr to QEMU.

Verified host behaviour (M0):

| Behaviour | Result |
|---|---|
| Exit status | `SYS_EXIT_EXTENDED` status becomes QEMU's process exit status, exactly, for 0 / 1 / 42 / 255 |
| Guest stdout | byte-exact on stdout with the chardev routing; nothing else is mixed in |
| Infinite loop | runs until killed — the runner's own timeout must bound it, as `tests/tester.nim` already does for the qemu-aarch64 pass |
| Fault (e.g. `UDF #0`) | QEMU aborts with status **134** and dumps the CPU state to stderr. A miscompile therefore fails fast and loudly instead of hanging, and 134 collides with no fixture's expected code. |

## Boot protocol

M-profile has no reset vector *instruction*; the core reads a table at
`VTOR` (0x00000000 out of reset):

* word 0 — initial MSP. Defaults to `0x20010000` (MPS2 SSRAM2/3 starts at
  0x20000000; the stack grows down from 64K in), and follows `nifasm`'s
  `--ram`/`--ram-size`/`--stack-top` for any other board.
* word 1 — reset handler address **with bit 0 set**. Bit 0 is the Thumb-state
  bit, not part of the address; clearing it faults immediately.

`e_entry` in the ELF header is essentially advisory for `-kernel` on M-profile —
the vector table is what the core actually reads — but the probe sets both.

On the MPS2 boards the region at 0x00000000 is ZBT SRAM rather than real flash,
so a first-cut image could put text, rodata and data all at 0 and skip the
flash→RAM `.data` copy loop. It no longer does: the image carries an initializer
blob after the code and the entry proc copies it into SRAM, because real silicon
needs that and because a skipped copy is invisible on a host that pre-loads the
data for you. See M6.

## Semihosting

Invoked as `bkpt #0xAB` with the operation in r0 and a parameter block pointer
in r1 (A-profile uses `svc 0x123456`; M-profile uses `bkpt`).

| Op | Number | r1 |
|---|---|---|
| `SYS_OPEN` | 0x01 | `&{name, mode, namelen}`; `":tt"` with mode 4 opens stdout |
| `SYS_WRITE0` | 0x04 | pointer to a NUL-terminated string |
| `SYS_WRITE` | 0x05 | `&{handle, buf, len}`; **returns bytes NOT written** (0 = success), unlike POSIX `write` |
| `SYS_EXIT_EXTENDED` | 0x20 | `&{0x20026, status}` |

`SYS_EXIT` (0x18) cannot carry a status on 32-bit — its r1 *is* the reason code,
not a pointer — so the extended form is required to drive `.exitcode` fixtures.

QEMU accepts a raw fd `1` for `SYS_WRITE` without a preceding `SYS_OPEN`, but a
hardware debug probe does not. The backend should `SYS_OPEN(":tt")` once at
entry and cache the handle, so the same images run on real hardware.

Both `exit` and `write` are all the existing arkham corpus needs: of 236
fixtures, 225 `importc "exit"` and 3 `importc "write"`.

`SYS_WRITE`'s first field is a semihosting HANDLE, not a POSIX fd. Passing a raw
`1` writes nothing AND reports success — the call returns "0 bytes not written",
so a caller checking the return value sees a complete write of nothing. The
handle comes from `SYS_OPEN(":tt")`, which the `write` shim does once and caches
in a `.bss` word; that is also what makes the same image work against a hardware
debug probe. Semihosting has one console, so the `fd` argument is ignored —
stdout and stderr are the same stream.

## Remaining milestones

* **M1 — word-size parameterization.** The toolchain hardcodes a 64-bit word:
  `arkham/slots.nim` (`scalarSlot` default, `PtrT`/`AptrT`/`ProctypeT` size 8,
  `inRegClass`), `arkham/abi.nim` (the eightbyte granule throughout),
  `nifasm/sem.nim` (`asmSizeOf`/`asmAlignOf` for `PtrT`/`NilT`/`ProcT`),
  `nifasm/slots.nim` (`max(8, slotAlign)`), `nifasm/assembler.nim`
  (`normScalarBits` → 64, the `(arg name k)` word stride). Must be provably
  inert for x64 and a64 — byte-identity gate against a saved baseline.
* **M2 — nifasm: `thumb2.nim` + bare-metal ELF32.** New `RelocKind`s for Thumb
  branches; note Thumb's PC is `insn_addr + 4` and `B.W`/`BL` use the split
  J1/J2 encoding, so `calculateRelocDistance` needs its own arm.
* **M3 — the arkham backend.** Done for 32-bit scalars, pointers, control flow,
  calls, globals and small aggregates: `tests/arkham_m/` holds 80 Leng fixtures
  that compile, assemble and run under QEMU with the right exit code.

  There is NO `codegen_m.nim`. `codegen_arm.nim` serves both targets, driven by
  `md`, `slots.setTargetWord` and a `thumbM` flag — the asm-NIF vocabulary is
  shared by design (`add3`, `cmp`, `beq`, `ldr`, `adr` mean the same on both),
  so a third backend needs a register file and a word size, not a second
  emitter. Reimplementing the fused value core would have meant reimplementing
  its register-binding protocol, which is the part with a formal model behind it
  (`proofs/arkham_bindings.tla`).

  A bare-metal entry proc cannot RETURN — `lr` at reset holds no valid address —
  so the entry tail-calls a semihosting exit shim (`` `mexit.0 ``) that every
  image carries. `importc "exit"` and `importc "write"` become semihosting shims
  too, called like ordinary procs; anything else `importc`'d is refused by name.

  **No fixture hangs, and no fixture computes a wrong answer.** Everything that
  does not work refuses BY NAME. The two converted fixtures that still produce a
  wrong value are inapplicable rather than unsupported — `memcpy_tail` stores
  2^32 into a slot conversion made 32-bit, and `stack_array_align` asserts a
  16-byte stack alignment AAPCS32 does not promise; both are named in
  `tests/arkham_m/README.md`.

  The Cortex-M `intTempRegs` pool is deliberately EMPTY. Emitter scratch is
  drawn while a call's arguments are being staged, and on this target the only
  volatiles ARE the argument registers — so an overlapping pool hands out r1 as
  a temp while r1 holds staged argument word 1. Temporaries come from the
  callee-saved homes instead. The narrower fix is to teach the scratch picker
  which argument registers are currently staged.
* **M4 — 64-bit integers.** DONE. `tests/arkham/` — the full 64-bit corpus — is
  compiled for Cortex-M and run under QEMU by `arkhamCortexM64Tests`, with a
  named skip list (`cortexMUnsupported`) that states why each remaining fixture
  cannot be served. 165 of 220 pass today, and the ONLY one that computes a
  wrong answer is `stack_array_align`, which asserts a 16-byte stack alignment
  AAPCS32 does not promise. Everything else refuses by name.

  **Not** register pairs. A 64-bit value here is EIGHT BYTES AT AN ADDRESS, and
  the ops read and write it a word at a time (`arkham/codegen_m64.nim`, included
  by `codegen_arm.nim`). The reason is the register file: four allocatable homes
  and an EMPTY volatile temp pool, because on this ABI the only caller-saved
  registers ARE the argument registers. A pair allocator would compete for two of
  four homes per live value, and every consumer in the shared value core — which
  has a formal model behind its binding protocol — would need a second-register
  case. `slots.inRegClass` already refuses a 64-bit scalar a register home on a
  32-bit target, so the allocator needed no change at all; what M4 added is the
  arithmetic.

  The cost is real (an `x + y` is six instructions, not two) and it is the price
  of the register file, not of the representation. What it buys is that the one
  thing a 64-bit lowering must never do — produce a plausible wrong number —
  cannot happen by a register running out.

  Each half is spelled `(cast (u 32) (mem <base> <byte offset>))`. The cast is
  load-bearing: without it the access is 64-bit-typed and nifasm REFUSES it
  (`checkRegWidthM`) rather than silently truncating, which is why an arm the
  emitter forgets shows up as a type error and not as a wrong answer.

  Division is a routine the image carries itself — a restoring shift-subtract
  divider emitted once per module, and only when something divides, since a
  firmware image has no `libgcc` to borrow `__aeabi_ldivmod` from. It is called
  with a bare `bl`, so a proc that looked like a leaf until it divided has its
  frame forced (`helperCalls`): `bl` overwrites lr, and nothing in the analyser's
  view of a `div` node says "call". For the same reason every 64-bit ARGUMENT is
  produced into its slot BEFORE the `(prepare …)` block opens — inside it,
  arguments are staged straight into r0–r3, which is exactly what the divider
  clobbers.

  The ABI is the two-word aggregate's: consecutive argument registers, r0:r1 for
  a result, `(regs …)` in the signature. That is not AAPCS32 — which would
  even-align the register pair — and it does not have to be: a firmware image has
  nothing to link against, so arkham owns both sides of every call. What DOES
  matter is that the two sides agree, and they agree by reading the same
  `CallPlan`. The plan follows the CALLEE's declared widths, not the argument
  expression's type: Leng leaves the C truncation of `exit(x + y)` (an `int64`
  sum into a `cint` parameter) implicit, and on a target where a scalar can span
  two registers that is an ABI mismatch rather than a rounding detail.

  Cortex-M also has no frame pointer to address the caller's stack-argument area
  with, so the incoming base is re-derived from SP (`sp + (ssize) + the
  prologue's own pushes`) — which is only final once the prologue has run. That
  is why the Cortex-M stack-parameter loads are emitted WITH the prologue rather
  than at the top of the body, and why they may only use the staging bridges:
  the prologue is written after `computeFrame` has frozen `usedCallee`, so a
  callee-saved register taken there would be used without being saved.
* **M5 — floating point.** DONE for `float32`. `tests/arkham_m/fp32_*` cover
  arithmetic, comparison, calls and returns, globals, arrays, object fields, and
  spilling past the callee-saved registers; `tests/thumb2_selftest.nim` checks
  all seventeen VFP encoders by RUNNING them.

  Cortex-M4F's FPU is FPv4-SP: single precision, s0–s31, and **no `.f64`
  instruction at all**. A `float64` is therefore refused by name — this is
  missing hardware, not a missing feature, and the alternative (a softfloat
  library nobody asked for) is not a decision a code generator should make
  quietly. So is `int64(f)` / `float32(i64)`: `vcvt` converts to and from a
  THIRTY-TWO bit integer, and a `vcvt` plus a sign-extend would be quietly wrong
  exactly where it matters. `int32(f)` and `float32(i32)` are what this core has.

  Two things about the target had to be learned the hard way:

  * **The FPU is OFF at reset.** CPACR grants no access to CP10/CP11, and the
    first VFP instruction takes a UsageFault — which, with no handler installed,
    is a lockup at the top of `main` with nothing to say why. Every image now
    enables it in the entry proc, DSB/ISB included (CPACR changes how LATER
    instructions behave; QEMU forgives the missing barriers, silicon does not).
  * **`vneg` and `vsqrt` differ only in their `opc3` field.** Getting them the
    wrong way round turns `-3.0` into `1.732` — no fault, no type error, just a
    number. Both are in the encoder self-test, with values chosen so neither can
    pass for the other.

  The float register file is roomy where the integer one is not, so the pools
  follow AAPCS32 (s0–s15 caller-saved, s16–s31 callee-saved) and — crucially —
  the temp pool is DISJOINT from the argument registers. That is the property
  the integer side could not have, and it is why float scratch needs no special
  care while a call's arguments are being staged. s30 is nifasm's (`vcvt` needs
  a float register to convert INTO, the same way operand folding needs r12) and
  s31 is the emitter's float staging bridge.

  Float parameters and results stay on the empty-signature manual-marshalling
  path, as they do on AArch64 — `isDeclarativeAbi` excludes them — so the
  assembler never sees a float in a `(param …)`.
* **M6 — actually embedded.** Exception/interrupt handlers with the right
  EXC_RETURN epilogue, volatile MMIO, and a UART output backend so real hardware
  works without a debugger attached.

  **The memory map is DONE.** `nifasm --flash:ADDR --flash-size:N --ram:ADDR
  --ram-size:N --stack-top:ADDR` — the two lines of linker script a firmware
  image actually needs, replacing the MPS2 constants that used to be compiled in.
  Sizes take a K/M/G suffix and addresses take `0x`, because a datasheet is where
  the numbers are read off. An STM32F407 is `--flash:0x08000000 --flash-size:1M
  --ram-size:128K`. The defaults are the MPS2 values, so an image built without
  any of them is byte-identical to one built before the flags existed, and giving
  them to any other target is an error rather than silence.

  The sizes are what makes them worth having: nothing bounded the image before.
  An image larger than the part's flash was not a diagnostic, it was an ELF that
  loads and a board that faults somewhere unrelated. Now both regions are checked
  and both name themselves, as do an overlapping map and a stack top outside RAM.

  Note the ORDER dependence the flags do not have: `--stack-top` defaults to the
  top of RAM, which both `--ram` and `--ram-size` move, so it is settled once
  after all flags are read rather than as each arrives.

  What must be run rather than inspected is that the map reaches the IMAGE, and
  the test does run it: `tests/tester.nim`'s `cortexMMemMapTests` relocates RAM to
  0x20001000 — still inside QEMU's SSRAM — and executes the fixture there. If the
  globals' `movw/movt` sites, the `(datavma)` the startup copy writes to, or the
  vector table's initial-MSP word had kept a compiled-in constant, it reads a
  global that was never written or pushes onto a stack that is not there. And
  because an image that ignored the flag ENTIRELY is internally consistent and
  exits 42 just the same, the test also reads the addresses back out of the ELF
  and requires that they moved. The STM32F407 map cannot be run — nothing in QEMU
  has flash at 0x08000000 — so it is checked by reading the two words a cold core
  reads.

  **`.data` init from flash is DONE.** A hosted program is handed a laid-out
  address space by its loader. A firmware image is handed a chip: flash holds
  everything the image shipped with, RAM holds nothing at all, and `var counter =
  7` has to become a 7 in RAM by some instruction that actually runs. So the
  initializer image travels in flash, appended after the code, and the entry
  proc's first act is to copy it into SRAM and zero the rest of the region
  (`emStartupInitM`).

  The four numbers this needs — where the image landed in flash, where the region
  sits in SRAM, and the size of each part — are `(dataload)`, `(datavma)`,
  `(datasize)` and `(bsssize)`. They are nifasm's, in exactly the sense `(ssize)`
  is: only `writeCortexMImage` knows the final layout, so it emits a MOVW/MOVT
  pair of fixed width and patches it, the same way it patches every global's
  address. Arkham writes the instructions; nifasm fills in its own numbers.

  The cut between "copy" and "zero" is the HIGH-WATER MARK of the initialized
  bytes, not a partition of the globals. Offsets are assigned as the gvar decls
  are scanned and every address site is patched against them long before the
  split is computed, so re-sorting is not available — and the scan order is not
  the declaration order either. A zero global that lands between two initialized
  ones is therefore copied rather than zeroed: flash wasted, never correctness,
  since the byte copied is the zero the image already holds. Two offset cursors
  at scan time would remove it.

  What made this worth doing now rather than at the end is the SRAM segment:
  it now declares `p_memsz` and **no file bytes at all**. Until then QEMU's
  `-kernel` placed the initialized globals itself, so a copy loop that did
  nothing would have passed every fixture in both corpora. It does not any more —
  `gvar_fnptr_init` calls through a global function pointer that is zero without
  the copy, and the fault is immediate. `tests/arkham_m/global_data_init` pins
  down the split's arithmetic specifically.

  The ZERO loop remains unobserved by the corpus: QEMU hands the guest zeroed
  RAM, so a `.bss` that is never written reads correct anyway. It is right by
  construction and by the layout arithmetic the fixture checks — not by
  execution, and this note is here rather than in a comment because no test will
  fail if it breaks.
