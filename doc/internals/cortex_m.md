# Cortex-M support

Status: **M0, M1, M2a/b complete; M2c in progress.**

| Milestone | State |
|---|---|
| M0 target contract | done — `tools/cortexm_probe.nim` |
| M1 word-size parameterization | done — `slots.setTargetWord` / `sem.setAsmWordSize` |
| M2a Thumb-2 encoder + relocations | done — `src/nifasm/thumb/encoder.nim`, 45-check self-test |
| M2b ELF32 firmware writer | done — `src/nifasm/image/elf32.nim` |
| M2c assembler integration | done — selector, frames, calls, marshalling |
| M3 arkham backend | **working** — 119 Leng fixtures run end to end |
| M4 64-bit integers | not started |
| M5 floating point | not started |
| M6 embedded features | not started |

### What M2c has

The instruction selector (`genInstM` in `nifasm/thumb/instr.nim`) works end to end:
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
| Spelled | `--os:embedded --cpu:arm32`, in nimony and arkham alike (`-a:cortex_m` still works). Not `--os:standalone`, which is Nim's word for a freestanding-with-a-`panicoverride` build nothing here offers; not `--os:none`, because the OS name becomes a `defined()` symbol and `defined(none)` says nothing about what is being built |
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

M-profile has no reset vector *instruction*; the core reads the INTERRUPT TABLE at
`VTOR` (0x00000000 out of reset):

* word 0 — initial MSP. Defaults to `0x20010000` (MPS2 SSRAM2/3 starts at
  0x20000000; the stack grows down from 64K in), and follows `nifasm`'s
  `--ram`/`--ram-size`/`--stack-top` for any other board.
* word 1 — reset handler address **with bit 0 set**. Bit 0 is the Thumb-state
  bit, not part of the address; clearing it faults immediately.

`e_entry` in the ELF header is essentially advisory for `-kernel` on M-profile —
the interrupt table is what the core actually reads — but the probe sets both.

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

Semihosting is the console arkham SYNTHESIZES, and the only one. A program that
`importc`s `write`/`exit` — which is what the hand-written fixture corpus does —
gets these shims; anything else is a driver, and a driver belongs in the
program. That is now sayable: `{.assembler.}` procs work on this target (M7), so
a board with a UART writes its console in Nimony over `volatileLoad`/
`volatileStore`, and a board with a debug probe can write the semihosting
sequence itself with `bkpt`. See M8 for why the back end stopped carrying a
second one.

`SYS_WRITE`'s first field is a semihosting HANDLE, not a POSIX fd. Passing a raw
`1` writes nothing AND reports success — the call returns "0 bytes not written",
so a caller checking the return value sees a complete write of nothing. The
handle comes from `SYS_OPEN(":tt")`, which the `write` shim does once and caches
in a `.bss` word; that is also what makes the same image work against a hardware
debug probe. Semihosting has one console, so the `fd` argument is ignored —
stdout and stderr are the same stream.

## Remaining milestones

* **M1 — word-size parameterization.** The toolchain hardcodes a 64-bit word:
  `arkham/core/asmslots.nim` (`scalarSlot` default, `PtrT`/`AptrT`/`ProctypeT` size 8,
  `inRegClass`), `arkham/core/abi.nim` (the eightbyte granule throughout),
  `nifasm/core/sem.nim` (`asmSizeOf`/`asmAlignOf` for `PtrT`/`NilT`/`ProcT`),
  `nifasm/core/stackslots.nim` (`max(8, slotAlign)`), `nifasm/pass2.nim`
  (`normScalarBits` → 64, the `(arg name k)` word stride). Must be provably
  inert for x64 and a64 — byte-identity gate against a saved baseline.
* **M2 — nifasm: `thumb/encoder.nim` + bare-metal ELF32.** New `RelocKind`s for Thumb
  branches; note Thumb's PC is `insn_addr + 4` and `B.W`/`BL` use the split
  J1/J2 encoding, so `calculateRelocDistance` needs its own arm.
* **M3 — the arkham backend.** Done for 32-bit scalars, pointers, control flow,
  calls, globals and small aggregates: `tests/arkham_m/` holds 80 Leng fixtures
  that compile, assemble and run under QEMU with the right exit code.

  There is NO separate Cortex-M emitter. `arkham/arm/` serves both targets, driven by
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

  Read that corpus for what it is. Nimony maps `int` to the target's width, so
  under `--cpu:arm32` it is 32 bits and 64-bit lowering is off the path of
  ordinary integer code entirely. `tests/arkham/` was authored for x86-64 and
  AArch64, where `int` WAS 64 bits, so nearly every integer in it reaches the
  Cortex-M backend as `(i 64)` — a deliberate stress test, and a poor model of a
  firmware image. `tests/arkham_m/` is the corpus with a 32-bit `int`.

  **Not** register pairs. A 64-bit value here is EIGHT BYTES AT AN ADDRESS, and
  the ops read and write it a word at a time (`arkham/arm/value.nim` for the half
  inside the value core's cycle, `arm/emit.nim` and `arm/aggr.nim` for the rest). The reason is the register file: four allocatable homes
  and an EMPTY volatile temp pool, because on this ABI the only caller-saved
  registers ARE the argument registers. A pair allocator would compete for two of
  four homes per live value, and every consumer in the shared value core — which
  has a formal model behind its binding protocol — would need a second-register
  case. `slots.inRegClass` already refuses a 64-bit scalar a register home on a
  32-bit target, so the allocator needed no change at all; what M4 added is the
  arithmetic.

  The cost is real (an `int64` `x + y` is six instructions, not two) and it is
  the price of the register file, not of the representation. What it buys is
  that the one thing a 64-bit lowering must never do — produce a plausible wrong
  number — cannot happen by a register running out.

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
* **M6 — actually embedded.** DONE.

  **Output** is semihosting, and only semihosting: `write` and `exit` go through
  a debug agent, which is the one console a bare-metal image can have without a
  driver. The back end briefly carried a second — a CMSDK UART behind
  `--writesTo:serial` — and M8 removed it.


  **Volatile MMIO is DONE.** `volatileLoad(p)` / `volatileStore(p, v)` from
  `std/volatile` — Nim's names and Nim's signatures, so source written against
  that module compiles here unchanged.

  Deliberately NOT a type qualifier. A qualifier is viral: it reaches every type
  comparison, every signature and every generic instantiation, in order to
  express a property that belongs to the ACCESS and not to the memory. As
  intrinsics it stays at the access site, which is where it is true.

  What the rows promise: the access happens, exactly once, at exactly the
  pointee's width, and is not reordered against another volatile access. What
  they do NOT promise is a barrier or any order against ORDINARY memory — the
  same line C draws, and drawn there because a peripheral write does not flush a
  store buffer. `dmb`/`dsb` are their own instructions for when a device needs
  more.

  A cell too wide for one machine access is REFUSED, not split: `volatileLoad`
  of a 64-bit cell on this target is two `ldr`s, and two accesses is not what a
  device register was asked for. The width comes from the POINTER — the one
  operand that cannot be wrong about the cell it addresses.

  The half that was not the interface: `IntrinsicRow.effects` had been in the
  table since it was written and NOTHING had ever read it, while the optimizer's
  purity predicates tested `(call …)` and did not know `(instr …)` existed. So
  `cse.isPureExpr` answered TRUE for every intrinsic. `shoggoth/intrinsiceffects`
  is the reader; `Ctz` and friends still say `efPure` and stay optimisable.

  This is also the first row to claim `tgThumbM`. Until it, arkham's Arm emitter
  read `tgA64` for both Arm targets — a proxy that held only while no row
  distinguished them, and one nothing had noticed because every fixture reaching
  an `(instr …)` was already in `cortexMUnsupported` for an unrelated reason.

  **Interrupt handlers are DONE.** `proc onTick {.interrupt: "SysTick".}` in Leng
  becomes a word in the image's interrupt table. Three things had to be true for
  that, and only one of them is the table:

  * **The handler survives to the back end at all.** Nothing in the program calls
    it — it is reached only through a table built after every reachability pass
    has run — so it is unreachable by construction and gets deleted. It is a DCE
    root in nimony (`dce1`) and marked used in nifasm (`handleInterrupts`), and
    both were verified by taking the marking out and watching the handler vanish
    from the output with no diagnostic at all.
  * **The body needs nothing special.** An M-profile handler IS an ordinary AAPCS
    function: the hardware stacks r0–r3/r12/lr/pc/xPSR on entry and `bx lr` on the
    EXC_RETURN value in lr unstacks them. So no `{.interrupt.}` prologue exists;
    the proc arkham already emits is correct, which is why this milestone is a
    table and not a calling convention.
  * **The name means a slot.** `machine_m.interruptSlot` is the ARMv7-M table:
    `NMI`=2 … `SysTick`=15, `IRQ<n>`=16+n. Those numbers are architectural, so
    the table is the same on every Cortex-M part and the names are CMSIS's.
    External interrupts are spelled by NUMBER because `TIM2_IRQn` is a number
    STM32 chose, not one arkham can know.

  Sem checks only what is true of every part — a handler takes no parameters and
  returns nothing, because hardware passes no arguments and has nowhere to put a
  result. Which names EXIST is arkham's, exactly as for `{.register.}`, and an
  unknown one is refused by name, as is a second claim on one slot.

  The table is now **at least sixteen words** whenever a module declares a
  handler, where it was always two. The fault entries do not have to be enabled to
  be TAKEN, so a fault reaching past the end of a shorter table would read
  whatever code follows and branch into it. A word no handler claimed stays zero,
  which faults on the Thumb-bit rule, escalates, and locks the core up:
  deterministic and findable on a debugger, which arbitrary execution is not. An
  image with NO handler still carries two words, so every existing fixture's
  layout is untouched.

  `tests/arkham_m/interrupt_pendsv` is the end-to-end gate: it pends PendSV by
  writing ICSR and exits with what the handler wrote into a global. That runs the
  table, the Thumb bit on the entry, and the handler's return — not just the
  emission.

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
  interrupt table's initial-MSP word had kept a compiled-in constant, it reads a
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

* **M7 — `{.assembler.}` procs.** DONE. `arkham/arm/asmproc.nim` gives both Arm profiles the transliteration mode
  `doc/intrinsics.md` §8 describes and x86-64 already had: no allocator, no value
  core, every location DECLARED, one instruction per statement.

  What Cortex-M gets out of it is the ability to say things this back end cannot
  be asked to infer. A `bkpt` sequence, an MMIO poll, a handler prologue — code
  whose whole content is WHICH instruction runs and in what order. Nothing about
  the register file changes: pins are `r0`..`r7`, conditions go through
  `(ite <flag> …)` (Cortex-M maps all eight of Arm's; AArch64's assembler
  implements the zero flag alone), and `{.naked.}` drops the prologue but never
  the `ret`.

  Which registers a body may claim is the part that needed care rather than
  translation. r12 is nifasm's own operand-folding scratch, written at sites
  arkham never sees. r8 is the produce bridge, r9 the indirect result pointer,
  r10/r11 the two staging bridges — all four callee-saved under AAPCS32, and none
  of them saved by a prologue that walks r4–r7. A value pinned there is preserved
  by nobody, and the damage shows up in the CALLER. So each is refused by the
  ROLE that already owns it, and `armFrameSaved` — one list — answers both "may
  this be pinned?" and "does the prologue save it?", which is also what keeps the
  mode sound under `-d:arkhamStress`, where the allocator's pools shrink but a
  body that names its own registers still needs them saved.

  Three things a shim actually needs came with it, each of which had been a
  documented gap rather than a decision:

  * **`bkpt`** — a pinned row (`{tgThumbM}`) whose one operand the INSTRUCTION
    encodes, which is a new operand pattern (`ptImmLit`): there is no register
    form of an 8-bit comment field, so a non-literal argument is refused by
    name. Its effects are the widest honest ones (`efReads`, `efWrites`,
    `efBarrier`) — whatever the debug agent does is invisible from here, and an
    `efPure` trap would be DCE's to delete. What it CANNOT say is that the answer
    comes back in r0, which is exactly why a semihosting call is written in a
    body that can name r0.
  * **Two-address arithmetic** — `add`/`sub`/`and`/`or`/`xor`/`shl`/`shr`/`sar`/
    `neg` now claim both Arm targets, in `{.assembler.}` bodies AND in ordinary
    procs. The allocated path serves a spilled destination through a staging
    bridge (load, operate, store back) rather than refusing it: Arm is a
    load/store machine, and a rejection there would fire only under register
    pressure, which is the worst possible shape for a diagnostic.
  * **`addr`** — `(lea D slot)` for a `{.stack.}` local, `(adr D sym)` for a
    global. A register is refused, because it has no address and spilling it
    behind the author's back is the one thing this mode never does.

  The flags needed a rule of their own. Arm has a flag-setting and a
  non-flag-setting form of every arithmetic instruction, and which one an
  assembler picks is an ENCODING decision — nifasm asks for the non-setting form,
  but Thumb's narrow 16-bit encoding, the one it prefers when every operand is a
  low register, sets them anyway. So after an `add` the flags depend on which
  registers the body pinned, which is no basis for reading one. A flag may
  therefore only be read by the `if` that IMMEDIATELY follows its `cmp`; a label,
  a branch, a loop boundary and every other instruction invalidate it. x86-64
  needs no such rule, and does not have one.

  `tests/arkham_m/assembler_m` covers the positive path end to end under QEMU
  (flag branch, `(s)` slot, callee-saved pin, `while true`/`break`, a `{.naked.}`
  proc that emits exactly one instruction, `addr` of a global);
  `tests/arkham_m/semihost_writec` prints through a `bkpt` SYS_WRITEC written in
  an `.assembler` body and checks both the exit code and the output;
  `tests/arkham_m/err_asm_*` covers the five rejections. The AArch64 twin is
  `tests/arkham/assembler_a64`.

* **M8 — one console, and it is not the back end's.** DONE. The `writesTo`
  mechanism is gone: the `--writesTo` flag, the `(writesTo …)` layout row and its
  asm-NIF tag, `WritesToKind` on both sides, the CMSDK register map, and the two
  UART shims (`emitUartWriteProc`, `emitUartExitProc`).

  It was a code generator carrying a device driver. The register layout was
  CMSDK's — ARM's own reference designs, and what QEMU's MPS2 models — which is
  the only layout it could honestly carry, so every real part was one `#ifdef`
  away from needing another. A flag that selects between two drivers is a
  question the back end should not be asked, and until M7 there was no other
  place to put the answer.

  Now there is. A board's console is a driver, and a driver is a program:
  `volatileLoad`/`volatileStore` for the registers, `{.assembler.}` where the
  instruction matters, and the whole thing in Nimony where it can be read, tested
  and changed without rebuilding the compiler. What the back end still
  synthesizes is the semihosting `write`/`exit` behind an `importc` — the one
  console that needs no driver, because the driver is on the other end of the
  wire — which is also what keeps a hand-written `.c.nif` fixture runnable.

  **The stdlib half is written** (`nimony/lib/std/system/semihosting.nim`,
  included by `system.nim` under `--os:embedded`). The whole of the assembler in
  it is one proc:

  ```nim
  proc semihostCall(op {.register: "r0".}: int32;
                    arg {.register: "r1".}: pointer): int32 {.assembler.} =
    bkpt(0xAB)
  ```

  One instruction, because the ABI has already done the rest — the operation is
  in r0 and the parameter block address in r1 because that is where AAPCS32 puts
  the first two arguments, and the agent's answer is in r0 because that is where
  a result is returned from. What the pins add is that this stays true: they are
  checked against the ABI, so a change on either side is a compile error rather
  than a trap taken with the wrong registers loaded. Above it, `SYS_OPEN(":tt")`
  with its cached handle, the parameter blocks, and the conversion from
  semihosting's "bytes NOT written" to POSIX's "bytes written" are ordinary
  Nimony. `syncio`'s `sysWrite` and `exits`' `cExit`/`cAbort` route to it under
  `defined(embedded)`.

  Two more things were needed to get an `--os:embedded` build that far, and both
  are the target's own truth rather than workarounds: the four `{.threadvar.}`s
  in `system` become plain globals there (one thread of execution means a
  thread-local IS a global, and this target has no TLS register for the back end
  to reach one through), and `nimony` gained a `--layout:FILE` flag that forwards
  the board description to arkham — a bare-metal image has no OS to ask how much
  RAM it may have, so that file IS the answer.

  What still stops a complete image is two Cortex-M gaps in code that has nothing
  to do with the console, both reachable for the first time now that the build
  gets past `system`'s thread-locals: the atomic rows have no Cortex-M lowering
  (ARC's refcount `AtomicAddFetch`), and `findSuitableBlock` in the allocator
  exhausts the register file (`reloadMemBase2` finds no register to reload a
  spilled memory base — r8 is the candidate, being in no pool, but whether the
  produce bridge is free across an address chain needs checking rather than
  assuming). arkham compiles a module WHOLE, so every proc `system` defines has
  to be servable before any bare-metal program links.

* **M9 — atomics.** DONE for 8, 16 and 32 bits. ARMv7-M's synchronization
  primitive is the exclusive pair and nothing else: `ldrex` takes the monitor's
  claim on an address, `strex` stores only if the claim still holds and reports
  in a status register whether it did. There is no acquire/release form of a load
  or a store — that is ARMv8-M — so the ordering an atomic owes is a separate
  instruction, and every sequence here is bracketed by `dmb`.

  What that costs, spelled out, is the difference from AArch64: `ldaxr`/`stlxr`
  carry their ordering, so the a64 lowering is the loop and nothing else. The
  Cortex-M one is `dmb` + the loop + `dmb`, and the CAS failure path must
  `clrex` — it leaves the pair WITHOUT the store, and the monitor would otherwise
  stay armed on that address for a later, unrelated `strex` to succeed against.

  The scratch is `bridgeRegs` (r10/r11/r8), which is the same choice AArch64
  makes (x14/x15/x16) and for the same reason: the sequence needs exactly three
  registers nothing else may hold — the observed value, the value to store, and
  the status — and those three are the ones the allocator never assigns. It is
  also why an atomic's OPERANDS may not use a bridge (`takeInstrReg`): parked
  there, one would be destroyed between the exclusive load and the store.

  **64 bits is refused by name.** ARMv7-M has no `ldrexd`, and two exclusive
  pairs over the halves would be two claims rather than one atom — so the answer
  is the message, not a lowering that is atomic per word and racy per value.
  `widths` in the row table cannot say "every width but one, on one target", and
  a per-target width column would be a second place for the same fact to be
  wrong, so the check lives at the emission site.

  Four `strex` rules are enforced where they can be: the status register must
  differ from the value and address registers (UNPREDICTABLE otherwise, and since
  the loop branches on the status, getting it wrong is an infinite loop rather
  than a wrong value) — checked in `thumb2.emitStrex` and again in nifasm's
  operand parser, because a typed assembler is where an encoding rule belongs.

  Tests: `tests/thumb2_selftest` gained seven checks that RUN the new encodings —
  a claim taken and honoured, a claim taken and abandoned by `clrex` (the next
  `strex` must then report failure), and the byte and halfword forms touching
  exactly one byte and one halfword of a word. `tests/arkham_m/atomics` covers
  every lowered row at 32 bits plus an 8-bit fetch-add with wraparound, and
  checks the C11 semantics that are easy to get backwards: which forms return the
  value BEFORE the update, and that a FAILING compare-exchange publishes what the
  cell actually held through its `expected` pointer. `atomic_subword_cas` came out
  of `cortexMUnsupported`.

  What is NOT served is an atomic whose OPERANDS cannot be placed. With four
  allocatable homes, an empty volatile pool and three registers the sequence
  claims for itself, a compare-exchange in a proc whose homes are already full
  has nowhere to put its three pointers — `takeInstrReg` refuses a bridge for
  them by the rule above, and there is nothing else. That is the shape
  `atomic_ptr_cell` and `atomic_cas_operand_home` are parked under, and it is a
  property of the register file rather than of this lowering: the narrower fix is
  the one `machine_m.IntTempRegs` already names — teach the scratch picker which
  argument registers are currently staged, so r0–r3 can serve where no call is in
  flight.

* **A complete image, from Nim source.** `nimony n --os:embedded --cpu:arm32
  --layout:board.nif t.nim` now produces a running firmware image: it prints
  through the stdlib's own semihosting console (M7/M8) and exits with the status
  the program asked for. Four one-line-ish holes stood between the atomics and
  that, and every one of them was unreachable until the whole of `system`
  compiled — which is why they are worth naming rather than just fixing:

  * **Module-local names in shared code.** The semihosting shim's `:tt` name and
    console handle, and the 64-bit divider routines, were spelled with ONE dot.
    A one-dot symbol is module-LOCAL: the render compresses it and the embedded
    index leaves it out, so a module that IMPORTS the shim cannot resolve what
    the shim names. They carry the module suffix now, exactly as the `.sys.`
    syprocs beside them do. Single-module fixtures never noticed, because there
    was nobody to import them.
  * **`csel` on a target that has none.** The branchless select-diamond fusion
    was attempted on both Arm profiles; ARMv7-M has no conditional select at all
    (its equivalent is an IT block, a shape this emitter does not build), so it
    now takes the branch lowering that every other `if` on this target already
    uses.
  * **An AArch64 register name in a Cortex-M module.** `emOp` — the text-path
    twin of `emReg`, used by the splice lowerings — spelled an UNBOUND register
    with `machine.regName` rather than through `ab.renderReg`. Invisible while
    every register reaching a splice happened to be bound; the first one that was
    not (`extendTo` narrowing a raw argument register during a call's
    marshalling) emitted `(uxtb (x0) (x0))` into a Thumb module.

  What that leaves is not a gap in the back end but the surface above it: `echo`
  and the rest of `syncio` pull in far more of `system` than this test does.
