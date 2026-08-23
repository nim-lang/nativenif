# Cortex-M support

Status: **M0, M1, M2a/b complete; M2c in progress.**

| Milestone | State |
|---|---|
| M0 target contract | done — `tools/cortexm_probe.nim` |
| M1 word-size parameterization | done — `slots.setTargetWord` / `sem.setAsmWordSize` |
| M2a Thumb-2 encoder + relocations | done — `src/nifasm/thumb2.nim`, 45-check self-test |
| M2b ELF32 firmware writer | done — `src/nifasm/elf32.nim` |
| M2c assembler integration | done — selector, frames, calls, marshalling |
| M3 arkham backend | **working** — 80 Leng fixtures run end to end |
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

* word 0 — initial MSP. The probe uses `0x20010000` (MPS2 SSRAM2/3 starts at
  0x20000000; the stack grows down from 64K in).
* word 1 — reset handler address **with bit 0 set**. Bit 0 is the Thumb-state
  bit, not part of the address; clearing it faults immediately.

`e_entry` in the ELF header is essentially advisory for `-kernel` on M-profile —
the vector table is what the core actually reads — but the probe sets both.

On the MPS2 boards the region at 0x00000000 is ZBT SRAM rather than real flash,
so a first-cut image can put text, rodata and data all at 0 and skip the
flash→RAM `.data` copy loop. Real silicon needs the copy; see M6.

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
* **M4 — 64-bit integers as register pairs.** `adds`/`adcs`, `umull`+`mla`,
  `__aeabi_ldivmod`. Un-skips most of the existing 236-fixture corpus (206 of
  them declare `(i 64)`).
* **M5 — floating point.** FPv4-SP hard-float for `(f 32)`; `(f 64)` rejected on
  M4F rather than dragged in via a softfloat library.
* **M6 — actually embedded.** Exception/interrupt handlers with the right
  EXC_RETURN epilogue, volatile MMIO, memory-map configuration, `.data` init
  from flash, and a UART output backend so real hardware works without a
  debugger attached.
