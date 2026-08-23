# Cortex-M support

Status: **M0, M1, M2a/b complete; M2c in progress.**

| Milestone | State |
|---|---|
| M0 target contract | done — `tools/cortexm_probe.nim` |
| M1 word-size parameterization | done — `slots.setTargetWord` / `sem.setAsmWordSize` |
| M2a Thumb-2 encoder + relocations | done — `src/nifasm/thumb2.nim`, 45-check self-test |
| M2b ELF32 firmware writer | done — `src/nifasm/elf32.nim` |
| M2c assembler integration | **partial** — see below |
| M3 arkham backend | not started |
| M4 64-bit integers | not started |
| M5 floating point | not started |
| M6 embedded features | not started |

### What M2c still needs

`(arch cortex_m)` is accepted, the word size switches to 4, `(rodata …)` and
the rest of pass1/pass2 work, and the image writer is wired to
`elf32.writeFirmware`. `tests/hello_cortex_m.nif` gets all the way to the first
instruction and then reports, by name, that the selector is missing.

What is missing is the MIDDLE layer — the Cortex-M counterpart of
`genInstA64`, roughly:

* `parseDestM` / `parseOperandM` and the `Operand` model (okReg / okMem / okImm)
  against the `MReg` tag set,
* the register-binding table (`mRegBindings`, the analogue of `a64RegBindings`)
  so `(var :x (r4) (i 32))` type-checks and a raw `(r4)` use is rejected,
* the per-mnemonic arms, which then call straight into the tested
  `thumb2.emit*` encoders,
* prologue/epilogue and stack-slot addressing for AAPCS32.

The `MInst` enum in `doc/instructions.md` is declared but still EMPTY: the
mnemonics should be added as MInst-only rows appended at the END of the
document, which keeps them in the late-numbered tail and moves no existing
tag id.

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
* **M3 — arkham: `machine_m.nim` + `codegen_m.nim`.** 32-bit scalars first;
  `(i 64)` and floats error out by name. New corpus `tests/arkham_m/`.
* **M4 — 64-bit integers as register pairs.** `adds`/`adcs`, `umull`+`mla`,
  `__aeabi_ldivmod`. Un-skips most of the existing 236-fixture corpus (206 of
  them declare `(i 64)`).
* **M5 — floating point.** FPv4-SP hard-float for `(f 32)`; `(f 64)` rejected on
  M4F rather than dragged in via a softfloat library.
* **M6 — actually embedded.** Exception/interrupt handlers with the right
  EXC_RETURN epilogue, volatile MMIO, memory-map configuration, `.data` init
  from flash, and a UART output backend so real hardware works without a
  debugger attached.
