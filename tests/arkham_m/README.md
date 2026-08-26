# `tests/arkham_m` — the Cortex-M Leng corpus

Mechanically derived from `tests/arkham/` by rewriting `(i 64)`/`(u 64)` to
32-bit, then filtered to what actually passes. Each fixture compiles with
`arkham -a:cortex_m`, assembles with `nifasm`, and runs under QEMU with the
exit code in its `.exitcode` file.

It is a separate corpus rather than a skip list because 206 of the 236
originals declare `(i 64)`: that needs the register-pair lowering of milestone
M4 (see `doc/cortex_m.md`), and a skip list would have been larger than the
corpus.

## Fixtures that are INAPPLICABLE, not unsupported

Two survive the conversion syntactically but no longer test anything true, and
are excluded on purpose rather than counted as backend failures:

* **`memcpy_tail`** stores `4294967296` (2^32) into what conversion turned into
  an `(i 32)` slot, and copies 12 bytes out of an 8-byte source to exercise the
  "one eightbyte plus a 4-byte tail" split. Both the sentinel and the split are
  properties of a 64-bit word.
* **`stack_array_align`** asserts `addr big and 15 == 0` — a 16-byte stack
  alignment. AAPCS32 requires 8, and over-aligning every frame to buy this back
  would cost stack on a device that has kilobytes of it.

A hand-written 32-bit equivalent of each would be worth having; the converted
ones are not it.

## Fixtures written by hand

* **`global_data_init`** is the geometry of the `.data`/`.bss` split (M6). Four
  globals — initialized, zero, initialized, zero — so that one zero global falls
  INSIDE the copied region and one falls above it, and the fixture checks all
  four values. It is the arithmetic of the split that this pins down; the copy
  itself is exercised by every initialized-global fixture in both corpora, since
  the SRAM segment carries no file bytes for QEMU to place.
