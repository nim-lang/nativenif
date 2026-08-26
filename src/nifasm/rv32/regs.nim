#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> RV32 registers.
##
## RV32 mints NO register spelling of its own. `(x0)`..`(x30)` and `(sp)` already
## exist as AArch64's, and `(arch …)` is what decides which machine they name —
## the same arrangement Cortex-M has with `(r0)`..`(r12)`. That is worth more
## than it looks: AVR had to mint 48 tags, which pushed them past the 511 that
## fit NIF's tag field and forced escape handling at every operand site. This
## target pays none of that, and the only cost is that `x31` stays unmapped.
##
## `x0` is not a register the allocator can use and never appears as a
## destination the emitter chose: it reads as zero and discards writes. It IS
## named constantly, though — as the source of a `mv`, the operand of a `neg`, or
## the second operand of a branch against zero — so it is spellable rather than
## reserved out of the vocabulary.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as rv

proc rawTagIsRv32Gpr*(t: TagEnum): bool {.inline.} =
  rawTagIsRv32Reg(t)

proc tagToRegisterRv32*(t: TagEnum; n: Cursor): rv.Register =
  let regTag = tagToRv32Reg(t)
  result =
    case regTag
    of X0RvR: rv.X0
    of X1RvR: rv.X1
    of X2RvR, SpRvR: rv.X2
    of X3RvR: rv.X3
    of X4RvR: rv.X4
    of X5RvR: rv.X5
    of X6RvR: rv.X6
    of X7RvR: rv.X7
    of X8RvR: rv.X8
    of X9RvR: rv.X9
    of X10RvR: rv.X10
    of X11RvR: rv.X11
    of X12RvR: rv.X12
    of X13RvR: rv.X13
    of X14RvR: rv.X14
    of X15RvR: rv.X15
    of X16RvR: rv.X16
    of X17RvR: rv.X17
    of X18RvR: rv.X18
    of X19RvR: rv.X19
    of X20RvR: rv.X20
    of X21RvR: rv.X21
    of X22RvR: rv.X22
    of X23RvR: rv.X23
    of X24RvR: rv.X24
    of X25RvR: rv.X25
    of X26RvR: rv.X26
    of X27RvR: rv.X27
    of X28RvR: rv.X28
    of X29RvR: rv.X29
    of X30RvR: rv.X30
    else:
      error("Expected an RV32 register `(x0)`..`(x30)` or `(sp)`", n)
      rv.X0

proc parseRegisterRv32*(n: var Cursor): rv.Register =
  if n.kind != TagLit or not rawTagIsRv32Gpr(n.tag):
    error("Expected an RV32 register `(x0)`..`(x30)` or `(sp)`", n)
  result = tagToRegisterRv32(n.tag, n)
  skip n

proc regName*(r: rv.Register): string =
  ## The ABI name where there is one, because that is what a diagnostic should
  ## say: `a0` and `x10` are the same register and only one of them tells the
  ## reader what it is for.
  case r
  of rv.X0: "zero"
  of rv.X1: "ra"
  of rv.X2: "sp"
  of rv.X3: "gp"
  of rv.X4: "tp"
  of rv.X5: "t0"
  of rv.X6: "t1"
  of rv.X7: "t2"
  of rv.X8: "s0"
  of rv.X9: "s1"
  of rv.X10: "a0"
  of rv.X11: "a1"
  of rv.X12: "a2"
  of rv.X13: "a3"
  of rv.X14: "a4"
  of rv.X15: "a5"
  of rv.X16: "a6"
  of rv.X17: "a7"
  of rv.X18: "s2"
  of rv.X19: "s3"
  of rv.X20: "s4"
  of rv.X21: "s5"
  of rv.X22: "s6"
  of rv.X23: "s7"
  of rv.X24: "s8"
  of rv.X25: "s9"
  of rv.X26: "s10"
  of rv.X27: "s11"
  of rv.X28: "t3"
  of rv.X29: "t4"
  of rv.X30: "t5"
  of rv.X31: "t6"
