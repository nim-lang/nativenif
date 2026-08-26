#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> AArch64 registers, integer and SIMD/FP.
##
## The AArch64 twin of `x64/regs`: a flat table and its diagnostic, with no
## knowledge of instructions, operands or run state.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as arm64

proc tagToRegisterA64*(t: TagEnum; n: Cursor): arm64.Register =
  ## Convert a TagEnum to an ARM64 Register (for register binding tracking)
  ## Note: X16/X17 are reserved for assembler scratch use but allowed in direct
  ## instructions (e.g., Darwin syscalls use X16 for syscall number).
  let regTag = tagToA64Reg(t)
  result =
    case regTag
    of X0R: arm64.X0
    of X1R: arm64.X1
    of X2R: arm64.X2
    of X3R: arm64.X3
    of X4R: arm64.X4
    of X5R: arm64.X5
    of X6R: arm64.X6
    of X7R: arm64.X7
    of X8R: arm64.X8
    of X9R: arm64.X9
    of X10R: arm64.X10
    of X11R: arm64.X11
    of X12R: arm64.X12
    of X13R: arm64.X13
    of X14R: arm64.X14
    of X15R: arm64.X15
    of X16R: arm64.X16
    of X17R: arm64.X17
    of X18R: arm64.X18
    of X19R: arm64.X19
    of X20R: arm64.X20
    of X21R: arm64.X21
    of X22R: arm64.X22
    of X23R: arm64.X23
    of X24R: arm64.X24
    of X25R: arm64.X25
    of X26R: arm64.X26
    of X27R: arm64.X27
    of X28R: arm64.X28
    of X29R: arm64.X29
    of X30R: arm64.X30
    of SpR: arm64.SP
    of LrR: arm64.LR
    of FpR: arm64.FP
    of XzrR: arm64.Register(31)
    else:
      error("Expected ARM64 register, got: " & $t, n)
      arm64.X0

proc parseRegisterA64*(n: var Cursor): arm64.Register =
  result = tagToRegisterA64(n.tag, n)
  inc n

proc isA64DoubleRegTag(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(D0TagId) and ord(t) <= ord(D31TagId)

proc isA64SingleRegTag*(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(S0TagId) and ord(t) <= ord(S31TagId)

proc isA64FpRegTag*(t: TagEnum): bool {.inline.} =
  ## True for any scalar fp register tag `(d0)`..`(d31)` / `(s0)`..`(s31)`.
  isA64DoubleRegTag(t) or isA64SingleRegTag(t)

proc isA64FpRegOperand*(n: Cursor): bool {.inline.} =
  n.kind == TagLit and isA64FpRegTag(n.tag)

proc isA64SingleOperand(n: Cursor): bool {.inline.} =
  ## Whether the fp register operand `n` is single-precision `(sN)`.
  n.kind == TagLit and isA64SingleRegTag(n.tag)

proc parseFloatRegisterA64*(n: var Cursor): arm64.FloatRegister =
  if not isA64FpRegOperand(n): error("Expected fp register (dN/sN)", n)
  let base = if isA64SingleRegTag(n.tag): ord(S0TagId) else: ord(D0TagId)
  result = arm64.FloatRegister(ord(n.tag) - base)
  inc n

proc tagToFloatRegA64*(t: TagEnum): arm64.FloatRegister {.inline.} =
  let base = if isA64SingleRegTag(t): ord(S0TagId) else: ord(D0TagId)
  result = arm64.FloatRegister(ord(t) - base)
