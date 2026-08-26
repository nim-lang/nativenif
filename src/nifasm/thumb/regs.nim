#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> Thumb (Cortex-M) registers, core and FPv4-SP.
##
## Note `rawTagIsMGpr`: a Cortex-M register tag is ALSO a valid x86-64 one —
## `(r0)` is an alias for rax there — so the two tag sets overlap and a reader
## that cannot see the target has to record such a tag in both. Which is why the
## predicate is here rather than inferred at a use site.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as thumb2

proc rawTagIsMFloatReg*(t: TagEnum): bool {.inline.} =
  ## `(s0)`..`(s31)` — the FPv4-SP single-precision file. These spellings are
  ## AArch64's too; `(arch …)` is what decides which machine they name.
  t >= S0TagId and t <= S31TagId

proc rawTagIsMGpr*(t: TagEnum): bool {.inline.} =
  ## A Cortex-M GENERAL-purpose register. `rawTagIsMReg` covers the float file
  ## as well, so every site that means "an integer register" has to say so —
  ## otherwise `(s3)` binds a variable to r3.
  rawTagIsMReg(t) and not rawTagIsMFloatReg(t)

proc tagToFloatRegisterM*(t: TagEnum; n: Cursor): thumb2.FloatRegister =
  if not rawTagIsMFloatReg(t):
    error("Expected a Cortex-M floating-point register", n)
    return thumb2.S0
  thumb2.FloatRegister(int(t) - int(S0TagId))

proc parseFloatRegisterM*(n: var Cursor): thumb2.FloatRegister =
  if n.kind != TagLit or not rawTagIsMFloatReg(n.tag):
    error("Expected a Cortex-M floating-point register", n)
  result = tagToFloatRegisterM(n.tag, n)
  inc n

proc tagToRegisterM*(t: TagEnum; n: Cursor): thumb2.Register =
  if rawTagIsMFloatReg(t):
    error("Expected an integer register, got a floating-point one", n)
    return thumb2.R0
  let regTag = tagToMReg(t)
  result =
    case regTag
    of R0MR: thumb2.R0
    of R1MR: thumb2.R1
    of R2MR: thumb2.R2
    of R3MR: thumb2.R3
    of R4MR: thumb2.R4
    of R5MR: thumb2.R5
    of R6MR: thumb2.R6
    of R7MR: thumb2.R7
    of R8MR: thumb2.R8
    of R9MR: thumb2.R9
    of R10MR: thumb2.R10
    of R11MR: thumb2.R11
    of R12MR: thumb2.R12
    of SpMR: thumb2.SP
    of LrMR: thumb2.LR
    else:
      error("Expected a Cortex-M register", n)
      thumb2.R0

proc parseRegisterM*(n: var Cursor): thumb2.Register =
  if n.kind != TagLit or not rawTagIsMGpr(n.tag):
    error("Expected a Cortex-M register", n)
  result = tagToRegisterM(n.tag, n)
  inc n
