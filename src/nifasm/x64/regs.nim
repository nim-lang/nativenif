#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> x86-64 registers.
##
## A flat table and the diagnostic for "that is not one of mine". Nothing here
## knows about instructions, operands or the run state, which is what lets the
## type parser reach it without dragging a selector in.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as x86

proc tagToRegister*(t: TagEnum; n: Cursor): x86.Register =
  ## Convert a TagEnum to an x86 Register (for register binding tracking)
  let regTag = tagToX64Reg(t)
  result =
    case regTag
    of RaxR, R0R: x86.RAX
    of RcxR, R2R: x86.RCX
    of RdxR, R3R: x86.RDX
    of RbxR, R1R: x86.RBX
    of RspR, R7R: x86.RSP
    of RbpR, R6R: x86.RBP
    of RsiR, R4R: x86.RSI
    of RdiR, R5R: x86.RDI
    of R8R: x86.R8
    of R9R: x86.R9
    of R10R: x86.R10
    of R11R: x86.R11
    of R12R: x86.R12
    of R13R: x86.R13
    of R14R: x86.R14
    of R15R: x86.R15
    else:
      error("Expected GPR register, got: " & $t, n)
      x86.RAX

proc parseRegister*(n: var Cursor): x86.Register =
  result = tagToRegister(n.tag, n)
  inc n

proc isXmmTag*(n: Cursor): bool {.inline.} =
  n.kind == TagLit and n.tag >= Xmm0TagId and n.tag <= Xmm15TagId

proc isXmmTagEnum*(t: TagEnum): bool {.inline.} =
  t >= Xmm0TagId and t <= Xmm15TagId

proc tagToXmm*(t: TagEnum): x86.XmmRegister {.inline.} =
  x86.XmmRegister(ord(t) - ord(Xmm0TagId))

proc parseXmm*(n: var Cursor): x86.XmmRegister =
  ## Parse a *raw* `(xmmN)` SSE register operand (N in 0..15). Used only where a
  ## bare register is required (the `rebind`/`withreg` target). Operand reads in the
  ## scalar-float instructions go through `parseXmmOperand`, which also accepts a
  ## bound name and rejects a raw use of a bound register.
  if not isXmmTag(n):
    error("expected xmm register", n)
  result = x86.XmmRegister(ord(n.tag) - ord(Xmm0TagId))
  inc n
