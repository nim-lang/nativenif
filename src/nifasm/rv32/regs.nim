#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> RV32 registers, integer and floating-point.
##
## RV32 mints no register spellings: it reuses AArch64's whole file, so every tag
## here is also a valid `A64Reg` and which machine it names is decided by
## `(arch …)`. The same arrangement `(r0)` already has between Cortex-M and
## x86-64, and for the same reason — see `tagToRvReg`.
##
## The mapping is the identity on the integer side (`(x0)`..`(x30)` are RISC-V's
## `x0`..`x30`) with `(sp)` as a second spelling of `x2`, which RISC-V's ABI
## names `sp`. `x31` is deliberately unreachable: no tag names it, so it is the
## one register the SELECTOR can always take as a transient — the RV32 answer to
## Thumb's `IP` and AArch64's `x16`, but stronger, because it is not merely
## reserved by convention. Nothing in asm-NIF can even spell it.
##
## The float side is where the two ISAs genuinely differ in shape. AArch64's
## `(d3)` and `(s3)` are two VIEWS of one 128-bit vector register; RISC-V's `f3`
## is one register whose precision is chosen by the instruction's `fmt` field.
## Both spellings therefore map to the same `FloatRegister` and differ only in
## the width they carry, which is exactly what `fmt` wants — so the asm-NIF that
## AArch64 already emits needs no translation at all.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as rv

const RvScratch* = rv.X31
  ## `t6`, the register no asm-NIF tag can name (see the module header). The
  ## selector materializes an out-of-range displacement, a compare's immediate
  ## operand and a folded index through it. Because arkham cannot spell it, no
  ## value ever lives here and nothing has to prove that.

proc rawTagIsRvFloatReg*(t: TagEnum): bool {.inline.} =
  ## `(d0)`..`(d31)` and `(s0)`..`(s31)`. Both name the FP file; the tag says
  ## which PRECISION, not which register bank.
  (t >= D0TagId and t <= D31TagId) or (t >= S0TagId and t <= S31TagId)

proc rawTagIsRvGpr*(t: TagEnum): bool {.inline.} =
  ## An INTEGER register. `rawTagIsRvReg` covers the float file too, so every site
  ## that means "a general-purpose register" has to say so — otherwise `(s3)`
  ## binds a variable to `x3`, which is `gp`.
  rawTagIsRvReg(t) and not rawTagIsRvFloatReg(t)

proc rvFloatWidth*(t: TagEnum): rv.FpWidth {.inline.} =
  ## Which precision the spelling names: `(dN)` double, `(sN)` single. This is the
  ## `fmt` field of every FP instruction the operand ends up in.
  if t >= D0TagId and t <= D31TagId: rv.FpD else: rv.FpS

proc tagToFloatRegisterRv*(t: TagEnum; n: Cursor): rv.FloatRegister =
  if t >= D0TagId and t <= D31TagId:
    rv.FloatRegister(int(t) - int(D0TagId))
  elif t >= S0TagId and t <= S31TagId:
    rv.FloatRegister(int(t) - int(S0TagId))
  else:
    error("Expected an RV32 floating-point register", n)
    rv.F0

proc parseFloatRegisterRv*(n: var Cursor): tuple[reg: rv.FloatRegister; w: rv.FpWidth] =
  if n.kind != TagLit or not rawTagIsRvFloatReg(n.tag):
    error("Expected an RV32 floating-point register", n)
    return (rv.F0, rv.FpD)
  result = (tagToFloatRegisterRv(n.tag, n), rvFloatWidth(n.tag))
  inc n

proc tagToRegisterRv*(t: TagEnum; n: Cursor): rv.Register =
  if rawTagIsRvFloatReg(t):
    error("Expected an integer register, got a floating-point one", n)
    return rv.X0
  let regTag = tagToRvReg(t)
  if regTag == SpRV: return rv.Sp        # `(sp)`: RISC-V's `x2`, spelled twice
  if regTag == NoRvReg:
    error("Expected an RV32 register", n)
    return rv.X0
  # `(x0)`..`(x30)` are consecutive tags AND consecutive registers, so the map is
  # arithmetic rather than a 31-arm case. `x31` is absent on purpose: it is the
  # selector's scratch and no tag names it.
  let t2 = TagEnum(ord(regTag))
  if t2 >= X0TagId and t2 <= X30TagId:
    rv.Register(int(t2) - int(X0TagId))
  else:
    error("Expected an RV32 register", n)
    rv.X0

proc parseRegisterRv*(n: var Cursor): rv.Register =
  if n.kind != TagLit or not rawTagIsRvGpr(n.tag):
    error("Expected an RV32 register", n)
  result = tagToRegisterRv(n.tag, n)
  inc n
