## Conversion functions from TagEnum to specific enum types
## These functions convert generic TagEnum values to architecture-specific enum types

import tags, model

proc tagToX64Inst*(t: TagEnum): X64Inst {.inline.} =
  ## Convert TagEnum to X64Inst. Returns NoX64Inst if not a valid X64Inst.
  if rawTagIsX64Inst(t):
    cast[X64Inst](t)
  else:
    NoX64Inst

proc tagToX64Reg*(t: TagEnum): X64Reg {.inline.} =
  ## Convert TagEnum to X64Reg. Returns NoReg if not a valid X64Reg.
  if rawTagIsX64Reg(t):
    cast[X64Reg](t)
  else:
    NoReg

proc tagToX64Flag*(t: TagEnum): X64Flag {.inline.} =
  ## Convert TagEnum to X64Flag. Returns NoFlag if not a valid X64Flag.
  if rawTagIsX64Flag(t):
    cast[X64Flag](t)
  else:
    NoFlag

proc tagToA64Inst*(t: TagEnum): A64Inst {.inline.} =
  ## Convert TagEnum to A64Inst. Returns NoA64Inst if not a valid A64Inst.
  if rawTagIsA64Inst(t):
    cast[A64Inst](t)
  else:
    NoA64Inst

proc tagToA64Reg*(t: TagEnum): A64Reg {.inline.} =
  ## Convert TagEnum to A64Reg. Returns NoReg if not a valid A64Reg.
  if rawTagIsA64Reg(t):
    cast[A64Reg](t)
  else:
    NoReg

proc tagToNifasmDecl*(t: TagEnum): NifasmDecl {.inline.} =
  ## Convert TagEnum to NifasmDecl. Returns NoDecl if not a valid NifasmDecl.
  if rawTagIsNifasmDecl(t):
    cast[NifasmDecl](t)
  else:
    NoDecl

proc tagToMInst*(t: TagEnum): MInst {.inline.} =
  ## Convert TagEnum to MInst (Cortex-M). Returns NoMInst if not a valid MInst.
  if rawTagIsMInst(t):
    cast[MInst](t)
  else:
    NoMInst

proc tagToMReg*(t: TagEnum): MReg {.inline.} =
  ## Convert TagEnum to MReg (Cortex-M). Returns NoMReg if not a valid MReg.
  ##
  ## Cortex-M shares its register SPELLINGS with the other targets — `(r0)` is
  ## also an x86-64 alias for rax — so a tag can be a valid `X64Reg` and a valid
  ## `MReg` at once. Which one it means is decided by `(arch …)`, not by the tag.
  if rawTagIsMReg(t):
    cast[MReg](t)
  else:
    NoMReg

proc tagToAvrInst*(t: TagEnum): AvrInst {.inline.} =
  ## Convert TagEnum to AvrInst. Returns NoAvrInst if not a valid AvrInst.
  if rawTagIsAvrInst(t):
    cast[AvrInst](t)
  else:
    NoAvrInst

proc tagToAvrReg*(t: TagEnum): AvrReg {.inline.} =
  ## Convert TagEnum to AvrReg. Returns NoAvrReg if not a valid AvrReg.
  ##
  ## AVR shares r0..r15 with the spellings that already existed and mints
  ## r16..r31 and the sixteen `(rpN)` PAIR tags of its own, so — as on Cortex-M —
  ## a tag can be a valid `X64Reg` and a valid `AvrReg` at once, and `(arch …)`
  ## is what decides which file it names.
  if rawTagIsAvrReg(t):
    cast[AvrReg](t)
  else:
    NoAvrReg

proc tagToRv32Inst*(t: TagEnum): Rv32Inst {.inline.} =
  ## Convert TagEnum to Rv32Inst. Returns NoRv32Inst if not a valid Rv32Inst.
  if rawTagIsRv32Inst(t):
    cast[Rv32Inst](t)
  else:
    NoRv32Inst

proc tagToRv32Reg*(t: TagEnum): Rv32Reg {.inline.} =
  ## Convert TagEnum to Rv32Reg. Returns NoRv32Reg if not a valid Rv32Reg.
  ##
  ## RV32 mints no register spelling of its own — `(x0)`..`(x30)` and `(sp)` are
  ## AArch64's, reused — so every tag here is a valid `A64Reg` too and `(arch …)`
  ## is what decides which machine it names.
  if rawTagIsRv32Reg(t):
    cast[Rv32Reg](t)
  else:
    NoRv32Reg

proc tagToNifasmExpr*(t: TagEnum): NifasmExpr {.inline.} =
  ## Convert TagEnum to NifasmExpr. Returns NoExpr if not a valid NifasmExpr.
  if rawTagIsNifasmExpr(t):
    cast[NifasmExpr](t)
  else:
    NoExpr
