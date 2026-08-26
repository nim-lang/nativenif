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

proc tagToNifasmExpr*(t: TagEnum): NifasmExpr {.inline.} =
  ## Convert TagEnum to NifasmExpr. Returns NoExpr if not a valid NifasmExpr.
  if rawTagIsNifasmExpr(t):
    cast[NifasmExpr](t)
  else:
    NoExpr

proc tagToRvInst*(t: TagEnum): RvInst {.inline.} =
  ## Convert TagEnum to RvInst (RV32). Returns NoRvInst if not a valid RvInst.
  if rawTagIsRvInst(t):
    cast[RvInst](t)
  else:
    NoRvInst

proc tagToRvReg*(t: TagEnum): RvReg {.inline.} =
  ## Convert TagEnum to RvReg (RV32). Returns NoRvReg if not a valid RvReg.
  ##
  ## RV32 shares its ENTIRE register file with AArch64 — `(x0)`, `(sp)`, `(d0)`,
  ## `(s0)` are the same tags on both — so every valid `RvReg` is also a valid
  ## `A64Reg`. Which machine one names is decided by `(arch …)`, exactly as it is
  ## for the `(r0)` that Cortex-M and x86-64 share.
  if rawTagIsRvReg(t):
    cast[RvReg](t)
  else:
    NoRvReg
