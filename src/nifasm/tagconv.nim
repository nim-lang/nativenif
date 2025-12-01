## Conversion functions from TagEnum to specific enum types
## These functions convert generic TagEnum values to architecture-specific enum types

import instructions, model

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

