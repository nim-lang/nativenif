#
#           Arkham — the RV32 backend entry point
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Leng in, RV32 asm-NIF out.
##
## The value core is `gen.nim`; this file is the program walk around it. RV32
## needs its own emitter rather than riding on AArch64's the way Cortex-M does,
## and the reason is narrow but decisive: **RISC-V has no condition flags**, so
## `(cmp D S)` followed by `(beq L)` describes nothing this machine does. A
## comparison is `slt` into a register or a two-register branch, and the shared
## vocabulary can spell neither. See doc/internals/rv32.md.

import std / [tables]
import nifcore
import ../core/[asmbuf, context, programs, machinedesc, asmslots, diag,
                lengdecl, typeutil]
import machine
import emit
import gen

proc rejectForRv32(g: CodeGen) =
  ## Everything this backend does not implement, refused BY NAME before a single
  ## instruction is emitted.
  for name, decl in g.prog.globals:
    lengError decl, "RV32: the global `" & name & "` is not implemented yet " &
                    "(see R5 in doc/internals/rv32.md)", lengInfo(decl)
  for name, decl in g.prog.tvars:
    lengError decl, "RV32: thread-local storage is not implemented yet: `" &
                    name & "`", lengInfo(decl)
  if g.prog.syscalls.len > 0:
    lengError default(Cursor),
      "RV32: a syscall is `(ecall)` with the number in a7, and the emitter does " &
      "not lower one yet (see R5 in doc/internals/rv32.md)"

proc generateRv32*(buf: var TokenBuf; inputPath: string; tags: TagPool): string =
  ## Compile a parsed Leng module to RV32 asm-NIF, which nifasm's `rv32` target
  ## assembles into a static Linux ELF32.
  setTargetWord Word32             # 4-byte pointers, 4-byte platform int
  var g = newCodeGen(buf, rv32Machine)
  g.ab.renderReg = machine.regName # `(xN)` — what `nifasm/rv32/regs` parses
  g.ab.arch = "rv32"               # no BodyLib entries apply to this target yet
  g.prog = collect(buf, inputPath, tags)
  g.rejectForRv32()
  g.adoptProgram()
  g.ab.tree StmtsRv:
    g.ab.tree NifasmDecl.ArchD: g.ab.ident "rv32"
    for info in g.prog.procs:
      g.genProcRv(info)
  result = g.ab.render("." & g.prog.thisModuleSuffix)
