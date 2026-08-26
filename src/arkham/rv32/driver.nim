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
  for name, decl in g.prog.tvars:
    lengError decl, "RV32: thread-local storage is not implemented yet: `" &
                    name & "`", lengInfo(decl)

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
    # No `(type …)` declarations: `genTypeBodyRv` INLINES a named type wherever
    # it is used, so nifasm sees the layout at the point it needs it. That costs
    # some asm-NIF size and buys one less thing to keep in agreement.
    for name, decl in g.prog.globals:
      g.genGlobalRv(name, decl)
    for sp in g.prog.syscalls:            # one shim each, called like any proc
      g.emitSyscallShim(sp)
    for info in g.prog.procs:
      g.genProcRv(info)
    for (nm, bytes) in g.rodata:
      g.ab.tree NifasmDecl.RodataD:
        g.ab.symDef nm
        g.ab.str bytes
  result = g.ab.render("." & g.prog.thisModuleSuffix)
