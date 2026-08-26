#
#           Arkham — the AVR backend entry point
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Leng in, AVR asm-NIF out.
##
## **Why this is a new emitter and not the Cortex-M arrangement.** `generateM`
## is the AArch64 emitter driven with a different machine model, and that works
## because Thumb-2 and AArch64 share the asm-NIF vocabulary at the instruction
## level: `add3`, `cmp`, `beq`, `ldr` mean the same thing on both, so a third
## target needed only a register file, a word size, and honest refusals.
##
## AVR cannot be reached that way, and the reason is exactly the thing that makes
## this target interesting: one asm-NIF node is one 8-bit instruction, so a
## 16-bit add is `(add)` plus `(adc)` on the halves and a 16-bit compare is
## `(cmp)` plus `(cpc)`. That decomposition has to happen inside the value core,
## which emits directly in over a hundred places rather than through a primitive
## layer a machine model could redirect. So the value core is this target's own —
## the irreducible piece `doc/internals/module_layout.md` measures at roughly
## four thousand lines per backend, and the one whose register-binding protocol
## has a formal model behind it.
##
## The value core is `gen.nim`; this file is the program walk around it — the
## module header, the types, and the refusals for what the target has no meaning
## for at all.

import std / [tables]
import nifcore
import ../core/[asmbuf, context, programs, machinedesc, asmslots, diag,
                lengdecl, typeutil]
import machine
import emit
import gen

proc rejectForAvr(g: CodeGen) =
  ## Everything the backend does not implement, refused BY NAME before a single
  ## instruction is emitted. A partial backend is only safe to ship if the gap is
  ## a diagnostic rather than a wrong answer, and the gap is wide here.
  if false:
    for name, decl in g.prog.globals:
      lengError decl, "AVR: the global `" & name & "` is not implemented yet " &
                      "(see M6 in doc/internals/avr.md)", lengInfo(decl)
  if g.prog.tvars.len > 0:
    for name, decl in g.prog.tvars:
      lengError decl, "AVR has no thread-local storage: `" & name & "`",
                lengInfo(decl)
  if g.prog.syscalls.len > 0:
    lengError default(Cursor),
      "AVR is a bare-metal target: there is no OS to call into"

proc generateAvr*(buf: var TokenBuf; inputPath: string; tags: TagPool): string =
  ## Compile a parsed Leng module to AVR asm-NIF, which nifasm's `avr` target
  ## assembles into a bare-metal firmware image.
  setTargetWord Word16             # 2-byte pointers, 2-byte platform int
  var g = newCodeGen(buf, avrMachine)
  g.ab.renderReg = machine.regName # render a slot as the PAIR it is: `(rpN)`
  g.ab.arch = "avr"                # no BodyLib entries apply to this target yet
  g.prog = collect(buf, inputPath, tags)
  g.rejectForAvr()
  g.adoptProgram()
  g.ab.tree StmtsAvr:
    g.ab.tree NifasmDecl.ArchD: g.ab.ident "avr"
    for name, decl in g.prog.globals:
      g.genGlobalAvr(name, decl)
    for info in g.prog.procs:
      g.isEntryProc = info.isEntry
      g.genProcAvr(info)
  result = g.ab.render("." & g.prog.thisModuleSuffix)
