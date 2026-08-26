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
## What exists today is the spine: the program walk, the proc signature, the ABI
## clobber list, and the entry proc's exit path. A proc whose body returns a
## constant compiles and runs. Everything else is refused BY NAME with the
## milestone that covers it, rather than emitted wrongly.

import std / [tables]
import nifcore
import ../core/[asmbuf, context, programs, machinedesc, asmslots, diag,
                lengdecl, typeutil]
import machine

const
  AvrtestExit = 30
    ## AVRtest's `SYSCALL 30`: exit with the status in r25:r24. The freestanding
    ## twin of Cortex-M's semihosting `SYS_EXIT_EXTENDED`, and reached the same
    ## way — the entry proc's `ret` IS the process exit, because there is nothing
    ## to return to. See doc/internals/avr.md.

proc emitLdi16(g: var CodeGen; d: Reg; v: int64) =
  ## A 16-bit constant into a pair. Two `ldi`s when the pair is `ldi`-capable,
  ## which the return pair (r25:r24) is — one more reason the ABI puts the result
  ## there. A low pair would need the constant staged through a bridge and a
  ## `movw`; nothing in this slice can reach one, so that path is M4c's.
  if ord(d) < ord(P16):
    lengError default(Cursor),
      "AVR: a constant cannot be materialized into " & regName(d) &
      " — `ldi` reaches r16..r31 only (see M4c in doc/internals/avr.md)"
  g.ab.tree LdiAvr:
    g.ab.regNamed lowName(d)
    g.ab.intLit(v and 0xFF)
  g.ab.tree LdiAvr:
    g.ab.regNamed highName(d)
    g.ab.intLit((v shr 8) and 0xFF)

proc retConstOf(decl: Cursor; v: var int64): bool =
  ## Recognise `(proc … (stmts (ret <int literal>)))` — the whole of the body
  ## shape this slice compiles. Deliberately a pattern match and not a walk: what
  ## it does NOT match is refused by name, which is the property that makes a
  ## partial backend safe to ship.
  ##
  ## Plain `inc`/`skip` on a copy rather than `into`, because `into` asserts that
  ## its body consumed every child — which a match that can fail at any step
  ## cannot promise.
  var c = decl
  inc c                        # into (proc …), at the name
  inc c                        # past the name, at (params …)
  skip c                       # past params, at the result type
  skip c                       # past the result type, at (pragmas …)
  skip c                       # past pragmas, at the body
  if c.stmtKind != StmtsS: return false
  inc c                        # into (stmts …), at the first statement
  if c.stmtKind != RetS: return false
  var retNode = c
  inc c                        # into (ret …), at the returned expression
  if c.kind notin {IntLit, UIntLit}: return false
  v = if c.kind == IntLit: intVal(c) else: cast[int64](uintVal(c))
  inc c
  if c.hasMore: return false   # `(ret …)` had more than one child
  skip retNode                 # past the whole `(ret …)`
  result = not retNode.hasMore # and the body held nothing after it

proc genProcAvr(g: var CodeGen; info: ProcInfo) =
  ## A proc with no parameters whose body returns a constant.
  ##
  ## Emitted with NO frame, and that is not an optimization to be revisited: an
  ## AVR frame costs seven instructions to establish — two `push`es, two `in`s,
  ## the arithmetic, two `out`s — because SP lives in the I/O space and has to be
  ## read and written a byte at a time. A proc with no stack slot pays none of it.
  if info.isAsm or info.isNaked or info.irqName.len > 0:
    lengError info.decl,
      "AVR: `{.assembler.}`, `{.naked.}` and `{.interrupt.}` are not implemented " &
      "yet (see M6 in doc/internals/avr.md)", lengInfo(info.decl)
  var v = 0'i64
  if not retConstOf(info.decl, v):
    lengError info.decl,
      "AVR: this proc's body is not yet supported — the backend compiles a `ret` " &
      "of a constant and nothing else so far (see M4c in doc/internals/avr.md)",
      lengInfo(info.decl)

  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef info.asmName
    g.ab.keyword NifasmDecl.ParamsD
    g.ab.tree NifasmDecl.ResultD:
      g.ab.symDef(SynthMark & "ret.0")
      g.ab.rawReg g.md.intRetReg
      g.ab.intType 16
    # The ABI declared at the signature rather than re-derived at every call
    # site, exactly as the other targets do it.
    g.ab.tree NifasmDecl.ClobberD:
      for r in g.md.convClobbersGpr: g.ab.rawReg r
    g.ab.tree StmtsAvr:
      g.emitLdi16(g.md.intRetReg, v)
      if info.isEntry:
        # The entry proc's `ret` IS the process exit: this is a freestanding
        # image and there is nothing to return to. `(bkpt 30)` hands r25:r24 to
        # the simulator as the status, which is what makes an `.exitcode` fixture
        # work here the way it does on every other target.
        g.ab.tree BkptAvr: g.ab.intLit AvrtestExit
      else:
        g.ab.keyword RetAvr

proc rejectForAvr(g: CodeGen) =
  ## Everything the backend does not implement, refused BY NAME before a single
  ## instruction is emitted. A partial backend is only safe to ship if the gap is
  ## a diagnostic rather than a wrong answer, and the gap is wide here.
  if g.prog.globals.len > 0:
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
    for info in g.prog.procs:
      g.isEntryProc = info.isEntry
      g.genProcAvr(info)
  result = g.ab.render("." & g.prog.thisModuleSuffix)
