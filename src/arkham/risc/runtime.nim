#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## The code arkham SYNTHESIZES for a bare-metal Cortex-M image — the part of a
## program nobody wrote.
##
##  * the reset path: enable the FPU, copy `.data` from its flash image, zero
##    `.bss`, and only then call `main`;
##  * semihosting: how a firmware image with no OS prints and exits, by
##    trapping to the debugger;
##  * the 64-bit divide helpers, because ARMv7E-M has no `udiv`/`sdiv` wide
##    enough and there is no libgcc to borrow one from.
##
## All three are emitted only for the target that needs them.

import std / [assertions]
import nifcore
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, typeutil, 
                    mirrors, abi]
import machine_a64 as machine
from machine_m as machine_m import nil
import emit, value

const
  Rv32DefaultStackTop* = 0x8020_0000'i64
    ## The top of QEMU `virt`'s SRAM region, used when no `--layout:` names one.
    ## MUST agree with `nifasm/image/writerv32`'s `Rv32SramAddr + Rv32SramSize` —
    ## a stack pointer above the region the image declares is not a diagnosable
    ## error, it is a store into nothing.
  CsrMstatus* = 0x300'i64
  MstatusFsDirty* = 0x6000'i64
    ## `mstatus.FS = Dirty`. Any non-zero FS enables the FP unit; `Dirty` is
    ## chosen because it is the state the first FP instruction would move it to
    ## anyway, so nothing has to reason about a later transition.

proc argReg*(g: CodeGen; i: int): Reg {.inline.} =
  ## Argument register `i` of the target being emitted for.
  ##
  ## This file is HAND-WRITTEN asm-NIF, not allocator output, so it names its
  ## registers directly — and naming them `R0`..`R3` was correct only while the
  ## one target with a runtime happened to put its arguments there. Cortex-M's
  ## `a0`–`a3` are `r0`–`r3`; RV32's are `x10`–`x13`. Reading them off the
  ## machine description is what lets one runtime serve both, and is the same
  ## move `MachineDesc`'s register ROLES already made for the emitter.
  ##
  ## `argReg(0)` is also the RESULT register on every target here — `intRetReg`
  ## and `intArgRegs[0]` coincide — so a shim that computes into it needs no
  ## separate spelling.
  assert i < g.md.intArgRegs.len, "runtime: argument register out of range"
  g.md.intArgRegs[i]

proc emSemihostCall*(g: var CodeGen) =
  ## The semihosting escape: operation in `argReg(0)`, parameter block in
  ## `argReg(1)`, result back in `argReg(0)`. The PROTOCOL is shared — RISC-V
  ## semihosting deliberately reuses ARM's `SYS_*` numbers — but the escape
  ## instruction is not: Arm traps with a `bkpt #0xAB`, and RISC-V with a
  ## three-word sequence whose two outer instructions write `x0` and are therefore
  ## architecturally no-ops. Both are one asm-NIF node here.
  case g.md.arch
  of ThumbM:
    g.ab.tree BkptM: g.ab.intLit SemiBkpt
  of Rv32:
    g.ab.keyword SemihostRv
  else:
    quit "arkham " & g.md.targetName & ": no semihosting escape on this target"

proc emEnableFpuM*(g: var CodeGen) =
  ## Turn the FPU on, first thing in the entry proc.
  ##
  ## Cortex-M4F comes out of reset with the FPU DISABLED: CPACR grants no access
  ## to CP10/CP11, and the first VFP instruction takes a UsageFault (NOCP) —
  ## which, with no handler installed, is a lockup at the top of `main` with
  ## nothing to say why. Every image gets this, because whether it uses a float
  ## is not known when the entry proc is emitted, and twenty bytes once is not
  ## worth being clever about.
  ##
  ## The DSB/ISB pair is not decoration: CPACR changes how LATER instructions
  ## behave, so the write has to complete and the pipeline be re-fetched before
  ## the first floating-point instruction. QEMU forgives its absence; silicon
  ## does not.
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit CpacrAddr)
  g.ab.tree LdrA64:
    g.ab.rawReg g.argReg(1)
    g.ab.tree MemX: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
  g.ab.tree OrrA64: (g.ab.rawReg g.argReg(1); g.ab.intLit CpacrFullAccessCp10Cp11)
  g.ab.tree StrA64:
    g.ab.tree MemX: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
    g.ab.rawReg g.argReg(1)
  g.ab.keyword DsbM
  g.ab.keyword IsbM

proc emResetPathRv*(g: var CodeGen; stackTop: int64) =
  ## What a RISC-V core does NOT do for an image, in the order it must be done.
  ##
  ## An M-profile core reads its initial SP out of vector-table word 0 and enters
  ## the reset handler with a usable stack. A RISC-V core does neither: `sp` holds
  ## whatever reset left there, and `mstatus.FS` is clear, so the first stack
  ## access is wild and the first floating-point instruction raises an
  ## illegal-instruction exception into an `mtvec` that has not been set either.
  ##
  ## Both failures present as a HANG rather than a fault, which is what makes them
  ## expensive: the image simply stops, at an instruction that is spelled and
  ## encoded correctly. So both are established unconditionally, before anything
  ## else, and neither is conditional on whether the program looks like it needs
  ## one — that is not knowable when this is emitted.
  g.ab.tree MovA64: (g.ab.rawReg SP; g.ab.intLit stackTop)
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit MstatusFsDirty)
  g.ab.tree CsrsRv: (g.ab.intLit CsrMstatus; g.ab.rawReg g.argReg(0))

proc emStartupInitM*(g: var CodeGen) =
  ## The reset handler's first duty: give SRAM the contents the program expects
  ## to find there.
  ##
  ## A hosted program is handed a laid-out address space by its loader. A firmware
  ## image is handed a chip: flash holds everything the image shipped with, RAM
  ## holds nothing at all, and `var counter = 7` has to become a 7 in RAM by some
  ## instruction that actually runs. So the initialized globals travel in flash as
  ## an image and are COPIED, and the rest of the region is ZEROED — the two loops
  ## below, in that order, because the second starts where the first stopped.
  ##
  ## All four numbers come from nifasm (`writeCortexMImage`), which is the only
  ## party that knows them: it decides where the initializer image lands in flash
  ## and where the region sits in SRAM. Same contract as `(ssize)` — arkham writes
  ## the instructions, nifasm fills in its own layout.
  ##
  ## r0–r3 only, and no frame: this runs before the prologue, where lr holds no
  ## return address and RAM is not yet trustworthy enough to push onto. Both counts
  ## are whole words, so the loops need no tail.
  let lDataDone = g.freshLabel()
  let lBssDone = g.freshLabel()
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.keyword DataloadX)   # flash source
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(1); g.ab.keyword DatavmaX)    # SRAM destination
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(2); g.ab.keyword DatasizeX)   # bytes to copy
  g.emitLoop:
    g.ab.tree CmpA64: (g.ab.rawReg g.argReg(2); g.ab.intLit 0)
    g.emBr(BeqA64, lDataDone)
    g.ab.tree LdrA64:
      g.ab.rawReg g.argReg(3)
      g.ab.tree MemX: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
    g.ab.tree StrA64:
      g.ab.tree MemX: (g.ab.rawReg g.argReg(1); g.ab.intLit 0)
      g.ab.rawReg g.argReg(3)
    g.ab.tree AddA64: (g.ab.rawReg g.argReg(0); g.ab.intLit 4)
    g.ab.tree AddA64: (g.ab.rawReg g.argReg(1); g.ab.intLit 4)
    g.ab.tree SubA64: (g.ab.rawReg g.argReg(2); g.ab.intLit 4)
  g.emLab(lDataDone)
  # r1 stopped exactly one byte past `.data`, which is where `.bss` begins — so
  # the zero loop needs no address of its own, and cannot disagree with the copy
  # about where the boundary was.
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(2); g.ab.keyword BsssizeX)
  g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.intLit 0)
  g.emitLoop:
    g.ab.tree CmpA64: (g.ab.rawReg g.argReg(2); g.ab.intLit 0)
    g.emBr(BeqA64, lBssDone)
    g.ab.tree StrA64:
      g.ab.tree MemX: (g.ab.rawReg g.argReg(1); g.ab.intLit 0)
      g.ab.rawReg g.argReg(3)
    g.ab.tree AddA64: (g.ab.rawReg g.argReg(1); g.ab.intLit 4)
    g.ab.tree SubA64: (g.ab.rawReg g.argReg(2); g.ab.intLit 4)
  g.emLab(lBssDone)

proc semiTtyName*(g: CodeGen): string {.inline.} =
  ## The `:tt` name and the console handle, MODULE-QUALIFIED.
  ##
  ## A one-dot symbol is module-LOCAL: the render compresses it, the embedded
  ## index leaves it out, and nothing outside the module can resolve it. That was
  ## fine while the only Cortex-M programs were single-module fixtures, and stops
  ## being fine the moment the `write` shim lives in a foreign module — which is
  ## where it lives in a real program, because `system` is what imports `write`.
  ## The importer loads the shim, the shim names these two, and nifasm has
  ## nothing to resolve them against: "Unknown symbol: `shwh.0 in proc
  ## write.sys.sysvq0asl".
  ##
  ## So they carry the module suffix, exactly as the syprocs beside them do
  ## (`<name>.sys.<thisModule>`, see `programs.collect`) and for exactly the same
  ## reason. The render compresses the suffix back to a trailing dot for a
  ## same-module reference, so the emitted text is unchanged where it already
  ## worked.
  SemiTtyBase & "." & thisModuleSuffix(g.prog)

proc semiTtyHandle*(g: CodeGen): string {.inline.} =
  SemiTtyHandleBase & "." & thisModuleSuffix(g.prog)

proc semiBlockSlot(g: var CodeGen; idx: int) =
  ## Declare one word of a semihosting parameter block as its own `(s)` slot.
  ##
  ## Individually, not as one `(array (i 32) N)`: a store into an array-typed slot
  ## is a type error in nifasm (the slot's type IS the array), and reaching a
  ## single element would need an `(at …)` here for no benefit. Consecutive `(s)`
  ## declarations are allocated in order and adjacent, which is exactly the layout
  ## the block needs — `allocSlotUp` walks upward from the frame base.
  g.ab.open NifasmDecl.VarD
  g.ab.symDef synth("shblk" & $idx & ".0")
  g.ab.keyword SO
  g.ab.intType(32)
  g.ab.close()

proc emitSemihostExitProc*(g: var CodeGen; asmName: string) =
  ## `exit(status)` via semihosting SYS_EXIT_EXTENDED, emitted under `asmName`.
  ##
  ## Emitted under two names in a module that imports `exit`: once as the shim
  ## the entry tail-calls, once as the `importc`'d proc. Two copies of ten nodes,
  ## rather than one plus a forwarding frame — the shim must work before any
  ## frame exists.
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef asmName
    g.ab.tree NifasmDecl.ParamsD:
      g.ab.tree NifasmDecl.ParamD:
        g.ab.symDef paramName(0)
        g.ab.rawReg g.argReg(0)
        g.ab.intType(32)
    g.ab.tree NifasmDecl.ClobberD:
      for r in g.md.convClobbersGpr: g.ab.rawReg r
    g.ab.tree StmtsA64:
      g.semiBlockSlot(0)                          # reason
      g.semiBlockSlot(1)                          # status
      g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.keyword SsizeX)
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(2); g.ab.intLit AdpStoppedApplicationExit)
      g.ab.tree MovA64: (g.ab.sym synth("shblk0.0"); g.ab.rawReg g.argReg(2))
      g.ab.tree MovA64: (g.ab.sym synth("shblk1.0"); g.ab.rawReg g.argReg(0))
      g.ab.tree LeaA64: (g.ab.rawReg g.argReg(1); g.ab.sym synth("shblk0.0"))
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit SemiExitExtended)
      g.emSemihostCall()
      g.ab.keyword RetA64               # unreachable: SYS_EXIT does not return

proc emitSemihostRuntime*(g: var CodeGen; sp: SyscallProc) =
  ## Emit the ARM-semihosting implementation of one "syscall".
  ##
  ## On Linux a `(syproc …)` declares the trap and every call site becomes an
  ## `svc`. Cortex-M has no OS to trap into, so the same NAME becomes a real proc
  ## here and the call sites stay ordinary `bl`s — which is why `genCall` only
  ## emits `(svc)` when not `thumbM`.
  ##
  ## Only the two operations semihosting actually provides are served; anything
  ## else is refused by name rather than silently emitted as a call to a proc
  ## that does not exist.
  ##
  ## Registers are emitted with `ab.rawReg`, not `emReg`: this body is hand-written
  ## rather than allocator output, so its raw r0–r3 uses are correct by
  ## construction and must not trip `emReg`'s unbound-scratch assertion (which
  ## exists to catch a temp that escaped the binder).
  # `asmName` is `<cname>.sys.<module>` (see programs.collect); take the C name.
  var base = sp.asmName
  block:
    for i in 0 ..< base.len - 4:
      if base[i] == '.' and base[i+1] == 's' and base[i+2] == 'y' and
         base[i+3] == 's' and base[i+4] == '.':
        base = base.substr(0, i - 1)
        break
  case base
  of "exit":
    g.emitSemihostExitProc(sp.asmName)
  of "write":
    g.ab.tree NifasmDecl.ProcD:
      g.ab.symDef sp.asmName
      # The signature has to be the one the CALL SITE plans, not three tidy
      # single-register words: Leng's `write` declares `count` as an `int64`, and
      # on this target that is a register PAIR (r2:r3). The body is unaffected —
      # `fd` and `buf` are one word each either way, so the length's low word is
      # in r2 regardless — but the DECLARATION must agree or the caller stages an
      # `(arg p2.0 1)` the callee never declared.
      var pslots: seq[AsmSlot] = @[]
      var pc = sp.decl
      inc pc                                   # (proc … → name
      inc pc                                   # name → params slot
      if pc.kind == TagLit: pslots = paramSlots(g.prog, pc)
      let plan = planCall(g.md, pslots, retByRef = false)
      g.ab.tree NifasmDecl.ParamsD:
        for i, pl in plan.args:
          g.ab.tree NifasmDecl.ParamD:
            g.ab.symDef paramName(i)
            if pl.words > 1:
              g.ab.tree RegsD:
                for k in 0 ..< pl.words: g.ab.rawReg g.md.gprAt(pl, k)
            else:
              g.ab.rawReg g.md.gprAt(pl)
            g.ab.intType(if pl.words > 1: 64 else: 32)
      var retC = sp.decl
      inc retC; skip retC; skip retC           # name, params → return type
      let wideRes = not retIsVoid(retC) and g.isWideSlot(slotOf(g.prog, retC))
      g.ab.tree NifasmDecl.ResultD:
        # A 64-bit result travels in r0:r1 with an EMPTY result slot, as
        # everywhere else on this target — see `emitSignature`.
        if not wideRes:
          g.ab.symDef synth("ret.0")
          g.ab.rawReg g.argReg(0)
          g.ab.intType(32)
      g.ab.tree NifasmDecl.ClobberD:
        for r in g.md.convClobbersGpr: g.ab.rawReg r
      g.ab.tree StmtsA64:
        # Five words: the three-field semihosting parameter block, plus somewhere
        # to keep `buf`/`len` across the SYS_OPEN that may run first (it needs the
        # block for its own arguments).
        for k in 0 ..< 5: g.semiBlockSlot(k)
        g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.keyword SsizeX)
        # SYS_WRITE's first field is a semihosting HANDLE, not a POSIX fd. Passing
        # a raw `1` writes NOTHING and reports success — the call returns "0 bytes
        # not written", so a caller checking the return value sees a complete
        # write of nothing. The handle comes from `SYS_OPEN(":tt")`, opened once
        # and cached in a `.bss` word; that is also what makes the same image work
        # against a hardware debug probe. Semihosting has ONE console, so the `fd`
        # argument is ignored — stdout and stderr are the same stream here.
        let lHave = g.freshLabel()
        g.ab.tree MovA64: (g.ab.sym synth("shblk3.0"); g.ab.rawReg g.argReg(1))   # save buf
        g.ab.tree MovA64: (g.ab.sym synth("shblk4.0"); g.ab.rawReg g.argReg(2))   # save len
        g.ab.tree AdrA64: (g.ab.rawReg g.argReg(0); g.ab.sym g.semiTtyHandle)
        g.ab.tree MovA64:
          g.ab.rawReg g.argReg(3)
          g.ab.tree MemX: g.ab.rawReg g.argReg(0)
        g.ab.tree CmpA64: (g.ab.rawReg g.argReg(3); g.ab.intLit 0)
        g.emBr(BneA64, lHave)
        g.ab.tree AdrA64: (g.ab.rawReg g.argReg(3); g.ab.sym g.semiTtyName)
        g.ab.tree MovA64: (g.ab.sym synth("shblk0.0"); g.ab.rawReg g.argReg(3))
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.intLit SemiOpenModeW)
        g.ab.tree MovA64: (g.ab.sym synth("shblk1.0"); g.ab.rawReg g.argReg(3))
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.intLit 3)                # len(":tt")
        g.ab.tree MovA64: (g.ab.sym synth("shblk2.0"); g.ab.rawReg g.argReg(3))
        g.ab.tree LeaA64: (g.ab.rawReg g.argReg(1); g.ab.sym synth("shblk0.0"))
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit SemiOpen)
        g.emSemihostCall()
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.rawReg g.argReg(0))                  # the handle
        g.ab.tree AdrA64: (g.ab.rawReg g.argReg(0); g.ab.sym g.semiTtyHandle)
        g.ab.tree MovA64:
          g.ab.tree MemX: g.ab.rawReg g.argReg(0)
          g.ab.rawReg g.argReg(3)
        g.emLab(lHave)
        g.ab.tree MovA64: (g.ab.sym synth("shblk0.0"); g.ab.rawReg g.argReg(3))   # handle
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.sym synth("shblk3.0"))
        g.ab.tree MovA64: (g.ab.sym synth("shblk1.0"); g.ab.rawReg g.argReg(3))   # buf
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.sym synth("shblk4.0"))
        g.ab.tree MovA64: (g.ab.sym synth("shblk2.0"); g.ab.rawReg g.argReg(3))   # len
        g.ab.tree LeaA64: (g.ab.rawReg g.argReg(1); g.ab.sym synth("shblk0.0"))
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit SemiWrite)
        g.emSemihostCall()
        # Semihosting returns the count NOT written; POSIX `write` returns the
        # count written. Converting here keeps every caller ordinary.
        g.ab.tree MovA64: (g.ab.rawReg g.argReg(2); g.ab.sym synth("shblk4.0"))
        g.ab.tree Sub3A64: (g.ab.rawReg g.argReg(0); g.ab.rawReg g.argReg(2); g.ab.rawReg g.argReg(0))
        if wideRes:
          # The caller reads r0:r1 raw. The count written is never negative, so
          # the high word is zero.
          g.ab.tree MovA64: (g.ab.rawReg g.argReg(1); g.ab.intLit 0)
        g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.keyword SsizeX)
        g.ab.keyword RetA64
  else:
    quit "arkham cortex-m: `" & base & "` has no semihosting equivalent. Only " &
         "`exit` and `write` are provided; bind anything else to an MMIO routine " &
         "of your own (see doc/cortex_m.md)."

proc emitUDivMod64*(g: var CodeGen) =
  ## The unsigned 64-bit divider.
  ##
  ## One bit per iteration: shift the 128-bit pair `R:N` left, and whenever the
  ## remainder has caught up with the divisor subtract it and set the bit that
  ## just vacated N's bottom. After 64 iterations N has been consumed entirely
  ## and holds the quotient — which is why no separate quotient register exists.
  ##
  ## Division by zero yields zero, matching what the hardware `udiv` on this
  ## core does (with DIV_0_TRP off) rather than the all-ones a shift-subtract
  ## loop would otherwise produce.
  let lZero = g.freshLabel()
  let lLoopEnd = g.freshLabel()
  let lDone = g.freshLabel()
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef g.uDivMod64Proc
    g.ab.keyword NifasmDecl.ParamsD
    g.ab.keyword NifasmDecl.ResultD
    g.ab.tree NifasmDecl.ClobberD:
      for r in g.md.convClobbersGpr: g.ab.rawReg r
    g.ab.tree StmtsA64:
      g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.intLit 16)
      for i, r in [R4, R5, R6, R7]:
        g.ab.tree StrA64:
          g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit int64(4 * i))
          g.ab.rawReg r
      # D == 0 → everything zero, like `udiv`.
      g.ab.tree MovA64: (g.ab.rawReg R7; g.ab.rawReg g.argReg(2))
      g.ab.tree OrrA64: (g.ab.rawReg R7; g.ab.rawReg g.argReg(3))
      g.ab.tree CmpA64: (g.ab.rawReg R7; g.ab.intLit 0)
      g.emBr(BneA64, lZero)
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(0); g.ab.intLit 0)
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(1); g.ab.intLit 0)
      g.emBr(BA64, lDone)
      g.emLab(lZero)
      g.ab.tree MovA64: (g.ab.rawReg R4; g.ab.intLit 0)     # R.lo
      g.ab.tree MovA64: (g.ab.rawReg R5; g.ab.intLit 0)     # R.hi
      g.ab.tree MovA64: (g.ab.rawReg R6; g.ab.intLit 64)    # bits to go
      g.ab.tree LoopA64:
        g.ab.tree StmtsA64:
          let lSub = g.freshLabel()
          let lSkip = g.freshLabel()
          # R:N <<= 1
          g.ab.tree Lsr3A64: (g.ab.rawReg R7; g.ab.rawReg R4; g.ab.intLit 31)
          g.ab.tree LslA64:  (g.ab.rawReg R5; g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.ab.rawReg R5; g.ab.rawReg R7)
          g.ab.tree Lsr3A64: (g.ab.rawReg R7; g.ab.rawReg g.argReg(1); g.ab.intLit 31)
          g.ab.tree LslA64:  (g.ab.rawReg R4; g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.ab.rawReg R4; g.ab.rawReg R7)
          g.ab.tree Lsr3A64: (g.ab.rawReg R7; g.ab.rawReg g.argReg(0); g.ab.intLit 31)
          g.ab.tree LslA64:  (g.ab.rawReg g.argReg(1); g.ab.intLit 1)
          g.ab.tree OrrA64:  (g.ab.rawReg g.argReg(1); g.ab.rawReg R7)
          g.ab.tree LslA64:  (g.ab.rawReg g.argReg(0); g.ab.intLit 1)
          # if R >= D
          g.ab.tree CmpA64: (g.ab.rawReg R5; g.ab.rawReg g.argReg(3))
          g.emBr(BloA64, lSkip)
          g.emBr(BhiA64, lSub)
          g.ab.tree CmpA64: (g.ab.rawReg R4; g.ab.rawReg g.argReg(2))
          g.emBr(BhsA64, lSub)
          g.emBr(BA64, lSkip)
          g.emLab(lSub)
          g.ab.tree Subs3M: (g.ab.rawReg R4; g.ab.rawReg R4; g.ab.rawReg g.argReg(2))
          g.ab.tree Sbcs3M: (g.ab.rawReg R5; g.ab.rawReg R5; g.ab.rawReg g.argReg(3))
          g.ab.tree OrrA64: (g.ab.rawReg g.argReg(0); g.ab.intLit 1)
          g.emLab(lSkip)
          g.ab.tree SubA64: (g.ab.rawReg R6; g.ab.intLit 1)
          g.ab.tree CmpA64: (g.ab.rawReg R6; g.ab.intLit 0)
          g.emBr(BeqA64, lLoopEnd)               # the ONLY way out of the loop
      g.emLab(lLoopEnd)
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(2); g.ab.rawReg R4)   # the remainder
      g.ab.tree MovA64: (g.ab.rawReg g.argReg(3); g.ab.rawReg R5)
      g.emLab(lDone)
      for i, r in [R4, R5, R6, R7]:
        g.ab.tree LdrA64:
          g.ab.rawReg r
          g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit int64(4 * i))
      g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.intLit 16)
      g.ab.keyword RetA64

proc emitSDivMod64*(g: var CodeGen) =
  ## The signed wrapper. Negation is `(x xor m) - m` with `m` the sign as a
  ## 0/-1 mask, which is branchless and — unlike a compare-and-negate — right
  ## for the most negative value too.
  g.ab.tree NifasmDecl.ProcD:
    g.ab.symDef g.sDivMod64Proc
    g.ab.keyword NifasmDecl.ParamsD
    g.ab.keyword NifasmDecl.ResultD
    g.ab.tree NifasmDecl.ClobberD:
      for r in g.md.convClobbersGpr: g.ab.rawReg r
    g.ab.tree StmtsA64:
      g.ab.tree SubA64: (g.ab.rawReg SP; g.ab.intLit 16)
      for i, r in [R4, R5, R6]:
        g.ab.tree StrA64:
          g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit int64(4 * i))
          g.ab.rawReg r
      g.ab.tree StrA64:
        g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit 12)
        g.ab.rawReg g.md.linkReg
      g.ab.tree Asr3A64: (g.ab.rawReg R4; g.ab.rawReg g.argReg(1); g.ab.intLit 31)   # sign of N
      g.ab.tree MovA64:  (g.ab.rawReg R5; g.ab.rawReg R4)                   # remainder's sign
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(0); g.ab.rawReg R4)                   # N = |N|
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(1); g.ab.rawReg R4)
      g.ab.tree Subs3M:  (g.ab.rawReg g.argReg(0); g.ab.rawReg g.argReg(0); g.ab.rawReg R4)
      g.ab.tree Sbcs3M:  (g.ab.rawReg g.argReg(1); g.ab.rawReg g.argReg(1); g.ab.rawReg R4)
      g.ab.tree Asr3A64: (g.ab.rawReg R6; g.ab.rawReg g.argReg(3); g.ab.intLit 31)   # sign of D
      g.ab.tree EorA64:  (g.ab.rawReg R4; g.ab.rawReg R6)                   # quotient's sign
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(2); g.ab.rawReg R6)                   # D = |D|
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(3); g.ab.rawReg R6)
      g.ab.tree Subs3M:  (g.ab.rawReg g.argReg(2); g.ab.rawReg g.argReg(2); g.ab.rawReg R6)
      g.ab.tree Sbcs3M:  (g.ab.rawReg g.argReg(3); g.ab.rawReg g.argReg(3); g.ab.rawReg R6)
      g.ab.tree BlA64: g.ab.sym g.uDivMod64Proc
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(0); g.ab.rawReg R4)
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(1); g.ab.rawReg R4)
      g.ab.tree Subs3M:  (g.ab.rawReg g.argReg(0); g.ab.rawReg g.argReg(0); g.ab.rawReg R4)
      g.ab.tree Sbcs3M:  (g.ab.rawReg g.argReg(1); g.ab.rawReg g.argReg(1); g.ab.rawReg R4)
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(2); g.ab.rawReg R5)
      g.ab.tree EorA64:  (g.ab.rawReg g.argReg(3); g.ab.rawReg R5)
      g.ab.tree Subs3M:  (g.ab.rawReg g.argReg(2); g.ab.rawReg g.argReg(2); g.ab.rawReg R5)
      g.ab.tree Sbcs3M:  (g.ab.rawReg g.argReg(3); g.ab.rawReg g.argReg(3); g.ab.rawReg R5)
      for i, r in [R4, R5, R6]:
        g.ab.tree LdrA64:
          g.ab.rawReg r
          g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit int64(4 * i))
      g.ab.tree LdrA64:
        g.ab.rawReg g.md.linkReg
        g.ab.tree MemX: (g.ab.rawReg SP; g.ab.intLit 12)
      g.ab.tree AddA64: (g.ab.rawReg SP; g.ab.intLit 16)
      g.ab.keyword RetA64
