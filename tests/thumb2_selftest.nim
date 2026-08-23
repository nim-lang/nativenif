## Thumb-2 encoder self-test: build ONE bare-metal image that computes a list of
## expressions and compares each against its expected value, exiting with the
## 1-based index of the first mismatch (0 = every check passed).
##
## Running the instructions is the strongest oracle available here: QEMU has no
## disassembler compiled in, but its DECODER is the one that will execute
## whatever the backend emits, so "the result is right" checks the encoding at
## exactly the level that matters. It also exercises the branch encoders and the
## relocation patcher, which a byte-comparison test could not.

import std / [os]
import "../src/nifasm/thumb2"
import "../src/nifasm/buffers"
import "../src/nifasm/relocs"
import "../src/nifasm/elf32"

type Check = object
  name: string
  emit: proc (b: var Buffer) {.closure.}   ## leave the computed value in r0
  want: uint32

var checks: seq[Check] = @[]
proc check(name: string; want: uint32; emit: proc (b: var Buffer) {.closure.}) =
  checks.add Check(name: name, emit: emit, want: want)

# ── the checks ──────────────────────────────────────────────────────────────
check "movs narrow", 7: (proc (b: var Buffer) = b.data.emitMovImm32(R0, 7))
check "movw", 0x1234: (proc (b: var Buffer) = b.data.emitMovImm32(R0, 0x1234))
check "movw+movt", 0xDEADBEEF'u32: (proc (b: var Buffer) = b.data.emitMovImm32(R0, 0xDEADBEEF'u32))
check "modified imm replicated", 0xFF00FF00'u32:
  (proc (b: var Buffer) = b.data.emitMovImm32(R0, 0xFF00FF00'u32))
check "modified imm rotated", 0x3E8:
  (proc (b: var Buffer) = b.data.emitMovImm32(R0, 1000))
check "mov reg", 0x99:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R5, 0x99); b.data.emitMovReg(R0, R5))
check "add3 narrow", 30:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 10); b.data.emitMovImm32(R2, 20)
    b.data.emitAdd3(R0, R1, R2))
check "add3 wide (high reg)", 30:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 10); b.data.emitMovImm32(R2, 20)
    b.data.emitAdd3(R8, R1, R2); b.data.emitMovReg(R0, R8))
check "sub3", 12:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 20); b.data.emitMovImm32(R2, 8)
    b.data.emitSub3(R0, R1, R2))
check "addImm imm3", 8:
  (proc (b: var Buffer) = b.data.emitMovImm32(R0, 3); b.data.emitAddImm(R0, R0, 5))
check "addImm imm8", 300:
  (proc (b: var Buffer) = b.data.emitMovImm32(R0, 100); b.data.emitAddImm(R0, R0, 200))
check "addImm ADDW", 4000:
  (proc (b: var Buffer) = b.data.emitMovImm32(R1, 1); b.data.emitAddImm(R0, R1, 3999))
check "subImm", 55:
  (proc (b: var Buffer) = b.data.emitMovImm32(R0, 255); b.data.emitSubImm(R0, R0, 200))
check "mul", 72:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 8); b.data.emitMovImm32(R2, 9); b.data.emitMul(R0, R1, R2))
check "umull lo", 0x50000000'u32:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R2, 0x10000000'u32); b.data.emitMovImm32(R3, 5)
    b.data.emitUmull(R0, R1, R2, R3))
check "umull hi", 0:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R2, 0x10000000'u32); b.data.emitMovImm32(R3, 5)
    b.data.emitUmull(R1, R0, R2, R3))
check "sdiv", 0xFFFFFFFD'u32:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xFFFFFFF6'u32)   # -10
    b.data.emitMovImm32(R2, 3)
    b.data.emitSdiv(R0, R1, R2))              # -10 / 3 == -3 (truncating)
check "udiv", 33:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 100); b.data.emitMovImm32(R2, 3); b.data.emitUdiv(R0, R1, R2))
check "mls (remainder)", 1:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R3, 100); b.data.emitMovImm32(R2, 3)
    b.data.emitUdiv(R1, R3, R2)               # q = 33
    b.data.emitMls(R0, R1, R2, R3))           # 100 - 33*3 == 1
check "neg", 0xFFFFFFECu32:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 20); b.data.emitNeg(R0, R2))
check "mvn", 0xFFFFFF0F'u32:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0xF0); b.data.emitMvn(R0, R2))
check "lsl imm", 0x50:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 5); b.data.emitLslImm(R0, R2, 4))
check "lsr imm", 5:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0x50); b.data.emitLsrImm(R0, R2, 4))
check "asr imm", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0xFFFFFFF0'u32); b.data.emitAsrImm(R0, R2, 8))
check "lsl reg", 0x50:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R2, 5); b.data.emitMovImm32(R3, 4); b.data.emitLsl(R0, R2, R3))
check "uxtb", 0xAB:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0x12AB); b.data.emitUxtb(R0, R2))
check "sxth", 0xFFFF8000'u32:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0x8000); b.data.emitSxth(R0, R2))
check "clz", 24:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0x80); b.data.emitClz(R0, R2))
check "rev", 0x78563412:
  (proc (b: var Buffer) = b.data.emitMovImm32(R2, 0x12345678); b.data.emitRev(R0, R2))
check "and3", 0x0F00:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xFF00); b.data.emitMovImm32(R2, 0x0FF0)
    b.data.emitAnd3(R0, R1, R2))
check "orr3", 0xFFF0:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xFF00); b.data.emitMovImm32(R2, 0x0FF0)
    b.data.emitOrr3(R0, R1, R2))
check "eor3", 0xF0F0:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xFF00); b.data.emitMovImm32(R2, 0x0FF0)
    b.data.emitEor3(R0, R1, R2))
check "adds/adcs 64-bit carry", 1:
  (proc (b: var Buffer) =
    # 0xFFFFFFFF + 1 must carry into the high word: the M4 i64 building block.
    b.data.emitMovImm32(R1, 0xFFFFFFFF'u32); b.data.emitMovImm32(R2, 1)
    b.data.emitMovImm32(R3, 0); b.data.emitMovImm32(R4, 0)
    b.data.emitAddsCarry(R5, R1, R2)
    b.data.emitAdcs(R0, R3, R4))
check "str/ldr word roundtrip", 0xCAFE:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xCAFE)
    b.data.emitSubImm(SP, SP, 16)
    b.data.emitStr(R1, SP, 8)
    b.data.emitLdr(R0, SP, 8)
    b.data.emitAddImm(SP, SP, 16))
check "strb/ldrb roundtrip", 0xAB:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0x12AB)
    b.data.emitSubImm(SP, SP, 16)
    b.data.emitStrb(R1, SP, 3)
    b.data.emitLdrb(R0, SP, 3)
    b.data.emitAddImm(SP, SP, 16))
check "strh/ldrsh sign-extends", 0xFFFF8001'u32:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0x8001)
    b.data.emitSubImm(SP, SP, 16)
    b.data.emitStrh(R1, SP, 4)
    b.data.emitLdrsh(R0, SP, 4)
    b.data.emitAddImm(SP, SP, 16))
check "ldr wide offset", 0xBEEF:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xBEEF)
    b.data.emitSubImm(SP, SP, 1024)
    b.data.emitStr(R1, SP, 800)
    b.data.emitLdr(R0, SP, 800)
    b.data.emitAddImm(SP, SP, 1024))
check "ldr negative offset", 0xD00D:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0xD00D)
    b.data.emitSubImm(SP, SP, 64)
    b.data.emitMovReg(R2, SP)
    b.data.emitAddImm(R2, R2, 40)
    b.data.emitStr(R1, R2, -20)
    b.data.emitLdr(R0, R2, -20)
    b.data.emitAddImm(SP, SP, 64))
check "scaled index load", 0x1111:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R1, 0x1111)
    b.data.emitSubImm(SP, SP, 64)
    b.data.emitMovReg(R2, SP)
    b.data.emitMovImm32(R3, 3)
    b.data.emitLoadStoreReg(R1, R2, R3, MemWord, isLoad = false, shift = 2)
    b.data.emitLoadStoreReg(R0, R2, R3, MemWord, isLoad = true, shift = 2)
    b.data.emitAddImm(SP, SP, 64))
check "push/pop roundtrip", 0x4242:
  (proc (b: var Buffer) =
    b.data.emitMovImm32(R4, 0x4242)
    b.data.emitPush({R4, R5})
    b.data.emitMovImm32(R4, 0)
    b.data.emitPop({R4, R5})
    b.data.emitMovReg(R0, R4))
check "cmp+bcond taken", 1:
  (proc (b: var Buffer) =
    let lTrue = b.createLabel()
    let lEnd = b.createLabel()
    b.data.emitMovImm32(R1, 5)
    b.data.emitCmpImm(R1, 5)
    b.emitBcond(CondEQ, lTrue)
    b.data.emitMovImm32(R0, 0)
    b.emitB(lEnd)
    b.defineLabel(lTrue)
    b.data.emitMovImm32(R0, 1)
    b.defineLabel(lEnd))
check "cmp+bcond not taken", 0:
  (proc (b: var Buffer) =
    let lTrue = b.createLabel()
    let lEnd = b.createLabel()
    b.data.emitMovImm32(R1, 4)
    b.data.emitCmpImm(R1, 5)
    b.emitBcond(CondEQ, lTrue)
    b.data.emitMovImm32(R0, 0)
    b.emitB(lEnd)
    b.defineLabel(lTrue)
    b.data.emitMovImm32(R0, 1)
    b.defineLabel(lEnd))
check "backward branch loop sums 1..10", 55:
  (proc (b: var Buffer) =
    let lTop = b.createLabel()
    let lDone = b.createLabel()
    b.data.emitMovImm32(R0, 0)     # acc
    b.data.emitMovImm32(R1, 1)     # i
    b.defineLabel(lTop)
    b.data.emitCmpImm(R1, 11)
    b.emitBcond(CondHS, lDone)
    b.data.emitAdd3(R0, R0, R1)
    b.data.emitAddImm(R1, R1, 1)
    b.emitB(lTop)
    b.defineLabel(lDone))
check "bl + bx lr (call/return)", 99:
  (proc (b: var Buffer) =
    let lFn = b.createLabel()
    let lAfter = b.createLabel()
    b.emitB(lAfter)
    b.defineLabel(lFn)
    b.data.emitMovImm32(R0, 99)
    b.data.emitRet()
    b.defineLabel(lAfter)
    b.emitBl(lFn))
check "signed compare blt", 1:
  (proc (b: var Buffer) =
    let lTrue = b.createLabel()
    let lEnd = b.createLabel()
    b.data.emitMovImm32(R1, 0xFFFFFFFF'u32)   # -1
    b.data.emitCmpImm(R1, 0)
    b.emitBcond(CondLT, lTrue)
    b.data.emitMovImm32(R0, 0)
    b.emitB(lEnd)
    b.defineLabel(lTrue)
    b.data.emitMovImm32(R0, 1)
    b.defineLabel(lEnd))

# ── FPv4-SP ─────────────────────────────────────────────────────────────────
# Every check below enables the FPU first: Cortex-M4F comes out of reset with
# CP10/CP11 access denied, and the first VFP instruction would take a UsageFault.
# Each check is self-contained, so it does the write itself rather than relying
# on an earlier one having run.

const
  Cpacr = 0xE000ED88'u32
  Cp10Cp11Full = 0x00F00000'u32
  F1_5 = 0x3FC00000'u32     ## 1.5f
  F2_25 = 0x40100000'u32    ## 2.25f
  F3_75 = 0x40700000'u32    ## 3.75f
  F7_0 = 0x40E00000'u32     ## 7.0f

proc enableFpu(b: var Buffer) =
  b.data.emitMovImm32(R1, Cpacr)
  b.data.emitLdr(R2, R1, 0)
  b.data.emitMovImm32(R3, Cp10Cp11Full)
  b.data.emitOrr3(R2, R2, R3)
  b.data.emitStr(R2, R1, 0)
  b.data.emitDsb()
  b.data.emitIsb()

template fcheck(nm: string; expect: uint32; body: untyped) {.dirty.} =
  ## `check`, with the FPU turned on first. `dirty` so the body can name `b`,
  ## which is the emitting closure's own parameter.
  check nm, expect:
    (proc (b: var Buffer) =
      enableFpu(b)
      body)

fcheck "vmov gpr->fp->gpr roundtrip", F1_5:
  b.data.emitMovImm32(R1, F1_5)
  b.data.emitVmovToFp(S0, R1)
  b.data.emitVmovFromFp(R0, S0)
fcheck "vadd.f32 1.5+2.25", F3_75:
  b.data.emitMovImm32(R1, F1_5); b.data.emitVmovToFp(S1, R1)
  b.data.emitMovImm32(R1, F2_25); b.data.emitVmovToFp(S2, R1)
  b.data.emitVadd(S3, S1, S2)
  b.data.emitVmovFromFp(R0, S3)
fcheck "vsub.f32 3.75-1.5", F2_25:
  b.data.emitMovImm32(R1, F3_75); b.data.emitVmovToFp(S1, R1)
  b.data.emitMovImm32(R1, F1_5); b.data.emitVmovToFp(S2, R1)
  b.data.emitVsub(S3, S1, S2)
  b.data.emitVmovFromFp(R0, S3)
fcheck "vmul.f32 1.5*1.5", F2_25:
  b.data.emitMovImm32(R1, F1_5); b.data.emitVmovToFp(S1, R1)
  b.data.emitVmul(S2, S1, S1)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vdiv.f32 3.75/2.5", F1_5:
  b.data.emitMovImm32(R1, F3_75); b.data.emitVmovToFp(S1, R1)
  b.data.emitMovImm32(R1, 0x40200000'u32); b.data.emitVmovToFp(S2, R1)   # 2.5f
  b.data.emitVdiv(S3, S1, S2)
  b.data.emitVmovFromFp(R0, S3)
# vneg and vsqrt differ ONLY in their opc3 field, so a swap turns `-3.0` into
# `1.732` — which is why both are checked and why the values are chosen so that
# one cannot pass for the other.
fcheck "vneg.f32", 0xBFC00000'u32:
  b.data.emitMovImm32(R1, F1_5); b.data.emitVmovToFp(S1, R1)
  b.data.emitVneg(S2, S1)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vabs.f32 of -1.5", F1_5:
  b.data.emitMovImm32(R1, 0xBFC00000'u32); b.data.emitVmovToFp(S1, R1)
  b.data.emitVabs(S2, S1)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vsqrt.f32 of 2.25", F1_5:
  b.data.emitMovImm32(R1, F2_25); b.data.emitVmovToFp(S1, R1)
  b.data.emitVsqrt(S2, S1)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vmov.f32 reg-reg", F7_0:
  b.data.emitMovImm32(R1, F7_0); b.data.emitVmovToFp(S1, R1)
  b.data.emitVmovReg(S9, S1)
  b.data.emitVmovFromFp(R0, S9)
fcheck "vcvt.f32.s32 of -5", 0xC0A00000'u32:
  b.data.emitMovImm32(R1, 0xFFFFFFFB'u32)                 # -5
  b.data.emitVmovToFp(S1, R1)
  b.data.emitVcvtToF32(S2, S1, signed = true)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vcvt.f32.u32 of 0x80000000", 0x4F000000'u32:      # 2147483648.0f
  b.data.emitMovImm32(R1, 0x80000000'u32)
  b.data.emitVmovToFp(S1, R1)
  b.data.emitVcvtToF32(S2, S1, signed = false)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vcvt.s32.f32 truncates toward zero", 0xFFFFFFFE'u32:   # -2
  b.data.emitMovImm32(R1, 0xC0133333'u32)                 # -2.3f
  b.data.emitVmovToFp(S1, R1)
  b.data.emitVcvtFromF32(S2, S1, signed = true)
  b.data.emitVmovFromFp(R0, S2)
fcheck "vldr/vstr .32 roundtrip", F2_25:
  b.data.emitMovImm32(R1, F2_25); b.data.emitVmovToFp(S4, R1)
  b.data.emitSubImm(SP, SP, 8)
  b.data.emitVstr(S4, SP, 4)
  b.data.emitVldr(S5, SP, 4)
  b.data.emitAddImm(SP, SP, 8)
  b.data.emitVmovFromFp(R0, S5)
fcheck "vldr negative offset", F7_0:
  b.data.emitMovImm32(R1, F7_0); b.data.emitVmovToFp(S4, R1)
  b.data.emitSubImm(SP, SP, 8)
  b.data.emitVstr(S4, SP, 0)
  b.data.emitAddImm(R2, SP, 8)
  b.data.emitVldr(S5, R2, -8)
  b.data.emitAddImm(SP, SP, 8)
  b.data.emitVmovFromFp(R0, S5)
fcheck "vcmp.f32 + vmrs: 1.5 < 2.25", 1:
  let lTrue = b.createLabel()
  let lEnd = b.createLabel()
  b.data.emitMovImm32(R1, F1_5); b.data.emitVmovToFp(S1, R1)
  b.data.emitMovImm32(R1, F2_25); b.data.emitVmovToFp(S2, R1)
  b.data.emitVcmp(S1, S2)
  b.data.emitVmrsApsr()
  b.emitBcond(CondLT, lTrue)
  b.data.emitMovImm32(R0, 0)
  b.emitB(lEnd)
  b.defineLabel(lTrue)
  b.data.emitMovImm32(R0, 1)
  b.defineLabel(lEnd)
fcheck "vcmp.f32 + vmrs: equal sets Z", 1:
  let lTrue = b.createLabel()
  let lEnd = b.createLabel()
  b.data.emitMovImm32(R1, F7_0); b.data.emitVmovToFp(S1, R1)
  b.data.emitVcmp(S1, S1)
  b.data.emitVmrsApsr()
  b.emitBcond(CondEQ, lTrue)
  b.data.emitMovImm32(R0, 0)
  b.emitB(lEnd)
  b.defineLabel(lTrue)
  b.data.emitMovImm32(R0, 1)
  b.defineLabel(lEnd)
fcheck "high s-register (s17) survives the D-bit split", F3_75:
  b.data.emitMovImm32(R1, F3_75); b.data.emitVmovToFp(S17, R1)
  b.data.emitVmovReg(S30, S17)
  b.data.emitVmovFromFp(R0, S30)

# ── image construction ──────────────────────────────────────────────────────

const
  VecSize = 8              ## the two vector-table words `elf32.writeFirmware` prepends
  SysExitExtended = 0x20
  AdpStoppedApplicationExit = 0x20026'u32

when isMainModule:
  var b = initBuffer()
  # The vector table occupies the first 8 bytes; emit placeholders that the
  # final image overwrites, so every code position below is already correct.
  b.data.addUint32 0
  b.data.addUint32 0

  let lFail = b.createLabel()
  # r7 holds the 1-based index of the check being run, so the failure path can
  # report WHICH one broke without any per-check code.
  for i, c in checks:
    b.data.emitMovImm32(R7, uint32(i + 1))
    c.emit(b)
    b.data.emitMovReg(R6, R0)
    b.data.emitMovImm32(R5, c.want)
    b.data.emitCmpReg(R6, R5)
    b.emitBcond(CondNE, lFail)

  b.data.emitMovImm32(R7, 0)          # all passed
  b.defineLabel(lFail)
  # exit(r7) via SYS_EXIT_EXTENDED. The two-word block is built on the stack so
  # the image needs no writable data section.
  b.data.emitSubImm(SP, SP, 8)
  b.data.emitMovImm32(R2, AdpStoppedApplicationExit)
  b.data.emitStr(R2, SP, 0)
  b.data.emitStr(R7, SP, 4)
  b.data.emitMovReg(R1, SP)
  b.data.emitMovImm32(R0, SysExitExtended)
  b.data.emitBkpt(0xAB)

  b.updateRelocDisplacements()

  # `writeFirmware` prepends the real vector table, so hand back only the code
  # that followed the two placeholder words.
  var code: seq[byte] = @[]
  for i in VecSize ..< b.data.len: code.add b.data[i]
  writeFile(paramStr(1), writeFirmware(code))
  echo "wrote ", paramStr(1), ": ", checks.len, " checks, ", code.len, " code bytes"
  for i, c in checks: echo "  ", i + 1, "  ", c.name
