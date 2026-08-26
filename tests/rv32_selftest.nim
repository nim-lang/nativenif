## RV32 encoder self-test: build ONE static Linux image that computes a list of
## expressions and compares each against its expected value, exiting with the
## 1-based index of the first mismatch (0 = every check passed).
##
## Running the instructions is the strongest oracle available. QEMU's decoder is
## the one that will execute whatever the backend emits, so "the result is right"
## checks the encoding at exactly the level that matters — and unlike a byte
## comparison it exercises the branch encoders and the relocation patcher, which
## is where this target's hazard lives: the B and J immediates are PERMUTED, not
## merely shifted, so a wrong reading produces a branch that lands somewhere
## plausible and runs.
##
## Each check leaves its value in `t0`. The harness uses `t1` to hold the
## expectation and `a0`/`a7` for the exit, so those are off limits to a check.
##
##   nim c -o:bin/rv32_selftest tests/rv32_selftest.nim
##   bin/rv32_selftest tests/rv32_selftest.elf
##   qemu-riscv32 tests/rv32_selftest.elf ; echo $?

import std / [os, strutils]
import "../src/nifasm/rv32/encoder"
import "../src/nifasm/core/buffers"
import "../src/nifasm/core/relocs"
import "../src/nifasm/image/elf32"

const
  T0 = X5
  T1 = X6
  T2 = X7
  T3 = X28
  A0 = X10
  A7 = X17
  SysExit = 93
  LoadBase = 0x10000'u32
  HdrBytes = 52 + 32          ## one program header: this image is a single
                              ## R+X segment, so the two-PT_LOAD page trap
                              ## `tools/rv32_probe.nim` documents cannot arise

type Check = object
  name: string
  emit: proc (b: var Buffer) {.closure.}   ## leave the computed value in t0
  want: int64

var checks: seq[Check] = @[]
proc check(name: string; want: int64; emit: proc (b: var Buffer) {.closure.}) =
  checks.add Check(name: name, emit: emit, want: want)

# ── materialization ─────────────────────────────────────────────────────────

check "addi from x0", 7:
  (proc (b: var Buffer) = b.data.emitLi(T0, 7))
check "negative immediate", -7:
  (proc (b: var Buffer) = b.data.emitLi(T0, -7))
check "the widest addi", 2047:
  (proc (b: var Buffer) = b.data.emitLi(T0, 2047))
check "one past it takes lui+addi", 2048:
  (proc (b: var Buffer) = b.data.emitLi(T0, 2048))
check "lui+addi, low half below 0x800", 0x12345:
  (proc (b: var Buffer) = b.data.emitLi(T0, 0x12345))
check "lui+addi, low half ABOVE 0x7FF", 0x12FFF:
  # The compensation case: `addi`'s immediate is SIGNED, so this low half is a
  # negative addend and the `lui` must be one higher. Without the `+0x800` the
  # answer is wrong by exactly 0x1000.
  (proc (b: var Buffer) = b.data.emitLi(T0, 0x12FFF))
check "a full 32-bit constant", cast[int32](0xDEADBEEF'u32):
  (proc (b: var Buffer) = b.data.emitLi(T0, 0xDEADBEEF))
check "emitLiWide is the same value in two words", 5:
  (proc (b: var Buffer) = b.data.emitLiWide(T0, 5))

# ── ALU ─────────────────────────────────────────────────────────────────────

check "add", 30:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 10); b.data.emitLi(T2, 20); b.data.emitAdd(T0, T1, T2))
check "sub borrows into negative", -5:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 10); b.data.emitLi(T2, 15); b.data.emitSub(T0, T1, T2))
check "and", 0x0F:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 0xFF); b.data.emitLi(T2, 0x0F); b.data.emitAnd(T0, T1, T2))
check "or", 0xFF:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 0xF0); b.data.emitLi(T2, 0x0F); b.data.emitOr(T0, T1, T2))
check "xor", 0xF0:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 0xFF); b.data.emitLi(T2, 0x0F); b.data.emitXor(T0, T1, T2))
check "andi", 0x0F:
  (proc (b: var Buffer) = (b.data.emitLi(T0, 0xFF); b.data.emitAndi(T0, T0, 0x0F)))
check "ori", 0xFF:
  (proc (b: var Buffer) = (b.data.emitLi(T0, 0xF0); b.data.emitOri(T0, T0, 0x0F)))
check "xori with -1 is a bitwise not", -256:
  (proc (b: var Buffer) = (b.data.emitLi(T0, 255); b.data.emitNot(T0, T0)))
check "neg is sub from x0", -42:
  (proc (b: var Buffer) = (b.data.emitLi(T1, 42); b.data.emitNeg(T0, T1)))
check "mv is addi 0", 99:
  (proc (b: var Buffer) = (b.data.emitLi(T1, 99); b.data.emitMv(T0, T1)))

# ── multiply and divide (the M extension) ───────────────────────────────────

check "mul", 600:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 200); b.data.emitLi(T2, 3); b.data.emitMul(T0, T1, T2))
check "mul wraps at 32 bits", 0:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 0x10000); b.data.emitLi(T2, 0x10000); b.data.emitMul(T0, T1, T2))
check "div truncates toward zero", -3:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, -10); b.data.emitLi(T2, 3); b.data.emitDiv(T0, T1, T2))
check "rem takes the dividend's sign", -1:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, -10); b.data.emitLi(T2, 3); b.data.emitRem(T0, T1, T2))
check "divu is unsigned", 1431655764:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, -4); b.data.emitLi(T2, 3); b.data.emitDivu(T0, T1, T2))

# ── shifts ──────────────────────────────────────────────────────────────────

check "slli", 0x100:
  (proc (b: var Buffer) = (b.data.emitLi(T0, 1); b.data.emitSlli(T0, T0, 8)))
check "srli is logical", 0x00FFFFFF:
  (proc (b: var Buffer) = (b.data.emitLi(T0, -1); b.data.emitSrli(T0, T0, 8)))
check "srai keeps the sign", -1:
  (proc (b: var Buffer) = (b.data.emitLi(T0, -256); b.data.emitSrai(T0, T0, 8)))
check "sll by a register", 0x100:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 1); b.data.emitLi(T2, 8); b.data.emitSll(T0, T1, T2))
check "sll masks the count to five bits", 2:
  # RISC-V takes the low five bits of the shift amount and ignores the rest, so
  # a shift by 33 is a shift by 1 rather than zero.
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 1); b.data.emitLi(T2, 33); b.data.emitSll(T0, T1, T2))

# ── set-less-than: how a bool exists at all on this machine ─────────────────

check "slt, true", 1:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 5); b.data.emitLi(T2, 9); b.data.emitSlt(T0, T1, T2))
check "slt, false", 0:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, 9); b.data.emitLi(T2, 5); b.data.emitSlt(T0, T1, T2))
check "slt is SIGNED", 1:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, -1); b.data.emitLi(T2, 1); b.data.emitSlt(T0, T1, T2))
check "sltu gets that one the other way", 0:
  (proc (b: var Buffer) =
    b.data.emitLi(T1, -1); b.data.emitLi(T2, 1); b.data.emitSltu(T0, T1, T2))
check "slti", 1:
  (proc (b: var Buffer) = (b.data.emitLi(T1, 5); b.data.emitSlti(T0, T1, 9)))
check "seqz", 1:
  (proc (b: var Buffer) = (b.data.emitLi(T1, 0); b.data.emitSeqz(T0, T1)))
check "snez", 1:
  (proc (b: var Buffer) = (b.data.emitLi(T1, 77); b.data.emitSnez(T0, T1)))

# ── memory ──────────────────────────────────────────────────────────────────

check "sw/lw through sp", 0xCAFE:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0xCAFE)
    b.data.emitSw(T1, Sp, 4)
    b.data.emitLw(T0, Sp, 4)
    b.data.emitAddi(Sp, Sp, 16))
check "a negative offset", 0xBEEF:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0xBEEF)
    b.data.emitSw(T1, Sp, 8)
    b.data.emitAddi(T2, Sp, 16)
    b.data.emitLw(T0, T2, -8)
    b.data.emitAddi(Sp, Sp, 16))
check "sb/lbu touch ONE byte", 0x12AB55CD:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0x12ABCDCD)
    b.data.emitSw(T1, Sp, 0)
    b.data.emitLi(T1, 0x55)
    b.data.emitSb(T1, Sp, 1)
    b.data.emitLw(T0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lb sign-extends", -1:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0xFF)
    b.data.emitSb(T1, Sp, 0)
    b.data.emitLb(T0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lbu does not", 255:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0xFF)
    b.data.emitSb(T1, Sp, 0)
    b.data.emitLbu(T0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "sh/lhu touch two", 0xBEEF:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T1, 0xBEEF)
    b.data.emitSh(T1, Sp, 0)
    b.data.emitLhu(T0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))

# ── branches and the relocation patcher ─────────────────────────────────────

check "beq taken, forward", 1:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 1)
    b.data.emitLi(T1, 5); b.data.emitLi(T2, 5)
    b.emitBranch(CondEq, T1, T2, l)
    b.data.emitLi(T0, 0)
    b.defineLabel(l))
check "beq not taken", 0:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 1)
    b.data.emitLi(T1, 5); b.data.emitLi(T2, 6)
    b.emitBranch(CondEq, T1, T2, l)
    b.data.emitLi(T0, 0)
    b.defineLabel(l))
check "blt is signed", 1:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 1)
    b.data.emitLi(T1, -1); b.data.emitLi(T2, 1)
    b.emitBranch(CondLt, T1, T2, l)
    b.data.emitLi(T0, 0)
    b.defineLabel(l))
check "bltu gets that one the other way", 0:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 1)
    b.data.emitLi(T1, -1); b.data.emitLi(T2, 1)
    b.emitBranch(CondLtu, T1, T2, l)
    b.data.emitLi(T0, 0)
    b.defineLabel(l))
check "a BACKWARD branch closes a counted loop", 30:
  (proc (b: var Buffer) =
    let top = b.createLabel()
    b.data.emitLi(T0, 0)
    b.data.emitLi(T2, 10)
    b.defineLabel(top)
    b.data.emitAddi(T0, T0, 3)
    b.data.emitAddi(T2, T2, -1)
    b.emitBranch(CondNe, T2, Zero, top))
check "a branch over more than 128 bytes", 5:
  # ±4 KB is generous next to AVR's ±128 bytes and Thumb's ±1 MB, but it is
  # still the field this patcher permutes, so a long one is worth running.
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 5)
    b.data.emitLi(T1, 1); b.data.emitLi(T2, 1)
    b.emitBranch(CondEq, T1, T2, l)
    for _ in 0 ..< 200: b.data.emitNop()
    b.data.emitLi(T0, 0)
    b.defineLabel(l))
check "jal forward", 5:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.data.emitLi(T0, 5)
    b.emitJ(l)
    b.data.emitLi(T0, 6)
    b.defineLabel(l))
check "jal and ret", 7:
  (proc (b: var Buffer) =
    let sub = b.createLabel()
    let after = b.createLabel()
    b.emitCall(sub)
    b.emitJ(after)
    b.defineLabel(sub)
    b.data.emitLi(T0, 7)
    b.data.emitRet()
    b.defineLabel(after))
check "jalr through a register", 7:
  (proc (b: var Buffer) =
    let sub = b.createLabel()
    let after = b.createLabel()
    b.emitLa(T3, sub)
    b.data.emitJalr(Ra, T3, 0)
    b.emitJ(after)
    b.defineLabel(sub)
    b.data.emitLi(T0, 7)
    b.data.emitRet()
    b.defineLabel(after))
check "la materializes a nonzero address", 1:
  # Not the value — where a label lands is whatever it lands on. What is checked
  # is that the pair agrees with itself and names something.
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.emitLa(T1, l)
    b.data.emitSnez(T0, T1)
    b.defineLabel(l))

when isMainModule:
  if paramCount() >= 1 and paramStr(1) == "--list":
    for i, c in checks: echo i + 1, "\t", c.name
    quit 0

  # `--mutate:N` corrupts check N's EXPECTED value BEFORE the image is built, so
  # a run must then fail with exactly N. Without it a check whose emitter writes
  # no instructions — or which compares against a value the harness itself left
  # in t0 — passes and says so. `tests/tester` sweeps all of them.
  if paramCount() >= 2 and paramStr(2).startsWith("--mutate:"):
    let m = parseInt(paramStr(2)[9 .. ^1])
    if m < 1 or m > checks.len:
      quit "rv32_selftest: --mutate: out of range 1.." & $checks.len
    checks[m - 1].want = checks[m - 1].want xor 0x5A5A

  var b = initBuffer()
  # Where the code will be LOADED, not where it sits in the buffer. `emitLa`
  # materializes an absolute address, so without this every `la` names a
  # small number and the `jalr` through it jumps into nothing.
  b.absBase = LoadBase + uint32(HdrBytes)
  let lDone = b.createLabel()
  for i, c in checks:
    # a0 carries the 1-based index, so the failure path reports WHICH check broke
    # with no per-check code.
    b.data.emitLi(A0, int64(i + 1))
    c.emit(b)
    b.data.emitLi(T1, c.want)
    b.emitBranch(CondNe, T0, T1, lDone)
  b.data.emitLi(A0, 0)                  # every check passed
  b.defineLabel(lDone)
  b.data.emitLi(A7, SysExit)
  b.data.emitEcall()

  finalize(b)
  var code = newSeq[byte](b.data.len)
  for i in 0 ..< b.data.len: code[i] = b.data[i]

  let outFile = if paramCount() >= 1: paramStr(1) else: "rv32_selftest.elf"
  let vaddr = LoadBase + uint32(HdrBytes)
  let img = writeElf32(
    [Segment(vaddr: vaddr, data: code, memSize: code.len, flags: PF_R or PF_X)],
    entry = vaddr, machine = EM_RISCV, flags = 0, entryTag = 0)
  writeFile outFile, img
  setFilePermissions(outFile, {fpUserRead, fpUserWrite, fpUserExec,
                               fpGroupRead, fpGroupExec,
                               fpOthersRead, fpOthersExec})
  echo outFile, ": ", code.len, " bytes, ", checks.len, " checks"
